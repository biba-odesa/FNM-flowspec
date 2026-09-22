#include "gobgp_flowspec_lifecycle.hpp"

#include <tuple>

bool gobgp_flowspec_rule_key_t::operator<(const gobgp_flowspec_rule_key_t& other) const {
    return std::tie(destination_ipv4, protocol_present, protocol, destination_port_present, destination_port)
           < std::tie(other.destination_ipv4,
                      other.protocol_present,
                      other.protocol,
                      other.destination_port_present,
                      other.destination_port);
}

bool build_gobgp_flowspec_rule_key(const flow_spec_rule_t& flow_spec_rule, gobgp_flowspec_rule_key_t& rule_key) {
    if (!flow_spec_rule.destination_subnet_ipv4_used || flow_spec_rule.destination_subnet_ipv4.cidr_prefix_length != 32
        || flow_spec_rule.protocols.size() > 1 || flow_spec_rule.destination_ports.size() > 1) {
        return false;
    }

    rule_key = gobgp_flowspec_rule_key_t{};
    rule_key.destination_ipv4 = flow_spec_rule.destination_subnet_ipv4.subnet_address;

    if (!flow_spec_rule.protocols.empty()) {
        rule_key.protocol_present = true;
        rule_key.protocol = flow_spec_rule.protocols.front();
    }

    if (!flow_spec_rule.destination_ports.empty()) {
        if (!rule_key.protocol_present) {
            return false;
        }

        rule_key.destination_port_present = true;
        rule_key.destination_port = flow_spec_rule.destination_ports.front();
    }

    return true;
}

bool gobgp_flowspec_lifecycle_t::begin_announce(const gobgp_flowspec_rule_key_t& rule_key,
                                                 const flow_spec_rule_t& flow_spec_rule) {
    std::lock_guard<std::mutex> lock(mutex);

    // Do not let a new BAN race with an unfinished withdrawal lifecycle for this victim.
    if (victims_withdraw_requested.count(rule_key.destination_ipv4) != 0) {
        return false;
    }

    if (rules.find(rule_key) != rules.end()) {
        return false;
    }

    rules.emplace(rule_key, gobgp_flowspec_rule_state_t{ gobgp_flowspec_rule_state_type_t::announcing, flow_spec_rule, "" });
    return true;
}

bool gobgp_flowspec_lifecycle_t::begin_refresh_announce(const gobgp_flowspec_rule_key_t& rule_key,
                                                         const flow_spec_rule_t& flow_spec_rule) {
    std::lock_guard<std::mutex> lock(mutex);

    // Do not let a refresh operation add a path after UNBAN has started for this victim.
    if (victims_withdraw_requested.count(rule_key.destination_ipv4) != 0) {
        return false;
    }

    if (rules.find(rule_key) != rules.end()) {
        return false;
    }

    rules.emplace(rule_key, gobgp_flowspec_rule_state_t{ gobgp_flowspec_rule_state_type_t::announcing, flow_spec_rule, "" });
    return true;
}

bool gobgp_flowspec_lifecycle_t::begin_refresh_capture(uint32_t victim_ipv4) {
    std::lock_guard<std::mutex> lock(mutex);

    if (victims_withdraw_requested.count(victim_ipv4) != 0 || victims_refresh_in_progress.count(victim_ipv4) != 0) {
        return false;
    }

    victims_refresh_in_progress.insert(victim_ipv4);
    return true;
}

void gobgp_flowspec_lifecycle_t::complete_refresh_capture(uint32_t victim_ipv4) {
    std::lock_guard<std::mutex> lock(mutex);
    victims_refresh_in_progress.erase(victim_ipv4);
}

void gobgp_flowspec_lifecycle_t::finish_refresh_capture(uint32_t victim_ipv4) {
    std::lock_guard<std::mutex> lock(mutex);
    victims_refresh_in_progress.erase(victim_ipv4);
    clear_withdraw_fence_if_finished_locked(victim_ipv4);
}

void gobgp_flowspec_lifecycle_t::fail_announce(const gobgp_flowspec_rule_key_t& rule_key) {
    std::lock_guard<std::mutex> lock(mutex);
    auto rule_iterator = rules.find(rule_key);

    if (rule_iterator == rules.end()) {
        return;
    }

    if (rule_iterator->second.state == gobgp_flowspec_rule_state_type_t::announcing
        || (rule_iterator->second.state == gobgp_flowspec_rule_state_type_t::withdraw_requested
            && rule_iterator->second.add_path_uuid.empty())) {
        rules.erase(rule_iterator);
        clear_withdraw_fence_if_finished_locked(rule_key.destination_ipv4);
    }
}

gobgp_flowspec_announce_completion_t gobgp_flowspec_lifecycle_t::complete_announce(
    const gobgp_flowspec_rule_key_t& rule_key, const std::string& add_path_uuid) {
    std::lock_guard<std::mutex> lock(mutex);
    auto rule_iterator = rules.find(rule_key);

    if (rule_iterator == rules.end() || add_path_uuid.empty()) {
        return gobgp_flowspec_announce_completion_t::ignored;
    }

    gobgp_flowspec_rule_state_t& rule_state = rule_iterator->second;

    if (rule_state.state == gobgp_flowspec_rule_state_type_t::announcing) {
        rule_state.add_path_uuid = add_path_uuid;
        rule_state.state = gobgp_flowspec_rule_state_type_t::installed;
        return gobgp_flowspec_announce_completion_t::installed;
    }

    if (rule_state.state == gobgp_flowspec_rule_state_type_t::withdraw_requested && rule_state.add_path_uuid.empty()) {
        rule_state.add_path_uuid = add_path_uuid;
        rule_state.state = gobgp_flowspec_rule_state_type_t::withdrawing;
        return gobgp_flowspec_announce_completion_t::withdraw_required;
    }

    return gobgp_flowspec_announce_completion_t::ignored;
}

gobgp_flowspec_withdraw_start_result_t gobgp_flowspec_lifecycle_t::begin_withdraw_for_victim(uint32_t victim_ipv4) {
    std::lock_guard<std::mutex> lock(mutex);
    gobgp_flowspec_withdraw_start_result_t result;

    // Keep this fence even if there are no rules yet: a concurrent refresh must not create a new path after UNBAN.
    victims_withdraw_requested.insert(victim_ipv4);

    for (auto& [rule_key, rule_state] : rules) {
        if (rule_key.destination_ipv4 != victim_ipv4) {
            continue;
        }

        if (rule_state.state == gobgp_flowspec_rule_state_type_t::announcing) {
            rule_state.state = gobgp_flowspec_rule_state_type_t::withdraw_requested;
            result.deferred_rules.push_back(rule_state.flow_spec_rule);
            continue;
        }

        if (rule_state.state == gobgp_flowspec_rule_state_type_t::installed
            || (rule_state.state == gobgp_flowspec_rule_state_type_t::withdraw_requested
                && !rule_state.add_path_uuid.empty())) {
            rule_state.state = gobgp_flowspec_rule_state_type_t::withdrawing;
            result.withdraw_requests.push_back(
                gobgp_flowspec_withdraw_request_t{ rule_key, rule_state.flow_spec_rule, rule_state.add_path_uuid });
            continue;
        }

        if (rule_state.state == gobgp_flowspec_rule_state_type_t::withdraw_requested) {
            result.deferred_rules.push_back(rule_state.flow_spec_rule);
            continue;
        }

        result.in_progress_rules.push_back(rule_state.flow_spec_rule);
    }

    clear_withdraw_fence_if_finished_locked(victim_ipv4);

    return result;
}

gobgp_flowspec_withdraw_completion_t gobgp_flowspec_lifecycle_t::complete_withdraw(
    const gobgp_flowspec_rule_key_t& rule_key, const std::string& add_path_uuid, bool success) {
    std::lock_guard<std::mutex> lock(mutex);
    auto rule_iterator = rules.find(rule_key);

    if (rule_iterator == rules.end() || rule_iterator->second.state != gobgp_flowspec_rule_state_type_t::withdrawing
        || rule_iterator->second.add_path_uuid != add_path_uuid) {
        return gobgp_flowspec_withdraw_completion_t::ignored;
    }

    if (success) {
        rules.erase(rule_iterator);
        clear_withdraw_fence_if_finished_locked(rule_key.destination_ipv4);
        return gobgp_flowspec_withdraw_completion_t::erased;
    }

    rule_iterator->second.state = gobgp_flowspec_rule_state_type_t::withdraw_requested;
    return gobgp_flowspec_withdraw_completion_t::retry_pending;
}

bool gobgp_flowspec_lifecycle_t::victim_has_rules_locked(uint32_t victim_ipv4) const {
    for (const auto& [rule_key, rule_state] : rules) {
        (void)rule_state;

        if (rule_key.destination_ipv4 == victim_ipv4) {
            return true;
        }
    }

    return false;
}

void gobgp_flowspec_lifecycle_t::clear_withdraw_fence_if_finished_locked(uint32_t victim_ipv4) {
    // A capture already reserved before UNBAN can still attempt a refresh announce.
    if (victim_has_rules_locked(victim_ipv4) || victims_refresh_in_progress.count(victim_ipv4) != 0) {
        return;
    }

    victims_withdraw_requested.erase(victim_ipv4);
}

gobgp_flowspec_refresh_protocol_plan_t gobgp_flowspec_lifecycle_t::begin_refresh_protocol_rules(
    const gobgp_flowspec_announce_request_t& protocol_only_request,
    const std::vector<gobgp_flowspec_announce_request_t>& port_rule_requests,
    uint64_t max_port_rules) {
    std::lock_guard<std::mutex> lock(mutex);
    gobgp_flowspec_refresh_protocol_plan_t plan;
    const gobgp_flowspec_rule_key_t& protocol_only_key = protocol_only_request.rule_key;

    if (victims_withdraw_requested.count(protocol_only_key.destination_ipv4) != 0) {
        plan.action = gobgp_flowspec_refresh_protocol_action_t::withdraw_in_progress;
        return plan;
    }

    // This entire decision is made under one mutex so announcing rules reserve capacity before another refresh can plan.
    for (const auto& [rule_key, rule_state] : rules) {
        (void)rule_state;

        if (rule_key.destination_ipv4 != protocol_only_key.destination_ipv4 || !rule_key.protocol_present
            || rule_key.protocol != protocol_only_key.protocol) {
            continue;
        }

        if (!rule_key.destination_port_present) {
            plan.action = gobgp_flowspec_refresh_protocol_action_t::protocol_only_covers;
            return plan;
        }

        ++plan.existing_port_rule_count;
    }

    std::map<gobgp_flowspec_rule_key_t, gobgp_flowspec_announce_request_t> unique_new_port_rules;
    for (const auto& request : port_rule_requests) {
        if (request.rule_key.destination_ipv4 != protocol_only_key.destination_ipv4 || !request.rule_key.protocol_present
            || request.rule_key.protocol != protocol_only_key.protocol || !request.rule_key.destination_port_present) {
            continue;
        }

        if (rules.find(request.rule_key) == rules.end()) {
            unique_new_port_rules.emplace(request.rule_key, request);
        }
    }

    plan.new_port_rule_count = unique_new_port_rules.size();
    if (plan.new_port_rule_count == 0) {
        plan.action = gobgp_flowspec_refresh_protocol_action_t::no_new_port_rules;
        return plan;
    }

    if (plan.existing_port_rule_count + plan.new_port_rule_count > max_port_rules) {
        rules.emplace(protocol_only_key,
                      gobgp_flowspec_rule_state_t{ gobgp_flowspec_rule_state_type_t::announcing,
                                                   protocol_only_request.flow_spec_rule,
                                                   "" });
        plan.action = gobgp_flowspec_refresh_protocol_action_t::escalate_protocol_only;
        plan.announce_requests.push_back(protocol_only_request);
        return plan;
    }

    for (const auto& [rule_key, request] : unique_new_port_rules) {
        rules.emplace(rule_key,
                      gobgp_flowspec_rule_state_t{ gobgp_flowspec_rule_state_type_t::announcing,
                                                   request.flow_spec_rule,
                                                   "" });
        plan.announce_requests.push_back(request);
    }

    plan.action = gobgp_flowspec_refresh_protocol_action_t::add_port_rules;
    return plan;
}

std::vector<gobgp_flowspec_withdraw_request_t> gobgp_flowspec_lifecycle_t::begin_protocol_only_escalation_cleanup(
    const gobgp_flowspec_rule_key_t& protocol_only_rule_key) {
    std::lock_guard<std::mutex> lock(mutex);
    std::vector<gobgp_flowspec_withdraw_request_t> withdraw_requests;
    const auto protocol_only_iterator = rules.find(protocol_only_rule_key);

    if (protocol_only_iterator == rules.end()
        || protocol_only_iterator->second.state != gobgp_flowspec_rule_state_type_t::installed
        || victims_withdraw_requested.count(protocol_only_rule_key.destination_ipv4) != 0) {
        return withdraw_requests;
    }

    // This is called only after the protocol-only AddPath is installed, preserving coverage while port rules are removed.
    for (auto& [rule_key, rule_state] : rules) {
        if (rule_key.destination_ipv4 != protocol_only_rule_key.destination_ipv4 || !rule_key.protocol_present
            || rule_key.protocol != protocol_only_rule_key.protocol || !rule_key.destination_port_present) {
            continue;
        }

        if (rule_state.state == gobgp_flowspec_rule_state_type_t::announcing) {
            rule_state.state = gobgp_flowspec_rule_state_type_t::withdraw_requested;
            continue;
        }

        if (rule_state.state == gobgp_flowspec_rule_state_type_t::installed
            || (rule_state.state == gobgp_flowspec_rule_state_type_t::withdraw_requested
                && !rule_state.add_path_uuid.empty())) {
            rule_state.state = gobgp_flowspec_rule_state_type_t::withdrawing;
            withdraw_requests.push_back({ rule_key, rule_state.flow_spec_rule, rule_state.add_path_uuid });
        }
    }

    return withdraw_requests;
}

std::optional<gobgp_flowspec_rule_state_snapshot_t> gobgp_flowspec_lifecycle_t::get_state(
    const gobgp_flowspec_rule_key_t& rule_key) const {
    std::lock_guard<std::mutex> lock(mutex);
    auto rule_iterator = rules.find(rule_key);

    if (rule_iterator == rules.end()) {
        return std::nullopt;
    }

    return gobgp_flowspec_rule_state_snapshot_t{ rule_iterator->second.state, rule_iterator->second.add_path_uuid };
}

size_t gobgp_flowspec_lifecycle_t::size() const {
    std::lock_guard<std::mutex> lock(mutex);
    return rules.size();
}
