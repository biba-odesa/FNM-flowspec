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

    if (rules.find(rule_key) != rules.end()) {
        return false;
    }

    rules.emplace(rule_key, gobgp_flowspec_rule_state_t{ gobgp_flowspec_rule_state_type_t::announcing, flow_spec_rule, "" });
    return true;
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
        return gobgp_flowspec_withdraw_completion_t::erased;
    }

    rule_iterator->second.state = gobgp_flowspec_rule_state_type_t::withdraw_requested;
    return gobgp_flowspec_withdraw_completion_t::retry_pending;
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
