#include "gobgp_action.hpp"
#include "../fastnetmon_actions.hpp"

#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

#include "../bgp_protocol.hpp"

#include "gobgp_flowspec_lifecycle.hpp"
#include "gobgp_log_formatter.hpp"
#include "gobgp_flowspec_notification_formatter.hpp"
#include "gobgp_flowspec_rule_builder.hpp"

#include "../gobgp_client/gobgp_client.hpp"

#include "../fastnetmon_configuration_scheme.hpp"

#include <cstdlib>
#include <cerrno>
#include <limits>

#include <boost/thread.hpp>

extern fastnetmon_configuration_t fastnetmon_global_configuration;

bool exec_with_stdin_params(std::string cmd, std::string params);

namespace {

// This state is process-local. After a FastNetMon restart UUIDs for paths added before the restart are unavailable,
// so reconciliation with already installed GoBGP FlowSpec paths is intentionally not implemented yet.
gobgp_flowspec_lifecycle_t gobgp_flowspec_lifecycle;

bool parse_positive_gobgp_flowspec_option(const std::string& option_name,
                                          const std::string& option_value,
                                          uint64_t maximum_value,
                                          uint64_t& parsed_value) {
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(option_value.c_str(), &end, 10);

    if (option_value.empty() || option_value.front() == '-' || errno == ERANGE || end == option_value.c_str()
        || *end != '\0' || value == 0 || value > maximum_value) {
        logger << log4cpp::Priority::ERROR << "Configuration error: " << option_name << " must be in range 1.."
               << maximum_value;
        return false;
    }

    parsed_value = value;
    return true;
}

void send_gobgp_flowspec_success_notification(
    const std::string& event,
    const flow_spec_rule_t& flow_spec_rule,
    const std::string& add_path_uuid,
    const std::optional<gobgp_flowspec_port_classifier_result_t>& classifier_result = std::nullopt) {
    const std::string& notification_script = fastnetmon_global_configuration.gobgp_flowspec_notify_script_path;
    if (notification_script.empty()) {
        return;
    }

    if (!flow_spec_rule.destination_subnet_ipv4_used || flow_spec_rule.destination_subnet_ipv4.cidr_prefix_length != 32) {
        logger << log4cpp::Priority::ERROR << "GoBGP FlowSpec " << event
               << " notification skipped because the successful rule has no IPv4 /32 destination";
        return;
    }

    const std::string victim_ip = convert_ip_as_uint_to_string(flow_spec_rule.destination_subnet_ipv4.subnet_address);
    const std::string command = notification_script + " " + event + " " + victim_ip;
    std::string report;

    if (event == "add") {
        report = format_gobgp_flowspec_add_success_notification(flow_spec_rule, add_path_uuid, classifier_result);
    } else {
        report = format_gobgp_flowspec_delete_success_notification(flow_spec_rule, add_path_uuid);
    }

    logger << log4cpp::Priority::INFO << "GoBGP FlowSpec " << event << " success notification scheduled for "
           << victim_ip;
    boost::thread notification_thread(exec_with_stdin_params, command, report);
    notification_thread.detach();
}

void withdraw_gobgp_flowspec_ipv4_rule(GrpcClient& gobgp_client,
                                       const gobgp_flowspec_withdraw_request_t& withdraw_request) {
    const std::string rule_details = format_gobgp_flowspec_rule(withdraw_request.flow_spec_rule);
    const std::string uuid_details = format_gobgp_uuid_as_hex(withdraw_request.add_path_uuid);

    logger << log4cpp::Priority::INFO << "GoBGP FlowSpec DELETE attempt " << rule_details << " " << uuid_details;

    const bool withdraw_result = gobgp_client.WithdrawFlowSpecIPv4(withdraw_request.add_path_uuid);
    gobgp_flowspec_withdraw_completion_t completion = gobgp_flowspec_lifecycle.complete_withdraw(
        withdraw_request.rule_key, withdraw_request.add_path_uuid, withdraw_result);

    if (withdraw_result) {
        logger << log4cpp::Priority::INFO << "GoBGP FlowSpec DELETE success " << rule_details << " " << uuid_details;

        send_gobgp_flowspec_success_notification("delete", withdraw_request.flow_spec_rule,
                                                  withdraw_request.add_path_uuid);

        if (completion != gobgp_flowspec_withdraw_completion_t::erased) {
            logger << log4cpp::Priority::ERROR << "GoBGP FlowSpec DELETE completed but lifecycle state was not erased "
                   << rule_details << " " << uuid_details;
        }
    } else {
        logger << log4cpp::Priority::ERROR << "GoBGP FlowSpec DELETE failed " << rule_details << " " << uuid_details;
    }
}

void announce_gobgp_flowspec_ipv4_rule(GrpcClient& gobgp_client,
                                       const gobgp_flowspec_rule_key_t& rule_key,
                                       const flow_spec_rule_t& flow_spec_rule,
                                       const std::optional<gobgp_flowspec_port_classifier_result_t>& classifier_result) {
    const std::string rule_details = format_gobgp_flowspec_rule(flow_spec_rule);

    logger << log4cpp::Priority::INFO << "GoBGP FlowSpec ADD attempt " << rule_details;

    std::string add_path_uuid;
    if (!gobgp_client.AnnounceFlowSpecIPv4(flow_spec_rule, add_path_uuid)) {
        gobgp_flowspec_lifecycle.fail_announce(rule_key);
        logger << log4cpp::Priority::ERROR << "GoBGP FlowSpec ADD failed " << rule_details;
        return;
    }

    if (add_path_uuid.empty()) {
        gobgp_flowspec_lifecycle.fail_announce(rule_key);
        logger << log4cpp::Priority::ERROR << "GoBGP FlowSpec ADD failed " << rule_details
               << " because GoBGP returned an empty AddPath UUID";
        return;
    }

    send_gobgp_flowspec_success_notification("add", flow_spec_rule, add_path_uuid, classifier_result);

    gobgp_flowspec_announce_completion_t completion =
        gobgp_flowspec_lifecycle.complete_announce(rule_key, add_path_uuid);
    const std::string uuid_details = format_gobgp_uuid_as_hex(add_path_uuid);

    if (completion == gobgp_flowspec_announce_completion_t::installed) {
        logger << log4cpp::Priority::INFO << "GoBGP FlowSpec ADD success " << rule_details << " " << uuid_details;
        return;
    }

    if (completion == gobgp_flowspec_announce_completion_t::withdraw_required) {
        logger << log4cpp::Priority::INFO << "GoBGP FlowSpec ADD success " << rule_details << " " << uuid_details;
        logger << log4cpp::Priority::INFO << "GoBGP FlowSpec DELETE requested while ADD was in progress " << rule_details
               << " " << uuid_details;

        withdraw_gobgp_flowspec_ipv4_rule(gobgp_client, { rule_key, flow_spec_rule, add_path_uuid });
        return;
    }

    logger << log4cpp::Priority::ERROR << "GoBGP FlowSpec ADD completed but lifecycle state was not updated " << rule_details
           << " " << uuid_details;
}

void gobgp_ban_manage_flowspec_ipv4(GrpcClient& gobgp_client,
                                    uint32_t client_ip,
                                    bool is_withdrawal,
                                    const attack_details_t& current_attack,
                                    std::optional<uint16_t> selected_destination_port,
                                    const std::optional<gobgp_flowspec_port_classifier_result_t>& classifier_result) {
    if (is_withdrawal) {
        gobgp_flowspec_withdraw_start_result_t withdraw_start = gobgp_flowspec_lifecycle.begin_withdraw_for_victim(client_ip);

        if (withdraw_start.withdraw_requests.empty() && withdraw_start.deferred_rules.empty()
            && withdraw_start.in_progress_rules.empty()) {
            logger << log4cpp::Priority::INFO << "GoBGP FlowSpec DELETE skipped dst="
                   << convert_ip_as_uint_to_string(client_ip) << "/32 reason=no_active_rules";
            return;
        }

        for (const auto& flow_spec_rule : withdraw_start.deferred_rules) {
            logger << log4cpp::Priority::INFO << "GoBGP FlowSpec DELETE deferred while ADD is in progress "
                   << format_gobgp_flowspec_rule(flow_spec_rule);
        }

        for (const auto& flow_spec_rule : withdraw_start.in_progress_rules) {
            logger << log4cpp::Priority::INFO << "GoBGP FlowSpec DELETE skipped because DELETE is already in progress "
                   << format_gobgp_flowspec_rule(flow_spec_rule);
        }

        for (const auto& withdraw_request : withdraw_start.withdraw_requests) {
            withdraw_gobgp_flowspec_ipv4_rule(gobgp_client, withdraw_request);
        }

        return;
    }

    uint32_t redirect_ipv4 = 0;
    if (!convert_ip_as_string_to_uint_safe(fastnetmon_global_configuration.gobgp_flowspec_redirect_ipv4, redirect_ipv4)
        || redirect_ipv4 == 0) {
        logger << log4cpp::Priority::ERROR << "GoBGP FlowSpec ADD failed because configured redirect IPv4 is invalid";
        return;
    }

    flow_spec_rule_t flow_spec_rule =
        build_gobgp_flowspec_ipv4_rule(client_ip, current_attack, redirect_ipv4, selected_destination_port);
    gobgp_flowspec_rule_key_t rule_key;

    if (!build_gobgp_flowspec_rule_key(flow_spec_rule, rule_key)) {
        logger << log4cpp::Priority::ERROR << "GoBGP FlowSpec ADD failed because the generated rule has an invalid identity "
               << format_gobgp_flowspec_rule(flow_spec_rule);
        return;
    }

    if (!gobgp_flowspec_lifecycle.begin_announce(rule_key, flow_spec_rule)) {
        logger << log4cpp::Priority::INFO << "GoBGP FlowSpec ADD skipped because an identical rule is already active "
               << format_gobgp_flowspec_rule(flow_spec_rule);
        return;
    }

    announce_gobgp_flowspec_ipv4_rule(gobgp_client, rule_key, flow_spec_rule, classifier_result);
}

} // namespace

void gobgp_action_init() {
    logger << log4cpp::Priority::INFO << "GoBGP action module loaded";

    if (configuration_map.count("gobgp_next_hop")) {
        fastnetmon_global_configuration.gobgp_next_hop = configuration_map["gobgp_next_hop"];
    }

    if (configuration_map.count("gobgp_next_hop_ipv6")) {
        fastnetmon_global_configuration.gobgp_next_hop_ipv6 = configuration_map["gobgp_next_hop_ipv6"];
    }

    if (configuration_map.count("gobgp_next_hop_host_ipv6")) {
        fastnetmon_global_configuration.gobgp_next_hop_host_ipv6 = configuration_map["gobgp_next_hop_host_ipv6"];
    }

    if (configuration_map.count("gobgp_next_hop_subnet_ipv6")) {
        fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv6 = configuration_map["gobgp_next_hop_subnet_ipv6"];
    }

    if (configuration_map.count("gobgp_announce_host")) {
        fastnetmon_global_configuration.gobgp_announce_host = configuration_map["gobgp_announce_host"] == "on";
    }

    if (configuration_map.count("gobgp_announce_whole_subnet")) {
        fastnetmon_global_configuration.gobgp_announce_whole_subnet = configuration_map["gobgp_announce_whole_subnet"] == "on";
    }

    if (configuration_map.count("gobgp_announce_host_ipv6")) {
        fastnetmon_global_configuration.gobgp_announce_host_ipv6 = configuration_map["gobgp_announce_host_ipv6"] == "on";
    }

    if (configuration_map.count("gobgp_announce_whole_subnet_ipv6")) {
        fastnetmon_global_configuration.gobgp_announce_whole_subnet_ipv6 = configuration_map["gobgp_announce_whole_subnet_ipv6"] == "on";
    }

    if (configuration_map.count("gobgp_community_host")) {
	fastnetmon_global_configuration.gobgp_community_host = configuration_map["gobgp_community_host"];
    }

    if (configuration_map.count("gobgp_community_subnet")) {
        fastnetmon_global_configuration.gobgp_community_subnet = configuration_map["gobgp_community_subnet"];
    }

    if (configuration_map.count("gobgp_community_host_ipv6")) {
        fastnetmon_global_configuration.gobgp_community_host_ipv6 = configuration_map["gobgp_community_host_ipv6"];	    
    }

    if (configuration_map.count("gobgp_community_subnet_ipv6")) {
        fastnetmon_global_configuration.gobgp_community_subnet_ipv6 = configuration_map["gobgp_community_subnet_ipv6"];
    }

    if (configuration_map.count("gobgp_flowspec_redirect_ipv4")) {
        fastnetmon_global_configuration.gobgp_flowspec_redirect_ipv4 = configuration_map["gobgp_flowspec_redirect_ipv4"];
    }

    if (configuration_map.count("gobgp_flowspec_notify_script_path")) {
        fastnetmon_global_configuration.gobgp_flowspec_notify_script_path =
            configuration_map["gobgp_flowspec_notify_script_path"];
    }

    if (configuration_map.count("gobgp_flowspec_port_detection")) {
        fastnetmon_global_configuration.gobgp_flowspec_port_detection =
            configuration_map["gobgp_flowspec_port_detection"] == "on";
    }

    if (fastnetmon_global_configuration.gobgp_flowspec) {
        uint32_t redirect_ipv4 = 0;

        if (!convert_ip_as_string_to_uint_safe(fastnetmon_global_configuration.gobgp_flowspec_redirect_ipv4, redirect_ipv4)
            || redirect_ipv4 == 0) {
            logger << log4cpp::Priority::ERROR
                   << "Configuration error: gobgp_flowspec=on requires a non-zero valid IPv4 "
                      "gobgp_flowspec_redirect_ipv4";
            exit(1);
        }

        uint64_t parsed_value = 0;
        if (configuration_map.count("gobgp_flowspec_port_min_samples")
            && !parse_positive_gobgp_flowspec_option("gobgp_flowspec_port_min_samples",
                                                      configuration_map["gobgp_flowspec_port_min_samples"],
                                                      std::numeric_limits<uint64_t>::max(), parsed_value)) {
            exit(1);
        }

        if (configuration_map.count("gobgp_flowspec_port_min_samples")) {
            fastnetmon_global_configuration.gobgp_flowspec_port_min_samples = parsed_value;
        }

        if (configuration_map.count("gobgp_flowspec_port_dominance_percent")
            && !parse_positive_gobgp_flowspec_option("gobgp_flowspec_port_dominance_percent",
                                                      configuration_map["gobgp_flowspec_port_dominance_percent"],
                                                      100, parsed_value)) {
            exit(1);
        }

        if (configuration_map.count("gobgp_flowspec_port_dominance_percent")) {
            fastnetmon_global_configuration.gobgp_flowspec_port_dominance_percent =
                static_cast<uint8_t>(parsed_value);
        }
    }
}

void gobgp_action_shutdown() {
}

void gobgp_ban_manage_ipv6(GrpcClient& gobgp_client,
                           const subnet_ipv6_cidr_mask_t& client_ipv6,
                           bool is_withdrawal,
                           const attack_details_t& current_attack) {
    // TODO: that's very weird approach to use subnet_ipv6_cidr_mask_t for storing next hop which is HOST address
    // We need to rework all structures in stack of BGP logic to switch it to plain in6_addr

    subnet_ipv6_cidr_mask_t ipv6_next_hop_legacy{};
    ipv6_next_hop_legacy.cidr_prefix_length = 128; //-V1048

    bool parsed_next_hop_result =
        read_ipv6_host_from_string(fastnetmon_global_configuration.gobgp_next_hop_ipv6, ipv6_next_hop_legacy.subnet_address);

    if (!parsed_next_hop_result) {
        logger << log4cpp::Priority::ERROR
               << "Can't parse specified IPv6 next hop to IPv6 address: " << fastnetmon_global_configuration.gobgp_next_hop_ipv6;
        return;
    }

    // Starting July 2024, 1.2.8 we have capability to specify different next hops for host and subnet
    subnet_ipv6_cidr_mask_t gobgp_next_hop_host_ipv6{};
    gobgp_next_hop_host_ipv6.cidr_prefix_length = 128; //-V1048

    if (fastnetmon_global_configuration.gobgp_next_hop_host_ipv6 != "") {
        if (!read_ipv6_host_from_string(fastnetmon_global_configuration.gobgp_next_hop_host_ipv6,
                                        gobgp_next_hop_host_ipv6.subnet_address)) {
            logger << log4cpp::Priority::ERROR << "Can't parse specified IPv6 next hop gobgp_next_hop_host_ipv6 as IPv6 address: "
                   << fastnetmon_global_configuration.gobgp_next_hop_host_ipv6;
            // We do not stop processing here. If we failed then let's keep it zero
        }
    } else {
        // That's fine. It's expected to be empty on new installations
    }

    // Starting July 2024, 1.2.8 we have capability to specify different next hops for host and subnet
    subnet_ipv6_cidr_mask_t gobgp_next_hop_subnet_ipv6{};
    gobgp_next_hop_subnet_ipv6.cidr_prefix_length = 128; //-V1048

    if (fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv6 != "") {
        if (!read_ipv6_host_from_string(fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv6,
                                        gobgp_next_hop_subnet_ipv6.subnet_address)) {
            logger << log4cpp::Priority::ERROR << "Can't parse specified IPv6 next hop gobgp_next_hop_subnet_ipv6 as IPv6 address: "
                   << fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv6;
            // We do not stop processing here. If we failed then let's keep it zero
        }
    } else {
        // That's fine. It's expected to be empty on new installations
    }

    // For backward compatibility with old deployments which still use value gobgp_next_hop_ipv6 we check new value and if it's zero use old one
    if (is_zero_ipv6_address(gobgp_next_hop_host_ipv6.subnet_address)) {
        logger << log4cpp::Priority::INFO << "gobgp_next_hop_host_ipv6 is zero, will use global gobgp_next_hop_ipv6: "
               << fastnetmon_global_configuration.gobgp_next_hop_ipv6;

        gobgp_next_hop_host_ipv6.subnet_address = ipv6_next_hop_legacy.subnet_address;
    }

    if (is_zero_ipv6_address(gobgp_next_hop_subnet_ipv6.subnet_address)) {
        logger << log4cpp::Priority::INFO << "gobgp_next_hop_subnet_ipv6 is zero, will use global gobgp_next_hop_ipv6: "
               << fastnetmon_global_configuration.gobgp_next_hop_ipv6;

        gobgp_next_hop_subnet_ipv6.subnet_address = ipv6_next_hop_legacy.subnet_address;
    }

    if (fastnetmon_global_configuration.gobgp_announce_host_ipv6) {
        IPv6UnicastAnnounce unicast_ipv6_announce;

        std::vector<std::string> host_ipv6_communities;

        // This one is an old configuration option which can carry only single community
        host_ipv6_communities.push_back(fastnetmon_global_configuration.gobgp_community_host_ipv6);

        for (auto community_string : host_ipv6_communities) {
            bgp_community_attribute_element_t bgp_community_host;

            if (!read_bgp_community_from_string(community_string, bgp_community_host)) {
                logger << log4cpp::Priority::ERROR << "Could not decode BGP community for IPv6 host: " << community_string;
                // We may have multiple communities and other communities may be correct, skip only broken one
                continue;
            }

            unicast_ipv6_announce.add_community(bgp_community_host);
        }

        unicast_ipv6_announce.set_prefix(client_ipv6);
        unicast_ipv6_announce.set_next_hop(gobgp_next_hop_host_ipv6);

        const std::string route_details = format_gobgp_ipv6_unicast_route(unicast_ipv6_announce);
        const char* operation           = is_withdrawal ? "WITHDRAW" : "ADD";

        logger << log4cpp::Priority::INFO << "GoBGP IPv6 unicast " << operation << " attempt " << route_details;

        if (gobgp_client.AnnounceUnicastPrefixLowLevelIPv6(unicast_ipv6_announce, is_withdrawal)) {
            logger << log4cpp::Priority::INFO << "GoBGP IPv6 unicast " << operation << " success " << route_details;
        } else {
            logger << log4cpp::Priority::ERROR << "GoBGP IPv6 unicast " << operation << " failed " << route_details;
        }
    }

    if (fastnetmon_global_configuration.gobgp_announce_whole_subnet_ipv6) {
        logger << log4cpp::Priority::ERROR << "Sorry but we do not support IPv6 per subnet announces";
    }
}

void gobgp_ban_manage_ipv4(GrpcClient& gobgp_client,
                           uint32_t client_ip,
                           bool is_withdrawal,
                           const attack_details_t& current_attack,
                           std::optional<uint16_t> selected_destination_port,
                           const std::optional<gobgp_flowspec_port_classifier_result_t>& classifier_result) {
    if (fastnetmon_global_configuration.gobgp_flowspec) {
        gobgp_ban_manage_flowspec_ipv4(gobgp_client, client_ip, is_withdrawal, current_attack, selected_destination_port,
                                       classifier_result);
        return;
    }

    // Previously we used same next hop for both subnet and host
    uint32_t next_hop_as_integer_legacy = 0;

    if (!convert_ip_as_string_to_uint_safe(fastnetmon_global_configuration.gobgp_next_hop, next_hop_as_integer_legacy)) {
        logger << log4cpp::Priority::ERROR
               << "Could not decode next hop to numeric form: " << fastnetmon_global_configuration.gobgp_next_hop;
        return;
    }

    // Starting July 2024, 1.1.8 we have capability to specify different next hops for host and subnet
    uint32_t gobgp_next_hop_host_ipv4   = 0;
    uint32_t gobgp_next_hop_subnet_ipv4 = 0;

    // Read next hop for host
    if (fastnetmon_global_configuration.gobgp_next_hop_host_ipv4 != "") {
        if (!convert_ip_as_string_to_uint_safe(fastnetmon_global_configuration.gobgp_next_hop_host_ipv4, gobgp_next_hop_host_ipv4)) {
            logger << log4cpp::Priority::ERROR << "Could not decode next hop to numeric form for gobgp_next_hop_host_ipv4: "
                   << fastnetmon_global_configuration.gobgp_next_hop_host_ipv4;
            // We do not stop processing here. If we failed then let's keep it zero
        }
    } else {
        // That's fine. It's expected to be empty on new installations
    }


    // Read next hop for subnet
    if (fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv4 != "") {
        if (!convert_ip_as_string_to_uint_safe(fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv4, gobgp_next_hop_subnet_ipv4)) {
            logger << log4cpp::Priority::ERROR << "Could not decode next hop to numeric form for gobgp_next_hop_subnet_ipv4: "
                   << fastnetmon_global_configuration.gobgp_next_hop_subnet_ipv4;

            // We do not stop processing here. If we failed then let's keep it zero
        }
    } else {
        // That's fine. It's expected to be empty on new installations
    }

    // For backward compatibility with old deployments which still use value gobgp_next_hop we check new value and if it's zero use old one
    if (gobgp_next_hop_host_ipv4 == 0) {
        logger << log4cpp::Priority::INFO << "gobgp_next_hop_host_ipv4 is empty, will use global gobgp_next_hop: "
               << fastnetmon_global_configuration.gobgp_next_hop;
        gobgp_next_hop_host_ipv4 = next_hop_as_integer_legacy;
    }

    if (gobgp_next_hop_subnet_ipv4 == 0) {
        logger << log4cpp::Priority::INFO << "gobgp_next_hop_subnet_ipv4 is empty, will use global gobgp_next_hop: "
               << fastnetmon_global_configuration.gobgp_next_hop;
        gobgp_next_hop_subnet_ipv4 = next_hop_as_integer_legacy;
    }

    if (fastnetmon_global_configuration.gobgp_announce_whole_subnet) {
        IPv4UnicastAnnounce unicast_ipv4_announce;

        std::vector<std::string> subnet_ipv4_communities;

        subnet_ipv4_communities.push_back(fastnetmon_global_configuration.gobgp_community_subnet);

        for (auto community_string : subnet_ipv4_communities) {
            bgp_community_attribute_element_t bgp_community_subnet;

            if (!read_bgp_community_from_string(community_string, bgp_community_subnet)) {
                logger << log4cpp::Priority::ERROR << "Could not decode BGP community for IPv4 subnet";
                // We may have multiple communities and other communities may be correct, skip only broken one
                continue;
            }

            unicast_ipv4_announce.add_community(bgp_community_subnet);
        }

        // By default use network from attack
        subnet_cidr_mask_t customer_network;
        customer_network.subnet_address     = current_attack.customer_network.subnet_address;
        customer_network.cidr_prefix_length = current_attack.customer_network.cidr_prefix_length;

        unicast_ipv4_announce.set_prefix(customer_network);
        unicast_ipv4_announce.set_next_hop(gobgp_next_hop_subnet_ipv4);

        const std::string route_details = format_gobgp_ipv4_unicast_route(unicast_ipv4_announce);
        const char* operation           = is_withdrawal ? "WITHDRAW" : "ADD";

        logger << log4cpp::Priority::INFO << "GoBGP IPv4 unicast " << operation << " attempt " << route_details;

        if (gobgp_client.AnnounceUnicastPrefixLowLevelIPv4(unicast_ipv4_announce, is_withdrawal)) {
            logger << log4cpp::Priority::INFO << "GoBGP IPv4 unicast " << operation << " success " << route_details;
        } else {
            logger << log4cpp::Priority::ERROR << "GoBGP IPv4 unicast " << operation << " failed " << route_details;
        }
    }

    if (fastnetmon_global_configuration.gobgp_announce_host) {
        IPv4UnicastAnnounce unicast_ipv4_announce;

        std::vector<std::string> host_ipv4_communities;

        host_ipv4_communities.push_back(fastnetmon_global_configuration.gobgp_community_host);

        for (auto community_string : host_ipv4_communities) {
            bgp_community_attribute_element_t bgp_community_host;

            if (!read_bgp_community_from_string(community_string, bgp_community_host)) {
                logger << log4cpp::Priority::ERROR << "Could not decode BGP community for IPv4 host: " << community_string;
                // We may have multiple communities and other communities may be correct, skip only broken one
                continue;
            }

            unicast_ipv4_announce.add_community(bgp_community_host);
        }

        subnet_cidr_mask_t host_address_as_subnet(client_ip, 32);

        unicast_ipv4_announce.set_prefix(host_address_as_subnet);
        unicast_ipv4_announce.set_next_hop(gobgp_next_hop_host_ipv4);

        const std::string route_details = format_gobgp_ipv4_unicast_route(unicast_ipv4_announce);
        const char* operation           = is_withdrawal ? "WITHDRAW" : "ADD";

        logger << log4cpp::Priority::INFO << "GoBGP IPv4 unicast " << operation << " attempt " << route_details;

        if (gobgp_client.AnnounceUnicastPrefixLowLevelIPv4(unicast_ipv4_announce, is_withdrawal)) {
            logger << log4cpp::Priority::INFO << "GoBGP IPv4 unicast " << operation << " success " << route_details;
        } else {
            logger << log4cpp::Priority::ERROR << "GoBGP IPv4 unicast " << operation << " failed " << route_details;
        }
    }
}


void gobgp_ban_manage(const std::string& action,
                      bool ipv6,
                      uint32_t client_ip,
                      const subnet_ipv6_cidr_mask_t& client_ipv6,
                      const attack_details_t& current_attack,
                      std::optional<uint16_t> selected_destination_port,
                      std::optional<gobgp_flowspec_port_classifier_result_t> classifier_result) {
    GrpcClient gobgp_client = GrpcClient(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

    bool is_withdrawal = false;

    std::string action_name;

    if (action == "ban") {
        is_withdrawal = false;
        action_name   = "announce";
    } else {
        is_withdrawal = true;
        action_name   = "withdraw";
    }

    if (ipv6) {
        gobgp_ban_manage_ipv6(gobgp_client, client_ipv6, is_withdrawal, current_attack);
    } else {
        gobgp_ban_manage_ipv4(gobgp_client, client_ip, is_withdrawal, current_attack, selected_destination_port,
                               classifier_result);
    }
}
