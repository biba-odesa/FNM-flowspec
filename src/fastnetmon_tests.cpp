#include <gtest/gtest.h>
#include <math.h>

#include "bgp_protocol_flow_spec.hpp"
#include "actions/gobgp_flowspec_lifecycle.hpp"
#include "actions/gobgp_flowspec_port_classifier.hpp"
#include "actions/gobgp_flowspec_notification_formatter.hpp"
#include "actions/gobgp_flowspec_protocol_admission.hpp"
#include "actions/gobgp_flowspec_rule_builder.hpp"
#include "actions/gobgp_log_formatter.hpp"
#include "fastnetmon_configuration_scheme.hpp"
#include "fast_library.hpp"

#include <array>
#include <cstring>
#include <fstream>

#include "log4cpp/Appender.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include <arpa/inet.h>

log4cpp::Category& logger = log4cpp::Category::getRoot();

namespace {

flow_spec_rule_t make_gobgp_flowspec_lifecycle_rule(uint32_t destination_ipv4,
                                                    ip_protocol_t protocol,
                                                    bool include_protocol,
                                                    bool include_destination_port = false) {
    uint32_t redirect_ipv4 = 0;
    convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4);

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ipv4, 32));
    flow_spec_rule.add_ipv4_nexthop(redirect_ipv4);

    if (include_protocol) {
        flow_spec_rule.add_protocol(protocol);
    }

    if (include_destination_port) {
        flow_spec_rule.add_destination_port(443);
    }

    return flow_spec_rule;
}

gobgp_flowspec_rule_key_t make_gobgp_flowspec_lifecycle_key(const flow_spec_rule_t& flow_spec_rule) {
    gobgp_flowspec_rule_key_t rule_key;
    EXPECT_TRUE(build_gobgp_flowspec_rule_key(flow_spec_rule, rule_key));
    return rule_key;
}

simple_packet_t make_gobgp_flowspec_port_sample(uint32_t victim_ipv4,
                                                unsigned int protocol,
                                                uint16_t destination_port,
                                                uint64_t number_of_packets = 1,
                                                uint32_t sample_ratio = 1) {
    simple_packet_t packet;
    packet.ip_protocol_version = 4;
    packet.packet_direction = INCOMING;
    packet.dst_ip = victim_ipv4;
    packet.protocol = protocol;
    packet.destination_port = destination_port;
    packet.number_of_packets = number_of_packets;
    packet.sample_ratio = sample_ratio;
    return packet;
}

attack_details_t make_gobgp_flowspec_port_attack(unsigned int protocol, direction_t direction = INCOMING) {
    attack_details_t current_attack;
    current_attack.attack_protocol = protocol;
    current_attack.attack_direction = direction;
    return current_attack;
}

boost::circular_buffer<simple_packet_t> make_gobgp_flowspec_port_samples(std::initializer_list<simple_packet_t> samples) {
    boost::circular_buffer<simple_packet_t> result(samples.size());
    for (const auto& sample : samples) {
        result.push_back(sample);
    }

    return result;
}

gobgp_flowspec_port_classifier_config_t make_gobgp_flowspec_port_config(uint64_t min_samples = 2,
                                                                          uint8_t dominance_percent = 70) {
    return { min_samples, dominance_percent };
}

gobgp_flowspec_protocol_admission_snapshot_t make_gobgp_flowspec_admission_snapshot(
    uint64_t tcp_pps,
    uint64_t udp_pps,
    uint64_t icmp_pps,
    bool tcp_enabled = true,
    bool udp_enabled = true,
    bool icmp_enabled = true) {
    gobgp_flowspec_protocol_admission_snapshot_t snapshot;
    snapshot.tcp_in_pps = tcp_pps;
    snapshot.udp_in_pps = udp_pps;
    snapshot.icmp_in_pps = icmp_pps;
    snapshot.tcp_pps_enabled = tcp_enabled;
    snapshot.udp_pps_enabled = udp_enabled;
    snapshot.icmp_pps_enabled = icmp_enabled;
    snapshot.tcp_pps_threshold = 50000;
    snapshot.udp_pps_threshold = 50000;
    snapshot.icmp_pps_threshold = 30000;
    return snapshot;
}

const gobgp_flowspec_refresh_candidate_t* find_gobgp_flowspec_refresh_candidate(
    const std::vector<gobgp_flowspec_refresh_candidate_t>& candidates,
    ip_protocol_t protocol) {
    for (const auto& candidate : candidates) {
        if (candidate.protocol == protocol) {
            return &candidate;
        }
    }

    return nullptr;
}

gobgp_flowspec_announce_request_t make_gobgp_flowspec_refresh_announce_request(
    uint32_t victim_ipv4,
    ip_protocol_t protocol,
    std::optional<uint16_t> destination_port = std::nullopt) {
    flow_spec_rule_t rule = make_gobgp_flowspec_lifecycle_rule(victim_ipv4, protocol, true);
    if (destination_port.has_value()) {
        rule.add_destination_port(*destination_port);
    }

    return { make_gobgp_flowspec_lifecycle_key(rule), rule };
}

const gobgp_flowspec_refresh_protocol_result_t* find_gobgp_flowspec_refresh_protocol_result(
    const std::vector<gobgp_flowspec_refresh_protocol_result_t>& results,
    ip_protocol_t protocol) {
    for (const auto& result : results) {
        if (result.protocol == protocol) {
            return &result;
        }
    }

    return nullptr;
}

} // namespace

TEST(gobgp_flowspec_lifecycle, first_ban_and_duplicate_ban) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t flow_spec_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::TCP, true);
    gobgp_flowspec_rule_key_t rule_key = make_gobgp_flowspec_lifecycle_key(flow_spec_rule);
    gobgp_flowspec_lifecycle_t lifecycle;

    EXPECT_TRUE(lifecycle.begin_announce(rule_key, flow_spec_rule));
    EXPECT_FALSE(lifecycle.begin_announce(rule_key, flow_spec_rule));
    EXPECT_EQ(lifecycle.size(), 1U);
}

TEST(gobgp_flowspec_lifecycle, add_success_installs_uuid) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t flow_spec_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::UDP, true);
    gobgp_flowspec_rule_key_t rule_key = make_gobgp_flowspec_lifecycle_key(flow_spec_rule);
    gobgp_flowspec_lifecycle_t lifecycle;

    ASSERT_TRUE(lifecycle.begin_announce(rule_key, flow_spec_rule));
    EXPECT_EQ(lifecycle.complete_announce(rule_key, std::string("\x00\x01", 2)),
              gobgp_flowspec_announce_completion_t::installed);

    std::optional<gobgp_flowspec_rule_state_snapshot_t> state = lifecycle.get_state(rule_key);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->state, gobgp_flowspec_rule_state_type_t::installed);
    EXPECT_EQ(state->add_path_uuid, std::string("\x00\x01", 2));
}

TEST(gobgp_flowspec_lifecycle, unban_during_announce_requires_immediate_withdraw) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t flow_spec_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::ICMP, true);
    gobgp_flowspec_rule_key_t rule_key = make_gobgp_flowspec_lifecycle_key(flow_spec_rule);
    gobgp_flowspec_lifecycle_t lifecycle;

    ASSERT_TRUE(lifecycle.begin_announce(rule_key, flow_spec_rule));
    gobgp_flowspec_withdraw_start_result_t withdraw_start = lifecycle.begin_withdraw_for_victim(destination_ipv4);
    EXPECT_TRUE(withdraw_start.withdraw_requests.empty());
    ASSERT_EQ(withdraw_start.deferred_rules.size(), 1U);

    EXPECT_EQ(lifecycle.complete_announce(rule_key, std::string("\x01\x02", 2)),
              gobgp_flowspec_announce_completion_t::withdraw_required);

    std::optional<gobgp_flowspec_rule_state_snapshot_t> state = lifecycle.get_state(rule_key);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->state, gobgp_flowspec_rule_state_type_t::withdrawing);
    EXPECT_EQ(state->add_path_uuid, std::string("\x01\x02", 2));
}

TEST(gobgp_flowspec_lifecycle, installed_unban_erases_only_after_successful_withdraw) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t flow_spec_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::TCP, true, true);
    gobgp_flowspec_rule_key_t rule_key = make_gobgp_flowspec_lifecycle_key(flow_spec_rule);
    gobgp_flowspec_lifecycle_t lifecycle;
    const std::string add_path_uuid("\x10\x20", 2);

    ASSERT_TRUE(lifecycle.begin_announce(rule_key, flow_spec_rule));
    ASSERT_EQ(lifecycle.complete_announce(rule_key, add_path_uuid), gobgp_flowspec_announce_completion_t::installed);

    gobgp_flowspec_withdraw_start_result_t withdraw_start = lifecycle.begin_withdraw_for_victim(destination_ipv4);
    ASSERT_EQ(withdraw_start.withdraw_requests.size(), 1U);
    EXPECT_EQ(withdraw_start.withdraw_requests.front().add_path_uuid, add_path_uuid);
    EXPECT_EQ(lifecycle.complete_withdraw(rule_key, add_path_uuid, true), gobgp_flowspec_withdraw_completion_t::erased);
    EXPECT_EQ(lifecycle.size(), 0U);
}

TEST(gobgp_flowspec_lifecycle, failed_withdraw_retains_uuid_for_retry) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t flow_spec_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::UDP, true);
    gobgp_flowspec_rule_key_t rule_key = make_gobgp_flowspec_lifecycle_key(flow_spec_rule);
    gobgp_flowspec_lifecycle_t lifecycle;
    const std::string add_path_uuid("\x30\x40", 2);

    ASSERT_TRUE(lifecycle.begin_announce(rule_key, flow_spec_rule));
    ASSERT_EQ(lifecycle.complete_announce(rule_key, add_path_uuid), gobgp_flowspec_announce_completion_t::installed);
    ASSERT_EQ(lifecycle.begin_withdraw_for_victim(destination_ipv4).withdraw_requests.size(), 1U);
    EXPECT_EQ(lifecycle.complete_withdraw(rule_key, add_path_uuid, false), gobgp_flowspec_withdraw_completion_t::retry_pending);

    std::optional<gobgp_flowspec_rule_state_snapshot_t> state = lifecycle.get_state(rule_key);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->state, gobgp_flowspec_rule_state_type_t::withdraw_requested);
    EXPECT_EQ(state->add_path_uuid, add_path_uuid);

    gobgp_flowspec_withdraw_start_result_t retry_start = lifecycle.begin_withdraw_for_victim(destination_ipv4);
    ASSERT_EQ(retry_start.withdraw_requests.size(), 1U);
    EXPECT_EQ(retry_start.withdraw_requests.front().add_path_uuid, add_path_uuid);
}

TEST(gobgp_flowspec_lifecycle, regular_announce_is_blocked_while_withdraw_is_pending_for_same_or_different_rule) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t tcp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::TCP, true, true);
    flow_spec_rule_t udp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::UDP, true, true);
    const auto tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_rule);
    const auto udp_key = make_gobgp_flowspec_lifecycle_key(udp_rule);
    gobgp_flowspec_lifecycle_t lifecycle;

    ASSERT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
    ASSERT_EQ(lifecycle.complete_announce(tcp_key, std::string("\\x01", 1)), gobgp_flowspec_announce_completion_t::installed);
    ASSERT_EQ(lifecycle.begin_withdraw_for_victim(destination_ipv4).withdraw_requests.size(), 1U);

    EXPECT_FALSE(lifecycle.begin_announce(tcp_key, tcp_rule));
    EXPECT_FALSE(lifecycle.begin_announce(udp_key, udp_rule));
    EXPECT_FALSE(lifecycle.begin_refresh_announce(udp_key, udp_rule));
    EXPECT_FALSE(lifecycle.begin_refresh_capture(destination_ipv4));
}

TEST(gobgp_flowspec_lifecycle, fence_clears_after_last_successful_withdraw_and_allows_reban) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t tcp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::TCP, true, true);
    const auto tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_rule);
    gobgp_flowspec_lifecycle_t lifecycle;
    const std::string uuid("\\x01", 1);

    ASSERT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
    ASSERT_EQ(lifecycle.complete_announce(tcp_key, uuid), gobgp_flowspec_announce_completion_t::installed);
    ASSERT_EQ(lifecycle.begin_withdraw_for_victim(destination_ipv4).withdraw_requests.size(), 1U);
    ASSERT_EQ(lifecycle.complete_withdraw(tcp_key, uuid, true), gobgp_flowspec_withdraw_completion_t::erased);

    EXPECT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
}

TEST(gobgp_flowspec_lifecycle, fence_clears_only_after_all_victim_rules_are_withdrawn) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t tcp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::TCP, true, true);
    flow_spec_rule_t udp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::UDP, true, true);
    const auto tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_rule);
    const auto udp_key = make_gobgp_flowspec_lifecycle_key(udp_rule);
    gobgp_flowspec_lifecycle_t lifecycle;
    const std::string tcp_uuid("\\x01", 1);
    const std::string udp_uuid("\\x02", 1);

    ASSERT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
    ASSERT_TRUE(lifecycle.begin_announce(udp_key, udp_rule));
    ASSERT_EQ(lifecycle.complete_announce(tcp_key, tcp_uuid), gobgp_flowspec_announce_completion_t::installed);
    ASSERT_EQ(lifecycle.complete_announce(udp_key, udp_uuid), gobgp_flowspec_announce_completion_t::installed);
    ASSERT_EQ(lifecycle.begin_withdraw_for_victim(destination_ipv4).withdraw_requests.size(), 2U);
    ASSERT_EQ(lifecycle.complete_withdraw(tcp_key, tcp_uuid, true), gobgp_flowspec_withdraw_completion_t::erased);

    EXPECT_FALSE(lifecycle.begin_announce(tcp_key, tcp_rule));
    ASSERT_EQ(lifecycle.complete_withdraw(udp_key, udp_uuid, true), gobgp_flowspec_withdraw_completion_t::erased);
    EXPECT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
}

TEST(gobgp_flowspec_lifecycle, failed_announce_after_unban_clears_last_rule_fence) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t tcp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::TCP, true, true);
    const auto tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_rule);
    gobgp_flowspec_lifecycle_t lifecycle;

    ASSERT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
    ASSERT_EQ(lifecycle.begin_withdraw_for_victim(destination_ipv4).deferred_rules.size(), 1U);
    lifecycle.fail_announce(tcp_key);

    EXPECT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
}

TEST(gobgp_flowspec_lifecycle, failed_withdraw_keeps_fence_and_blocks_all_new_operations) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t tcp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::TCP, true, true);
    flow_spec_rule_t udp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::UDP, true, true);
    const auto tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_rule);
    const auto udp_key = make_gobgp_flowspec_lifecycle_key(udp_rule);
    gobgp_flowspec_lifecycle_t lifecycle;
    const std::string uuid("\\x01", 1);

    ASSERT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
    ASSERT_EQ(lifecycle.complete_announce(tcp_key, uuid), gobgp_flowspec_announce_completion_t::installed);
    ASSERT_EQ(lifecycle.begin_withdraw_for_victim(destination_ipv4).withdraw_requests.size(), 1U);
    ASSERT_EQ(lifecycle.complete_withdraw(tcp_key, uuid, false), gobgp_flowspec_withdraw_completion_t::retry_pending);

    EXPECT_FALSE(lifecycle.begin_announce(udp_key, udp_rule));
    EXPECT_FALSE(lifecycle.begin_refresh_announce(udp_key, udp_rule));
    EXPECT_FALSE(lifecycle.begin_refresh_capture(destination_ipv4));
}

TEST(gobgp_flowspec_lifecycle, unban_without_rules_does_not_leave_a_fence) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t tcp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::TCP, true, true);
    const auto tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_rule);
    gobgp_flowspec_lifecycle_t lifecycle;

    const auto withdraw_start = lifecycle.begin_withdraw_for_victim(destination_ipv4);
    EXPECT_TRUE(withdraw_start.withdraw_requests.empty());
    EXPECT_TRUE(withdraw_start.deferred_rules.empty());
    EXPECT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
}

TEST(gobgp_flowspec_lifecycle, multiple_rule_keys_for_one_victim_can_coexist) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t tcp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::TCP, true, true);
    flow_spec_rule_t udp_rule = make_gobgp_flowspec_lifecycle_rule(destination_ipv4, ip_protocol_t::UDP, true, true);
    gobgp_flowspec_rule_key_t tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_rule);
    gobgp_flowspec_rule_key_t udp_key = make_gobgp_flowspec_lifecycle_key(udp_rule);
    gobgp_flowspec_lifecycle_t lifecycle;

    ASSERT_TRUE(lifecycle.begin_announce(tcp_key, tcp_rule));
    ASSERT_TRUE(lifecycle.begin_announce(udp_key, udp_rule));
    ASSERT_EQ(lifecycle.complete_announce(tcp_key, std::string("\x01", 1)), gobgp_flowspec_announce_completion_t::installed);
    ASSERT_EQ(lifecycle.complete_announce(udp_key, std::string("\x02", 1)), gobgp_flowspec_announce_completion_t::installed);

    gobgp_flowspec_withdraw_start_result_t withdraw_start = lifecycle.begin_withdraw_for_victim(destination_ipv4);
    EXPECT_EQ(withdraw_start.withdraw_requests.size(), 2U);
}

TEST(gobgp_log_formatter, uuid_binary_hex_encoding) {
    const std::string uuid = std::string("\x00\x01\x7f\x80\xff", 5);
    EXPECT_EQ(format_gobgp_uuid_as_hex(uuid), "uuid=hex:00017f80ff");
}

TEST(gobgp_log_formatter, flowspec_tcp_without_destination_port) {
    uint32_t destination_ip = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ip));

    uint32_t redirect_next_hop = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_next_hop));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ip, 32));
    flow_spec_rule.add_protocol(ip_protocol_t::TCP);
    flow_spec_rule.add_ipv4_nexthop(redirect_next_hop);

    EXPECT_EQ(format_gobgp_flowspec_rule(flow_spec_rule),
              "dst=10.10.10.10/32 protocol=TCP redirect=192.168.100.50");
}

TEST(gobgp_log_formatter, flowspec_tcp_with_destination_port) {
    uint32_t destination_ip = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ip));

    uint32_t redirect_next_hop = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_next_hop));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ip, 32));
    flow_spec_rule.add_protocol(ip_protocol_t::TCP);
    flow_spec_rule.add_destination_port(443);
    flow_spec_rule.add_ipv4_nexthop(redirect_next_hop);

    EXPECT_EQ(format_gobgp_flowspec_rule(flow_spec_rule),
              "dst=10.10.10.10/32 protocol=TCP dst_port=443 redirect=192.168.100.50");
}

TEST(gobgp_log_formatter, flowspec_icmp_without_destination_port) {
    uint32_t destination_ip = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ip));

    uint32_t redirect_next_hop = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_next_hop));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ip, 32));
    flow_spec_rule.add_protocol(ip_protocol_t::ICMP);
    flow_spec_rule.add_ipv4_nexthop(redirect_next_hop);

    EXPECT_EQ(format_gobgp_flowspec_rule(flow_spec_rule),
              "dst=10.10.10.10/32 protocol=ICMP redirect=192.168.100.50");
}

TEST(gobgp_log_formatter, flowspec_destination_only) {
    uint32_t destination_ip = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ip));

    uint32_t redirect_next_hop = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_next_hop));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ip, 32));
    flow_spec_rule.add_ipv4_nexthop(redirect_next_hop);

    EXPECT_EQ(format_gobgp_flowspec_rule(flow_spec_rule),
              "dst=10.10.10.10/32 protocol=ANY redirect=192.168.100.50");
}

TEST(flowspec, gobgp_static_redirect_ipv4_wire_encoding) {
    uint32_t destination_ip = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ip));

    uint32_t redirect_next_hop = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_next_hop));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ip, 32));
    flow_spec_rule.add_protocol(ip_protocol_t::TCP);
    flow_spec_rule.add_destination_port(443);
    flow_spec_rule.add_ipv4_nexthop(redirect_next_hop);

    dynamic_binary_buffer_t encoded_nlri;
    ASSERT_TRUE(encode_bgp_flow_spec_elements_into_bgp_mp_attribute(flow_spec_rule, encoded_nlri, false));

    const std::array<uint8_t, 14> expected_nlri = { 0x0d, 0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x0a,
                                                     0x03, 0x81, 0x06, 0x05, 0x91, 0x01, 0xbb };
    ASSERT_EQ(encoded_nlri.get_used_size(), expected_nlri.size());
    EXPECT_EQ(memcmp(encoded_nlri.get_pointer(), expected_nlri.data(), expected_nlri.size()), 0);

    std::vector<dynamic_binary_buffer_t> attributes = build_attributes_for_gobgp_flowspec_announce(flow_spec_rule);
    ASSERT_EQ(attributes.size(), 3U);

    const std::array<uint8_t, 4> expected_origin = { 0x40, 0x01, 0x01, 0x02 };
    const std::array<uint8_t, 7> expected_next_hop_carrier = { 0x40, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const std::array<uint8_t, 11> expected_redirect_extended_community = {
        0xc0, 0x10, 0x08, 0x01, 0x0c, 0xc0, 0xa8, 0x64, 0x32, 0x00, 0x00
    };

    ASSERT_EQ(attributes[0].get_used_size(), expected_origin.size());
    EXPECT_EQ(memcmp(attributes[0].get_pointer(), expected_origin.data(), expected_origin.size()), 0);
    ASSERT_EQ(attributes[1].get_used_size(), expected_next_hop_carrier.size());
    EXPECT_EQ(memcmp(attributes[1].get_pointer(), expected_next_hop_carrier.data(), expected_next_hop_carrier.size()), 0);
    ASSERT_EQ(attributes[2].get_used_size(), expected_redirect_extended_community.size());
    EXPECT_EQ(memcmp(attributes[2].get_pointer(), expected_redirect_extended_community.data(),
                     expected_redirect_extended_community.size()),
              0);
}

TEST(flowspec, gobgp_static_redirect_ipv4_icmp_wire_encoding) {
    uint32_t destination_ip = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ip));

    uint32_t redirect_next_hop = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_next_hop));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ip, 32));
    flow_spec_rule.add_protocol(ip_protocol_t::ICMP);
    flow_spec_rule.add_ipv4_nexthop(redirect_next_hop);

    dynamic_binary_buffer_t encoded_nlri;
    ASSERT_TRUE(encode_bgp_flow_spec_elements_into_bgp_mp_attribute(flow_spec_rule, encoded_nlri, false));

    const std::array<uint8_t, 10> expected_nlri = { 0x09, 0x01, 0x20, 0x0a, 0x0a,
                                                     0x0a, 0x0a, 0x03, 0x81, 0x01 };
    ASSERT_EQ(encoded_nlri.get_used_size(), expected_nlri.size());
    EXPECT_EQ(memcmp(encoded_nlri.get_pointer(), expected_nlri.data(), expected_nlri.size()), 0);

    std::vector<dynamic_binary_buffer_t> attributes = build_attributes_for_gobgp_flowspec_announce(flow_spec_rule);
    ASSERT_EQ(attributes.size(), 3U);

    const std::array<uint8_t, 4> expected_origin = { 0x40, 0x01, 0x01, 0x02 };
    const std::array<uint8_t, 7> expected_next_hop_carrier = { 0x40, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const std::array<uint8_t, 11> expected_redirect_extended_community = {
        0xc0, 0x10, 0x08, 0x01, 0x0c, 0xc0, 0xa8, 0x64, 0x32, 0x00, 0x00
    };

    ASSERT_EQ(attributes[0].get_used_size(), expected_origin.size());
    EXPECT_EQ(memcmp(attributes[0].get_pointer(), expected_origin.data(), expected_origin.size()), 0);
    ASSERT_EQ(attributes[1].get_used_size(), expected_next_hop_carrier.size());
    EXPECT_EQ(memcmp(attributes[1].get_pointer(), expected_next_hop_carrier.data(), expected_next_hop_carrier.size()), 0);
    ASSERT_EQ(attributes[2].get_used_size(), expected_redirect_extended_community.size());
    EXPECT_EQ(memcmp(attributes[2].get_pointer(), expected_redirect_extended_community.data(),
                     expected_redirect_extended_community.size()),
              0);
}

TEST(flowspec, gobgp_static_redirect_ipv4_destination_only_wire_encoding) {
    uint32_t destination_ip = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ip));

    uint32_t redirect_next_hop = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_next_hop));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ip, 32));
    flow_spec_rule.add_ipv4_nexthop(redirect_next_hop);

    dynamic_binary_buffer_t encoded_nlri;
    ASSERT_TRUE(encode_bgp_flow_spec_elements_into_bgp_mp_attribute(flow_spec_rule, encoded_nlri, false));

    const std::array<uint8_t, 7> expected_nlri = { 0x06, 0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x0a };
    ASSERT_EQ(encoded_nlri.get_used_size(), expected_nlri.size());
    EXPECT_EQ(memcmp(encoded_nlri.get_pointer(), expected_nlri.data(), expected_nlri.size()), 0);

    std::vector<dynamic_binary_buffer_t> attributes = build_attributes_for_gobgp_flowspec_announce(flow_spec_rule);
    ASSERT_EQ(attributes.size(), 3U);

    const std::array<uint8_t, 4> expected_origin = { 0x40, 0x01, 0x01, 0x02 };
    const std::array<uint8_t, 7> expected_next_hop_carrier = { 0x40, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const std::array<uint8_t, 11> expected_redirect_extended_community = {
        0xc0, 0x10, 0x08, 0x01, 0x0c, 0xc0, 0xa8, 0x64, 0x32, 0x00, 0x00
    };

    ASSERT_EQ(attributes[0].get_used_size(), expected_origin.size());
    EXPECT_EQ(memcmp(attributes[0].get_pointer(), expected_origin.data(), expected_origin.size()), 0);
    ASSERT_EQ(attributes[1].get_used_size(), expected_next_hop_carrier.size());
    EXPECT_EQ(memcmp(attributes[1].get_pointer(), expected_next_hop_carrier.data(), expected_next_hop_carrier.size()), 0);
    ASSERT_EQ(attributes[2].get_used_size(), expected_redirect_extended_community.size());
    EXPECT_EQ(memcmp(attributes[2].get_pointer(), expected_redirect_extended_community.data(),
                     expected_redirect_extended_community.size()),
              0);
}

TEST(flowspec, gobgp_static_discard_ipv4_wire_encoding) {
    uint32_t destination_ip = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ip));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ip, 32));
    flow_spec_rule.add_protocol(ip_protocol_t::TCP);
    flow_spec_rule.add_destination_port(443);

    bgp_flow_spec_action_t discard_action;
    discard_action.set_type(bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD);
    flow_spec_rule.set_action(discard_action);

    EXPECT_TRUE(flow_spec_rule.ipv4_nexthops.empty());

    std::vector<dynamic_binary_buffer_t> attributes = build_attributes_for_gobgp_flowspec_announce(flow_spec_rule);
    ASSERT_EQ(attributes.size(), 3U);

    const std::array<uint8_t, 4> expected_origin = { 0x40, 0x01, 0x01, 0x02 };
    const std::array<uint8_t, 7> expected_next_hop_carrier = { 0x40, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const std::array<uint8_t, 11> expected_discard_extended_community = {
        0xc0, 0x10, 0x08, 0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    ASSERT_EQ(attributes[0].get_used_size(), expected_origin.size());
    EXPECT_EQ(memcmp(attributes[0].get_pointer(), expected_origin.data(), expected_origin.size()), 0);
    ASSERT_EQ(attributes[1].get_used_size(), expected_next_hop_carrier.size());
    EXPECT_EQ(memcmp(attributes[1].get_pointer(), expected_next_hop_carrier.data(), expected_next_hop_carrier.size()), 0);
    ASSERT_EQ(attributes[2].get_used_size(), expected_discard_extended_community.size());
    EXPECT_EQ(memcmp(attributes[2].get_pointer(), expected_discard_extended_community.data(),
                     expected_discard_extended_community.size()),
              0);
}

TEST(gobgp_flowspec_rule_builder, default_and_explicit_redirect_actions_are_backward_compatible) {
    uint32_t victim_ipv4 = 0;
    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    attack_details_t current_attack = make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::TCP));
    const flow_spec_rule_t default_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, current_attack, redirect_ipv4, 443);
    const flow_spec_rule_t explicit_rule = build_gobgp_flowspec_ipv4_rule(
        victim_ipv4, current_attack, redirect_ipv4, 443, bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT);

    EXPECT_EQ(default_rule.get_action().get_type(), bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT);
    EXPECT_EQ(explicit_rule.get_action().get_type(), bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT);
    EXPECT_EQ(default_rule.ipv4_nexthops, std::vector<uint32_t>{ redirect_ipv4 });
    EXPECT_EQ(explicit_rule.ipv4_nexthops, std::vector<uint32_t>{ redirect_ipv4 });
    EXPECT_EQ(build_attributes_for_gobgp_flowspec_announce(default_rule).size(), 3U);
    EXPECT_EQ(build_attributes_for_gobgp_flowspec_announce(explicit_rule).size(), 3U);
}

TEST(gobgp_flowspec_rule_builder, discard_rules_do_not_include_redirect_ipv4) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto discard = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD;
    const attack_details_t tcp_attack = make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::TCP));
    const attack_details_t udp_attack = make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::UDP));
    const attack_details_t icmp_attack = make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::ICMP));

    const flow_spec_rule_t tcp_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, tcp_attack, 0, 443, discard);
    const flow_spec_rule_t udp_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, udp_attack, 0, 53, discard);
    const flow_spec_rule_t icmp_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, icmp_attack, 0, std::nullopt, discard);

    EXPECT_EQ(tcp_rule.destination_ports, std::vector<uint16_t>{ 443 });
    EXPECT_EQ(udp_rule.destination_ports, std::vector<uint16_t>{ 53 });
    EXPECT_TRUE(icmp_rule.destination_ports.empty());

    for (const flow_spec_rule_t* rule : { &tcp_rule, &udp_rule, &icmp_rule }) {
        EXPECT_EQ(rule->get_action().get_type(), discard);
        EXPECT_TRUE(rule->ipv4_nexthops.empty());
        EXPECT_NE(format_gobgp_flowspec_rule(*rule).find("action=discard"), std::string::npos);
        EXPECT_EQ(format_gobgp_flowspec_rule(*rule).find("redirect="), std::string::npos);
        EXPECT_EQ(build_attributes_for_gobgp_flowspec_announce(*rule).size(), 3U);
    }
}

TEST(gobgp_flowspec_rule_builder, validates_configured_action_names) {
    bgp_flow_spec_action_types_t action_type;
    EXPECT_TRUE(parse_gobgp_flowspec_action("redirect", action_type));
    EXPECT_EQ(action_type, bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT);
    EXPECT_TRUE(parse_gobgp_flowspec_action("discard", action_type));
    EXPECT_EQ(action_type, bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD);
    EXPECT_FALSE(parse_gobgp_flowspec_action("drop", action_type));
    EXPECT_FALSE(parse_gobgp_flowspec_action("", action_type));
}

TEST(gobgp_flowspec_lifecycle, discard_protocol_only_escalation_preserves_action) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto discard = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD;
    const attack_details_t udp_attack = make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::UDP));
    const flow_spec_rule_t protocol_only_rule =
        build_gobgp_flowspec_ipv4_rule(victim_ipv4, udp_attack, 0, std::nullopt, discard);
    gobgp_flowspec_rule_key_t protocol_only_key;
    ASSERT_TRUE(build_gobgp_flowspec_rule_key(protocol_only_rule, protocol_only_key));

    gobgp_flowspec_lifecycle_t lifecycle;
    for (uint16_t port : { 8080, 4431, 53, 123 }) {
        const flow_spec_rule_t port_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, udp_attack, 0, port, discard);
        gobgp_flowspec_rule_key_t port_key;
        ASSERT_TRUE(build_gobgp_flowspec_rule_key(port_rule, port_key));
        ASSERT_TRUE(lifecycle.begin_announce(port_key, port_rule));
        ASSERT_EQ(lifecycle.complete_announce(port_key, std::string(1, static_cast<char>(port & 0xff))),
                  gobgp_flowspec_announce_completion_t::installed);
    }

    const flow_spec_rule_t fifth_port_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, udp_attack, 0, 773, discard);
    gobgp_flowspec_rule_key_t fifth_port_key;
    ASSERT_TRUE(build_gobgp_flowspec_rule_key(fifth_port_rule, fifth_port_key));

    const auto plan = lifecycle.begin_refresh_protocol_rules(
        { protocol_only_key, protocol_only_rule }, { { fifth_port_key, fifth_port_rule } }, 4);
    ASSERT_EQ(plan.action, gobgp_flowspec_refresh_protocol_action_t::escalate_protocol_only);
    ASSERT_EQ(plan.announce_requests.size(), 1U);
    EXPECT_EQ(plan.announce_requests.front().flow_spec_rule.get_action().get_type(), discard);
    EXPECT_TRUE(plan.announce_requests.front().flow_spec_rule.ipv4_nexthops.empty());
}

TEST(gobgp_flowspec_rule_builder, tcp_protocol) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    attack_details_t current_attack;
    current_attack.attack_protocol = static_cast<unsigned int>(ip_protocol_t::TCP);

    flow_spec_rule_t flow_spec_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, current_attack, redirect_ipv4);

    EXPECT_TRUE(flow_spec_rule.destination_subnet_ipv4_used);
    EXPECT_EQ(flow_spec_rule.destination_subnet_ipv4, subnet_cidr_mask_t(victim_ipv4, 32));
    EXPECT_EQ(flow_spec_rule.protocols, std::vector<ip_protocol_t>{ ip_protocol_t::TCP });
    EXPECT_TRUE(flow_spec_rule.destination_ports.empty());
    EXPECT_TRUE(flow_spec_rule.tcp_flags.empty());
    EXPECT_EQ(flow_spec_rule.ipv4_nexthops, std::vector<uint32_t>{ redirect_ipv4 });

    dynamic_binary_buffer_t encoded_nlri;
    ASSERT_TRUE(encode_bgp_flow_spec_elements_into_bgp_mp_attribute(flow_spec_rule, encoded_nlri, false));
    const std::array<uint8_t, 10> expected_nlri = { 0x09, 0x01, 0x20, 0x0a, 0x0a,
                                                     0x0a, 0x0a, 0x03, 0x81, 0x06 };
    ASSERT_EQ(encoded_nlri.get_used_size(), expected_nlri.size());
    EXPECT_EQ(memcmp(encoded_nlri.get_pointer(), expected_nlri.data(), expected_nlri.size()), 0);
}

TEST(gobgp_flowspec_rule_builder, udp_protocol) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    attack_details_t current_attack;
    current_attack.attack_protocol = static_cast<unsigned int>(ip_protocol_t::UDP);

    flow_spec_rule_t flow_spec_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, current_attack, redirect_ipv4);

    EXPECT_TRUE(flow_spec_rule.destination_subnet_ipv4_used);
    EXPECT_EQ(flow_spec_rule.destination_subnet_ipv4, subnet_cidr_mask_t(victim_ipv4, 32));
    EXPECT_EQ(flow_spec_rule.protocols, std::vector<ip_protocol_t>{ ip_protocol_t::UDP });
    EXPECT_TRUE(flow_spec_rule.destination_ports.empty());
    EXPECT_TRUE(flow_spec_rule.tcp_flags.empty());
    EXPECT_EQ(flow_spec_rule.ipv4_nexthops, std::vector<uint32_t>{ redirect_ipv4 });

    dynamic_binary_buffer_t encoded_nlri;
    ASSERT_TRUE(encode_bgp_flow_spec_elements_into_bgp_mp_attribute(flow_spec_rule, encoded_nlri, false));
    const std::array<uint8_t, 10> expected_nlri = { 0x09, 0x01, 0x20, 0x0a, 0x0a,
                                                     0x0a, 0x0a, 0x03, 0x81, 0x11 };
    ASSERT_EQ(encoded_nlri.get_used_size(), expected_nlri.size());
    EXPECT_EQ(memcmp(encoded_nlri.get_pointer(), expected_nlri.data(), expected_nlri.size()), 0);
}

TEST(gobgp_flowspec_rule_builder, icmp_protocol) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    attack_details_t current_attack;
    current_attack.attack_protocol = static_cast<unsigned int>(ip_protocol_t::ICMP);

    flow_spec_rule_t flow_spec_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, current_attack, redirect_ipv4);

    EXPECT_TRUE(flow_spec_rule.destination_subnet_ipv4_used);
    EXPECT_EQ(flow_spec_rule.destination_subnet_ipv4, subnet_cidr_mask_t(victim_ipv4, 32));
    EXPECT_EQ(flow_spec_rule.protocols, std::vector<ip_protocol_t>{ ip_protocol_t::ICMP });
    EXPECT_TRUE(flow_spec_rule.destination_ports.empty());
    EXPECT_TRUE(flow_spec_rule.tcp_flags.empty());
    EXPECT_EQ(flow_spec_rule.ipv4_nexthops, std::vector<uint32_t>{ redirect_ipv4 });

    dynamic_binary_buffer_t encoded_nlri;
    ASSERT_TRUE(encode_bgp_flow_spec_elements_into_bgp_mp_attribute(flow_spec_rule, encoded_nlri, false));
    const std::array<uint8_t, 10> expected_nlri = { 0x09, 0x01, 0x20, 0x0a, 0x0a,
                                                     0x0a, 0x0a, 0x03, 0x81, 0x01 };
    ASSERT_EQ(encoded_nlri.get_used_size(), expected_nlri.size());
    EXPECT_EQ(memcmp(encoded_nlri.get_pointer(), expected_nlri.data(), expected_nlri.size()), 0);
}

TEST(gobgp_flowspec_rule_builder, unsupported_protocol) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    attack_details_t current_attack;
    current_attack.attack_protocol = 0;

    flow_spec_rule_t flow_spec_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, current_attack, redirect_ipv4);

    EXPECT_TRUE(flow_spec_rule.destination_subnet_ipv4_used);
    EXPECT_EQ(flow_spec_rule.destination_subnet_ipv4, subnet_cidr_mask_t(victim_ipv4, 32));
    EXPECT_TRUE(flow_spec_rule.protocols.empty());
    EXPECT_TRUE(flow_spec_rule.destination_ports.empty());
    EXPECT_TRUE(flow_spec_rule.tcp_flags.empty());
    EXPECT_EQ(flow_spec_rule.ipv4_nexthops, std::vector<uint32_t>{ redirect_ipv4 });

    dynamic_binary_buffer_t encoded_nlri;
    ASSERT_TRUE(encode_bgp_flow_spec_elements_into_bgp_mp_attribute(flow_spec_rule, encoded_nlri, false));
    const std::array<uint8_t, 7> expected_nlri = { 0x06, 0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x0a };
    ASSERT_EQ(encoded_nlri.get_used_size(), expected_nlri.size());
    EXPECT_EQ(memcmp(encoded_nlri.get_pointer(), expected_nlri.data(), expected_nlri.size()), 0);
}

TEST(gobgp_flowspec_rule_builder, tcp_selected_destination_port) {
    uint32_t victim_ipv4 = 0;
    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    attack_details_t current_attack = make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::TCP));
    flow_spec_rule_t flow_spec_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, current_attack, redirect_ipv4, 443);

    EXPECT_EQ(flow_spec_rule.protocols, std::vector<ip_protocol_t>{ ip_protocol_t::TCP });
    EXPECT_EQ(flow_spec_rule.destination_ports, std::vector<uint16_t>{ 443 });
}

TEST(gobgp_flowspec_rule_builder, udp_selected_destination_port) {
    uint32_t victim_ipv4 = 0;
    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    attack_details_t current_attack = make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::UDP));
    flow_spec_rule_t flow_spec_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, current_attack, redirect_ipv4, 53);

    EXPECT_EQ(flow_spec_rule.protocols, std::vector<ip_protocol_t>{ ip_protocol_t::UDP });
    EXPECT_EQ(flow_spec_rule.destination_ports, std::vector<uint16_t>{ 53 });
}

TEST(gobgp_flowspec_rule_builder, icmp_ignores_selected_destination_port) {
    uint32_t victim_ipv4 = 0;
    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    attack_details_t current_attack = make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::ICMP));
    flow_spec_rule_t flow_spec_rule = build_gobgp_flowspec_ipv4_rule(victim_ipv4, current_attack, redirect_ipv4, 443);

    EXPECT_EQ(flow_spec_rule.protocols, std::vector<ip_protocol_t>{ ip_protocol_t::ICMP });
    EXPECT_TRUE(flow_spec_rule.destination_ports.empty());
}

TEST(gobgp_flowspec_port_classifier, tcp_dominant_port_is_selected) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    const unsigned int tcp = static_cast<unsigned int>(ip_protocol_t::TCP);
    auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 443, 9),
                                                       make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 80) });
    auto result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(tcp), samples,
                                                            make_gobgp_flowspec_port_config());
    EXPECT_EQ(result.selected_destination_port, std::optional<uint16_t>(443));
    EXPECT_EQ(result.dominance_percent, 90);
    EXPECT_EQ(result.qualifying_sample_count, 2U);
    EXPECT_EQ(result.reason, gobgp_flowspec_port_classifier_reason_t::selected);
}

TEST(gobgp_flowspec_port_classifier, udp_dominant_port_is_selected) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    const unsigned int udp = static_cast<unsigned int>(ip_protocol_t::UDP);
    auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, udp, 53, 8),
                                                       make_gobgp_flowspec_port_sample(victim_ipv4, udp, 123, 2) });
    auto result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(udp), samples,
                                                            make_gobgp_flowspec_port_config());
    EXPECT_EQ(result.selected_destination_port, std::optional<uint16_t>(53));
}

TEST(gobgp_flowspec_port_classifier, multiple_udp_ports_below_dominance_are_not_selected) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    const unsigned int udp = static_cast<unsigned int>(ip_protocol_t::UDP);
    auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, udp, 53, 6),
                                                       make_gobgp_flowspec_port_sample(victim_ipv4, udp, 123, 4) });
    auto result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(udp), samples,
                                                            make_gobgp_flowspec_port_config());
    EXPECT_FALSE(result.selected_destination_port.has_value());
    EXPECT_EQ(result.reason, gobgp_flowspec_port_classifier_reason_t::below_dominance);
}

TEST(gobgp_flowspec_port_classifier, insufficient_samples_are_not_selected) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    const unsigned int tcp = static_cast<unsigned int>(ip_protocol_t::TCP);
    auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 443, 100) });
    auto result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(tcp), samples,
                                                            make_gobgp_flowspec_port_config(2));
    EXPECT_FALSE(result.selected_destination_port.has_value());
    EXPECT_EQ(result.reason, gobgp_flowspec_port_classifier_reason_t::insufficient_samples);
}

TEST(gobgp_flowspec_port_classifier, icmp_and_unknown_protocols_are_not_classified) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 1, 443, 100) });
    auto icmp_result = classify_gobgp_flowspec_destination_port(
        victim_ipv4, make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::ICMP)), samples,
        make_gobgp_flowspec_port_config(1));
    auto unknown_result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(99),
                                                                    samples, make_gobgp_flowspec_port_config(1));
    EXPECT_FALSE(icmp_result.selected_destination_port.has_value());
    EXPECT_FALSE(unknown_result.selected_destination_port.has_value());
    EXPECT_EQ(icmp_result.reason, gobgp_flowspec_port_classifier_reason_t::unsupported_protocol);
    EXPECT_EQ(unknown_result.reason, gobgp_flowspec_port_classifier_reason_t::unsupported_protocol);
}

TEST(gobgp_flowspec_port_classifier, zero_port_non_initial_fragments_and_unrelated_packets_are_ignored) {
    uint32_t victim_ipv4 = 0;
    uint32_t another_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.11", another_ipv4));
    const unsigned int tcp = static_cast<unsigned int>(ip_protocol_t::TCP);
    simple_packet_t non_initial_fragment = make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 80, 100);
    non_initial_fragment.ip_fragmented = true;
    non_initial_fragment.ip_fragment_offset = 8;
    auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 0, 100),
                                                       non_initial_fragment,
                                                       make_gobgp_flowspec_port_sample(another_ipv4, tcp, 22, 100),
                                                       make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 443, 1) });
    auto result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(tcp), samples,
                                                            make_gobgp_flowspec_port_config(1));
    EXPECT_EQ(result.selected_destination_port, std::optional<uint16_t>(443));
    EXPECT_EQ(result.qualifying_sample_count, 1U);
}

TEST(gobgp_flowspec_port_classifier, unrelated_protocol_is_ignored) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    const unsigned int tcp = static_cast<unsigned int>(ip_protocol_t::TCP);
    const unsigned int udp = static_cast<unsigned int>(ip_protocol_t::UDP);
    auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, udp, 53, 100),
                                                       make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 443, 1) });
    auto result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(tcp), samples,
                                                            make_gobgp_flowspec_port_config(1));
    EXPECT_EQ(result.selected_destination_port, std::optional<uint16_t>(443));
    EXPECT_EQ(result.qualifying_sample_count, 1U);
}

TEST(gobgp_flowspec_port_classifier, sampling_weight_can_change_the_winner) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    const unsigned int tcp = static_cast<unsigned int>(ip_protocol_t::TCP);
    auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 443, 100, 1),
                                                       make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 53, 2, 100) });
    auto result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(tcp), samples,
                                                            make_gobgp_flowspec_port_config(2, 60));
    EXPECT_EQ(result.selected_destination_port, std::optional<uint16_t>(53));
    EXPECT_EQ(result.dominant_weight, 200U);
}

TEST(gobgp_flowspec_port_classifier, exact_dominance_threshold_is_selected_and_one_below_is_not) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    const unsigned int udp = static_cast<unsigned int>(ip_protocol_t::UDP);
    auto exact_samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, udp, 53, 70),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, udp, 123, 30) });
    auto below_samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, udp, 53, 69),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, udp, 123, 31) });
    auto exact_result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(udp),
                                                                  exact_samples, make_gobgp_flowspec_port_config());
    auto below_result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(udp),
                                                                  below_samples, make_gobgp_flowspec_port_config());
    EXPECT_EQ(exact_result.selected_destination_port, std::optional<uint16_t>(53));
    EXPECT_FALSE(below_result.selected_destination_port.has_value());
    EXPECT_EQ(below_result.reason, gobgp_flowspec_port_classifier_reason_t::below_dominance);
}

TEST(gobgp_flowspec_port_classifier, outgoing_attacks_are_not_classified) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    const unsigned int tcp = static_cast<unsigned int>(ip_protocol_t::TCP);
    auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, tcp, 443, 100) });
    auto result = classify_gobgp_flowspec_destination_port(victim_ipv4, make_gobgp_flowspec_port_attack(tcp, OUTGOING),
                                                            samples, make_gobgp_flowspec_port_config(1));
    EXPECT_FALSE(result.selected_destination_port.has_value());
    EXPECT_EQ(result.reason, gobgp_flowspec_port_classifier_reason_t::not_incoming);
}

TEST(gobgp_flowspec_notification_formatter, add_success_report_uses_exact_rule_uuid_and_classifier_result) {
    uint32_t destination_ipv4 = 0;
    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ipv4, 32));
    flow_spec_rule.add_protocol(ip_protocol_t::UDP);
    flow_spec_rule.add_destination_port(53);
    flow_spec_rule.add_ipv4_nexthop(redirect_ipv4);

    gobgp_flowspec_port_classifier_result_t classifier_result;
    classifier_result.dominant_port = 53;
    classifier_result.selected_destination_port = 53;
    classifier_result.dominance_percent = 94;
    classifier_result.qualifying_sample_count = 37;
    classifier_result.reason = gobgp_flowspec_port_classifier_reason_t::selected;

    EXPECT_EQ(format_gobgp_flowspec_add_success_notification(flow_spec_rule, std::string("\x00\xff", 2), classifier_result),
              "FlowSpec ADD success (GoBGP)\n"
              "Rule: dst=10.10.10.10/32 protocol=UDP dst_port=53 redirect=192.168.100.50\n"
              "UUID: uuid=hex:00ff\n"
              "Dominant port: 53\n"
              "Selected port: 53\n"
              "Dominance: 94%\n"
              "Qualifying samples: 37\n"
              "Classifier reason: selected\n");
}

TEST(gobgp_flowspec_notification_formatter, delete_success_report_uses_lifecycle_rule_without_classifier_result) {
    uint32_t destination_ipv4 = 0;
    uint32_t redirect_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("192.168.100.50", redirect_ipv4));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ipv4, 32));
    flow_spec_rule.add_protocol(ip_protocol_t::ICMP);
    flow_spec_rule.add_ipv4_nexthop(redirect_ipv4);

    EXPECT_EQ(format_gobgp_flowspec_delete_success_notification(flow_spec_rule, std::string("\x01\x02", 2)),
              "FlowSpec DELETE success (GoBGP)\n"
              "Rule: dst=10.10.10.10/32 protocol=ICMP redirect=192.168.100.50\n"
              "UUID: uuid=hex:0102\n");
}

TEST(gobgp_flowspec_notification_formatter, discard_reports_exact_rule_action) {
    uint32_t destination_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", destination_ipv4));

    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(destination_ipv4, 32));
    flow_spec_rule.add_protocol(ip_protocol_t::UDP);
    flow_spec_rule.add_destination_port(53);
    bgp_flow_spec_action_t discard_action;
    discard_action.set_type(bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD);
    flow_spec_rule.set_action(discard_action);

    EXPECT_EQ(format_gobgp_flowspec_add_success_notification(flow_spec_rule, std::string("\x01\x02", 2), std::nullopt),
              "FlowSpec ADD success (GoBGP)\n"
              "Rule: dst=10.10.10.10/32 protocol=UDP dst_port=53 action=discard\n"
              "UUID: uuid=hex:0102\n");
    EXPECT_EQ(format_gobgp_flowspec_delete_success_notification(flow_spec_rule, std::string("\x01\x02", 2)),
              "FlowSpec DELETE success (GoBGP)\n"
              "Rule: dst=10.10.10.10/32 protocol=UDP dst_port=53 action=discard\n"
              "UUID: uuid=hex:0102\n");
}

TEST(gobgp_flowspec_protocol_admission, hostgroup_pps_thresholds_admit_only_active_protocols) {
    const auto snapshot = make_gobgp_flowspec_admission_snapshot(180000, 120000, 500);
    const std::set<ip_protocol_t> active_protocols = get_gobgp_flowspec_active_protocols(snapshot);

    EXPECT_EQ(active_protocols.size(), 2U);
    EXPECT_TRUE(active_protocols.count(ip_protocol_t::TCP));
    EXPECT_TRUE(active_protocols.count(ip_protocol_t::UDP));
    EXPECT_FALSE(active_protocols.count(ip_protocol_t::ICMP));
}

TEST(gobgp_flowspec_protocol_admission, strict_threshold_comparison_and_disabled_protocol_are_respected) {
    const auto at_threshold = make_gobgp_flowspec_admission_snapshot(50000, 50000, 30000);
    EXPECT_TRUE(get_gobgp_flowspec_active_protocols(at_threshold).empty());

    const auto udp_below_threshold = make_gobgp_flowspec_admission_snapshot(300000, 3000, 0);
    const std::set<ip_protocol_t> active_protocols = get_gobgp_flowspec_active_protocols(udp_below_threshold);
    EXPECT_TRUE(active_protocols.count(ip_protocol_t::TCP));
    EXPECT_FALSE(active_protocols.count(ip_protocol_t::UDP));
}

TEST(gobgp_flowspec_refresh_classifier, tcp_dominant_port_becomes_candidate) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 6, 443, 96),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 6, 80, 4) });
    const auto candidates = build_gobgp_flowspec_refresh_candidates(
        victim_ipv4, { ip_protocol_t::TCP }, samples, make_gobgp_flowspec_port_config());

    ASSERT_EQ(candidates.size(), 1U);
    EXPECT_EQ(candidates.front().protocol, ip_protocol_t::TCP);
    ASSERT_TRUE(candidates.front().destination_port.has_value());
    EXPECT_EQ(*candidates.front().destination_port, 443);
}

TEST(gobgp_flowspec_refresh_classifier, tcp_and_udp_same_port_are_distinct_candidates) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 6, 443, 96),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 6, 80, 4),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 17, 443, 98),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 17, 53, 2) });
    const auto candidates = build_gobgp_flowspec_refresh_candidates(
        victim_ipv4, { ip_protocol_t::TCP, ip_protocol_t::UDP }, samples, make_gobgp_flowspec_port_config());

    const auto* tcp_candidate = find_gobgp_flowspec_refresh_candidate(candidates, ip_protocol_t::TCP);
    const auto* udp_candidate = find_gobgp_flowspec_refresh_candidate(candidates, ip_protocol_t::UDP);
    ASSERT_NE(tcp_candidate, nullptr);
    ASSERT_NE(udp_candidate, nullptr);
    EXPECT_EQ(*tcp_candidate->destination_port, 443);
    EXPECT_EQ(*udp_candidate->destination_port, 443);
}

TEST(gobgp_flowspec_refresh_classifier, inactive_udp_is_not_classified_even_with_dominant_samples) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto admission_snapshot = make_gobgp_flowspec_admission_snapshot(300000, 3000, 0);
    const auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 6, 443, 100),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 6, 443, 100),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 17, 443, 100) });
    const auto candidates = build_gobgp_flowspec_refresh_candidates(
        victim_ipv4, get_gobgp_flowspec_active_protocols(admission_snapshot), samples, make_gobgp_flowspec_port_config());

    ASSERT_EQ(candidates.size(), 1U);
    EXPECT_EQ(candidates.front().protocol, ip_protocol_t::TCP);
    EXPECT_EQ(*candidates.front().destination_port, 443);
}

TEST(gobgp_flowspec_refresh_classifier, tcp_udp_and_icmp_candidates_follow_refresh_v1_rules) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 6, 443, 90),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 6, 80, 10),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 17, 53, 90),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 17, 443, 10) });
    const auto candidates = build_gobgp_flowspec_refresh_candidates(
        victim_ipv4, { ip_protocol_t::TCP, ip_protocol_t::UDP, ip_protocol_t::ICMP }, samples,
        make_gobgp_flowspec_port_config());

    const auto* tcp_candidate = find_gobgp_flowspec_refresh_candidate(candidates, ip_protocol_t::TCP);
    const auto* udp_candidate = find_gobgp_flowspec_refresh_candidate(candidates, ip_protocol_t::UDP);
    const auto* icmp_candidate = find_gobgp_flowspec_refresh_candidate(candidates, ip_protocol_t::ICMP);
    ASSERT_NE(tcp_candidate, nullptr);
    ASSERT_NE(udp_candidate, nullptr);
    ASSERT_NE(icmp_candidate, nullptr);
    EXPECT_EQ(*tcp_candidate->destination_port, 443);
    EXPECT_EQ(*udp_candidate->destination_port, 53);
    EXPECT_FALSE(icmp_candidate->destination_port.has_value());
}

TEST(gobgp_flowspec_refresh_classifier, tcp_without_reliable_port_does_not_produce_candidate) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 6, 443, 40),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 6, 80, 30),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 6, 22, 30) });
    const auto candidates = build_gobgp_flowspec_refresh_candidates(
        victim_ipv4, { ip_protocol_t::TCP }, samples, make_gobgp_flowspec_port_config());
    EXPECT_TRUE(candidates.empty());
}

TEST(gobgp_flowspec_refresh_classifier, significant_ports_include_multiple_ports_at_or_above_refresh_share) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 17, 8080, 55),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 17, 4431, 42),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 17, 53, 3) });
    const auto results = classify_gobgp_flowspec_refresh_protocols(
        victim_ipv4, { ip_protocol_t::UDP }, samples, make_gobgp_flowspec_port_config(2), 20);
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results.front().significant_ports.size(), 2U);
    EXPECT_EQ(*results.front().significant_ports[0].destination_port, 4431);
    EXPECT_EQ(*results.front().significant_ports[1].destination_port, 8080);
}

TEST(gobgp_flowspec_port_classifier, initial_udp_eighty_percent_dominance_semantics_are_unchanged) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 17, 8080, 80),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 17, 4431, 20) });
    const auto result = classify_gobgp_flowspec_destination_port(
        victim_ipv4, make_gobgp_flowspec_port_attack(static_cast<unsigned int>(ip_protocol_t::UDP)), samples,
        make_gobgp_flowspec_port_config(2, 70));
    EXPECT_EQ(result.selected_destination_port, std::optional<uint16_t>(8080));
}

TEST(gobgp_flowspec_refresh_classifier, fifty_fifty_ports_and_exact_twenty_percent_are_significant) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto equal_samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 17, 8080, 50),
                                                                   make_gobgp_flowspec_port_sample(victim_ipv4, 17, 4431, 50) });
    const auto equal_results = classify_gobgp_flowspec_refresh_protocols(
        victim_ipv4, { ip_protocol_t::UDP }, equal_samples, make_gobgp_flowspec_port_config(2), 20);
    ASSERT_EQ(equal_results.front().significant_ports.size(), 2U);

    const auto exact_samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 17, 53, 20),
                                                                   make_gobgp_flowspec_port_sample(victim_ipv4, 17, 8080, 80) });
    const auto exact_results = classify_gobgp_flowspec_refresh_protocols(
        victim_ipv4, { ip_protocol_t::UDP }, exact_samples, make_gobgp_flowspec_port_config(2), 20);
    ASSERT_EQ(exact_results.front().significant_ports.size(), 2U);
}

TEST(gobgp_flowspec_refresh_classifier, below_share_insufficient_and_empty_samples_do_not_produce_ports) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto below_samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 17, 8080, 81),
                                                                   make_gobgp_flowspec_port_sample(victim_ipv4, 17, 4431, 19) });
    const auto below_results = classify_gobgp_flowspec_refresh_protocols(
        victim_ipv4, { ip_protocol_t::UDP }, below_samples, make_gobgp_flowspec_port_config(2), 20);
    ASSERT_EQ(below_results.front().significant_ports.size(), 1U);
    EXPECT_EQ(*below_results.front().significant_ports.front().destination_port, 8080);

    const auto insufficient_results = classify_gobgp_flowspec_refresh_protocols(
        victim_ipv4, { ip_protocol_t::UDP }, below_samples, make_gobgp_flowspec_port_config(3), 20);
    EXPECT_TRUE(insufficient_results.front().significant_ports.empty());
    EXPECT_EQ(insufficient_results.front().reason, gobgp_flowspec_port_classifier_reason_t::insufficient_samples);

    const auto empty_samples = make_gobgp_flowspec_port_samples({});
    const auto empty_results = classify_gobgp_flowspec_refresh_protocols(
        victim_ipv4, { ip_protocol_t::UDP }, empty_samples, make_gobgp_flowspec_port_config(1), 20);
    EXPECT_TRUE(empty_results.front().significant_ports.empty());
    EXPECT_EQ(empty_results.front().reason, gobgp_flowspec_port_classifier_reason_t::no_qualifying_samples);
}

TEST(gobgp_flowspec_refresh_classifier, tcp_udp_and_icmp_refresh_results_are_independent) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    const auto samples = make_gobgp_flowspec_port_samples({ make_gobgp_flowspec_port_sample(victim_ipv4, 6, 443, 100),
                                                             make_gobgp_flowspec_port_sample(victim_ipv4, 17, 53, 100) });
    const auto results = classify_gobgp_flowspec_refresh_protocols(
        victim_ipv4, { ip_protocol_t::TCP, ip_protocol_t::UDP, ip_protocol_t::ICMP }, samples,
        make_gobgp_flowspec_port_config(1), 20);
    const auto* tcp = find_gobgp_flowspec_refresh_protocol_result(results, ip_protocol_t::TCP);
    const auto* udp = find_gobgp_flowspec_refresh_protocol_result(results, ip_protocol_t::UDP);
    const auto* icmp = find_gobgp_flowspec_refresh_protocol_result(results, ip_protocol_t::ICMP);
    ASSERT_NE(tcp, nullptr);
    ASSERT_NE(udp, nullptr);
    ASSERT_NE(icmp, nullptr);
    EXPECT_EQ(*tcp->significant_ports.front().destination_port, 443);
    EXPECT_EQ(*udp->significant_ports.front().destination_port, 53);
    EXPECT_TRUE(icmp->significant_ports.empty());
}

TEST(gobgp_flowspec_lifecycle, refresh_port_plan_deduplicates_and_adds_multiple_ports_below_limit) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    gobgp_flowspec_lifecycle_t lifecycle;
    const auto protocol_only = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP);
    const auto existing = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, 8080);
    const auto new_4431 = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, 4431);
    const auto new_53 = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, 53);

    ASSERT_TRUE(lifecycle.begin_announce(existing.rule_key, existing.flow_spec_rule));
    ASSERT_EQ(lifecycle.complete_announce(existing.rule_key, std::string("\x01", 1)), gobgp_flowspec_announce_completion_t::installed);
    const auto plan = lifecycle.begin_refresh_protocol_rules(protocol_only, { existing, new_4431, new_53 }, 4);

    EXPECT_EQ(plan.action, gobgp_flowspec_refresh_protocol_action_t::add_port_rules);
    EXPECT_EQ(plan.existing_port_rule_count, 1U);
    EXPECT_EQ(plan.new_port_rule_count, 2U);
    EXPECT_EQ(plan.announce_requests.size(), 2U);
}

TEST(gobgp_flowspec_lifecycle, fifth_port_and_multiple_new_ports_escalate_to_protocol_only) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    gobgp_flowspec_lifecycle_t lifecycle;
    const auto protocol_only = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP);
    std::vector<gobgp_flowspec_announce_request_t> existing;

    for (uint16_t port : { 8080, 4431, 53, 123 }) {
        const auto request = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, port);
        ASSERT_TRUE(lifecycle.begin_announce(request.rule_key, request.flow_spec_rule));
        ASSERT_EQ(lifecycle.complete_announce(request.rule_key, std::string(1, static_cast<char>(port & 0xff))),
                  gobgp_flowspec_announce_completion_t::installed);
        existing.push_back(request);
    }

    const auto fifth = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, 773);
    const auto plan = lifecycle.begin_refresh_protocol_rules(protocol_only, { fifth }, 4);
    EXPECT_EQ(plan.action, gobgp_flowspec_refresh_protocol_action_t::escalate_protocol_only);
    ASSERT_EQ(plan.announce_requests.size(), 1U);
    EXPECT_EQ(plan.announce_requests.front().rule_key.destination_port_present, false);

    ASSERT_EQ(lifecycle.complete_announce(protocol_only.rule_key, std::string("\x55", 1)),
              gobgp_flowspec_announce_completion_t::installed);
    const auto cleanup_requests = lifecycle.begin_protocol_only_escalation_cleanup(protocol_only.rule_key);
    EXPECT_EQ(cleanup_requests.size(), 4U);
    EXPECT_FALSE(lifecycle.get_state(fifth.rule_key).has_value());
    ASSERT_EQ(lifecycle.complete_withdraw(cleanup_requests.front().rule_key, cleanup_requests.front().add_path_uuid, false),
              gobgp_flowspec_withdraw_completion_t::retry_pending);
    const auto failed_cleanup_state = lifecycle.get_state(cleanup_requests.front().rule_key);
    ASSERT_TRUE(failed_cleanup_state.has_value());
    EXPECT_EQ(failed_cleanup_state->state, gobgp_flowspec_rule_state_type_t::withdraw_requested);
    EXPECT_EQ(failed_cleanup_state->add_path_uuid, cleanup_requests.front().add_path_uuid);
    EXPECT_EQ(lifecycle.get_state(protocol_only.rule_key)->state, gobgp_flowspec_rule_state_type_t::installed);

    gobgp_flowspec_lifecycle_t three_ports_lifecycle;
    for (uint16_t port : { 8080, 4431, 53 }) {
        const auto request = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, port);
        ASSERT_TRUE(three_ports_lifecycle.begin_announce(request.rule_key, request.flow_spec_rule));
        ASSERT_EQ(three_ports_lifecycle.complete_announce(request.rule_key, std::string(1, static_cast<char>(port & 0xff))),
                  gobgp_flowspec_announce_completion_t::installed);
    }
    const auto new_123 = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, 123);
    const auto new_773 = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, 773);
    const auto simultaneous_plan = three_ports_lifecycle.begin_refresh_protocol_rules(protocol_only, { new_123, new_773 }, 4);
    EXPECT_EQ(simultaneous_plan.action, gobgp_flowspec_refresh_protocol_action_t::escalate_protocol_only);
    EXPECT_FALSE(three_ports_lifecycle.get_state(new_123.rule_key).has_value());
    EXPECT_FALSE(three_ports_lifecycle.get_state(new_773.rule_key).has_value());
}

TEST(gobgp_flowspec_lifecycle, protocol_only_coverage_preserves_ports_on_add_failure_and_is_protocol_specific) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    gobgp_flowspec_lifecycle_t lifecycle;
    const auto udp_protocol_only = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP);
    const auto udp_port = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, 8080);
    const auto udp_other_port = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::UDP, 53);
    const auto tcp_port = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::TCP, 443);

    ASSERT_TRUE(lifecycle.begin_announce(udp_port.rule_key, udp_port.flow_spec_rule));
    ASSERT_EQ(lifecycle.complete_announce(udp_port.rule_key, std::string("\x01", 1)), gobgp_flowspec_announce_completion_t::installed);
    const auto escalation = lifecycle.begin_refresh_protocol_rules(udp_protocol_only, { udp_other_port }, 1);
    EXPECT_EQ(escalation.action, gobgp_flowspec_refresh_protocol_action_t::escalate_protocol_only);
    lifecycle.fail_announce(udp_protocol_only.rule_key);
    EXPECT_TRUE(lifecycle.get_state(udp_port.rule_key).has_value());

    ASSERT_TRUE(lifecycle.begin_announce(udp_protocol_only.rule_key, udp_protocol_only.flow_spec_rule));
    ASSERT_EQ(lifecycle.complete_announce(udp_protocol_only.rule_key, std::string("\x02", 1)),
              gobgp_flowspec_announce_completion_t::installed);
    const auto covered = lifecycle.begin_refresh_protocol_rules(udp_protocol_only, { udp_port }, 4);
    EXPECT_EQ(covered.action, gobgp_flowspec_refresh_protocol_action_t::protocol_only_covers);

    gobgp_flowspec_lifecycle_t announcing_lifecycle;
    ASSERT_TRUE(announcing_lifecycle.begin_announce(udp_protocol_only.rule_key, udp_protocol_only.flow_spec_rule));
    const auto announcing_covered = announcing_lifecycle.begin_refresh_protocol_rules(udp_protocol_only, { udp_other_port }, 4);
    EXPECT_EQ(announcing_covered.action, gobgp_flowspec_refresh_protocol_action_t::protocol_only_covers);

    const auto tcp_protocol_only = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::TCP);
    const auto tcp_plan = lifecycle.begin_refresh_protocol_rules(tcp_protocol_only, { tcp_port }, 4);
    EXPECT_EQ(tcp_plan.action, gobgp_flowspec_refresh_protocol_action_t::add_port_rules);
}

TEST(gobgp_flowspec_lifecycle, announcing_port_rules_count_toward_refresh_limit) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    gobgp_flowspec_lifecycle_t lifecycle;
    const auto protocol_only = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::TCP);

    for (uint16_t port : { 443, 80, 22 }) {
        const auto request = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::TCP, port);
        ASSERT_TRUE(lifecycle.begin_announce(request.rule_key, request.flow_spec_rule));
        ASSERT_EQ(lifecycle.complete_announce(request.rule_key, std::string(1, static_cast<char>(port & 0xff))),
                  gobgp_flowspec_announce_completion_t::installed);
    }

    const auto announcing_port = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::TCP, 25);
    ASSERT_TRUE(lifecycle.begin_refresh_announce(announcing_port.rule_key, announcing_port.flow_spec_rule));
    const auto fifth_port = make_gobgp_flowspec_refresh_announce_request(victim_ipv4, ip_protocol_t::TCP, 587);
    const auto plan = lifecycle.begin_refresh_protocol_rules(protocol_only, { fifth_port }, 4);
    EXPECT_EQ(plan.action, gobgp_flowspec_refresh_protocol_action_t::escalate_protocol_only);
    EXPECT_FALSE(lifecycle.get_state(fifth_port.rule_key).has_value());
}

TEST(gobgp_flowspec_lifecycle, additive_refresh_rules_are_deduplicated_and_unbanned_together) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    flow_spec_rule_t tcp_443 = make_gobgp_flowspec_lifecycle_rule(victim_ipv4, ip_protocol_t::TCP, true, true);
    flow_spec_rule_t udp_53 = make_gobgp_flowspec_lifecycle_rule(victim_ipv4, ip_protocol_t::UDP, true);
    udp_53.add_destination_port(53);
    flow_spec_rule_t tcp_80 = make_gobgp_flowspec_lifecycle_rule(victim_ipv4, ip_protocol_t::TCP, true);
    tcp_80.add_destination_port(80);

    const auto tcp_443_key = make_gobgp_flowspec_lifecycle_key(tcp_443);
    const auto udp_53_key = make_gobgp_flowspec_lifecycle_key(udp_53);
    const auto tcp_80_key = make_gobgp_flowspec_lifecycle_key(tcp_80);
    gobgp_flowspec_lifecycle_t lifecycle;

    ASSERT_TRUE(lifecycle.begin_announce(tcp_443_key, tcp_443));
    ASSERT_EQ(lifecycle.complete_announce(tcp_443_key, std::string("\x01", 1)), gobgp_flowspec_announce_completion_t::installed);
    EXPECT_FALSE(lifecycle.begin_refresh_announce(tcp_443_key, tcp_443));
    ASSERT_TRUE(lifecycle.begin_refresh_announce(udp_53_key, udp_53));
    ASSERT_TRUE(lifecycle.begin_refresh_announce(tcp_80_key, tcp_80));
    ASSERT_EQ(lifecycle.complete_announce(udp_53_key, std::string("\x02", 1)), gobgp_flowspec_announce_completion_t::installed);
    ASSERT_EQ(lifecycle.complete_announce(tcp_80_key, std::string("\x03", 1)), gobgp_flowspec_announce_completion_t::installed);

    const auto withdraw_start = lifecycle.begin_withdraw_for_victim(victim_ipv4);
    EXPECT_EQ(withdraw_start.withdraw_requests.size(), 3U);
}

TEST(gobgp_flowspec_lifecycle, refresh_add_is_fenced_after_unban_and_pending_add_is_withdrawn) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    flow_spec_rule_t tcp_443 = make_gobgp_flowspec_lifecycle_rule(victim_ipv4, ip_protocol_t::TCP, true, true);
    flow_spec_rule_t udp_53 = make_gobgp_flowspec_lifecycle_rule(victim_ipv4, ip_protocol_t::UDP, true);
    udp_53.add_destination_port(53);
    const auto tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_443);
    const auto udp_key = make_gobgp_flowspec_lifecycle_key(udp_53);
    gobgp_flowspec_lifecycle_t lifecycle;

    ASSERT_TRUE(lifecycle.begin_refresh_announce(tcp_key, tcp_443));
    EXPECT_TRUE(lifecycle.begin_withdraw_for_victim(victim_ipv4).deferred_rules.size() == 1U);
    EXPECT_FALSE(lifecycle.begin_refresh_announce(udp_key, udp_53));
    EXPECT_EQ(lifecycle.complete_announce(tcp_key, std::string("\xaa", 1)),
              gobgp_flowspec_announce_completion_t::withdraw_required);
    EXPECT_EQ(lifecycle.complete_withdraw(tcp_key, std::string("\xaa", 1), true),
              gobgp_flowspec_withdraw_completion_t::erased);
    EXPECT_TRUE(lifecycle.begin_announce(tcp_key, tcp_443));
}

TEST(gobgp_flowspec_lifecycle, refresh_capture_completion_does_not_clear_fence_while_withdraw_is_pending) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    flow_spec_rule_t tcp_443 = make_gobgp_flowspec_lifecycle_rule(victim_ipv4, ip_protocol_t::TCP, true, true);
    const auto tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_443);
    gobgp_flowspec_lifecycle_t lifecycle;
    const std::string uuid("\xaa", 1);

    ASSERT_TRUE(lifecycle.begin_announce(tcp_key, tcp_443));
    ASSERT_EQ(lifecycle.complete_announce(tcp_key, uuid), gobgp_flowspec_announce_completion_t::installed);
    ASSERT_TRUE(lifecycle.begin_refresh_capture(victim_ipv4));
    ASSERT_EQ(lifecycle.begin_withdraw_for_victim(victim_ipv4).withdraw_requests.size(), 1U);
    lifecycle.complete_refresh_capture(victim_ipv4);

    EXPECT_FALSE(lifecycle.begin_announce(tcp_key, tcp_443));
    ASSERT_EQ(lifecycle.complete_withdraw(tcp_key, uuid, true), gobgp_flowspec_withdraw_completion_t::erased);
    EXPECT_TRUE(lifecycle.begin_announce(tcp_key, tcp_443));
}

TEST(gobgp_flowspec_lifecycle, refresh_capture_without_rules_releases_fence_after_capture_completes) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));

    flow_spec_rule_t tcp_443 = make_gobgp_flowspec_lifecycle_rule(victim_ipv4, ip_protocol_t::TCP, true, true);
    const auto tcp_key = make_gobgp_flowspec_lifecycle_key(tcp_443);
    gobgp_flowspec_lifecycle_t lifecycle;

    ASSERT_TRUE(lifecycle.begin_refresh_capture(victim_ipv4));
    lifecycle.begin_withdraw_for_victim(victim_ipv4);
    EXPECT_FALSE(lifecycle.begin_announce(tcp_key, tcp_443));

    lifecycle.complete_refresh_capture(victim_ipv4);
    EXPECT_FALSE(lifecycle.begin_announce(tcp_key, tcp_443));
    lifecycle.finish_refresh_capture(victim_ipv4);
    EXPECT_TRUE(lifecycle.begin_announce(tcp_key, tcp_443));
}

TEST(gobgp_flowspec_lifecycle, only_one_refresh_capture_is_allowed_per_victim) {
    uint32_t victim_ipv4 = 0;
    ASSERT_TRUE(convert_ip_as_string_to_uint_safe("10.10.10.10", victim_ipv4));
    gobgp_flowspec_lifecycle_t lifecycle;

    EXPECT_TRUE(lifecycle.begin_refresh_capture(victim_ipv4));
    EXPECT_FALSE(lifecycle.begin_refresh_capture(victim_ipv4));
    lifecycle.complete_refresh_capture(victim_ipv4);
    EXPECT_TRUE(lifecycle.begin_refresh_capture(victim_ipv4));

    lifecycle.begin_withdraw_for_victim(victim_ipv4);
    EXPECT_FALSE(lifecycle.begin_refresh_capture(victim_ipv4));
}

TEST(gobgp_flowspec_refresh, disabled_by_default_and_empty_profile_produces_no_candidates) {
    fastnetmon_configuration_t configuration;
    EXPECT_FALSE(configuration.gobgp_flowspec_rule_refresh);
    EXPECT_EQ(configuration.gobgp_flowspec_rule_refresh_interval, 5U);
    EXPECT_EQ(configuration.gobgp_flowspec_refresh_port_min_share_percent, 20U);
    EXPECT_EQ(configuration.gobgp_flowspec_max_port_rules_per_protocol, 4U);

    gobgp_flowspec_protocol_admission_snapshot_t missing_speed_snapshot;
    EXPECT_TRUE(get_gobgp_flowspec_active_protocols(missing_speed_snapshot).empty());
}

/* Patricia tests */

TEST(patricia, negative_lookup_ipv6_prefix) {
    patricia_tree_t* lookup_ipv6_tree;
    lookup_ipv6_tree = New_Patricia(128);

    make_and_lookup_ipv6(lookup_ipv6_tree, (char*)"2a03:f480::/32");

    // Destroy_Patricia(lookup_ipv6_tree);

    prefix_t prefix_for_check_address;

    // Convert fb.com frontend address to internal structure
    inet_pton(AF_INET6, "2a03:2880:2130:cf05:face:b00c::1", (void*)&prefix_for_check_address.add.sin6);

    prefix_for_check_address.family = AF_INET6;
    prefix_for_check_address.bitlen = 128;

    bool found = patricia_search_best2(lookup_ipv6_tree, &prefix_for_check_address, 1) != NULL;

    EXPECT_EQ(found, false);
}

TEST(convert_ip_as_string_to_uint_test, convert_ip_as_string_to_uint) {
    uint32_t ip = 0;

    convert_ip_as_string_to_uint_safe("255.255.255.0", ip);

    EXPECT_EQ(ip, convert_cidr_to_binary_netmask(24));

    convert_ip_as_string_to_uint_safe("255.255.255.255", ip);

    EXPECT_EQ(ip, convert_cidr_to_binary_netmask(32));
}

TEST(patricia, positive_lookup_ipv6_prefix) {
    patricia_tree_t* lookup_ipv6_tree;
    lookup_ipv6_tree = New_Patricia(128);

    make_and_lookup_ipv6(lookup_ipv6_tree, (char*)"2a03:f480::/32");

    // Destroy_Patricia(lookup_ipv6_tree);

    prefix_t prefix_for_check_address;

    inet_pton(AF_INET6, "2a03:f480:2130:cf05:face:b00c::1", (void*)&prefix_for_check_address.add.sin6);

    prefix_for_check_address.family = AF_INET6;
    prefix_for_check_address.bitlen = 128;

    bool found = patricia_search_best2(lookup_ipv6_tree, &prefix_for_check_address, 1) != NULL;

    EXPECT_EQ(found, true);
}

TEST(serialize_attack_description, blank_attack) {
    attack_details_t current_attack;
    std::string result = serialize_attack_description(current_attack);
    EXPECT_EQ(result, "Attack type: unknown\nInitial attack power: 0 packets per second\nPeak attack power: 0 "
                      "packets per second\nAttack direction: other\nAttack protocol: unknown\nTotal incoming "
                      "traffic: 0 mbps\nTotal outgoing traffic: 0 mbps\nTotal incoming pps: 0 packets per "
                      "second\nTotal outgoing pps: 0 packets per second\nTotal incoming flows: 0 flows per "
                      "second\nTotal outgoing flows: 0 flows per second\nAverage incoming traffic: 0 mbps\nAverage "
                      "outgoing traffic: 0 mbps\nAverage incoming pps: 0 packets per second\nAverage outgoing pps: 0 "
                      "packets per second\nAverage incoming flows: 0 flows per second\nAverage outgoing flows: 0 "
                      "flows per second\nIncoming ip fragmented traffic: 0 mbps\nOutgoing ip fragmented traffic: 0 "
                      "mbps\nIncoming ip fragmented pps: 0 packets per second\nOutgoing ip fragmented pps: 0 packets "
                      "per second\nIncoming tcp traffic: 0 mbps\nOutgoing tcp traffic: 0 mbps\nIncoming tcp pps: 0 "
                      "packets per second\nOutgoing tcp pps: 0 packets per second\nIncoming syn tcp traffic: 0 "
                      "mbps\nOutgoing syn tcp traffic: 0 mbps\nIncoming syn tcp pps: 0 packets per second\nOutgoing "
                      "syn tcp pps: 0 packets per second\nIncoming udp traffic: 0 mbps\nOutgoing udp traffic: 0 "
                      "mbps\nIncoming udp pps: 0 packets per second\nOutgoing udp pps: 0 packets per "
                      "second\nIncoming icmp traffic: 0 mbps\nOutgoing icmp traffic: 0 mbps\nIncoming icmp pps: 0 "
                      "packets per second\nOutgoing icmp pps: 0 packets per second\n");
}
