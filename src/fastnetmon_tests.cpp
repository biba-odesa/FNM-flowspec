#include <gtest/gtest.h>
#include <math.h>

#include "bgp_protocol_flow_spec.hpp"
#include "actions/gobgp_flowspec_lifecycle.hpp"
#include "actions/gobgp_flowspec_rule_builder.hpp"
#include "actions/gobgp_log_formatter.hpp"
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
