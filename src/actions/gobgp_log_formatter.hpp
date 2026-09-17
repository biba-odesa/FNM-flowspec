#pragma once

#include <string>

#include "../bgp_protocol.hpp"
#include "../bgp_protocol_flow_spec.hpp"

std::string format_gobgp_uuid_as_hex(const std::string& add_path_uuid);
std::string format_gobgp_flowspec_rule(const flow_spec_rule_t& flow_spec_rule);
std::string format_gobgp_ipv4_unicast_route(IPv4UnicastAnnounce& unicast_ipv4_announce);
std::string format_gobgp_ipv6_unicast_route(const IPv6UnicastAnnounce& unicast_ipv6_announce);
