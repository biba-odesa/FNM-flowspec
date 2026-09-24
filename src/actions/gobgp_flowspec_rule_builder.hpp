#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "../bgp_protocol_flow_spec.hpp"
#include "../fastnetmon_types.hpp"
#include "../attack_details.hpp"

flow_spec_rule_t build_gobgp_flowspec_ipv4_rule(uint32_t victim_ipv4,
                                                 const attack_details_t& current_attack,
                                                 uint32_t redirect_ipv4,
                                                 std::optional<uint16_t> destination_port = std::nullopt,
                                                 bgp_flow_spec_action_types_t action_type =
                                                     bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT,
                                                 uint32_t redirect_rt_as = 0,
                                                 uint32_t redirect_rt_value = 0);

bool parse_gobgp_flowspec_action(const std::string& action_name, bgp_flow_spec_action_types_t& action_type);
bool parse_gobgp_flowspec_redirect_rt(const std::string& route_target, uint32_t& asn, uint32_t& value);
