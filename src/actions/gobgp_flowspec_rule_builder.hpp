#pragma once

#include <cstdint>

#include "../bgp_protocol_flow_spec.hpp"
#include "../fastnetmon_types.hpp"
#include "../attack_details.hpp"

flow_spec_rule_t build_gobgp_flowspec_ipv4_rule(uint32_t victim_ipv4,
                                                 const attack_details_t& current_attack,
                                                 uint32_t redirect_ipv4);
