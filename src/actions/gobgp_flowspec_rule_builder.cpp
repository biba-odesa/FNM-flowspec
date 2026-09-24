#include "gobgp_flowspec_rule_builder.hpp"

bool parse_gobgp_flowspec_action(const std::string& action_name, bgp_flow_spec_action_types_t& action_type) {
    if (action_name == "redirect") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT;
        return true;
    }

    if (action_name == "discard") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD;
        return true;
    }

    return false;
}

flow_spec_rule_t build_gobgp_flowspec_ipv4_rule(uint32_t victim_ipv4,
                                                 const attack_details_t& current_attack,
                                                 uint32_t redirect_ipv4,
                                                 std::optional<uint16_t> destination_port,
                                                 bgp_flow_spec_action_types_t action_type) {
    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(victim_ipv4, 32));

    bgp_flow_spec_action_t flow_spec_action;
    flow_spec_action.set_type(action_type);
    flow_spec_rule.set_action(flow_spec_action);

    if (action_type == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT) {
        flow_spec_rule.add_ipv4_nexthop(redirect_ipv4);
    }

    switch (current_attack.attack_protocol) {
    case static_cast<unsigned int>(ip_protocol_t::TCP):
        flow_spec_rule.add_protocol(ip_protocol_t::TCP);
        if (destination_port.has_value()) {
            flow_spec_rule.add_destination_port(*destination_port);
        }
        break;
    case static_cast<unsigned int>(ip_protocol_t::UDP):
        flow_spec_rule.add_protocol(ip_protocol_t::UDP);
        if (destination_port.has_value()) {
            flow_spec_rule.add_destination_port(*destination_port);
        }
        break;
    case static_cast<unsigned int>(ip_protocol_t::ICMP):
        flow_spec_rule.add_protocol(ip_protocol_t::ICMP);
        break;
    default:
        break;
    }

    return flow_spec_rule;
}
