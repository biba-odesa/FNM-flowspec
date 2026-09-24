#include "gobgp_flowspec_rule_builder.hpp"

#include <charconv>

namespace {

bool parse_uint32_strict(const std::string& value, uint32_t& parsed_value) {
    if (value.empty()) {
        return false;
    }

    const char* begin = value.data();
    const char* end   = begin + value.size();
    const std::from_chars_result result = std::from_chars(begin, end, parsed_value);
    return result.ec == std::errc{} && result.ptr == end;
}

} // namespace

bool parse_gobgp_flowspec_action(const std::string& action_name, bgp_flow_spec_action_types_t& action_type) {
    if (action_name == "redirect") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT;
        return true;
    }

    if (action_name == "discard") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD;
        return true;
    }

    if (action_name == "redirect-vrf") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT_VRF;
        return true;
    }

    return false;
}

bool parse_gobgp_flowspec_redirect_rt(const std::string& route_target, uint32_t& asn, uint32_t& value) {
    const size_t separator = route_target.find(':');
    if (separator == std::string::npos || separator != route_target.rfind(':')) {
        return false;
    }

    if (!parse_uint32_strict(route_target.substr(0, separator), asn)
        || !parse_uint32_strict(route_target.substr(separator + 1), value)) {
        return false;
    }

    // RFC 7674 uses the AS-4byte format for ASNs above 65535, whose value field is two octets.
    return asn <= UINT16_MAX || value <= UINT16_MAX;
}

flow_spec_rule_t build_gobgp_flowspec_ipv4_rule(uint32_t victim_ipv4,
                                                 const attack_details_t& current_attack,
                                                 uint32_t redirect_ipv4,
                                                 std::optional<uint16_t> destination_port,
                                                 bgp_flow_spec_action_types_t action_type,
                                                 uint32_t redirect_rt_as,
                                                 uint32_t redirect_rt_value) {
    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(victim_ipv4, 32));

    bgp_flow_spec_action_t flow_spec_action;
    flow_spec_action.set_type(action_type);
    flow_spec_action.set_redirect_rt_as(redirect_rt_as);
    flow_spec_action.set_redirect_rt_value(redirect_rt_value);
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
