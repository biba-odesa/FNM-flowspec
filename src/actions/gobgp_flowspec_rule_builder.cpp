#include "gobgp_flowspec_rule_builder.hpp"

flow_spec_rule_t build_gobgp_flowspec_ipv4_rule(uint32_t victim_ipv4,
                                                 const attack_details_t& current_attack,
                                                 uint32_t redirect_ipv4) {
    flow_spec_rule_t flow_spec_rule;
    flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask_t(victim_ipv4, 32));
    flow_spec_rule.add_ipv4_nexthop(redirect_ipv4);

    switch (current_attack.attack_protocol) {
    case static_cast<unsigned int>(ip_protocol_t::TCP):
        flow_spec_rule.add_protocol(ip_protocol_t::TCP);
        break;
    case static_cast<unsigned int>(ip_protocol_t::UDP):
        flow_spec_rule.add_protocol(ip_protocol_t::UDP);
        break;
    case static_cast<unsigned int>(ip_protocol_t::ICMP):
        flow_spec_rule.add_protocol(ip_protocol_t::ICMP);
        break;
    default:
        break;
    }

    return flow_spec_rule;
}
