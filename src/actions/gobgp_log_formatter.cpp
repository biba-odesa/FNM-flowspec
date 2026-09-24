#include "gobgp_log_formatter.hpp"

#include "../fast_library.hpp"

#include <functional>
#include <iomanip>
#include <sstream>

namespace {

template <typename value_type>
std::string format_value_list(const std::vector<value_type>& values, const std::function<std::string(value_type)>& formatter) {
    std::stringstream buffer;

    if (values.size() > 1) {
        buffer << "[";
    }

    for (size_t index = 0; index < values.size(); index++) {
        if (index > 0) {
            buffer << ",";
        }

        buffer << formatter(values[index]);
    }

    if (values.size() > 1) {
        buffer << "]";
    }

    return buffer.str();
}

std::string format_bgp_communities(const std::vector<bgp_community_attribute_element_t>& communities) {
    return format_value_list<bgp_community_attribute_element_t>(
        communities, [](bgp_community_attribute_element_t community) {
            return std::to_string(community.asn_number) + ":" + std::to_string(community.community_number);
        });
}

} // namespace

std::string format_gobgp_uuid_as_hex(const std::string& add_path_uuid) {
    std::stringstream buffer;
    buffer << "uuid=hex:";

    for (unsigned char byte : add_path_uuid) {
        buffer << std::hex << std::nouppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(byte);
    }

    return buffer.str();
}

std::string format_gobgp_flowspec_rule(const flow_spec_rule_t& flow_spec_rule) {
    std::stringstream buffer;

    buffer << "dst=";
    if (flow_spec_rule.destination_subnet_ipv4_used) {
        buffer << convert_ip_as_uint_to_string(flow_spec_rule.destination_subnet_ipv4.subnet_address) << "/"
               << flow_spec_rule.destination_subnet_ipv4.cidr_prefix_length;
    } else {
        buffer << "<missing>";
    }

    buffer << " protocol=";
    if (flow_spec_rule.protocols.empty()) {
        buffer << "ANY";
    } else {
        buffer << format_value_list<ip_protocol_t>(flow_spec_rule.protocols, [](ip_protocol_t protocol) {
            return std::string(get_ip_protocol_name(protocol));
        });
    }

    if (!flow_spec_rule.destination_ports.empty()) {
        buffer << " dst_port=" << format_value_list<uint16_t>(flow_spec_rule.destination_ports, [](uint16_t port) {
            return std::to_string(port);
        });
    }

    if (flow_spec_rule.get_action().get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD) {
        buffer << " action=discard";
    } else {
        buffer << " redirect=";
        if (flow_spec_rule.ipv4_nexthops.empty()) {
            buffer << "<missing>";
        } else {
            buffer << format_value_list<uint32_t>(flow_spec_rule.ipv4_nexthops, [](uint32_t next_hop) {
                return convert_ip_as_uint_to_string(next_hop);
            });
        }
    }

    return buffer.str();
}

std::string format_gobgp_ipv4_unicast_route(IPv4UnicastAnnounce& unicast_ipv4_announce) {
    std::stringstream buffer;
    buffer << "prefix=" << unicast_ipv4_announce.get_prefix_in_cidr_form()
           << " next_hop=" << convert_ip_as_uint_to_string(unicast_ipv4_announce.get_next_hop());

    std::vector<bgp_community_attribute_element_t> communities = unicast_ipv4_announce.get_communities();
    if (!communities.empty()) {
        buffer << " communities=" << format_bgp_communities(communities);
    }

    return buffer.str();
}

std::string format_gobgp_ipv6_unicast_route(const IPv6UnicastAnnounce& unicast_ipv6_announce) {
    std::stringstream buffer;
    buffer << "prefix=" << unicast_ipv6_announce.get_prefix_in_cidr_form()
           << " next_hop=" << convert_ipv6_subnet_to_string(unicast_ipv6_announce.get_next_hop());

    std::vector<bgp_community_attribute_element_t> communities = unicast_ipv6_announce.get_communities();
    if (!communities.empty()) {
        buffer << " communities=" << format_bgp_communities(communities);
    }

    return buffer.str();
}
