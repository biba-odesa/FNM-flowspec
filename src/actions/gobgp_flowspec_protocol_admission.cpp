#include "gobgp_flowspec_protocol_admission.hpp"

std::set<ip_protocol_t> get_gobgp_flowspec_active_protocols(
    const gobgp_flowspec_protocol_admission_snapshot_t& snapshot) {
    std::set<ip_protocol_t> active_protocols;

    // Keep strict comparison aligned with FastNetMon's existing PPS threshold semantics.
    if (snapshot.tcp_pps_enabled && snapshot.tcp_in_pps > snapshot.tcp_pps_threshold) {
        active_protocols.insert(ip_protocol_t::TCP);
    }

    if (snapshot.udp_pps_enabled && snapshot.udp_in_pps > snapshot.udp_pps_threshold) {
        active_protocols.insert(ip_protocol_t::UDP);
    }

    if (snapshot.icmp_pps_enabled && snapshot.icmp_in_pps > snapshot.icmp_pps_threshold) {
        active_protocols.insert(ip_protocol_t::ICMP);
    }

    return active_protocols;
}
