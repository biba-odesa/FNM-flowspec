#pragma once

#include "../iana/iana_ip_protocols.hpp"

#include <cstdint>
#include <set>
#include <string>

struct gobgp_flowspec_protocol_admission_snapshot_t {
    uint32_t victim_ipv4 = 0;
    std::string host_group_name;

    uint64_t total_in_pps = 0;
    uint64_t tcp_in_pps = 0;
    uint64_t udp_in_pps = 0;
    uint64_t icmp_in_pps = 0;

    bool tcp_pps_enabled = false;
    unsigned int tcp_pps_threshold = 0;

    bool udp_pps_enabled = false;
    unsigned int udp_pps_threshold = 0;

    bool icmp_pps_enabled = false;
    unsigned int icmp_pps_threshold = 0;
};

std::set<ip_protocol_t> get_gobgp_flowspec_active_protocols(
    const gobgp_flowspec_protocol_admission_snapshot_t& snapshot);

