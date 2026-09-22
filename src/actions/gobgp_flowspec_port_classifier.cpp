#include "gobgp_flowspec_port_classifier.hpp"

#include "../iana/iana_ip_protocols.hpp"

#include <limits>
#include <map>

namespace {

uint64_t saturating_add(uint64_t first, uint64_t second) {
    if (std::numeric_limits<uint64_t>::max() - first < second) {
        return std::numeric_limits<uint64_t>::max();
    }

    return first + second;
}

uint64_t saturating_multiply(uint64_t first, uint64_t second) {
    if (first != 0 && second > std::numeric_limits<uint64_t>::max() / first) {
        return std::numeric_limits<uint64_t>::max();
    }

    return first * second;
}

// This comparison is equivalent to numerator * 100 >= denominator * percent,
// but avoids overflowing a 64-bit weighted counter.
bool meets_dominance_percent(uint64_t numerator, uint64_t denominator, uint8_t percent) {
    if (denominator == 0) {
        return false;
    }

    const uint64_t denominator_hundreds = denominator / 100;
    const uint64_t denominator_remainder = denominator % 100;
    const uint64_t threshold = denominator_hundreds * percent
                               + (denominator_remainder * percent + 99) / 100;

    return numerator >= threshold;
}

uint8_t calculate_dominance_percent(uint64_t numerator, uint64_t denominator) {
    uint8_t result = 0;

    for (uint8_t candidate = 1; candidate <= 100; ++candidate) {
        if (!meets_dominance_percent(numerator, denominator, candidate)) {
            break;
        }

        result = candidate;
    }

    return result;
}

bool is_tcp_or_udp_attack(unsigned int attack_protocol) {
    return attack_protocol == static_cast<unsigned int>(ip_protocol_t::TCP)
           || attack_protocol == static_cast<unsigned int>(ip_protocol_t::UDP);
}

} // namespace

const char* get_gobgp_flowspec_port_classifier_reason_name(gobgp_flowspec_port_classifier_reason_t reason) {
    switch (reason) {
    case gobgp_flowspec_port_classifier_reason_t::selected:
        return "selected";
    case gobgp_flowspec_port_classifier_reason_t::port_detection_disabled:
        return "disabled";
    case gobgp_flowspec_port_classifier_reason_t::not_incoming:
        return "not_incoming";
    case gobgp_flowspec_port_classifier_reason_t::unsupported_protocol:
        return "unsupported_protocol";
    case gobgp_flowspec_port_classifier_reason_t::no_qualifying_samples:
        return "no_qualifying_samples";
    case gobgp_flowspec_port_classifier_reason_t::insufficient_samples:
        return "insufficient_samples";
    case gobgp_flowspec_port_classifier_reason_t::below_dominance:
        return "below_dominance";
    case gobgp_flowspec_port_classifier_reason_t::ambiguous_dominant_port:
        return "ambiguous_dominant_port";
    }

    return "unknown";
}

gobgp_flowspec_port_classifier_result_t classify_gobgp_flowspec_destination_port(
    uint32_t victim_ipv4,
    const attack_details_t& current_attack,
    const boost::circular_buffer<simple_packet_t>& packet_samples,
    const gobgp_flowspec_port_classifier_config_t& classifier_config) {
    gobgp_flowspec_port_classifier_result_t result;

    if (current_attack.attack_direction != INCOMING) {
        result.reason = gobgp_flowspec_port_classifier_reason_t::not_incoming;
        return result;
    }

    if (!is_tcp_or_udp_attack(current_attack.attack_protocol)) {
        result.reason = gobgp_flowspec_port_classifier_reason_t::unsupported_protocol;
        return result;
    }

    std::map<uint16_t, uint64_t> destination_port_weights;

    for (const auto& packet : packet_samples) {
        // Port fields are only safe for initial IPv4 TCP/UDP packets. A zero
        // port is also how flow exporters represent absent/unavailable L4 data.
        if (packet.ip_protocol_version != 4 || packet.packet_direction != INCOMING || packet.dst_ip != victim_ipv4
            || packet.protocol != current_attack.attack_protocol || packet.destination_port == 0
            || (packet.ip_fragmented && packet.ip_fragment_offset != 0)) {
            continue;
        }

        const uint64_t weight = saturating_multiply(packet.number_of_packets, packet.sample_ratio);
        result.qualifying_sample_count = saturating_add(result.qualifying_sample_count, 1);
        result.total_weight = saturating_add(result.total_weight, weight);
        destination_port_weights[packet.destination_port] =
            saturating_add(destination_port_weights[packet.destination_port], weight);
    }

    if (destination_port_weights.empty() || result.total_weight == 0) {
        result.reason = gobgp_flowspec_port_classifier_reason_t::no_qualifying_samples;
        return result;
    }

    bool tied_for_dominance = false;
    for (const auto& [port, weight] : destination_port_weights) {
        if (!result.dominant_port.has_value() || weight > result.dominant_weight) {
            result.dominant_port = port;
            result.dominant_weight = weight;
            tied_for_dominance = false;
        } else if (weight == result.dominant_weight) {
            tied_for_dominance = true;
        }
    }

    result.dominance_percent = calculate_dominance_percent(result.dominant_weight, result.total_weight);

    if (result.qualifying_sample_count < classifier_config.min_samples) {
        result.reason = gobgp_flowspec_port_classifier_reason_t::insufficient_samples;
        return result;
    }

    if (tied_for_dominance) {
        result.reason = gobgp_flowspec_port_classifier_reason_t::ambiguous_dominant_port;
        return result;
    }

    if (!meets_dominance_percent(result.dominant_weight, result.total_weight, classifier_config.dominance_percent)) {
        result.reason = gobgp_flowspec_port_classifier_reason_t::below_dominance;
        return result;
    }

    result.selected_destination_port = result.dominant_port;
    result.reason = gobgp_flowspec_port_classifier_reason_t::selected;
    return result;
}

std::vector<gobgp_flowspec_refresh_protocol_result_t> classify_gobgp_flowspec_refresh_protocols(
    uint32_t victim_ipv4,
    const std::set<ip_protocol_t>& active_protocols,
    const boost::circular_buffer<simple_packet_t>& packet_samples,
    const gobgp_flowspec_port_classifier_config_t& classifier_config,
    uint8_t significant_port_min_share_percent) {
    std::vector<gobgp_flowspec_refresh_protocol_result_t> results;

    // Initial BAN deliberately keeps its stricter single-dominant-port policy. Refresh supplements an already
    // admitted attack with every independently significant TCP or UDP destination port.
    for (const ip_protocol_t protocol : active_protocols) {
        gobgp_flowspec_refresh_protocol_result_t result;
        result.protocol = protocol;

        if (protocol == ip_protocol_t::ICMP) {
            result.reason = gobgp_flowspec_port_classifier_reason_t::selected;
            results.push_back(result);
            continue;
        }

        if (protocol != ip_protocol_t::TCP && protocol != ip_protocol_t::UDP) {
            result.reason = gobgp_flowspec_port_classifier_reason_t::unsupported_protocol;
            results.push_back(result);
            continue;
        }

        std::map<uint16_t, uint64_t> destination_port_weights;

        for (const auto& packet : packet_samples) {
            if (packet.ip_protocol_version != 4 || packet.packet_direction != INCOMING || packet.dst_ip != victim_ipv4
                || packet.protocol != static_cast<unsigned int>(protocol) || packet.destination_port == 0
                || (packet.ip_fragmented && packet.ip_fragment_offset != 0)) {
                continue;
            }

            const uint64_t weight = saturating_multiply(packet.number_of_packets, packet.sample_ratio);
            result.qualifying_sample_count = saturating_add(result.qualifying_sample_count, 1);
            result.total_weight = saturating_add(result.total_weight, weight);
            destination_port_weights[packet.destination_port] =
                saturating_add(destination_port_weights[packet.destination_port], weight);
        }

        if (destination_port_weights.empty() || result.total_weight == 0) {
            result.reason = gobgp_flowspec_port_classifier_reason_t::no_qualifying_samples;
            results.push_back(result);
            continue;
        }

        if (result.qualifying_sample_count < classifier_config.min_samples) {
            result.reason = gobgp_flowspec_port_classifier_reason_t::insufficient_samples;
            results.push_back(result);
            continue;
        }

        for (const auto& [port, weight] : destination_port_weights) {
            if (!meets_dominance_percent(weight, result.total_weight, significant_port_min_share_percent)) {
                continue;
            }

            gobgp_flowspec_refresh_candidate_t candidate;
            candidate.protocol = protocol;
            candidate.destination_port = port;
            candidate.port_weight = weight;
            candidate.port_share_percent = calculate_dominance_percent(weight, result.total_weight);
            result.significant_ports.push_back(candidate);
        }

        result.reason = result.significant_ports.empty() ? gobgp_flowspec_port_classifier_reason_t::below_dominance
                                                          : gobgp_flowspec_port_classifier_reason_t::selected;
        results.push_back(result);
    }

    return results;
}

std::vector<gobgp_flowspec_refresh_candidate_t> build_gobgp_flowspec_refresh_candidates(
    uint32_t victim_ipv4,
    const std::set<ip_protocol_t>& active_protocols,
    const boost::circular_buffer<simple_packet_t>& packet_samples,
    const gobgp_flowspec_port_classifier_config_t& classifier_config) {
    std::vector<gobgp_flowspec_refresh_candidate_t> candidates;
    const auto protocol_results = classify_gobgp_flowspec_refresh_protocols(
        victim_ipv4, active_protocols, packet_samples, classifier_config, classifier_config.dominance_percent);

    for (const auto& result : protocol_results) {
        if (result.protocol == ip_protocol_t::ICMP) {
            candidates.push_back({ result.protocol, std::nullopt, std::nullopt });
            continue;
        }

        for (const auto& candidate : result.significant_ports) {
            candidates.push_back(candidate);
        }
    }

    return candidates;
}
