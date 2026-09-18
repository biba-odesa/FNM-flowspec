#pragma once

#include "../fastnetmon_types.hpp"
#include "../attack_details.hpp"
#include "../fastnetmon_simple_packet.hpp"

#include <boost/circular_buffer.hpp>

#include <cstdint>
#include <optional>

enum class gobgp_flowspec_port_classifier_reason_t {
    selected,
    port_detection_disabled,
    not_incoming,
    unsupported_protocol,
    no_qualifying_samples,
    insufficient_samples,
    below_dominance,
    ambiguous_dominant_port,
};

struct gobgp_flowspec_port_classifier_config_t {
    uint64_t min_samples = 10;
    uint8_t dominance_percent = 70;
};

struct gobgp_flowspec_port_classifier_result_t {
    std::optional<uint16_t> selected_destination_port;
    uint64_t qualifying_sample_count = 0;
    uint64_t total_weight = 0;
    std::optional<uint16_t> dominant_port;
    uint64_t dominant_weight = 0;
    uint8_t dominance_percent = 0;
    gobgp_flowspec_port_classifier_reason_t reason = gobgp_flowspec_port_classifier_reason_t::no_qualifying_samples;
};

gobgp_flowspec_port_classifier_result_t classify_gobgp_flowspec_destination_port(
    uint32_t victim_ipv4,
    const attack_details_t& current_attack,
    const boost::circular_buffer<simple_packet_t>& packet_samples,
    const gobgp_flowspec_port_classifier_config_t& classifier_config);

const char* get_gobgp_flowspec_port_classifier_reason_name(gobgp_flowspec_port_classifier_reason_t reason);
