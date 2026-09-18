#pragma once

#include "gobgp_flowspec_port_classifier.hpp"
#include "../bgp_protocol_flow_spec.hpp"

#include <optional>
#include <string>

std::string format_gobgp_flowspec_add_success_notification(
    const flow_spec_rule_t& flow_spec_rule,
    const std::string& add_path_uuid,
    const std::optional<gobgp_flowspec_port_classifier_result_t>& classifier_result);

std::string format_gobgp_flowspec_delete_success_notification(const flow_spec_rule_t& flow_spec_rule,
                                                               const std::string& add_path_uuid);
