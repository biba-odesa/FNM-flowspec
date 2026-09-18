#include "gobgp_flowspec_notification_formatter.hpp"

#include "gobgp_log_formatter.hpp"

#include <sstream>

namespace {

std::string format_port(const std::optional<uint16_t>& port) {
    return port.has_value() ? std::to_string(*port) : "none";
}

} // namespace

std::string format_gobgp_flowspec_add_success_notification(
    const flow_spec_rule_t& flow_spec_rule,
    const std::string& add_path_uuid,
    const std::optional<gobgp_flowspec_port_classifier_result_t>& classifier_result) {
    std::stringstream report;
    report << "FlowSpec ADD success (GoBGP)\n";
    report << "Rule: " << format_gobgp_flowspec_rule(flow_spec_rule) << "\n";
    report << "UUID: " << format_gobgp_uuid_as_hex(add_path_uuid) << "\n";

    if (classifier_result.has_value()) {
        report << "Dominant port: " << format_port(classifier_result->dominant_port) << "\n";
        report << "Selected port: " << format_port(classifier_result->selected_destination_port) << "\n";
        report << "Dominance: " << static_cast<unsigned int>(classifier_result->dominance_percent) << "%\n";
        report << "Qualifying samples: " << classifier_result->qualifying_sample_count << "\n";
        report << "Classifier reason: "
               << get_gobgp_flowspec_port_classifier_reason_name(classifier_result->reason) << "\n";
    }

    return report.str();
}

std::string format_gobgp_flowspec_delete_success_notification(const flow_spec_rule_t& flow_spec_rule,
                                                               const std::string& add_path_uuid) {
    std::stringstream report;
    report << "FlowSpec DELETE success (GoBGP)\n";
    report << "Rule: " << format_gobgp_flowspec_rule(flow_spec_rule) << "\n";
    report << "UUID: " << format_gobgp_uuid_as_hex(add_path_uuid) << "\n";
    return report.str();
}
