#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "../bgp_protocol_flow_spec.hpp"

struct gobgp_flowspec_rule_key_t {
    uint32_t destination_ipv4 = 0;
    bool protocol_present = false;
    ip_protocol_t protocol = ip_protocol_t::HOPOPT;
    bool destination_port_present = false;
    uint16_t destination_port = 0;

    bool operator<(const gobgp_flowspec_rule_key_t& other) const;
};

bool build_gobgp_flowspec_rule_key(const flow_spec_rule_t& flow_spec_rule, gobgp_flowspec_rule_key_t& rule_key);

enum class gobgp_flowspec_rule_state_type_t {
    announcing,
    installed,
    withdraw_requested,
    withdrawing,
};

struct gobgp_flowspec_rule_state_snapshot_t {
    gobgp_flowspec_rule_state_type_t state;
    std::string add_path_uuid;
};

struct gobgp_flowspec_withdraw_request_t {
    gobgp_flowspec_rule_key_t rule_key;
    flow_spec_rule_t flow_spec_rule;
    std::string add_path_uuid;
};

enum class gobgp_flowspec_announce_completion_t {
    installed,
    withdraw_required,
    ignored,
};

enum class gobgp_flowspec_withdraw_completion_t {
    erased,
    retry_pending,
    ignored,
};

struct gobgp_flowspec_withdraw_start_result_t {
    std::vector<gobgp_flowspec_withdraw_request_t> withdraw_requests;
    std::vector<flow_spec_rule_t> deferred_rules;
    std::vector<flow_spec_rule_t> in_progress_rules;
};

class gobgp_flowspec_lifecycle_t {
    public:
    bool begin_announce(const gobgp_flowspec_rule_key_t& rule_key, const flow_spec_rule_t& flow_spec_rule);
    void fail_announce(const gobgp_flowspec_rule_key_t& rule_key);
    gobgp_flowspec_announce_completion_t complete_announce(const gobgp_flowspec_rule_key_t& rule_key,
                                                            const std::string& add_path_uuid);

    gobgp_flowspec_withdraw_start_result_t begin_withdraw_for_victim(uint32_t victim_ipv4);
    gobgp_flowspec_withdraw_completion_t complete_withdraw(const gobgp_flowspec_rule_key_t& rule_key,
                                                            const std::string& add_path_uuid,
                                                            bool success);

    std::optional<gobgp_flowspec_rule_state_snapshot_t> get_state(const gobgp_flowspec_rule_key_t& rule_key) const;
    size_t size() const;

    private:
    struct gobgp_flowspec_rule_state_t {
        gobgp_flowspec_rule_state_type_t state;
        flow_spec_rule_t flow_spec_rule;
        std::string add_path_uuid;
    };

    mutable std::mutex mutex;
    std::map<gobgp_flowspec_rule_key_t, gobgp_flowspec_rule_state_t> rules;
};
