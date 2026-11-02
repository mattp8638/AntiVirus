#pragma once

#include <string>

namespace agent {

struct Config {
    std::string transport_url;
    std::string tenant_id;
    std::string asset_id;
    std::string identity_id;
    std::string agent_version;
    std::string hostname;
    std::string os_name;
    std::string trust_state;
    std::string shared_key;
    std::string api_key;
    std::string cert_fingerprint;
    std::string identity_header;
    int heartbeat_interval_seconds;
    int watchdog_timeout_seconds;
    int max_heartbeat_interval_seconds;
    int patch_poll_interval_seconds;
    std::string expected_binary_hash;
};

Config LoadConfig();

}  // namespace agent
