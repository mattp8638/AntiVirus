#include "agent_config.h"


#include <cstdlib>
#include <fstream>
#include <sstream>
#include <map>

namespace {
// Simple INI parser for [agent] section, returns key-value map
std::map<std::string, std::string> ParseAgentConfigIni(const std::string& path) {
    std::ifstream file(path);
    std::map<std::string, std::string> result;
    if (!file) return result;
    std::string line;
    bool in_agent_section = false;
    while (std::getline(file, line)) {
        // Remove comments
        auto comment = line.find('#');
        if (comment != std::string::npos) line = line.substr(0, comment);
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (line.empty()) continue;
        if (line[0] == '[') {
            in_agent_section = (line == "[agent]");
            continue;
        }
        if (!in_agent_section) continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);
        // Remove quotes if present
        key.erase(0, key.find_first_not_of(" \t\r\n"));
        key.erase(key.find_last_not_of(" \t\r\n") + 1);
        value.erase(0, value.find_first_not_of(" \t\r\n"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);
        if (!value.empty() && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }
        result[key] = value;
    }
    return result;
}

std::string GetIniOrEnv(const std::map<std::string, std::string>& ini, const char* key, const char* env, const std::string& fallback) {
    auto it = ini.find(key);
    if (it != ini.end() && !it->second.empty()) return it->second;
    const char* value = std::getenv(env);
    if (value != nullptr) return std::string(value);
    return fallback;
}
} // namespace

#include "agent_system.h"

namespace agent {

namespace {
std::string GetEnv(const char* key, const std::string& fallback) {
    const char* value = std::getenv(key);
    if (value == nullptr) {
        return fallback;
    }
    return std::string(value);
}
}  // namespace


namespace {
std::string ResolveConfigPath() {
    std::string override_path = GetEnv("AGENT_CONFIG_PATH", "");
    if (!override_path.empty()) {
        return override_path;
    }
    std::string executable_dir = DetectExecutableDir();
    if (!executable_dir.empty()) {
        return executable_dir + "/config/agent_config.ini";
    }
    return "agent_config.ini";
}
}  // namespace

Config LoadConfig() {
    Config config{};
    auto ini = ParseAgentConfigIni(ResolveConfigPath());
    config.transport_url = GetIniOrEnv(ini, "transport_url", "AGENT_TRANSPORT_URL", "https://10.252.0.2:8085");
    config.tenant_id = GetIniOrEnv(ini, "tenant_id", "AGENT_TENANT_ID", "");
    config.asset_id = GetIniOrEnv(ini, "asset_id", "AGENT_ASSET_ID", "");
    config.identity_id = GetIniOrEnv(ini, "identity_id", "AGENT_IDENTITY_ID", "");
    config.agent_version = GetIniOrEnv(ini, "agent_version", "AGENT_VERSION", "0.1.0");
    config.hostname = GetIniOrEnv(ini, "hostname", "AGENT_HOSTNAME", "");
    if (config.hostname.empty()) {
        config.hostname = DetectHostname();
    }
    config.os_name = GetIniOrEnv(ini, "os_name", "AGENT_OS_NAME", "");
    if (config.os_name.empty()) {
        config.os_name = DetectOsName();
    }
    if (config.tenant_id.empty()) {
        config.tenant_id = DetectTenantId();
    }
    if (config.asset_id.empty()) {
        config.asset_id = config.hostname;
    }
    if (config.identity_id.empty()) {
        config.identity_id = DetectIdentityId();
    }
    config.trust_state = GetIniOrEnv(ini, "trust_state", "AGENT_TRUST_STATE", "bootstrap");
    config.shared_key = GetIniOrEnv(ini, "shared_key", "AGENT_HMAC_SHARED_KEY", "");
    config.api_key = GetIniOrEnv(ini, "api_key", "AGENT_API_KEY", "");
    config.cert_fingerprint = GetIniOrEnv(ini, "cert_fingerprint", "AGENT_CERT_FINGERPRINT", "sha256:placeholder");
    config.identity_header = GetIniOrEnv(ini, "identity_header", "AGENT_IDENTITY", "agent-placeholder");
    config.heartbeat_interval_seconds = std::stoi(GetIniOrEnv(ini, "heartbeat_interval_seconds", "AGENT_HEARTBEAT_INTERVAL", "45"));
    config.watchdog_timeout_seconds = std::stoi(GetIniOrEnv(ini, "watchdog_timeout_seconds", "AGENT_WATCHDOG_TIMEOUT", "120"));
    config.max_heartbeat_interval_seconds = std::stoi(GetIniOrEnv(ini, "max_heartbeat_interval_seconds", "AGENT_HEARTBEAT_MAX_INTERVAL", "300"));
    config.patch_poll_interval_seconds = std::stoi(GetIniOrEnv(ini, "patch_poll_interval_seconds", "AGENT_PATCH_POLL_INTERVAL", "30"));
    config.expected_binary_hash = GetIniOrEnv(ini, "expected_binary_hash", "AGENT_EXPECTED_SHA256", "");
    return config;
}

}  // namespace agent
