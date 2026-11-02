// agent_rmm.cpp
// RMM telemetry emission using lightweight JSON and the Rust uplink queue.
#include "agent_rmm.h"

#include <chrono>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>

namespace agent_rmm {

namespace {
std::string SanitiseFilenameToken(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (const char c : input) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') {
            output.push_back(c);
        } else {
            output.push_back('_');
        }
    }
    if (output.empty()) {
        return "unnamed";
    }
    return output;
}

std::string JsonEscape(const std::string& input) {
    std::ostringstream escaped;
    for (char c : input) {
        switch (c) {
            case '"':
                escaped << "\\\"";
                break;
            case '\\':
                escaped << "\\\\";
                break;
            case '\n':
                escaped << "\\n";
                break;
            case '\r':
                escaped << "\\r";
                break;
            case '\t':
                escaped << "\\t";
                break;
            default:
                escaped << c;
                break;
        }
    }
    return escaped.str();
}

std::string GenerateCorrelationId() {
    std::random_device random_device;
    std::mt19937 rng(random_device());
    std::uniform_int_distribution<int> dist(0, 15);
    std::ostringstream stream;
    for (int i = 0; i < 32; ++i) {
        stream << std::hex << dist(rng);
    }
    return stream.str();
}

std::string BuildIsoTimestamp(const std::chrono::system_clock::time_point& time_point) {
    auto now_time = std::chrono::system_clock::to_time_t(time_point);
    std::tm utc_tm{};
#if defined(_WIN32)
    gmtime_s(&utc_tm, &now_time);
#else
    gmtime_r(&now_time, &utc_tm);
#endif
    std::ostringstream stream;
    stream << std::put_time(&utc_tm, "%FT%TZ");
    return stream.str();
}

bool EnqueueUplinkRmmPayload(
    const std::string& queue_dir,
    const std::string& category,
    const std::string& path,
    const std::string& payload
) {
    if (queue_dir.empty() || payload.empty() || path.empty()) {
        std::cerr << "[RMM] Missing queue directory, path, or payload for uplink." << std::endl;
        return false;
    }

    std::filesystem::path queue_path(queue_dir);
    std::filesystem::create_directories(queue_path);

    const auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string safe_category = SanitiseFilenameToken(category);
    std::filesystem::path payload_path = queue_path / ("rmm_" + safe_category + "_" + std::to_string(now_epoch) + ".json");

    std::ofstream out(payload_path);
    if (!out) {
        std::cerr << "[RMM] Unable to write uplink queue item: " << payload_path << std::endl;
        return false;
    }

    std::string json;
    json.reserve(payload.size() + path.size() + 64);
    json += "{";
    json += "\"kind\":\"rmm\",";
    json += "\"path\":\"" + JsonEscape(path) + "\",";
    json += "\"payload_json\":\"" + JsonEscape(payload) + "\"";
    json += "}";

    out << json;
    out.close();
    return true;
}

void AppendString(std::ostringstream& stream, const std::string& key, const std::string& value, bool trailing_comma = true) {
    stream << "\"" << key << "\":\"" << JsonEscape(value) << "\"";
    if (trailing_comma) {
        stream << ",";
    }
}

void AppendInt(std::ostringstream& stream, const std::string& key, int value, bool trailing_comma = true) {
    stream << "\"" << key << "\":" << value;
    if (trailing_comma) {
        stream << ",";
    }
}

void LogOutcome(const std::string& category, const std::string& correlation_id, bool ok) {
    std::cout << "[RMM] " << category << " correlation_id=" << correlation_id
              << " status=" << (ok ? "success" : "failed") << std::endl;
}
}  // namespace

RmmTelemetryClient::RmmTelemetryClient(const agent::Config& config) : config_(config) {}

bool RmmTelemetryClient::SendConfigProfile(const RmmConfigProfile& profile) const {
    std::string correlation_id = GenerateCorrelationId();
    std::ostringstream payload;
    payload << '{';
    AppendString(payload, "name", profile.name);
    AppendString(payload, "profile_type", profile.profile_type);
    AppendString(payload, "description", profile.description, false);
    payload << '}';

    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    bool ok = EnqueueUplinkRmmPayload(queue_path, "config_profile", "/configuration_profiles", payload.str());
    LogOutcome("config_profile", correlation_id, ok);
    return ok;
}

bool RmmTelemetryClient::SendPatchCatalog(const std::vector<RmmPatchCatalogItem>& items) const {
    std::string correlation_id = GenerateCorrelationId();
    bool ok = true;
    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    for (const auto& item : items) {
        std::ostringstream payload;
        payload << '{';
        AppendString(payload, "vendor", item.vendor);
        AppendString(payload, "product", item.product);
        AppendString(payload, "patch_id", item.patch_id);
        AppendString(payload, "release_date", item.release_date);
        AppendInt(payload, "severity", item.severity, false);
        payload << '}';

        ok = EnqueueUplinkRmmPayload(queue_path, "patch_catalog", "/patch_catalog", payload.str()) && ok;
    }
    LogOutcome("patch_catalog", correlation_id, ok);
    return ok;
}

bool RmmTelemetryClient::SendPatchJob(const RmmPatchJob& job) const {
    std::string correlation_id = GenerateCorrelationId();
    std::ostringstream payload;
    payload << '{';
    AppendString(payload, "psa_case_id", job.psa_case_id);
    AppendString(payload, "scheduled_for", job.scheduled_for);
    AppendString(payload, "reboot_policy", job.reboot_policy, false);
    payload << '}';

    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    bool ok = EnqueueUplinkRmmPayload(queue_path, "patch_job", "/patch_jobs", payload.str());
    LogOutcome("patch_job", correlation_id, ok);
    return ok;
}

bool RmmTelemetryClient::SendScriptResult(const RmmScriptResult& result) const {
    std::string correlation_id = GenerateCorrelationId();
    std::ostringstream payload;
    payload << '{';
    AppendString(payload, "job_id", result.job_id);
    AppendString(payload, "stdout", result.stdout_data);
    AppendString(payload, "stderr", result.stderr_data);
    AppendInt(payload, "exit_code", result.exit_code);
    AppendString(payload, "hash", result.hash, false);
    payload << '}';

    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    bool ok = EnqueueUplinkRmmPayload(queue_path, "script_result", "/script_results", payload.str());
    LogOutcome("script_result", correlation_id, ok);
    return ok;
}

bool RmmTelemetryClient::SendRemoteSession(const RmmRemoteSession& session) const {
    std::string correlation_id = GenerateCorrelationId();
    std::ostringstream payload;
    payload << '{';
    AppendString(payload, "asset_id", session.asset_id);
    AppendString(payload, "initiated_by", session.initiated_by);
    AppendString(payload, "session_type", session.session_type, false);
    payload << '}';

    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    bool ok = EnqueueUplinkRmmPayload(queue_path, "remote_session", "/remote_sessions", payload.str());
    LogOutcome("remote_session", correlation_id, ok);
    return ok;
}

bool RmmTelemetryClient::SendEvidenceRecord(const RmmEvidenceRecord& record) const {
    std::string correlation_id = GenerateCorrelationId();
    std::ostringstream payload;
    payload << '{';
    AppendString(payload, "asset_id", record.asset_id);
    AppendString(payload, "evidence_type", record.evidence_type);
    AppendString(payload, "related_entity", record.related_entity);
    AppendString(payload, "related_id", record.related_id);
    AppendString(payload, "hash", record.hash);
    AppendString(payload, "storage_uri", record.storage_uri);
    payload << '}';

    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    bool ok = EnqueueUplinkRmmPayload(queue_path, "evidence", "/evidence", payload.str());
    LogOutcome("evidence", correlation_id, ok);
    return ok;
}

bool RmmTelemetryClient::SendDeviceInventory(const RmmDeviceInventory& inventory) const {
    std::string correlation_id = GenerateCorrelationId();
    std::ostringstream payload;
    payload << '{';
    AppendString(payload, "asset_id", inventory.asset_id);
    AppendString(payload, "hostname", inventory.hostname);
    AppendString(payload, "os_name", inventory.os_name);
    AppendString(payload, "os_version", inventory.os_version);
    AppendString(payload, "serial_number", inventory.serial_number);
    AppendString(payload, "collected_at", BuildIsoTimestamp(inventory.collected_at), false);
    payload << '}';

    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    bool ok = EnqueueUplinkRmmPayload(queue_path, "device_inventory", "/device_inventory", payload.str());
    LogOutcome("device_inventory", correlation_id, ok);
    return ok;
}

}  // namespace agent_rmm
