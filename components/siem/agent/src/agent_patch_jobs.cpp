// agent_patch_jobs.cpp
// Patch job command channel implementation using libcurl and HMAC validation.
#include "agent_patch_jobs.h"

#include "agent_signing.h"

#include <curl/curl.h>

#include <chrono>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>

namespace agent_patch {

namespace {
constexpr int kSignatureSkewSeconds = 300;

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

std::chrono::system_clock::time_point ParseIsoTimestamp(const std::string& value) {
    if (value.empty()) {
        return std::chrono::system_clock::now();
    }
    std::tm tm{};
    std::istringstream stream(value);
    stream >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (stream.fail()) {
        return std::chrono::system_clock::now();
    }
#if defined(_WIN32)
    return std::chrono::system_clock::from_time_t(_mkgmtime(&tm));
#else
    return std::chrono::system_clock::from_time_t(timegm(&tm));
#endif
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

std::string GenerateNonce() {
    std::random_device random_device;
    std::mt19937 rng(random_device());
    std::uniform_int_distribution<int> dist(0, 15);
    std::ostringstream stream;
    for (int i = 0; i < 32; ++i) {
        stream << std::hex << dist(rng);
    }
    return stream.str();
}

bool EnqueueUplinkMtlsRmmPayload(const std::string& queue_dir, const std::string& category, const std::string& payload) {
    if (queue_dir.empty() || payload.empty()) {
        std::cerr << "[PatchJobs] Missing queue directory or payload for uplink." << std::endl;
        return false;
    }

    std::filesystem::path queue_path(queue_dir);
    std::filesystem::create_directories(queue_path);

    const auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string safe_category = SanitiseFilenameToken(category);
    std::filesystem::path payload_path = queue_path / ("mtls_rmm_" + safe_category + "_" + std::to_string(now_epoch) + ".json");

    std::ofstream out(payload_path);
    if (!out) {
        std::cerr << "[PatchJobs] Unable to write uplink queue item: " << payload_path << std::endl;
        return false;
    }

    std::string json;
    json.reserve(payload.size() + 64);
    json += "{";
    json += "\"kind\":\"mtls_rmm\",";
    json += "\"path\":\"/patch-jobs/ack\",";
    json += "\"payload_json\":\"" + JsonEscape(payload) + "\"";
    json += "}";

    out << json;
    out.close();
    return true;
}

bool EnqueueUplinkPatchPayload(const std::string& queue_dir, const std::string& job_id, const std::string& payload) {
    if (queue_dir.empty() || payload.empty()) {
        std::cerr << "[PatchJobs] Missing queue directory or payload for uplink." << std::endl;
        return false;
    }

    std::filesystem::path queue_path(queue_dir);
    std::filesystem::create_directories(queue_path);

    const auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string safe_job = SanitiseFilenameToken(job_id);
    std::filesystem::path payload_path = queue_path / ("patch_result_" + safe_job + "_" + std::to_string(now_epoch) + ".json");

    std::ofstream out(payload_path);
    if (!out) {
        std::cerr << "[PatchJobs] Unable to write uplink queue item: " << payload_path << std::endl;
        return false;
    }

    std::string json;
    json.reserve(payload.size() + 64);
    json += "{";
    json += "\"kind\":\"patch\",";
    json += "\"payload_json\":\"" + JsonEscape(payload) + "\"";
    json += "}";

    out << json;
    out.close();
    return true;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::string* mem = static_cast<std::string*>(userp);
    mem->append(static_cast<char*>(contents), realsize);
    return realsize;
}

bool BuildSignedHeaders(
    const agent::Config& config,
    const std::string& payload,
    std::vector<std::string>* headers_out
) {
    if (!headers_out) {
        return false;
    }
    headers_out->push_back("Content-Type: application/json");
    headers_out->push_back("X-Forwarded-Proto: https");
    if (!config.identity_header.empty()) {
        headers_out->push_back("X-Agent-Identity: " + config.identity_header);
    }
    if (!config.api_key.empty()) {
        headers_out->push_back("X-API-Key: " + config.api_key);
    }

    long long now_epoch = static_cast<long long>(std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()));
    std::string nonce = GenerateNonce();
    headers_out->push_back("X-Agent-Nonce: " + nonce);
    headers_out->push_back("X-Agent-Timestamp: " + std::to_string(now_epoch));

    if (config.shared_key.empty()) {
        std::cerr << "[PatchJobs] Missing shared key; cannot sign payload." << std::endl;
        return false;
    }
    std::string signature = agent::SignPayload(config.shared_key, payload, now_epoch);
    headers_out->push_back("X-Agent-Signature: " + signature);
    return true;
}

bool GetJson(const agent::Config& config, const std::string& url, std::string* response, long* http_code) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }

    std::string response_body;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "TamsilAgent/1.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);

    std::vector<std::string> header_strings;
    if (!BuildSignedHeaders(config, "", &header_strings)) {
        curl_easy_cleanup(curl);
        return false;
    }
    struct curl_slist* headers = nullptr;
    for (const auto& header : header_strings) {
        headers = curl_slist_append(headers, header.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode result = curl_easy_perform(curl);
    long status_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    if (http_code) {
        *http_code = status_code;
    }
    if (result == CURLE_OK && response) {
        *response = response_body;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return result == CURLE_OK;
}

std::string ExtractStringValue(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t start = json.find(needle);
    if (start == std::string::npos) {
        return "";
    }
    start = json.find(':', start + needle.size());
    if (start == std::string::npos) {
        return "";
    }
    start = json.find('"', start);
    if (start == std::string::npos) {
        return "";
    }
    size_t end = json.find('"', start + 1);
    if (end == std::string::npos) {
        return "";
    }
    return json.substr(start + 1, end - start - 1);
}

long long ExtractLongValue(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t start = json.find(needle);
    if (start == std::string::npos) {
        return 0;
    }
    start = json.find(':', start + needle.size());
    if (start == std::string::npos) {
        return 0;
    }
    start = json.find_first_of("0123456789", start);
    if (start == std::string::npos) {
        return 0;
    }
    size_t end = json.find_first_not_of("0123456789", start);
    std::string value = json.substr(start, end - start);
    try {
        return std::stoll(value);
    } catch (...) {
        return 0;
    }
}

std::vector<std::string> ExtractObjectArray(const std::string& json, const std::string& key) {
    std::vector<std::string> objects;
    std::string needle = "\"" + key + "\"";
    size_t start = json.find(needle);
    if (start == std::string::npos) {
        return objects;
    }
    start = json.find('[', start + needle.size());
    if (start == std::string::npos) {
        return objects;
    }
    size_t index = start + 1;
    int depth = 0;
    size_t object_start = std::string::npos;
    while (index < json.size()) {
        char c = json[index];
        if (c == '{') {
            if (depth == 0) {
                object_start = index;
            }
            ++depth;
        } else if (c == '}') {
            --depth;
            if (depth == 0 && object_start != std::string::npos) {
                objects.push_back(json.substr(object_start, index - object_start + 1));
                object_start = std::string::npos;
            }
        } else if (c == ']' && depth == 0) {
            break;
        }
        ++index;
    }
    return objects;
}

std::string BuildSignaturePayload(const PatchJobCommand& command) {
    std::ostringstream payload;
    payload << '{';
    payload << "\"job_id\":\"" << JsonEscape(command.job_id) << "\",";
    payload << "\"asset_id\":\"" << JsonEscape(command.asset_id) << "\",";
    std::string scheduled_at = command.scheduled_at_raw.empty()
        ? BuildIsoTimestamp(command.scheduled_at)
        : command.scheduled_at_raw;
    payload << "\"scheduled_at\":\"" << JsonEscape(scheduled_at) << "\",";
    payload << "\"reboot_policy\":\"" << JsonEscape(command.reboot_policy) << "\",";
    payload << "\"issued_at\":" << command.issued_at_epoch << ",";
    payload << "\"nonce\":\"" << JsonEscape(command.nonce) << "\",";
    payload << "\"patches\":[";
    for (size_t i = 0; i < command.patches.size(); ++i) {
        const auto& patch = command.patches[i];
        payload << '{';
        payload << "\"patch_id\":\"" << JsonEscape(patch.patch_id) << "\",";
        payload << "\"title\":\"" << JsonEscape(patch.title) << "\",";
        payload << "\"vendor\":\"" << JsonEscape(patch.vendor) << "\",";
        payload << "\"severity\":\"" << JsonEscape(patch.severity) << "\",";
        payload << "\"kb\":\"" << JsonEscape(patch.kb) << "\"";
        payload << '}';
        if (i + 1 < command.patches.size()) {
            payload << ',';
        }
    }
    payload << "]}";
    return payload.str();
}

bool ValidateSignature(
    const agent::Config& config,
    const PatchJobCommand& command
) {
    if (config.shared_key.empty()) {
        std::cerr << "[PatchJobs] Missing shared key for signature validation." << std::endl;
        return false;
    }
    long long now_epoch = static_cast<long long>(std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()));
    if (command.issued_at_epoch == 0 ||
        std::llabs(now_epoch - command.issued_at_epoch) > kSignatureSkewSeconds) {
        std::cerr << "[PatchJobs] Command timestamp outside tolerance." << std::endl;
        return false;
    }
    std::string payload = BuildSignaturePayload(command);
    return agent::VerifySignature(config.shared_key, payload, command.issued_at_epoch, command.signature);
}

std::string BuildEndpoint(const agent::Config& config, const std::string& path) {
    return config.transport_url + "/mtls/rmm" + path;
}
}  // namespace

PatchJobClient::PatchJobClient(const agent::Config& config) : config_(config) {}

bool PatchJobClient::PollNextPatchJob(PatchJobCommand* job_out) const {
    if (!job_out) {
        return false;
    }
    std::string response;
    long http_code = 0;
    std::string url = BuildEndpoint(config_, "/patch-jobs/next?asset_id=" + config_.asset_id);
    if (!GetJson(config_, url, &response, &http_code)) {
        std::cerr << "[PatchJobs] Failed to poll patch jobs." << std::endl;
        return false;
    }
    if (http_code == 204) {
        return false;
    }
    if (http_code < 200 || http_code >= 300) {
        std::cerr << "[PatchJobs] Unexpected status code: " << http_code << std::endl;
        return false;
    }

    PatchJobCommand command{};
    command.job_id = ExtractStringValue(response, "job_id");
    if (command.job_id.empty()) {
        return false;
    }
    command.asset_id = ExtractStringValue(response, "asset_id");
    command.reboot_policy = ExtractStringValue(response, "reboot_policy");
    command.issued_at_epoch = ExtractLongValue(response, "issued_at");
    command.nonce = ExtractStringValue(response, "nonce");
    command.signature = ExtractStringValue(response, "signature");
    std::string scheduled_at = ExtractStringValue(response, "scheduled_at");
    command.scheduled_at_raw = scheduled_at;
    command.scheduled_at = ParseIsoTimestamp(scheduled_at);

    for (const auto& patch_obj : ExtractObjectArray(response, "patches")) {
        PatchDescriptor patch{};
        patch.patch_id = ExtractStringValue(patch_obj, "patch_id");
        patch.title = ExtractStringValue(patch_obj, "title");
        patch.vendor = ExtractStringValue(patch_obj, "vendor");
        patch.severity = ExtractStringValue(patch_obj, "severity");
        patch.kb = ExtractStringValue(patch_obj, "kb");
        if (!patch.patch_id.empty()) {
            command.patches.push_back(patch);
        }
    }

    if (!command.asset_id.empty() && command.asset_id != config_.asset_id) {
        std::cerr << "[PatchJobs] Job asset mismatch: " << command.asset_id << std::endl;
        return false;
    }
    if (!ValidateSignature(config_, command)) {
        std::cerr << "[PatchJobs] Signature validation failed for job " << command.job_id << std::endl;
        return false;
    }
    *job_out = command;
    return true;
}

bool PatchJobClient::AcknowledgePatchJob(const PatchJobAck& ack) const {
    std::ostringstream payload;
    payload << '{';
    payload << "\"tenant_id\":\"" << JsonEscape(config_.tenant_id) << "\",";
    payload << "\"asset_id\":\"" << JsonEscape(config_.asset_id) << "\",";
    payload << "\"job_id\":\"" << JsonEscape(ack.job_id) << "\",";
    payload << "\"status\":\"" << JsonEscape(ack.status) << "\",";
    payload << "\"detail\":\"" << JsonEscape(ack.detail) << "\",";
    payload << "\"acknowledged_at\":\"" << JsonEscape(BuildIsoTimestamp(ack.acknowledged_at)) << "\"";
    payload << '}';

    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    bool queued = EnqueueUplinkMtlsRmmPayload(queue_path, "patch_job_ack", payload.str());
    if (!queued) {
        std::cerr << "[PatchJobs] Failed to queue acknowledgement for job " << ack.job_id << std::endl;
    }
    return queued;
}

bool PatchJobClient::ReportPatchResult(const agent_execution::PatchJobResult& result) const {
    std::ostringstream payload;
    payload << '{';
    payload << "\"tenant_id\":\"" << JsonEscape(config_.tenant_id) << "\",";
    payload << "\"asset_id\":\"" << JsonEscape(config_.asset_id) << "\",";
    payload << "\"job_id\":\"" << JsonEscape(result.job_id) << "\",";
    payload << "\"status\":\"" << JsonEscape(result.status) << "\",";
    payload << "\"result\":\"" << JsonEscape(result.result) << "\",";
    payload << "\"exit_code\":" << result.exit_code << ",";
    payload << "\"stdout_summary\":\"" << JsonEscape(result.stdout_summary) << "\",";
    payload << "\"stderr_summary\":\"" << JsonEscape(result.stderr_summary) << "\",";
    payload << "\"reboot_required\":" << (result.reboot_required ? "true" : "false") << ",";
    payload << "\"started_at\":\"" << JsonEscape(BuildIsoTimestamp(result.started_at)) << "\",";
    payload << "\"completed_at\":\"" << JsonEscape(BuildIsoTimestamp(result.completed_at)) << "\"";
    payload << '}';

    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    bool queued = EnqueueUplinkPatchPayload(queue_path, result.job_id, payload.str());
    if (!queued) {
        std::cerr << "[PatchJobs] Failed to queue patch result for job " << result.job_id << std::endl;
    }
    return queued;
}

}  // namespace agent_patch
