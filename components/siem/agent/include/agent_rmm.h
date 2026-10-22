// agent_rmm.h
// RMM telemetry models and client for patch, script, remote session, and evidence reporting.
#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "agent_config.h"

namespace agent_rmm {

struct RmmConfigProfile {
    std::string name;
    std::string profile_type;
    std::string description;
};

struct RmmPatchCatalogItem {
    std::string vendor;
    std::string product;
    std::string patch_id;
    std::string release_date;
    int severity;
};

struct RmmPatchJob {
    std::string psa_case_id;
    std::string scheduled_for;
    std::string reboot_policy;
};

struct RmmScriptResult {
    std::string job_id;
    std::string stdout_data;
    std::string stderr_data;
    int exit_code;
    std::string hash;
};

struct RmmRemoteSession {
    std::string asset_id;
    std::string initiated_by;
    std::string session_type;
};

struct RmmEvidenceRecord {
    std::string asset_id;
    std::string evidence_type;
    std::string related_entity;
    std::string related_id;
    std::string storage_uri;
    std::string hash;
};

struct RmmDeviceInventory {
    std::string asset_id;
    std::string hostname;
    std::string os_name;
    std::string os_version;
    std::string serial_number;
    std::chrono::system_clock::time_point collected_at;
};

class RmmTelemetryClient {
public:
    explicit RmmTelemetryClient(const agent::Config& config);

    bool SendConfigProfile(const RmmConfigProfile& profile) const;
    bool SendPatchCatalog(const std::vector<RmmPatchCatalogItem>& items) const;
    bool SendPatchJob(const RmmPatchJob& job) const;
    bool SendScriptResult(const RmmScriptResult& result) const;
    bool SendRemoteSession(const RmmRemoteSession& session) const;
    bool SendEvidenceRecord(const RmmEvidenceRecord& record) const;
    bool SendDeviceInventory(const RmmDeviceInventory& inventory) const;

private:
    agent::Config config_;
};

}  // namespace agent_rmm
