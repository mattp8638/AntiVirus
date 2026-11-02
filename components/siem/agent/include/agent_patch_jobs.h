// agent_patch_jobs.h
// Patch job command channel models and client for RMM patch orchestration.
#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "agent_config.h"
#include "agent_execution.h"

namespace agent_patch {

struct PatchDescriptor {
    std::string patch_id;
    std::string title;
    std::string vendor;
    std::string severity;
    std::string kb;
};

struct PatchJobCommand {
    std::string job_id;
    std::string asset_id;
    std::string reboot_policy;
    std::chrono::system_clock::time_point scheduled_at;
    std::string scheduled_at_raw;
    std::vector<PatchDescriptor> patches;
    long long issued_at_epoch;
    std::string nonce;
    std::string signature;
};

struct PatchJobAck {
    std::string job_id;
    std::string status;
    std::string detail;
    std::chrono::system_clock::time_point acknowledged_at;
};

class PatchJobClient {
public:
    explicit PatchJobClient(const agent::Config& config);

    bool PollNextPatchJob(PatchJobCommand* job_out) const;
    bool AcknowledgePatchJob(const PatchJobAck& ack) const;
    bool ReportPatchResult(const agent_execution::PatchJobResult& result) const;

private:
    agent::Config config_;
};

}  // namespace agent_patch
