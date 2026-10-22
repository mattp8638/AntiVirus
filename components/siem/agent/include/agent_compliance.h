// agent_compliance.h
// Compliance Self-Audit Engine interface
#pragma once
#include <string>
#include <chrono>

namespace agent_compliance {
    struct ComplianceCheckResult {
        std::string control_id;
        bool passed;
        std::string evidence_path;
        std::chrono::system_clock::time_point evaluated_at;
    };

    class ComplianceEngine {
    public:
        ComplianceCheckResult RunCheck(const std::string& control_id);
        void CollectArtefact(const std::string& evidence_path);
        void BundleEvidence(const std::string& bundle_id);
    };
}
