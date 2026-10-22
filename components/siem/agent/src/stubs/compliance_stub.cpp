#include "../../include/agent_compliance.h"

namespace agent_compliance {

ComplianceCheckResult ComplianceEngine::RunCheck(const std::string& control_id) {
    ComplianceCheckResult r;
    r.control_id = control_id;
    r.passed = true;
    r.evidence_path = "";
    r.evaluated_at = std::chrono::system_clock::now();
    return r;
}

void ComplianceEngine::CollectArtefact(const std::string& evidence_path) {
    (void)evidence_path;
}

void ComplianceEngine::BundleEvidence(const std::string& bundle_id) {
    (void)bundle_id;
}

} // namespace agent_compliance
