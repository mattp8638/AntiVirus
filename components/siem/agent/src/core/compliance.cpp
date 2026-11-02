// Compliance subsystem implementation for Agent Core
#include "agent_compliance.h"
#include <iostream>

namespace agent_core {
    void RunComplianceChecks() {
        agent_compliance::ComplianceEngine engine;
        auto result = engine.RunCheck("firewall_enabled");
        std::cout << "Compliance check: " << result.control_id << " passed: " << result.passed << std::endl;
        engine.CollectArtefact(result.evidence_path);
        engine.BundleEvidence("bundle-001");
    }
}
