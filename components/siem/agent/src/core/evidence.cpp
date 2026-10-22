// Evidence subsystem implementation for Agent Core
#include "agent_evidence.h"
#include <iostream>

namespace agent_core {
    void AddSampleEvidence() {
        agent_evidence::EvidenceBroker broker;
        agent_evidence::EvidenceItem item;
        item.evidence_id = "ev-001";
        item.source = "Sensor";
        item.type = "ProcessCreateEvent";
        item.related_id = "case-123";
        item.hash = "TODO: compute hash";
        item.storage_path = "C:/evidence/ev-001.bin";
        item.captured_at = std::chrono::system_clock::now();
        broker.AddEvidence(item);
        broker.SealEvidence(item.evidence_id);
        broker.UploadEvidence(item.evidence_id);
        std::cout << "Sample evidence added, sealed, and uploaded." << std::endl;
    }
}
