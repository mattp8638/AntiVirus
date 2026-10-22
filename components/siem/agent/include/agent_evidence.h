// agent_evidence.h
// Evidence subsystem for immutable, hashed, time-stamped artefacts
#pragma once
#include <string>
#include <vector>
#include <chrono>

namespace agent_evidence {
    struct EvidenceItem {
        std::string evidence_id;
        std::string source;
        std::string type;
        std::string related_id;
        std::string hash;
        std::string storage_path;
        std::chrono::system_clock::time_point captured_at;
    };

    class EvidenceBroker {
    public:
        void AddEvidence(const EvidenceItem& item);
        void SealEvidence(const std::string& evidence_id);
        void UploadEvidence(const std::string& evidence_id);
        std::vector<EvidenceItem> ListEvidence() const;
    private:
        std::vector<EvidenceItem> evidence_store_;
    };
}
