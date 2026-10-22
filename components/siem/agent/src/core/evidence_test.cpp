// evidence_test.cpp
// Simple runner to exercise EvidenceBroker: create temp file, add, seal, upload
#include "../../include/agent_evidence.h"
#include <fstream>
#include <iostream>
#include <chrono>

int main() {
    // Create a temp evidence file
    std::string tmp_path = "tmp_evidence.bin";
    std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
    if (!ofs.good()) {
        std::cerr << "Failed to create temp evidence file" << std::endl;
        return 1;
    }
    std::string sample = "sample evidence content";
    ofs.write(sample.data(), (std::streamsize)sample.size());
    ofs.close();

    agent_evidence::EvidenceBroker broker;
    agent_evidence::EvidenceItem item;
    item.evidence_id = "test-ev-001";
    item.source = "unit-test";
    item.type = "test";
    item.related_id = "case-test";
    item.storage_path = tmp_path;
    item.captured_at = std::chrono::system_clock::now();

    broker.AddEvidence(item);
    broker.SealEvidence(item.evidence_id);
    broker.UploadEvidence(item.evidence_id);

    auto list = broker.ListEvidence();
    std::cout << "Evidence store contains: " << list.size() << " items" << std::endl;
    return 0;
}
