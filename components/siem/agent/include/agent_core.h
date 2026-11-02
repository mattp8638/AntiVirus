// agent_core.h
// Agent Core Service interface and subsystems
#pragma once
#include <string>
#include <memory>
#include <vector>
#include <chrono>

namespace agent_core {
    struct AgentIdentity {
        std::string agent_uuid;
        std::string hardware_id;
        std::string public_key;
        std::string private_key;
        std::string config_signature;
        std::chrono::system_clock::time_point registered_at;
    };

    struct ConfigManager {
        std::string config_blob;
        std::string config_signature;
        bool is_valid;
        std::chrono::system_clock::time_point loaded_at;
    };

    struct ModuleInfo {
        std::string name;
        std::string version;
        bool enabled;
    };

    class ModuleRegistry {
    public:
        void RegisterModule(const ModuleInfo& info);
        std::vector<ModuleInfo> ListModules() const;
    private:
        std::vector<ModuleInfo> modules_;
    };

    struct TelemetryRouter {
        void RouteTelemetry(const std::string& envelope);
    };

    struct CommandDispatcher {
        void DispatchCommand(const std::string& command);
    };

    struct EvidenceBroker {
        void PackageEvidence(const std::string& evidence_blob);
        void UploadEvidence(const std::string& evidence_id);
    };

    // Convenience helpers used by the core service main for self-audit and sample evidence
    void RunComplianceChecks();
    void AddSampleEvidence();
}
