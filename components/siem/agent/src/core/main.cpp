// Agent Core Service
// Responsibilities: Orchestration, identity, config, module registry, telemetry, evidence, uplink
#include "agent_config.h"
#include "agent_id.h"
#include "agent_identity.h"
#include "agent_inventory.h"
#include "agent_signing.h"
#include "agent_core.h"
#include "agent_compliance.h"
#include "agent_evidence.h"
#include <iostream>
#include "../../ipc/named_pipe_ipc.h"

int main(int argc, char* argv[]) {
    // Agent Core Service startup
    // Initialize or load persistent agent identity
    auto identity = agent_identity::GenerateOrLoadIdentity("agent_identity.txt");
    std::cout << "Agent UUID: " << identity.uuid << std::endl;
    // TODO: Generate keypair (if missing), register with backend, receive signed config

    agent_core::ConfigManager config_mgr;
    config_mgr.config_blob = "TODO: load config";
    config_mgr.is_valid = false;
    config_mgr.loaded_at = std::chrono::system_clock::now();
    // TODO: Validate config signature

    agent_core::ModuleRegistry registry;
    registry.RegisterModule({"Sensor", "1.0", true});
    registry.RegisterModule({"Execution", "1.0", true});
    registry.RegisterModule({"Watchdog", "1.0", true});
    // ... add other modules

    agent_core::TelemetryRouter telemetry_router;
    agent_core::CommandDispatcher dispatcher;
    agent_core::EvidenceBroker evidence_broker;

    // Compliance self-audit
    agent_core::RunComplianceChecks();

    // Evidence system
    agent_core::AddSampleEvidence();

    // Start named pipe server and wait for client immediately
    // Validate pipe name (must not contain invalid characters)
    std::wstring pipe_name = L"tamsil_agent_pipe";
    for (wchar_t c : pipe_name) {
        if (!(iswalnum(c) || c == L'_' || c == L'-')) {
            std::wcerr << L"[Core] Invalid character in pipe name. Falling back to 'tamsil_agent_pipe'." << std::endl;
            pipe_name = L"tamsil_agent_pipe";
            break;
        }
    }
    agent_ipc::NamedPipeServer pipe_server(pipe_name);
    if (!pipe_server.Start()) {
        DWORD err = GetLastError();
        std::cerr << "[Core] Failed to start named pipe server. Win32 error: " << err << std::endl;
        return 1;
    }
    std::cout << "[Core] Named pipe server started, waiting for client..." << std::endl;
    if (!pipe_server.WaitForClient()) {
        std::cerr << "[Core] Client failed to connect to pipe" << std::endl;
        pipe_server.Close();
        return 1;
    }
    std::cout << "[Core] Client connected to pipe." << std::endl;

    // TODO: Uplink communications, state reporting, evidence packaging
    std::cout << "Agent Core Service started. Modules registered: " << registry.ListModules().size() << std::endl;

    // Keep the pipe server alive for the agent's lifetime
    while (true) {
        std::vector<uint8_t> msg;
        if (!pipe_server.ReadMessage(msg)) {
            std::cerr << "[Core] Failed to read message from pipe. Waiting for next client..." << std::endl;
            pipe_server.Close();
            // Recreate the pipe and wait for the next client
            if (!pipe_server.Start()) {
                DWORD err = GetLastError();
                std::cerr << "[Core] Failed to restart named pipe server. Win32 error: " << err << std::endl;
                break;
            }
            if (!pipe_server.WaitForClient()) {
                std::cerr << "[Core] Client failed to connect to pipe (after restart)" << std::endl;
                break;
            }
            continue;
        }
        std::string s(msg.begin(), msg.end());
        std::cout << "[Core] Received message: " << s << std::endl;
        // Optionally, process the message or respond
    }
    pipe_server.Close();
    return 0;
}
