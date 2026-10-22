// ipc_client.cpp
// Simple client that connects to the core named pipe and sends a telemetry-like message
#include "../../ipc/named_pipe_ipc.h"
#include <iostream>
#include <vector>

int SendTelemetryMessage() {
    std::wstring pipe_name = L"tamsil_agent_pipe";
    agent_ipc::NamedPipeClient client(pipe_name);
    if (!client.Connect()) {
        std::cerr << "Failed to connect to pipe" << std::endl;
        return 1;
    }
    std::string payload = "TELEMETRY|asset:asset-1|agent:agent-1|time:now|payload:example";
    std::vector<uint8_t> data(payload.begin(), payload.end());
    if (!client.WriteMessage(data)) {
        std::cerr << "WriteMessage failed" << std::endl;
        client.Close();
        return 1;
    }
    std::cout << "Telemetry message sent." << std::endl;
    client.Close();
    return 0;
}
