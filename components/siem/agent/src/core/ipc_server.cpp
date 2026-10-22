// ipc_server.cpp
// Simple test server using NamedPipeServer to receive a message from Sensor
#include "../../ipc/named_pipe_ipc.h"
#include <iostream>
#include <vector>

int main_ipc_server() {
    std::wstring pipe_name = L"tamsil_agent_pipe";
    agent_ipc::NamedPipeServer server(pipe_name);
    if (!server.Start()) {
        std::cerr << "Failed to start named pipe server" << std::endl;
        return 1;
    }
    std::cout << "Named pipe server started, waiting for client..." << std::endl;
    if (!server.WaitForClient()) {
        std::cerr << "Client failed to connect" << std::endl;
        server.Close();
        return 1;
    }
    std::vector<uint8_t> msg;
    if (!server.ReadMessage(msg)) {
        std::cerr << "Failed to read message" << std::endl;
        server.Close();
        return 1;
    }
    std::string s(msg.begin(), msg.end());
    std::cout << "Received message: " << s << std::endl;
    server.Close();
    return 0;
}
