// Windows Service entry point for Agent Core Service
#include "windows_service_entry.h"
#include <iostream>

namespace agent_core {
    void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
        std::wcout << L"Agent Core Service running as Windows service." << std::endl;
        // TODO: Call main agent logic here
        // ...
    }

    void WINAPI ServiceCtrlHandler(DWORD ctrl_code) {
        switch (ctrl_code) {
        case SERVICE_CONTROL_STOP:
            std::wcout << L"Agent Core Service stopping..." << std::endl;
            // TODO: Cleanup and stop
            break;
        default:
            break;
        }
    }
}

extern "C" int wmain(int argc, wchar_t* argv[]) {
    agent_winservice::RegisterService(L"TamsilAgentCore", agent_core::ServiceMain);
    return 0;
}
