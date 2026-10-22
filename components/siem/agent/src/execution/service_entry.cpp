#include "../../include/windows_service_entry.h"
#include <iostream>

namespace agent_execution {
    void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
        (void)argc; (void)argv;
        std::wcout << L"Execution Service running as Windows service." << std::endl;
        // TODO: Initialize execution gate, signed command verification
        while (true) {
            Sleep(1000);
        }
    }
}

extern "C" int wmain_execution(int argc, wchar_t* argv[]) {
    agent_winservice::RegisterService(L"TamsilAgentExecution", agent_execution::ServiceMain);
    return 0;
}
