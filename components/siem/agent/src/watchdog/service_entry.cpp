#include "../../include/windows_service_entry.h"
#include <iostream>

namespace agent_watchdog {
    void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
        (void)argc; (void)argv;
        std::wcout << L"Watchdog Service running as Windows service." << std::endl;
        // TODO: Monitor processes/services and restart if needed
        while (true) {
            Sleep(1000);
        }
    }
}

extern "C" int wmain_watchdog(int argc, wchar_t* argv[]) {
    agent_winservice::RegisterService(L"TamsilAgentWatchdog", agent_watchdog::ServiceMain);
    return 0;
}
