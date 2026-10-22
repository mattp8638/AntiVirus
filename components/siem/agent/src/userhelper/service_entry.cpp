#include "../../include/windows_service_entry.h"
#include <iostream>

namespace agent_userhelper {
    void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
        (void)argc; (void)argv;
        std::wcout << L"User Helper Service running as Windows service (optional)." << std::endl;
        // Note: user helper often runs in user context; service may broker to user session
        while (true) {
            Sleep(1000);
        }
    }
}

extern "C" int wmain_userhelper(int argc, wchar_t* argv[]) {
    agent_winservice::RegisterService(L"TamsilAgentUserHelper", agent_userhelper::ServiceMain);
    return 0;
}
