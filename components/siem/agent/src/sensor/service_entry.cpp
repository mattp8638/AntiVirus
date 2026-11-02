#include "../../include/windows_service_entry.h"
#include <iostream>

namespace agent_sensor {
    void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
        (void)argc; (void)argv;
        std::wcout << L"Sensor Service running as Windows service." << std::endl;
        // TODO: Initialize sensor listeners (ETW, Event Log)
        while (true) {
            Sleep(1000);
        }
    }
}

extern "C" int wmain_sensor(int argc, wchar_t* argv[]) {
    agent_winservice::RegisterService(L"TamsilAgentSensor", agent_sensor::ServiceMain);
    return 0;
}
