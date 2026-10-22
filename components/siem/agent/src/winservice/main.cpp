// Minimal Windows service host for agent_winservice.
// This keeps the service alive so SCM reports it as running.
#include <windows.h>
#include <iostream>

namespace {
const wchar_t* kServiceName = L"TamsilAgentWinService";
SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status = {};
HANDLE g_stop_event = nullptr;

void SetServiceState(DWORD state) {
    g_status.dwCurrentState = state;
    SetServiceStatus(g_status_handle, &g_status);
}

void WINAPI ServiceCtrlHandler(DWORD ctrl_code) {
    if (ctrl_code == SERVICE_CONTROL_STOP && g_stop_event) {
        SetServiceState(SERVICE_STOP_PENDING);
        SetEvent(g_stop_event);
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerW(kServiceName, ServiceCtrlHandler);
    if (!g_status_handle) {
        return;
    }

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_status.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_status_handle, &g_status);

    g_stop_event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    SetServiceState(SERVICE_RUNNING);

    WaitForSingleObject(g_stop_event, INFINITE);
    SetServiceState(SERVICE_STOPPED);
    CloseHandle(g_stop_event);
}
}  // namespace

int wmain() {
    SERVICE_TABLE_ENTRYW dispatch_table[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherW(dispatch_table)) {
        std::wcerr << L"agent_winservice must be started by the Service Control Manager.\n";
        return 1;
    }
    return 0;
}
