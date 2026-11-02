// TamsilCMS launcher with self-installing Windows service support.
// Usage:
//   tamsilcms.exe --install    ; installs and starts service (requires admin)
//   tamsilcms.exe --uninstall  ; stops and removes service (requires admin)
//   tamsilcms.exe              ; run as console (or service when started by SCM)

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <thread>

static std::vector<PROCESS_INFORMATION> children;
static HANDLE g_stopEvent = nullptr;

const wchar_t* SERVICE_NAME = L"TamsilCMS";
const wchar_t* WINSERVICE_NAME = L"TamsilAgentWinService";
const wchar_t* WINSERVICE_DISPLAY = L"Tamsil Agent WinService";
const wchar_t* CORE_PIPE_NAME = L"\\\\.\\pipe\\tamsil_agent_pipe";
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_serviceStatus = {};

bool FileExists(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

void WaitForCorePipe() {
    constexpr DWORD kWaitIntervalMs = 250;
    DWORD attempt = 0;
    while (true) {
        if (WaitNamedPipeW(CORE_PIPE_NAME, kWaitIntervalMs)) {
            std::wcout << L"Core pipe available. Proceeding to launch remaining services.\n";
            return;
        }
        attempt++;
        std::wcout << L"Waiting for core pipe... (" << attempt << L")\n";
    }
}

bool StartChild(const std::wstring &path) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + path + L"\"";
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::wcerr << L"Failed to start: " << path << L" (" << GetLastError() << L")\n";
        return false;
    }
    children.push_back(pi);
    std::wcout << L"Started " << path << L" (PID=" << pi.dwProcessId << L")\n";
    return true;
}

void ShutdownChildren() {
    for (auto &pi : children) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    children.clear();
}

void WorkerRun(const std::wstring &dir) {
    std::wstring core_path = dir + L"\\agent_core.exe";
    StartChild(core_path);
    WaitForCorePipe();

    std::vector<std::wstring> childrenNames = {
        L"agent_sensor.exe",
        L"agent_execution.exe",
        L"agent_watchdog.exe"
    };

    for (auto &name : childrenNames) {
        std::wstring full = dir + L"\\" + name;
        StartChild(full);
    }

    // Wait until stop event is signalled
    WaitForSingleObject(g_stopEvent, INFINITE);
    ShutdownChildren();
}

// Service control handler
void WINAPI ServiceCtrlHandler(DWORD ctrl) {
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
        g_serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
        if (g_stopEvent) SetEvent(g_stopEvent);
        g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
        break;
    default:
        break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPWSTR *argv) {
    g_statusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_statusHandle) return;

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwServiceSpecificExitCode = 0;
    g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_statusHandle, &g_serviceStatus);

    g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    // Determine exe directory
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring exePath(buf);
    size_t pos = exePath.find_last_of(L"\\/");
    std::wstring dir = (pos==std::wstring::npos) ? L"." : exePath.substr(0,pos);

    g_serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_statusHandle, &g_serviceStatus);

    WorkerRun(dir);

    CloseHandle(g_stopEvent);
}

bool InstallService(const std::wstring &exePath) {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    std::wstring display = L"Tamsil CMS Agent";
    SC_HANDLE svc = CreateServiceW(
        scm,
        SERVICE_NAME,
        display.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        exePath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }
    // start it
    BOOL started = StartServiceW(svc, 0, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return started == TRUE;
}

bool InstallWinService(const std::wstring &dir) {
    std::wstring winservice_path = dir + L"\\agent_winservice.exe";
    if (!FileExists(winservice_path)) {
        std::wcerr << L"agent_winservice.exe not found; skipping service creation.\n";
        return false;
    }
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    SC_HANDLE svc = CreateServiceW(
        scm,
        WINSERVICE_NAME,
        WINSERVICE_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        winservice_path.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }
    BOOL started = StartServiceW(svc, 0, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return started == TRUE;
}

bool UninstallService() {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) { CloseServiceHandle(scm); return false; }

    SERVICE_STATUS status{};
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    BOOL deleted = DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return deleted == TRUE;
}

bool UninstallWinService() {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, WINSERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS status{};
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    BOOL deleted = DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return deleted == TRUE;
}

int wmain(int argc, wchar_t** argv) {
    // Build exe path
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring exePath(buf);
    size_t pos = exePath.find_last_of(L"\\/");
    std::wstring exeDir = (pos==std::wstring::npos) ? L"." : exePath.substr(0,pos);

    if (argc > 1) {
        std::wstring arg = argv[1];
        if (arg == L"--install") {
            if (!InstallService(exePath)) {
                std::wcerr << L"Service install failed (try running as admin)\n";
                return 1;
            }
            InstallWinService(exeDir);
            std::wcout << L"Service installed and started.\n";
            return 0;
        }
        if (arg == L"--uninstall") {
            if (!UninstallService()) {
                std::wcerr << L"Service uninstall failed (try running as admin)\n";
                return 1;
            }
            UninstallWinService();
            std::wcout << L"Service removed.\n";
            return 0;
        }
    }

    // Try to run as service; if not running under SCM, fall back to console
    SERVICE_TABLE_ENTRYW dispatchTable[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherW(dispatchTable)) {
        // not started by SCM — run as console app
        g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        std::thread worker(WorkerRun, exeDir);
        std::wcout << L"TamsilCMS running in console. Press Enter to stop.\n";
        std::wstring dummy; std::getline(std::wcin, dummy);
        SetEvent(g_stopEvent);
        worker.join();
        CloseHandle(g_stopEvent);
    }

    return 0;
}
