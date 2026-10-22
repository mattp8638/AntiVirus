#include "../../include/windows_service_entry.h"
#include <windows.h>
#include <iostream>

namespace agent_winservice {

    static SERVICE_STATUS_HANDLE g_status_handle = nullptr;

    BOOL CreateServiceIfMissing(const std::wstring& service_name, const std::wstring& bin_path) {
        // Minimal no-op: installation should be performed separately via InstallService
        (void)service_name; (void)bin_path;
        return TRUE;
    }

    bool RegisterService(const std::wstring& service_name, void(*ServiceMain)(DWORD, LPWSTR*)) {
        SERVICE_TABLE_ENTRYW dispatchTable[] = {
            { const_cast<LPWSTR>(service_name.c_str()), (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
            { nullptr, nullptr }
        };
        if (!StartServiceCtrlDispatcherW(dispatchTable)) {
            DWORD err = GetLastError();
            std::wcerr << L"StartServiceCtrlDispatcher failed: " << err << std::endl;
            return false;
        }
        return true;
    }

    void WINAPI ServiceCtrlHandler(DWORD ctrl_code) {
        switch (ctrl_code) {
        case SERVICE_CONTROL_STOP:
            if (g_status_handle) {
                SERVICE_STATUS status = {0};
                status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
                status.dwCurrentState = SERVICE_STOP_PENDING;
                SetServiceStatus(g_status_handle, &status);
            }
            break;
        default:
            break;
        }
    }

    void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
        (void)argc; (void)argv;
        // Default placeholder; real service implementations override this.
        g_status_handle = RegisterServiceCtrlHandlerW(L"TamsilAgentService", (LPHANDLER_FUNCTION)ServiceCtrlHandler);
        if (!g_status_handle) {
            std::wcerr << L"RegisterServiceCtrlHandler failed" << std::endl;
            return;
        }
        SERVICE_STATUS status = {0};
        status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        status.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(g_status_handle, &status);

        // Run until stopped
        while (status.dwCurrentState == SERVICE_RUNNING) {
            Sleep(1000);
        }
    }

    bool InstallService(const std::wstring& service_name, const std::wstring& display_name, const std::wstring& bin_path) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm) return false;
        SC_HANDLE svc = CreateServiceW(scm, service_name.c_str(), display_name.c_str(), SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
            bin_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            CloseServiceHandle(scm);
            return false;
        }
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return true;
    }

    bool UninstallService(const std::wstring& service_name) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;
        SC_HANDLE svc = OpenServiceW(scm, service_name.c_str(), DELETE);
        if (!svc) { CloseServiceHandle(scm); return false; }
        BOOL ok = DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return ok == TRUE;
    }

}
