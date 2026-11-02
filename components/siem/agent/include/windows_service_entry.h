// windows_service_entry.h
// Windows Service entry point helpers for agent services
#pragma once
#include <windows.h>
#include <string>

namespace agent_winservice {
    // Registers the service main function with the SCM
    bool RegisterService(const std::wstring& service_name, void(*ServiceMain)(DWORD, LPWSTR*));

    // Service control handler
    void WINAPI ServiceCtrlHandler(DWORD ctrl_code);

    // Service main function signature
    void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);

    // Utility to install/uninstall the service
    bool InstallService(const std::wstring& service_name, const std::wstring& display_name, const std::wstring& bin_path);
    bool UninstallService(const std::wstring& service_name);
}
