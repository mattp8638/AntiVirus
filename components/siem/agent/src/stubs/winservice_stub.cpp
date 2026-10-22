#include "../../include/windows_service_entry.h"

namespace agent_winservice {

bool RegisterService(const std::wstring& service_name, void(*ServiceMain)(DWORD, LPWSTR*)) {
    (void)service_name; (void)ServiceMain;
    // Minimal stub: when running as console we don't register with SCM.
    return true;
}

void WINAPI ServiceCtrlHandler(DWORD ctrl_code) {
    (void)ctrl_code;
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    (void)argc; (void)argv;
}

bool InstallService(const std::wstring& service_name, const std::wstring& display_name, const std::wstring& bin_path) {
    (void)service_name; (void)display_name; (void)bin_path; return false;
}

bool UninstallService(const std::wstring& service_name) {
    (void)service_name; return false;
}

} // namespace agent_winservice
