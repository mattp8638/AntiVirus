#include "../../include/agent_ipc_shared_memory.h"
#include <windows.h>
#include <sddl.h>
#include <iostream>

namespace agent_ipc {

    SharedMemoryRegion::SharedMemoryRegion(const std::wstring& name, size_t size, const std::wstring& sddl)
        : name_(name), size_(size), sddl_(sddl) {}

    SharedMemoryRegion::~SharedMemoryRegion() { Close(); }

    bool SharedMemoryRegion::CreateOrOpen() {
        std::wstring full_name = L"Global\\" + name_;

        SECURITY_ATTRIBUTES sa;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (!sddl_.empty()) {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_.c_str(), SDDL_REVISION_1, &pSD, nullptr)) {
                std::wcerr << L"Failed to convert SDDL" << std::endl;
                return false;
            }
            sa.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa.lpSecurityDescriptor = pSD;
            sa.bInheritHandle = FALSE;
        }
        else {
            // Default: allow SYSTEM and Administrators full control only (restrictive)
            std::wstring default_sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(default_sddl.c_str(), SDDL_REVISION_1, &pSD, nullptr)) {
                std::wcerr << L"Failed to convert default SDDL" << std::endl;
                return false;
            }
            sa.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa.lpSecurityDescriptor = pSD;
            sa.bInheritHandle = FALSE;
        }

        mapping_handle_ = CreateFileMappingW(INVALID_HANDLE_VALUE, (pSD != nullptr) ? &sa : nullptr, PAGE_READWRITE, 0, (DWORD)size_, full_name.c_str());

        if (pSD) LocalFree(pSD);

        if (!mapping_handle_ || mapping_handle_ == INVALID_HANDLE_VALUE) {
            std::wcerr << L"CreateFileMapping failed: " << GetLastError() << std::endl;
            return false;
        }
        return true;
    }

    void* SharedMemoryRegion::Map() {
        if (!mapping_handle_) return nullptr;
        view_ = MapViewOfFile(mapping_handle_, FILE_MAP_ALL_ACCESS, 0, 0, size_);
        if (!view_) {
            std::wcerr << L"MapViewOfFile failed: " << GetLastError() << std::endl;
        }
        return view_;
    }

    void SharedMemoryRegion::Unmap() {
        if (view_) { UnmapViewOfFile(view_); view_ = nullptr; }
    }

    void SharedMemoryRegion::Close() {
        Unmap();
        if (mapping_handle_) { CloseHandle(mapping_handle_); mapping_handle_ = nullptr; }
    }

}
