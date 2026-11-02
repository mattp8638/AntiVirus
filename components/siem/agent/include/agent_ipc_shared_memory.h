// agent_ipc_shared_memory.h
// Shared memory IPC helper with ACLs (Windows)
#pragma once
#include <string>
#include <windows.h>

namespace agent_ipc {
    // Create or open a shared memory region with a security descriptor SDDL
    // sddl allows callers to define ACLs, e.g. "D:...". If empty, a default restrictive SDDL is used.
    class SharedMemoryRegion {
    public:
        SharedMemoryRegion(const std::wstring& name, size_t size, const std::wstring& sddl = L"");
        ~SharedMemoryRegion();

        bool CreateOrOpen();
        void* Map();
        void Unmap();
        void Close();

        HANDLE Handle() const { return mapping_handle_; }
        size_t Size() const { return size_; }

    private:
        std::wstring name_;
        size_t size_ = 0;
        std::wstring sddl_;
        HANDLE mapping_handle_ = nullptr;
        void* view_ = nullptr;
    };
}
