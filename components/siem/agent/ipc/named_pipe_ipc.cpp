#include "named_pipe_ipc.h"
#include <iostream>

namespace agent_ipc {

    NamedPipeServer::NamedPipeServer(const std::wstring& pipe_name) : pipe_name_(pipe_name) {}
    NamedPipeServer::~NamedPipeServer() { Close(); }

    static std::wstring SanitizePipeName(const std::wstring& in) {
        // Accept only alnum, '_' and '-' in the pipe name; replace others with '_'
        std::wstring out;
        for (wchar_t c : in) {
            if (iswalnum(c) || c == L'_' || c == L'-') out.push_back(c);
            else if (c == L'\\' || c == L'.' || c == L':' || c == L'/') {
                // skip path separators from provided full path
            } else {
                out.push_back(L'_');
            }
        }
        if (out.empty()) return L"tamsil_agent_pipe";
        return out;
    }

    bool NamedPipeServer::Start() {
        const std::wstring prefix = L"\\\\.\\pipe\\";
        std::wstring name = pipe_name_;
        // If caller provided a full path, strip the prefix and sanitize the remainder
        if (name.size() >= prefix.size() && name.compare(0, prefix.size(), prefix) == 0) {
            name = name.substr(prefix.size());
        }
        name = SanitizePipeName(name);
        std::wstring full = prefix + name;
        std::wcout << L"[IPC] Creating named pipe: " << full << std::endl;
        pipe_handle_ = CreateNamedPipeW(full.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nullptr);
        if (pipe_handle_ == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            std::wcerr << L"[IPC] CreateNamedPipeW failed, Win32 error: " << err << std::endl;
            return false;
        }
        return true;
    }

    bool NamedPipeServer::WaitForClient() {
        if (pipe_handle_ == INVALID_HANDLE_VALUE) return false;
        BOOL connected = ConnectNamedPipe(pipe_handle_, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected == TRUE) {
            // Try to obtain the client's PID for diagnostic logging (Windows 7+/Server 2008 R2+)
            ULONG clientPid = 0;
            if (GetNamedPipeClientProcessId(pipe_handle_, &clientPid) == TRUE) {
                std::wcout << L"[IPC] Client connected, PID=" << clientPid << std::endl;
            } else {
                DWORD err = GetLastError();
                std::wcerr << L"[IPC] Client connected (could not get PID), Win32 error: " << err << std::endl;
            }
        }
        return connected == TRUE;
    }

    bool NamedPipeServer::ReadMessage(std::vector<uint8_t>& out_msg) {
        if (pipe_handle_ == INVALID_HANDLE_VALUE) return false;
        const uint32_t MAX_MSG_SIZE = 16 * 1024 * 1024; // 16 MiB limit
        uint32_t size = 0; DWORD read = 0;
        if (!ReadFile(pipe_handle_, &size, sizeof(size), &read, nullptr)) {
            DWORD err = GetLastError();
            std::cerr << "[IPC] ReadMessage failed reading size, Win32 error: " << err << std::endl;
            return false;
        }
        if (size == 0) {
            out_msg.clear();
            return true;
        }
        std::cout << "[IPC] ReadMessage header size: " << size << std::endl;
        if (size > MAX_MSG_SIZE) {
            std::cerr << "[IPC] ReadMessage received oversized message: " << size << " bytes\n";
            return false;
        }
        out_msg.resize(size);
        uint32_t to_read = size;
        uint8_t* ptr = out_msg.data();
        while (to_read > 0) {
            DWORD chunk = 0;
            if (!ReadFile(pipe_handle_, ptr, to_read, &chunk, nullptr)) {
                DWORD err = GetLastError();
                std::cerr << "[IPC] ReadMessage failed reading payload, Win32 error: " << err << std::endl;
                return false;
            }
            if (chunk == 0) { std::cerr << "[IPC] ReadMessage unexpected zero-length read\n"; return false; }
            ptr += chunk;
            to_read -= chunk;
        }
        return true;
    }

    bool NamedPipeServer::WriteMessage(const std::vector<uint8_t>& msg) {
        if (pipe_handle_ == INVALID_HANDLE_VALUE) return false;
        const uint32_t MAX_MSG_SIZE = 16 * 1024 * 1024; // 16 MiB limit
        uint32_t size = (uint32_t)msg.size();
        if (size > MAX_MSG_SIZE) {
            std::cerr << "[IPC] WriteMessage refusing to send oversized message: " << size << " bytes\n";
            return false;
        }
        std::cout << "[IPC] WriteMessage sending size: " << size << std::endl;
        DWORD written = 0;
        if (!WriteFile(pipe_handle_, &size, sizeof(size), &written, nullptr)) {
            DWORD err = GetLastError();
            std::cerr << "[IPC] WriteMessage failed writing size, Win32 error: " << err << std::endl;
            return false;
        }
        uint32_t to_write = size;
        const uint8_t* ptr = msg.data();
        while (to_write > 0) {
            DWORD chunk = 0;
            if (!WriteFile(pipe_handle_, ptr, to_write, &chunk, nullptr)) {
                DWORD err = GetLastError();
                std::cerr << "[IPC] WriteMessage failed writing payload, Win32 error: " << err << std::endl;
                return false;
            }
            if (chunk == 0) { std::cerr << "[IPC] WriteMessage wrote zero bytes\n"; return false; }
            ptr += chunk;
            to_write -= chunk;
        }
        return true;
    }

    void NamedPipeServer::Close() {
        if (pipe_handle_ != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(pipe_handle_);
            DisconnectNamedPipe(pipe_handle_);
            CloseHandle(pipe_handle_);
            pipe_handle_ = INVALID_HANDLE_VALUE;
        }
    }

    NamedPipeClient::NamedPipeClient(const std::wstring& pipe_name) : pipe_name_(pipe_name) {}
    NamedPipeClient::~NamedPipeClient() { Close(); }

    bool NamedPipeClient::Connect() {
        const std::wstring prefix = L"\\\\.\\pipe\\";
        std::wstring name = pipe_name_;
        if (name.size() >= prefix.size() && name.compare(0, prefix.size(), prefix) == 0) {
            name = name.substr(prefix.size());
        }
        std::wstring full = prefix + name;
        // Wait indefinitely for the server to appear; avoid noisy logs by
        // reporting every N attempts.
        const DWORD sleep_ms = 100;
        const int log_every = 50;
        int attempts = 0;
        while (true) {
            HANDLE h = CreateFileW(full.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE) { pipe_handle_ = h; return true; }
            DWORD err = GetLastError();
            attempts++;
            if ((attempts % log_every) == 0) {
                std::wcerr << L"[IPC] CreateFileW still failing when connecting to " << full << L" Win32 error: " << err << L" after " << attempts << L" attempts" << std::endl;
            }
            Sleep(sleep_ms);
        }
    }

    bool NamedPipeClient::ReadMessage(std::vector<uint8_t>& out_msg) {
        if (pipe_handle_ == INVALID_HANDLE_VALUE) return false;
        const uint32_t MAX_MSG_SIZE = 16 * 1024 * 1024; // 16 MiB
        uint32_t size = 0; DWORD read = 0;
        if (!ReadFile(pipe_handle_, &size, sizeof(size), &read, nullptr)) {
            DWORD err = GetLastError();
            std::cerr << "[IPC] ReadMessage (client) failed reading size, Win32 error: " << err << std::endl;
            return false;
        }
        if (size == 0) { out_msg.clear(); return true; }
        std::cout << "[IPC] ReadMessage (client) header size: " << size << std::endl;
        if (size > MAX_MSG_SIZE) {
            std::cerr << "[IPC] ReadMessage (client) received oversized message: " << size << " bytes\n";
            return false;
        }
        out_msg.resize(size);
        uint32_t to_read = size;
        uint8_t* ptr = out_msg.data();
        while (to_read > 0) {
            DWORD chunk = 0;
            if (!ReadFile(pipe_handle_, ptr, to_read, &chunk, nullptr)) {
                DWORD err = GetLastError();
                std::cerr << "[IPC] ReadMessage (client) failed reading payload, Win32 error: " << err << std::endl;
                return false;
            }
            if (chunk == 0) { std::cerr << "[IPC] ReadMessage (client) unexpected zero-length read\n"; return false; }
            ptr += chunk;
            to_read -= chunk;
        }
        return true;
    }

    bool NamedPipeClient::WriteMessage(const std::vector<uint8_t>& msg) {
        if (pipe_handle_ == INVALID_HANDLE_VALUE) return false;
        const uint32_t MAX_MSG_SIZE = 16 * 1024 * 1024; // 16 MiB
        uint32_t size = (uint32_t)msg.size();
        if (size > MAX_MSG_SIZE) {
            std::cerr << "[IPC] WriteMessage (client) refusing to send oversized message: " << size << " bytes\n";
            return false;
        }
        std::cout << "[IPC] WriteMessage (client) sending size: " << size << std::endl;
        DWORD written = 0;
        if (!WriteFile(pipe_handle_, &size, sizeof(size), &written, nullptr)) {
            DWORD err = GetLastError();
            std::cerr << "[IPC] WriteMessage (client) failed writing size, Win32 error: " << err << std::endl;
            return false;
        }
        uint32_t to_write = size;
        const uint8_t* ptr = msg.data();
        while (to_write > 0) {
            DWORD chunk = 0;
            if (!WriteFile(pipe_handle_, ptr, to_write, &chunk, nullptr)) {
                DWORD err = GetLastError();
                std::cerr << "[IPC] WriteMessage (client) failed writing payload, Win32 error: " << err << std::endl;
                return false;
            }
            if (chunk == 0) { std::cerr << "[IPC] WriteMessage (client) wrote zero bytes\n"; return false; }
            ptr += chunk;
            to_write -= chunk;
        }
        return true;
    }

    void NamedPipeClient::Close() {
        if (pipe_handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(pipe_handle_);
            pipe_handle_ = INVALID_HANDLE_VALUE;
        }
    }

}
