// named_pipe_ipc.h
// IPC implementation for agent services using Windows Named Pipes
#pragma once
#include <string>
#include <vector>
#include <windows.h>

namespace agent_ipc {
    class NamedPipeServer {
    public:
        NamedPipeServer(const std::wstring& pipe_name);
        ~NamedPipeServer();
        bool Start();
        bool WaitForClient();
        bool ReadMessage(std::vector<uint8_t>& out_msg);
        bool WriteMessage(const std::vector<uint8_t>& msg);
        void Close();
    private:
        HANDLE pipe_handle_ = INVALID_HANDLE_VALUE;
        std::wstring pipe_name_;
    };

    class NamedPipeClient {
    public:
        NamedPipeClient(const std::wstring& pipe_name);
        ~NamedPipeClient();
        bool Connect();
        bool ReadMessage(std::vector<uint8_t>& out_msg);
        bool WriteMessage(const std::vector<uint8_t>& msg);
        void Close();
    private:
        HANDLE pipe_handle_ = INVALID_HANDLE_VALUE;
        std::wstring pipe_name_;
    };
}
