#include "RemotePipeIo.h"

#include <iostream>
#include <stdexcept>
#include <string>

using antivirus::agent::remote::FinishPipeIo;

struct Handle {
  HANDLE value;
  ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

void Check(bool condition, const char* reason) {
  if (!condition) throw std::runtime_error(reason);
}

int main() {
  try {
    const auto name = L"\\\\.\\pipe\\fenrir-sas-io-test-" + std::to_wstring(GetCurrentProcessId());
    Handle server{CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                  PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                  1, 1024, 1024, 0, nullptr)};
    Handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Check(server.value != INVALID_HANDLE_VALUE && event.value, "could not create test pipe");
    OVERLAPPED operation{};
    operation.hEvent = event.value;
    const BOOL connecting = ConnectNamedPipe(server.value, &operation);
    const DWORD connectError = GetLastError();
    Handle client{CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr)};
    DWORD transferred = 0;
    const bool connected = FinishPipeIo(server.value, operation, connecting, connectError, 2000, nullptr, transferred);
    Check(client.value != INVALID_HANDLE_VALUE && connected, "test client could not connect");

    // A connected but silent service/peer used to block ReadFile forever.
    char data[32]{};
    operation = {};
    operation.hEvent = event.value;
    ResetEvent(event.value);
    const BOOL reading = ReadFile(server.value, data, sizeof(data), nullptr, &operation);
    const DWORD readError = GetLastError();
    const auto started = GetTickCount64();
    Check(!FinishPipeIo(server.value, operation, reading, readError, 50, nullptr, transferred), "a silent peer did not time out");
    Check(GetLastError() == ERROR_TIMEOUT, "timeout reason was lost");
    Check(GetTickCount64() - started < 2000, "pipe timeout did not stay bounded");
    Check(!GetOverlappedResult(server.value, &operation, &transferred, FALSE) && GetLastError() == ERROR_OPERATION_ABORTED,
          "cancelled I/O was left pending against a stack buffer");

    // Cancellation must not poison subsequent requests on this connection.
    Handle clientEvent{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    OVERLAPPED write{};
    write.hEvent = clientEvent.value;
    const BOOL writing = WriteFile(client.value, "sas", 3, nullptr, &write);
    Check(FinishPipeIo(client.value, write, writing, GetLastError(), 2000, nullptr, transferred) && transferred == 3,
          "request could not be written after cancellation");
    operation = {};
    operation.hEvent = event.value;
    ResetEvent(event.value);
    const BOOL receiving = ReadFile(server.value, data, sizeof(data), nullptr, &operation);
    Check(FinishPipeIo(server.value, operation, receiving, GetLastError(), 2000, nullptr, transferred) &&
          std::string(data, transferred) == "sas", "immediately completed request was lost");

    // A terminating helper cancels the wait instead of leaking a broker thread.
    Handle exited{CreateEventW(nullptr, TRUE, TRUE, nullptr)};
    operation = {};
    operation.hEvent = event.value;
    ResetEvent(event.value);
    const BOOL stalled = ReadFile(server.value, data, sizeof(data), nullptr, &operation);
    Check(!FinishPipeIo(server.value, operation, stalled, GetLastError(), 2000, exited.value, transferred) &&
          GetLastError() == ERROR_BROKEN_PIPE, "helper exit did not cancel the pending operation");
    std::cout << "Remote pipe I/O tests passed (deadline, cancellation, immediate completion, helper exit).\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
