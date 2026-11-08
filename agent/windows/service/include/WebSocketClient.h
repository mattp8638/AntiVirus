#pragma once

// Minimal WebSocket client on WinHTTP (Windows 8+). Used for the realtime
// wake channel and by the remote-access helper to reach the cloud relay.

#include <windows.h>
#include <winhttp.h>

#include <mutex>
#include <memory>
#include <string>
#include <vector>

namespace antivirus::agent {

class WebSocketClient {
 public:
  WebSocketClient() = default;
  ~WebSocketClient();
  WebSocketClient(const WebSocketClient&) = delete;
  WebSocketClient& operator=(const WebSocketClient&) = delete;

  // url: ws:// or wss://. headers: "Name: value\r\n" pairs. Throws std::runtime_error on failure.
  void Connect(const std::wstring& url, const std::wstring& headers = L"", DWORD timeoutMs = 20000);
  bool SendText(const std::string& utf8);
  bool SendBinary(const void* data, std::size_t size);
  // Blocks until a full message arrives. Returns false when the socket closed.
  bool Receive(std::string* message, bool* binary);
  void Close(unsigned short status = 1000, const std::string& reason = "");
  bool Connected() const;

 private:
  bool Send(WINHTTP_WEB_SOCKET_BUFFER_TYPE type, const void* data, std::size_t size);
  struct Connection;
  std::shared_ptr<Connection> Current() const;
  mutable std::mutex stateMutex_;
  std::shared_ptr<Connection> active_;
  std::mutex sendMutex_;
};

}  // namespace antivirus::agent
