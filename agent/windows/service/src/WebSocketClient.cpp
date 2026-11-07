#include "WebSocketClient.h"

#include <stdexcept>

namespace antivirus::agent {

// An in-flight operation retains its handles until WinHTTP returns. Close
// detaches the connection first, then interrupts the outstanding receive.
struct WebSocketClient::Connection {
  HINTERNET session{};
  HINTERNET connection{};
  HINTERNET socket{};
  ~Connection() {
    if (socket) WinHttpCloseHandle(socket);
    if (connection) WinHttpCloseHandle(connection);
    if (session) WinHttpCloseHandle(session);
  }
};

std::shared_ptr<WebSocketClient::Connection> WebSocketClient::Current() const {
  std::lock_guard lock(stateMutex_);
  return active_;
}

bool WebSocketClient::Connected() const { return static_cast<bool>(Current()); }

WebSocketClient::~WebSocketClient() { Close(); }

void WebSocketClient::Connect(const std::wstring& url, const std::wstring& headers, const DWORD timeoutMs) {
  Close();
  URL_COMPONENTS parts{};
  parts.dwStructSize = sizeof(parts);
  wchar_t host[256]{};
  wchar_t path[4096]{};
  wchar_t scheme[16]{};
  parts.lpszHostName = host;
  parts.dwHostNameLength = 255;
  parts.lpszUrlPath = path;
  parts.dwUrlPathLength = 4095;
  parts.lpszScheme = scheme;
  parts.dwSchemeLength = 15;
  wchar_t extra[4096]{};
  parts.lpszExtraInfo = extra;
  parts.dwExtraInfoLength = 4095;
  // WinHttpCrackUrl only understands http(s); map ws(s) first.
  std::wstring httpUrl = url;
  if (httpUrl.rfind(L"wss://", 0) == 0) {
    httpUrl = L"https://" + httpUrl.substr(6);
  } else if (httpUrl.rfind(L"ws://", 0) == 0) {
    httpUrl = L"http://" + httpUrl.substr(5);
  }
  if (!WinHttpCrackUrl(httpUrl.c_str(), 0, 0, &parts)) {
    throw std::runtime_error("Invalid WebSocket URL");
  }
  const bool secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
  auto handles = std::make_shared<Connection>();
  handles->session = WinHttpOpen(L"Fenrir-Agent/1.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!handles->session) {
    handles->session = WinHttpOpen(L"Fenrir-Agent/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  }
  if (!handles->session) {
    throw std::runtime_error("WinHttpOpen failed");
  }
  WinHttpSetTimeouts(handles->session, static_cast<int>(timeoutMs), static_cast<int>(timeoutMs), static_cast<int>(timeoutMs), 0);
  handles->connection = WinHttpConnect(handles->session, host, parts.nPort, 0);
  if (!handles->connection) {
    throw std::runtime_error("WinHttpConnect failed");
  }
  const std::wstring target = std::wstring(path) + extra;
  HINTERNET request = WinHttpOpenRequest(handles->connection, L"GET", target.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         secure ? WINHTTP_FLAG_SECURE : 0);
  if (!request) {
    throw std::runtime_error("WinHttpOpenRequest failed");
  }
  DWORD responseTimeout = timeoutMs;
  if (!WinHttpSetOption(request, WINHTTP_OPTION_RECEIVE_TIMEOUT, &responseTimeout, sizeof(responseTimeout)) ||
      !WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
    WinHttpCloseHandle(request);
    throw std::runtime_error("This version of Windows does not support WebSockets");
  }
  const BOOL sent = WinHttpSendRequest(request, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                                       headers.empty() ? 0 : static_cast<DWORD>(-1L), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
  if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
    WinHttpCloseHandle(request);
    throw std::runtime_error("The relay could not be reached");
  }
  DWORD status = 0, size = sizeof(status);
  WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                      WINHTTP_NO_HEADER_INDEX);
  if (status != 101) {
    WinHttpCloseHandle(request);
    throw std::runtime_error("The relay refused the connection (HTTP " + std::to_string(status) + ")");
  }
  // The upgrade response is bounded. Once upgraded an idle channel is valid;
  // its owner drives the keepalive and cancellation policy.
  DWORD idleTimeout = 0;
  if (!WinHttpSetOption(request, WINHTTP_OPTION_RECEIVE_TIMEOUT, &idleTimeout, sizeof(idleTimeout))) {
    WinHttpCloseHandle(request);
    throw std::runtime_error("Could not configure the upgraded WebSocket timeout");
  }
  handles->socket = WinHttpWebSocketCompleteUpgrade(request, 0);
  WinHttpCloseHandle(request);
  if (!handles->socket) {
    throw std::runtime_error("WebSocket upgrade failed");
  }
  std::lock_guard lock(stateMutex_);
  active_ = std::move(handles);
}

bool WebSocketClient::Send(const WINHTTP_WEB_SOCKET_BUFFER_TYPE type, const void* data, const std::size_t size) {
  std::lock_guard lock(sendMutex_);
  const auto handles = Current();
  if (!handles) {
    return false;
  }
  return WinHttpWebSocketSend(handles->socket, type, const_cast<void*>(data), static_cast<DWORD>(size)) == ERROR_SUCCESS;
}

bool WebSocketClient::SendText(const std::string& utf8) {
  return Send(WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, utf8.data(), utf8.size());
}

bool WebSocketClient::SendBinary(const void* data, const std::size_t size) {
  return Send(WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE, data, size);
}

bool WebSocketClient::Receive(std::string* message, bool* binary) {
  message->clear();
  std::vector<char> buffer(64 * 1024);
  const auto handles = Current();
  if (!handles) return false;
  for (;;) {
    DWORD read = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
    if (WinHttpWebSocketReceive(handles->socket, buffer.data(), static_cast<DWORD>(buffer.size()), &read, &type) != ERROR_SUCCESS) {
      return false;
    }
    if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
      return false;
    }
    message->append(buffer.data(), read);
    if (message->size() > 32 * 1024 * 1024) {
      return false;
    }
    if (type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
      *binary = type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
      return true;
    }
  }
}

void WebSocketClient::Close(const unsigned short status, const std::string& reason) {
  std::shared_ptr<Connection> handles;
  {
    std::lock_guard lock(stateMutex_);
    handles = std::move(active_);
  }
  if (handles) {
    WinHttpWebSocketClose(handles->socket, status, reason.empty() ? nullptr : const_cast<char*>(reason.data()),
                          static_cast<DWORD>(reason.size()));
  }
}

}  // namespace antivirus::agent
