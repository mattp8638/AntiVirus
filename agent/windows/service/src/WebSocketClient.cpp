#include "WebSocketClient.h"

#include <stdexcept>

namespace antivirus::agent {

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
  session_ = WinHttpOpen(L"Fenrir-Agent/1.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!session_) {
    session_ = WinHttpOpen(L"Fenrir-Agent/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  }
  if (!session_) {
    throw std::runtime_error("WinHttpOpen failed");
  }
  WinHttpSetTimeouts(session_, static_cast<int>(timeoutMs), static_cast<int>(timeoutMs), static_cast<int>(timeoutMs), 0);
  connection_ = WinHttpConnect(session_, host, parts.nPort, 0);
  if (!connection_) {
    Close();
    throw std::runtime_error("WinHttpConnect failed");
  }
  const std::wstring target = std::wstring(path) + extra;
  HINTERNET request = WinHttpOpenRequest(connection_, L"GET", target.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         secure ? WINHTTP_FLAG_SECURE : 0);
  if (!request) {
    Close();
    throw std::runtime_error("WinHttpOpenRequest failed");
  }
  if (!WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
    WinHttpCloseHandle(request);
    Close();
    throw std::runtime_error("This version of Windows does not support WebSockets");
  }
  const BOOL sent = WinHttpSendRequest(request, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                                       headers.empty() ? 0 : static_cast<DWORD>(-1L), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
  if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
    WinHttpCloseHandle(request);
    Close();
    throw std::runtime_error("The relay could not be reached");
  }
  DWORD status = 0, size = sizeof(status);
  WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                      WINHTTP_NO_HEADER_INDEX);
  if (status != 101) {
    WinHttpCloseHandle(request);
    Close();
    throw std::runtime_error("The relay refused the connection (HTTP " + std::to_string(status) + ")");
  }
  socket_ = WinHttpWebSocketCompleteUpgrade(request, 0);
  WinHttpCloseHandle(request);
  if (!socket_) {
    Close();
    throw std::runtime_error("WebSocket upgrade failed");
  }
}

bool WebSocketClient::Send(const WINHTTP_WEB_SOCKET_BUFFER_TYPE type, const void* data, const std::size_t size) {
  std::lock_guard lock(sendMutex_);
  if (!socket_) {
    return false;
  }
  return WinHttpWebSocketSend(socket_, type, const_cast<void*>(data), static_cast<DWORD>(size)) == ERROR_SUCCESS;
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
  for (;;) {
    if (!socket_) {
      return false;
    }
    DWORD read = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
    if (WinHttpWebSocketReceive(socket_, buffer.data(), static_cast<DWORD>(buffer.size()), &read, &type) != ERROR_SUCCESS) {
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
  if (socket_) {
    WinHttpWebSocketClose(socket_, status, reason.empty() ? nullptr : const_cast<char*>(reason.data()), static_cast<DWORD>(reason.size()));
    WinHttpCloseHandle(socket_);
    socket_ = nullptr;
  }
  if (connection_) {
    WinHttpCloseHandle(connection_);
    connection_ = nullptr;
  }
  if (session_) {
    WinHttpCloseHandle(session_);
    session_ = nullptr;
  }
}

}  // namespace antivirus::agent
