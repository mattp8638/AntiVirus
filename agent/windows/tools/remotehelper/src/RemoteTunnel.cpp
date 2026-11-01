#include <winsock2.h>
#include <ws2tcpip.h>

#include "RemoteTunnel.h"

#include <cstring>
#include <thread>

namespace fenrir::remote {
namespace {

constexpr std::size_t kMaxStreams = 32;
constexpr std::uintptr_t kConnecting = ~static_cast<std::uintptr_t>(0);
constexpr int kChunk = 32 * 1024;

std::string Json(const char* type, std::uint32_t id, const std::string& message = {}) {
  std::string out = std::string("{\"ch\":\"tunnel\",\"t\":\"") + type + "\",\"id\":" + std::to_string(id);
  if (!message.empty()) {
    out += ",\"message\":\"";
    for (const char c : message) {
      if (c == '"' || c == '\\') out += '\\';
      out += static_cast<unsigned char>(c) < 0x20 ? ' ' : c;
    }
    out += '"';
  }
  return out + "}";
}

}  // namespace

TunnelStreams::TunnelStreams(std::string host, int port, std::vector<int> allowedPorts, SendText sendText, SendBinary sendBinary)
    : host_(std::move(host)), port_(port), allowedPorts_(std::move(allowedPorts)), sendText_(std::move(sendText)),
      sendBinary_(std::move(sendBinary)) {
  WSADATA wsa{};
  winsock_ = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}

TunnelStreams::~TunnelStreams() {
  CloseAll();
  if (winsock_) WSACleanup();
}

bool TunnelStreams::TargetAllowed(const std::string& host, int port, const std::vector<int>& allowedPorts) {
  bool portOk = false;
  for (const int allowed : allowedPorts) portOk = portOk || allowed == port;
  if (!portOk) return false;
  in_addr v4{};
  if (inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    const auto ip = ntohl(v4.s_addr);
    return (ip >> 24) == 10 || (ip >> 20) == ((172u << 4) | 1u) || (ip >> 16) == ((192u << 8) | 168u);
  }
  in6_addr v6{};
  if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
    return (v6.s6_addr[0] & 0xfe) == 0xfc;  // unique local fc00::/7
  }
  return false;  // names are not resolved: the console sends the address it discovered
}

void TunnelStreams::Open(std::uint32_t id) {
  if (!winsock_ || !TargetAllowed(host_, port_, allowedPorts_)) {
    sendText_(Json("error", id, "This tunnel target is not allowed on this device"));
    return;
  }
  {
    std::lock_guard lock(mutex_);
    if (streams_.count(id) || streams_.size() >= kMaxStreams) {
      sendText_(Json("error", id, "stream id in use or too many streams"));
      return;
    }
    streams_[id] = kConnecting;
  }
  std::thread([this, id] {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    addrinfo* found = nullptr;
    SOCKET s = INVALID_SOCKET;
    if (getaddrinfo(host_.c_str(), std::to_string(port_).c_str(), &hints, &found) == 0 && found) {
      s = socket(found->ai_family, SOCK_STREAM, IPPROTO_TCP);
      if (s != INVALID_SOCKET && connect(s, found->ai_addr, static_cast<int>(found->ai_addrlen)) != 0) {
        closesocket(s);
        s = INVALID_SOCKET;
      }
      freeaddrinfo(found);
    }
    {
      std::lock_guard lock(mutex_);
      auto it = streams_.find(id);
      if (s == INVALID_SOCKET || it == streams_.end()) {
        if (it != streams_.end()) streams_.erase(it);
        if (s != INVALID_SOCKET) closesocket(s);
        sendText_(Json("error", id, "Could not connect to " + host_ + ":" + std::to_string(port_)));
        return;
      }
      it->second = static_cast<std::uintptr_t>(s);
    }
    sendText_(Json("opened", id));
    Pump(id, static_cast<std::uintptr_t>(s));
  }).detach();
}

void TunnelStreams::Pump(std::uint32_t id, std::uintptr_t socketValue) {
  const auto s = static_cast<SOCKET>(socketValue);
  std::vector<char> buffer(5 + kChunk);
  buffer[0] = 0x05;
  buffer[1] = static_cast<char>(id >> 24);
  buffer[2] = static_cast<char>(id >> 16);
  buffer[3] = static_cast<char>(id >> 8);
  buffer[4] = static_cast<char>(id);
  for (;;) {
    const int read = recv(s, buffer.data() + 5, kChunk, 0);
    if (read <= 0 || !sendBinary_(buffer.data(), 5 + static_cast<std::size_t>(read))) break;
  }
  Close(id, true);
}

void TunnelStreams::Data(const std::string& frame) {
  if (frame.size() <= 5) return;
  const std::uint32_t id = (static_cast<std::uint8_t>(frame[1]) << 24) | (static_cast<std::uint8_t>(frame[2]) << 16) |
                           (static_cast<std::uint8_t>(frame[3]) << 8) | static_cast<std::uint8_t>(frame[4]);
  SOCKET s = INVALID_SOCKET;
  {
    std::lock_guard lock(mutex_);
    const auto it = streams_.find(id);
    if (it == streams_.end() || it->second == kConnecting) return;
    s = static_cast<SOCKET>(it->second);
  }
  const char* data = frame.data() + 5;
  int left = static_cast<int>(frame.size() - 5);
  while (left > 0) {
    const int sent = send(s, data, left, 0);
    if (sent <= 0) {
      Close(id, true);
      return;
    }
    data += sent;
    left -= sent;
  }
}

void TunnelStreams::Close(std::uint32_t id, bool notify) {
  std::uintptr_t value = 0;
  {
    std::lock_guard lock(mutex_);
    const auto it = streams_.find(id);
    if (it == streams_.end()) return;
    value = it->second;
    streams_.erase(it);
  }
  if (value != kConnecting) {
    shutdown(static_cast<SOCKET>(value), SD_BOTH);
    closesocket(static_cast<SOCKET>(value));
  }
  if (notify) sendText_(Json("close", id));
}

void TunnelStreams::CloseAll() {
  std::vector<std::uint32_t> ids;
  {
    std::lock_guard lock(mutex_);
    for (const auto& [id, value] : streams_) ids.push_back(id);
  }
  for (const auto id : ids) Close(id, false);
}

}  // namespace fenrir::remote
