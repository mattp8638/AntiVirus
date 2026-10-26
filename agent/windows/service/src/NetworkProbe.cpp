#include <winsock2.h>
#include <ws2tcpip.h>

#include "NetworkProbe.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "ExtendedPolicy.h"

namespace antivirus::agent {
namespace {

constexpr std::size_t kMaxTargets = 100;
constexpr std::size_t kBatch = 60;  // below FD_SETSIZE (64)
constexpr auto kTimeout = std::chrono::seconds(2);

struct Probe {
  std::string monitorId;
  sockaddr_storage address{};
  int addressLength{0};
  SOCKET socket{INVALID_SOCKET};
  bool done{false};
  bool up{false};
  double latencyMs{0};
  std::string error;
};

std::string Escape(const std::string& value) {
  std::string out;
  for (const char ch : value) {
    if (ch == '"' || ch == '\\') {
      out += '\\';
      out += ch;
    } else if (static_cast<unsigned char>(ch) < 0x20) {
      out += ' ';
    } else {
      out += ch;
    }
  }
  return out;
}

bool AllowedTarget(const sockaddr_storage& address) {
  if (address.ss_family == AF_INET) {
    const auto* v4 = reinterpret_cast<const sockaddr_in*>(&address);
    const auto ip = ntohl(v4->sin_addr.s_addr);
    const auto first = ip >> 24;
    if (ip == 0 || first == 127 || (ip >> 16) == ((169u << 8) | 254u) || first >= 224) {
      return false;  // unspecified, loopback, link-local/metadata, multicast and reserved
    }
    return true;
  }
  if (address.ss_family == AF_INET6) {
    const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&address);
    const auto* b = v6->sin6_addr.s6_addr;
    static const unsigned char kZero[16] = {};
    unsigned char loopback[16] = {};
    loopback[15] = 1;
    if (std::memcmp(b, kZero, 16) == 0 || std::memcmp(b, loopback, 16) == 0) return false;
    if (b[0] == 0xff) return false;                              // multicast
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return false;     // link-local
    static const unsigned char kMapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (std::memcmp(b, kMapped, 12) == 0) return false;          // use the IPv4 form instead
    return true;
  }
  return false;
}

bool ParseTarget(const std::string& address, int port, sockaddr_storage* out, int* length) {
  std::memset(out, 0, sizeof(*out));
  auto* v4 = reinterpret_cast<sockaddr_in*>(out);
  if (inet_pton(AF_INET, address.c_str(), &v4->sin_addr) == 1) {
    v4->sin_family = AF_INET;
    v4->sin_port = htons(static_cast<u_short>(port));
    *length = sizeof(sockaddr_in);
    return true;
  }
  auto* v6 = reinterpret_cast<sockaddr_in6*>(out);
  if (inet_pton(AF_INET6, address.c_str(), &v6->sin6_addr) == 1) {
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(static_cast<u_short>(port));
    *length = sizeof(sockaddr_in6);
    return true;
  }
  return false;
}

void RunBatch(std::vector<Probe*>& batch) {
  const auto started = std::chrono::steady_clock::now();
  for (auto* probe : batch) {
    probe->socket = ::socket(probe->address.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (probe->socket == INVALID_SOCKET) {
      probe->done = true;
      probe->error = "socket failed";
      continue;
    }
    u_long nonBlocking = 1;
    ioctlsocket(probe->socket, FIONBIO, &nonBlocking);
    if (::connect(probe->socket, reinterpret_cast<const sockaddr*>(&probe->address), probe->addressLength) == 0) {
      probe->done = probe->up = true;
    } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
      probe->done = true;
      probe->error = "connect failed (" + std::to_string(WSAGetLastError()) + ")";
    }
  }
  for (;;) {
    const auto elapsed = std::chrono::steady_clock::now() - started;
    if (elapsed >= kTimeout) break;
    fd_set writable;
    fd_set failed;
    FD_ZERO(&writable);
    FD_ZERO(&failed);
    int pending = 0;
    for (auto* probe : batch) {
      if (!probe->done) {
        FD_SET(probe->socket, &writable);
        FD_SET(probe->socket, &failed);
        ++pending;
      }
    }
    if (pending == 0) break;
    const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(kTimeout - elapsed).count();
    timeval wait{static_cast<long>(remaining / 1000000), static_cast<long>(remaining % 1000000)};
    if (::select(0, nullptr, &writable, &failed, &wait) <= 0) break;
    const auto now = std::chrono::steady_clock::now();
    for (auto* probe : batch) {
      if (probe->done) continue;
      if (FD_ISSET(probe->socket, &writable) || FD_ISSET(probe->socket, &failed)) {
        int socketError = 0;
        int size = sizeof(socketError);
        getsockopt(probe->socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socketError), &size);
        probe->done = true;
        probe->up = socketError == 0 && FD_ISSET(probe->socket, &writable);
        if (probe->up) {
          probe->latencyMs = std::chrono::duration<double, std::milli>(now - started).count();
        } else {
          probe->error = socketError == WSAECONNREFUSED ? "connection refused" : "connect failed (" + std::to_string(socketError) + ")";
        }
      }
    }
  }
  for (auto* probe : batch) {
    if (!probe->done) {
      probe->done = true;
      probe->error = "timed out";
    }
    if (probe->socket != INVALID_SOCKET) {
      closesocket(probe->socket);
      probe->socket = INVALID_SOCKET;
    }
  }
}

}  // namespace

std::string RunNetworkProbe(const std::string& payloadUtf8) {
  const auto parsed = json::Parse(payloadUtf8);
  const auto* targets = parsed ? parsed->Get("targets") : nullptr;
  const auto* list = targets ? std::get_if<json::Array>(&targets->v) : nullptr;
  if (list == nullptr) {
    throw std::runtime_error("network.probe needs a targets list");
  }
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    throw std::runtime_error("Winsock could not start");
  }
  std::vector<Probe> probes;
  probes.reserve(std::min(list->size(), kMaxTargets));
  for (const auto& item : *list) {
    if (probes.size() >= kMaxTargets) break;
    Probe probe;
    probe.monitorId = item.Get("monitorId") ? item.Get("monitorId")->String().value_or("") : "";
    const auto address = item.Get("address") ? item.Get("address")->String().value_or("") : "";
    const auto port = item.Get("port") ? static_cast<int>(item.Get("port")->Number().value_or(0)) : 0;
    if (port < 1 || port > 65535 || !ParseTarget(address, port, &probe.address, &probe.addressLength) ||
        !AllowedTarget(probe.address)) {
      probe.done = true;
      probe.error = "target not allowed";
    }
    probes.push_back(std::move(probe));
  }
  std::vector<Probe*> batch;
  for (auto& probe : probes) {
    if (probe.done) continue;
    batch.push_back(&probe);
    if (batch.size() == kBatch) {
      RunBatch(batch);
      batch.clear();
    }
  }
  if (!batch.empty()) RunBatch(batch);
  WSACleanup();

  std::string out = "{\"results\":[";
  for (std::size_t i = 0; i < probes.size(); ++i) {
    const auto& probe = probes[i];
    if (i) out += ',';
    out += "{\"monitorId\":\"" + Escape(probe.monitorId) + "\",\"up\":" + (probe.up ? "true" : "false");
    if (probe.up) {
      char latency[32];
      std::snprintf(latency, sizeof(latency), "%.2f", probe.latencyMs);
      out += std::string(",\"latencyMs\":") + latency;
    } else {
      out += ",\"error\":\"" + Escape(probe.error) + "\"";
    }
    out += '}';
  }
  out += "]}";
  return out;
}

}  // namespace antivirus::agent
