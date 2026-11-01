#pragma once

// TCP tunnel streams for remote session routing (docs/REMOTE_PROTOCOL.md, channel "tunnel"): the helper connects to a
// private address on this PC's LAN and relays each stream over the session as binary 0x05 id:u32 frames.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace fenrir::remote {

class TunnelStreams {
 public:
  using SendText = std::function<bool(const std::string&)>;
  using SendBinary = std::function<bool(const char*, std::size_t)>;

  TunnelStreams(std::string host, int port, std::vector<int> allowedPorts, SendText sendText, SendBinary sendBinary);
  ~TunnelStreams();

  // A private (RFC 1918 / ULA) address and one of the allowed ports.
  static bool TargetAllowed(const std::string& host, int port, const std::vector<int>& allowedPorts);

  void Open(std::uint32_t id);
  void Close(std::uint32_t id, bool notify);
  void Data(const std::string& frame);  // 0x05 id:u32 payload, from the technician
  void CloseAll();

 private:
  void Pump(std::uint32_t id, std::uintptr_t socket);

  std::string host_;
  int port_;
  std::vector<int> allowedPorts_;
  SendText sendText_;
  SendBinary sendBinary_;
  std::mutex mutex_;
  std::map<std::uint32_t, std::uintptr_t> streams_;  // SOCKET values; ~0 while connecting
  bool winsock_{false};
};

}  // namespace fenrir::remote
