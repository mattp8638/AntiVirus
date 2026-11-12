#pragma once

// The Windows local DNS proxy's runtime (see DnsProxyCore.h for how it works): UDP and TCP listeners on
// 127.77.0.53:53, a small worker pool, DNS over HTTPS to the device's Fenrir resolver through WinHTTP, and the
// network's own DNS servers for internal names and as the fail-open fallback.

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "DnsProxyCore.h"

namespace antivirus::agent::dnsproxy {

struct Options {
  std::wstring dohUrl;  // https://server/dns/<token>/dns-query
  std::wstring apiKey;  // sent as X-Device-Api-Key
  bool failClosed{false};
  int cacheMinutes{30};
  std::vector<std::string> localDomains;
  std::string listenAddress{kListenAddress};
  unsigned short port{53};
  // A lookup answered from the local block cache (the cloud did not see it). At most once per domain per 10 minutes.
  std::function<void(const std::string& domain, const std::string& reason)> onCachedBlock;
};

struct Stats {
  long long queries{0}, cloud{0}, network{0}, cachedBlocks{0}, fallback{0}, refused{0}, failures{0};
};

class Proxy {
 public:
  explicit Proxy(Options options);
  ~Proxy();
  Proxy(const Proxy&) = delete;
  Proxy& operator=(const Proxy&) = delete;

  // Binds the listeners and starts the workers. false (with a reason) if the address is in use or WinHTTP fails.
  bool Start(std::string* error);
  void Stop();
  // Answers one query (also used directly by tests).
  Bytes Resolve(const Bytes& query, bool overTcp);
  Stats Snapshot() const;

 private:
  struct CloudAnswer { Bytes reply; std::string action, reason; };
  struct NetworkInfo { std::vector<std::vector<unsigned char>> servers; std::vector<std::string> suffixes; long long at{0}; };

  void UdpLoop();
  void TcpLoop();
  void WorkerLoop();
  bool Enqueue(std::function<void()> task);
  void ServeTcp(std::uintptr_t client);
  bool AskCloud(const Bytes& query, CloudAnswer* answer);
  bool AskNetwork(const Bytes& query, bool overTcp, Bytes* reply);
  bool IsLocal(const std::string& name);
  NetworkInfo Network();
  void ReportCachedBlock(const std::string& domain, const std::string& reason);

  Options options_;
  std::wstring dohHost_, dohPath_;
  unsigned short dohPort_{443};
  bool dohSecure_{true};
  void* session_{nullptr};
  void* connection_{nullptr};
  std::uintptr_t udp_{~std::uintptr_t{0}}, tcp_{~std::uintptr_t{0}};
  std::atomic<bool> stopping_{false};
  bool started_{false};
  std::thread udpThread_, tcpThread_;
  std::vector<std::thread> workers_;
  std::mutex queueMutex_;
  std::condition_variable queueReady_;
  std::deque<std::function<void()>> queue_;
  std::mutex clientsMutex_;
  std::vector<std::uintptr_t> tcpClients_;
  std::mutex networkMutex_;
  NetworkInfo network_;
  std::atomic<long long> cloudDownUntil_{0};
  std::mutex reportMutex_;
  std::map<std::string, long long> reported_;
  VerdictCache verdicts_;
  AnswerCache answers_;
  mutable std::mutex statsMutex_;
  Stats stats_;
};

// Sends the health query to address:port; true when the proxy answers within timeoutMs.
bool Probe(const std::string& address, unsigned short port, int timeoutMs);
// Domain controllers and Windows DNS servers answer DNS themselves; the proxy is not used on them.
bool IsDomainControllerOrDnsServer();

}  // namespace antivirus::agent::dnsproxy
