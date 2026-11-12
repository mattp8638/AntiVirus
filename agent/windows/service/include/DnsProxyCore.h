#pragma once

// Local DNS proxy for Windows (policy dns.localProxy): the parts that do not touch the operating system, so they can
// be unit tested anywhere. DnsProxy.h has the sockets, the DoH client and the service integration.
//
// How it works on Windows:
//  - The agent answers DNS on 127.77.0.53 (UDP and TCP, port 53).
//  - One Name Resolution Policy Table rule for "." (comment "Fenrir DNS protection") sends every lookup made through
//    the Windows DNS client to that address. Adapter settings are not touched, so the network's own DNS servers stay
//    visible to the proxy for internal names and as the fallback, and new networks, Wi-Fi changes and VPNs need
//    nothing re-applied.
//  - Each lookup goes to the device's private DoH URL on Fenrir Cloud, which applies the policy and says what it
//    decided in X-Fenrir-Dns-Action. Blocked names are remembered, so they stay blocked offline.
//  - Internal names (the Active Directory domain, the network's DNS suffixes, single-label names, private reverse
//    zones, the Fenrir server itself and the policy's local domains) go to the network's own DNS servers.

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace antivirus::agent::dnsproxy {

using Bytes = std::vector<std::uint8_t>;

constexpr char kListenAddress[] = "127.77.0.53";
constexpr char kRuleComment[] = "Fenrir DNS protection";
// Answered by the proxy itself (NXDOMAIN), never forwarded: the watchdog and the self-test use it.
constexpr char kHealthName[] = "health.fenrir-dns-proxy.invalid";

constexpr std::uint8_t kFormErr = 1, kServFail = 2, kNxDomain = 3, kRefused = 5;
constexpr std::uint16_t kTypeA = 1, kTypeAAAA = 28, kTypeOpt = 41;

struct Settings {
  bool enabled{false};     // dns.enabled && dns.localProxy
  bool failClosed{false};  // dns.localProxyFailMode == "closed"
  int cacheMinutes{30};    // dns.localCacheMinutes
  std::vector<std::string> localDomains;  // dns.localDomains: always sent to the network's own DNS
};

Settings Parse(const std::string& modulesJson);

struct Question {
  std::string name;  // lower case, no trailing dot ("" for the root)
  std::uint16_t type{0};
  std::uint16_t qclass{0};
  std::size_t end{0};  // offset just after the question
};

// A standard query with exactly one question; nullopt for anything else (replies, malformed messages).
std::optional<Question> ParseQuestion(const Bytes& message);

// An answer with no records and the given response code, echoing the question when it can be read.
Bytes ErrorReply(const Bytes& query, std::uint8_t rcode);
// A blocked name answered offline from the cache: A 0.0.0.0, AAAA ::, other types an empty answer.
Bytes BlockedReply(const Bytes& query, const Question& question);
// reply with the query's transaction ID (cached answers were stored under another ID).
Bytes WithId(const Bytes& reply, const Bytes& query);
// The smallest TTL among the answers, capped at 300 seconds; 0 when the reply has no usable answers.
int MinAnswerTtl(const Bytes& reply);
// The largest UDP reply the client accepts: its EDNS buffer size (512..4096), or 512 without EDNS.
std::size_t MaxUdpSize(const Bytes& query);
// A reply too large for the client over UDP becomes header + question with the TC bit, so the client retries on TCP.
Bytes TruncateForUdp(const Bytes& reply, const Bytes& query);
bool IsTruncated(const Bytes& reply);

std::string Normalise(std::string domain);
// name is suffix itself or ends in "." + suffix.
bool MatchesSuffix(const std::string& name, const std::vector<std::string>& suffixes);
// Reverse lookups for private, loopback and link-local addresses (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16,
// fc00::/7, fe80::/10, ::1): only the local network can answer them.
bool IsPrivateReverseName(const std::string& name);
// Names that never belong on the internet: single labels, .local, .lan, .home.arpa, .internal, .localdomain, wpad.
bool IsLocalOnlyName(const std::string& name);

// Domains the cloud blocked, remembered for the policy's cache time so they stay blocked offline.
class VerdictCache {
 public:
  using Clock = std::chrono::steady_clock;
  void Block(const std::string& domain, const std::string& reason, std::chrono::seconds ttl, Clock::time_point now = Clock::now());
  void Allow(const std::string& domain);  // the cloud now allows it: forget an earlier block
  std::optional<std::string> Blocked(const std::string& domain, Clock::time_point now = Clock::now());  // reason
  std::size_t Size();

 private:
  struct Entry { std::string reason; Clock::time_point expires; };
  std::mutex mutex_;
  std::map<std::string, Entry> entries_;
};

// Answers by name and type for their TTL (at most 5 minutes), so repeated lookups do not go to the cloud each time.
class AnswerCache {
 public:
  using Clock = std::chrono::steady_clock;
  void Put(const std::string& name, std::uint16_t type, const Bytes& reply, int ttlSeconds, Clock::time_point now = Clock::now());
  std::optional<Bytes> Get(const std::string& name, std::uint16_t type, Clock::time_point now = Clock::now());
  void Clear();

 private:
  struct Entry { Bytes reply; Clock::time_point expires; };
  std::mutex mutex_;
  std::map<std::string, Entry> entries_;
};

// PowerShell that adds the NRPT rule (replacing an older Fenrir rule) and prints {"ok":..,"reason":..} as JSON.
// It refuses when Group Policy manages the NRPT (local rules would be ignored) and reports it.
std::string BuildApplyScript();
// PowerShell that removes every Fenrir NRPT rule and flushes the DNS cache; prints {"ok":..,"removed":n}.
std::string BuildRemoveScript();

}  // namespace antivirus::agent::dnsproxy
