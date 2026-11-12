// Portable tests for the Windows local DNS proxy's message handling, caches, settings and rule scripts.
#include "DnsProxyCore.h"

#include <iostream>
#include <stdexcept>
#include <string>

using namespace antivirus::agent::dnsproxy;

namespace {

void Check(bool condition, const std::string& reason) {
  if (!condition) throw std::runtime_error(reason);
}

Bytes Query(const std::string& name, std::uint16_t type, int ednsSize = 0, std::uint16_t id = 0x1234) {
  Bytes m{static_cast<std::uint8_t>(id >> 8), static_cast<std::uint8_t>(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0,
          static_cast<std::uint8_t>(ednsSize ? 1 : 0)};
  std::size_t start = 0;
  while (start < name.size()) {
    auto dot = name.find('.', start);
    if (dot == std::string::npos) dot = name.size();
    m.push_back(static_cast<std::uint8_t>(dot - start));
    for (auto i = start; i < dot; ++i) m.push_back(static_cast<std::uint8_t>(name[i]));
    start = dot + 1;
  }
  m.push_back(0);
  m.push_back(static_cast<std::uint8_t>(type >> 8));
  m.push_back(static_cast<std::uint8_t>(type & 0xFF));
  m.push_back(0);
  m.push_back(1);
  if (ednsSize) {
    m.insert(m.end(), {0, 0, 41, static_cast<std::uint8_t>(ednsSize >> 8), static_cast<std::uint8_t>(ednsSize & 0xFF), 0, 0, 0, 0, 0, 0});
  }
  return m;
}

// A reply to query with one A record per address, each with the given TTL.
Bytes Reply(const Bytes& query, int records, std::uint32_t ttl) {
  const auto q = *ParseQuestion(query);
  Bytes m(query.begin(), query.begin() + static_cast<std::ptrdiff_t>(q.end));
  m[2] = 0x81;
  m[3] = 0x80;
  m[7] = static_cast<std::uint8_t>(records);
  m[11] = 0;
  for (int i = 0; i < records; ++i) {
    m.insert(m.end(), {0xC0, 0x0C, 0, 1, 0, 1, static_cast<std::uint8_t>(ttl >> 24), static_cast<std::uint8_t>(ttl >> 16),
                       static_cast<std::uint8_t>(ttl >> 8), static_cast<std::uint8_t>(ttl), 0, 4, 192, 0, 2,
                       static_cast<std::uint8_t>(i)});
  }
  return m;
}

}  // namespace

int main() {
  try {
    // Questions
    const auto q = Query("Login.Example.COM", kTypeA);
    const auto parsed = ParseQuestion(q);
    Check(parsed && parsed->name == "login.example.com" && parsed->type == kTypeA && parsed->end == q.size(), "question parsed");
    auto reply = q;
    reply[2] |= 0x80;
    Check(!ParseQuestion(reply), "a reply is not a query");
    Check(!ParseQuestion(Bytes(5, 0)), "short message refused");
    auto twoQuestions = q;
    twoQuestions[5] = 2;
    Check(!ParseQuestion(twoQuestions), "two questions refused");
    auto truncated = q;
    truncated.resize(q.size() - 3);
    Check(!ParseQuestion(truncated), "truncated question refused");
    auto pointer = q;
    pointer[12] = 0xC0;
    Check(!ParseQuestion(pointer), "compression in a question refused");

    // Synthetic answers
    const auto refused = ErrorReply(q, kRefused);
    Check(refused.size() == q.size() && refused[0] == 0x12 && refused[1] == 0x34 && (refused[2] & 0x80) && (refused[3] & 0x0F) == kRefused,
          "error reply keeps ID and question");
    Check(ErrorReply(Bytes(3, 0), kServFail).empty(), "tiny input gives no reply");
    const auto blockedA = BlockedReply(q, *parsed);
    Check(blockedA[7] == 1 && blockedA.size() == q.size() + 16 && blockedA[blockedA.size() - 1] == 0, "blocked A answers 0.0.0.0");
    const auto qAAAA = Query("bad.test", kTypeAAAA);
    const auto blockedAAAA = BlockedReply(qAAAA, *ParseQuestion(qAAAA));
    Check(blockedAAAA[7] == 1 && blockedAAAA.size() == qAAAA.size() + 28, "blocked AAAA answers ::");
    const auto qTxt = Query("bad.test", 16);
    Check(BlockedReply(qTxt, *ParseQuestion(qTxt))[7] == 0, "blocked TXT answers empty");

    // IDs and TTLs
    const auto answer = Reply(q, 2, 120);
    const auto other = Query("login.example.com", kTypeA, 0, 0x9999);
    const auto rewritten = WithId(answer, other);
    Check(rewritten[0] == 0x99 && rewritten[1] == 0x99 && rewritten.size() == answer.size(), "cached answer gets the new ID");
    Check(MinAnswerTtl(answer) == 120, "minimum TTL read");
    Check(MinAnswerTtl(Reply(q, 1, 86400)) == 300, "TTL capped at five minutes");
    Check(MinAnswerTtl(Reply(q, 0, 60)) == 0, "no answers, no TTL");
    Check(MinAnswerTtl(ErrorReply(q, kNxDomain)) == 0, "error replies are not cached");

    // UDP sizes and truncation
    Check(MaxUdpSize(q) == 512, "no EDNS: 512");
    Check(MaxUdpSize(Query("a.test", kTypeA, 1232)) == 1232, "EDNS size honoured");
    Check(MaxUdpSize(Query("a.test", kTypeA, 100)) == 512, "EDNS size at least 512");
    Check(MaxUdpSize(Query("a.test", kTypeA, 65000)) == 4096, "EDNS size at most 4096");
    const auto big = Reply(q, 40, 60);
    Check(big.size() > 512, "big reply built");
    const auto cut = TruncateForUdp(big, q);
    Check(IsTruncated(cut) && cut.size() == q.size() && cut[7] == 0, "too big for UDP: TC with the question only");
    Check(!IsTruncated(TruncateForUdp(big, Query("login.example.com", kTypeA, 4096))), "fits the EDNS buffer: unchanged");

    // Names
    Check(Normalise(" Example.COM. ") == "example.com", "normalised");
    Check(MatchesSuffix("dc1.corp.example", {"corp.example"}) && MatchesSuffix("corp.example", {"corp.example"}), "suffix matches");
    Check(!MatchesSuffix("evilcorp.example", {"corp.example"}), "suffix needs a dot boundary");
    Check(IsPrivateReverseName("4.3.2.10.in-addr.arpa") && IsPrivateReverseName("1.1.168.192.in-addr.arpa"), "private v4 reverse");
    Check(IsPrivateReverseName("9.9.20.172.in-addr.arpa") && !IsPrivateReverseName("9.9.32.172.in-addr.arpa"), "172.16/12 only");
    Check(!IsPrivateReverseName("8.8.8.8.in-addr.arpa"), "public reverse goes to the cloud");
    Check(IsPrivateReverseName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"), "::1 reverse");
    Check(IsPrivateReverseName("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa"), "fe80 reverse");
    Check(!IsPrivateReverseName("8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.6.8.4.1.0.0.2.ip6.arpa"), "public v6 reverse");
    Check(IsLocalOnlyName("fileserver") && IsLocalOnlyName("printer.local") && IsLocalOnlyName("nas.home.arpa"), "local-only names");
    Check(IsLocalOnlyName("wpad.corp.example") && !IsLocalOnlyName("www.example.com"), "wpad local, internet names not");

    // Caches
    using Clock = std::chrono::steady_clock;
    const auto now = Clock::now();
    VerdictCache verdicts;
    verdicts.Block("bad.test", "malware", std::chrono::seconds(60), now);
    Check(verdicts.Blocked("bad.test", now + std::chrono::seconds(30)) == std::optional<std::string>("malware"), "block remembered");
    Check(!verdicts.Blocked("bad.test", now + std::chrono::seconds(61)), "block expires");
    verdicts.Block("bad.test", "malware", std::chrono::seconds(60), now);
    verdicts.Allow("bad.test");
    Check(!verdicts.Blocked("bad.test", now), "allow forgets the block");
    AnswerCache answers;
    answers.Put("login.example.com", kTypeA, answer, 120, now);
    Check(answers.Get("login.example.com", kTypeA, now + std::chrono::seconds(100)).has_value(), "answer cached");
    Check(!answers.Get("login.example.com", kTypeAAAA, now).has_value(), "per type");
    Check(!answers.Get("login.example.com", kTypeA, now + std::chrono::seconds(121)).has_value(), "answer expires");
    answers.Put("x.test", kTypeA, answer, 0, now);
    Check(!answers.Get("x.test", kTypeA, now).has_value(), "TTL 0 not cached");

    // Settings
    Check(!Parse("{}").enabled && !Parse("not json").enabled, "off without a dns section");
    const auto on = Parse(R"({"dns":{"enabled":true,"localProxy":true,"localProxyFailMode":"closed","localCacheMinutes":5000,)"
                          R"("localDomains":["Corp.Example.","*.branch.example",""]}})");
    Check(on.enabled && on.failClosed && on.cacheMinutes == 1440, "settings parsed and clamped");
    Check(on.localDomains.size() == 2 && on.localDomains[0] == "corp.example" && on.localDomains[1] == "branch.example", "local domains cleaned");
    Check(!Parse(R"({"dns":{"enabled":false,"localProxy":true}})").enabled, "DNS protection off turns the proxy off");
    Check(!Parse(R"({"dns":{"enabled":true}})").enabled, "the proxy is off by default");

    // Scripts
    const auto apply = BuildApplyScript();
    Check(apply.find("Add-DnsClientNrptRule -Namespace '.' -NameServers '127.77.0.53' -Comment 'Fenrir DNS protection'") != std::string::npos,
          "apply adds the catch-all rule");
    Check(apply.find("DnsPolicyConfig") != std::string::npos, "apply checks for Group Policy NRPT");
    const auto remove = BuildRemoveScript();
    Check(remove.find("Remove-DnsClientNrptRule") != std::string::npos && remove.find("'Fenrir DNS protection'") != std::string::npos,
          "remove deletes only Fenrir's rules");

    std::cout << "DNS proxy tests passed (wire format, truncation, local names, caches, settings, rule scripts).\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
