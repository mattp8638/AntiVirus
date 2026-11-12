#include "DnsProxyCore.h"

#include <algorithm>
#include <cctype>

#include "ExtendedPolicy.h"

namespace antivirus::agent::dnsproxy {
namespace {

std::uint16_t Read16(const Bytes& m, std::size_t i) { return static_cast<std::uint16_t>((m[i] << 8) | m[i + 1]); }

void Write16(Bytes& m, std::size_t i, std::uint16_t v) {
  m[i] = static_cast<std::uint8_t>(v >> 8);
  m[i + 1] = static_cast<std::uint8_t>(v & 0xFF);
}

void Append16(Bytes& m, std::uint16_t v) {
  m.push_back(static_cast<std::uint8_t>(v >> 8));
  m.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void Append32(Bytes& m, std::uint32_t v) {
  for (int shift = 24; shift >= 0; shift -= 8) m.push_back(static_cast<std::uint8_t>((v >> shift) & 0xFF));
}

// Offset after a (possibly compressed) name starting at i, or nullopt.
std::optional<std::size_t> SkipName(const Bytes& m, std::size_t i) {
  for (int labels = 0; i < m.size() && labels < 128; ++labels) {
    const auto length = m[i];
    if (length == 0) return i + 1;
    if ((length & 0xC0) == 0xC0) return i + 2 <= m.size() ? std::optional<std::size_t>(i + 2) : std::nullopt;
    if ((length & 0xC0) != 0) return std::nullopt;
    i += 1 + length;
  }
  return std::nullopt;
}

Bytes Header(const Bytes& query, std::uint8_t rcode, std::uint16_t answers, bool withQuestion) {
  Bytes h(12, 0);
  h[0] = query[0];
  h[1] = query[1];
  h[2] = static_cast<std::uint8_t>(0x80 | (query[2] & 0x79));  // QR, keep opcode and RD
  h[3] = static_cast<std::uint8_t>(0x80 | (rcode & 0x0F));     // RA
  Write16(h, 4, withQuestion ? 1 : 0);
  Write16(h, 6, answers);
  return h;
}

std::string StringOr(const json::Value* section, const char* key, const std::string& fallback) {
  if (!section) return fallback;
  const auto* value = section->Get(key);
  return value ? value->String().value_or(fallback) : fallback;
}

bool BoolOr(const json::Value* section, const char* key, bool fallback) {
  if (!section) return fallback;
  const auto* value = section->Get(key);
  return value ? value->Bool().value_or(fallback) : fallback;
}

bool AllDigits(const std::string& value) {
  return !value.empty() && value.size() <= 3 && std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c); });
}

std::vector<std::string> Split(const std::string& name) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start <= name.size()) {
    const auto dot = name.find('.', start);
    out.push_back(name.substr(start, dot == std::string::npos ? std::string::npos : dot - start));
    if (dot == std::string::npos) break;
    start = dot + 1;
  }
  return out;
}

}  // namespace

Settings Parse(const std::string& modulesJson) {
  Settings settings;
  const auto root = json::Parse(modulesJson);
  if (!root || !root->IsObject()) return settings;
  const auto* dns = root->Get("dns");
  if (!dns || !dns->IsObject()) return settings;
  settings.enabled = BoolOr(dns, "enabled", true) && BoolOr(dns, "localProxy", false);
  settings.failClosed = StringOr(dns, "localProxyFailMode", "open") == "closed";
  if (const auto* minutes = dns->Get("localCacheMinutes")) {
    if (const auto value = minutes->Number()) settings.cacheMinutes = std::clamp(static_cast<int>(*value), 1, 1440);
  }
  if (const auto* domains = dns->Get("localDomains")) {
    for (const auto& domain : domains->Strings()) {
      auto clean = Normalise(domain);
      if (clean.rfind("*.", 0) == 0) clean = clean.substr(2);
      if (!clean.empty() && clean.size() <= 253) settings.localDomains.push_back(clean);
    }
  }
  return settings;
}

std::optional<Question> ParseQuestion(const Bytes& m) {
  if (m.size() < 12 || (m[2] & 0x80) != 0 || ((m[2] >> 3) & 0x0F) != 0 || Read16(m, 4) != 1) return std::nullopt;
  std::string name;
  std::size_t i = 12;
  for (;;) {
    if (i >= m.size()) return std::nullopt;
    const auto length = m[i];
    if (length == 0) {
      ++i;
      break;
    }
    if ((length & 0xC0) != 0 || i + 1 + length > m.size()) return std::nullopt;
    if (!name.empty()) name += '.';
    for (std::size_t k = i + 1; k < i + 1 + length; ++k) name += static_cast<char>(std::tolower(m[k]));
    i += 1 + length;
    if (name.size() > 253) return std::nullopt;
  }
  if (i + 4 > m.size()) return std::nullopt;
  return Question{name, Read16(m, i), Read16(m, i + 2), i + 4};
}

Bytes ErrorReply(const Bytes& query, std::uint8_t rcode) {
  if (query.size() < 12) return {};
  const auto question = ParseQuestion(query);
  auto out = Header(query, rcode, 0, question.has_value());
  if (question) out.insert(out.end(), query.begin() + 12, query.begin() + static_cast<std::ptrdiff_t>(question->end));
  return out;
}

Bytes BlockedReply(const Bytes& query, const Question& question) {
  Bytes rdata;
  if (question.type == kTypeA) rdata.assign(4, 0);
  if (question.type == kTypeAAAA) rdata.assign(16, 0);
  auto out = Header(query, 0, rdata.empty() ? 0 : 1, true);
  out.insert(out.end(), query.begin() + 12, query.begin() + static_cast<std::ptrdiff_t>(question.end));
  if (!rdata.empty()) {
    out.push_back(0xC0);
    out.push_back(0x0C);
    Append16(out, question.type);
    Append16(out, 1);
    Append32(out, 60);
    Append16(out, static_cast<std::uint16_t>(rdata.size()));
    out.insert(out.end(), rdata.begin(), rdata.end());
  }
  return out;
}

Bytes WithId(const Bytes& reply, const Bytes& query) {
  auto out = reply;
  if (out.size() >= 2 && query.size() >= 2) {
    out[0] = query[0];
    out[1] = query[1];
  }
  return out;
}

int MinAnswerTtl(const Bytes& m) {
  if (m.size() < 12 || (m[3] & 0x0F) != 0 || Read16(m, 4) != 1) return 0;
  const auto answers = Read16(m, 6);
  if (answers == 0) return 0;
  auto i = SkipName(m, 12);
  if (!i || *i + 4 > m.size()) return 0;
  std::size_t at = *i + 4;
  std::uint32_t minimum = 300;
  for (int n = 0; n < answers; ++n) {
    const auto end = SkipName(m, at);
    if (!end || *end + 10 > m.size()) return 0;
    const std::uint32_t ttl = (static_cast<std::uint32_t>(m[*end + 4]) << 24) | (static_cast<std::uint32_t>(m[*end + 5]) << 16) |
                              (static_cast<std::uint32_t>(m[*end + 6]) << 8) | m[*end + 7];
    minimum = std::min(minimum, ttl);
    at = *end + 10 + Read16(m, *end + 8);
    if (at > m.size()) return 0;
  }
  return static_cast<int>(minimum);
}

std::size_t MaxUdpSize(const Bytes& m) {
  const auto question = ParseQuestion(m);
  if (!question) return 512;
  std::size_t at = question->end;
  const int records = Read16(m, 6) + Read16(m, 8) + Read16(m, 10);
  for (int n = 0; n < records && n < 16; ++n) {
    const auto end = SkipName(m, at);
    if (!end || *end + 10 > m.size()) break;
    if (Read16(m, *end) == kTypeOpt) {
      return std::clamp<std::size_t>(Read16(m, *end + 2), 512, 4096);
    }
    at = *end + 10 + Read16(m, *end + 8);
  }
  return 512;
}

Bytes TruncateForUdp(const Bytes& reply, const Bytes& query) {
  if (reply.size() <= MaxUdpSize(query) || reply.size() < 12) return reply;
  const auto question = ParseQuestion(query);
  Bytes out(reply.begin(), reply.begin() + 12);
  out[2] |= 0x02;  // TC
  Write16(out, 4, question ? 1 : 0);
  Write16(out, 6, 0);
  Write16(out, 8, 0);
  Write16(out, 10, 0);
  if (question) out.insert(out.end(), query.begin() + 12, query.begin() + static_cast<std::ptrdiff_t>(question->end));
  return out;
}

bool IsTruncated(const Bytes& reply) { return reply.size() >= 12 && (reply[2] & 0x02) != 0; }

std::string Normalise(std::string domain) {
  domain.erase(0, domain.find_first_not_of(" \t"));
  while (!domain.empty() && (domain.back() == '.' || domain.back() == ' ' || domain.back() == '\t')) domain.pop_back();
  std::transform(domain.begin(), domain.end(), domain.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return domain;
}

bool MatchesSuffix(const std::string& name, const std::vector<std::string>& suffixes) {
  for (const auto& suffix : suffixes) {
    if (suffix.empty()) continue;
    if (name == suffix) return true;
    if (name.size() > suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0 &&
        name[name.size() - suffix.size() - 1] == '.') {
      return true;
    }
  }
  return false;
}

bool IsPrivateReverseName(const std::string& name) {
  const std::string v4 = ".in-addr.arpa";
  if (name.size() > v4.size() && name.compare(name.size() - v4.size(), v4.size(), v4) == 0) {
    auto labels = Split(name.substr(0, name.size() - v4.size()));
    std::reverse(labels.begin(), labels.end());  // now most significant octet first
    if (labels.empty() || !AllDigits(labels[0])) return false;
    const int first = std::stoi(labels[0]);
    const int second = labels.size() > 1 && AllDigits(labels[1]) ? std::stoi(labels[1]) : -1;
    if (first == 10 || first == 127) return true;
    if (first == 192 && second == 168) return true;
    if (first == 169 && second == 254) return true;
    if (first == 172 && second >= 16 && second <= 31) return true;
    return false;
  }
  const std::string v6 = ".ip6.arpa";
  if (name.size() > v6.size() && name.compare(name.size() - v6.size(), v6.size(), v6) == 0) {
    auto nibbles = Split(name.substr(0, name.size() - v6.size()));
    std::reverse(nibbles.begin(), nibbles.end());
    std::string prefix;
    for (const auto& n : nibbles) prefix += n;
    if (prefix.size() >= 2 && (prefix.compare(0, 2, "fc") == 0 || prefix.compare(0, 2, "fd") == 0)) return true;
    if (prefix.size() >= 3 && prefix[0] == 'f' && prefix[1] == 'e' && (prefix[2] >= '8' && prefix[2] <= 'b')) return true;
    if (prefix == std::string(31, '0') + "1") return true;
    return false;
  }
  return false;
}

bool IsLocalOnlyName(const std::string& name) {
  if (name.empty() || name.find('.') == std::string::npos) return true;  // the root, single labels
  static const std::vector<std::string> kLocal{"local", "lan", "home.arpa", "internal", "localdomain", "localhost", "invalid"};
  if (MatchesSuffix(name, kLocal)) return true;
  return name.rfind("wpad.", 0) == 0;  // proxy discovery: a LAN name, and WinHTTP looks it up while proxying our DoH
}

void VerdictCache::Block(const std::string& domain, const std::string& reason, std::chrono::seconds ttl, Clock::time_point now) {
  std::lock_guard lock(mutex_);
  if (entries_.size() >= 20000) {
    for (auto it = entries_.begin(); it != entries_.end();) it = it->second.expires <= now ? entries_.erase(it) : std::next(it);
    if (entries_.size() >= 20000) entries_.clear();
  }
  entries_[domain] = Entry{reason, now + ttl};
}

void VerdictCache::Allow(const std::string& domain) {
  std::lock_guard lock(mutex_);
  entries_.erase(domain);
}

std::optional<std::string> VerdictCache::Blocked(const std::string& domain, Clock::time_point now) {
  std::lock_guard lock(mutex_);
  const auto it = entries_.find(domain);
  if (it == entries_.end()) return std::nullopt;
  if (it->second.expires <= now) {
    entries_.erase(it);
    return std::nullopt;
  }
  return it->second.reason;
}

std::size_t VerdictCache::Size() {
  std::lock_guard lock(mutex_);
  return entries_.size();
}

void AnswerCache::Put(const std::string& name, std::uint16_t type, const Bytes& reply, int ttlSeconds, Clock::time_point now) {
  if (ttlSeconds <= 0) return;
  std::lock_guard lock(mutex_);
  if (entries_.size() >= 4096) {
    for (auto it = entries_.begin(); it != entries_.end();) it = it->second.expires <= now ? entries_.erase(it) : std::next(it);
    if (entries_.size() >= 4096) entries_.clear();
  }
  entries_[name + "|" + std::to_string(type)] = Entry{reply, now + std::chrono::seconds(std::min(ttlSeconds, 300))};
}

std::optional<Bytes> AnswerCache::Get(const std::string& name, std::uint16_t type, Clock::time_point now) {
  std::lock_guard lock(mutex_);
  const auto it = entries_.find(name + "|" + std::to_string(type));
  if (it == entries_.end()) return std::nullopt;
  if (it->second.expires <= now) {
    entries_.erase(it);
    return std::nullopt;
  }
  return it->second.reply;
}

void AnswerCache::Clear() {
  std::lock_guard lock(mutex_);
  entries_.clear();
}

std::string BuildApplyScript() {
  const std::string comment = kRuleComment;
  const std::string address = kListenAddress;
  return "$ErrorActionPreference = 'Stop'\n"
         "function Out-Result($ok, $reason) { @{ ok = $ok; reason = $reason } | ConvertTo-Json -Compress; exit 0 }\n"
         "$gpo = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig'\n"
         "if ((Test-Path $gpo) -and @(Get-ChildItem -Path $gpo -ErrorAction SilentlyContinue).Count -gt 0) {\n"
         "  Out-Result $false 'Group Policy manages the Name Resolution Policy Table on this device, so a local rule would be ignored.' }\n"
         "try {\n"
         "  Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + comment + "' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }\n"
         "  Add-DnsClientNrptRule -Namespace '.' -NameServers '" + address + "' -Comment '" + comment + "' | Out-Null\n"
         "  Clear-DnsClientCache\n"
         "  $rule = @(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + comment + "' })\n"
         "  if ($rule.Count -eq 0) { Out-Result $false 'The rule was not created.' }\n"
         "  Out-Result $true ''\n"
         "} catch { Out-Result $false $_.Exception.Message }\n";
}

std::string BuildRemoveScript() {
  const std::string comment = kRuleComment;
  return "$removed = 0; $ok = $true; $reason = ''\n"
         "try {\n"
         "  Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -eq '" + comment + "' } | ForEach-Object {\n"
         "    Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop; $removed++ }\n"
         "  Clear-DnsClientCache -ErrorAction SilentlyContinue\n"
         "} catch { $ok = $false; $reason = $_.Exception.Message }\n"
         "@{ ok = $ok; removed = $removed; reason = $reason } | ConvertTo-Json -Compress\n";
}

}  // namespace antivirus::agent::dnsproxy
