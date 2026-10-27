#include "BruteForceGuard.h"

#include <winevt.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>

#include "ExtendedPolicy.h"
#include "RmmExecutors.h"
#include "StringUtils.h"

namespace antivirus::agent {

namespace {

std::wstring J(const std::wstring& value) { return L"\"" + Utf8ToWide(EscapeJsonString(value)) + L"\""; }

unsigned long long UnixNow() { return static_cast<unsigned long long>(std::time(nullptr)); }

std::wstring RuleName(const std::wstring& address) { return L"Fenrir brute-force block " + address; }

std::wstring VariantString(const EVT_VARIANT& value) {
  if (value.Type == EvtVarTypeString && value.StringVal != nullptr) return value.StringVal;
  return {};
}

}  // namespace

BruteForceGuard::BruteForceGuard(std::filesystem::path stateDirectory) : stateDirectory_(std::move(stateDirectory)) {}

BruteForceGuard::~BruteForceGuard() { Stop(); }

void BruteForceGuard::SetUrgentCallback(std::function<void()> callback) {
  const std::scoped_lock lock(mutex_);
  urgent_ = std::move(callback);
}

void BruteForceGuard::Apply(const bool enabled) {
  {
    const std::scoped_lock lock(mutex_);
    if (applied_ && enabled_ == enabled) return;
    enabled_ = enabled;
    applied_ = true;
  }
  if (!thread_.joinable()) {
    stop_ = false;
    thread_ = std::thread([this] { Loop(); });
  }
}

void BruteForceGuard::Stop() {
  stop_ = true;
  if (thread_.joinable()) thread_.join();
}

std::vector<TelemetryRecord> BruteForceGuard::DrainTelemetry() {
  const std::scoped_lock lock(mutex_);
  auto out = std::move(telemetry_);
  telemetry_.clear();
  return out;
}

void BruteForceGuard::Queue(const std::wstring& eventType, const std::wstring& summary, const std::wstring& payload,
                            const bool urgent) {
  std::function<void()> callback;
  {
    const std::scoped_lock lock(mutex_);
    if (telemetry_.size() < 500) {
      telemetry_.push_back({GenerateGuidString(), eventType, L"brute-force-guard", summary, CurrentUtcTimestamp(), payload});
    }
    if (urgent) callback = urgent_;
  }
  if (callback) callback();
}

void BruteForceGuard::Loop() {
  while (!stop_.load()) {
    bool enabled = false;
    {
      const std::scoped_lock lock(mutex_);
      enabled = enabled_;
    }
    try {
      if (!loaded_) {
        loaded_ = true;
        Load();
      }
      const auto now = UnixNow();
      if (enabled) {
        Poll();
        bool changed = false;
        for (const auto& address : tracker_.Expire(now)) {
          SetRule(address, false);
          changed = true;
          Queue(L"auth.bruteforce.unblocked", L"Lifted the brute-force block on " + address,
                L"{\"remoteAddress\":" + J(address) + L"}", false);
        }
        if (changed) Save();
      } else if (!tracker_.Blocks().empty()) {
        for (const auto& address : tracker_.Clear()) SetRule(address, false);
        Save();
        Queue(L"auth.bruteforce.cleared", L"Brute-force protection is off; all blocks were lifted.", L"{}", false);
      }
    } catch (const std::exception& error) {
      Queue(L"auth.bruteforce.error", L"Brute-force protection hit an error and carried on.",
            L"{\"error\":" + J(Utf8ToWide(error.what())) + L"}", false);
    }
    for (int i = 0; i < 200 && !stop_.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

void BruteForceGuard::Poll() {
  // 4625: an account failed to log on (network logons cover SMB and RDP with NLA; type 10 is RDP without NLA).
  const std::wstring query =
      lastRecordId_ == 0 ? L"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 600000]]]"
                         : L"*[System[(EventID=4625) and (EventRecordID > " + std::to_wstring(lastRecordId_) + L")]]";
  const auto results = EvtQuery(nullptr, L"Security", query.c_str(), EvtQueryChannelPath | EvtQueryForwardDirection);
  if (results == nullptr) {
    if (!readErrorReported_) {
      readErrorReported_ = true;
      Queue(L"auth.bruteforce.degraded", L"Brute-force protection cannot read the Security event log.",
            L"{\"error\":" + std::to_wstring(GetLastError()) + L"}", false);
    }
    return;
  }
  readErrorReported_ = false;
  LPCWSTR paths[] = {L"Event/System/EventRecordID", L"Event/EventData/Data[@Name='IpAddress']",
                     L"Event/EventData/Data[@Name='TargetUserName']", L"Event/EventData/Data[@Name='LogonType']",
                     L"Event/EventData/Data[@Name='TargetDomainName']"};
  const auto context = EvtCreateRenderContext(5, paths, EvtRenderContextValues);
  if (context == nullptr) {
    EvtClose(results);
    return;
  }
  const auto now = UnixNow();
  bool changed = false;
  std::vector<BYTE> buffer(4096);
  EVT_HANDLE events[64];
  DWORD returned = 0;
  int processed = 0;
  while (processed < 20000 && EvtNext(results, 64, events, 0, 0, &returned)) {
    for (DWORD i = 0; i < returned; ++i) {
      DWORD used = 0, count = 0;
      if (!EvtRender(context, events[i], EvtRenderEventValues, static_cast<DWORD>(buffer.size()), buffer.data(), &used, &count) &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(used);
        EvtRender(context, events[i], EvtRenderEventValues, static_cast<DWORD>(buffer.size()), buffer.data(), &used, &count);
      }
      if (count >= 5) {
        const auto* values = reinterpret_cast<const EVT_VARIANT*>(buffer.data());
        if (values[0].Type == EvtVarTypeUInt64 && values[0].UInt64Val > lastRecordId_) lastRecordId_ = values[0].UInt64Val;
        const auto address = VariantString(values[1]);
        auto account = VariantString(values[2]);
        const auto domain = VariantString(values[4]);
        if (!domain.empty() && domain != L"-" && !account.empty()) account = domain + L"\\" + account;
        const auto logonType = VariantString(values[3]);
        if (const auto block = tracker_.OnFailure(address, account, now)) {
          const bool applied = SetRule(block->address, true);
          changed = true;
          std::wstring accounts = L"[";
          for (std::size_t a = 0; a < block->accounts.size(); ++a) accounts += (a ? L"," : L"") + J(block->accounts[a]);
          accounts += L"]";
          const auto minutes = (block->until - now) / 60;
          Queue(L"auth.bruteforce.blocked",
                (applied ? L"Blocked " : L"Could not block ") + block->address + L" after " + std::to_wstring(block->failures) +
                    L" failed sign-ins in 10 minutes" + (applied ? L" (for " + std::to_wstring(minutes) + L" minutes)" : L""),
                L"{\"remoteAddress\":" + J(block->address) + L",\"failures\":" + std::to_wstring(block->failures) +
                    L",\"accounts\":" + accounts + L",\"logonType\":" + J(logonType) + L",\"blockMinutes\":" +
                    std::to_wstring(minutes) + L",\"strikes\":" + std::to_wstring(block->strikes) + L",\"action\":" +
                    J(applied ? L"blocked" : L"block failed") + L",\"mitre\":\"T1110\"}",
                true);
        }
      }
      EvtClose(events[i]);
      ++processed;
    }
  }
  EvtClose(context);
  EvtClose(results);
  if (changed) Save();
}

bool BruteForceGuard::SetRule(const std::wstring& address, const bool block) {
  if (bruteforce::NormaliseRemoteAddress(address) != address) return false;  // only plain IP literals reach netsh
  wchar_t systemDir[MAX_PATH]{};
  GetSystemDirectoryW(systemDir, MAX_PATH);
  const std::wstring netsh = L"\"" + std::wstring(systemDir) + L"\\netsh.exe\" advfirewall firewall ";
  const auto name = L"name=\"" + RuleName(address) + L"\"";
  // Remove first so a block is never duplicated.
  rmm::RunProcess(netsh + L"delete rule " + name, systemDir, {}, 30'000);
  if (!block) return true;
  const auto result = rmm::RunProcess(netsh + L"add rule " + name + L" dir=in action=block remoteip=" + address +
                                          L" description=\"Fenrir Endpoint: repeated failed sign-ins\"",
                                      systemDir, {}, 30'000);
  return !result.timedOut && result.exitCode == 0;
}

void BruteForceGuard::Save() {
  std::wstring body = L"{\"blocks\":[";
  bool first = true;
  for (const auto& [address, block] : tracker_.Blocks()) {
    body += (first ? L"" : L",") + std::wstring(L"{\"address\":") + J(address) + L",\"until\":" + std::to_wstring(block.until) +
            L",\"strikes\":" + std::to_wstring(block.strikes) + L"}";
    first = false;
  }
  body += L"]}";
  std::error_code ec;
  std::filesystem::create_directories(stateDirectory_, ec);
  std::ofstream out(stateDirectory_ / L"brute-force-blocks.json", std::ios::binary | std::ios::trunc);
  out << WideToUtf8(body);
}

void BruteForceGuard::Load() {
  std::ifstream in(stateDirectory_ / L"brute-force-blocks.json", std::ios::binary);
  if (!in) return;
  std::stringstream text;
  text << in.rdbuf();
  const auto parsed = json::Parse(text.str());
  if (!parsed) return;
  const auto* blocks = parsed->Get("blocks");
  const auto* list = blocks ? std::get_if<json::Array>(&blocks->v) : nullptr;
  if (list == nullptr) return;
  for (const auto& item : *list) {
    const auto* address = item.Get("address");
    const auto* until = item.Get("until");
    const auto* strikes = item.Get("strikes");
    if (!address || !until || !address->String() || !until->Number()) continue;
    bruteforce::Block block;
    block.address = Utf8ToWide(*address->String());
    block.until = static_cast<unsigned long long>(*until->Number());
    block.strikes = strikes ? static_cast<int>(strikes->Number().value_or(1)) : 1;
    tracker_.Restore(block);
  }
}

}  // namespace antivirus::agent
