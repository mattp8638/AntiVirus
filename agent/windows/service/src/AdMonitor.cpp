#include "AdMonitor.h"

#include <dsrole.h>
#include <winevt.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <cwctype>
#include <fstream>
#include <sstream>

#include "ExtendedPolicy.h"
#include "RmmExecutors.h"
#include "StringUtils.h"

namespace antivirus::agent {

namespace admonitor {

MachineRole DetectRole() {
  DSROLE_PRIMARY_DOMAIN_INFO_BASIC* info = nullptr;
  if (DsRoleGetPrimaryDomainInformation(nullptr, DsRolePrimaryDomainInfoBasic, reinterpret_cast<PBYTE*>(&info)) != ERROR_SUCCESS ||
      info == nullptr) {
    return MachineRole::Unknown;
  }
  MachineRole role = MachineRole::Workstation;
  switch (info->MachineRole) {
    case DsRole_RolePrimaryDomainController:
    case DsRole_RoleBackupDomainController:
      role = MachineRole::DomainController;
      break;
    case DsRole_RoleStandaloneServer:
    case DsRole_RoleMemberServer:
      role = MachineRole::Server;
      break;
    default:
      break;
  }
  DsRoleFreeMemory(info);
  return role;
}

std::wstring RoleName(const MachineRole role) {
  switch (role) {
    case MachineRole::DomainController: return L"domain-controller";
    case MachineRole::Server: return L"server";
    case MachineRole::Workstation: return L"workstation";
    default: return L"unknown";
  }
}

}  // namespace admonitor

namespace {

unsigned long long UnixNow() { return static_cast<unsigned long long>(std::time(nullptr)); }

std::wstring J(const std::wstring& value) { return L"\"" + Utf8ToWide(EscapeJsonString(value)) + L"\""; }

constexpr int kMaxEventsPerMinute = 300;

std::wstring BuildQuery(const unsigned long long lastRecordId) {
  const std::wstring since = lastRecordId == 0 ? L"TimeCreated[timediff(@SystemTime) &lt;= 600000]"
                                               : L"EventRecordID &gt; " + std::to_wstring(lastRecordId);
  const auto select = [&](const std::wstring& condition) {
    return L"<Select Path=\"Security\">*[System[" + since + L" and (" + condition + L")]]</Select>";
  };
  const auto data = [&](const std::wstring& ids, const std::wstring& eventData) {
    return L"<Select Path=\"Security\">*[System[" + since + L" and (" + ids + L")] and EventData[" + eventData + L"]]</Select>";
  };
  std::wstring query = L"<QueryList><Query Id=\"0\" Path=\"Security\">";
  query += select(L"(EventID &gt;= 4720 and EventID &lt;= 4767) or EventID=4662 or EventID=4706 or EventID=4707 or EventID=4713 or "
                  L"EventID=4716 or EventID=4739 or EventID=4794 or EventID=4771 or EventID=1102 or "
                  L"(EventID &gt;= 5136 and EventID &lt;= 5141)");
  // Only the Kerberos/NTLM events that matter: these channels carry every sign-in in the domain.
  query += data(L"EventID=4768", L"Data[@Name='PreAuthType']='0' or Data[@Name='Status']='0x6' or Data[@Name='Status']='0x12' or "
                                 L"Data[@Name='Status']='0x18'");
  query += data(L"EventID=4769", L"Data[@Name='TicketEncryptionType']='0x17' or Data[@Name='TicketEncryptionType']='0x18'");
  query += data(L"EventID=4776", L"Data[@Name='Status']!='0x0'");
  query += L"</Query></QueryList>";
  return query;
}

}  // namespace

AdMonitor::AdMonitor(std::filesystem::path stateDirectory) : stateDirectory_(std::move(stateDirectory)) {}

AdMonitor::~AdMonitor() { Stop(); }

void AdMonitor::SetUrgentCallback(std::function<void()> callback) {
  const std::scoped_lock lock(mutex_);
  urgent_ = std::move(callback);
}

void AdMonitor::Start() {
  if (thread_.joinable()) return;
  stop_ = false;
  thread_ = std::thread([this] { Loop(); });
}

void AdMonitor::Stop() {
  stop_ = true;
  if (thread_.joinable()) thread_.join();
}

std::vector<TelemetryRecord> AdMonitor::DrainTelemetry() {
  const std::scoped_lock lock(mutex_);
  auto out = std::move(telemetry_);
  telemetry_.clear();
  return out;
}

void AdMonitor::Queue(const std::wstring& eventType, const std::wstring& summary, const std::wstring& payload, const bool urgent) {
  std::function<void()> callback;
  {
    const std::scoped_lock lock(mutex_);
    if (telemetry_.size() < 2000) {
      telemetry_.push_back({GenerateGuidString(), eventType, L"ad-monitor", summary, CurrentUtcTimestamp(), payload});
    }
    if (urgent) callback = urgent_;
  }
  if (callback) callback();
}

void AdMonitor::Loop() {
  while (!stop_.load()) {
    try {
      const auto now = UnixNow();
      if (now - lastRoleCheck_ >= 3600) {
        lastRoleCheck_ = now;
        const auto role = admonitor::DetectRole();
        if (role != role_ && role != admonitor::MachineRole::Unknown) {
          const bool wasDc = role_ == admonitor::MachineRole::DomainController;
          role_ = role;
          if (role == admonitor::MachineRole::DomainController) {
            Queue(L"ad.monitor.started", L"This server is a domain controller; Active Directory monitoring is on.",
                  L"{\"role\":\"domain-controller\"}", false);
          } else if (wasDc) {
            Queue(L"ad.monitor.stopped", L"This server is no longer a domain controller; Active Directory monitoring is off.",
                  L"{\"role\":" + J(admonitor::RoleName(role)) + L"}", false);
          }
        }
      }
      if (role_ == admonitor::MachineRole::DomainController) {
        if (!loaded_) {
          loaded_ = true;
          Load();
        }
        Poll();
      }
    } catch (const std::exception& error) {
      Queue(L"ad.monitor.error", L"Active Directory monitoring hit an error and carried on.",
            L"{\"error\":" + J(Utf8ToWide(error.what())) + L"}", false);
    }
    for (int i = 0; i < 150 && !stop_.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

void AdMonitor::Poll() {
  const auto query = BuildQuery(lastRecordId_);
  const auto results = EvtQuery(nullptr, nullptr, query.c_str(), EvtQueryChannelPath | EvtQueryForwardDirection);
  if (results == nullptr) {
    if (!readErrorReported_) {
      readErrorReported_ = true;
      Queue(L"ad.monitor.degraded", L"Active Directory monitoring cannot read the Security event log.",
            L"{\"error\":" + std::to_wstring(GetLastError()) + L"}", false);
    }
    return;
  }
  readErrorReported_ = false;
  const auto start = lastRecordId_;
  std::vector<wchar_t> buffer(16384);
  EVT_HANDLE events[64];
  DWORD returned = 0;
  int processed = 0;
  bool urgent = false;
  while (processed < 20000 && EvtNext(results, 64, events, 0, 0, &returned)) {
    for (DWORD i = 0; i < returned; ++i) {
      DWORD used = 0, count = 0;
      if (!EvtRender(nullptr, events[i], EvtRenderEventXml, static_cast<DWORD>(buffer.size() * sizeof(wchar_t)), buffer.data(), &used,
                     &count) &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(used / sizeof(wchar_t) + 1);
        EvtRender(nullptr, events[i], EvtRenderEventXml, static_cast<DWORD>(buffer.size() * sizeof(wchar_t)), buffer.data(), &used, &count);
      }
      EvtClose(events[i]);
      ++processed;
      const auto parsed = admonitor::ParseEventXml(std::wstring(buffer.data()));
      if (!parsed) continue;
      if (parsed->recordId > lastRecordId_) lastRecordId_ = parsed->recordId;
      const auto classified = admonitor::Classify(*parsed);
      if (classified.eventType.empty()) continue;

      const auto now = UnixNow();
      if (now - minuteStart_ >= 60) {
        if (droppedThisMinute_ > 0) {
          Queue(L"ad.monitor.throttled",
                L"Active Directory monitoring skipped " + std::to_wstring(droppedThisMinute_) + L" events in a busy minute.",
                L"{\"dropped\":" + std::to_wstring(droppedThisMinute_) + L"}", false);
        }
        minuteStart_ = now;
        sentThisMinute_ = 0;
        droppedThisMinute_ = 0;
      }
      if (++sentThisMinute_ > kMaxEventsPerMinute) {
        ++droppedThisMinute_;
        continue;
      }

      std::wstring payload = L"{\"EventID\":" + std::to_wstring(parsed->eventId) + L",\"recordId\":" +
                             std::to_wstring(parsed->recordId) + L",\"domainController\":" + J(parsed->computer) +
                             L",\"eventTime\":" + J(parsed->timeCreated);
      for (const auto& [name, value] : parsed->data) {
        if (name.empty() || name.size() > 64) continue;
        payload += L"," + J(name) + L":" + J(value);
      }
      if (!classified.extraJson.empty()) payload += L"," + classified.extraJson;
      payload += L"}";
      const bool important = classified.eventType == L"ad.replication.requested" || classified.eventType == L"ad.adminsdholder.modified" ||
                             classified.extraJson.find(L"privilegedGroup") != std::wstring::npos;
      urgent = urgent || important;
      Queue(classified.eventType, classified.summary, payload, false);
    }
  }
  EvtClose(results);
  if (lastRecordId_ != start) Save();
  if (urgent) {
    std::function<void()> callback;
    {
      const std::scoped_lock lock(mutex_);
      callback = urgent_;
    }
    if (callback) callback();
  }
}

void AdMonitor::Save() {
  std::error_code ec;
  std::filesystem::create_directories(stateDirectory_, ec);
  std::ofstream out(stateDirectory_ / L"ad-monitor.json", std::ios::binary | std::ios::trunc);
  out << "{\"lastRecordId\":" << lastRecordId_ << "}";
}

void AdMonitor::Load() {
  std::ifstream in(stateDirectory_ / L"ad-monitor.json", std::ios::binary);
  if (!in) return;
  std::stringstream text;
  text << in.rdbuf();
  const auto parsed = json::Parse(text.str());
  if (!parsed) return;
  if (const auto* last = parsed->Get("lastRecordId"); last && last->Number()) {
    lastRecordId_ = static_cast<unsigned long long>(*last->Number());
  }
}

}  // namespace antivirus::agent
