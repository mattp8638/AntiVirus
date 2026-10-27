#pragma once

// Active Directory monitoring on domain controllers. The agent checks the machine's role every hour (so a server
// promoted to a DC is picked up without a reinstall) and, on a DC, reads the Security event log for directory
// changes and attacks: account and group changes (privileged groups flagged), Kerberoasting and AS-REP roasting,
// password spraying, DCSync, AdminSDHolder/GPO/delegation changes, trusts, DSRM and SID history. Events are
// filtered on the DC so routine traffic (machine accounts, AES tickets, successful pre-authentication) never
// leaves it. The read position survives restarts (ad-monitor.json).

#include <windows.h>

#include <atomic>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "AdEventRules.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

namespace admonitor {

enum class MachineRole { Unknown, Workstation, Server, DomainController };

MachineRole DetectRole();
std::wstring RoleName(MachineRole role);

}  // namespace admonitor

class AdMonitor {
 public:
  explicit AdMonitor(std::filesystem::path stateDirectory);
  ~AdMonitor();
  AdMonitor(const AdMonitor&) = delete;
  AdMonitor& operator=(const AdMonitor&) = delete;

  void Start();
  void Stop();
  std::vector<TelemetryRecord> DrainTelemetry();
  void SetUrgentCallback(std::function<void()> callback);

 private:
  void Loop();
  void Poll();
  void Save();
  void Load();
  void Queue(const std::wstring& eventType, const std::wstring& summary, const std::wstring& payload, bool urgent);

  std::filesystem::path stateDirectory_;
  std::mutex mutex_;
  std::vector<TelemetryRecord> telemetry_;
  std::function<void()> urgent_;
  admonitor::MachineRole role_{admonitor::MachineRole::Unknown};
  unsigned long long lastRoleCheck_{0};
  unsigned long long lastRecordId_{0};
  unsigned long long minuteStart_{0};
  int sentThisMinute_{0};
  int droppedThisMinute_{0};
  bool loaded_{false};
  bool readErrorReported_{false};
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

}  // namespace antivirus::agent
