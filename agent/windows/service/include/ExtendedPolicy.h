#pragma once

// Settings from Fenrir Cloud's policy "modules" object that the original
// PolicySnapshot does not carry: attack surface rules, application control,
// device control, ML sensitivity and ransomware options. Kept separate so the
// runtime database schema does not change; the raw JSON is cached on disk.

#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "BehaviorRules.h"

namespace antivirus::agent {

namespace json {

struct Value;
using Object = std::map<std::string, Value>;
using Array = std::vector<Value>;

struct Value {
  std::variant<std::monostate, bool, double, std::string, Array, Object> v;

  bool IsObject() const { return std::holds_alternative<Object>(v); }
  const Value* Get(const std::string& key) const;
  std::optional<bool> Bool() const;
  std::optional<double> Number() const;
  std::optional<std::string> String() const;
  std::vector<std::string> Strings() const;
};

// Strict RFC 8259 parser with depth/size limits. Returns nullopt on malformed input.
std::optional<Value> Parse(const std::string& text);

}  // namespace json

struct DeviceControlSettings {
  bool enabled{false};
  std::wstring usbStorage{L"allow"};   // allow | audit | read-only | block
  std::wstring opticalMedia{L"allow"};  // allow | read-only | block
  std::wstring mtpDevices{L"allow"};    // allow | read-only | block
  std::wstring bluetoothFileTransfer{L"allow"};
  std::wstring printing{L"allow"};
  bool encryptedUsbOnly{false};
  std::vector<std::wstring> usbAllowedIds;
};

// A calendar scan schedule from the cloud ("daily 12:30" -> every day at 750 minutes, device local time).
struct ScanPlan {
  bool present{false};  // false: no usable schedule; keep the agent's built-in interval
  bool off{false};
  std::vector<int> days;  // 0 = Monday .. 6 = Sunday
  int minuteOfDay{0};
};

// modules.ransomware (plus response.autoRollbackRansomware), used by RansomwareShield.
struct RansomwareSettings {
  bool enabled{true};
  std::wstring mode{L"block"};  // audit | block | block-and-rollback
  int filesPerMinute{40};
  bool entropyDetection{true};
  bool canaryFiles{true};
  std::vector<std::wstring> protectedFolders;  // may contain %USERPROFILE% and other variables
  std::wstring protectedFoldersMode{L"audit"};  // off | audit | block
  std::vector<std::wstring> allowedApps;
  bool rollbackSnapshots{true};
  int snapshotIntervalHours{4};
  bool networkShareProtection{true};

  bool Blocks() const { return mode == L"block" || mode == L"block-and-rollback"; }
  // response.autoRollbackRansomware is handled by the cloud, which queues the ransomware.rollback command.
  bool RollsBack() const { return mode == L"block-and-rollback"; }
};

struct ExtendedPolicy {
  bool present{false};  // false until a cloud policy with modules has been received
  std::wstring mlSensitivity{L"balanced"};
  behavior::BehaviorPolicy behavior;
  DeviceControlSettings deviceControl;
  bool ransomwareEnabled{true};
  bool canaryFiles{true};
  RansomwareSettings ransomware;
  bool bruteForceProtection{true};  // modules.firewall.bruteForceProtection
  bool removeLocalAdmins{false};      // privilege.enabled && privilege.removeLocalAdmins
  bool tamperServiceLocked{true};     // tamper.enabled && tamper.protectServiceAndFiles
  bool tamperUninstallToken{true};    // tamper.enabled && tamper.uninstallRequiresToken
  bool scriptExecution{true};      // modules.response.scriptExecution
  bool remoteAccessEnabled{true};  // modules.remoteAccess.enabled
  // modules.edr collection switches: routine telemetry only; detections are always sent.
  bool collectProcessEvents{true};
  bool collectFileEvents{true};
  bool collectScriptEvents{true};
  bool collectDnsEvents{true};
  bool telemetryMinimal{false};      // edr.telemetryLevel == "minimal"
  bool allowQuarantineRestore{false};  // modules.experience: end users may restore from quarantine
  bool breakGlassAllowed{true};        // modules.privilege.breakGlassAllowed
  bool scanNetworkDrives{false};   // modules.antimalware.scanNetworkDrives: full scans include mapped drives
  int scanCpuLimitPercent{100};    // modules.antimalware.scanCpuLimitPercent: scheduled scans, share of one core
  ScanPlan quickScanPlan;          // modules.antimalware.quickScanPlan
  ScanPlan fullScanPlan;           // modules.antimalware.fullScanPlan

  static ExtendedPolicy Parse(const std::string& modulesJson);
};

std::wstring Utf8ToWideString(const std::string& value);

// How long a throttled scan should rest after using cpuMs of processor time, to stay at limitPercent.
unsigned long long ScanThrottleRestMs(int limitPercent, unsigned long long cpuMs);

// Applies the edr collection switches to one telemetry record. Only routine activity (process starts and
// exits, file changes, allowed script scans, observed destinations) can be dropped; detections, scans,
// quarantine, blocks and agent health always pass.
bool RoutineTelemetryAllowed(const ExtendedPolicy& policy, const std::wstring& eventType, const std::wstring& payloadJson);

}  // namespace antivirus::agent
