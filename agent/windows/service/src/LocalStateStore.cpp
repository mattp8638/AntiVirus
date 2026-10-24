#include "LocalStateStore.h"

#include <Windows.h>
#include <objbase.h>  // CoCreateGuid / StringFromGUID2 with WIN32_LEAN_AND_MEAN

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

bool ParseBool(const std::string& value) { return value == "true" || value == "1"; }

std::wstring DetectHostname() {
  wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] = {};
  DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
  return GetComputerNameW(buffer, &size) != 0 ? std::wstring(buffer, size) : L"UNKNOWN-HOST";
}

std::wstring DetectOsVersion() {
  using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
  const auto ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto rtlGetVersion =
      ntdll == nullptr ? nullptr : reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));

  OSVERSIONINFOW versionInfo{};
  versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
  if (rtlGetVersion != nullptr && rtlGetVersion(&versionInfo) == 0) {
    std::wstringstream stream;
    stream << L"Windows " << versionInfo.dwMajorVersion << L"." << versionInfo.dwMinorVersion << L" Build "
           << versionInfo.dwBuildNumber;
    return stream.str();
  }
  return L"Windows";
}

std::wstring GenerateSerialNumber() {
  GUID guid{};
  if (CoCreateGuid(&guid) != S_OK) {
    return L"SERIAL-UNAVAILABLE";
  }
  wchar_t buffer[64] = {};
  const auto written = StringFromGUID2(guid, buffer, 64);
  return written > 1 ? std::wstring(buffer, written - 1) : L"SERIAL-UNAVAILABLE";
}

AgentState BuildSeedState() {
  AgentState state;
  state.hostname = DetectHostname();
  state.osVersion = DetectOsVersion();
  state.serialNumber = GenerateSerialNumber();
  state.policy = CreateDefaultPolicySnapshot();
  return state;
}

std::map<std::string, std::string> ParseLegacyStateFile(const std::filesystem::path& stateFilePath) {
  std::ifstream input(stateFilePath);
  if (!input.is_open()) {
    return {};
  }

  std::map<std::string, std::string> values;
  std::string line;
  while (std::getline(input, line)) {
    const auto trimmed = TrimCopy(line);
    if (trimmed.empty() || trimmed.starts_with('#')) {
      continue;
    }

    const auto separator = trimmed.find('=');
    if (separator == std::string::npos) {
      continue;
    }
    values.emplace(trimmed.substr(0, separator), trimmed.substr(separator + 1));
  }
  return values;
}

std::wstring GetWString(const std::map<std::string, std::string>& values, const std::string& key,
                        const std::wstring& fallback = L"") {
  if (const auto entry = values.find(key); entry != values.end()) {
    return Utf8ToWide(entry->second);
  }
  return fallback;
}

bool GetBool(const std::map<std::string, std::string>& values, const std::string& key, const bool fallback) {
  if (const auto entry = values.find(key); entry != values.end()) {
    return ParseBool(entry->second);
  }
  return fallback;
}

int GetInt(const std::map<std::string, std::string>& values, const std::string& key, const int fallback) {
  if (const auto entry = values.find(key); entry != values.end()) {
    try {
      return std::stoi(entry->second);
    } catch (...) {
      return fallback;
    }
  }
  return fallback;
}

std::vector<std::wstring> GetStringList(const std::map<std::string, std::string>& values, const std::string& key) {
  if (const auto entry = values.find(key); entry != values.end()) {
    std::vector<std::wstring> results;
    std::stringstream stream(entry->second);
    std::string item;
    while (std::getline(stream, item, ';')) {
      const auto trimmed = TrimCopy(item);
      if (!trimmed.empty()) {
        results.push_back(Utf8ToWide(trimmed));
      }
    }
    return results;
  }

  return {};
}

AgentState ImportLegacyState(const std::filesystem::path& stateFilePath) {
  AgentState state = BuildSeedState();
  const auto values = ParseLegacyStateFile(stateFilePath);
  if (values.empty()) {
    return state;
  }

  state.deviceId = GetWString(values, "device_id");
  state.hostname = GetWString(values, "hostname", state.hostname);
  state.osVersion = GetWString(values, "os_version", state.osVersion);
  state.serialNumber = GetWString(values, "serial_number", state.serialNumber);
  state.agentVersion = GetWString(values, "agent_version", state.agentVersion);
  state.platformVersion = GetWString(values, "platform_version", state.platformVersion);
  state.commandChannelUrl = GetWString(values, "command_channel_url");
  state.lastEnrollmentAt = GetWString(values, "last_enrollment_at");
  state.lastHeartbeatAt = GetWString(values, "last_heartbeat_at");
  state.lastPolicySyncAt = GetWString(values, "last_policy_sync_at");
  state.healthState = GetWString(values, "health_state", state.healthState);
  state.isolated = GetBool(values, "isolated", false);
  state.policy.policyId = GetWString(values, "policy_id", state.policy.policyId);
  state.policy.policyName = GetWString(values, "policy_name", state.policy.policyName);
  state.policy.revision = GetWString(values, "policy_revision", state.policy.revision);
  state.policy.realtimeProtectionEnabled =
      GetBool(values, "policy_realtime_protection_enabled", state.policy.realtimeProtectionEnabled);
  state.policy.cloudLookupEnabled = GetBool(values, "policy_cloud_lookup_enabled", state.policy.cloudLookupEnabled);
  state.policy.scriptInspectionEnabled =
      GetBool(values, "policy_script_inspection_enabled", state.policy.scriptInspectionEnabled);
  state.policy.networkContainmentEnabled =
      GetBool(values, "policy_network_containment_enabled", state.policy.networkContainmentEnabled);
  state.policy.quarantineOnMalicious =
      GetBool(values, "policy_quarantine_on_malicious", state.policy.quarantineOnMalicious);
    state.policy.scanMaliciousBlockThreshold = static_cast<std::uint32_t>(
      std::clamp(GetInt(values, "policy_scan_malicious_block_threshold",
              static_cast<int>(state.policy.scanMaliciousBlockThreshold)),
           1, 99));
    state.policy.scanMaliciousQuarantineThreshold = static_cast<std::uint32_t>(
      std::clamp(GetInt(values, "policy_scan_malicious_quarantine_threshold",
              static_cast<int>(state.policy.scanMaliciousQuarantineThreshold)),
           static_cast<int>(state.policy.scanMaliciousBlockThreshold), 99));
    state.policy.scanBenignDampeningScore = static_cast<std::uint32_t>(
      std::clamp(GetInt(values, "policy_scan_benign_dampening_score",
              static_cast<int>(state.policy.scanBenignDampeningScore)),
           0, 80));
    state.policy.genericRuleScoreScalePercent = static_cast<std::uint32_t>(
      std::clamp(GetInt(values, "policy_generic_rule_score_scale_percent",
              static_cast<int>(state.policy.genericRuleScoreScalePercent)),
           20, 100));
    state.policy.realtimeExecuteBlockThreshold = static_cast<std::uint32_t>(
      std::clamp(GetInt(values, "policy_realtime_execute_block_threshold",
              static_cast<int>(state.policy.realtimeExecuteBlockThreshold)),
           40, 99));
    state.policy.realtimeNonExecuteBlockThreshold = static_cast<std::uint32_t>(
      std::clamp(GetInt(values, "policy_realtime_non_execute_block_threshold",
              static_cast<int>(state.policy.realtimeNonExecuteBlockThreshold)),
           50, 99));
    state.policy.realtimeQuarantineThreshold = static_cast<std::uint32_t>(
      std::clamp(GetInt(values, "policy_realtime_quarantine_threshold",
              static_cast<int>(state.policy.realtimeQuarantineThreshold)),
           std::max<int>(static_cast<int>(state.policy.realtimeExecuteBlockThreshold),
                   static_cast<int>(state.policy.realtimeNonExecuteBlockThreshold)),
           99));
    state.policy.realtimeObserveTelemetryThreshold = static_cast<std::uint32_t>(
      std::clamp(GetInt(values, "policy_realtime_observe_telemetry_threshold",
              static_cast<int>(state.policy.realtimeObserveTelemetryThreshold)),
           1, 95));
    state.policy.realtimeObserveOnlyForNonExecute =
      GetBool(values, "policy_realtime_observe_only_non_execute", state.policy.realtimeObserveOnlyForNonExecute);
    state.policy.archiveObserveOnly =
      GetBool(values, "policy_archive_observe_only", state.policy.archiveObserveOnly);
    state.policy.networkObserveOnly =
      GetBool(values, "policy_network_observe_only", state.policy.networkObserveOnly);
    state.policy.cloudLookupObserveOnly =
      GetBool(values, "policy_cloud_lookup_observe_only", state.policy.cloudLookupObserveOnly);
    state.policy.requireSignerForSuppression =
      GetBool(values, "policy_require_signer_for_suppression", state.policy.requireSignerForSuppression);
    state.policy.allowUnsignedSuppressionPathExecutables =
      GetBool(values, "policy_allow_unsigned_suppression_path_executables",
          state.policy.allowUnsignedSuppressionPathExecutables);
    state.policy.enableCleanwareSignerDampening =
      GetBool(values, "policy_enable_cleanware_signer_dampening", state.policy.enableCleanwareSignerDampening);
    state.policy.enableKnownGoodHashDampening =
      GetBool(values, "policy_enable_known_good_hash_dampening", state.policy.enableKnownGoodHashDampening);
  state.policy.suppressionPathRoots = GetStringList(values, "policy_suppression_path_roots");
  state.policy.suppressionSha256 = GetStringList(values, "policy_suppression_sha256");
  state.policy.suppressionSignerNames = GetStringList(values, "policy_suppression_signer_names");
  return state;
}

}  // namespace

LocalStateStore::LocalStateStore(std::filesystem::path databasePath, std::filesystem::path legacyStateFilePath)
    : databasePath_(std::move(databasePath)), legacyStateFilePath_(std::move(legacyStateFilePath)) {}

AgentState LocalStateStore::LoadOrCreate() const {
  RuntimeDatabase database(databasePath_);
  AgentState state = BuildSeedState();
  if (database.LoadAgentState(state)) {
    return state;
  }

  if (!legacyStateFilePath_.empty() && std::filesystem::exists(legacyStateFilePath_)) {
    state = ImportLegacyState(legacyStateFilePath_);
  }

  database.SaveAgentState(state);
  return state;
}

void LocalStateStore::Save(const AgentState& state) const {
  RuntimeDatabase(databasePath_).SaveAgentState(state);
}

}  // namespace antivirus::agent
