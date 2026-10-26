#include "AgentService.h"
#include "BuildInfo.h"
#include "LocalAdminRotation.h"
#include "ExtendedPolicy.h"
#include "FirewallPolicy.h"
#include "NetworkProbe.h"
#include "BundleArchive.h"

#include <wtsapi32.h>

#include "RmmExecutors.h"
#include "WebSocketClient.h"

#include "MlStaticModel.h"

#include <wtsapi32.h>
#include <lm.h>
#include <sddl.h>
#include <userenv.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#include "EvidenceRecorder.h"
#include "ContextAwareness.h"
#include "CryptoUtils.h"
#include "DestinationEventRecorder.h"
#include "DestinationRuntimeStore.h"
#include "DestinationVerdictEngine.h"
#include "DeviceInventoryCollector.h"
#include "FileInventory.h"
#include "FileSnapshotCollector.h"
#include "HardeningManager.h"
#include "LocalScanRunner.h"
#include "LocalSecurity.h"
#include "ProcessInventory.h"
#include "ProcessSnapshotCollector.h"
#include "ServiceSnapshotCollector.h"
#include "QuarantineStore.h"
#include "ReputationLookup.h"
#include "RemediationEngine.h"
#include "RuntimeDatabase.h"
#include "RuntimeTrustValidator.h"
#include "ScanEngine.h"
#include "StringUtils.h"
#include "UpdaterService.h"
#include "WscCoexistenceManager.h"

namespace antivirus::agent {

namespace {

struct ProcessExecutionResult {
  DWORD exitCode{0};
  std::wstring output;
};

constexpr wchar_t kPamRequestEventName[] = L"Global\\FenrirPamRequestReady";
constexpr wchar_t kPamRequestFileName[] = L"pam-request.json";
constexpr wchar_t kPamAuditFileName[] = L"privilege-requests.jsonl";
constexpr wchar_t kPamPolicyFileName[] = L"pam-policy.json";
constexpr wchar_t kPamPolicyDigestFileName[] = L"pam-policy.sha256";
constexpr wchar_t kPamPolicyBackupFileName[] = L"pam-policy.backup.json";
constexpr wchar_t kLocalApprovalQueueFileName[] = L"local-approval-requests.jsonl";
constexpr wchar_t kLocalApprovalLedgerFileName[] = L"local-approval-ledger.jsonl";
constexpr wchar_t kLocalAdminBaselineFileName[] = L"local-admin-baseline.jsonl";
constexpr std::size_t kMaxCommandPayloadChars = 64 * 1024;

struct PamRequestPayload {
  std::wstring requestedAt;
  std::wstring requester;
  std::wstring action;
  std::wstring targetPath;
  std::wstring arguments;
  std::wstring reason;
};

struct PamLaunchPlan {
  std::wstring executablePath;
  std::wstring arguments;
  std::wstring targetPath;
  std::optional<std::uint32_t> maxRuntimeSeconds;
};

struct PamPolicySnapshot {
  bool enabled{true};
  bool requireReason{true};
  bool allowBuiltInAdminTools{true};
  bool allowArbitraryApplications{true};
  std::uint32_t maxTimedRuntimeSeconds{120};
  std::vector<std::wstring> allowedActions;
  std::vector<std::wstring> allowedRequesters;
  std::vector<std::wstring> blockedPathPrefixes;
  std::vector<std::wstring> allowedPathPrefixes;
};

struct QueuedLocalApprovalRequest {
  std::wstring requestId;
  std::wstring createdAt;
  std::wstring type;
  std::wstring requester;
  std::wstring callerSid;
  std::wstring role;
  std::wstring reason;
  std::wstring recordId;
  std::wstring targetPath;
  std::wstring payloadJson;
};

struct LocalAdminMember {
  std::wstring accountName;
  std::wstring sid;
};

struct ClassifiedLocalAdminMember {
  LocalAdminMember member;
  std::wstring memberClass;
  bool protectedMember{false};
  bool managedCandidate{false};
};

struct LoadedLocalAdminBaseline {
  std::wstring baselineId;
  std::wstring capturedAt;
  std::vector<LocalAdminMember> members;
  std::wstring source{L"journal"};
};

std::wstring GetSystemBinaryPath(const wchar_t* relativePath);
bool QueuePamRequestPayload(const std::filesystem::path& requestPath, const PamRequestPayload& request,
                            std::wstring* errorMessage);
std::optional<std::chrono::system_clock::time_point> ParseUtcTimestamp(const std::wstring& value);

std::string EscapeRegex(const std::string& value) {
  std::string escaped;
  escaped.reserve(value.size() * 2);

  for (const auto ch : value) {
    switch (ch) {
      case '\\':
      case '^':
      case '$':
      case '.':
      case '|':
      case '?':
      case '*':
      case '+':
      case '(':
      case ')':
      case '[':
      case ']':
      case '{':
      case '}':
        escaped.push_back('\\');
        break;
      default:
        break;
    }

    escaped.push_back(ch);
  }

  return escaped;
}

std::string UnescapeJsonString(const std::string& value) {
  std::string result;
  result.reserve(value.size());

  bool escaping = false;
  for (const auto ch : value) {
    if (!escaping) {
      if (ch == '\\') {
        escaping = true;
      } else {
        result.push_back(ch);
      }
      continue;
    }

    switch (ch) {
      case '\\':
        result.push_back('\\');
        break;
      case '"':
        result.push_back('"');
        break;
      case 'n':
        result.push_back('\n');
        break;
      case 'r':
        result.push_back('\r');
        break;
      case 't':
        result.push_back('\t');
        break;
      default:
        result.push_back(ch);
        break;
    }

    escaping = false;
  }

  if (escaping) {
    result.push_back('\\');
  }

  return result;
}

std::optional<std::wstring> ExtractPayloadString(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return std::nullopt;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:\\s*\\\"((?:\\\\\\\\.|[^\\\"])*)\\\"");
  std::smatch match;
  if (std::regex_search(utf8Json, match, pattern)) {
    return Utf8ToWide(UnescapeJsonString(match[1].str()));
  }

  return std::nullopt;
}

std::optional<std::uint32_t> ExtractPayloadUInt32(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return std::nullopt;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (std::regex_search(utf8Json, match, pattern)) {
    try {
      return static_cast<std::uint32_t>(std::stoul(match[1].str()));
    } catch (...) {
      return std::nullopt;
    }
  }

  return std::nullopt;
}

std::optional<bool> ExtractPayloadBool(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return std::nullopt;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:\\s*(true|false|1|0)");
  std::smatch match;
  if (!std::regex_search(utf8Json, match, pattern)) {
    return std::nullopt;
  }

  const auto token = match[1].str();
  return token == "true" || token == "1";
}

std::vector<std::wstring> ExtractPayloadStringArray(const std::wstring& json, const std::string& key) {
  std::vector<std::wstring> values;
  if (json.size() > kMaxCommandPayloadChars) {
    return values;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex arrayPattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:\\s*\\[(.*?)\\]");
  std::smatch arrayMatch;
  if (!std::regex_search(utf8Json, arrayMatch, arrayPattern)) {
    return values;
  }

  const std::regex itemPattern("\\\"((?:\\\\\\\\.|[^\\\"])*)\\\"");
  auto begin = std::sregex_iterator(arrayMatch[1].first, arrayMatch[1].second, itemPattern);
  const auto end = std::sregex_iterator();
  for (auto iterator = begin; iterator != end; ++iterator) {
    values.push_back(Utf8ToWide(UnescapeJsonString((*iterator)[1].str())));
  }

  return values;
}

bool PayloadContainsKey(const std::wstring& json, const std::string& key) {
  if (json.size() > kMaxCommandPayloadChars) {
    return false;
  }

  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\\\"" + EscapeRegex(key) + "\\\"\\s*:");
  return std::regex_search(utf8Json, pattern);
}

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring TrimWide(std::wstring value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }
  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

bool PathStartsWith(std::wstring path, std::wstring prefix) {
  if (path.empty() || prefix.empty()) {
    return false;
  }

  path = ToLowerCopy(path);
  prefix = ToLowerCopy(prefix);
  if (!prefix.empty() && prefix.back() != L'\\') {
    prefix += L'\\';
  }

  return path == prefix.substr(0, prefix.size() - 1) || path.starts_with(prefix);
}

bool IsAppliedUpdateStatus(const std::wstring& status) {
  const auto normalized = ToLowerCopy(status);
  return normalized == L"completed" || normalized == L"pending_restart";
}

std::wstring BuildUpdateIdentityKey(const std::wstring& packageId, const std::wstring& targetVersion) {
  return ToLowerCopy(packageId) + L"|" + ToLowerCopy(targetVersion);
}

std::filesystem::path ResolveRuntimeRoot(const AgentConfig& config) {
  auto runtimeRoot = config.runtimeDatabasePath.parent_path();
  if (runtimeRoot.empty()) {
    runtimeRoot = config.runtimeDatabasePath;
  }
  return runtimeRoot;
}

std::filesystem::path ResolveInstallRootForConfig(const AgentConfig& config) {
  if (!config.installRootPath.empty()) {
    return config.installRootPath;
  }

  const auto runtimeRoot = ResolveRuntimeRoot(config);
  return runtimeRoot.has_parent_path() ? runtimeRoot.parent_path() : std::filesystem::current_path();
}

std::filesystem::path ResolveLocalApprovalRuntimeRoot() {
  const auto programData = ReadEnvironmentVariable(L"PROGRAMDATA");
  if (!programData.empty()) {
    return std::filesystem::path(programData) / L"FenrirAgent" / L"runtime";
  }

  return std::filesystem::current_path() / L"runtime";
}

std::filesystem::path ResolveLocalApprovalQueuePath() {
  return ResolveLocalApprovalRuntimeRoot() / kLocalApprovalQueueFileName;
}

std::filesystem::path ResolveLocalApprovalLedgerPath() {
  return ResolveLocalApprovalRuntimeRoot() / kLocalApprovalLedgerFileName;
}

std::filesystem::path ResolveLocalAdminBaselinePath(const AgentConfig& config) {
  return ResolveRuntimeRoot(config) / kLocalAdminBaselineFileName;
}

std::wstring BuildJsonStringArray(const std::vector<std::wstring>& values) {
  std::wstring result = L"[";
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      result += L",";
    }
    result += L"\\\"" + Utf8ToWide(EscapeJsonString(values[index])) + L"\\\"";
  }
  result += L"]";
  return result;
}

std::wstring BuildLocalAdminMembersJson(const std::vector<LocalAdminMember>& members) {
  std::wstring result = L"[";
  for (std::size_t index = 0; index < members.size(); ++index) {
    if (index != 0) {
      result += L",";
    }

    result += L"{\\\"accountName\\\":\\\"" + Utf8ToWide(EscapeJsonString(members[index].accountName)) +
              L"\\\",\\\"sid\\\":\\\"" + Utf8ToWide(EscapeJsonString(members[index].sid)) + L"\\\"}";
  }
  result += L"]";
  return result;
}

std::wstring BuildClassifiedLocalAdminMembersJson(const std::vector<ClassifiedLocalAdminMember>& members) {
  std::wstring result = L"[";
  for (std::size_t index = 0; index < members.size(); ++index) {
    if (index != 0) {
      result += L",";
    }

    const auto& item = members[index];
    result += L"{\\\"accountName\\\":\\\"" + Utf8ToWide(EscapeJsonString(item.member.accountName)) +
              L"\\\",\\\"sid\\\":\\\"" + Utf8ToWide(EscapeJsonString(item.member.sid)) + L"\\\",\\\"memberClass\\\":\\\"" +
              Utf8ToWide(EscapeJsonString(item.memberClass)) + L"\\\",\\\"protected\\\":" +
              (item.protectedMember ? std::wstring(L"true") : std::wstring(L"false")) + L",\\\"managedCandidate\\\":" +
              (item.managedCandidate ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
  }
  result += L"]";
  return result;
}

void EnforceTelemetryQueueBudget(std::vector<TelemetryRecord>* pendingTelemetry) {
  if (pendingTelemetry == nullptr) {
    return;
  }

  constexpr std::size_t kMaxQueuedTelemetry = 5000;
  if (pendingTelemetry->size() <= kMaxQueuedTelemetry) {
    return;
  }

  pendingTelemetry->erase(pendingTelemetry->begin(),
                          pendingTelemetry->begin() + (pendingTelemetry->size() - kMaxQueuedTelemetry));
}

std::optional<EventEnvelope> BuildBehaviorEventFromNetworkTelemetry(const TelemetryRecord& record,
                                                                    const std::wstring& deviceId) {
  const auto targetPath = ExtractPayloadString(record.payloadJson, "path").value_or(L"");
  const auto processImagePath = ExtractPayloadString(record.payloadJson, "processImagePath").value_or(L"");
  const auto remoteAddress = ExtractPayloadString(record.payloadJson, "remoteAddress").value_or(L"");
  if (remoteAddress.empty() && processImagePath.empty() && targetPath.empty()) {
    return std::nullopt;
  }

  return EventEnvelope{
      .kind = EventKind::NetworkConnect,
      .deviceId = deviceId,
      .correlationId = GenerateGuidString(),
      .targetPath = remoteAddress,
      .sha256 = {},
      .process = ProcessContext{
          .imagePath = processImagePath,
          .commandLine = ExtractPayloadString(record.payloadJson, "commandLine").value_or(L""),
          .parentImagePath = ExtractPayloadString(record.payloadJson, "parentProcessImagePath").value_or(L""),
          .userSid = ExtractPayloadString(record.payloadJson, "userSid").value_or(L""),
          .signer = {}},
      .occurredAt = std::chrono::system_clock::now()};
}

constexpr wchar_t kScheduledQuickScanSource[] = L"agent-service.auto.quick-scan";
constexpr wchar_t kScheduledFullDriveScanSource[] = L"agent-service.auto.full-drive-scan";
constexpr wchar_t kLiveThreatSweepSource[] = L"agent-service.auto.live-threat-sweep";
constexpr wchar_t kVulnerabilityAssessmentSource[] = L"agent-service.auto.vulnerability-assessment";
constexpr wchar_t kSignatureIntelSyncSource[] = L"agent-service.auto.signature-intelligence";
constexpr int kSignatureIntelSyncIntervalMinutes = 1440;

std::map<std::wstring, std::wstring> LoadSimpleStateFile(const std::filesystem::path& path) {
  std::map<std::wstring, std::wstring> state;
  std::wifstream input(path);
  if (!input.is_open()) {
    return state;
  }

  std::wstring line;
  while (std::getline(input, line)) {
    const auto trimmed = TrimWide(line);
    if (trimmed.empty() || trimmed.starts_with(L"#") || trimmed.starts_with(L";")) {
      continue;
    }

    const auto separator = trimmed.find(L'=');
    if (separator == std::wstring::npos) {
      continue;
    }

    const auto key = TrimWide(trimmed.substr(0, separator));
    const auto value = TrimWide(trimmed.substr(separator + 1));
    if (!key.empty()) {
      state[key] = value;
    }
  }

  return state;
}

void SaveSimpleStateFile(const std::filesystem::path& path, const std::map<std::wstring, std::wstring>& state) {
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);

  std::wofstream output(path, std::ios::trunc);
  if (!output.is_open()) {
    return;
  }

  for (const auto& [key, value] : state) {
    output << key << L"=" << value << L"\n";
  }
  output.flush();
}

bool HasInteractiveUserSession() {
  PWTS_SESSION_INFOW sessions = nullptr;
  DWORD sessionCount = 0;
  if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount) == FALSE) {
    return true;
  }

  bool hasActiveSession = false;
  for (DWORD index = 0; index < sessionCount; ++index) {
    if (sessions[index].State == WTSActive) {
      hasActiveSession = true;
      break;
    }
  }

  if (sessions != nullptr) {
    WTSFreeMemory(sessions);
  }
  return hasActiveSession;
}

std::wstring CurrentLocalDate() {
  SYSTEMTIME localTime{};
  GetLocalTime(&localTime);
  wchar_t buffer[16]{};
  swprintf(buffer, std::size(buffer), L"%04u-%02u-%02u", localTime.wYear, localTime.wMonth, localTime.wDay);
  return buffer;
}

bool ShouldRunSignatureIntelSync(const std::filesystem::path& statePath, const int intervalMinutes) {
  if (intervalMinutes <= 0) {
    return false;
  }
  if (!HasInteractiveUserSession()) {
    return false;
  }

  const auto state = LoadSimpleStateFile(statePath);
  const auto currentSyncDate = CurrentLocalDate();
  const auto lastSyncDate = [&state]() -> std::optional<std::wstring> {
    const auto explicitDate = state.find(L"lastSyncDate");
    if (explicitDate != state.end() && explicitDate->second.size() >= 10) {
      return explicitDate->second.substr(0, 10);
    }

    const auto lastSyncAt = state.find(L"lastSyncAt");
    if (lastSyncAt != state.end() && lastSyncAt->second.size() >= 10) {
      return lastSyncAt->second.substr(0, 10);
    }

    return std::nullopt;
  }();
  if (!lastSyncDate.has_value()) {
    return true;
  }
  if (*lastSyncDate != currentSyncDate) {
    return true;
  }

  const auto lastSync = [&state]() -> std::optional<std::wstring> {
    const auto iterator = state.find(L"lastSyncAt");
    if (iterator == state.end() || iterator->second.empty()) {
      return std::nullopt;
    }
    return iterator->second;
  }();
  if (!lastSync.has_value()) {
    return true;
  }

  const auto lastSyncTime = ParseUtcTimestamp(*lastSync);
  if (!lastSyncTime.has_value()) {
    return true;
  }

  const auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(std::chrono::system_clock::now() - *lastSyncTime);
  return elapsed >= std::chrono::minutes(intervalMinutes);
}

std::size_t AppendMissingThreatIntelRecords(const std::filesystem::path& databasePath,
                                            const std::vector<ThreatIntelRecord>& records) {
  if (records.empty()) {
    return 0;
  }

  RuntimeDatabase database(databasePath);
  std::size_t added = 0;
  for (const auto& record : records) {
    if (record.indicatorType == ThreatIndicatorType::Unknown || record.indicatorKey.empty()) {
      continue;
    }

    ThreatIntelRecord existing{};
    if (database.TryGetThreatIntelRecord(record.indicatorType, record.indicatorKey, existing)) {
      continue;
    }

    database.UpsertThreatIntelRecord(record);
    ++added;
  }

  return added;
}

std::wstring SanitizeSignatureField(std::wstring value) {
  std::replace(value.begin(), value.end(), L'|', L'/');
  std::replace(value.begin(), value.end(), L'\r', L' ');
  std::replace(value.begin(), value.end(), L'\n', L' ');
  return TrimWide(value);
}

std::wstring BuildSignatureRuleLine(const SignatureRuleDelta& rule) {
  if (rule.patterns.empty()) {
    return {};
  }

  std::wstring joinedPatterns;
  for (const auto& pattern : rule.patterns) {
    const auto cleanedPattern = SanitizeSignatureField(pattern);
    if (cleanedPattern.empty()) {
      continue;
    }
    if (!joinedPatterns.empty()) {
      joinedPatterns += L";";
    }
    joinedPatterns += ToLowerCopy(cleanedPattern);
  }
  if (joinedPatterns.empty()) {
    return {};
  }

  const auto scope = SanitizeSignatureField(rule.scope.empty() ? std::wstring(L"text") : ToLowerCopy(rule.scope));
  const auto code = SanitizeSignatureField(rule.code.empty() ? std::wstring(L"CLOUD_SIGNATURE") : rule.code);
  const auto message = SanitizeSignatureField(rule.message.empty() ? std::wstring(L"Cloud-fed signature match.") : rule.message);
  const auto tacticId = SanitizeSignatureField(rule.tacticId.empty() ? std::wstring(L"TA0002") : rule.tacticId);
  const auto techniqueId = SanitizeSignatureField(rule.techniqueId.empty() ? std::wstring(L"T1204.002") : rule.techniqueId);
  const auto score = std::clamp(rule.score, 1, 99);

  return scope + L"|" + code + L"|" + message + L"|" + tacticId + L"|" + techniqueId + L"|" +
         std::to_wstring(score) + L"|" + joinedPatterns;
}

std::set<std::wstring> LoadExistingNormalizedLines(const std::filesystem::path& path) {
  std::set<std::wstring> values;
  std::wifstream input(path);
  if (!input.is_open()) {
    return values;
  }

  std::wstring line;
  while (std::getline(input, line)) {
    const auto trimmed = TrimWide(line);
    if (trimmed.empty() || trimmed.starts_with(L"#") || trimmed.starts_with(L";")) {
      continue;
    }
    values.insert(ToLowerCopy(trimmed));
  }
  return values;
}

std::size_t AppendUniqueSignatureLines(const std::filesystem::path& path, const std::vector<std::wstring>& lines) {
  auto existing = LoadExistingNormalizedLines(path);
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  const auto createHeader = !std::filesystem::exists(path, error) || error;

  std::wofstream output(path, std::ios::app);
  if (!output.is_open()) {
    return 0;
  }

  if (createHeader) {
    output << L"# scope|code|message|tacticId|techniqueId|score|pattern1;pattern2;pattern3\n";
  }

  std::size_t added = 0;
  for (const auto& rawLine : lines) {
    const auto line = TrimWide(rawLine);
    if (line.empty()) {
      continue;
    }
    const auto key = ToLowerCopy(line);
    if (!existing.insert(key).second) {
      continue;
    }
    output << line << L"\n";
    ++added;
  }

  output.flush();
  return added;
}

std::wstring NormalizeRuleName(std::wstring value) {
  value = ToLowerCopy(TrimWide(std::move(value)));
  for (auto& ch : value) {
    if ((ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9') || ch == L'_') {
      continue;
    }
    ch = L'_';
  }
  return value;
}

std::wstring ExtractYaraRuleName(const std::wstring& ruleText) {
  static const std::wregex pattern(LR"(rule\s+([A-Za-z0-9_]+))", std::regex_constants::icase);
  std::wsmatch match;
  if (!std::regex_search(ruleText, match, pattern) || match.size() < 2) {
    return {};
  }
  return match[1].str();
}

std::vector<std::wstring> ExtractYaraLiteralPatterns(const std::wstring& ruleText) {
  std::vector<std::wstring> patterns;
  std::set<std::wstring> seen;

  bool insideString = false;
  bool escaping = false;
  std::wstring current;

  for (const auto ch : ruleText) {
    if (!insideString) {
      if (ch == L'"') {
        insideString = true;
        escaping = false;
        current.clear();
      }
      continue;
    }

    if (escaping) {
      current.push_back(ch);
      escaping = false;
      continue;
    }

    if (ch == L'\\') {
      escaping = true;
      continue;
    }

    if (ch == L'"') {
      insideString = false;
      const auto literal = TrimWide(current);
      const auto hasAlphaNumeric =
          std::any_of(literal.begin(), literal.end(), [](const wchar_t token) { return std::iswalnum(token) != 0; });
      if (literal.size() >= 4 && literal.size() <= 128 && hasAlphaNumeric) {
        const auto normalized = ToLowerCopy(literal);
        if (seen.insert(normalized).second) {
          patterns.push_back(normalized);
        }
      }
      current.clear();
      continue;
    }

    current.push_back(ch);
  }

  return patterns;
}

std::vector<SignatureRuleDelta> BuildSignatureRulesFromYara(const std::vector<std::wstring>& yaraRules) {
  std::vector<SignatureRuleDelta> rules;
  for (std::size_t index = 0; index < yaraRules.size(); ++index) {
    const auto patterns = ExtractYaraLiteralPatterns(yaraRules[index]);
    if (patterns.empty()) {
      continue;
    }

    auto normalizedName = NormalizeRuleName(ExtractYaraRuleName(yaraRules[index]));
    if (normalizedName.empty()) {
      normalizedName = L"dynamic_" + std::to_wstring(index + 1);
    }

    rules.push_back(SignatureRuleDelta{
        .scope = L"text",
        .code = L"YARA_" + normalizedName,
        .message = L"YARA-derived cloud signature matched suspicious string literals.",
        .tacticId = L"TA0005",
        .techniqueId = L"T1027",
        .score = 28,
        .patterns = patterns});
  }

  return rules;
}

std::size_t AppendUniqueYaraRules(const std::filesystem::path& path, const std::vector<std::wstring>& rules) {
  std::set<std::wstring> existingRuleNames;
  std::set<std::wstring> existingRuleBodies;

  std::wifstream input(path);
  if (input.is_open()) {
    std::wstringstream buffer;
    buffer << input.rdbuf();
    const auto content = buffer.str();
    std::wistringstream lineStream(content);
    std::wstring line;
    while (std::getline(lineStream, line)) {
      const auto name = NormalizeRuleName(ExtractYaraRuleName(line));
      if (!name.empty()) {
        existingRuleNames.insert(name);
      }
    }
    if (!content.empty()) {
      existingRuleBodies.insert(ToLowerCopy(TrimWide(content)));
    }
  }

  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  std::wofstream output(path, std::ios::app);
  if (!output.is_open()) {
    return 0;
  }

  std::size_t added = 0;
  for (const auto& rawRule : rules) {
    const auto rule = TrimWide(rawRule);
    if (rule.empty()) {
      continue;
    }

    const auto bodyKey = ToLowerCopy(rule);
    if (existingRuleBodies.find(bodyKey) != existingRuleBodies.end()) {
      continue;
    }

    const auto name = NormalizeRuleName(ExtractYaraRuleName(rule));
    if (!name.empty() && existingRuleNames.find(name) != existingRuleNames.end()) {
      continue;
    }

    if (!name.empty()) {
      existingRuleNames.insert(name);
    }
    existingRuleBodies.insert(bodyKey);

    output << L"\n" << rule << L"\n";
    ++added;
  }

  output.flush();
  return added;
}

std::optional<std::chrono::system_clock::time_point> ParseUtcTimestamp(const std::wstring& value) {
  if (value.empty()) {
    return std::nullopt;
  }

  int year = 0;
  int month = 0;
  int day = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;

  if (swscanf(value.c_str(), L"%4d-%2d-%2dT%2d:%2d:%2d", &year, &month, &day, &hour, &minute, &second) < 6) {
    return std::nullopt;
  }

  std::tm utc{};
  utc.tm_year = year - 1900;
  utc.tm_mon = month - 1;
  utc.tm_mday = day;
  utc.tm_hour = hour;
  utc.tm_min = minute;
  utc.tm_sec = second;
  utc.tm_isdst = 0;
  const auto epochSeconds = _mkgmtime(&utc);
  if (epochSeconds < 0) {
    return std::nullopt;
  }

  return std::chrono::system_clock::from_time_t(epochSeconds);
}

std::optional<std::wstring> FindLatestScanSessionTimestamp(const RuntimeDatabase& database,
                                                           const std::wstring& source,
                                                           const std::size_t limit = 500) {
  const auto history = database.ListScanHistory(limit);
  for (const auto& record : history) {
    if (_wcsicmp(record.contentType.c_str(), L"scan-session") == 0 && _wcsicmp(record.source.c_str(), source.c_str()) == 0 &&
        !record.recordedAt.empty()) {
      return record.recordedAt;
    }
  }

  return std::nullopt;
}

bool ShouldRunScheduledTask(const RuntimeDatabase& database, const std::wstring& source, const int intervalMinutes) {
  if (intervalMinutes <= 0) {
    return false;
  }

  const auto lastRecordedAt = FindLatestScanSessionTimestamp(database, source);
  if (!lastRecordedAt.has_value()) {
    return true;
  }

  const auto lastRecordedTime = ParseUtcTimestamp(*lastRecordedAt);
  if (!lastRecordedTime.has_value()) {
    return true;
  }

  const auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(std::chrono::system_clock::now() - *lastRecordedTime);
  return elapsed >= std::chrono::minutes(intervalMinutes);
}

// Most recent slot of a calendar scan plan at or before now, in device local time (looks back a week).
std::optional<std::chrono::system_clock::time_point> LatestPlannedSlot(const ScanPlan& plan) {
  const std::time_t nowT = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  for (int back = 0; back <= 7; ++back) {
    std::time_t dayT = nowT - static_cast<std::time_t>(back) * 24 * 60 * 60;
    std::tm local{};
    if (localtime_s(&local, &dayT) != 0) {
      return std::nullopt;
    }
    const int weekday = (local.tm_wday + 6) % 7;  // tm_wday: 0 = Sunday
    if (std::find(plan.days.begin(), plan.days.end(), weekday) == plan.days.end()) {
      continue;
    }
    local.tm_hour = plan.minuteOfDay / 60;
    local.tm_min = plan.minuteOfDay % 60;
    local.tm_sec = 0;
    local.tm_isdst = -1;
    const std::time_t slot = std::mktime(&local);
    if (slot != static_cast<std::time_t>(-1) && slot <= nowT) {
      return std::chrono::system_clock::from_time_t(slot);
    }
  }
  return std::nullopt;
}

// With a cloud schedule: run once per slot, catching up a slot missed while the device was off.
// Without one: the agent's built-in interval.
bool ShouldRunPlannedScan(const RuntimeDatabase& database, const std::wstring& source, const ScanPlan& plan,
                          const int fallbackIntervalMinutes) {
  if (!plan.present) {
    return ShouldRunScheduledTask(database, source, fallbackIntervalMinutes);
  }
  if (plan.off) {
    return false;
  }
  const auto slot = LatestPlannedSlot(plan);
  if (!slot.has_value()) {
    return false;
  }
  const auto lastRecordedAt = FindLatestScanSessionTimestamp(database, source);
  if (!lastRecordedAt.has_value()) {
    return true;
  }
  const auto lastRecordedTime = ParseUtcTimestamp(*lastRecordedAt);
  return !lastRecordedTime.has_value() || *lastRecordedTime < *slot;
}

bool IsPendingWindowsVulnerability(const WindowsUpdateRecord& record) {
  const auto lowerStatus = ToLowerCopy(record.status);
  if (lowerStatus != L"available") {
    return false;
  }

  if (record.hidden || record.installed) {
    return false;
  }

  if (record.mandatory) {
    return true;
  }

  const auto lowerClassification = ToLowerCopy(record.classification);
  if (lowerClassification.find(L"security") != std::wstring::npos || lowerClassification.find(L"critical") != std::wstring::npos) {
    return true;
  }

  const auto lowerSeverity = ToLowerCopy(record.severity);
  return lowerSeverity.find(L"critical") != std::wstring::npos || lowerSeverity.find(L"important") != std::wstring::npos ||
         lowerSeverity.find(L"high") != std::wstring::npos;
}

bool IsPendingSoftwareVulnerability(const SoftwarePatchRecord& record) {
  if (!record.supported) {
    return false;
  }

  const auto lowerState = ToLowerCopy(record.updateState);
  if (lowerState != L"available") {
    return false;
  }

  return record.highRisk || !record.manualOnly;
}

}  // namespace

AgentService::AgentService() = default;

AgentService::~AgentService() {
  if (localControlChannel_) {
    localControlChannel_->Stop();
    localControlChannel_.reset();
  }
  if (pamRequestEvent_ != nullptr) {
    CloseHandle(pamRequestEvent_);
    pamRequestEvent_ = nullptr;
  }
  StopRealtimeChannel();
  if (firewallThread_.joinable()) {
    firewallThread_.join();  // bounded by the script's three-minute timeout
  }
  if (wakeEvent_ != nullptr) {
    CloseHandle(wakeEvent_);
    wakeEvent_ = nullptr;
  }
  if (stopEvent_ != nullptr) {
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
  }
}

int AgentService::Run(const AgentRunMode mode) {
  mainThreadId_ = std::this_thread::get_id();
  try {
    if (stopEvent_ == nullptr) {
      stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (stopEvent_ == nullptr) {
        throw std::runtime_error("Unable to create the agent stop event");
      }
    }

    if (pamRequestEvent_ == nullptr) {
      pamRequestEvent_ = CreateEventW(nullptr, TRUE, FALSE, kPamRequestEventName);
    }
    if (wakeEvent_ == nullptr) {
      wakeEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    }

    config_ = LoadAgentConfig();
    stateStore_ = std::make_unique<LocalStateStore>(config_.runtimeDatabasePath, config_.stateFilePath);
    controlPlaneClient_ = std::make_unique<ControlPlaneClient>(config_.controlPlaneBaseUrl);
    commandJournalStore_ = std::make_unique<CommandJournalStore>(config_.runtimeDatabasePath);
    telemetryQueueStore_ = std::make_unique<TelemetryQueueStore>(config_.runtimeDatabasePath, config_.telemetryQueuePath);
    realtimeProtectionBroker_ = std::make_unique<RealtimeProtectionBroker>(config_);
    processGuard_ = std::make_unique<ProcessGuard>(config_.installRootPath, config_.runtimeDatabasePath.parent_path());
    ml::SetDefaultModelPath(processGuard_->ModelPath().wstring());
    processEtwSensor_ = std::make_unique<ProcessEtwSensor>(config_);
    processEtwSensor_->SetProcessStartHandler(
        [guard = processGuard_.get()](const EtwProcessContext& process) { return guard->OnProcessStart(process); });
    processEtwSensor_->SetRemoteThreadHandler([guard = processGuard_.get()](const EtwProcessContext& source, DWORD target) {
      return guard->OnRemoteThread(source, target);
    });
    networkIsolationManager_ = std::make_unique<NetworkIsolationManager>(config_);
    ransomwareShield_ = std::make_unique<RansomwareShield>(config_.runtimeDatabasePath.parent_path());
    ransomwareShield_->SetUrgentCallback([this] {
      if (wakeEvent_ != nullptr) SetEvent(wakeEvent_);  // send a detection now, not at the next cycle
    });
    bruteForceGuard_ = std::make_unique<BruteForceGuard>(config_.runtimeDatabasePath.parent_path());
    registryWatcher_ = std::make_unique<RegistryWatcher>();
    bruteForceGuard_->SetUrgentCallback([this] {
      if (wakeEvent_ != nullptr) SetEvent(wakeEvent_);
    });

    LoadLocalPolicyCache();
    PublishIdentitySnapshot();
    ApplyProtectionPolicy();
    RelaunchClientAfterUpgrade();
    realtimeProtectionBroker_->SetPolicy(EnforcedPolicy());
    realtimeProtectionBroker_->SetDeviceId(state_.deviceId);
    processEtwSensor_->SetDeviceId(state_.deviceId);
    networkIsolationManager_->SetDeviceId(state_.deviceId);

    realtimeProtectionBroker_->Start();
    processEtwSensor_->Start();
    networkIsolationManager_->Start();
    localControlChannel_ = std::make_unique<LocalControlChannel>(
        [this](const RemoteCommand& command) { return ExecuteCommand(command); },
        [this]() { return ShouldStop(); });
    localControlChannel_->Start();

    QueueEndpointStatusTelemetry();
    if (state_.isolated) {
      std::wstring isolationError;
      if (!networkIsolationManager_->ApplyIsolation(true, &isolationError)) {
        state_.isolated = false;
        QueueTelemetryEvent(L"network.isolation.resume.failed", L"network-wfp",
                            L"The endpoint could not restore WFP-backed isolation during startup.",
                            std::wstring(L"{\"errorMessage\":\"") +
                                Utf8ToWide(EscapeJsonString(isolationError.empty() ? L"Unknown startup isolation failure"
                                                                                  : isolationError)) +
                                L"\"}");
      }
    }

    StartTelemetrySpool();
    StartCommandLoop();
    StartRealtimeChannel();
    QueueTelemetryEvent(L"service.started", L"agent-service", L"The endpoint agent boot sequence started.",
                        L"{\"phase\":\"bootstrap\"}");

    RunSyncLoop(mode);
    StopRealtimeChannel();
    DrainProcessTelemetry();
    DrainRansomwareTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();

    if (localControlChannel_) {
      localControlChannel_->Stop();
      localControlChannel_.reset();
    }
    if (networkIsolationManager_) {
      networkIsolationManager_->Stop();
    }
    if (processEtwSensor_) {
      processEtwSensor_->Stop();
    }
    if (ransomwareShield_) {
      ransomwareShield_->Stop();
    }
    if (bruteForceGuard_) {
      bruteForceGuard_->Stop();
    }
    if (registryWatcher_) {
      registryWatcher_->Stop();
    }
    if (realtimeProtectionBroker_) {
      realtimeProtectionBroker_->Stop();
    }

    PersistState();

    if (mode == AgentRunMode::Console) {
      std::wcout << L"Agent service is running." << std::endl;
      PrintStatus();
    }
    return 0;
  } catch (const std::exception& error) {
    std::wcerr << L"Agent service failed to initialize: " << Utf8ToWide(error.what()) << std::endl;
    StopRealtimeChannel();  // a running thread left behind would crash the process on exit
    return 1;  // non-zero: Windows' recovery actions restart the service
  }
}

void AgentService::RequestStop() {
  stopRequested_->store(true);  // also cancels a running background scan
  if (stopEvent_ != nullptr) {
    SetEvent(stopEvent_);
  }
  if (localControlChannel_) {
    localControlChannel_->Stop();
  }
}

std::wstring AgentService::BuildCyclePayload(const int cycle, const std::wstring& extraFields) {
  std::wstring payload = L"{\"cycle\":";
  payload += std::to_wstring(cycle);
  if (!extraFields.empty()) {
    payload += L",";
    payload += extraFields;
  }
  payload += L"}";
  return payload;
}

std::vector<std::filesystem::path> AgentService::BuildMonitoredRoots() const {
  std::vector<std::filesystem::path> roots;

  const auto userProfile = ReadEnvironmentVariable(L"USERPROFILE");
  if (!userProfile.empty()) {
    roots.emplace_back(std::filesystem::path(userProfile) / L"Downloads");
    roots.emplace_back(std::filesystem::path(userProfile) / L"Desktop");
    roots.emplace_back(std::filesystem::path(userProfile) / L"Documents");
  }

  roots.emplace_back(LR"(C:\Users\Public\Downloads)");
  return roots;
}

void AgentService::RunSyncLoop(const AgentRunMode mode) {
  const auto configuredIterations = std::max(config_.syncIterations, 1);
  int cycle = 1;

  while (!ShouldStop()) {
    // One bad cycle (a scan, the database, the network) must never stop the agent: log it and carry on.
    try {
    ProcessPamRequests();
    QueueCycleTelemetry(cycle);
    DrainProcessTelemetry();
    DrainRansomwareTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    DrainDeferredTelemetry();
    if (config_.managedMode) {
      // Check in before the scans: a first full-drive scan can take hours.
      SyncWithControlPlane(cycle);
      PublishIdentitySnapshot();
      PollAndExecuteCommands(cycle);
      FlushTelemetryQueue();
      PublishHeartbeat(cycle);
      MaybeSelfUpdate(cycle);
      ExpireBreakGlassAccount();
      ExpireElevations();
      if (GetTickCount64() - lastLocalAdminCheck_ > 60ULL * 60 * 1000 || lastLocalAdminCheck_ == 0) {
        lastLocalAdminCheck_ = GetTickCount64();
        EnforceLocalAdminPolicy();
        try {
          RotateLocalAdminPassword(false);
        } catch (const std::exception& error) {
          QueueTelemetryEvent(L"laps.rotation.failed", L"laps", L"The local admin password could not be rotated.",
                              L"{\"error\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}");
        }
      }
    }
    SyncUpdateOnly(cycle);
    RunAutomatedRiskAssessments(cycle);
    DrainProcessTelemetry();
    DrainRansomwareTelemetry();
    DrainRealtimeProtectionTelemetry();
    DrainNetworkTelemetry();
    if (config_.managedMode) {
      FlushTelemetryQueue();
    }
    PersistState();
    } catch (const std::exception& error) {
      std::wcerr << L"Sync cycle " << cycle << L" failed, continuing: " << Utf8ToWide(error.what()) << std::endl;
      try {
        QueueTelemetryEvent(L"agent.cycle.failed", L"agent-service", L"A sync cycle failed; the agent carried on.",
                            BuildCyclePayload(cycle, L"\"error\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\""));
      } catch (...) {
      }
    } catch (...) {
      std::wcerr << L"Sync cycle " << cycle << L" failed with an unknown error, continuing." << std::endl;
    }

    if (mode == AgentRunMode::Console && cycle >= configuredIterations) {
      break;
    }

    ++cycle;
    if (!WaitForNextCycle(mode, cycle)) {
      break;
    }
  }
}

void AgentService::RunAutomatedRiskAssessments(const int cycle) {
  RunScheduledQuickScan(cycle);
  RunLiveThreatSweep(cycle);
  RunVulnerabilityAssessment(cycle);
  RunScheduledFullDriveScan(cycle);
}

void AgentService::RunScheduledQuickScan(const int cycle) {
  try {
    RuntimeDatabase database(config_.runtimeDatabasePath);
    const auto plan = policy_.modulesJson.empty() ? ScanPlan{} : ExtendedPolicy::Parse(policy_.modulesJson).quickScanPlan;
    if (!ShouldRunPlannedScan(database, kScheduledQuickScanSource, plan, config_.scheduledQuickScanIntervalMinutes)) {
      return;
    }

    // Runs in the background; skipped this cycle if another scan is still running.
    StartBackgroundScan(L"scan.quick-scheduled", L"quick", kScheduledQuickScanSource, BuildQuickScanTargets(),
                        ScheduledScanCpuLimit());
  } catch (const std::exception& error) {
    QueueTelemetryEvent(L"scan.quick-scheduled.failed", L"agent-service",
                        L"The endpoint failed to complete a scheduled quick scan.",
                        BuildCyclePayload(cycle, std::wstring(L"\"scope\":\"quick\",\"error\":\"") +
                                                     Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\""));
  }
}

void AgentService::RunScheduledFullDriveScan(const int cycle) {
  try {
    RuntimeDatabase database(config_.runtimeDatabasePath);
    const auto plan = policy_.modulesJson.empty() ? ScanPlan{} : ExtendedPolicy::Parse(policy_.modulesJson).fullScanPlan;
    if (!ShouldRunPlannedScan(database, kScheduledFullDriveScanSource, plan,
                              config_.scheduledFullDriveScanIntervalMinutes)) {
      return;
    }
    // A fresh install waits a day before its first full-drive scan (it can take hours and holds up
    // commands and remote sessions); quick scans and the live sweep still run straight away.
    if (!FindLatestScanSessionTimestamp(database, kScheduledFullDriveScanSource).has_value()) {
      WIN32_FILE_ATTRIBUTE_DATA attributes{};
      if (GetFileAttributesExW(config_.runtimeDatabasePath.c_str(), GetFileExInfoStandard, &attributes) != FALSE) {
        FILETIME now{};
        GetSystemTimeAsFileTime(&now);
        const auto toTicks = [](const FILETIME& value) {
          return (static_cast<unsigned long long>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
        };
        constexpr unsigned long long kTicksPerDay = 24ULL * 60 * 60 * 10000000ULL;
        if (toTicks(now) - toTicks(attributes.ftCreationTime) < kTicksPerDay) {
          return;
        }
      }
    }

    StartBackgroundScan(L"scan.scheduled", L"full", kScheduledFullDriveScanSource, BuildFullScanTargets(ScanNetworkDrives()),
                        ScheduledScanCpuLimit());
  } catch (const std::exception& error) {
    QueueTelemetryEvent(L"scan.scheduled.failed", L"agent-service",
                        L"The endpoint failed to complete a scheduled full C: drive scan.",
                        BuildCyclePayload(cycle, std::wstring(L"\"scope\":\"C:\\\\\",\"error\":\"") +
                                                     Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\""));
  }
}

void AgentService::RunLiveThreatSweep(const int cycle) {
  try {
    RuntimeDatabase database(config_.runtimeDatabasePath);
    if (!ShouldRunScheduledTask(database, kLiveThreatSweepSource, config_.liveThreatSweepIntervalMinutes)) {
      return;
    }

    const auto processInventory = CollectProcessInventory();
    std::vector<std::filesystem::path> liveTargets;
    std::set<std::wstring> seenTargets;
    for (const auto& process : processInventory) {
      if (process.imagePath.empty()) {
        continue;
      }

      std::filesystem::path candidate(process.imagePath);
      std::error_code error;
      candidate = std::filesystem::absolute(candidate, error);
      if (error || candidate.empty() || !std::filesystem::exists(candidate, error) || error) {
        continue;
      }

      const auto dedupeKey = ToLowerCopy(candidate.lexically_normal().wstring());
      if (seenTargets.insert(dedupeKey).second) {
        liveTargets.push_back(candidate);
      }
    }

    QueueTelemetryEvent(L"scan.live-threat-sweep.started", L"agent-service",
                        L"The endpoint is starting a live threat sweep for active process images.",
                        BuildCyclePayload(cycle, std::wstring(L"\"runningProcesses\":") +
                                                     std::to_wstring(processInventory.size()) + L",\"targets\":"
                                                     + std::to_wstring(liveTargets.size())));

    LocalScanExecutionOptions options{};
    options.source = kLiveThreatSweepSource;
    options.queueTelemetry = true;
    options.applyRemediation = true;
    const auto result = ExecuteLocalScan(config_, state_, liveTargets, options);

    QueueTelemetryEvent(L"scan.live-threat-sweep.completed", L"agent-service",
                        L"The endpoint completed a live threat sweep.",
                        BuildCyclePayload(cycle, std::wstring(L"\"targetsScanned\":") +
                                                     std::to_wstring(result.targetCount) + L",\"findings\":"
                                                     + std::to_wstring(result.findings.size()) +
                                                     L",\"remediationFailed\":"
                                                     + (result.remediationFailed ? std::wstring(L"true")
                                                                                 : std::wstring(L"false"))));
  } catch (const std::exception& error) {
    QueueTelemetryEvent(L"scan.live-threat-sweep.failed", L"agent-service",
                        L"The endpoint failed to complete a live threat sweep.",
                        BuildCyclePayload(cycle, std::wstring(L"\"error\":\"") +
                                                     Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\""));
  }
}

void AgentService::RunVulnerabilityAssessment(const int cycle) {
  try {
    RuntimeDatabase database(config_.runtimeDatabasePath);
    if (!ShouldRunScheduledTask(database, kVulnerabilityAssessmentSource,
                                config_.vulnerabilityAssessmentIntervalMinutes)) {
      return;
    }

    PatchOrchestrator orchestrator(config_);
    const auto refreshSummary = orchestrator.RefreshPatchState();
    const auto snapshot = orchestrator.LoadSnapshot(200, 200, 50, 200);

    std::size_t pendingWindowsVulnerabilities = 0;
    std::size_t pendingSoftwareVulnerabilities = 0;
    for (const auto& update : snapshot.windowsUpdates) {
      if (IsPendingWindowsVulnerability(update)) {
        ++pendingWindowsVulnerabilities;
      }
    }
    for (const auto& software : snapshot.software) {
      if (IsPendingSoftwareVulnerability(software)) {
        ++pendingSoftwareVulnerabilities;
      }
    }

    const auto pendingTotal = pendingWindowsVulnerabilities + pendingSoftwareVulnerabilities;
    const auto summary =
        pendingTotal == 0
            ? std::wstring(L"No pending high-priority vulnerabilities were detected.")
            : std::to_wstring(pendingTotal) +
                  (pendingTotal == 1 ? std::wstring(L" pending vulnerability detected.")
                                     : std::wstring(L" pending vulnerabilities detected."));

    QueueTelemetryEvent(L"vulnerability.assessment.completed", L"patch-orchestrator",
                        L"The endpoint completed a vulnerability assessment pass.",
                        BuildCyclePayload(cycle, std::wstring(L"\"pendingTotal\":") +
                                                     std::to_wstring(pendingTotal) +
                                                     L",\"pendingWindows\":"
                                                     + std::to_wstring(pendingWindowsVulnerabilities) +
                                                     L",\"pendingSoftware\":"
                                                     + std::to_wstring(pendingSoftwareVulnerabilities) +
                                                     L",\"windowsCatalog\":"
                                                     + std::to_wstring(refreshSummary.windowsUpdateCount) +
                                                     L",\"softwareCatalog\":"
                                                     + std::to_wstring(refreshSummary.softwareCount) +
                                                     L",\"summary\":\"" +
                                                     Utf8ToWide(EscapeJsonString(summary)) + L"\""));

    database.RecordScanHistory(ScanHistoryRecord{
        .recordedAt = CurrentUtcTimestamp(),
        .source = kVulnerabilityAssessmentSource,
        .subjectPath = std::filesystem::path(L"[Vulnerability assessment]"),
        .sha256 = L"",
        .contentType = L"scan-session",
        .reputation = summary,
        .disposition = pendingTotal == 0 ? L"completed-clean" : L"completed-with-findings",
        .confidence = pendingTotal == 0 ? 100u : 85u,
        .tacticId = L"",
        .techniqueId = L"",
        .remediationStatus = pendingTotal == 0 ? L"completed" : L"review-required",
        .evidenceRecordId = L"",
        .quarantineRecordId = L"",
        .alertTitle = pendingTotal == 0 ? L"Vulnerability assessment complete"
                                        : L"Vulnerability findings require patching",
        .contextType = L"local",
        .sourceApplication = L"patch-orchestrator",
        .originReference = L"",
        .contextJson = std::wstring(L"{\"pendingWindows\":") + std::to_wstring(pendingWindowsVulnerabilities) +
                       L",\"pendingSoftware\":" + std::to_wstring(pendingSoftwareVulnerabilities) + L"}"});
  } catch (const std::exception& error) {
    QueueTelemetryEvent(L"vulnerability.assessment.failed", L"patch-orchestrator",
                        L"The endpoint failed to complete a vulnerability assessment pass.",
                        BuildCyclePayload(cycle, std::wstring(L"\"error\":\"") +
                                                     Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\""));
  }
}

bool AgentService::WaitForNextCycle(const AgentRunMode mode, const int nextCycle) {
  if (ShouldStop()) {
    return false;
  }

  if (mode == AgentRunMode::Console) {
    std::wcout << L"Sleeping " << config_.syncIntervalSeconds << L" seconds before sync cycle " << nextCycle
               << std::endl;
  }

  const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(std::max(config_.syncIntervalSeconds, 1)) * 1000;
  for (;;) {
    const auto now = GetTickCount64();
    if (now >= deadline) {
      return true;
    }
    CheckRemovableMedia();
    ApplyPauseState();
    HANDLE events[2] = {stopEvent_, wakeEvent_};
    const DWORD count = wakeEvent_ != nullptr ? 2 : 1;
    // Wake every few seconds to notice USB drives being plugged in.
    const auto signalled =
        WaitForMultipleObjects(count, events, FALSE, static_cast<DWORD>(std::min<ULONGLONG>(deadline - now, 3000)));
    if (signalled == WAIT_TIMEOUT) {
      continue;
    }
    if (signalled == WAIT_OBJECT_0) {
      return false;
    }
    if (signalled == WAIT_OBJECT_0 + 1) {
      // The cloud queued something (a remote session, a script): run it now instead of at the next cycle.
      try {
        DrainDeferredTelemetry();
        PollAndExecuteCommands(nextCycle);
        DrainProcessTelemetry();
        // Detections (ransomware, brute force) also wake the loop: send them now.
        DrainRansomwareTelemetry();
        if (config_.managedMode) {
          FlushTelemetryQueue();
        }
      } catch (const std::exception& error) {
        std::wcerr << L"Handling a wake-up failed, continuing: " << Utf8ToWide(error.what()) << std::endl;
      } catch (...) {
      }
      continue;
    }
    return true;
  }
}

void AgentService::CheckRemovableMedia() {
  const auto drives = GetLogicalDrives();
  unsigned long removable = 0;
  for (int i = 2; i < 26; ++i) {  // C: onwards; A: and B: are floppy letters
    if ((drives & (1UL << i)) == 0) continue;
    const wchar_t root[4] = {static_cast<wchar_t>(L'A' + i), L':', L'\\', 0};
    if (GetDriveTypeW(root) == DRIVE_REMOVABLE) removable |= 1UL << i;
  }
  if (!drivesPrimed_) {
    // Drives already attached when the service starts are not rescanned on every restart.
    drivesPrimed_ = true;
    knownDrives_ = removable;
    return;
  }
  pendingRemovable_ |= removable & ~knownDrives_;
  pendingRemovable_ &= removable;  // unplugged before its scan started
  knownDrives_ = removable;
  if (pendingRemovable_ == 0) return;
  const auto extended = policy_.modulesJson.empty() ? ExtendedPolicy{} : ExtendedPolicy::Parse(policy_.modulesJson);
  if (!extended.scanRemovableMedia) {
    pendingRemovable_ = 0;
    return;
  }
  for (int i = 2; i < 26; ++i) {
    if ((pendingRemovable_ & (1UL << i)) == 0) continue;
    const std::wstring root = std::wstring(1, static_cast<wchar_t>(L'A' + i)) + L":\\";
    // One scan at a time: if another is running, try again on the next tick.
    if (StartBackgroundScan(L"scan.removable", L"removable drive " + root.substr(0, 2), L"removable:" + root.substr(0, 2),
                            {std::filesystem::path(root)})) {
      pendingRemovable_ &= ~(1UL << i);
    }
    break;
  }
}

bool AgentService::ShouldStop() const {
  return stopEvent_ != nullptr && WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0;
}

void AgentService::ProcessPamRequests() {
  if (pamRequestEvent_ == nullptr || WaitForSingleObject(pamRequestEvent_, 0) != WAIT_OBJECT_0) {
    return;
  }

  ResetEvent(pamRequestEvent_);
  QueueTelemetryEvent(L"pam.request.observed", L"local-control",
                      L"A privileged access request was observed and queued for later handling.",
                      std::wstring(L"{\"requestPath\":\"") +
                          Utf8ToWide(EscapeJsonString(GetPamRequestPath().wstring())) + L"\"}");
}

std::filesystem::path AgentService::GetPamRequestPath() const {
  return ResolveRuntimeRoot(config_) / kPamRequestFileName;
}

std::vector<std::filesystem::path> AgentService::GetPamRequestPaths() const {
  return {GetPamRequestPath()};
}

std::filesystem::path AgentService::GetPamAuditJournalPath() const {
  return ResolveRuntimeRoot(config_) / kPamAuditFileName;
}

void AgentService::SyncWithControlPlane(const int cycle) {
  bool attemptedRecovery = false;

  for (;;) {
    try {
      EnsureEnrollment();
      RefreshPolicy(cycle);
      lastControlPlaneSyncFailed_ = false;
      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"control-plane sync")) {
        attemptedRecovery = true;
        continue;
      }

      lastControlPlaneSyncFailed_ = true;
      QueueTelemetryEvent(L"control-plane.sync.failed", L"control-plane-client",
                          L"The agent could not complete a control-plane sync and is using cached state.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Control-plane sync failed, continuing with cached state: " << Utf8ToWide(error.what())
                 << std::endl;
      return;
    }
  }
}

void AgentService::SyncUpdateOnly(const int cycle) {
  try {
    RuntimeDatabase database(config_.runtimeDatabasePath);
    const auto journal = database.ListUpdateJournal(200);

    std::set<std::wstring> appliedUpdateKeys;
    std::wstring signaturesVersion;
    for (const auto& record : journal) {
      if (!record.packageId.empty() && !record.targetVersion.empty() && IsAppliedUpdateStatus(record.status)) {
        appliedUpdateKeys.insert(BuildUpdateIdentityKey(record.packageId, record.targetVersion));
      }

      if (signaturesVersion.empty() && IsAppliedUpdateStatus(record.status) &&
          ToLowerCopy(record.packageType) == L"signatures" && !record.targetVersion.empty()) {
        signaturesVersion = record.targetVersion;
      }
    }

    const auto updateCheck = controlPlaneClient_->CheckForUpdates(state_, signaturesVersion);
    state_.lastPolicySyncAt = updateCheck.checkedAt;
    state_.lastHeartbeatAt = updateCheck.checkedAt;

    if (!updateCheck.items.empty()) {
      QueueTelemetryEvent(L"updates.polled", L"control-plane-client",
                          L"The endpoint checked for signature and platform update manifests.",
                          BuildCyclePayload(cycle, std::wstring(L"\"count\":") +
                                                     std::to_wstring(updateCheck.items.size())));
    }

    const auto installRoot = ResolveInstallRootForConfig(config_);
    UpdaterService updater(config_, installRoot);

    for (const auto& offer : updateCheck.items) {
      if (offer.manifestPath.empty()) {
        continue;
      }

      const auto updateKey = BuildUpdateIdentityKey(offer.packageId, offer.targetVersion);
      if (!offer.packageId.empty() && !offer.targetVersion.empty() &&
          appliedUpdateKeys.find(updateKey) != appliedUpdateKeys.end()) {
        QueueTelemetryEvent(L"update.skipped.current", L"update-client",
                            L"The endpoint skipped an already-applied update target version.",
                            std::wstring(L"{\"packageId\":\"") + offer.packageId + L"\",\"targetVersion\":\"" +
                                offer.targetVersion + L"\"}");
        continue;
      }

      const auto result = updater.ApplyPackage(offer.manifestPath, UpdateApplyMode::InService);
      if (!result.success) {
        QueueTelemetryEvent(L"update.apply.failed", L"update-client",
                            L"The endpoint failed to apply an available update package.",
                            std::wstring(L"{\"packageId\":\"") + offer.packageId + L"\",\"targetVersion\":\"" +
                                offer.targetVersion + L"\",\"error\":\"" +
                                Utf8ToWide(EscapeJsonString(result.errorMessage)) + L"\"}");
        continue;
      }

      if (ToLowerCopy(offer.packageType) == L"platform" && !offer.targetVersion.empty()) {
        state_.platformVersion = offer.targetVersion;
      }

      if (!offer.packageId.empty() && !offer.targetVersion.empty()) {
        appliedUpdateKeys.insert(updateKey);
      }

      QueueTelemetryEvent(L"update.applied", L"update-client",
                          L"The endpoint applied an update package from the update feed.",
                          std::wstring(L"{\"packageId\":\"") + result.packageId + L"\",\"targetVersion\":\"" +
                              result.targetVersion + L"\",\"transactionId\":\"" + result.transactionId +
                              L"\",\"restartRequired\":" +
                              (result.restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}");
    }

    const auto signatureRuntimeDirectory = config_.updateRootPath / L"signatures";
    const auto signatureStatePath = signatureRuntimeDirectory / L"delta-sync-state.ini";
    if (ShouldRunSignatureIntelSync(signatureStatePath, kSignatureIntelSyncIntervalMinutes)) {
      SyncMlModel(cycle);
      auto signatureSyncState = LoadSimpleStateFile(signatureStatePath);
      const auto currentSignatureVersion = signatureSyncState[L"signatureVersion"];
      const auto currentYaraVersion = signatureSyncState[L"yaraVersion"];

      try {
        const auto signatureDelta =
            controlPlaneClient_->FetchSignatureDelta(currentSignatureVersion, currentYaraVersion,
                                                     config_.signatureFeedToken);
        auto signatureRules = signatureDelta.signatures;
        const auto yaraDerivedRules = BuildSignatureRulesFromYara(signatureDelta.yaraRules);
        signatureRules.insert(signatureRules.end(), yaraDerivedRules.begin(), yaraDerivedRules.end());

        std::vector<std::wstring> signatureLines;
        signatureLines.reserve(signatureRules.size());
        for (const auto& rule : signatureRules) {
          const auto line = BuildSignatureRuleLine(rule);
          if (!line.empty()) {
            signatureLines.push_back(line);
          }
        }

        const auto signaturesPath = signatureRuntimeDirectory / L"daily-signatures.tsv";
        const auto yaraPath = signatureRuntimeDirectory / L"daily-yara.yar";
        const auto addedSignatures = AppendUniqueSignatureLines(signaturesPath, signatureLines);
        const auto addedYaraRules = AppendUniqueYaraRules(yaraPath, signatureDelta.yaraRules);
        const auto addedThreatIntel =
            AppendMissingThreatIntelRecords(config_.runtimeDatabasePath, signatureDelta.threatIntelRecords);

        signatureSyncState[L"lastSyncAt"] = CurrentUtcTimestamp();
        signatureSyncState[L"lastSyncDate"] = CurrentLocalDate();
        if (!signatureDelta.signatureVersion.empty()) {
          signatureSyncState[L"signatureVersion"] = signatureDelta.signatureVersion;
        }
        if (!signatureDelta.yaraVersion.empty()) {
          signatureSyncState[L"yaraVersion"] = signatureDelta.yaraVersion;
        }
        signatureSyncState[L"lastStatus"] = L"ok";
        signatureSyncState[L"lastError"] = L"";
        SaveSimpleStateFile(signatureStatePath, signatureSyncState);

        QueueTelemetryEvent(
            L"signatures.delta.applied", L"signature-intel",
            L"The endpoint merged additive signature and YARA intelligence from the control plane.",
            BuildCyclePayload(
                cycle, std::wstring(L"\"source\":\"") + kSignatureIntelSyncSource + L"\",\"addedSignatures\":" +
                           std::to_wstring(addedSignatures) + L",\"addedYaraRules\":" +
                           std::to_wstring(addedYaraRules) + L",\"addedThreatIntel\":" +
                           std::to_wstring(addedThreatIntel) + L",\"signatureVersion\":\"" +
                           Utf8ToWide(EscapeJsonString(signatureSyncState[L"signatureVersion"])) +
                           L"\",\"yaraVersion\":\"" +
                           Utf8ToWide(EscapeJsonString(signatureSyncState[L"yaraVersion"])) + L"\""));
      } catch (const std::exception& signatureError) {
        const auto signatureErrorMessage = Utf8ToWide(signatureError.what());
        signatureSyncState[L"lastSyncAt"] = CurrentUtcTimestamp();
        signatureSyncState[L"lastSyncDate"] = CurrentLocalDate();
        signatureSyncState[L"lastStatus"] = L"failed";
        signatureSyncState[L"lastError"] = signatureErrorMessage;
        SaveSimpleStateFile(signatureStatePath, signatureSyncState);

        QueueTelemetryEvent(
            L"signatures.delta.failed", L"signature-intel",
            L"The endpoint could not merge signature intelligence deltas and kept the local rule baseline.",
            BuildCyclePayload(cycle, std::wstring(L"\"source\":\"") + kSignatureIntelSyncSource + L"\",\"error\":\"" +
                                      Utf8ToWide(EscapeJsonString(signatureErrorMessage)) + L"\""));
      }
    }

    const auto wfpIsolationActive = networkIsolationManager_ && networkIsolationManager_->IsolationActive();
    const auto wfpUnavailable =
        policy_.networkContainmentEnabled && (!networkIsolationManager_ || !networkIsolationManager_->EngineReady());
    state_.isolated = wfpIsolationActive;
    state_.healthState = wfpIsolationActive
                             ? L"isolated"
                             : ((wfpUnavailable || lastHardeningCheckFailed_) ? L"degraded" : L"healthy");

    lastControlPlaneSyncFailed_ = false;
  } catch (const std::exception& error) {
    lastControlPlaneSyncFailed_ = true;
    QueueTelemetryEvent(L"update.sync.failed", L"control-plane-client",
                        L"The endpoint failed to retrieve update metadata and kept the local baseline.",
                        BuildCyclePayload(cycle));
    std::wcerr << L"Update sync failed, keeping local baselines: " << Utf8ToWide(error.what()) << std::endl;
  }
}

void AgentService::EnsureEnrollment() {
  if (!state_.deviceId.empty()) {
    return;
  }

  const auto enrollment = controlPlaneClient_->Enroll(state_, config_.enrollmentToken);
  state_.deviceId = enrollment.deviceId;
  state_.commandChannelUrl = enrollment.commandChannelUrl;
  state_.lastEnrollmentAt = enrollment.issuedAt;
  state_.policy = enrollment.policy;
  policy_ = enrollment.policy;
  ApplyProtectionPolicy();

  if (realtimeProtectionBroker_) {
    realtimeProtectionBroker_->SetDeviceId(state_.deviceId);
    realtimeProtectionBroker_->SetPolicy(EnforcedPolicy());
  }
  if (processEtwSensor_) {
    processEtwSensor_->SetDeviceId(state_.deviceId);
  }
  if (networkIsolationManager_) {
    networkIsolationManager_->SetDeviceId(state_.deviceId);
  }

  QueueTelemetryEvent(L"device.enrolled", L"control-plane-client",
                      L"The endpoint enrolled with the control plane.",
                      std::wstring(L"{\"deviceId\":\"") + state_.deviceId + L"\"}");
}

void AgentService::ResetEnrollmentState() {
  state_.deviceId.clear();
  state_.commandChannelUrl.clear();
  state_.lastEnrollmentAt.clear();
  state_.lastHeartbeatAt.clear();
  state_.lastPolicySyncAt.clear();
  if (realtimeProtectionBroker_) {
    realtimeProtectionBroker_->SetDeviceId(L"");
  }
  if (processEtwSensor_) {
    processEtwSensor_->SetDeviceId(L"");
  }
  if (networkIsolationManager_) {
    networkIsolationManager_->SetDeviceId(L"");
  }
}

bool AgentService::RecoverDeviceIdentity(const std::exception& error, const std::wstring& operationName) {
  const auto* rejectedError = dynamic_cast<const DeviceIdentityRejectedError*>(&error);
  if (rejectedError == nullptr) {
    return false;
  }

  const auto previousDeviceId = state_.deviceId;
  QueueTelemetryEvent(L"device.identity.rejected", L"control-plane-client",
                      L"The control plane rejected the cached device identity and the agent is re-enrolling.",
                      std::wstring(L"{\"previousDeviceId\":\"") + previousDeviceId + L"\",\"operation\":\"" +
                          Utf8ToWide(EscapeJsonString(operationName)) + L"\"}");

  ResetEnrollmentState();

  try {
    EnsureEnrollment();
    PersistState();
    return true;
  } catch (const std::exception& recoveryError) {
    std::wcerr << L"Re-enrollment after identity rejection failed: " << Utf8ToWide(recoveryError.what()) << std::endl;
    return false;
  }
}

void AgentService::RefreshPolicy(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  const auto policyCheckIn = controlPlaneClient_->CheckInPolicy(state_);
  state_.lastPolicySyncAt = policyCheckIn.retrievedAt;
  state_.policy = policyCheckIn.policy;
  policy_ = policyCheckIn.policy;
  ApplyProtectionPolicy();
  if (realtimeProtectionBroker_) {
    realtimeProtectionBroker_->SetPolicy(EnforcedPolicy());
  }

  QueueTelemetryEvent(L"policy.checked-in", L"control-plane-client",
                      policyCheckIn.changed ? L"The endpoint retrieved a newer effective policy."
                                            : L"The endpoint confirmed that policy is already current.",
                      BuildCyclePayload(cycle, std::wstring(L"\"revision\":\"") + policy_.revision + L"\""));
}

void AgentService::PollAndExecuteCommands(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  bool attemptedRecovery = false;

  for (;;) {
    try {
      const auto pollResult = controlPlaneClient_->PollPendingCommands(state_);
      if (pollResult.items.empty()) {
        return;
      }

      QueueTelemetryEvent(L"commands.polled", L"command-executor",
                          L"The endpoint pulled pending response actions from the control plane.",
                          BuildCyclePayload(cycle, std::wstring(L"\"count\":") + std::to_wstring(pollResult.items.size())));

      for (const auto& command : pollResult.items) {
        if (IsInteractiveCommand(command.type) && interactiveLoopRunning_) {
          continue;  // the interactive thread runs these
        }
        ExecuteJournaledCommand(command, state_);
      }

      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"command polling")) {
        attemptedRecovery = true;
        continue;
      }

      QueueTelemetryEvent(L"command.poll.failed", L"command-executor",
                          L"The endpoint could not retrieve pending commands from the control plane.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Command polling failed: " << Utf8ToWide(error.what()) << std::endl;
      return;
    }
  }
}

bool AgentService::IsInteractiveCommand(const std::wstring& type) {
  return type == L"remote.session.start" || type == L"remote.session.end";
}

void AgentService::ExecuteJournaledCommand(const RemoteCommand& command, const AgentState& identity) {
  if (!commandJournalStore_) {
    std::wcerr << L"Cannot execute remote command without its durable journal." << std::endl;
    return;
  }
  // Previously executed commands may be re-polled if the cloud did not
  // receive the completion. Never perform their side effects again.
  try {
    std::wstring savedStatus;
    std::wstring savedResult;
    if (commandJournalStore_->LoadReceipt(command.commandId, savedStatus, savedResult)) {
      if (savedStatus == L"started" || savedStatus == L"polled") {
        savedStatus = L"failed";
        savedResult = L"{\"outcomeUncertain\":true,\"error\":\"Agent stopped while command execution was in progress; manual review required. No automatic replay.\"}";
        commandJournalStore_->RecordFailed(command, savedResult,
                                            L"Interrupted command; outcome uncertain");
      }
      if (savedStatus == L"completed" || savedStatus == L"failed") {
        try {
          controlPlaneClient_->CompleteCommand(identity, command.commandId, savedStatus, savedResult);
        } catch (const std::exception& error) {
          std::wcerr << L"Could not replay command outcome: " << Utf8ToWide(error.what()) << std::endl;
        }
        return;
      }
      std::wcerr << L"Unrecognised prior command state; manual investigation needed." << std::endl;
      return;
    }
    // Atomic sqlite commit before any potentially irreversible action.
    commandJournalStore_->RecordPolled(command);
  } catch (const std::exception& error) {
    std::wcerr << L"Cannot safely journal command before execution: " << Utf8ToWide(error.what()) << std::endl;
    return;
  }

  std::wstring resultJson;
  std::wstring completionStatus = L"completed";
  std::wstring failureReason;
  try {
    resultJson = ExecuteCommand(command);
  } catch (const rmm::CommandFailed& failed) {
    completionStatus = L"failed";
    failureReason = Utf8ToWide(failed.what());
    resultJson = Utf8ToWide(failed.resultJson);
    if (!resultJson.empty() && resultJson.back() == L'}') {
      resultJson.pop_back();
      resultJson += std::wstring(resultJson.size() > 1 ? L"," : L"") + L"\"error\":\"" +
                    Utf8ToWide(EscapeJsonString(failureReason)) + L"\"}";
    }
  } catch (const std::exception& error) {
    completionStatus = L"failed";
    failureReason = Utf8ToWide(error.what());
    resultJson = std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"error\":\"" +
                 Utf8ToWide(EscapeJsonString(failureReason)) + L"\"}";
  }

  try {
    if (completionStatus == L"completed") {
      commandJournalStore_->RecordCompleted(command, resultJson);
    } else {
      commandJournalStore_->RecordFailed(command, resultJson, failureReason);
    }
  } catch (const std::exception& error) {
    // Do not acknowledge work whose result cannot survive a process
    // restart. The 'started' journal entry will require manual review.
    std::wcerr << L"Remote command result persistence failed: " << Utf8ToWide(error.what()) << std::endl;
    return;
  }

  try {
    controlPlaneClient_->CompleteCommand(identity, command.commandId, completionStatus, resultJson);
  } catch (const std::exception& error) {
    // The saved outcome will be re-sent on the next poll; never rerun.
    std::wcerr << L"Command completion not delivered; saved for reconnect: " <<
                  Utf8ToWide(error.what()) << std::endl;
  }
  if (completionStatus == L"failed") {
    QueueTelemetryEvent(L"command.failed", L"command-executor",
                        std::wstring(L"Remote command failed: ") + command.type + L".", resultJson);
  }
}

void AgentService::InteractiveCommandLoop() {
  while (!ShouldStop()) {
    const auto identity = IdentitySnapshot();
    if (!identity.deviceId.empty() && !ControlPlaneClient::DeviceApiKey(identity).empty()) {
      try {
        const auto poll = controlPlaneClient_->PollPendingCommands(identity, 25, L"remote.session.start,remote.session.end");
        for (const auto& command : poll.items) {
          if (IsInteractiveCommand(command.type)) {
            ExecuteJournaledCommand(command, identity);
          }
        }
      } catch (const std::exception& error) {
        std::wcerr << L"Interactive command polling failed: " << Utf8ToWide(error.what()) << std::endl;
      }
    }
    // Woken at once by the realtime channel; without it, check every 15 seconds.
    const DWORD wait = realtimeConnected_ ? 60000 : 15000;
    HANDLE events[] = {stopEvent_, interactiveWakeEvent_};
    if (WaitForMultipleObjects(2, events, FALSE, wait) == WAIT_OBJECT_0) {
      return;
    }
  }
}

std::wstring AgentService::ExecuteCommand(const RemoteCommand& command) {
  if (command.type == L"device.isolate") {
    return ExecuteIsolationCommand(command, true);
  }
  if (command.type == L"device.release") {
    return ExecuteIsolationCommand(command, false);
  }
  if (command.type == L"scan.targeted") {
    return ExecuteTargetedScan(command);
  }
  if (command.type == L"scan.quick" || command.type == L"scan.full") {
    return ExecuteOnDemandScan(command, command.type == L"scan.full");
  }
  if (command.type == L"inventory.refresh") {
    return ExecuteInventoryRefreshCommand(command);
  }
  if (command.type == L"network.probe") {
    return Utf8ToWide(RunNetworkProbe(WideToUtf8(command.payloadJson)));
  }
  if (command.type == L"amsi.telemetry.submit") {
    return ExecuteAmsiTelemetrySubmitCommand(command);
  }
  if (command.type == L"policy.refresh") {
    return ExecutePolicyRefreshCommand(command);
  }
  if (command.type == L"forensics.collect") {
    // A full (unsanitised) support bundle: processes, network, persistence, logs and runtime evidence.
    return ExecuteSupportBundleCommand(command, false);
  }
  if (command.type == L"quarantine.restore") {
    return ExecuteQuarantineMutation(command, true);
  }
  if (command.type == L"quarantine.delete") {
    return ExecuteQuarantineMutation(command, false);
  }
  if (command.type == L"update.apply") {
    return ExecuteUpdateCommand(command, false);
  }
  if (command.type == L"update.rollback") {
    return ExecuteUpdateCommand(command, true);
  }
  if (command.type == L"agent.repair") {
    return ExecuteRepairCommand(command);
  }
  if (command.type == L"patch.windows.security" || command.type == L"patch.windows.install") {
    return ExecutePatchCommand(command, true, false, false);
  }
  if (command.type == L"patch.software" || command.type == L"patch.software.install") {
    return ExecutePatchCommand(command, false, true, false);
  }
  if (command.type == L"patch.cycle" || command.type == L"patch.cycle.run") {
    return ExecutePatchCommand(command, true, true, true);
  }
  if (command.type == L"support.bundle") {
    return ExecuteSupportBundleCommand(command, false);
  }
  if (command.type == L"support.bundle.sanitized") {
    return ExecuteSupportBundleCommand(command, true);
  }
  if (command.type == L"storage.maintenance") {
    return ExecuteStorageMaintenanceCommand(command);
  }
  if (command.type == L"threatintel.lookup") {
    return ExecuteThreatIntelLookupCommand(command);
  }
  if (command.type == L"threatintel.pack.ingest") {
    return ExecuteThreatIntelPackIngestCommand(command);
  }
  if (command.type == L"breakglass.enable") {
    return ExecuteBreakGlassCommand(command, true);
  }
  if (command.type == L"breakglass.disable") {
    return ExecuteBreakGlassCommand(command, false);
  }
  if (command.type == L"local.approval.request" || command.type == L"local.approval.execute") {
    return ExecuteLocalApprovalCommand(command);
  }
  if (command.type == L"local.approval.list") {
    return ExecuteLocalApprovalListCommand(command);
  }
  if (command.type == L"localadmin.audit") {
    return ExecuteLocalAdminAuditCommand(command);
  }
  if (command.type == L"localadmin.reduce") {
    return ExecuteLocalAdminReductionCommand(command, true);
  }
  if (command.type == L"localadmin.rollback") {
    return ExecuteLocalAdminRollbackCommand(command);
  }
  if (command.type == L"householdrole.audit") {
    return ExecuteHouseholdRoleAuditCommand(command);
  }
  if (command.type == L"householdrole.propagate") {
    return ExecuteHouseholdRolePropagationCommand(command, true);
  }
  if (command.type == L"process.terminate") {
    return ExecuteProcessTerminationCommand(command, false);
  }
  if (command.type == L"process.tree.terminate") {
    return ExecuteProcessTerminationCommand(command, true);
  }
  if (command.type == L"persistence.cleanup") {
    return ExecutePersistenceCleanupCommand(command);
  }
  if (command.type == L"remediate.path") {
    return ExecutePathRemediationCommand(command);
  }
  if (command.type == L"script.run" || command.type == L"patch.scan" || command.type == L"patch.install" ||
      command.type == L"software.install" || command.type == L"service.control" || command.type == L"device.reboot" ||
      command.type == L"device.shutdown" || command.type == L"device.message") {
    return ExecuteRmmCommand(command);
  }
  if (command.type == L"localadmin.rotate") {
    return RotateLocalAdminPassword(true);
  }
  if (command.type == L"protection.pause" || command.type == L"protection.resume") {
    if (command.issuedBy.rfind(L"local-dashboard:", 0) != 0) {
      throw std::runtime_error("Protection is paused from the agent window on the device");
    }
    return command.type == L"protection.pause" ? PauseProtection(command) : ResumeProtection(command);
  }
  if (command.type == L"elevation.request" || command.type == L"elevation.status") {
    // Only the signed-in user, from the agent window (the local pipe), asks for their own elevation.
    if (command.issuedBy.rfind(L"local-dashboard:", 0) != 0 || command.callerSid.empty()) {
      throw std::runtime_error("Admin access is requested from the agent window on the device");
    }
    return command.type == L"elevation.request" ? RequestElevation(command) : ElevationStatus(command);
  }
  if (command.type == L"elevation.grant" || command.type == L"elevation.revoke") {
    if (command.issuedBy.rfind(L"local-dashboard:", 0) == 0) {
      throw std::runtime_error("Admin access is granted from the Fenrir console");
    }
    return command.type == L"elevation.grant" ? GrantElevation(command) : RevokeElevation(command);
  }
  if (command.type == L"ransomware.rollback") {
    if (command.issuedBy.rfind(L"local-dashboard:", 0) == 0) {
      throw std::runtime_error("Ransomware rollback can only be started from the Fenrir console.");
    }
    if (!ransomwareShield_) {
      throw std::runtime_error("The ransomware shield is not running.");
    }
    const auto result = ransomwareShield_->RollbackLastIncident(L"console command");
    if (result.find(L"\"ok\":false") != std::wstring::npos) {
      throw std::runtime_error(WideToUtf8(result));
    }
    return result;
  }
  if (command.type == L"support.request") {
    // Only from the agent window on this PC (the local pipe); the cloud never asks a device to file a ticket.
    if (command.issuedBy.rfind(L"local-dashboard:", 0) != 0) {
      throw std::runtime_error("Support requests can only be sent from the agent window");
    }
    const auto field = [&command](const char* key, std::size_t limit) {
      auto value = WideToUtf8(ExtractPayloadString(command.payloadJson, key).value_or(L""));
      return EscapeJsonString(Utf8ToWide(value.substr(0, limit)));
    };
    const auto user = WideToUtf8(command.issuedBy.substr(std::wstring(L"local-dashboard:").size()));
    const std::string body = "{\"summary\":\"" + field("summary", 200) + "\",\"details\":\"" + field("details", 4000) +
                             "\",\"contact\":\"" + field("contact", 200) + "\",\"user\":\"" +
                             EscapeJsonString(Utf8ToWide(user.substr(0, 120))) + "\"}";
    const auto number = controlPlaneClient_->SubmitSupportRequest(IdentitySnapshot(), body);
    QueueTelemetryEvent(L"support.requested", L"endpoint-client", L"The user asked their IT provider for help (ticket " + number + L").",
                        L"{\"ticketNumber\":\"" + number + L"\"}");
    return L"{\"ticketNumber\":\"" + number + L"\"}";
  }
  if (command.type == L"remote.session.start") {
    return LaunchRemoteHelper(command);
  }
  if (command.type == L"remote.session.end") {
    return EndRemoteHelper(command);
  }
  if (command.type == L"software.search") {
    return ExecuteSoftwareCommand(command, false, true);
  }
  if (command.type == L"software.update") {
    return ExecuteSoftwareCommand(command, false, false);
  }
  if (command.type == L"software.uninstall") {
    if (command.payloadJson.find(L"\"installer\"") != std::wstring::npos) {
      return ExecuteRmmCommand(command);  // a package from the cloud software library
    }
    return ExecuteSoftwareCommand(command, true, false);
  }
  if (command.type == L"software.block") {
    return ExecuteSoftwareBlockCommand(command);
  }

  throw std::runtime_error("Unsupported remote command type");
}

bool AgentService::StartBackgroundScan(const std::wstring& eventPrefix, const std::wstring& scopeLabel, const std::wstring& source,
                                       std::vector<std::filesystem::path> targets, const int cpuLimitPercent) {
  bool expected = false;
  if (!backgroundScanBusy_->compare_exchange_strong(expected, true)) {
    return false;
  }
  QueueTelemetryEvent(eventPrefix + L".started", L"agent-service", L"The endpoint started a " + scopeLabel + L" scan.",
                      L"{\"scope\":\"" + scopeLabel + L"\",\"source\":\"" + source + L"\",\"targets\":" +
                          std::to_wstring(targets.size()) + L"}");
  // The thread works only on copies and shared flags, never on `this`, so it is safe even if the
  // service object goes away; a stop request cancels it at the next file.
  auto busy = backgroundScanBusy_;
  auto stopping = stopRequested_;
  const auto config = config_;
  const auto state = state_;
  std::thread([busy, stopping, config, state, eventPrefix, scopeLabel, source, cpuLimitPercent, targets = std::move(targets)]() {
    // CPU limit (scheduled scans): measure this thread's processor time between files and rest to match.
    if (cpuLimitPercent < 100) {
      SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    }
    const auto threadCpuMs = []() -> unsigned long long {
      FILETIME created{}, exited{}, kernel{}, user{};
      if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user)) {
        return 0;
      }
      const auto ticks = [](const FILETIME& t) { return (static_cast<unsigned long long>(t.dwHighDateTime) << 32) | t.dwLowDateTime; };
      return (ticks(kernel) + ticks(user)) / 10000;  // 100 ns units to ms
    };
    unsigned long long lastCpu = threadCpuMs();
    unsigned long long restDebt = 0;
    const TelemetryQueueStore queue(config.runtimeDatabasePath, config.telemetryQueuePath);
    const auto record = [&](const std::wstring& type, const std::wstring& summary, const std::wstring& payload) {
      try {
        queue.Append({TelemetryRecord{.eventId = GenerateGuidString(), .eventType = type, .source = L"agent-service",
                                      .summary = summary, .occurredAt = CurrentUtcTimestamp(), .payloadJson = payload}});
      } catch (...) {
      }
    };
    try {
      LocalScanExecutionOptions options{};
      options.source = source;
      options.queueTelemetry = true;  // appended to the shared queue (findings + summary)
      options.applyRemediation = true;
      const auto result = ExecuteLocalScan(config, state, targets, options, [&](const LocalScanProgressUpdate&) {
        if (stopping->load()) {
          throw std::runtime_error("the service is stopping");
        }
        if (cpuLimitPercent < 100) {
          const auto now = threadCpuMs();
          restDebt += ScanThrottleRestMs(cpuLimitPercent, now - lastCpu);
          lastCpu = now;
          if (restDebt >= 20) {
            Sleep(static_cast<DWORD>(std::min<unsigned long long>(restDebt, 2000)));
            restDebt = 0;
            lastCpu = threadCpuMs();
          }
        }
      });
      record(eventPrefix + L".completed", L"The endpoint completed a " + scopeLabel + L" scan.",
             L"{\"scope\":\"" + scopeLabel + L"\",\"targetsScanned\":" + std::to_wstring(result.targetCount) +
                 L",\"findings\":" + std::to_wstring(result.findings.size()) + L",\"remediationFailed\":" +
                 (result.remediationFailed ? L"true" : L"false") + L"}");
    } catch (const std::exception& error) {
      record(eventPrefix + L".failed", L"The endpoint could not complete a " + scopeLabel + L" scan.",
             L"{\"scope\":\"" + scopeLabel + L"\",\"error\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}");
    }
    busy->store(false);
  }).detach();
  return true;
}

std::wstring AgentService::ExecuteOnDemandScan(const RemoteCommand& command, const bool full) {
  const auto scope = full ? std::wstring(L"full") : std::wstring(L"quick");
  auto targets = full ? BuildFullScanTargets(ScanNetworkDrives()) : BuildQuickScanTargets();
  const auto count = targets.size();
  if (!StartBackgroundScan(L"scan." + scope, scope, L"command." + command.commandId, std::move(targets))) {
    throw std::runtime_error("Another scan is already running on this device; try again when it finishes");
  }
  // Findings arrive as scan.finding telemetry; completion as scan.<scope>.completed.
  return std::wstring(L"{\"started\":true,\"scope\":\"") + scope + L"\",\"targets\":" + std::to_wstring(count) + L"}";
}

std::wstring AgentService::ExecuteInventoryRefreshCommand(const RemoteCommand& command) {
  QueueDeviceInventoryTelemetry(0);
  QueuePatchTelemetry(0);
  FlushTelemetryQueue();
  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"inventory\":\"sent\"}";
}

std::wstring AgentService::ExecutePolicyRefreshCommand(const RemoteCommand& command) {
  RefreshPolicy(0);
  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"revision\":\"" + policy_.revision + L"\"}";
}

std::wstring AgentService::ExecuteTargetedScan(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("scan.targeted command is missing targetPath");
  }

  const std::filesystem::path targetPath(command.targetPath);
  std::error_code error;
  if (!std::filesystem::exists(targetPath, error)) {
    throw std::runtime_error("Targeted scan path does not exist");
  }

  auto findings = ScanTargets({targetPath}, policy_);
  QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
  EvidenceRecorder evidenceRecorder(config_.evidenceRootPath, config_.runtimeDatabasePath);

  for (auto& finding : findings) {
    if (finding.verdict.disposition == VerdictDisposition::Quarantine) {
      const auto quarantineResult = quarantineStore.QuarantineFile(finding);
      if (quarantineResult.success) {
        finding.remediationStatus = RemediationStatus::Quarantined;
        finding.quarantineRecordId = quarantineResult.recordId;
        finding.quarantinedPath = quarantineResult.quarantinedPath;
      } else {
        finding.remediationStatus = RemediationStatus::Failed;
        finding.remediationError =
            quarantineResult.errorMessage.empty() ? L"Unable to move the file into quarantine" : quarantineResult.errorMessage;
      }
    }

    const auto evidenceResult = evidenceRecorder.RecordScanFinding(finding, policy_, L"agent-service");
    finding.evidenceRecordId = evidenceResult.recordId;
  }

  const auto summaryTelemetry = BuildScanSummaryTelemetry(1, findings.size(), policy_, L"agent-service");
  QueueTelemetryEvent(summaryTelemetry.eventType, summaryTelemetry.source, summaryTelemetry.summary,
                      summaryTelemetry.payloadJson);
  for (const auto& finding : findings) {
    const auto record = BuildScanFindingTelemetry(finding, L"agent-service");
    QueueTelemetryEvent(record.eventType, record.source, record.summary, record.payloadJson);
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
         Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"findingCount\":" + std::to_wstring(findings.size()) +
         L"}";
}

std::wstring AgentService::ExecuteIsolationCommand(const RemoteCommand& command, const bool isolate) {
  if (!networkIsolationManager_) {
    throw std::runtime_error("The WFP isolation manager is not available");
  }

  std::wstring errorMessage;
  if (!networkIsolationManager_->ApplyIsolation(isolate, &errorMessage)) {
    throw std::runtime_error(WideToUtf8(errorMessage.empty() ? L"The WFP isolation manager rejected the requested state"
                                                            : errorMessage));
  }

  state_.isolated = networkIsolationManager_->IsolationActive();

  QueueTelemetryEvent(isolate ? L"device.isolated" : L"device.released", L"command-executor",
                      isolate ? L"The endpoint entered WFP-backed host isolation after a remote action."
                              : L"The endpoint left WFP-backed host isolation after a remote action.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"wfpApplied\":true}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"isolated\":" +
         (state_.isolated ? L"true" : L"false") + L",\"wfpApplied\":true}";
}

std::wstring AgentService::ExecuteQuarantineMutation(const RemoteCommand& command, const bool restore) {
  if (command.recordId.empty()) {
    throw std::runtime_error("Quarantine command is missing recordId");
  }

  if (restore && command.issuedBy.rfind(L"local-dashboard:", 0) == 0) {
    const auto extended = policy_.modulesJson.empty() ? ExtendedPolicy{} : ExtendedPolicy::Parse(policy_.modulesJson);
    if (!extended.allowQuarantineRestore) {
      throw std::runtime_error("Your administrator does not allow restoring files from quarantine on this device. "
                               "Ask your IT provider to review the file.");
    }
  }
  QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
  const auto result = restore ? quarantineStore.RestoreFile(command.recordId) : quarantineStore.DeleteRecord(command.recordId);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Quarantine operation failed" : result.errorMessage));
  }

  QueueTelemetryEvent(restore ? L"quarantine.restored" : L"quarantine.deleted", L"command-executor",
                      restore ? L"A quarantined item was restored after a remote action."
                              : L"A quarantined item was deleted after a remote action.",
                      std::wstring(L"{\"recordId\":\"") + result.recordId + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"recordId\":\"" + result.recordId +
         L"\",\"action\":\"" + (restore ? std::wstring(L"restore") : std::wstring(L"delete")) + L"\"}";
}

std::wstring AgentService::ExecuteUpdateCommand(const RemoteCommand& command, const bool rollback) {
  const auto installRoot = ResolveInstallRootForConfig(config_);
  UpdaterService updater(config_, installRoot);
  const auto result = rollback ? updater.RollbackTransaction(command.recordId)
                               : updater.ApplyPackage(command.targetPath, UpdateApplyMode::InService);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Update operation failed" : result.errorMessage));
  }

  QueueTelemetryEvent(rollback ? L"update.rolled_back" : L"update.applied", L"command-executor",
                      rollback ? L"The endpoint rolled back a staged platform update."
                               : L"The endpoint applied a staged platform or engine update.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"transactionId\":\"" +
                          result.transactionId + L"\",\"restartRequired\":" +
                          (result.restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"transactionId\":\"" + result.transactionId +
         L"\",\"packageId\":\"" + result.packageId + L"\",\"status\":\"" + result.status + L"\"}";
}

std::wstring AgentService::ExecuteRepairCommand(const RemoteCommand& command) {
  const auto installRoot = ResolveInstallRootForConfig(config_);
  HardeningManager hardeningManager(config_, installRoot);
  std::wstring errorMessage;
  const auto applied = hardeningManager.ApplyPostInstallHardening(ReadEnvironmentVariable(L"ANTIVIRUS_UNINSTALL_TOKEN"),
                                                                  &errorMessage);
  lastHardeningCheckFailed_ = !applied;

  QueueTelemetryEvent(applied ? L"agent.repaired" : L"agent.repair.failed", L"command-executor",
                      applied ? L"The endpoint reapplied service hardening and coexistence checks."
                              : L"The endpoint could not fully reapply service hardening.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"hardeningApplied\":" +
                          (applied ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  if (!applied) {
    throw std::runtime_error(WideToUtf8(errorMessage.empty() ? L"Endpoint repair failed" : errorMessage));
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"hardeningApplied\":true}";
}

std::wstring AgentService::ExecutePatchCommand(const RemoteCommand& command, const bool installWindows,
                                               const bool installSoftware, const bool runCycle) {
  PatchOrchestrator orchestrator(config_);
  PatchExecutionResult result{};

  if (runCycle) {
    result = orchestrator.RunPatchCycle();
  } else if (installWindows) {
    result = orchestrator.InstallWindowsUpdates(true);
  } else if (installSoftware) {
    const auto softwareId =
        !command.recordId.empty() ? command.recordId : ExtractPayloadString(command.payloadJson, "softwareId").value_or(command.targetPath);
    if (softwareId.empty()) {
      throw std::runtime_error("Software patch command is missing a software identifier");
    }
    result = orchestrator.UpdateSoftware(softwareId, false);
  } else {
    throw std::runtime_error("Patch command did not specify a supported action");
  }

  QueueTelemetryEvent(result.success ? L"patch.executed" : L"patch.failed", L"patch-orchestrator",
                      result.success ? L"The endpoint completed a patch orchestration action."
                                     : L"The endpoint patch orchestration action failed.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"status\":\"" + result.status +
                          L"\",\"targetId\":\"" + result.targetId + L"\",\"provider\":\"" + result.provider + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"action\":\"" +
         Utf8ToWide(EscapeJsonString(result.action)) + L"\",\"success\":" +
         (result.success ? std::wstring(L"true") : std::wstring(L"false")) + L",\"status\":\"" +
         Utf8ToWide(EscapeJsonString(result.status)) + L"\",\"targetId\":\"" +
         Utf8ToWide(EscapeJsonString(result.targetId)) + L"\",\"provider\":\"" +
         Utf8ToWide(EscapeJsonString(result.provider)) + L"\",\"errorCode\":\"" +
         Utf8ToWide(EscapeJsonString(result.errorCode)) + L"\",\"detailJson\":\"" +
         Utf8ToWide(EscapeJsonString(result.detailJson)) + L"\",\"rebootRequired\":" +
         (result.rebootRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
}

std::wstring AgentService::ExecuteSupportBundleCommand(const RemoteCommand& command, const bool sanitized) {
  const auto result = ExportSupportBundle(config_, state_, policy_, sanitized);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Support bundle export failed" : result.errorMessage));
  }

  QueueTelemetryEvent(L"support.bundle.exported", L"support-bundle",
                      sanitized ? L"The endpoint exported a sanitized support bundle."
                                : L"The endpoint exported a full support bundle.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"manifestPath\":\"" +
                          Utf8ToWide(EscapeJsonString(result.manifestPath.wstring())) + L"\"}");

  // Send the bundle to the cloud so responders can download it; the local copy stays as before.
  std::wstring upload;
  try {
    std::vector<std::string> skipped;
    const auto archive = BuildTarArchive(result.bundleRoot, 150u * 1024u * 1024u, &skipped);
    if (!controlPlaneClient_ || state_.deviceId.empty()) {
      throw std::runtime_error("the device is not enrolled");
    }
    const auto name = std::wstring(sanitized ? L"support-bundle-sanitized" : L"support-bundle") + L".tar";
    const auto artifactId = controlPlaneClient_->UploadCommandArtifact(state_, command.commandId, name, archive);
    upload = L",\"artifactId\":\"" + artifactId + L"\",\"bundleBytes\":" + std::to_wstring(archive.size()) +
             L",\"skippedFiles\":" + std::to_wstring(skipped.size());
  } catch (const std::exception& error) {
    upload = L",\"uploadError\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"";
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"manifestPath\":\"" +
         Utf8ToWide(EscapeJsonString(result.manifestPath.wstring())) + L"\",\"copiedFileCount\":" +
         std::to_wstring(result.copiedFileCount) + upload + L"}";
}

std::wstring AgentService::ExecuteStorageMaintenanceCommand(const RemoteCommand& command) {
  const auto result = RunStorageMaintenance(config_);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Storage maintenance failed" : result.errorMessage));
  }

  QueueTelemetryEvent(L"storage.maintenance.completed", L"storage-maintenance",
                      L"The endpoint completed local protection storage maintenance.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"deletedEntries\":" +
                          std::to_wstring(result.deletedEntries) + L",\"reclaimedBytes\":" +
                          std::to_wstring(result.reclaimedBytes) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"deletedEntries\":" +
         std::to_wstring(result.deletedEntries) + L",\"reclaimedBytes\":" + std::to_wstring(result.reclaimedBytes) + L"}";
}

std::wstring AgentService::ExecuteThreatIntelLookupCommand(const RemoteCommand& command) {
  const auto indicator =
      !command.targetPath.empty() ? command.targetPath : ExtractPayloadString(command.payloadJson, "indicator").value_or(L"");
  if (indicator.empty()) {
    throw std::runtime_error("Threat intelligence lookup is missing an indicator");
  }

  const auto result = LookupDestinationReputation(indicator, config_.runtimeDatabasePath);
  QueueTelemetryEvent(L"threatintel.lookup.completed", L"threat-intelligence",
                      L"The endpoint completed a local threat intelligence lookup.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"indicator\":\"" +
                          Utf8ToWide(EscapeJsonString(indicator)) + L"\",\"lookupSucceeded\":" +
                          (result.lookupSucceeded ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"indicator\":\"" +
         Utf8ToWide(EscapeJsonString(indicator)) + L"\",\"summary\":\"" +
         Utf8ToWide(EscapeJsonString(DescribeReputationLookup(result))) + L"\"}";
}

std::wstring AgentService::ExecuteThreatIntelPackIngestCommand(const RemoteCommand& command) {
  const auto packPath = std::filesystem::path(command.targetPath);
  if (packPath.empty()) {
    throw std::runtime_error("Threat intelligence pack ingest is missing targetPath");
  }

  const auto result = IngestSignedThreatIntelPack(packPath, config_.runtimeDatabasePath);
  if (!result.success) {
    throw std::runtime_error(WideToUtf8(result.errorMessage.empty() ? L"Threat intelligence ingest failed"
                                                                   : result.errorMessage));
  }

  QueueTelemetryEvent(L"threatintel.pack.ingested", L"threat-intelligence",
                      L"The endpoint ingested a signed threat intelligence pack.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"recordsLoaded\":" +
                          std::to_wstring(result.recordsLoaded) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"recordsLoaded\":" +
         std::to_wstring(result.recordsLoaded) + L",\"recordsRejected\":" + std::to_wstring(result.recordsRejected) + L"}";
}

std::wstring AgentService::ExecuteBreakGlassCommand(const RemoteCommand& command, const bool enable) {
  if (enable) {
    const auto extended = policy_.modulesJson.empty() ? ExtendedPolicy{} : ExtendedPolicy::Parse(policy_.modulesJson);
    if (!extended.breakGlassAllowed) {
      throw std::runtime_error("The break-glass admin account is turned off by this device's policy");
    }
  }
  if (laps::IsDomainController()) {
    throw std::runtime_error("This is a domain controller; the break-glass account is never created on one");
  }
  const auto expiryFile = config_.runtimeDatabasePath.parent_path() / L"breakglass-expiry.txt";
  const std::wstring account = laps::kBreakGlassAccount;
  if (!enable) {
    const auto status = laps::DisableBreakGlassAccount();
    std::error_code ec;
    std::filesystem::remove(expiryFile, ec);
    if (status != 0) {
      throw std::runtime_error("The break-glass account could not be disabled (error " + std::to_string(status) + ")");
    }
    QueueTelemetryEvent(L"breakglass.disabled", L"local-security", L"The break-glass admin account was disabled.",
                        L"{\"commandId\":\"" + command.commandId + L"\",\"account\":\"" + account + L"\"}");
    return L"{\"enabled\":false,\"account\":\"" + account + L"\"}";
  }
  if (state_.deviceId.empty()) {
    throw std::runtime_error("The device is not enrolled");
  }
  double hours = 4;
  if (const auto value = ExtractPayloadString(command.payloadJson, "hours")) {
    hours = std::wcstod(value->c_str(), nullptr);
  } else if (const auto pos = command.payloadJson.find(L"\"hours\""); pos != std::wstring::npos) {
    const auto digits = command.payloadJson.find_first_of(L"0123456789", pos + 7);
    if (digits != std::wstring::npos) hours = std::wcstod(command.payloadJson.c_str() + digits, nullptr);
  }
  hours = std::clamp(hours <= 0 ? 4.0 : hours, 1.0, 24.0);
  auto password = laps::GeneratePassword(24);
  // Escrow first, as with LAPS: the cloud always holds the password before the account uses it.
  const auto version = controlPlaneClient_->EscrowLocalAdminPassword(state_, account, password);
  const auto status = laps::EnableBreakGlassAccount(password);
  SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
  if (status != 0) {
    const auto error = L"The break-glass account could not be enabled (error " + std::to_wstring(status) + L")";
    controlPlaneClient_->ConfirmLocalAdminPassword(state_, version, false, error);
    throw std::runtime_error(WideToUtf8(error));
  }
  controlPlaneClient_->ConfirmLocalAdminPassword(state_, version, true, L"");
  const auto expires = static_cast<long long>(std::time(nullptr)) + static_cast<long long>(hours * 3600);
  std::ofstream(expiryFile, std::ios::trunc) << expires;
  QueueTelemetryEvent(L"breakglass.enabled", L"local-security",
                      L"The break-glass admin account was enabled for " + std::to_wstring(static_cast<int>(hours)) +
                          L" hours; its password is in the device's Local admin tab.",
                      L"{\"commandId\":\"" + command.commandId + L"\",\"account\":\"" + account + L"\",\"hours\":" +
                          std::to_wstring(static_cast<int>(hours)) + L",\"version\":\"" + version + L"\"}");
  return L"{\"enabled\":true,\"account\":\"" + account + L"\",\"hours\":" + std::to_wstring(static_cast<int>(hours)) +
         L",\"version\":\"" + version + L"\"}";
}

void AgentService::ExpireBreakGlassAccount() {
  const auto expiryFile = config_.runtimeDatabasePath.parent_path() / L"breakglass-expiry.txt";
  long long expires = 0;
  {
    std::ifstream in(expiryFile);
    if (!(in >> expires)) return;
  }
  if (static_cast<long long>(std::time(nullptr)) < expires) return;
  const auto status = laps::DisableBreakGlassAccount();
  if (status == 0) {
    std::error_code ec;
    std::filesystem::remove(expiryFile, ec);
  }
  QueueTelemetryEvent(status == 0 ? L"breakglass.expired" : L"breakglass.expiry.failed", L"local-security",
                      status == 0 ? L"The break-glass admin account expired and was disabled."
                                  : L"The break-glass admin account expired but could not be disabled.",
                      L"{\"error\":" + std::to_wstring(status) + L"}");
}

// AMSI runs inside user processes that cannot write the protected runtime database, so the provider
// hands findings to the service over the local control pipe. Only AMSI event types are accepted, the
// source is fixed and the submitting user is recorded, so a local user cannot forge other telemetry.
std::wstring AgentService::ExecuteAmsiTelemetrySubmitCommand(const RemoteCommand& command) {
  if (command.recordId != L"scan.finding" && command.recordId != L"amsi.scan") {
    throw std::runtime_error("Only AMSI telemetry can be submitted through local control.");
  }
  const auto parsed = json::Parse(WideToUtf8(command.payloadJson));
  const auto* members = parsed ? std::get_if<json::Object>(&parsed->v) : nullptr;
  if (members == nullptr) {
    throw std::runtime_error("AMSI telemetry payload must be a JSON object.");
  }
  {
    static std::mutex rateLock;
    static auto windowStart = std::chrono::steady_clock::now();
    static int submitted = 0;
    std::lock_guard guard(rateLock);
    const auto now = std::chrono::steady_clock::now();
    if (now - windowStart > std::chrono::minutes(1)) {
      windowStart = now;
      submitted = 0;
    }
    if (++submitted > 120) {
      throw std::runtime_error("AMSI telemetry rate limit reached; try again shortly.");
    }
  }
  auto payload = command.payloadJson;
  const auto open = payload.find(L'{');
  payload.insert(open + 1, L"\"reportedBy\":\"" + Utf8ToWide(EscapeJsonString(command.issuedBy)) + L"\"" +
                               (members->empty() ? L"" : L","));
  QueueTelemetryRecords({TelemetryRecord{.eventId = GenerateGuidString(),
                                         .eventType = command.recordId,
                                         .source = L"amsi-provider",
                                         .summary = command.targetPath.substr(0, 1000),
                                         .occurredAt = CurrentUtcTimestamp(),
                                         .payloadJson = payload}});
  return L"{\"queued\":1}";
}

std::wstring AgentService::ExecuteLocalApprovalCommand(const RemoteCommand&) {
  throw std::runtime_error("Local approval execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteLocalApprovalListCommand(const RemoteCommand&) {
  throw std::runtime_error("Local approval listing is not wired into the current service build");
}

namespace {

std::wstring AdminMembersJson(const std::vector<laps::AdminMember>& members, const std::vector<std::size_t>* only = nullptr) {
  std::wstring out = L"[";
  bool first = true;
  for (std::size_t i = 0; i < members.size(); ++i) {
    if (only && std::find(only->begin(), only->end(), i) == only->end()) continue;
    const auto& m = members[i];
    out += (first ? L"" : L",") + std::wstring(L"{\"name\":\"") + Utf8ToWide(EscapeJsonString(m.name)) + L"\",\"sid\":\"" + m.sid +
           L"\",\"type\":\"" + (m.group ? L"group" : L"user") + L"\",\"enabled\":" + (m.enabled ? L"true" : L"false") +
           L",\"builtin\":" + (m.builtin ? L"true" : L"false") + L"}";
    first = false;
  }
  return out + L"]";
}

}  // namespace

std::wstring AgentService::ExecuteLocalAdminAuditCommand(const RemoteCommand& command) {
  const auto members = laps::ListAdministrators();
  const auto body = L"{\"domainController\":" + std::wstring(laps::IsDomainController() ? L"true" : L"false") +
                    L",\"members\":" + AdminMembersJson(members) + L"}";
  QueueTelemetryEvent(L"localadmin.audited", L"local-security",
                      L"The local Administrators group has " + std::to_wstring(members.size()) + L" members.",
                      L"{\"commandId\":\"" + command.commandId + L"\",\"members\":" + AdminMembersJson(members) + L"}");
  return body;
}

std::vector<std::wstring> AgentService::LocalAdminKeepList(const std::wstring& payloadJson) const {
  auto keep = ExtractPayloadStringArray(payloadJson, "keep");
  keep.push_back(laps::kBreakGlassAccount);
  // Users with temporary admin rights keep them until they expire.
  {
    std::ifstream in(config_.runtimeDatabasePath.parent_path() / L"elevations.json", std::ios::binary);
    std::stringstream text;
    text << in.rdbuf();
    if (const auto parsed = json::Parse(text.str())) {
      if (const auto* grants = parsed->Get("grants"); grants && std::get_if<json::Array>(&grants->v)) {
        for (const auto& grant : std::get<json::Array>(grants->v)) {
          if (const auto* sid = grant.Get("sid"); sid && sid->String()) keep.push_back(Utf8ToWide(*sid->String()));
        }
      }
    }
  }
  // The account LAPS manages stays an administrator.
  if (const auto root = policy_.modulesJson.empty() ? std::optional<json::Value>{} : json::Parse(policy_.modulesJson)) {
    if (const auto* privilege = root->Get("privilege")) {
      if (const auto* account = privilege->Get("localAdminAccount"); account && account->String() && !account->String()->empty()) {
        keep.push_back(Utf8ToWide(*account->String()));
      }
    }
  }
  return keep;
}

std::wstring AgentService::ExecuteLocalAdminReductionCommand(const RemoteCommand& command, const bool applyChanges) {
  if (laps::IsDomainController()) {
    throw std::runtime_error("This is a domain controller; its Administrators group is the domain's and is never changed");
  }
  const auto members = laps::ListAdministrators();
  const auto plan = laps::PlanAdminRemoval(members, LocalAdminKeepList(command.payloadJson));
  if (plan.empty()) {
    return L"{\"removed\":[],\"note\":\"Nothing to remove (or removing would leave no administrator).\"}";
  }
  if (!applyChanges) {
    return L"{\"wouldRemove\":" + AdminMembersJson(members, &plan) + L"}";
  }
  // Remember who was removed so localadmin.rollback can put them back.
  const auto stateFile = config_.runtimeDatabasePath.parent_path() / L"local-admins-removed.json";
  std::vector<std::pair<std::wstring, std::wstring>> saved;  // sid, name
  {
    std::ifstream in(stateFile, std::ios::binary);
    std::stringstream text;
    text << in.rdbuf();
    if (const auto parsed = json::Parse(text.str())) {
      if (const auto* list = std::get_if<json::Array>(&parsed->v)) {
        for (const auto& item : *list) {
          const auto* sid = item.Get("sid");
          const auto* name = item.Get("name");
          if (sid && sid->String()) saved.emplace_back(Utf8ToWide(*sid->String()), name && name->String() ? Utf8ToWide(*name->String()) : L"");
        }
      }
    }
  }
  std::vector<std::size_t> removed;
  std::wstring failures;
  for (const auto index : plan) {
    const auto status = laps::RemoveAdministrator(members[index].sid);
    if (status == 0) {
      removed.push_back(index);
      if (std::none_of(saved.begin(), saved.end(), [&](const auto& s) { return s.first == members[index].sid; })) {
        saved.emplace_back(members[index].sid, members[index].name);
      }
    } else {
      failures += (failures.empty() ? L"" : L", ") + members[index].name + L" (error " + std::to_wstring(status) + L")";
    }
  }
  {
    std::wstring body = L"[";
    for (std::size_t i = 0; i < saved.size(); ++i) {
      body += (i ? L"," : L"") + std::wstring(L"{\"sid\":\"") + saved[i].first + L"\",\"name\":\"" +
              Utf8ToWide(EscapeJsonString(saved[i].second)) + L"\"}";
    }
    std::ofstream(stateFile, std::ios::binary | std::ios::trunc) << WideToUtf8(body + L"]");
  }
  if (!removed.empty()) {
    QueueTelemetryEvent(L"localadmin.reduced", L"local-security",
                        L"Removed local admin rights from " + std::to_wstring(removed.size()) + L" account(s).",
                        L"{\"commandId\":\"" + command.commandId + L"\",\"removed\":" + AdminMembersJson(members, &removed) + L"}");
  }
  if (!failures.empty()) {
    throw std::runtime_error("Could not remove: " + WideToUtf8(failures));
  }
  return L"{\"removed\":" + AdminMembersJson(members, &removed) + L"}";
}

std::wstring AgentService::ExecuteLocalAdminRollbackCommand(const RemoteCommand& command) {
  const auto stateFile = config_.runtimeDatabasePath.parent_path() / L"local-admins-removed.json";
  std::ifstream in(stateFile, std::ios::binary);
  std::stringstream text;
  text << in.rdbuf();
  in.close();
  const auto parsed = json::Parse(text.str());
  const auto* list = parsed ? std::get_if<json::Array>(&parsed->v) : nullptr;
  if (list == nullptr || list->empty()) {
    return L"{\"restored\":0,\"note\":\"No removed administrators are recorded on this device.\"}";
  }
  int restored = 0;
  std::wstring names, failures;
  for (const auto& item : *list) {
    const auto* sid = item.Get("sid");
    const auto* name = item.Get("name");
    if (!sid || !sid->String()) continue;
    const auto label = name && name->String() ? Utf8ToWide(*name->String()) : Utf8ToWide(*sid->String());
    const auto status = laps::AddAdministrator(Utf8ToWide(*sid->String()));
    if (status == 0) {
      ++restored;
      names += (names.empty() ? L"" : L", ") + label;
    } else {
      failures += (failures.empty() ? L"" : L", ") + label + L" (error " + std::to_wstring(status) + L")";
    }
  }
  if (failures.empty()) {
    std::error_code ec;
    std::filesystem::remove(stateFile, ec);
  }
  QueueTelemetryEvent(L"localadmin.restored", L"local-security",
                      L"Restored local admin rights to " + std::to_wstring(restored) + L" account(s).",
                      L"{\"commandId\":\"" + command.commandId + L"\",\"accounts\":\"" + Utf8ToWide(EscapeJsonString(names)) + L"\"}");
  if (!failures.empty()) {
    throw std::runtime_error("Could not restore: " + WideToUtf8(failures));
  }
  return L"{\"restored\":" + std::to_wstring(restored) + L"}";
}

std::wstring AgentService::ExecuteHouseholdRoleAuditCommand(const RemoteCommand&) {
  throw std::runtime_error("Household role audit execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteHouseholdRolePropagationCommand(const RemoteCommand&, const bool) {
  throw std::runtime_error("Household role propagation execution is not wired into the current service build");
}

std::wstring AgentService::ExecuteProcessTerminationCommand(const RemoteCommand& command, const bool includeChildren) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("Process termination command is missing targetPath");
  }

  // PID-targeted kill: only that process (and children), and only if it is still the same program.
  const auto pidPosition = command.payloadJson.find(L"\"pid\"");
  if (pidPosition != std::wstring::npos) {
    const auto digits = command.payloadJson.find_first_of(L"0123456789", pidPosition + 5);
    if (digits != std::wstring::npos) {
      const auto pid = std::wcstoul(command.payloadJson.c_str() + digits, nullptr, 10);
      const auto killed = ProcessGuard::TerminateIfImageMatches(pid, command.targetPath, includeChildren);
      QueueTelemetryEvent(includeChildren ? L"process.tree.terminated" : L"process.terminated", L"command-executor",
                          killed > 0 ? L"The endpoint terminated the targeted process."
                                     : L"The targeted process had already exited or no longer matched.",
                          std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"pid\":" + std::to_wstring(pid) +
                              L",\"terminatedCount\":" + std::to_wstring(killed < 0 ? 0 : killed) + L"}");
      return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"pid\":" + std::to_wstring(pid) +
             L",\"terminatedCount\":" + std::to_wstring(killed < 0 ? 0 : killed) + L"}";
    }
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.TerminateProcessesForPath(command.targetPath, includeChildren);
  QueueTelemetryEvent(includeChildren ? L"process.tree.terminated" : L"process.terminated", L"command-executor",
                      includeChildren ? L"The endpoint terminated a malicious process tree."
                                      : L"The endpoint terminated a malicious process.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"targetPath\":\"" +
                          Utf8ToWide(EscapeJsonString(command.targetPath)) + L"\",\"terminatedCount\":" +
                          std::to_wstring(result.processesTerminated) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"terminatedCount\":" +
         std::to_wstring(result.processesTerminated) + L"}";
}

std::wstring AgentService::ExecutePersistenceCleanupCommand(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("Persistence cleanup command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.CleanupPersistenceForPath(command.targetPath);
  QueueTelemetryEvent(L"persistence.cleaned", L"command-executor",
                      L"The endpoint removed startup persistence tied to a malicious artifact.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"registryValuesRemoved\":" +
                          std::to_wstring(result.registryValuesRemoved) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"registryValuesRemoved\":" +
         std::to_wstring(result.registryValuesRemoved) + L",\"startupArtifactsRemoved\":" +
         std::to_wstring(result.startupArtifactsRemoved) + L"}";
}

std::wstring AgentService::ExecutePathRemediationCommand(const RemoteCommand& command) {
  if (command.targetPath.empty()) {
    throw std::runtime_error("remediate.path command is missing targetPath");
  }

  RemediationEngine remediationEngine(config_);
  const auto result = remediationEngine.RemediatePath(command.targetPath, policy_);
  QueueTelemetryEvent(L"remediation.completed", L"command-executor",
                      L"The endpoint executed a full remediation workflow for a malicious artifact.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"quarantineApplied\":" +
                          (result.quarantineApplied ? std::wstring(L"true") : std::wstring(L"false")) + L"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"quarantineApplied\":" +
         (result.quarantineApplied ? std::wstring(L"true") : std::wstring(L"false")) + L",\"quarantineRecordId\":\"" +
         result.quarantineRecordId + L"\",\"evidenceRecordId\":\"" + result.evidenceRecordId + L"\"}";
}

std::wstring AgentService::ExecuteScriptCommand(const RemoteCommand& command) { return ExecuteRmmCommand(command); }

std::wstring AgentService::ExecuteRmmCommand(const RemoteCommand& command) {
  const auto workRoot = config_.runtimeDatabasePath.parent_path() / L"rmm";
  std::string result;
  if (command.type == L"script.run") {
    if (!processGuard_ || processGuard_->CurrentExtendedPolicy().scriptExecution) {
      result = rmm::RunScript(command.payloadJson, workRoot);
    } else {
      throw std::runtime_error("Script execution is turned off by policy");
    }
  } else if (command.type == L"patch.scan") {
    result = rmm::PatchScan(workRoot);
  } else if (command.type == L"patch.install") {
    result = rmm::PatchInstall(command.payloadJson, workRoot);
  } else if (command.type == L"software.install") {
    result = rmm::Software(command.payloadJson, false, workRoot);
  } else if (command.type == L"software.uninstall") {
    result = rmm::Software(command.payloadJson, true, workRoot);
  } else if (command.type == L"service.control") {
    result = rmm::ServiceControl(command.targetPath, command.payloadJson);
  } else if (command.type == L"device.reboot" || command.type == L"device.shutdown") {
    result = rmm::PowerAction(command.type == L"device.reboot", command.payloadJson);
  } else if (command.type == L"device.message") {
    result = rmm::MessageUser(command.payloadJson);
  }
  QueueTelemetryEvent(L"rmm." + command.type, L"rmm", L"Completed " + command.type,
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\"}");
  return Utf8ToWide(result);
}

namespace {

DWORD InteractiveSessionId() {
  const auto console = WTSGetActiveConsoleSessionId();
  if (console != 0xFFFFFFFF) {
    return console;
  }
  // No console (a server reached over RDP): use the first active remote session.
  WTS_SESSION_INFOW* sessions = nullptr;
  DWORD count = 0;
  DWORD found = 0xFFFFFFFF;
  if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
    for (DWORD i = 0; i < count; ++i) {
      if (sessions[i].State == WTSActive) {
        found = sessions[i].SessionId;
        break;
      }
    }
    WTSFreeMemory(sessions);
  }
  return found;
}

}  // namespace

// The cloud builds relayUrl from its public URL, which may not be reachable from this PC (a
// placeholder, or a name that only resolves outside the LAN). Point it at the server this agent
// already talks to, keeping the /ws/remote/... path and query.
static std::wstring RelayUrlForServer(std::wstring server, const std::wstring& relay) {
  const auto relayScheme = relay.find(L"://");
  if (relayScheme == std::wstring::npos) {
    return relay;
  }
  const auto relayPath = relay.find(L'/', relayScheme + 3);
  if (relayPath == std::wstring::npos || relay.compare(relayPath, 11, L"/ws/remote/") != 0) {
    return relay;
  }
  while (!server.empty() && (server.back() == L'/' || server.back() == L' ')) {
    server.pop_back();
  }
  if (server.size() > 7 && server.compare(server.size() - 7, 7, L"/api/v1") == 0) {
    server.resize(server.size() - 7);
  }
  if (server.rfind(L"https://", 0) == 0) {
    server = L"wss://" + server.substr(8);
  } else if (server.rfind(L"http://", 0) == 0) {
    server = L"ws://" + server.substr(7);
  } else {
    return relay;
  }
  return server + relay.substr(relayPath);
}

std::wstring AgentService::LaunchRemoteHelper(const RemoteCommand& command) {
  if (processGuard_ && !processGuard_->CurrentExtendedPolicy().remoteAccessEnabled) {
    throw std::runtime_error("Remote access is turned off by policy");
  }
  const auto sessionId = ExtractPayloadString(command.payloadJson, "sessionId").value_or(L"");
  if (sessionId.empty() || sessionId.size() > 64 || sessionId.find_first_of(L"\\/:*?\"<>|") != std::wstring::npos) {
    throw std::runtime_error("The remote session id is missing or invalid");
  }
  const auto helper = config_.installRootPath / L"fenrir-remote.exe";
  std::error_code ec;
  if (!std::filesystem::exists(helper, ec)) {
    throw std::runtime_error("The remote access helper (fenrir-remote.exe) is not installed");
  }
  // The token travels in a file inside the protected runtime folder, never on a command line.
  const auto folder = config_.runtimeDatabasePath.parent_path() / L"remote";
  std::filesystem::create_directories(folder, ec);
  const auto optionsPath = folder / (sessionId + L".json");
  auto payload = command.payloadJson;
  if (const auto relay = ExtractPayloadString(payload, "relayUrl"); relay.has_value() && !relay->empty()) {
    const auto rewritten = RelayUrlForServer(config_.controlPlaneBaseUrl, *relay);
    const auto quoted = L"\"" + *relay + L"\"";
    if (const auto at = payload.find(quoted); rewritten != *relay && at != std::wstring::npos) {
      payload.replace(at, quoted.size(), L"\"" + rewritten + L"\"");
    }
  }
  {
    std::ofstream out(optionsPath, std::ios::binary | std::ios::trunc);
    out << WideToUtf8(payload);
  }
  const auto windowsSession = InteractiveSessionId();
  HANDLE self = nullptr, primary = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &self) ||
      !DuplicateTokenEx(self, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &primary)) {
    if (self) CloseHandle(self);
    std::filesystem::remove(optionsPath, ec);
    throw std::runtime_error("Could not prepare the remote access helper token");
  }
  CloseHandle(self);
  DWORD target = windowsSession;
  if (target != 0xFFFFFFFF) {
    SetTokenInformation(primary, TokenSessionId, &target, sizeof(target));
  }
  std::wstring commandLine = L"\"" + helper.wstring() + L"\" --options \"" + optionsPath.wstring() + L"\"";
  std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
  mutableCommand.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  wchar_t desktop[] = L"winsta0\\default";
  startup.lpDesktop = desktop;
  PROCESS_INFORMATION process{};
  const BOOL created = CreateProcessAsUserW(primary, helper.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
                                            CREATE_NEW_PROCESS_GROUP, nullptr, helper.parent_path().c_str(), &startup, &process);
  CloseHandle(primary);
  if (!created) {
    std::filesystem::remove(optionsPath, ec);
    throw std::runtime_error("Could not start the remote access helper (error " + std::to_string(GetLastError()) + ")");
  }
  CloseHandle(process.hThread);
  // Wait until the helper reaches the relay (its log says so) or quits, so a helper that cannot connect
  // fails the command with its reason instead of leaving the technician on "waiting" forever.
  const auto logPath = std::filesystem::path(optionsPath).replace_extension(L".log");
  const auto readLog = [&logPath]() {
    std::ifstream in(logPath, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  };
  bool reachedRelay = false;
  for (int waited = 0; waited < 30000; waited += 250) {
    if (readLog().find("Connected to the relay.") != std::string::npos) {
      reachedRelay = true;
      break;
    }
    if (WaitForSingleObject(process.hProcess, 250) == WAIT_OBJECT_0) {
      break;
    }
  }
  if (!reachedRelay && WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) {
    DWORD exitCode = 0;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hProcess);
    std::filesystem::remove(optionsPath, ec);
    auto log = readLog();
    std::string last;
    for (std::size_t end = log.size(); end > 0 && last.empty();) {
      const auto start = log.rfind('\n', end - 1);
      auto line = log.substr(start == std::string::npos ? 0 : start + 1, end - (start == std::string::npos ? 0 : start + 1));
      while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
      if (!line.empty() && line.find("Helper exiting") == std::string::npos) last = line.size() > 21 ? line.substr(21) : line;
      if (start == std::string::npos) break;
      end = start;
    }
    throw std::runtime_error("The remote helper stopped before reaching the relay (exit code " + std::to_string(exitCode) + ")" +
                             (last.empty() ? std::string(".") : ": " + last) + " Log: " + WideToUtf8(logPath.wstring()));
  }
  {
    std::lock_guard lock(remoteMutex_);
    if (auto it = remoteHelpers_.find(sessionId); it != remoteHelpers_.end()) {
      CloseHandle(it->second);
    }
    remoteHelpers_[sessionId] = process.hProcess;
  }
  QueueTelemetryEvent(L"remote.session.started", L"remote-access", L"A remote access session was started.",
                      std::wstring(L"{\"sessionId\":\"") + sessionId + L"\",\"windowsSession\":" + std::to_wstring(windowsSession) +
                          L",\"technician\":\"" + Utf8ToWide(EscapeJsonString(ExtractPayloadString(command.payloadJson, "technician").value_or(L""))) + L"\"}");
  return std::wstring(L"{\"started\":true,\"consent\":\"pending\",\"helperPid\":") + std::to_wstring(process.dwProcessId) +
         L",\"windowsSession\":" + std::to_wstring(windowsSession) + L",\"reachedRelay\":" + (reachedRelay ? L"true" : L"false") +
         L",\"logPath\":\"" + Utf8ToWide(EscapeJsonString(logPath.wstring())) + L"\"}";
}

std::wstring AgentService::EndRemoteHelper(const RemoteCommand& command) {
  const auto sessionId = ExtractPayloadString(command.payloadJson, "sessionId").value_or(L"");
  HANDLE process = nullptr;
  {
    std::lock_guard lock(remoteMutex_);
    if (auto it = remoteHelpers_.find(sessionId); it != remoteHelpers_.end()) {
      process = it->second;
      remoteHelpers_.erase(it);
    }
  }
  bool ended = false;
  if (process) {
    // The helper normally exits by itself when the relay closes; give it a moment first.
    if (WaitForSingleObject(process, 5000) == WAIT_TIMEOUT) {
      TerminateProcess(process, 0);
    }
    CloseHandle(process);
    ended = true;
  }
  return std::wstring(L"{\"ended\":") + (ended ? L"true" : L"false") + L"}";
}

void AgentService::PublishIdentitySnapshot() {
  std::lock_guard lock(remoteMutex_);
  identitySnapshot_ = state_;
}

AgentState AgentService::IdentitySnapshot() {
  std::lock_guard lock(remoteMutex_);
  return identitySnapshot_;
}

void AgentService::DrainDeferredTelemetry() {
  std::vector<DeferredTelemetry> events;
  {
    std::lock_guard lock(remoteMutex_);
    events.swap(deferredTelemetry_);
  }
  for (const auto& event : events) {
    QueueTelemetryEvent(event.eventType, event.source, event.summary, event.payloadJson);
  }
}

void AgentService::StartRealtimeChannel() {
  if (realtimeThread_.joinable() || wakeEvent_ == nullptr) {
    return;
  }
  realtimeThread_ = std::thread([this] { RealtimeLoop(); });
  if (!interactiveThread_.joinable()) {
    interactiveWakeEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (interactiveWakeEvent_ != nullptr) {
      interactiveLoopRunning_ = true;
      interactiveThread_ = std::thread([this] { InteractiveCommandLoop(); });
    }
  }
}

void AgentService::StopRealtimeChannel() {
  if (stopEvent_ != nullptr) {
    SetEvent(stopEvent_);
  }
  if (realtimeThread_.joinable()) {
    realtimeThread_.join();
  }
  if (interactiveThread_.joinable()) {
    interactiveThread_.join();
  }
  interactiveLoopRunning_ = false;
  if (interactiveWakeEvent_ != nullptr) {
    CloseHandle(interactiveWakeEvent_);
    interactiveWakeEvent_ = nullptr;
  }
}

void AgentService::RealtimeLoop() {
  DWORD backoff = 5000;
  while (!ShouldStop()) {
    const auto identity = IdentitySnapshot();
    if (identity.deviceId.empty() || ControlPlaneClient::DeviceApiKey(identity).empty()) {
      WaitForSingleObject(stopEvent_, 2000);  // not enrolled yet: check again soon
      continue;
    }
    const auto started = GetTickCount64();
    try {
      WebSocketClient socket;
      socket.Connect(controlPlaneClient_->RealtimeUrl(identity), L"X-Device-Api-Key: " + ControlPlaneClient::DeviceApiKey(identity) + L"\r\n");
      SetEvent(wakeEvent_);  // Main loop owns execution and journal persistence.
      if (interactiveWakeEvent_) SetEvent(interactiveWakeEvent_);
      realtimeConnected_ = true;
      // A watcher closes the socket when the service stops, which unblocks Receive.
      std::atomic<bool> done{false};
      std::thread watcher([&] {
        while (!done) {
          if (WaitForSingleObject(stopEvent_, 30000) == WAIT_OBJECT_0) {
            socket.Close();
            return;
          }
          socket.SendText("ping");
        }
      });
      std::string message;
      bool binary = false;
      while (!ShouldStop() && socket.Receive(&message, &binary)) {
        if (message.find("\"commands\"") != std::string::npos || message.find("\"pollNow\":true") != std::string::npos) {
          SetEvent(wakeEvent_);
          if (interactiveWakeEvent_) SetEvent(interactiveWakeEvent_);
        }
      }
      realtimeConnected_ = false;
      done = true;
      socket.Close();
      watcher.join();
    } catch (const std::exception& error) {
      realtimeConnected_ = false;
      // Report why the live channel is down (once per distinct error) so it shows in the device's activity.
      static std::string lastError;
      if (lastError != error.what()) {
        lastError = error.what();
        QueueTelemetryEvent(L"realtime.connect_failed", L"agent-service",
                            L"The agent could not open its live connection to the server; remote sessions start on the next poll instead.",
                            L"{\"error\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(lastError))) + L"\",\"url\":\"" +
                                Utf8ToWide(EscapeJsonString(controlPlaneClient_->RealtimeUrl(identity))) + L"\"}");
      }
    }
    if (GetTickCount64() - started > 60000) {
      backoff = 5000;
    }
    if (WaitForSingleObject(stopEvent_, backoff) == WAIT_OBJECT_0) {
      return;
    }
    backoff = std::min<DWORD>(backoff * 2, 120000);
  }
}

void AgentService::PublishHeartbeat(const int cycle) {
  if (state_.deviceId.empty()) {
    return;
  }

  const auto wfpIsolationActive = networkIsolationManager_ && networkIsolationManager_->IsolationActive();
  const auto wfpUnavailable =
      policy_.networkContainmentEnabled && (!networkIsolationManager_ || !networkIsolationManager_->EngineReady());

  state_.isolated = wfpIsolationActive;
  state_.healthState = wfpIsolationActive
                           ? L"isolated"
                           : ((wfpUnavailable || lastControlPlaneSyncFailed_ || lastTelemetryFlushFailed_ ||
                               lastHardeningCheckFailed_)
                                  ? L"degraded"
                                  : L"healthy");

  bool attemptedRecovery = false;
  for (;;) {
    try {
      const auto heartbeat = controlPlaneClient_->SendHeartbeat(state_, rmm::CollectHealthMetricsJson());
      state_.lastHeartbeatAt = heartbeat.receivedAt;
      lastControlPlaneSyncFailed_ = false;
      QueueTelemetryEvent(L"device.heartbeat", L"control-plane-client",
                          L"The endpoint heartbeat was acknowledged by the control plane.",
                          BuildCyclePayload(cycle, std::wstring(L"\"commandsPending\":") +
                                                       std::to_wstring(heartbeat.commandsPending)));
      return;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"heartbeat")) {
        attemptedRecovery = true;
        continue;
      }

      lastControlPlaneSyncFailed_ = true;
      QueueTelemetryEvent(L"device.heartbeat.failed", L"control-plane-client",
                          L"The endpoint heartbeat could not be delivered to the control plane.",
                          BuildCyclePayload(cycle));
      std::wcerr << L"Heartbeat failed, keeping the previous health state cached: " << Utf8ToWide(error.what())
                 << std::endl;
      return;
    }
  }
}

void AgentService::PersistState() {
  if (!stateStore_ || !telemetryQueueStore_) {
    return;
  }

  stateStore_->Save(state_);
  // Telemetry is appended to the queue as it is raised (QueueTelemetryRecords), so nothing to rewrite here.
}

void AgentService::ApplyProtectionPolicy() {
  if (!processGuard_) {
    return;
  }
  processGuard_->UpdatePolicy(EnforcedPolicy());
  {
    const std::lock_guard lock(modulesCopyMutex_);
    modulesCopy_ = policy_.modulesJson;
  }
  for (const auto& record : processGuard_->ApplyDeviceControl()) {
    QueueTelemetryEvent(record.eventType, record.source, record.summary, record.payloadJson);
  }
  ApplyFirewallPolicy();
  WriteExperienceFile();
  if (ransomwareShield_ && !policy_.modulesJson.empty()) {
    const auto extended = ExtendedPolicy::Parse(policy_.modulesJson);
    if (extended.present) {
      ransomwareShield_->Apply(extended.ransomware);
      if (bruteForceGuard_) {
        bruteForceGuard_->Apply(extended.bruteForceProtection);
      }
      if (registryWatcher_) {
        registryWatcher_->Apply(extended.collectRegistryEvents);
      }
      ApplyTamperPolicy(extended);
      ApplyCredentialHardening(extended.ransomware.credentialProtection);
    }
  }
}

void AgentService::ApplyCredentialHardening(const bool enable) {
  if (appliedCredentialHardening_ == (enable ? 1 : 0)) {
    return;
  }
  HardeningManager hardening(config_, ResolveInstallRootForConfig(config_));
  bool reboot = false;
  std::wstring error;
  const bool ok = hardening.ApplyCredentialHardening(enable, &reboot, &error);
  if (ok) {
    appliedCredentialHardening_ = enable ? 1 : 0;
  }
  if (!ok || reboot) {
    QueueTelemetryEvent(ok ? L"credential.hardening.applied" : L"credential.hardening.failed", L"hardening-manager",
                        ok ? (enable ? L"LSA protection turned on; it takes effect after the next restart"
                                     : L"LSA protection set by Fenrir was removed; this takes effect after the next restart")
                           : L"Credential protection settings could not all be applied",
                        L"{\"enabled\":" + std::wstring(enable ? L"true" : L"false") + L",\"rebootRequired\":" +
                            (reboot ? L"true" : L"false") + L",\"error\":\"" + Utf8ToWide(EscapeJsonString(error)) + L"\"}");
  }
}

void AgentService::ApplyTamperPolicy(const ExtendedPolicy& extended) {
  const std::wstring key = std::wstring(extended.tamperServiceLocked ? L"1" : L"0") + (extended.tamperUninstallToken ? L"1" : L"0");
  if (key == appliedTamperPolicy_) {
    return;
  }
  HardeningManager hardening(config_, ResolveInstallRootForConfig(config_));
  std::wstring error;
  const bool ok = hardening.ApplyTamperPolicy(extended.tamperServiceLocked, extended.tamperUninstallToken, &error);
  if (ok) {
    appliedTamperPolicy_ = key;
  }
  const auto flags = std::wstring(L"\"serviceLocked\":") + (extended.tamperServiceLocked ? L"true" : L"false") +
                     L",\"uninstallRequiresToken\":" + (extended.tamperUninstallToken ? L"true" : L"false");
  QueueTelemetryEvent(ok ? L"tamper.policy.applied" : L"tamper.policy.failed", L"hardening-manager",
                      ok ? (extended.tamperServiceLocked ? L"Tamper protection on: the agent service cannot be stopped or removed"
                                                         : L"Tamper protection relaxed by policy: administrators can stop the agent service")
                         : L"Tamper protection policy could not be applied",
                      L"{" + flags + (ok ? L"" : L",\"error\":" + Utf8ToWide("\"" + EscapeJsonString(error) + "\"")) + L"}");
}

// Publishes what the agent window may show (branding, support contact, which protections are on) to
// experience.json in the install folder, which signed-in users can read. Nothing sensitive goes in it.
std::wstring AgentService::RotateLocalAdminPassword(const bool force) {
  const auto root = policy_.modulesJson.empty() ? std::optional<json::Value>{} : json::Parse(policy_.modulesJson);
  const auto* privilege = root && root->IsObject() ? root->Get("privilege") : nullptr;
  const auto field = [privilege](const char* key) { return privilege ? privilege->Get(key) : nullptr; };
  const bool enabled = field("rotateLocalAdminPassword") && field("rotateLocalAdminPassword")->Bool().value_or(false);
  if (!enabled && !force) {
    return L"{\"rotated\":false,\"reason\":\"off by policy\"}";
  }
  if (state_.deviceId.empty()) {
    throw std::runtime_error("The device is not enrolled");
  }
  if (laps::IsDomainController()) {
    throw std::runtime_error("This is a domain controller; local admin password rotation never runs on one");
  }
  double days = 30;
  if (const auto* value = field("localAdminPasswordDays"); value && value->Number()) {
    days = std::clamp(*value->Number(), 1.0, 365.0);
  }
  const auto stampFile = config_.runtimeDatabasePath.parent_path() / L"laps-last-rotation.txt";
  if (!force) {
    std::ifstream in(stampFile);
    long long last = 0;
    if (in >> last && static_cast<long long>(std::time(nullptr)) - last < static_cast<long long>(days * 86400)) {
      return L"{\"rotated\":false,\"reason\":\"not due\"}";
    }
  }
  std::wstring account;
  if (const auto* value = field("localAdminAccount"); value && value->String() && !value->String()->empty()) {
    account = Utf8ToWide(*value->String());
  } else {
    account = laps::BuiltinAdministratorName();
  }
  if (account.empty() || account.size() > 20 || account.find_first_of(L"\\/[]:;|=,+*?<>\"@") != std::wstring::npos) {
    throw std::runtime_error("The local admin account to manage could not be determined");
  }
  auto password = laps::GeneratePassword(24);
  // Escrow first: if the cloud cannot store it, the account keeps its current password.
  const auto version = controlPlaneClient_->EscrowLocalAdminPassword(state_, account, password);
  const auto status = laps::SetLocalAccountPassword(account, password);
  SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
  if (status != 0) {
    const auto error = L"NetUserSetInfo failed with error " + std::to_wstring(status);
    controlPlaneClient_->ConfirmLocalAdminPassword(state_, version, false, error);
    throw std::runtime_error(WideToUtf8(error));
  }
  controlPlaneClient_->ConfirmLocalAdminPassword(state_, version, true, L"");
  std::ofstream(stampFile, std::ios::trunc) << static_cast<long long>(std::time(nullptr));
  QueueTelemetryEvent(L"laps.rotated", L"laps", L"The local admin password was rotated and stored in the vault.",
                      L"{\"account\":\"" + Utf8ToWide(EscapeJsonString(account)) + L"\",\"version\":\"" + version + L"\"}");
  return L"{\"rotated\":true,\"account\":\"" + Utf8ToWide(EscapeJsonString(account)) + L"\",\"version\":\"" + version + L"\"}";
}

namespace {

struct ElevationGrant {
  std::wstring sid, user, requestId;
  long long until{0};
  bool wasAdmin{false};
};
struct ElevationPending {
  std::wstring sid, requestId;
  long long at{0};
};
struct ElevationState {
  std::vector<ElevationGrant> grants;
  std::vector<ElevationPending> pending;
};

ElevationState LoadElevations(const std::filesystem::path& file) {
  ElevationState state;
  std::ifstream in(file, std::ios::binary);
  std::stringstream text;
  text << in.rdbuf();
  const auto parsed = json::Parse(text.str());
  if (!parsed || !parsed->IsObject()) return state;
  const auto str = [](const json::Value& v, const char* key) {
    const auto* f = v.Get(key);
    return f && f->String() ? Utf8ToWide(*f->String()) : std::wstring{};
  };
  const auto num = [](const json::Value& v, const char* key) {
    const auto* f = v.Get(key);
    return f && f->Number() ? static_cast<long long>(*f->Number()) : 0LL;
  };
  if (const auto* grants = parsed->Get("grants"); grants && std::get_if<json::Array>(&grants->v)) {
    for (const auto& g : std::get<json::Array>(grants->v)) {
      const auto* was = g.Get("wasAdmin");
      state.grants.push_back({str(g, "sid"), str(g, "user"), str(g, "requestId"), num(g, "until"), was && was->Bool().value_or(false)});
    }
  }
  if (const auto* pending = parsed->Get("pending"); pending && std::get_if<json::Array>(&pending->v)) {
    for (const auto& p : std::get<json::Array>(pending->v)) state.pending.push_back({str(p, "sid"), str(p, "requestId"), num(p, "at")});
  }
  return state;
}

void SaveElevations(const std::filesystem::path& file, const ElevationState& state) {
  const auto q = [](const std::wstring& v) { return L"\"" + Utf8ToWide(EscapeJsonString(v)) + L"\""; };
  std::wstring body = L"{\"grants\":[";
  for (std::size_t i = 0; i < state.grants.size(); ++i) {
    const auto& g = state.grants[i];
    body += (i ? L"," : L"") + std::wstring(L"{\"sid\":") + q(g.sid) + L",\"user\":" + q(g.user) + L",\"requestId\":" +
            q(g.requestId) + L",\"until\":" + std::to_wstring(g.until) + L",\"wasAdmin\":" + (g.wasAdmin ? L"true" : L"false") + L"}";
  }
  body += L"],\"pending\":[";
  for (std::size_t i = 0; i < state.pending.size(); ++i) {
    const auto& p = state.pending[i];
    body += (i ? L"," : L"") + std::wstring(L"{\"sid\":") + q(p.sid) + L",\"requestId\":" + q(p.requestId) + L",\"at\":" +
            std::to_wstring(p.at) + L"}";
  }
  body += L"]}";
  std::ofstream(file, std::ios::binary | std::ios::trunc) << WideToUtf8(body);
}

bool PlausibleUserSid(const std::wstring& sid) {
  if (sid.size() > 120 || (sid.rfind(L"S-1-5-21-", 0) != 0 && sid.rfind(L"S-1-12-1-", 0) != 0)) return false;
  return std::all_of(sid.begin() + 2, sid.end(), [](wchar_t c) { return (c >= L'0' && c <= L'9') || c == L'-'; });
}

std::wstring UnixToIso(const long long seconds) {
  const std::time_t t = static_cast<std::time_t>(seconds);
  std::tm utc{};
  gmtime_s(&utc, &t);
  wchar_t buffer[32]{};
  wcsftime(buffer, 32, L"%Y-%m-%dT%H:%M:%SZ", &utc);
  return buffer;
}

}  // namespace

std::wstring AgentService::RequestElevation(const RemoteCommand& command) {
  const auto modules = ModulesJsonCopy();  // the local pipe runs on its own thread
  const auto root = modules.empty() ? std::optional<json::Value>{} : json::Parse(modules);
  const auto* privilege = root && root->IsObject() ? root->Get("privilege") : nullptr;
  const auto* enabled = privilege ? privilege->Get("enabled") : nullptr;
  const auto* mode = privilege ? privilege->Get("elevationRequests") : nullptr;
  if (!enabled || !enabled->Bool().value_or(false) || (mode && mode->String().value_or("approval") == "off")) {
    throw std::runtime_error("Admin access requests are turned off on this device.");
  }
  const auto user = command.issuedBy.substr(std::wstring(L"local-dashboard:").size());
  const auto reason = ExtractPayloadString(command.payloadJson, "reason").value_or(L"");
  const std::string body = "{\"user\":\"" + EscapeJsonString(user.substr(0, 200)) + "\",\"userSid\":\"" +
                           EscapeJsonString(command.callerSid) + "\",\"reason\":\"" + EscapeJsonString(reason.substr(0, 1000)) + "\"}";
  const auto response = controlPlaneClient_->RequestElevation(IdentitySnapshot(), body);
  const auto parsed = json::Parse(response);
  const auto* id = parsed ? parsed->Get("id") : nullptr;
  if (id && id->String()) {
    const std::lock_guard lock(elevationMutex_);
    const auto file = config_.runtimeDatabasePath.parent_path() / L"elevations.json";
    auto state = LoadElevations(file);
    std::erase_if(state.pending, [&](const ElevationPending& p) { return p.sid == command.callerSid; });
    state.pending.push_back({command.callerSid, Utf8ToWide(*id->String()), static_cast<long long>(std::time(nullptr))});
    SaveElevations(file, state);
  }
  QueueTelemetryEvent(L"elevation.requested", L"endpoint-client", user + L" asked for temporary admin access.",
                      L"{\"user\":\"" + Utf8ToWide(EscapeJsonString(user)) + L"\"}");
  return Utf8ToWide(response);
}

std::wstring AgentService::ElevationStatus(const RemoteCommand& command) {
  const std::lock_guard lock(elevationMutex_);
  const auto state = LoadElevations(config_.runtimeDatabasePath.parent_path() / L"elevations.json");
  const auto now = static_cast<long long>(std::time(nullptr));
  for (const auto& grant : state.grants) {
    if (grant.sid == command.callerSid && grant.until > now) {
      return L"{\"state\":\"granted\",\"until\":\"" + UnixToIso(grant.until) + L"\"}";
    }
  }
  for (const auto& pending : state.pending) {
    if (pending.sid == command.callerSid && now - pending.at < 24 * 3600) return L"{\"state\":\"pending\"}";
  }
  return L"{\"state\":\"none\"}";
}

std::wstring AgentService::GrantElevation(const RemoteCommand& command) {
  const auto sid = ExtractPayloadString(command.payloadJson, "userSid").value_or(L"");
  const auto user = ExtractPayloadString(command.payloadJson, "user").value_or(sid);
  const auto requestId = ExtractPayloadString(command.payloadJson, "requestId").value_or(L"");
  long long minutes = 30;
  if (const auto pos = command.payloadJson.find(L"\"minutes\""); pos != std::wstring::npos) {
    const auto digits = command.payloadJson.find_first_of(L"0123456789", pos + 9);
    if (digits != std::wstring::npos) minutes = std::wcstoll(command.payloadJson.c_str() + digits, nullptr, 10);
  }
  minutes = std::clamp(minutes, 5LL, 480LL);
  if (!PlausibleUserSid(sid)) {
    throw std::runtime_error("The request does not name a valid user account");
  }
  if (laps::IsDomainController()) {
    throw std::runtime_error("This is a domain controller; temporary admin rights are never granted on one");
  }
  const auto members = laps::ListAdministrators();
  const bool wasAdmin = std::any_of(members.begin(), members.end(), [&](const laps::AdminMember& m) { return _wcsicmp(m.sid.c_str(), sid.c_str()) == 0; });
  if (!wasAdmin) {
    if (const auto status = laps::AddAdministrator(sid); status != 0) {
      throw std::runtime_error("The user could not be added to the Administrators group (error " + std::to_string(status) + ")");
    }
  }
  const auto until = static_cast<long long>(std::time(nullptr)) + minutes * 60;
  {
    const std::lock_guard lock(elevationMutex_);
    const auto file = config_.runtimeDatabasePath.parent_path() / L"elevations.json";
    auto state = LoadElevations(file);
    bool keepWasAdmin = wasAdmin;
    for (const auto& existing : state.grants) {
      if (existing.sid == sid) keepWasAdmin = existing.wasAdmin;  // extending a grant keeps the original state
    }
    std::erase_if(state.grants, [&](const ElevationGrant& g) { return g.sid == sid; });
    std::erase_if(state.pending, [&](const ElevationPending& p) { return p.sid == sid; });
    state.grants.push_back({sid, user, requestId, until, keepWasAdmin});
    SaveElevations(file, state);
  }
  QueueTelemetryEvent(L"elevation.granted", L"local-security",
                      user + L" has temporary admin rights for " + std::to_wstring(minutes) + L" minutes.",
                      L"{\"commandId\":\"" + command.commandId + L"\",\"user\":\"" + Utf8ToWide(EscapeJsonString(user)) +
                          L"\",\"minutes\":" + std::to_wstring(minutes) + L",\"alreadyAdmin\":" + (wasAdmin ? L"true" : L"false") + L"}");
  return L"{\"granted\":true,\"until\":\"" + UnixToIso(until) + L"\",\"alreadyAdmin\":" + (wasAdmin ? L"true" : L"false") + L"}";
}

std::wstring AgentService::RevokeElevation(const RemoteCommand& command) {
  const auto sid = ExtractPayloadString(command.payloadJson, "userSid").value_or(L"");
  const std::lock_guard lock(elevationMutex_);
  const auto file = config_.runtimeDatabasePath.parent_path() / L"elevations.json";
  auto state = LoadElevations(file);
  bool removed = false;
  for (const auto& grant : state.grants) {
    if (grant.sid == sid && !grant.wasAdmin) removed = laps::RemoveAdministrator(sid) == 0;
  }
  std::erase_if(state.grants, [&](const ElevationGrant& g) { return g.sid == sid; });
  std::erase_if(state.pending, [&](const ElevationPending& p) { return p.sid == sid; });
  SaveElevations(file, state);
  QueueTelemetryEvent(L"elevation.revoked", L"local-security", L"Temporary admin rights were revoked.",
                      L"{\"commandId\":\"" + command.commandId + L"\",\"removed\":" + (removed ? L"true" : L"false") + L"}");
  return L"{\"revoked\":true}";
}

void AgentService::ExpireElevations() {
  const std::lock_guard lock(elevationMutex_);
  const auto file = config_.runtimeDatabasePath.parent_path() / L"elevations.json";
  std::error_code ec;
  if (!std::filesystem::exists(file, ec)) return;
  auto state = LoadElevations(file);
  const auto now = static_cast<long long>(std::time(nullptr));
  bool changed = false;
  for (auto it = state.grants.begin(); it != state.grants.end();) {
    if (it->until > now) {
      ++it;
      continue;
    }
    const auto status = it->wasAdmin ? 0UL : laps::RemoveAdministrator(it->sid);
    QueueTelemetryEvent(status == 0 ? L"elevation.expired" : L"elevation.expiry.failed", L"local-security",
                        status == 0 ? it->user + L"'s temporary admin rights ended."
                                    : it->user + L"'s temporary admin rights ended but could not be removed.",
                        L"{\"user\":\"" + Utf8ToWide(EscapeJsonString(it->user)) + L"\",\"error\":" + std::to_wstring(status) + L"}");
    if (status == 0) {
      it = state.grants.erase(it);
      changed = true;
    } else {
      ++it;
    }
  }
  const auto before = state.pending.size();
  std::erase_if(state.pending, [now](const ElevationPending& p) { return now - p.at > 24 * 3600; });
  changed = changed || before != state.pending.size();
  if (changed) SaveElevations(file, state);
}

PolicySnapshot AgentService::EnforcedPolicy() const {
  auto policy = policy_;
  if (pausedUntil_.load() > static_cast<long long>(std::time(nullptr))) {
    // experience.allowUserPause: real-time file scanning and process-start blocking are off for a while.
    policy.realtimeProtectionEnabled = false;
  }
  return policy;
}

std::string AgentService::ModulesJsonCopy() const {
  const std::lock_guard lock(modulesCopyMutex_);
  return modulesCopy_;
}

std::wstring AgentService::PauseProtection(const RemoteCommand& command) {
  const auto modules = ModulesJsonCopy();
  const auto root = modules.empty() ? std::optional<json::Value>{} : json::Parse(modules);
  const auto* experience = root && root->IsObject() ? root->Get("experience") : nullptr;
  const auto* allowed = experience ? experience->Get("allowUserPause") : nullptr;
  if (!allowed || !allowed->Bool().value_or(false)) {
    throw std::runtime_error("Your IT provider does not allow pausing protection on this device.");
  }
  long long minutes = 15;
  if (const auto pos = command.payloadJson.find(L"\"minutes\""); pos != std::wstring::npos) {
    const auto digits = command.payloadJson.find_first_of(L"0123456789", pos + 9);
    if (digits != std::wstring::npos) minutes = std::wcstoll(command.payloadJson.c_str() + digits, nullptr, 10);
  }
  minutes = std::clamp(minutes, 5LL, 60LL);
  const auto until = static_cast<long long>(std::time(nullptr)) + minutes * 60;
  pausedUntil_.store(until);
  const auto user = command.issuedBy.substr(std::wstring(L"local-dashboard:").size());
  QueueTelemetryEvent(L"protection.paused", L"endpoint-client",
                      user + L" paused real-time protection for " + std::to_wstring(minutes) + L" minutes.",
                      L"{\"user\":\"" + Utf8ToWide(EscapeJsonString(user)) + L"\",\"minutes\":" + std::to_wstring(minutes) + L"}");
  if (wakeEvent_ != nullptr) SetEvent(wakeEvent_);  // the main loop applies it
  return L"{\"pausedUntil\":\"" + UnixToIso(until) + L"\"}";
}

std::wstring AgentService::ResumeProtection(const RemoteCommand& command) {
  pausedUntil_.store(0);
  const auto user = command.issuedBy.substr(std::wstring(L"local-dashboard:").size());
  QueueTelemetryEvent(L"protection.resumed", L"endpoint-client", user + L" turned real-time protection back on.",
                      L"{\"user\":\"" + Utf8ToWide(EscapeJsonString(user)) + L"\"}");
  if (wakeEvent_ != nullptr) SetEvent(wakeEvent_);
  return L"{\"resumed\":true}";
}

// Applies a pause, resume or expiry to the real-time components (main thread only).
void AgentService::ApplyPauseState() {
  const bool paused = pausedUntil_.load() > static_cast<long long>(std::time(nullptr));
  if (paused == appliedPaused_) return;
  if (appliedPaused_ && !paused && pausedUntil_.load() != 0) {
    QueueTelemetryEvent(L"protection.resumed", L"agent-service", L"The protection pause ended; real-time protection is back on.", L"{}");
  }
  appliedPaused_ = paused;
  if (!paused) pausedUntil_.store(0);
  const auto policy = EnforcedPolicy();
  if (realtimeProtectionBroker_) realtimeProtectionBroker_->SetPolicy(policy);
  if (processGuard_) processGuard_->UpdatePolicy(policy);
  WriteExperienceFile();
}

void AgentService::EnforceLocalAdminPolicy() {
  const auto extended = policy_.modulesJson.empty() ? ExtendedPolicy{} : ExtendedPolicy::Parse(policy_.modulesJson);
  if (!extended.removeLocalAdmins || state_.deviceId.empty() || laps::IsDomainController()) {
    return;
  }
  try {
    RemoteCommand command{};
    command.commandId = L"policy";
    command.payloadJson = L"{}";
    ExecuteLocalAdminReductionCommand(command, true);
  } catch (const std::exception& error) {
    QueueTelemetryEvent(L"localadmin.reduce.failed", L"local-security", L"Standing local admin rights could not all be removed.",
                        L"{\"error\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}");
  }
}

std::wstring AgentService::ExecuteInventoryUninstall(const RemoteCommand& command) {
  const auto softwareId =
      !command.recordId.empty() ? command.recordId : ExtractPayloadString(command.payloadJson, "softwareId").value_or(L"");
  if (softwareId.empty()) {
    throw std::runtime_error("Software uninstall needs the application's record ID from the device's software list");
  }
  RuntimeDatabase database(config_.runtimeDatabasePath);
  const auto software = database.ListSoftwarePatchRecords(5000);
  const auto match = std::find_if(software.begin(), software.end(), [&](const auto& r) { return r.softwareId == softwareId; });
  if (match == software.end()) {
    throw std::runtime_error("That application is not in this device's software list; refresh the inventory and try again");
  }
  std::wstring commandLine = match->quietUninstallCommand;
  if (commandLine.empty()) {
    // MSI products uninstall silently through msiexec with their product code.
    auto lower = match->uninstallCommand;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    const auto open = match->uninstallCommand.find(L'{');
    const auto close = match->uninstallCommand.find(L'}', open == std::wstring::npos ? 0 : open);
    if (lower.find(L"msiexec") != std::wstring::npos && open != std::wstring::npos && close != std::wstring::npos &&
        close - open == 37) {
      wchar_t systemDir[MAX_PATH]{};
      GetSystemDirectoryW(systemDir, MAX_PATH);
      commandLine = L"\"" + std::wstring(systemDir) + L"\\msiexec.exe\" /x " + match->uninstallCommand.substr(open, 38) +
                    L" /qn /norestart";
    }
  }
  if (commandLine.empty()) {
    throw std::runtime_error("\"" + WideToUtf8(match->displayName) +
                             "\" has no silent uninstaller. Add it to the software library with uninstall arguments, or "
                             "remove it from a remote session.");
  }
  wchar_t systemDir[MAX_PATH]{};
  GetSystemDirectoryW(systemDir, MAX_PATH);
  const auto result = rmm::RunProcess(commandLine, systemDir, {}, 60 * 60 * 1000);
  // 3010: done, restart needed. 1605: not installed any more. 1614: already uninstalled.
  const bool ok = !result.timedOut && (result.exitCode == 0 || result.exitCode == 3010 || result.exitCode == 1605 ||
                                       result.exitCode == 1614);
  QueueTelemetryEvent(ok ? L"software.uninstalled" : L"software.uninstall.failed", L"command-executor",
                      (ok ? L"Uninstalled " : L"Could not uninstall ") + match->displayName,
                      L"{\"commandId\":\"" + command.commandId + L"\",\"softwareId\":\"" + Utf8ToWide(EscapeJsonString(softwareId)) +
                          L"\",\"exitCode\":" + std::to_wstring(static_cast<long>(result.exitCode)) + L"}");
  if (!ok) {
    throw std::runtime_error(result.timedOut ? "The uninstaller did not finish within an hour"
                                             : "The uninstaller exited with code " + std::to_string(static_cast<long>(result.exitCode)));
  }
  return L"{\"uninstalled\":\"" + Utf8ToWide(EscapeJsonString(match->displayName)) + L"\",\"exitCode\":" +
         std::to_wstring(static_cast<long>(result.exitCode)) + L",\"rebootRequired\":" + (result.exitCode == 3010 ? L"true" : L"false") + L"}";
}

void AgentService::MaybeSelfUpdate(const int cycle) {
  if (std::wstring(kFenrirBuildId) == L"dev" || state_.deviceId.empty()) {
    return;
  }
  const auto now = GetTickCount64();
  if (lastSelfUpdateCheck_ != 0 && now - lastSelfUpdateCheck_ < 30ULL * 60 * 1000) {
    return;
  }
  lastSelfUpdateCheck_ = now;
  const auto folder = config_.runtimeDatabasePath.parent_path() / L"updates";
  try {
    const auto info = controlPlaneClient_->CheckWindowsAgentUpdate(state_);
    const auto isHex = [](const std::wstring& v, std::size_t min, std::size_t max) {
      return v.size() >= min && v.size() <= max &&
             std::all_of(v.begin(), v.end(), [](wchar_t c) { return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'); });
    };
    if (!info.available || !info.autoUpdate || !isHex(info.buildId, 8, 64) || !isHex(info.sha256, 64, 64) ||
        info.buildId == kFenrirBuildId) {
      return;
    }
    // One attempt per build every six hours, so a failing upgrade cannot loop.
    std::error_code ec;
    std::filesystem::create_directories(folder, ec);
    const auto attemptFile = folder / L"last-attempt.txt";
    {
      std::wifstream in(attemptFile);
      std::wstring lastBuild;
      long long lastTime = 0;
      if (in >> lastBuild >> lastTime && lastBuild == info.buildId &&
          static_cast<long long>(std::time(nullptr)) - lastTime < 6LL * 3600) {
        return;
      }
    }
    std::wofstream(attemptFile, std::ios::trunc) << info.buildId << L" " << static_cast<long long>(std::time(nullptr));

    const auto package = folder / (L"FenrirSetup-" + info.buildId + L".exe");
    controlPlaneClient_->DownloadToFile(state_, info.url, package);
    if (ToLowerCopy(ComputeFileSha256(package)) != info.sha256) {
      std::filesystem::remove(package, ec);
      throw std::runtime_error("the downloaded installer failed its SHA-256 check");
    }
    QueueTelemetryEvent(L"agent.update.started", L"updater",
                        L"Upgrading the agent to the server's current build.",
                        L"{\"from\":\"" + std::wstring(kFenrirBuildId) + L"\",\"to\":\"" + info.buildId + L"\"}");
    FlushTelemetryQueue();  // the installer stops this service next

    std::wstring commandLine = L"\"" + package.wstring() + L"\" --silent-upgrade";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const DWORD flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
    BOOL started = CreateProcessW(package.c_str(), commandLine.data(), nullptr, nullptr, FALSE, flags | CREATE_BREAKAWAY_FROM_JOB,
                                  nullptr, folder.c_str(), &startup, &process);
    if (!started) {
      started = CreateProcessW(package.c_str(), commandLine.data(), nullptr, nullptr, FALSE, flags, nullptr, folder.c_str(),
                               &startup, &process);
    }
    if (!started) {
      throw std::runtime_error("could not start the installer (error " + std::to_string(GetLastError()) + ")");
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
  } catch (const std::exception& error) {
    QueueTelemetryEvent(L"agent.update.failed", L"updater", L"The agent could not upgrade itself.",
                        BuildCyclePayload(cycle, L"\"error\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\""));
  }
}

// After a silent upgrade the installer (running as SYSTEM) cannot open the agent window for the user, so the
// restarted service does it in the active console session.
void AgentService::RelaunchClientAfterUpgrade() {
  const auto flag = config_.installRootPath / L"runtime" / L"relaunch-client.flag";
  std::error_code ec;
  if (!std::filesystem::exists(flag, ec)) {
    return;
  }
  std::filesystem::remove(flag, ec);
  QueueTelemetryEvent(L"agent.updated", L"updater", L"The agent finished upgrading to the server's current build.",
                      L"{\"buildId\":\"" + std::wstring(kFenrirBuildId) + L"\"}");
  const auto sessionId = WTSGetActiveConsoleSessionId();
  HANDLE userToken = nullptr;
  if (sessionId == 0xFFFFFFFF || !WTSQueryUserToken(sessionId, &userToken)) {
    return;  // nobody signed in: the window starts at the next sign-in
  }
  LPVOID environment = nullptr;
  CreateEnvironmentBlock(&environment, userToken, FALSE);
  const auto client = config_.installRootPath / L"fenrir-endpoint-client.exe";
  std::wstring commandLine = L"\"" + client.wstring() + L"\" --background";
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  wchar_t desktop[] = L"winsta0\\default";
  startup.lpDesktop = desktop;
  PROCESS_INFORMATION process{};
  if (CreateProcessAsUserW(userToken, client.c_str(), commandLine.data(), nullptr, nullptr, FALSE,
                           CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, environment, config_.installRootPath.c_str(), &startup,
                           &process)) {
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
  }
  if (environment) DestroyEnvironmentBlock(environment);
  CloseHandle(userToken);
}

void AgentService::WriteExperienceFile() {
  const auto root = policy_.modulesJson.empty() ? std::optional<json::Value>{} : json::Parse(policy_.modulesJson);
  const auto section = [&root](const char* name) -> const json::Value* { return root && root->IsObject() ? root->Get(name) : nullptr; };
  const auto text = [](const json::Value* s, const char* key, const std::string& fallback) {
    const auto* v = s ? s->Get(key) : nullptr;
    const auto value = v ? v->String() : std::nullopt;
    return value.has_value() && !value->empty() ? *value : fallback;
  };
  const auto flag = [](const json::Value* s, const char* key, bool fallback) {
    const auto* v = s ? s->Get(key) : nullptr;
    return v ? v->Bool().value_or(fallback) : fallback;
  };
  const auto* experience = section("experience");
  const auto* firewallSection = section("firewall");
  const auto* ransomware = section("ransomware");
  const auto q = [](const std::string& v) { return "\"" + EscapeJsonString(Utf8ToWide(v.substr(0, 300))) + "\""; };
  const auto b = [](bool v) { return std::string(v ? "true" : "false"); };
  std::string out = "{";
  out += "\"brandName\":" + q(text(experience, "brandName", "Fenrir"));
  out += ",\"supportContact\":" + q(text(experience, "supportContact", ""));
  out += ",\"notifications\":" + q(text(experience, "notifications", "important"));
  out += ",\"trayIcon\":" + b(flag(experience, "trayIcon", true));
  out += ",\"allowUserScans\":" + b(flag(experience, "allowUserScans", true));
  out += ",\"policyName\":" + q(WideToUtf8(policy_.policyName));
  out += ",\"agentVersion\":" + q(WideToUtf8(config_.agentVersion));
  out += ",\"managed\":" + b(!state_.deviceId.empty());
  out += ",\"realtime\":" + b(policy_.realtimeProtectionEnabled);
  out += ",\"webProtection\":" + b(policy_.webProtectionEnabled || policy_.destinationProtectionEnabled);
  out += ",\"scriptInspection\":" + b(policy_.scriptInspectionEnabled);
  out += ",\"firewallManaged\":" + b(flag(firewallSection, "enabled", false));
  out += ",\"ransomwareProtection\":" + b(flag(ransomware, "enabled", true));
  out += ",\"quickScanSchedule\":" + q(text(section("antimalware"), "quickScanSchedule", ""));
  out += ",\"allowUserPause\":" + b(flag(experience, "allowUserPause", false));
  {
    const auto until = pausedUntil_.load();
    out += ",\"pausedUntil\":" + q(until > static_cast<long long>(std::time(nullptr)) ? WideToUtf8(UnixToIso(until)) : std::string());
  }
  {
    const auto* privilege = section("privilege");
    const auto mode = flag(privilege, "enabled", false) ? text(privilege, "elevationRequests", "approval") : std::string("off");
    out += ",\"elevationRequests\":" + q(mode == "auto-approve" || mode == "approval" ? mode : "off");
  }
  out += "}";
  try {
    const auto path = config_.installRootPath / L"experience.json";
    const auto temp = config_.installRootPath / L"experience.json.tmp";
    {
      std::ofstream file(temp, std::ios::binary | std::ios::trunc);
      file << out;
    }
    std::error_code ec;
    std::filesystem::rename(temp, path, ec);
  } catch (...) {
  }
}

bool AgentService::ScanNetworkDrives() const {
  return !policy_.modulesJson.empty() && ExtendedPolicy::Parse(policy_.modulesJson).scanNetworkDrives;
}

int AgentService::ScheduledScanCpuLimit() const {
  return policy_.modulesJson.empty() ? 100 : ExtendedPolicy::Parse(policy_.modulesJson).scanCpuLimitPercent;
}

void AgentService::ApplyFirewallPolicy() {
  if (policy_.modulesJson.empty()) {
    return;
  }
  const auto settings = firewall::Parse(policy_.modulesJson);
  if (!settings.present) {
    return;
  }
  auto script = firewall::BuildScript(settings, WideToUtf8(config_.installRootPath.wstring()));
  std::wstring summary = settings.enabled
                             ? std::wstring(L"Firewall policy applied (inbound ") + (settings.blockInbound ? L"block" : L"allow") +
                                   L", outbound " + (settings.blockOutbound ? L"block" : L"allow") + L", " +
                                   std::to_wstring(settings.rules.size()) + L" custom rules)"
                             : std::wstring(L"Network hardening applied (Windows Firewall not managed)");
  std::lock_guard lock(firewallMutex_);
  if (script == appliedFirewallScript_ && pendingFirewallScript_.empty()) {
    return;
  }
  pendingFirewallScript_ = std::move(script);
  pendingFirewallSummary_ = std::move(summary);
  if (firewallWorkerBusy_) {
    return;  // the running worker picks up the newest script when it finishes
  }
  if (firewallThread_.joinable()) {
    firewallThread_.join();  // finished: busy is false
  }
  firewallWorkerBusy_ = true;
  firewallThread_ = std::thread([this] { FirewallWorker(); });
}

void AgentService::FirewallWorker() {
  for (;;) {
    std::string script;
    std::wstring summary;
    {
      std::lock_guard lock(firewallMutex_);
      if (pendingFirewallScript_.empty() || pendingFirewallScript_ == appliedFirewallScript_) {
        pendingFirewallScript_.clear();
        firewallWorkerBusy_ = false;
        return;
      }
      script = std::move(pendingFirewallScript_);
      summary = std::move(pendingFirewallSummary_);
      pendingFirewallScript_.clear();
    }
    const bool ok = RunFirewallScript(script, summary);
    std::lock_guard lock(firewallMutex_);
    if (ok) {
      appliedFirewallScript_ = script;
    }
    if (!ok && pendingFirewallScript_.empty()) {
      firewallWorkerBusy_ = false;
      return;  // retried on the next policy change or service start
    }
  }
}

bool AgentService::RunFirewallScript(const std::string& script, const std::wstring& summaryIn) {
  const auto workRoot = config_.runtimeDatabasePath.parent_path() / L"rmm" / L"firewall";
  try {
    std::error_code ec;
    std::filesystem::create_directories(workRoot, ec);
    const auto path = workRoot / L"apply-firewall.ps1";
    {
      std::ofstream file(path, std::ios::binary | std::ios::trunc);
      file << "\xEF\xBB\xBF" << script;
    }
    wchar_t systemDir[MAX_PATH]{};
    GetSystemDirectoryW(systemDir, MAX_PATH);
    const std::wstring command = L"\"" + std::wstring(systemDir) +
                                 L"\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                                 path.wstring() + L"\"";
    const auto result = rmm::RunProcess(command, workRoot.wstring(), {}, 3 * 60 * 1000);
    std::filesystem::remove(path, ec);
    auto output = result.stdoutText;
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r' || output.back() == ' ')) {
      output.pop_back();
    }
    const auto parsed = json::Parse(output);
    if (result.timedOut || !parsed || !parsed->IsObject()) {
      QueueTelemetryEvent(L"firewall.apply_failed", L"firewall", L"Firewall policy could not be applied",
                          L"{\"stderr\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(result.stderrText.substr(0, 2000)))) + L"\"}");
      return false;
    }
    const bool ok = parsed->Get("ok") && parsed->Get("ok")->Bool().value_or(false);
    QueueTelemetryEvent(ok ? L"firewall.applied" : L"firewall.applied_with_warnings", L"firewall",
                        ok ? summaryIn : summaryIn + L" with warnings", Utf8ToWide(output));
    return true;
  } catch (const std::exception& error) {
    QueueTelemetryEvent(L"firewall.apply_failed", L"firewall", L"Firewall policy could not be applied",
                        L"{\"error\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}");
    return false;
  }
}

void AgentService::SyncMlModel(const int cycle) {
  if (!processGuard_ || state_.deviceId.empty()) {
    return;
  }
  const auto modelPath = processGuard_->ModelPath();
  const auto versionPath = modelPath.parent_path() / L"fenrir-pe.version";
  try {
    const auto manifest = controlPlaneClient_->FetchMlModelManifest(state_);
    if (manifest.version.empty()) {
      return;
    }
    std::wstring installedVersion;
    {
      std::wifstream in(versionPath);
      std::getline(in, installedVersion);
    }
    std::error_code error;
    if (installedVersion == manifest.version && std::filesystem::exists(modelPath, error)) {
      return;
    }
    const auto bytes = controlPlaneClient_->DownloadMlModel(state_);
    const auto digest = ComputeBufferSha256(bytes);
    if (!manifest.sha256.empty() && _wcsicmp(digest.c_str(), manifest.sha256.c_str()) != 0) {
      throw std::runtime_error("model checksum mismatch");
    }
    std::string loadError;
    if (!ml::GbdtModel::Load(bytes, &loadError)) {
      throw std::runtime_error("downloaded model is invalid: " + loadError);
    }
    std::filesystem::create_directories(modelPath.parent_path(), error);
    const auto staging = modelPath.wstring() + L".download";
    {
      std::ofstream out(std::filesystem::path(staging), std::ios::binary | std::ios::trunc);
      out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    std::filesystem::rename(staging, modelPath, error);
    if (error) {
      throw std::runtime_error("could not install model: " + error.message());
    }
    std::wofstream(versionPath, std::ios::trunc) << manifest.version;
    QueueTelemetryEvent(L"ml.model.updated", L"ml-updater", L"The endpoint installed a new static ML model.",
                        BuildCyclePayload(cycle, L"\"version\":\"" + Utf8ToWide(EscapeJsonString(manifest.version)) +
                                                     L"\",\"bytes\":" + std::to_wstring(bytes.size())));
  } catch (const std::exception& error) {
    QueueTelemetryEvent(L"ml.model.update_failed", L"ml-updater", L"The endpoint could not update the static ML model.",
                        BuildCyclePayload(cycle, L"\"error\":\"" + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\""));
  }
}

void AgentService::LoadLocalPolicyCache() {
  state_ = stateStore_ ? stateStore_->LoadOrCreate() : AgentState{};
  state_.agentVersion = config_.agentVersion;
  state_.platformVersion = config_.platformVersion;
  if (state_.policy.policyId.empty()) {
    state_.policy = CreateDefaultPolicySnapshot();
  }
  policy_ = state_.policy;
  pendingTelemetry_ = telemetryQueueStore_ ? telemetryQueueStore_->LoadPending() : std::vector<TelemetryRecord>{};
}

void AgentService::StartTelemetrySpool() const {
  const auto deviceLabel = state_.deviceId.empty()
                               ? std::wstring(config_.managedMode ? L"(not enrolled yet)" : L"(unlicensed update-only mode)")
                               : state_.deviceId;
  std::wcout << L"Telemetry spool ready for device " << deviceLabel << L" with " << pendingTelemetry_.size()
             << L" queued event(s)." << std::endl;
}

void AgentService::StartCommandLoop() const {
  std::wcout << L"Update feed source: " << config_.controlPlaneBaseUrl << L"/api/v1/update-check" << std::endl;
  std::wcout << L"Signature feed source: " << config_.controlPlaneBaseUrl << L"/api/v1/agent/bundle" << std::endl;

  if (config_.managedMode) {
    std::wcout << L"Managed mode: enrolling with " << config_.controlPlaneBaseUrl
               << L" for heartbeats, telemetry, commands and remote access." << std::endl;
  } else {
    std::wcout << L"External reporting is disabled; agent runs in update-only sync mode." << std::endl;
  }

  std::wcout << L"Real-time protection broker targeting port " << config_.realtimeProtectionPortName << std::endl;
  std::wcout << L"ETW process telemetry sensor " << (processEtwSensor_ && processEtwSensor_->IsActive() ? L"active"
                                                                                                          : L"fallback")
             << std::endl;
  std::wcout << L"WFP isolation manager "
             << (networkIsolationManager_ ? (networkIsolationManager_->EngineReady() ? L"ready" : L"unavailable")
                                          : L"not configured")
             << std::endl;
}

void AgentService::PrintStatus() const {
  const auto deviceLabel = state_.deviceId.empty() ? std::wstring(L"(not used in update-only mode)") : state_.deviceId;
  const auto lastPolicySync = state_.lastPolicySyncAt.empty() ? std::wstring(L"(never)") : state_.lastPolicySyncAt;
  const auto lastHeartbeat = state_.lastHeartbeatAt.empty() ? std::wstring(L"(never)") : state_.lastHeartbeatAt;

  std::wcout << L"Hostname: " << state_.hostname << std::endl;
  std::wcout << L"Device ID: " << deviceLabel << std::endl;
  std::wcout << L"Policy: " << policy_.policyName << L" (" << policy_.revision << L")" << std::endl;
  std::wcout << L"Health state: " << state_.healthState << std::endl;
  std::wcout << L"Last update sync: " << lastPolicySync << std::endl;
  std::wcout << L"Last control-plane contact: " << lastHeartbeat << std::endl;
  std::wcout << L"Pending telemetry events: " << pendingTelemetry_.size() << std::endl;
}

void AgentService::QueueEndpointStatusTelemetry() {
  const auto installRoot = ResolveInstallRootForConfig(config_);
  HardeningManager hardeningManager(config_, installRoot);
  const auto hardeningStatus = hardeningManager.QueryStatus();
  const auto protectedServiceExpected = hardeningStatus.elamDriverPresent || !config_.elamDriverPath.empty();
  lastHardeningCheckFailed_ =
      !(hardeningStatus.registryConfigured && hardeningStatus.runtimePathsProtected &&
        (!protectedServiceExpected || hardeningStatus.launchProtectedConfigured));

  QueueTelemetryEvent(lastHardeningCheckFailed_ ? L"tamper.protection.degraded" : L"tamper.protection.ready",
                      L"hardening-manager", hardeningStatus.statusMessage,
                      std::wstring(L"{\"registryConfigured\":") +
                          (hardeningStatus.registryConfigured ? std::wstring(L"true") : std::wstring(L"false")) +
                          L",\"runtimePathsProtected\":" +
                          (hardeningStatus.runtimePathsProtected ? std::wstring(L"true") : std::wstring(L"false")) +
                          L"}");

  const WscCoexistenceManager wscManager;
  QueueTelemetryEvent(L"wsc.coexistence.state", L"wsc-coexistence",
                      L"Windows Security Center coexistence data was collected.",
                      WscCoexistenceManager::ToJson(wscManager.CaptureSnapshot()));
}

void AgentService::QueueDeviceInventoryTelemetry(const int cycle) {
  const auto snapshot = CollectDeviceInventorySnapshot();
  QueueTelemetryEvent(L"device.inventory.snapshot", L"device-inventory",
                      L"The endpoint collected a local device inventory snapshot.",
                      BuildCyclePayload(cycle, std::wstring(L"\"inventory\":") + BuildDeviceInventoryPayload(snapshot)));
}

void AgentService::QueuePatchTelemetry(const int cycle) {
  PatchOrchestrator orchestrator(config_);
  const auto snapshot = orchestrator.LoadSnapshot(20, 50, 20, 50);
  QueueTelemetryEvent(L"patch.snapshot", L"patch-orchestrator",
                      L"The endpoint collected a local patch posture snapshot.",
                      BuildCyclePayload(cycle, std::wstring(L"\"windowsUpdates\":") +
                                                   std::to_wstring(snapshot.windowsUpdates.size()) +
                                                   L",\"software\":" + std::to_wstring(snapshot.software.size()) +
                                                   L",\"history\":" + std::to_wstring(snapshot.history.size())));
}

void AgentService::DrainProcessTelemetry() {
  if (!processEtwSensor_) {
    return;
  }

  const auto telemetry = processEtwSensor_->DrainTelemetry();
  if (!telemetry.empty()) {
    QueueTelemetryRecords(telemetry);
  }
}

void AgentService::DrainRansomwareTelemetry() {
  if (!ransomwareShield_) {
    return;
  }
  auto telemetry = ransomwareShield_->DrainTelemetry();
  if (bruteForceGuard_) {
    auto more = bruteForceGuard_->DrainTelemetry();
    telemetry.insert(telemetry.end(), more.begin(), more.end());
  }
  if (registryWatcher_) {
    auto more = registryWatcher_->DrainTelemetry();
    telemetry.insert(telemetry.end(), more.begin(), more.end());
  }
  if (!telemetry.empty()) {
    QueueTelemetryRecords(telemetry);
  }
}

void AgentService::DrainRealtimeProtectionTelemetry() {
  if (!realtimeProtectionBroker_) {
    return;
  }

  const auto telemetry = realtimeProtectionBroker_->DrainTelemetry();
  if (!telemetry.empty()) {
    QueueTelemetryRecords(telemetry);
  }
}

void AgentService::DrainNetworkTelemetry() {
  if (!networkIsolationManager_) {
    return;
  }

  const auto telemetry = networkIsolationManager_->DrainTelemetry();
  if (telemetry.empty()) {
    return;
  }

  RuntimeDatabase runtimeDatabase(config_.runtimeDatabasePath);
  DestinationRuntimeStore destinationStore(config_.runtimeDatabasePath);
  destinationStore.SavePolicy(policy_);
  const auto destinationPolicy = ProjectDestinationPolicy(policy_);
  DestinationVerdictEngine verdictEngine(config_.runtimeDatabasePath);

  bool isolationAttempted = false;

  for (const auto& record : telemetry) {
    if (realtimeProtectionBroker_) {
      if (const auto behaviorEvent = BuildBehaviorEventFromNetworkTelemetry(record, state_.deviceId);
          behaviorEvent.has_value()) {
        realtimeProtectionBroker_->ObserveBehaviorEvent(*behaviorEvent);
      }
    }

    const auto remoteAddress = ExtractPayloadString(record.payloadJson, "remoteAddress").value_or(L"");
    if (remoteAddress.empty()) {
      continue;
    }

    auto processImagePath = ExtractPayloadString(record.payloadJson, "processImagePath").value_or(L"");
    if (processImagePath.empty()) {
      processImagePath = ExtractPayloadString(record.payloadJson, "appId").value_or(L"");
    }

    const auto parentImagePath = ExtractPayloadString(record.payloadJson, "parentProcessImagePath").value_or(L"");
    const auto browserOrigin =
        BuildContentOriginContext(std::filesystem::path(remoteAddress), processImagePath, parentImagePath,
                                  ExtractPayloadString(record.payloadJson, "commandLine").value_or(L""),
                                  record.occurredAt);

    DestinationContext context{};
    context.indicatorType = ThreatIndicatorType::Ip;
    context.originalIndicator = remoteAddress;
    context.normalizedIndicator = NormalizeDestinationIndicator(ThreatIndicatorType::Ip, remoteAddress);
    context.host = ExtractPayloadString(record.payloadJson, "remoteHost").value_or(L"");
    if (context.host.empty()) {
      context.host = remoteAddress;
    }
    context.source = record.source.empty() ? L"network-wfp" : record.source;
    context.sourceApplication = processImagePath;
    context.parentApplication = parentImagePath;
    context.userName = ExtractPayloadString(record.payloadJson, "userSid").value_or(L"");
    context.browserFamily = browserOrigin.browserFamily;
    context.deliveryVector = record.eventType;
    context.navigationType = browserOrigin.navigationType;
    context.sourceDomain = browserOrigin.sourceDomain;
    context.sourceUrl = browserOrigin.sourceUrl;
    context.observedAt = record.occurredAt;
    context.browserInitiated = browserOrigin.browserOriginated;
    context.emailOriginated = browserOrigin.emailOriginated;
    context.attachmentOriginated = browserOrigin.attachmentOriginated;
    context.redirectNavigation = browserOrigin.navigationType == L"redirect_navigation";
    context.downloadInitiated = browserOrigin.downloadOriginated;
    context.browserLaunchedFile = browserOrigin.browserLaunchedFile;
    context.browserExtensionHost = browserOrigin.browserExtensionHost;
    context.abusivePermissionPrompt = browserOrigin.abusivePermissionPrompt;
    context.suspiciousBrowserChildProcess = browserOrigin.suspiciousChildProcess;
    context.fakeUpdatePattern = browserOrigin.fakeUpdatePattern;
    context.offlineMode = lastControlPlaneSyncFailed_;

    const auto verdict = verdictEngine.Evaluate(context, destinationPolicy);
    const auto evidence = verdictEngine.BuildEvidenceRecord(context, destinationPolicy, verdict, policy_.policyId,
                                                            policy_.revision);
    const auto intelRecord = BuildDestinationIntelligenceRecord(context, verdict, evidence,
                                                                destinationPolicy.destinationCacheTtlMinutes);
    destinationStore.UpsertIntelligenceRecord(intelRecord);

    QueueTelemetryEvent(BuildDestinationEventType(verdict), L"destination-protection",
                        BuildDestinationEventSummary(verdict),
                        BuildDestinationTelemetryPayload(context, verdict, evidence));

    if (verdict.action == DestinationAction::Warn || verdict.action == DestinationAction::Block ||
        verdict.action == DestinationAction::DegradedAllow) {
      runtimeDatabase.RecordScanHistory(BuildDestinationScanHistoryRecord(context, verdict, evidence));
    }

    if (verdict.action == DestinationAction::Block) {
      if (!policy_.networkObserveOnly && !isolationAttempted) {
        isolationAttempted = true;
        std::wstring isolationError;
        const auto enforced = networkIsolationManager_->IsolationActive() ||
                              networkIsolationManager_->ApplyIsolation(true, &isolationError);
        QueueTelemetryEvent(enforced ? L"network.destination.reputation.enforced"
                                     : L"network.destination.reputation.enforcement_failed",
                            L"network-wfp",
                            enforced ? L"Fenrir enforced host isolation after a blocked destination verdict."
                                     : L"Fenrir attempted destination-based isolation enforcement but the WFP action failed.",
                            std::wstring(L"{\"remoteAddress\":\"") + Utf8ToWide(EscapeJsonString(remoteAddress)) +
                                L"\",\"action\":\"" + DestinationActionToString(verdict.action) +
                                L"\",\"category\":\"" + DestinationThreatCategoryToString(verdict.category) +
                                L"\",\"confidence\":" + std::to_wstring(verdict.confidence) +
                                L",\"error\":\"" + Utf8ToWide(EscapeJsonString(isolationError)) + L"\"}");
      } else if (policy_.networkObserveOnly) {
        QueueTelemetryEvent(L"network.destination.reputation.observe_only", L"network-wfp",
                            L"Fenrir observed a blocked destination verdict but skipped isolation because policy is observe-only.",
                            std::wstring(L"{\"remoteAddress\":\"") + Utf8ToWide(EscapeJsonString(remoteAddress)) +
                                L"\",\"action\":\"" + DestinationActionToString(verdict.action) +
                                L"\",\"category\":\"" + DestinationThreatCategoryToString(verdict.category) +
                                L"\",\"confidence\":" + std::to_wstring(verdict.confidence) + L"}");
      }
    }
  }

  QueueTelemetryRecords(telemetry);
}

void AgentService::QueueCycleTelemetry(const int cycle) {
  QueueTelemetryEvent(L"service.sync.cycle", L"agent-service",
                      L"The endpoint is starting a scheduled sync cycle.",
                      BuildCyclePayload(cycle, std::wstring(L"\\\"hostname\\\":\\\"") + state_.hostname + L"\\\""));

  DrainProcessTelemetry();
  DrainNetworkTelemetry();
  if (!processEtwSensor_ || !processEtwSensor_->IsActive()) {
    const auto processInventory = CollectProcessInventory();
    const auto processSnapshotRecords = BuildProcessSnapshotTelemetry(processInventory, 4);
    if (processSnapshotRecords.empty()) {
      QueueTelemetryEvent(L"process.snapshot.empty", L"process-snapshot",
                          L"No process snapshot records were collected during this cycle.", BuildCyclePayload(cycle));
    } else {
      QueueTelemetryRecords(processSnapshotRecords);
    }
    QueueTelemetryRecords(processDeltaTracker_.CollectDeltaTelemetry(processInventory));
  }

  const auto serviceSnapshotRecords = CollectServiceSnapshotTelemetry(4);
  if (serviceSnapshotRecords.empty()) {
    QueueTelemetryEvent(L"service.snapshot.empty", L"service-snapshot",
                        L"No service snapshot records were collected during this cycle.", BuildCyclePayload(cycle));
  } else {
    QueueTelemetryRecords(serviceSnapshotRecords);
  }

  const auto fileInventory = CollectFileInventory(BuildMonitoredRoots());
  const auto fileSnapshotRecords = BuildRecentFileTelemetry(fileInventory, 4);
  if (fileSnapshotRecords.empty()) {
    QueueTelemetryEvent(L"file.snapshot.empty", L"file-snapshot",
                        L"No recent files were found in the monitored folders during this cycle.",
                        BuildCyclePayload(cycle));
  } else {
    QueueTelemetryRecords(fileSnapshotRecords);
  }
  QueueTelemetryRecords(fileDeltaTracker_.CollectDeltaTelemetry(fileInventory));

  if (networkIsolationManager_ && networkIsolationManager_->EngineReady()) {
    QueueTelemetryRecords(networkIsolationManager_->CollectConnectionSnapshotTelemetry(6));
  }

  if (cycle == 1 || cycle % 10 == 0) {
    QueueDeviceInventoryTelemetry(cycle);
  }

  QueuePatchTelemetry(cycle);
}

void AgentService::QueueTelemetryEvent(const std::wstring& eventType, const std::wstring& source,
                                       const std::wstring& summary, const std::wstring& payloadJson) {
  if (mainThreadId_ != std::thread::id{} && std::this_thread::get_id() != mainThreadId_) {
    std::lock_guard lock(remoteMutex_);
    deferredTelemetry_.push_back({eventType, source, summary, payloadJson});
    return;
  }
  QueueTelemetryRecords({TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payloadJson}});
}

void AgentService::QueueTelemetryRecords(const std::vector<TelemetryRecord>& source) {
  // The policy's EDR collection switches decide which routine activity events are kept.
  ExtendedPolicy filter;
  {
    std::lock_guard guard(telemetryFilterMutex_);
    if (policy_.revision != telemetryFilterRevision_) {
      telemetryFilter_ = policy_.modulesJson.empty() ? ExtendedPolicy{} : ExtendedPolicy::Parse(policy_.modulesJson);
      telemetryFilterRevision_ = policy_.revision;
    }
    filter = telemetryFilter_;
  }
  std::vector<TelemetryRecord> records;
  records.reserve(source.size());
  for (const auto& record : source) {
    if (RoutineTelemetryAllowed(filter, record.eventType, record.payloadJson)) {
      records.push_back(record);
    }
  }
  if (records.empty()) {
    return;
  }
  // Append only: scans, the scanner CLI and the AMSI provider add rows to the same queue, and a
  // whole-queue rewrite from this in-memory copy would silently drop them.
  pendingTelemetry_.insert(pendingTelemetry_.end(), records.begin(), records.end());
  telemetryQueueStore_->Append(records);
  constexpr std::size_t kMaxQueuedTelemetry = 5000;
  if (pendingTelemetry_.size() > kMaxQueuedTelemetry) {
    EnforceTelemetryQueueBudget(&pendingTelemetry_);
    telemetryQueueStore_->Trim(kMaxQueuedTelemetry);
  }
}

void AgentService::FlushTelemetryQueue() {
  if (telemetryQueueStore_) {
    // Pick up rows other writers appended since the last flush.
    pendingTelemetry_ = telemetryQueueStore_->LoadPending();
  }
  if (state_.deviceId.empty() || pendingTelemetry_.empty()) {
    lastTelemetryFlushFailed_ = false;
    return;
  }

  lastTelemetryFlushFailed_ = false;
  bool attemptedRecovery = false;
  while (!pendingTelemetry_.empty() && !ShouldStop()) {
    const auto batchSize =
        std::min<std::size_t>(pendingTelemetry_.size(), static_cast<std::size_t>(config_.telemetryBatchSize));
    const std::vector<TelemetryRecord> batch(pendingTelemetry_.begin(), pendingTelemetry_.begin() + batchSize);

    try {
      const auto result = controlPlaneClient_->SendTelemetryBatch(state_, batch);
      std::vector<std::wstring> delivered;
      delivered.reserve(batch.size());
      for (const auto& record : batch) {
        delivered.push_back(record.eventId);
      }
      telemetryQueueStore_->Remove(delivered);
      pendingTelemetry_.erase(pendingTelemetry_.begin(), pendingTelemetry_.begin() + batchSize);
      std::wcout << L"Uploaded " << result.accepted << L" telemetry event(s) at " << result.receivedAt
                 << L". Backend now stores " << result.totalStored << L" event(s)." << std::endl;
    } catch (const std::exception& error) {
      if (!attemptedRecovery && RecoverDeviceIdentity(error, L"telemetry upload")) {
        attemptedRecovery = true;
        continue;
      }

      lastTelemetryFlushFailed_ = true;
      std::wcerr << L"Telemetry upload failed, leaving " << pendingTelemetry_.size()
                 << L" event(s) queued locally: " << Utf8ToWide(error.what()) << std::endl;
      break;
    }
  }
}

std::wstring AgentService::ExecuteSoftwareCommand(const RemoteCommand& command, const bool uninstall,
                                                  const bool searchOnly) {
  if (uninstall) {
    return ExecuteInventoryUninstall(command);
  }

  const auto softwareId =
      !command.recordId.empty() ? command.recordId : ExtractPayloadString(command.payloadJson, "softwareId").value_or(command.targetPath);
  if (softwareId.empty()) {
    throw std::runtime_error("Software command is missing a software identifier");
  }

  PatchOrchestrator orchestrator(config_);
  const auto result = orchestrator.UpdateSoftware(softwareId, searchOnly);
  QueueTelemetryEvent(searchOnly ? L"software.search.completed" : L"software.update.completed", L"patch-orchestrator",
                      searchOnly ? L"The endpoint refreshed software update metadata for a managed application."
                                 : L"The endpoint executed a software update action for a managed application.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" +
                          Utf8ToWide(EscapeJsonString(softwareId)) + L"\",\"status\":\"" + result.status + L"\"}");

  if (!result.success && !searchOnly) {
    throw std::runtime_error(WideToUtf8(result.detailJson.empty() ? L"Software update failed" : result.detailJson));
  }

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" +
         Utf8ToWide(EscapeJsonString(softwareId)) + L"\",\"status\":\"" + result.status + L"\"}";
}

std::wstring AgentService::ExecuteSoftwareBlockCommand(const RemoteCommand& command) {
  const auto softwareId =
      !command.recordId.empty() ? command.recordId : ExtractPayloadString(command.payloadJson, "softwareId").value_or(L"");
  if (softwareId.empty()) {
    throw std::runtime_error("Software block command is missing a software identifier");
  }

  RuntimeDatabase runtimeDatabase(config_.runtimeDatabasePath);
  runtimeDatabase.UpsertBlockedSoftwareRule(BlockedSoftwareRule{
      .softwareId = softwareId,
      .displayName = ExtractPayloadString(command.payloadJson, "displayName").value_or(L""),
      .installLocation = command.targetPath,
      .executableNames = ExtractPayloadStringArray(command.payloadJson, "executableNames"),
      .blockedAt = CurrentUtcTimestamp()});

  EnforceBlockedSoftware();

  QueueTelemetryEvent(L"software.blocked", L"policy-enforcement",
                      L"The endpoint recorded a blocked software rule.",
                      std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" +
                          Utf8ToWide(EscapeJsonString(softwareId)) + L"\"}");

  return std::wstring(L"{\"commandId\":\"") + command.commandId + L"\",\"softwareId\":\"" +
         Utf8ToWide(EscapeJsonString(softwareId)) + L"\"}";
}

void AgentService::EnforceBlockedSoftware() {
  RuntimeDatabase runtimeDatabase(config_.runtimeDatabasePath);
  const auto rules = runtimeDatabase.ListBlockedSoftwareRules(200);
  if (rules.empty()) {
    return;
  }

  const auto processInventory = CollectProcessInventory();
  for (const auto& process : processInventory) {
    const auto processName = ToLowerCopy(process.imageName);
    for (const auto& rule : rules) {
      bool matched = false;
      for (const auto& executableName : rule.executableNames) {
        if (!executableName.empty() && processName == ToLowerCopy(executableName)) {
          matched = true;
          break;
        }
      }

      if (!matched) {
        continue;
      }

      RemediationEngine remediationEngine(config_);
      const auto result = remediationEngine.TerminateProcessByPid(process.pid, true);
      QueueTelemetryEvent(L"software.block.enforced", L"policy-enforcement",
                          L"The endpoint terminated a running process due to a blocked software rule.",
                          std::wstring(L"{\"softwareId\":\"") + Utf8ToWide(EscapeJsonString(rule.softwareId)) +
                              L"\",\"processId\":" + std::to_wstring(process.pid) + L",\"terminatedCount\":" +
                              std::to_wstring(result.processesTerminated) + L"}");
    }
  }
}

ScanVerdict AgentService::EvaluateEvent(const EventEnvelope& event) const {
  if (realtimeProtectionBroker_) {
    return realtimeProtectionBroker_->EvaluateEvent(event);
  }

  return ScanVerdict{};
}

}  // namespace antivirus::agent
