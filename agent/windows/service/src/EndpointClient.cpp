#include "EndpointClient.h"

#include <windows.h>
#include <lm.h>

#include <algorithm>
#include <fstream>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <string>

#include "LocalStateStore.h"
#include "LocalControlChannel.h"
#include "QuarantineStore.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kAgentServiceName[] = L"FenrirAgent";
constexpr wchar_t kPamRequestFileName[] = L"pam-request.json";
constexpr wchar_t kPamAuditFileName[] = L"privilege-requests.jsonl";

struct PamPostureSummary {
  std::size_t pendingRequestCount{0};
  std::size_t approvedCount{0};
  std::size_t deniedCount{0};
  std::wstring healthState{L"unknown"};
};

struct LocalAdminExposureSummary {
  bool known{false};
  std::size_t memberCount{0};
  bool exposed{false};
};

struct ServiceHandleCloser {
  void operator()(SC_HANDLE handle) const noexcept {
    if (handle != nullptr) {
      CloseServiceHandle(handle);
    }
  }
};

using ServiceHandle = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ServiceHandleCloser>;

bool IsLocalBrokerRetryableError(const DWORD error) {
  return error == ERROR_FILE_NOT_FOUND || error == ERROR_PIPE_BUSY;
}

std::wstring BuildLocalBrokerUnavailableMessage(const LocalServiceState serviceState) {
  switch (serviceState) {
    case LocalServiceState::StartPending:
      return L"Fenrir local control is still starting. Try again in a moment.";
    case LocalServiceState::Running:
      return L"Fenrir local control is still initializing. Try again in a moment.";
    default:
      return L"Fenrir local control is unavailable. Start the protection service and try again.";
  }
}

bool IsThreatDisposition(const std::wstring& disposition) {
  return _wcsicmp(disposition.c_str(), L"allow") != 0;
}

bool IsScanSessionRecord(const ScanHistoryRecord& record) {
  return _wcsicmp(record.contentType.c_str(), L"scan-session") == 0;
}

std::filesystem::path ResolveRuntimeRoot(const AgentConfig& config) {
  auto runtimeRoot = config.runtimeDatabasePath.parent_path();
  if (runtimeRoot.empty()) {
    runtimeRoot = config.runtimeDatabasePath;
  }

  if (!runtimeRoot.empty()) {
    return runtimeRoot;
  }

  return std::filesystem::current_path() / L"runtime";
}

std::filesystem::path ResolvePamRequestPath(const AgentConfig& config) {
  return ResolveRuntimeRoot(config) / kPamRequestFileName;
}

std::filesystem::path ResolvePamAuditPath(const AgentConfig& config) {
  auto journalRoot = config.journalRootPath;
  if (journalRoot.empty()) {
    journalRoot = ResolveRuntimeRoot(config);
  }

  return journalRoot / kPamAuditFileName;
}

std::size_t CountToken(const std::string& value, const std::string& token) {
  if (token.empty() || value.empty()) {
    return 0;
  }

  std::size_t count = 0;
  std::size_t position = 0;
  while ((position = value.find(token, position)) != std::string::npos) {
    ++count;
    position += token.size();
  }

  return count;
}

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

std::optional<std::wstring> ExtractJsonString(const std::wstring& json, const std::string& key) {
  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (!std::regex_search(utf8Json, match, pattern)) {
    return std::nullopt;
  }

  return Utf8ToWide(UnescapeJsonString(match[1].str()));
}

std::optional<int> ExtractJsonInt(const std::wstring& json, const std::string& key) {
  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (!std::regex_search(utf8Json, match, pattern)) {
    return std::nullopt;
  }

  return std::stoi(match[1].str());
}

std::optional<bool> ExtractJsonBool(const std::wstring& json, const std::string& key) {
  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(true|false|1|0)");
  std::smatch match;
  if (!std::regex_search(utf8Json, match, pattern)) {
    return std::nullopt;
  }

  const auto token = match[1].str();
  return token == "true" || token == "1";
}

std::wstring EscapeJsonValue(const std::wstring& value) {
  return Utf8ToWide(EscapeJsonString(value));
}

std::wstring BuildBrokerRequestJson(const std::wstring& type, const std::wstring& recordId, const std::wstring& payloadJson,
                                    const std::wstring& targetPath, const std::wstring& sessionAuth) {
  return std::wstring(L"{\"type\":\"") + EscapeJsonValue(type) + L"\",\"recordId\":\"" + EscapeJsonValue(recordId) +
         L"\",\"targetPath\":\"" + EscapeJsonValue(targetPath) + L"\",\"payloadJson\":\"" + EscapeJsonValue(payloadJson) +
         L"\",\"sessionAuth\":\"" + EscapeJsonValue(sessionAuth) + L"\"}";
}

std::wstring FormatWindowsErrorMessage(const DWORD error) {
  LPWSTR buffer = nullptr;
  const auto flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
  const auto length = FormatMessageW(flags, nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
  if (length == 0 || buffer == nullptr) {
    return L"Windows error " + std::to_wstring(error);
  }

  std::wstring message(buffer, length);
  LocalFree(buffer);

  while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
    message.pop_back();
  }
  return message;
}

std::optional<std::wstring> AcquireLocalSessionApproval(const AgentConfig& config, std::wstring* errorMessage) {
  const auto approvalResult = SendLocalBrokerCommand(config, L"local.auth.session.begin");
  if (!approvalResult.success) {
    if (errorMessage != nullptr) {
      if (!approvalResult.errorMessage.empty()) {
        *errorMessage = approvalResult.errorMessage;
      } else if (approvalResult.requestOnly) {
        *errorMessage =
            L"Fenrir requires a device-owner administrator approval before this action can run for this user.";
      } else {
        *errorMessage = L"Fenrir could not establish a local approval session for this sensitive action.";
      }
    }
    return std::nullopt;
  }

  const auto sessionAuth = ExtractJsonString(approvalResult.responseJson, "sessionAuth");
  if (!sessionAuth.has_value() || sessionAuth->empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir approval session handshake did not return a valid session token.";
    }
    return std::nullopt;
  }

  return sessionAuth;
}

PamPostureSummary QueryPamPosture(const AgentConfig& config) {
  PamPostureSummary summary;

  const auto requestPath = ResolvePamRequestPath(config);
  const auto auditPath = ResolvePamAuditPath(config);

  std::error_code error;
  const auto requestRootReady = std::filesystem::exists(requestPath.parent_path(), error) && !error;
  error.clear();
  const auto auditRootReady = std::filesystem::exists(auditPath.parent_path(), error) && !error;
  summary.healthState = (requestRootReady && auditRootReady) ? L"healthy" : L"degraded";

  error.clear();
  if (std::filesystem::exists(requestPath, error) && !error) {
    summary.pendingRequestCount = 1;
  }

  error.clear();
  if (std::filesystem::exists(auditPath, error) && !error) {
    std::ifstream input(auditPath, std::ios::binary);
    if (input.is_open()) {
      const std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
      summary.approvedCount = CountToken(content, "\"decision\":\"approved\"");
      summary.deniedCount = CountToken(content, "\"decision\":\"denied\"");
    }
  }

  return summary;
}

LocalAdminExposureSummary QueryLocalAdminExposure() {
  LocalAdminExposureSummary summary;

  std::set<std::wstring> members;
  DWORD_PTR resumeHandle = 0;
  NET_API_STATUS status = NERR_Success;

  do {
    LPLOCALGROUP_MEMBERS_INFO_2 records = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    status = NetLocalGroupGetMembers(nullptr, L"Administrators", 2, reinterpret_cast<LPBYTE*>(&records),
                                     MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
    if (status != NERR_Success && status != ERROR_MORE_DATA) {
      if (records != nullptr) {
        NetApiBufferFree(records);
      }
      return summary;
    }

    for (DWORD index = 0; index < entriesRead; ++index) {
      if (records[index].lgrmi2_domainandname != nullptr) {
        members.insert(records[index].lgrmi2_domainandname);
      }
    }

    if (records != nullptr) {
      NetApiBufferFree(records);
    }
  } while (status == ERROR_MORE_DATA);

  summary.known = true;
  summary.memberCount = members.size();
  summary.exposed = summary.memberCount > 1;
  return summary;
}

}  // namespace

LocalServiceState QueryAgentServiceState() {
  ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    return LocalServiceState::Unknown;
  }

  ServiceHandle service(OpenServiceW(manager.get(), kAgentServiceName, SERVICE_QUERY_STATUS));
  if (!service) {
    return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? LocalServiceState::NotInstalled : LocalServiceState::Unknown;
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                            &bytesNeeded)) {
    return LocalServiceState::Unknown;
  }

  switch (status.dwCurrentState) {
    case SERVICE_RUNNING:
      return LocalServiceState::Running;
    case SERVICE_STOPPED:
      return LocalServiceState::Stopped;
    case SERVICE_START_PENDING:
      return LocalServiceState::StartPending;
    case SERVICE_STOP_PENDING:
      return LocalServiceState::StopPending;
    case SERVICE_PAUSED:
      return LocalServiceState::Paused;
    default:
      return LocalServiceState::Unknown;
  }
}

std::wstring LocalServiceStateToString(const LocalServiceState state) {
  switch (state) {
    case LocalServiceState::NotInstalled:
      return L"not installed";
    case LocalServiceState::Running:
      return L"running";
    case LocalServiceState::Stopped:
      return L"stopped";
    case LocalServiceState::StartPending:
      return L"starting";
    case LocalServiceState::StopPending:
      return L"stopping";
    case LocalServiceState::Paused:
      return L"paused";
    default:
      return L"unknown";
  }
}

bool StartAgentService() {
  ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    return false;
  }

  ServiceHandle service(OpenServiceW(manager.get(), kAgentServiceName, SERVICE_START | SERVICE_QUERY_STATUS));
  if (!service) {
    return false;
  }

  if (StartServiceW(service.get(), 0, nullptr)) {
    return true;
  }

  return GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool StopAgentService() {
  ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    return false;
  }

  ServiceHandle service(OpenServiceW(manager.get(), kAgentServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS));
  if (!service) {
    return false;
  }

  SERVICE_STATUS status{};
  if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &status)) {
    const auto error = GetLastError();
    if (error != ERROR_SERVICE_NOT_ACTIVE) {
      return false;
    }
  }

  for (int attempt = 0; attempt < 30; ++attempt) {
    SERVICE_STATUS_PROCESS current{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&current),
                              sizeof(current), &bytesNeeded)) {
      return false;
    }

    if (current.dwCurrentState == SERVICE_STOPPED) {
      return true;
    }

    Sleep(250);
  }

  return false;
}

bool RestartAgentService() {
  const auto currentState = QueryAgentServiceState();
  if (currentState == LocalServiceState::Running || currentState == LocalServiceState::StopPending ||
      currentState == LocalServiceState::StartPending || currentState == LocalServiceState::Paused) {
    if (!StopAgentService()) {
      return false;
    }
  }

  return StartAgentService();
}

EndpointClientSnapshot LoadEndpointClientSnapshot(const AgentConfig& config, const std::size_t threatLimit,
                                                  const std::size_t quarantineLimit, const std::size_t findingLimit,
                                                  const std::size_t updateLimit) {
  LocalStateStore stateStore(config.runtimeDatabasePath, config.stateFilePath);
  const auto state = stateStore.LoadOrCreate();
  auto serviceState = QueryAgentServiceState();
  if (serviceState == LocalServiceState::Stopped || serviceState == LocalServiceState::Paused) {
    if (StartAgentService()) {
      serviceState = QueryAgentServiceState();
    }
  }

  RuntimeDatabase database(config.runtimeDatabasePath);
  const auto findings = database.ListScanHistory(std::max<std::size_t>({threatLimit, findingLimit, 200}));
  const auto quarantineItems = database.ListQuarantineRecords(quarantineLimit);

  EndpointClientSnapshot snapshot{
      .agentState = state,
      .serviceState = serviceState,
      .queuedTelemetryCount = database.CountTelemetryQueue(),
      .quarantineItems = quarantineItems,
      .updateJournal = database.ListUpdateJournal(updateLimit),
      .windowsUpdates = database.ListWindowsUpdateRecords(50),
      .softwarePatches = database.ListSoftwarePatchRecords(100),
      .patchHistory = database.ListPatchHistoryRecords(50)};

  database.LoadRebootCoordinator(snapshot.rebootCoordinator);

  const auto pamPosture = QueryPamPosture(config);
  snapshot.pendingPamRequestCount = pamPosture.pendingRequestCount;
  snapshot.pamApprovedCount = pamPosture.approvedCount;
  snapshot.pamDeniedCount = pamPosture.deniedCount;
  snapshot.pamHealthState = pamPosture.healthState;

  const auto localAdminExposure = QueryLocalAdminExposure();
  snapshot.localAdminExposureKnown = localAdminExposure.known;
  snapshot.localAdminMemberCount = localAdminExposure.memberCount;
  snapshot.localAdminExposure = localAdminExposure.exposed;

  snapshot.activeQuarantineCount = std::count_if(
      quarantineItems.begin(), quarantineItems.end(),
      [](const QuarantineIndexRecord& record) { return record.localStatus.rfind(L"quarantined", 0) == 0; });

  for (const auto& finding : findings) {
    if (snapshot.recentFindings.size() < findingLimit) {
      snapshot.recentFindings.push_back(finding);
    }

    if (IsScanSessionRecord(finding)) {
      continue;
    }

    if (!IsThreatDisposition(finding.disposition)) {
      continue;
    }

    if (snapshot.recentThreats.size() < threatLimit) {
      snapshot.recentThreats.push_back(finding);
    }

    const auto remediated = _wcsicmp(finding.remediationStatus.c_str(), L"quarantined") == 0;
    if (!remediated) {
      ++snapshot.openThreatCount;
    }
  }

  return snapshot;
}

QuarantineActionResult RestoreQuarantinedItem(const AgentConfig& config, const std::wstring& recordId) {
  std::wstring approvalError;
  const auto approvalToken = AcquireLocalSessionApproval(config, &approvalError);
  if (!approvalToken.has_value()) {
    return QuarantineActionResult{
        .success = false,
        .recordId = recordId,
        .errorMessage = approvalError.empty()
                            ? L"Fenrir could not open an approval session for quarantine restore."
                            : approvalError};
  }

  const auto brokerResult = SendLocalBrokerCommand(config, L"quarantine.restore", recordId, L"{}", L"", *approvalToken);
  if (!brokerResult.success) {
    auto message = brokerResult.errorMessage.empty()
                       ? std::wstring(L"Fenrir could not broker the quarantine restore action through the protection service.")
                       : brokerResult.errorMessage;
    if (brokerResult.requestOnly && !brokerResult.approvalRequestId.empty()) {
      message += L" Your IT provider can do this for you from the Fenrir console (reference " +
                 brokerResult.approvalRequestId + L").";
    }

    return QuarantineActionResult{
        .success = false,
        .recordId = recordId,
        .approvalRequestId = brokerResult.approvalRequestId,
        .errorMessage = message};
  }

  return QuarantineActionResult{
      .success = true,
      .recordId = ExtractJsonString(brokerResult.responseJson, "recordId").value_or(recordId)};
}

QuarantineActionResult DeleteQuarantinedItem(const AgentConfig& config, const std::wstring& recordId) {
  std::wstring approvalError;
  const auto approvalToken = AcquireLocalSessionApproval(config, &approvalError);
  if (!approvalToken.has_value()) {
    return QuarantineActionResult{
        .success = false,
        .recordId = recordId,
        .errorMessage = approvalError.empty()
                            ? L"Fenrir could not open an approval session for quarantine delete."
                            : approvalError};
  }

  const auto brokerResult = SendLocalBrokerCommand(config, L"quarantine.delete", recordId, L"{}", L"", *approvalToken);
  if (!brokerResult.success) {
    auto message = brokerResult.errorMessage.empty()
                       ? std::wstring(L"Fenrir could not broker the quarantine delete action through the protection service.")
                       : brokerResult.errorMessage;
    if (brokerResult.requestOnly && !brokerResult.approvalRequestId.empty()) {
      message += L" Your IT provider can do this for you from the Fenrir console (reference " +
                 brokerResult.approvalRequestId + L").";
    }

    return QuarantineActionResult{
        .success = false,
        .recordId = recordId,
        .approvalRequestId = brokerResult.approvalRequestId,
        .errorMessage = message};
  }

  return QuarantineActionResult{
      .success = true,
      .recordId = ExtractJsonString(brokerResult.responseJson, "recordId").value_or(recordId)};
}

LocalBrokerCommandResult SendLocalBrokerCommand(const AgentConfig&, const std::wstring& type, const std::wstring& recordId,
                                                const std::wstring& payloadJson, const std::wstring& targetPath,
                                                const std::wstring& sessionAuth) {
  constexpr DWORD kReadTimeoutMilliseconds = 10'000;
  constexpr DWORD kBufferBytes = 64 * 1024;
  constexpr int kConnectionRetryCount = 20;
  constexpr DWORD kConnectionRetryDelayMilliseconds = 250;

  const auto requestJson = BuildBrokerRequestJson(type, recordId, payloadJson, targetPath, sessionAuth);
  const auto requestUtf8 = WideToUtf8(requestJson);
  std::vector<char> responseBuffer(kBufferBytes, '\0');
  DWORD bytesRead = 0;

  DWORD lastError = ERROR_SUCCESS;
  auto lastObservedServiceState = QueryAgentServiceState();
  for (int attempt = 0; attempt < kConnectionRetryCount; ++attempt) {
    lastObservedServiceState = QueryAgentServiceState();
    if (lastObservedServiceState == LocalServiceState::Stopped || lastObservedServiceState == LocalServiceState::Paused) {
      StartAgentService();
      lastObservedServiceState = QueryAgentServiceState();
    }

    bytesRead = 0;
    const auto success = CallNamedPipeW(kFenrirLocalControlPipeName, const_cast<char*>(requestUtf8.data()),
                                        static_cast<DWORD>(requestUtf8.size()),
                                        responseBuffer.data(), kBufferBytes, &bytesRead, kReadTimeoutMilliseconds);
    if (success != FALSE) {
      const auto responseJson = Utf8ToWide(std::string(responseBuffer.data(), responseBuffer.data() + bytesRead));
      auto result = LocalBrokerCommandResult{
          .success = ExtractJsonBool(responseJson, "success").value_or(false),
          .statusCode = ExtractJsonInt(responseJson, "statusCode").value_or(0),
          .requestOnly = ExtractJsonBool(responseJson, "requestOnly").value_or(false),
          .requiresReauth = ExtractJsonBool(responseJson, "requiresReauth").value_or(false),
          .approvalRequestId = ExtractJsonString(responseJson, "approvalRequestId").value_or(L""),
          .responseJson = ExtractJsonString(responseJson, "resultJson").value_or(L""),
          .errorMessage = ExtractJsonString(responseJson, "errorMessage").value_or(L"")};

      if (!result.success && result.errorMessage.empty()) {
        if (result.requiresReauth) {
          result.errorMessage = L"Fenrir requires a fresh approval session for this sensitive action.";
        } else if (result.requestOnly) {
          result.errorMessage = L"Fenrir policy requires elevated owner approval for this local action.";
        }
      }

      return result;
    }

    lastError = GetLastError();
    if (!IsLocalBrokerRetryableError(lastError) || lastObservedServiceState == LocalServiceState::NotInstalled ||
        attempt + 1 >= kConnectionRetryCount) {
      break;
    }

    Sleep(kConnectionRetryDelayMilliseconds);
  }

  const auto message = IsLocalBrokerRetryableError(lastError)
                           ? BuildLocalBrokerUnavailableMessage(lastObservedServiceState)
                           : L"Fenrir local control request failed: " + FormatWindowsErrorMessage(lastError);
  return LocalBrokerCommandResult{
      .success = false,
      .statusCode = static_cast<int>(lastError),
      .errorMessage = message};
}

LocalBrokerCommandResult ExecuteQueuedLocalApproval(const AgentConfig& config, const std::wstring& approvalRequestId) {
  if (approvalRequestId.empty()) {
    return LocalBrokerCommandResult{
        .success = false,
        .statusCode = 400,
        .errorMessage = L"Fenrir local approval execution requires a non-empty approvalRequestId."};
  }

  std::wstring approvalError;
  const auto approvalToken = AcquireLocalSessionApproval(config, &approvalError);
  if (!approvalToken.has_value()) {
    return LocalBrokerCommandResult{
        .success = false,
        .statusCode = 401,
        .requiresReauth = true,
        .errorMessage = approvalError.empty()
                            ? L"Fenrir could not obtain a fresh local approval session to execute this request."
                            : approvalError};
  }

  const auto payloadJson = std::wstring(L"{\"approvalRequestId\":\"") +
                           EscapeJsonValue(approvalRequestId) + L"\"}";
  return SendLocalBrokerCommand(config, L"local.approval.execute", L"", payloadJson, L"", *approvalToken);
}

LocalBrokerCommandResult SetBreakGlassMode(const AgentConfig& config, const bool enable,
                                           const std::wstring& reason, const bool queuePamRecovery) {
  std::wstring approvalError;
  const auto approvalToken = AcquireLocalSessionApproval(config, &approvalError);
  if (!approvalToken.has_value()) {
    return LocalBrokerCommandResult{
        .success = false,
        .statusCode = 401,
        .requiresReauth = true,
        .errorMessage = approvalError.empty()
                            ? L"Fenrir could not obtain a fresh local approval session for break-glass mode changes."
                            : approvalError};
  }

  const auto commandType = enable ? L"local.breakglass.enable" : L"local.breakglass.disable";
  const auto payloadJson = std::wstring(L"{\"reason\":\"") + EscapeJsonValue(reason) +
                           L"\",\"queuePamRecovery\":" +
                           (queuePamRecovery ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
  return SendLocalBrokerCommand(config, commandType, L"", payloadJson, L"", *approvalToken);
}

LocalBrokerCommandResult ListPendingLocalApprovals(const AgentConfig& config, const std::size_t limit) {
  std::wstring approvalError;
  const auto approvalToken = AcquireLocalSessionApproval(config, &approvalError);
  if (!approvalToken.has_value()) {
    return LocalBrokerCommandResult{
        .success = false,
        .statusCode = 401,
        .requiresReauth = true,
        .errorMessage = approvalError.empty()
                            ? L"Fenrir could not obtain a fresh local approval session for local approval queue review."
                            : approvalError};
  }

  const auto boundedLimit = std::clamp<std::size_t>(limit, 1, 200);
  const auto payloadJson = std::wstring(L"{\"limit\":") + std::to_wstring(boundedLimit) + L"}";
  return SendLocalBrokerCommand(config, L"local.approval.list", L"", payloadJson, L"", *approvalToken);
}

PatchExecutionResult ExecuteSoftwarePatchThroughService(const AgentConfig& config, const std::wstring& softwareId, bool searchOnly) {
  const auto payloadJson = std::wstring(L"{\"softwareId\":\"") + EscapeJsonValue(softwareId) + L"\"}";
  const auto brokerResult = SendLocalBrokerCommand(config, searchOnly ? L"software.update.search" : L"patch.software.install", L"", payloadJson);
  if (!brokerResult.success) {
    return PatchExecutionResult{
        .success = false,
        .targetId = softwareId,
        .provider = L"service-broker",
        .status = L"broker_failed",
        .errorCode = std::to_wstring(brokerResult.statusCode),
        .detailJson = std::wstring(L"{\"error\":\"") +
                      EscapeJsonValue(brokerResult.errorMessage.empty() ? L"Fenrir local broker request failed."
                                                                       : brokerResult.errorMessage) +
                      L"\"}"};
  }

  return PatchExecutionResult{
      .success = ExtractJsonBool(brokerResult.responseJson, "success").value_or(
          ExtractJsonString(brokerResult.responseJson, "status").value_or(L"") == L"installed" ||
          ExtractJsonString(brokerResult.responseJson, "status").value_or(L"") == L"updated" ||
          ExtractJsonString(brokerResult.responseJson, "status").value_or(L"") == L"available"),
      .rebootRequired = ExtractJsonBool(brokerResult.responseJson, "rebootRequired").value_or(false),
      .action = ExtractJsonString(brokerResult.responseJson, "action").value_or(L"patch.software.install"),
      .targetId = ExtractJsonString(brokerResult.responseJson, "targetId").value_or(softwareId),
      .provider = ExtractJsonString(brokerResult.responseJson, "provider").value_or(L"service-broker"),
      .status = ExtractJsonString(brokerResult.responseJson, "status").value_or(L"unknown"),
      .errorCode = ExtractJsonString(brokerResult.responseJson, "errorCode").value_or(L""),
      .detailJson = ExtractJsonString(brokerResult.responseJson, "detailJson").value_or(L"{}")};
}

}  // namespace antivirus::agent
