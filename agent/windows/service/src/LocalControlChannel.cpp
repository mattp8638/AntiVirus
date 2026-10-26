#include "LocalControlChannel.h"

#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "LocalSecurity.h"
#include "StringUtils.h"

namespace antivirus::agent {

namespace {

struct LocalPipeRequest {
  std::wstring type;
  std::wstring recordId;
  std::wstring targetPath;
  std::wstring payloadJson;
  std::wstring sessionAuth;
};

struct SessionApprovalGrant {
  std::wstring userSid;
  std::chrono::steady_clock::time_point expiresAt;
};

constexpr std::size_t kMaxPipeMessageBytes = 64 * 1024;
constexpr std::size_t kMaxCommandTypeChars = 96;
constexpr std::size_t kMaxRecordIdChars = 128;
constexpr std::size_t kMaxTargetPathChars = 4096;
constexpr std::size_t kMaxPayloadJsonChars = 32 * 1024;
constexpr std::size_t kMaxSessionAuthChars = 128;
constexpr auto kSessionApprovalLifetime = std::chrono::minutes(5);

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool IsSafeCommandType(const std::wstring& type) {
  if (type.empty() || type.size() > kMaxCommandTypeChars) {
    return false;
  }

  return std::all_of(type.begin(), type.end(), [](const wchar_t ch) {
    return (ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9') || ch == L'.' || ch == L'_' || ch == L'-';
  });
}

bool RequiresSessionApproval(const std::wstring& type) {
  return type == L"quarantine.restore" || type == L"quarantine.delete" ||
         type == L"local.approval.execute" || type == L"local.approval.list" || type == L"local.breakglass.enable" ||
         type == L"local.breakglass.disable" || type == L"local.admin.audit" ||
         type == L"local.admin.reduction.plan" || type == L"local.admin.reduction.apply" ||
         type == L"local.admin.reduction.rollback" || type == L"local.household.roles.audit" ||
         type == L"intel.pack.ingest" ||
         type == L"local.household.roles.plan" || type == L"local.household.roles.apply";
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

std::optional<std::wstring> ExtractPayloadString(const std::wstring& json, const std::string& key) {
  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (!std::regex_search(utf8Json, match, pattern)) {
    return std::nullopt;
  }

  return Utf8ToWide(UnescapeJsonString(match[1].str()));
}

std::wstring EscapeJsonValue(const std::wstring& value) {
  return Utf8ToWide(EscapeJsonString(value));
}

std::wstring BuildResponseJson(const bool success, const int statusCode, const std::wstring& resultJson,
                               const std::wstring& errorMessage, const std::wstring& role = L"",
                               const std::wstring& requester = L"", const bool requestOnly = false,
                               const bool requiresReauth = false,
                               const std::wstring& approvalRequestId = L"") {
  std::wstring json = L"{\"success\":";
  json += success ? L"true" : L"false";
  json += L",\"statusCode\":";
  json += std::to_wstring(statusCode);
  json += L",\"resultJson\":\"";
  json += EscapeJsonValue(resultJson);
  json += L"\",\"errorMessage\":\"";
  json += EscapeJsonValue(errorMessage);
  json += L"\"";
  if (!role.empty()) {
    json += L",\"role\":\"";
    json += EscapeJsonValue(role);
    json += L"\"";
  }
  if (!requester.empty()) {
    json += L",\"requester\":\"";
    json += EscapeJsonValue(requester);
    json += L"\"";
  }
  if (requestOnly) {
    json += L",\"requestOnly\":true";
  }
  if (requiresReauth) {
    json += L",\"requiresReauth\":true";
  }
  if (!approvalRequestId.empty()) {
    json += L",\"approvalRequestId\":\"";
    json += EscapeJsonValue(approvalRequestId);
    json += L"\"";
  }
  json += L"}";
  return json;
}

LocalAction ResolveActionForCommandType(const std::wstring& type) {
  if (type == L"local.auth.session.begin") {
    return LocalAction::IssueSessionApproval;
  }

  if (type == L"quarantine.restore" || type == L"quarantine.delete") {
    return LocalAction::QuarantineMutate;
  }

  if (type == L"patch.software.install" || type == L"patch.windows.install" || type == L"patch.cycle.run") {
    return LocalAction::PatchInstall;
  }

  if (type == L"patch.scan" || type == L"software.update.search") {
    return LocalAction::PatchRefresh;
  }

  if (type == L"intel.lookup") {
    return LocalAction::ViewStatus;
  }

  if (type == L"intel.pack.ingest") {
    return LocalAction::StartServiceAction;
  }

  if (type == L"support.bundle.export" || type == L"support.bundle.export.full" || type == L"storage.maintenance.run") {
    return LocalAction::ExportSupportBundle;
  }

  if (type == L"local.approval.execute") {
    return LocalAction::StartServiceAction;
  }

  if (type == L"local.approval.list") {
    return LocalAction::StartServiceAction;
  }

  if (type == L"local.breakglass.enable" || type == L"local.breakglass.disable") {
    return LocalAction::StartServiceAction;
  }

  if (type == L"local.admin.audit" || type == L"local.admin.reduction.plan" ||
      type == L"local.admin.reduction.apply" || type == L"local.admin.reduction.rollback") {
    return LocalAction::StartServiceAction;
  }

  if (type == L"local.household.roles.audit" || type == L"local.household.roles.plan" ||
      type == L"local.household.roles.apply") {
    return LocalAction::StartServiceAction;
  }

  return LocalAction::ViewStatus;
}

bool IsSupportedLocalCommand(const std::wstring& type) {
  static const std::array<const wchar_t*, 26> kSupportedTypes = {
      L"local.auth.session.begin",
      L"support.request",
      L"amsi.telemetry.submit",
      L"quarantine.restore",
      L"quarantine.delete",
      L"software.update.search",
      L"patch.scan",
      L"patch.software.install",
      L"patch.windows.install",
      L"patch.cycle.run",
      L"intel.lookup",
      L"intel.pack.ingest",
      L"support.bundle.export",
      L"support.bundle.export.full",
      L"storage.maintenance.run",
      L"local.approval.execute",
      L"local.approval.list",
      L"local.breakglass.enable",
      L"local.breakglass.disable",
      L"local.admin.audit",
      L"local.admin.reduction.plan",
      L"local.admin.reduction.apply",
      L"local.admin.reduction.rollback",
      L"local.household.roles.audit",
      L"local.household.roles.plan",
      L"local.household.roles.apply"};

  return std::any_of(kSupportedTypes.begin(), kSupportedTypes.end(),
                     [&type](const auto* candidate) { return type == candidate; });
}

bool ReadPipeMessage(const HANDLE pipe, std::wstring* message) {
  if (message == nullptr) {
    return false;
  }

  std::string buffer;
  std::array<char, 4096> chunk{};
  DWORD bytesRead = 0;

  for (;;) {
    if (ReadFile(pipe, chunk.data(), static_cast<DWORD>(chunk.size()), &bytesRead, nullptr) != FALSE) {
      if (buffer.size() + bytesRead > kMaxPipeMessageBytes) {
        return false;
      }
      buffer.append(chunk.data(), chunk.data() + bytesRead);
      break;
    }

    const auto error = GetLastError();
    if (error != ERROR_MORE_DATA) {
      return false;
    }

    if (buffer.size() + bytesRead > kMaxPipeMessageBytes) {
      return false;
    }
    buffer.append(chunk.data(), chunk.data() + bytesRead);
  }

  *message = Utf8ToWide(buffer);
  return true;
}

bool WritePipeMessage(const HANDLE pipe, const std::wstring& message) {
  const auto payload = WideToUtf8(message);
  DWORD bytesWritten = 0;
  return WriteFile(pipe, payload.data(), static_cast<DWORD>(payload.size()), &bytesWritten, nullptr) != FALSE;
}

bool ParsePipeRequest(const std::wstring& json, LocalPipeRequest* request, std::wstring* errorMessage) {
  if (request == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local control did not receive a request target.";
    }
    return false;
  }

  if (json.size() > kMaxPipeMessageBytes) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local control rejected a request larger than the allowed pipe payload limit.";
    }
    return false;
  }

  const auto type = ExtractPayloadString(json, "type");
  if (!type.has_value() || type->empty() || !IsSafeCommandType(*type)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local control request contains an invalid command type.";
    }
    return false;
  }

  request->type = *type;
  request->recordId = ExtractPayloadString(json, "recordId").value_or(L"");
  request->targetPath = ExtractPayloadString(json, "targetPath").value_or(L"");
  request->payloadJson = ExtractPayloadString(json, "payloadJson").value_or(L"{}");
  request->sessionAuth = ExtractPayloadString(json, "sessionAuth").value_or(L"");

  if (request->recordId.size() > kMaxRecordIdChars || request->targetPath.size() > kMaxTargetPathChars ||
      request->payloadJson.size() > kMaxPayloadJsonChars || request->sessionAuth.size() > kMaxSessionAuthChars) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local control request exceeded one or more field safety limits.";
    }
    return false;
  }

  if (request->payloadJson.find(L'\0') != std::wstring::npos) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local control rejected a malformed request payload.";
    }
    return false;
  }

  return true;
}

std::wstring QueryImpersonatedUserName() {
  std::array<wchar_t, 256> buffer{};
  DWORD size = static_cast<DWORD>(buffer.size());
  if (GetUserNameW(buffer.data(), &size) == FALSE) {
    return L"unknown";
  }

  if (size > 0 && buffer[size - 1] == L'\0') {
    --size;
  }
  return std::wstring(buffer.data(), size);
}

HANDLE CreatePipeSecurityDescriptor() {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)", SDDL_REVISION_1, &descriptor, nullptr) == FALSE) {
    return nullptr;
  }

  return descriptor;
}

std::wstring BuildLocalCommandId() {
  return L"local-" + CurrentUtcTimestamp() + L"-" + GenerateGuidString();
}

std::filesystem::path ResolveApprovalRequestQueuePath() {
  const auto programData = ReadEnvironmentVariable(L"PROGRAMDATA");
  if (!programData.empty()) {
    return std::filesystem::path(programData) / L"FenrirAgent" / L"runtime" / L"local-approval-requests.jsonl";
  }

  return std::filesystem::current_path() / L"runtime" / L"local-approval-requests.jsonl";
}

std::wstring QueueApprovalRequestRecord(const LocalPipeRequest& request, const std::wstring& requester,
                                        const std::wstring& callerSid, const LocalActionAuthorization& authorization) {
  const auto requestId = GenerateGuidString();
  const auto queuePath = ResolveApprovalRequestQueuePath();

  std::error_code createError;
  std::filesystem::create_directories(queuePath.parent_path(), createError);
  if (createError) {
    return {};
  }

  std::ofstream output(queuePath, std::ios::binary | std::ios::app);
  if (!output.is_open()) {
    return {};
  }

  const std::wstring line =
      L"{\"requestId\":\"" + requestId + L"\",\"createdAt\":\"" + CurrentUtcTimestamp() +
      L"\",\"type\":\"" + EscapeJsonValue(request.type) + L"\",\"requester\":\"" +
      EscapeJsonValue(requester) + L"\",\"callerSid\":\"" + EscapeJsonValue(callerSid) +
      L"\",\"role\":\"" + EscapeJsonValue(LocalUserRoleToString(authorization.role)) +
      L"\",\"reason\":\"" + EscapeJsonValue(authorization.reason) +
      L"\",\"recordId\":\"" + EscapeJsonValue(request.recordId) + L"\",\"targetPath\":\"" +
      EscapeJsonValue(request.targetPath) + L"\",\"payloadJson\":\"" + EscapeJsonValue(request.payloadJson) +
      L"\",\"status\":\"pending\"}\n";
  const auto utf8Line = WideToUtf8(line);
  output.write(utf8Line.data(), static_cast<std::streamsize>(utf8Line.size()));
  output.flush();

  return requestId;
}

void PurgeExpiredSessionApprovals(std::unordered_map<std::wstring, SessionApprovalGrant>* grants) {
  if (grants == nullptr) {
    return;
  }

  const auto now = std::chrono::steady_clock::now();
  for (auto it = grants->begin(); it != grants->end();) {
    if (it->second.expiresAt <= now) {
      it = grants->erase(it);
      continue;
    }
    ++it;
  }
}

std::wstring BuildSessionApprovalResultJson(const std::wstring& sessionAuth) {
  return std::wstring(L"{\"sessionAuth\":\"") + EscapeJsonValue(sessionAuth) +
         L"\",\"expiresInSeconds\":" + std::to_wstring(std::chrono::duration_cast<std::chrono::seconds>(
                                                     kSessionApprovalLifetime)
                                                     .count()) +
         L"}";
}

std::wstring IssueSessionApprovalToken(std::unordered_map<std::wstring, SessionApprovalGrant>* grants,
                                       const std::wstring& callerSid) {
  if (grants == nullptr) {
    return {};
  }

  PurgeExpiredSessionApprovals(grants);
  const auto token = GenerateGuidString();
  (*grants)[token] = SessionApprovalGrant{
      .userSid = ToLowerCopy(callerSid),
      .expiresAt = std::chrono::steady_clock::now() + kSessionApprovalLifetime};
  return token;
}

bool ConsumeSessionApprovalToken(std::unordered_map<std::wstring, SessionApprovalGrant>* grants,
                                 const std::wstring& sessionAuth, const std::wstring& callerSid,
                                 std::wstring* errorMessage) {
  if (grants == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local approval state is unavailable.";
    }
    return false;
  }

  PurgeExpiredSessionApprovals(grants);
  const auto grant = grants->find(sessionAuth);
  if (grant == grants->end()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local approval session is missing or expired. Re-authenticate and try again.";
    }
    return false;
  }

  if (ToLowerCopy(callerSid) != grant->second.userSid) {
    grants->erase(grant);
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local approval session did not match the caller identity.";
    }
    return false;
  }

  grants->erase(grant);
  return true;
}

}  // namespace

class LocalControlChannelState {
 public:
  std::mutex lock;
  HANDLE activePipe{INVALID_HANDLE_VALUE};
  std::thread worker;
  std::mutex sessionApprovalLock;
  std::unordered_map<std::wstring, SessionApprovalGrant> sessionApprovals;
};

struct LocalControlChannel::State : public LocalControlChannelState {};

LocalControlChannel::LocalControlChannel(CommandExecutor executor, StopPredicate shouldStop)
    : executor_(std::move(executor)), shouldStop_(std::move(shouldStop)), state_(std::make_unique<State>()) {}

LocalControlChannel::~LocalControlChannel() { Stop(); }

void LocalControlChannel::Start() {
  auto* state = state_.get();
  if (state == nullptr || running_) {
    return;
  }

  stopRequested_ = false;
  running_ = true;
  state->worker = std::thread([this]() { Run(); });
}

void LocalControlChannel::Stop() {
  auto* state = state_.get();
  if (state == nullptr || !running_) {
    return;
  }

  stopRequested_ = true;
  {
    std::lock_guard guard(state->lock);
    if (state->activePipe != INVALID_HANDLE_VALUE) {
      CancelSynchronousIo(reinterpret_cast<HANDLE>(state->worker.native_handle()));
      CloseHandle(state->activePipe);
      state->activePipe = INVALID_HANDLE_VALUE;
    }
  }

  if (state->worker.joinable()) {
    state->worker.join();
  }
  running_ = false;
}

void LocalControlChannel::Run() {
  auto* state = state_.get();
  if (state == nullptr) {
    return;
  }

  while (!stopRequested_ && !(shouldStop_ && shouldStop_())) {
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = FALSE;
    attributes.lpSecurityDescriptor = CreatePipeSecurityDescriptor();

    const HANDLE pipe =
        CreateNamedPipeW(kFenrirLocalControlPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                         4, 16 * 1024, 16 * 1024, 1000, &attributes);
    if (attributes.lpSecurityDescriptor != nullptr) {
      LocalFree(attributes.lpSecurityDescriptor);
      attributes.lpSecurityDescriptor = nullptr;
    }

    if (pipe == INVALID_HANDLE_VALUE) {
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      continue;
    }

    {
      std::lock_guard guard(state->lock);
      state->activePipe = pipe;
    }

    const auto connected = ConnectNamedPipe(pipe, nullptr) != FALSE || GetLastError() == ERROR_PIPE_CONNECTED;
    if (!connected) {
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      if (stopRequested_ || (shouldStop_ && shouldStop_())) {
        break;
      }
      continue;
    }

    std::wstring requestMessage;
    if (!ReadPipeMessage(pipe, &requestMessage)) {
      WritePipeMessage(pipe, BuildResponseJson(false, 400, L"", L"Fenrir local control could not read the request payload."));
      FlushFileBuffers(pipe);
      DisconnectNamedPipe(pipe);
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      continue;
    }

    LocalPipeRequest request{};
    std::wstring parseError;
    if (!ParsePipeRequest(requestMessage, &request, &parseError)) {
      WritePipeMessage(pipe, BuildResponseJson(false, 400, L"", parseError));
      FlushFileBuffers(pipe);
      DisconnectNamedPipe(pipe);
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      continue;
    }

    if (!IsSupportedLocalCommand(request.type)) {
      WritePipeMessage(pipe, BuildResponseJson(false, 404, L"", L"Fenrir local control does not expose that command."));
      FlushFileBuffers(pipe);
      DisconnectNamedPipe(pipe);
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      continue;
    }

    LocalActionAuthorization authorization{};
    std::wstring requester = L"unknown";
    std::wstring callerSid;
    if (ImpersonateNamedPipeClient(pipe) != FALSE) {
      authorization = AuthorizeCurrentUser(ResolveActionForCommandType(request.type));
      requester = QueryImpersonatedUserName();
      callerSid = QueryCurrentUserSid();
      RevertToSelf();
    } else {
      authorization = LocalActionAuthorization{
          .role = LocalUserRole::Unknown,
          .allowed = false,
          .requestOnly = false,
          .reason = L"Fenrir could not verify the caller identity for this local action."};
    }

    if (!authorization.allowed) {
      const auto deniedStatusCode = authorization.requestOnly ? 423 : 403;
      std::wstring denialReason = authorization.reason;
      std::wstring approvalRequestId;
      if (authorization.requestOnly) {
        approvalRequestId = QueueApprovalRequestRecord(request, requester, callerSid, authorization);
        if (!approvalRequestId.empty()) {
          denialReason += L" Use approval request " + approvalRequestId + L" to complete this action with an administrator.";
        }
      }
      WritePipeMessage(pipe,
                       BuildResponseJson(false, deniedStatusCode, L"", denialReason,
                                         LocalUserRoleToString(authorization.role), requester,
                                         authorization.requestOnly, false, approvalRequestId));
      FlushFileBuffers(pipe);
      DisconnectNamedPipe(pipe);
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      continue;
    }

    if (request.type == L"local.auth.session.begin") {
      if (callerSid.empty()) {
        WritePipeMessage(pipe, BuildResponseJson(false, 401, L"",
                                                 L"Fenrir could not bind a local approval session to the caller identity.",
                                                 LocalUserRoleToString(authorization.role), requester, false, true));
      } else {
        std::wstring sessionAuth;
        {
          std::lock_guard guard(state->sessionApprovalLock);
          sessionAuth = IssueSessionApprovalToken(&state->sessionApprovals, callerSid);
        }

        if (sessionAuth.empty()) {
          WritePipeMessage(pipe,
                           BuildResponseJson(false, 500, L"",
                                             L"Fenrir could not issue a local approval session for this request.",
                                             LocalUserRoleToString(authorization.role), requester, false, true));
        } else {
          WritePipeMessage(pipe,
                           BuildResponseJson(true, 200, BuildSessionApprovalResultJson(sessionAuth), L"",
                                             LocalUserRoleToString(authorization.role), requester));
        }
      }

      FlushFileBuffers(pipe);
      DisconnectNamedPipe(pipe);
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      continue;
    }

    if (RequiresSessionApproval(request.type)) {
      if (request.sessionAuth.empty() || callerSid.empty()) {
        WritePipeMessage(pipe, BuildResponseJson(false, 401, L"",
                                                 L"Fenrir requires a fresh local approval session for this sensitive action.",
                                                 LocalUserRoleToString(authorization.role), requester, false, true));
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        {
          std::lock_guard guard(state->lock);
          if (state->activePipe == pipe) {
            state->activePipe = INVALID_HANDLE_VALUE;
          }
        }
        CloseHandle(pipe);
        continue;
      }

      std::wstring sessionValidationError;
      bool approved = false;
      {
        std::lock_guard guard(state->sessionApprovalLock);
        approved = ConsumeSessionApprovalToken(&state->sessionApprovals, request.sessionAuth, callerSid,
                                               &sessionValidationError);
      }

      if (!approved) {
        WritePipeMessage(pipe,
                         BuildResponseJson(false, 403, L"", sessionValidationError,
                                           LocalUserRoleToString(authorization.role), requester, false, true));
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        {
          std::lock_guard guard(state->lock);
          if (state->activePipe == pipe) {
            state->activePipe = INVALID_HANDLE_VALUE;
          }
        }
        CloseHandle(pipe);
        continue;
      }
    }

    try {
      RemoteCommand command{};
      command.commandId = BuildLocalCommandId();
      command.type = request.type;
      command.issuedBy = L"local-dashboard:" + requester;
      command.createdAt = CurrentUtcTimestamp();
      command.updatedAt = command.createdAt;
      command.recordId = request.recordId;
      command.targetPath = request.targetPath;
      command.payloadJson = request.payloadJson;

      const auto resultJson = executor_(command);
      WritePipeMessage(pipe, BuildResponseJson(true, 200, resultJson, L"", LocalUserRoleToString(authorization.role),
                                               requester));
    } catch (const std::exception& error) {
      WritePipeMessage(pipe,
                       BuildResponseJson(false, 500, L"", Utf8ToWide(error.what()), LocalUserRoleToString(authorization.role),
                                         requester));
    }

    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    {
      std::lock_guard guard(state->lock);
      if (state->activePipe == pipe) {
        state->activePipe = INVALID_HANDLE_VALUE;
      }
    }
    CloseHandle(pipe);
  }
}

}  // namespace antivirus::agent
