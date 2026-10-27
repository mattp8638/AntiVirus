#include "RealtimeProtectionBroker.h"

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cwctype>
#include <deque>
#include <filesystem>
#include <initializer_list>
#include <numeric>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include "CryptoUtils.h"
#include "EvidenceRecorder.h"
#include "QuarantineStore.h"
#include "RemediationEngine.h"
#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct FilterMessageHeader {
  ULONG replyLength;
  ULONGLONG messageId;
};

struct FilterReplyHeader {
  LONG status;
  ULONGLONG messageId;
};

using FilterConnectCommunicationPortFn =
    HRESULT(WINAPI*)(LPCWSTR, DWORD, LPVOID, WORD, LPSECURITY_ATTRIBUTES, HANDLE*);
using FilterGetMessageFn = HRESULT(WINAPI*)(HANDLE, FilterMessageHeader*, DWORD, LPOVERLAPPED);
using FilterReplyMessageFn = HRESULT(WINAPI*)(HANDLE, FilterReplyHeader*, DWORD);

struct FilterApi {
  HMODULE module{nullptr};
  FilterConnectCommunicationPortFn connect{nullptr};
  FilterGetMessageFn getMessage{nullptr};
  FilterReplyMessageFn replyMessage{nullptr};

  bool Load() {
    module = LoadLibraryW(L"fltlib.dll");
    if (module == nullptr) {
      return false;
    }

    connect = reinterpret_cast<FilterConnectCommunicationPortFn>(
        GetProcAddress(module, "FilterConnectCommunicationPort"));
    getMessage = reinterpret_cast<FilterGetMessageFn>(GetProcAddress(module, "FilterGetMessage"));
    replyMessage = reinterpret_cast<FilterReplyMessageFn>(GetProcAddress(module, "FilterReplyMessage"));
    if (connect == nullptr || getMessage == nullptr || replyMessage == nullptr) {
      FreeLibrary(module);
      module = nullptr;
      connect = nullptr;
      getMessage = nullptr;
      replyMessage = nullptr;
      return false;
    }

    return true;
  }

  ~FilterApi() {
    if (module != nullptr) {
      FreeLibrary(module);
      module = nullptr;
    }
  }
};

#pragma pack(push, 8)
struct BrokerPortMessage {
  FilterMessageHeader header;
  RealtimeFileScanRequest request;
};

struct BrokerPortReply {
  FilterReplyHeader header;
  RealtimeFileScanReply reply;
};
#pragma pack(pop)

constexpr DWORD kBrokerMessageWaitMilliseconds = 1'000;
constexpr auto kProcessContextCacheTtl = std::chrono::seconds(15);
constexpr std::size_t kProcessContextCacheMaxEntries = 512;

struct CachedRealtimeProcessContext {
  DWORD parentPid{0};
  std::wstring imagePath;
  std::wstring parentImagePath;
  std::wstring commandLine;
  std::wstring userSid;
  std::chrono::steady_clock::time_point cachedAt{};
};

struct EnrichedRealtimeRequest {
  RealtimeFileScanRequest request{};
  bool contextEnriched{false};
};

std::mutex gProcessContextCacheMutex;
std::unordered_map<DWORD, CachedRealtimeProcessContext> gProcessContextCache;

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring SafeCopy(const wchar_t* value) {
  if (value == nullptr) {
    return {};
  }

  return std::wstring(value);
}

template <std::size_t N>
void CopyWideField(wchar_t (&destination)[N], const std::wstring& source) {
  std::fill(std::begin(destination), std::end(destination), L'\0');
  if constexpr (N == 0) {
    return;
  }

  wcsncpy_s(destination, N, source.c_str(), _TRUNCATE);
}

void PruneProcessContextCacheLocked(const std::chrono::steady_clock::time_point now) {
  for (auto iterator = gProcessContextCache.begin(); iterator != gProcessContextCache.end();) {
    if ((now - iterator->second.cachedAt) > kProcessContextCacheTtl) {
      iterator = gProcessContextCache.erase(iterator);
      continue;
    }

    ++iterator;
  }

  if (gProcessContextCache.size() > kProcessContextCacheMaxEntries) {
    gProcessContextCache.clear();
  }
}

std::wstring QueryProcessImagePath(const DWORD pid) {
  if (pid == 0) {
    return {};
  }

  const HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return {};
  }

  std::wstring buffer(4096, L'\0');
  DWORD length = static_cast<DWORD>(buffer.size());
  const auto succeeded = QueryFullProcessImageNameW(processHandle, 0, buffer.data(), &length) != FALSE;
  CloseHandle(processHandle);

  if (!succeeded) {
    return {};
  }

  buffer.resize(length);
  return buffer;
}

DWORD QueryParentProcessId(const DWORD pid) {
  if (pid == 0) {
    return 0;
  }

  const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return 0;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  DWORD parentPid = 0;

  if (Process32FirstW(snapshot, &entry) != FALSE) {
    do {
      if (entry.th32ProcessID == pid) {
        parentPid = entry.th32ParentProcessID;
        break;
      }
    } while (Process32NextW(snapshot, &entry) != FALSE);
  }

  CloseHandle(snapshot);
  return parentPid;
}

std::wstring QueryProcessUserSid(const DWORD pid) {
  if (pid == 0) {
    return {};
  }

  const HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return {};
  }

  HANDLE tokenHandle = nullptr;
  if (OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE) {
    CloseHandle(processHandle);
    return {};
  }

  DWORD requiredBytes = 0;
  GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &requiredBytes);
  if (requiredBytes == 0) {
    CloseHandle(tokenHandle);
    CloseHandle(processHandle);
    return {};
  }

  std::vector<unsigned char> buffer(requiredBytes);
  if (GetTokenInformation(tokenHandle, TokenUser, buffer.data(), requiredBytes, &requiredBytes) == FALSE) {
    CloseHandle(tokenHandle);
    CloseHandle(processHandle);
    return {};
  }

  const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  LPWSTR sidString = nullptr;
  const auto converted = ConvertSidToStringSidW(tokenUser->User.Sid, &sidString) != FALSE;

  std::wstring userSid;
  if (converted && sidString != nullptr) {
    userSid = sidString;
    LocalFree(sidString);
  }

  CloseHandle(tokenHandle);
  CloseHandle(processHandle);
  return userSid;
}

std::wstring QueryProcessCommandLine(const DWORD pid) {
  if (pid == 0) {
    return {};
  }

  const HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return {};
  }

  using NtQueryInformationProcessFn = LONG(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
  static const auto ntQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
  if (ntQueryInformationProcess == nullptr) {
    CloseHandle(processHandle);
    return {};
  }

  ULONG requiredBytes = 0;
  constexpr auto kProcessCommandLineInformation =
      static_cast<PROCESSINFOCLASS>(60);
  (void)ntQueryInformationProcess(processHandle, kProcessCommandLineInformation, nullptr, 0, &requiredBytes);
  if (requiredBytes < sizeof(UNICODE_STRING)) {
    CloseHandle(processHandle);
    return {};
  }

  std::vector<unsigned char> buffer(requiredBytes);
  const auto status =
      ntQueryInformationProcess(processHandle, kProcessCommandLineInformation, buffer.data(), requiredBytes,
                                &requiredBytes);
  CloseHandle(processHandle);

  if (status < 0) {
    return {};
  }

  const auto* commandLine = reinterpret_cast<const UNICODE_STRING*>(buffer.data());
  if (commandLine->Length == 0 || commandLine->Buffer == nullptr) {
    return {};
  }

  return std::wstring(commandLine->Buffer, commandLine->Length / sizeof(wchar_t));
}

std::optional<CachedRealtimeProcessContext> QueryRealtimeProcessContext(const DWORD pid) {
  if (pid == 0) {
    return std::nullopt;
  }

  const auto now = std::chrono::steady_clock::now();
  {
    const std::scoped_lock lock(gProcessContextCacheMutex);
    PruneProcessContextCacheLocked(now);
    if (const auto existing = gProcessContextCache.find(pid); existing != gProcessContextCache.end()) {
      return existing->second;
    }
  }

  CachedRealtimeProcessContext context{
      .parentPid = QueryParentProcessId(pid),
      .imagePath = QueryProcessImagePath(pid),
      .parentImagePath = {},
      .commandLine = QueryProcessCommandLine(pid),
      .userSid = QueryProcessUserSid(pid),
      .cachedAt = now};

  if (context.parentPid != 0 && context.parentPid != pid) {
    context.parentImagePath = QueryProcessImagePath(context.parentPid);
  }

  if (context.imagePath.empty() && context.parentImagePath.empty() && context.commandLine.empty() &&
      context.userSid.empty()) {
    return std::nullopt;
  }

  {
    const std::scoped_lock lock(gProcessContextCacheMutex);
    PruneProcessContextCacheLocked(now);
    gProcessContextCache[pid] = context;
  }

  return context;
}

EnrichedRealtimeRequest EnrichRequestProcessContext(const RealtimeFileScanRequest& request) {
  if (request.processId == 0) {
    return EnrichedRealtimeRequest{.request = request, .contextEnriched = false};
  }

  const auto context = QueryRealtimeProcessContext(request.processId);
  if (!context.has_value()) {
    return EnrichedRealtimeRequest{.request = request, .contextEnriched = false};
  }

  auto enriched = request;
  bool changed = false;
  const auto processImage = SafeCopy(request.processImage);
  const auto parentImage = SafeCopy(request.parentImage);
  const auto commandLine = SafeCopy(request.commandLine);
  const auto userSid = SafeCopy(request.userSid);

  if (!context->imagePath.empty() && (processImage.empty() || processImage.find(L'\\') == std::wstring::npos)) {
    CopyWideField(enriched.processImage, context->imagePath);
    changed = true;
  }

  if (!context->parentImagePath.empty() && (parentImage.empty() || parentImage.find(L'\\') == std::wstring::npos)) {
    CopyWideField(enriched.parentImage, context->parentImagePath);
    changed = true;
  }

  if (!context->commandLine.empty() && commandLine.empty()) {
    CopyWideField(enriched.commandLine, context->commandLine);
    changed = true;
  }

  if (!context->userSid.empty() && userSid.empty()) {
    CopyWideField(enriched.userSid, context->userSid);
    changed = true;
  }

  return EnrichedRealtimeRequest{.request = enriched, .contextEnriched = changed};
}

std::wstring OperationToString(const RealtimeFileOperation operation) {
  switch (operation) {
    case ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE:
      return L"create";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN:
      return L"open";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE:
      return L"write";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE:
      return L"execute";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME:
      return L"rename";
    case ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP:
      return L"section-map";
    default:
      return L"unknown";
  }
}

std::wstring EventKindToString(const EventKind kind) {
  switch (kind) {
    case EventKind::FileCreate:
      return L"file-create";
    case EventKind::FileOpen:
      return L"file-open";
    case EventKind::FileWrite:
      return L"file-write";
    case EventKind::FileExecute:
      return L"file-execute";
    case EventKind::ProcessStart:
      return L"process-start";
    case EventKind::ScriptScan:
      return L"script-scan";
    case EventKind::NetworkConnect:
      return L"network-connect";
    default:
      return L"unknown";
  }
}

RealtimeFileOperation EventKindToRealtimeOperation(const EventKind kind) {
  switch (kind) {
    case EventKind::FileCreate:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE;
    case EventKind::FileOpen:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN;
    case EventKind::FileWrite:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE;
    case EventKind::NetworkConnect:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN;
    case EventKind::ProcessStart:
    case EventKind::ScriptScan:
    case EventKind::FileExecute:
    default:
      return ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
  }
}

EventKind OperationToEventKind(const RealtimeFileOperation operation) {
  switch (operation) {
    case ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE:
      return EventKind::FileCreate;
    case ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN:
      return EventKind::FileOpen;
    case ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE:
    case ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME:
      return EventKind::FileWrite;
    case ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE:
    case ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP:
    default:
      return EventKind::FileExecute;
  }
}

bool PathContains(const std::wstring& path, const std::wstring& pattern) {
  return path.find(pattern) != std::wstring::npos;
}

bool ContainsAnyToken(std::wstring_view haystack, std::initializer_list<std::wstring_view> needles) {
  return std::any_of(needles.begin(), needles.end(),
                     [haystack](const auto needle) { return haystack.find(needle) != std::wstring_view::npos; });
}

bool ImageContainsAny(std::wstring_view imageLower, std::initializer_list<std::wstring_view> candidates) {
  return ContainsAnyToken(imageLower, candidates);
}

bool IsUserControlledPath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return PathContains(lower, L"\\users\\") || PathContains(lower, L"\\programdata\\") ||
         PathContains(lower, L"\\temp\\") || PathContains(lower, L"\\downloads\\") ||
         PathContains(lower, L"\\desktop\\") || PathContains(lower, L"\\appdata\\local\\temp\\") ||
         PathContains(lower, L"\\start menu\\programs\\startup\\");
}

bool IsExecutableExtension(const std::wstring& extension) {
  return extension == L".exe" || extension == L".dll" || extension == L".scr" || extension == L".msi";
}

bool IsScriptExtension(const std::wstring& extension) {
  return extension == L".ps1" || extension == L".bat" || extension == L".cmd" || extension == L".js" ||
         extension == L".jse" || extension == L".vbs" || extension == L".vbe" || extension == L".hta";
}

bool IsContainerExtension(const std::wstring& extension) {
  return extension == L".lnk" || extension == L".iso" || extension == L".zip";
}

bool IsScriptingHostImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower, {L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"wscript.exe", L"cscript.exe"});
}

bool IsLolbinImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower, {L"mshta.exe", L"rundll32.exe", L"regsvr32.exe", L"wmic.exe", L"msbuild.exe",
                                       L"installutil.exe", L"regasm.exe", L"regsvcs.exe"});
}

bool IsOfficeOrMailImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower, {L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe",
                                       L"onenote.exe", L"acrord32.exe"});
}

bool IsBrowserImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower, {L"chrome.exe", L"msedge.exe", L"firefox.exe", L"iexplore.exe", L"brave.exe"});
}

bool IsTrustedInstallerImage(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower,
                          {L"msiexec.exe", L"winget.exe", L"choco.exe", L"scoop.exe", L"trustedinstaller.exe"});
}

bool IsLikelyBenignBulkIoProcess(std::wstring_view imageLower) {
  return ImageContainsAny(imageLower, {L"backup", L"wbengine.exe", L"filehistory", L"onedrive.exe",
                                       L"dropbox", L"googledrivesync", L"google drive", L"syncthing",
                                       L"robocopy.exe", L"xcopy.exe", L"7z.exe", L"winrar.exe", L"rar.exe",
                                       L"ffmpeg.exe", L"lightroom", L"photoshop", L"premiere", L"veeam",
                                       L"acronis", L"devenv.exe", L"msbuild.exe", L"git.exe"});
}

bool IsWriteLikeOperation(const RealtimeFileOperation operation) {
  return operation == ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE ||
         operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE ||
         operation == ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME;
}

bool IsUserDataExtension(const std::wstring& extension) {
  return extension == L".doc" || extension == L".docx" || extension == L".xls" || extension == L".xlsx" ||
         extension == L".ppt" || extension == L".pptx" || extension == L".txt" || extension == L".rtf" ||
         extension == L".pdf" || extension == L".jpg" || extension == L".jpeg" || extension == L".png" ||
         extension == L".gif" || extension == L".bmp" || extension == L".csv" || extension == L".json" ||
         extension == L".xml" || extension == L".zip" || extension == L".7z";
}

bool IsSuspiciousEncryptedExtension(const std::wstring& extension) {
  return extension == L".locked" || extension == L".lock" || extension == L".encrypted" || extension == L".enc" ||
         extension == L".crypt" || extension == L".crypted" || extension == L".cry" ||
         extension == L".lockbit" || extension == L".conti" || extension == L".akira" || extension == L".clop" ||
         extension == L".ryuk" || extension == L".blackcat";
}

bool IsExecuteLikeOperation(const RealtimeFileOperation operation) {
  return operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
         operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP;
}

bool IsHighRiskCreateOperation(const RealtimeFileScanRequest& request, const ScanFinding& finding,
                               const PolicySnapshot& policy) {
  if (request.operation != ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE) {
    return false;
  }

  const auto extension = ToLowerCopy(finding.path.extension().wstring());
  const auto highRiskFileType = IsExecutableExtension(extension) || IsScriptExtension(extension) ||
                                IsContainerExtension(extension) || extension == L".hta";
  if (!highRiskFileType || !IsUserControlledPath(finding.path)) {
    return false;
  }

  const auto executeThreshold = static_cast<std::uint32_t>(
      std::clamp(policy.realtimeExecuteBlockThreshold, static_cast<std::uint32_t>(1), static_cast<std::uint32_t>(99)));

  const auto requestFlaggedHighRisk =
      (request.pathRiskFlags & (ANTIVIRUS_REALTIME_PATH_RISK_EXECUTABLE_EXTENSION |
                                ANTIVIRUS_REALTIME_PATH_RISK_SCRIPT_EXTENSION |
                                ANTIVIRUS_REALTIME_PATH_RISK_CONTAINER_EXTENSION)) != 0;

  return requestFlaggedHighRisk || finding.verdict.confidence >= executeThreshold;
}

bool LooksLikeDoubleExtensionLure(const std::wstring& fileNameLower) {
  return ContainsAnyToken(fileNameLower, {L".pdf.exe", L".doc.exe", L".docx.exe", L".xls.exe", L".xlsx.exe",
                                          L".jpg.exe", L".jpeg.exe", L".png.exe", L".txt.exe", L".html.exe"});
}

bool IsHighRiskPersistencePath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return ContainsAnyToken(lower, {L"\\start menu\\programs\\startup\\", L"\\currentversion\\run",
                                  L"\\currentversion\\runonce"});
}

bool IsKnownSafeLocation(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return ContainsAnyToken(lower, {L"\\windows\\", L"\\program files\\", L"\\program files (x86)\\"});
}

struct RealtimeHit {
  std::wstring code;
  std::wstring message;
  std::wstring tacticId;
  std::wstring techniqueId;
  int score{0};
};

void AddRealtimeHit(std::vector<RealtimeHit>& hits, RealtimeHit hit) {
  const auto exists = std::any_of(hits.begin(), hits.end(),
                                  [&hit](const auto& existing) { return existing.code == hit.code; });
  if (!exists) {
    hits.push_back(std::move(hit));
  }
}

int ScoreRealtimeHits(const std::vector<RealtimeHit>& hits) {
  return std::accumulate(hits.begin(), hits.end(), 0,
                         [](const int total, const auto& hit) { return total + hit.score; });
}

void AddContextualRealtimeHits(std::vector<RealtimeHit>& hits, const std::filesystem::path& path,
                               const std::wstring& extension, const RealtimeFileOperation operation,
                               const std::wstring& processImageLower, const std::wstring& parentImageLower,
                               const std::wstring& commandLineLower, const bool userControlledPath) {
  const auto executeLike = IsExecuteLikeOperation(operation);
  const auto highRiskFileType = IsExecutableExtension(extension) || IsScriptExtension(extension) ||
                                IsContainerExtension(extension) || extension == L".hta";
  const auto fileNameLower = ToLowerCopy(path.filename().wstring());

  const auto hasEncodedPayload = ContainsAnyToken(commandLineLower, {L"-enc ", L"-encodedcommand", L"frombase64string"});
  const auto hasDownloadCradle =
      ContainsAnyToken(commandLineLower, {L"downloadstring", L"downloadfile", L"invoke-webrequest", L"invoke-restmethod",
                                          L"start-bitstransfer", L"iwr "});
  const auto hasDynamicExecution = ContainsAnyToken(commandLineLower, {L"invoke-expression", L" iex", L"iex("});
  const auto hasRecoveryInhibition =
      ContainsAnyToken(commandLineLower, {L"vssadmin delete shadows", L"wbadmin delete", L"wmic shadowcopy delete",
                                          L"bcdedit /set", L"reagentc /disable"});
  const auto hasProcessInjectionKeywords =
      ContainsAnyToken(commandLineLower, {L"createremotethread", L"writeprocessmemory", L"queueuserapc",
                                          L"rundll32", L"regsvr32", L"mshta"});
  const auto likelyBenignBulkIoProcess =
      IsLikelyBenignBulkIoProcess(processImageLower) || IsLikelyBenignBulkIoProcess(parentImageLower);
  const auto knownSafeLocation = IsKnownSafeLocation(path);

  if (hasEncodedPayload) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_ENCODED_COMMANDLINE",
                                     L"The invoking process used encoded command-line content.",
                                     L"TA0005", L"T1027", 34});
  }

  if (hasDownloadCradle) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_DOWNLOAD_CRADLE",
                                     L"The invoking process used download cradle command-line patterns.",
                                     L"TA0011", L"T1105", 32});
  }

  if (hasDynamicExecution) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_DYNAMIC_EXECUTION",
                                     L"The invoking process used dynamic execution command-line patterns.",
                                     L"TA0002", L"T1059.001", 30});
  }

  if (hasRecoveryInhibition) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_RECOVERY_INHIBITION",
                                     L"The invoking process attempted recovery inhibition commands.",
                                     L"TA0040", L"T1490", 45});
  }

  if (hasProcessInjectionKeywords) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_PROCESS_INJECTION_CHAIN",
                                     L"The command-line included process-injection or proxy-execution patterns.",
                                     L"TA0005", L"T1055", 36});
  }

  if (hasDownloadCradle && hasDynamicExecution) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_STAGED_PAYLOAD_CHAIN",
                                     L"The command-line combined staging download and immediate execution behavior.",
                                     L"TA0002", L"T1204.002", 44});
  }

  if (LooksLikeDoubleExtensionLure(fileNameLower)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_DOUBLE_EXTENSION_LURE",
                                     L"The target file name resembles a deceptive double-extension lure.",
                                     L"TA0001", L"T1566", 40});
  }

  if (IsHighRiskPersistencePath(path)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_PERSISTENCE_PATH",
                                     L"The target path is associated with user startup persistence.",
                                     L"TA0003", L"T1547.001", 30});
  }

  if (IsScriptingHostImage(processImageLower) && highRiskFileType && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_SCRIPTING_HOST_CHAIN",
                                     L"A scripting host process attempted to launch high-risk content.",
                                     L"TA0002", L"T1059", 34});
  }

  if (IsLolbinImage(processImageLower) && highRiskFileType && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_LOLBIN_PROXY_CHAIN",
                                     L"A Windows LOLBin process attempted to proxy high-risk content execution.",
                                     L"TA0005", L"T1218", 38});
  }

  if ((IsOfficeOrMailImage(parentImageLower) || IsBrowserImage(parentImageLower)) && highRiskFileType &&
      userControlledPath && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_PARENT_CHILD_LURE_CHAIN",
                                     L"High-risk content was launched from Office, mail, or browser parent context.",
                                     L"TA0002", L"T1204.002", 42});
  }

  if (IsTrustedInstallerImage(processImageLower) && (extension == L".msi" || extension == L".exe") && !hasEncodedPayload &&
      !hasDownloadCradle && !hasDynamicExecution) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_TRUSTED_INSTALLER_CONTEXT",
                                     L"Execution context matches a trusted installer workflow.",
                                     L"TA0000", L"T0000", -24});
  }

  if (likelyBenignBulkIoProcess && IsWriteLikeOperation(operation) && userControlledPath && !hasRecoveryInhibition &&
      !hasDynamicExecution && !hasProcessInjectionKeywords) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_BENIGN_BULK_IO_CONTEXT",
                                     L"Execution context resembles trusted backup, sync, or migration activity.",
                                     L"TA0000", L"T0000", -32});
  }

  if (!executeLike && likelyBenignBulkIoProcess && !hasRecoveryInhibition && !hasDynamicExecution &&
      !hasProcessInjectionKeywords) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_NON_EXECUTE_BENIGN_CONTEXT",
                                     L"Fenrir reduced non-execute confidence for a likely benign bulk-I/O process.",
                                     L"TA0000", L"T0000", -26});
  }

  if (!executeLike && knownSafeLocation && !hasRecoveryInhibition && !hasDynamicExecution &&
      !hasProcessInjectionKeywords && !LooksLikeDoubleExtensionLure(fileNameLower)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_SAFE_LOCATION_DAMPENING",
                                     L"Fenrir reduced confidence because the target resides in a hardened system/application path.",
                                     L"TA0000", L"T0000", -22});
  }
}

void ApplyRealtimeHitsToFinding(ScanFinding& finding, const std::vector<RealtimeHit>& hits,
                                const RealtimeFileOperation operation, const PolicySnapshot& policy,
                                const bool allowQuarantine) {
  if (hits.empty()) {
    return;
  }

  const auto topHit = std::max_element(hits.begin(), hits.end(),
                                       [](const auto& left, const auto& right) { return left.score < right.score; });
  const auto totalScore = std::clamp(ScoreRealtimeHits(hits), 0, 99);
  const auto executeLike = IsExecuteLikeOperation(operation);
  const auto blockThreshold = static_cast<int>(
      std::clamp(executeLike ? policy.realtimeExecuteBlockThreshold : policy.realtimeNonExecuteBlockThreshold,
                 static_cast<std::uint32_t>(1), static_cast<std::uint32_t>(99)));
  const auto quarantineThreshold = static_cast<int>(
      std::clamp(policy.realtimeQuarantineThreshold, static_cast<std::uint32_t>(blockThreshold + 1),
                 static_cast<std::uint32_t>(99)));
    const auto nonExecuteObserveOnlyLowConfidence =
      policy.realtimeObserveOnlyForNonExecute && !executeLike && totalScore < blockThreshold;

  finding.verdict.confidence = std::max<std::uint32_t>(finding.verdict.confidence, static_cast<std::uint32_t>(totalScore));
  if (topHit != hits.end() && !topHit->tacticId.empty() && topHit->tacticId != L"TA0000") {
    finding.verdict.tacticId = topHit->tacticId;
  }
  if (topHit != hits.end() && !topHit->techniqueId.empty() && topHit->techniqueId != L"T0000") {
    finding.verdict.techniqueId = topHit->techniqueId;
  }

  for (const auto& hit : hits) {
    finding.verdict.reasons.push_back({hit.code, hit.message});
  }

  if (finding.verdict.disposition == VerdictDisposition::Allow) {
    if (totalScore >= quarantineThreshold) {
      finding.verdict.disposition = allowQuarantine ? VerdictDisposition::Quarantine : VerdictDisposition::Block;
    } else if (totalScore >= blockThreshold) {
      finding.verdict.disposition = VerdictDisposition::Block;
    } else if (nonExecuteObserveOnlyLowConfidence) {
      finding.verdict.reasons.push_back({L"REALTIME_NON_EXECUTE_LOW_CONFIDENCE_OBSERVED",
                                         L"Fenrir kept non-execute interception in observe mode because confidence stayed below the block threshold."});
    }
  } else if (finding.verdict.disposition == VerdictDisposition::Block && allowQuarantine &&
             totalScore >= quarantineThreshold) {
    finding.verdict.disposition = VerdictDisposition::Quarantine;
  }
}

struct BehaviorHistoryEntry {
  std::chrono::steady_clock::time_point observedAt{};
  std::wstring fingerprint;
  std::uint32_t signals{0};
};

struct BehaviorCorrelationSnapshot {
  std::uint32_t historicalSignals{0};
  std::size_t recentSignalEvents{0};
};

constexpr std::uint32_t kSignalDownload = 1u << 0;
constexpr std::uint32_t kSignalEncoded = 1u << 1;
constexpr std::uint32_t kSignalDynamicExecution = 1u << 2;
constexpr std::uint32_t kSignalScriptHost = 1u << 3;
constexpr std::uint32_t kSignalLolbin = 1u << 4;
constexpr std::uint32_t kSignalPersistence = 1u << 5;
constexpr std::uint32_t kSignalRecoveryInhibition = 1u << 6;
constexpr std::uint32_t kSignalUserPathExecutable = 1u << 7;
constexpr std::uint32_t kSignalLure = 1u << 8;
constexpr std::uint32_t kSignalInjection = 1u << 9;

constexpr auto kBehaviorHistoryWindow = std::chrono::minutes(6);
constexpr auto kBehaviorBurstWindow = std::chrono::minutes(2);
constexpr std::size_t kBehaviorHistoryMaxEntries = 2048;

std::mutex gBehaviorHistoryMutex;
std::deque<BehaviorHistoryEntry> gBehaviorHistory;

void PruneBehaviorHistoryLocked(const std::chrono::steady_clock::time_point now) {
  while (!gBehaviorHistory.empty() && (now - gBehaviorHistory.front().observedAt) > kBehaviorHistoryWindow) {
    gBehaviorHistory.pop_front();
  }

  while (gBehaviorHistory.size() > kBehaviorHistoryMaxEntries) {
    gBehaviorHistory.pop_front();
  }
}

std::wstring BuildBehaviorFingerprint(const RealtimeFileScanRequest& request, const std::filesystem::path& path) {
  const auto processImage = ToLowerCopy(SafeCopy(request.processImage));
  const auto parentImage = ToLowerCopy(SafeCopy(request.parentImage));
  const auto userSid = ToLowerCopy(SafeCopy(request.userSid));
  const auto correlationId = ToLowerCopy(SafeCopy(request.correlationId));
  const auto directory = ToLowerCopy(path.parent_path().wstring());

  if (processImage.empty() && parentImage.empty() && userSid.empty()) {
    if (!correlationId.empty()) {
      return L"correlation:" + correlationId;
    }
    if (!directory.empty()) {
      return L"path:" + directory;
    }
    return L"global";
  }

  return processImage + L"|" + parentImage + L"|" + userSid;
}

struct RansomwareWriteHistoryEntry {
  std::chrono::steady_clock::time_point observedAt{};
  std::wstring fingerprint;
  std::wstring directory;
  std::wstring extension;
  bool userControlled{false};
  bool userDataExtension{false};
  bool suspiciousEncryptedExtension{false};
};

struct RansomwareWriteBurstSnapshot {
  std::size_t writeEvents{0};
  std::size_t userDataWrites{0};
  std::size_t suspiciousExtensionWrites{0};
  std::size_t uniqueDirectories{0};
  std::size_t uniqueExtensions{0};
};

constexpr auto kRansomwareWriteHistoryWindow = std::chrono::minutes(5);
constexpr auto kRansomwareWriteBurstWindow = std::chrono::seconds(30);
constexpr std::size_t kRansomwareWriteHistoryMaxEntries = 8192;

std::mutex gRansomwareWriteHistoryMutex;
std::deque<RansomwareWriteHistoryEntry> gRansomwareWriteHistory;

void PruneRansomwareWriteHistoryLocked(const std::chrono::steady_clock::time_point now) {
  while (!gRansomwareWriteHistory.empty() &&
         (now - gRansomwareWriteHistory.front().observedAt) > kRansomwareWriteHistoryWindow) {
    gRansomwareWriteHistory.pop_front();
  }

  while (gRansomwareWriteHistory.size() > kRansomwareWriteHistoryMaxEntries) {
    gRansomwareWriteHistory.pop_front();
  }
}

std::size_t CountUniqueValues(std::vector<std::wstring> values) {
  if (values.empty()) {
    return 0;
  }

  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
  return values.size();
}

RansomwareWriteBurstSnapshot ObserveRansomwareWriteBurst(const RealtimeFileScanRequest& request,
                                                         const std::filesystem::path& path,
                                                         const RealtimeFileOperation operation) {
  RansomwareWriteBurstSnapshot snapshot{};
  if (!IsWriteLikeOperation(operation) || path.empty()) {
    return snapshot;
  }

  const auto fingerprint = BuildBehaviorFingerprint(request, path);
  if (fingerprint.empty()) {
    return snapshot;
  }

  const auto now = std::chrono::steady_clock::now();
  const auto extension = ToLowerCopy(path.extension().wstring());
  const auto userControlledPath = IsUserControlledPath(path);

  std::vector<std::wstring> burstDirectories;
  std::vector<std::wstring> burstExtensions;

  {
    const std::scoped_lock lock(gRansomwareWriteHistoryMutex);
    PruneRansomwareWriteHistoryLocked(now);

    gRansomwareWriteHistory.push_back(RansomwareWriteHistoryEntry{
        .observedAt = now,
        .fingerprint = fingerprint,
        .directory = ToLowerCopy(path.parent_path().wstring()),
        .extension = extension,
        .userControlled = userControlledPath,
        .userDataExtension = IsUserDataExtension(extension),
        .suspiciousEncryptedExtension = IsSuspiciousEncryptedExtension(extension)});

    PruneRansomwareWriteHistoryLocked(now);

    for (const auto& entry : gRansomwareWriteHistory) {
      if (entry.fingerprint != fingerprint || !entry.userControlled ||
          (now - entry.observedAt) > kRansomwareWriteBurstWindow) {
        continue;
      }

      ++snapshot.writeEvents;
      if (entry.userDataExtension) {
        ++snapshot.userDataWrites;
      }
      if (entry.suspiciousEncryptedExtension) {
        ++snapshot.suspiciousExtensionWrites;
      }
      if (!entry.directory.empty()) {
        burstDirectories.push_back(entry.directory);
      }
      if (!entry.extension.empty()) {
        burstExtensions.push_back(entry.extension);
      }
    }
  }

  snapshot.uniqueDirectories = CountUniqueValues(std::move(burstDirectories));
  snapshot.uniqueExtensions = CountUniqueValues(std::move(burstExtensions));
  return snapshot;
}

std::wstring BuildBehaviorFingerprintFromEvent(const EventEnvelope& event) {
  const auto processImage = ToLowerCopy(event.process.imagePath);
  const auto parentImage = ToLowerCopy(event.process.parentImagePath);
  const auto userSid = ToLowerCopy(event.process.userSid);
  const auto correlationId = ToLowerCopy(event.correlationId);
  const auto targetPath = ToLowerCopy(event.targetPath);

  if (processImage.empty() && parentImage.empty() && userSid.empty()) {
    if (!correlationId.empty()) {
      return L"correlation:" + correlationId;
    }
    if (!targetPath.empty()) {
      return L"path:" + targetPath;
    }
    return L"global";
  }

  return processImage + L"|" + parentImage + L"|" + userSid;
}

std::uint32_t DeriveBehaviorSignals(const ScanFinding& finding, const RealtimeFileScanRequest& request,
                                    const RealtimeFileOperation operation) {
  std::uint32_t signals = 0;
  const auto extension = ToLowerCopy(finding.path.extension().wstring());
  const auto executeLike = IsExecuteLikeOperation(operation);
  const auto commandLineLower = ToLowerCopy(SafeCopy(request.commandLine));

  for (const auto& reason : finding.verdict.reasons) {
    const auto codeLower = ToLowerCopy(reason.code);
    if (ContainsAnyToken(codeLower, {L"download_cradle", L"pe_download_and_execute"})) {
      signals |= kSignalDownload;
    }
    if (ContainsAnyToken(codeLower, {L"encoded_payload", L"encoded_commandline", L"long_base64_blob", L"script_obfuscation"})) {
      signals |= kSignalEncoded;
    }
    if (ContainsAnyToken(codeLower, {L"dynamic_execution"})) {
      signals |= kSignalDynamicExecution;
    }
    if (ContainsAnyToken(codeLower, {L"script_host_abuse", L"scripting_host_chain", L"script_intercept"})) {
      signals |= kSignalScriptHost;
    }
    if (ContainsAnyToken(codeLower, {L"lolbin", L"lnk_proxy_execution"})) {
      signals |= kSignalLolbin;
    }
    if (ContainsAnyToken(codeLower, {L"run_key_persistence", L"scheduled_task_persistence", L"service_persistence",
                                     L"persistence_path"})) {
      signals |= kSignalPersistence;
    }
    if (ContainsAnyToken(codeLower, {L"recovery_inhibition", L"ransom_note_artifact", L"encrypted_impact_artifact"})) {
      signals |= kSignalRecoveryInhibition;
    }
    if (ContainsAnyToken(codeLower, {L"user_path_unsigned_executable", L"user_path_executable", L"executable_drop"})) {
      signals |= kSignalUserPathExecutable;
    }
    if (ContainsAnyToken(codeLower, {L"double_extension_lure", L"archive_double_extension", L"container_lure"})) {
      signals |= kSignalLure;
    }
    if (ContainsAnyToken(codeLower, {L"process_injection"})) {
      signals |= kSignalInjection;
    }
  }

  if (IsExecutableExtension(extension) && executeLike && IsUserControlledPath(finding.path)) {
    signals |= kSignalUserPathExecutable;
  }
  if (LooksLikeDoubleExtensionLure(ToLowerCopy(finding.path.filename().wstring()))) {
    signals |= kSignalLure;
  }
  if (IsHighRiskPersistencePath(finding.path)) {
    signals |= kSignalPersistence;
  }

  if (ContainsAnyToken(commandLineLower, {L"downloadstring", L"downloadfile", L"invoke-webrequest", L"invoke-restmethod",
                                          L"start-bitstransfer", L"iwr "})) {
    signals |= kSignalDownload;
  }
  if (ContainsAnyToken(commandLineLower, {L"-enc ", L"-encodedcommand", L"frombase64string"})) {
    signals |= kSignalEncoded;
  }
  if (ContainsAnyToken(commandLineLower, {L"invoke-expression", L" iex", L"iex("})) {
    signals |= kSignalDynamicExecution;
  }
  if (ContainsAnyToken(commandLineLower, {L"vssadmin delete shadows", L"wbadmin delete", L"wmic shadowcopy delete",
                                          L"bcdedit /set", L"reagentc /disable"})) {
    signals |= kSignalRecoveryInhibition;
  }
  if (ContainsAnyToken(commandLineLower, {L"createremotethread", L"writeprocessmemory", L"queueuserapc"})) {
    signals |= kSignalInjection;
  }

  return signals;
}

std::uint32_t DeriveBehaviorSignalsFromEvent(const EventEnvelope& event) {
  std::uint32_t signals = 0;

  const auto processImageLower = ToLowerCopy(event.process.imagePath);
  const auto parentImageLower = ToLowerCopy(event.process.parentImagePath);
  const auto commandLineLower = ToLowerCopy(event.process.commandLine);
  const auto targetLower = ToLowerCopy(event.targetPath);
  const std::filesystem::path targetPath(event.targetPath);
  const auto extension = ToLowerCopy(targetPath.extension().wstring());
  const auto executeLike =
      event.kind == EventKind::FileExecute || event.kind == EventKind::ProcessStart || event.kind == EventKind::ScriptScan;

  if (IsScriptingHostImage(processImageLower) || IsScriptingHostImage(parentImageLower)) {
    signals |= kSignalScriptHost;
  }
  if (IsLolbinImage(processImageLower) || IsLolbinImage(parentImageLower)) {
    signals |= kSignalLolbin;
  }

  if (ContainsAnyToken(commandLineLower, {L"downloadstring", L"downloadfile", L"invoke-webrequest", L"invoke-restmethod",
                                          L"start-bitstransfer", L"iwr ", L"curl ", L"bitsadmin"})) {
    signals |= kSignalDownload;
  }
  if (ContainsAnyToken(commandLineLower, {L"-enc ", L"-encodedcommand", L"frombase64string"})) {
    signals |= kSignalEncoded;
  }
  if (ContainsAnyToken(commandLineLower, {L"invoke-expression", L" iex", L"iex("})) {
    signals |= kSignalDynamicExecution;
  }
  if (ContainsAnyToken(commandLineLower, {L"vssadmin delete shadows", L"wbadmin delete", L"wmic shadowcopy delete",
                                          L"bcdedit /set", L"reagentc /disable"})) {
    signals |= kSignalRecoveryInhibition;
  }
  if (ContainsAnyToken(commandLineLower, {L"createremotethread", L"writeprocessmemory", L"queueuserapc"})) {
    signals |= kSignalInjection;
  }

  if (!event.targetPath.empty()) {
    const auto userControlledTarget = IsUserControlledPath(targetPath);
    if (IsExecutableExtension(extension) && userControlledTarget && executeLike) {
      signals |= kSignalUserPathExecutable;
    }
    if (LooksLikeDoubleExtensionLure(ToLowerCopy(targetPath.filename().wstring()))) {
      signals |= kSignalLure;
    }
    if (IsHighRiskPersistencePath(targetPath)) {
      signals |= kSignalPersistence;
    }
    if (IsScriptExtension(extension) && executeLike) {
      signals |= kSignalScriptHost;
    }
  }

  if (event.kind == EventKind::ProcessStart &&
      (IsOfficeOrMailImage(parentImageLower) || IsBrowserImage(parentImageLower)) &&
      IsExecutableExtension(extension) && IsUserControlledPath(targetPath)) {
    signals |= (kSignalUserPathExecutable | kSignalLure);
  }

  if (event.kind == EventKind::NetworkConnect &&
      (IsScriptingHostImage(processImageLower) || IsLolbinImage(processImageLower) || IsBrowserImage(processImageLower))) {
    signals |= kSignalDownload;
    if (ContainsAnyToken(targetLower, {L".onion", L":4444", L":8080", L":8443"})) {
      signals |= kSignalDynamicExecution;
    }
  }

  return signals;
}

BehaviorCorrelationSnapshot QueryBehaviorCorrelation(const std::wstring& fingerprint,
                                                     const std::chrono::steady_clock::time_point now) {
  BehaviorCorrelationSnapshot snapshot{};
  if (fingerprint.empty()) {
    return snapshot;
  }

  for (const auto& entry : gBehaviorHistory) {
    if (entry.fingerprint != fingerprint) {
      continue;
    }

    snapshot.historicalSignals |= entry.signals;
    if (entry.signals != 0 && (now - entry.observedAt) <= kBehaviorBurstWindow) {
      ++snapshot.recentSignalEvents;
    }
  }

  return snapshot;
}

std::vector<RealtimeHit> BuildBehaviorCorrelationHits(const std::uint32_t currentSignals,
                                                      const BehaviorCorrelationSnapshot& snapshot,
                                                      const RealtimeFileOperation operation) {
  std::vector<RealtimeHit> hits;
  if (currentSignals == 0) {
    return hits;
  }

  const auto historical = snapshot.historicalSignals;
  const auto executeLike = IsExecuteLikeOperation(operation);

  const auto hasCurrentStager = (currentSignals & (kSignalUserPathExecutable | kSignalLure | kSignalScriptHost)) != 0;
  const auto hasHistoricalInitialAccess = (historical & (kSignalDownload | kSignalEncoded | kSignalDynamicExecution)) != 0;
  if (hasCurrentStager && hasHistoricalInitialAccess && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_STAGED_PAYLOAD",
                                     L"Fenrir correlated this event with earlier staging behavior from the same process lineage.",
                                     L"TA0002", L"T1204.002", 46});
  }

  const auto hasCurrentPersistence = (currentSignals & kSignalPersistence) != 0;
  const auto hasHistoricalExecutionProxy = (historical & (kSignalScriptHost | kSignalLolbin | kSignalDownload)) != 0;
  if (hasCurrentPersistence && hasHistoricalExecutionProxy) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_PERSISTENCE",
                                     L"Fenrir correlated persistence behavior with earlier execution-proxy activity.",
                                     L"TA0003", L"T1547.001", 42});
  }

  const auto hasCurrentImpact = (currentSignals & kSignalRecoveryInhibition) != 0;
  const auto hasHistoricalPreImpact =
      (historical & (kSignalUserPathExecutable | kSignalDownload | kSignalPersistence | kSignalScriptHost)) != 0;
  if (hasCurrentImpact && hasHistoricalPreImpact) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_RANSOMWARE_IMPACT",
                                     L"Fenrir correlated recovery-inhibition behavior with prior compromise staging signals.",
                                     L"TA0040", L"T1490", 58});
  }

  const auto hasCurrentInjection = (currentSignals & kSignalInjection) != 0;
  const auto hasHistoricalStaging = (historical & (kSignalDownload | kSignalEncoded | kSignalDynamicExecution)) != 0;
  if (hasCurrentInjection && hasHistoricalStaging) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_INJECTION_STAGE",
                                     L"Fenrir correlated process-injection behavior with earlier staged payload activity.",
                                     L"TA0005", L"T1055", 44});
  }

  if (snapshot.recentSignalEvents >= 2 && executeLike) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CHAIN_BURST_ACTIVITY",
                                     L"Fenrir observed multiple suspicious events from this process lineage in a short window.",
                                     L"TA0005", L"T1204.002", 36});
  }

  return hits;
}

void AddRansomwareBurstRealtimeHits(std::vector<RealtimeHit>& hits, const std::filesystem::path& path,
                                    const RealtimeFileOperation operation, const RealtimeFileScanRequest& request,
                                    const std::wstring& processImageLower, const std::wstring& parentImageLower,
                                    const std::wstring& commandLineLower) {
  const auto snapshot = ObserveRansomwareWriteBurst(request, path, operation);
  if (snapshot.writeEvents == 0) {
    return;
  }

  const auto hasRecoveryInhibition =
      ContainsAnyToken(commandLineLower, {L"vssadmin delete shadows", L"wbadmin delete", L"wmic shadowcopy delete",
                                          L"bcdedit /set", L"reagentc /disable"});
  const auto hasCryptoBehavior =
      ContainsAnyToken(commandLineLower, {L"aesmanaged", L"rijndaelmanaged", L"cryptostream", L"createencryptor",
                                          L"transformfinalblock", L"encryptor"});
  const auto likelyBenignBulkIoProcess =
      IsLikelyBenignBulkIoProcess(processImageLower) || IsLikelyBenignBulkIoProcess(parentImageLower);

  if (snapshot.userDataWrites >= 24 && snapshot.uniqueDirectories >= 4) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_RANSOMWARE_WRITE_BURST",
                                     L"Rapid multi-directory write churn across user data resembles ransomware pre-encryption behavior.",
                                     L"TA0040", L"T1486", 56});
  }

  if (snapshot.suspiciousExtensionWrites >= 5 && snapshot.uniqueDirectories >= 3) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_RANSOMWARE_EXTENSION_BURST",
                                     L"Repeated writes with suspicious encrypted extensions indicate destructive encryption activity.",
                                     L"TA0040", L"T1486", 62});
  }

  if (snapshot.writeEvents >= 30 && snapshot.uniqueDirectories >= 4 && snapshot.uniqueExtensions >= 5) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_RANSOMWARE_CROSS_DIRECTORY_CHURN",
                                     L"High-rate cross-directory write churn indicates potential mass-encryption behavior.",
                                     L"TA0040", L"T1486", 48});
  }

  if ((snapshot.userDataWrites >= 12 && hasRecoveryInhibition) ||
      (snapshot.userDataWrites >= 15 && hasCryptoBehavior)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_RANSOMWARE_PREIMPACT_CHAIN",
                                     L"Write-burst behavior combined with recovery inhibition or crypto primitives signals ransomware impact staging.",
                                     L"TA0040", L"T1490", 58});
  }

  if (likelyBenignBulkIoProcess && snapshot.userDataWrites >= 20 && !hasRecoveryInhibition && !hasCryptoBehavior) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_BENIGN_BULK_IO_DAMPENING",
                                     L"Fenrir reduced ransomware burst confidence because process context resembles known backup/sync workflows.",
                                     L"TA0000", L"T0000", -40});
  }
}

TelemetryRecord BuildBehaviorObservationTelemetry(const EventEnvelope& event, const std::wstring& deviceId,
                                                  const std::uint32_t currentSignals,
                                                  const BehaviorCorrelationSnapshot& snapshot,
                                                  const std::vector<RealtimeHit>& chainHits) {
  std::wstring subject = event.targetPath;
  if (subject.empty()) {
    subject = event.process.imagePath;
  }
  if (subject.empty()) {
    subject = L"(unknown target)";
  }

  std::wstring summary = L"Fenrir correlated runtime behavior signals for ";
  summary += subject;
  summary += L".";

  std::wstring payload = L"{\"deviceId\":\"";
  payload += Utf8ToWide(EscapeJsonString(deviceId));
  payload += L"\",\"correlationId\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.correlationId));
  payload += L"\",\"kind\":\"";
  payload += EventKindToString(event.kind);
  payload += L"\",\"targetPath\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.targetPath));
  payload += L"\",\"processImage\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.process.imagePath));
  payload += L"\",\"parentImage\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.process.parentImagePath));
  payload += L"\",\"userSid\":\"";
  payload += Utf8ToWide(EscapeJsonString(event.process.userSid));
  payload += L"\",\"signalMask\":";
  payload += std::to_wstring(currentSignals);
  payload += L",\"historicalSignalMask\":";
  payload += std::to_wstring(snapshot.historicalSignals);
  payload += L",\"recentSignalEvents\":";
  payload += std::to_wstring(snapshot.recentSignalEvents);
  payload += L",\"reasonCodes\":[";
  for (std::size_t index = 0; index < chainHits.size(); ++index) {
    if (index > 0) {
      payload += L",";
    }
    payload += L"\"";
    payload += Utf8ToWide(EscapeJsonString(chainHits[index].code));
    payload += L"\"";
  }
  payload += L"]}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"realtime.behavior.chain",
      .source = L"realtime-protection",
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

bool ApplyBehaviorChainCorrelation(const RealtimeFileScanRequest& request, const RealtimeFileOperation operation,
                                   const PolicySnapshot& policy, ScanFinding& finding) {
  const auto fingerprint = BuildBehaviorFingerprint(request, finding.path);
  const auto now = std::chrono::steady_clock::now();
  const auto currentSignals = DeriveBehaviorSignals(finding, request, operation);

  BehaviorCorrelationSnapshot snapshot{};
  {
    const std::scoped_lock lock(gBehaviorHistoryMutex);
    PruneBehaviorHistoryLocked(now);
    snapshot = QueryBehaviorCorrelation(fingerprint, now);
    if (!fingerprint.empty()) {
      gBehaviorHistory.push_back(BehaviorHistoryEntry{
          .observedAt = now,
          .fingerprint = fingerprint,
          .signals = currentSignals});
      PruneBehaviorHistoryLocked(now);
    }
  }

  const auto chainHits = BuildBehaviorCorrelationHits(currentSignals, snapshot, operation);
  if (chainHits.empty()) {
    return false;
  }

  ApplyRealtimeHitsToFinding(finding, chainHits, operation, policy, policy.quarantineOnMalicious);
  finding.verdict.reasons.push_back(
      {L"REALTIME_CHAIN_CORRELATED",
       L"Fenrir correlated this event with recent behavior from the same process lineage."});
  return true;
}

ScanFinding BuildRealtimeFinding(const std::filesystem::path& path, const RealtimeFileOperation operation,
                                 const RealtimeFileScanRequest& request, const PolicySnapshot& policy,
                                 const std::vector<std::filesystem::path>& excludedPaths) {
  const auto extension = ToLowerCopy(path.extension().wstring());
  const auto userControlledPath = IsUserControlledPath(path);
  const auto processImageLower = ToLowerCopy(SafeCopy(request.processImage));
  const auto parentImageLower = ToLowerCopy(SafeCopy(request.parentImage));
  const auto commandLineLower = ToLowerCopy(SafeCopy(request.commandLine));
  const auto originContext =
      BuildContentOriginContext(path, SafeCopy(request.processImage), SafeCopy(request.parentImage),
                                SafeCopy(request.commandLine), CurrentUtcTimestamp());

  if (const auto allowOverride = BuildAllowOverrideFinding(path, policy, excludedPaths); allowOverride.has_value()) {
    auto finding = *allowOverride;
    finding.originContext = originContext;
    return finding;
  }

  ScanFinding finding{
      .path = path,
      .sizeBytes = 0,
      .sha256 = {},
      .verdict = {},
      .remediationStatus = RemediationStatus::None,
      .quarantinedPath = {},
      .quarantineRecordId = {},
      .evidenceRecordId = {},
      .remediationError = {},
      .originContext = originContext};

  std::error_code error;
  if (std::filesystem::exists(path, error)) {
    error.clear();
    if (std::filesystem::is_regular_file(path, error)) {
      finding.sizeBytes = std::filesystem::file_size(path, error);
      try {
        finding.sha256 = ComputeFileSha256(path);
      } catch (...) {
        finding.verdict.reasons.push_back(
            {L"HASH_UNAVAILABLE", L"SHA-256 computation failed during real-time evaluation."});
      }

      if (const auto analyzedFinding = ScanFile(path, policy, excludedPaths, originContext); analyzedFinding.has_value()) {
        auto promoted = *analyzedFinding;
        if (promoted.verdict.disposition == VerdictDisposition::Block &&
            operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE) {
          promoted.verdict.confidence = std::min<std::uint32_t>(99, promoted.verdict.confidence + 5);
        }
        std::vector<RealtimeHit> contextualHits;
        AddContextualRealtimeHits(contextualHits, path, extension, operation, processImageLower, parentImageLower,
                                  commandLineLower, userControlledPath);
        ApplyRealtimeHitsToFinding(promoted, contextualHits, operation, policy, policy.quarantineOnMalicious);
        return promoted;
      }
    }
  }

  std::vector<RealtimeHit> hits;
  const auto executeLike = IsExecuteLikeOperation(operation);
  const auto highRiskFileType = IsExecutableExtension(extension) || IsScriptExtension(extension) ||
                                IsContainerExtension(extension) || extension == L".hta";

  if (IsExecutableExtension(extension) && userControlledPath) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_EXECUTABLE_DROP",
                                     L"Executable content in a user-controlled path was intercepted by real-time protection.",
                                     L"TA0002", L"T1204.002", executeLike ? 78 : 66});
  }

  if (extension == L".hta") {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_HTA_CONTENT",
                                     L"HTA content was intercepted before it could be proxied through MSHTA.",
                                     L"TA0005", L"T1218.005", executeLike ? 74 : 68});
  }

  if (IsScriptExtension(extension)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_SCRIPT_INTERCEPT",
                                     L"Script content was intercepted by real-time protection.",
                                     L"TA0002", extension == L".ps1" ? L"T1059.001" : L"T1059",
                                     executeLike ? (userControlledPath ? 70 : 58)
                                                 : (userControlledPath ? 62 : 44)});
  }

  if (IsContainerExtension(extension) && userControlledPath &&
      (operation == ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN ||
       operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE ||
       operation == ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME || executeLike)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_CONTAINER_LURE",
                                     L"User-writable lure or archive content was intercepted before staging could continue.",
                                     L"TA0002", extension == L".lnk" ? L"T1204.001" : L"T1204.002",
                                     executeLike ? 62 : 56});
  }

  if (operation == ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME &&
      (IsExecutableExtension(extension) || IsScriptExtension(extension) || extension == L".hta")) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_RENAME_TO_EXECUTABLE",
                                     L"Fenrir intercepted a rename operation that staged executable or script content.",
                                     L"TA0002", L"T1036", 68});
  }

  if (operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE && userControlledPath &&
      (IsExecutableExtension(extension) || IsScriptExtension(extension) ||
       IsContainerExtension(extension) || extension == L".hta")) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_HIGH_RISK_CREATE_STAGING",
                                     L"Fenrir intercepted high-risk create-time staging in a user-controlled path.",
                                     L"TA0002", L"T1204.002", 64});
  }

  if ((IsOfficeOrMailImage(parentImageLower) || IsBrowserImage(parentImageLower)) && userControlledPath &&
      (IsScriptExtension(extension) || IsContainerExtension(extension) || extension == L".hta") &&
      (operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE ||
       operation == ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME || executeLike)) {
    AddRealtimeHit(hits, RealtimeHit{L"REALTIME_PARENT_STAGE_CHAIN",
                                     L"Office, mail, or browser parent context attempted script or container staging in user space.",
                                     L"TA0002", L"T1204.002", 66});
  }

  AddContextualRealtimeHits(hits, path, extension, operation, processImageLower, parentImageLower, commandLineLower,
                            userControlledPath);
  AddRansomwareBurstRealtimeHits(hits, path, operation, request, processImageLower, parentImageLower,
                                 commandLineLower);

  const auto topHit = std::max_element(hits.begin(), hits.end(),
                                       [](const auto& left, const auto& right) { return left.score < right.score; });
  const auto score = std::clamp(ScoreRealtimeHits(hits), 0, 99);

  const auto blockThreshold = static_cast<int>(
      std::clamp(executeLike ? policy.realtimeExecuteBlockThreshold : policy.realtimeNonExecuteBlockThreshold,
                 static_cast<std::uint32_t>(1), static_cast<std::uint32_t>(99)));
  const auto quarantineThreshold = static_cast<int>(
      std::clamp(policy.realtimeQuarantineThreshold, static_cast<std::uint32_t>(blockThreshold + 1),
                 static_cast<std::uint32_t>(99)));
  const auto nonExecuteObserveOnly = policy.realtimeObserveOnlyForNonExecute && !executeLike;
  const auto archiveObserveAllow = policy.archiveObserveOnly && IsContainerExtension(extension) && !executeLike;

  if (score >= blockThreshold && !archiveObserveAllow) {
    finding.verdict.disposition = policy.quarantineOnMalicious && highRiskFileType && score >= quarantineThreshold
                                      ? VerdictDisposition::Quarantine
                                      : VerdictDisposition::Block;
    finding.verdict.confidence = static_cast<std::uint32_t>(score);
    finding.verdict.tacticId = topHit != hits.end() && !topHit->tacticId.empty() ? topHit->tacticId : L"TA0002";
    finding.verdict.techniqueId =
        topHit != hits.end() && !topHit->techniqueId.empty() ? topHit->techniqueId : L"T1204.002";
    for (const auto& hit : hits) {
      finding.verdict.reasons.push_back({hit.code, hit.message});
    }
    return finding;
  }

  finding.verdict.disposition = VerdictDisposition::Allow;
  finding.verdict.confidence = static_cast<std::uint32_t>(std::max(score, 5));
  if (topHit != hits.end() && topHit->score > 0 && !topHit->tacticId.empty()) {
    finding.verdict.tacticId = topHit->tacticId;
  }
  if (topHit != hits.end() && topHit->score > 0 && !topHit->techniqueId.empty()) {
    finding.verdict.techniqueId = topHit->techniqueId;
  }
  for (const auto& hit : hits) {
    if (hit.score > 0) {
      finding.verdict.reasons.push_back({hit.code, hit.message});
    }
  }
  if (archiveObserveAllow && score >= blockThreshold) {
    finding.verdict.reasons.push_back(
        {L"REALTIME_ARCHIVE_OBSERVE_ONLY", L"Archive mode is configured for observe-only handling at this confidence."});
  }
  if (nonExecuteObserveOnly && score < blockThreshold) {
    finding.verdict.reasons.push_back({L"REALTIME_NON_EXECUTE_LOW_CONFIDENCE_OBSERVED",
                                       L"Fenrir kept non-execute interception in observe mode because confidence stayed below the block threshold."});
  }
  finding.verdict.reasons.push_back({L"REALTIME_ALLOW", L"No blocking rule matched the intercepted file event."});
  return finding;
}

TelemetryRecord BuildRealtimeProtectionTelemetry(const ScanFinding& finding, const std::wstring& source,
                                                 const std::wstring& deviceId, const std::wstring& correlationId,
                                                 const RealtimeFileOperation operation,
                                                 const RealtimeResponseAction action,
                                                 const RealtimeFileScanRequest& request,
                                                 const bool contextEnriched) {
  const auto actionValue = action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ? L"block" : L"allow";
  const auto dispositionValue = VerdictDispositionToString(finding.verdict.disposition);
  const auto techniqueId = finding.verdict.techniqueId.empty() ? L"unknown" : finding.verdict.techniqueId;
  auto subject = finding.path.filename().wstring();
  if (subject.empty()) {
    subject = finding.path.wstring();
  }

  std::wstring summary = L"Real-time protection ";
  summary += actionValue;
  summary += L"ed ";
  summary += subject;
  summary += L" during ";
  summary += OperationToString(operation);
  summary += L".";

  std::wstring payload = L"{\"deviceId\":\"";
  payload += Utf8ToWide(EscapeJsonString(deviceId));
  payload += L"\",\"correlationId\":\"";
  payload += Utf8ToWide(EscapeJsonString(correlationId));
  payload += L"\",\"path\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.path.wstring()));
  payload += L"\",\"operation\":\"";
  payload += OperationToString(operation);
  payload += L"\",\"action\":\"";
  payload += actionValue;
  payload += L"\",\"disposition\":\"";
  payload += dispositionValue;
  payload += L"\",\"confidence\":";
  payload += std::to_wstring(finding.verdict.confidence);
  payload += L",\"tacticId\":\"";
  payload += finding.verdict.tacticId;
  payload += L"\",\"techniqueId\":\"";
  payload += techniqueId;
  payload += L"\",\"sha256\":\"";
  payload += finding.sha256;
  payload += L"\",\"quarantineRecordId\":\"";
  payload += finding.quarantineRecordId;
  payload += L"\",\"evidenceRecordId\":\"";
  payload += finding.evidenceRecordId;
  payload += L"\",\"remediationStatus\":\"";
  payload += RemediationStatusToString(finding.remediationStatus);
  payload += L"\",\"processId\":";
  payload += std::to_wstring(request.processId);
  payload += L",\"threadId\":";
  payload += std::to_wstring(request.threadId);
  payload += L",\"fileSizeBytes\":";
  payload += std::to_wstring(request.fileSizeBytes);
  payload += L",\"processImage\":\"";
  payload += Utf8ToWide(EscapeJsonString(SafeCopy(request.processImage)));
  payload += L"\",\"parentImage\":\"";
  payload += Utf8ToWide(EscapeJsonString(SafeCopy(request.parentImage)));
  payload += L"\",\"commandLine\":\"";
  payload += Utf8ToWide(EscapeJsonString(SafeCopy(request.commandLine)));
  payload += L"\",\"userSid\":\"";
  payload += Utf8ToWide(EscapeJsonString(SafeCopy(request.userSid)));
  payload += L"\",\"contextEnriched\":";
  payload += contextEnriched ? L"true" : L"false";
  payload += L",\"alertTitle\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.alertTitle));
  payload += L"\",\"contextType\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.originContext.channel));
  payload += L"\",\"originReference\":\"";
  payload += Utf8ToWide(EscapeJsonString(
      !finding.originContext.sourceDomain.empty() ? finding.originContext.sourceDomain : finding.originContext.navigationType));
  payload += L"\",\"reasonCodes\":[";
  for (std::size_t index = 0; index < finding.verdict.reasons.size(); ++index) {
    if (index != 0) {
      payload += L",";
    }
    payload += L"\"";
    payload += Utf8ToWide(EscapeJsonString(finding.verdict.reasons[index].code));
    payload += L"\"";
  }
  payload += L"]";
  payload += L"}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"realtime.protection.action",
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

}  // namespace

RealtimeProtectionBroker::RealtimeProtectionBroker(AgentConfig config) : config_(std::move(config)) {
  stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

RealtimeProtectionBroker::~RealtimeProtectionBroker() {
  Stop();
  if (stopEvent_ != nullptr) {
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
  }
}

void RealtimeProtectionBroker::Start() {
  if (workerThread_ != nullptr || stopEvent_ == nullptr) {
    return;
  }

  ResetEvent(stopEvent_);
  workerActive_.store(false);
  portConnected_.store(false);
  workerThread_ = CreateThread(nullptr, 0, ThreadEntry, this, 0, nullptr);
  if (workerThread_ == nullptr) {
    QueueBrokerStateEvent(L"realtime.broker.failed",
                          L"The real-time protection broker could not start its communication worker.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
  }
}

void RealtimeProtectionBroker::Stop() {
  if (stopEvent_ != nullptr) {
    SetEvent(stopEvent_);
  }

  if (workerThread_ != nullptr) {
    WaitForSingleObject(workerThread_, 5'000);
    CloseHandle(workerThread_);
    workerThread_ = nullptr;
  }

  portConnected_.store(false);
  workerActive_.store(false);
}

void RealtimeProtectionBroker::SetPolicy(const PolicySnapshot& policy) {
  const std::scoped_lock lock(stateMutex_);
  policy_ = policy;
}

void RealtimeProtectionBroker::SetDeviceId(std::wstring deviceId) {
  const std::scoped_lock lock(stateMutex_);
  deviceId_ = std::move(deviceId);
}

bool RealtimeProtectionBroker::IsRealtimeCoverageHealthy() const {
  return workerActive_.load() && portConnected_.load();
}

RealtimeInspectionOutcome RealtimeProtectionBroker::InspectFile(const RealtimeFileScanRequest& request) {
  PolicySnapshot policy;
  std::wstring deviceId;
  {
    const std::scoped_lock lock(stateMutex_);
    policy = policy_;
    deviceId = deviceId_;
  }

  const auto effectiveRequest = EnrichRequestProcessContext(request);
  const auto operation = static_cast<RealtimeFileOperation>(request.operation);
  const std::filesystem::path targetPath(SafeCopy(request.path));
  const auto observedOrigin =
      BuildContentOriginContext(targetPath, SafeCopy(effectiveRequest.request.processImage),
                                SafeCopy(effectiveRequest.request.parentImage),
                                SafeCopy(effectiveRequest.request.commandLine), CurrentUtcTimestamp());

  if (!policy.realtimeProtectionEnabled) {
    return RealtimeInspectionOutcome{
        .action = ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW,
        .detection = false,
        .finding =
            ScanFinding{
                .path = targetPath,
                .verdict =
                    ScanVerdict{
                        .disposition = VerdictDisposition::Allow,
                        .confidence = 0,
                        .tacticId = L"",
                        .techniqueId = L"",
                        .reasons = {{L"REALTIME_DISABLED", L"Real-time protection is disabled by policy."}}}}};
  }

  if (!targetPath.empty() &&
      (observedOrigin.browserOriginated || observedOrigin.attachmentOriginated || observedOrigin.downloadOriginated)) {
    RuntimeDatabase(config_.runtimeDatabasePath)
        .UpsertDownloadContextRecord(DownloadContextRecord{
            .targetPath = targetPath,
            .observedAt = CurrentUtcTimestamp(),
            .channel = observedOrigin.channel,
            .browserFamily = observedOrigin.browserFamily,
            .sourceApplication = observedOrigin.sourceApplication,
            .parentApplication = observedOrigin.parentApplication,
            .sourceDomain = observedOrigin.sourceDomain,
            .sourceUrl = observedOrigin.sourceUrl,
            .navigationType = observedOrigin.navigationType,
            .reputationAtObservation = observedOrigin.browserOriginated ? L"browser-context" : L"email-context",
            .contextJson = SerializeContentOriginContext(observedOrigin)});
  }

  auto finding =
      BuildRealtimeFinding(targetPath, operation, effectiveRequest.request, policy, config_.scanExcludedPaths);
  const auto correlatedChain = ApplyBehaviorChainCorrelation(effectiveRequest.request, operation, policy, finding);
  if (finding.verdict.disposition == VerdictDisposition::Allow) {
    const auto allowTelemetryThreshold =
        std::clamp(policy.realtimeObserveTelemetryThreshold, static_cast<std::uint32_t>(1),
                   static_cast<std::uint32_t>(99));
    const auto elevatedAllowSignal =
        correlatedChain ||
        finding.verdict.confidence >= allowTelemetryThreshold ||
        std::any_of(finding.verdict.reasons.begin(), finding.verdict.reasons.end(), [](const auto& reason) {
          return reason.code != L"REALTIME_ALLOW";
        });
    if (elevatedAllowSignal) {
      QueueTelemetry(BuildRealtimeProtectionTelemetry(finding, L"realtime-protection", deviceId,
                                                     SafeCopy(effectiveRequest.request.correlationId), operation,
                                                     ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW,
                                                     effectiveRequest.request, effectiveRequest.contextEnriched));
    }

    return RealtimeInspectionOutcome{
        .action = ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW,
        .detection = false,
        .finding = std::move(finding)};
  }

  const auto immediateContainmentOperation =
      operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
      operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP ||
      IsHighRiskCreateOperation(effectiveRequest.request, finding, policy);

  int preQuarantineContainmentCount = 0;
  bool preQuarantineContainmentAttempted = false;
  if (!finding.path.empty() && immediateContainmentOperation && policy.terminateProcessTreeOnExecuteBlock) {
    preQuarantineContainmentAttempted = true;
    RemediationEngine remediationEngine(config_);
    const auto containment = remediationEngine.TerminateProcessesForRealtimeRequest(effectiveRequest.request, true);
    preQuarantineContainmentCount = containment.processesTerminated;
    if (containment.processesTerminated > 0) {
      finding.verdict.reasons.push_back(
          {L"PROCESS_TREE_TERMINATED_PRE_QUARANTINE",
           L"Fenrir terminated " + std::to_wstring(containment.processesTerminated) +
               L" process(es) immediately before quarantine to contain active execution."});
    } else if (!containment.errorMessage.empty()) {
      finding.verdict.reasons.push_back({L"PROCESS_TREE_TERMINATION_FAILED", containment.errorMessage});
    }
  }

  auto quarantineEligible = policy.quarantineOnMalicious && !finding.path.empty();
  if (immediateContainmentOperation && !policy.quarantineAfterProcessKill &&
      preQuarantineContainmentCount > 0) {
    quarantineEligible = false;
    finding.verdict.reasons.push_back(
        {L"QUARANTINE_DEFERRED_AFTER_KILL",
         L"Policy deferred quarantine because immediate process-tree termination already contained the execution path."});
  }

  if (quarantineEligible) {
    QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
    auto quarantineResult = quarantineStore.QuarantineFile(finding);
    if (!quarantineResult.success && (!preQuarantineContainmentAttempted || preQuarantineContainmentCount == 0)) {
      RemediationEngine remediationEngine(config_);
      const auto containment = remediationEngine.TerminateProcessesForRealtimeRequest(effectiveRequest.request, true);
      const auto retryContainmentCount = containment.processesTerminated;
      if (retryContainmentCount > 0) {
        finding.verdict.reasons.push_back(
            {L"PROCESS_TREE_TERMINATED_PRE_QUARANTINE_RETRY",
             L"Fenrir terminated " + std::to_wstring(retryContainmentCount) +
                 L" process(es) before retrying quarantine after initial quarantine failure."});
        quarantineResult = quarantineStore.QuarantineFile(finding);
      } else if (!containment.errorMessage.empty()) {
        finding.verdict.reasons.push_back({L"PROCESS_TREE_TERMINATION_FAILED", containment.errorMessage});
      }
    }

    if (quarantineResult.success) {
      finding.remediationStatus = RemediationStatus::Quarantined;
      finding.quarantineRecordId = quarantineResult.recordId;
      finding.quarantinedPath = quarantineResult.quarantinedPath;
      finding.verdict.reasons.push_back(
          {L"QUARANTINE_APPLIED", L"Fenrir moved the intercepted artifact into local quarantine."});
      if (!quarantineResult.localStatus.empty()) {
        finding.verdict.reasons.push_back(
            {L"QUARANTINE_STATUS", L"Quarantine status: " + quarantineResult.localStatus + L"."});
      }
      if (!quarantineResult.verificationDetail.empty()) {
        finding.verdict.reasons.push_back({L"QUARANTINE_VERIFIED", quarantineResult.verificationDetail});
      }
    } else {
      if (!quarantineResult.recordId.empty()) {
        finding.quarantineRecordId = quarantineResult.recordId;
      }
      if (!quarantineResult.quarantinedPath.empty()) {
        finding.quarantinedPath = quarantineResult.quarantinedPath;
      }
      finding.remediationStatus = RemediationStatus::Failed;
      finding.remediationError =
          quarantineResult.errorMessage.empty() ? L"Real-time quarantine failed during interception."
                                                : quarantineResult.errorMessage;
      if (!quarantineResult.localStatus.empty()) {
        finding.verdict.reasons.push_back(
            {L"QUARANTINE_STATUS", L"Quarantine status: " + quarantineResult.localStatus + L"."});
      }
      if (!quarantineResult.verificationDetail.empty()) {
        finding.verdict.reasons.push_back(
            {L"QUARANTINE_VERIFICATION_FAILED", quarantineResult.verificationDetail});
      }
      finding.verdict.reasons.push_back({L"QUARANTINE_FAILED", finding.remediationError});
    }
  }

  EvidenceRecorder evidenceRecorder(config_.evidenceRootPath, config_.runtimeDatabasePath);
  const auto evidence = evidenceRecorder.RecordScanFinding(finding, policy, L"realtime-protection");
  finding.evidenceRecordId = evidence.recordId;

  QueueTelemetry(BuildScanFindingTelemetry(finding, L"realtime-protection"));
  QueueTelemetry(BuildRealtimeProtectionTelemetry(finding, L"realtime-protection", deviceId,
                                                 SafeCopy(effectiveRequest.request.correlationId), operation,
                                                 ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK,
                                                 effectiveRequest.request, effectiveRequest.contextEnriched));

  return RealtimeInspectionOutcome{
      .action = ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK,
      .detection = true,
      .finding = std::move(finding)};
}

void RealtimeProtectionBroker::ObserveBehaviorEvent(const EventEnvelope& event) {
  const auto currentSignals = DeriveBehaviorSignalsFromEvent(event);
  if (currentSignals == 0) {
    return;
  }

  const auto fingerprint = BuildBehaviorFingerprintFromEvent(event);
  const auto operation = EventKindToRealtimeOperation(event.kind);
  const auto now = std::chrono::steady_clock::now();

  BehaviorCorrelationSnapshot snapshot{};
  {
    const std::scoped_lock lock(gBehaviorHistoryMutex);
    PruneBehaviorHistoryLocked(now);
    snapshot = QueryBehaviorCorrelation(fingerprint, now);
    if (!fingerprint.empty()) {
      gBehaviorHistory.push_back(BehaviorHistoryEntry{
          .observedAt = now,
          .fingerprint = fingerprint,
          .signals = currentSignals});
      PruneBehaviorHistoryLocked(now);
    }
  }

  const auto chainHits = BuildBehaviorCorrelationHits(currentSignals, snapshot, operation);
  if (chainHits.empty()) {
    return;
  }

  std::wstring deviceId;
  {
    const std::scoped_lock lock(stateMutex_);
    deviceId = deviceId_;
  }
  QueueTelemetry(BuildBehaviorObservationTelemetry(event, deviceId, currentSignals, snapshot, chainHits));
}

ScanVerdict RealtimeProtectionBroker::EvaluateEvent(const EventEnvelope& event) {
  RealtimeFileScanRequest request{};
  request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
  request.requestSize = sizeof(request);
  request.requestId = 0;
  request.operation = EventKindToRealtimeOperation(event.kind);
  request.parentProcessId = 0;
  request.desiredAccess = 0;
  request.createDisposition = 0;
  request.requestFlags = 0;
  request.signerTrustLevel = ANTIVIRUS_REALTIME_SIGNER_TRUST_UNKNOWN;
  request.pathRiskFlags = 0;

  if (event.kind == EventKind::ProcessStart || event.kind == EventKind::FileExecute ||
      event.kind == EventKind::ScriptScan) {
    request.requestFlags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_EXECUTE_INTENT;
  }
  if (event.kind == EventKind::FileWrite || event.kind == EventKind::FileCreate) {
    request.requestFlags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_WRITE_INTENT;
  }

  CopyWideField(request.correlationId, event.correlationId);
  CopyWideField(request.path, event.targetPath);
  CopyWideField(request.processImage, event.process.imagePath);
  CopyWideField(request.commandLine, event.process.commandLine);
  CopyWideField(request.parentImage, event.process.parentImagePath);
  CopyWideField(request.userSid, event.process.userSid);

  const auto outcome = InspectFile(request);
  return outcome.finding.verdict;
}

std::vector<TelemetryRecord> RealtimeProtectionBroker::DrainTelemetry() {
  const std::scoped_lock lock(telemetryMutex_);
  auto telemetry = pendingTelemetry_;
  pendingTelemetry_.clear();
  return telemetry;
}

DWORD WINAPI RealtimeProtectionBroker::ThreadEntry(LPVOID context) {
  auto* broker = reinterpret_cast<RealtimeProtectionBroker*>(context);
  broker->PumpLoop();
  return 0;
}

void RealtimeProtectionBroker::PumpLoop() {
  workerActive_.store(true);
  portConnected_.store(false);

  FilterApi api;
  if (!api.Load()) {
    workerActive_.store(false);
    portConnected_.store(false);
    QueueBrokerStateEvent(L"realtime.broker.unavailable",
                          L"The real-time protection broker could not load Filter Manager user-mode APIs.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
    return;
  }

  while (WaitForSingleObject(stopEvent_, 0) != WAIT_OBJECT_0) {
    HANDLE port = nullptr;
    const auto connectResult =
        api.connect(config_.realtimeProtectionPortName.c_str(), 0, nullptr, 0, nullptr, &port);
    if (FAILED(connectResult) || port == nullptr) {
      portConnected_.store(false);
      QueueBrokerStateEvent(L"realtime.broker.waiting",
                            L"The real-time protection broker is waiting for the minifilter communication port.",
                            std::wstring(L"{\"portName\":\"") +
                                Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
      const auto retryMilliseconds =
          static_cast<DWORD>(std::max(config_.realtimeBrokerRetrySeconds, 1) * 1000);
      if (WaitForSingleObject(stopEvent_, retryMilliseconds) == WAIT_OBJECT_0) {
        return;
      }
      continue;
    }

    portConnected_.store(true);
    QueueBrokerStateEvent(L"realtime.broker.connected",
                          L"The real-time protection broker connected to the minifilter communication port.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");

    while (WaitForSingleObject(stopEvent_, 0) != WAIT_OBJECT_0) {
      BrokerPortMessage message{};
      OVERLAPPED overlapped{};
      overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (overlapped.hEvent == nullptr) {
        break;
      }

      const auto getMessageResult =
          api.getMessage(port, &message.header, static_cast<DWORD>(sizeof(message)), &overlapped);
      bool messageReady = SUCCEEDED(getMessageResult);

      if (!messageReady && getMessageResult == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
        const auto waitResult = WaitForSingleObject(overlapped.hEvent, kBrokerMessageWaitMilliseconds);
        if (waitResult == WAIT_OBJECT_0) {
          DWORD transferred = 0;
          messageReady = GetOverlappedResult(port, &overlapped, &transferred, FALSE) != FALSE;
        } else if (waitResult == WAIT_TIMEOUT) {
          CloseHandle(overlapped.hEvent);
          continue;
        }
      }

      if (!messageReady) {
        CancelIoEx(port, &overlapped);
        CloseHandle(overlapped.hEvent);
        break;
      }

      CloseHandle(overlapped.hEvent);

      const auto outcome = InspectFile(message.request);
      BrokerPortReply reply{};
      reply.header.status = 0;
      reply.header.messageId = message.header.messageId;
      reply.reply.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
      reply.reply.replySize = sizeof(reply.reply);
      reply.reply.requestId = message.request.requestId;
      reply.reply.action = outcome.action;
      reply.reply.disposition = outcome.detection ? ANTIVIRUS_REALTIME_RESPONSE_DISPOSITION_MALICIOUS
                                                  : ANTIVIRUS_REALTIME_RESPONSE_DISPOSITION_CLEAN;
      reply.reply.confidence = outcome.finding.verdict.confidence;

      if (!outcome.finding.verdict.reasons.empty()) {
        CopyWideField(reply.reply.reasonCode, outcome.finding.verdict.reasons.front().code);
        CopyWideField(reply.reply.reasonMessage, outcome.finding.verdict.reasons.front().message);
      }

      CopyWideField(reply.reply.tacticId, outcome.finding.verdict.tacticId);
      CopyWideField(reply.reply.techniqueId, outcome.finding.verdict.techniqueId);
      CopyWideField(reply.reply.quarantineRecordId, outcome.finding.quarantineRecordId);
      CopyWideField(reply.reply.evidenceRecordId, outcome.finding.evidenceRecordId);

      api.replyMessage(port, &reply.header, static_cast<DWORD>(sizeof(reply)));
    }

    CloseHandle(port);
    portConnected_.store(false);
    QueueBrokerStateEvent(L"realtime.broker.disconnected",
                          L"The real-time protection broker lost its connection to the minifilter communication port.",
                          std::wstring(L"{\"portName\":\"") +
                              Utf8ToWide(EscapeJsonString(config_.realtimeProtectionPortName)) + L"\"}");
  }

  workerActive_.store(false);
  portConnected_.store(false);
}

void RealtimeProtectionBroker::QueueTelemetry(const TelemetryRecord& record) {
  const std::scoped_lock lock(telemetryMutex_);
  pendingTelemetry_.push_back(record);
}

void RealtimeProtectionBroker::QueueBrokerStateEvent(const std::wstring& eventType, const std::wstring& summary,
                                                     const std::wstring& payloadJson) {
  QueueTelemetry(TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = L"realtime-protection",
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payloadJson});
}

}  // namespace antivirus::agent
