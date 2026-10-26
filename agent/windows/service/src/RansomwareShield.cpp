#include "RansomwareShield.h"

#include <lm.h>
#include <tdh.h>

#include <algorithm>
#include <cwchar>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <set>
#include <sstream>

#include "CryptoUtils.h"
#include "RmmExecutors.h"
#include "StringUtils.h"

namespace antivirus::agent {

namespace {

// Microsoft-Windows-Kernel-File
constexpr GUID kKernelFileProvider = {0xEDD08927, 0x9CC4, 0x4E65, {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}};
constexpr ULONGLONG kKeywordCreate = 0x80;
constexpr ULONGLONG kKeywordWrite = 0x200;
constexpr USHORT kEventCreate = 12;
constexpr USHORT kEventWrite = 16;
constexpr ULONG kIrpPagingIo = 0x2;
constexpr ULONG kIrpSynchronousPagingIo = 0x40;
constexpr wchar_t kSessionName[] = L"FenrirRansomwareShield";
constexpr std::size_t kMaxPending = 50'000;
constexpr std::size_t kMaxFileObjects = 100'000;
constexpr int kSampleFiles = 8;
constexpr DWORD kSampleBytes = 64 * 1024;

std::wstring J(const std::wstring& value) { return L"\"" + Utf8ToWide(EscapeJsonString(value)) + L"\""; }

std::wstring JList(const std::vector<std::wstring>& values, std::size_t limit) {
  std::wstring out = L"[";
  for (std::size_t i = 0; i < values.size() && i < limit; ++i) {
    if (i != 0) out += L",";
    out += J(values[i]);
  }
  return out + L"]";
}

unsigned long long UnixNow() { return static_cast<unsigned long long>(std::time(nullptr)); }

bool StartsWithI(const std::wstring& value, const std::wstring& prefix) {
  return value.size() >= prefix.size() && _wcsnicmp(value.c_str(), prefix.c_str(), prefix.size()) == 0;
}

bool UnderI(const wchar_t* path, std::size_t length, const std::wstring& root) {
  if (length < root.size() || _wcsnicmp(path, root.c_str(), root.size()) != 0) return false;
  return length == root.size() || path[root.size()] == L'\\';
}

bool IsDirectory(const std::wstring& path) {
  const auto attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::wstring ExpandVariables(const std::wstring& value) {
  if (value.find(L'%') == std::wstring::npos) return value;
  std::wstring buffer(32768, L'\0');
  const auto length = ExpandEnvironmentStringsW(value.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length > buffer.size()) return value;
  buffer.resize(length - 1);
  return buffer;
}

// Signed-in and roaming user profiles from the registry (the service runs as SYSTEM).
std::vector<std::wstring> UserProfiles() {
  std::vector<std::wstring> profiles;
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0, KEY_READ,
                    &key) != ERROR_SUCCESS) {
    return profiles;
  }
  for (DWORD index = 0;; ++index) {
    wchar_t name[256];
    DWORD nameLength = 256;
    if (RegEnumKeyExW(key, index, name, &nameLength, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
    const std::wstring sid(name, nameLength);
    // Local and domain accounts (S-1-5-21-) and Entra ID accounts (S-1-12-1-).
    if (sid.rfind(L"S-1-5-21-", 0) != 0 && sid.rfind(L"S-1-12-1-", 0) != 0) continue;
    wchar_t path[MAX_PATH * 2]{};
    DWORD size = sizeof(path);
    if (RegGetValueW(key, sid.c_str(), L"ProfileImagePath", RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, path,
                     &size) == ERROR_SUCCESS &&
        IsDirectory(path)) {
      profiles.emplace_back(path);
    }
  }
  RegCloseKey(key);
  std::sort(profiles.begin(), profiles.end());
  return profiles;
}

// OneDrive folders inside a profile ("OneDrive", "OneDrive - Contoso"): Known Folder Move puts Documents there.
std::vector<std::wstring> OneDriveBases(const std::wstring& profile) {
  std::vector<std::wstring> out;
  WIN32_FIND_DATAW data{};
  const auto find = FindFirstFileW((profile + L"\\OneDrive*").c_str(), &data);
  if (find == INVALID_HANDLE_VALUE) return out;
  do {
    if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
      out.push_back(profile + L"\\" + data.cFileName);
    }
  } while (FindNextFileW(find, &data));
  FindClose(find);
  return out;
}

// Local folders shared over SMB (ordinary disk shares, not ADMIN$/C$/IPC$).
std::vector<std::wstring> SharedFolders() {
  std::vector<std::wstring> out;
  LPBYTE buffer = nullptr;
  DWORD read = 0, total = 0, resume = 0;
  if (NetShareEnum(nullptr, 2, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume) != NERR_Success || buffer == nullptr) {
    if (buffer != nullptr) NetApiBufferFree(buffer);
    return out;
  }
  const auto* shares = reinterpret_cast<const SHARE_INFO_2*>(buffer);
  for (DWORD i = 0; i < read; ++i) {
    if ((shares[i].shi2_type & 0xFF) != STYPE_DISKTREE || (shares[i].shi2_type & STYPE_SPECIAL) != 0) continue;
    if (shares[i].shi2_path != nullptr && IsDirectory(shares[i].shi2_path)) out.emplace_back(shares[i].shi2_path);
  }
  NetApiBufferFree(buffer);
  return out;
}

std::string CanaryContent() {
  std::string content = "Fenrir Endpoint ransomware canary. Do not edit, move or delete this file.\r\n";
  std::string line = "Budget 2024 - Q1 Q2 Q3 Q4 - Operations, Payroll, Facilities, Marketing, Contingency\r\n";
  while (content.size() < 24 * 1024) content += line;
  return content;
}

bool ReadSmallFile(const std::wstring& path, std::string& out, std::size_t limit) {
  const auto file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  out.assign(limit, '\0');
  DWORD read = 0;
  const bool ok = ReadFile(file, out.data(), static_cast<DWORD>(limit), &read, nullptr) != FALSE;
  CloseHandle(file);
  out.resize(ok ? read : 0);
  return ok;
}

bool WriteCanary(const std::wstring& path, const std::string& content) {
  SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
  const auto file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  const bool ok = WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written, nullptr) != FALSE &&
                  written == content.size();
  CloseHandle(file);
  return ok;
}

std::wstring PowerShellPath() {
  wchar_t systemDir[MAX_PATH]{};
  GetSystemDirectoryW(systemDir, MAX_PATH);
  return std::wstring(systemDir) + L"\\WindowsPowerShell\\v1.0\\powershell.exe";
}

// Runs a PowerShell script that prints one JSON document. Returns the parsed value (or nullopt).
std::optional<json::Value> RunPowerShellJson(const std::filesystem::path& work, const std::string& script,
                                             unsigned long timeoutMs, std::string& error) {
  std::error_code ec;
  std::filesystem::create_directories(work, ec);
  const auto path = work / (L"shield-" + GenerateGuidString() + L".ps1");
  {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << "\xEF\xBB\xBF" << script;
  }
  const auto command = L"\"" + PowerShellPath() + L"\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                       path.wstring() + L"\"";
  const auto result = rmm::RunProcess(command, work.wstring(), {}, timeoutMs, 1024 * 1024);
  std::filesystem::remove(path, ec);
  auto output = result.stdoutText;
  while (!output.empty() && (output.back() == '\n' || output.back() == '\r' || output.back() == ' ')) output.pop_back();
  auto parsed = json::Parse(output);
  if (result.timedOut || !parsed) {
    error = result.timedOut ? "timed out" : result.stderrText.substr(0, 1000);
    return std::nullopt;
  }
  return parsed;
}

std::string PsQuote(const std::wstring& value) {
  std::string out = "'";
  for (const char c : WideToUtf8(value)) {
    out += c;
    if (c == '\'') out += '\'';
  }
  return out + "'";
}

std::wstring SystemRootLower() {
  wchar_t buffer[MAX_PATH]{};
  GetWindowsDirectoryW(buffer, MAX_PATH);
  return ransomware::Lower(buffer) + L"\\";
}

std::wstring ModuleDirectoryLower() {
  wchar_t buffer[MAX_PATH * 2]{};
  GetModuleFileNameW(nullptr, buffer, MAX_PATH * 2);
  auto value = ransomware::Lower(buffer);
  const auto slash = value.find_last_of(L'\\');
  return slash == std::wstring::npos ? value : value.substr(0, slash + 1);
}

bool SameSettings(const RansomwareSettings& a, const RansomwareSettings& b) {
  return a.enabled == b.enabled && a.mode == b.mode && a.filesPerMinute == b.filesPerMinute &&
         a.entropyDetection == b.entropyDetection && a.canaryFiles == b.canaryFiles && a.protectedFolders == b.protectedFolders &&
         a.protectedFoldersMode == b.protectedFoldersMode && a.allowedApps == b.allowedApps &&
         a.rollbackSnapshots == b.rollbackSnapshots && a.snapshotIntervalHours == b.snapshotIntervalHours &&
         a.networkShareProtection == b.networkShareProtection;
}

}  // namespace

RansomwareShield::RansomwareShield(std::filesystem::path stateDirectory) : stateDirectory_(std::move(stateDirectory)) {}

RansomwareShield::~RansomwareShield() { Stop(); }

void RansomwareShield::SetUrgentCallback(std::function<void()> callback) {
  const std::scoped_lock lock(mutex_);
  urgent_ = std::move(callback);
}

void RansomwareShield::Apply(const RansomwareSettings& settings) {
  {
    const std::scoped_lock lock(mutex_);
    if (settingsApplied_ && SameSettings(settings_, settings)) return;
    settings_ = settings;
    settingsApplied_ = true;
    reconfigure_ = true;
  }
  if (!worker_.joinable()) {
    stop_ = false;
    worker_ = std::thread([this] { WorkerLoop(); });
  }
}

void RansomwareShield::Stop() {
  stop_ = true;
  if (worker_.joinable()) worker_.join();
  StopEtw();
  if (snapshotThread_.joinable()) snapshotThread_.join();
}

std::vector<TelemetryRecord> RansomwareShield::DrainTelemetry() {
  const std::scoped_lock lock(mutex_);
  auto out = std::move(telemetry_);
  telemetry_.clear();
  return out;
}

void RansomwareShield::Queue(const std::wstring& eventType, const std::wstring& summary, const std::wstring& payloadJson,
                             const bool urgent) {
  std::function<void()> callback;
  {
    const std::scoped_lock lock(mutex_);
    if (telemetry_.size() < 2000) {
      telemetry_.push_back({GenerateGuidString(), eventType, L"ransomware-shield", summary, CurrentUtcTimestamp(), payloadJson});
    }
    if (urgent) callback = urgent_;
  }
  if (callback) callback();
}

// ---------------------------------------------------------------------------------------------------------------
// Configuration

void RansomwareShield::Reconfigure() {
  RansomwareSettings settings;
  {
    const std::scoped_lock lock(mutex_);
    settings = settings_;
    reconfigure_ = false;
  }

  // Drive letter <-> NT device names, because ETW reports \Device\HarddiskVolumeN\... paths.
  std::vector<std::pair<std::wstring, std::wstring>> deviceMap;
  for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
    const wchar_t drive[3] = {letter, L':', 0};
    wchar_t target[1024]{};
    if (QueryDosDeviceW(drive, target, 1024) != 0 && std::wcsncmp(target, L"\\??\\", 4) != 0) {
      deviceMap.emplace_back(ransomware::Lower(target), drive);
    }
  }

  profiles_ = UserProfiles();
  lastProfileRefreshMs_ = GetTickCount64();
  std::vector<std::wstring> roots, canaryRoots;
  std::set<std::wstring> seen;
  auto add = [&](const std::wstring& path, bool canary) {
    if (path.size() < 3 || path.rfind(L"\\\\", 0) == 0 || !IsDirectory(path)) return;  // local folders only
    if (!seen.insert(ransomware::Lower(path)).second) return;
    roots.push_back(path);
    if (canary) canaryRoots.push_back(path);
  };
  if (settings.enabled) {
    for (const auto& entry : settings.protectedFolders) {
      for (const auto& folder : ransomware::ExpandProtectedFolder(entry, profiles_)) add(ExpandVariables(folder), true);
      // The same folder inside OneDrive (Known Folder Move); watched but no canary, so nothing extra syncs.
      const auto lowered = ransomware::Lower(entry);
      if (lowered.rfind(L"%userprofile%\\", 0) == 0) {
        const auto rest = entry.substr(13);
        for (const auto& profile : profiles_) {
          for (const auto& base : OneDriveBases(profile)) add(base + rest, false);
        }
      }
    }
  }
  std::vector<std::wstring> shares;
  if (settings.enabled && settings.networkShareProtection) shares = SharedFolders();

  // Remove our canaries where they are no longer wanted (feature off, folder dropped from policy).
  const auto content = CanaryContent();
  std::vector<std::wstring> canaries;
  if (settings.enabled && settings.canaryFiles) {
    for (const auto& root : canaryRoots) canaries.push_back(root + L"\\" + kCanaryName);
  }
  for (const auto& old : canaryPaths_) {
    if (std::find(canaries.begin(), canaries.end(), old) == canaries.end()) {
      std::string existing;
      if (ReadSmallFile(old, existing, content.size() + 1) && existing == content) {
        SetFileAttributesW(old.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(old.c_str());
      }
    }
  }

  auto toDevice = [&deviceMap](const std::wstring& dos) {
    for (const auto& [device, drive] : deviceMap) {
      if (StartsWithI(dos, drive)) return device + dos.substr(drive.size());
    }
    return ransomware::Lower(dos);
  };
  ransomware::DetectorConfig config;
  for (const auto& root : roots) config.roots.push_back(toDevice(root));
  for (const auto& share : shares) config.shareRoots.push_back(toDevice(share));
  for (const auto& canary : canaries) config.canaries.insert(toDevice(canary));
  config.filesPerMinute = settings.filesPerMinute;
  config.protectedFoldersWatch = settings.enabled && settings.protectedFoldersMode != L"off";
  for (const auto& app : settings.allowedApps) config.allowedApps.push_back(ExpandVariables(app));
  config.selfPid = GetCurrentProcessId();
  {
    const std::scoped_lock lock(filterMutex_);
    deviceRoots_.clear();
    for (const auto& root : config.roots) deviceRoots_.push_back(root);
    for (const auto& root : config.shareRoots) deviceRoots_.push_back(root);
  }
  detector_.Configure(config);
  {
    const std::scoped_lock lock(mutex_);
    deviceToDos_ = std::move(deviceMap);
    dosRoots_ = roots;
    canaryPaths_ = canaries;
  }
  lastCanaryCheckMs_ = 0;  // place canaries straight away

  if (settings.enabled && !roots.empty()) {
    if (!etwActive_.load() && !StartEtw() && !degradedReported_) {
      degradedReported_ = true;
      Queue(L"ransomware.shield.degraded", L"The ransomware file watcher could not start; canaries and snapshots still run.",
            L"{\"watcher\":\"etw\",\"error\":" + std::to_wstring(GetLastError()) + L"}", false);
    }
  } else {
    StopEtw();
  }
  if (etwActive_.load()) {
    Queue(L"ransomware.shield.configured", L"Ransomware shield watching " + std::to_wstring(roots.size()) + L" folders",
          L"{\"folders\":" + JList(roots, 50) + L",\"shares\":" + JList(shares, 50) + L",\"canaries\":" +
              std::to_wstring(canaries.size()) + L",\"mode\":" + J(settings.mode) + L",\"protectedFoldersMode\":" +
              J(settings.protectedFoldersMode) + L",\"filesPerMinute\":" + std::to_wstring(settings.filesPerMinute) + L"}",
          false);
  }
}

std::wstring RansomwareShield::ToDosPath(const std::wstring& devicePath) const {
  const std::scoped_lock lock(mutex_);
  for (const auto& [device, drive] : deviceToDos_) {
    if (UnderI(devicePath.c_str(), devicePath.size(), device)) return drive + devicePath.substr(device.size());
  }
  return devicePath;
}

std::wstring RansomwareShield::ToDevicePath(const std::wstring& dosPath) const {
  const std::scoped_lock lock(mutex_);
  for (const auto& [device, drive] : deviceToDos_) {
    if (StartsWithI(dosPath, drive)) return device + dosPath.substr(drive.size());
  }
  return dosPath;
}

// ---------------------------------------------------------------------------------------------------------------
// ETW

bool RansomwareShield::StartEtw() {
  lastEtwAttemptMs_ = GetTickCount64();
  const auto nameBytes = static_cast<ULONG>((std::wcslen(kSessionName) + 1) * sizeof(wchar_t));
  const ULONG total = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
  std::vector<BYTE> buffer(total, 0);
  auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
  auto reset = [&] {
    std::fill(buffer.begin(), buffer.end(), 0);
    properties->Wnode.BufferSize = total;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1;  // QPC timestamps
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    properties->BufferSize = 256;  // KB
    properties->MinimumBuffers = 16;
    properties->MaximumBuffers = 64;
    properties->FlushTimer = 1;
  };
  reset();
  ControlTraceW(0, kSessionName, properties, EVENT_TRACE_CONTROL_STOP);  // a session left behind by a crash
  reset();
  TRACEHANDLE session = 0;
  auto status = StartTraceW(&session, kSessionName, properties);
  if (status != ERROR_SUCCESS) {
    SetLastError(status);
    return false;
  }
  status = EnableTraceEx2(session, &kKernelFileProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
                          kKeywordCreate | kKeywordWrite, 0, 0, nullptr);
  if (status != ERROR_SUCCESS) {
    reset();
    ControlTraceW(session, nullptr, properties, EVENT_TRACE_CONTROL_STOP);
    SetLastError(status);
    return false;
  }
  EVENT_TRACE_LOGFILEW logFile{};
  logFile.LoggerName = const_cast<wchar_t*>(kSessionName);
  logFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
  logFile.EventRecordCallback = &RansomwareShield::EtwEventCallback;
  logFile.Context = this;
  const auto trace = OpenTraceW(&logFile);
  if (trace == INVALID_PROCESSTRACE_HANDLE) {
    const auto error = GetLastError();
    reset();
    ControlTraceW(session, nullptr, properties, EVENT_TRACE_CONTROL_STOP);
    SetLastError(error);
    return false;
  }
  session_ = session;
  trace_ = trace;
  etwActive_ = true;
  etwThread_ = CreateThread(nullptr, 0, &RansomwareShield::EtwThreadEntry, this, 0, nullptr);
  if (etwThread_ == nullptr) {
    const auto error = GetLastError();
    StopEtw();
    SetLastError(error);
    return false;
  }
  Queue(L"ransomware.shield.started", L"The ransomware file watcher started.", L"{\"watcher\":\"etw\"}", false);
  return true;
}

void RansomwareShield::StopEtw() {
  if (session_ != 0) {
    const auto nameBytes = static_cast<ULONG>((std::wcslen(kSessionName) + 1) * sizeof(wchar_t));
    const ULONG total = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
    std::vector<BYTE> buffer(total, 0);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    properties->Wnode.BufferSize = total;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(session_, nullptr, properties, EVENT_TRACE_CONTROL_STOP);
    session_ = 0;
  }
  if (trace_ != 0) {
    CloseTrace(trace_);
    trace_ = 0;
  }
  if (etwThread_ != nullptr) {
    WaitForSingleObject(etwThread_, 10'000);
    CloseHandle(etwThread_);
    etwThread_ = nullptr;
  }
  etwActive_ = false;
}

DWORD WINAPI RansomwareShield::EtwThreadEntry(LPVOID context) {
  auto* self = static_cast<RansomwareShield*>(context);
  TRACEHANDLE trace = self->trace_;
  ProcessTrace(&trace, 1, nullptr, nullptr);
  self->etwActive_ = false;
  return 0;
}

VOID WINAPI RansomwareShield::EtwEventCallback(EVENT_RECORD* record) {
  if (record != nullptr && record->UserContext != nullptr) {
    static_cast<RansomwareShield*>(record->UserContext)->OnEtwEvent(*record);
  }
}

namespace {

// Checks once per event id/version that the payload starts with the fields the fast parser expects.
bool LayoutMatches(const EVENT_RECORD& record, const std::vector<std::wstring>& expected) {
  ULONG size = 0;
  auto* mutableRecord = const_cast<EVENT_RECORD*>(&record);
  if (TdhGetEventInformation(mutableRecord, 0, nullptr, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER || size == 0) return false;
  std::vector<BYTE> buffer(size);
  auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
  if (TdhGetEventInformation(mutableRecord, 0, nullptr, info, &size) != ERROR_SUCCESS) return false;
  if (info->TopLevelPropertyCount < expected.size()) return false;
  for (std::size_t i = 0; i < expected.size(); ++i) {
    const auto* name = reinterpret_cast<const wchar_t*>(buffer.data() + info->EventPropertyInfoArray[i].NameOffset);
    if (_wcsicmp(name, expected[i].c_str()) != 0) return false;
  }
  return true;
}

}  // namespace

void RansomwareShield::OnEtwEvent(const EVENT_RECORD& record) {
  if (record.EventHeader.ProviderId != kKernelFileProvider) return;
  const auto id = record.EventHeader.EventDescriptor.Id;
  if (id != kEventCreate && id != kEventWrite) return;
  const auto key = (static_cast<unsigned long long>(id) << 8) | record.EventHeader.EventDescriptor.Version;
  auto layout = layoutOk_.find(key);
  if (layout == layoutOk_.end()) {
    const bool ok = id == kEventCreate
                        ? LayoutMatches(record, {L"Irp", L"FileObject", L"IssuingThreadId", L"CreateOptions",
                                                 L"CreateAttributes", L"ShareAccess", L"FileName"})
                        : LayoutMatches(record, {L"ByteOffset", L"Irp", L"FileObject", L"FileKey", L"IssuingThreadId",
                                                 L"IOSize", L"IOFlags"});
    layout = layoutOk_.emplace(key, ok ? 1 : -1).first;
    if (!ok) {
      Queue(L"ransomware.shield.degraded", L"The ransomware file watcher does not understand this Windows build's file events.",
            L"{\"eventId\":" + std::to_wstring(id) + L",\"version\":" +
                std::to_wstring(record.EventHeader.EventDescriptor.Version) + L"}",
            false);
    }
  }
  if (layout->second != 1) return;

  const auto* data = static_cast<const BYTE*>(record.UserData);
  const std::size_t size = record.UserDataLength;
  const std::size_t ptr = (record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0 ? 4 : 8;
  auto readPtr = [&](std::size_t offset) -> unsigned long long {
    if (offset + ptr > size) return 0;
    if (ptr == 8) {
      unsigned long long value = 0;
      std::memcpy(&value, data + offset, 8);
      return value;
    }
    unsigned int value = 0;
    std::memcpy(&value, data + offset, 4);
    return value;
  };
  auto readU32 = [&](std::size_t offset) -> unsigned int {
    unsigned int value = 0;
    if (offset + 4 <= size) std::memcpy(&value, data + offset, 4);
    return value;
  };
  const auto pid = record.EventHeader.ProcessId;
  const auto nowMs = GetTickCount64();

  auto push = [this](unsigned long processId, const std::wstring& path) {
    const std::scoped_lock lock(pendingMutex_);
    if (pending_.size() >= kMaxPending) {
      ++dropped_;
      return;
    }
    pending_.push_back({processId, path});
  };

  if (id == kEventCreate) {
    const std::size_t nameOffset = 2 * ptr + 16;
    if (size < nameOffset + sizeof(wchar_t)) return;
    const auto fileObject = readPtr(ptr);
    const auto options = readU32(2 * ptr + 4);
    const auto* name = reinterpret_cast<const wchar_t*>(data + nameOffset);
    const auto maxChars = (size - nameOffset) / sizeof(wchar_t);
    const auto length = wcsnlen(name, maxChars);
    bool watched = false;
    {
      const std::scoped_lock lock(filterMutex_);
      for (const auto& root : deviceRoots_) {
        if (UnderI(name, length, root)) {
          watched = true;
          break;
        }
      }
    }
    if (!watched) {
      fileObjects_.erase(fileObject);  // file objects are reused; drop any stale mapping
      return;
    }
    if (fileObjects_.size() >= kMaxFileObjects) fileObjects_.clear();
    auto& entry = fileObjects_[fileObject];
    entry.path.assign(name, length);
    entry.lastPid = 0;
    entry.lastQueuedMs = 0;
    const auto disposition = options >> 24;  // FILE_SUPERSEDE, FILE_CREATE, FILE_OVERWRITE, FILE_OVERWRITE_IF write
    if (disposition == 0 || disposition == 2 || disposition == 4 || disposition == 5) {
      entry.lastPid = pid;
      entry.lastQueuedMs = nowMs;
      push(pid, entry.path);
    }
    return;
  }

  // Write: ByteOffset, Irp, FileObject, FileKey, IssuingThreadId, IOSize, IOFlags
  const auto fileObject = readPtr(8 + ptr);
  const auto flags = readU32(8 + 3 * ptr + 8);
  if ((flags & (kIrpPagingIo | kIrpSynchronousPagingIo)) != 0) return;  // cache manager / mapped-page writes
  const auto it = fileObjects_.find(fileObject);
  if (it == fileObjects_.end()) return;
  if (it->second.lastPid == pid && nowMs - it->second.lastQueuedMs < 2000) return;
  it->second.lastPid = pid;
  it->second.lastQueuedMs = nowMs;
  push(pid, it->second.path);
}

// ---------------------------------------------------------------------------------------------------------------
// Worker

void RansomwareShield::WorkerLoop() {
  while (!stop_.load()) {
    bool reconfigure = false;
    bool enabled = false;
    {
      const std::scoped_lock lock(mutex_);
      reconfigure = reconfigure_;
      enabled = settings_.enabled;
    }
    try {
      if (reconfigure) Reconfigure();
      const auto now = GetTickCount64();
      if (enabled && now - lastProfileRefreshMs_ > 10 * 60'000 && UserProfiles() != profiles_) Reconfigure();
      // Restart the watcher if its session died (another tool stopped it, low resources) or never started.
      bool haveRoots = false;
      {
        const std::scoped_lock lock(mutex_);
        haveRoots = !dosRoots_.empty();
      }
      if (enabled && haveRoots && !etwActive_.load() && now - lastEtwAttemptMs_ > 10 * 60'000) {
        StopEtw();
        StartEtw();
      }
      ProcessPending();
      if (now - lastCanaryCheckMs_ >= 60'000 || lastCanaryCheckMs_ == 0) {
        lastCanaryCheckMs_ = now;
        MaintainCanaries();
      }
      if (now - lastSnapshotCheckMs_ >= 5 * 60'000 || lastSnapshotCheckMs_ == 0) {
        lastSnapshotCheckMs_ = now;
        MaybeSnapshot();
      }
    } catch (const std::exception& error) {
      Queue(L"ransomware.shield.error", L"The ransomware shield hit an error and carried on.",
            L"{\"error\":" + J(Utf8ToWide(error.what())) + L"}", false);
    }
    for (int i = 0; i < 4 && !stop_.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

std::wstring RansomwareShield::ImageFor(const unsigned long pid) {
  if (pid == ransomware::kSystemPid) return L"System";
  const auto now = GetTickCount64();
  const auto cached = images_.find(pid);
  if (cached != images_.end() && cached->second.second > now) return cached->second.first;
  if (images_.size() > 4096) images_.clear();
  std::wstring image;
  if (const auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)) {
    wchar_t buffer[MAX_PATH * 2]{};
    DWORD length = MAX_PATH * 2;
    if (QueryFullProcessImageNameW(process, 0, buffer, &length) != FALSE) image.assign(buffer, length);
    CloseHandle(process);
  }
  images_[pid] = {image, now + 30'000};
  return image;
}

void RansomwareShield::ProcessPending() {
  std::vector<PendingWrite> batch;
  {
    const std::scoped_lock lock(pendingMutex_);
    batch.swap(pending_);
  }
  const auto dropped = dropped_.exchange(0);
  if (dropped != 0) {
    Queue(L"ransomware.shield.overloaded", L"The ransomware file watcher fell behind and skipped some file events.",
          L"{\"skipped\":" + std::to_wstring(dropped) + L"}", false);
  }
  const auto now = GetTickCount64();
  for (const auto& write : batch) {
    const auto image = ImageFor(write.pid);
    for (const auto& observation : detector_.OnWrite(write.pid, image, write.devicePath, now)) {
      Handle(observation);
    }
  }
}

bool RansomwareShield::Killable(const unsigned long pid, const std::wstring& image) const {
  if (pid <= ransomware::kSystemPid || pid == GetCurrentProcessId() || image.empty()) return false;
  const auto lowered = ransomware::Lower(image);
  static const auto windows = SystemRootLower();
  static const auto own = ModuleDirectoryLower();
  return lowered.rfind(windows, 0) != 0 && lowered.rfind(own, 0) != 0;
}

bool RansomwareShield::Terminate(const unsigned long pid, const std::wstring& image) {
  const auto process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (process == nullptr) return false;
  wchar_t buffer[MAX_PATH * 2]{};
  DWORD length = MAX_PATH * 2;
  bool same = QueryFullProcessImageNameW(process, 0, buffer, &length) != FALSE && _wcsicmp(buffer, image.c_str()) == 0;
  const bool ok = same && TerminateProcess(process, 0xC0000022) != FALSE;  // STATUS_ACCESS_DENIED as exit code
  CloseHandle(process);
  if (ok) {
    detector_.Forget(pid);
    images_.erase(pid);
  }
  return ok;
}

void RansomwareShield::Handle(const ransomware::Observation& observation) {
  RansomwareSettings settings;
  {
    const std::scoped_lock lock(mutex_);
    settings = settings_;
  }
  const auto path = ToDosPath(observation.path);
  const std::wstring actor = observation.remote ? L"a computer on the network (SMB)" : observation.image;
  const auto processFields = L"\"processImagePath\":" + J(observation.remote ? L"System" : observation.image) +
                             L",\"pid\":" + std::to_wstring(observation.pid) + L",\"remote\":" +
                             (observation.remote ? L"true" : L"false");

  if (observation.kind == ransomware::ObservationKind::Canary) {
    const bool killed = settings.Blocks() && !observation.remote && Killable(observation.pid, observation.image) &&
                        Terminate(observation.pid, observation.image);
    canaryAlertedMs_[ransomware::Lower(path)] = GetTickCount64();
    Queue(L"ransomware.canary.touched",
          L"A ransomware canary file was changed by " + actor + (killed ? L"; the process was stopped" : L""),
          L"{\"path\":" + J(path) + L"," + processFields + L",\"change\":\"modified\",\"action\":" +
              J(killed ? L"terminated" : L"reported") + L"}",
          true);
    return;
  }

  if (observation.kind == ransomware::ObservationKind::ProtectedFolderWrite) {
    if (settings.protectedFoldersMode == L"off" || observation.image.empty()) return;
    static std::map<std::wstring, bool> signedCache;
    auto signedIt = signedCache.find(observation.image);
    if (signedIt == signedCache.end()) {
      if (signedCache.size() > 2000) signedCache.clear();
      signedIt = signedCache.emplace(observation.image, VerifyFileAuthenticodeSignature(observation.image)).first;
    }
    if (signedIt->second) return;  // signed software is trusted, like Windows Controlled Folder Access
    const bool block = settings.protectedFoldersMode == L"block";
    const bool killed = block && Killable(observation.pid, observation.image) && Terminate(observation.pid, observation.image);
    Queue(killed ? L"ransomware.protected_folder.blocked" : L"ransomware.protected_folder.write",
          (killed ? L"Stopped an unsigned program writing to a protected folder: " : L"An unsigned program wrote to a protected folder: ") +
              observation.image,
          L"{\"path\":" + J(path) + L"," + processFields + L",\"mode\":" + J(settings.protectedFoldersMode) +
              L",\"action\":" + J(killed ? L"terminated" : L"reported") + L"}",
          killed);
    return;
  }

  // Mass change: confirm by sampling the newest files for encryption.
  int sampled = 0, encrypted = 0;
  if (settings.entropyDetection) {
    std::vector<unsigned char> buffer(kSampleBytes);
    for (auto it = observation.paths.rbegin(); it != observation.paths.rend() && sampled < kSampleFiles; ++it) {
      const auto file = CreateFileW((L"\\\\?\\GLOBALROOT" + *it).c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
      if (file == INVALID_HANDLE_VALUE) continue;
      DWORD read = 0;
      const bool ok = ReadFile(file, buffer.data(), kSampleBytes, &read, nullptr) != FALSE;
      CloseHandle(file);
      if (!ok || read < 512) continue;
      ++sampled;
      if (ransomware::LooksEncrypted(buffer.data(), read)) ++encrypted;
    }
    if (!ransomware::EncryptionConfirmed(sampled, encrypted)) return;
  }
  const bool killed = settings.Blocks() && !observation.remote && Killable(observation.pid, observation.image) &&
                      Terminate(observation.pid, observation.image);
  Incident incident;
  incident.startedUnix = UnixNow() - 75;  // the burst covers the last minute; leave a margin
  incident.image = observation.remote ? L"System" : observation.image;
  incident.pid = observation.pid;
  for (const auto& changed : observation.paths) incident.paths.push_back(ToDosPath(changed));
  SaveIncident(incident);
  const auto action = killed ? L"terminated" : (settings.Blocks() && !observation.remote ? L"could not stop" : L"reported");
  Queue(killed ? L"ransomware.blocked" : L"ransomware.detected",
        (killed ? L"Ransomware stopped: " : L"Possible ransomware: ") + actor + L" rewrote " +
            std::to_wstring(observation.count) + L" files in a minute" +
            (settings.entropyDetection ? L" (" + std::to_wstring(encrypted) + L" of " + std::to_wstring(sampled) +
                                             L" sampled files look encrypted)"
                                       : L""),
        L"{" + processFields + L",\"path\":" + J(path) + L",\"filesChanged\":" + std::to_wstring(observation.count) +
            L",\"threshold\":" + std::to_wstring(settings.filesPerMinute) + L",\"entropyChecked\":" +
            (settings.entropyDetection ? L"true" : L"false") + L",\"sampled\":" + std::to_wstring(sampled) +
            L",\"encrypted\":" + std::to_wstring(encrypted) + L",\"action\":" + J(action) + L",\"samplePaths\":" +
            JList(incident.paths, 10) + L",\"mitre\":\"T1486\"}",
        true);
  if (killed && settings.RollsBack()) {
    RollbackLastIncident(L"automatic (block-and-rollback)");
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Canaries

void RansomwareShield::MaintainCanaries() {
  std::vector<std::wstring> canaries;
  {
    const std::scoped_lock lock(mutex_);
    canaries = canaryPaths_;
  }
  if (canaries.empty()) return;
  static const auto content = CanaryContent();
  const auto now = GetTickCount64();
  for (const auto& path : canaries) {
    std::string existing;
    const bool exists = GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    if (exists && ReadSmallFile(path, existing, content.size() + 1) && existing == content) continue;
    if (exists) {
      // Changed without the watcher seeing it (watcher off, or a write it could not attribute).
      const auto alerted = canaryAlertedMs_.find(ransomware::Lower(path));
      if (alerted == canaryAlertedMs_.end() || now - alerted->second > 5 * 60'000) {
        canaryAlertedMs_[ransomware::Lower(path)] = now;
        Queue(L"ransomware.canary.touched", L"A ransomware canary file was changed (found by the periodic check)",
              L"{\"path\":" + J(path) + L",\"change\":\"modified\",\"action\":\"reported\"}", true);
      }
    }
    WriteCanary(path, content);
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Snapshots and rollback

void RansomwareShield::MaybeSnapshot() {
  RansomwareSettings settings;
  std::vector<std::wstring> roots;
  {
    const std::scoped_lock lock(mutex_);
    settings = settings_;
    roots = dosRoots_;
  }
  if (!settings.enabled || !settings.rollbackSnapshots || snapshotBusy_.load()) return;
  const auto stamp = stateDirectory_ / L"ransomware-last-snapshot.txt";
  unsigned long long last = 0;
  {
    std::ifstream in(stamp);
    in >> last;
  }
  const auto now = UnixNow();
  if (last != 0 && now >= last && now - last < static_cast<unsigned long long>(settings.snapshotIntervalHours) * 3600ULL) return;

  std::set<std::wstring> volumes;
  for (const auto& root : roots) {
    if (root.size() >= 3 && root[1] == L':') {
      const auto volume = root.substr(0, 3);
      if (GetDriveTypeW(volume.c_str()) == DRIVE_FIXED) volumes.insert(volume);
    }
  }
  if (volumes.empty()) {
    wchar_t windows[MAX_PATH]{};
    GetWindowsDirectoryW(windows, MAX_PATH);
    volumes.insert(std::wstring(windows).substr(0, 3));
  }
  std::string list;
  for (const auto& volume : volumes) list += (list.empty() ? "" : ",") + PsQuote(volume);
  const std::string script =
      "$ErrorActionPreference = 'Stop'\r\n"
      "$results = @()\r\n"
      "foreach ($v in @(" + list + ")) {\r\n"
      "  try {\r\n"
      "    $r = ([wmiclass]'root\\cimv2:Win32_ShadowCopy').Create($v, 'ClientAccessible')\r\n"
      "    $results += [pscustomobject]@{ volume = $v; code = [int]$r.ReturnValue; id = [string]$r.ShadowID }\r\n"
      "  } catch { $results += [pscustomobject]@{ volume = $v; code = -1; error = $_.Exception.Message } }\r\n"
      "}\r\n"
      "[pscustomobject]@{ snapshots = @($results) } | ConvertTo-Json -Compress -Depth 4\r\n";
  if (snapshotThread_.joinable()) snapshotThread_.join();
  snapshotBusy_ = true;
  snapshotThread_ = std::thread([this, script, stamp, settings] {
    std::string error;
    const auto result = RunPowerShellJson(stateDirectory_ / L"ransomware", script, 10 * 60 * 1000, error);
    bool ok = false;
    if (result) {
      ok = true;
      if (const auto* snapshots = result->Get("snapshots")) {
        if (const auto* list = std::get_if<json::Array>(&snapshots->v)) {
          for (const auto& item : *list) {
            const auto* code = item.Get("code");
            if (code == nullptr || code->Number().value_or(-1) != 0) ok = false;
          }
        }
      }
    }
    const auto now = UnixNow();
    // On failure try again in an hour rather than at the next check.
    const auto next = ok ? now : now - static_cast<unsigned long long>(settings.snapshotIntervalHours) * 3600ULL + 3600ULL;
    {
      std::ofstream out(stamp, std::ios::trunc);
      out << next;
    }
    Queue(ok ? L"ransomware.snapshot.created" : L"ransomware.snapshot.failed",
          ok ? L"Took a rollback snapshot (Volume Shadow Copy)" : L"A rollback snapshot (Volume Shadow Copy) could not be taken",
          ok || result ? L"{\"intervalHours\":" + std::to_wstring(settings.snapshotIntervalHours) + L"}"
                       : L"{\"error\":" + J(Utf8ToWide(error)) + L"}",
          false);
    snapshotBusy_ = false;
  });
}

void RansomwareShield::SaveIncident(const Incident& incident) {
  std::error_code ec;
  std::filesystem::create_directories(stateDirectory_, ec);
  std::wstring body = L"{\"startedUnix\":" + std::to_wstring(incident.startedUnix) + L",\"restoredUnix\":" +
                      std::to_wstring(incident.restoredUnix) + L",\"image\":" + J(incident.image) +
                      L",\"pid\":" + std::to_wstring(incident.pid) + L",\"paths\":" + JList(incident.paths, 5000) + L"}";
  std::ofstream out(stateDirectory_ / L"ransomware-incident.json", std::ios::binary | std::ios::trunc);
  out << WideToUtf8(body);
}

bool RansomwareShield::LoadIncident(Incident& incident) const {
  std::ifstream in(stateDirectory_ / L"ransomware-incident.json", std::ios::binary);
  std::stringstream text;
  text << in.rdbuf();
  const auto parsed = json::Parse(text.str());
  if (!parsed || !parsed->IsObject()) return false;
  const auto* started = parsed->Get("startedUnix");
  if (started == nullptr || !started->Number()) return false;
  incident.startedUnix = static_cast<unsigned long long>(*started->Number());
  if (const auto* restored = parsed->Get("restoredUnix")) {
    incident.restoredUnix = static_cast<unsigned long long>(restored->Number().value_or(0));
  }
  if (const auto* image = parsed->Get("image")) incident.image = Utf8ToWide(image->String().value_or(""));
  if (const auto* pid = parsed->Get("pid")) incident.pid = static_cast<unsigned long>(pid->Number().value_or(0));
  if (const auto* paths = parsed->Get("paths")) {
    for (const auto& path : paths->Strings()) incident.paths.push_back(Utf8ToWide(path));
  }
  return !incident.paths.empty();
}

std::wstring RansomwareShield::RollbackLastIncident(const std::wstring& reason) {
  Incident incident;
  if (!LoadIncident(incident)) {
    return L"{\"ok\":false,\"error\":\"No ransomware incident is recorded on this device, so there is nothing to roll back.\"}";
  }
  // Only a recent attack is rolled back, and only once: restoring old snapshots over today's files would lose work.
  const auto now = UnixNow();
  if (now > incident.startedUnix + 24 * 3600) {
    return L"{\"ok\":false,\"error\":\"The last recorded ransomware incident is more than 24 hours old; restore files from "
           L"Previous Versions instead.\"}";
  }
  if (incident.restoredUnix != 0) {
    return L"{\"ok\":true,\"alreadyRestored\":true,\"restoredUnix\":" + std::to_wstring(incident.restoredUnix) + L"}";
  }
  const auto result = Rollback(incident, reason);
  if (result.find(L"\"ok\":true") != std::wstring::npos) {
    incident.restoredUnix = now;
    SaveIncident(incident);
  }
  return result;
}

std::wstring RansomwareShield::Rollback(const Incident& incident, const std::wstring& reason) {
  const std::scoped_lock lock(rollbackMutex_);
  const std::string script =
      "$ErrorActionPreference = 'Stop'\r\n"
      "$list = @(Get-CimInstance Win32_ShadowCopy | ForEach-Object { [pscustomobject]@{ device = $_.DeviceObject; "
      "volume = $_.VolumeName; created = [DateTimeOffset]::new($_.InstallDate.ToUniversalTime()).ToUnixTimeSeconds() } })\r\n"
      "ConvertTo-Json -InputObject @($list) -Compress -Depth 3\r\n";
  std::string error;
  const auto shadows = RunPowerShellJson(stateDirectory_ / L"ransomware", script, 5 * 60 * 1000, error);
  const auto* list = shadows ? std::get_if<json::Array>(&shadows->v) : nullptr;
  if (list == nullptr) {
    const auto body = L"{\"ok\":false,\"error\":" + J(L"Could not list snapshots: " + Utf8ToWide(error)) + L"}";
    Queue(L"ransomware.restore.failed", L"Ransomware rollback failed: snapshots could not be listed", body, true);
    return body;
  }
  struct Shadow {
    std::wstring device;
    unsigned long long created{0};
  };
  std::map<std::wstring, Shadow> chosen;  // lower volume GUID path -> newest shadow before the incident
  for (const auto& item : *list) {
    const auto* device = item.Get("device");
    const auto* volume = item.Get("volume");
    const auto* created = item.Get("created");
    if (!device || !volume || !created || !created->Number()) continue;
    const auto when = static_cast<unsigned long long>(*created->Number());
    if (when >= incident.startedUnix) continue;
    const auto key = ransomware::Lower(Utf8ToWide(volume->String().value_or("")));
    auto& slot = chosen[key];
    if (when > slot.created) slot = {Utf8ToWide(device->String().value_or("")), when};
  }

  int restored = 0, unchanged = 0, failed = 0, missingSnapshot = 0;
  unsigned long long snapshotTime = 0;
  std::set<std::wstring> directories;
  std::set<std::wstring> done;
  auto shadowFor = [&](const std::wstring& path) -> const Shadow* {
    if (path.size() < 3 || path[1] != L':') return nullptr;
    wchar_t volume[MAX_PATH]{};
    if (!GetVolumeNameForVolumeMountPointW(path.substr(0, 3).c_str(), volume, MAX_PATH)) return nullptr;
    const auto it = chosen.find(ransomware::Lower(volume));
    return it == chosen.end() || it->second.device.empty() ? nullptr : &it->second;
  };
  auto restoreOne = [&](const std::wstring& source, const std::wstring& target) {
    if (!done.insert(ransomware::Lower(target)).second) return;
    WIN32_FILE_ATTRIBUTE_DATA before{}, live{};
    if (!GetFileAttributesExW(source.c_str(), GetFileExInfoStandard, &before)) return;
    if (GetFileAttributesExW(target.c_str(), GetFileExInfoStandard, &live)) {
      if (live.nFileSizeLow == before.nFileSizeLow && live.nFileSizeHigh == before.nFileSizeHigh &&
          CompareFileTime(&live.ftLastWriteTime, &before.ftLastWriteTime) == 0) {
        ++unchanged;
        return;
      }
      // Keep what is there now, in case the rollback was not wanted.
      if (!MoveFileExW(target.c_str(), (target + L".fenrir-pre-restore").c_str(), MOVEFILE_REPLACE_EXISTING)) {
        ++failed;
        return;
      }
    }
    if (CopyFileW(source.c_str(), target.c_str(), FALSE)) {
      ++restored;
    } else {
      ++failed;
    }
  };
  for (const auto& path : incident.paths) {
    if (restored + unchanged + failed > 20000) break;
    const auto* shadow = shadowFor(path);
    if (shadow == nullptr) {
      ++missingSnapshot;
      continue;
    }
    snapshotTime = std::max(snapshotTime, shadow->created);
    const auto slash = path.find_last_of(L'\\');
    if (slash != std::wstring::npos) directories.insert(path.substr(0, slash));
    auto source = shadow->device + path.substr(2);
    auto target = path;
    if (GetFileAttributesW(source.c_str()) == INVALID_FILE_ATTRIBUTES) {
      // Renamed copies (report.docx.locked): try the name without the extra extension.
      const auto dot = path.find_last_of(L'.');
      if (dot == std::wstring::npos || dot < slash) continue;
      target = path.substr(0, dot);
      source = shadow->device + target.substr(2);
      const auto innerDot = target.find_last_of(L'.');
      if (innerDot == std::wstring::npos || innerDot < slash || GetFileAttributesW(source.c_str()) == INVALID_FILE_ATTRIBUTES) {
        continue;
      }
    }
    restoreOne(source, target);
  }
  // Files the attacker deleted after writing encrypted copies: anything in the snapshot that is missing now.
  for (const auto& directory : directories) {
    const auto* shadow = shadowFor(directory + L"\\");
    if (shadow == nullptr) continue;
    WIN32_FIND_DATAW data{};
    const auto shadowDir = shadow->device + directory.substr(2);
    const auto find = FindFirstFileW((shadowDir + L"\\*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) continue;
    do {
      if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) continue;
      const auto target = directory + L"\\" + data.cFileName;
      if (GetFileAttributesW(target.c_str()) == INVALID_FILE_ATTRIBUTES) restoreOne(shadowDir + L"\\" + data.cFileName, target);
    } while (FindNextFileW(find, &data) && restored + failed < 20000);
    FindClose(find);
  }
  const bool ok = restored > 0 || (failed == 0 && unchanged > 0);
  const auto body = L"{\"ok\":" + std::wstring(ok ? L"true" : L"false") + L",\"reason\":" + J(reason) +
                    L",\"restored\":" + std::to_wstring(restored) + L",\"unchanged\":" + std::to_wstring(unchanged) +
                    L",\"failed\":" + std::to_wstring(failed) + L",\"withoutSnapshot\":" + std::to_wstring(missingSnapshot) +
                    L",\"snapshotUnix\":" + std::to_wstring(snapshotTime) + L",\"incidentProcess\":" + J(incident.image) +
                    L",\"note\":\"Files that were replaced keep their pre-restore copy as <name>.fenrir-pre-restore.\"}";
  Queue(ok ? L"ransomware.restore.completed" : L"ransomware.restore.failed",
        ok ? L"Ransomware rollback restored " + std::to_wstring(restored) + L" files from a snapshot"
           : L"Ransomware rollback could not restore files (no usable snapshot from before the attack)",
        body, true);
  return body;
}

}  // namespace antivirus::agent
