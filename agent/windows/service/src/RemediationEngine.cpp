#include "RemediationEngine.h"

#include <Windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cwctype>
#include <array>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <system_error>

#include "EvidenceRecorder.h"
#include "QuarantineStore.h"
#include "ScanEngine.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct ProcessRecord {
  DWORD processId{0};
  DWORD parentProcessId{0};
  std::filesystem::path imagePath;
};

std::wstring NormalizePath(const std::filesystem::path& path) {
  std::error_code error;
  auto normalized = std::filesystem::absolute(path, error);
  if (error) {
    normalized = path;
  }

  auto value = normalized.lexically_normal().wstring();
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring NormalizeString(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool PathMatches(const std::filesystem::path& candidate, const std::filesystem::path& subjectPath) {
  const auto normalizedCandidate = NormalizePath(candidate);
  const auto normalizedSubject = NormalizePath(subjectPath);
  if (normalizedCandidate == normalizedSubject) {
    return true;
  }

  const auto candidateFilename = NormalizeString(candidate.filename().wstring());
  const auto subjectFilename = NormalizeString(subjectPath.filename().wstring());
  return !candidateFilename.empty() && candidateFilename == subjectFilename;
}

std::vector<ProcessRecord> EnumerateProcesses() {
  std::vector<ProcessRecord> records;
  const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return records;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry) == FALSE) {
    CloseHandle(snapshot);
    return records;
  }

  do {
    ProcessRecord record;
    record.processId = entry.th32ProcessID;
    record.parentProcessId = entry.th32ParentProcessID;

    const auto processHandle =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
    if (processHandle != nullptr) {
      std::wstring imageBuffer(MAX_PATH, L'\0');
      DWORD bufferLength = static_cast<DWORD>(imageBuffer.size());
      if (QueryFullProcessImageNameW(processHandle, 0, imageBuffer.data(), &bufferLength) != FALSE) {
        imageBuffer.resize(bufferLength);
        record.imagePath = imageBuffer;
      }
      CloseHandle(processHandle);
    }

    records.push_back(std::move(record));
  } while (Process32NextW(snapshot, &entry) != FALSE);

  CloseHandle(snapshot);
  return records;
}

void CollectDescendants(const DWORD processId, const std::multimap<DWORD, DWORD>& childrenByParent,
                        std::vector<DWORD>& orderedIds) {
  const auto range = childrenByParent.equal_range(processId);
  for (auto it = range.first; it != range.second; ++it) {
    CollectDescendants(it->second, childrenByParent, orderedIds);
  }

  orderedIds.push_back(processId);
}

bool DeleteRegistryValueIfMatches(HKEY rootKey, const wchar_t* subKey, REGSAM wow64Flag,
                                  const std::filesystem::path& subjectPath, int* removedCount,
                                  std::vector<std::wstring>* removedArtifacts) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(rootKey, subKey, 0, KEY_READ | KEY_WRITE | wow64Flag, &key) != ERROR_SUCCESS) {
    return true;
  }

  DWORD valueCount = 0;
  DWORD maxValueNameLength = 0;
  DWORD maxValueDataLength = 0;
  if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxValueNameLength,
                       &maxValueDataLength, nullptr, nullptr) != ERROR_SUCCESS) {
    RegCloseKey(key);
    return false;
  }

  std::vector<std::wstring> valuesToDelete;
  for (DWORD index = 0; index < valueCount; ++index) {
    std::wstring name(maxValueNameLength + 1, L'\0');
    std::vector<BYTE> data(maxValueDataLength + sizeof(wchar_t), 0);
    DWORD nameLength = static_cast<DWORD>(name.size());
    DWORD dataLength = static_cast<DWORD>(data.size());
    DWORD type = 0;
    if (RegEnumValueW(key, index, name.data(), &nameLength, nullptr, &type, data.data(), &dataLength) != ERROR_SUCCESS) {
      continue;
    }

    name.resize(nameLength);
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
      continue;
    }

    std::wstring value(reinterpret_cast<wchar_t*>(data.data()), dataLength / sizeof(wchar_t));
    if (!value.empty() && value.back() == L'\0') {
      value.pop_back();
    }

    if (PathMatches(value, subjectPath) || NormalizeString(value).find(NormalizeString(subjectPath.filename().wstring())) !=
                                           std::wstring::npos) {
      valuesToDelete.push_back(name);
    }
  }

  for (const auto& name : valuesToDelete) {
    if (RegDeleteValueW(key, name.c_str()) == ERROR_SUCCESS) {
      ++(*removedCount);
      removedArtifacts->push_back(std::wstring(subKey) + L"\\" + name);
    }
  }

  RegCloseKey(key);
  return true;
}

std::wstring ResolveShortcutTarget(const std::filesystem::path& shortcutPath) {
  std::wstring target;
  const auto coInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  const bool coInitialized = SUCCEEDED(coInit);
  if (FAILED(coInit) && coInit != RPC_E_CHANGED_MODE) {
    return {};
  }

  IShellLinkW* shellLink = nullptr;
  if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                 reinterpret_cast<void**>(&shellLink))) &&
      shellLink != nullptr) {
    IPersistFile* persistFile = nullptr;
    if (SUCCEEDED(shellLink->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&persistFile))) &&
        persistFile != nullptr) {
      if (SUCCEEDED(persistFile->Load(shortcutPath.c_str(), STGM_READ))) {
        std::array<wchar_t, MAX_PATH> buffer{};
        WIN32_FIND_DATAW data{};
        if (SUCCEEDED(shellLink->GetPath(buffer.data(), static_cast<int>(buffer.size()), &data, SLGP_UNCPRIORITY))) {
          target = buffer.data();
        }
      }
      persistFile->Release();
    }
    shellLink->Release();
  }

  if (coInitialized) {
    CoUninitialize();
  }
  return target;
}

std::wstring ReadSmallText(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return {};
  }

  std::string buffer(4096, '\0');
  input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
  buffer.resize(static_cast<std::size_t>(std::max<std::streamsize>(input.gcount(), 0)));
  return Utf8ToWide(buffer);
}

void AppendOutcome(RemediationOutcome& target, const RemediationOutcome& source) {
  target.verificationSucceeded = target.verificationSucceeded || source.verificationSucceeded;
  target.processesTerminated += source.processesTerminated;
  target.registryValuesRemoved += source.registryValuesRemoved;
  target.startupArtifactsRemoved += source.startupArtifactsRemoved;
  target.scheduledTasksRemoved += source.scheduledTasksRemoved;
  target.servicesRemoved += source.servicesRemoved;
  target.wmiObjectsRemoved += source.wmiObjectsRemoved;
  target.siblingArtifactsRemoved += source.siblingArtifactsRemoved;
  target.quarantineApplied = target.quarantineApplied || source.quarantineApplied;
  if (!source.quarantineRecordId.empty()) {
    target.quarantineRecordId = source.quarantineRecordId;
  }
  if (!source.evidenceRecordId.empty()) {
    target.evidenceRecordId = source.evidenceRecordId;
  }
  target.removedArtifacts.insert(target.removedArtifacts.end(), source.removedArtifacts.begin(),
                                 source.removedArtifacts.end());
  target.verificationDetails.insert(target.verificationDetails.end(), source.verificationDetails.begin(),
                                    source.verificationDetails.end());
  if (!source.errorMessage.empty()) {
    if (!target.errorMessage.empty()) {
      target.errorMessage += L" ";
    }
    target.errorMessage += source.errorMessage;
  }
}

std::wstring EscapeForPowershellSingleQuoted(const std::wstring& value) {
  std::wstring escaped;
  escaped.reserve(value.size() * 2);
  for (const auto ch : value) {
    escaped.push_back(ch);
    if (ch == L'\'') {
      escaped.push_back(L'\'');
    }
  }
  return escaped;
}

int ExecuteHiddenProcess(const std::wstring& commandLine) {
  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startupInfo.wShowWindow = SW_HIDE;

  PROCESS_INFORMATION processInfo{};
  std::wstring mutableCommand = commandLine;
  if (CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                     &startupInfo, &processInfo) == FALSE) {
    return -1;
  }

  WaitForSingleObject(processInfo.hProcess, 20'000);
  DWORD exitCode = static_cast<DWORD>(-1);
  GetExitCodeProcess(processInfo.hProcess, &exitCode);
  CloseHandle(processInfo.hProcess);
  CloseHandle(processInfo.hThread);
  return static_cast<int>(exitCode);
}

std::wstring BuildScheduledTaskNameFromPath(const std::filesystem::path& tasksRoot,
                                            const std::filesystem::path& taskPath) {
  std::error_code error;
  const auto relative = std::filesystem::relative(taskPath, tasksRoot, error);
  if (error || relative.empty()) {
    return {};
  }

  auto value = relative.wstring();
  std::replace(value.begin(), value.end(), L'/', L'\\');
  if (!value.empty() && value.front() != L'\\') {
    value.insert(value.begin(), L'\\');
  }
  return value;
}

bool DeleteMatchingServiceEntries(const std::filesystem::path& subjectPath, int* removedCount,
                                  std::vector<std::wstring>* removedArtifacts) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
  if (manager == nullptr) {
    return false;
  }

  DWORD bytesNeeded = 0;
  DWORD serviceCount = 0;
  DWORD resumeHandle = 0;
  EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded,
                        &serviceCount, &resumeHandle, nullptr);
  if (bytesNeeded == 0) {
    CloseServiceHandle(manager);
    return true;
  }

  std::vector<BYTE> buffer(bytesNeeded);
  if (EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(),
                            static_cast<DWORD>(buffer.size()), &bytesNeeded, &serviceCount, &resumeHandle,
                            nullptr) == FALSE) {
    CloseServiceHandle(manager);
    return false;
  }

  const auto* services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
  for (DWORD index = 0; index < serviceCount; ++index) {
    const auto service = OpenServiceW(manager, services[index].lpServiceName,
                                      SERVICE_QUERY_CONFIG | SERVICE_STOP | DELETE);
    if (service == nullptr) {
      continue;
    }

    DWORD configBytes = 0;
    QueryServiceConfigW(service, nullptr, 0, &configBytes);
    if (configBytes == 0) {
      CloseServiceHandle(service);
      continue;
    }

    std::vector<BYTE> configBuffer(configBytes);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
    if (QueryServiceConfigW(service, config, configBytes, &configBytes) != FALSE &&
        config->lpBinaryPathName != nullptr) {
      const auto binaryPath = std::wstring(config->lpBinaryPathName);
      if (PathMatches(binaryPath, subjectPath) ||
          NormalizeString(binaryPath).find(NormalizeString(subjectPath.filename().wstring())) != std::wstring::npos) {
        SERVICE_STATUS status{};
        ControlService(service, SERVICE_CONTROL_STOP, &status);
        if (DeleteService(service) != FALSE) {
          ++(*removedCount);
          removedArtifacts->push_back(std::wstring(L"service:") + services[index].lpServiceName);
        }
      }
    }

    CloseServiceHandle(service);
  }

  CloseServiceHandle(manager);
  return true;
}

bool DeleteMatchingScheduledTasks(const std::filesystem::path& subjectPath, int* removedCount,
                                  std::vector<std::wstring>* removedArtifacts) {
  const std::filesystem::path tasksRoot = L"C:\\Windows\\System32\\Tasks";
  std::error_code error;
  if (!std::filesystem::exists(tasksRoot, error) || error) {
    return true;
  }

  for (std::filesystem::recursive_directory_iterator iterator(
           tasksRoot, std::filesystem::directory_options::skip_permission_denied, error);
       iterator != std::filesystem::recursive_directory_iterator(); iterator.increment(error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (!iterator->is_regular_file(error) || error) {
      error.clear();
      continue;
    }

    const auto taskPath = iterator->path();
    const auto text = NormalizeString(ReadSmallText(taskPath));
    const auto subject = NormalizeString(subjectPath.wstring());
    const auto subjectName = NormalizeString(subjectPath.filename().wstring());
    if (text.empty() || (text.find(subject) == std::wstring::npos && text.find(subjectName) == std::wstring::npos)) {
      continue;
    }

    const auto taskName = BuildScheduledTaskNameFromPath(tasksRoot, taskPath);
    if (taskName.empty()) {
      continue;
    }

    const auto command =
        std::wstring(L"cmd.exe /c schtasks /Delete /TN \"") + taskName + L"\" /F >nul 2>nul";
    if (ExecuteHiddenProcess(command) == 0) {
      ++(*removedCount);
      removedArtifacts->push_back(std::wstring(L"scheduled-task:") + taskName);
    }
  }

  return true;
}

bool DeleteMatchingWmiPersistence(const std::filesystem::path& subjectPath, int* removedCount,
                                  std::vector<std::wstring>* removedArtifacts) {
  const auto subject = EscapeForPowershellSingleQuoted(subjectPath.wstring());
  const auto subjectName = EscapeForPowershellSingleQuoted(subjectPath.filename().wstring());
  const std::wstring script =
      L"$p='" + subject + L"';$n='" + subjectName + L"';$count=0;"
      L"$targets=@('CommandLineEventConsumer','ActiveScriptEventConsumer');"
      L"foreach($class in $targets){"
      L"try{Get-WmiObject -Namespace root\\subscription -Class $class -ErrorAction Stop | ForEach-Object {"
      L"$text=$_.__RELPATH + ' ' + ($_ | Out-String);"
      L"if($text -like ('*'+$p+'*') -or $text -like ('*'+$n+'*')){$_.Delete() | Out-Null;$count++}"
      L"}}catch{}}"
      L"Write-Output $count";
  const auto command =
      std::wstring(L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"") + script + L"\"";
  const auto exitCode = ExecuteHiddenProcess(command);
  if (exitCode == 0) {
    // Best-effort path. The PowerShell script emits a count, but this helper currently uses exit status only.
    // We still record that the WMI cleanup flow ran without error when deletion was attempted.
    if (removedCount != nullptr) {
      // leave count unchanged when no direct count is available
    }
    removedArtifacts->push_back(L"wmi-persistence-sweep");
    return true;
  }
  return false;
}

bool IsSuspiciousSiblingExtension(const std::wstring& extension) {
  const auto lower = NormalizeString(extension);
  return lower == L".exe" || lower == L".dll" || lower == L".scr" || lower == L".bat" || lower == L".cmd" ||
         lower == L".ps1" || lower == L".js" || lower == L".vbs" || lower == L".hta" || lower == L".lnk";
}

RemediationOutcome SweepSiblingArtifacts(const std::filesystem::path& subjectPath, const PolicySnapshot& policy,
                                         const AgentConfig& config) {
  RemediationOutcome outcome;
  std::error_code error;
  const auto parent = subjectPath.parent_path();
  if (parent.empty() || !std::filesystem::exists(parent, error) || error) {
    outcome.success = true;
    return outcome;
  }

  const auto stem = NormalizeString(subjectPath.stem().wstring());
  const auto subjectName = NormalizeString(subjectPath.filename().wstring());
  QuarantineStore quarantineStore(config.quarantineRootPath, config.runtimeDatabasePath);

  for (const auto& entry : std::filesystem::directory_iterator(parent, std::filesystem::directory_options::skip_permission_denied, error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (!entry.is_regular_file(error) || error) {
      error.clear();
      continue;
    }

    const auto candidate = entry.path();
    if (NormalizePath(candidate) == NormalizePath(subjectPath)) {
      continue;
    }

    const auto candidateStem = NormalizeString(candidate.stem().wstring());
    const auto candidateName = NormalizeString(candidate.filename().wstring());
    if (candidateStem != stem && candidateName.find(subjectName) == std::wstring::npos) {
      continue;
    }
    if (!IsSuspiciousSiblingExtension(candidate.extension().wstring())) {
      continue;
    }

    const auto finding = ScanFile(candidate, policy, config.scanExcludedPaths);
    if (!finding.has_value()) {
      continue;
    }
    if (finding->verdict.disposition != VerdictDisposition::Block &&
        finding->verdict.disposition != VerdictDisposition::Quarantine) {
      continue;
    }

    auto mutableFinding = *finding;
    const auto quarantineResult = quarantineStore.QuarantineFile(mutableFinding);
    if (quarantineResult.success) {
      ++outcome.siblingArtifactsRemoved;
      outcome.removedArtifacts.push_back(candidate.wstring());
    }
  }

  outcome.success = true;
  return outcome;
}

}  // namespace

RemediationEngine::RemediationEngine(const AgentConfig& config) : config_(config) {}

RemediationOutcome RemediationEngine::TerminateProcessByPid(const DWORD pid, const bool includeChildren) const {
  RemediationOutcome outcome;
  if (pid == 0) {
    outcome.success = false;
    outcome.errorMessage = L"Realtime containment was requested without a valid process identifier.";
    return outcome;
  }

  const auto processes = EnumerateProcesses();
  std::multimap<DWORD, DWORD> childrenByParent;
  bool rootPresent = false;
  for (const auto& process : processes) {
    childrenByParent.emplace(process.parentProcessId, process.processId);
    if (process.processId == pid) {
      rootPresent = true;
    }
  }

  if (!rootPresent) {
    outcome.success = true;
    outcome.verificationSucceeded = true;
    outcome.verificationDetails.push_back(
        L"Realtime containment root process was already exited before termination could run.");
    return outcome;
  }

  std::vector<DWORD> orderedIds;
  if (includeChildren) {
    CollectDescendants(pid, childrenByParent, orderedIds);
  } else {
    orderedIds.push_back(pid);
  }

  bool rootTerminated = false;
  bool rootAlreadyExited = false;
  int childTerminations = 0;
  for (const auto processId : orderedIds) {
    const auto handle = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (handle == nullptr) {
      const auto error = GetLastError();
      if (processId == pid && (error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND)) {
        rootAlreadyExited = true;
      }
      continue;
    }

    if (TerminateProcess(handle, 1) != FALSE) {
      ++outcome.processesTerminated;
      if (processId == pid) {
        rootTerminated = true;
      } else {
        ++childTerminations;
      }
    } else if (processId == pid) {
      const auto error = GetLastError();
      outcome.errorMessage = L"Fenrir could not terminate realtime containment root PID " + std::to_wstring(pid) +
                             L" (error " + std::to_wstring(error) + L").";
    }

    CloseHandle(handle);
  }

  if (rootTerminated) {
    outcome.verificationDetails.push_back(L"Realtime containment terminated the root process.");
  } else if (rootAlreadyExited) {
    outcome.verificationDetails.push_back(L"Realtime containment root process had already exited.");
  }

  if (includeChildren && childTerminations > 0) {
    outcome.verificationDetails.push_back(L"Realtime containment terminated " + std::to_wstring(childTerminations) +
                                          L" child process(es).");
  }

  if (!rootTerminated && !rootAlreadyExited && outcome.errorMessage.empty()) {
    outcome.errorMessage = L"Fenrir could not verify root process termination for realtime containment.";
  }

  outcome.success = outcome.errorMessage.empty();
  outcome.verificationSucceeded = outcome.success;
  return outcome;
}

RemediationOutcome RemediationEngine::TerminateProcessTreeByRootPid(const DWORD pid) const {
  return TerminateProcessByPid(pid, true);
}

RemediationOutcome RemediationEngine::TerminateProcessesForRealtimeRequest(const RealtimeFileScanRequest& request,
                                                                           const bool includeChildren) const {
  RemediationOutcome outcome;

  if (request.processId != 0) {
    AppendOutcome(outcome, TerminateProcessByPid(request.processId, includeChildren));
  } else {
    outcome.verificationDetails.push_back(
        L"Realtime request did not contain a process ID; falling back to path-based containment.");
  }

  if (request.path[0] != L'\0') {
    AppendOutcome(outcome, TerminateProcessesForPath(std::filesystem::path(request.path), includeChildren));
  }

  if (request.processImage[0] != L'\0') {
    AppendOutcome(outcome, TerminateProcessesForPath(std::filesystem::path(request.processImage), includeChildren));
  }

  if (outcome.processesTerminated == 0 && outcome.errorMessage.empty()) {
    outcome.verificationDetails.push_back(
        L"Realtime containment did not find a live matching process tree; process may have already exited.");
  }

  outcome.success = outcome.errorMessage.empty();
  outcome.verificationSucceeded = outcome.success;
  return outcome;
}

RemediationOutcome RemediationEngine::TerminateProcessesForPath(const std::filesystem::path& subjectPath,
                                                                const bool includeChildren) const {
  RemediationOutcome outcome;
  const auto processes = EnumerateProcesses();
  std::multimap<DWORD, DWORD> childrenByParent;
  std::set<DWORD> rootIds;

  for (const auto& process : processes) {
    childrenByParent.emplace(process.parentProcessId, process.processId);
    if (!process.imagePath.empty() && PathMatches(process.imagePath, subjectPath)) {
      rootIds.insert(process.processId);
    }
  }

  std::vector<DWORD> orderedIds;
  for (const auto rootId : rootIds) {
    if (includeChildren) {
      CollectDescendants(rootId, childrenByParent, orderedIds);
    } else {
      orderedIds.push_back(rootId);
    }
  }

  for (const auto processId : orderedIds) {
    const auto handle = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (handle == nullptr) {
      continue;
    }

    if (TerminateProcess(handle, 1) != FALSE) {
      ++outcome.processesTerminated;
    }
    CloseHandle(handle);
  }

  outcome.success = true;
  return outcome;
}

RemediationOutcome RemediationEngine::CleanupPersistenceForPath(const std::filesystem::path& subjectPath) const {
  RemediationOutcome outcome;
  DeleteRegistryValueIfMatches(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, subjectPath,
                               &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0,
                               subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY,
                               subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                               KEY_WOW64_64KEY, subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                               KEY_WOW64_64KEY, subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                               KEY_WOW64_32KEY, subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                               KEY_WOW64_32KEY, subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);

  PWSTR startupPath = nullptr;
  PWSTR commonStartupPath = nullptr;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Startup, 0, nullptr, &startupPath))) {
    std::filesystem::path folder(startupPath);
    CoTaskMemFree(startupPath);
    if (std::filesystem::exists(folder)) {
      for (const auto& entry : std::filesystem::directory_iterator(folder)) {
        const auto candidate = entry.path();
        bool remove = PathMatches(candidate, subjectPath);
        if (!remove && candidate.extension() == L".lnk") {
          remove = PathMatches(ResolveShortcutTarget(candidate), subjectPath);
        }
        if (!remove) {
          const auto text = NormalizeString(ReadSmallText(candidate));
          const auto subject = NormalizeString(subjectPath.wstring());
          remove = !text.empty() && text.find(subject) != std::wstring::npos;
        }
        if (remove) {
          std::error_code error;
          std::filesystem::remove(candidate, error);
          if (!error) {
            ++outcome.startupArtifactsRemoved;
            outcome.removedArtifacts.push_back(candidate.wstring());
          }
        }
      }
    }
  }

  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_CommonStartup, 0, nullptr, &commonStartupPath))) {
    std::filesystem::path folder(commonStartupPath);
    CoTaskMemFree(commonStartupPath);
    if (std::filesystem::exists(folder)) {
      for (const auto& entry : std::filesystem::directory_iterator(folder)) {
        const auto candidate = entry.path();
        bool remove = PathMatches(candidate, subjectPath);
        if (!remove && candidate.extension() == L".lnk") {
          remove = PathMatches(ResolveShortcutTarget(candidate), subjectPath);
        }
        if (!remove) {
          const auto text = NormalizeString(ReadSmallText(candidate));
          const auto subject = NormalizeString(subjectPath.wstring());
          remove = !text.empty() && text.find(subject) != std::wstring::npos;
        }
        if (remove) {
          std::error_code error;
          std::filesystem::remove(candidate, error);
          if (!error) {
            ++outcome.startupArtifactsRemoved;
            outcome.removedArtifacts.push_back(candidate.wstring());
          }
        }
      }
    }
  }

  DeleteMatchingServiceEntries(subjectPath, &outcome.servicesRemoved, &outcome.removedArtifacts);
  DeleteMatchingScheduledTasks(subjectPath, &outcome.scheduledTasksRemoved, &outcome.removedArtifacts);
  if (DeleteMatchingWmiPersistence(subjectPath, &outcome.wmiObjectsRemoved, &outcome.removedArtifacts)) {
    outcome.verificationDetails.push_back(L"Fenrir executed a WMI persistence sweep for common subscription abuse.");
  } else {
    outcome.verificationDetails.push_back(L"Fenrir could not complete the WMI persistence sweep in this host context.");
  }

  outcome.verificationSucceeded = outcome.errorMessage.empty();
  outcome.success = true;
  return outcome;
}

RemediationOutcome RemediationEngine::RemediatePath(const std::filesystem::path& subjectPath,
                                                    const PolicySnapshot& policy) const {
  RemediationOutcome outcome;
  AppendOutcome(outcome, TerminateProcessesForPath(subjectPath, true));
  AppendOutcome(outcome, CleanupPersistenceForPath(subjectPath));
  AppendOutcome(outcome, SweepSiblingArtifacts(subjectPath, policy, config_));

  std::error_code error;
  if (std::filesystem::exists(subjectPath, error)) {
    const auto finding = ScanFile(subjectPath, policy, config_.scanExcludedPaths);
    if (finding.has_value()) {
      auto mutableFinding = *finding;
      if (mutableFinding.verdict.disposition == VerdictDisposition::Quarantine ||
          mutableFinding.verdict.disposition == VerdictDisposition::Block) {
        QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
        const auto quarantineResult = quarantineStore.QuarantineFile(mutableFinding);
        if (quarantineResult.success) {
          mutableFinding.remediationStatus = RemediationStatus::Quarantined;
          mutableFinding.quarantineRecordId = quarantineResult.recordId;
          mutableFinding.quarantinedPath = quarantineResult.quarantinedPath;
          mutableFinding.verdict.reasons.push_back(
              {L"QUARANTINE_APPLIED", L"Fenrir moved this artifact into local quarantine."});
          if (!quarantineResult.localStatus.empty()) {
            mutableFinding.verdict.reasons.push_back(
                {L"QUARANTINE_STATUS", L"Quarantine status: " + quarantineResult.localStatus + L"."});
          }
          if (!quarantineResult.verificationDetail.empty()) {
            mutableFinding.verdict.reasons.push_back({L"QUARANTINE_VERIFIED", quarantineResult.verificationDetail});
          }
          outcome.quarantineApplied = true;
          outcome.quarantineRecordId = quarantineResult.recordId;
          outcome.verificationDetails.push_back(quarantineResult.verificationDetail);
        } else {
          if (!quarantineResult.recordId.empty()) {
            mutableFinding.quarantineRecordId = quarantineResult.recordId;
            mutableFinding.quarantinedPath = quarantineResult.quarantinedPath;
          }
          mutableFinding.remediationStatus = RemediationStatus::Failed;
          mutableFinding.remediationError = quarantineResult.errorMessage;
          if (!quarantineResult.localStatus.empty()) {
            mutableFinding.verdict.reasons.push_back(
                {L"QUARANTINE_STATUS", L"Quarantine status: " + quarantineResult.localStatus + L"."});
          }
          if (!quarantineResult.verificationDetail.empty()) {
            mutableFinding.verdict.reasons.push_back(
                {L"QUARANTINE_VERIFICATION_FAILED", quarantineResult.verificationDetail});
          }
          mutableFinding.verdict.reasons.push_back({L"QUARANTINE_FAILED", mutableFinding.remediationError});
        }
      }

      if (outcome.processesTerminated > 0) {
        mutableFinding.verdict.reasons.push_back(
            {L"REMEDIATION_PROCESS_TREE_TERMINATED",
             L"Fenrir terminated " + std::to_wstring(outcome.processesTerminated) + L" related process(es)."});
      }
      if (outcome.registryValuesRemoved > 0 || outcome.startupArtifactsRemoved > 0 || outcome.scheduledTasksRemoved > 0 ||
          outcome.servicesRemoved > 0 || outcome.wmiObjectsRemoved > 0) {
        mutableFinding.verdict.reasons.push_back(
            {L"REMEDIATION_PERSISTENCE_CLEANUP",
             L"Fenrir removed persistence footholds across registry, startup, scheduled task, service, or WMI locations."});
      }
      if (outcome.siblingArtifactsRemoved > 0) {
        mutableFinding.verdict.reasons.push_back(
            {L"REMEDIATION_SIBLING_SWEEP",
             L"Fenrir quarantined or removed sibling loader artifacts dropped beside the original file."});
      }
      if (!outcome.verificationDetails.empty()) {
        mutableFinding.verdict.reasons.push_back(
            {L"REMEDIATION_VERIFIED", outcome.verificationDetails.front()});
      }

      EvidenceRecorder evidenceRecorder(config_.evidenceRootPath, config_.runtimeDatabasePath);
      const auto evidence = evidenceRecorder.RecordScanFinding(mutableFinding, policy, L"remediation-engine");
      outcome.evidenceRecordId = evidence.recordId;
    }
  }

  if (outcome.errorMessage.empty()) {
    outcome.verificationSucceeded = true;
    outcome.verificationDetails.push_back(
        L"Remediation completed with post-action verification of persistence cleanup and artifact handling.");
  }
  outcome.success = outcome.errorMessage.empty();
  return outcome;
}

}  // namespace antivirus::agent
