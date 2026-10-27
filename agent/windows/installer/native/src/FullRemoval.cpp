// Full removal: everything Fenrir leaves on a Windows device, including the folders it locks to SYSTEM.
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <evntrace.h>
#include <fwpmu.h>
#include <lm.h>
#include <sddl.h>
#include <setupapi.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "FullRemoval.h"

namespace fenrir::setup {
namespace {

constexpr GUID kAgentWfpProviderKey = {0x51d9501d, 0x6b2f, 0x4cd0, {0xa1, 0x4f, 0x28, 0x13, 0x5e, 0x77, 0x8d, 0x10}};
constexpr GUID kAgentWfpSubLayerKey = {0x89b894f1, 0x25b0, 0x4dc6, {0x9b, 0xcb, 0x15, 0x7e, 0x4e, 0xf6, 0x40, 0x63}};
constexpr wchar_t kAmsiClsid[] = L"{7EE9F29E-3E5B-4D44-9B48-33A25F0D2C61}";
constexpr wchar_t kBreakGlassAccount[] = L"FenrirBreakGlass";
constexpr wchar_t kRunValueName[] = L"FenrirEndpointClient";
constexpr wchar_t kTempHive[] = L"FenrirRemovalHive";

// Machine registry trees Fenrir (and its pre-rename "AntiVirus" builds) create.
const std::vector<std::wstring> kMachineKeys = {
    L"SOFTWARE\\FenrirAgent",
    L"SOFTWARE\\AntiVirusAgent",
    L"SOFTWARE\\Fenrir",
    L"SOFTWARE\\WOW6432Node\\FenrirAgent",
    L"SOFTWARE\\WOW6432Node\\AntiVirusAgent",
    L"SOFTWARE\\WOW6432Node\\Fenrir",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FenrirEndpoint",
    L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FenrirEndpoint",
    std::wstring(L"SOFTWARE\\Microsoft\\AMSI\\Providers\\") + kAmsiClsid,
    std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + kAmsiClsid,
    std::wstring(L"SOFTWARE\\WOW6432Node\\Classes\\CLSID\\") + kAmsiClsid,
    L"SYSTEM\\CurrentControlSet\\Services\\FenrirAgent",
    L"SYSTEM\\CurrentControlSet\\Services\\AntivirusMinifilter",
    L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\FenrirAgent",
};

// Per-user trees (relative to a user hive root).
const std::vector<std::wstring> kUserKeys = {L"Software\\FenrirAgent", L"Software\\AntiVirusAgent", L"Software\\Fenrir",
                                             L"Software\\Fenrir Endpoint"};
const std::vector<std::wstring> kRunKeys = {
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
};

// Per-user folders under %LOCALAPPDATA%.
const std::vector<std::wstring> kUserLocalFolders = {L"FenrirAgent", L"AntiVirusAgent", L"Fenrir Endpoint", L"Fenrir"};

std::wstring Lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  return value;
}

std::wstring Env(const wchar_t* name) {
  std::array<wchar_t, 32768> buffer{};
  const auto length = GetEnvironmentVariableW(name, buffer.data(), static_cast<DWORD>(buffer.size()));
  return length > 0 && length < buffer.size() ? std::wstring(buffer.data(), length) : std::wstring();
}

std::filesystem::path SystemDirectory() {
  std::array<wchar_t, MAX_PATH> buffer{};
  const auto length = GetSystemDirectoryW(buffer.data(), MAX_PATH);
  return length > 0 ? std::filesystem::path(std::wstring(buffer.data(), length)) : std::filesystem::path(L"C:\\Windows\\System32");
}

bool RunHidden(const std::filesystem::path& exe, const std::wstring& args, DWORD timeoutMs, DWORD* exitCode) {
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION process{};
  std::wstring commandLine = L"\"" + exe.wstring() + L"\" " + args;
  if (!CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
    return false;
  }
  CloseHandle(process.hThread);
  const auto waited = WaitForSingleObject(process.hProcess, timeoutMs);
  DWORD code = 1;
  if (waited == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &code);
  CloseHandle(process.hProcess);
  if (exitCode) *exitCode = code;
  return waited == WAIT_OBJECT_0;
}

bool EnablePrivilege(const wchar_t* name) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
  TOKEN_PRIVILEGES privileges{};
  privileges.PrivilegeCount = 1;
  privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  const bool ok = LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid) &&
                  AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
  CloseHandle(token);
  return ok;
}

struct WellKnownSids {
  std::array<BYTE, SECURITY_MAX_SID_SIZE> admins{};
  std::array<BYTE, SECURITY_MAX_SID_SIZE> system{};
  WellKnownSids() {
    DWORD size = SECURITY_MAX_SID_SIZE;
    CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins.data(), &size);
    size = SECURITY_MAX_SID_SIZE;
    CreateWellKnownSid(WinLocalSystemSid, nullptr, system.data(), &size);
  }
};

// Owner = Administrators, DACL = Administrators + SYSTEM full control, inheritance re-enabled.
bool Reclaim(const std::wstring& objectName, SE_OBJECT_TYPE type, bool container) {
  static WellKnownSids sids;
  SetNamedSecurityInfoW(const_cast<LPWSTR>(objectName.c_str()), type, OWNER_SECURITY_INFORMATION, sids.admins.data(), nullptr,
                        nullptr, nullptr);
  std::array<EXPLICIT_ACCESSW, 2> entries{};
  const DWORD inherit = container ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
  for (std::size_t i = 0; i < entries.size(); ++i) {
    entries[i].grfAccessPermissions = GENERIC_ALL;
    entries[i].grfAccessMode = SET_ACCESS;
    entries[i].grfInheritance = inherit;
    entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[i].Trustee.TrusteeType = i == 0 ? TRUSTEE_IS_GROUP : TRUSTEE_IS_USER;
    entries[i].Trustee.ptstrName = reinterpret_cast<LPWSTR>(i == 0 ? sids.admins.data() : sids.system.data());
  }
  PACL acl = nullptr;
  if (SetEntriesInAclW(static_cast<ULONG>(entries.size()), entries.data(), nullptr, &acl) != ERROR_SUCCESS) return false;
  const auto status = SetNamedSecurityInfoW(const_cast<LPWSTR>(objectName.c_str()), type,
                                            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl,
                                            nullptr);
  LocalFree(acl);
  return status == ERROR_SUCCESS;
}

bool IsLink(const std::filesystem::path& path) {
  const auto attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

void ReclaimTree(const std::filesystem::path& path) {
  const bool link = IsLink(path);
  std::error_code error;
  const bool directory = !link && std::filesystem::is_directory(path, error);
  Reclaim(path.wstring(), SE_FILE_OBJECT, directory);
  SetFileAttributesW(path.c_str(), directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL);
  if (!directory) return;
  for (std::filesystem::directory_iterator it(path, std::filesystem::directory_options::skip_permission_denied, error), end;
       !error && it != end; it.increment(error)) {
    ReclaimTree(it->path());
  }
}

void DeleteOrSchedule(const std::filesystem::path& path, RemovalReport& report) {
  const bool link = IsLink(path);
  std::error_code error;
  const bool directory = std::filesystem::is_directory(path, error);
  if (directory && !link) {
    for (std::filesystem::directory_iterator it(path, std::filesystem::directory_options::skip_permission_denied, error), end;
         !error && it != end; it.increment(error)) {
      DeleteOrSchedule(it->path(), report);
    }
  }
  const bool removed = directory ? RemoveDirectoryW(path.c_str()) != FALSE : DeleteFileW(path.c_str()) != FALSE;
  if (removed) {
    ++report.removed;
  } else if (std::filesystem::exists(path, error) &&
             MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE) {
    ++report.pendingReboot;
  }
}

// Recursive registry delete that reclaims keys Fenrir protected before retrying.
void ReclaimRegistryTree(HKEY root, const std::wstring& rootName, const std::wstring& subKey) {
  Reclaim(rootName + L"\\" + subKey, SE_REGISTRY_KEY, true);
  HKEY key = nullptr;
  if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &key) != ERROR_SUCCESS) return;
  std::vector<std::wstring> children;
  std::array<wchar_t, 256> name{};
  for (DWORD index = 0;; ++index) {
    DWORD length = static_cast<DWORD>(name.size());
    if (RegEnumKeyExW(key, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
    children.emplace_back(name.data(), length);
  }
  RegCloseKey(key);
  for (const auto& child : children) ReclaimRegistryTree(root, rootName, subKey + L"\\" + child);
}

bool KeyExists(HKEY root, const std::wstring& subKey) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) return false;
  RegCloseKey(key);
  return true;
}

void DeleteKey(HKEY root, const std::wstring& rootName, const std::wstring& subKey, RemovalReport& report, const RemovalLog& log) {
  if (!KeyExists(root, subKey)) return;
  auto status = RegDeleteTreeW(root, subKey.c_str());
  if (status == ERROR_SUCCESS) status = RegDeleteKeyW(root, subKey.c_str());
  if (status == ERROR_ACCESS_DENIED || KeyExists(root, subKey)) {
    ReclaimRegistryTree(root, rootName, subKey);
    RegDeleteTreeW(root, subKey.c_str());
    RegDeleteKeyW(root, subKey.c_str());
  }
  if (KeyExists(root, subKey)) {
    ++report.warnings;
    log(L"Warning: could not delete registry key " + rootName + L"\\" + subKey);
  } else {
    ++report.removed;
    log(L"Removed registry key " + rootName + L"\\" + subKey);
  }
}

void DeleteValue(HKEY root, const std::wstring& subKey, const wchar_t* value, RemovalReport& report) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) return;
  if (RegDeleteValueW(key, value) == ERROR_SUCCESS) ++report.removed;
  RegCloseKey(key);
}

struct Profile {
  std::wstring sid;
  std::filesystem::path path;
};

std::vector<Profile> UserProfiles() {
  std::vector<Profile> profiles;
  HKEY list = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0, KEY_READ, &list) !=
      ERROR_SUCCESS) {
    return profiles;
  }
  std::array<wchar_t, 256> name{};
  for (DWORD index = 0;; ++index) {
    DWORD length = static_cast<DWORD>(name.size());
    if (RegEnumKeyExW(list, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
    const std::wstring sid(name.data(), length);
    std::array<wchar_t, MAX_PATH> raw{};
    DWORD bytes = sizeof(raw);
    if (RegGetValueW(list, sid.c_str(), L"ProfileImagePath", RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr, raw.data(),
                     &bytes) != ERROR_SUCCESS) {
      continue;
    }
    std::array<wchar_t, MAX_PATH> expanded{};
    if (ExpandEnvironmentStringsW(raw.data(), expanded.data(), MAX_PATH) == 0) continue;
    profiles.push_back({sid, std::filesystem::path(expanded.data())});
  }
  RegCloseKey(list);
  return profiles;
}

void PurgeUsers(RemovalReport& report, const RemovalLog& log) {
  for (const auto& profile : UserProfiles()) {
    for (const auto& folder : kUserLocalFolders) {
      ForceDeleteTree(profile.path / L"AppData" / L"Local" / folder, report, log);
    }
    if (profile.sid.rfind(L"S-1-5-21-", 0) != 0) continue;  // service profiles have no Fenrir user settings
    HKEY loaded = nullptr;
    if (RegOpenKeyExW(HKEY_USERS, profile.sid.c_str(), 0, KEY_READ, &loaded) == ERROR_SUCCESS) {
      RegCloseKey(loaded);
      for (const auto& key : kUserKeys) DeleteKey(HKEY_USERS, L"USER", profile.sid + L"\\" + key, report, log);
      for (const auto& run : kRunKeys) DeleteValue(HKEY_USERS, profile.sid + L"\\" + run, kRunValueName, report);
      continue;
    }
    // Signed-out user: load their hive just long enough to clean it.
    const auto hiveFile = profile.path / L"NTUSER.DAT";
    std::error_code error;
    if (!std::filesystem::exists(hiveFile, error)) continue;
    if (RegLoadKeyW(HKEY_USERS, kTempHive, hiveFile.c_str()) != ERROR_SUCCESS) continue;
    for (const auto& key : kUserKeys) DeleteKey(HKEY_USERS, L"USER", std::wstring(kTempHive) + L"\\" + key, report, log);
    for (const auto& run : kRunKeys) DeleteValue(HKEY_USERS, std::wstring(kTempHive) + L"\\" + run, kRunValueName, report);
    RegUnLoadKeyW(HKEY_USERS, kTempHive);
  }
}

void StopEtwSessions(RemovalReport& report, const RemovalLog& log) {
  constexpr ULONG kMax = 64;
  constexpr ULONG kNameBytes = 1024 * sizeof(wchar_t);
  const ULONG propertySize = sizeof(EVENT_TRACE_PROPERTIES) + 2 * kNameBytes;
  std::vector<std::vector<BYTE>> buffers(kMax, std::vector<BYTE>(propertySize));
  std::array<PEVENT_TRACE_PROPERTIES, kMax> sessions{};
  for (ULONG i = 0; i < kMax; ++i) {
    auto* properties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffers[i].data());
    properties->Wnode.BufferSize = propertySize;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    properties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + kNameBytes;
    sessions[i] = properties;
  }
  ULONG count = 0;
  if (QueryAllTracesW(sessions.data(), kMax, &count) != ERROR_SUCCESS) return;
  for (ULONG i = 0; i < count; ++i) {
    const std::wstring name(reinterpret_cast<wchar_t*>(buffers[i].data() + sessions[i]->LoggerNameOffset));
    const auto lower = Lower(name);
    if (lower.rfind(L"fenrir", 0) != 0 && lower.rfind(L"antivirusprocessetw-", 0) != 0) continue;
    std::vector<BYTE> stop(propertySize);
    auto* properties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(stop.data());
    properties->Wnode.BufferSize = propertySize;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    if (ControlTraceW(0, name.c_str(), properties, EVENT_TRACE_CONTROL_STOP) == ERROR_SUCCESS) {
      ++report.removed;
      log(L"Stopped event trace session " + name);
    }
  }
}

void RemoveWfp(RemovalReport& report, const RemovalLog& log) {
  HANDLE engine = nullptr;
  if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine) != ERROR_SUCCESS) return;
  HANDLE enumHandle = nullptr;
  std::vector<UINT64> ids;
  if (FwpmFilterCreateEnumHandle0(engine, nullptr, &enumHandle) == ERROR_SUCCESS) {
    FWPM_FILTER0** filters = nullptr;
    UINT32 returned = 0;
    while (FwpmFilterEnum0(engine, enumHandle, 512, &filters, &returned) == ERROR_SUCCESS && returned > 0) {
      for (UINT32 i = 0; i < returned; ++i) {
        const auto* filter = filters[i];
        const bool ours = (filter->providerKey && IsEqualGUID(*filter->providerKey, kAgentWfpProviderKey)) ||
                          IsEqualGUID(filter->subLayerKey, kAgentWfpSubLayerKey);
        if (ours) ids.push_back(filter->filterId);
      }
      FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
      if (returned < 512) break;
    }
    FwpmFilterDestroyEnumHandle0(engine, enumHandle);
  }
  for (const auto id : ids) {
    if (FwpmFilterDeleteById0(engine, id) == ERROR_SUCCESS) ++report.removed;
  }
  FwpmSubLayerDeleteByKey0(engine, &kAgentWfpSubLayerKey);
  FwpmProviderDeleteByKey0(engine, &kAgentWfpProviderKey);
  FwpmEngineClose0(engine);
  if (!ids.empty()) log(L"Removed " + std::to_wstring(ids.size()) + L" network filter(s) (isolation and destination blocking)");
}

// The minifilter's driver package is published in the driver store as oemNN.inf; find it by content, not by
// pnputil's localised output.
void RemoveDriverPackages(RemovalReport& report, const RemovalLog& log) {
  const auto infDirectory = std::filesystem::path(Env(L"WINDIR").empty() ? L"C:\\Windows" : Env(L"WINDIR")) / L"INF";
  std::error_code error;
  for (std::filesystem::directory_iterator it(infDirectory, error), end; !error && it != end; it.increment(error)) {
    const auto name = Lower(it->path().filename().wstring());
    if (name.rfind(L"oem", 0) != 0 || it->path().extension() != L".inf") continue;
    std::ifstream file(it->path(), std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::string lowered = content;
    lowered.erase(std::remove(lowered.begin(), lowered.end(), '\0'), lowered.end());  // UTF-16 INFs
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lowered.find("antivirusminifilter") == std::string::npos) continue;
    if (SetupUninstallOEMInfW(it->path().filename().c_str(), SUOI_FORCEDELETE, nullptr)) {
      ++report.removed;
      log(L"Removed driver package " + it->path().filename().wstring() + L" from the driver store");
    } else {
      ++report.warnings;
      log(L"Warning: could not remove driver package " + it->path().filename().wstring());
    }
  }
  const auto driverFile = SystemDirectory() / L"drivers" / L"AntivirusMinifilter.sys";
  if (std::filesystem::exists(driverFile, error)) DeleteOrSchedule(driverFile, report);
}

void RemoveServiceRegistration(const wchar_t* name, RemovalReport& report, const RemovalLog& log) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) return;
  const auto service = OpenServiceW(manager, name, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
  if (service) {
    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    if (DeleteService(service)) {
      ++report.removed;
      log(std::wstring(L"Removed service ") + name);
    }
    CloseServiceHandle(service);
  }
  CloseServiceHandle(manager);
}

void RemoveBreakGlassAccount(RemovalReport& report, const RemovalLog& log) {
  const auto status = NetUserDel(nullptr, kBreakGlassAccount);
  if (status == NERR_Success) {
    ++report.removed;
    log(L"Removed the FenrirBreakGlass local account");
  }
}

// Firewall rules, scheduled tasks and the policy settings Fenrir applied, through PowerShell (no stable native API
// for task folders and firewall rule groups).
void RunPowerShellCleanup(RemovalReport& report, const RemovalLog& log) {
  const std::wstring script =
      L"$ErrorActionPreference='SilentlyContinue';"
      L"Get-NetFirewallRule -Group 'Fenrir policy' | Remove-NetFirewallRule;"
      L"Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'Fenrir *' -or $_.DisplayName -like 'AntiVirus *' } | Remove-NetFirewallRule;"
      L"Get-ScheduledTask -TaskPath '\\Fenrir\\' | Unregister-ScheduledTask -Confirm:$false;"
      L"try { $s = New-Object -ComObject Schedule.Service; $s.Connect(); $s.GetFolder('\\').DeleteFolder('Fenrir', 0) } catch { };"
      // Device control: Fenrir blocked removable storage through these policy values; give the device back.
      L"$rs='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices';"
      L"foreach ($c in '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}','{53f56308-b6bf-11d0-94f2-00a0c91efb8b}','{6AC27878-A6FA-4155-BA85-F98F491D4F33}','{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}') {"
      L"  foreach ($v in 'Deny_Read','Deny_Write','Deny_Execute') { Remove-ItemProperty -Path \"$rs\\$c\" -Name $v };"
      L"  if ((Get-Item \"$rs\\$c\").ValueCount -eq 0 -and (Get-Item \"$rs\\$c\").SubKeyCount -eq 0) { Remove-Item \"$rs\\$c\" } };"
      L"if ((Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR').Start -eq 4) { Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start -Value 3 };"
      L"Remove-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Policies\\Microsoft\\FVE' -Name RDVDenyWriteAccess;"
      // LLMNR/NetBIOS: undo only if Fenrir's marker says it changed them.
      L"if ((Get-ItemProperty 'HKLM:\\SOFTWARE\\Fenrir\\PolicyHardening').LlmnrNetbios -eq 1) {"
      L"  Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast;"
      L"  Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 0 } };"
      L"exit 0";
  DWORD exitCode = 1;
  const auto powershell = SystemDirectory() / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe";
  if (RunHidden(powershell, L"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + script + L"\"", 120'000, &exitCode) &&
      exitCode == 0) {
    log(L"Removed Fenrir firewall rules and scheduled tasks, and restored USB/LLMNR settings Fenrir changed");
  } else {
    ++report.warnings;
    log(L"Warning: firewall rule / scheduled task cleanup did not finish");
  }
}

}  // namespace

void EnableRemovalPrivileges() {
  for (const auto* name : {SE_TAKE_OWNERSHIP_NAME, SE_RESTORE_NAME, SE_BACKUP_NAME, SE_SECURITY_NAME}) EnablePrivilege(name);
}

void ForceDeleteTree(const std::filesystem::path& root, RemovalReport& report, const RemovalLog& log) {
  std::error_code error;
  if (root.empty() || !std::filesystem::exists(root, error)) return;
  // Never touch a drive root or the Windows/ProgramData/Users folders themselves.
  if (root == root.root_path() || root.filename().empty()) return;
  const auto before = report.pendingReboot;
  if (!IsLink(root)) {
    std::filesystem::remove_all(root, error);
    if (!std::filesystem::exists(root)) {
      ++report.removed;
      log(L"Deleted " + root.wstring());
      return;
    }
    ReclaimTree(root);  // locked to SYSTEM (quarantine, evidence) or read-only
  }
  DeleteOrSchedule(root, report);
  if (!std::filesystem::exists(root, error)) {
    log(L"Deleted " + root.wstring());
  } else if (report.pendingReboot > before) {
    log(L"Some files in " + root.wstring() + L" are in use; they will be deleted when Windows restarts");
  } else {
    ++report.warnings;
    log(L"Warning: could not delete " + root.wstring());
  }
}

void PurgeMachineState(const std::filesystem::path& installRoot, RemovalReport& report, const RemovalLog& log) {
  EnableRemovalPrivileges();
  StopEtwSessions(report, log);
  RemoveWfp(report, log);
  RemoveServiceRegistration(L"FenrirAgent", report, log);
  RemoveServiceRegistration(L"AntivirusMinifilter", report, log);
  RemoveDriverPackages(report, log);
  RunPowerShellCleanup(report, log);
  RemoveBreakGlassAccount(report, log);

  const auto programData = std::filesystem::path(Env(L"ProgramData").empty() ? L"C:\\ProgramData" : Env(L"ProgramData"));
  for (const auto* folder : {L"FenrirAgent", L"AntiVirusAgent", L"Fenrir", L"Fenrir Endpoint"}) {
    ForceDeleteTree(programData / folder, report, log);
  }
  ForceDeleteTree(programData / L"Microsoft" / L"Windows" / L"Start Menu" / L"Programs" / L"Fenrir", report, log);
  ForceDeleteTree(programData / L"Microsoft" / L"Windows" / L"Start Menu" / L"Programs" / L"Fenrir Endpoint", report, log);
  // A previous version installed under Program Files (x86) or a custom folder; the current one is removed by the
  // cleanup helper once setup exits.
  for (const auto* variable : {L"ProgramFiles", L"ProgramFiles(x86)"}) {
    const auto base = Env(variable);
    if (base.empty()) continue;
    const auto candidate = std::filesystem::path(base) / L"Fenrir Endpoint";
    std::error_code error;
    if (!std::filesystem::equivalent(candidate, installRoot, error)) ForceDeleteTree(candidate, report, log);
  }

  PurgeUsers(report, log);
  for (const auto& key : kMachineKeys) DeleteKey(HKEY_LOCAL_MACHINE, L"MACHINE", key, report, log);
  for (const auto& run : kRunKeys) DeleteValue(HKEY_LOCAL_MACHINE, run, kRunValueName, report);
}

}  // namespace fenrir::setup
