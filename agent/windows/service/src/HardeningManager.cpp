#include "HardeningManager.h"

#include <Windows.h>
#include <aclapi.h>

#include <array>
#include <filesystem>
#include <vector>

#include "CryptoUtils.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kRegistryRoot[] = L"SOFTWARE\\FenrirAgent";
constexpr wchar_t kLegacyRegistryRoot[] = L"SOFTWARE\\AntiVirusAgent";
constexpr wchar_t kRuntimeRootValueName[] = L"RuntimeRoot";
constexpr wchar_t kServiceLaunchProtectedValueName[] = L"LaunchProtectedConfigured";
constexpr wchar_t kServiceControlProtectedValueName[] = L"ServiceControlProtected";
constexpr wchar_t kElamCertificateInstalledValueName[] = L"ElamCertificateInstalled";
constexpr wchar_t kElamDriverPathValueName[] = L"ElamDriverPath";

struct ServiceLaunchProtectedInfoCompat {
  DWORD dwLaunchProtected;
};

enum class UsersAccessMode {
  None,
  ReadExecute,
  Modify
};

std::wstring HashToken(const std::wstring& token) {
  const auto utf8 = WideToUtf8(token);
  const auto* bytes = reinterpret_cast<const unsigned char*>(utf8.data());
  return ComputeBufferSha256(bytes, utf8.size());
}

bool CreateKnownSid(const WELL_KNOWN_SID_TYPE type, std::array<BYTE, SECURITY_MAX_SID_SIZE>& buffer, PSID* sid) {
  DWORD size = static_cast<DWORD>(buffer.size());
  if (CreateWellKnownSid(type, nullptr, buffer.data(), &size) == FALSE) {
    return false;
  }

  *sid = buffer.data();
  return true;
}

DWORD UsersAccessMask(const UsersAccessMode mode) {
  switch (mode) {
    case UsersAccessMode::ReadExecute:
      return GENERIC_READ | GENERIC_EXECUTE;
    case UsersAccessMode::Modify:
      return GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE;
    case UsersAccessMode::None:
    default:
      return 0;
  }
}

bool ApplyProtectedAcl(const std::filesystem::path& path, const UsersAccessMode usersAccessMode,
                       const bool includeAdministrators, std::wstring* errorMessage) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not create " + path.wstring();
    }
    return false;
  }

  std::array<BYTE, SECURITY_MAX_SID_SIZE> systemBuffer{};
  std::array<BYTE, SECURITY_MAX_SID_SIZE> usersBuffer{};
  PSID systemSid = nullptr;
  PSID usersSid = nullptr;
  std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsBuffer{};
  PSID administratorsSid = nullptr;
  if (!CreateKnownSid(WinLocalSystemSid, systemBuffer, &systemSid) ||
      (includeAdministrators && !CreateKnownSid(WinBuiltinAdministratorsSid, administratorsBuffer, &administratorsSid)) ||
      (usersAccessMode != UsersAccessMode::None && !CreateKnownSid(WinBuiltinUsersSid, usersBuffer, &usersSid))) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not resolve well-known SIDs for ACL hardening";
    }
    return false;
  }

  std::vector<EXPLICIT_ACCESSW> entries;
  entries.reserve((includeAdministrators ? 1U : 0U) + 1U + (usersAccessMode != UsersAccessMode::None ? 1U : 0U));

  if (includeAdministrators) {
    EXPLICIT_ACCESSW administratorsAccess{};
    administratorsAccess.grfAccessPermissions = GENERIC_ALL;
    administratorsAccess.grfAccessMode = SET_ACCESS;
    administratorsAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    administratorsAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    administratorsAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    administratorsAccess.Trustee.ptstrName = static_cast<LPWSTR>(administratorsSid);
    entries.push_back(administratorsAccess);
  }

  EXPLICIT_ACCESSW systemAccess{};
  systemAccess.grfAccessPermissions = GENERIC_ALL;
  systemAccess.grfAccessMode = SET_ACCESS;
  systemAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  systemAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  systemAccess.Trustee.TrusteeType = TRUSTEE_IS_USER;
  systemAccess.Trustee.ptstrName = static_cast<LPWSTR>(systemSid);
  entries.push_back(systemAccess);

  if (usersAccessMode != UsersAccessMode::None) {
    EXPLICIT_ACCESSW usersAccess{};
    usersAccess.grfAccessPermissions = UsersAccessMask(usersAccessMode);
    usersAccess.grfAccessMode = SET_ACCESS;
    usersAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    usersAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    usersAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    usersAccess.Trustee.ptstrName = static_cast<LPWSTR>(usersSid);
    entries.push_back(usersAccess);
  }

  PACL acl = nullptr;
  const auto aclStatus = SetEntriesInAclW(static_cast<ULONG>(entries.size()), entries.data(), nullptr, &acl);
  if (aclStatus != ERROR_SUCCESS) {
    if (errorMessage != nullptr) {
      *errorMessage = L"SetEntriesInAclW failed";
    }
    return false;
  }

  const auto securityStatus = SetNamedSecurityInfoW(
      const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
  LocalFree(acl);

  if (securityStatus != ERROR_SUCCESS) {
    if (errorMessage != nullptr) {
      *errorMessage = L"SetNamedSecurityInfoW failed for " + path.wstring();
    }
    return false;
  }

  return true;
}

bool WriteRegistryString(HKEY key, const wchar_t* name, const std::wstring& value) {
  return RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

bool WriteRegistryDword(HKEY key, const wchar_t* name, const DWORD value) {
  return RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value)) == ERROR_SUCCESS;
}

DWORD ReadRegistryDword(HKEY key, const wchar_t* name, const DWORD fallback = 0) {
  DWORD type = 0;
  DWORD value = fallback;
  DWORD bytes = sizeof(value);
  if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &bytes) != ERROR_SUCCESS ||
      type != REG_DWORD) {
    return fallback;
  }
  return value;
}

std::wstring ReadRegistryString(HKEY key, const wchar_t* name) {
  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || type != REG_SZ || bytes == 0) {
    return {};
  }

  std::wstring value(bytes / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &bytes) != ERROR_SUCCESS) {
    return {};
  }

  if (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }
  return value;
}

bool ApplyRegistryAcl(HKEY key, const bool allowUsersRead) {
  std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsBuffer{};
  std::array<BYTE, SECURITY_MAX_SID_SIZE> systemBuffer{};
  std::array<BYTE, SECURITY_MAX_SID_SIZE> usersBuffer{};
  PSID administratorsSid = nullptr;
  PSID systemSid = nullptr;
  PSID usersSid = nullptr;
  if (!CreateKnownSid(WinBuiltinAdministratorsSid, administratorsBuffer, &administratorsSid) ||
      !CreateKnownSid(WinLocalSystemSid, systemBuffer, &systemSid) ||
      (allowUsersRead && !CreateKnownSid(WinBuiltinUsersSid, usersBuffer, &usersSid))) {
    return false;
  }

  std::vector<EXPLICIT_ACCESSW> entries;
  entries.resize(allowUsersRead ? 3 : 2);

  entries[0].grfAccessPermissions = KEY_ALL_ACCESS;
  entries[0].grfAccessMode = SET_ACCESS;
  entries[0].grfInheritance = CONTAINER_INHERIT_ACE;
  entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entries[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  entries[0].Trustee.ptstrName = static_cast<LPWSTR>(administratorsSid);

  entries[1].grfAccessPermissions = KEY_ALL_ACCESS;
  entries[1].grfAccessMode = SET_ACCESS;
  entries[1].grfInheritance = CONTAINER_INHERIT_ACE;
  entries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entries[1].Trustee.TrusteeType = TRUSTEE_IS_USER;
  entries[1].Trustee.ptstrName = static_cast<LPWSTR>(systemSid);

  if (allowUsersRead) {
    entries[2].grfAccessPermissions = KEY_READ;
    entries[2].grfAccessMode = SET_ACCESS;
    entries[2].grfInheritance = CONTAINER_INHERIT_ACE;
    entries[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    entries[2].Trustee.ptstrName = static_cast<LPWSTR>(usersSid);
  }

  PACL acl = nullptr;
  if (SetEntriesInAclW(static_cast<ULONG>(entries.size()), entries.data(), nullptr, &acl) != ERROR_SUCCESS) {
    return false;
  }

  const auto status = SetSecurityInfo(key, SE_REGISTRY_KEY,
                                      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                      acl, nullptr);
  LocalFree(acl);
  return status == ERROR_SUCCESS;
}

bool PersistRegistryDwordValue(const wchar_t* valueName, const DWORD value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegistryRoot, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE,
                      nullptr, &key, nullptr) != ERROR_SUCCESS) {
    return false;
  }

  const auto wroteValue = WriteRegistryDword(key, valueName, value);
  const auto aclApplied = ApplyRegistryAcl(key, true);
  RegCloseKey(key);
  return wroteValue && aclApplied;
}

HKEY OpenHardeningRegistryKeyForRead() {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegistryRoot, 0, KEY_READ, &key) == ERROR_SUCCESS) {
    return key;
  }

  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kLegacyRegistryRoot, 0, KEY_READ, &key) == ERROR_SUCCESS) {
    return key;
  }

  return nullptr;
}

bool QueryServiceLaunchProtected(const std::wstring& serviceName, bool* configured) {
  if (configured != nullptr) {
    *configured = false;
  }

  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    return false;
  }

  const auto service = OpenServiceW(manager, serviceName.c_str(), SERVICE_QUERY_CONFIG);
  if (service == nullptr) {
    CloseServiceHandle(manager);
    return false;
  }

  DWORD bytesNeeded = 0;
  QueryServiceConfig2W(service, SERVICE_CONFIG_LAUNCH_PROTECTED, nullptr, 0, &bytesNeeded);
  if (bytesNeeded == 0) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return false;
  }

  std::vector<BYTE> buffer(bytesNeeded, 0);
  const auto ok =
      QueryServiceConfig2W(service, SERVICE_CONFIG_LAUNCH_PROTECTED, buffer.data(), bytesNeeded, &bytesNeeded) != FALSE;
  if (ok) {
    const auto* info = reinterpret_cast<const ServiceLaunchProtectedInfoCompat*>(buffer.data());
    if (configured != nullptr) {
      *configured = info->dwLaunchProtected == SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
    }
  }

  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return ok;
}

bool InstallElamCertificateInfoCompat(HANDLE elamFileHandle) {
  using InstallElamCertificateInfoFn = BOOL(WINAPI*)(HANDLE);
  const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
  if (kernel32 == nullptr) {
    SetLastError(ERROR_MOD_NOT_FOUND);
    return FALSE;
  }

  const auto installFn =
      reinterpret_cast<InstallElamCertificateInfoFn>(GetProcAddress(kernel32, "InstallELAMCertificateInfo"));
  if (installFn == nullptr) {
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
  }

  return installFn(elamFileHandle);
}

}  // namespace

HardeningManager::HardeningManager(const AgentConfig& config, std::filesystem::path installRoot)
    : config_(config), installRoot_(std::move(installRoot)) {}

bool HardeningManager::ApplyPostInstallHardening(const std::wstring& uninstallToken, std::wstring* errorMessage) const {
  std::wstring localError;

  if (!ApplyProtectedAcl(installRoot_, UsersAccessMode::ReadExecute, true, &localError) ||
      !ApplyProtectedAcl(config_.runtimeDatabasePath.parent_path(), UsersAccessMode::Modify, true, &localError) ||
      !ApplyProtectedAcl(config_.quarantineRootPath, UsersAccessMode::None, false, &localError) ||
      !ApplyProtectedAcl(config_.evidenceRootPath, UsersAccessMode::None, true, &localError) ||
      !ApplyProtectedAcl(config_.updateRootPath, UsersAccessMode::None, true, &localError)) {
    if (errorMessage != nullptr) {
      *errorMessage = localError;
    }
    return false;
  }

  HKEY key = nullptr;
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegistryRoot, 0, nullptr, REG_OPTION_NON_VOLATILE,
                      KEY_READ | KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not create the Fenrir anti-tamper registry root";
    }
    return false;
  }

  const auto tokenHash = uninstallToken.empty() ? std::wstring{} : HashToken(uninstallToken);
  const auto success =
      WriteRegistryString(key, L"InstallRoot", installRoot_.wstring()) &&
      WriteRegistryString(key, kRuntimeRootValueName, config_.runtimeDatabasePath.parent_path().wstring()) &&
      WriteRegistryString(key, L"RuntimeDatabasePath", config_.runtimeDatabasePath.wstring()) &&
      WriteRegistryString(key, L"AgentVersion", config_.agentVersion) &&
      WriteRegistryString(key, L"ProtectedAt", CurrentUtcTimestamp()) &&
      WriteRegistryString(key, kElamDriverPathValueName, config_.elamDriverPath.wstring()) &&
      WriteRegistryString(key, L"UninstallTokenSha256", tokenHash) &&
      WriteRegistryDword(key, L"UninstallProtectionEnabled", tokenHash.empty() ? 0 : 1) &&
      WriteRegistryDword(key, kServiceControlProtectedValueName, 0) &&
      WriteRegistryDword(key, kElamCertificateInstalledValueName, 0) &&
      WriteRegistryDword(key, kServiceLaunchProtectedValueName, 0);
  const auto aclApplied = ApplyRegistryAcl(key, true);
  RegCloseKey(key);

  if (!success || !aclApplied) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not persist tamper-protection settings";
    }
    return false;
  }

  return true;
}

bool HardeningManager::ApplyServiceControlProtection(const std::wstring& serviceName, SC_HANDLE serviceHandle,
                                                     std::wstring* errorMessage, const bool locked) const {
  SC_HANDLE manager = nullptr;
  SC_HANDLE ownedService = nullptr;
  if (serviceHandle == nullptr) {
    manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Could not connect to the Service Control Manager to harden service permissions.";
      }
      return false;
    }

    ownedService = OpenServiceW(manager, serviceName.c_str(), READ_CONTROL | WRITE_DAC);
    if (ownedService == nullptr) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Could not open the protection service to apply stop-control protection.";
      }
      CloseServiceHandle(manager);
      return false;
    }

    serviceHandle = ownedService;
  }

  std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsBuffer{};
  std::array<BYTE, SECURITY_MAX_SID_SIZE> systemBuffer{};
  std::array<BYTE, SECURITY_MAX_SID_SIZE> usersBuffer{};
  PSID administratorsSid = nullptr;
  PSID systemSid = nullptr;
  PSID usersSid = nullptr;
  if (!CreateKnownSid(WinBuiltinAdministratorsSid, administratorsBuffer, &administratorsSid) ||
      !CreateKnownSid(WinLocalSystemSid, systemBuffer, &systemSid) ||
      !CreateKnownSid(WinBuiltinUsersSid, usersBuffer, &usersSid)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not resolve service-control SIDs for service hardening.";
    }
    if (ownedService != nullptr) {
      CloseServiceHandle(ownedService);
    }
    if (manager != nullptr) {
      CloseServiceHandle(manager);
    }
    return false;
  }

  std::array<EXPLICIT_ACCESSW, 3> entries{};

  entries[0].grfAccessPermissions =
      locked ? (SERVICE_ALL_ACCESS & ~(SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_CHANGE_CONFIG | DELETE))
             : SERVICE_ALL_ACCESS;
  entries[0].grfAccessMode = SET_ACCESS;
  entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entries[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  entries[0].Trustee.ptstrName = static_cast<LPWSTR>(administratorsSid);

  entries[1].grfAccessPermissions = SERVICE_ALL_ACCESS;
  entries[1].grfAccessMode = SET_ACCESS;
  entries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entries[1].Trustee.TrusteeType = TRUSTEE_IS_USER;
  entries[1].Trustee.ptstrName = static_cast<LPWSTR>(systemSid);

  entries[2].grfAccessPermissions = SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_START | READ_CONTROL;
  entries[2].grfAccessMode = SET_ACCESS;
  entries[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entries[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  entries[2].Trustee.ptstrName = static_cast<LPWSTR>(usersSid);

  PACL acl = nullptr;
  const auto aclStatus = SetEntriesInAclW(static_cast<ULONG>(entries.size()), entries.data(), nullptr, &acl);
  if (aclStatus != ERROR_SUCCESS) {
    if (errorMessage != nullptr) {
      *errorMessage = L"SetEntriesInAclW failed while securing service stop permissions.";
    }
    if (ownedService != nullptr) {
      CloseServiceHandle(ownedService);
    }
    if (manager != nullptr) {
      CloseServiceHandle(manager);
    }
    return false;
  }

  const auto securityStatus = SetSecurityInfo(serviceHandle, SE_SERVICE,
                                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                              nullptr, acl, nullptr);
  LocalFree(acl);

  if (ownedService != nullptr) {
    CloseServiceHandle(ownedService);
  }
  if (manager != nullptr) {
    CloseServiceHandle(manager);
  }

  if (securityStatus != ERROR_SUCCESS) {
    if (errorMessage != nullptr) {
      *errorMessage = L"SetSecurityInfo failed while preventing standard users from stopping the service.";
    }
    PersistRegistryDwordValue(kServiceControlProtectedValueName, 0);
    return false;
  }

  PersistRegistryDwordValue(kServiceControlProtectedValueName, locked ? 1 : 0);
  return true;
}

bool HardeningManager::ApplyProtectedServiceRegistration(const std::wstring& serviceName, SC_HANDLE serviceHandle,
                                                         const std::filesystem::path& elamDriverPath,
                                                         std::wstring* errorMessage) const {
  if (serviceHandle == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The service handle was not available for launch-protected registration.";
    }
    return false;
  }

  if (elamDriverPath.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"No ELAM driver path was provided for launch-protected service registration.";
    }
    return false;
  }

  std::error_code error;
  if (!std::filesystem::exists(elamDriverPath, error) || error) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The ELAM driver was not found at " + elamDriverPath.wstring();
    }
    return false;
  }

  const auto elamHandle =
      CreateFileW(elamDriverPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                  nullptr);
  if (elamHandle == INVALID_HANDLE_VALUE) {
    if (errorMessage != nullptr) {
      *errorMessage = L"CreateFileW failed while opening the ELAM driver.";
    }
    return false;
  }

  const auto certificateInstalled = InstallElamCertificateInfoCompat(elamHandle) != FALSE;
  CloseHandle(elamHandle);
  if (!certificateInstalled) {
    if (errorMessage != nullptr) {
      *errorMessage = L"InstallELAMCertificateInfo failed for the ELAM driver.";
    }
    return false;
  }

  ServiceLaunchProtectedInfoCompat launchProtected{};
  launchProtected.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
  if (ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_LAUNCH_PROTECTED, &launchProtected) == FALSE) {
    if (errorMessage != nullptr) {
      *errorMessage = L"ChangeServiceConfig2W(SERVICE_CONFIG_LAUNCH_PROTECTED) failed for " + serviceName + L".";
    }
    return false;
  }

  HKEY key = nullptr;
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegistryRoot, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE,
                      nullptr, &key, nullptr) == ERROR_SUCCESS) {
    WriteRegistryString(key, kElamDriverPathValueName, elamDriverPath.wstring());
    WriteRegistryDword(key, kElamCertificateInstalledValueName, 1);
    WriteRegistryDword(key, kServiceLaunchProtectedValueName, 1);
    ApplyRegistryAcl(key, true);
    RegCloseKey(key);
  }

  return true;
}

bool HardeningManager::ValidateUninstallAuthorization(const std::wstring& uninstallToken,
                                                      std::wstring* errorMessage) const {
  HKEY key = OpenHardeningRegistryKeyForRead();
  if (key == nullptr) {
    return true;
  }

  const auto expectedHash = ReadRegistryString(key, L"UninstallTokenSha256");
  RegCloseKey(key);
  if (expectedHash.empty()) {
    return true;
  }

  if (uninstallToken.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Uninstall protection is enabled and requires a valid token.";
    }
    return false;
  }

  if (HashToken(uninstallToken) != expectedHash) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The provided uninstall token did not match the protected endpoint policy.";
    }
    return false;
  }

  return true;
}

HardeningStatus HardeningManager::QueryStatus(const std::wstring& serviceName) const {
  HardeningStatus status;
  HKEY key = OpenHardeningRegistryKeyForRead();
  if (key != nullptr) {
    status.registryConfigured = true;
    status.uninstallTokenHash = ReadRegistryString(key, L"UninstallTokenSha256");
    status.uninstallProtectionEnabled = !status.uninstallTokenHash.empty();
    status.serviceControlProtected = ReadRegistryDword(key, kServiceControlProtectedValueName, 0) != 0;
    status.elamDriverPath = ReadRegistryString(key, kElamDriverPathValueName);
    status.elamCertificateInstalled = ReadRegistryDword(key, kElamCertificateInstalledValueName, 0) != 0;
    status.launchProtectedConfigured = ReadRegistryDword(key, kServiceLaunchProtectedValueName, 0) != 0;
    RegCloseKey(key);
  }

  const auto runtimeValidation = ValidateRuntimePaths(config_);
  const auto effectiveInstallRoot = runtimeValidation.installRootPath.empty() ? installRoot_ : runtimeValidation.installRootPath;
  status.installPathProtected = std::filesystem::exists(effectiveInstallRoot);
  status.runtimePathsTrusted = runtimeValidation.trusted;
  status.runtimePathsProtected = status.runtimePathsTrusted && std::filesystem::exists(runtimeValidation.runtimeRootPath) &&
                                 std::filesystem::exists(config_.quarantineRootPath) &&
                                 std::filesystem::exists(config_.evidenceRootPath) &&
                                 std::filesystem::exists(config_.journalRootPath) &&
                                 std::filesystem::exists(config_.updateRootPath);
  const auto effectiveElamPath =
      !config_.elamDriverPath.empty() ? config_.elamDriverPath : std::filesystem::path(status.elamDriverPath);
  status.elamDriverPresent = !effectiveElamPath.empty() && std::filesystem::exists(effectiveElamPath);

  bool queriedLaunchProtected = false;
  if (QueryServiceLaunchProtected(serviceName, &queriedLaunchProtected)) {
    status.launchProtectedConfigured = queriedLaunchProtected;
  }

  if (!status.runtimePathsTrusted) {
    status.statusMessage = runtimeValidation.message.empty()
                             ? L"Runtime path boundaries are not trusted."
                             : runtimeValidation.message;
  } else {
    status.statusMessage =
        status.registryConfigured && status.runtimePathsProtected && status.serviceControlProtected
            ? (status.launchProtectedConfigured
                   ? L"Tamper protection, trusted runtime path boundaries, service stop-hardening, ELAM-backed certificate registration, and launch-protected service posture are configured."
                   : L"Tamper protection, trusted runtime path boundaries, and service stop-hardening are configured, but launch-protected service registration is not yet active.")
            : L"Tamper-protection is only partially configured.";
  }
  return status;
}

}  // namespace antivirus::agent
