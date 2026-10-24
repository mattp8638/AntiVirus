#include "LocalSecurity.h"

#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <cwctype>
#include <optional>
#include <set>
#include <vector>

namespace antivirus::agent {

namespace {

constexpr wchar_t kRegistryRoot[] = L"SOFTWARE\\FenrirAgent";
constexpr wchar_t kLegacyRegistryRoot[] = L"SOFTWARE\\AntiVirusAgent";
constexpr wchar_t kOwnerSidValueName[] = L"DeviceOwnerSid";
constexpr wchar_t kBreakGlassEnabledValueName[] = L"BreakGlassEnabled";
constexpr wchar_t kTrustedHouseholdSidsValueName[] = L"HouseholdTrustedSids";
constexpr wchar_t kRestrictedHouseholdSidsValueName[] = L"HouseholdRestrictedSids";
constexpr std::size_t kMaxHouseholdRoleSidEntries = 256;

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool ParseBooleanValue(const std::wstring& rawValue, const bool fallback) {
  if (rawValue.empty()) {
    return fallback;
  }

  const auto lower = ToLowerCopy(rawValue);
  if (lower == L"1" || lower == L"true" || lower == L"yes" || lower == L"on") {
    return true;
  }
  if (lower == L"0" || lower == L"false" || lower == L"no" || lower == L"off") {
    return false;
  }

  return fallback;
}

std::vector<std::wstring> SplitSidList(const std::wstring& value) {
  std::vector<std::wstring> values;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == L';' || ch == L',') {
      if (!current.empty()) {
        values.push_back(current);
        current.clear();
      }
      continue;
    }
    if (ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n') {
      continue;
    }
    current.push_back(ch);
  }

  if (!current.empty()) {
    values.push_back(current);
  }

  return values;
}

std::wstring TrimSidToken(std::wstring value) {
  value.erase(std::remove_if(value.begin(), value.end(),
                             [](const wchar_t ch) {
                               return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
                             }),
              value.end());
  return value;
}

std::optional<std::wstring> CanonicalizeSidToken(const std::wstring& sidToken) {
  const auto trimmed = TrimSidToken(sidToken);
  if (trimmed.empty()) {
    return std::nullopt;
  }

  PSID parsedSid = nullptr;
  if (ConvertStringSidToSidW(trimmed.c_str(), &parsedSid) == FALSE || parsedSid == nullptr) {
    return std::nullopt;
  }

  LPWSTR canonicalSid = nullptr;
  if (ConvertSidToStringSidW(parsedSid, &canonicalSid) == FALSE || canonicalSid == nullptr) {
    LocalFree(parsedSid);
    return std::nullopt;
  }

  std::wstring normalized(canonicalSid);
  LocalFree(canonicalSid);
  LocalFree(parsedSid);
  return normalized;
}

std::vector<std::wstring> NormalizeSidTokens(const std::vector<std::wstring>& values) {
  std::vector<std::wstring> normalized;
  std::set<std::wstring> dedupe;
  for (const auto& value : values) {
    const auto canonicalSid = CanonicalizeSidToken(value);
    if (!canonicalSid.has_value()) {
      continue;
    }

    const auto sidLower = ToLowerCopy(*canonicalSid);
    if (dedupe.insert(sidLower).second) {
      normalized.push_back(*canonicalSid);
    }
  }

  return normalized;
}

std::wstring JoinSidList(const std::vector<std::wstring>& values) {
  std::wstring joined;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      joined += L";";
    }
    joined += values[index];
  }

  return joined;
}

bool WriteRegistryStringToRoot(const HKEY hive, const wchar_t* rootPath, const wchar_t* valueName,
                               const std::wstring& value);

bool WriteRegistryValueWithFallback(const HKEY hive, const wchar_t* valueName, const std::wstring& value) {
  return WriteRegistryStringToRoot(hive, kRegistryRoot, valueName, value) ||
         WriteRegistryStringToRoot(hive, kLegacyRegistryRoot, valueName, value);
}

bool NormalizeHouseholdRolePolicy(const HouseholdRolePolicySnapshot& input, const bool requireOwnerSid,
                                  HouseholdRolePolicySnapshot* normalized, std::wstring* errorMessage) {
  if (normalized == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir household role propagation did not receive a destination snapshot.";
    }
    return false;
  }

  normalized->ownerSid.clear();
  normalized->trustedHouseholdSids.clear();
  normalized->restrictedHouseholdSids.clear();

  if (input.trustedHouseholdSids.size() > kMaxHouseholdRoleSidEntries ||
      input.restrictedHouseholdSids.size() > kMaxHouseholdRoleSidEntries) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir household role policy exceeds the maximum supported SID entry count.";
    }
    return false;
  }

  if (!TrimSidToken(input.ownerSid).empty()) {
    const auto canonicalOwner = CanonicalizeSidToken(input.ownerSid);
    if (!canonicalOwner.has_value()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir household role policy owner SID is not a valid Windows SID.";
      }
      return false;
    }

    normalized->ownerSid = *canonicalOwner;
  } else if (requireOwnerSid) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir requires a valid owner SID before applying household role propagation.";
    }
    return false;
  }

  std::set<std::wstring> trustedLower;
  for (const auto& sid : input.trustedHouseholdSids) {
    const auto canonicalSid = CanonicalizeSidToken(sid);
    if (!canonicalSid.has_value()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir household trusted SID list contains an invalid SID entry.";
      }
      return false;
    }

    const auto sidLower = ToLowerCopy(*canonicalSid);
    if (trustedLower.insert(sidLower).second) {
      normalized->trustedHouseholdSids.push_back(*canonicalSid);
    }
  }

  std::set<std::wstring> restrictedLower;
  for (const auto& sid : input.restrictedHouseholdSids) {
    const auto canonicalSid = CanonicalizeSidToken(sid);
    if (!canonicalSid.has_value()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir household restricted SID list contains an invalid SID entry.";
      }
      return false;
    }

    const auto sidLower = ToLowerCopy(*canonicalSid);
    if (restrictedLower.insert(sidLower).second) {
      normalized->restrictedHouseholdSids.push_back(*canonicalSid);
    }
  }

  for (const auto& sidLower : trustedLower) {
    if (restrictedLower.find(sidLower) != restrictedLower.end()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir household role policy cannot place the same SID in both trusted and restricted sets.";
      }
      return false;
    }
  }

  if (!normalized->ownerSid.empty() && restrictedLower.find(ToLowerCopy(normalized->ownerSid)) != restrictedLower.end()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir household role policy cannot place the owner SID into the restricted household set.";
    }
    return false;
  }

  return true;
}

bool OpenEffectiveToken(const DWORD accessMask, HANDLE* token) {
  if (token == nullptr) {
    return false;
  }

  *token = nullptr;
  if (OpenThreadToken(GetCurrentThread(), accessMask, TRUE, token) != FALSE) {
    return true;
  }

  if (GetLastError() != ERROR_NO_TOKEN) {
    return false;
  }

  return OpenProcessToken(GetCurrentProcess(), accessMask, token) != FALSE;
}

std::optional<bool> IsCurrentTokenInAdministratorsGroup() {
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
  PSID administratorsGroup = nullptr;
  BOOL isMember = FALSE;
  if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0,
                               0, &administratorsGroup) == FALSE) {
    return std::nullopt;
  }

  const auto membershipChecked = CheckTokenMembership(nullptr, administratorsGroup, &isMember) != FALSE;
  FreeSid(administratorsGroup);
  if (!membershipChecked) {
    return std::nullopt;
  }

  return isMember != FALSE;
}

std::wstring ReadRegistryStringFromRoot(const HKEY hive, const wchar_t* rootPath, const wchar_t* valueName) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(hive, rootPath, 0, KEY_READ, &key) != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || type != REG_SZ ||
      bytes == 0) {
    RegCloseKey(key);
    return {};
  }

  std::wstring value(bytes / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &bytes) !=
      ERROR_SUCCESS) {
    RegCloseKey(key);
    return {};
  }

  RegCloseKey(key);
  while (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }

  return value;
}

bool WriteRegistryStringToRoot(const HKEY hive, const wchar_t* rootPath, const wchar_t* valueName,
                               const std::wstring& value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(hive, rootPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &key,
                      nullptr) != ERROR_SUCCESS) {
    return false;
  }

  const auto status = RegSetValueExW(key, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                                     static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
  RegCloseKey(key);
  return status == ERROR_SUCCESS;
}

std::wstring ReadDeviceOwnerSid() {
  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    const auto sid = ReadRegistryStringFromRoot(hive, kRegistryRoot, kOwnerSidValueName);
    if (!sid.empty()) {
      return sid;
    }

    const auto legacySid = ReadRegistryStringFromRoot(hive, kLegacyRegistryRoot, kOwnerSidValueName);
    if (!legacySid.empty()) {
      return legacySid;
    }
  }

  return {};
}

std::vector<std::wstring> ReadHouseholdSidList(const wchar_t* valueName) {
  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    const auto list = ReadRegistryStringFromRoot(hive, kRegistryRoot, valueName);
    if (!list.empty()) {
      return NormalizeSidTokens(SplitSidList(list));
    }

    const auto legacyList = ReadRegistryStringFromRoot(hive, kLegacyRegistryRoot, valueName);
    if (!legacyList.empty()) {
      return NormalizeSidTokens(SplitSidList(legacyList));
    }
  }

  return {};
}

bool IsSidInList(const std::wstring& sid, const std::vector<std::wstring>& values) {
  if (sid.empty()) {
    return false;
  }

  return std::any_of(values.begin(), values.end(), [&sid](const std::wstring& candidate) {
    return !candidate.empty() && _wcsicmp(candidate.c_str(), sid.c_str()) == 0;
  });
}

bool IsBreakGlassEnabled() {
  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    const auto current = ReadRegistryStringFromRoot(hive, kRegistryRoot, kBreakGlassEnabledValueName);
    if (!current.empty()) {
      return ParseBooleanValue(current, false);
    }

    const auto legacy = ReadRegistryStringFromRoot(hive, kLegacyRegistryRoot, kBreakGlassEnabledValueName);
    if (!legacy.empty()) {
      return ParseBooleanValue(legacy, false);
    }
  }

  return false;
}

void PersistDeviceOwnerSid(const std::wstring& sid) {
  if (sid.empty()) {
    return;
  }

  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    if (WriteRegistryStringToRoot(hive, kRegistryRoot, kOwnerSidValueName, sid)) {
      return;
    }
  }
}

std::wstring ResolveDeviceOwnerSid(const std::wstring& currentUserSid) {
  auto ownerSid = ReadDeviceOwnerSid();
  if (!ownerSid.empty()) {
    return ownerSid;
  }

  if (currentUserSid.empty() || !IsCurrentTokenElevated()) {
    return {};
  }

  PersistDeviceOwnerSid(currentUserSid);
  return ReadDeviceOwnerSid();
}

bool IsAdminRole(const LocalUserRole role) {
  return role == LocalUserRole::DeviceOwnerAdmin || role == LocalUserRole::BreakGlassAdmin ||
         role == LocalUserRole::LocalAdmin;
}

}  // namespace

LocalUserRole QueryCurrentLocalUserRole() {
  const auto adminMembership = IsCurrentTokenInAdministratorsGroup();
  if (!adminMembership.has_value()) {
    return LocalUserRole::Unknown;
  }

  const auto currentSid = QueryCurrentUserSid();

  if (!(*adminMembership)) {
    const auto restrictedHouseholdSids = ReadHouseholdSidList(kRestrictedHouseholdSidsValueName);
    if (IsSidInList(currentSid, restrictedHouseholdSids)) {
      return LocalUserRole::HouseholdRestrictedUser;
    }

    const auto trustedHouseholdSids = ReadHouseholdSidList(kTrustedHouseholdSidsValueName);
    if (IsSidInList(currentSid, trustedHouseholdSids)) {
      return LocalUserRole::HouseholdTrustedUser;
    }

    return LocalUserRole::StandardUser;
  }

  const auto ownerSid = ResolveDeviceOwnerSid(currentSid);
  if (!ownerSid.empty() && !currentSid.empty() && _wcsicmp(ownerSid.c_str(), currentSid.c_str()) == 0) {
    return LocalUserRole::DeviceOwnerAdmin;
  }

  if (IsBreakGlassEnabled()) {
    return LocalUserRole::BreakGlassAdmin;
  }

  return LocalUserRole::LocalAdmin;
}

bool IsCurrentUserElevatedAdmin() {
  return IsCurrentTokenElevated() && IsAdminRole(QueryCurrentLocalUserRole());
}

bool QueryBreakGlassModeEnabled() {
  return IsBreakGlassEnabled();
}

bool SetBreakGlassModeEnabled(const bool enabled, std::wstring* errorMessage) {
  const auto value = enabled ? L"1" : L"0";
  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    if (WriteRegistryStringToRoot(hive, kRegistryRoot, kBreakGlassEnabledValueName, value) ||
        WriteRegistryStringToRoot(hive, kLegacyRegistryRoot, kBreakGlassEnabledValueName, value)) {
      return true;
    }
  }

  if (errorMessage != nullptr) {
    *errorMessage = L"Fenrir could not persist break-glass mode state to local policy registry hives.";
  }
  return false;
}

bool IsCurrentTokenElevated() {
  HANDLE token = nullptr;
  if (!OpenEffectiveToken(TOKEN_QUERY, &token)) {
    return false;
  }

  TOKEN_ELEVATION elevation{};
  DWORD bytesReturned = 0;
  auto elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytesReturned) != FALSE &&
                  elevation.TokenIsElevated != 0;
  CloseHandle(token);
  if (elevated) {
    return true;
  }

  // During named-pipe impersonation, the effective caller can be an elevated admin
  // even when TokenElevation is not reported like a primary process token.
  const auto adminMembership = IsCurrentTokenInAdministratorsGroup();
  return adminMembership.has_value() && *adminMembership;
}

std::wstring QueryCurrentUserSid() {
  HANDLE token = nullptr;
  if (!OpenEffectiveToken(TOKEN_QUERY, &token)) {
    return {};
  }

  DWORD bytesNeeded = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &bytesNeeded);
  if (bytesNeeded == 0) {
    CloseHandle(token);
    return {};
  }

  std::vector<BYTE> buffer(bytesNeeded);
  if (GetTokenInformation(token, TokenUser, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesNeeded) == FALSE) {
    CloseHandle(token);
    return {};
  }

  const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  LPWSTR sidString = nullptr;
  if (ConvertSidToStringSidW(tokenUser->User.Sid, &sidString) == FALSE || sidString == nullptr) {
    CloseHandle(token);
    return {};
  }

  std::wstring sid(sidString);
  LocalFree(sidString);
  CloseHandle(token);
  return sid;
}

std::wstring QueryConfiguredDeviceOwnerSid() {
  return ReadDeviceOwnerSid();
}

HouseholdRolePolicySnapshot QueryHouseholdRolePolicySnapshot() {
  HouseholdRolePolicySnapshot snapshot{};
  snapshot.ownerSid = ReadDeviceOwnerSid();
  snapshot.trustedHouseholdSids = ReadHouseholdSidList(kTrustedHouseholdSidsValueName);
  snapshot.restrictedHouseholdSids = ReadHouseholdSidList(kRestrictedHouseholdSidsValueName);
  return snapshot;
}

bool ValidateHouseholdRolePolicySnapshot(const HouseholdRolePolicySnapshot& snapshot, std::wstring* errorMessage) {
  HouseholdRolePolicySnapshot normalized;
  return NormalizeHouseholdRolePolicy(snapshot, false, &normalized, errorMessage);
}

bool SetHouseholdRolePolicySnapshot(const HouseholdRolePolicySnapshot& snapshot, const bool persistOwnerSid,
                                    std::wstring* errorMessage) {
  HouseholdRolePolicySnapshot normalized;
  if (!NormalizeHouseholdRolePolicy(snapshot, persistOwnerSid, &normalized, errorMessage)) {
    return false;
  }

  const auto trustedJoined = JoinSidList(normalized.trustedHouseholdSids);
  const auto restrictedJoined = JoinSidList(normalized.restrictedHouseholdSids);
  auto trustedPersisted = false;
  auto restrictedPersisted = false;
  auto ownerPersisted = !persistOwnerSid;

  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    if (!trustedPersisted) {
      trustedPersisted = WriteRegistryValueWithFallback(hive, kTrustedHouseholdSidsValueName, trustedJoined);
    }

    if (!restrictedPersisted) {
      restrictedPersisted = WriteRegistryValueWithFallback(hive, kRestrictedHouseholdSidsValueName, restrictedJoined);
    }

    if (persistOwnerSid && !ownerPersisted) {
      ownerPersisted = WriteRegistryValueWithFallback(hive, kOwnerSidValueName, normalized.ownerSid);
    }
  }

  if (trustedPersisted && restrictedPersisted && ownerPersisted) {
    return true;
  }

  if (errorMessage != nullptr) {
    *errorMessage = L"Fenrir could not persist one or more household role policy values to local registry policy roots.";
  }
  return false;
}

std::wstring LocalUserRoleToString(const LocalUserRole role) {
  switch (role) {
    case LocalUserRole::DeviceOwnerAdmin:
      return L"device_owner_admin";
    case LocalUserRole::BreakGlassAdmin:
      return L"break_glass_admin";
    case LocalUserRole::LocalAdmin:
      return L"local_admin";
    case LocalUserRole::HouseholdTrustedUser:
      return L"household_trusted_user";
    case LocalUserRole::HouseholdRestrictedUser:
      return L"household_restricted_user";
    case LocalUserRole::StandardUser:
      return L"standard_user";
    default:
      return L"unknown";
  }
}

LocalActionAuthorization AuthorizeCurrentUser(const LocalAction action) {
  const auto role = QueryCurrentLocalUserRole();
  const auto elevated = IsCurrentTokenElevated();
  const auto isAdmin = IsAdminRole(role);
  const auto isOwner = role == LocalUserRole::DeviceOwnerAdmin;
  const auto isBreakGlass = role == LocalUserRole::BreakGlassAdmin;
  const auto isTrustedHouseholdUser = role == LocalUserRole::HouseholdTrustedUser;
  const auto isRestrictedHouseholdUser = role == LocalUserRole::HouseholdRestrictedUser;

  switch (action) {
    case LocalAction::ViewStatus:
      return LocalActionAuthorization{
          .role = role,
          .allowed = true,
          .requestOnly = false,
          .reason = L"Local status and update posture inspection are available to all local users."};

    case LocalAction::PatchRefresh:
      if (isRestrictedHouseholdUser) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = false,
            .requestOnly = true,
            .reason = L"This household profile requires owner approval before requesting patch posture refresh actions."};
      }
      return LocalActionAuthorization{
          .role = role,
          .allowed = true,
          .requestOnly = false,
          .reason = L"Local patch posture refresh is available for trusted household and standard users."};

    case LocalAction::ExportSupportBundle:
      if (isRestrictedHouseholdUser) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = false,
            .requestOnly = true,
            .reason = L"Support bundle export is blocked for restricted household profiles unless approved by the owner."};
      }
      return LocalActionAuthorization{
          .role = role,
          .allowed = true,
          .requestOnly = false,
          .reason = L"Support bundle export is available to standard and trusted household users."};

    case LocalAction::IssueSessionApproval:
      if (isAdmin && elevated) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = L"Administrator re-auth can issue a short-lived approval session for privileged local actions."};
      }

      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"Issuing approval sessions requires an elevated administrator context."};

    case LocalAction::PatchInstall:
      if (isRestrictedHouseholdUser) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = false,
            .requestOnly = true,
            .reason = L"This household profile requires owner approval before installing software or Windows updates."};
      }

      return LocalActionAuthorization{
          .role = role,
          .allowed = true,
          .requestOnly = false,
          .reason = L"Fenrir can run software and Windows update maintenance through the protected service."};

    case LocalAction::QuarantineMutate:
      if (isAdmin && elevated) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = L"Elevated administrators can run sensitive local response actions."};
      }

      if (isTrustedHouseholdUser) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = false,
            .requestOnly = true,
            .reason = L"Trusted household users can request this action, but owner or administrator approval is required."};
      }

      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"Sensitive local response actions require elevated administrator approval."};

    case LocalAction::StartServiceAction:
    case LocalAction::EditExclusions:
      if ((isOwner || isBreakGlass) && elevated) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = true,
            .requestOnly = false,
            .reason = isBreakGlass
                          ? L"Break-glass administrator mode is active and permits emergency local protection changes."
                          : L"The device owner administrator can change long-lived local protection posture."};
      }

      if (isAdmin) {
        return LocalActionAuthorization{
            .role = role,
            .allowed = false,
            .requestOnly = true,
            .reason = L"This operation is reserved for the registered device owner administrator."};
      }

      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = true,
          .reason = L"System-wide local protection changes require explicit device-owner approval."};

    default:
      return LocalActionAuthorization{
          .role = role,
          .allowed = false,
          .requestOnly = false,
          .reason = L"Fenrir could not determine whether this local action is safe to allow."};
  }
}

}  // namespace antivirus::agent
