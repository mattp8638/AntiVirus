#include "LocalAdminRotation.h"

#include <windows.h>
#include <bcrypt.h>
#include <dsrole.h>
#include <lm.h>
#include <ntsecapi.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cwctype>
#include <stdexcept>
#include <vector>

namespace antivirus::agent::laps {

namespace {

// Uniform random number in [0, bound) from the system CSPRNG (rejection sampling avoids modulo bias).
unsigned int RandomBelow(const unsigned int bound) {
  const unsigned int limit = UINT_MAX - (UINT_MAX % bound);
  for (;;) {
    unsigned int value = 0;
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&value), sizeof(value), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
      throw std::runtime_error("The system random number generator failed");
    }
    if (value < limit) {
      return value % bound;
    }
  }
}

}  // namespace

std::wstring GeneratePassword(const std::size_t length) {
  static const std::array<std::wstring, 4> classes = {L"ABCDEFGHJKLMNPQRSTUVWXYZ", L"abcdefghijkmnopqrstuvwxyz", L"23456789",
                                                      L"!#$%&*+-=?@_~"};
  const std::wstring all = classes[0] + classes[1] + classes[2] + classes[3];
  std::wstring password;
  for (const auto& set : classes) {
    password += set[RandomBelow(static_cast<unsigned int>(set.size()))];  // one of each class meets complexity rules
  }
  while (password.size() < length) {
    password += all[RandomBelow(static_cast<unsigned int>(all.size()))];
  }
  for (std::size_t i = password.size() - 1; i > 0; --i) {  // Fisher-Yates, so the class order is not predictable
    std::swap(password[i], password[RandomBelow(static_cast<unsigned int>(i + 1))]);
  }
  return password;
}

bool IsDomainController() {
  DSROLE_PRIMARY_DOMAIN_INFO_BASIC* info = nullptr;
  if (DsRoleGetPrimaryDomainInformation(nullptr, DsRolePrimaryDomainInfoBasic, reinterpret_cast<PBYTE*>(&info)) != ERROR_SUCCESS ||
      info == nullptr) {
    return true;  // cannot tell: treat as a domain controller and do nothing
  }
  const bool dc = info->MachineRole == DsRole_RoleBackupDomainController || info->MachineRole == DsRole_RolePrimaryDomainController;
  DsRoleFreeMemory(info);
  return dc;
}

std::wstring BuiltinAdministratorName() {
  LSA_OBJECT_ATTRIBUTES attributes{};
  LSA_HANDLE policy = nullptr;
  if (LsaOpenPolicy(nullptr, &attributes, POLICY_VIEW_LOCAL_INFORMATION, &policy) != 0) {
    return {};
  }
  POLICY_ACCOUNT_DOMAIN_INFO* domain = nullptr;
  std::wstring name;
  if (LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation, reinterpret_cast<PVOID*>(&domain)) == 0 && domain != nullptr &&
      domain->DomainSid != nullptr) {
    const auto subCount = *GetSidSubAuthorityCount(domain->DomainSid);
    std::vector<BYTE> sid(GetSidLengthRequired(static_cast<UCHAR>(subCount + 1)));
    if (InitializeSid(sid.data(), GetSidIdentifierAuthority(domain->DomainSid), static_cast<BYTE>(subCount + 1))) {
      for (UCHAR i = 0; i < subCount; ++i) {
        *GetSidSubAuthority(sid.data(), i) = *GetSidSubAuthority(domain->DomainSid, i);
      }
      *GetSidSubAuthority(sid.data(), subCount) = DOMAIN_USER_RID_ADMIN;  // 500
      wchar_t account[256]{}, domainName[256]{};
      DWORD accountSize = 256, domainSize = 256;
      SID_NAME_USE use{};
      if (LookupAccountSidW(nullptr, sid.data(), account, &accountSize, domainName, &domainSize, &use)) {
        name = account;
      }
    }
  }
  if (domain) LsaFreeMemory(domain);
  LsaClose(policy);
  return name;
}

unsigned long SetLocalAccountPassword(const std::wstring& account, const std::wstring& password) {
  std::wstring copy = password;
  USER_INFO_1003 info{copy.data()};
  DWORD parameterError = 0;
  const auto status = NetUserSetInfo(nullptr, account.c_str(), 1003, reinterpret_cast<LPBYTE>(&info), &parameterError);
  SecureZeroMemory(copy.data(), copy.size() * sizeof(wchar_t));
  return status;
}

namespace {

std::wstring LowerCopy(std::wstring value) {
  for (auto& c : value) c = static_cast<wchar_t>(std::towlower(c));
  return value;
}

std::wstring AdministratorsGroupName() {
  BYTE sid[SECURITY_MAX_SID_SIZE];
  DWORD size = sizeof(sid);
  if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &size)) return L"Administrators";
  wchar_t name[256]{}, domain[256]{};
  DWORD nameSize = 256, domainSize = 256;
  SID_NAME_USE use{};
  return LookupAccountSidW(nullptr, sid, name, &nameSize, domain, &domainSize, &use) ? std::wstring(name) : L"Administrators";
}

unsigned long ChangeMembership(const std::wstring& sidText, const bool add) {
  PSID sid = nullptr;
  if (!ConvertStringSidToSidW(sidText.c_str(), &sid)) return GetLastError();
  LOCALGROUP_MEMBERS_INFO_0 member{sid};
  const auto group = AdministratorsGroupName();
  const auto status = add ? NetLocalGroupAddMembers(nullptr, group.c_str(), 0, reinterpret_cast<LPBYTE>(&member), 1)
                          : NetLocalGroupDelMembers(nullptr, group.c_str(), 0, reinterpret_cast<LPBYTE>(&member), 1);
  LocalFree(sid);
  if (add && status == ERROR_MEMBER_IN_ALIAS) return 0;
  if (!add && status == ERROR_MEMBER_NOT_IN_ALIAS) return 0;
  return status;
}

}  // namespace

std::vector<std::size_t> PlanAdminRemoval(const std::vector<AdminMember>& members, const std::vector<std::wstring>& keep) {
  std::vector<std::wstring> keepLower;
  for (const auto& entry : keep) {
    if (!entry.empty()) keepLower.push_back(LowerCopy(entry));
  }
  const auto kept = [&keepLower](const AdminMember& m) {
    const auto name = LowerCopy(m.name);
    const auto slash = name.find(L'\\');
    const auto shortName = slash == std::wstring::npos ? name : name.substr(slash + 1);
    const auto sid = LowerCopy(m.sid);
    return std::any_of(keepLower.begin(), keepLower.end(),
                       [&](const std::wstring& k) { return k == name || k == shortName || k == sid; });
  };
  std::vector<std::size_t> remove;
  bool usableLeft = false;
  for (std::size_t i = 0; i < members.size(); ++i) {
    const auto& m = members[i];
    if (m.group || m.builtin || kept(m)) {
      if (m.group || m.enabled) usableLeft = true;
      continue;
    }
    remove.push_back(i);
  }
  if (!usableLeft) return {};
  return remove;
}

std::vector<AdminMember> ListAdministrators() {
  std::vector<AdminMember> out;
  const auto group = AdministratorsGroupName();
  LPBYTE buffer = nullptr;
  DWORD read = 0, total = 0;
  DWORD_PTR resume = 0;
  if (NetLocalGroupGetMembers(nullptr, group.c_str(), 2, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume) != NERR_Success) {
    if (buffer) NetApiBufferFree(buffer);
    throw std::runtime_error("The members of the local Administrators group could not be read");
  }
  const auto* members = reinterpret_cast<const LOCALGROUP_MEMBERS_INFO_2*>(buffer);
  for (DWORD i = 0; i < read; ++i) {
    AdminMember m;
    m.name = members[i].lgrmi2_domainandname ? members[i].lgrmi2_domainandname : L"";
    LPWSTR sidText = nullptr;
    if (members[i].lgrmi2_sid && ConvertSidToStringSidW(members[i].lgrmi2_sid, &sidText)) {
      m.sid = sidText;
      LocalFree(sidText);
    }
    const auto use = members[i].lgrmi2_sidusage;
    m.group = use == SidTypeGroup || use == SidTypeWellKnownGroup || use == SidTypeAlias;
    if (members[i].lgrmi2_sid && IsValidSid(members[i].lgrmi2_sid)) {
      const auto count = *GetSidSubAuthorityCount(members[i].lgrmi2_sid);
      m.builtin = count > 0 && *GetSidSubAuthority(members[i].lgrmi2_sid, count - 1) == DOMAIN_USER_RID_ADMIN;
    }
    if (!m.group) {
      // Local accounts: report whether they are enabled. Domain accounts count as enabled.
      const auto slash = m.name.find(L'\\');
      USER_INFO_1* info = nullptr;
      if (slash != std::wstring::npos &&
          NetUserGetInfo(nullptr, m.name.substr(slash + 1).c_str(), 1, reinterpret_cast<LPBYTE*>(&info)) == NERR_Success && info) {
        wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
        GetComputerNameW(computer, &size);
        if (_wcsicmp(m.name.substr(0, slash).c_str(), computer) == 0) m.enabled = (info->usri1_flags & UF_ACCOUNTDISABLE) == 0;
        NetApiBufferFree(info);
      }
    }
    out.push_back(std::move(m));
  }
  NetApiBufferFree(buffer);
  return out;
}

unsigned long RemoveAdministrator(const std::wstring& sid) { return ChangeMembership(sid, false); }
unsigned long AddAdministrator(const std::wstring& sid) { return ChangeMembership(sid, true); }

unsigned long EnableBreakGlassAccount(const std::wstring& password) {
  std::wstring copy = password;
  std::wstring name = kBreakGlassAccount;
  std::wstring comment = L"Fenrir Endpoint break-glass administrator (temporary)";
  USER_INFO_1 info{};
  info.usri1_name = name.data();
  info.usri1_password = copy.data();
  info.usri1_priv = USER_PRIV_USER;
  info.usri1_comment = comment.data();
  info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
  DWORD parameterError = 0;
  auto status = NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&info), &parameterError);
  if (status == NERR_UserExists) {
    status = SetLocalAccountPassword(name, copy);
    if (status == NERR_Success) {
      USER_INFO_1008 flags{UF_SCRIPT | UF_DONT_EXPIRE_PASSWD};
      status = NetUserSetInfo(nullptr, name.c_str(), 1008, reinterpret_cast<LPBYTE>(&flags), &parameterError);
    }
  }
  SecureZeroMemory(copy.data(), copy.size() * sizeof(wchar_t));
  if (status != NERR_Success) return status;
  // Add by name: the account was just created or found locally.
  LOCALGROUP_MEMBERS_INFO_3 member{name.data()};
  const auto group = AdministratorsGroupName();
  status = NetLocalGroupAddMembers(nullptr, group.c_str(), 3, reinterpret_cast<LPBYTE>(&member), 1);
  return status == ERROR_MEMBER_IN_ALIAS ? 0 : status;
}

unsigned long DisableBreakGlassAccount() {
  std::wstring name = kBreakGlassAccount;
  USER_INFO_1* existing = nullptr;
  if (NetUserGetInfo(nullptr, name.c_str(), 1, reinterpret_cast<LPBYTE*>(&existing)) != NERR_Success) return 0;
  NetApiBufferFree(existing);
  auto password = GeneratePassword(32);
  auto status = SetLocalAccountPassword(name, password);
  SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
  USER_INFO_1008 flags{UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_ACCOUNTDISABLE};
  DWORD parameterError = 0;
  const auto disable = NetUserSetInfo(nullptr, name.c_str(), 1008, reinterpret_cast<LPBYTE>(&flags), &parameterError);
  (void)status;  // a failed password change matters less once the account is disabled
  return disable;
}

}  // namespace antivirus::agent::laps
