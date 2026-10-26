#include "LocalAdminRotation.h"

#include <windows.h>
#include <bcrypt.h>
#include <dsrole.h>
#include <lm.h>
#include <ntsecapi.h>
#include <sddl.h>

#include <array>
#include <climits>
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

}  // namespace antivirus::agent::laps
