#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <userenv.h>

#include "TemporaryAdmin.h"

#include "LocalAdminRotation.h"

namespace antivirus::agent::tempadmin {
namespace {

std::wstring AdministratorsGroupName() {
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  PSID sid = nullptr;
  std::wstring result = L"Administrators";
  if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)) {
    wchar_t name[256]{};
    wchar_t domain[256]{};
    DWORD nameSize = 256, domainSize = 256;
    SID_NAME_USE use{};
    if (LookupAccountSidW(nullptr, sid, name, &nameSize, domain, &domainSize, &use)) result = name;
    FreeSid(sid);
  }
  return result;
}

std::wstring LocalSidOf(const std::wstring& account) {
  wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
  DWORD computerSize = MAX_COMPUTERNAME_LENGTH + 1;
  GetComputerNameW(computer, &computerSize);
  const std::wstring qualified = std::wstring(computer) + L"\\" + account;  // never a domain account of the same name
  BYTE sid[SECURITY_MAX_SID_SIZE]{};
  DWORD sidSize = sizeof(sid);
  wchar_t domain[256]{};
  DWORD domainSize = 256;
  SID_NAME_USE use{};
  if (!LookupAccountNameW(nullptr, qualified.c_str(), sid, &sidSize, domain, &domainSize, &use)) return {};
  LPWSTR text = nullptr;
  if (!ConvertSidToStringSidW(sid, &text)) return {};
  std::wstring result = text;
  LocalFree(text);
  return result;
}

bool CarriesFenrirComment(const std::wstring& name) {
  USER_INFO_1* info = nullptr;
  if (NetUserGetInfo(nullptr, name.c_str(), 1, reinterpret_cast<LPBYTE*>(&info)) != NERR_Success || info == nullptr) return false;
  const bool ours = info->usri1_comment != nullptr && wcscmp(info->usri1_comment, kComment) == 0;
  NetApiBufferFree(info);
  return ours;
}

}  // namespace

unsigned long Create(const std::wstring& name, const std::wstring& password, long long expiresAtUnix, std::wstring* sid) {
  if (!IsTemporaryAccountName(name)) return ERROR_INVALID_PARAMETER;
  std::wstring account = name;
  std::wstring secret = password;
  std::wstring comment = kComment;
  USER_INFO_1 info{};
  info.usri1_name = account.data();
  info.usri1_password = secret.data();
  info.usri1_priv = USER_PRIV_USER;
  info.usri1_comment = comment.data();
  info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE;
  DWORD parameterError = 0;
  auto status = NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&info), &parameterError);
  if (status == NERR_UserExists) {
    if (!CarriesFenrirComment(account)) {
      SecureZeroMemory(secret.data(), secret.size() * sizeof(wchar_t));
      return ERROR_USER_EXISTS;  // someone else's account with this name: never take it over
    }
    status = laps::SetLocalAccountPassword(account, secret);
    if (status == NERR_Success) {
      USER_INFO_1008 flags{UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE};
      status = NetUserSetInfo(nullptr, account.c_str(), 1008, reinterpret_cast<LPBYTE>(&flags), &parameterError);
    }
  }
  SecureZeroMemory(secret.data(), secret.size() * sizeof(wchar_t));
  if (status != NERR_Success) return status;
  // Windows stops the account working at this time even if the agent is not running to delete it.
  USER_INFO_1017 expiry{static_cast<DWORD>(expiresAtUnix)};
  NetUserSetInfo(nullptr, account.c_str(), 1017, reinterpret_cast<LPBYTE>(&expiry), &parameterError);
  LOCALGROUP_MEMBERS_INFO_3 member{account.data()};
  const auto group = AdministratorsGroupName();
  status = NetLocalGroupAddMembers(nullptr, group.c_str(), 3, reinterpret_cast<LPBYTE>(&member), 1);
  if (status != NERR_Success && status != ERROR_MEMBER_IN_ALIAS) {
    NetUserDel(nullptr, account.c_str());
    return status;
  }
  if (sid != nullptr) *sid = LocalSidOf(account);
  return 0;
}

unsigned long SetPassword(const std::wstring& name, const std::wstring& password) {
  if (!IsTemporaryAccountName(name) || !CarriesFenrirComment(name)) return ERROR_INVALID_PARAMETER;
  return laps::SetLocalAccountPassword(name, password);
}

bool RemoveProfile(const std::wstring& sid) {
  if (sid.empty()) return true;
  if (DeleteProfileW(sid.c_str(), nullptr, nullptr)) return true;
  const auto error = GetLastError();
  return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND || error == ERROR_NO_SUCH_USER;  // no profile was made
}

unsigned long Remove(const std::wstring& name, const std::wstring& sid, bool* profileRemoved) {
  if (profileRemoved != nullptr) *profileRemoved = false;
  if (!IsTemporaryAccountName(name)) return ERROR_INVALID_PARAMETER;
  unsigned long status = NERR_Success;
  USER_INFO_1* info = nullptr;
  if (NetUserGetInfo(nullptr, name.c_str(), 1, reinterpret_cast<LPBYTE*>(&info)) == NERR_Success && info != nullptr) {
    const bool ours = info->usri1_comment != nullptr && wcscmp(info->usri1_comment, kComment) == 0;
    NetApiBufferFree(info);
    if (!ours) return ERROR_ACCESS_DENIED;  // only accounts Fenrir made are ever deleted
    status = NetUserDel(nullptr, name.c_str());
  }
  if (status == NERR_UserNotFound) status = NERR_Success;
  if (profileRemoved != nullptr) *profileRemoved = status == NERR_Success && RemoveProfile(sid);
  return status;
}

std::vector<Account> List() {
  std::vector<Account> accounts;
  DWORD resume = 0;
  NET_API_STATUS status;
  do {
    USER_INFO_1* buffer = nullptr;
    DWORD read = 0, total = 0;
    status = NetUserEnum(nullptr, 1, FILTER_NORMAL_ACCOUNT, reinterpret_cast<LPBYTE*>(&buffer), MAX_PREFERRED_LENGTH, &read, &total,
                         &resume);
    if ((status == NERR_Success || status == ERROR_MORE_DATA) && buffer != nullptr) {
      for (DWORD i = 0; i < read; ++i) {
        const std::wstring name = buffer[i].usri1_name ? buffer[i].usri1_name : L"";
        if (IsTemporaryAccountName(name) && buffer[i].usri1_comment != nullptr && wcscmp(buffer[i].usri1_comment, kComment) == 0) {
          accounts.push_back({name, LocalSidOf(name)});
        }
      }
    }
    if (buffer != nullptr) NetApiBufferFree(buffer);
  } while (status == ERROR_MORE_DATA);
  return accounts;
}

}  // namespace antivirus::agent::tempadmin
