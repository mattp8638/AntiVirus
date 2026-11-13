#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <vector>

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

namespace {

std::wstring TokenUserSid(HANDLE token) {
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  if (size == 0) return {};
  std::vector<BYTE> buffer(size);
  if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) return {};
  LPWSTR text = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) return {};
  std::wstring result = text;
  LocalFree(text);
  return result;
}

std::wstring SystemPath(const wchar_t* file) {
  wchar_t folder[MAX_PATH]{};
  const UINT length = GetSystemDirectoryW(folder, MAX_PATH);
  return length == 0 ? std::wstring(file) : (std::filesystem::path(folder) / file).wstring();
}

std::wstring Quote(const std::wstring& value) { return L"\"" + value + L"\""; }

using LogonUserExExWFn = BOOL(WINAPI*)(LPWSTR, LPWSTR, LPWSTR, DWORD, DWORD, PTOKEN_GROUPS, PHANDLE, PSID*, PVOID*, LPDWORD,
                                       PQUOTA_LIMITS);

}  // namespace

unsigned long FindUserSession(const std::wstring& userSid) {
  PWTS_SESSION_INFOW sessions = nullptr;
  DWORD count = 0;
  if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) return kNoSession;
  unsigned long found = kNoSession;
  for (DWORD i = 0; i < count; ++i) {
    HANDLE token = nullptr;
    if (!WTSQueryUserToken(sessions[i].SessionId, &token)) continue;
    const bool match = _wcsicmp(TokenUserSid(token).c_str(), userSid.c_str()) == 0;
    CloseHandle(token);
    if (!match) continue;
    if (sessions[i].State == WTSActive) {
      found = sessions[i].SessionId;
      break;
    }
    if (found == kNoSession) found = sessions[i].SessionId;
  }
  WTSFreeMemory(sessions);
  return found;
}

unsigned long LaunchElevated(const std::wstring& account, const std::wstring& password, unsigned long sessionId,
                             const std::wstring& target, const std::wstring& arguments, Launch* out, std::wstring* step) {
  const auto fail = [&](const wchar_t* what, unsigned long error) {
    if (step != nullptr) *step = what;
    return error == 0 ? static_cast<unsigned long>(ERROR_GEN_FAILURE) : error;
  };
  const bool ownToken = account.empty();  // the user is already an administrator: their own elevated token
  if (out == nullptr || (!ownToken && !IsTemporaryAccountName(account))) return fail(L"check the request", ERROR_INVALID_PARAMETER);
  *out = {};

  // What to run: programs directly, scripts through cmd.exe, installers through msiexec.
  auto extension = std::filesystem::path(target).extension().wstring();
  std::transform(extension.begin(), extension.end(), extension.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  std::wstring application = target;
  std::wstring commandLine = Quote(target) + (arguments.empty() ? L"" : L" " + arguments);
  if (extension == L".bat" || extension == L".cmd") {
    application = SystemPath(L"cmd.exe");
    commandLine = L"cmd.exe /c \"" + Quote(target) + (arguments.empty() ? L"" : L" " + arguments) + L"\"";
  } else if (extension == L".msi") {
    application = SystemPath(L"msiexec.exe");
    commandLine = L"msiexec.exe /i " + Quote(target) + (arguments.empty() ? L"" : L" " + arguments);
  } else if (extension != L".exe" && extension != L".com") {
    return fail(L"choose a program (.exe), a script (.bat, .cmd) or an installer (.msi)", ERROR_BAD_FORMAT);
  }
  if (GetFileAttributesW(target.c_str()) == INVALID_FILE_ATTRIBUTES) return fail(L"find the program", ERROR_FILE_NOT_FOUND);

  // The new logon also carries the user's own logon SID, which is what grants access to the desktop of their session.
  HANDLE userToken = nullptr;
  if (!WTSQueryUserToken(sessionId, &userToken)) return fail(L"find the user's session", GetLastError());
  DWORD size = 0;
  HANDLE logon = nullptr;
  std::wstring user = account;
  if (ownToken) {
    logon = userToken;
  } else {
    GetTokenInformation(userToken, TokenGroups, nullptr, 0, &size);
    std::vector<BYTE> userGroups(size ? size : 1);
    const BOOL gotGroups = size != 0 && GetTokenInformation(userToken, TokenGroups, userGroups.data(), size, &size);
    CloseHandle(userToken);
    if (!gotGroups) return fail(L"read the user's session", GetLastError());
    PSID logonSid = nullptr;
    const auto* groups = reinterpret_cast<TOKEN_GROUPS*>(userGroups.data());
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
      if ((groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) logonSid = groups->Groups[i].Sid;
    }
    if (logonSid == nullptr) return fail(L"read the user's session", ERROR_NO_SUCH_LOGON_SESSION);

    const auto logonUserExEx = reinterpret_cast<LogonUserExExWFn>(GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "LogonUserExExW"));
    if (logonUserExEx == nullptr) return fail(L"find LogonUserExExW", ERROR_PROC_NOT_FOUND);
    TOKEN_GROUPS extra{};
    extra.GroupCount = 1;
    extra.Groups[0].Sid = logonSid;
    extra.Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    std::wstring domain = L".", secret = password;
    const BOOL loggedOn = logonUserExEx(user.data(), domain.data(), secret.data(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                                        &extra, &logon, nullptr, nullptr, nullptr, nullptr);
    const DWORD logonError = GetLastError();
    SecureZeroMemory(secret.data(), secret.size() * sizeof(wchar_t));
    if (!loggedOn) return fail(L"sign in the temporary administrator", logonError);
  }

  // With UAC on, an administrator signs in with a filtered token; the full one is linked to it.
  HANDLE full = nullptr;
  TOKEN_ELEVATION_TYPE type = TokenElevationTypeDefault;
  if (GetTokenInformation(logon, TokenElevationType, &type, sizeof(type), &size) && type == TokenElevationTypeLimited) {
    TOKEN_LINKED_TOKEN linked{};
    if (GetTokenInformation(logon, TokenLinkedToken, &linked, sizeof(linked), &size)) full = linked.LinkedToken;
  }
  HANDLE primary = nullptr;
  const BOOL duplicated = DuplicateTokenEx(full != nullptr ? full : logon, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &primary);
  const DWORD duplicateError = GetLastError();
  if (full != nullptr) CloseHandle(full);
  CloseHandle(logon);
  if (!duplicated) return fail(L"get the administrator token", duplicateError);
  TOKEN_ELEVATION elevation{};
  if (!GetTokenInformation(primary, TokenElevation, &elevation, sizeof(elevation), &size) || elevation.TokenIsElevated == 0) {
    CloseHandle(primary);
    return fail(L"get an elevated token", ERROR_ELEVATION_REQUIRED);
  }
  DWORD session = sessionId;
  if (!SetTokenInformation(primary, TokenSessionId, &session, sizeof(session))) {
    const DWORD error = GetLastError();
    CloseHandle(primary);
    return fail(L"move the token to the user's session", error);
  }

  PROFILEINFOW profile{};
  profile.dwSize = sizeof(profile);
  profile.dwFlags = PI_NOUI;
  profile.lpUserName = user.data();
  if (!ownToken && !LoadUserProfileW(primary, &profile)) {  // the user's own profile is already loaded
    const DWORD error = GetLastError();
    CloseHandle(primary);
    return fail(L"load the temporary administrator's profile", error);
  }
  LPVOID environment = nullptr;
  CreateEnvironmentBlock(&environment, primary, FALSE);

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_SHOWNORMAL;
  PROCESS_INFORMATION process{};
  std::vector<wchar_t> line(commandLine.begin(), commandLine.end());
  line.push_back(L'\0');
  const auto directory = std::filesystem::path(target).parent_path().wstring();
  const BOOL started = CreateProcessAsUserW(primary, application.c_str(), line.data(), nullptr, nullptr, FALSE,
                                            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, environment,
                                            directory.empty() ? nullptr : directory.c_str(), &startup, &process);
  const DWORD startError = GetLastError();
  if (environment != nullptr) DestroyEnvironmentBlock(environment);
  if (!started) {
    if (job != nullptr) CloseHandle(job);
    if (profile.hProfile != nullptr) UnloadUserProfile(primary, profile.hProfile);
    CloseHandle(primary);
    return fail(L"start the program", startError);
  }
  if (job != nullptr && !AssignProcessToJobObject(job, process.hProcess)) {
    CloseHandle(job);
    job = nullptr;  // still runs; the service then follows the process itself rather than the job
  }
  ResumeThread(process.hThread);
  CloseHandle(process.hThread);

  // A process that cannot reach the desktop fails at once with STATUS_DLL_INIT_FAILED; report that so the caller
  // can fall back to the agent window's way of starting it.
  if (WaitForSingleObject(process.hProcess, 2500) == WAIT_OBJECT_0) {
    DWORD code = 0;
    GetExitCodeProcess(process.hProcess, &code);
    if (code == 0xC0000142u) {
      CloseHandle(process.hProcess);
      if (job != nullptr) CloseHandle(job);
      if (profile.hProfile != nullptr) UnloadUserProfile(primary, profile.hProfile);
      CloseHandle(primary);
      return fail(L"open a window on the user's desktop", ERROR_ACCESS_DENIED);
    }
  }
  out->pid = process.dwProcessId;
  out->process = process.hProcess;
  out->job = job;
  out->token = primary;
  out->profile = profile.hProfile;
  return 0;
}

unsigned long RunningProcesses(const Launch& launch) {
  if (launch.job != nullptr) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
    if (QueryInformationJobObject(static_cast<HANDLE>(launch.job), JobObjectBasicAccountingInformation, &info, sizeof(info), nullptr)) {
      return info.ActiveProcesses;
    }
  }
  if (launch.process != nullptr) return WaitForSingleObject(static_cast<HANDLE>(launch.process), 0) == WAIT_TIMEOUT ? 1 : 0;
  return 0;
}

void Terminate(const Launch& launch) {
  if (launch.job != nullptr) TerminateJobObject(static_cast<HANDLE>(launch.job), 1);
  else if (launch.process != nullptr) TerminateProcess(static_cast<HANDLE>(launch.process), 1);
}

void Release(Launch* launch) {
  if (launch == nullptr) return;
  if (launch->token != nullptr && launch->profile != nullptr) UnloadUserProfile(static_cast<HANDLE>(launch->token), static_cast<HANDLE>(launch->profile));
  for (void* handle : {launch->process, launch->job, launch->token}) {
    if (handle != nullptr) CloseHandle(static_cast<HANDLE>(handle));
  }
  *launch = {};
}

}  // namespace antivirus::agent::tempadmin
