#pragma once

// Temporary local administrator accounts for privileged access management (elevation.grant). Each approved request
// gets its own account, named after the user it is for, with a random password that never leaves the device and a
// Windows account expiry as a backstop. The service deletes the account and its profile when the session ends.

#include <cwctype>
#include <string>
#include <vector>

namespace antivirus::agent::tempadmin {

// Marks the accounts Fenrir made, so only those are ever deleted (and leftovers after a crash are found).
constexpr const wchar_t* kComment = L"Fenrir temporary administrator (removed automatically)";
constexpr const wchar_t* kPrefix = L"fadm-";

// "fadm-<up to 8 letters/digits of the user name>-<last 4 letters/digits of the request id>": at most 18 characters,
// within Windows' 20. Portable (no Windows headers) so it is unit-tested natively.
inline std::wstring AccountName(const std::wstring& user, const std::wstring& requestId) {
  std::wstring base = user;
  if (const auto slash = base.find_last_of(L"\\/"); slash != std::wstring::npos) base = base.substr(slash + 1);
  if (const auto at = base.find(L'@'); at != std::wstring::npos) base = base.substr(0, at);
  const auto plain = [](wchar_t c) { return c < 128 && std::iswalnum(static_cast<wint_t>(c)); };
  std::wstring part;
  for (const wchar_t c : base) {
    if (part.size() == 8) break;
    if (plain(c)) part += static_cast<wchar_t>(std::towlower(static_cast<wint_t>(c)));
  }
  if (part.empty()) part = L"user";
  std::wstring tail;
  for (auto it = requestId.rbegin(); it != requestId.rend() && tail.size() < 4; ++it) {
    if (plain(*it)) tail.insert(tail.begin(), static_cast<wchar_t>(std::towlower(static_cast<wint_t>(*it))));
  }
  if (tail.empty()) tail = L"0000";
  return kPrefix + part + L"-" + tail;
}

inline bool IsTemporaryAccountName(const std::wstring& name) {
  return name.size() <= 20 && name.rfind(kPrefix, 0) == 0;
}

struct Account {
  std::wstring name;
  std::wstring sid;
};

// Creates the account with this password and a Windows account expiry (Unix seconds), and makes it a local
// administrator. An existing account of the same name is reset. 0 or a Windows error; sid receives its SID.
unsigned long Create(const std::wstring& name, const std::wstring& password, long long expiresAtUnix, std::wstring* sid);
// New password for an existing temporary account (after a service restart, which forgets passwords).
unsigned long SetPassword(const std::wstring& name, const std::wstring& password);
// Deletes the account (only one carrying kComment) and then its profile. 0 when the account is gone (also when it
// never existed); profileRemoved is false while the profile is still in use, so the caller retries RemoveProfile.
unsigned long Remove(const std::wstring& name, const std::wstring& sid, bool* profileRemoved);
bool RemoveProfile(const std::wstring& sid);
// Local accounts carrying kComment: what a crash or power cut may have left behind.
std::vector<Account> List();

}  // namespace antivirus::agent::tempadmin
