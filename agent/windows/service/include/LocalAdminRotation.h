#pragma once

// LAPS-style rotation of a local administrator password. The service escrows the new password with the
// cloud before setting it, so the cloud always holds whatever the account's password is.

#include <string>
#include <vector>

namespace antivirus::agent::laps {

// Random password with upper, lower, digit and symbol characters (no look-alike characters).
std::wstring GeneratePassword(std::size_t length = 24);
// True on domain controllers, where a "local" account is a domain account: rotation must never run there.
bool IsDomainController();
// Name of the built-in Administrator account (RID 500), whatever it has been renamed to; empty if unknown.
std::wstring BuiltinAdministratorName();
// Sets the password of a local account. Returns 0 (NERR_Success) or the Windows error code.
unsigned long SetLocalAccountPassword(const std::wstring& account, const std::wstring& password);

// --- Members of the local Administrators group (localadmin.audit / reduce / rollback) ---

struct AdminMember {
  std::wstring name;  // DOMAIN\name
  std::wstring sid;   // S-1-5-...
  bool group{false};  // a group (Domain Admins, an Entra role); groups are never removed
  bool enabled{true};  // local user accounts only
  bool builtin{false};  // RID 500
};

// The members to remove: direct user members except the built-in Administrator and the names/SIDs in keep
// (case-insensitive; names may be given with or without the DOMAIN\ part). Returns indexes into members.
// Empty when removing them would leave the group with no enabled user and no group (nobody could administer).
std::vector<std::size_t> PlanAdminRemoval(const std::vector<AdminMember>& members, const std::vector<std::wstring>& keep);

std::vector<AdminMember> ListAdministrators();
unsigned long RemoveAdministrator(const std::wstring& sid);
unsigned long AddAdministrator(const std::wstring& sid);

// --- Break-glass account ---
constexpr const wchar_t* kBreakGlassAccount = L"FenrirBreakGlass";
// Creates (or re-enables) the account with this password and makes it a local administrator. 0 or a Windows error.
unsigned long EnableBreakGlassAccount(const std::wstring& password);
// Disables the account and gives it a random password nobody knows. 0 (also when it does not exist) or an error.
unsigned long DisableBreakGlassAccount();

}  // namespace antivirus::agent::laps
