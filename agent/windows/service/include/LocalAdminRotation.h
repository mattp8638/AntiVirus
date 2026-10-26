#pragma once

// LAPS-style rotation of a local administrator password. The service escrows the new password with the
// cloud before setting it, so the cloud always holds whatever the account's password is.

#include <string>

namespace antivirus::agent::laps {

// Random password with upper, lower, digit and symbol characters (no look-alike characters).
std::wstring GeneratePassword(std::size_t length = 24);
// True on domain controllers, where a "local" account is a domain account: rotation must never run there.
bool IsDomainController();
// Name of the built-in Administrator account (RID 500), whatever it has been renamed to; empty if unknown.
std::wstring BuiltinAdministratorName();
// Sets the password of a local account. Returns 0 (NERR_Success) or the Windows error code.
unsigned long SetLocalAccountPassword(const std::wstring& account, const std::wstring& password);

}  // namespace antivirus::agent::laps
