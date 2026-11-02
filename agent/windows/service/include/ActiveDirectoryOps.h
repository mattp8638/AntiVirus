#pragma once

// Active Directory changes for hybrid (AD-synced) Microsoft 365 onboarding and offboarding. One ad.directory command
// runs one allowlisted operation of the embedded script (src/ActiveDirectoryOpsScript.ps1) as SYSTEM on a domain
// controller, or Entra Connect's delta sync on the server that runs it.

#include <filesystem>
#include <string>

namespace antivirus::agent {

// requestJson: {"operation": "...", "params": {...}}. secret: a one-time value (a new starter's temporary password),
// handed to the script in its own file and deleted straight after; empty when the operation needs none. Returns the
// script's JSON ({"ok": true, ...} or {"ok": false, "error": "..."}). Throws when the script could not run at all.
std::string RunActiveDirectoryOperation(const std::string& requestJson, const std::wstring& secret,
                                        const std::filesystem::path& workRoot);

}  // namespace antivirus::agent
