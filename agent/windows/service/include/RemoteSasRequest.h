#pragma once

#include <cstdint>
#include <string_view>

namespace antivirus::agent::remote {

// Bind a service-side SAS request to the specific SYSTEM helper and interactive
// Windows session that the service launched, never to session 0 or another user.
inline std::string_view ValidateSasCaller(std::uint32_t expectedPid, std::uint32_t callerPid,
                                        std::uint32_t expectedSession, std::uint32_t callerSession,
                                        bool localSystem, bool canImpersonate) {
  if (expectedPid == 0 || callerPid != expectedPid) {
    return "only this remote session's helper may request Ctrl+Alt+Del";
  }
  if (expectedSession == 0 || expectedSession == UINT32_MAX || callerSession != expectedSession) {
    return "the Ctrl+Alt+Del request does not belong to the remote Windows session";
  }
  if (!localSystem || !canImpersonate) {
    return "Ctrl+Alt+Del requires the authenticated SYSTEM remote helper";
  }
  return {};
}

}  // namespace antivirus::agent::remote
