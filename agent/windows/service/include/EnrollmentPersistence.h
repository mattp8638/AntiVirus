#pragma once
#include <string>

namespace antivirus::agent {

inline std::wstring NormalizeEnrollmentServer(std::wstring value) {
  while (!value.empty() && value.back() == L'/') value.pop_back();
  return value;
}

// A routine reinstall must not silently move an enrolled machine to another
// customer or invalidate its stored device API key. An explicit migration
// workflow can be designed and approved separately.
inline bool EnrollmentChangeRequiresMigration(const std::wstring& existingServer,
                                              const std::wstring& existingToken,
                                              const std::wstring& proposedServer,
                                              const std::wstring& proposedToken,
                                              const bool hasExistingDeviceIdentity) {
  if (!hasExistingDeviceIdentity) return false;
  const bool serverChanged = !proposedServer.empty() &&
      NormalizeEnrollmentServer(proposedServer) != NormalizeEnrollmentServer(existingServer);
  const bool tokenChanged = !proposedToken.empty() && proposedToken != existingToken;
  return serverChanged || tokenChanged;
}

// An enrolled device reinstalled or repaired from a package for the SAME server keeps its identity and simply does
// not use the package's deployment token (each download of the installer carries a fresh token, and the agent may
// have cleared its own after enrolling). Nothing moves, so no migration is needed. A different server still is.
inline bool DeploymentTokenNotNeeded(const std::wstring& existingServer, const std::wstring& existingToken,
                                     const std::wstring& proposedServer, const std::wstring& proposedToken,
                                     const bool hasExistingDeviceIdentity) {
  if (!hasExistingDeviceIdentity || proposedToken.empty() || proposedToken == existingToken) return false;
  return proposedServer.empty() || NormalizeEnrollmentServer(proposedServer) == NormalizeEnrollmentServer(existingServer);
}

}  // namespace antivirus::agent
