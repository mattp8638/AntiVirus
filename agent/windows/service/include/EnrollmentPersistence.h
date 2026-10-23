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

}  // namespace antivirus::agent
