#pragma once

#include <filesystem>
#include <string>
#include <vector>
#include <windows.h>

#include "AgentConfig.h"
#include "PolicySnapshot.h"
#include "../../shared/include/RealtimeProtectionProtocol.h"

namespace antivirus::agent {

struct RemediationOutcome {
  bool success{false};
  bool verificationSucceeded{false};
  int processesTerminated{0};
  int registryValuesRemoved{0};
  int startupArtifactsRemoved{0};
  int scheduledTasksRemoved{0};
  int servicesRemoved{0};
  int wmiObjectsRemoved{0};
  int siblingArtifactsRemoved{0};
  bool quarantineApplied{false};
  std::wstring quarantineRecordId;
  std::wstring evidenceRecordId;
  std::wstring errorMessage;
  std::vector<std::wstring> removedArtifacts;
  std::vector<std::wstring> verificationDetails;
};

class RemediationEngine {
 public:
  explicit RemediationEngine(const AgentConfig& config);

  RemediationOutcome TerminateProcessByPid(DWORD pid, bool includeChildren) const;
  RemediationOutcome TerminateProcessTreeByRootPid(DWORD pid) const;
  RemediationOutcome TerminateProcessesForRealtimeRequest(const RealtimeFileScanRequest& request,
                                                          bool includeChildren) const;
  RemediationOutcome TerminateProcessesForPath(const std::filesystem::path& subjectPath, bool includeChildren) const;
  RemediationOutcome CleanupPersistenceForPath(const std::filesystem::path& subjectPath) const;
  RemediationOutcome RemediatePath(const std::filesystem::path& subjectPath, const PolicySnapshot& policy) const;

 private:
  AgentConfig config_;
};

}  // namespace antivirus::agent
