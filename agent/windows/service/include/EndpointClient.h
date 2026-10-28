#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "AgentConfig.h"
#include "AgentState.h"
#include "QuarantineStore.h"
#include "RuntimeDatabase.h"

namespace antivirus::agent {

enum class LocalServiceState {
  NotInstalled,
  Running,
  Stopped,
  StartPending,
  StopPending,
  Paused,
  Unknown
};

struct EndpointClientSnapshot {
  AgentState agentState;
  LocalServiceState serviceState{LocalServiceState::Unknown};
  std::size_t queuedTelemetryCount{0};
  std::size_t activeQuarantineCount{0};
  std::size_t openThreatCount{0};
  std::size_t pendingPamRequestCount{0};
  std::size_t pamApprovedCount{0};
  std::size_t pamDeniedCount{0};
  std::wstring pamHealthState{L"unknown"};
  bool localAdminExposureKnown{false};
  std::size_t localAdminMemberCount{0};
  bool localAdminExposure{false};
  std::vector<ScanHistoryRecord> recentThreats;
  std::vector<ScanHistoryRecord> recentFindings;
  std::vector<QuarantineIndexRecord> quarantineItems;
  std::vector<UpdateJournalRecord> updateJournal;
  RebootCoordinatorRecord rebootCoordinator;
  std::vector<WindowsUpdateRecord> windowsUpdates;
  std::vector<SoftwarePatchRecord> softwarePatches;
  std::vector<PatchHistoryRecord> patchHistory;
};

struct LocalBrokerCommandResult {
  bool success{false};
  int statusCode{0};
  bool requestOnly{false};
  bool requiresReauth{false};
  std::wstring approvalRequestId;
  std::wstring responseJson;
  std::wstring errorMessage;
};

LocalServiceState QueryAgentServiceState();
std::wstring LocalServiceStateToString(LocalServiceState state);
bool StartAgentService();
bool StopAgentService();
bool RestartAgentService();

EndpointClientSnapshot LoadEndpointClientSnapshot(const AgentConfig& config, std::size_t threatLimit = 25,
                                                  std::size_t quarantineLimit = 50, std::size_t findingLimit = 50,
                                                  std::size_t updateLimit = 10);

QuarantineActionResult RestoreQuarantinedItem(const AgentConfig& config, const std::wstring& recordId);
QuarantineActionResult DeleteQuarantinedItem(const AgentConfig& config, const std::wstring& recordId);
LocalBrokerCommandResult SendLocalBrokerCommand(const AgentConfig& config, const std::wstring& type,
                                                const std::wstring& recordId = L"",
                                                const std::wstring& payloadJson = L"{}",
                                                const std::wstring& targetPath = L"",
                                                const std::wstring& sessionAuth = L"");
LocalBrokerCommandResult ExecuteQueuedLocalApproval(const AgentConfig& config, const std::wstring& approvalRequestId);
LocalBrokerCommandResult SetBreakGlassMode(const AgentConfig& config, bool enable,
                                           const std::wstring& reason = L"", bool queuePamRecovery = true);
LocalBrokerCommandResult ListPendingLocalApprovals(const AgentConfig& config, std::size_t limit = 50);
PatchExecutionResult ExecuteSoftwarePatchThroughService(const AgentConfig& config, const std::wstring& softwareId, bool searchOnly = false);

}  // namespace antivirus::agent
