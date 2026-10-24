#pragma once

#include <winsock2.h>
#include <windows.h>

#include <atomic>
#include <filesystem>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "AgentConfig.h"
#include "AgentState.h"
#include "ControlPlaneClient.h"
#include "CommandJournalStore.h"
#include "DeviceInventoryCollector.h"
#include "EventEnvelope.h"
#include "FileDeltaTracker.h"
#include "HardeningManager.h"
#include "LocalControlChannel.h"
#include "LocalStateStore.h"
#include "PatchOrchestrator.h"
#include "PolicySnapshot.h"
#include "ProcessGuard.h"
#include "ProcessDeltaTracker.h"
#include "RemediationEngine.h"
#include "ScanVerdict.h"
#include "SupportBundleService.h"
#include "TelemetryQueueStore.h"
#include "RealtimeProtectionBroker.h"
#include "UpdaterService.h"
#include "WscCoexistenceManager.h"
#include "../../sensor/etw/include/ProcessEtwSensor.h"
#include "../../sensor/wfp/include/NetworkIsolationManager.h"

namespace antivirus::agent {

enum class AgentRunMode {
  Console,
  Service
};

class AgentService {
 public:
  AgentService();
  ~AgentService();

  AgentService(const AgentService&) = delete;
  AgentService& operator=(const AgentService&) = delete;

  int Run(AgentRunMode mode);
  void RequestStop();

 private:
  static std::wstring BuildCyclePayload(int cycle, const std::wstring& extraFields = L"");

  std::vector<std::filesystem::path> BuildMonitoredRoots() const;
  void RunSyncLoop(AgentRunMode mode);
  void RunAutomatedRiskAssessments(int cycle);
  void RunScheduledQuickScan(int cycle);
  void RunScheduledFullDriveScan(int cycle);
  void RunLiveThreatSweep(int cycle);
  void RunVulnerabilityAssessment(int cycle);
  bool WaitForNextCycle(AgentRunMode mode, int nextCycle);
  bool ShouldStop() const;
  void ProcessPamRequests();
  std::filesystem::path GetPamRequestPath() const;
  std::vector<std::filesystem::path> GetPamRequestPaths() const;
  std::filesystem::path GetPamAuditJournalPath() const;

  void SyncWithControlPlane(int cycle);
  void SyncUpdateOnly(int cycle);
  void EnsureEnrollment();
  void ResetEnrollmentState();
  bool RecoverDeviceIdentity(const std::exception& error, const std::wstring& operationName);
  void RefreshPolicy(int cycle);
  void PollAndExecuteCommands(int cycle);
  std::wstring ExecuteCommand(const RemoteCommand& command);
  std::wstring ExecuteTargetedScan(const RemoteCommand& command);
  std::wstring ExecuteIsolationCommand(const RemoteCommand& command, bool isolate);
  std::wstring ExecuteQuarantineMutation(const RemoteCommand& command, bool restore);
  std::wstring ExecuteUpdateCommand(const RemoteCommand& command, bool rollback);
  std::wstring ExecuteRepairCommand(const RemoteCommand& command);
  std::wstring ExecutePatchCommand(const RemoteCommand& command, bool installWindows, bool installSoftware, bool runCycle);
  std::wstring ExecuteSupportBundleCommand(const RemoteCommand& command, bool sanitized);
  std::wstring ExecuteStorageMaintenanceCommand(const RemoteCommand& command);
  std::wstring ExecuteThreatIntelLookupCommand(const RemoteCommand& command);
  std::wstring ExecuteThreatIntelPackIngestCommand(const RemoteCommand& command);
  std::wstring ExecuteBreakGlassCommand(const RemoteCommand& command, bool enable);
  std::wstring ExecuteLocalApprovalCommand(const RemoteCommand& command);
  std::wstring ExecuteLocalApprovalListCommand(const RemoteCommand& command);
  std::wstring ExecuteLocalAdminAuditCommand(const RemoteCommand& command);
  std::wstring ExecuteLocalAdminReductionCommand(const RemoteCommand& command, bool applyChanges);
  std::wstring ExecuteLocalAdminRollbackCommand(const RemoteCommand& command);
  std::wstring ExecuteHouseholdRoleAuditCommand(const RemoteCommand& command);
  std::wstring ExecuteHouseholdRolePropagationCommand(const RemoteCommand& command, bool applyChanges);
  std::wstring ExecuteProcessTerminationCommand(const RemoteCommand& command, bool includeChildren);
  std::wstring ExecutePersistenceCleanupCommand(const RemoteCommand& command);
  std::wstring ExecutePathRemediationCommand(const RemoteCommand& command);
  std::wstring ExecuteScriptCommand(const RemoteCommand& command);
  void PublishHeartbeat(int cycle);
  void PersistState();
  void LoadLocalPolicyCache();
  void StartTelemetrySpool() const;
  void StartCommandLoop() const;
  void PrintStatus() const;
  void QueueEndpointStatusTelemetry();
  void QueueDeviceInventoryTelemetry(int cycle);
  void QueuePatchTelemetry(int cycle);
  void DrainProcessTelemetry();
  void DrainRealtimeProtectionTelemetry();
  void DrainNetworkTelemetry();
  void QueueCycleTelemetry(int cycle);
  void ApplyProtectionPolicy();
  void SyncMlModel(int cycle);
  void QueueTelemetryEvent(const std::wstring& eventType, const std::wstring& source, const std::wstring& summary,
                           const std::wstring& payloadJson);
  void QueueTelemetryRecords(const std::vector<TelemetryRecord>& records);
  void FlushTelemetryQueue();
  ScanVerdict EvaluateEvent(const EventEnvelope& event) const;
  std::wstring ExecuteSoftwareCommand(const RemoteCommand& command, bool uninstall, bool searchOnly);
  std::wstring ExecuteSoftwareBlockCommand(const RemoteCommand& command);
  void EnforceBlockedSoftware();
  // RMM and remote access
  std::wstring ExecuteRmmCommand(const RemoteCommand& command);
  std::wstring LaunchRemoteHelper(const RemoteCommand& command);
  std::wstring EndRemoteHelper(const RemoteCommand& command);
  void StartRealtimeChannel();
  void StopRealtimeChannel();
  void RealtimeLoop();

  AgentConfig config_{};
  AgentState state_{};
  PolicySnapshot policy_{};
  std::unique_ptr<LocalStateStore> stateStore_{};
  std::unique_ptr<ControlPlaneClient> controlPlaneClient_{};
  std::unique_ptr<CommandJournalStore> commandJournalStore_{};
  std::unique_ptr<TelemetryQueueStore> telemetryQueueStore_{};
  ProcessDeltaTracker processDeltaTracker_{};
  FileDeltaTracker fileDeltaTracker_{};
  std::vector<TelemetryRecord> pendingTelemetry_{};
  std::unique_ptr<RealtimeProtectionBroker> realtimeProtectionBroker_{};
  std::unique_ptr<LocalControlChannel> localControlChannel_{};
  std::unique_ptr<ProcessGuard> processGuard_{};
  std::unique_ptr<ProcessEtwSensor> processEtwSensor_{};
  std::unique_ptr<NetworkIsolationManager> networkIsolationManager_{};
  bool lastControlPlaneSyncFailed_{false};
  bool lastHardeningCheckFailed_{false};
  bool lastTelemetryFlushFailed_{false};
  HANDLE stopEvent_{nullptr};
  HANDLE pamRequestEvent_{nullptr};
  // Set by the realtime channel when the cloud queues a command.
  HANDLE wakeEvent_{nullptr};
  std::thread realtimeThread_{};
  std::mutex remoteMutex_{};
  std::map<std::wstring, HANDLE> remoteHelpers_{};
  // The realtime thread starts remote sessions straight away, even while the main loop is busy
  // scanning. It works from a copy of the device identity, claims commands so a session never starts
  // and hands telemetry to the main thread (guarded by remoteMutex_).
  struct DeferredTelemetry {
    std::wstring eventType, source, summary, payloadJson;
  };
  void PublishIdentitySnapshot();
  AgentState IdentitySnapshot();
  void DrainDeferredTelemetry();
  std::thread::id mainThreadId_{};
  AgentState identitySnapshot_{};
  std::vector<DeferredTelemetry> deferredTelemetry_{};
};

}  // namespace antivirus::agent
