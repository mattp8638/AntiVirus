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
#include "ExtendedPolicy.h"
#include "RansomwareShield.h"
#include "BruteForceGuard.h"
#include "RegistryWatcher.h"
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
  // Quick/full scans run on a background thread so commands and check-ins continue meanwhile.
  bool StartBackgroundScan(const std::wstring& eventPrefix, const std::wstring& scopeLabel, const std::wstring& source,
                           std::vector<std::filesystem::path> targets, int cpuLimitPercent = 100);
  std::wstring ExecuteOnDemandScan(const RemoteCommand& command, bool full);
  std::wstring ExecuteInventoryRefreshCommand(const RemoteCommand& command);
  std::wstring ExecutePolicyRefreshCommand(const RemoteCommand& command);
  std::wstring ExecuteAmsiTelemetrySubmitCommand(const RemoteCommand& command);
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
  void DrainRansomwareTelemetry();
  void DrainNetworkTelemetry();
  void QueueCycleTelemetry(int cycle);
  void ApplyProtectionPolicy();
  void SyncMlModel(int cycle);
  void QueueTelemetryEvent(const std::wstring& eventType, const std::wstring& source, const std::wstring& summary,
                           const std::wstring& payloadJson);
  void QueueTelemetryRecords(const std::vector<TelemetryRecord>& source);
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
  // Remote-session commands run on their own thread so a long patch scan or install on the main loop
  // never keeps a technician waiting.
  void InteractiveCommandLoop();
  void ExecuteJournaledCommand(const RemoteCommand& command, const AgentState& identity);
  static bool IsInteractiveCommand(const std::wstring& type);

  AgentConfig config_{};
  AgentState state_{};
  PolicySnapshot policy_{};
  ExtendedPolicy telemetryFilter_{};  // parsed edr collection switches, refreshed when the policy revision changes
  std::wstring telemetryFilterRevision_;
  std::mutex telemetryFilterMutex_{};
  // Firewall and network hardening (FirewallPolicy.h) run on a worker thread so PowerShell never delays protection.
  std::mutex firewallMutex_{};
  std::string appliedFirewallScript_{};  // last script that ran; re-run only on change
  std::string pendingFirewallScript_{};
  std::wstring pendingFirewallSummary_{};
  bool firewallWorkerBusy_{false};
  std::thread firewallThread_{};
  void ApplyFirewallPolicy();
  void ApplyTamperPolicy(const ExtendedPolicy& extended);
  void ApplyCredentialHardening(bool enable);
  int appliedCredentialHardening_{-1};
  std::wstring appliedTamperPolicy_;
  void WriteExperienceFile();
  // Self-update (Windows): compare this build's id with the server's and run its installer silently.
  void MaybeSelfUpdate(int cycle);
  void RelaunchClientAfterUpgrade();
  // Local admin password rotation (privilege.rotateLocalAdminPassword); force = the localadmin.rotate command.
  std::wstring RotateLocalAdminPassword(bool force);
  void ExpireBreakGlassAccount();
  void CheckRemovableMedia();  // antimalware.scanRemovableMedia
  unsigned long knownDrives_{0};
  unsigned long pendingRemovable_{0};
  bool drivesPrimed_{false};
  void EnforceLocalAdminPolicy();  // privilege.removeLocalAdmins
  std::vector<std::wstring> LocalAdminKeepList(const std::wstring& payloadJson) const;
  std::wstring ExecuteInventoryUninstall(const RemoteCommand& command);
  unsigned long long lastLocalAdminCheck_{0};
  unsigned long long lastSelfUpdateCheck_{0};
  bool ScanNetworkDrives() const;
  int ScheduledScanCpuLimit() const;
  void FirewallWorker();
  bool RunFirewallScript(const std::string& script, const std::wstring& summary);
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
  std::unique_ptr<RansomwareShield> ransomwareShield_{};
  std::unique_ptr<BruteForceGuard> bruteForceGuard_{};
  std::unique_ptr<RegistryWatcher> registryWatcher_{};
  std::unique_ptr<NetworkIsolationManager> networkIsolationManager_{};
  bool lastControlPlaneSyncFailed_{false};
  bool lastHardeningCheckFailed_{false};
  bool lastTelemetryFlushFailed_{false};
  HANDLE stopEvent_{nullptr};
  HANDLE pamRequestEvent_{nullptr};
  // Set by the realtime channel when the cloud queues a command.
  HANDLE wakeEvent_{nullptr};
  std::thread realtimeThread_{};
  std::thread interactiveThread_{};
  HANDLE interactiveWakeEvent_{nullptr};
  std::atomic<bool> interactiveLoopRunning_{false};
  std::atomic<bool> realtimeConnected_{false};
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
  std::shared_ptr<std::atomic<bool>> backgroundScanBusy_{std::make_shared<std::atomic<bool>>(false)};
  std::shared_ptr<std::atomic<bool>> stopRequested_{std::make_shared<std::atomic<bool>>(false)};
  AgentState identitySnapshot_{};
  std::vector<DeferredTelemetry> deferredTelemetry_{};
};

}  // namespace antivirus::agent
