#pragma once

#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>

#include <mutex>
#include <string>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../../../service/include/AgentConfig.h"
#include "../../../service/include/DestinationEnforcementBridge.h"
#include "../../../service/include/TelemetryRecord.h"

namespace antivirus::agent {

class NetworkIsolationManager {
 public:
  explicit NetworkIsolationManager(AgentConfig config);
  ~NetworkIsolationManager();

  NetworkIsolationManager(const NetworkIsolationManager&) = delete;
  NetworkIsolationManager& operator=(const NetworkIsolationManager&) = delete;

  void Start();
  void Stop();

  void SetDeviceId(std::wstring deviceId);
  bool ApplyIsolation(bool isolate, std::wstring* errorMessage = nullptr);
  bool ApplyDestinationBlock(const DestinationEnforcementRequest& request,
                             std::wstring* errorMessage = nullptr);

  bool EngineReady() const;
  bool IsolationActive() const;

  std::vector<TelemetryRecord> DrainTelemetry();
  std::vector<TelemetryRecord> CollectConnectionSnapshotTelemetry(std::size_t maxRecords) const;

 private:
  struct ActiveDestinationBlock {
    std::wstring key;
    std::wstring remoteAddress;
    std::wstring sourceApplication;
    std::wstring reason;
    std::wstring displayDestination;
    std::wstring expiresAt;
    std::vector<UINT64> filterIds;
    std::chrono::steady_clock::time_point addedAt{};
    std::chrono::steady_clock::time_point lastTouchedAt{};
  };

  static void CALLBACK NetEventCallback(void* context, const FWPM_NET_EVENT1* event);
  static bool DestinationEnforcementThunk(void* context,
                                          const DestinationEnforcementRequest& request,
                                          std::wstring* errorMessage);

  void EnsureProviderAndSubLayer();
  void SubscribeNetEvents();
  void UnsubscribeNetEvents();
  void RemoveIsolationFilters();
  void AddIsolationFilters();
  void RemoveDestinationBlockFilters();
  void RemoveDestinationBlockFiltersLocked();
  void RemoveDestinationBlockLocked(const std::wstring& key);
  void AddDestinationBlockFilters(const DestinationEnforcementRequest& request);
  void AddDestinationBlockFiltersLocked(const DestinationEnforcementRequest& request);
  void PurgeExpiredDestinationBlocksLocked();
  void ReconcileDestinationBlocksLocked(bool force = false);
  void ReplayPersistedDestinationBlocksLocked();
  void HandleNetEvent(const FWPM_NET_EVENT1& event);
  void QueueTelemetry(const TelemetryRecord& record);
  void QueueStateEvent(const std::wstring& eventType, const std::wstring& summary,
                       const std::wstring& payloadJson);

  AgentConfig config_;
  mutable std::mutex stateMutex_{};
  mutable std::mutex telemetryMutex_{};
  std::wstring deviceId_{};
  std::vector<TelemetryRecord> pendingTelemetry_{};
  HANDLE engineHandle_{nullptr};
  HANDLE netEventHandle_{nullptr};
  bool engineReady_{false};
  bool isolationActive_{false};
  std::vector<UINT64> activeFilterIds_{};
  std::unordered_set<UINT64> activeFilterIdIndex_{};
  std::unordered_map<std::wstring, ActiveDestinationBlock> activeDestinationBlocks_{};
  std::unordered_map<UINT64, std::wstring> activeDestinationBlockKeyByFilterId_{};
  std::chrono::steady_clock::time_point lastDestinationReconcileAt_{};
};

}  // namespace antivirus::agent
