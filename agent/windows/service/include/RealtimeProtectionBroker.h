#pragma once

#include <windows.h>

#include <atomic>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

#include "AgentConfig.h"
#include "EventEnvelope.h"
#include "PolicySnapshot.h"
#include "ScanEngine.h"
#include "ScanVerdict.h"
#include "TelemetryRecord.h"
#include "../../shared/include/RealtimeProtectionProtocol.h"

namespace antivirus::agent {

struct RealtimeInspectionOutcome {
  RealtimeResponseAction action{ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW};
  bool detection{false};
  ScanFinding finding{};
};

class RealtimeProtectionBroker {
 public:
  explicit RealtimeProtectionBroker(AgentConfig config);
  ~RealtimeProtectionBroker();

  RealtimeProtectionBroker(const RealtimeProtectionBroker&) = delete;
  RealtimeProtectionBroker& operator=(const RealtimeProtectionBroker&) = delete;

  void Start();
  void Stop();

  void SetPolicy(const PolicySnapshot& policy);
  void SetDeviceId(std::wstring deviceId);
  bool IsRealtimeCoverageHealthy() const;

  RealtimeInspectionOutcome InspectFile(const RealtimeFileScanRequest& request);
  void ObserveBehaviorEvent(const EventEnvelope& event);
  ScanVerdict EvaluateEvent(const EventEnvelope& event);
  std::vector<TelemetryRecord> DrainTelemetry();

 private:
  static DWORD WINAPI ThreadEntry(LPVOID context);
  void PumpLoop();
  void QueueTelemetry(const TelemetryRecord& record);
  void QueueBrokerStateEvent(const std::wstring& eventType, const std::wstring& summary,
                             const std::wstring& payloadJson);

  AgentConfig config_;
  std::wstring deviceId_;
  PolicySnapshot policy_{CreateDefaultPolicySnapshot()};
  std::mutex stateMutex_{};
  std::mutex telemetryMutex_{};
  std::vector<TelemetryRecord> pendingTelemetry_{};
  HANDLE stopEvent_{nullptr};
  HANDLE workerThread_{nullptr};
  std::atomic<bool> workerActive_{false};
  std::atomic<bool> portConnected_{false};
};

}  // namespace antivirus::agent
