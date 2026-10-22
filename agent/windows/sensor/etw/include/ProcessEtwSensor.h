#pragma once

#include <Windows.h>
#include <evntrace.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "../../../service/include/AgentConfig.h"
#include "../../../service/include/TelemetryRecord.h"

namespace antivirus::agent {

struct EtwProcessContext {
  DWORD pid{0};
  DWORD parentPid{0};
  std::wstring imageName;
  std::wstring imagePath;
  std::wstring parentImageName;
  std::wstring parentImagePath;
  std::wstring commandLine;
  std::wstring userSid;
  std::wstring integrityLevel;
  std::wstring sessionId;
  std::wstring signer;
  std::wstring startedAt;
};

class ProcessEtwSensor {
 public:
  explicit ProcessEtwSensor(AgentConfig config);
  ~ProcessEtwSensor();

  ProcessEtwSensor(const ProcessEtwSensor&) = delete;
  ProcessEtwSensor& operator=(const ProcessEtwSensor&) = delete;

  void Start();
  void Stop();

  bool IsActive() const;
  void SetDeviceId(std::wstring deviceId);
  // Called on the ETW thread for every process start; returned records are queued as telemetry.
  using ProcessStartHandler = std::function<std::vector<TelemetryRecord>(const EtwProcessContext&)>;
  void SetProcessStartHandler(ProcessStartHandler handler);
  std::vector<TelemetryRecord> DrainTelemetry();

 private:
  static DWORD WINAPI ThreadEntry(LPVOID context);
  static VOID WINAPI EventRecordCallback(EVENT_RECORD* eventRecord);

  void RunTraceLoop();
  void HandleEventRecord(const EVENT_RECORD& eventRecord);
  void QueueTelemetry(const TelemetryRecord& record);
  void QueueStateEvent(const std::wstring& eventType, const std::wstring& summary,
                       const std::wstring& payloadJson);
  void StopControllerSession();

  AgentConfig config_;
  mutable std::mutex stateMutex_{};
  std::mutex telemetryMutex_{};
  std::vector<TelemetryRecord> pendingTelemetry_{};
  std::unordered_map<DWORD, EtwProcessContext> activeProcesses_{};
  std::wstring deviceId_{};
  std::wstring sessionName_{};
  HANDLE stopEvent_{nullptr};
  HANDLE workerThread_{nullptr};
  TRACEHANDLE sessionHandle_{0};
  TRACEHANDLE traceHandle_{0};
  std::atomic<bool> active_{false};
  ProcessStartHandler processStartHandler_{};
};

}  // namespace antivirus::agent
