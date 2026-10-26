#pragma once

// Ransomware shield (modules.ransomware):
//  - watches protected folders, and folders behind SMB shares, through the Microsoft-Windows-Kernel-File
//    ETW provider, so every file write is tied to the process that made it;
//  - counts files rewritten per process per minute and samples them for encryption (entropy), then
//    stops the process in block modes;
//  - keeps hidden canary files in protected folders and reports anything that touches them;
//  - reports (audit) or stops (block) unsigned, unapproved programs writing into protected folders;
//  - takes Volume Shadow Copy snapshots on the policy's interval and restores attacked files from them.
// Decisions live in RansomwareDetector (unit tested); this class is the Windows plumbing.

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>

#include <atomic>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ExtendedPolicy.h"
#include "RansomwareDetector.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

class RansomwareShield {
 public:
  explicit RansomwareShield(std::filesystem::path stateDirectory);
  ~RansomwareShield();
  RansomwareShield(const RansomwareShield&) = delete;
  RansomwareShield& operator=(const RansomwareShield&) = delete;

  // Applies (or re-applies) policy; starts or stops the watcher as needed. Safe to call every cycle.
  void Apply(const RansomwareSettings& settings);
  void Stop();
  std::vector<TelemetryRecord> DrainTelemetry();
  // Called when something urgent was queued (a detection), so the service can send it straight away.
  void SetUrgentCallback(std::function<void()> callback);
  // Restores the files of the most recent incident from the newest snapshot taken before it. Returns JSON.
  std::wstring RollbackLastIncident(const std::wstring& reason);
  bool WatcherActive() const { return etwActive_.load(); }

  // Canary file name placed in each protected folder.
  static constexpr const wchar_t* kCanaryName = L"$fenrir-canary-budget-2024.docx";

 private:
  enum class PendingKind { Write, CredentialRead, ExecutableCreate };
  struct PendingWrite {
    unsigned long pid;
    std::wstring devicePath;
    PendingKind kind{PendingKind::Write};
  };
  struct PendingDelete {
    std::wstring dosPath;
    unsigned long pid;
    std::wstring image;
    unsigned long long untilMs;
  };
  struct Incident {
    unsigned long long startedUnix{0};
    unsigned long long restoredUnix{0};  // set once the incident has been rolled back
    std::wstring image;
    unsigned long pid{0};
    std::vector<std::wstring> paths;  // DOS paths
  };

  static DWORD WINAPI EtwThreadEntry(LPVOID context);
  static VOID WINAPI EtwEventCallback(EVENT_RECORD* record);
  void OnEtwEvent(const EVENT_RECORD& record);
  bool StartEtw();
  void StopEtw();
  void WorkerLoop();
  void Reconfigure();
  void ProcessPending();
  void Handle(const ransomware::Observation& observation);
  void HandleCredentialRead(unsigned long pid, const std::wstring& devicePath);
  void HandleExecutableCreate(unsigned long pid, const std::wstring& devicePath);
  void RetryDeletes();
  bool IsSigned(const std::wstring& image);
  std::map<std::wstring, bool> signedCache_;
  std::map<unsigned long, unsigned long long> credentialReportedMs_;
  std::vector<PendingDelete> deletes_;
  void MaintainCanaries();
  void MaybeSnapshot();
  void Queue(const std::wstring& eventType, const std::wstring& summary, const std::wstring& payloadJson, bool urgent);
  std::wstring ImageFor(unsigned long pid);
  bool Killable(unsigned long pid, const std::wstring& image) const;
  bool Terminate(unsigned long pid, const std::wstring& image);
  std::wstring ToDosPath(const std::wstring& devicePath) const;
  std::wstring ToDevicePath(const std::wstring& dosPath) const;
  void SaveIncident(const Incident& incident);
  bool LoadIncident(Incident& incident) const;
  std::wstring Rollback(const Incident& incident, const std::wstring& reason);

  std::filesystem::path stateDirectory_;
  mutable std::mutex mutex_;  // settings, telemetry, device map
  RansomwareSettings settings_{};
  bool settingsApplied_{false};
  bool reconfigure_{false};
  std::vector<TelemetryRecord> telemetry_;
  std::function<void()> urgent_;
  std::vector<std::pair<std::wstring, std::wstring>> deviceToDos_;  // lower "\device\harddiskvolume3" -> "C:"
  std::vector<std::wstring> dosRoots_;                              // protected folders (DOS form)
  std::vector<std::wstring> canaryPaths_;                           // DOS form
  std::vector<std::wstring> profiles_;

  // ETW thread state. The filter is swapped under filterMutex_; the file-object map is ETW-thread only.
  std::mutex filterMutex_;
  std::vector<std::wstring> deviceRoots_;  // device form, used to pre-filter Create events
  std::vector<std::wstring> credentialRoots_;  // browser profile folders (device form)
  bool watchExecutableCreates_{false};
  struct FileObjectEntry {
    std::wstring path;
    unsigned long lastPid{0};
    unsigned long long lastQueuedMs{0};
  };
  std::map<unsigned long long, FileObjectEntry> fileObjects_;
  std::map<unsigned long long, int> layoutOk_;  // (event id << 8 | version) -> 1 fast path, -1 unsupported
  std::mutex pendingMutex_;
  std::vector<PendingWrite> pending_;
  std::atomic<unsigned long long> dropped_{0};

  ransomware::Detector detector_;
  std::map<unsigned long, std::pair<std::wstring, unsigned long long>> images_;  // pid -> (image, expiry)
  std::map<std::wstring, unsigned long long> canaryAlertedMs_;
  TRACEHANDLE session_{0};
  TRACEHANDLE trace_{0};
  HANDLE etwThread_{nullptr};
  std::atomic<bool> etwActive_{false};
  std::atomic<bool> stop_{false};
  std::thread worker_;
  std::thread snapshotThread_;
  std::atomic<bool> snapshotBusy_{false};
  std::mutex rollbackMutex_;
  unsigned long long lastCanaryCheckMs_{0};
  unsigned long long lastSnapshotCheckMs_{0};
  unsigned long long lastProfileRefreshMs_{0};
  unsigned long long lastEtwAttemptMs_{0};
  unsigned long long lastFullReconfigureMs_{0};
  bool degradedReported_{false};
};

}  // namespace antivirus::agent
