#pragma once

// firewall.bruteForceProtection on Windows: reads failed sign-ins (Security event 4625, which covers RDP and
// SMB/network logons) and blocks an address with a Windows Firewall rule once it fails too often.
// Blocks survive restarts (brute-force-blocks.json) and are lifted when they expire or the setting is off.

#include <windows.h>

#include <atomic>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "BruteForceTracker.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

class BruteForceGuard {
 public:
  explicit BruteForceGuard(std::filesystem::path stateDirectory);
  ~BruteForceGuard();
  BruteForceGuard(const BruteForceGuard&) = delete;
  BruteForceGuard& operator=(const BruteForceGuard&) = delete;

  void Apply(bool enabled);
  void Stop();
  std::vector<TelemetryRecord> DrainTelemetry();
  void SetUrgentCallback(std::function<void()> callback);

 private:
  void Loop();
  void Poll();
  bool SetRule(const std::wstring& address, bool block);
  void Save();
  void Load();
  void Queue(const std::wstring& eventType, const std::wstring& summary, const std::wstring& payload, bool urgent);

  std::filesystem::path stateDirectory_;
  std::mutex mutex_;
  bool enabled_{false};
  bool applied_{false};
  std::vector<TelemetryRecord> telemetry_;
  std::function<void()> urgent_;
  bruteforce::Tracker tracker_;
  unsigned long long lastRecordId_{0};
  bool loaded_{false};
  bool readErrorReported_{false};
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

}  // namespace antivirus::agent
