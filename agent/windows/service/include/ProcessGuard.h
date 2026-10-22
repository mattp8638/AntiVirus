#pragma once

#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ExtendedPolicy.h"
#include "PolicySnapshot.h"
#include "TelemetryRecord.h"

namespace antivirus::agent {

struct EtwProcessContext;

// Applies attack surface reduction, application control and the static ML
// model to every new process reported by the ETW sensor, and terminates the
// process when policy says block. Thread-safe: called on the ETW thread while
// the service thread updates policy.
//
// Without a kernel callback this acts just after process creation, not before.
class ProcessGuard {
 public:
  ProcessGuard(std::filesystem::path installRoot, std::filesystem::path runtimeRoot);

  // Updates policy; persists/loads the modules JSON so settings survive restarts.
  void UpdatePolicy(const PolicySnapshot& policy);
  ExtendedPolicy CurrentExtendedPolicy() const;

  std::vector<TelemetryRecord> OnProcessStart(const EtwProcessContext& process);

  // Applies device control settings; returns telemetry describing the result.
  std::vector<TelemetryRecord> ApplyDeviceControl();

  std::filesystem::path ModelPath() const;

  // Terminates one process (and optionally its children) only if its image still matches
  // expectedImagePath. Returns the number terminated, or -1 if the process is gone or different.
  static int TerminateIfImageMatches(unsigned long pid, const std::wstring& expectedImagePath, bool includeChildren);

 private:
  std::filesystem::path installRoot_;
  std::filesystem::path runtimeRoot_;
  mutable std::mutex mutex_;
  PolicySnapshot policy_{};
  ExtendedPolicy extended_{};
  std::wstring appliedDeviceControlSummary_;
  std::map<std::wstring, double> mlCache_;
};

}  // namespace antivirus::agent
