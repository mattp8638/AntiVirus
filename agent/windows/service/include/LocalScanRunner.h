#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "AgentConfig.h"
#include "AgentState.h"
#include "ScanEngine.h"

namespace antivirus::agent {

struct LocalScanExecutionOptions {
  bool queueTelemetry{true};
  bool applyRemediation{true};
  std::wstring source{L"endpoint-client"};
};

struct LocalScanExecutionResult {
  std::size_t targetCount{0};
  std::vector<ScanFinding> findings;
  bool remediationFailed{false};
};

struct LocalScanProgressUpdate {
  std::size_t completedTargets{0};
  std::size_t totalTargets{0};
  std::size_t findingCount{0};
  std::filesystem::path currentTarget;
};

using LocalScanProgressCallback = std::function<void(const LocalScanProgressUpdate&)>;

std::vector<std::filesystem::path> ResolveScanTargets(const std::vector<std::filesystem::path>& requestedTargets,
                                                      bool allowMissingFiles = false);
std::vector<std::filesystem::path> BuildQuickScanTargets();
std::vector<std::filesystem::path> BuildFullScanTargets(bool includeNetworkDrives = false);

LocalScanExecutionResult ExecuteLocalScan(const AgentConfig& config, const AgentState& state,
                                          const std::vector<std::filesystem::path>& targets,
                                          const LocalScanExecutionOptions& options,
                                          const LocalScanProgressCallback& progressCallback = {});

}  // namespace antivirus::agent
