#pragma once

#include <Windows.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::agent {

struct AgentConfig {
  std::wstring controlPlaneBaseUrl{L"https://api.fenrir-security.co.uk"};
  // Managed mode enrolls with the Fenrir cloud, sends heartbeats and telemetry, and runs commands.
  // Off by default (standalone, update-only); turned on when a cloud URL is configured.
  bool managedMode{false};
  std::wstring enrollmentToken{};
  std::wstring signatureFeedToken{};
  std::filesystem::path installRootPath{};
  std::filesystem::path runtimeDatabasePath{std::filesystem::path(L"runtime") / L"agent-runtime.db"};
  std::filesystem::path stateFilePath{std::filesystem::path(L"runtime") / L"agent-state.ini"};
  std::filesystem::path telemetryQueuePath{std::filesystem::path(L"runtime") / L"telemetry-queue.tsv"};
  std::filesystem::path updateRootPath{std::filesystem::path(L"runtime") / L"updates"};
  std::filesystem::path journalRootPath{std::filesystem::path(L"runtime") / L"journal"};
  std::filesystem::path elamDriverPath{};
  std::filesystem::path quarantineRootPath{std::filesystem::path(L"runtime") / L"quarantine"};
  std::filesystem::path evidenceRootPath{std::filesystem::path(L"runtime") / L"evidence"};
  std::filesystem::path threatIntelPackPath{};
  std::filesystem::path cleanwareSignerListPath{std::filesystem::path(L"signatures") /
                                                L"default-cleanware-signers.tsv"};
  std::filesystem::path knownGoodHashListPath{std::filesystem::path(L"signatures") /
                                              L"default-known-good-hashes.tsv"};
  std::filesystem::path observeOnlyRuleListPath{std::filesystem::path(L"signatures") /
                                                L"default-observe-only.tsv"};
  std::filesystem::path phase2CleanwareCorpusPath{};
  std::filesystem::path phase2FalsePositiveCorpusPath{};
  std::filesystem::path phase2RuleQualityReportPath{std::filesystem::path(L"runtime") /
                                                    L"phase2-rule-quality.json"};
  std::wstring realtimeProtectionPortName{L"\\AntiVirusRealtimePort"};
  std::wstring agentVersion{L"0.1.0-alpha"};
  std::wstring platformVersion{L"platform-0.1.0"};
  int syncIntervalSeconds{60};
  int syncIterations{1};
  int scheduledQuickScanIntervalMinutes{1440};
  int scheduledFullDriveScanIntervalMinutes{10080};
  int liveThreatSweepIntervalMinutes{30};
  int vulnerabilityAssessmentIntervalMinutes{240};
  int telemetryBatchSize{25};
  int realtimeBrokerRetrySeconds{5};
  int realtimeCoverageStartupTimeoutSeconds{30};
  bool failServiceStartupIfRealtimeCoverageMissing{true};
  bool enforceProcessStartVerdicts{true};
  bool terminateProcessTreeOnExecuteBlock{true};
  bool strictRealtimeMode{true};
  bool enforceOperationalGates{true};
  int maxCpuLoadPercent{85};
  int maxMemoryLoadPercent{90};
  int minFreeDiskMb{1024};
  bool deferHeavyActionsOnBattery{true};
  bool enforceReleasePromotionGates{true};
  int phase2FalsePositiveBudgetPercent{2};
  int phase2MaxFalsePositiveFindings{2};
  int phase2MinRuleQualityScore{70};
  int phase2MinMaliciousPassRatePercent{90};
  int phase2MinCleanwarePassRatePercent{98};
  int genericRuleScoreCap{34};
  int benignContextDampeningScore{30};
  int nonExecuteRealtimeBlockBias{10};
  int reputationKnownGoodDampeningBonus{25};
  bool isolationAllowLoopback{true};
  std::vector<std::wstring> isolationAllowedRemoteAddresses{};
  std::vector<std::wstring> isolationAllowedApplications{};
  std::vector<std::filesystem::path> scanExcludedPaths{};
};

struct RuntimePathValidation {
  bool trusted{false};
  std::filesystem::path installRootPath;
  std::filesystem::path runtimeRootPath;
  std::wstring message;
};

struct ScanExclusionEntry {
  std::filesystem::path path;
  std::wstring createdAt;
  std::wstring expiresAt;
  std::wstring createdBy;
  std::wstring reason;
  std::wstring riskLevel;
  bool dangerous{false};
};

struct ScanScheduleSettings {
  int quickScanIntervalMinutes{1440};
  int fullScanIntervalMinutes{10080};
};

AgentConfig LoadAgentConfig();
// Saves the cloud URL and enrollment token (HKLM) and turns managed mode on. Needs Administrator.
bool SaveCloudEnrollmentSettings(const std::wstring& serverUrl, const std::wstring& enrollmentToken);
AgentConfig LoadAgentConfigForModule(HMODULE moduleHandle);
RuntimePathValidation ValidateRuntimePaths(const AgentConfig& config);
std::vector<std::filesystem::path> LoadConfiguredScanExclusions();
bool SaveConfiguredScanExclusions(const std::vector<std::filesystem::path>& exclusions);
ScanScheduleSettings LoadConfiguredScanScheduleSettings();
bool SaveConfiguredScanScheduleSettings(const ScanScheduleSettings& scheduleSettings);
std::vector<ScanExclusionEntry> LoadConfiguredScanExclusionEntries();
bool SaveConfiguredScanExclusionEntries(const std::vector<ScanExclusionEntry>& exclusions);
std::wstring DescribeExclusionRisk(const std::filesystem::path& path);
bool IsDangerousExclusionPath(const std::filesystem::path& path);

}  // namespace antivirus::agent
