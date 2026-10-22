#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace antivirus::agent {

struct PolicySnapshot {
  std::wstring policyId;
  std::wstring policyName;
  std::wstring revision;
  bool realtimeProtectionEnabled{true};
  bool cloudLookupEnabled{true};
  bool scriptInspectionEnabled{true};
  bool networkContainmentEnabled{false};
  bool quarantineOnMalicious{true};
  std::uint32_t scanMaliciousBlockThreshold{45};
  std::uint32_t scanMaliciousQuarantineThreshold{70};
  std::uint32_t scanBenignDampeningScore{20};
  std::uint32_t genericRuleScoreScalePercent{75};
  std::uint32_t realtimeExecuteBlockThreshold{55};
  std::uint32_t realtimeNonExecuteBlockThreshold{60};
  std::uint32_t realtimeQuarantineThreshold{75};
  std::uint32_t realtimeObserveTelemetryThreshold{35};
  bool realtimeObserveOnlyForNonExecute{false};
  bool terminateProcessTreeOnExecuteBlock{true};
  bool enforceProcessStartVerdicts{true};
  bool quarantineAfterProcessKill{true};
  bool failServiceStartupIfRealtimeCoverageMissing{true};
  bool requireMinifilterBrokerConnection{true};
  bool archiveObserveOnly{false};
  bool networkObserveOnly{false};
  bool cloudLookupObserveOnly{false};
  bool requireSignerForSuppression{false};
  bool allowUnsignedSuppressionPathExecutables{false};
  bool enableCleanwareSignerDampening{true};
  bool enableKnownGoodHashDampening{true};
  bool destinationProtectionEnabled{true};
  bool antiPhishingEnabled{true};
  bool webProtectionEnabled{true};
  bool emailLinkProtectionEnabled{true};
  bool evaluateDomains{true};
  bool evaluateUrls{true};
  bool blockKnownMaliciousDestinations{true};
  bool blockKnownPhishingDestinations{true};
  bool blockKnownScamDestinations{false};
  bool warnOnSuspiciousDestinations{true};
  bool warnOnNewlyRegisteredDomains{true};
  bool allowDegradedDestinationModeWhenOffline{true};
  bool browserContextRequiredForWarnOnly{false};
  std::uint32_t suspiciousDestinationWarnThreshold{45};
  std::uint32_t phishingWarnThreshold{55};
  std::uint32_t phishingBlockThreshold{80};
  std::uint32_t destinationCacheTtlMinutes{240};
  std::vector<std::wstring> suppressionPathRoots;
  std::vector<std::wstring> suppressionSha256;
  std::vector<std::wstring> suppressionSignerNames;
  // Raw "modules" object from Fenrir Cloud (UTF-8 JSON); parsed by ExtendedPolicy.
  std::string modulesJson;
};

inline PolicySnapshot CreateDefaultPolicySnapshot() {
  return PolicySnapshot{
      .policyId = L"policy-default",
      .policyName = L"Local Protection Baseline",
      .revision = L"local-bootstrap",
      .realtimeProtectionEnabled = true,
      .cloudLookupEnabled = true,
      .scriptInspectionEnabled = true,
      .networkContainmentEnabled = true,
      .quarantineOnMalicious = true,
      .scanMaliciousBlockThreshold = 45,
      .scanMaliciousQuarantineThreshold = 70,
      .scanBenignDampeningScore = 20,
      .genericRuleScoreScalePercent = 75,
      .realtimeExecuteBlockThreshold = 55,
      .realtimeNonExecuteBlockThreshold = 60,
      .realtimeQuarantineThreshold = 75,
      .realtimeObserveTelemetryThreshold = 35,
      .realtimeObserveOnlyForNonExecute = false,
      .terminateProcessTreeOnExecuteBlock = true,
      .enforceProcessStartVerdicts = true,
      .quarantineAfterProcessKill = true,
      .failServiceStartupIfRealtimeCoverageMissing = true,
      .requireMinifilterBrokerConnection = true,
      .archiveObserveOnly = false,
      .networkObserveOnly = false,
      .cloudLookupObserveOnly = false,
      .requireSignerForSuppression = false,
      .allowUnsignedSuppressionPathExecutables = false,
      .enableCleanwareSignerDampening = true,
      .enableKnownGoodHashDampening = true,
      .destinationProtectionEnabled = true,
      .antiPhishingEnabled = true,
      .webProtectionEnabled = true,
      .emailLinkProtectionEnabled = true,
      .evaluateDomains = true,
      .evaluateUrls = true,
      .blockKnownMaliciousDestinations = true,
      .blockKnownPhishingDestinations = true,
      .blockKnownScamDestinations = false,
      .warnOnSuspiciousDestinations = true,
      .warnOnNewlyRegisteredDomains = true,
      .allowDegradedDestinationModeWhenOffline = true,
      .browserContextRequiredForWarnOnly = false,
      .suspiciousDestinationWarnThreshold = 45,
      .phishingWarnThreshold = 55,
      .phishingBlockThreshold = 80,
      .destinationCacheTtlMinutes = 240,
      .suppressionPathRoots = {},
      .suppressionSha256 = {},
      .suppressionSignerNames = {}};
}

}  // namespace antivirus::agent
