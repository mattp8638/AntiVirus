#include "DestinationEnforcementBridge.h"
#include "DestinationEventRecorder.h"
#include "DestinationProtection.h"
#include "DestinationRuntimeStore.h"
#include "DestinationVerdictEngine.h"
#include "PhishingHeuristics.h"

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <optional>
#include <set>

#define LookupDestinationReputation LookupDestinationReputation_Legacy
#include "ReputationLookup.cpp"
#undef LookupDestinationReputation

namespace antivirus::agent {
namespace {

DestinationPolicySnapshot LoadDestinationPolicyOrDefault(const std::filesystem::path& databasePath) {
  DestinationRuntimeStore store(databasePath);
  auto policy = CreateDefaultDestinationPolicySnapshot();
  if (!store.LoadPolicy(policy)) {
    store.SavePolicy(policy);
  }
  return policy;
}

std::vector<DestinationReasonCode> BuildPhase1DestinationReasonCodes(const ReputationLookupResult& result,
                                                                     const DestinationThreatCategory category) {
  std::vector<DestinationReasonCode> reasons;
  switch (category) {
    case DestinationThreatCategory::Phishing:
      reasons.push_back(DestinationReasonCode::KnownPhishingDestination);
      break;
    case DestinationThreatCategory::Scam:
      reasons.push_back(DestinationReasonCode::KnownScamDestination);
      break;
    case DestinationThreatCategory::Malware:
    case DestinationThreatCategory::CommandAndControl:
      reasons.push_back(DestinationReasonCode::KnownMaliciousDestination);
      break;
    case DestinationThreatCategory::Suspicious:
      reasons.push_back(DestinationReasonCode::SuspiciousTld);
      break;
    default:
      break;
  }

  if (result.fromCache) {
    reasons.push_back(DestinationReasonCode::CacheHit);
  }
  if (!result.lookupSucceeded) {
    reasons.push_back(DestinationReasonCode::CloudLookupUnavailable);
  }

  return reasons;
}

std::uint32_t BuildDestinationRiskConfidence(const ReputationLookupResult& result,
                                             const DestinationThreatCategory category) {
  if (category == DestinationThreatCategory::Clean) {
    return 0;
  }

  const auto trust = std::min<std::uint32_t>(result.trustScore, 100);
  if (result.malicious || category == DestinationThreatCategory::Phishing ||
      category == DestinationThreatCategory::Scam ||
      category == DestinationThreatCategory::CommandAndControl) {
    const auto inverted = 100u - trust;
    return std::clamp<std::uint32_t>(inverted + 20u, 1u, 100u);
  }

  return std::clamp<std::uint32_t>(100u - trust, 1u, 100u);
}

void AddUniqueReasons(std::vector<DestinationReasonCode>* target,
                      const std::vector<DestinationReasonCode>& values) {
  for (const auto value : values) {
    if (value == DestinationReasonCode::None) {
      continue;
    }
    if (std::find(target->begin(), target->end(), value) == target->end()) {
      target->push_back(value);
    }
  }
}

DestinationVerdict BuildPhase1DestinationVerdict(const DestinationContext& context,
                                                 const DestinationPolicySnapshot& policy,
                                                 const ReputationLookupResult& result) {
  DestinationVerdict verdict{};
  verdict.indicatorType = context.indicatorType;
  verdict.indicator = context.normalizedIndicator.empty() ? context.originalIndicator : context.normalizedIndicator;
  verdict.canonicalUrl = context.canonicalUrl;
  verdict.host = context.host.empty() ? verdict.indicator : context.host;
  verdict.source = context.source;
  verdict.provider = result.provider;
  verdict.category = MapReputationToDestinationCategory(result);
  verdict.confidence = BuildDestinationRiskConfidence(result, verdict.category);
  verdict.knownBad = result.malicious;
  verdict.suspicious = verdict.category == DestinationThreatCategory::Suspicious ||
                       verdict.category == DestinationThreatCategory::Phishing ||
                       verdict.category == DestinationThreatCategory::Scam;
  verdict.fromCache = result.fromCache;
  verdict.degradedMode = !result.lookupSucceeded;
  verdict.reasonCodes = BuildPhase1DestinationReasonCodes(result, verdict.category);
  verdict.action = DetermineDestinationAction(policy, verdict.category, verdict.confidence,
                                              verdict.knownBad, verdict.suspicious, false);
  verdict.userOverrideAllowed = verdict.action == DestinationAction::Warn ||
                                verdict.action == DestinationAction::DegradedAllow;
  verdict.summary = BuildDestinationSummary(verdict);
  verdict.details = BuildDestinationDetails(result, context, verdict);
  return verdict;
}

bool IsDestinationLikeIndicator(const ThreatIndicatorType indicatorType) {
  return indicatorType == ThreatIndicatorType::Domain || indicatorType == ThreatIndicatorType::Url ||
         indicatorType == ThreatIndicatorType::Ip;
}

std::optional<std::wstring> ExtractHostFromUrl(const std::wstring& url) {
  URL_COMPONENTSW components{};
  components.dwStructSize = sizeof(components);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  std::wstring mutableUrl = url;
  if (WinHttpCrackUrl(mutableUrl.data(), static_cast<DWORD>(mutableUrl.size()), 0, &components) == FALSE ||
      components.dwHostNameLength == 0) {
    return std::nullopt;
  }
  return std::wstring(components.lpszHostName, components.dwHostNameLength);
}

std::vector<std::wstring> ResolveHostAddresses(const std::wstring& host) {
  std::vector<std::wstring> results;
  if (host.empty()) {
    return results;
  }

  ADDRINFOW hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  ADDRINFOW* resultList = nullptr;
  if (GetAddrInfoW(host.c_str(), nullptr, &hints, &resultList) != 0 || resultList == nullptr) {
    return results;
  }

  std::set<std::wstring> unique;
  for (auto* entry = resultList; entry != nullptr; entry = entry->ai_next) {
    wchar_t buffer[INET6_ADDRSTRLEN] = {};
    if (entry->ai_family == AF_INET) {
      const auto* sockaddr = reinterpret_cast<const SOCKADDR_IN*>(entry->ai_addr);
      if (InetNtopW(AF_INET, &sockaddr->sin_addr, buffer, ARRAYSIZE(buffer)) != nullptr) {
        unique.insert(buffer);
      }
    } else if (entry->ai_family == AF_INET6) {
      const auto* sockaddr = reinterpret_cast<const SOCKADDR_IN6*>(entry->ai_addr);
      if (InetNtopW(AF_INET6, &sockaddr->sin6_addr, buffer, ARRAYSIZE(buffer)) != nullptr) {
        unique.insert(buffer);
      }
    }
  }

  FreeAddrInfoW(resultList);
  results.assign(unique.begin(), unique.end());
  return results;
}

std::vector<std::wstring> BuildRemoteAddressesForEnforcement(const DestinationContext& context) {
  std::vector<std::wstring> addresses;
  if (context.indicatorType == ThreatIndicatorType::Ip && !context.normalizedIndicator.empty()) {
    addresses.push_back(context.normalizedIndicator);
    return addresses;
  }

  std::wstring host = context.host;
  if (host.empty() && context.indicatorType == ThreatIndicatorType::Url && !context.canonicalUrl.empty()) {
    const auto extracted = ExtractHostFromUrl(context.canonicalUrl);
    if (extracted.has_value()) {
      host = *extracted;
    }
  }
  if (host.empty()) {
    host = context.normalizedIndicator;
  }

  return ResolveHostAddresses(host);
}

void MergeHeuristicAssessment(DestinationVerdict* verdict,
                              const PhishingHeuristicAssessment& assessment) {
  if (assessment.confidence == 0 || assessment.category == DestinationThreatCategory::Unknown) {
    return;
  }

  AddUniqueReasons(&verdict->reasonCodes, assessment.reasonCodes);
  verdict->confidence = std::max(verdict->confidence, assessment.confidence);
  verdict->suspicious = verdict->suspicious || assessment.suspicious;

  if (verdict->provider.empty() || verdict->provider == L"local-cache") {
    verdict->provider = L"local-heuristics";
  } else if (verdict->provider.find(L"heuristics") == std::wstring::npos) {
    verdict->provider += L"+heuristics";
  }

  if (assessment.category == DestinationThreatCategory::Phishing ||
      assessment.category == DestinationThreatCategory::Scam) {
    if (verdict->category == DestinationThreatCategory::Unknown ||
        verdict->category == DestinationThreatCategory::Clean ||
        verdict->category == DestinationThreatCategory::Suspicious) {
      verdict->category = assessment.category;
    }
  } else if (assessment.category == DestinationThreatCategory::Suspicious &&
             (verdict->category == DestinationThreatCategory::Unknown ||
              verdict->category == DestinationThreatCategory::Clean)) {
    verdict->category = DestinationThreatCategory::Suspicious;
  }

  if (!assessment.details.empty()) {
    if (!verdict->details.empty()) {
      verdict->details += L" ";
    }
    verdict->details += assessment.details;
  }
}

}  // namespace

ReputationLookupResult LookupDestinationReputation(const std::wstring& indicator,
                                                   const std::filesystem::path& databasePath) {
  const auto resolvedDatabasePath = ResolveDatabasePath(databasePath);
  const auto result = LookupDestinationReputation_Legacy(indicator, resolvedDatabasePath);
  if (!result.attempted || !IsDestinationLikeIndicator(result.indicatorType)) {
    return result;
  }

  const auto destinationPolicy = LoadDestinationPolicyOrDefault(resolvedDatabasePath);

  DestinationContext context{};
  context.indicatorType = result.indicatorType;
  context.originalIndicator = indicator;
  context.normalizedIndicator = NormalizeDestinationIndicator(result.indicatorType, indicator);
  context.canonicalUrl = result.indicatorType == ThreatIndicatorType::Url ? context.normalizedIndicator : L"";
  context.host = result.indicatorType == ThreatIndicatorType::Domain || result.indicatorType == ThreatIndicatorType::Ip
                     ? context.normalizedIndicator
                     : L"";
  context.source = L"reputation-lookup";
  context.observedAt = CurrentUtcTimestamp();
  context.fromCache = result.fromCache;
  context.offlineMode = !result.lookupSucceeded;

  auto verdict = BuildPhase1DestinationVerdict(context, destinationPolicy, result);
  if (destinationPolicy.antiPhishingEnabled &&
      (context.indicatorType == ThreatIndicatorType::Domain || context.indicatorType == ThreatIndicatorType::Url)) {
    const auto heuristicAssessment = ScorePhishingHeuristics(context);
    MergeHeuristicAssessment(&verdict, heuristicAssessment);
    verdict.action = DetermineDestinationAction(destinationPolicy, verdict.category, verdict.confidence,
                                                verdict.knownBad, verdict.suspicious, false);
    verdict.userOverrideAllowed = verdict.action == DestinationAction::Warn ||
                                  verdict.action == DestinationAction::DegradedAllow;
    verdict.summary = BuildDestinationSummary(verdict);
  }

  DestinationVerdictEngine evidenceBuilder(resolvedDatabasePath);
  const auto evidence = evidenceBuilder.BuildEvidenceRecord(context, destinationPolicy, verdict,
                                                            L"policy-default", L"phase1-chunk3-phishing");
  const auto intelRecord = BuildDestinationIntelligenceRecord(context, verdict, evidence,
                                                              destinationPolicy.destinationCacheTtlMinutes);

  DestinationRuntimeStore destinationStore(resolvedDatabasePath);
  destinationStore.UpsertIntelligenceRecord(intelRecord);
  destinationStore.PurgeExpiredIntelligenceRecords();

  if (verdict.action == DestinationAction::Warn || verdict.action == DestinationAction::Block ||
      verdict.action == DestinationAction::DegradedAllow) {
    RuntimeDatabase(resolvedDatabasePath).RecordScanHistory(
        BuildDestinationScanHistoryRecord(context, verdict, evidence));
  }

  if (verdict.action == DestinationAction::Block) {
    DestinationEnforcementRequest request{};
    request.requestId = intelRecord.normalizedIndicator;
    request.displayDestination = verdict.host.empty() ? verdict.indicator : verdict.host;
    request.remoteAddresses = BuildRemoteAddressesForEnforcement(context);
    request.sourceApplication = context.sourceApplication;
    request.summary = verdict.summary.empty() ? BuildDestinationSummary(verdict) : verdict.summary;
    request.reason = verdict.details.empty() ? DestinationThreatCategoryToString(verdict.category) : verdict.details;
    request.expiresAt = intelRecord.expiresAt;
    if (!request.remoteAddresses.empty()) {
      std::wstring enforcementError;
      if (!InvokeDestinationEnforcementHandler(request, &enforcementError)) {
        RuntimeDatabase(resolvedDatabasePath).RecordScanHistory(ScanHistoryRecord{
            .recordedAt = CurrentUtcTimestamp(),
            .source = L"destination-enforcement",
            .subjectPath = std::filesystem::path(request.displayDestination),
            .sha256 = L"",
            .contentType = L"destination-enforcement-failure",
            .reputation = enforcementError.empty() ? L"Destination block enforcement failed."
                                                   : L"Destination block enforcement failed: " + enforcementError,
            .disposition = L"degraded",
            .confidence = verdict.confidence,
            .tacticId = verdict.category == DestinationThreatCategory::Phishing ? L"TA0001" : L"TA0011",
            .techniqueId = verdict.category == DestinationThreatCategory::Phishing ? L"T1566" : L"T1105",
            .remediationStatus = L"enforcement-failed",
            .evidenceRecordId = evidence.evidenceId,
            .quarantineRecordId = L"",
            .alertTitle = L"Website block enforcement degraded",
            .contextType = context.browserInitiated ? L"browser" : (context.emailOriginated ? L"email" : L"destination"),
            .sourceApplication = context.sourceApplication,
            .originReference = !context.sourceDomain.empty() ? context.sourceDomain : request.displayDestination,
            .contextJson = evidence.metadataJson});
      }
    }
  }

  return result;
}

}  // namespace antivirus::agent
