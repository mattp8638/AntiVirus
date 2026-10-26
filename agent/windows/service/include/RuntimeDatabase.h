#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "AgentState.h"
#include "ControlPlaneClient.h"
#include "PatchOrchestrator.h"
#include "TelemetryRecord.h"
#include "ThreatIntelligence.h"

namespace antivirus::agent {

struct QuarantineIndexRecord {
  std::wstring recordId;
  std::wstring capturedAt;
  std::filesystem::path originalPath;
  std::filesystem::path quarantinedPath;
  std::wstring sha256;
  std::uintmax_t sizeBytes{0};
  std::wstring techniqueId;
  std::wstring localStatus;
};

struct EvidenceIndexRecord {
  std::wstring recordId;
  std::wstring recordedAt;
  std::wstring source;
  std::filesystem::path recordPath;
  std::filesystem::path subjectPath;
  std::wstring sha256;
  std::wstring disposition;
  std::wstring tacticId;
  std::wstring techniqueId;
  std::wstring appName;
  std::wstring contentName;
  std::wstring alertTitle;
  std::wstring contextType;
  std::wstring sourceApplication;
  std::wstring originReference;
  std::wstring contextJson;
};

struct ScanHistoryRecord {
  std::wstring recordedAt;
  std::wstring source;
  std::filesystem::path subjectPath;
  std::wstring sha256;
  std::wstring contentType;
  std::wstring reputation;
  std::wstring disposition;
  std::uint32_t confidence{0};
  std::wstring tacticId;
  std::wstring techniqueId;
  std::wstring remediationStatus;
  std::wstring evidenceRecordId;
  std::wstring quarantineRecordId;
  std::wstring alertTitle;
  std::wstring contextType;
  std::wstring sourceApplication;
  std::wstring originReference;
  std::wstring contextJson;
};

struct DownloadContextRecord {
  std::filesystem::path targetPath;
  std::wstring observedAt;
  std::wstring channel;
  std::wstring browserFamily;
  std::wstring sourceApplication;
  std::wstring parentApplication;
  std::wstring sourceDomain;
  std::wstring sourceUrl;
  std::wstring navigationType;
  std::wstring reputationAtObservation;
  std::wstring contextJson;
};

struct UpdateJournalRecord {
  std::wstring transactionId;
  std::wstring packageId;
  std::wstring packageType;
  std::wstring targetVersion;
  std::filesystem::path manifestPath;
  std::filesystem::path backupRoot;
  std::filesystem::path stagedRoot;
  std::wstring startedAt;
  std::wstring completedAt;
  std::wstring status;
  std::wstring resultJson;
  bool requiresRestart{false};
};

struct BlockedSoftwareRule {
  std::wstring softwareId;
  std::wstring displayName;
  std::wstring installLocation;
  std::vector<std::wstring> executableNames;
  std::wstring blockedAt;
};

struct LocalAdminBaselineMemberRecord {
  std::wstring baselineId;
  std::wstring capturedAt;
  std::wstring capturedBy;
  std::wstring accountName;
  std::wstring sid;
  std::wstring memberClass;
  bool protectedMember{false};
  bool managedCandidate{false};
};

struct TrustedSignerRecord {
  std::wstring signerName;
  std::wstring publisher;
  std::wstring trustLevel;
  std::wstring source;
  std::wstring summary;
  std::wstring details;
  std::wstring firstSeenAt;
  std::wstring lastSeenAt;
  std::wstring expiresAt;
  std::uint32_t prevalence{0};
  bool allowSuppression{true};
};

struct KnownGoodHashRecord {
  std::wstring sha256;
  std::wstring source;
  std::wstring summary;
  std::wstring details;
  std::wstring signerName;
  std::wstring firstSeenAt;
  std::wstring lastSeenAt;
  std::wstring expiresAt;
  std::uint32_t prevalence{0};
};

struct ThreatPrevalenceRecord {
  ThreatIndicatorType indicatorType{ThreatIndicatorType::Unknown};
  std::wstring indicatorKey;
  std::uint64_t sightingCount{0};
  std::wstring firstSeenAt;
  std::wstring lastSeenAt;
  std::wstring lastSource;
};

struct RealtimeFeedbackRecord {
  std::wstring feedbackId;
  std::wstring correlationId;
  std::filesystem::path subjectPath;
  std::wstring sha256;
  std::wstring disposition;
  std::wstring action;
  std::wstring reasonCode;
  std::wstring feedbackSource;
  std::wstring operatorName;
  std::wstring notes;
  int confidenceDelta{0};
  std::wstring createdAt;
};

struct SelfTestOutcomeRecord {
  std::wstring checkId;
  std::wstring checkName;
  std::wstring status;
  std::wstring details;
  std::wstring remediation;
  std::wstring phase;
  std::wstring buildVersion;
  std::wstring recordedAt;
};

struct RuleQualityRecord {
  std::wstring ruleCode;
  std::wstring phase;
  std::uint32_t maliciousHits{0};
  std::uint32_t benignHits{0};
  std::uint32_t totalEvaluations{0};
  std::uint32_t qualityScore{0};
  std::wstring summary;
  std::wstring details;
  std::wstring updatedAt;
};

class RuntimeDatabase {
 public:
  explicit RuntimeDatabase(std::filesystem::path databasePath);

  bool LoadAgentState(AgentState& state) const;
  void SaveAgentState(const AgentState& state) const;

  std::vector<TelemetryRecord> LoadTelemetryQueue() const;
  void ReplaceTelemetryQueue(const std::vector<TelemetryRecord>& records) const;
  // Append-only writers (service, scans, scanner CLI) and delete-after-delivery keep concurrent
  // writers from overwriting each other's queued events.
  void AppendTelemetryQueue(const std::vector<TelemetryRecord>& records) const;
  void DeleteTelemetryEvents(const std::vector<std::wstring>& eventIds) const;
  std::size_t TrimTelemetryQueue(std::size_t keepNewest) const;
  std::size_t CountTelemetryQueue() const;

  void UpsertCommandJournal(const RemoteCommand& command, const std::wstring& status, const std::wstring& resultJson,
                            const std::wstring& lastError) const;
  void UpdateCommandJournalStatus(const std::wstring& commandId, const std::wstring& status,
                                  const std::wstring& resultJson, const std::wstring& lastError) const;
  bool LoadCommandJournal(const std::wstring& commandId, std::wstring& status, std::wstring& resultJson) const;

  bool LoadQuarantineRecord(const std::wstring& recordId, QuarantineIndexRecord& record) const;
  void UpsertQuarantineRecord(const QuarantineIndexRecord& record) const;
  std::vector<QuarantineIndexRecord> ListQuarantineRecords(std::size_t limit = 100) const;

  void UpsertEvidenceRecord(const EvidenceIndexRecord& record) const;
  std::vector<EvidenceIndexRecord> ListEvidenceRecords(std::size_t limit = 100) const;
  void RecordScanHistory(const ScanHistoryRecord& record) const;
  std::vector<ScanHistoryRecord> ListScanHistory(std::size_t limit = 100) const;
  void UpsertDownloadContextRecord(const DownloadContextRecord& record) const;
  bool TryGetDownloadContextRecord(const std::filesystem::path& targetPath, DownloadContextRecord& record) const;

  void UpsertUpdateJournal(const UpdateJournalRecord& record) const;
  bool LoadUpdateJournal(const std::wstring& transactionId, UpdateJournalRecord& record) const;
  std::vector<UpdateJournalRecord> ListUpdateJournal(std::size_t limit = 20) const;
  void UpsertBlockedSoftwareRule(const BlockedSoftwareRule& record) const;
  std::vector<BlockedSoftwareRule> ListBlockedSoftwareRules(std::size_t limit = 200) const;
  void SavePatchPolicy(const PatchPolicyRecord& record) const;
  bool LoadPatchPolicy(PatchPolicyRecord& record) const;
  void ReplaceWindowsUpdateRecords(const std::vector<WindowsUpdateRecord>& records) const;
  std::vector<WindowsUpdateRecord> ListWindowsUpdateRecords(std::size_t limit = 200) const;
  void ReplaceSoftwarePatchRecords(const std::vector<SoftwarePatchRecord>& records) const;
  std::vector<SoftwarePatchRecord> ListSoftwarePatchRecords(std::size_t limit = 500) const;
  void UpsertPatchHistoryRecord(const PatchHistoryRecord& record) const;
  std::vector<PatchHistoryRecord> ListPatchHistoryRecords(std::size_t limit = 200) const;
  void ReplacePackageRecipes(const std::vector<PackageRecipeRecord>& records) const;
  std::vector<PackageRecipeRecord> ListPackageRecipes(std::size_t limit = 500) const;
  void SaveRebootCoordinator(const RebootCoordinatorRecord& record) const;
  bool LoadRebootCoordinator(RebootCoordinatorRecord& record) const;
  void UpsertThreatIntelRecord(const ThreatIntelRecord& record) const;
  bool TryGetThreatIntelRecord(ThreatIndicatorType indicatorType, const std::wstring& indicatorKey,
                               ThreatIntelRecord& record) const;
  std::vector<ThreatIntelRecord> ListThreatIntelRecords(std::size_t limit = 200) const;
  void PurgeExpiredThreatIntelRecords(const std::wstring& referenceTimestamp) const;
  void UpsertTrustedSignerRecord(const TrustedSignerRecord& record) const;
  bool TryGetTrustedSignerRecord(const std::wstring& signerName, TrustedSignerRecord& record) const;
  std::vector<TrustedSignerRecord> ListTrustedSignerRecords(std::size_t limit = 200) const;
  void UpsertKnownGoodHashRecord(const KnownGoodHashRecord& record) const;
  bool TryGetKnownGoodHashRecord(const std::wstring& sha256, KnownGoodHashRecord& record) const;
  std::vector<KnownGoodHashRecord> ListKnownGoodHashRecords(std::size_t limit = 200) const;
  void UpsertThreatPrevalenceRecord(const ThreatPrevalenceRecord& record) const;
  bool TryGetThreatPrevalenceRecord(ThreatIndicatorType indicatorType, const std::wstring& indicatorKey,
                                    ThreatPrevalenceRecord& record) const;
  void UpsertRealtimeFeedbackRecord(const RealtimeFeedbackRecord& record) const;
  std::vector<RealtimeFeedbackRecord> ListRealtimeFeedbackRecords(std::size_t limit = 200) const;
  void UpsertSelfTestOutcomeRecord(const SelfTestOutcomeRecord& record) const;
  std::vector<SelfTestOutcomeRecord> ListSelfTestOutcomeRecords(const std::wstring& phase = {},
                                                                std::size_t limit = 200) const;
  void UpsertRuleQualityRecord(const RuleQualityRecord& record) const;
  std::vector<RuleQualityRecord> ListRuleQualityRecords(const std::wstring& phase = {},
                                                        std::size_t limit = 200) const;
  void UpsertExclusionPolicyRecord(const ExclusionPolicyRecord& record) const;
  std::vector<ExclusionPolicyRecord> ListExclusionPolicyRecords(std::size_t limit = 200) const;
  void UpsertQuarantineApprovalRecord(const QuarantineApprovalRecord& record) const;
  std::vector<QuarantineApprovalRecord> ListQuarantineApprovalRecords(std::size_t limit = 200) const;
  void ReplaceLocalAdminBaselineSnapshot(const std::wstring& baselineId, const std::wstring& capturedAt,
                                         const std::wstring& capturedBy,
                                         const std::vector<LocalAdminBaselineMemberRecord>& members) const;
  std::vector<LocalAdminBaselineMemberRecord> ListLocalAdminBaselineSnapshot(const std::wstring& baselineId,
                                                                              std::size_t limit = 512) const;
  std::vector<LocalAdminBaselineMemberRecord> ListLatestLocalAdminBaselineSnapshot(std::size_t limit = 512) const;

 private:
  std::filesystem::path databasePath_;
};

}  // namespace antivirus::agent
