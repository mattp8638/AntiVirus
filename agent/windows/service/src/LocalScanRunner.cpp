#include "LocalScanRunner.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <set>
#include <system_error>

#include "EvidenceRecorder.h"
#include "QuarantineStore.h"
#include "RemediationEngine.h"
#include "RuntimeDatabase.h"
#include "StringUtils.h"
#include "TelemetryQueueStore.h"

namespace antivirus::agent {
namespace {

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool RequiresProcessContainment(const ScanFinding& finding) {
  if (finding.path.empty()) {
    return false;
  }

  const auto extension = ToLowerCopy(finding.path.extension().wstring());
  return extension == L".exe" || extension == L".dll" || extension == L".scr" || extension == L".msi" ||
         extension == L".com" || extension == L".ps1" || extension == L".psm1" || extension == L".cmd" ||
         extension == L".bat" || extension == L".js" || extension == L".jse" || extension == L".vbs" ||
         extension == L".vbe" || extension == L".hta" || extension == L".lnk";
}

void QueueTelemetry(const AgentConfig& config, const PolicySnapshot& policy, const std::vector<ScanFinding>& findings,
                    const std::size_t targetCount, const std::wstring& source) {
  TelemetryQueueStore queueStore(config.runtimeDatabasePath, config.telemetryQueuePath);
  auto pending = queueStore.LoadPending();

  pending.push_back(BuildScanSummaryTelemetry(targetCount, findings.size(), policy, source));
  for (const auto& finding : findings) {
    pending.push_back(BuildScanFindingTelemetry(finding, source));
  }

  queueStore.SavePending(pending);
}

void ApplyLocalRemediation(const AgentConfig& config, std::vector<ScanFinding>& findings, const bool applyRemediation) {
  if (!applyRemediation) {
    return;
  }

  QuarantineStore quarantineStore(config.quarantineRootPath, config.runtimeDatabasePath);
  RemediationEngine remediationEngine(config);
  for (auto& finding : findings) {
    if (finding.verdict.disposition == VerdictDisposition::Allow || finding.path.empty()) {
      continue;
    }

    if (IsProtectedSystemLocation(finding.path, config.installRootPath)) {
      finding.verdict.reasons.push_back(
          {L"PROTECTED_LOCATION", L"Fenrir left this file in place because it is in a Windows, Program Files or "
                                  L"Fenrir folder, where it never removes files. Review the alert and remove "
                                  L"the file by hand if it is malicious."});
      continue;
    }

    if (RequiresProcessContainment(finding)) {
      const auto containment = remediationEngine.TerminateProcessesForPath(finding.path, true);
      if (containment.processesTerminated > 0) {
        finding.verdict.reasons.push_back(
            {L"PROCESS_TREE_CONTAINED",
             L"Fenrir terminated " + std::to_wstring(containment.processesTerminated) +
                 L" related process(es) before quarantine."});
      }
    }

    auto result = quarantineStore.QuarantineFile(finding);
    if (!result.success && RequiresProcessContainment(finding)) {
      const auto retryContainment = remediationEngine.TerminateProcessesForPath(finding.path, true);
      if (retryContainment.processesTerminated > 0) {
        finding.verdict.reasons.push_back(
            {L"PROCESS_TREE_CONTAINED_RETRY",
             L"Fenrir terminated " + std::to_wstring(retryContainment.processesTerminated) +
                 L" additional process(es) before retrying quarantine."});
      }
      result = quarantineStore.QuarantineFile(finding);
    }

    if (!result.recordId.empty()) {
      finding.quarantineRecordId = result.recordId;
    }
    if (!result.quarantinedPath.empty()) {
      finding.quarantinedPath = result.quarantinedPath;
    }

    if (result.success) {
      finding.remediationStatus = RemediationStatus::Quarantined;
      finding.verdict.reasons.push_back(
          {L"QUARANTINE_APPLIED", L"Fenrir moved this artifact into local quarantine."});
      if (!result.localStatus.empty()) {
        finding.verdict.reasons.push_back(
            {L"QUARANTINE_STATUS", L"Quarantine status: " + result.localStatus + L"."});
      }
      if (!result.verificationDetail.empty()) {
        finding.verdict.reasons.push_back({L"QUARANTINE_VERIFIED", result.verificationDetail});
      }
      continue;
    }

    finding.remediationStatus = RemediationStatus::Failed;
    finding.remediationError = result.errorMessage.empty() ? L"Unknown quarantine error" : result.errorMessage;
    if (!result.localStatus.empty()) {
      finding.verdict.reasons.push_back(
          {L"QUARANTINE_STATUS", L"Quarantine status: " + result.localStatus + L"."});
    }
    if (!result.verificationDetail.empty()) {
      finding.verdict.reasons.push_back({L"QUARANTINE_VERIFICATION_FAILED", result.verificationDetail});
    }
    finding.verdict.reasons.push_back({L"QUARANTINE_FAILED", finding.remediationError});
  }
}

void RecordEvidence(const AgentConfig& config, const PolicySnapshot& policy, std::vector<ScanFinding>& findings,
                    const std::wstring& source) {
  EvidenceRecorder evidenceRecorder(config.evidenceRootPath, config.runtimeDatabasePath);
  for (auto& finding : findings) {
    try {
      const auto result = evidenceRecorder.RecordScanFinding(finding, policy, source);
      finding.evidenceRecordId = result.recordId;
      if (finding.evidenceRecordId.empty()) {
        finding.verdict.reasons.push_back(
            {L"EVIDENCE_RECORD_SKIPPED",
             L"Fenrir could not persist a local evidence file and continued with finding telemetry only."});
      }
    } catch (const std::exception& error) {
      finding.evidenceRecordId.clear();
      finding.verdict.reasons.push_back(
          {L"EVIDENCE_RECORD_SKIPPED",
           L"Fenrir could not persist a local evidence file and continued scanning: " + Utf8ToWide(error.what())});
    } catch (...) {
      finding.evidenceRecordId.clear();
      finding.verdict.reasons.push_back(
          {L"EVIDENCE_RECORD_SKIPPED",
           L"Fenrir could not persist a local evidence file and continued scanning."});
    }
  }
}

void AttachStoredOriginContext(const AgentConfig& config, std::vector<ScanFinding>& findings) {
  RuntimeDatabase database(config.runtimeDatabasePath);
  for (auto& finding : findings) {
    if (!finding.originContext.channel.empty() || finding.path.empty()) {
      continue;
    }

    DownloadContextRecord record{};
    if (!database.TryGetDownloadContextRecord(finding.path, record)) {
      continue;
    }

    finding.originContext.channel = record.channel;
    finding.originContext.browserFamily = record.browserFamily;
    finding.originContext.sourceApplication = record.sourceApplication;
    finding.originContext.parentApplication = record.parentApplication;
    finding.originContext.sourceDomain = record.sourceDomain;
    finding.originContext.sourceUrl = record.sourceUrl;
    finding.originContext.navigationType = record.navigationType;
    finding.originContext.observedAt = record.observedAt;
    finding.originContext.browserOriginated = record.channel == L"browser";
    finding.originContext.emailOriginated = record.channel == L"email";
    finding.originContext.attachmentOriginated = record.channel == L"email";
    finding.originContext.downloadOriginated = record.channel == L"browser";
    if (finding.alertTitle.empty()) {
      finding.alertTitle = finding.originContext.attachmentOriginated ? L"Suspicious email attachment"
                                                                     : L"Risky download from website";
    }
  }
}

std::wstring BuildScanSessionLabel(const std::wstring& source) {
  if (_wcsicmp(source.c_str(), L"endpoint-ui.quick-scan") == 0) {
    return L"[Quick scan]";
  }

  if (_wcsicmp(source.c_str(), L"endpoint-ui.full-scan") == 0) {
    return L"[Full scan]";
  }

  if (_wcsicmp(source.c_str(), L"endpoint-ui.custom-scan") == 0) {
    return L"[Folder scan]";
  }

  if (_wcsicmp(source.c_str(), L"agent-service.auto.quick-scan") == 0) {
    return L"[Scheduled quick scan]";
  }

  if (_wcsicmp(source.c_str(), L"agent-service.auto.full-drive-scan") == 0) {
    return L"[Scheduled full scan]";
  }

  return L"[On-demand scan]";
}

std::wstring BuildScanSessionReputation(const std::size_t targetCount, const std::size_t findingCount) {
  std::wstring detail = std::to_wstring(targetCount);
  detail += targetCount == 1 ? L" target scanned" : L" targets scanned";
  if (findingCount == 0) {
    detail += L"; no suspicious findings";
  } else {
    detail += L"; ";
    detail += std::to_wstring(findingCount);
    detail += findingCount == 1 ? L" suspicious finding" : L" suspicious findings";
  }
  return detail;
}

void RecordScanSession(const AgentConfig& config, const std::size_t targetCount, const std::size_t findingCount,
                       const bool remediationFailed, const std::wstring& source) {
  RuntimeDatabase(config.runtimeDatabasePath)
      .RecordScanHistory(ScanHistoryRecord{
          .recordedAt = CurrentUtcTimestamp(),
          .source = source,
          .subjectPath = std::filesystem::path(BuildScanSessionLabel(source)),
          .sha256 = L"",
          .contentType = L"scan-session",
          .reputation = BuildScanSessionReputation(targetCount, findingCount),
          .disposition = findingCount == 0 ? L"completed-clean" : L"completed-with-findings",
          .confidence = findingCount == 0 ? 100u : 90u,
          .tacticId = L"",
          .techniqueId = L"",
          .remediationStatus = remediationFailed ? L"review-required" : L"completed",
          .evidenceRecordId = L"",
          .quarantineRecordId = L""});
}

void AddUniqueTarget(std::vector<std::filesystem::path>& targets, std::set<std::wstring>& seen,
                     const std::filesystem::path& path) {
  if (path.empty()) {
    return;
  }

  std::error_code error;
  auto normalized = std::filesystem::absolute(path, error);
  if (error) {
    normalized = path;
  }

  const auto key = normalized.lexically_normal().wstring();
  if (seen.insert(key).second) {
    targets.push_back(normalized);
  }
}

std::filesystem::path ExpandEnvironmentFolder(const wchar_t* variableName, const wchar_t* fallbackLeaf = nullptr) {
  const auto required = GetEnvironmentVariableW(variableName, nullptr, 0);
  if (required == 0) {
    return fallbackLeaf == nullptr ? std::filesystem::path() : std::filesystem::path(fallbackLeaf);
  }

  std::wstring value(required, L'\0');
  GetEnvironmentVariableW(variableName, value.data(), required);
  if (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }

  if (fallbackLeaf == nullptr) {
    return value;
  }

  return std::filesystem::path(value) / fallbackLeaf;
}

}  // namespace

std::vector<std::filesystem::path> ResolveScanTargets(const std::vector<std::filesystem::path>& requestedTargets,
                                                      const bool allowMissingFiles) {
  std::vector<std::filesystem::path> resolvedTargets;
  for (const auto& target : requestedTargets) {
    std::error_code error;
    const auto absoluteTarget = std::filesystem::absolute(target, error);
    const auto& candidate = error ? target : absoluteTarget;

    if (!std::filesystem::exists(candidate, error)) {
      if (allowMissingFiles) {
        resolvedTargets.push_back(candidate);
      }
      continue;
    }

    resolvedTargets.push_back(candidate);
  }

  return resolvedTargets;
}

std::vector<std::filesystem::path> BuildQuickScanTargets() {
  std::vector<std::filesystem::path> targets;
  std::set<std::wstring> seen;

  const auto userProfile = ExpandEnvironmentFolder(L"USERPROFILE");
  if (!userProfile.empty()) {
    AddUniqueTarget(targets, seen, userProfile / L"Desktop");
    AddUniqueTarget(targets, seen, userProfile / L"Downloads");
    AddUniqueTarget(targets, seen, userProfile / L"Documents");
    AddUniqueTarget(targets, seen, userProfile / L"AppData\\Local\\Temp");
    AddUniqueTarget(targets, seen, userProfile / L"AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
  }

  AddUniqueTarget(targets, seen, ExpandEnvironmentFolder(L"TEMP"));
  AddUniqueTarget(targets, seen, ExpandEnvironmentFolder(L"PROGRAMDATA", L"Microsoft\\Windows\\Start Menu\\Programs\\Startup"));

  return ResolveScanTargets(targets, false);
}

std::vector<std::filesystem::path> BuildFullScanTargets() {
  DWORD bufferLength = GetLogicalDriveStringsW(0, nullptr);
  if (bufferLength == 0) {
    return {};
  }

  std::wstring buffer(bufferLength + 1, L'\0');
  bufferLength = GetLogicalDriveStringsW(static_cast<DWORD>(buffer.size()), buffer.data());
  if (bufferLength == 0) {
    return {};
  }

  std::vector<std::filesystem::path> targets;
  std::set<std::wstring> seen;

  const wchar_t* current = buffer.c_str();
  while (*current != L'\0') {
    std::wstring drive(current);
    if (GetDriveTypeW(drive.c_str()) == DRIVE_FIXED) {
      AddUniqueTarget(targets, seen, drive);
    }

    current += drive.size() + 1;
  }

  return ResolveScanTargets(targets, false);
}

LocalScanExecutionResult ExecuteLocalScan(const AgentConfig& config, const AgentState& state,
                                          const std::vector<std::filesystem::path>& targets,
                                          const LocalScanExecutionOptions& options,
                                          const LocalScanProgressCallback& progressCallback) {
  const auto resolvedTargets = ResolveScanTargets(targets, false);
  auto findings = ScanTargets(resolvedTargets, state.policy, [&](const ScanProgressUpdate& update) {
    if (!progressCallback) {
      return;
    }

    progressCallback(LocalScanProgressUpdate{
        .completedTargets = update.completedTargets,
        .totalTargets = update.totalTargets,
        .findingCount = update.findingCount,
        .currentTarget = update.currentPath,
    });
  }, config.scanExcludedPaths);
  AttachStoredOriginContext(config, findings);

  ApplyLocalRemediation(config, findings, options.applyRemediation);
  RecordEvidence(config, state.policy, findings, options.source);

  if (options.queueTelemetry) {
    QueueTelemetry(config, state.policy, findings, resolvedTargets.size(), options.source);
  }

  const auto remediationFailed = std::any_of(findings.begin(), findings.end(), [](const ScanFinding& finding) {
    return finding.remediationStatus == RemediationStatus::Failed;
  });

  RecordScanSession(config, resolvedTargets.size(), findings.size(), remediationFailed, options.source);

  return LocalScanExecutionResult{
      .targetCount = resolvedTargets.size(),
      .findings = std::move(findings),
      .remediationFailed = remediationFailed};
}

}  // namespace antivirus::agent
