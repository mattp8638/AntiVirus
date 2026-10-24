#include <windows.h>

#include <algorithm>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "AgentConfig.h"
#include "EvidenceRecorder.h"
#include "LocalStateStore.h"
#include "QuarantineStore.h"
#include "RealtimeProtectionBroker.h"
#include "RemediationEngine.h"
#include "ScanEngine.h"
#include "StringUtils.h"
#include "TelemetryQueueStore.h"

namespace {

struct CliOptions {
  bool json{false};
  bool noTelemetry{false};
  bool noRemediation{false};
  bool helpRequested{false};
  bool realtimeMode{false};
  antivirus::agent::RealtimeFileOperation realtimeOperation{ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE};
  std::vector<std::filesystem::path> exclusions;
  std::vector<std::filesystem::path> targets;
};

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool RequiresProcessContainment(const antivirus::agent::ScanFinding& finding) {
  if (finding.path.empty()) {
    return false;
  }

  const auto extension = ToLowerCopy(finding.path.extension().wstring());
  return extension == L".exe" || extension == L".dll" || extension == L".scr" || extension == L".msi" ||
         extension == L".com" || extension == L".ps1" || extension == L".psm1" || extension == L".cmd" ||
         extension == L".bat" || extension == L".js" || extension == L".jse" || extension == L".vbs" ||
         extension == L".vbe" || extension == L".hta" || extension == L".lnk";
}

void PrintUsage() {
  std::wcout << L"Usage: antivirus-scannercli.exe [--json] [--no-telemetry] [--no-remediation] [--exclude <path>] [--realtime-op <create|open|write|execute|rename|section-map>] [--path <target>] <target>..."
             << std::endl;
  std::wcout << L"  --json          Print findings as JSON." << std::endl;
  std::wcout << L"  --no-telemetry  Do not queue scan telemetry locally." << std::endl;
  std::wcout << L"  --no-remediation  Do not quarantine files even when policy would allow it." << std::endl;
  std::wcout << L"  --exclude <path>  Skip a file or directory during the scan. Repeatable." << std::endl;
  std::wcout << L"  --realtime-op <operation>  Simulate a minifilter request through the real-time verdict broker."
             << std::endl;
  std::wcout << L"  --path <target> Add an explicit file or directory target." << std::endl;
}

bool TryParseRealtimeOperation(const std::wstring& rawValue, antivirus::agent::RealtimeFileOperation& operation) {
  if (rawValue == L"create") {
    operation = ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE;
    return true;
  }

  if (rawValue == L"open") {
    operation = ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN;
    return true;
  }

  if (rawValue == L"write") {
    operation = ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE;
    return true;
  }

  if (rawValue == L"execute") {
    operation = ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
    return true;
  }

  if (rawValue == L"rename") {
    operation = ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME;
    return true;
  }

  if (rawValue == L"section-map" || rawValue == L"section_map") {
    operation = ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP;
    return true;
  }

  return false;
}

bool ParseOptions(const int argc, wchar_t* argv[], CliOptions& options) {
  for (int index = 1; index < argc; ++index) {
    const std::wstring argument = argv[index];

    if (argument == L"--help") {
      PrintUsage();
      options.helpRequested = true;
      return false;
    }

    if (argument == L"--json") {
      options.json = true;
      continue;
    }

    if (argument == L"--no-telemetry") {
      options.noTelemetry = true;
      continue;
    }

    if (argument == L"--no-remediation") {
      options.noRemediation = true;
      continue;
    }

    if (argument == L"--exclude") {
      if (index + 1 >= argc) {
        std::wcerr << L"--exclude requires a following file or directory path." << std::endl;
        return false;
      }

      options.exclusions.emplace_back(argv[++index]);
      continue;
    }

    if (argument == L"--realtime-op") {
      if (index + 1 >= argc) {
        std::wcerr << L"--realtime-op requires one of: create, open, write, execute, rename, section-map." << std::endl;
        return false;
      }

      const std::wstring rawOperation = argv[++index];
      if (!TryParseRealtimeOperation(rawOperation, options.realtimeOperation)) {
        std::wcerr << L"Unsupported real-time operation: " << rawOperation << std::endl;
        return false;
      }

      options.realtimeMode = true;
      continue;
    }

    if (argument == L"--path") {
      if (index + 1 >= argc) {
        std::wcerr << L"--path requires a following file or directory path." << std::endl;
        return false;
      }

      options.targets.emplace_back(argv[++index]);
      continue;
    }

    if (argument.starts_with(L"--")) {
      std::wcerr << L"Unknown option: " << argument << std::endl;
      return false;
    }

    options.targets.emplace_back(argument);
  }

  if (options.targets.empty()) {
    std::wcerr << L"At least one file or directory target is required." << std::endl;
    PrintUsage();
    return false;
  }

  return true;
}

std::vector<std::filesystem::path> ResolveTargets(const std::vector<std::filesystem::path>& requestedTargets,
                                                  const bool allowMissingFiles = false) {
  std::vector<std::filesystem::path> resolvedTargets;
  for (const auto& target : requestedTargets) {
    std::error_code error;
    const auto absoluteTarget = std::filesystem::absolute(target, error);
    const auto& candidate = error ? target : absoluteTarget;

    if (!std::filesystem::exists(candidate, error)) {
      if (allowMissingFiles) {
        resolvedTargets.push_back(candidate);
        continue;
      }

      std::wcerr << L"Skipping missing target: " << candidate << std::endl;
      continue;
    }

    resolvedTargets.push_back(candidate);
  }

  return resolvedTargets;
}

void QueueTelemetry(const antivirus::agent::AgentConfig& config, const antivirus::agent::PolicySnapshot& policy,
                    const std::vector<antivirus::agent::ScanFinding>& findings, const std::size_t targetCount) {
  antivirus::agent::TelemetryQueueStore queueStore(config.runtimeDatabasePath, config.telemetryQueuePath);
  auto pending = queueStore.LoadPending();

  pending.push_back(antivirus::agent::BuildScanSummaryTelemetry(targetCount, findings.size(), policy, L"scannercli"));
  for (const auto& finding : findings) {
    pending.push_back(antivirus::agent::BuildScanFindingTelemetry(finding, L"scannercli"));
  }

  queueStore.SavePending(pending);
}

void QueueTelemetryRecords(const antivirus::agent::AgentConfig& config,
                          const std::vector<antivirus::agent::TelemetryRecord>& records) {
  antivirus::agent::TelemetryQueueStore queueStore(config.runtimeDatabasePath, config.telemetryQueuePath);
  auto pending = queueStore.LoadPending();
  pending.insert(pending.end(), records.begin(), records.end());
  queueStore.SavePending(pending);
}

void ApplyLocalRemediation(const antivirus::agent::AgentConfig& config, std::vector<antivirus::agent::ScanFinding>& findings,
                           const bool noRemediation) {
  if (noRemediation) {
    return;
  }

  antivirus::agent::QuarantineStore quarantineStore(config.quarantineRootPath, config.runtimeDatabasePath);
  antivirus::agent::RemediationEngine remediationEngine(config);
  for (auto& finding : findings) {
    if (finding.verdict.disposition == antivirus::agent::VerdictDisposition::Allow) {
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

    if (result.success) {
      finding.remediationStatus = antivirus::agent::RemediationStatus::Quarantined;
      finding.quarantinedPath = result.quarantinedPath;
      finding.quarantineRecordId = result.recordId;
      finding.verdict.reasons.push_back(
          {L"QUARANTINE_APPLIED", L"Fenrir moved this artifact into local quarantine."});
    } else {
      finding.remediationStatus = antivirus::agent::RemediationStatus::Failed;
      finding.remediationError = result.errorMessage.empty() ? L"Unknown quarantine error" : result.errorMessage;
      finding.verdict.reasons.push_back({L"QUARANTINE_FAILED", finding.remediationError});
    }
  }
}

void RecordEvidence(const antivirus::agent::AgentConfig& config, const antivirus::agent::PolicySnapshot& policy,
                    std::vector<antivirus::agent::ScanFinding>& findings) {
  antivirus::agent::EvidenceRecorder evidenceRecorder(config.evidenceRootPath, config.runtimeDatabasePath);
  for (auto& finding : findings) {
    try {
      const auto result = evidenceRecorder.RecordScanFinding(finding, policy, L"scannercli");
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
           L"Fenrir could not persist a local evidence file and continued scanning: " +
               antivirus::agent::Utf8ToWide(error.what())});
    } catch (...) {
      finding.evidenceRecordId.clear();
      finding.verdict.reasons.push_back(
          {L"EVIDENCE_RECORD_SKIPPED",
           L"Fenrir could not persist a local evidence file and continued scanning."});
    }
  }
}

void PrintJson(const std::vector<antivirus::agent::ScanFinding>& findings) {
  std::wcout << L"{\"findings\":[";

  for (std::size_t index = 0; index < findings.size(); ++index) {
    const auto& finding = findings[index];
    if (index != 0) {
      std::wcout << L',';
    }

    const auto disposition = antivirus::agent::VerdictDispositionToString(finding.verdict.disposition);
    const auto remediationStatus = antivirus::agent::RemediationStatusToString(finding.remediationStatus);
    const auto techniqueId = finding.verdict.techniqueId.empty() ? L"" : finding.verdict.techniqueId;
    std::wcout << L"{\"path\":\"" << antivirus::agent::Utf8ToWide(antivirus::agent::EscapeJsonString(finding.path.wstring()))
               << L"\",\"sizeBytes\":" << finding.sizeBytes << L",\"disposition\":\"" << disposition
               << L"\",\"tacticId\":\"" << finding.verdict.tacticId << L"\",\"techniqueId\":\"" << techniqueId
               << L"\",\"confidence\":" << finding.verdict.confidence
               << L",\"sha256\":\"" << finding.sha256
               << L"\",\"contentType\":\"" << finding.contentType
               << L"\",\"reputation\":\"" << finding.reputation
               << L"\",\"signer\":\""
               << antivirus::agent::Utf8ToWide(antivirus::agent::EscapeJsonString(finding.signer))
               << L"\",\"heuristicScore\":" << finding.heuristicScore
               << L",\"archiveEntryCount\":" << finding.archiveEntryCount
               << L",\"remediationStatus\":\"" << remediationStatus
               << L"\",\"quarantineRecordId\":\"" << finding.quarantineRecordId
               << L"\",\"evidenceRecordId\":\"" << finding.evidenceRecordId
               << L"\",\"quarantinedPath\":\""
               << antivirus::agent::Utf8ToWide(antivirus::agent::EscapeJsonString(finding.quarantinedPath.wstring()))
               << L"\",\"remediationError\":\""
               << antivirus::agent::Utf8ToWide(antivirus::agent::EscapeJsonString(finding.remediationError))
               << L"\"}";
  }

  std::wcout << L"]}" << std::endl;
}

void PrintText(const std::vector<antivirus::agent::ScanFinding>& findings, const std::size_t targetCount) {
  if (findings.empty()) {
    std::wcout << L"No suspicious files detected across " << targetCount << L" target(s)." << std::endl;
    return;
  }

  std::wcout << L"Detected " << findings.size() << L" suspicious file(s) across " << targetCount << L" target(s)."
             << std::endl;

  for (const auto& finding : findings) {
    std::wcout << L"[" << antivirus::agent::VerdictDispositionToString(finding.verdict.disposition) << L"] "
               << finding.path << L" (" << finding.sizeBytes << L" bytes)" << std::endl;
    std::wcout << L"  SHA-256: " << (finding.sha256.empty() ? std::wstring(L"(unavailable)") : finding.sha256)
               << std::endl;
    std::wcout << L"  Content type: " << finding.contentType << std::endl;
    std::wcout << L"  Reputation: " << finding.reputation << std::endl;
    if (!finding.signer.empty()) {
      std::wcout << L"  Signer: " << finding.signer << std::endl;
    }
    std::wcout << L"  Heuristic score: " << finding.heuristicScore << std::endl;
    if (finding.archiveEntryCount != 0) {
      std::wcout << L"  Archive entry count: " << finding.archiveEntryCount << std::endl;
    }
    std::wcout << L"  ATT&CK: " << finding.verdict.tacticId << L" / " << finding.verdict.techniqueId << std::endl;
    std::wcout << L"  Remediation: " << antivirus::agent::RemediationStatusToString(finding.remediationStatus)
               << std::endl;
    if (!finding.quarantinedPath.empty()) {
      std::wcout << L"  Quarantined path: " << finding.quarantinedPath << std::endl;
    }
    if (!finding.evidenceRecordId.empty()) {
      std::wcout << L"  Evidence ID: " << finding.evidenceRecordId << std::endl;
    }
    for (const auto& reason : finding.verdict.reasons) {
      std::wcout << L"  " << reason.code << L": " << reason.message << std::endl;
    }
  }
}

void PrintFailClosedJson(const CliOptions& options, const std::wstring& errorMessage) {
  const std::wstring targetPath = options.targets.empty() ? std::wstring{} : options.targets.front().wstring();
  std::wcout << L"{\"findings\":[{\"path\":\""
             << antivirus::agent::Utf8ToWide(antivirus::agent::EscapeJsonString(targetPath))
             << L"\",\"disposition\":\"block\",\"remediationStatus\":\"failed\",\"remediationError\":\""
             << antivirus::agent::Utf8ToWide(antivirus::agent::EscapeJsonString(errorMessage))
             << L"\"}]}" << std::endl;
}

int RunRealtimeMode(const antivirus::agent::AgentConfig& config, const antivirus::agent::AgentState& state,
                    const CliOptions& options, const std::filesystem::path& targetPath) {
  antivirus::agent::RealtimeProtectionBroker broker(config);
  broker.SetDeviceId(state.deviceId);
  broker.SetPolicy(state.policy);

  antivirus::agent::RealtimeFileScanRequest request{};
  request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
  request.requestSize = sizeof(request);
  request.requestId = 1;
  request.operation = options.realtimeOperation;
  request.processId = GetCurrentProcessId();
  request.threadId = GetCurrentThreadId();
  request.fileSizeBytes = 0;
  wcsncpy_s(request.correlationId, ANTIVIRUS_REALTIME_CORRELATION_CAPACITY, targetPath.wstring().c_str(), _TRUNCATE);
  wcsncpy_s(request.path, ANTIVIRUS_REALTIME_PATH_CAPACITY, targetPath.wstring().c_str(), _TRUNCATE);
  wcsncpy_s(request.processImage, ANTIVIRUS_REALTIME_IMAGE_CAPACITY, L"antivirus-scannercli.exe", _TRUNCATE);
  wcsncpy_s(request.commandLine, ANTIVIRUS_REALTIME_COMMAND_LINE_CAPACITY, GetCommandLineW(), _TRUNCATE);

  const auto outcome = broker.InspectFile(request);
  const auto brokerTelemetry = broker.DrainTelemetry();
  if (!options.noTelemetry && !brokerTelemetry.empty()) {
    QueueTelemetryRecords(config, brokerTelemetry);
  }

  if (outcome.detection) {
    const auto findings = std::vector<antivirus::agent::ScanFinding>{outcome.finding};
    if (options.json) {
      PrintJson(findings);
    } else {
      PrintText(findings, 1);
    }

    return outcome.finding.remediationStatus == antivirus::agent::RemediationStatus::Failed ? 3 : 2;
  }

  if (options.json) {
    std::wcout << L"{\"findings\":[]}" << std::endl;
  } else {
    std::wcout << L"Real-time inspection allowed " << targetPath << L" for "
               << antivirus::agent::Utf8ToWide(antivirus::agent::EscapeJsonString(targetPath.filename().wstring()))
               << L"." << std::endl;
  }

  return 0;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  CliOptions options;
  try {
    if (!ParseOptions(argc, argv, options)) {
      return options.helpRequested ? 0 : 1;
    }

    const auto resolvedTargets =
        ResolveTargets(options.targets, options.realtimeMode &&
                                           options.realtimeOperation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE);
    if (resolvedTargets.empty()) {
      std::wcerr << L"No valid targets remain after validation." << std::endl;
      return 1;
    }

    const auto config = antivirus::agent::LoadAgentConfig();
    auto effectiveConfig = config;
    effectiveConfig.scanExcludedPaths.insert(effectiveConfig.scanExcludedPaths.end(), options.exclusions.begin(),
                                            options.exclusions.end());
    antivirus::agent::LocalStateStore stateStore(config.runtimeDatabasePath, config.stateFilePath);
    const auto state = stateStore.LoadOrCreate();

    if (options.realtimeMode) {
      if (resolvedTargets.size() != 1 || std::filesystem::is_directory(resolvedTargets.front())) {
        std::wcerr << L"Real-time simulation requires exactly one file path target." << std::endl;
        return 1;
      }

      return RunRealtimeMode(effectiveConfig, state, options, resolvedTargets.front());
    }

    auto findings = antivirus::agent::ScanTargets(resolvedTargets, state.policy,
                                                  antivirus::agent::ScanProgressCallback{}, effectiveConfig.scanExcludedPaths);

    ApplyLocalRemediation(effectiveConfig, findings, options.noRemediation);
    RecordEvidence(effectiveConfig, state.policy, findings);

    if (!options.noTelemetry) {
      QueueTelemetry(effectiveConfig, state.policy, findings, resolvedTargets.size());
    }

    if (options.json) {
      PrintJson(findings);
    } else {
      PrintText(findings, resolvedTargets.size());
    }

    const auto remediationFailed = std::any_of(findings.begin(), findings.end(),
                                               [](const antivirus::agent::ScanFinding& finding) {
                                                 return finding.remediationStatus ==
                                                        antivirus::agent::RemediationStatus::Failed;
                                               });

    if (findings.empty()) {
      return 0;
    }

    return remediationFailed ? 3 : 2;
  } catch (const std::exception& error) {
    const auto errorWide = antivirus::agent::Utf8ToWide(error.what());
    if (options.json) {
      PrintFailClosedJson(options, errorWide);
    } else {
      std::wcerr << L"Scanner execution failed closed: " << errorWide << std::endl;
    }
    return 3;
  } catch (...) {
    const auto fallback = std::wstring(L"Unknown scanner failure");
    if (options.json) {
      PrintFailClosedJson(options, fallback);
    } else {
      std::wcerr << L"Scanner execution failed closed: " << fallback << std::endl;
    }
    return 3;
  }
}
