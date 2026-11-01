#include "ProcessGuard.h"

#include <windows.h>
#include <tlhelp32.h>

#include <fstream>
#include <algorithm>
#include <iterator>
#include <sstream>

#include "BehaviorRules.h"
#include "CryptoUtils.h"
#include "DeviceControl.h"
#include "MlStaticModel.h"
#include "StringUtils.h"
#include "../../sensor/etw/include/ProcessEtwSensor.h"

namespace antivirus::agent {
namespace {

constexpr std::uintmax_t kMaxMlFileBytes = 64ull * 1024 * 1024;
constexpr std::uintmax_t kMaxExclusionHashBytes = 512ull * 1024 * 1024;

std::wstring LowerCopy(std::wstring value) {
  for (auto& c : value) c = static_cast<wchar_t>(towlower(c));
  return value;
}

bool OnRemovableDrive(const std::wstring& path) {
  if (path.size() < 3 || path[1] != L':') return false;
  const std::wstring root = path.substr(0, 3);
  return GetDriveTypeW(root.c_str()) == DRIVE_REMOVABLE;
}

bool TrustedPublisher(const std::wstring& signer) {
  const auto s = LowerCopy(signer);
  return s == L"microsoft windows" || s == L"microsoft corporation" || s == L"microsoft windows publisher";
}

std::vector<DWORD> ChildProcesses(DWORD root) {
  std::vector<DWORD> out;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return out;
  std::vector<std::pair<DWORD, DWORD>> pairs;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      pairs.emplace_back(entry.th32ProcessID, entry.th32ParentProcessID);
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  std::vector<DWORD> stack{root};
  while (!stack.empty()) {
    const auto current = stack.back();
    stack.pop_back();
    for (const auto& [pid, parent] : pairs) {
      if (parent == current && pid != root && pid != 0) {
        out.push_back(pid);
        stack.push_back(pid);
      }
    }
  }
  return out;
}

bool Terminate(DWORD pid) {
  HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (process == nullptr) return false;
  const bool ok = TerminateProcess(process, 0xC0000022) != FALSE;  // STATUS_ACCESS_DENIED as exit code
  CloseHandle(process);
  return ok;
}

std::vector<unsigned char> ReadFileCapped(const std::wstring& path, std::uintmax_t cap) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(std::filesystem::path(path), ec);
  if (ec || size == 0 || size > cap) return {};
  std::ifstream in(std::filesystem::path(path), std::ios::binary);
  std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
  if (!in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size))) return {};
  return bytes;
}

TelemetryRecord Record(const std::wstring& type, const std::wstring& summary, const std::wstring& payload) {
  return TelemetryRecord{.eventId = GenerateGuidString(), .eventType = type, .source = L"process-guard",
                         .summary = summary, .occurredAt = CurrentUtcTimestamp(), .payloadJson = payload};
}

std::wstring J(const std::wstring& value) { return Utf8ToWide(EscapeJsonString(value)); }

}  // namespace

int ProcessGuard::TerminateIfImageMatches(unsigned long pid, const std::wstring& expectedImagePath, bool includeChildren) {
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (process == nullptr) return -1;
  wchar_t buffer[32768];
  DWORD size = static_cast<DWORD>(std::size(buffer));
  const bool ok = QueryFullProcessImageNameW(process, 0, buffer, &size) != FALSE;
  CloseHandle(process);
  if (!ok || LowerCopy(std::wstring(buffer, size)) != LowerCopy(expectedImagePath)) return -1;
  int killed = 0;
  if (includeChildren) {
    for (const auto child : ChildProcesses(pid)) killed += Terminate(child) ? 1 : 0;
  }
  killed += Terminate(pid) ? 1 : 0;
  return killed;
}

ProcessGuard::ProcessGuard(std::filesystem::path installRoot, std::filesystem::path runtimeRoot)
    : installRoot_(std::move(installRoot)), runtimeRoot_(std::move(runtimeRoot)) {}

std::filesystem::path ProcessGuard::ModelPath() const {
  const auto overridePath = ReadEnvironmentVariable(L"FENRIR_ML_MODEL");
  if (!overridePath.empty()) return overridePath;
  return runtimeRoot_ / L"models" / L"fenrir-pe.fgbt";
}

void ProcessGuard::UpdatePolicy(const PolicySnapshot& policy) {
  const auto cache = runtimeRoot_ / L"policy-modules.json";
  std::string modules = policy.modulesJson;
  std::error_code ec;
  if (!modules.empty()) {
    std::filesystem::create_directories(runtimeRoot_, ec);
    std::ofstream(cache, std::ios::binary | std::ios::trunc) << modules;
  } else if (std::filesystem::exists(cache, ec)) {
    std::ifstream in(cache, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    modules = ss.str();
  }
  auto extended = ExtendedPolicy::Parse(modules);
  extended.behavior.agentInstallRoot = installRoot_.wstring();
  extended.behavior.excludedPathRoots = policy.suppressionPathRoots;
  std::lock_guard lock(mutex_);
  policy_ = policy;
  extended_ = std::move(extended);
}

ExtendedPolicy ProcessGuard::CurrentExtendedPolicy() const {
  std::lock_guard lock(mutex_);
  return extended_;
}

std::wstring ProcessGuard::CachedSha256(const std::wstring& path) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(std::filesystem::path(path), ec);
  if (ec || size > kMaxExclusionHashBytes) return {};
  const auto stamp = std::filesystem::last_write_time(std::filesystem::path(path), ec);
  if (ec) return {};
  const auto key = LowerCopy(path) + L"|" + std::to_wstring(size) + L"|" + std::to_wstring(stamp.time_since_epoch().count());
  {
    std::lock_guard lock(mutex_);
    if (const auto it = hashCache_.find(key); it != hashCache_.end()) return it->second;
  }
  std::wstring sha;
  try {
    sha = LowerCopy(ComputeFileSha256(path));
  } catch (...) {
    return {};
  }
  std::lock_guard lock(mutex_);
  if (hashCache_.size() > 4096) hashCache_.clear();
  hashCache_[key] = sha;
  return sha;
}

std::vector<TelemetryRecord> ProcessGuard::OnProcessStart(EtwProcessContext& process) {
  std::vector<TelemetryRecord> out;
  if (process.pid == 0 || process.pid == GetCurrentProcessId() || process.imagePath.empty()) return out;
  PolicySnapshot policy;
  ExtendedPolicy extended;
  {
    std::lock_guard lock(mutex_);
    policy = policy_;
    extended = extended_;
  }
  if (!policy.realtimeProtectionEnabled) return out;

  behavior::ProcessFacts facts{.pid = process.pid, .imagePath = process.imagePath, .commandLine = process.commandLine,
                               .parentImagePath = process.parentImagePath, .signer = process.signer,
                               .signatureVerified = !process.signer.empty(), .onRemovableMedia = OnRemovableDrive(process.imagePath)};
  const auto& exclusions = extended.behavior.exclusions;
  const bool needsHash = !extended.behavior.blockedApps.empty() || !extended.behavior.allowedHashes.empty() ||
                         behavior::NeedsChildHash(exclusions);
  if (needsHash) {
    facts.sha256 = CachedSha256(process.imagePath);
  }
  if (!process.parentImagePath.empty() && behavior::NeedsParentHash(exclusions, process.parentImagePath)) {
    facts.parentSha256 = CachedSha256(process.parentImagePath);
    process.parentSha256 = facts.parentSha256;  // reported on process.started so cloud rules can verify the chain
  }
  auto decisions = behavior::Evaluate(facts, extended.behavior);
  std::vector<std::wstring> excludedRules;
  const behavior::ExclusionRule* appliedExclusion = nullptr;
  if (!decisions.empty()) {
    if (const auto* rule = behavior::MatchExclusion(exclusions, L"behavior", facts); rule != nullptr) {
      for (const auto& d : decisions) excludedRules.push_back(d.rule);
      decisions.clear();
      appliedExclusion = rule;
    }
  }

  // Static ML on images that are not signed by Microsoft. Verdicts are cached per (path, size, mtime).
  double mlScore = -1.0;
  if (extended.mlSensitivity != L"off" && !TrustedPublisher(process.signer) &&
      LowerCopy(process.imagePath).rfind(LowerCopy(installRoot_.wstring()), 0) != 0) {
    if (const auto model = ml::LoadCached(ModelPath().wstring()); model) {
      if (const auto cut = model->ThresholdFor(extended.mlSensitivity); cut) {
        std::error_code ec;
        const auto size = std::filesystem::file_size(std::filesystem::path(process.imagePath), ec);
        const auto stamp = std::filesystem::last_write_time(std::filesystem::path(process.imagePath), ec);
        const auto key = LowerCopy(process.imagePath) + L"|" + std::to_wstring(size) + L"|" +
                         std::to_wstring(stamp.time_since_epoch().count()) + L"|" + Utf8ToWide(model->Version());
        {
          std::lock_guard lock(mutex_);
          if (const auto it = mlCache_.find(key); it != mlCache_.end()) mlScore = it->second;
        }
        if (mlScore < 0 && !ec) {
          const auto bytes = ReadFileCapped(process.imagePath, kMaxMlFileBytes);
          if (!bytes.empty() && ml::IsPortableExecutable(bytes)) {
            mlScore = model->Score(ml::ExtractFeatures(bytes));
            std::lock_guard lock(mutex_);
            if (mlCache_.size() > 8192) mlCache_.clear();
            mlCache_[key] = mlScore;
          }
        }
        if (mlScore >= *cut) {
          if (const auto* rule = behavior::MatchExclusion(exclusions, L"antimalware", facts); rule != nullptr) {
            excludedRules.push_back(L"antimalware.mlStatic");
            appliedExclusion = rule;
          } else {
            decisions.push_back({L"antimalware.mlStatic",
                                 policy.enforceProcessStartVerdicts ? behavior::RuleMode::Block : behavior::RuleMode::Audit,
                                 L"static machine-learning model scored " + std::to_wstring(mlScore), L"T1204.002"});
          }
        }
      }
    }
  }
  if (appliedExclusion != nullptr && !excludedRules.empty()) {
    std::wstringstream payload;
    payload << L"{\"exclusionId\":\"" << J(appliedExclusion->id) << L"\",\"suppressed\":[";
    for (size_t i = 0; i < excludedRules.size(); ++i) payload << (i ? L"," : L"") << L"\"" << J(excludedRules[i]) << L"\"";
    payload << L"],\"pid\":" << process.pid << L",\"processImagePath\":\"" << J(process.imagePath) << L"\",\"commandLine\":\""
            << J(process.commandLine) << L"\",\"parentProcessImagePath\":\"" << J(process.parentImagePath)
            << L"\",\"parentSha256\":\"" << J(facts.parentSha256) << L"\"}";
    out.push_back(Record(L"edr.exclusion.applied",
                         L"Exclusion " + appliedExclusion->id + L" allowed " + process.imageName, payload.str()));
  }
  if (decisions.empty()) return out;

  const auto strongest = behavior::Strongest(decisions);
  bool terminated = false;
  int killed = 0;
  if (strongest == behavior::RuleMode::Block) {
    if (policy.terminateProcessTreeOnExecuteBlock) {
      for (const auto child : ChildProcesses(process.pid)) killed += Terminate(child) ? 1 : 0;
    }
    terminated = Terminate(process.pid);
    killed += terminated ? 1 : 0;
  }

  for (const auto& d : decisions) {
    const bool blocked = d.mode == behavior::RuleMode::Block && terminated;
    const auto family = d.rule.rfind(L"applicationControl", 0) == 0 ? L"appcontrol"
                        : d.rule == L"antimalware.mlStatic"          ? L"threat.ml"
                                                                     : L"asr.rule";
    const auto type = std::wstring(family) + (blocked ? L".blocked" : d.mode == behavior::RuleMode::Block ? L".block_failed"
                                                                                                        : L".audited");
    std::wstringstream payload;
    payload << L"{\"rule\":\"" << J(d.rule) << L"\",\"mode\":\"" << behavior::RuleModeName(d.mode) << L"\",\"pid\":"
            << process.pid << L",\"processImagePath\":\"" << J(process.imagePath) << L"\",\"commandLine\":\""
            << J(process.commandLine) << L"\",\"parentProcessImagePath\":\"" << J(process.parentImagePath)
            << L"\",\"signer\":\"" << J(process.signer) << L"\",\"reason\":\"" << J(d.reason) << L"\",\"technique\":\""
            << J(d.mitre) << L"\",\"terminatedCount\":" << killed;
    if (mlScore >= 0) payload << L",\"mlScore\":" << mlScore << L",\"score\":" << static_cast<int>(mlScore * 100);
    payload << L"}";
    out.push_back(Record(type, (blocked ? L"Blocked " : L"Detected ") + process.imageName + L": " + d.reason, payload.str()));
  }
  return out;
}

std::vector<TelemetryRecord> ProcessGuard::OnRemoteThread(const EtwProcessContext& source, const unsigned long targetPid) {
  static const wchar_t* kOffice[] = {L"winword.exe", L"excel.exe",  L"powerpnt.exe", L"msaccess.exe", L"mspub.exe",
                                     L"visio.exe",   L"onenote.exe", L"outlook.exe", L"eqnedt32.exe"};
  const auto name = LowerCopy(source.imageName.empty() ? source.imagePath.substr(source.imagePath.find_last_of(L'\\') + 1)
                                                       : source.imageName);
  if (std::none_of(std::begin(kOffice), std::end(kOffice), [&](const wchar_t* office) { return name == office; })) return {};
  behavior::RuleMode mode = behavior::RuleMode::Off;
  {
    std::lock_guard lock(mutex_);
    const auto it = extended_.behavior.asr.find(L"blockOfficeCodeInjection");
    if (it != extended_.behavior.asr.end()) mode = it->second;
  }
  if (mode == behavior::RuleMode::Off) return {};
  std::wstring targetImage;
  if (HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid)) {
    wchar_t buffer[MAX_PATH * 2];
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (QueryFullProcessImageNameW(process, 0, buffer, &size)) targetImage.assign(buffer, size);
    CloseHandle(process);
  }
  // Office never needs to start threads in other programs; console and debugging helpers aside.
  const auto targetName = LowerCopy(targetImage.substr(targetImage.find_last_of(L'\\') + 1));
  if (targetName == L"conhost.exe" || targetName == L"werfault.exe" || targetName == L"dwwin.exe") return {};
  int killed = 0;
  bool blocked = false;
  if (mode == behavior::RuleMode::Block) {
    // Stop the Office process that did it, and the program it injected into unless that is part of Windows.
    blocked = Terminate(source.pid);
    killed += blocked ? 1 : 0;
    wchar_t windows[MAX_PATH]{};
    GetWindowsDirectoryW(windows, MAX_PATH);
    if (!targetImage.empty() && LowerCopy(targetImage).rfind(LowerCopy(windows) + L"\\", 0) != 0 && Terminate(targetPid)) ++killed;
  }
  const auto type = mode == behavior::RuleMode::Block ? (blocked ? L"asr.rule.blocked" : L"asr.rule.block_failed") : L"asr.rule.audited";
  std::wstringstream payload;
  payload << L"{\"rule\":\"attackSurface.blockOfficeCodeInjection\",\"mode\":\"" << behavior::RuleModeName(mode)
          << L"\",\"pid\":" << source.pid << L",\"processImagePath\":\"" << J(source.imagePath) << L"\",\"targetPid\":"
          << targetPid << L",\"targetImagePath\":\"" << J(targetImage)
          << L"\",\"reason\":\"Office started a thread in another process\",\"technique\":\"T1055\",\"terminatedCount\":" << killed
          << L"}";
  return {Record(type, (blocked ? L"Blocked " : L"Detected ") + name + L": code injection into " +
                           (targetName.empty() ? std::to_wstring(targetPid) : targetName),
                 payload.str())};
}

std::vector<TelemetryRecord> ProcessGuard::ApplyDeviceControl() {
  DeviceControlSettings settings;
  {
    std::lock_guard lock(mutex_);
    if (!extended_.present) return {};
    settings = extended_.deviceControl;
  }
  const auto plan = devicecontrol::BuildPlan(settings);
  {
    std::lock_guard lock(mutex_);
    if (plan.summary == appliedDeviceControlSummary_) return {};
  }
  std::wstring error;
  const auto failures = devicecontrol::Apply(plan, &error);
  {
    std::lock_guard lock(mutex_);
    if (failures == 0) appliedDeviceControlSummary_ = plan.summary;
  }
  std::wstringstream payload;
  payload << L"{\"summary\":\"" << J(plan.summary) << L"\",\"failures\":" << failures << L",\"error\":\"" << J(error)
          << L"\",\"notes\":[";
  for (std::size_t i = 0; i < plan.notes.size(); ++i) payload << (i ? L"," : L"") << L"\"" << J(plan.notes[i]) << L"\"";
  payload << L"]}";
  return {Record(failures ? L"devicecontrol.apply_failed" : L"devicecontrol.applied",
                 failures ? L"Device control could not be fully applied: " + error : L"Device control applied (" + plan.summary + L")",
                 payload.str())};
}

}  // namespace antivirus::agent
