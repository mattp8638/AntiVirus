#include "ProcessGuard.h"

#include <windows.h>
#include <tlhelp32.h>

#include <fstream>
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

std::vector<TelemetryRecord> ProcessGuard::OnProcessStart(const EtwProcessContext& process) {
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
  const bool needsHash = !extended.behavior.blockedApps.empty() || !extended.behavior.allowedHashes.empty();
  if (needsHash) {
    try {
      facts.sha256 = LowerCopy(ComputeFileSha256(process.imagePath));
    } catch (...) {
    }
  }
  auto decisions = behavior::Evaluate(facts, extended.behavior);

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
          decisions.push_back({L"antimalware.mlStatic",
                               policy.enforceProcessStartVerdicts ? behavior::RuleMode::Block : behavior::RuleMode::Audit,
                               L"static machine-learning model scored " + std::to_wstring(mlScore), L"T1204.002"});
        }
      }
    }
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
