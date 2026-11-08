#include "AgentWatchdog.h"

#include <winsock2.h>
#include <windows.h>
#include <oleauto.h>
#include <taskschd.h>
#include <winhttp.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>

#include "AgentConfig.h"
#include "Liveness.h"

namespace antivirus::agent::watchdog {
namespace {

constexpr wchar_t kServiceName[] = L"FenrirAgent";
constexpr long long kMinute = 60;
constexpr long long kPendingLimit = 10 * kMinute;      // stuck starting or stopping
constexpr long long kFrozenLimit = 10 * kMinute;       // liveness record not written
constexpr long long kLoopLimit = 60 * kMinute;         // main loop silent (the agent restarts itself at 45)
constexpr long long kContactLimit = 20 * kMinute;      // no answer from the server while it is reachable
constexpr long long kRestartGap = 30 * kMinute;        // at most one forced restart per half hour
constexpr long long kRepairWindow = 6 * 60 * kMinute;  // 3 forced restarts in this window: repair
constexpr long long kRepairGap = 12 * 60 * kMinute;

struct State {
  long long lastRestartAt{0};
  long long windowStart{0};
  long long restartsInWindow{0};
  long long lastRepairAt{0};
  long long pendingState{0};
  long long pendingSince{0};
};

std::filesystem::path ModulePath() {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  buffer.resize(written);
  return buffer;
}

std::string Narrow(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), size, nullptr, nullptr);
  return out;
}

std::string Iso(long long unix) {
  const std::time_t t = static_cast<std::time_t>(unix);
  std::tm tm{};
  gmtime_s(&tm, &t);
  char buffer[32]{};
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buffer;
}

long long Field(const std::string& json, const char* name) {
  const auto key = std::string("\"") + name + "\":";
  const auto at = json.find(key);
  if (at == std::string::npos) return 0;
  try {
    return std::stoll(json.substr(at + key.size()));
  } catch (...) {
    return 0;
  }
}

class Watchdog {
 public:
  Watchdog() {
    installRoot_ = ModulePath().parent_path();
    config_ = LoadAgentConfigForModule(nullptr);
    runtime_ = config_.runtimeDatabasePath.parent_path();
    if (runtime_.empty() || runtime_.is_relative()) runtime_ = installRoot_ / runtime_;
    std::error_code ec;
    std::filesystem::create_directories(runtime_, ec);
    now_ = liveness::Now();
    LoadState();
  }

  int Run() {
    if (InMaintenance()) return 0;
    const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) {
      Log("cannot open the service manager (error " + std::to_string(GetLastError()) + ")");
      return 1;
    }
    auto service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_PAUSE_CONTINUE);
    if (service == nullptr) {
      const auto error = GetLastError();
      CloseServiceHandle(manager);
      if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
        if (now_ - state_.lastRepairAt > 60 * kMinute) Repair("the FenrirAgent service is not registered");
      } else {
        Log("cannot open the FenrirAgent service (error " + std::to_string(error) + ")");
      }
      SaveState();
      return 0;
    }
    if (const auto config = OpenServiceW(manager, kServiceName, SERVICE_CHANGE_CONFIG)) {
      std::wstring ignored;
      ApplyRecoverySettings(config, &ignored);  // may be refused while the service is locked; then it stays as set
      CloseServiceHandle(config);
    }
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
      Log("cannot read the service status (error " + std::to_string(GetLastError()) + ")");
    } else {
      Check(service, status);
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    SaveState();
    return 0;
  }

 private:
  void Check(SC_HANDLE service, const SERVICE_STATUS_PROCESS& status) {
    switch (status.dwCurrentState) {
      case SERVICE_STOPPED:
        state_.pendingState = 0;
        Start(service, "the agent was stopped");
        return;
      case SERVICE_PAUSED: {
        SERVICE_STATUS ignored{};
        ControlService(service, SERVICE_CONTROL_CONTINUE, &ignored);
        Act("resumed", "the agent was paused");
        return;
      }
      case SERVICE_RUNNING:
        state_.pendingState = 0;
        CheckRunning(service, status.dwProcessId);
        return;
      default: {  // starting, stopping, pausing or resuming
        if (state_.pendingState != static_cast<long long>(status.dwCurrentState)) {
          state_.pendingState = status.dwCurrentState;
          state_.pendingSince = now_;
          return;
        }
        if (now_ - state_.pendingSince > kPendingLimit) {
          ForceRestart(service, status.dwProcessId,
                       std::string(status.dwCurrentState == SERVICE_START_PENDING ? "stuck starting" : "stuck stopping") +
                           " for " + std::to_string((now_ - state_.pendingSince) / kMinute) + " minutes");
        }
        return;
      }
    }
  }

  void CheckRunning(SC_HANDLE service, const DWORD pid) {
    const auto age = ProcessAge(pid);
    const auto record = liveness::Read(runtime_ / L"liveness.json");
    const auto awake = liveness::AwakeSeconds();
    std::string reason;
    if (!record || record->pid != static_cast<long long>(pid)) {
      if (age > 15 * kMinute) reason = "the running agent has not written its liveness record";
    } else if (liveness::Stalled(awake, record->writtenAwake, kFrozenLimit)) {
      reason = "the agent is frozen (no liveness update for " + std::to_string((awake - record->writtenAwake) / kMinute) + " minutes)";
    } else if (liveness::Stalled(awake, record->loopAwake, kLoopLimit)) {
      reason = "the agent's main loop has been stuck for " + std::to_string((awake - record->loopAwake) / kMinute) + " minutes";
    } else {
      const auto lastOk = std::max(record->contactOkAt, record->startedAt);
      if (liveness::Stalled(awake, record->contactAttemptAwake, kContactLimit) && now_ - lastOk > kContactLimit && age > kContactLimit) {
        const auto reachable = ServerReachable();
        if (reachable) {
          reason = "no answer from the server for " + std::to_string((now_ - lastOk) / kMinute) +
                   " minutes although this machine can reach it (last status " + std::to_string(record->lastStatus) +
                   (record->lastError.empty() ? "" : ": " + record->lastError.substr(0, 160)) + ")";
        }
      }
    }
    if (!reason.empty()) ForceRestart(service, pid, reason);
  }

  void ForceRestart(SC_HANDLE service, const DWORD pid, const std::string& reason) {
    if (state_.lastRestartAt != 0 && now_ - state_.lastRestartAt < kRestartGap) {
      Log("not restarting yet (restarted " + std::to_string((now_ - state_.lastRestartAt) / kMinute) + " minutes ago): " + reason);
      return;
    }
    if (now_ - state_.windowStart > kRepairWindow) {
      state_.windowStart = now_;
      state_.restartsInWindow = 0;
    }
    if (!Kill(service, pid)) return;
    state_.lastRestartAt = now_;
    ++state_.restartsInWindow;
    if (state_.restartsInWindow > 3 && now_ - state_.lastRepairAt > kRepairGap) {
      Repair(reason + "; restarting did not help " + std::to_string(state_.restartsInWindow - 1) + " times");
      return;
    }
    Start(service, reason, true);
  }

  void Start(SC_HANDLE service, const std::string& reason, const bool afterKill = false) {
    // After a kill, Windows' own restart-on-failure may already be starting it: give it a moment, then make sure.
    if (afterKill) Sleep(8000);
    if (StartServiceW(service, 0, nullptr) != FALSE || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
      SERVICE_STATUS_PROCESS status{};
      DWORD needed = 0;
      for (int attempt = 0; attempt < 20; ++attempt) {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status),
                                  sizeof(status), &needed)) break;
        if (status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0) {
          Act(afterKill ? "restarted" : "started", reason);
          return;
        }
        if (status.dwCurrentState != SERVICE_START_PENDING) break;
        Sleep(500);
      }
      Log("start requested but running state was not confirmed: " + reason);
    } else {
      Log("could not start the agent (error " + std::to_string(GetLastError()) + "): " + reason);
    }
  }

  static void EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return;
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &privileges.Privileges[0].Luid)) {
      AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    }
    CloseHandle(token);
  }

  bool Kill(SC_HANDLE service, const DWORD pid) {
    if (pid == 0) return false;
    EnableDebugPrivilege();
    const auto process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (process == nullptr) {
      Log("could not open the agent process " + std::to_string(pid) + " to end it (error " + std::to_string(GetLastError()) + ")");
      return false;
    }
    // Holding the process handle prevents PID reuse during the second SCM check.
    SERVICE_STATUS_PROCESS current{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&current),
                              sizeof(current), &needed) || current.dwProcessId != pid || InMaintenance()) {
      CloseHandle(process);
      Log("skipped restart because the service changed or maintenance started");
      return false;
    }
    const bool terminated = TerminateProcess(process, 0x46454E02) != FALSE;
    const bool exited = WaitForSingleObject(process, terminated ? 20'000 : 0) == WAIT_OBJECT_0;
    CloseHandle(process);
    if (!exited) Log("could not confirm exit of agent process " + std::to_string(pid));
    return exited;
  }

  void Repair(const std::string& reason) {
    state_.lastRepairAt = now_;
    const auto exe = installRoot_ / L"fenrir-agent-service.exe";
    std::wstring command = L"\"" + exe.wstring() + L"\" --repair";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, installRoot_.c_str(), &startup,
                        &process)) {
      Log("could not run the repair (error " + std::to_string(GetLastError()) + "): " + reason);
      return;
    }
    WaitForSingleObject(process.hProcess, 3 * 60 * 1000);
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)) {
      if (const auto service = OpenServiceW(manager, kServiceName, SERVICE_START)) {
        StartServiceW(service, 0, nullptr);
        CloseServiceHandle(service);
      }
      CloseServiceHandle(manager);
    }
    Act(exitCode == 0 ? "repaired" : "repair-failed", reason);
  }

  bool ServerReachable() const {
    const auto url = config_.controlPlaneBaseUrl;
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    if (url.empty() || !WinHttpCrackUrl(url.c_str(), 0, 0, &parts)) return false;
    const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
    auto session = WinHttpOpen(L"FenrirWatchdog/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) session = WinHttpOpen(L"FenrirWatchdog/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) return false;
    WinHttpSetTimeouts(session, 15000, 15000, 15000, 15000);
    bool reachable = false;
    if (const auto connection = WinHttpConnect(session, host.c_str(), parts.nPort, 0)) {
      if (const auto request = WinHttpOpenRequest(connection, L"GET", L"/health", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                  parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0)) {
        if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(request, nullptr)) {
          DWORD code = 0, size = sizeof(code);
          WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &size,
                              WINHTTP_NO_HEADER_INDEX);
          reachable = code >= 200 && code < 300;
        }
        WinHttpCloseHandle(request);
      }
      WinHttpCloseHandle(connection);
    }
    WinHttpCloseHandle(session);
    return reachable;
  }

  long long ProcessAge(const DWORD pid) const {
    const auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return 0;
    FILETIME created{}, exited{}, kernel{}, user{};
    long long age = 0;
    if (GetProcessTimes(process, &created, &exited, &kernel, &user)) {
      FILETIME now{};
      GetSystemTimeAsFileTime(&now);
      const auto ticks = [](const FILETIME& t) { return (static_cast<long long>(t.dwHighDateTime) << 32) | t.dwLowDateTime; };
      age = (ticks(now) - ticks(created)) / 10'000'000LL;
    }
    CloseHandle(process);
    return age;
  }

  bool InMaintenance() const {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    const auto flag = installRoot_ / L"runtime" / L"maintenance.flag";
    if (!GetFileAttributesExW(flag.c_str(), GetFileExInfoStandard, &data)) return false;
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    const auto ticks = [](const FILETIME& t) { return (static_cast<long long>(t.dwHighDateTime) << 32) | t.dwLowDateTime; };
    return (ticks(now) - ticks(data.ftLastWriteTime)) / 10'000'000LL < 30 * kMinute;
  }

  // An action the agent reports to the console when it next starts (runtime\watchdog-action.json).
  void Act(const std::string& action, const std::string& reason) {
    Log(action + ": " + reason);
    std::string escaped;
    for (const char c : reason.substr(0, 500)) {
      if (c == '"' || c == '\\') escaped += '\\';
      if (static_cast<unsigned char>(c) < 0x20) continue;
      escaped += c;
    }
    std::ofstream(runtime_ / L"watchdog-action.json", std::ios::trunc)
        << "{\"at\":" << now_ << ",\"action\":\"" << action << "\",\"reason\":\"" << escaped << "\"}";
  }

  void Log(const std::string& line) const {
    const auto file = runtime_ / L"watchdog.log";
    std::error_code ec;
    if (std::filesystem::exists(file, ec) && std::filesystem::file_size(file, ec) > 256 * 1024) {
      std::filesystem::rename(file, runtime_ / L"watchdog.log.1", ec);
    }
    std::ofstream(file, std::ios::app) << Iso(now_) << " " << line << "\r\n";
  }

  void LoadState() {
    std::ifstream in(runtime_ / L"watchdog-state.json");
    if (!in) return;
    std::stringstream buffer;
    buffer << in.rdbuf();
    const auto json = buffer.str();
    state_.lastRestartAt = Field(json, "lastRestartAt");
    state_.windowStart = Field(json, "windowStart");
    state_.restartsInWindow = Field(json, "restartsInWindow");
    state_.lastRepairAt = Field(json, "lastRepairAt");
    state_.pendingState = Field(json, "pendingState");
    state_.pendingSince = Field(json, "pendingSince");
  }

  void SaveState() const {
    std::ofstream(runtime_ / L"watchdog-state.json", std::ios::trunc)
        << "{\"lastRestartAt\":" << state_.lastRestartAt << ",\"windowStart\":" << state_.windowStart
        << ",\"restartsInWindow\":" << state_.restartsInWindow << ",\"lastRepairAt\":" << state_.lastRepairAt
        << ",\"pendingState\":" << state_.pendingState << ",\"pendingSince\":" << state_.pendingSince << ",\"checkedAt\":" << now_ << "}";
  }

  std::filesystem::path installRoot_;
  std::filesystem::path runtime_;
  AgentConfig config_;
  long long now_{0};
  State state_{};
};

std::wstring XmlEscape(const std::wstring& value) {
  std::wstring out;
  for (const auto c : value) {
    switch (c) {
      case L'&': out += L"&amp;"; break;
      case L'<': out += L"&lt;"; break;
      case L'>': out += L"&gt;"; break;
      case L'"': out += L"&quot;"; break;
      default: out += c;
    }
  }
  return out;
}

struct Bstr {
  explicit Bstr(const std::wstring& value) : value(SysAllocString(value.c_str())) {}
  ~Bstr() { SysFreeString(value); }
  BSTR value;
};

template <typename T>
void Release(T*& pointer) {
  if (pointer != nullptr) {
    pointer->Release();
    pointer = nullptr;
  }
}

}  // namespace

int Run() {
  try {
    return Watchdog().Run();
  } catch (...) {
    return 1;
  }
}

bool ApplyRecoverySettings(void* serviceHandle, std::wstring* error) {
  const auto service = static_cast<SC_HANDLE>(serviceHandle);
  SC_ACTION actions[3]{};
  actions[0] = {SC_ACTION_RESTART, 5'000};
  actions[1] = {SC_ACTION_RESTART, 15'000};
  actions[2] = {SC_ACTION_RESTART, 60'000};
  SERVICE_FAILURE_ACTIONSW failure{};
  failure.dwResetPeriod = 60 * 60;
  failure.cActions = 3;
  failure.lpsaActions = actions;
  if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure)) {
    if (error) *error = L"restart-on-failure could not be set (error " + std::to_wstring(GetLastError()) + L")";
    return false;
  }
  SERVICE_FAILURE_ACTIONS_FLAG flag{};
  flag.fFailureActionsOnNonCrashFailures = TRUE;
  ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);
  return true;
}

bool RegisterTask(const std::filesystem::path& serviceExe, std::wstring* error) {
  const auto fail = [&](const wchar_t* step, HRESULT hr) {
    if (error) {
      std::wostringstream text;
      text << step << L" failed (0x" << std::hex << static_cast<unsigned long>(hr) << L")";
      *error = text.str();
    }
    return false;
  };
  const HRESULT init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  const bool uninit = SUCCEEDED(init);
  ITaskService* scheduler = nullptr;
  ITaskFolder* root = nullptr;
  ITaskFolder* folder = nullptr;
  IRegisteredTask* task = nullptr;
  bool ok = false;
  [&] {
    HRESULT hr = CoCreateInstance(__uuidof(TaskScheduler), nullptr, CLSCTX_INPROC_SERVER, __uuidof(ITaskService),
                                  reinterpret_cast<void**>(&scheduler));
    if (FAILED(hr)) return fail(L"Task Scheduler", hr);
    VARIANT empty{};
    VariantInit(&empty);
    hr = scheduler->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) return fail(L"Connecting to Task Scheduler", hr);
    Bstr rootPath(L"\\");
    hr = scheduler->GetFolder(rootPath.value, &root);
    if (FAILED(hr)) return fail(L"Opening the task root", hr);
    Bstr fenrirPath(L"\\Fenrir");
    if (FAILED(root->GetFolder(fenrirPath.value, &folder))) {
      hr = root->CreateFolder(fenrirPath.value, empty, &folder);
      if (FAILED(hr)) return fail(L"Creating the Fenrir task folder", hr);
    }
    const auto exe = XmlEscape(serviceExe.wstring());
    const auto dir = XmlEscape(serviceExe.parent_path().wstring());
    const std::wstring xml =
        L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
        L"<RegistrationInfo><Author>Fenrir</Author><Description>Keeps the Fenrir agent running and connected: starts it if it "
        L"stops and restarts it if it gets stuck.</Description></RegistrationInfo>"
        L"<Triggers>"
        L"<BootTrigger><Enabled>true</Enabled><Delay>PT3M</Delay></BootTrigger>"
        L"<TimeTrigger><Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>"
        L"<StartBoundary>2020-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>"
        L"</Triggers>"
        L"<Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
        L"<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        L"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        L"<AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>"
        L"<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
        L"<IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>"
        L"<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>"
        L"<RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT10M</ExecutionTimeLimit>"
        L"<Priority>5</Priority></Settings>"
        L"<Actions Context=\"Author\"><Exec><Command>" + exe + L"</Command><Arguments>--watchdog</Arguments>"
        L"<WorkingDirectory>" + dir + L"</WorkingDirectory></Exec></Actions>"
        L"</Task>";
    Bstr name(L"Agent watchdog");
    Bstr definition(xml);
    hr = folder->RegisterTask(name.value, definition.value, TASK_CREATE_OR_UPDATE, empty, empty, TASK_LOGON_SERVICE_ACCOUNT,
                              empty, &task);
    if (FAILED(hr)) return fail(L"Registering the watchdog task", hr);
    ok = true;
    return true;
  }();
  Release(task);
  Release(folder);
  Release(root);
  Release(scheduler);
  if (uninit) CoUninitialize();
  return ok;
}

}  // namespace antivirus::agent::watchdog
