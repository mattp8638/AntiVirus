#include "Liveness.h"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <mutex>
#include <sstream>
#include <system_error>
#include <thread>

namespace antivirus::agent::liveness {
namespace {

std::atomic<long long> g_started{0};
std::atomic<long long> g_loop{0};
std::atomic<long long> g_loopAwake{0};
std::atomic<long long> g_attemptAwake{0};
std::atomic<long long> g_contactOk{0};
std::atomic<long long> g_contactAttempt{0};
std::atomic<long long> g_lastStatus{0};
std::atomic<long long> g_selfRestartAt{0};
std::atomic<unsigned long> g_mainThread{0};
std::mutex g_textMutex;
std::string g_lastError;
std::string g_selfRestartReason;
std::filesystem::path g_file;
std::thread g_thread;
HANDLE g_stop = nullptr;

std::string Escape(const std::string& value) {
  std::string out;
  for (const char c : value.substr(0, 400)) {
    if (c == '"' || c == '\\') out += '\\';
    if (c == '\r' || c == '\n' || c == '\t') { out += ' '; continue; }
    if (static_cast<unsigned char>(c) < 0x20) continue;
    out += c;
  }
  return out;
}

long long NumberField(const std::string& json, const char* name) {
  const auto key = std::string("\"") + name + "\":";
  const auto at = json.find(key);
  if (at == std::string::npos) return 0;
  try {
    return std::stoll(json.substr(at + key.size()));
  } catch (...) {
    return 0;
  }
}

std::string TextField(const std::string& json, const char* name) {
  const auto key = std::string("\"") + name + "\":\"";
  const auto at = json.find(key);
  if (at == std::string::npos) return {};
  std::string out;
  for (auto i = at + key.size(); i < json.size(); ++i) {
    if (json[i] == '\\' && i + 1 < json.size()) { out += json[++i]; continue; }
    if (json[i] == '"') break;
    out += json[i];
  }
  return out;
}

Snapshot Current() {
  Snapshot s;
  s.pid = static_cast<long long>(GetCurrentProcessId());
  s.startedAt = g_started.load();
  s.writtenAt = Now();
  s.writtenAwake = AwakeSeconds();
  s.loopAwake = g_loopAwake.load();
  s.contactAttemptAwake = g_attemptAwake.load();
  s.loopAt = g_loop.load();
  s.contactOkAt = g_contactOk.load();
  s.contactAttemptAt = g_contactAttempt.load();
  s.lastStatus = g_lastStatus.load();
  s.selfRestartAt = g_selfRestartAt.load();
  std::lock_guard<std::mutex> lock(g_textMutex);
  s.lastError = g_lastError;
  s.selfRestartReason = g_selfRestartReason;
  return s;
}

void ReportEvent(const std::wstring& text) {
  if (const auto source = RegisterEventSourceW(nullptr, L"FenrirAgent")) {
    const wchar_t* strings[] = {text.c_str()};
    ReportEventW(source, EVENTLOG_WARNING_TYPE, 0, 0x1002, nullptr, 1, 0, strings, nullptr);
    DeregisterEventSource(source);
  }
}

// Ends this process so Windows' restart-on-failure starts a fresh one. Used only when the agent is stuck.
[[noreturn]] void RestartSelf(const std::string& reason) {
  {
    std::lock_guard<std::mutex> lock(g_textMutex);
    g_selfRestartReason = reason;
  }
  g_selfRestartAt = Now();
  if (!g_file.empty()) Write(g_file, Current());
  ReportEvent(L"FenrirAgent restarted itself: " + std::wstring(reason.begin(), reason.end()));
  TerminateProcess(GetCurrentProcess(), 0x46454E01);  // "FEN\x01": not 0, so Windows treats it as a failure and restarts
  ExitProcess(0x46454E01);
}

void Loop() {
  int ticks = 0;
  for (;;) {
    if (WaitForSingleObject(g_stop, 30'000) == WAIT_OBJECT_0) return;
    Write(g_file, Current());
    if (++ticks % 2 != 0) continue;  // stall checks once a minute
    const auto now = AwakeSeconds();
    const auto loop = g_loopAwake.load();
    if (Stalled(now, loop, kMainLoopStallMinutes * 60LL)) {
      RestartSelf("the main loop made no progress for " + std::to_string((now - loop) / 60) + " awake minutes");
    }
  }
}

}  // namespace

long long Now() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

long long AwakeSeconds() {
  ULONGLONG ticks = 0;
  return QueryUnbiasedInterruptTime(&ticks) ? static_cast<long long>(ticks / 10'000'000) : 0;
}

void MarkLoop() {
  g_loop = Now();
  g_loopAwake = AwakeSeconds();
}

void SetMainThread() { g_mainThread = GetCurrentThreadId(); }

long long LastContactOk() { return g_contactOk.load(); }

void MarkProgress() {
  if (g_mainThread.load() == GetCurrentThreadId()) MarkLoop();
}

void MarkContactOk(const unsigned long status) {
  const auto now = Now();
  g_attemptAwake = AwakeSeconds();
  g_contactAttempt = now;
  g_contactOk = now;
  g_lastStatus = static_cast<long long>(status);
}

void MarkContactFailed(const unsigned long status, const std::string& why) {
  g_attemptAwake = AwakeSeconds();
  g_contactAttempt = Now();
  g_lastStatus = static_cast<long long>(status);
  std::lock_guard<std::mutex> lock(g_textMutex);
  g_lastError = why.substr(0, 300);
}

void Start(const std::filesystem::path& file, std::optional<Snapshot>* previous) {
  if (g_thread.joinable()) return;
  g_file = file;
  const auto last = Read(file);
  if (previous != nullptr) *previous = last;
  if (last) g_selfRestartAt = last->selfRestartAt;  // retain the previous restart timestamp for diagnostics
  const auto now = Now();
  g_started = now;
  MarkLoop();
  g_attemptAwake = AwakeSeconds();
  std::error_code ec;
  std::filesystem::create_directories(file.parent_path(), ec);
  Write(file, Current());
  g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_stop) throw std::system_error(GetLastError(), std::system_category(), "create liveness event");
  try {
    g_thread = std::thread(Loop);
  } catch (...) {
    CloseHandle(g_stop);
    g_stop = nullptr;
    throw;
  }
}

void Stop() {
  if (!g_thread.joinable()) return;
  SetEvent(g_stop);
  g_thread.join();
  CloseHandle(g_stop);
  g_stop = nullptr;
}

std::optional<Snapshot> Read(const std::filesystem::path& file) {
  std::ifstream in(file, std::ios::binary);
  if (!in) return std::nullopt;
  std::stringstream buffer;
  buffer << in.rdbuf();
  const auto json = buffer.str();
  if (json.find("\"writtenAt\"") == std::string::npos) return std::nullopt;
  Snapshot s;
  s.pid = NumberField(json, "pid");
  s.startedAt = NumberField(json, "startedAt");
  s.writtenAt = NumberField(json, "writtenAt");
  s.writtenAwake = NumberField(json, "writtenAwake");
  s.loopAwake = NumberField(json, "loopAwake");
  s.contactAttemptAwake = NumberField(json, "contactAttemptAwake");
  s.loopAt = NumberField(json, "loopAt");
  s.contactOkAt = NumberField(json, "contactOkAt");
  s.contactAttemptAt = NumberField(json, "contactAttemptAt");
  s.lastStatus = NumberField(json, "lastStatus");
  s.selfRestartAt = NumberField(json, "selfRestartAt");
  s.lastError = TextField(json, "lastError");
  s.selfRestartReason = TextField(json, "selfRestartReason");
  return s;
}

bool Write(const std::filesystem::path& file, const Snapshot& s) {
  std::ostringstream json;
  json << "{\"pid\":" << s.pid << ",\"startedAt\":" << s.startedAt << ",\"writtenAt\":" << s.writtenAt
       << ",\"writtenAwake\":" << s.writtenAwake << ",\"loopAwake\":" << s.loopAwake
       << ",\"contactAttemptAwake\":" << s.contactAttemptAwake
       << ",\"loopAt\":" << s.loopAt << ",\"contactOkAt\":" << s.contactOkAt << ",\"contactAttemptAt\":" << s.contactAttemptAt
       << ",\"lastStatus\":" << s.lastStatus << ",\"selfRestartAt\":" << s.selfRestartAt << ",\"lastError\":\""
       << Escape(s.lastError) << "\",\"selfRestartReason\":\"" << Escape(s.selfRestartReason) << "\"}";
  auto temp = file;
  temp += L".tmp";
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << json.str();
  }
  return MoveFileExW(temp.c_str(), file.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
}

}  // namespace antivirus::agent::liveness
