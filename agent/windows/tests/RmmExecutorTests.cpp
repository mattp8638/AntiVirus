// Tests for the Windows RMM executors and remote-access key map. Windows-only (run natively or under Wine).
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <windows.h>

#include "CommandCancellation.h"
#include "ExtendedPolicy.h"
#include "RemoteKeymap.h"
#include "RmmExecutors.h"
#include "StringUtils.h"

using namespace antivirus::agent;

static int failures = 0;
#define CHECK(cond)                                              \
  do {                                                           \
    if (!(cond)) {                                               \
      std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
      ++failures;                                                \
    }                                                            \
  } while (0)

int main(int argc, char** argv) {
  // A real parent/child pair proves that cancelling a process stops its tree.
  if (argc == 3 && std::string(argv[1]) == "--cancellation-leaf") {
    { std::ofstream out(argv[2]); out << GetCurrentProcessId(); }
    Sleep(30000); return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--cancellation-parent") {
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr, executable, 32768);
    auto command = L"\"" + std::wstring(executable) + L"\" --cancellation-leaf \"" + Utf8ToWide(argv[2]) + L"\"";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION child{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &child)) return 2;
    CloseHandle(child.hThread); CloseHandle(child.hProcess); Sleep(30000); return 0;
  }
  // Key map: physical keys become scan codes; navigation keys are extended.
  CHECK(remote::ScanCodeForKey("KeyA").code == 0x1E && !remote::ScanCodeForKey("KeyA").extended);
  CHECK(remote::ScanCodeForKey("Enter").code == 0x1C && !remote::ScanCodeForKey("Enter").extended);
  CHECK(remote::ScanCodeForKey("NumpadEnter").code == 0x1C && remote::ScanCodeForKey("NumpadEnter").extended);
  CHECK(remote::ScanCodeForKey("ArrowLeft").code == 0x4B && remote::ScanCodeForKey("ArrowLeft").extended);
  CHECK(remote::ScanCodeForKey("LaunchMail").code == 0);

  // Input validation.
  CHECK(rmm::QuotePowerShell("it's") == "'it''s'");
  CHECK(rmm::IsSafePackageId("Mozilla.Firefox"));
  CHECK(rmm::IsSafePackageId("Notepad++.Notepad++"));
  CHECK(!rmm::IsSafePackageId("--source evil"));
  CHECK(!rmm::IsSafePackageId("app & calc"));

  // Process runner: separate stdout/stderr, exit codes, environment, timeouts.
  const auto echo = rmm::RunProcess(L"cmd.exe /c echo out-%FENRIR_X% & echo err 1>&2 & exit /b 7", L"", {{L"FENRIR_X", L"42"}}, 30000);
  CHECK(echo.exitCode == 7);
  CHECK(echo.stdoutText.find("out-42") != std::string::npos);
  CHECK(echo.stderrText.find("err") != std::string::npos);
  CHECK(!echo.timedOut);
  const auto slow = rmm::RunProcess(L"cmd.exe /c ping -n 30 127.0.0.1", L"", {}, 1500);
  CHECK(slow.timedOut);

  const auto leafFile = std::filesystem::temp_directory_path() / L"fenrir-cancellation-leaf.pid";
  std::filesystem::remove(leafFile);
  auto cancellation = std::make_shared<command_control::State>();
  std::thread stop([&] {
    for (int n = 0; n < 100 && !std::filesystem::exists(leafFile); ++n) Sleep(30);
    cancellation->requested.store(true);
  });
  bool cancelled = false;
  const auto start = std::chrono::steady_clock::now();
  {
    command_control::Scope scope(cancellation);
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr, executable, 32768);
    try {
      rmm::RunProcess(L"\"" + std::wstring(executable) + L"\" --cancellation-parent \"" + leafFile.wstring() + L"\"", L"", {}, 30000);
    } catch (const command_control::Cancelled&) { cancelled = true; }
  }
  stop.join();
  CHECK(cancelled);
  CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(6));
  DWORD childPid = 0; { std::ifstream file(leafFile); file >> childPid; }
  CHECK(childPid != 0);
  if (HANDLE child = OpenProcess(SYNCHRONIZE, FALSE, childPid)) {
    CHECK(WaitForSingleObject(child, 5000) == WAIT_OBJECT_0); CloseHandle(child);
  }
  std::filesystem::remove(leafFile);

  // Script payloads from the cloud.
  const auto root = std::filesystem::temp_directory_path() / L"fenrir-rmm-test";
  const auto ok = rmm::RunScript(LR"({"language":"cmd","body":"@echo off\r\necho hello %Name%\r\n","environment":{"Name":"Fenrir","bad name":"x"},"timeoutSeconds":60})", root);
  const auto parsed = json::Parse(ok);
  CHECK(parsed && parsed->Get("exitCode") && *parsed->Get("exitCode")->Number() == 0);
  CHECK(parsed && parsed->Get("stdout")->String()->find("hello Fenrir") != std::string::npos);
  bool threw = false;
  try {
    rmm::RunScript(LR"({"language":"cmd","body":"@echo partial\r\nexit /b 3\r\n","timeoutSeconds":60})", root);
  } catch (const rmm::CommandFailed& failed) {
    threw = true;
    const auto result = json::Parse(failed.resultJson);
    CHECK(result && *result->Get("exitCode")->Number() == 3);
    CHECK(result->Get("stdout")->String()->find("partial") != std::string::npos);
  }
  CHECK(threw);
  threw = false;
  try {
    rmm::RunScript(LR"({"language":"bash","body":"echo hi"})", root);
  } catch (const std::runtime_error&) {
    threw = true;
  }
  CHECK(threw);

  // Health metrics are valid JSON with the fields the cloud monitors read.
  rmm::CollectHealthMetricsJson();
  const auto metrics = json::Parse(rmm::CollectHealthMetricsJson());
  CHECK(metrics && metrics->IsObject());
  CHECK(metrics && metrics->Get("memoryPercent") && metrics->Get("uptimeSeconds") && metrics->Get("disks"));
  CHECK(metrics && metrics->Get("rebootPending") && metrics->Get("rebootPending")->Bool());

  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  std::printf(failures ? "%d FAILURES\n" : "rmm executor tests passed\n", failures);
  return failures ? 1 : 0;
}
