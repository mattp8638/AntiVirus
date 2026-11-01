#include "WingetSupport.h"

#include <cstdio>
#include <vector>

using namespace antivirus::agent::winget;
static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)

struct FakeWinget {
  std::vector<ProcessOutput> replies;
  std::vector<std::wstring> commands{};
  ProcessOutput operator()(const std::wstring& command) {
    commands.push_back(command);
    if (commands.size() > replies.size()) throw std::runtime_error("Unexpected provider invocation");
    return replies[commands.size() - 1];
  }
  bool InstalledAnything() const {
    for (const auto& command : commands) if (command.find(L" upgrade ") != std::wstring::npos) return true;
    return false;
  }
};

int main() {
  const std::wstring exe = L"C:\\Program Files\\WindowsApps\\AppInstaller\\winget.exe";
  const std::wstring id = L"Google.Chrome";
  const ProcessOutput found{0, L"Google Chrome Google.Chrome 130.0 winget"};
  const ProcessOutput available{0, L"Nombre Id Versión Disponible Fuente\nGoogle Chrome Google.Chrome 130.0 131.0 winget\n"};
  const ProcessOutput noUpgrade{kNoApplications, L"No applicable packages"};
  {
    FakeWinget runner{{found, available}};
    const auto result = Query(exe, id, runner);
    CHECK(result.success && result.status == L"available" && result.availableVersion == L"131.0");
    CHECK(!runner.InstalledAnything());
    CHECK(runner.commands[0].find(L"--exact --source winget") != std::wstring::npos);
    CHECK(runner.commands[1].find(L"--upgrade-available") != std::wstring::npos);
  }
  {
    FakeWinget runner{{{kNoApplications, L"No installed package found matching input criteria."}}};
    const auto result = Query(exe, id, runner);
    CHECK(!result.success && result.status == L"package_not_found");
    CHECK(runner.commands.size() == 1 && !runner.InstalledAnything());
    CHECK(ExitCodeText(2316632084u) == L"0x8A150014");
  }
  {
    FakeWinget runner{{found, noUpgrade}};
    const auto result = Upgrade(exe, id, runner);
    CHECK(result.success && result.status == L"current" && !runner.InstalledAnything());
  }
  {
    FakeWinget runner{{{0x8A15000Fu, L"Upgrade unavailable: source data missing"}}};
    const auto result = Query(exe, id, runner);
    CHECK(!result.success && result.status == L"provider_source_unavailable");
  }
  {
    FakeWinget runner{{found, {0, L"No readable row for this exact package"}}};
    const auto result = Query(exe, id, runner);
    CHECK(!result.success && result.status == L"provider_result_unknown");
  }
  {
    FakeWinget runner{{found, available, {0, L"Installer completed"}, found, noUpgrade}};
    const auto result = Upgrade(exe, id, runner);
    CHECK(result.success && result.status == L"completed" && runner.commands.size() == 5);
    CHECK(runner.commands[2].find(L" upgrade ") != std::wstring::npos);
    CHECK(runner.commands[2].find(L"--silent --accept-package-agreements") != std::wstring::npos);
  }
  {
    FakeWinget runner{{found, available, {0, L"Installer exited"}, found, available}};
    const auto result = Upgrade(exe, id, runner);
    CHECK(!result.success && result.status == L"verification_pending");
  }
  {
    FakeWinget runner{{found, available, {3010, L"Restart required"}}};
    const auto result = Upgrade(exe, id, runner);
    CHECK(result.success && result.rebootRequired && result.status == L"reboot_required");
  }
  {
    FakeWinget runner{{{0, L"Upgrade available", true}}};
    const auto result = Query(exe, id, runner);
    CHECK(!result.success && result.status == L"provider_timeout");
  }
  {
    FakeWinget runner;
    CHECK(Query(L"", id, runner).status == L"provider_missing");
    CHECK(runner.commands.empty());
    bool threw = false;
    try { Query(exe, L"Google.Chrome\" & calc", runner); } catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw && runner.commands.empty());
  }
  std::printf(failures ? "%d WinGet failures\n" : "WinGet discovery, execution and verification tests passed\n", failures);
  return failures ? 1 : 0;
}
