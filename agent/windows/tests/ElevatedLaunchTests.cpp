// End-to-end check of how the service starts approved programs (tempadmin::LaunchElevated). Run as LocalSystem, like
// the service (CI uses a scheduled task), on a machine with a signed-in user:
//   fenrir-elevated-launch-tests.exe --out <folder>
// It creates a temporary administrator, starts "whoami /groups" as that account in the user's session, and checks the
// program really ran elevated (high integrity, Administrators enabled) with the user's logon SID, so it could reach
// their desktop. It then does the same with the user's own token (an existing administrator) and removes the account.
// Writes <folder>\result.txt: PASS, FAIL <why> or SKIP <why>.
#include <windows.h>
#include <wtsapi32.h>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

#include "LocalAdminRotation.h"
#include "TemporaryAdmin.h"

using namespace antivirus::agent;

namespace {

std::filesystem::path g_out;

int Finish(const std::string& verdict) {
  std::ofstream(g_out / "result.txt", std::ios::trunc) << verdict << "\n";
  std::printf("%s\n", verdict.c_str());
  return verdict.rfind("FAIL", 0) == 0 ? 1 : 0;
}

std::string Narrow(const std::wstring& value) {
  std::string out;
  for (const wchar_t c : value) out += c < 128 ? static_cast<char>(c) : '?';
  return out;
}

std::string ReadAll(const std::filesystem::path& file) {
  std::ifstream in(file, std::ios::binary);
  std::stringstream text;
  text << in.rdbuf();
  // whoami writes the console's code page; keep the ASCII.
  std::string out;
  for (const char c : text.str()) {
    if (c != '\0') out += c;
  }
  return out;
}

// Runs whoami /groups as the launch and returns its output, or an error starting with "error:".
std::string RunWhoami(const std::wstring& account, const std::wstring& password, DWORD session, const std::wstring& name) {
  const auto file = g_out / (name + L".txt");
  std::filesystem::remove(file);
  wchar_t system[MAX_PATH]{};
  GetSystemDirectoryW(system, MAX_PATH);
  const auto cmd = (std::filesystem::path(system) / L"cmd.exe").wstring();
  const auto whoami = (std::filesystem::path(system) / L"whoami.exe").wstring();
  const std::wstring arguments = L"/c \"\"" + whoami + L"\" /groups /fo csv > \"" + file.wstring() + L"\"\"";
  tempadmin::Launch launch;
  std::wstring step;
  const auto status = tempadmin::LaunchElevated(account, password, session, cmd, arguments, &launch, &step);
  if (status != 0) return "error: could not " + Narrow(step) + " (Windows error " + std::to_string(status) + ")";
  for (int i = 0; i < 300 && tempadmin::RunningProcesses(launch) > 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(200));
  const bool finished = tempadmin::RunningProcesses(launch) == 0;
  tempadmin::Release(&launch);
  if (!finished) return "error: the program did not finish";
  return ReadAll(file);
}

std::string CheckElevated(const std::string& groups, const char* who) {
  if (groups.rfind("error:", 0) == 0) return std::string("FAIL ") + who + ": " + groups.substr(7);
  if (groups.find("S-1-16-12288") == std::string::npos) return std::string("FAIL ") + who + ": not high integrity:\n" + groups;
  const auto admins = groups.find("S-1-5-32-544");
  if (admins == std::string::npos) return std::string("FAIL ") + who + ": no Administrators group:\n" + groups;
  const auto line = groups.substr(admins, groups.find('\n', admins) - admins);
  if (line.find("Enabled group") == std::string::npos) return std::string("FAIL ") + who + ": Administrators not enabled: " + line;
  if (groups.find("S-1-5-5-") == std::string::npos) return std::string("FAIL ") + who + ": no logon SID:\n" + groups;
  return {};
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  g_out = std::filesystem::temp_directory_path();
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::wstring(argv[i]) == L"--out") g_out = argv[i + 1];
  }
  std::filesystem::create_directories(g_out);

  const DWORD session = WTSGetActiveConsoleSessionId();
  HANDLE probe = nullptr;
  if (session == 0xFFFFFFFF || !WTSQueryUserToken(session, &probe)) {
    return Finish("SKIP nobody is signed in at the console, or this is not running as LocalSystem (error " +
                  std::to_string(GetLastError()) + ")");
  }
  CloseHandle(probe);

  const auto account = tempadmin::AccountName(L"ci\\elevated", L"elv_test9z9z");
  const auto password = laps::GeneratePassword(20);
  std::wstring sid;
  const auto expires = static_cast<long long>(std::time(nullptr)) + 3600;
  if (const auto status = tempadmin::Create(account, password, expires, &sid); status != 0) {
    return Finish("FAIL could not create the temporary administrator (" + std::to_string(status) + ")");
  }
  auto verdict = CheckElevated(RunWhoami(account, password, session, L"temporary"), "temporary administrator");
  bool profileRemoved = false;
  const auto removed = tempadmin::Remove(account, sid, &profileRemoved);
  if (!verdict.empty()) return Finish(verdict);
  if (removed != 0) return Finish("FAIL the temporary administrator could not be removed (" + std::to_string(removed) + ")");

  // The signed-in user's own token (they are already an administrator on the CI runner).
  verdict = CheckElevated(RunWhoami(L"", L"", session, L"own"), "user's own token");
  if (!verdict.empty()) return Finish(verdict);
  return Finish("PASS");
}
