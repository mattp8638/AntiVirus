#include "SystemProfile.h"

#include <windows.h>

#include <fstream>
#include <stdexcept>

#include "RmmExecutors.h"
#include "StringUtils.h"
#include "SystemProfileScript.h"

namespace antivirus::agent {

std::string CollectSystemProfileJson(const std::filesystem::path& workRoot) {
  std::error_code ec;
  std::filesystem::create_directories(workRoot, ec);
  // The script is written next to the runtime data (SYSTEM and administrators only) for the run, then removed.
  const auto path = workRoot / (L"system-profile-" + GenerateGuidString() + L".ps1");
  {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << "\xEF\xBB\xBF";
    for (const auto* part : kSystemProfileScriptParts) file << part;
  }
  wchar_t systemDir[MAX_PATH]{};
  GetSystemDirectoryW(systemDir, MAX_PATH);
  const std::wstring command = L"\"" + std::wstring(systemDir) +
                               L"\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NoProfile -NonInteractive "
                               L"-ExecutionPolicy Bypass -File \"" + path.wstring() + L"\"";
  const auto result = rmm::RunProcess(command, workRoot.wstring(), {}, 5 * 60 * 1000, 8 * 1024 * 1024);
  std::filesystem::remove(path, ec);
  auto output = result.stdoutText;
  // ConvertTo-Json prints one line; ignore anything before it (a module warning, say).
  const auto start = output.find("{\"profile\"");
  if (result.timedOut || start == std::string::npos) {
    throw std::runtime_error(result.timedOut ? "the system profile collector timed out"
                                             : "the system profile collector printed no profile: " + result.stderrText.substr(0, 500));
  }
  output = output.substr(start);
  while (!output.empty() && (output.back() == '\n' || output.back() == '\r' || output.back() == ' ')) output.pop_back();
  return output;
}

}  // namespace antivirus::agent
