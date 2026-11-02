#include "ActiveDirectoryOps.h"

#include <windows.h>

#include <fstream>
#include <stdexcept>

#include "ActiveDirectoryOpsScript.h"
#include "RmmExecutors.h"
#include "StringUtils.h"

namespace antivirus::agent {

std::string RunActiveDirectoryOperation(const std::string& requestJson, const std::wstring& secret,
                                        const std::filesystem::path& workRoot) {
  std::error_code ec;
  std::filesystem::create_directories(workRoot, ec);
  const auto id = GenerateGuidString();
  // The runtime folder is readable by SYSTEM and administrators only; every file is removed after the run.
  const auto script = workRoot / (L"ad-ops-" + id + L".ps1");
  const auto request = workRoot / (L"ad-ops-" + id + L".json");
  const auto secretFile = workRoot / (L"ad-ops-" + id + L".secret");
  {
    std::ofstream file(script, std::ios::binary | std::ios::trunc);
    file << "\xEF\xBB\xBF";
    for (const auto* part : kActiveDirectoryOpsScriptParts) file << part;
  }
  {
    std::ofstream file(request, std::ios::binary | std::ios::trunc);
    file << requestJson;
  }
  if (!secret.empty()) {
    std::ofstream file(secretFile, std::ios::binary | std::ios::trunc);
    const auto utf8 = WideToUtf8(secret);
    file << utf8;
  }
  wchar_t systemDir[MAX_PATH]{};
  GetSystemDirectoryW(systemDir, MAX_PATH);
  std::wstring command = L"\"" + std::wstring(systemDir) + L"\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NoProfile -NonInteractive "
                         L"-ExecutionPolicy Bypass -File \"" + script.wstring() + L"\" \"" + request.wstring() + L"\"";
  if (!secret.empty()) command += L" \"" + secretFile.wstring() + L"\"";
  const auto result = rmm::RunProcess(command, workRoot.wstring(), {}, 3 * 60 * 1000, 4 * 1024 * 1024);
  if (!secret.empty()) {
    // Overwrite before deleting, so the password does not linger in free disk space.
    std::ofstream wipe(secretFile, std::ios::binary | std::ios::trunc);
    wipe << std::string(64, '\0');
    wipe.close();
  }
  std::filesystem::remove(secretFile, ec);
  std::filesystem::remove(request, ec);
  std::filesystem::remove(script, ec);
  if (result.timedOut) {
    throw std::runtime_error("the Active Directory operation did not finish within 3 minutes");
  }
  auto output = result.stdoutText;
  const auto start = output.find("{\"ok\"");
  if (start == std::string::npos) {
    throw std::runtime_error("the Active Directory operation printed no result: " + result.stderrText.substr(0, 500));
  }
  output = output.substr(start);
  while (!output.empty() && (output.back() == '\n' || output.back() == '\r' || output.back() == ' ')) output.pop_back();
  return output;
}

}  // namespace antivirus::agent
