#pragma once

// Remote monitoring and management actions for the Windows agent:
// scripts, health metrics, patching by update id, software installs,
// services and power. Each returns the UTF-8 result JSON the cloud stores.

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace antivirus::agent::rmm {

// Thrown when an action ran but failed. The cloud still receives resultJson
// (for example a script's stdout/stderr and exit code) with status "failed".
struct CommandFailed : std::runtime_error {
  CommandFailed(const std::string& message, std::string json) : std::runtime_error(message), resultJson(std::move(json)) {}
  std::string resultJson;
};

struct ProcessResult {
  unsigned long exitCode{0};
  std::string stdoutText;
  std::string stderrText;
  bool timedOut{false};
  std::uint64_t durationMs{0};
};

// Runs a hidden process in a job object (so the whole tree dies on timeout) and captures its output.
ProcessResult RunProcess(const std::wstring& commandLine, const std::wstring& workingDirectory,
                         const std::vector<std::pair<std::wstring, std::wstring>>& extraEnvironment, unsigned long timeoutMs,
                         std::size_t maxOutputBytes = 64 * 1024);

std::string RunScript(const std::wstring& payloadJson, const std::filesystem::path& workRoot);
std::string CollectHealthMetricsJson();
std::string PatchScan(const std::filesystem::path& workRoot);
std::string PatchInstall(const std::wstring& payloadJson, const std::filesystem::path& workRoot);
std::string Software(const std::wstring& payloadJson, bool uninstall, const std::filesystem::path& workRoot);
std::string ServiceControl(const std::wstring& serviceName, const std::wstring& payloadJson);
std::string PowerAction(bool reboot, const std::wstring& payloadJson);
std::string MessageUser(const std::wstring& payloadJson);

// Pure helpers (unit tested on any platform).
std::string QuotePowerShell(const std::string& value);
bool IsSafePackageId(const std::string& value);

}  // namespace antivirus::agent::rmm
