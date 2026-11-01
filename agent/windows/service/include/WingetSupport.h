#pragma once

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <filesystem>
#endif

namespace antivirus::agent::winget {

constexpr std::uint32_t kNoApplications = 0x8A150014u;
constexpr std::uint32_t kNoUpgrade = 0x8A15002Bu;

struct ProcessOutput {
  std::uint32_t exitCode{};
  std::wstring output;
  bool timedOut{false};
};

struct Result {
  bool success{false};
  bool rebootRequired{false};
  std::wstring status;
  std::wstring summary;
  std::wstring availableVersion;
  ProcessOutput process;
};

inline bool IsPackageId(const std::wstring& id) {
  return !id.empty() && id.size() <= 200 &&
         ((id.front() >= L'A' && id.front() <= L'Z') || (id.front() >= L'a' && id.front() <= L'z') ||
          (id.front() >= L'0' && id.front() <= L'9')) &&
         std::all_of(id.begin(), id.end(), [](wchar_t ch) {
           return (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') ||
                  (ch >= L'0' && ch <= L'9') || ch == L'.' || ch == L'+' || ch == L'_' || ch == L'-';
         });
}

inline std::wstring ExitCodeText(std::uint32_t code) {
  std::wostringstream out;
  out << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << code;
  return out.str();
}

// Discovery MUST use list. `upgrade --id` runs an installer, even without --all.
inline std::wstring Command(const std::wstring& exe, const std::wstring& id,
                            bool upgrade = false, bool availableOnly = false) {
  if (exe.empty() || !IsPackageId(id)) throw std::invalid_argument("Invalid WinGet executable or package id");
  return L"\"" + exe + L"\" " + (upgrade ? L"upgrade" : L"list") + L" --id \"" + id +
         L"\" --exact --source winget --accept-source-agreements --disable-interactivity" +
         (upgrade ? L" --silent --accept-package-agreements" :
          availableOnly ? L" --upgrade-available" : L"");
}

inline Result Failure(ProcessOutput process) {
  Result result;
  result.process = std::move(process);
  if (result.process.timedOut) {
    result.status = L"provider_timeout";
    result.summary = L"WinGet exceeded its execution time limit. Check the provider logs before retrying.";
  } else if (result.process.exitCode == kNoApplications) {
    result.status = L"package_not_found";
    result.summary = L"WinGet could not match this installed package in the service account. Check the package ID and whether the app is installed for a different user.";
  } else if (result.process.exitCode == 2) {
    result.status = L"provider_missing";
    result.summary = L"WinGet/App Installer is not available to the protection service.";
  } else if (result.process.exitCode == 0x8A15000Fu || result.process.exitCode == 0x8A150012u ||
             result.process.exitCode == 0x8A150015u) {
    result.status = L"provider_source_unavailable";
    result.summary = L"The WinGet source is missing or unavailable in the service account.";
  } else if (result.process.exitCode == 0x8A150109u || result.process.exitCode == 0x8A15010Au ||
             result.process.exitCode == 0x8A15010Bu) {
    result.status = L"reboot_required";
    result.rebootRequired = true;
    result.summary = L"WinGet requires a restart before installation can be completed or verified.";
  } else {
    result.status = L"provider_failed";
    result.summary = L"WinGet failed (" + ExitCodeText(result.process.exitCode) + L"). Review the captured provider output.";
  }
  return result;
}

// Read values from the matched row, without depending on translated headers or
// searching prose for words such as 'upgrade' (which also appear in errors).
inline std::wstring AvailableVersion(const std::wstring& output, const std::wstring& id) {
  std::wistringstream lines(output);
  std::wstring line;
  while (std::getline(lines, line)) {
    std::wistringstream words(line);
    std::wstring word;
    while (words >> word) {
      if (word != id) continue;
      std::wstring installed, available;
      if (words >> installed >> available && available != L"winget") return available;
    }
  }
  return {};
}

template <typename Runner>
Result Query(const std::wstring& exe, const std::wstring& id, Runner&& run) {
  if (exe.empty()) return Failure({2, {}, false});
  auto installed = run(Command(exe, id));
  if (installed.timedOut || installed.exitCode != 0) return Failure(std::move(installed));
  auto updates = run(Command(exe, id, false, true));
  if (!updates.timedOut && (updates.exitCode == kNoApplications || updates.exitCode == kNoUpgrade)) {
    return {true, false, L"current", L"WinGet matched the installed package and found no applicable upgrade.", {}, std::move(updates)};
  }
  if (updates.timedOut || updates.exitCode != 0) return Failure(std::move(updates));
  auto version = AvailableVersion(updates.output, id);
  if (version.empty()) {
    return {false, false, L"provider_result_unknown", L"WinGet returned an unreadable update result; update status is unknown.", {}, std::move(updates)};
  }
  return {true, false, L"available", L"WinGet confirmed an available upgrade.", std::move(version), std::move(updates)};
}

template <typename Runner>
Result Upgrade(const std::wstring& exe, const std::wstring& id, Runner&& run) {
  auto before = Query(exe, id, run);
  if (!before.success || before.status != L"available") return before;
  auto installed = run(Command(exe, id, true));
  if (installed.timedOut) return Failure(std::move(installed));
  if (installed.exitCode == kNoUpgrade) {
    return {true, false, L"current", L"WinGet reports no applicable upgrade.", {}, std::move(installed)};
  }
  if (installed.exitCode == 3010 || installed.exitCode == 1641) {
    return {true, true, L"reboot_required", L"The installer requires a restart; the new version must be verified afterwards.", {}, std::move(installed)};
  }
  if (installed.exitCode != 0) return Failure(std::move(installed));
  auto after = Query(exe, id, run);
  if (after.success && after.status == L"current") {
    return {true, false, L"completed", L"The installer finished and WinGet confirmed no remaining applicable upgrade.", {}, std::move(installed)};
  }
  return {false, false, L"verification_pending", L"The installer returned success, but the updated package has not been verified. Refresh after the installer finishes or the device restarts.", before.availableVersion, std::move(installed)};
}

#ifdef _WIN32
// Resolve App Installer from the protected machine package directory, rather
// than relying on a per-user app alias or searching the service's working dir.
inline std::wstring FindExecutable() {
  wchar_t programFiles[32768]{};
  auto count = GetEnvironmentVariableW(L"ProgramW6432", programFiles, 32768);
  if (!count || count >= 32768) count = GetEnvironmentVariableW(L"ProgramFiles", programFiles, 32768);
  if (!count || count >= 32768) return {};
  SYSTEM_INFO info{};
  GetNativeSystemInfo(&info);
  const auto arch = info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? L"_arm64__" : L"_x64__";
  std::filesystem::path best;
  std::vector<unsigned long> bestVersion;
  std::error_code error;
  for (std::filesystem::directory_iterator it(std::filesystem::path(programFiles) / L"WindowsApps", error), end;
       !error && it != end; it.increment(error)) {
    auto name = it->path().filename().wstring();
    constexpr wchar_t prefix[] = L"Microsoft.DesktopAppInstaller_";
    if (name.rfind(prefix, 0) != 0 || name.find(arch) == std::wstring::npos || !name.ends_with(L"__8wekyb3d8bbwe")) continue;
    const auto exe = it->path() / L"winget.exe";
    if (!std::filesystem::is_regular_file(exe, error)) { error.clear(); continue; }
    std::vector<unsigned long> version;
    std::wistringstream parts(name.substr(std::size(prefix) - 1));
    std::wstring part;
    try {
      while (std::getline(parts, part, L'.')) version.push_back(std::stoul(part));
    } catch (...) { continue; }
    if (best.empty() || version > bestVersion) { best = exe; bestVersion = std::move(version); }
  }
  return best.wstring();
}
#endif

}  // namespace antivirus::agent::winget
