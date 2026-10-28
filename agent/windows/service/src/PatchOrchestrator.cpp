#include "PatchOrchestrator.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "RuntimeDatabase.h"
#include "RmmExecutors.h"
#include "ExtendedPolicy.h"
#include "WingetSupport.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct ProcessExecutionResult {
  DWORD exitCode{0};
  std::wstring output;
};

struct SoftwareProviderResolution {
  PatchProviderKind provider{PatchProviderKind::Manual};
  std::wstring providerId;
  std::wstring supportedSource;
  std::wstring summary;
  bool supported{false};
  bool manualOnly{false};
};

struct PatchDebtSignals {
  int urgencyScore{0};
  int debtScore{0};
  std::wstring debtTier;
  bool likelyKnownExploited{false};
  bool internetFacingLikely{false};
};

struct SoftwareUpdateCandidate {
  PatchProviderKind provider{PatchProviderKind::Manual};
  std::wstring providerId;
  const PackageRecipeRecord* recipe{nullptr};
};

constexpr std::size_t kMaxSoftwareUpdatesPerCycle = 24;

bool IsRunningOnBatteryPower() {
  SYSTEM_POWER_STATUS status{};
  if (GetSystemPowerStatus(&status) == FALSE) {
    return false;
  }

  if (status.ACLineStatus == 1) {
    return false;
  }

  return status.BatteryFlag != 128;
}

bool TreatConnectionAsMetered() {
  auto override = ReadEnvironmentVariable(L"ANTIVIRUS_METERED_CONNECTION");
  std::transform(override.begin(), override.end(), override.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return override == L"1" || override == L"true" || override == L"yes" || override == L"on";
}

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring EscapeWideForJson(const std::wstring& value) {
  return Utf8ToWide(EscapeJsonString(value));
}

bool StartsWithCaseInsensitive(const std::wstring& value, const std::wstring& prefix) {
  if (value.size() < prefix.size()) {
    return false;
  }

  return ToLowerCopy(value.substr(0, prefix.size())) == ToLowerCopy(prefix);
}

bool IsHexLowerSha256(const std::wstring& value) {
  if (value.size() != 64) {
    return false;
  }

  return std::all_of(value.begin(), value.end(), [](const wchar_t ch) {
    return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
  });
}

bool RecipeHasTrustMaterial(const PackageRecipeRecord& recipe) {
  const auto digest = ToLowerCopy(recipe.installerSha256);
  const auto hasDigest = !digest.empty() && IsHexLowerSha256(digest);
  const auto hasSigner = !recipe.requiredSigner.empty();
  return hasDigest || hasSigner;
}

bool RecipeDefinitionTrusted(const PackageRecipeRecord& recipe, std::wstring* reason) {
  if (!StartsWithCaseInsensitive(recipe.sourceUrl, L"https://")) {
    if (reason != nullptr) {
      *reason = L"Recipe source URL is not HTTPS.";
    }
    return false;
  }

  if (!recipe.installerSha256.empty() && !IsHexLowerSha256(ToLowerCopy(recipe.installerSha256))) {
    if (reason != nullptr) {
      *reason = L"Recipe SHA256 metadata is malformed.";
    }
    return false;
  }

  if (!RecipeHasTrustMaterial(recipe)) {
    if (reason != nullptr) {
      *reason = L"Recipe must define installer hash or required signer before automatic execution.";
    }
    return false;
  }

  return true;
}

std::vector<std::wstring> SplitLines(const std::wstring& value) {
  std::vector<std::wstring> lines;
  std::wstringstream stream(value);
  std::wstring line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == L'\r') {
      line.pop_back();
    }
    if (!line.empty()) {
      lines.push_back(line);
    }
  }
  return lines;
}

std::vector<std::wstring> SplitWide(const std::wstring& value, const wchar_t separator) {
  std::vector<std::wstring> parts;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == separator) {
      parts.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  parts.push_back(current);
  return parts;
}

std::wstring JoinStrings(const std::vector<std::wstring>& values, const wchar_t separator = L';') {
  std::wstring joined;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      joined.push_back(separator);
    }
    joined += values[index];
  }
  return joined;
}

std::wstring QuoteForPowerShellSingleQuoted(const std::wstring& value) {
  std::wstring escaped;
  for (const auto ch : value) {
    if (ch == L'\'') {
      escaped += L"''";
    } else {
      escaped.push_back(ch);
    }
  }
  return escaped;
}

ProcessExecutionResult ExecuteHiddenProcessCapture(const std::wstring& commandLine,
                                                   const std::wstring& workingDirectory = {}) {
  SECURITY_ATTRIBUTES securityAttributes{};
  securityAttributes.nLength = sizeof(securityAttributes);
  securityAttributes.bInheritHandle = TRUE;

  HANDLE readHandle = nullptr;
  HANDLE writeHandle = nullptr;
  if (CreatePipe(&readHandle, &writeHandle, &securityAttributes, 0) == FALSE) {
    throw std::runtime_error("CreatePipe failed");
  }

  SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0);

  std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
  mutableCommandLine.push_back(L'\0');

  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  startupInfo.wShowWindow = SW_HIDE;
  startupInfo.hStdOutput = writeHandle;
  startupInfo.hStdError = writeHandle;
  startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION processInfo{};
  const auto created =
      CreateProcessW(nullptr, mutableCommandLine.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                     workingDirectory.empty() ? nullptr : workingDirectory.c_str(), &startupInfo, &processInfo);
  CloseHandle(writeHandle);
  if (!created) {
    CloseHandle(readHandle);
    throw std::runtime_error("CreateProcessW failed");
  }

  std::string output;
  std::array<char, 4096> buffer{};
  DWORD bytesRead = 0;
  while (ReadFile(readHandle, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) != FALSE &&
         bytesRead > 0) {
    output.append(buffer.data(), bytesRead);
  }

  WaitForSingleObject(processInfo.hProcess, INFINITE);

  DWORD exitCode = 0;
  GetExitCodeProcess(processInfo.hProcess, &exitCode);
  CloseHandle(readHandle);
  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);

  return ProcessExecutionResult{
      .exitCode = exitCode,
      .output = Utf8ToWide(output)};
}

std::filesystem::path WriteTempPowerShellScript(const AgentConfig& config, const std::wstring& scriptContent,
                                                const std::wstring& prefix) {
  const auto jobsRoot = config.updateRootPath / L"patch-orchestrator";
  std::error_code error;
  std::filesystem::create_directories(jobsRoot, error);
  if (error) throw std::runtime_error("Unable to create service patch directory: " + error.message());
  const auto scriptPath = jobsRoot / (prefix + L"-" + GenerateGuidString() + L".ps1");

  std::ofstream output(scriptPath, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("Unable to create temporary patch orchestrator script");
  }

  const auto utf8Content = WideToUtf8(scriptContent);
  output.write(utf8Content.data(), static_cast<std::streamsize>(utf8Content.size()));
  output.close();
  if (!output) throw std::runtime_error("Unable to write service patch script");
  return scriptPath;
}

ProcessExecutionResult ExecutePowerShellScript(const AgentConfig& config, const std::wstring& scriptContent,
                                               const std::wstring& prefix,
                                               const std::vector<std::wstring>& arguments = {}) {
  const auto scriptPath = WriteTempPowerShellScript(config, scriptContent, prefix);
  std::wstring commandLine = L"powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath.wstring() + L"\"";
  for (const auto& argument : arguments) {
    commandLine += L" '";
    commandLine += QuoteForPowerShellSingleQuoted(argument);
    commandLine += L"'";
  }

  const auto result = ExecuteHiddenProcessCapture(commandLine, config.updateRootPath.wstring());
  std::error_code removeError;
  std::filesystem::remove(scriptPath, removeError);
  return result;
}

std::vector<PackageRecipeRecord> BuildDefaultRecipes() {
  const auto now = CurrentUtcTimestamp();
  return {
      PackageRecipeRecord{.recipeId = L"google-chrome",
                          .displayName = L"Google Chrome",
                          .publisher = L"Google",
                          .matchPattern = L"google chrome",
                          .wingetId = L"Google.Chrome",
                          .requiredSigner = L"Google",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 100},
      PackageRecipeRecord{.recipeId = L"microsoft-edge",
                          .displayName = L"Microsoft Edge",
                          .publisher = L"Microsoft",
                          .matchPattern = L"microsoft edge",
                          .wingetId = L"Microsoft.Edge",
                          .requiredSigner = L"Microsoft",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 100},
      PackageRecipeRecord{.recipeId = L"mozilla-firefox",
                          .displayName = L"Mozilla Firefox",
                          .publisher = L"Mozilla",
                          .matchPattern = L"firefox",
                          .wingetId = L"Mozilla.Firefox",
                          .requiredSigner = L"Mozilla",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 120},
      PackageRecipeRecord{.recipeId = L"adobe-reader",
                          .displayName = L"Adobe Acrobat Reader",
                          .publisher = L"Adobe",
                          .matchPattern = L"adobe",
                          .wingetId = L"Adobe.Acrobat.Reader.64-bit",
                          .requiredSigner = L"Adobe",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 120},
      PackageRecipeRecord{.recipeId = L"7zip",
                          .displayName = L"7-Zip",
                          .publisher = L"Igor Pavlov",
                          .matchPattern = L"7-zip",
                          .wingetId = L"7zip.7zip",
                          .requiredSigner = L"Igor Pavlov",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 140},
      PackageRecipeRecord{.recipeId = L"java-runtime",
                          .displayName = L"Java",
                          .publisher = L"Oracle",
                          .matchPattern = L"java",
                          .wingetId = L"Oracle.JavaRuntimeEnvironment",
                          .requiredSigner = L"Oracle",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 140},
      PackageRecipeRecord{.recipeId = L"vlc-media-player",
                          .displayName = L"VLC media player",
                          .publisher = L"VideoLAN",
                          .matchPattern = L"vlc",
                          .wingetId = L"VideoLAN.VLC",
                          .requiredSigner = L"VideoLAN",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 150},
      PackageRecipeRecord{.recipeId = L"notepad-plus-plus",
                          .displayName = L"Notepad++",
                          .publisher = L"Notepad++ Team",
                          .matchPattern = L"notepad++",
                          .wingetId = L"Notepad++.Notepad++",
                          .requiredSigner = L"Notepad++",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 150},
      PackageRecipeRecord{.recipeId = L"microsoft-teams",
                          .displayName = L"Microsoft Teams",
                          .publisher = L"Microsoft",
                          .matchPattern = L"teams",
                          .wingetId = L"Microsoft.Teams",
                          .requiredSigner = L"Microsoft",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 160},
      PackageRecipeRecord{.recipeId = L"zoom",
                          .displayName = L"Zoom",
                          .publisher = L"Zoom",
                          .matchPattern = L"zoom",
                          .wingetId = L"Zoom.Zoom",
                          .requiredSigner = L"Zoom",
                          .rebootBehavior = L"none",
                          .updatedAt = now,
                          .priority = 160},
      PackageRecipeRecord{.recipeId = L"vcpp-redistributable",
                          .displayName = L"Microsoft Visual C++ Redistributable",
                          .publisher = L"Microsoft",
                          .matchPattern = L"visual c++",
                          .wingetId = L"Microsoft.VCRedist.2015+.x64",
                          .requiredSigner = L"Microsoft",
                          .rebootBehavior = L"possible",
                          .updatedAt = now,
                          .priority = 180},
  };
}

bool IsHighRiskSoftware(const InstalledSoftwareInventoryItem& item) {
  const auto lowerName = ToLowerCopy(item.displayName);
  const std::vector<std::wstring> patterns = {
      L"chrome", L"edge", L"firefox", L"adobe", L"reader", L"java", L"zoom", L"teams",
      L"vpn",    L"remote", L"support", L"7-zip",  L"vlc",   L"notepad++", L"redistributable"};

  return std::any_of(patterns.begin(), patterns.end(),
                     [&lowerName](const auto& pattern) { return lowerName.find(pattern) != std::wstring::npos; });
}

int ClampPatchScore(const int value) {
  return std::max(0, std::min(100, value));
}

std::wstring DebtTierFromScore(const int score) {
  if (score >= 85) {
    return L"critical";
  }
  if (score >= 65) {
    return L"high";
  }
  if (score >= 40) {
    return L"medium";
  }
  if (score >= 20) {
    return L"low";
  }
  return L"minimal";
}

bool ContainsAnyToken(const std::wstring& value, const std::vector<std::wstring>& tokens) {
  const auto lower = ToLowerCopy(value);
  return std::any_of(tokens.begin(), tokens.end(),
                     [&lower](const std::wstring& token) { return lower.find(token) != std::wstring::npos; });
}

PatchDebtSignals ComputeWindowsPatchDebtSignals(const WindowsUpdateRecord& record) {
  const auto lowerTitle = ToLowerCopy(record.title);
  const auto lowerSeverity = ToLowerCopy(record.severity);
  const auto lowerCategories = ToLowerCopy(record.categories);
  const auto lowerClassification = ToLowerCopy(record.classification);

  int urgency = 15;
  if (lowerClassification == L"security") {
    urgency += 30;
  } else if (lowerClassification == L"critical") {
    urgency += 42;
  } else if (lowerClassification == L"quality") {
    urgency += 18;
  }

  if (lowerSeverity.find(L"critical") != std::wstring::npos) {
    urgency += 30;
  } else if (lowerSeverity.find(L"important") != std::wstring::npos ||
             lowerSeverity.find(L"high") != std::wstring::npos) {
    urgency += 18;
  }

  const auto cveReferenced = lowerTitle.find(L"cve-") != std::wstring::npos ||
                             lowerCategories.find(L"cve-") != std::wstring::npos;
  const auto likelyExploited = cveReferenced || lowerTitle.find(L"zero-day") != std::wstring::npos ||
                               lowerTitle.find(L"actively exploited") != std::wstring::npos ||
                               lowerTitle.find(L"out-of-band") != std::wstring::npos;
  if (likelyExploited) {
    urgency += 22;
  }

  if (record.mandatory) {
    urgency += 8;
  }
  if (record.rebootRequired) {
    urgency += 6;
  }
  if (record.driver || record.optional) {
    urgency -= 18;
  }
  if (record.featureUpdate) {
    urgency -= 15;
  }

  PatchDebtSignals signals;
  signals.urgencyScore = ClampPatchScore(urgency);
  signals.debtScore = ClampPatchScore(signals.urgencyScore + (record.downloaded ? 5 : 0));
  signals.debtTier = DebtTierFromScore(signals.debtScore);
  signals.likelyKnownExploited = likelyExploited;
  return signals;
}

PatchDebtSignals ComputeSoftwarePatchDebtSignals(const SoftwarePatchRecord& record) {
  int urgency = 8;
  const auto lowerName = ToLowerCopy(record.displayName);
  const auto lowerState = ToLowerCopy(record.updateState);
  const auto lowerProvider = ToLowerCopy(record.provider);

  const std::vector<std::wstring> internetFacingTokens = {L"chrome", L"edge", L"firefox", L"zoom", L"teams", L"vpn",
                                                          L"remote", L"browser"};
  const auto internetFacing = ContainsAnyToken(lowerName, internetFacingTokens);

  if (record.highRisk) {
    urgency += 32;
  }

  if (lowerState == L"available") {
    urgency += 28;
  } else if (lowerState == L"provider_ready") {
    urgency += 20;
  } else if (lowerState == L"manual") {
    urgency -= 8;
  }

  if (lowerProvider == L"native-updater" || lowerProvider == L"winget") {
    urgency += 10;
  } else if (lowerProvider == L"recipe") {
    urgency += 5;
  }

  if (record.manualOnly) {
    urgency -= 18;
  }
  if (record.userInteractionRequired) {
    urgency -= 10;
  }
  if (record.blocked) {
    urgency = 0;
  }

  const auto likelyExploited = internetFacing && (record.highRisk || lowerState == L"available");
  if (likelyExploited) {
    urgency += 14;
  }

  PatchDebtSignals signals;
  signals.urgencyScore = ClampPatchScore(urgency);
  signals.debtScore = ClampPatchScore(signals.urgencyScore + (record.rebootRequired ? 4 : 0));
  signals.debtTier = DebtTierFromScore(signals.debtScore);
  signals.likelyKnownExploited = likelyExploited;
  signals.internetFacingLikely = internetFacing;
  return signals;
}

std::wstring BuildWindowsUpdateDetailJson(const bool canRequestUserInput, const PatchDebtSignals& signals) {
  return std::wstring(L"{\"canRequestUserInput\":") + (canRequestUserInput ? L"true" : L"false") +
         L",\"urgencyScore\":" + std::to_wstring(signals.urgencyScore) + L",\"debtScore\":" +
         std::to_wstring(signals.debtScore) + L",\"debtTier\":\"" +
         Utf8ToWide(EscapeJsonString(signals.debtTier)) + L"\",\"likelyKnownExploited\":" +
         (signals.likelyKnownExploited ? L"true" : L"false") + L"}";
}

std::wstring BuildSoftwarePatchDetailJson(const SoftwarePatchRecord& record, const PatchDebtSignals& signals) {
  return std::wstring(L"{\"urgencyScore\":") + std::to_wstring(signals.urgencyScore) + L",\"debtScore\":" +
         std::to_wstring(signals.debtScore) + L",\"debtTier\":\"" +
         Utf8ToWide(EscapeJsonString(signals.debtTier)) + L"\",\"likelyKnownExploited\":" +
         (signals.likelyKnownExploited ? L"true" : L"false") + L",\"internetFacingLikely\":" +
         (signals.internetFacingLikely ? L"true" : L"false") + L",\"provider\":\"" +
         Utf8ToWide(EscapeJsonString(record.provider)) + L"\",\"updateState\":\"" +
         Utf8ToWide(EscapeJsonString(record.updateState)) + L"\"}";
}

std::optional<PackageRecipeRecord> MatchRecipe(const InstalledSoftwareInventoryItem& item,
                                               const std::vector<PackageRecipeRecord>& recipes) {
  const auto lowerName = ToLowerCopy(item.displayName);
  const auto lowerPublisher = ToLowerCopy(item.publisher);
  for (const auto& recipe : recipes) {
    if (!recipe.enabled) {
      continue;
    }

    if (!recipe.matchPattern.empty() && lowerName.find(ToLowerCopy(recipe.matchPattern)) != std::wstring::npos) {
      return recipe;
    }

    if (!recipe.publisher.empty() && !item.publisher.empty() &&
        lowerPublisher.find(ToLowerCopy(recipe.publisher)) != std::wstring::npos &&
        lowerName.find(ToLowerCopy(recipe.displayName)) != std::wstring::npos) {
      return recipe;
    }
  }

  return std::nullopt;
}

const PackageRecipeRecord* FindRecipeForSoftwareRecord(const SoftwarePatchRecord& record,
                                                       const std::vector<PackageRecipeRecord>& recipes) {
  if (record.provider == L"recipe" && !record.providerId.empty()) {
    const auto byId = std::find_if(recipes.begin(), recipes.end(), [&](const PackageRecipeRecord& recipe) {
      return recipe.enabled && recipe.recipeId == record.providerId;
    });
    if (byId != recipes.end()) {
      return &(*byId);
    }
  }

  const auto lowerName = ToLowerCopy(record.displayName);
  const auto lowerPublisher = ToLowerCopy(record.publisher);
  for (const auto& recipe : recipes) {
    if (!recipe.enabled) {
      continue;
    }

    if (!recipe.matchPattern.empty() &&
        lowerName.find(ToLowerCopy(recipe.matchPattern)) != std::wstring::npos) {
      return &recipe;
    }

    if (!recipe.displayName.empty() && lowerName.find(ToLowerCopy(recipe.displayName)) != std::wstring::npos) {
      return &recipe;
    }
  }

  return nullptr;
}

void AppendSoftwareUpdateCandidate(std::vector<SoftwareUpdateCandidate>* candidates, const PatchProviderKind provider,
                                   const std::wstring& providerId, const PackageRecipeRecord* recipe) {
  if (candidates == nullptr) {
    return;
  }

  if (provider == PatchProviderKind::NativeUpdater && providerId.empty()) {
    return;
  }

  if (provider == PatchProviderKind::Winget && providerId.empty()) {
    return;
  }

  if (provider == PatchProviderKind::Recipe && recipe == nullptr) {
    return;
  }

  if (provider == PatchProviderKind::Manual) {
    return;
  }

  const auto duplicate = std::find_if(candidates->begin(), candidates->end(),
                                      [&](const SoftwareUpdateCandidate& existing) {
                                        return existing.provider == provider &&
                                               existing.providerId == providerId;
                                      });
  if (duplicate != candidates->end()) {
    return;
  }

  candidates->push_back(SoftwareUpdateCandidate{
      .provider = provider,
      .providerId = providerId,
      .recipe = recipe});
}

std::vector<SoftwareUpdateCandidate> BuildSoftwareUpdateCandidates(const SoftwarePatchRecord& record,
                                                                   const PatchPolicyRecord& policy,
                                                                   const PackageRecipeRecord* recipe) {
  std::vector<SoftwareUpdateCandidate> candidates;
  candidates.reserve(4);

  const auto primaryProvider = PatchProviderKindFromString(record.provider);
  switch (primaryProvider) {
    case PatchProviderKind::NativeUpdater:
      AppendSoftwareUpdateCandidate(&candidates, PatchProviderKind::NativeUpdater, record.providerId, recipe);
      break;
    case PatchProviderKind::Winget:
      AppendSoftwareUpdateCandidate(&candidates, PatchProviderKind::Winget, record.providerId, recipe);
      break;
    case PatchProviderKind::Recipe:
      AppendSoftwareUpdateCandidate(&candidates, PatchProviderKind::Recipe,
                                    record.providerId.empty() && recipe != nullptr ? recipe->recipeId : record.providerId,
                                    recipe);
      break;
    default:
      break;
  }

  if (recipe != nullptr) {
    if (policy.allowWinget && !recipe->wingetId.empty()) {
      AppendSoftwareUpdateCandidate(&candidates, PatchProviderKind::Winget, recipe->wingetId, recipe);
    }

    if (policy.allowRecipes && !recipe->sourceUrl.empty()) {
      AppendSoftwareUpdateCandidate(&candidates, PatchProviderKind::Recipe, recipe->recipeId, recipe);
    }
  }

  return candidates;
}

std::filesystem::path FindNativeUpdaterExecutable(const InstalledSoftwareInventoryItem& item, const std::wstring& updaterName) {
  const auto localAppData = ReadEnvironmentVariable(L"LOCALAPPDATA");
  const auto programFiles = ReadEnvironmentVariable(L"ProgramFiles");
  const auto programFilesX86 = ReadEnvironmentVariable(L"ProgramFiles(x86)");

  std::vector<std::filesystem::path> candidates;
  if (!item.installLocation.empty()) {
    candidates.emplace_back(std::filesystem::path(item.installLocation) / updaterName);
    candidates.emplace_back(std::filesystem::path(item.installLocation).parent_path() / L"Update" / updaterName);
  }
  if (!localAppData.empty()) {
    candidates.emplace_back(std::filesystem::path(localAppData) / L"Google" / L"Update" / updaterName);
    candidates.emplace_back(std::filesystem::path(localAppData) / L"Microsoft" / L"EdgeUpdate" / updaterName);
  }
  if (!programFiles.empty()) {
    candidates.emplace_back(std::filesystem::path(programFiles) / L"Google" / L"Update" / updaterName);
    candidates.emplace_back(std::filesystem::path(programFiles) / L"Microsoft" / L"EdgeUpdate" / updaterName);
  }
  if (!programFilesX86.empty()) {
    candidates.emplace_back(std::filesystem::path(programFilesX86) / L"Google" / L"Update" / updaterName);
    candidates.emplace_back(std::filesystem::path(programFilesX86) / L"Microsoft" / L"EdgeUpdate" / updaterName);
  }

  std::error_code error;
  for (const auto& candidate : candidates) {
    if (std::filesystem::exists(candidate, error)) {
      return candidate;
    }
  }

  return {};
}

std::wstring BuildWindowsUpdateDiscoveryScript() {
  return LR"(
$ErrorActionPreference = 'Stop'
function Sanitize([string]$value) {
  if ($null -eq $value) { return '' }
  return ($value -replace "`t", ' ' -replace "`r", ' ' -replace "`n", ' ').Trim()
}

$reasons = New-Object System.Collections.Generic.List[string]
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons.Add('windows_update') | Out-Null }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons.Add('component_servicing') | Out-Null }
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager') {
  $pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).PendingFileRenameOperations
  if ($pending) { $reasons.Add('pending_file_rename') | Out-Null }
}
$computerName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue).ComputerName
$pendingComputerName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue).ComputerName
if ($computerName -and $pendingComputerName -and $computerName -ne $pendingComputerName) { $reasons.Add('computer_rename') | Out-Null }
Write-Output ("REBOOT`t{0}`t{1}" -f ($(if ($reasons.Count -gt 0) { '1' } else { '0' })), (Sanitize ($reasons -join ';')))

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$criteriaList = @("IsInstalled=0 and Type='Software'", "IsInstalled=0 and Type='Driver'")
foreach ($criteria in $criteriaList) {
  try {
    $searchResult = $searcher.Search($criteria)
    foreach ($update in $searchResult.Updates) {
      $categories = @($update.Categories | ForEach-Object { $_.Name }) -join ';'
      $kbs = @($update.KBArticleIDs) -join ';'
      $type = if ($criteria -like "*Driver*") { 'driver' } else { 'software' }
      Write-Output ("UPDATE`t{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}`t{8}`t{9}`t{10}`t{11}`t{12}" -f `
        (Sanitize $update.Identity.UpdateID), `
        (Sanitize ([string]$update.Identity.RevisionNumber)), `
        (Sanitize $update.Title), `
        (Sanitize $kbs), `
        (Sanitize $categories), `
        (Sanitize $type), `
        (Sanitize $update.MsrcSeverity), `
        (Sanitize ([string]$update.InstallationBehavior.RebootBehavior)), `
        ($(if ($update.IsDownloaded) { '1' } else { '0' })), `
        ($(if ($update.IsHidden) { '1' } else { '0' })), `
        ($(if ($update.AutoSelectOnWebSites) { '1' } else { '0' })), `
        ($(if ($update.BrowseOnly) { '1' } else { '0' })), `
        ($(if ($update.InstallationBehavior.CanRequestUserInput) { '1' } else { '0' })))
    }
  } catch {
    Write-Output ("ERROR`tSEARCH`t{0}" -f (Sanitize $_.Exception.Message))
  }
}

try {
  $count = $searcher.GetTotalHistoryCount()
  if ($count -gt 0) {
    $history = $searcher.QueryHistory(0, [Math]::Min($count, 25))
    foreach ($entry in $history) {
      if ($entry.ResultCode -ne 2) {
        Write-Output ("HISTORY`t{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f `
          (Sanitize $entry.UpdateIdentity.UpdateID), `
          (Sanitize $entry.Title), `
          (Sanitize ([string]$entry.ResultCode)), `
          (Sanitize ([string]$entry.HResult)), `
          (Sanitize ([string]$entry.Operation)), `
          (Sanitize ($entry.Date.ToString('o'))))
      }
    }
  }
} catch {
  Write-Output ("ERROR`tHISTORY`t{0}" -f (Sanitize $_.Exception.Message))
}
)";
}

std::wstring BuildWindowsUpdateInstallScript() {
  return LR"PATCH(
param([string]$securityOnly, [string]$includeDrivers, [string]$includeOptional, [string]$deferFeatureUpdates)
$ErrorActionPreference = 'Stop'
function Sanitize([string]$value) {
  if ($null -eq $value) { return '' }
  return ($value -replace "`t", ' ' -replace "`r", ' ' -replace "`n", ' ').Trim()
}
function IsMatch([string]$text, [string[]]$patterns) {
  $lower = ([string]::IsNullOrEmpty($text) ? '' : $text).ToLowerInvariant()
  foreach ($pattern in $patterns) {
    if ($lower.Contains($pattern)) { return $true }
  }
  return $false
}
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$criteriaList = @("IsInstalled=0 and Type='Software'")
if ($includeDrivers -eq '1') { $criteriaList += "IsInstalled=0 and Type='Driver'" }
$collection = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($criteria in $criteriaList) {
  $searchResult = $searcher.Search($criteria)
  foreach ($update in $searchResult.Updates) {
    $categories = @($update.Categories | ForEach-Object { $_.Name }) -join ';'
    $title = $update.Title
    $feature = (IsMatch $title @('feature update', 'windows 11, version', 'windows 10, version')) -or (IsMatch $categories @('feature packs', 'upgrades'))
    $optional = $update.BrowseOnly
    $securityLike = (IsMatch $title @('security', 'cumulative', '.net', 'defender', 'critical')) -or (IsMatch $categories @('security updates', 'critical updates', 'definition updates', 'update rollups', '.net'))
    if ($deferFeatureUpdates -eq '1' -and $feature) { continue }
    if ($includeOptional -ne '1' -and $optional) { continue }
    if ($securityOnly -eq '1' -and -not $securityLike) { continue }
    [void]$collection.Add($update)
  }
}
if ($collection.Count -eq 0) {
  Write-Output "RESULT`tno_updates`t0`t0"
  exit 0
}
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $collection
$downloadResult = $downloader.Download()
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $collection
$installResult = $installer.Install()
Write-Output ("RESULT`t{0}`t{1}`t{2}" -f (Sanitize ([string]$installResult.ResultCode)), ($(if ($installResult.RebootRequired) { '1' } else { '0' })), (Sanitize ([string]$downloadResult.ResultCode)))
for ($i = 0; $i -lt $collection.Count; $i++) {
  $update = $collection.Item($i)
  $result = $installResult.GetUpdateResult($i)
  Write-Output ("INSTALLED`t{0}`t{1}`t{2}`t{3}" -f (Sanitize $update.Identity.UpdateID), (Sanitize $update.Title), (Sanitize ([string]$result.ResultCode)), (Sanitize ([string]$result.HResult)))
}
)PATCH";
}

std::wstring BuildRecipeInstallScript() {
  return LR"PATCH(
param([string]$sourceUrl, [string]$targetPath, [string]$expectedSha256, [string]$requiredSigner, [string]$silentArgs)
$ErrorActionPreference = 'Stop'
Invoke-WebRequest -Uri $sourceUrl -OutFile $targetPath
if ($expectedSha256) {
  $hash = (Get-FileHash -Path $targetPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($hash -ne $expectedSha256.ToLowerInvariant()) {
    Write-Output ("RESULT`tfailed_hash`t0`t" + $hash)
    exit 3
  }
}
if ($requiredSigner) {
  $signature = Get-AuthenticodeSignature -FilePath $targetPath
  if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notlike ("*" + $requiredSigner + "*")) {
    Write-Output ("RESULT`tfailed_signer`t0`t" + ($signature.Status.ToString()))
    exit 4
  }
}
$process = Start-Process -FilePath $targetPath -ArgumentList $silentArgs -Wait -PassThru -WindowStyle Hidden
Write-Output ("RESULT`tcompleted`t0`t" + $process.ExitCode)
)PATCH";
}

std::wstring ClassifyWindowsUpdate(const std::wstring& title, const std::wstring& categories, const bool driver,
                                   const bool optional) {
  const auto lowerTitle = ToLowerCopy(title);
  const auto lowerCategories = ToLowerCopy(categories);
  if (driver) {
    return L"driver";
  }
  if (lowerTitle.find(L"feature update") != std::wstring::npos || lowerCategories.find(L"upgrades") != std::wstring::npos) {
    return L"feature";
  }
  if (lowerTitle.find(L".net") != std::wstring::npos || lowerCategories.find(L".net") != std::wstring::npos) {
    return L"dotnet";
  }
  if (lowerTitle.find(L"defender") != std::wstring::npos || lowerCategories.find(L"definition") != std::wstring::npos) {
    return L"defender";
  }
  if (lowerTitle.find(L"security") != std::wstring::npos || lowerCategories.find(L"security updates") != std::wstring::npos) {
    return L"security";
  }
  if (lowerTitle.find(L"critical") != std::wstring::npos || lowerCategories.find(L"critical updates") != std::wstring::npos) {
    return L"critical";
  }
  if (lowerTitle.find(L"cumulative") != std::wstring::npos || lowerCategories.find(L"update rollups") != std::wstring::npos) {
    return L"cumulative";
  }
  if (optional) {
    return L"optional";
  }
  return L"quality";
}

PatchPolicyRecord LoadOrCreatePolicy(RuntimeDatabase& database) {
  PatchPolicyRecord policy;
  if (!database.LoadPatchPolicy(policy)) {
    policy.updatedAt = CurrentUtcTimestamp();
    database.SavePatchPolicy(policy);
  }
  return policy;
}

SoftwareProviderResolution ResolveProvider(const InstalledSoftwareInventoryItem& item, const PatchPolicyRecord& policy,
                                           const std::vector<PackageRecipeRecord>& recipes) {
  SoftwareProviderResolution resolution{};
  const auto recipe = MatchRecipe(item, recipes);
  if (!recipe.has_value()) {
    resolution.summary = L"Fenrir does not currently have a trusted update provider for this software.";
    resolution.manualOnly = true;
    return resolution;
  }

  const auto lowerName = ToLowerCopy(item.displayName);
  if (policy.allowNativeUpdaters &&
      (lowerName.find(L"google chrome") != std::wstring::npos || lowerName.find(L"microsoft edge") != std::wstring::npos)) {
    const auto updaterPath =
        lowerName.find(L"google chrome") != std::wstring::npos
            ? FindNativeUpdaterExecutable(item, L"GoogleUpdate.exe")
            : FindNativeUpdaterExecutable(item, L"MicrosoftEdgeUpdate.exe");
    if (!updaterPath.empty()) {
      resolution.provider = PatchProviderKind::NativeUpdater;
      resolution.providerId = updaterPath.wstring();
      resolution.supportedSource = L"native-updater";
      resolution.supported = true;
      resolution.summary = L"Fenrir can patch this application using its trusted native silent updater.";
      return resolution;
    }
  }

  if (policy.allowWinget && !recipe->wingetId.empty()) {
    resolution.provider = PatchProviderKind::Winget;
    resolution.providerId = recipe->wingetId;
    resolution.supportedSource = L"winget";
    resolution.supported = true;
    resolution.summary = L"Fenrir can patch this application using winget.";
    return resolution;
  }

  if (policy.allowRecipes && !recipe->sourceUrl.empty()) {
    std::wstring trustReason;
    if (RecipeDefinitionTrusted(*recipe, &trustReason)) {
      resolution.provider = PatchProviderKind::Recipe;
      resolution.providerId = recipe->recipeId;
      resolution.supportedSource = L"recipe";
      resolution.supported = true;
      resolution.summary = L"Fenrir can patch this application using a maintained package recipe.";
      resolution.manualOnly = recipe->manualOnly;
      return resolution;
    }

    resolution.provider = PatchProviderKind::Manual;
    resolution.providerId = recipe->recipeId;
    resolution.supportedSource = L"manual";
    resolution.supported = false;
    resolution.manualOnly = true;
    resolution.summary = L"Fenrir found a recipe but blocked automation because trust metadata is incomplete: " +
                         trustReason;
    return resolution;
  }

  resolution.provider = PatchProviderKind::Manual;
  resolution.providerId = recipe->recipeId;
  resolution.supportedSource = L"manual";
  resolution.supported = false;
  resolution.manualOnly = true;
  resolution.summary = L"Fenrir can inventory this application but patching currently requires a manual workflow.";
  return resolution;
}

winget::Result RunWingetOperation(const std::wstring& id, bool install) {
  const auto exe = winget::FindExecutable();
  auto run = [](const std::wstring& command) {
    const bool installing = command.find(L" --silent ") != std::wstring::npos;
    const auto process = rmm::RunProcess(command, L"", {}, installing ? 45 * 60 * 1000 : 2 * 60 * 1000,
                                         4 * 1024 * 1024);
    return winget::ProcessOutput{process.exitCode,
        Utf8ToWide(process.stdoutText + "\n" + process.stderrText), process.timedOut};
  };
  try {
    return install ? winget::Upgrade(exe, id, run) : winget::Query(exe, id, run);
  } catch (const std::exception& error) {
    auto result = winget::Failure({1, Utf8ToWide(error.what()), false});
    result.summary = L"WinGet could not complete the request. " + result.process.output;
    return result;
  }
}

std::vector<SoftwarePatchRecord> BuildSoftwarePatchInventory(const DeviceInventorySnapshot& snapshot,
                                                             const PatchPolicyRecord& policy,
                                                             const std::vector<PackageRecipeRecord>& recipes) {
  std::vector<SoftwarePatchRecord> records;
  records.reserve(snapshot.installedSoftware.size());

  for (const auto& item : snapshot.installedSoftware) {
    const auto resolution = ResolveProvider(item, policy, recipes);
    auto updateState = resolution.manualOnly ? std::wstring(L"manual") : (resolution.supported ? L"not_checked" : L"unsupported");
    auto availableVersion = std::wstring{};
    auto summary = resolution.summary;

    if (resolution.provider == PatchProviderKind::Winget) {
      const auto result = RunWingetOperation(resolution.providerId, false);
      updateState = result.status;
      availableVersion = result.availableVersion;
      summary = result.summary;
    } else if (resolution.provider == PatchProviderKind::NativeUpdater && !resolution.providerId.empty()) {
      summary = L"Fenrir can invoke the product's native updater during a maintenance window.";
      updateState = L"provider_ready";
    }

    auto record = SoftwarePatchRecord{
        .softwareId = item.softwareId,
        .displayName = item.displayName,
        .displayVersion = item.displayVersion,
        .availableVersion = availableVersion,
        .publisher = item.publisher,
        .installLocation = item.installLocation,
        .uninstallCommand = item.uninstallCommand,
        .quietUninstallCommand = item.quietUninstallCommand,
        .executableNames = JoinStrings(item.executableNames),
        .executablePaths = JoinStrings(item.executablePaths),
        .provider = PatchProviderKindToString(resolution.provider),
        .providerId = resolution.providerId,
        .supportedSource = resolution.supportedSource,
        .updateState = updateState,
        .updateSummary = summary,
        .lastCheckedAt = CurrentUtcTimestamp(),
        .blocked = item.blocked,
        .supported = resolution.supported,
        .manualOnly = resolution.manualOnly,
        .highRisk = IsHighRiskSoftware(item)};
      const auto debtSignals = ComputeSoftwarePatchDebtSignals(record);
      record.detailJson = BuildSoftwarePatchDetailJson(record, debtSignals);
      records.push_back(std::move(record));
  }

  return records;
}

std::vector<WindowsUpdateRecord> DiscoverWindowsUpdates(const AgentConfig& config, RebootCoordinatorRecord* rebootState,
                                                        std::vector<PatchHistoryRecord>* history) {
  const auto result = ExecutePowerShellScript(config, BuildWindowsUpdateDiscoveryScript(), L"wu-discovery");
  std::vector<WindowsUpdateRecord> updates;
  for (const auto& line : SplitLines(result.output)) {
    const auto parts = SplitWide(line, L'\t');
    if (parts.empty()) {
      continue;
    }

    if (parts[0] == L"REBOOT" && rebootState != nullptr) {
      rebootState->detectedAt = CurrentUtcTimestamp();
      rebootState->status = L"current";
      rebootState->rebootRequired = parts.size() >= 2 && parts[1] == L"1";
      rebootState->rebootReasons = parts.size() >= 3 ? parts[2] : L"";
      rebootState->pendingWindowsUpdate = rebootState->rebootReasons.find(L"windows_update") != std::wstring::npos;
      rebootState->pendingFileRename = rebootState->rebootReasons.find(L"pending_file_rename") != std::wstring::npos;
      rebootState->pendingComputerRename = rebootState->rebootReasons.find(L"computer_rename") != std::wstring::npos;
      rebootState->pendingComponentServicing = rebootState->rebootReasons.find(L"component_servicing") != std::wstring::npos;
      continue;
    }

    if (parts[0] == L"UPDATE" && parts.size() >= 13) {
      const auto driver = parts[5] == L"driver";
      const auto optional = parts[11] == L"1";
      const auto classification = ClassifyWindowsUpdate(parts[3], parts[5], driver, optional);
      auto record = WindowsUpdateRecord{
          .updateId = parts[1],
          .revision = parts[2],
          .title = parts[3],
          .kbArticles = parts[4],
          .categories = parts[5],
          .classification = classification,
          .severity = parts[6],
          .updateType = parts[5],
          .deploymentAction = parts[7],
          .discoveredAt = CurrentUtcTimestamp(),
          .status = L"available",
          .hidden = parts[9] == L"1",
          .downloaded = parts[8] == L"1",
          .mandatory = parts[10] == L"1",
          .browseOnly = optional,
          .rebootRequired = parts[7] != L"0",
          .driver = driver,
          .featureUpdate = classification == L"feature",
            .optional = optional};
          const auto debtSignals = ComputeWindowsPatchDebtSignals(record);
          record.detailJson = BuildWindowsUpdateDetailJson(parts[12] == L"1", debtSignals);
          updates.push_back(std::move(record));
      continue;
    }

    if (parts[0] == L"HISTORY" && parts.size() >= 7 && history != nullptr) {
      history->push_back(PatchHistoryRecord{
          .recordId = GenerateGuidString(),
          .targetType = L"windows-update",
          .targetId = parts[1],
          .title = parts[2],
          .provider = L"windows-update-agent",
          .action = L"history",
          .status = parts[3] == L"2" ? L"succeeded" : L"failed",
          .startedAt = parts[6],
          .completedAt = parts[6],
          .errorCode = parts[4],
          .detailJson = std::wstring(L"{\"operation\":\"") + Utf8ToWide(EscapeJsonString(parts[5])) + L"\"}"});
    }
  }
  return updates;
}

PatchExecutionResult ExecuteWingetOperation(const std::wstring& wingetId, const bool searchOnly) {
  const auto result = RunWingetOperation(wingetId, !searchOnly);
  return PatchExecutionResult{
      .success = result.success,
      .rebootRequired = result.rebootRequired,
      .action = searchOnly ? L"search" : L"install",
      .provider = L"winget",
      .status = result.status,
      .errorCode = result.success ? std::wstring{} : result.process.exitCode == 0 ? L"WINGET_UNVERIFIED_RESULT" : L"WINGET_" + winget::ExitCodeText(result.process.exitCode),
      .detailJson = L"{\"summary\":\"" + EscapeWideForJson(result.summary) +
          L"\",\"exitCode\":" + std::to_wstring(result.process.exitCode) +
          L",\"output\":\"" + EscapeWideForJson(result.process.output) + L"\"}"};
}

PatchExecutionResult ExecuteNativeOperation(const std::wstring& providerId) {
  const auto lowerProvider = ToLowerCopy(providerId);
  std::wstring commandLine;
  if (lowerProvider.find(L"googleupdate.exe") != std::wstring::npos ||
      lowerProvider.find(L"microsoftedgeupdate.exe") != std::wstring::npos) {
    commandLine = L"\"" + providerId + L"\" /ua /installsource scheduler";
  } else {
    return PatchExecutionResult{
        .success = false,
        .action = L"install",
        .provider = L"native-updater",
        .status = L"unsupported",
        .errorCode = L"NATIVE_PROVIDER_UNSUPPORTED",
        .detailJson = L"{\"message\":\"Fenrir does not have a vetted native updater command for this product.\"}"};
  }

  const auto result = ExecuteHiddenProcessCapture(commandLine);
  return PatchExecutionResult{
      .success = result.exitCode == 0,
      .action = L"install",
      .provider = L"native-updater",
      .status = result.exitCode == 0 ? L"completed" : L"failed",
      .detailJson = std::wstring(L"{\"output\":\"") + Utf8ToWide(EscapeJsonString(result.output)) + L"\"}"};
}

PatchExecutionResult ExecuteRecipeOperation(const AgentConfig& config, const PackageRecipeRecord& recipe) {
  if (recipe.sourceUrl.empty()) {
    return PatchExecutionResult{
        .success = false,
        .action = L"install",
        .provider = L"recipe",
        .status = L"manual",
        .errorCode = L"RECIPE_SOURCE_MISSING",
        .detailJson = L"{\"message\":\"Recipe has no source URL and requires manual fulfillment.\"}"};
  }

  const auto downloadRoot = config.updateRootPath / L"third-party";
  std::error_code error;
  std::filesystem::create_directories(downloadRoot, error);
  const auto targetPath = downloadRoot / (recipe.recipeId + L".bin");
  const auto result = ExecutePowerShellScript(
      config, BuildRecipeInstallScript(), L"recipe-install",
      {recipe.sourceUrl, targetPath.wstring(), recipe.installerSha256, recipe.requiredSigner, recipe.silentArgs});

  std::wstring status = L"failed";
  std::wstring errorCode;
  for (const auto& line : SplitLines(result.output)) {
    const auto parts = SplitWide(line, L'\t');
    if (!parts.empty() && parts[0] == L"RESULT") {
      status = parts.size() >= 2 ? parts[1] : L"failed";
      errorCode = parts.size() >= 4 ? parts[3] : L"";
      break;
    }
  }

  return PatchExecutionResult{
      .success = result.exitCode == 0 && status == L"completed",
      .action = L"install",
      .provider = L"recipe",
      .status = status,
      .errorCode = errorCode,
      .detailJson = std::wstring(L"{\"output\":\"") + Utf8ToWide(EscapeJsonString(result.output)) + L"\"}"};
}

std::wstring BuildAuthenticodeValidationScript() {
  return LR"PATCH(
param([string]$targetPath, [string]$requiredSigner)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
  Write-Output "RESULT`tmissing`tpath_missing"
  exit 2
}
$sig = Get-AuthenticodeSignature -FilePath $targetPath
if (-not $sig.SignerCertificate) {
  Write-Output ("RESULT`tunsigned`t" + [string]$sig.Status)
  exit 3
}
$subject = [string]$sig.SignerCertificate.Subject
if ($requiredSigner -and $subject -notlike ("*" + $requiredSigner + "*")) {
  Write-Output ("RESULT`tsigner_mismatch`t" + $subject)
  exit 4
}
if ([string]$sig.Status -ne 'Valid') {
  Write-Output ("RESULT`tinvalid_signature`t" + [string]$sig.Status)
  exit 5
}
Write-Output ("RESULT`tok`t" + $subject)
)PATCH";
}

bool VerifyAuthenticodeProvider(const AgentConfig& config, const std::wstring& binaryPath,
                                const std::wstring& requiredSigner, std::wstring* failureReason) {
  const auto result = ExecutePowerShellScript(config, BuildAuthenticodeValidationScript(), L"provider-signature",
                                              {binaryPath, requiredSigner});
  if (result.exitCode == 0) {
    return true;
  }

  if (failureReason != nullptr) {
    std::wstring detail = result.output;
    if (detail.empty()) {
      detail = L"signature validation command failed";
    }
    *failureReason = detail;
  }
  return false;
}

bool IsPathUnderRoot(const std::filesystem::path& candidatePath, const std::filesystem::path& rootPath) {
  if (candidatePath.empty() || rootPath.empty()) {
    return false;
  }

  std::error_code candidateError;
  const auto normalizedCandidate = std::filesystem::weakly_canonical(candidatePath, candidateError);
  if (candidateError) {
    return false;
  }

  std::error_code rootError;
  const auto normalizedRoot = std::filesystem::weakly_canonical(rootPath, rootError);
  if (rootError) {
    return false;
  }

  auto candidateText = ToLowerCopy(normalizedCandidate.wstring());
  auto rootText = ToLowerCopy(normalizedRoot.wstring());
  if (candidateText == rootText) {
    return true;
  }

  if (rootText.empty()) {
    return false;
  }

  if (rootText.back() != L'\\' && rootText.back() != L'/') {
    rootText.push_back(L'\\');
  }
  return candidateText.rfind(rootText, 0) == 0;
}

bool ValidateNativeProviderPath(const std::wstring& providerId, std::wstring* failureReason) {
  if (providerId.empty()) {
    if (failureReason != nullptr) {
      *failureReason = L"Native updater path is empty.";
    }
    return false;
  }

  const std::filesystem::path providerPath(providerId);
  if (!providerPath.is_absolute()) {
    if (failureReason != nullptr) {
      *failureReason = L"Native updater path must be absolute.";
    }
    return false;
  }

  if (ToLowerCopy(providerPath.extension().wstring()) != L".exe") {
    if (failureReason != nullptr) {
      *failureReason = L"Native updater must resolve to a trusted executable.";
    }
    return false;
  }

  std::error_code fileError;
  if (!std::filesystem::exists(providerPath, fileError) || fileError ||
      !std::filesystem::is_regular_file(providerPath, fileError)) {
    if (failureReason != nullptr) {
      *failureReason = L"Native updater executable is missing or inaccessible.";
    }
    return false;
  }

  std::vector<std::filesystem::path> trustedRoots;
  const auto programFiles = ReadEnvironmentVariable(L"ProgramFiles");
  const auto programFilesX86 = ReadEnvironmentVariable(L"ProgramFiles(x86)");
  const auto localAppData = ReadEnvironmentVariable(L"LOCALAPPDATA");
  const auto programData = ReadEnvironmentVariable(L"ProgramData");
  if (!programFiles.empty()) {
    trustedRoots.emplace_back(programFiles);
  }
  if (!programFilesX86.empty()) {
    trustedRoots.emplace_back(programFilesX86);
  }
  if (!localAppData.empty()) {
    trustedRoots.emplace_back(localAppData);
  }
  if (!programData.empty()) {
    trustedRoots.emplace_back(programData);
  }

  const auto trusted = std::any_of(trustedRoots.begin(), trustedRoots.end(),
                                   [&](const std::filesystem::path& root) {
                                     return IsPathUnderRoot(providerPath, root);
                                   });
  if (!trusted) {
    if (failureReason != nullptr) {
      *failureReason = L"Native updater path is outside trusted install directories.";
    }
    return false;
  }

  return true;
}

std::wstring ResolveExpectedNativeSigner(const SoftwarePatchRecord& record, const PackageRecipeRecord* recipe) {
  if (recipe != nullptr && !recipe->requiredSigner.empty()) {
    return recipe->requiredSigner;
  }

  const auto lowerName = ToLowerCopy(record.displayName);
  const auto lowerPublisher = ToLowerCopy(record.publisher);
  if (lowerName.find(L"google") != std::wstring::npos || lowerName.find(L"chrome") != std::wstring::npos ||
      lowerPublisher.find(L"google") != std::wstring::npos) {
    return L"Google";
  }
  if (lowerName.find(L"microsoft") != std::wstring::npos || lowerName.find(L"edge") != std::wstring::npos ||
      lowerPublisher.find(L"microsoft") != std::wstring::npos) {
    return L"Microsoft";
  }

  return {};
}

std::wstring BuildPatchAttemptTrailJson(const std::vector<PatchExecutionResult>& attempts,
                                        const std::optional<std::size_t> winnerIndex,
                                        const std::wstring& providerDetail) {
  std::wstring json = L"{\"fallbackUsed\":";
  json += attempts.size() > 1 ? L"true" : L"false";
  json += L",\"winnerIndex\":";
  json += winnerIndex.has_value() ? std::to_wstring(*winnerIndex) : L"-1";
  json += L",\"providerDetail\":\"";
  json += EscapeWideForJson(providerDetail);
  json += L"\",\"attempts\":[";
  for (std::size_t index = 0; index < attempts.size(); ++index) {
    if (index != 0) {
      json += L",";
    }

    const auto& attempt = attempts[index];
    json += L"{\"provider\":\"";
    json += EscapeWideForJson(attempt.provider);
    json += L"\",\"status\":\"";
    json += EscapeWideForJson(attempt.status);
    json += L"\",\"errorCode\":\"";
    json += EscapeWideForJson(attempt.errorCode);
    json += L"\",\"detailJson\":\"";
    json += EscapeWideForJson(attempt.detailJson);
    json += L"\",\"success\":";
    json += attempt.success ? L"true" : L"false";
    json += L"}";
  }
  json += L"]";
  if (const auto detail = json::Parse(WideToUtf8(providerDetail)); detail) {
    const auto* summary = detail->Get("summary");
    if (summary && summary->String()) json += L",\"summary\":\"" + EscapeWideForJson(Utf8ToWide(*summary->String())) + L"\"";
  }
  json += L"}";
  return json;
}

}  // namespace

std::wstring PatchProviderKindToString(const PatchProviderKind provider) {
  switch (provider) {
    case PatchProviderKind::NativeUpdater:
      return L"native-updater";
    case PatchProviderKind::Winget:
      return L"winget";
    case PatchProviderKind::Recipe:
      return L"recipe";
    default:
      return L"manual";
  }
}

PatchProviderKind PatchProviderKindFromString(const std::wstring& value) {
  const auto lower = ToLowerCopy(value);
  if (lower == L"native-updater") {
    return PatchProviderKind::NativeUpdater;
  }
  if (lower == L"winget") {
    return PatchProviderKind::Winget;
  }
  if (lower == L"recipe") {
    return PatchProviderKind::Recipe;
  }
  return PatchProviderKind::Manual;
}

PatchOrchestrator::PatchOrchestrator(const AgentConfig& config) : config_(config) {}

PatchRefreshSummary PatchOrchestrator::RefreshPatchState() const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  auto policy = LoadOrCreatePolicy(database);
  if (policy.updatedAt.empty()) {
    policy.updatedAt = CurrentUtcTimestamp();
    database.SavePatchPolicy(policy);
  }

  const auto recipes = BuildDefaultRecipes();
  database.ReplacePackageRecipes(recipes);

  std::vector<PatchHistoryRecord> historyFromDiscovery;
  RebootCoordinatorRecord rebootState{
      .gracePeriodMinutes = policy.rebootGracePeriodMinutes,
      .status = L"current"};
  const auto windowsUpdates = DiscoverWindowsUpdates(config_, &rebootState, &historyFromDiscovery);
  database.ReplaceWindowsUpdateRecords(windowsUpdates);
  database.SaveRebootCoordinator(rebootState);
  for (const auto& historyRecord : historyFromDiscovery) {
    database.UpsertPatchHistoryRecord(historyRecord);
  }

  const auto deviceInventory = CollectDeviceInventorySnapshot();
  const auto software = BuildSoftwarePatchInventory(deviceInventory, policy, recipes);
  database.ReplaceSoftwarePatchRecords(software);

  return PatchRefreshSummary{
      .windowsUpdateCount = windowsUpdates.size(),
      .softwareCount = software.size(),
      .recipeCount = recipes.size(),
      .rebootPending = rebootState.rebootRequired};
}

PatchSnapshot PatchOrchestrator::LoadSnapshot(const std::size_t windowsLimit, const std::size_t softwareLimit,
                                              const std::size_t historyLimit, const std::size_t recipeLimit) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  PatchSnapshot snapshot{};
  snapshot.policy = LoadPolicy();
  database.LoadRebootCoordinator(snapshot.rebootState);
  snapshot.windowsUpdates = database.ListWindowsUpdateRecords(windowsLimit);
  snapshot.software = database.ListSoftwarePatchRecords(softwareLimit);
  snapshot.history = database.ListPatchHistoryRecords(historyLimit);
  snapshot.recipes = database.ListPackageRecipes(recipeLimit);
  return snapshot;
}

PatchExecutionResult PatchOrchestrator::InstallWindowsUpdates(const bool securityOnly) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  const auto policy = LoadPolicy();

  if (policy.batteryAware && config_.deferHeavyActionsOnBattery && IsRunningOnBatteryPower()) {
    return PatchExecutionResult{
        .success = false,
        .action = L"install",
        .targetId = securityOnly ? L"security-only" : L"policy-selected",
        .provider = L"windows-update-agent",
        .status = L"deferred_battery",
        .errorCode = L"BATTERY_DEFERRED",
        .detailJson = L"{\"message\":\"Windows patch installation was deferred because the device is running on battery power.\"}"};
  }

  if (policy.respectMeteredConnections && TreatConnectionAsMetered()) {
    return PatchExecutionResult{
        .success = false,
        .action = L"install",
        .targetId = securityOnly ? L"security-only" : L"policy-selected",
        .provider = L"windows-update-agent",
        .status = L"deferred_metered",
        .errorCode = L"METERED_DEFERRED",
        .detailJson = L"{\"message\":\"Windows patch installation was deferred because the current connection is treated as metered.\"}"};
  }

  PatchHistoryRecord history{
      .recordId = GenerateGuidString(),
      .targetType = L"windows-update",
      .targetId = securityOnly ? L"security-only" : L"policy-selected",
      .title = securityOnly ? L"Windows security patch cycle" : L"Windows patch cycle",
      .provider = L"windows-update-agent",
      .action = L"install",
      .status = L"started",
      .startedAt = CurrentUtcTimestamp()};
  database.UpsertPatchHistoryRecord(history);

  const auto result = ExecutePowerShellScript(
      config_, BuildWindowsUpdateInstallScript(), L"wu-install",
      {securityOnly ? L"1" : L"0", policy.includeDriverUpdates ? L"1" : L"0", policy.includeOptionalUpdates ? L"1" : L"0",
       policy.deferFeatureUpdates ? L"1" : L"0"});

  PatchExecutionResult execution{
      .action = L"install",
      .targetId = history.targetId,
      .provider = L"windows-update-agent",
      .status = result.exitCode == 0 ? L"completed" : L"failed",
      .detailJson = std::wstring(L"{\"output\":\"") + Utf8ToWide(EscapeJsonString(result.output)) + L"\"}"};

  for (const auto& line : SplitLines(result.output)) {
    const auto parts = SplitWide(line, L'\t');
    if (!parts.empty() && parts[0] == L"RESULT") {
      execution.status = parts.size() >= 2 ? parts[1] : execution.status;
      execution.rebootRequired = parts.size() >= 3 && parts[2] == L"1";
      execution.errorCode = parts.size() >= 4 ? parts[3] : L"";
      break;
    }
  }

  execution.success = result.exitCode == 0 && execution.status != L"failed";
  history.status = execution.status;
  history.completedAt = CurrentUtcTimestamp();
  history.errorCode = execution.errorCode;
  history.detailJson = execution.detailJson;
  history.rebootRequired = execution.rebootRequired;
  database.UpsertPatchHistoryRecord(history);

  if (execution.rebootRequired) {
    auto rebootState = RebootCoordinatorRecord{
        .rebootRequired = true,
        .pendingWindowsUpdate = true,
        .rebootReasons = L"windows_update",
        .detectedAt = CurrentUtcTimestamp(),
        .gracePeriodMinutes = policy.rebootGracePeriodMinutes,
        .status = L"pending"};
    database.SaveRebootCoordinator(rebootState);
  }

  RefreshPatchState();
  return execution;
}

PatchExecutionResult PatchOrchestrator::UpdateSoftware(const std::wstring& softwareId, const bool searchOnly) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  const auto policy = LoadPolicy();
  if (!searchOnly && policy.batteryAware && config_.deferHeavyActionsOnBattery && IsRunningOnBatteryPower()) {
    return PatchExecutionResult{
        .success = false,
        .action = L"install",
        .targetId = softwareId,
        .provider = L"policy",
        .status = L"deferred_battery",
        .errorCode = L"BATTERY_DEFERRED",
        .detailJson = L"{\"message\":\"Software patching was deferred because the device is running on battery power.\"}"};
  }
  if (!searchOnly && policy.respectMeteredConnections && TreatConnectionAsMetered()) {
    return PatchExecutionResult{
        .success = false,
        .action = L"install",
        .targetId = softwareId,
        .provider = L"policy",
        .status = L"deferred_metered",
        .errorCode = L"METERED_DEFERRED",
        .detailJson = L"{\"message\":\"Software patching was deferred because the current connection is treated as metered.\"}"};
  }

  const auto software = database.ListSoftwarePatchRecords(1000);
  const auto match = std::find_if(software.begin(), software.end(),
                                  [&](const auto& candidate) { return candidate.softwareId == softwareId; });
  if (match == software.end()) {
    throw std::runtime_error("Requested software patch target was not found");
  }

  const auto recipes = database.ListPackageRecipes(500);
  const auto matchedRecipe = FindRecipeForSoftwareRecord(*match, recipes);
  const auto candidates = BuildSoftwareUpdateCandidates(*match, policy, matchedRecipe);

  PatchHistoryRecord history{
      .recordId = GenerateGuidString(),
      .targetType = L"software",
      .targetId = match->softwareId,
      .title = match->displayName,
      .provider = match->provider,
      .action = searchOnly ? L"search" : L"install",
      .status = L"started",
      .startedAt = CurrentUtcTimestamp()};
  database.UpsertPatchHistoryRecord(history);

  std::vector<PatchExecutionResult> attempts;
  attempts.reserve(std::max<std::size_t>(1, candidates.size()));
  std::optional<std::size_t> winnerIndex;
  PatchExecutionResult execution{};

  for (const auto& candidate : candidates) {
    PatchExecutionResult attempt{};
    switch (candidate.provider) {
      case PatchProviderKind::NativeUpdater: {
        if (!policy.allowNativeUpdaters) {
          attempt = PatchExecutionResult{
              .success = false,
              .action = searchOnly ? L"search" : L"install",
              .provider = L"native-updater",
              .status = L"policy_blocked",
              .errorCode = L"NATIVE_UPDATER_DISABLED",
              .detailJson = L"{\"message\":\"Patch policy disabled native updaters.\"}"};
          break;
        }

        std::wstring pathError;
        if (!ValidateNativeProviderPath(candidate.providerId, &pathError)) {
          attempt = PatchExecutionResult{
              .success = false,
              .action = searchOnly ? L"search" : L"install",
              .provider = L"native-updater",
              .status = L"provider_untrusted",
              .errorCode = L"NATIVE_PROVIDER_PATH_UNTRUSTED",
              .detailJson = std::wstring(L"{\"message\":\"") + EscapeWideForJson(pathError) + L"\"}"};
          break;
        }

        const auto expectedSigner = ResolveExpectedNativeSigner(*match, candidate.recipe);
        if (expectedSigner.empty()) {
          attempt = PatchExecutionResult{
              .success = false,
              .action = searchOnly ? L"search" : L"install",
              .provider = L"native-updater",
              .status = L"provider_untrusted",
              .errorCode = L"NATIVE_PROVIDER_SIGNER_UNKNOWN",
              .detailJson =
                  L"{\"message\":\"Fenrir could not determine an expected signer for this native updater.\"}"};
          break;
        }

        std::wstring signatureError;
        if (!VerifyAuthenticodeProvider(config_, candidate.providerId, expectedSigner, &signatureError)) {
          attempt = PatchExecutionResult{
              .success = false,
              .action = searchOnly ? L"search" : L"install",
              .provider = L"native-updater",
              .status = L"provider_untrusted",
              .errorCode = L"NATIVE_PROVIDER_SIGNATURE_INVALID",
              .detailJson = std::wstring(L"{\"message\":\"") + EscapeWideForJson(signatureError) + L"\"}"};
          break;
        }

        attempt = searchOnly ? PatchExecutionResult{.success = true,
                                                    .action = L"search",
                                                    .provider = L"native-updater",
                                                    .status = L"provider_ready",
                                                    .detailJson = L"{\"message\":\"Native updater path and signer are trusted.\"}"}
                             : ExecuteNativeOperation(candidate.providerId);
        break;
      }
      case PatchProviderKind::Winget:
        if (!policy.allowWinget) {
          attempt = PatchExecutionResult{
              .success = false,
              .action = searchOnly ? L"search" : L"install",
              .provider = L"winget",
              .status = L"policy_blocked",
              .errorCode = L"WINGET_DISABLED",
              .detailJson = L"{\"message\":\"Patch policy disabled winget.\"}"};
          break;
        }

        if (candidate.providerId.empty()) {
          attempt = PatchExecutionResult{
              .success = false,
              .action = searchOnly ? L"search" : L"install",
              .provider = L"winget",
              .status = L"unsupported",
              .errorCode = L"WINGET_ID_MISSING",
              .detailJson = L"{\"message\":\"Winget provider id is missing.\"}"};
          break;
        }

        attempt = ExecuteWingetOperation(candidate.providerId, searchOnly);
        break;
      case PatchProviderKind::Recipe:
        if (!policy.allowRecipes) {
          attempt = PatchExecutionResult{
              .success = false,
              .action = searchOnly ? L"search" : L"install",
              .provider = L"recipe",
              .status = L"policy_blocked",
              .errorCode = L"RECIPE_DISABLED",
              .detailJson = L"{\"message\":\"Patch policy disabled package recipes.\"}"};
          break;
        }

        if (candidate.recipe == nullptr) {
          attempt = PatchExecutionResult{
              .success = false,
              .action = searchOnly ? L"search" : L"install",
              .provider = L"recipe",
              .status = L"missing_recipe",
              .errorCode = L"RECIPE_NOT_FOUND",
              .detailJson = L"{\"message\":\"Recipe metadata is unavailable for this software.\"}"};
          break;
        }

        {
          std::wstring trustReason;
          if (!RecipeDefinitionTrusted(*candidate.recipe, &trustReason)) {
            attempt = PatchExecutionResult{
                .success = false,
                .action = searchOnly ? L"search" : L"install",
                .provider = L"recipe",
                .status = L"provider_untrusted",
                .errorCode = L"RECIPE_TRUST_MISSING",
                .detailJson = std::wstring(L"{\"message\":\"") + EscapeWideForJson(trustReason) + L"\"}"};
            break;
          }
        }

        attempt = searchOnly
                      ? PatchExecutionResult{.success = !candidate.recipe->manualOnly,
                                             .action = L"search",
                                             .provider = L"recipe",
                                             .status = candidate.recipe->manualOnly ? L"manual" : L"provider_ready",
                                             .detailJson = L"{\"message\":\"Recipe provider metadata is trusted.\"}"}
                      : ExecuteRecipeOperation(config_, *candidate.recipe);
        break;
      default:
        attempt = PatchExecutionResult{
            .success = false,
            .action = searchOnly ? L"search" : L"install",
            .provider = L"manual",
            .status = L"manual",
            .errorCode = L"MANUAL_ONLY",
            .detailJson = L"{\"message\":\"This software currently requires a manual update workflow.\"}"};
        break;
    }

    attempt.targetId = match->softwareId;
    attempts.push_back(attempt);
    if (attempt.success) {
      winnerIndex = attempts.size() - 1;
      execution = attempt;
      break;
    }
  }

  if (!winnerIndex.has_value()) {
    if (!attempts.empty()) {
      execution = attempts.back();
      if (execution.errorCode.empty() && attempts.size() > 1) {
        execution.errorCode = L"ALL_PROVIDERS_FAILED";
      }
    } else {
      execution = PatchExecutionResult{
          .success = false,
          .action = searchOnly ? L"search" : L"install",
          .targetId = match->softwareId,
          .provider = L"manual",
          .status = L"manual",
          .errorCode = L"MANUAL_ONLY",
          .detailJson = L"{\"message\":\"This software currently requires a manual update workflow.\"}"};
      attempts.push_back(execution);
    }
  }

  execution.targetId = match->softwareId;
  execution.detailJson = BuildPatchAttemptTrailJson(attempts, winnerIndex, execution.detailJson);
  history.provider = execution.provider.empty() ? match->provider : execution.provider;
  history.status = execution.status;
  history.completedAt = CurrentUtcTimestamp();
  history.errorCode = execution.errorCode;
  history.detailJson = execution.detailJson;
  history.rebootRequired = execution.rebootRequired;
  database.UpsertPatchHistoryRecord(history);

  RefreshPatchState();
  return execution;
}

PatchExecutionResult PatchOrchestrator::RunPatchCycle() const {
  RefreshPatchState();
  RuntimeDatabase database(config_.runtimeDatabasePath);
  const auto policy = LoadPolicy();
  if (policy.paused) {
    return PatchExecutionResult{
        .success = false,
        .action = L"cycle",
        .provider = L"policy",
        .status = L"paused",
        .errorCode = L"PATCH_POLICY_PAUSED"};
  }

  if (policy.batteryAware && config_.deferHeavyActionsOnBattery && IsRunningOnBatteryPower()) {
    return PatchExecutionResult{
        .success = false,
        .action = L"cycle",
        .provider = L"policy",
        .status = L"deferred_battery",
        .errorCode = L"BATTERY_DEFERRED",
        .detailJson = L"{\"message\":\"Fenrir deferred the patch cycle because the device is running on battery power.\"}"};
  }

  if (policy.respectMeteredConnections && TreatConnectionAsMetered()) {
    return PatchExecutionResult{
        .success = false,
        .action = L"cycle",
        .provider = L"policy",
        .status = L"deferred_metered",
        .errorCode = L"METERED_DEFERRED",
        .detailJson = L"{\"message\":\"Fenrir deferred the patch cycle because the current connection is treated as metered.\"}"};
  }

  const auto windowsResult = InstallWindowsUpdates(true);
  const auto software = database.ListSoftwarePatchRecords(500);
  struct ScheduledSoftwareUpdate {
    std::wstring softwareId;
    int priorityScore{0};
  };

  std::vector<ScheduledSoftwareUpdate> scheduledUpdates;
  scheduledUpdates.reserve(software.size());

  for (const auto& record : software) {
    if (!record.supported || record.manualOnly || record.blocked) {
      continue;
    }
    if (policy.autoUpdateHighRiskAppsOnly && !record.highRisk && !policy.autoUpdateAllSupportedApps) {
      continue;
    }
    if (record.updateState != L"available" && !policy.autoUpdateAllSupportedApps) {
      continue;
    }

    auto priorityScore = ComputeSoftwarePatchDebtSignals(record).urgencyScore;
    if (!record.failureCode.empty()) {
      priorityScore = std::max(priorityScore - 8, 0);
    }

    scheduledUpdates.push_back(ScheduledSoftwareUpdate{
        .softwareId = record.softwareId,
        .priorityScore = priorityScore});
  }

  std::sort(scheduledUpdates.begin(), scheduledUpdates.end(), [](const ScheduledSoftwareUpdate& left,
                                                                 const ScheduledSoftwareUpdate& right) {
    if (left.priorityScore == right.priorityScore) {
      return left.softwareId < right.softwareId;
    }
    return left.priorityScore > right.priorityScore;
  });

  std::size_t appliedCount = 0;
  for (const auto& scheduled : scheduledUpdates) {
    if (appliedCount >= kMaxSoftwareUpdatesPerCycle) {
      break;
    }
    UpdateSoftware(scheduled.softwareId, false);
    ++appliedCount;
  }

  RefreshPatchState();
  return PatchExecutionResult{
      .success = windowsResult.success,
      .rebootRequired = windowsResult.rebootRequired,
      .action = L"cycle",
      .provider = L"fenrir",
      .status = L"completed",
      .detailJson = std::wstring(L"{\"scheduledSoftware\":") + std::to_wstring(scheduledUpdates.size()) +
                    L",\"appliedSoftware\":" + std::to_wstring(appliedCount) + L",\"maxSoftwarePerCycle\":" +
                    std::to_wstring(kMaxSoftwareUpdatesPerCycle) + L"}"};
}

void PatchOrchestrator::SavePolicy(const PatchPolicyRecord& policy) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  auto persisted = policy;
  persisted.updatedAt = CurrentUtcTimestamp();
  database.SavePatchPolicy(persisted);
}

PatchPolicyRecord PatchOrchestrator::LoadPolicy() const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  return LoadOrCreatePolicy(database);
}

}  // namespace antivirus::agent
