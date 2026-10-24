#include "UpdaterService.h"

#include <windows.h>

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <unordered_set>

#include "CryptoUtils.h"
#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring TrimWide(std::wstring value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }

  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::vector<std::wstring> SplitWide(const std::wstring& value, const wchar_t separator) {
  std::vector<std::wstring> parts;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == separator) {
      parts.push_back(TrimWide(current));
      current.clear();
      continue;
    }

    current.push_back(ch);
  }

  parts.push_back(TrimWide(current));
  return parts;
}

bool ParseBoolText(const std::wstring& value) {
  const auto lower = ToLowerCopy(TrimWide(value));
  return lower == L"1" || lower == L"true" || lower == L"yes";
}

constexpr std::size_t kMaxManifestLineChars = 4096;
constexpr std::size_t kMaxManifestFiles = 512;
constexpr std::size_t kMaxManifestLines = 2048;
constexpr std::uintmax_t kMaxManifestBytes = 256ull * 1024ull;

bool IsPathWithinRoot(const std::filesystem::path& candidate, const std::filesystem::path& root);

void EnsureManifestFieldLength(const std::wstring& value, const std::size_t maxChars, const char* fieldName) {
  if (value.size() <= maxChars) {
    return;
  }

  throw std::runtime_error(std::string("Update manifest field exceeded allowed length: ") + fieldName);
}

std::optional<std::int32_t> ParseManifestInt(const std::wstring& value) {
  if (value.empty()) {
    return std::nullopt;
  }

  try {
    const auto parsed = std::stoll(value);
    if (parsed < static_cast<long long>(std::numeric_limits<std::int32_t>::min()) ||
        parsed > static_cast<long long>(std::numeric_limits<std::int32_t>::max())) {
      return std::nullopt;
    }
    return static_cast<std::int32_t>(parsed);
  } catch (...) {
    return std::nullopt;
  }
}

bool ContainsForbiddenControlCharacters(const std::wstring& value) {
  return std::any_of(value.begin(), value.end(), [](const wchar_t ch) {
    return ch < 0x20 && ch != L'\t';
  });
}

void EnsureSourcePathWithinManifestRoot(const std::filesystem::path& sourcePath,
                                        const std::filesystem::path& manifestDirectory) {
  if (!IsPathWithinRoot(sourcePath, manifestDirectory)) {
    throw std::runtime_error("Update source path escaped the trusted manifest package root");
  }
}

bool IsSha256HexString(const std::wstring& value) {
  if (value.size() != 64) {
    return false;
  }

  return std::all_of(value.begin(), value.end(), [](const wchar_t ch) { return iswxdigit(ch) != 0; });
}

std::wstring DefaultTrustDomainForPackageType(const std::wstring& packageType) {
  const auto lowerType = ToLowerCopy(packageType);
  if (lowerType == L"rules" || lowerType == L"signatures") {
    return L"content";
  }

  return L"platform";
}

std::vector<std::wstring> SplitVersionTokens(const std::wstring& value) {
  std::vector<std::wstring> tokens;
  std::wstring current;
  for (const auto ch : value) {
    if ((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z')) {
      current.push_back(static_cast<wchar_t>(std::towlower(ch)));
      continue;
    }

    if (!current.empty()) {
      tokens.push_back(current);
      current.clear();
    }
  }

  if (!current.empty()) {
    tokens.push_back(current);
  }
  return tokens;
}

int CompareVersionStrings(const std::wstring& left, const std::wstring& right) {
  const auto leftTokens = SplitVersionTokens(left);
  const auto rightTokens = SplitVersionTokens(right);
  const auto limit = std::max(leftTokens.size(), rightTokens.size());

  for (std::size_t index = 0; index < limit; ++index) {
    const auto leftToken = index < leftTokens.size() ? leftTokens[index] : std::wstring(L"0");
    const auto rightToken = index < rightTokens.size() ? rightTokens[index] : std::wstring(L"0");

    const auto leftNumeric = std::all_of(leftToken.begin(), leftToken.end(), [](const wchar_t ch) { return iswdigit(ch) != 0; });
    const auto rightNumeric =
        std::all_of(rightToken.begin(), rightToken.end(), [](const wchar_t ch) { return iswdigit(ch) != 0; });
    if (leftNumeric && rightNumeric) {
      const auto leftValue = std::stoll(leftToken);
      const auto rightValue = std::stoll(rightToken);
      if (leftValue < rightValue) {
        return -1;
      }
      if (leftValue > rightValue) {
        return 1;
      }
      continue;
    }

    if (leftToken < rightToken) {
      return -1;
    }
    if (leftToken > rightToken) {
      return 1;
    }
  }

  return 0;
}

std::vector<std::wstring> LoadKeyList(const std::filesystem::path& path) {
  std::vector<std::wstring> values;
  std::wifstream input(path);
  if (!input.is_open()) {
    return values;
  }

  std::wstring line;
  while (std::getline(input, line)) {
    const auto trimmed = TrimWide(line);
    if (!trimmed.empty() && !trimmed.starts_with(L"#") && !trimmed.starts_with(L";")) {
      values.push_back(trimmed);
    }
  }
  return values;
}

std::vector<std::wstring> TrustedKeyIdsForPackageType(const AgentConfig& config, const std::wstring& packageType,
                                                      const std::wstring& trustDomain) {
  const auto lowerType = ToLowerCopy(packageType);
  const auto lowerDomain = ToLowerCopy(trustDomain);
  const auto trustRoot = config.updateRootPath / L"trust";

  if (!lowerDomain.empty()) {
    const auto domainTrusted = LoadKeyList(trustRoot / (lowerDomain + L"-trusted-key-ids.txt"));
    if (!domainTrusted.empty()) {
      return domainTrusted;
    }
  }

  auto trusted = LoadKeyList((lowerType == L"rules" || lowerType == L"signatures")
                                 ? (trustRoot / L"content-trusted-key-ids.txt")
                                 : (trustRoot / L"platform-trusted-key-ids.txt"));
  if (!trusted.empty()) {
    return trusted;
  }

  if (lowerType == L"rules" || lowerType == L"signatures") {
    return {L"fenrir-content-prod-2026"};
  }
  return {L"fenrir-platform-prod-2026"};
}

bool SigningKeyRevoked(const AgentConfig& config, const std::wstring& signingKeyId) {
  const auto revoked = LoadKeyList(config.updateRootPath / L"trust" / L"revoked-key-ids.txt");
  return std::find(revoked.begin(), revoked.end(), signingKeyId) != revoked.end();
}

std::optional<std::wstring> LatestKnownPackageVersion(const RuntimeDatabase& database, const std::wstring& packageId) {
  const auto journal = database.ListUpdateJournal(100);
  std::optional<std::wstring> latest;
  for (const auto& record : journal) {
    if (record.packageId != packageId || record.targetVersion.empty()) {
      continue;
    }
    if (!latest.has_value() || CompareVersionStrings(record.targetVersion, *latest) > 0) {
      latest = record.targetVersion;
    }
  }
  return latest;
}

std::wstring NormalizePathForCompare(const std::filesystem::path& path) {
  auto normalized = std::filesystem::absolute(path).lexically_normal().wstring();
  normalized = ToLowerCopy(normalized);
  if (!normalized.empty() && normalized.back() != L'\\' && normalized.back() != L'/') {
    normalized.push_back(L'\\');
  }
  return normalized;
}

bool IsPathWithinRoot(const std::filesystem::path& candidate, const std::filesystem::path& root) {
  const auto normalizedCandidate = NormalizePathForCompare(candidate);
  const auto normalizedRoot = NormalizePathForCompare(root);
  return normalizedCandidate.starts_with(normalizedRoot);
}

std::filesystem::path ResolveTargetPath(const std::filesystem::path& targetPath, const std::filesystem::path& installRoot) {
  const auto resolved = targetPath.is_absolute() ? targetPath : (installRoot / targetPath);
  const auto normalized = std::filesystem::absolute(resolved).lexically_normal();
  if (!IsPathWithinRoot(normalized, installRoot)) {
    throw std::runtime_error("Update target path escaped the install root");
  }
  return normalized;
}

UpdateManifest LoadManifestFile(const std::filesystem::path& manifestPath, const std::filesystem::path& installRoot) {
  std::error_code manifestError;
  if (!std::filesystem::exists(manifestPath, manifestError) || manifestError ||
      !std::filesystem::is_regular_file(manifestPath, manifestError)) {
    throw std::runtime_error("Update manifest path is missing or not a regular file");
  }

  manifestError.clear();
  const auto manifestSize = std::filesystem::file_size(manifestPath, manifestError);
  if (manifestError || manifestSize == 0 || manifestSize > kMaxManifestBytes) {
    throw std::runtime_error("Update manifest file size exceeded the allowed safety budget");
  }

  std::wifstream input(manifestPath);
  if (!input.is_open()) {
    throw std::runtime_error("Could not open the update manifest");
  }

  UpdateManifest manifest;
  manifest.manifestPath = std::filesystem::absolute(manifestPath);
  const auto manifestDirectory = manifest.manifestPath.parent_path();
  std::unordered_set<std::wstring> singletonKeysSeen;
  std::size_t manifestLineCount = 0;
  std::wstring line;
  while (std::getline(input, line)) {
    ++manifestLineCount;
    if (manifestLineCount > kMaxManifestLines) {
      throw std::runtime_error("Update manifest exceeded the allowed line-count safety budget");
    }

    if (line.size() > kMaxManifestLineChars) {
      throw std::runtime_error("Update manifest line exceeded the safety size limit");
    }

    const auto trimmed = TrimWide(line);
    if (trimmed.empty() || trimmed.starts_with(L"#") || trimmed.starts_with(L";")) {
      continue;
    }

    const auto separator = trimmed.find(L'=');
    if (separator == std::wstring::npos) {
      continue;
    }

    const auto key = ToLowerCopy(TrimWide(trimmed.substr(0, separator)));
    const auto value = TrimWide(trimmed.substr(separator + 1));
    if (key.empty()) {
      throw std::runtime_error("Update manifest contains an empty key");
    }

    if (ContainsForbiddenControlCharacters(value)) {
      throw std::runtime_error("Update manifest contains unsupported control characters");
    }

    if (key != L"file") {
      if (singletonKeysSeen.find(key) != singletonKeysSeen.end()) {
        throw std::runtime_error("Update manifest repeated a singleton field");
      }
      singletonKeysSeen.insert(key);
    }

    if (key == L"package_id") {
      EnsureManifestFieldLength(value, 128, "package_id");
      manifest.packageId = value;
      continue;
    }

    if (key == L"package_type") {
      EnsureManifestFieldLength(value, 64, "package_type");
      manifest.packageType = value;
      continue;
    }

    if (key == L"target_version") {
      EnsureManifestFieldLength(value, 64, "target_version");
      manifest.targetVersion = value;
      continue;
    }

    if (key == L"channel") {
      EnsureManifestFieldLength(value, 32, "channel");
      manifest.channel = value;
      continue;
    }

    if (key == L"trust_domain") {
      EnsureManifestFieldLength(value, 32, "trust_domain");
      manifest.trustDomain = value;
      continue;
    }

    if (key == L"promotion_track") {
      EnsureManifestFieldLength(value, 64, "promotion_track");
      manifest.promotionTrack = value;
      continue;
    }

    if (key == L"promotion_gate") {
      EnsureManifestFieldLength(value, 32, "promotion_gate");
      manifest.promotionGate = value;
      continue;
    }

    if (key == L"approval_ticket") {
      EnsureManifestFieldLength(value, 128, "approval_ticket");
      manifest.approvalTicket = value;
      continue;
    }

    if (key == L"package_signer") {
      EnsureManifestFieldLength(value, 256, "package_signer");
      manifest.packageSigner = value;
      continue;
    }

    if (key == L"signing_key_id") {
      EnsureManifestFieldLength(value, 128, "signing_key_id");
      manifest.signingKeyId = value;
      continue;
    }

    if (key == L"crash_budget_ppm") {
      const auto parsed = ParseManifestInt(value);
      if (!parsed.has_value() || *parsed < 0 || *parsed > 1'000'000) {
        throw std::runtime_error("Update manifest crash_budget_ppm is invalid");
      }
      manifest.crashBudgetPpm = *parsed;
      continue;
    }

    if (key == L"false_positive_budget_ppm") {
      const auto parsed = ParseManifestInt(value);
      if (!parsed.has_value() || *parsed < 0 || *parsed > 1'000'000) {
        throw std::runtime_error("Update manifest false_positive_budget_ppm is invalid");
      }
      manifest.falsePositiveBudgetPpm = *parsed;
      continue;
    }

    if (key == L"rollback_budget_ppm") {
      const auto parsed = ParseManifestInt(value);
      if (!parsed.has_value() || *parsed < 0 || *parsed > 1'000'000) {
        throw std::runtime_error("Update manifest rollback_budget_ppm is invalid");
      }
      manifest.rollbackBudgetPpm = *parsed;
      continue;
    }

    if (key == L"self_test_pass_percent") {
      const auto parsed = ParseManifestInt(value);
      if (!parsed.has_value() || *parsed < 0 || *parsed > 100) {
        throw std::runtime_error("Update manifest self_test_pass_percent is invalid");
      }
      manifest.selfTestPassPercent = *parsed;
      continue;
    }

    if (key == L"patch_test_pass_percent") {
      const auto parsed = ParseManifestInt(value);
      if (!parsed.has_value() || *parsed < 0 || *parsed > 100) {
        throw std::runtime_error("Update manifest patch_test_pass_percent is invalid");
      }
      manifest.patchTestPassPercent = *parsed;
      continue;
    }

    if (key == L"ransomware_test_pass_percent") {
      const auto parsed = ParseManifestInt(value);
      if (!parsed.has_value() || *parsed < 0 || *parsed > 100) {
        throw std::runtime_error("Update manifest ransomware_test_pass_percent is invalid");
      }
      manifest.ransomwareTestPassPercent = *parsed;
      continue;
    }

    if (key == L"upgrade_rollback_pass_percent") {
      const auto parsed = ParseManifestInt(value);
      if (!parsed.has_value() || *parsed < 0 || *parsed > 100) {
        throw std::runtime_error("Update manifest upgrade_rollback_pass_percent is invalid");
      }
      manifest.upgradeRollbackPassPercent = *parsed;
      continue;
    }

    if (key == L"hotfix_required") {
      manifest.hotfixRequired = ParseBoolText(value);
      continue;
    }

    if (key == L"allow_downgrade") {
      manifest.allowDowngrade = ParseBoolText(value);
      continue;
    }

    if (key == L"break_glass") {
      manifest.breakGlass = ParseBoolText(value);
      continue;
    }

    if (key == L"file") {
      const auto parts = SplitWide(value, L'|');
      if (parts.size() < 3 || parts.size() > 5) {
        throw std::runtime_error("Update manifest file entries require source|target|sha256");
      }

      if (manifest.files.size() >= kMaxManifestFiles) {
        throw std::runtime_error("Update manifest defined too many file entries");
      }

      UpdateFilePlan filePlan;
      EnsureManifestFieldLength(parts[0], 1024, "file.source");
      EnsureManifestFieldLength(parts[1], 1024, "file.target");
      EnsureManifestFieldLength(parts[2], 128, "file.sha256");

      const std::filesystem::path sourceRelative(parts[0]);
      if (sourceRelative.is_absolute()) {
        throw std::runtime_error("Update manifest file source path must be relative to the manifest package root");
      }

      filePlan.sourcePath = std::filesystem::absolute(manifestDirectory / sourceRelative).lexically_normal();
      EnsureSourcePathWithinManifestRoot(filePlan.sourcePath, manifestDirectory);
      filePlan.targetPath = ResolveTargetPath(parts[1], installRoot);
      filePlan.sha256 = ToLowerCopy(parts[2]);
      filePlan.requiredSigner = parts.size() >= 4 ? parts[3] : manifest.packageSigner;
      filePlan.requireSignature =
          (parts.size() >= 5 && (ToLowerCopy(parts[4]) == L"1" || ToLowerCopy(parts[4]) == L"true")) ||
          !filePlan.requiredSigner.empty();
      manifest.files.push_back(std::move(filePlan));
    }
  }

  if (manifest.packageId.empty()) {
    manifest.packageId = manifest.manifestPath.stem().wstring();
  }
  if (manifest.packageType.empty()) {
    manifest.packageType = L"platform";
  }
  if (manifest.trustDomain.empty()) {
    manifest.trustDomain = DefaultTrustDomainForPackageType(manifest.packageType);
  }
  if (manifest.promotionTrack.empty()) {
    manifest.promotionTrack = manifest.channel;
  }
  if (manifest.promotionGate.empty()) {
    manifest.promotionGate = L"unspecified";
  }
  if (manifest.targetVersion.empty()) {
    manifest.targetVersion = L"unknown";
  }
  if (manifest.files.empty()) {
    throw std::runtime_error("Update manifest does not define any files");
  }

  return manifest;
}

void VerifyManifestPolicy(const UpdateManifest& manifest, const AgentConfig& config, const RuntimeDatabase& database) {
  static const std::vector<std::wstring> allowedPackageTypes = {L"platform", L"driver", L"rules", L"signatures"};
  static const std::vector<std::wstring> allowedChannels = {L"stable", L"beta", L"alpha", L"dev", L"lab"};

  const auto lowerType = ToLowerCopy(manifest.packageType);
  const auto lowerChannel = ToLowerCopy(manifest.channel);
  const auto lowerTrustDomain = ToLowerCopy(manifest.trustDomain);
  const auto lowerPromotionGate = ToLowerCopy(manifest.promotionGate);
  if (std::find(allowedPackageTypes.begin(), allowedPackageTypes.end(), lowerType) == allowedPackageTypes.end()) {
    throw std::runtime_error("Update manifest package type is not allowed");
  }
  if (manifest.channel.empty() ||
      std::find(allowedChannels.begin(), allowedChannels.end(), lowerChannel) == allowedChannels.end()) {
    throw std::runtime_error("Update manifest channel is not allowed");
  }
  if (manifest.packageSigner.empty()) {
    throw std::runtime_error("Update manifest must declare a package signer");
  }
  if (manifest.signingKeyId.empty()) {
    throw std::runtime_error("Update manifest must declare a signing key id");
  }
  if (lowerTrustDomain.empty()) {
    throw std::runtime_error("Update manifest must declare a trust domain");
  }

  const auto expectedTrustDomain = DefaultTrustDomainForPackageType(manifest.packageType);
  if (lowerTrustDomain != expectedTrustDomain) {
    throw std::runtime_error("Update manifest trust domain does not match the package type trust boundary");
  }

  if (lowerPromotionGate == L"blocked" || lowerPromotionGate == L"rejected") {
    throw std::runtime_error("Update manifest promotion gate explicitly blocks release application");
  }

  if (manifest.breakGlass && lowerChannel == L"stable") {
    throw std::runtime_error("Break-glass update manifests are not allowed on the stable channel");
  }

  if (config.enforceReleasePromotionGates) {
    if ((lowerChannel == L"stable" || lowerChannel == L"beta") && lowerPromotionGate != L"approved") {
      throw std::runtime_error("Update manifest promotion gate is not approved for this release channel");
    }
    if ((lowerChannel == L"stable" || lowerChannel == L"beta") && manifest.approvalTicket.empty()) {
      throw std::runtime_error("Update manifest is missing an approval ticket for promoted release channels");
    }
    if (manifest.promotionTrack.empty()) {
      throw std::runtime_error("Update manifest is missing a promotion track");
    }

    const auto promotedChannel = lowerChannel == L"stable" || lowerChannel == L"beta";
    if (promotedChannel) {
      const auto minPassRate = lowerChannel == L"stable" ? 99 : 95;
      const auto maxCrashBudget = lowerChannel == L"stable" ? 25 : 100;
      const auto maxFalsePositiveBudget = lowerChannel == L"stable" ? 10 : 50;
      const auto maxRollbackBudget = lowerChannel == L"stable" ? 50 : 200;

      if (manifest.selfTestPassPercent < minPassRate || manifest.patchTestPassPercent < minPassRate ||
          manifest.ransomwareTestPassPercent < minPassRate || manifest.upgradeRollbackPassPercent < minPassRate) {
        throw std::runtime_error("Update manifest test pass rates do not meet promotion thresholds");
      }

      if (manifest.crashBudgetPpm > maxCrashBudget || manifest.falsePositiveBudgetPpm > maxFalsePositiveBudget ||
          manifest.rollbackBudgetPpm > maxRollbackBudget) {
        throw std::runtime_error("Update manifest risk budgets exceed promotion thresholds");
      }

      if (manifest.hotfixRequired) {
        throw std::runtime_error("Update manifest requests hotfix-only handling and cannot promote on this channel");
      }
    }
  }

  if (SigningKeyRevoked(config, manifest.signingKeyId)) {
    throw std::runtime_error("Update manifest signing key has been revoked");
  }

  const auto trustedKeyIds = TrustedKeyIdsForPackageType(config, manifest.packageType, manifest.trustDomain);
  if (std::find(trustedKeyIds.begin(), trustedKeyIds.end(), manifest.signingKeyId) == trustedKeyIds.end()) {
    throw std::runtime_error("Update manifest signing key id is not trusted for this package type");
  }

  if (!manifest.allowDowngrade) {
    const auto baselineVersion =
        (lowerType == L"platform" || lowerType == L"driver")
            ? std::optional<std::wstring>(config.platformVersion)
            : LatestKnownPackageVersion(database, manifest.packageId);

    if (baselineVersion.has_value() && CompareVersionStrings(manifest.targetVersion, *baselineVersion) < 0) {
      throw std::runtime_error("Update manifest target version is lower than the current trusted baseline");
    }
  }
}

void VerifyPlan(const UpdateManifest& manifest) {
  for (const auto& file : manifest.files) {
    if (!std::filesystem::exists(file.sourcePath)) {
      throw std::runtime_error("Update source file is missing");
    }

    if (!IsSha256HexString(file.sha256)) {
      throw std::runtime_error("Update manifest file hash must be a 64-character SHA-256 hex string");
    }

    if (ToLowerCopy(ComputeFileSha256(file.sourcePath)) != ToLowerCopy(file.sha256)) {
      throw std::runtime_error("Update package hash verification failed");
    }

    if (file.requireSignature && !VerifyFileAuthenticodeSignature(file.sourcePath)) {
      throw std::runtime_error("Update package signature verification failed");
    }

    if (!file.requiredSigner.empty()) {
      const auto signer = ToLowerCopy(QueryFileSignerSubject(file.sourcePath));
      if (signer.find(ToLowerCopy(file.requiredSigner)) == std::wstring::npos) {
        throw std::runtime_error("Update package signer did not match the manifest requirement");
      }
    }
  }
}

std::filesystem::path RelativeTargetPath(const std::filesystem::path& targetPath, const std::filesystem::path& installRoot) {
  const auto relative = targetPath.lexically_relative(installRoot);
  return relative.empty() ? targetPath.filename() : relative;
}

bool CopyFileWithParents(const std::filesystem::path& sourcePath, const std::filesystem::path& targetPath) {
  std::error_code error;
  std::filesystem::create_directories(targetPath.parent_path(), error);
  error.clear();
  return std::filesystem::copy_file(sourcePath, targetPath, std::filesystem::copy_options::overwrite_existing, error) &&
         !error;
}

bool ApplySingleFile(const std::filesystem::path& stagedPath, const std::filesystem::path& targetPath,
                     const UpdateApplyMode mode, bool* restartRequired) {
  std::error_code error;
  std::filesystem::create_directories(targetPath.parent_path(), error);
  if (CopyFileW(stagedPath.c_str(), targetPath.c_str(), FALSE) != FALSE) {
    return true;
  }

  const auto lastError = GetLastError();
  if (mode == UpdateApplyMode::InService &&
      (lastError == ERROR_SHARING_VIOLATION || lastError == ERROR_ACCESS_DENIED || lastError == ERROR_USER_MAPPED_FILE)) {
    if (MoveFileExW(stagedPath.c_str(), targetPath.c_str(), MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING) !=
        FALSE) {
      *restartRequired = true;
      return true;
    }
  }

  return false;
}

void RestoreBackupTree(const UpdateManifest& manifest, const std::filesystem::path& installRoot,
                       const std::filesystem::path& backupRoot, bool* restartRequired) {
  std::error_code error;
  for (const auto& file : manifest.files) {
    const auto relativeTarget = RelativeTargetPath(file.targetPath, installRoot);
    const auto backupPath = backupRoot / relativeTarget;
    if (std::filesystem::exists(backupPath)) {
      std::filesystem::create_directories(file.targetPath.parent_path(), error);
      error.clear();
      if (!std::filesystem::copy_file(backupPath, file.targetPath, std::filesystem::copy_options::overwrite_existing,
                                      error) &&
          error) {
        // Some endpoints deny overwrite on in-place replacement even when backup is readable.
        // Remove-and-copy fallback preserves rollback behavior before requesting reboot-time move.
        error.clear();
        std::filesystem::remove(file.targetPath, error);
        error.clear();
        if (std::filesystem::copy_file(backupPath, file.targetPath,
                                       std::filesystem::copy_options::overwrite_existing, error) &&
            !error) {
          continue;
        }

        error.clear();
        if (MoveFileExW(backupPath.c_str(), file.targetPath.c_str(),
                        MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING) != FALSE) {
          *restartRequired = true;
          continue;
        }

        throw std::runtime_error("Rollback could not restore a protected file");
      }

      continue;
    }

    std::filesystem::remove(file.targetPath, error);
  }
}

}  // namespace

UpdaterService::UpdaterService(const AgentConfig& config, std::filesystem::path installRoot)
    : config_(config), installRoot_(std::filesystem::absolute(std::move(installRoot)).lexically_normal()) {}

UpdateResult UpdaterService::ApplyPackage(const std::filesystem::path& manifestPath, const UpdateApplyMode mode) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  UpdateJournalRecord journal;
  journal.transactionId = GenerateGuidString();
  journal.startedAt = CurrentUtcTimestamp();
  journal.manifestPath = std::filesystem::absolute(manifestPath).lexically_normal();
  journal.backupRoot = config_.updateRootPath / L"backups" / journal.transactionId;
  journal.stagedRoot = config_.updateRootPath / L"staged" / journal.transactionId;
  journal.status = L"verifying";

  UpdateResult result;
  result.transactionId = journal.transactionId;

  try {
    const auto manifest = LoadManifestFile(manifestPath, installRoot_);
    VerifyManifestPolicy(manifest, config_, database);
    VerifyPlan(manifest);

    result.packageId = manifest.packageId;
    result.packageType = manifest.packageType;
    result.targetVersion = manifest.targetVersion;
    journal.packageId = manifest.packageId;
    journal.packageType = manifest.packageType;
    journal.targetVersion = manifest.targetVersion;
    database.UpsertUpdateJournal(journal);

    std::error_code error;
    std::filesystem::create_directories(journal.backupRoot, error);
    std::filesystem::create_directories(journal.stagedRoot, error);

    std::vector<std::filesystem::path> stagedFiles;
    stagedFiles.reserve(manifest.files.size());
    for (const auto& file : manifest.files) {
      const auto relativeTarget = RelativeTargetPath(file.targetPath, installRoot_);
      const auto stagedPath = journal.stagedRoot / relativeTarget;
      std::filesystem::create_directories(stagedPath.parent_path(), error);
      if (!CopyFileWithParents(file.sourcePath, stagedPath)) {
        throw std::runtime_error("Could not stage a verified update file");
      }
      stagedFiles.push_back(stagedPath);
    }

    journal.status = L"applying";
    database.UpsertUpdateJournal(journal);

    bool restartRequired = false;
    for (std::size_t index = 0; index < manifest.files.size(); ++index) {
      const auto& file = manifest.files[index];
      const auto relativeTarget = RelativeTargetPath(file.targetPath, installRoot_);
      const auto backupPath = journal.backupRoot / relativeTarget;

      if (std::filesystem::exists(file.targetPath)) {
        std::filesystem::create_directories(backupPath.parent_path(), error);
        if (!CopyFileWithParents(file.targetPath, backupPath)) {
          throw std::runtime_error("Could not back up an existing endpoint binary before update");
        }
      }

      if (!ApplySingleFile(stagedFiles[index], file.targetPath, mode, &restartRequired)) {
        result.rollbackAttempted = true;
        RestoreBackupTree(manifest, installRoot_, journal.backupRoot, &restartRequired);
        result.rollbackPerformed = true;
        throw std::runtime_error("Could not apply an update payload to the installation root");
      }
    }

    journal.completedAt = CurrentUtcTimestamp();
    journal.requiresRestart = restartRequired;
    journal.status = restartRequired ? L"pending_restart" : L"completed";
    journal.resultJson = std::wstring(L"{\"packageId\":\"") + manifest.packageId + L"\",\"targetVersion\":\"" +
                         manifest.targetVersion + L"\",\"restartRequired\":" +
                         (restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
    database.UpsertUpdateJournal(journal);

    result.success = true;
    result.restartRequired = restartRequired;
    result.status = journal.status;
    return result;
  } catch (const std::exception& error) {
    journal.completedAt = CurrentUtcTimestamp();
    journal.status = L"failed";
    journal.resultJson =
        std::wstring(L"{\"error\":\"") + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}";
    database.UpsertUpdateJournal(journal);

    result.status = journal.status;
    result.errorMessage = Utf8ToWide(error.what());
    return result;
  }
}

UpdateResult UpdaterService::RollbackTransaction(const std::wstring& transactionId) const {
  RuntimeDatabase database(config_.runtimeDatabasePath);
  UpdateJournalRecord journal;
  if (!database.LoadUpdateJournal(transactionId, journal)) {
    return UpdateResult{
        .success = false,
        .transactionId = transactionId,
        .status = L"missing",
        .errorMessage = L"The requested update transaction could not be found."};
  }

  try {
    const auto manifest = LoadManifestFile(journal.manifestPath, installRoot_);
    bool restartRequired = false;
    RestoreBackupTree(manifest, installRoot_, journal.backupRoot, &restartRequired);

    journal.completedAt = CurrentUtcTimestamp();
    journal.status = restartRequired ? L"rolled_back_pending_restart" : L"rolled_back";
    journal.requiresRestart = restartRequired;
    journal.resultJson = std::wstring(L"{\"rolledBack\":true,\"restartRequired\":") +
                         (restartRequired ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
    database.UpsertUpdateJournal(journal);

    return UpdateResult{
        .success = true,
        .restartRequired = restartRequired,
        .rollbackPerformed = true,
        .transactionId = journal.transactionId,
        .packageId = journal.packageId,
        .packageType = journal.packageType,
        .targetVersion = journal.targetVersion,
        .status = journal.status};
  } catch (const std::exception& error) {
    journal.completedAt = CurrentUtcTimestamp();
    journal.status = L"rollback_failed";
    journal.resultJson =
        std::wstring(L"{\"error\":\"") + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}";
    database.UpsertUpdateJournal(journal);

    return UpdateResult{
        .success = false,
        .transactionId = journal.transactionId,
        .packageId = journal.packageId,
        .packageType = journal.packageType,
        .targetVersion = journal.targetVersion,
        .status = journal.status,
        .errorMessage = Utf8ToWide(error.what())};
  }
}

}  // namespace antivirus::agent
