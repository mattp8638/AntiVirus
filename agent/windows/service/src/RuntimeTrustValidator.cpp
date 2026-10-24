#include "RuntimeTrustValidator.h"

#include <windows.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <vector>

#include "CryptoUtils.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kRegistryRoot[] = L"SOFTWARE\\FenrirAgent";
constexpr wchar_t kLegacyRegistryRoot[] = L"SOFTWARE\\AntiVirusAgent";
constexpr wchar_t kRuntimeRootValueName[] = L"RuntimeRoot";
constexpr wchar_t kRuntimeDatabasePathValueName[] = L"RuntimeDatabasePath";
constexpr wchar_t kInstallRootValueName[] = L"InstallRoot";
constexpr wchar_t kServiceExecutableName[] = L"fenrir-agent-service.exe";
constexpr wchar_t kAmsiProviderDllName[] = L"fenrir-amsi-provider.dll";

struct RegistryTrustMarker {
  std::filesystem::path runtimeRootPath;
  std::filesystem::path runtimeDatabasePath;
  std::filesystem::path installRootPath;
};

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::filesystem::path NormalizeAbsolutePath(const std::filesystem::path& value) {
  if (value.empty()) {
    return {};
  }

  std::error_code error;
  const auto absolute = std::filesystem::absolute(value, error);
  if (error) {
    return value.lexically_normal();
  }

  return absolute.lexically_normal();
}

std::wstring NormalizePathForCompare(const std::filesystem::path& value) {
  auto normalized = ToLowerCopy(NormalizeAbsolutePath(value).wstring());
  while (!normalized.empty() && (normalized.back() == L'\\' || normalized.back() == L'/')) {
    normalized.pop_back();
  }
  return normalized;
}

bool PathsEqual(const std::filesystem::path& left, const std::filesystem::path& right) {
  if (left.empty() || right.empty()) {
    return false;
  }

  return NormalizePathForCompare(left) == NormalizePathForCompare(right);
}

std::wstring ReadRegistryStringFromRoot(HKEY hive, const wchar_t* registryRoot, const wchar_t* valueName) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(hive, registryRoot, 0, KEY_READ, &key) != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || type != REG_SZ ||
      bytes == 0) {
    RegCloseKey(key);
    return {};
  }

  std::wstring value(bytes / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &bytes) !=
      ERROR_SUCCESS) {
    RegCloseKey(key);
    return {};
  }

  RegCloseKey(key);
  while (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }
  return value;
}

std::vector<RegistryTrustMarker> ReadRegistryTrustMarkers() {
  std::vector<RegistryTrustMarker> markers;
  for (const auto hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
    for (const auto root : {kRegistryRoot, kLegacyRegistryRoot}) {
      RegistryTrustMarker marker;
      marker.runtimeRootPath =
          std::filesystem::path(ReadRegistryStringFromRoot(hive, root, kRuntimeRootValueName));
      marker.runtimeDatabasePath =
          std::filesystem::path(ReadRegistryStringFromRoot(hive, root, kRuntimeDatabasePathValueName));
      marker.installRootPath = std::filesystem::path(ReadRegistryStringFromRoot(hive, root, kInstallRootValueName));

      if (!marker.runtimeRootPath.empty() || !marker.runtimeDatabasePath.empty() || !marker.installRootPath.empty()) {
        markers.push_back(std::move(marker));
      }
    }
  }

  return markers;
}

bool ParseBooleanValue(const std::wstring& rawValue) {
  if (rawValue.empty()) {
    return false;
  }

  const auto lower = ToLowerCopy(rawValue);
  return lower == L"1" || lower == L"true" || lower == L"yes" || lower == L"on";
}

}  // namespace

RuntimeTrustValidation ValidateRuntimeTrust(const AgentConfig& config, const std::filesystem::path& installRoot) {
  RuntimeTrustValidation validation;
  validation.requireSignedBinaries = ParseBooleanValue(ReadEnvironmentVariable(L"ANTIVIRUS_REQUIRE_SIGNED_RUNTIME"));

  const auto runtimeValidation = ValidateRuntimePaths(config);
  validation.runtimePathsTrusted = runtimeValidation.trusted;
  if (!runtimeValidation.trusted) {
    validation.message = runtimeValidation.message.empty()
                             ? L"Runtime path boundary validation failed."
                             : runtimeValidation.message;
    return validation;
  }

  const auto expectedRuntimeRoot = NormalizeAbsolutePath(runtimeValidation.runtimeRootPath.empty()
                                                             ? config.runtimeDatabasePath.parent_path()
                                                             : runtimeValidation.runtimeRootPath);
  const auto expectedInstallRoot =
      NormalizeAbsolutePath(installRoot.empty() ? runtimeValidation.installRootPath : installRoot);
  const auto expectedRuntimeDatabasePath = NormalizeAbsolutePath(config.runtimeDatabasePath);

  const auto registryMarkers = ReadRegistryTrustMarkers();
  validation.registryRuntimeMarkerPresent = !registryMarkers.empty();
  if (!validation.registryRuntimeMarkerPresent) {
    validation.message =
        L"No runtime trust registry marker was found in HKLM/HKCU (RuntimeRoot/RuntimeDatabasePath).";
    return validation;
  }

  for (const auto& marker : registryMarkers) {
    const auto markerRuntimeRoot = NormalizeAbsolutePath(marker.runtimeRootPath);
    const auto markerRuntimeDatabasePath = NormalizeAbsolutePath(marker.runtimeDatabasePath);
    const auto markerInstallRoot = NormalizeAbsolutePath(marker.installRootPath);

    const auto runtimeRootMatches = !markerRuntimeRoot.empty() && PathsEqual(markerRuntimeRoot, expectedRuntimeRoot);
    const auto runtimeDatabaseMatches =
        markerRuntimeDatabasePath.empty() || PathsEqual(markerRuntimeDatabasePath, expectedRuntimeDatabasePath);
    if (!(runtimeRootMatches && runtimeDatabaseMatches)) {
      continue;
    }

    validation.registryRuntimeMatches = true;
    if (expectedInstallRoot.empty() || (!markerInstallRoot.empty() && PathsEqual(markerInstallRoot, expectedInstallRoot))) {
      validation.registryInstallMatches = true;
      break;
    }
  }

  if (!validation.registryRuntimeMatches) {
    validation.message =
        L"Runtime trust marker mismatch: registry RuntimeRoot/RuntimeDatabasePath does not match the active runtime paths.";
    return validation;
  }

  if (!expectedInstallRoot.empty() && !validation.registryInstallMatches) {
    validation.message =
        L"Runtime trust marker mismatch: registry InstallRoot does not match the active install root.";
    return validation;
  }

  const auto servicePath = expectedInstallRoot / kServiceExecutableName;
  const auto providerPath = expectedInstallRoot / kAmsiProviderDllName;

  std::error_code error;
  validation.serviceBinaryPresent = std::filesystem::exists(servicePath, error) && !error;
  error.clear();
  validation.amsiProviderPresent = std::filesystem::exists(providerPath, error) && !error;

  if (!validation.serviceBinaryPresent || !validation.amsiProviderPresent) {
    validation.message = L"Runtime trust validation could not find required service binaries under install root.";
    return validation;
  }

  validation.serviceBinarySigned = VerifyFileAuthenticodeSignature(servicePath);
  validation.amsiProviderSigned = VerifyFileAuthenticodeSignature(providerPath);

  const auto signaturesValid = validation.serviceBinarySigned && validation.amsiProviderSigned;
  if (!signaturesValid) {
    if (validation.requireSignedBinaries) {
      validation.message = L"Runtime trust validation failed Authenticode verification for one or more binaries.";
      return validation;
    }

    validation.signatureWarning = true;
    validation.message =
        L"Runtime trust boundaries and registry markers are valid, but one or more binaries are unsigned in this build context.";
  } else {
    validation.message = L"Runtime trust boundaries, registry markers, and binary signatures are valid.";
  }

  validation.trusted = true;
  return validation;
}

}  // namespace antivirus::agent
