#include "ScanEngine.h"
#include "CommandCancellation.h"

#include <windows.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <system_error>

#include "CryptoUtils.h"
#include "ExtendedPolicy.h"
#include "MlStaticModel.h"
#include "ReputationLookup.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

constexpr std::size_t kReadLimit = 1024 * 1024;
constexpr std::uint32_t kMaxArchiveEntryCount = 5000;
constexpr std::size_t kMaxZipEntryNameOutputChars = 64 * 1024;
constexpr std::size_t kMaxDecodedTextChars = 512 * 1024;

struct Hit {
  std::wstring code;
  std::wstring message;
  std::wstring tacticId;
  std::wstring techniqueId;
  int score{0};
  bool exactIndicator{false};
};

struct Rule {
  std::wstring scope;
  std::wstring code;
  std::wstring message;
  std::wstring tacticId;
  std::wstring techniqueId;
  int score{0};
  std::vector<std::wstring> patterns;
};

struct FileData {
  std::filesystem::path path;
  std::uintmax_t sizeBytes{0};
  std::wstring extension;
  std::wstring fileNameLower;
  std::wstring contentType;
  std::wstring signer;
  std::wstring reputation;
  std::wstring sha256;
  std::wstring textLower;
  std::wstring asciiLower;
  std::wstring zipEntryNamesLower;
  std::vector<unsigned char> bytes;
  bool readLimitHit{false};
  bool userPath{false};
  bool trustedPath{false};
  bool signatureVerified{false};
  bool pe{false};
  bool zip{false};
  bool ole{false};
  bool lnk{false};
  bool zipMalformed{false};
  bool zipEntryLimitExceeded{false};
  bool zipEntryNamesTruncated{false};
  double entropy{0.0};
  std::uint32_t archiveEntryCount{0};
};

struct AllowOverrideMatch {
  std::wstring code;
  std::wstring message;
};

std::wstring ToLowerCopy(std::wstring value);
bool ContainsAny(std::wstring_view haystack, std::initializer_list<std::wstring_view> needles);
std::wstring TrimWide(std::wstring value);
std::filesystem::path ResolveSignatureBundlePath();

int ResolveGenericRuleScoreCap() {
  const auto configured = ReadEnvironmentVariable(L"ANTIVIRUS_GENERIC_RULE_SCORE_CAP");
  if (configured.empty()) {
    return 34;
  }

  try {
    return std::clamp(std::stoi(configured), 1, 99);
  } catch (...) {
    return 34;
  }
}

std::filesystem::path ResolveObserveOnlyRuleCodesPath() {
  const auto envPath = ReadEnvironmentVariable(L"ANTIVIRUS_OBSERVE_ONLY_RULES_PATH");
  if (!envPath.empty()) {
    return std::filesystem::path(envPath);
  }

  const auto signaturePath = ResolveSignatureBundlePath();
  if (!signaturePath.empty()) {
    return signaturePath.parent_path() / L"default-observe-only.tsv";
  }

  return std::filesystem::path{};
}

const std::set<std::wstring>& LoadObserveOnlyRuleCodes() {
  static std::once_flag once;
  static std::set<std::wstring> codes;

  std::call_once(once, [] {
    const auto path = ResolveObserveOnlyRuleCodesPath();
    if (path.empty()) {
      return;
    }

    std::ifstream input(WideToUtf8(path.wstring()), std::ios::binary);
    if (!input.is_open()) {
      return;
    }

    std::string lineUtf8;
    while (std::getline(input, lineUtf8)) {
      const auto line = TrimWide(Utf8ToWide(lineUtf8));
      if (line.empty() || line.starts_with(L"#") || line.starts_with(L";")) {
        continue;
      }
      codes.insert(ToLowerCopy(line));
    }
  });

  return codes;
}

bool IsObserveOnlyRuleCode(const std::wstring& code) {
  const auto& codes = LoadObserveOnlyRuleCodes();
  if (codes.empty()) {
    return false;
  }

  return codes.find(ToLowerCopy(code)) != codes.end();
}

bool IsGenericRuleCode(const std::wstring& code) {
  const auto lower = ToLowerCopy(code);
  return ContainsAny(lower, {L"persistence", L"credential_access", L"defender_config_tamper", L"script_host",
                             L"long_base64", L"obfuscation", L"download", L"archive_"});
}

int ScaleRuleScoreForPolicy(const Rule& rule, const PolicySnapshot& policy) {
  if (rule.score <= 0) {
    return rule.score;
  }

  auto scaled = rule.score;
  if (IsObserveOnlyRuleCode(rule.code)) {
    scaled = std::min(scaled, 12);
  }
  if (IsGenericRuleCode(rule.code)) {
    scaled = std::max(1, (scaled * static_cast<int>(policy.genericRuleScoreScalePercent)) / 100);
    scaled = std::min(scaled, ResolveGenericRuleScoreCap());
  }

  return std::clamp(scaled, 1, 99);
}

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

bool Contains(std::wstring_view haystack, std::wstring_view needle) {
  return haystack.find(needle) != std::wstring_view::npos;
}

bool ContainsAny(std::wstring_view haystack, std::initializer_list<std::wstring_view> needles) {
  return std::any_of(needles.begin(), needles.end(),
                     [haystack](const auto needle) { return Contains(haystack, needle); });
}

bool UserPath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return Contains(lower, L"\\users\\") || Contains(lower, L"\\downloads\\") || Contains(lower, L"\\desktop\\") ||
         Contains(lower, L"\\temp\\") ||
         Contains(lower, L"\\appdata\\local\\temp\\") || Contains(lower, L"\\startup\\");
}

bool IsNoisyCachePath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return ContainsAny(lower, {L"\\node-compile-cache\\", L"\\v8-compile-cache\\", L"\\npm-cache\\",
                             L"\\pnpm-store\\", L"\\yarn\\cache\\", L"\\.cache\\",
                             L"\\appdata\\local\\temp\\node-compile-cache\\"});
}

bool ExecutableExt(const std::wstring& ext);
bool ScriptExt(const std::wstring& ext);

bool IsHighRiskExecutionSurface(const FileData& file) {
  return file.pe || file.zip || file.ole || file.lnk || ExecutableExt(file.extension) ||
         ScriptExt(file.extension) || file.extension == L".hta" || file.extension == L".url";
}

bool ContainsEicarMarker(const FileData& file) {
  return ContainsAny(file.fileNameLower, {L"eicar"}) ||
         ContainsAny(file.textLower, {L"eicar-standard-antivirus-test-file"}) ||
         ContainsAny(file.zipEntryNamesLower, {L"eicar"});
}

bool ShouldSuppressNoisyCacheFile(const FileData& file) {
  if (!IsNoisyCachePath(file.path) || ContainsEicarMarker(file)) {
    return false;
  }

  return !IsHighRiskExecutionSurface(file);
}

bool TrustedPath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return Contains(lower, L"\\windows\\") || Contains(lower, L"\\program files\\") ||
         Contains(lower, L"\\program files (x86)\\");
}

bool IsWindowsSystemBinaryPath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return Contains(lower, L"\\windows\\system32\\") || Contains(lower, L"\\windows\\syswow64\\");
}

bool VerifyAuthenticodeSignature(const std::filesystem::path& path) {
  WINTRUST_FILE_INFO fileInfo{};
  fileInfo.cbStruct = sizeof(fileInfo);
  fileInfo.pcwszFilePath = path.c_str();

  WINTRUST_DATA trustData{};
  trustData.cbStruct = sizeof(trustData);
  trustData.dwUIChoice = WTD_UI_NONE;
  trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
  trustData.dwUnionChoice = WTD_CHOICE_FILE;
  trustData.pFile = &fileInfo;
  trustData.dwStateAction = WTD_STATEACTION_VERIFY;
  trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

  GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const auto status = WinVerifyTrust(nullptr, &policyGuid, &trustData);
  trustData.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policyGuid, &trustData);
  return status == ERROR_SUCCESS;
}

// Most Windows system files carry no embedded signature: they are signed through a catalog (.cat)
// file instead. Returns the catalog's signer when the file's hash is in a catalog that verifies,
// so System32 files count as Microsoft-signed like they do in Windows itself.
std::wstring QuerySigner(const std::wstring& path);

std::wstring VerifyCatalogSigner(const std::filesystem::path& path) {
  using AcquireContext2 = BOOL(WINAPI*)(HCATADMIN*, const GUID*, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
  using CalcHash2 = BOOL(WINAPI*)(HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);
  using AcquireContext1 = BOOL(WINAPI*)(HCATADMIN*, const GUID*, DWORD);
  using CalcHash1 = BOOL(WINAPI*)(HANDLE, DWORD*, BYTE*, DWORD);
  using ReleaseContext = BOOL(WINAPI*)(HCATADMIN, DWORD);

  static const HMODULE wintrust = LoadLibraryExW(L"wintrust.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (wintrust == nullptr) {
    return {};
  }
  const auto acquire2 = reinterpret_cast<AcquireContext2>(GetProcAddress(wintrust, "CryptCATAdminAcquireContext2"));
  const auto hash2 = reinterpret_cast<CalcHash2>(GetProcAddress(wintrust, "CryptCATAdminCalcHashFromFileHandle2"));
  const auto acquire1 = reinterpret_cast<AcquireContext1>(GetProcAddress(wintrust, "CryptCATAdminAcquireContext"));
  const auto hash1 = reinterpret_cast<CalcHash1>(GetProcAddress(wintrust, "CryptCATAdminCalcHashFromFileHandle"));
  const auto release = reinterpret_cast<ReleaseContext>(GetProcAddress(wintrust, "CryptCATAdminReleaseContext"));
  if (release == nullptr) {
    return {};
  }

  const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return {};
  }

  GUID driverAction = DRIVER_ACTION_VERIFY;
  std::wstring signer;
  // Windows 8+ catalogs use SHA-256; older ones SHA-1. Try both.
  for (int attempt = 0; attempt < 2 && signer.empty(); ++attempt) {
    HCATADMIN admin = nullptr;
    const bool sha256 = attempt == 0;
    if (sha256 ? (acquire2 == nullptr || acquire2(&admin, &driverAction, L"SHA256", nullptr, 0) == FALSE)
               : (acquire1 == nullptr || acquire1(&admin, &driverAction, 0) == FALSE)) {
      continue;
    }

    std::vector<BYTE> hash(64);
    DWORD hashSize = static_cast<DWORD>(hash.size());
    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
    const BOOL hashed = sha256 ? (hash2 != nullptr && hash2(admin, file, &hashSize, hash.data(), 0))
                               : (hash1 != nullptr && hash1(file, &hashSize, hash.data(), 0));
    if (hashed != FALSE) {
      HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hashSize, 0, nullptr);
      if (catalog != nullptr) {
        CATALOG_INFO catalogInfo{};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        if (CryptCATCatalogInfoFromContext(catalog, &catalogInfo, 0) != FALSE) {
          std::wstring memberTag;
          static const wchar_t* hex = L"0123456789ABCDEF";
          for (DWORD index = 0; index < hashSize; ++index) {
            memberTag.push_back(hex[hash[index] >> 4]);
            memberTag.push_back(hex[hash[index] & 0x0F]);
          }

          WINTRUST_CATALOG_INFO trustCatalog{};
          trustCatalog.cbStruct = sizeof(trustCatalog);
          trustCatalog.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
          trustCatalog.pcwszMemberTag = memberTag.c_str();
          trustCatalog.pcwszMemberFilePath = path.c_str();
          trustCatalog.hMemberFile = file;
          trustCatalog.pbCalculatedFileHash = hash.data();
          trustCatalog.cbCalculatedFileHash = hashSize;
          trustCatalog.hCatAdmin = admin;

          WINTRUST_DATA trustData{};
          trustData.cbStruct = sizeof(trustData);
          trustData.dwUIChoice = WTD_UI_NONE;
          trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
          trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
          trustData.pCatalog = &trustCatalog;
          trustData.dwStateAction = WTD_STATEACTION_VERIFY;
          trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
          GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
          const auto status = WinVerifyTrust(nullptr, &policyGuid, &trustData);
          trustData.dwStateAction = WTD_STATEACTION_CLOSE;
          WinVerifyTrust(nullptr, &policyGuid, &trustData);
          if (status == ERROR_SUCCESS) {
            signer = QuerySigner(catalogInfo.wszCatalogFile);
            if (signer.empty()) {
              signer = L"catalog-signed (publisher unknown)";
            }
          }
        }
        CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
      }
    }
    release(admin, 0);
  }

  CloseHandle(file);
  return signer;
}

std::wstring NormalizePathForComparison(const std::filesystem::path& path) {
  if (path.empty()) {
    return {};
  }

  std::error_code error;
  auto normalized = std::filesystem::absolute(path, error);
  if (error) {
    normalized = path;
  }

  normalized = normalized.lexically_normal();
  auto value = ToLowerCopy(normalized.wstring());
  std::replace(value.begin(), value.end(), L'/', L'\\');
  while (value.size() > 1 && value.back() == L'\\') {
    if (value.size() == 3 && value[1] == L':') {
      break;
    }
    if (value.size() == 2 && value[0] == L'\\' && value[1] == L'\\') {
      break;
    }
    value.pop_back();
  }

  return value;
}

bool PathIsWithinRoot(const std::wstring& candidate, const std::wstring& root) {
  if (candidate.empty() || root.empty()) {
    return false;
  }

  if (candidate == root) {
    return true;
  }

  std::wstring rootPrefix = root;
  if (!rootPrefix.empty() && rootPrefix.back() != L'\\') {
    rootPrefix.push_back(L'\\');
  }

  return candidate.starts_with(rootPrefix);
}

bool IsExcludedPath(const std::filesystem::path& path, const std::vector<std::filesystem::path>& exclusions) {
  const auto normalizedPath = NormalizePathForComparison(path);
  if (normalizedPath.empty()) {
    return false;
  }

  for (const auto& exclusion : exclusions) {
    const auto normalizedExclusion = NormalizePathForComparison(exclusion);
    if (PathIsWithinRoot(normalizedPath, normalizedExclusion)) {
      return true;
    }
  }

  return false;
}

bool ExecutableExt(const std::wstring& ext) {
  return ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".msi" || ext == L".com";
}

bool ScriptExt(const std::wstring& ext) {
  return ext == L".ps1" || ext == L".psm1" || ext == L".bat" || ext == L".cmd" || ext == L".js" ||
         ext == L".jse" || ext == L".vbs" || ext == L".vbe" || ext == L".hta";
}

std::wstring GetModuleDirectory() {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (written == 0) {
    return {};
  }

  buffer.resize(written);
  const auto path = std::filesystem::path(buffer);
  return path.has_parent_path() ? path.parent_path().wstring() : std::filesystem::current_path().wstring();
}

std::filesystem::path ResolveSignatureBundlePath() {
  const auto envPath = ReadEnvironmentVariable(L"ANTIVIRUS_SIGNATURE_BUNDLE_PATH");
  if (!envPath.empty()) {
    return std::filesystem::path(envPath);
  }

  auto moduleDirectory = std::filesystem::path(GetModuleDirectory());
  for (int depth = 0; depth < 4 && !moduleDirectory.empty(); ++depth) {
    const auto directCandidate = moduleDirectory / L"signatures" / L"default-signatures.tsv";
    if (std::error_code error; std::filesystem::exists(directCandidate, error) && !error) {
      return directCandidate;
    }

    const auto repoCandidate = moduleDirectory / L"agent" / L"windows" / L"signatures" / L"default-signatures.tsv";
    if (std::error_code error; std::filesystem::exists(repoCandidate, error) && !error) {
      return repoCandidate;
    }

    moduleDirectory = moduleDirectory.parent_path();
  }

  const auto cwdCandidate = std::filesystem::current_path() / L"signatures" / L"default-signatures.tsv";
  if (std::error_code error; std::filesystem::exists(cwdCandidate, error) && !error) {
    return cwdCandidate;
  }

  return std::filesystem::current_path() / L"agent" / L"windows" / L"signatures" / L"default-signatures.tsv";
}

std::vector<std::filesystem::path> ResolveSignatureBundlePaths() {
  std::vector<std::filesystem::path> paths;
  const auto primary = ResolveSignatureBundlePath();
  if (!primary.empty()) {
    paths.push_back(primary);
  }

  const auto addIfExists = [&paths](const std::filesystem::path& path) {
    if (path.empty()) {
      return;
    }
    std::error_code error;
    if (std::filesystem::exists(path, error) && !error) {
      paths.push_back(path);
    }
  };

  const auto baseDirectory = primary.parent_path();
  addIfExists(baseDirectory / L"default-signatures-malicious.tsv");
  addIfExists(baseDirectory / L"default-signatures-observe.tsv");
  addIfExists(baseDirectory / L"daily-signatures.tsv");

  const auto runtimeDeltaFromEnv = ReadEnvironmentVariable(L"ANTIVIRUS_RUNTIME_SIGNATURE_DELTA_PATH");
  if (!runtimeDeltaFromEnv.empty()) {
    addIfExists(std::filesystem::path(runtimeDeltaFromEnv));
  }

  auto moduleDirectory = std::filesystem::path(GetModuleDirectory());
  for (int depth = 0; depth < 4 && !moduleDirectory.empty(); ++depth) {
    addIfExists(moduleDirectory / L"runtime" / L"updates" / L"signatures" / L"daily-signatures.tsv");
    moduleDirectory = moduleDirectory.parent_path();
  }

  const auto programData = ReadEnvironmentVariable(L"PROGRAMDATA");
  if (!programData.empty()) {
    addIfExists(std::filesystem::path(programData) / L"FenrirAgent" / L"runtime" / L"updates" / L"signatures" /
                L"daily-signatures.tsv");
  }

  const auto localAppData = ReadEnvironmentVariable(L"LOCALAPPDATA");
  if (!localAppData.empty()) {
    addIfExists(std::filesystem::path(localAppData) / L"FenrirAgent" / L"runtime" / L"updates" / L"signatures" /
                L"daily-signatures.tsv");
  }

  std::sort(paths.begin(), paths.end());
  paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
  return paths;
}

std::vector<std::wstring> SplitPatterns(const std::wstring& value, const wchar_t separator) {
  std::vector<std::wstring> parts;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == separator) {
      const auto trimmed = TrimWide(current);
      if (!trimmed.empty()) {
        parts.push_back(ToLowerCopy(trimmed));
      }
      current.clear();
      continue;
    }
    current.push_back(ch);
  }

  const auto trailing = TrimWide(current);
  if (!trailing.empty()) {
    parts.push_back(ToLowerCopy(trailing));
  }
  return parts;
}

std::vector<std::wstring> SplitColumns(const std::wstring& value, const wchar_t separator) {
  std::vector<std::wstring> columns;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == separator) {
      columns.push_back(TrimWide(current));
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  columns.push_back(TrimWide(current));
  return columns;
}

std::vector<unsigned char> ReadBytes(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return {};
  }
  input.seekg(0, std::ios::end);
  const auto size = static_cast<std::size_t>(std::max<std::streamoff>(input.tellg(), 0));
  input.seekg(0, std::ios::beg);
  std::vector<unsigned char> bytes(std::min(size, kReadLimit));
  input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  bytes.resize(static_cast<std::size_t>(std::max<std::streamsize>(input.gcount(), 0)));
  return bytes;
}

std::wstring DecodeText(const std::vector<unsigned char>& bytes) {
  if (bytes.empty()) {
    return {};
  }
  if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) {
    std::wstring text;
    text.reserve(std::min(bytes.size() / 2, kMaxDecodedTextChars));
    for (std::size_t i = 2; i + 1 < bytes.size(); i += 2) {
      const auto ch = static_cast<wchar_t>(bytes[i] | (bytes[i + 1] << 8));
      if (ch != L'\0') {
        text.push_back(ch);
        if (text.size() >= kMaxDecodedTextChars) {
          break;
        }
      }
    }
    return text;
  }
  const auto utf8 = Utf8ToWide(std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
  if (!utf8.empty()) {
    return utf8.size() > kMaxDecodedTextChars ? utf8.substr(0, kMaxDecodedTextChars) : utf8;
  }
  std::wstring text;
  text.reserve(std::min(bytes.size(), kMaxDecodedTextChars));
  for (const auto byte : bytes) {
    text.push_back(byte >= 0x20 && byte <= 0x7E ? static_cast<wchar_t>(byte) : L' ');
    if (text.size() >= kMaxDecodedTextChars) {
      break;
    }
  }
  return text;
}

std::wstring ExtractAsciiLower(const std::vector<unsigned char>& bytes) {
  std::wstring text;
  text.reserve(std::min(bytes.size(), kMaxDecodedTextChars));
  for (const auto byte : bytes) {
    text.push_back(byte >= 0x20 && byte <= 0x7E ? static_cast<wchar_t>(std::towlower(static_cast<wchar_t>(byte)))
                                                : L' ');
    if (text.size() >= kMaxDecodedTextChars) {
      break;
    }
  }
  return text;
}

double Entropy(const std::vector<unsigned char>& bytes) {
  if (bytes.empty()) {
    return 0.0;
  }
  std::array<std::size_t, 256> counts{};
  for (const auto byte : bytes) {
    ++counts[byte];
  }
  double entropy = 0.0;
  const auto total = static_cast<double>(bytes.size());
  for (const auto count : counts) {
    if (count == 0) {
      continue;
    }
    const auto p = static_cast<double>(count) / total;
    entropy -= p * std::log2(p);
  }
  return entropy;
}

std::uint32_t CountZipEntries(const std::vector<unsigned char>& bytes, bool* entryLimitExceeded) {
  std::uint32_t count = 0;
  if (entryLimitExceeded != nullptr) {
    *entryLimitExceeded = false;
  }

  for (std::size_t index = 0; index + 3 < bytes.size(); ++index) {
    if (bytes[index] == 'P' && bytes[index + 1] == 'K' && bytes[index + 2] == 0x03 && bytes[index + 3] == 0x04) {
      if (count >= kMaxArchiveEntryCount) {
        if (entryLimitExceeded != nullptr) {
          *entryLimitExceeded = true;
        }
        return kMaxArchiveEntryCount;
      }
      ++count;
    }
  }
  return count;
}

std::wstring ExtractZipEntryNamesLower(const std::vector<unsigned char>& bytes, bool* malformed,
                                       bool* outputTruncated) {
  if (malformed != nullptr) {
    *malformed = false;
  }
  if (outputTruncated != nullptr) {
    *outputTruncated = false;
  }

  std::wstring entryNames;
  for (std::size_t index = 0; index + 46 <= bytes.size(); ++index) {
    if (bytes[index] != 'P' || bytes[index + 1] != 'K' || bytes[index + 2] != 0x01 || bytes[index + 3] != 0x02) {
      continue;
    }

    const auto fileNameLength = static_cast<std::uint16_t>(bytes[index + 28] | (bytes[index + 29] << 8));
    const auto extraFieldLength = static_cast<std::uint16_t>(bytes[index + 30] | (bytes[index + 31] << 8));
    const auto commentLength = static_cast<std::uint16_t>(bytes[index + 32] | (bytes[index + 33] << 8));

    const auto fileNameOffset = index + 46;
    const auto fileNameEnd = fileNameOffset + fileNameLength;
    if (fileNameEnd > bytes.size()) {
      if (malformed != nullptr) {
        *malformed = true;
      }
      break;
    }

    const auto decodedName = Utf8ToWide(std::string(reinterpret_cast<const char*>(bytes.data() + fileNameOffset),
                                                    fileNameLength));
    if (decodedName.empty()) {
      continue;
    }

    if (!entryNames.empty()) {
      entryNames.push_back(L' ');
    }
    entryNames += ToLowerCopy(decodedName);

    if (entryNames.size() >= kMaxZipEntryNameOutputChars) {
      entryNames.resize(kMaxZipEntryNameOutputChars);
      if (outputTruncated != nullptr) {
        *outputTruncated = true;
      }
      break;
    }

    const auto skipTo = fileNameEnd + extraFieldLength + commentLength;
    if (skipTo < fileNameEnd || skipTo > bytes.size()) {
      if (malformed != nullptr) {
        *malformed = true;
      }
      break;
    }

    if (skipTo > index) {
      index = skipTo > 0 ? skipTo - 1 : index;
    }
  }

  return entryNames;
}

bool LongBase64(std::wstring_view text) {
  std::size_t run = 0;
  for (const auto ch : text) {
    const auto ok = (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9') ||
                    ch == L'+' || ch == L'/' || ch == L'=';
    run = ok ? run + 1 : 0;
    if (run >= 96) {
      return true;
    }
  }
  return false;
}

bool LooksLikeRansomNoteName(std::wstring_view fileNameLower) {
  return ContainsAny(fileNameLower, {L"readme", L"decrypt", L"recover", L"restore", L"how_to", L"help", L"ransom"}) &&
         (ContainsAny(fileNameLower, {L".txt", L".html", L".hta", L".url"}) ||
          fileNameLower.find(L'_') != std::wstring_view::npos || fileNameLower.find(L'-') != std::wstring_view::npos);
}

bool ContainsRansomNoteLanguage(std::wstring_view textLower) {
  const auto mentionsEncryption =
      ContainsAny(textLower, {L"your files have been encrypted", L"all your files have been encrypted",
                              L"data encrypted", L"files are encrypted", L"encrypted with"});
  const auto mentionsRecovery =
      ContainsAny(textLower, {L"how to decrypt", L"recover your files", L"restore your files",
                              L"private key", L"decryptor", L"decryption key"});
  const auto mentionsPayment =
      ContainsAny(textLower, {L"bitcoin", L"monero", L"onion", L"tor browser", L"contact us", L"pay"});

  return (mentionsEncryption && mentionsRecovery) || (mentionsEncryption && mentionsPayment);
}

bool LooksLikeEncryptedArtifact(const FileData& file) {
  if (file.pe || file.zip || file.ole || file.lnk || ScriptExt(file.extension) || ExecutableExt(file.extension)) {
    return false;
  }

  const auto suspiciousExtension =
      ContainsAny(file.extension, {L".locked", L".lock", L".encrypted", L".enc", L".crypt", L".crypted", L".cry",
                                   L".lockbit", L".conti", L".akira", L".clop", L".ryuk", L".blackcat"});
  return suspiciousExtension && file.entropy >= 6.8;
}

bool ContainsRecoveryInhibitionCommands(std::wstring_view textLower) {
  return ContainsAny(textLower, {L"vssadmin delete shadows", L"wmic shadowcopy delete", L"wbadmin delete catalog",
                                 L"wbadmin delete backup", L"bcdedit /set {default} recoveryenabled no",
                                 L"bcdedit /set {current} recoveryenabled no",
                                 L"bcdedit /set {default} bootstatuspolicy ignoreallfailures",
                                 L"bcdedit /set {current} bootstatuspolicy ignoreallfailures", L"reagentc /disable"});
}

bool ContainsMassEncryptionScriptBehavior(std::wstring_view textLower) {
  const auto enumeratesFiles =
      ContainsAny(textLower, {L"get-childitem", L"enumeratefiles", L"directory.getfiles", L"findfirstfile",
                              L"forfiles", L"dir /s", L"walk("});
  const auto usesCrypto =
      ContainsAny(textLower, {L"aesmanaged", L"rijndaelmanaged", L"cryptostream", L"createencryptor",
                              L"transformfinalblock", L"encryptor", L"cryptoapi"});
  const auto rewritesContent =
      ContainsAny(textLower, {L"writeallbytes", L"set-content", L"writealltext", L"move-item", L"rename-item",
                              L"copyto(", L"filesystem::rename"});

  return enumeratesFiles && usesCrypto && rewritesContent;
}

std::wstring QuerySigner(const std::wstring& path) {
  HCERTSTORE store = nullptr;
  HCRYPTMSG message = nullptr;
  PCCERT_CONTEXT cert = nullptr;
  DWORD encoding = 0;
  DWORD contentType = 0;
  DWORD formatType = 0;
  if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                           CERT_QUERY_CONTENT_FLAG_CTL,  // CTL: catalog (.cat) files
                       CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType, &formatType, &store, &message,
                       nullptr) == FALSE) {
    return {};
  }
  // CryptQueryObject can succeed for a CTL without returning a message.
  // CryptMsgGetParam dereferences its handle; passing nullptr crashes CRYPT32.
  if (message == nullptr || store == nullptr) {
    if (message != nullptr) {
      CryptMsgClose(message);
    }
    if (store != nullptr) {
      CertCloseStore(store, 0);
    }
    return {};
  }

  DWORD signerInfoSize = 0;
  if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) == FALSE) {
    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    return {};
  }
  std::vector<BYTE> buffer(signerInfoSize);
  if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, buffer.data(), &signerInfoSize) == FALSE) {
    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    return {};
  }
  const auto* signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(buffer.data());
  CERT_INFO info{};
  info.Issuer = signerInfo->Issuer;
  info.SerialNumber = signerInfo->SerialNumber;
  cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &info,
                                    nullptr);
  std::wstring subject;
  if (cert != nullptr) {
    const auto length = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (length > 1) {
      subject.resize(length - 1);
      CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject.data(), length);
    }
    CertFreeCertificateContext(cert);
  }
  if (message) CryptMsgClose(message);
  if (store) CertCloseStore(store, 0);
  return subject;
}

bool TrustedSigner(const std::wstring& signer) {
  const auto lower = ToLowerCopy(signer);
  static const std::array<const wchar_t*, 13> trusted = {
      L"microsoft", L"google",     L"adobe",     L"mozilla", L"intel",      L"nvidia", L"vmware",
      L"cisco",     L"oracle",     L"crowdstrike", L"eset",    L"bitdefender", L"kaspersky"};
  return std::any_of(trusted.begin(), trusted.end(),
                     [&lower](const auto* value) { return lower.find(value) != std::wstring::npos; });
}

void AddHit(std::vector<Hit>& hits, Hit hit) {
  const auto found =
      std::any_of(hits.begin(), hits.end(), [&hit](const auto& existing) { return existing.code == hit.code; });
  if (!found) {
    hits.push_back(std::move(hit));
  }
}

bool RuleApplies(const Rule& rule, const FileData& file) {
  if (rule.scope.empty() || rule.scope == L"any") {
    return true;
  }
  if (rule.scope == L"text") {
    return true;
  }
  if (rule.scope == L"ascii") {
    return true;
  }
  if (rule.scope == L"sha256" || rule.scope == L"hash") {
    return !file.sha256.empty();
  }
  if (rule.scope == L"pe") {
    return file.pe || ExecutableExt(file.extension);
  }
  if (rule.scope == L"zip") {
    return file.zip;
  }
  if (rule.scope == L"script") {
    return ScriptExt(file.extension);
  }
  if (rule.scope == L"ole") {
    return file.ole;
  }
  if (rule.scope == L"lnk") {
    return file.lnk || file.extension == L".lnk";
  }
  if (rule.scope == L"office") {
    return file.ole || file.zip ||
           file.extension == L".doc" || file.extension == L".docm" || file.extension == L".docx" ||
           file.extension == L".xls" || file.extension == L".xlsm" || file.extension == L".xlsx" ||
           file.extension == L".ppt" || file.extension == L".pptm" || file.extension == L".pptx" ||
           file.extension == L".rtf";
  }
  return true;
}

std::wstring_view RuleHaystack(const Rule& rule, const FileData& file) {
  if (rule.scope == L"ascii" || rule.scope == L"pe" || rule.scope == L"zip" || rule.scope == L"lnk") {
    return file.asciiLower;
  }
  if (rule.scope == L"sha256" || rule.scope == L"hash") {
    return file.sha256;
  }
  return file.textLower;
}

bool IsExactIndicatorRule(const Rule& rule) {
  return rule.scope == L"sha256" || rule.scope == L"hash";
}

bool ShouldApplyRuleToFile(const Rule& rule, const bool trustedSystemBinary) {
  if (!trustedSystemBinary) {
    return true;
  }

  return IsExactIndicatorRule(rule);
}

void AddRuleHits(const std::vector<Rule>& rules, const FileData& file, const PolicySnapshot& policy,
                 std::vector<Hit>& hits, const bool trustedSystemBinary) {
  for (const auto& rule : rules) {
    if (!ShouldApplyRuleToFile(rule, trustedSystemBinary)) {
      continue;
    }
    if (!RuleApplies(rule, file)) {
      continue;
    }
    const auto haystack = RuleHaystack(rule, file);
    for (const auto& pattern : rule.patterns) {
      if (Contains(haystack, pattern)) {
        AddHit(hits, Hit{rule.code, rule.message, rule.tacticId, rule.techniqueId,
                         ScaleRuleScoreForPolicy(rule, policy), IsExactIndicatorRule(rule)});
        break;
      }
    }
  }
}

std::vector<Rule> LoadExternalRules() {
  static std::mutex cacheMutex;
  static std::vector<Rule> cachedRules;
  static std::wstring cacheFingerprint;

  const auto bundlePaths = ResolveSignatureBundlePaths();
  std::wstring currentFingerprint;
  for (const auto& path : bundlePaths) {
    currentFingerprint += NormalizePathForComparison(path);
    currentFingerprint += L"|";
    std::error_code error;
    const auto writeTime = std::filesystem::last_write_time(path, error);
    if (!error) {
      currentFingerprint += std::to_wstring(writeTime.time_since_epoch().count());
    }
    currentFingerprint += L";";
  }

  std::scoped_lock lock(cacheMutex);
  if (currentFingerprint == cacheFingerprint) {
    return cachedRules;
  }

  std::vector<Rule> refreshedRules;
  for (const auto& path : bundlePaths) {
    std::ifstream input(WideToUtf8(path.wstring()), std::ios::binary);
    if (!input.is_open()) {
      continue;
    }

    std::string lineUtf8;
    while (std::getline(input, lineUtf8)) {
      const auto trimmed = TrimWide(Utf8ToWide(lineUtf8));
      if (trimmed.empty() || trimmed.starts_with(L"#") || trimmed.starts_with(L";")) {
        continue;
      }

      const auto columns = SplitColumns(trimmed, L'|');
      if (columns.size() < 7) {
        continue;
      }

      Rule rule;
      rule.scope = ToLowerCopy(columns[0]);
      rule.code = columns[1];
      rule.message = columns[2];
      rule.tacticId = columns[3];
      rule.techniqueId = columns[4];
      try {
        rule.score = std::stoi(columns[5]);
      } catch (...) {
        continue;
      }
      rule.patterns = SplitPatterns(columns[6], L';');
      if (!rule.code.empty() && !rule.patterns.empty()) {
        refreshedRules.push_back(std::move(rule));
      }
    }
  }

  cachedRules = std::move(refreshedRules);
  cacheFingerprint = std::move(currentFingerprint);

  return cachedRules;
}

std::wstring MlSensitivityFor(const PolicySnapshot& policy) {
  static std::mutex mutex;
  static std::string cachedJson;
  static std::wstring cachedSensitivity = L"balanced";
  std::lock_guard lock(mutex);
  if (policy.modulesJson != cachedJson) {
    cachedJson = policy.modulesJson;
    cachedSensitivity = policy.modulesJson.empty() ? L"balanced" : ExtendedPolicy::Parse(policy.modulesJson).mlSensitivity;
  }
  return cachedSensitivity;
}

// Adds a hit from the static ML model for portable executables. The model needs the whole file,
// so it reads up to 64 MB independently of the 1 MB content window used by the rules.
void AddMlHit(const FileData& file, const PolicySnapshot& policy, std::vector<Hit>& hits) {
  const auto sensitivity = MlSensitivityFor(policy);
  const auto modelPath = ml::DefaultModelPath();
  if (!file.pe || sensitivity == L"off" || modelPath.empty() || file.sizeBytes > 64ull * 1024 * 1024) {
    return;
  }
  const auto model = ml::LoadCached(modelPath);
  if (!model) {
    return;
  }
  std::vector<unsigned char> bytes = file.bytes;
  if (file.readLimitHit) {
    std::ifstream in(file.path, std::ios::binary);
    bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  }
  if (!ml::IsPortableExecutable(bytes)) {
    return;
  }
  const auto score = model->Score(ml::ExtractFeatures(bytes));
  const auto cut = model->ThresholdFor(sensitivity);
  const auto& thresholds = model->Thresholds();
  int weight = 0;
  if (score >= thresholds.fpr001) {
    weight = 92;
  } else if (cut && score >= *cut) {
    weight = 70;
  } else if (score >= thresholds.fpr1) {
    weight = 30;
  }
  if (weight > 0) {
    AddHit(hits, Hit{L"ML_STATIC_PE", L"The static machine-learning model classified this executable as malicious (score " +
                                          std::to_wstring(static_cast<int>(score * 100)) + L"%).",
                     L"TA0002", L"T1204.002", weight});
  }
}

std::optional<FileData> LoadFileData(const std::filesystem::path& path) {
  std::error_code error;
  if (!std::filesystem::exists(path, error) || !std::filesystem::is_regular_file(path, error)) {
    return std::nullopt;
  }
  FileData file{};
  file.path = path;
  file.sizeBytes = std::filesystem::file_size(path, error);
  file.extension = ToLowerCopy(path.extension().wstring());
  file.fileNameLower = ToLowerCopy(path.filename().wstring());
  file.bytes = ReadBytes(path);
  file.readLimitHit = file.sizeBytes > file.bytes.size();
  file.pe = file.bytes.size() >= 2 && file.bytes[0] == 'M' && file.bytes[1] == 'Z';
  file.zip = file.bytes.size() >= 4 && file.bytes[0] == 'P' && file.bytes[1] == 'K';
  file.ole = file.bytes.size() >= 8 && file.bytes[0] == 0xD0 && file.bytes[1] == 0xCF;
  file.lnk = file.bytes.size() >= 4 && file.bytes[0] == 0x4C && file.bytes[1] == 0x00;
  file.userPath = UserPath(path);
  file.trustedPath = TrustedPath(path);
  file.textLower = ToLowerCopy(DecodeText(file.bytes));
  file.asciiLower = ExtractAsciiLower(file.bytes);
  file.zipEntryNamesLower =
      file.zip ? ExtractZipEntryNamesLower(file.bytes, &file.zipMalformed, &file.zipEntryNamesTruncated)
               : std::wstring{};
  file.entropy = Entropy(file.bytes);
  file.archiveEntryCount = file.zip ? CountZipEntries(file.bytes, &file.zipEntryLimitExceeded) : 0;
  file.contentType = file.pe ? L"portable-executable" : file.zip ? L"zip-archive" : file.ole ? L"ole-document"
                              : file.lnk ? L"windows-shortcut" : ScriptExt(file.extension) ? L"script" : L"binary";
  if (file.pe || ExecutableExt(file.extension)) {
    file.signer = QuerySigner(path.wstring());
    file.signatureVerified = VerifyAuthenticodeSignature(path);
    if (!file.signatureVerified) {
      if (auto catalogSigner = VerifyCatalogSigner(path); !catalogSigner.empty()) {
        file.signer = std::move(catalogSigner);
        file.signatureVerified = true;
      }
    }
  }
  file.reputation = file.signatureVerified && !file.signer.empty() && TrustedSigner(file.signer) && file.trustedPath
                        ? L"trusted-signed-system"
                    : file.signatureVerified && !file.signer.empty() && TrustedSigner(file.signer)
                        ? L"trusted-signed"
                    : file.trustedPath                                                     ? L"trusted-path"
                    : file.userPath && file.signer.empty()                                 ? L"user-writable-unsigned"
                                                                                           : L"unknown";
  try {
    file.sha256 = ToLowerCopy(ComputeFileSha256(path));
  } catch (...) {
  }
  return file;
}

std::wstring NormalizeSuppressionValue(std::wstring value) { return ToLowerCopy(TrimWide(std::move(value))); }

bool IsDriveRootPath(const std::wstring& path) {
  return path.size() == 3 && path[1] == L':' && path[2] == L'\\';
}

std::optional<AllowOverrideMatch> MatchPolicyAllowOverride(const FileData& file, const PolicySnapshot& policy) {
  const auto highRiskUnsignedUserSurface =
      file.userPath && file.signer.empty() && IsHighRiskExecutionSurface(file);

  if (!file.sha256.empty()) {
    const auto normalizedSha256 = NormalizeSuppressionValue(file.sha256);
    for (const auto& candidate : policy.suppressionSha256) {
      if (NormalizeSuppressionValue(candidate) == normalizedSha256) {
        return AllowOverrideMatch{
            .code = L"POLICY_SUPPRESSION_SHA256",
            .message = L"Policy suppression matched an exact SHA-256 allow entry."};
      }
    }
  }

  if (!highRiskUnsignedUserSurface || policy.allowUnsignedSuppressionPathExecutables) {
    if (policy.requireSignerForSuppression && file.signer.empty()) {
      return std::nullopt;
    }

    const auto normalizedPath = NormalizePathForComparison(file.path);
    for (const auto& root : policy.suppressionPathRoots) {
      const auto normalizedRoot = NormalizePathForComparison(std::filesystem::path(root));
      if (normalizedRoot.empty() || IsDriveRootPath(normalizedRoot)) {
        continue;
      }

      if (PathIsWithinRoot(normalizedPath, normalizedRoot)) {
        return AllowOverrideMatch{
            .code = L"POLICY_SUPPRESSION_PATH_ROOT",
            .message = L"Policy suppression matched configured cleanware path root " + normalizedRoot + L"."};
      }
    }
  }

  if (!file.signer.empty() && (!file.userPath || policy.requireSignerForSuppression)) {
    const auto normalizedSigner = NormalizeSuppressionValue(file.signer);
    for (const auto& signer : policy.suppressionSignerNames) {
      if (NormalizeSuppressionValue(signer) == normalizedSigner) {
        return AllowOverrideMatch{
            .code = L"POLICY_SUPPRESSION_SIGNER",
            .message = L"Policy suppression matched signed publisher " + file.signer + L"."};
      }
    }
  }

  return std::nullopt;
}

std::wstring BuildReportedReputation(const std::wstring& internalReputation,
                                     const ReputationLookupResult& reputationLookup) {
  if (!reputationLookup.attempted) {
    return internalReputation;
  }

  std::wstring reportedReputation = internalReputation;
  if (!reportedReputation.empty()) {
    reportedReputation += L";";
  }
  reportedReputation += DescribeReputationLookup(reputationLookup);
  return reportedReputation;
}

std::wstring GuessTechnique(const FileData& file) {
  if (file.extension == L".ps1" || file.extension == L".psm1") return L"T1059.001";
  if (file.extension == L".bat" || file.extension == L".cmd") return L"T1059.003";
  if (file.extension == L".js" || file.extension == L".jse") return L"T1059.007";
  if (file.extension == L".vbs" || file.extension == L".vbe" || file.ole) return L"T1059.005";
  if (file.extension == L".hta") return L"T1218.005";
  if (file.lnk || file.extension == L".lnk") return L"T1204.001";
  return L"T1204.002";
}

std::wstring BuildAlertTitle(const ScanFinding& finding) {
  if (!finding.alertTitle.empty()) {
    return finding.alertTitle;
  }

  if (finding.originContext.attachmentOriginated) {
    return finding.verdict.disposition == VerdictDisposition::Allow ? L"Email attachment checked"
                                                                    : L"Suspicious email attachment";
  }
  if (finding.originContext.downloadOriginated || finding.originContext.browserLaunchedFile) {
    return finding.verdict.disposition == VerdictDisposition::Allow ? L"Website download checked"
                                                                    : L"Risky download from website";
  }
  return finding.verdict.disposition == VerdictDisposition::Allow ? L"File check completed" : L"Suspicious file blocked";
}

std::wstring BuildAlertSummary(const ScanFinding& finding) {
  if (!finding.alertSummary.empty()) {
    return finding.alertSummary;
  }

  const auto item = finding.path.filename().empty() ? finding.path.wstring() : finding.path.filename().wstring();
  const auto origin = BuildContentOriginLabel(finding.originContext);
  if (finding.verdict.disposition == VerdictDisposition::Allow) {
    return origin + L": " + item + L" was checked.";
  }

  if (finding.originContext.browserLaunchedFile) {
    return origin + L" tried to open " + item + L".";
  }
  return origin + L" delivered " + item + L".";
}

ScanFinding BuildAllowOverrideFindingInternal(const std::filesystem::path& path, const std::optional<FileData>& loaded,
                                              const AllowOverrideMatch& match) {
  ScanFinding finding{
      .path = path,
      .sizeBytes = loaded.has_value() ? loaded->sizeBytes : 0,
      .sha256 = loaded.has_value() ? loaded->sha256 : std::wstring{},
      .contentType = loaded.has_value() ? loaded->contentType : std::wstring{},
      .reputation = loaded.has_value() ? loaded->reputation : std::wstring{},
      .signer = loaded.has_value() ? loaded->signer : std::wstring{},
      .heuristicScore = 0,
      .archiveEntryCount = loaded.has_value() ? loaded->archiveEntryCount : 0,
      .verdict =
          ScanVerdict{
              .disposition = VerdictDisposition::Allow,
              .confidence = 100,
              .tacticId = L"",
              .techniqueId = loaded.has_value() ? GuessTechnique(*loaded) : L"",
              .reasons = {{match.code, match.message}}}};

  if (loaded.has_value() && !loaded->signer.empty()) {
    finding.verdict.reasons.push_back({L"SIGNER_CONTEXT", L"Embedded signer: " + loaded->signer});
  }

  finding.alertTitle = L"Protection policy allow";
  finding.alertSummary = L"Fenrir allowed this file because a local suppression or exclusion matched.";

  return finding;
}

}  // namespace

std::optional<ScanFinding> ScanFile(const std::filesystem::path& path, const PolicySnapshot& policy,
                                    const std::vector<std::filesystem::path>& excludedPaths,
                                    const ContentOriginContext& originContext) {
  if (IsExcludedPath(path, excludedPaths)) {
    return std::nullopt;
  }

  const auto loaded = LoadFileData(path);
  if (!loaded.has_value()) {
    return std::nullopt;
  }

  const auto& file = *loaded;
  ContentOriginContext effectiveOrigin = originContext;
  const auto trustedSystemBinary =
      IsWindowsSystemBinaryPath(file.path) && file.signatureVerified && !file.signer.empty() && TrustedSigner(file.signer);

  if (ShouldSuppressNoisyCacheFile(file)) {
    return std::nullopt;
  }
  if (MatchPolicyAllowOverride(file, policy).has_value()) {
    return std::nullopt;
  }

  std::vector<Hit> hits;
  const auto archiveText = file.zipEntryNamesLower.empty() ? file.asciiLower : file.zipEntryNamesLower + L" " + file.asciiLower;

  if (ContainsAny(file.fileNameLower, {L"eicar"}) ||
      ContainsAny(file.textLower, {L"eicar-standard-antivirus-test-file"}) ||
      ContainsAny(archiveText, {L"eicar-standard-antivirus-test-file", L"x5o!p%@ap", L"eicar.com", L"eicar.txt"})) {
    AddHit(hits, Hit{L"EICAR_TEST_SIGNATURE", L"A standard antivirus test signature was detected.", L"TA0002",
                     L"T1204.002", 99});
  }

  if ((file.pe || ExecutableExt(file.extension)) && file.userPath) {
    AddHit(hits, Hit{file.signer.empty() ? L"USER_PATH_UNSIGNED_EXECUTABLE" : L"USER_PATH_EXECUTABLE",
                     file.signer.empty() ? L"Unsigned portable executable was found in a user-controlled path."
                                         : L"Portable executable was found in a user-controlled path.",
                     L"TA0002", L"T1204.002", file.signer.empty() ? 52 : 18});
  }
  if (file.extension == L".hta") {
    AddHit(hits, Hit{L"HTA_EXECUTION_SURFACE", L"HTA content is a high-risk execution surface on Windows.", L"TA0005",
                     L"T1218.005", file.userPath ? 72 : 60});
  }
  if ((file.lnk || file.extension == L".lnk") && file.userPath) {
    AddHit(hits, Hit{L"USER_PATH_SHORTCUT", L"Shortcut content in a user-controlled path often serves as an execution lure.",
                     L"TA0002", L"T1204.001", 30});
  }
  if (file.zip && file.userPath) {
    AddHit(hits, Hit{L"USER_PATH_ARCHIVE", L"Archive content in a user-controlled path can stage payload delivery.",
                     L"TA0002", L"T1204.002", 12});
  }

  if (file.zip && file.zipMalformed) {
    AddHit(hits, Hit{L"ARCHIVE_MALFORMED_STRUCTURE",
                     L"Archive parsing detected malformed structures and fail-safe handling was applied.",
                     L"TA0005", L"T1562.001", 74});
  }

  if (file.zip && file.zipEntryLimitExceeded) {
    AddHit(hits, Hit{L"ARCHIVE_ENTRY_LIMIT_EXCEEDED",
                     L"Archive entry count exceeded parser safety limits and was treated as high risk.",
                     L"TA0005", L"T1027", 58});
  }

  if (file.zip && file.zipEntryNamesTruncated) {
    AddHit(hits, Hit{L"ARCHIVE_NAME_LIST_TRUNCATED",
                     L"Archive entry metadata exceeded parser output limits and was truncated safely.",
                     L"TA0005", L"T1027", 18});
  }

  if (file.ole && file.bytes.size() < 512) {
    AddHit(hits, Hit{L"OLE_MALFORMED_HEADER",
                     L"OLE content is shorter than the minimum structured-storage header size.",
                     L"TA0005", L"T1562.001", 62});
  }

  if ((file.lnk || file.extension == L".lnk") && file.bytes.size() < 76) {
    AddHit(hits, Hit{L"LNK_MALFORMED_HEADER",
                     L"Shortcut content is malformed and shorter than the minimum shell-link header.",
                     L"TA0005", L"T1562.001", 62});
  }

  if (file.readLimitHit && (ScriptExt(file.extension) || file.zip || file.ole || file.lnk)) {
    AddHit(hits, Hit{L"PARSER_READ_LIMIT_REACHED",
                     L"Parser read limits were reached while inspecting a high-risk content type.",
                     L"TA0005", L"T1027", 24});
  }

  if (!trustedSystemBinary) {
    if (Contains(file.textLower, L"amsiutils")) {
      AddHit(hits, Hit{L"DEFENSE_EVASION_AMSI", L"Content contains AMSI bypass or defense-evasion patterns.",
                       L"TA0005", L"T1562.001", 55});
    }

    if (Contains(file.textLower, L"frombase64string") || Contains(file.textLower, L"encodedcommand") ||
        Contains(file.textLower, L"-enc ")) {
      AddHit(hits, Hit{L"ENCODED_PAYLOAD", L"Content contains encoded payload or decode routines.", L"TA0005",
                       L"T1027", 35});
    }
    if (Contains(file.textLower, L"downloadstring") || Contains(file.textLower, L"downloadfile") ||
        Contains(file.textLower, L"invoke-webrequest") || Contains(file.textLower, L"start-bitstransfer") ||
        Contains(file.textLower, L"net.webclient")) {
      AddHit(hits, Hit{L"DOWNLOAD_CRADLE", L"Content contains network download cradle behavior.", L"TA0011",
                       L"T1105", 35});
    }
    if (Contains(file.textLower, L"invoke-expression") || Contains(file.textLower, L"iex ") ||
        Contains(file.textLower, L"iex(")) {
      AddHit(hits, Hit{L"DYNAMIC_EXECUTION", L"Content uses dynamic execution primitives.", L"TA0002",
                       L"T1059.001", 30});
    }
    if (Contains(file.textLower, L"autoopen") || Contains(file.textLower, L"document_open") ||
        Contains(file.textLower, L"workbook_open") || Contains(file.textLower, L"createobject(\"wscript.shell\")")) {
      AddHit(hits, Hit{L"OFFICE_MACRO_LAUNCH", L"Macro auto-run or shell execution patterns were found.", L"TA0002",
                       L"T1059.005", 40});
    }
    if (Contains(file.textLower, L"schtasks /create") || Contains(file.textLower, L"register-scheduledtask") ||
        Contains(file.textLower, L"new-scheduledtaskaction")) {
      AddHit(hits, Hit{L"SCHEDULED_TASK_PERSISTENCE",
                       L"Content contains scheduled-task persistence commands or helper APIs.", L"TA0003",
                       L"T1053.005", 24});
    }
    if (Contains(file.textLower, L"currentversion\\run") || Contains(file.textLower, L"\\runonce") ||
        Contains(file.textLower, L"reg add hkcu\\software\\microsoft\\windows\\currentversion\\run") ||
        Contains(file.textLower, L"reg add hklm\\software\\microsoft\\windows\\currentversion\\run")) {
      AddHit(hits, Hit{L"RUN_KEY_PERSISTENCE",
                       L"Content contains run-key persistence commands or registry paths.", L"TA0003",
                       L"T1547.001", 24});
    }
    if (Contains(file.textLower, L"sc create") || Contains(file.textLower, L"new-service") ||
        Contains(file.textLower, L"createservice")) {
      AddHit(hits, Hit{L"SERVICE_PERSISTENCE", L"Content contains service-install persistence patterns.", L"TA0003",
                       L"T1543.003", 28});
    }
    if (Contains(file.textLower, L"virtualalloc") || Contains(file.textLower, L"writeprocessmemory") ||
        Contains(file.textLower, L"createremotethread") || Contains(file.textLower, L"queueuserapc")) {
      AddHit(hits, Hit{L"PROCESS_INJECTION_API", L"Content references in-memory injection APIs.", L"TA0005",
                       L"T1055", 45});
    }
    if (Contains(file.textLower, L"wscript.shell") || Contains(file.textLower, L"shell.application") ||
        Contains(file.textLower, L"regsvr32") || Contains(file.textLower, L"mshta") ||
        Contains(file.textLower, L"rundll32")) {
      AddHit(hits, Hit{L"SCRIPT_HOST_ABUSE", L"Script host abuse patterns were detected.", L"TA0002", L"T1059", 30});
    }
  }
  if ((ScriptExt(file.extension) || file.extension == L".hta" || file.extension == L".txt" || file.extension == L".html") &&
      ContainsRecoveryInhibitionCommands(file.textLower)) {
    AddHit(hits, Hit{L"RECOVERY_INHIBITION",
                     L"Content attempts to delete shadow copies, backups, or recovery settings commonly targeted by ransomware.",
                     L"TA0040", L"T1490", 72});
  }
  if (ScriptExt(file.extension) && ContainsMassEncryptionScriptBehavior(file.textLower)) {
    AddHit(hits, Hit{L"MASS_ENCRYPTION_SCRIPT",
                     L"Script content combines file enumeration, cryptography, and rewrite operations consistent with ransomware.",
                     L"TA0040", L"T1486", 70});
  }
  if (LooksLikeRansomNoteName(file.fileNameLower) && ContainsRansomNoteLanguage(file.textLower)) {
    AddHit(hits, Hit{L"RANSOM_NOTE_ARTIFACT",
                     L"Content resembles a ransom note with file-recovery and payment instructions.", L"TA0040",
                     L"T1486", 68});
  }
  if (!trustedSystemBinary) {
    if (LongBase64(file.textLower)) {
      AddHit(hits,
             Hit{L"LONG_BASE64_BLOB", L"Content contains a long encoded payload blob.", L"TA0005", L"T1027", 30});
    }
    if (std::count(file.textLower.begin(), file.textLower.end(), L'^') >= 12 ||
        std::count(file.textLower.begin(), file.textLower.end(), L'`') >= 12) {
      AddHit(hits, Hit{L"SCRIPT_OBFUSCATION", L"Content uses common obfuscation markers.", L"TA0005", L"T1027", 28});
    }

    if (Contains(file.asciiLower, L"http://") || Contains(file.asciiLower, L"https://") ||
        Contains(file.asciiLower, L"urldownloadtofile") || Contains(file.asciiLower, L"winhttp") ||
        Contains(file.asciiLower, L"internetopenurl")) {
      AddHit(hits, Hit{L"PE_DOWNLOAD_AND_EXECUTE", L"Portable executable contains download-and-execute strings.",
                       L"TA0011", L"T1105", 35});
    }
    if (Contains(file.asciiLower, L"virtualalloc") || Contains(file.asciiLower, L"writeprocessmemory") ||
        Contains(file.asciiLower, L"createremotethread") || Contains(file.asciiLower, L"queueuserapc")) {
      AddHit(hits, Hit{L"PE_PROCESS_INJECTION", L"Portable executable contains process injection strings.", L"TA0005",
                       L"T1055", 45});
    }
    if (Contains(file.asciiLower, L"powershell") || Contains(file.asciiLower, L"rundll32") ||
        Contains(file.asciiLower, L"regsvr32") || Contains(file.asciiLower, L"mshta") ||
        Contains(file.asciiLower, L"cmd.exe") || Contains(file.asciiLower, L"wscript") ||
        Contains(file.asciiLower, L"cscript")) {
      AddHit(hits, Hit{L"PE_LOLBIN_PROXY", L"Portable executable references LOLBins often used for proxy execution.",
                       L"TA0005", L"T1218", 32});
    }
  }
  if (file.pe && file.entropy >= 7.2 && file.signer.empty()) {
    AddHit(hits, Hit{L"PE_HIGH_ENTROPY_PACKED",
                     L"Unsigned portable executable has high entropy consistent with packing or encryption.", L"TA0005",
                     L"T1027.002", 28});
  }
  if (LooksLikeEncryptedArtifact(file)) {
    AddHit(hits, Hit{L"ENCRYPTED_IMPACT_ARTIFACT",
                     L"File resembles an encrypted-impact artifact based on extension and entropy.", L"TA0040",
                     L"T1486", 52});
  }

  if (file.zip && (Contains(archiveText, L".exe") || Contains(archiveText, L".dll") ||
                   Contains(archiveText, L".scr") || Contains(archiveText, L".msi"))) {
    AddHit(hits, Hit{L"ARCHIVE_EXECUTABLE_PAYLOAD", L"Archive contains executable payload content.", L"TA0002",
                     L"T1204.002", 48});
  }
  if (file.zip && (Contains(archiveText, L".ps1") || Contains(archiveText, L".js") ||
                   Contains(archiveText, L".vbs") || Contains(archiveText, L".hta") ||
                   Contains(archiveText, L".bat") || Contains(archiveText, L".cmd"))) {
    AddHit(hits, Hit{L"ARCHIVE_SCRIPT_PAYLOAD", L"Archive contains script payload content.", L"TA0002", L"T1059",
                     45});
  }
  if (file.zip && Contains(archiveText, L".lnk")) {
    AddHit(hits, Hit{L"ARCHIVE_SHORTCUT_PAYLOAD", L"Archive contains shortcut content that can proxy execution.",
                     L"TA0002", L"T1204.001", 42});
  }
  if (file.zip && (Contains(archiveText, L".pdf.exe") || Contains(archiveText, L".doc.exe") ||
                   Contains(archiveText, L".jpg.exe"))) {
    AddHit(hits, Hit{L"ARCHIVE_DOUBLE_EXTENSION", L"Archive contains a deceptive double-extension lure.", L"TA0001",
                     L"T1566", 40});
  }
  if (file.zip && (Contains(archiveText, L".docm") || Contains(archiveText, L".xlsm") ||
                   Contains(archiveText, L".pptm"))) {
    AddHit(hits, Hit{L"ARCHIVE_MACRO_DOCUMENT", L"Archive contains macro-capable Office content.", L"TA0002",
                     L"T1204.002", 36});
  }
  if ((file.lnk || file.extension == L".lnk") &&
      (Contains(file.asciiLower, L"powershell") || Contains(file.asciiLower, L"cmd.exe") ||
       Contains(file.asciiLower, L"mshta") || Contains(file.asciiLower, L"rundll32"))) {
    AddHit(hits, Hit{L"LNK_PROXY_EXECUTION",
                     L"Shortcut content references a high-risk command interpreter or proxy binary.", L"TA0002",
                     L"T1204.001", 45});
  }

  if (file.extension == L".rtf" &&
      (Contains(file.textLower, L"\\objdata") || Contains(file.textLower, L"\\object") ||
       Contains(file.textLower, L"\\objupdate"))) {
    AddHit(hits, Hit{L"RTF_EMBEDDED_OBJECT", L"RTF content contains embedded object markers often used for payload delivery.",
                     L"TA0001", L"T1204.002", 32});
  }

  if (file.extension == L".msi" &&
      (Contains(file.asciiLower, L"customaction") || Contains(file.asciiLower, L"installexecutesequence")) &&
      (Contains(file.asciiLower, L"powershell") || Contains(file.asciiLower, L"cmd.exe") ||
       Contains(file.asciiLower, L"rundll32") || Contains(file.asciiLower, L"mshta"))) {
    AddHit(hits, Hit{L"MSI_PROXY_EXECUTION",
                     L"MSI content appears to wire a custom action into a high-risk interpreter or proxy binary.",
                     L"TA0002", L"T1218.007", 42});
  }

  if (file.userPath && file.path.wstring().find(L':', 3) != std::wstring::npos) {
    AddHit(hits, Hit{L"ALTERNATE_DATA_STREAM_PATH",
                     L"The path resembles an alternate data stream, which attackers sometimes use to hide payloads.",
                     L"TA0005", L"T1564.004", 26});
  }

  AddRuleHits(LoadExternalRules(), file, policy, hits, trustedSystemBinary);
  if (!trustedSystemBinary) {
    AddMlHit(file, policy, hits);
  }

  int maliciousPressure = 0;
  int benignPressure = 0;
  for (const auto& hit : hits) {
    if (hit.score >= 0) {
      maliciousPressure += hit.score;
    } else {
      benignPressure += std::abs(hit.score);
    }
  }

  const auto highSeverity =
      std::any_of(hits.begin(), hits.end(), [](const auto& hit) { return hit.score >= 45; });
  const auto highRiskSurface = IsHighRiskExecutionSurface(file) && file.userPath;
  const auto archiveSurface = file.zip || file.ole;

  int detectThreshold = static_cast<int>(policy.scanMaliciousBlockThreshold);
  if (highRiskSurface) {
    detectThreshold = std::max(20, detectThreshold - 8);
  }
  if (archiveSurface) {
    detectThreshold += 4;
  }
  detectThreshold = std::clamp(detectThreshold, 1, 95);

  int quarantineThreshold = static_cast<int>(policy.scanMaliciousQuarantineThreshold);
  if (highRiskSurface) {
    quarantineThreshold = std::max(detectThreshold + 4, quarantineThreshold - 4);
  }
  if (archiveSurface) {
    quarantineThreshold += 4;
  }
  quarantineThreshold = std::clamp(quarantineThreshold, detectThreshold + 1, 99);

  const auto signerLookup = policy.enableCleanwareSignerDampening && !file.signer.empty()
                                ? LookupSignerReputation(file.signer)
                                : ReputationLookupResult{};
  const auto reputationLookup = policy.cloudLookupEnabled && !file.sha256.empty()
                                    ? LookupPublicFileReputation(file.sha256)
                                    : ReputationLookupResult{};
  const auto maliciousCloudSignal =
      reputationLookup.lookupSucceeded && reputationLookup.malicious && !policy.cloudLookupObserveOnly;
  const auto exactIndicatorMatch =
      std::any_of(hits.begin(), hits.end(), [](const auto& hit) { return hit.exactIndicator; });

  if (trustedSystemBinary && !maliciousCloudSignal && !exactIndicatorMatch) {
    return std::nullopt;
  }

  if ((file.reputation == L"trusted-signed-system" || file.reputation == L"trusted-signed") && !highSeverity) {
    benignPressure += static_cast<int>(policy.scanBenignDampeningScore);
  } else if (file.reputation == L"trusted-path" && !highSeverity) {
    benignPressure += static_cast<int>(policy.scanBenignDampeningScore / 2);
  }

  if (trustedSystemBinary && !highSeverity && !maliciousCloudSignal) {
    benignPressure += static_cast<int>(policy.scanBenignDampeningScore) + 24;
    detectThreshold = std::min(95, detectThreshold + 10);
    quarantineThreshold = std::min(99, quarantineThreshold + 12);
  }

  if (policy.enableCleanwareSignerDampening && signerLookup.lookupSucceeded &&
      (signerLookup.knownGood || signerLookup.trustedSigner)) {
    benignPressure += static_cast<int>(policy.scanBenignDampeningScore) + 12;
  }

  if (policy.enableKnownGoodHashDampening && reputationLookup.lookupSucceeded && reputationLookup.knownGood) {
    benignPressure += static_cast<int>(policy.scanBenignDampeningScore) + 18;
  }

  if (maliciousCloudSignal) {
    maliciousPressure += 18;
  }

  if (file.userPath && file.signer.empty() && IsHighRiskExecutionSurface(file)) {
    maliciousPressure += 8;
  }

  for (const auto& originSignal : CollectContentOriginSignals(effectiveOrigin, path)) {
    AddHit(hits, Hit{originSignal.code, originSignal.message, L"TA0001",
                     effectiveOrigin.attachmentOriginated ? L"T1566.001" : L"T1204.002", originSignal.score});
    if (originSignal.score >= 0) {
      maliciousPressure += originSignal.score;
    } else {
      benignPressure += std::abs(originSignal.score);
    }
  }

  const auto netPressure = std::clamp(maliciousPressure - benignPressure, 0, 99);
  const auto shouldSurfaceFinding = netPressure >= detectThreshold ||
                                    (highSeverity && maliciousPressure >= detectThreshold);
  if (!shouldSurfaceFinding) {
    return std::nullopt;
  }

  const auto top =
      std::max_element(hits.begin(), hits.end(),
                       [](const auto& left, const auto& right) { return left.score < right.score; });
  const auto quarantineCandidate =
      file.pe || ExecutableExt(file.extension) || file.ole || file.zip || file.extension == L".hta";
  const auto trustedCleanware = (policy.enableCleanwareSignerDampening && signerLookup.lookupSucceeded &&
                                 (signerLookup.knownGood || signerLookup.trustedSigner)) ||
                                (policy.enableKnownGoodHashDampening && reputationLookup.lookupSucceeded &&
                                 reputationLookup.knownGood);

  auto reportedReputation = BuildReportedReputation(file.reputation, signerLookup);
  reportedReputation = BuildReportedReputation(reportedReputation, reputationLookup);

  auto disposition = VerdictDisposition::Block;
  if (trustedCleanware && netPressure < quarantineThreshold) {
    disposition = VerdictDisposition::Allow;
  }
  if (policy.archiveObserveOnly && archiveSurface && netPressure < quarantineThreshold) {
    disposition = VerdictDisposition::Allow;
  }

  if (policy.cloudLookupObserveOnly && reputationLookup.lookupSucceeded && reputationLookup.malicious &&
      disposition == VerdictDisposition::Block && !highSeverity) {
    disposition = VerdictDisposition::Allow;
  }
  if (trustedSystemBinary && !highSeverity && !maliciousCloudSignal && disposition == VerdictDisposition::Block &&
      netPressure < (quarantineThreshold + 8)) {
    disposition = VerdictDisposition::Allow;
  }
  // Quarantine only at the policy's quarantine score or on hard evidence (a known-malicious hash or signature, or a
  // malicious cloud verdict). A moderate heuristic score is reported for review and the file is left alone: on clean
  // machines those are mostly unsigned installers, admin tools and scripts.
  if (disposition == VerdictDisposition::Block && quarantineCandidate &&
      (netPressure >= quarantineThreshold || exactIndicatorMatch || maliciousCloudSignal)) {
    disposition = VerdictDisposition::Quarantine;
  }

  ScanFinding finding{
      .path = file.path,
      .sizeBytes = file.sizeBytes,
      .sha256 = file.sha256,
      .contentType = file.contentType,
      .reputation = reportedReputation,
      .signer = file.signer,
      .heuristicScore = static_cast<std::uint32_t>(netPressure),
      .archiveEntryCount = file.archiveEntryCount,
      .verdict =
          ScanVerdict{
              .disposition = disposition,
              .confidence = static_cast<std::uint32_t>(std::clamp(std::max(netPressure, maliciousPressure / 2), 1, 99)),
              .tacticId = top != hits.end() ? top->tacticId : L"TA0002",
              .techniqueId = top != hits.end() ? top->techniqueId : GuessTechnique(file),
              .reasons = {}},
      .originContext = effectiveOrigin};

  if (signerLookup.attempted) {
    finding.verdict.reasons.push_back(
        {signerLookup.knownGood || signerLookup.trustedSigner ? L"SIGNER_REPUTATION_VERIFIED" : L"SIGNER_REPUTATION_LOOKUP",
         signerLookup.summary.empty() ? L"Signer reputation lookup completed." : signerLookup.summary});
  }
  if (reputationLookup.attempted) {
    finding.verdict.reasons.push_back({
        reputationLookup.knownGood ? L"REPUTATION_VERIFIED"
                                   : (policy.cloudLookupObserveOnly && reputationLookup.malicious
                                          ? L"REPUTATION_OBSERVE_ONLY"
                                          : L"REPUTATION_LOOKUP"),
        reputationLookup.summary.empty() ? L"File reputation lookup completed." : reputationLookup.summary});
  }

  finding.verdict.reasons.push_back(
      {L"CONFIDENCE_PRESSURE_BALANCE",
       L"Malicious pressure " + std::to_wstring(maliciousPressure) + L", benign pressure " +
           std::to_wstring(benignPressure) + L", net " + std::to_wstring(netPressure) + L"."});

  for (const auto& hit : hits) {
    if (hit.score > 0 || disposition != VerdictDisposition::Block) {
      finding.verdict.reasons.push_back({hit.code, hit.message});
    }
  }
  if (finding.sha256.empty()) {
    finding.verdict.reasons.push_back(
        {L"HASH_UNAVAILABLE", L"SHA-256 computation failed, so the finding is based on content and path heuristics."});
  }
  if (!file.signer.empty()) {
    finding.verdict.reasons.push_back({L"SIGNER_CONTEXT", L"Embedded signer: " + file.signer});
  }
  if (finding.verdict.disposition == VerdictDisposition::Allow && trustedCleanware) {
    finding.verdict.reasons.push_back(
        {L"CLEANWARE_DAMPENING", L"Fenrir reduced confidence because trusted signer/hash cleanware intelligence matched."});
  }
  if (finding.verdict.disposition == VerdictDisposition::Allow && trustedSystemBinary) {
    finding.verdict.reasons.push_back(
        {L"SYSTEM32_TRUST_DAMPENING",
         L"Fenrir reduced confidence for a trusted signed Windows system binary in System32/SysWOW64."});
  }
  if (finding.verdict.disposition == VerdictDisposition::Allow && policy.archiveObserveOnly && archiveSurface) {
    finding.verdict.reasons.push_back(
        {L"ARCHIVE_OBSERVE_ONLY", L"Archive policy is observe-only for this confidence tier."});
  }
  if (finding.verdict.disposition == VerdictDisposition::Quarantine) {
    finding.verdict.reasons.push_back({L"BLOCK_FIRST",
                                       L"Fenrir blocked this item immediately and can quarantine it during remediation."});
  } else if (finding.verdict.disposition == VerdictDisposition::Block) {
    finding.verdict.reasons.push_back({L"REPORT_ONLY_SCORE",
                                       L"The score is below the quarantine threshold and nothing known-malicious matched, so "
                                       L"Fenrir reports this file for review and leaves it in place."});
  }
  finding.alertTitle = BuildAlertTitle(finding);
  finding.alertSummary = BuildAlertSummary(finding);
  return finding;
}

std::optional<ScanFinding> ScanFile(const std::filesystem::path& path, const PolicySnapshot& policy,
                                    const std::vector<std::filesystem::path>& excludedPaths) {
  return ScanFile(path, policy, excludedPaths, {});
}

std::optional<ScanFinding> ScanFile(const std::filesystem::path& path, const PolicySnapshot& policy) {
  return ScanFile(path, policy, {}, {});
}

std::optional<ScanFinding> BuildAllowOverrideFinding(const std::filesystem::path& path, const PolicySnapshot& policy,
                                                     const std::vector<std::filesystem::path>& excludedPaths) {
  if (IsExcludedPath(path, excludedPaths)) {
    return BuildAllowOverrideFindingInternal(
        path, LoadFileData(path),
        AllowOverrideMatch{.code = L"EXCLUDED_PATH",
                           .message = L"The target path is inside a configured Fenrir exclusion root."});
  }

  const auto normalizedPath = NormalizePathForComparison(path);
  bool suppressionPathCandidate = false;
  for (const auto& root : policy.suppressionPathRoots) {
    const auto normalizedRoot = NormalizePathForComparison(std::filesystem::path(root));
    if (normalizedRoot.empty() || IsDriveRootPath(normalizedRoot)) {
      continue;
    }

    if (PathIsWithinRoot(normalizedPath, normalizedRoot)) {
      suppressionPathCandidate = true;
      break;
    }
  }

  const auto requiresLoadedInspection =
      IsNoisyCachePath(path) || suppressionPathCandidate || !policy.suppressionSha256.empty() ||
      !policy.suppressionSignerNames.empty();
  if (!requiresLoadedInspection) {
    return std::nullopt;
  }

  const auto loaded = LoadFileData(path);
  if (!loaded.has_value()) {
    return std::nullopt;
  }

  if (ShouldSuppressNoisyCacheFile(*loaded)) {
    return BuildAllowOverrideFindingInternal(
        path, loaded,
        AllowOverrideMatch{.code = L"NOISY_CACHE_SUPPRESSION",
                           .message = L"Fenrir skipped a known noisy cache artifact outside high-risk execution surfaces."});
  }

  if (const auto match = MatchPolicyAllowOverride(*loaded, policy); match.has_value()) {
    return BuildAllowOverrideFindingInternal(path, loaded, *match);
  }

  return std::nullopt;
}

std::optional<ScanFinding> BuildAllowOverrideFinding(const std::filesystem::path& path, const PolicySnapshot& policy) {
  return BuildAllowOverrideFinding(path, policy, {});
}

std::vector<ScanFinding> ScanTargets(const std::vector<std::filesystem::path>& targets, const PolicySnapshot& policy,
                                     const ScanProgressCallback& progressCallback) {
  return ScanTargets(targets, policy, progressCallback, {});
}

std::vector<ScanFinding> ScanTargets(const std::vector<std::filesystem::path>& targets, const PolicySnapshot& policy) {
  return ScanTargets(targets, policy, ScanProgressCallback{}, {});
}

std::vector<ScanFinding> ScanTargets(const std::vector<std::filesystem::path>& targets, const PolicySnapshot& policy,
                                     const ScanProgressCallback& progressCallback,
                                     const std::vector<std::filesystem::path>& excludedPaths) {
  std::vector<std::filesystem::path> files;
  for (const auto& target : targets) {
    command_control::Check();
    std::error_code error;
    if (IsExcludedPath(target, excludedPaths)) {
      continue;
    }

    if (std::filesystem::is_regular_file(target, error)) {
      files.push_back(target);
      continue;
    }

    error.clear();
    if (!std::filesystem::is_directory(target, error)) {
      continue;
    }

    for (std::filesystem::recursive_directory_iterator iterator(
             target, std::filesystem::directory_options::skip_permission_denied, error);
         iterator != std::filesystem::recursive_directory_iterator(); iterator.increment(error)) {
      command_control::Check();
      if (error) {
        error.clear();
        continue;
      }

      const auto entryPath = iterator->path();
      if (IsExcludedPath(entryPath, excludedPaths)) {
        if (iterator->is_directory(error)) {
          iterator.disable_recursion_pending();
        }
        if (error) {
          error.clear();
        }
        continue;
      }

      if (iterator->is_regular_file(error)) {
        files.push_back(entryPath);
      }

      if (error) {
        error.clear();
      }
    }
  }

  std::sort(files.begin(), files.end());
  files.erase(std::unique(files.begin(), files.end()), files.end());

  std::vector<ScanFinding> findings;
  for (std::size_t index = 0; index < files.size(); ++index) {
    const auto& file = files[index];
    if (progressCallback) {
      progressCallback(ScanProgressUpdate{
          .completedTargets = index,
          .totalTargets = files.size(),
          .findingCount = findings.size(),
          .currentPath = file,
      });
    }

    if (const auto finding = ScanFile(file, policy, excludedPaths); finding.has_value()) {
      findings.push_back(*finding);
    }
  }

  if (progressCallback) {
    progressCallback(ScanProgressUpdate{
        .completedTargets = files.size(),
        .totalTargets = files.size(),
        .findingCount = findings.size(),
        .currentPath = {},
    });
  }

  std::sort(findings.begin(), findings.end(),
            [](const ScanFinding& left, const ScanFinding& right) { return left.path < right.path; });
  return findings;
}

std::wstring VerdictDispositionToString(const VerdictDisposition disposition) {
  switch (disposition) {
    case VerdictDisposition::Allow:
      return L"allow";
    case VerdictDisposition::Block:
      return L"block";
    case VerdictDisposition::Quarantine:
      return L"quarantine";
    case VerdictDisposition::Unknown:
    default:
      return L"unknown";
  }
}

std::wstring RemediationStatusToString(const RemediationStatus status) {
  switch (status) {
    case RemediationStatus::Quarantined:
      return L"quarantined";
    case RemediationStatus::Failed:
      return L"failed";
    case RemediationStatus::None:
    default:
      return L"none";
  }
}

TelemetryRecord BuildScanFindingTelemetry(const ScanFinding& finding, const std::wstring& source) {
  const auto disposition = VerdictDispositionToString(finding.verdict.disposition);
  const auto techniqueId = finding.verdict.techniqueId.empty() ? L"unknown" : finding.verdict.techniqueId;
  const auto remediationStatus = RemediationStatusToString(finding.remediationStatus);
  const auto alertTitle = BuildAlertTitle(finding);
  const auto alertSummary = BuildAlertSummary(finding);

  std::wstring summary = alertTitle + L": " + alertSummary;

  std::wstring payload = L"{\"path\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.path.wstring()));
  payload += L"\",\"sizeBytes\":";
  payload += std::to_wstring(finding.sizeBytes);
  payload += L",\"sha256\":\"";
  payload += finding.sha256;
  payload += L"\",\"contentType\":\"";
  payload += finding.contentType;
  payload += L"\",\"reputation\":\"";
  payload += finding.reputation;
  payload += L"\",\"signer\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.signer));
  payload += L"\",\"heuristicScore\":";
  payload += std::to_wstring(finding.heuristicScore);
  payload += L",\"archiveEntryCount\":";
  payload += std::to_wstring(finding.archiveEntryCount);
  payload += L",\"remediationStatus\":\"";
  payload += remediationStatus;
  payload += L"\"";
  payload += L",\"disposition\":\"";
  payload += disposition;
  payload += L"\",\"tacticId\":\"";
  payload += finding.verdict.tacticId;
  payload += L"\",\"techniqueId\":\"";
  payload += techniqueId;
  payload += L"\",\"quarantineRecordId\":\"";
  payload += finding.quarantineRecordId;
  payload += L"\",\"evidenceRecordId\":\"";
  payload += finding.evidenceRecordId;
  payload += L"\",\"quarantinedPath\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.quarantinedPath.wstring()));
  payload += L"\",\"remediationError\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.remediationError));
  payload += L"\",\"alertTitle\":\"";
  payload += Utf8ToWide(EscapeJsonString(alertTitle));
  payload += L"\",\"alertSummary\":\"";
  payload += Utf8ToWide(EscapeJsonString(alertSummary));
  payload += L"\",\"contextType\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.originContext.channel));
  payload += L"\",\"originLabel\":\"";
  payload += Utf8ToWide(EscapeJsonString(BuildContentOriginLabel(finding.originContext)));
  payload += L"\",\"originContext\":";
  payload += SerializeContentOriginContext(finding.originContext);
  payload += L"}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"scan.finding",
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

TelemetryRecord BuildScanSummaryTelemetry(const std::size_t targetCount, const std::size_t findingCount,
                                          const PolicySnapshot& policy, const std::wstring& source) {
  std::wstring summary;
  if (findingCount == 0) {
    summary = L"On-demand scan completed without suspicious findings.";
  } else {
    summary = L"On-demand scan completed with ";
    summary += std::to_wstring(findingCount);
    summary += L" suspicious finding(s).";
  }

  std::wstring payload = L"{\"targetCount\":";
  payload += std::to_wstring(targetCount);
  payload += L",\"findingCount\":";
  payload += std::to_wstring(findingCount);
  payload += L",\"policyRevision\":\"";
  payload += policy.revision;
  payload += L"\"}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"scan.completed",
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

}  // namespace antivirus::agent
