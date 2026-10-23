#include "QuarantineStore.h"

#include <Windows.h>
#include <aclapi.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

std::string EscapeRegex(const std::string& value) {
  std::string escaped;
  escaped.reserve(value.size() * 2);

  for (const auto ch : value) {
    switch (ch) {
      case '\\':
      case '^':
      case '$':
      case '.':
      case '|':
      case '?':
      case '*':
      case '+':
      case '(':
      case ')':
      case '[':
      case ']':
      case '{':
      case '}':
        escaped.push_back('\\');
        break;
      default:
        break;
    }

    escaped.push_back(ch);
  }

  return escaped;
}

std::string UnescapeJsonString(const std::string& value) {
  std::string result;
  result.reserve(value.size());

  bool escaping = false;
  for (const auto ch : value) {
    if (!escaping) {
      if (ch == '\\') {
        escaping = true;
      } else {
        result.push_back(ch);
      }
      continue;
    }

    switch (ch) {
      case '\\':
        result.push_back('\\');
        break;
      case '"':
        result.push_back('"');
        break;
      case 'n':
        result.push_back('\n');
        break;
      case 'r':
        result.push_back('\r');
        break;
      case 't':
        result.push_back('\t');
        break;
      default:
        result.push_back(ch);
        break;
    }

    escaping = false;
  }

  if (escaping) {
    result.push_back('\\');
  }

  return result;
}

std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return UnescapeJsonString(match[1].str());
  }

  return std::nullopt;
}

std::optional<std::uintmax_t> ExtractJsonNumber(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return static_cast<std::uintmax_t>(std::stoull(match[1].str()));
  }

  return std::nullopt;
}

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool ParseBooleanValue(const std::wstring& rawValue, const bool fallback) {
  if (rawValue.empty()) {
    return fallback;
  }

  const auto lower = ToLowerCopy(rawValue);
  if (lower == L"1" || lower == L"true" || lower == L"yes" || lower == L"on") {
    return true;
  }
  if (lower == L"0" || lower == L"false" || lower == L"no" || lower == L"off") {
    return false;
  }

  return fallback;
}

int ParsePositiveInt(const std::wstring& rawValue, const int fallback) {
  if (rawValue.empty()) {
    return fallback;
  }

  try {
    const auto parsed = std::stoi(rawValue);
    return std::max(parsed, 1);
  } catch (...) {
    return fallback;
  }
}

std::uintmax_t MegabytesToBytes(const int megabytes) {
  return static_cast<std::uintmax_t>(std::max(megabytes, 1)) * 1024ull * 1024ull;
}

std::uintmax_t ResolveQuarantineQuotaBytes() {
  const auto quotaMb = ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_STORAGE_QUOTA_QUARANTINE_MB"), 2048);
  return MegabytesToBytes(quotaMb);
}

std::uintmax_t ComputePathSizeBytes(const std::filesystem::path& path) {
  std::error_code error;
  if (!std::filesystem::exists(path, error) || error) {
    return 0;
  }

  if (std::filesystem::is_regular_file(path, error) && !error) {
    const auto fileSize = std::filesystem::file_size(path, error);
    return error ? 0 : fileSize;
  }

  std::uintmax_t total = 0;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(path, error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (entry.is_regular_file(error) && !error) {
      const auto size = entry.file_size(error);
      if (!error) {
        total += size;
      } else {
        error.clear();
      }
    } else {
      error.clear();
    }
  }

  return total;
}

std::filesystem::path BuildQuarantineFilePath(const std::filesystem::path& rootPath, const std::wstring& recordId,
                                              const std::filesystem::path& originalPath) {
  const auto extension = originalPath.extension().wstring();
  const auto fileName = extension.empty() ? recordId + L".quarantine" : recordId + extension + L".quarantine";
  return rootPath / L"files" / fileName;
}

void WriteMetadata(const std::filesystem::path& rootPath, const std::wstring& recordId, const ScanFinding& finding,
                   const std::filesystem::path& quarantinedPath, const std::wstring& localStatus) {
  const auto metadataDirectory = rootPath / L"records";
  std::filesystem::create_directories(metadataDirectory);

  const auto metadataPath = metadataDirectory / (recordId + L".json");
  std::ofstream output(metadataPath, std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("Unable to write quarantine metadata");
  }

  output << "{\n";
  output << "  \"recordId\": \"" << EscapeJsonString(recordId) << "\",\n";
  output << "  \"capturedAt\": \"" << EscapeJsonString(CurrentUtcTimestamp()) << "\",\n";
  output << "  \"originalPath\": \"" << EscapeJsonString(finding.path.wstring()) << "\",\n";
  output << "  \"quarantinedPath\": \"" << EscapeJsonString(quarantinedPath.wstring()) << "\",\n";
  output << "  \"sha256\": \"" << EscapeJsonString(finding.sha256) << "\",\n";
  output << "  \"sizeBytes\": " << finding.sizeBytes << ",\n";
  output << "  \"disposition\": \"" << EscapeJsonString(VerdictDispositionToString(finding.verdict.disposition))
         << "\",\n";
  output << "  \"techniqueId\": \"" << EscapeJsonString(finding.verdict.techniqueId) << "\",\n";
  output << "  \"localStatus\": \"" << EscapeJsonString(localStatus) << "\"\n";
  output << "}\n";
}

void WriteMetadata(const std::filesystem::path& rootPath, const QuarantineEntry& entry) {
  const auto metadataDirectory = rootPath / L"records";
  std::filesystem::create_directories(metadataDirectory);

  const auto metadataPath = metadataDirectory / (entry.recordId + L".json");
  std::ofstream output(metadataPath, std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("Unable to write quarantine metadata");
  }

  output << "{\n";
  output << "  \"recordId\": \"" << EscapeJsonString(entry.recordId) << "\",\n";
  output << "  \"capturedAt\": \"" << EscapeJsonString(CurrentUtcTimestamp()) << "\",\n";
  output << "  \"originalPath\": \"" << EscapeJsonString(entry.originalPath.wstring()) << "\",\n";
  output << "  \"quarantinedPath\": \"" << EscapeJsonString(entry.quarantinedPath.wstring()) << "\",\n";
  output << "  \"sha256\": \"" << EscapeJsonString(entry.sha256) << "\",\n";
  output << "  \"sizeBytes\": " << entry.sizeBytes << ",\n";
  output << "  \"techniqueId\": \"" << EscapeJsonString(entry.techniqueId) << "\",\n";
  output << "  \"localStatus\": \"" << EscapeJsonString(entry.localStatus) << "\"\n";
  output << "}\n";
}

std::string ReadMetadataFile(const std::filesystem::path& metadataPath) {
  std::ifstream input(metadataPath);
  if (!input.is_open()) {
    throw std::runtime_error("Unable to open quarantine metadata");
  }

  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

std::filesystem::path ResolveDatabasePath(const std::filesystem::path& rootPath, const std::filesystem::path& databasePath) {
  if (!databasePath.empty()) {
    return databasePath;
  }

  return rootPath.parent_path() / L"agent-runtime.db";
}

bool IsAlternateDataStreamPath(const std::filesystem::path& path) {
  const auto value = path.wstring();
  const auto firstColon = value.find(L':');
  if (firstColon == std::wstring::npos) {
    return false;
  }

  if (firstColon != 1) {
    return true;
  }

  return value.find(L':', firstColon + 1) != std::wstring::npos;
}

bool IsPathWithinRoot(const std::filesystem::path& candidate, const std::filesystem::path& root) {
  std::error_code error;
  auto normalizedCandidate = std::filesystem::absolute(candidate, error).lexically_normal().wstring();
  if (error) {
    return false;
  }
  auto normalizedRoot = std::filesystem::absolute(root, error).lexically_normal().wstring();
  if (error) {
    return false;
  }

  normalizedCandidate = ToLowerCopy(normalizedCandidate);
  normalizedRoot = ToLowerCopy(normalizedRoot);
  if (!normalizedRoot.empty() && normalizedRoot.back() != L'\\' && normalizedRoot.back() != L'/') {
    normalizedRoot.push_back(L'\\');
  }

  return normalizedCandidate == normalizedRoot.substr(0, normalizedRoot.size() - 1) ||
         normalizedCandidate.starts_with(normalizedRoot);
}

bool PathContainsReparsePoint(const std::filesystem::path& path) {
  if (path.empty()) {
    return false;
  }

  std::error_code error;
  auto current = std::filesystem::absolute(path, error).lexically_normal();
  if (error) {
    return false;
  }

  for (;;) {
    const auto attributes = GetFileAttributesW(current.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
      return true;
    }

    if (!current.has_parent_path() || current == current.root_path()) {
      break;
    }

    const auto parent = current.parent_path();
    if (parent == current) {
      break;
    }

    current = parent;
  }

  return false;
}

bool IsRestoreEligibleStatus(const std::wstring& status) {
  const auto lowerStatus = ToLowerCopy(status);
  return lowerStatus.starts_with(L"quarantined");
}

std::optional<std::wstring> ValidateRestoreDestination(const std::filesystem::path& originalPath) {
  if (originalPath.empty()) {
    return L"Restore target path is missing from quarantine metadata.";
  }

  if (!originalPath.is_absolute()) {
    return L"Restore target path must be absolute.";
  }

  if (IsAlternateDataStreamPath(originalPath)) {
    return L"Restore target path contains an alternate data stream and is blocked by policy.";
  }

  if (PathContainsReparsePoint(originalPath.parent_path())) {
    return L"Restore target path traverses a reparse point and is blocked by policy.";
  }

  const auto allowSystemRestore =
      ParseBooleanValue(ReadEnvironmentVariable(L"ANTIVIRUS_ALLOW_SYSTEM_RESTORE"), false);
  if (!allowSystemRestore) {
    const auto windowsRoot = ReadEnvironmentVariable(L"WINDIR");
    const auto programFiles = ReadEnvironmentVariable(L"ProgramFiles");
    const auto programFilesX86 = ReadEnvironmentVariable(L"ProgramFiles(x86)");
    const auto target = std::filesystem::path(originalPath);

    if ((!windowsRoot.empty() && IsPathWithinRoot(target, windowsRoot)) ||
        (!programFiles.empty() && IsPathWithinRoot(target, programFiles)) ||
        (!programFilesX86.empty() && IsPathWithinRoot(target, programFilesX86))) {
      return L"Restore target path is inside a protected system location and requires explicit override.";
    }
  }

  return std::nullopt;
}

std::filesystem::path BuildAlternateRestoreTarget(const std::filesystem::path& originalPath) {
  const auto fileName = originalPath.filename().wstring();
  const auto stem = originalPath.stem().wstring();
  const auto extension = originalPath.extension().wstring();
  const auto suffix = stem.empty() ? fileName : stem;
  return originalPath.parent_path() /
         (suffix + L".fenrir-restored-" + GenerateGuidString() + (extension.empty() ? L"" : extension));
}

bool SecureDeleteRegularFile(const std::filesystem::path& path, const int passes) {
  if (passes <= 0) {
    return true;
  }

  std::error_code error;
  if (!std::filesystem::exists(path, error) || error || !std::filesystem::is_regular_file(path, error)) {
    return true;
  }

  const auto fileHandle = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
  if (fileHandle == INVALID_HANDLE_VALUE) {
    return false;
  }

  LARGE_INTEGER size{};
  if (GetFileSizeEx(fileHandle, &size) == FALSE || size.QuadPart < 0) {
    CloseHandle(fileHandle);
    return false;
  }

  std::vector<char> zeroBuffer(64 * 1024, 0);
  for (int pass = 0; pass < passes; ++pass) {
    LARGE_INTEGER seek{};
    if (SetFilePointerEx(fileHandle, seek, nullptr, FILE_BEGIN) == FALSE) {
      CloseHandle(fileHandle);
      return false;
    }

    auto remaining = static_cast<std::uint64_t>(size.QuadPart);
    while (remaining > 0) {
      const auto toWrite = static_cast<DWORD>(std::min<std::uint64_t>(remaining, zeroBuffer.size()));
      DWORD bytesWritten = 0;
      if (WriteFile(fileHandle, zeroBuffer.data(), toWrite, &bytesWritten, nullptr) == FALSE || bytesWritten != toWrite) {
        CloseHandle(fileHandle);
        return false;
      }
      remaining -= bytesWritten;
    }
    FlushFileBuffers(fileHandle);
  }

  CloseHandle(fileHandle);
  return true;
}

bool ScheduleDeleteOnReboot(const std::filesystem::path& path) {
  return MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE;
}

bool CreateKnownSid(const WELL_KNOWN_SID_TYPE type, std::array<BYTE, SECURITY_MAX_SID_SIZE>& buffer, PSID* sid) {
  DWORD size = static_cast<DWORD>(buffer.size());
  if (CreateWellKnownSid(type, nullptr, buffer.data(), &size) == FALSE) {
    return false;
  }

  *sid = buffer.data();
  return true;
}

bool LockDownPathForSystemOnly(const std::filesystem::path& path) {
  std::array<BYTE, SECURITY_MAX_SID_SIZE> systemBuffer{};
  PSID systemSid = nullptr;
  if (!CreateKnownSid(WinLocalSystemSid, systemBuffer, &systemSid)) {
    return false;
  }

  EXPLICIT_ACCESSW systemAccess{};
  systemAccess.grfAccessPermissions = GENERIC_ALL;
  systemAccess.grfAccessMode = SET_ACCESS;
  systemAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  systemAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  systemAccess.Trustee.TrusteeType = TRUSTEE_IS_USER;
  systemAccess.Trustee.ptstrName = static_cast<LPWSTR>(systemSid);

  PACL acl = nullptr;
  const auto aclStatus = SetEntriesInAclW(1, &systemAccess, nullptr, &acl);
  if (aclStatus != ERROR_SUCCESS) {
    return false;
  }

  const auto securityStatus = SetNamedSecurityInfoW(
      const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
  LocalFree(acl);
  return securityStatus == ERROR_SUCCESS;
}

struct NeutralizationVerification {
  bool neutralized{false};
  bool originalPresent{false};
  std::wstring localStatus;
  std::wstring detail;
};

std::mutex gQuarantineJournalMutex;

bool CanOpenForExecution(const std::filesystem::path& path) {
  const HANDLE handle =
      CreateFileW(path.c_str(), FILE_EXECUTE | FILE_READ_ATTRIBUTES,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return false;
  }

  CloseHandle(handle);
  return true;
}

NeutralizationVerification VerifyNeutralizationState(const std::filesystem::path& originalPath,
                                                     const std::wstring& currentStatus) {
  std::error_code existsError;
  const bool originalPresent = std::filesystem::exists(originalPath, existsError);
  if (existsError) {
    return NeutralizationVerification{
        .neutralized = false,
        .originalPresent = true,
        .localStatus = L"quarantined-verification-error",
        .detail = L"Fenrir could not verify the original path after quarantine."};
  }

  if (!originalPresent) {
    return NeutralizationVerification{
        .neutralized = true,
        .originalPresent = false,
        .localStatus = L"quarantined-verified-removed",
        .detail = L"Original artifact removed from the source path."};
  }

  if (_wcsicmp(currentStatus.c_str(), L"quarantined-pending-delete") == 0) {
    return NeutralizationVerification{
        .neutralized = true,
        .originalPresent = true,
        .localStatus = L"quarantined-pending-delete",
        .detail = L"Original artifact remains on disk until the scheduled reboot deletion executes."};
  }

  if (_wcsicmp(currentStatus.c_str(), L"quarantined-locked") == 0) {
    if (!CanOpenForExecution(originalPath)) {
      return NeutralizationVerification{
          .neutralized = true,
          .originalPresent = true,
          .localStatus = L"quarantined-verified-locked",
          .detail = L"Original artifact path remains but execution access is blocked by lockdown."};
    }

    return NeutralizationVerification{
        .neutralized = false,
        .originalPresent = true,
        .localStatus = L"quarantined-locked-unverified",
        .detail = L"Original artifact is still executable after lockdown and requires additional remediation."};
  }

  if (ScheduleDeleteOnReboot(originalPath)) {
    return NeutralizationVerification{
        .neutralized = true,
        .originalPresent = true,
        .localStatus = L"quarantined-pending-delete",
        .detail = L"Original artifact was still present; Fenrir scheduled delete-on-reboot."};
  }

  return NeutralizationVerification{
      .neutralized = false,
      .originalPresent = true,
      .localStatus = L"quarantined-original-still-present",
      .detail = L"Original artifact is still present after quarantine and no delete-on-reboot fallback was applied."};
}

void AppendQuarantineJournalEntry(const std::filesystem::path& rootPath, const std::wstring& action,
                                  const std::wstring& recordId, const std::filesystem::path& originalPath,
                                  const std::filesystem::path& quarantinedPath, const std::wstring& localStatus,
                                  const bool success, const std::wstring& detail) {
  const std::scoped_lock lock(gQuarantineJournalMutex);

  std::error_code createError;
  const auto recordsDirectory = rootPath / L"records";
  std::filesystem::create_directories(recordsDirectory, createError);
  if (createError) {
    return;
  }

  std::ofstream output(recordsDirectory / L"quarantine-journal.jsonl", std::ios::binary | std::ios::app);
  if (!output.is_open()) {
    return;
  }

  const std::wstring line = L"{\"recordedAt\":\"" + CurrentUtcTimestamp() + L"\",\"action\":\"" +
                            Utf8ToWide(EscapeJsonString(action)) + L"\",\"recordId\":\"" +
                            Utf8ToWide(EscapeJsonString(recordId)) + L"\",\"originalPath\":\"" +
                            Utf8ToWide(EscapeJsonString(originalPath.wstring())) + L"\",\"quarantinedPath\":\"" +
                            Utf8ToWide(EscapeJsonString(quarantinedPath.wstring())) + L"\",\"localStatus\":\"" +
                            Utf8ToWide(EscapeJsonString(localStatus)) + L"\",\"success\":" +
                            (success ? L"true" : L"false") + L",\"detail\":\"" +
                            Utf8ToWide(EscapeJsonString(detail)) + L"\"}\n";
  const auto utf8Line = WideToUtf8(line);
  output.write(utf8Line.data(), static_cast<std::streamsize>(utf8Line.size()));
}

}  // namespace

QuarantineStore::QuarantineStore(std::filesystem::path rootPath, std::filesystem::path databasePath)
    : rootPath_(std::move(rootPath)), databasePath_(ResolveDatabasePath(rootPath_, databasePath)) {}

namespace {

std::wstring LowerFolder(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  std::replace(value.begin(), value.end(), L'/', L'\\');
  while (!value.empty() && value.back() == L'\\') {
    value.pop_back();
  }
  return value.empty() ? value : value + L"\\";
}

std::wstring EnvironmentFolder(const wchar_t* name) {
  wchar_t buffer[MAX_PATH]{};
  const auto length = GetEnvironmentVariableW(name, buffer, MAX_PATH);
  return length > 0 && length < MAX_PATH ? LowerFolder(buffer) : std::wstring{};
}

std::wstring ModuleFolder() {
  wchar_t buffer[MAX_PATH]{};
  const auto length = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
  if (length == 0 || length >= MAX_PATH) {
    return {};
  }
  return LowerFolder(std::filesystem::path(buffer).parent_path().wstring());
}

}  // namespace

bool IsProtectedSystemLocation(const std::filesystem::path& path, const std::filesystem::path& extraRoot) {
  std::vector<std::wstring> roots;
  wchar_t windowsDirectory[MAX_PATH]{};
  const auto windowsLength = GetSystemWindowsDirectoryW(windowsDirectory, MAX_PATH);
  roots.push_back(windowsLength > 0 && windowsLength < MAX_PATH ? LowerFolder(windowsDirectory)
                                                                 : std::wstring(L"c:\\windows\\"));
  for (const auto* name : {L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramW6432", L"CommonProgramFiles",
                           L"CommonProgramFiles(x86)"}) {
    roots.push_back(EnvironmentFolder(name));
  }
  roots.push_back(L"c:\\program files\\");
  roots.push_back(L"c:\\program files (x86)\\");
  const auto programData = EnvironmentFolder(L"ProgramData");
  if (!programData.empty()) {
    roots.push_back(programData + L"fenriragent\\");
  }
  roots.push_back(ModuleFolder());
  if (!extraRoot.empty()) {
    roots.push_back(LowerFolder(extraRoot.wstring()));
  }

  std::error_code error;
  const auto absolute = std::filesystem::absolute(path, error);
  auto candidate = (error ? path : absolute).lexically_normal().wstring();
  std::transform(candidate.begin(), candidate.end(), candidate.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  std::replace(candidate.begin(), candidate.end(), L'/', L'\\');
  return std::any_of(roots.begin(), roots.end(), [&candidate](const std::wstring& root) {
    return root.size() > 3 && candidate.rfind(root, 0) == 0;
  });
}

QuarantineResult QuarantineStore::QuarantineFile(const ScanFinding& finding) const {
  QuarantineResult result{
      .attempted = true,
      .success = false,
      .neutralized = false,
      .originalArtifactPresent = false,
      .recordId = GenerateGuidString(),
      .quarantinedPath = {},
      .localStatus = L"quarantine-failed",
      .verificationDetail = {},
      .errorMessage = {}};

  if (IsProtectedSystemLocation(finding.path)) {
    result.attempted = false;
    result.originalArtifactPresent = true;
    result.localStatus = L"protected-location";
    result.errorMessage = L"Fenrir does not quarantine files in Windows, Program Files or Fenrir folders.";
    return result;
  }

  try {
    std::filesystem::create_directories(rootPath_ / L"files");
    const auto quarantineRoot = rootPath_ / L"files";
    const auto currentUsageBytes = ComputePathSizeBytes(quarantineRoot);
    const auto quotaBytes = ResolveQuarantineQuotaBytes();
    const auto incomingBytes = finding.sizeBytes;
    const auto wouldExceedQuota = incomingBytes > quotaBytes ||
                                  (currentUsageBytes > quotaBytes - std::min(quotaBytes, incomingBytes));
    if (wouldExceedQuota) {
      result.localStatus = L"quarantine-quota-exceeded";
      result.errorMessage = L"Fenrir blocked quarantine intake because storage quota would be exceeded.";
      result.verificationDetail = L"Current bytes=" + std::to_wstring(currentUsageBytes) + L", incoming bytes=" +
                                  std::to_wstring(incomingBytes) + L", quota bytes=" + std::to_wstring(quotaBytes);
      AppendQuarantineJournalEntry(rootPath_, L"quarantine", result.recordId, finding.path, {}, result.localStatus,
                                   false, result.verificationDetail);
      return result;
    }

    const auto destinationPath = BuildQuarantineFilePath(rootPath_, result.recordId, finding.path);
    auto localStatus = L"quarantined";

    std::error_code error;
    std::filesystem::rename(finding.path, destinationPath, error);
    if (error) {
      error.clear();
      std::filesystem::copy_file(finding.path, destinationPath, std::filesystem::copy_options::overwrite_existing,
                                 error);
      if (error) {
        throw std::runtime_error("Copy to quarantine failed");
      }

      error.clear();
      std::filesystem::remove(finding.path, error);
      if (error) {
        const auto locked = LockDownPathForSystemOnly(finding.path);
        const auto scheduled = ScheduleDeleteOnReboot(finding.path);
        localStatus = scheduled ? L"quarantined-pending-delete" : L"quarantined-locked";
        if (!locked && !scheduled) {
          throw std::runtime_error("Original file could not be removed or locked after quarantine copy");
        }
      }
    }

    const auto verification = VerifyNeutralizationState(finding.path, localStatus);
    result.localStatus = verification.localStatus;
    result.neutralized = verification.neutralized;
    result.originalArtifactPresent = verification.originalPresent;
    result.verificationDetail = verification.detail;

    WriteMetadata(rootPath_, result.recordId, finding, destinationPath, result.localStatus);
    RuntimeDatabase(databasePath_).UpsertQuarantineRecord(QuarantineIndexRecord{
        .recordId = result.recordId,
        .capturedAt = CurrentUtcTimestamp(),
        .originalPath = finding.path,
        .quarantinedPath = destinationPath,
        .sha256 = finding.sha256,
        .sizeBytes = finding.sizeBytes,
        .techniqueId = finding.verdict.techniqueId,
        .localStatus = result.localStatus});
    result.success = result.neutralized;
    result.quarantinedPath = destinationPath;
    if (!result.success) {
      result.errorMessage = result.verificationDetail.empty()
                                ? L"Fenrir could not verify original artifact neutralization after quarantine."
                                : result.verificationDetail;
    }
    AppendQuarantineJournalEntry(
        rootPath_, L"quarantine", result.recordId, finding.path, destinationPath, result.localStatus, result.success,
        result.success ? L"Fenrir quarantined and verified the artifact." : result.errorMessage);
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    AppendQuarantineJournalEntry(rootPath_, L"quarantine", result.recordId, finding.path, result.quarantinedPath,
                                 result.localStatus, false, result.errorMessage);
    return result;
  }
}

QuarantineEntry QuarantineStore::LoadEntry(const std::wstring& recordId) const {
  QuarantineIndexRecord indexedRecord;
  if (RuntimeDatabase(databasePath_).LoadQuarantineRecord(recordId, indexedRecord)) {
    return QuarantineEntry{
        .recordId = indexedRecord.recordId,
        .originalPath = indexedRecord.originalPath,
        .quarantinedPath = indexedRecord.quarantinedPath,
        .sha256 = indexedRecord.sha256,
        .sizeBytes = indexedRecord.sizeBytes,
        .techniqueId = indexedRecord.techniqueId,
        .localStatus = indexedRecord.localStatus};
  }

  const auto metadataPath = rootPath_ / L"records" / (recordId + L".json");
  const auto rawJson = ReadMetadataFile(metadataPath);

  QuarantineEntry entry{
      .recordId = recordId,
      .originalPath = Utf8ToWide(ExtractJsonString(rawJson, "originalPath").value_or("")),
      .quarantinedPath = Utf8ToWide(ExtractJsonString(rawJson, "quarantinedPath").value_or("")),
      .sha256 = Utf8ToWide(ExtractJsonString(rawJson, "sha256").value_or("")),
      .sizeBytes = ExtractJsonNumber(rawJson, "sizeBytes").value_or(0),
      .techniqueId = Utf8ToWide(ExtractJsonString(rawJson, "techniqueId").value_or("")),
      .localStatus = Utf8ToWide(ExtractJsonString(rawJson, "localStatus").value_or("quarantined"))};

  if (entry.originalPath.empty() || entry.quarantinedPath.empty()) {
    throw std::runtime_error("Quarantine metadata is missing required file paths");
  }

  RuntimeDatabase(databasePath_).UpsertQuarantineRecord(QuarantineIndexRecord{
      .recordId = entry.recordId,
      .capturedAt = CurrentUtcTimestamp(),
      .originalPath = entry.originalPath,
      .quarantinedPath = entry.quarantinedPath,
      .sha256 = entry.sha256,
      .sizeBytes = entry.sizeBytes,
      .techniqueId = entry.techniqueId,
      .localStatus = entry.localStatus});

  return entry;
}

QuarantineActionResult QuarantineStore::RestoreFile(const std::wstring& recordId) const {
  QuarantineActionResult result{
      .success = false,
      .recordId = recordId,
      .originalPath = {},
      .quarantinedPath = {},
      .errorMessage = {}};

  try {
    auto entry = LoadEntry(recordId);

    if (!IsRestoreEligibleStatus(entry.localStatus)) {
      throw std::runtime_error("Restore is only allowed for quarantined artifacts that have not already been restored or deleted");
    }

    if (const auto destinationValidation = ValidateRestoreDestination(entry.originalPath); destinationValidation.has_value()) {
      throw std::runtime_error(WideToUtf8(*destinationValidation));
    }

    std::error_code existsError;
    if (!std::filesystem::exists(entry.quarantinedPath, existsError) || existsError) {
      throw std::runtime_error("Quarantined artifact content is missing and cannot be restored");
    }

    result.originalPath = entry.originalPath;
    result.quarantinedPath = entry.quarantinedPath;

    auto restorePolicy = CreateDefaultPolicySnapshot();
    restorePolicy.cloudLookupEnabled = true;
    const auto finding = ScanFile(entry.quarantinedPath, restorePolicy);
    if (finding.has_value() &&
        (finding->verdict.disposition == VerdictDisposition::Block ||
         finding->verdict.disposition == VerdictDisposition::Quarantine)) {
      throw std::runtime_error("Restore blocked because the quarantined artifact still scores as malicious");
    }

    auto restoreTargetPath = entry.originalPath;
    if (std::filesystem::exists(restoreTargetPath, existsError) && !existsError) {
      restoreTargetPath = BuildAlternateRestoreTarget(restoreTargetPath);
    }

    std::filesystem::create_directories(restoreTargetPath.parent_path());
    std::error_code error;
    std::filesystem::rename(entry.quarantinedPath, restoreTargetPath, error);
    if (error) {
      error.clear();
      std::filesystem::copy_file(entry.quarantinedPath, restoreTargetPath,
                                 std::filesystem::copy_options::overwrite_existing, error);
      if (error) {
        throw std::runtime_error("Unable to restore the quarantined file");
      }

      error.clear();
      std::filesystem::remove(entry.quarantinedPath, error);
      if (error) {
        throw std::runtime_error("Unable to remove the quarantined copy after restore");
      }
    }

    const auto restoredFinding = ScanFile(restoreTargetPath, restorePolicy);
    if (restoredFinding.has_value() &&
        (restoredFinding->verdict.disposition == VerdictDisposition::Block ||
         restoredFinding->verdict.disposition == VerdictDisposition::Quarantine)) {
      std::error_code rollbackError;
      std::filesystem::rename(restoreTargetPath, entry.quarantinedPath, rollbackError);
      if (rollbackError) {
        rollbackError.clear();
        std::filesystem::copy_file(restoreTargetPath, entry.quarantinedPath,
                                   std::filesystem::copy_options::overwrite_existing, rollbackError);
        if (!rollbackError) {
          rollbackError.clear();
          std::filesystem::remove(restoreTargetPath, rollbackError);
        }
      }

      throw std::runtime_error("Restore blocked after mandatory post-restore rescan detected malicious content");
    }

    entry.originalPath = restoreTargetPath;
    entry.localStatus = L"restored-verified";
    WriteMetadata(rootPath_, entry);
    RuntimeDatabase database(databasePath_);
    database.UpsertQuarantineRecord(QuarantineIndexRecord{
        .recordId = entry.recordId,
        .capturedAt = CurrentUtcTimestamp(),
        .originalPath = entry.originalPath,
        .quarantinedPath = entry.quarantinedPath,
        .sha256 = entry.sha256,
        .sizeBytes = entry.sizeBytes,
        .techniqueId = entry.techniqueId,
        .localStatus = entry.localStatus});
    database.UpsertQuarantineApprovalRecord(QuarantineApprovalRecord{
        .recordId = entry.recordId,
        .action = L"restore",
        .requestedBy = ReadEnvironmentVariable(L"USERNAME"),
        .approvedBy = ReadEnvironmentVariable(L"USERNAME"),
        .restorePath = entry.originalPath.wstring(),
        .requestedAt = CurrentUtcTimestamp(),
        .decidedAt = CurrentUtcTimestamp(),
        .decision = L"approved",
        .reason = L"Local quarantine restore executed after mandatory re-scan and destination validation."});
    result.success = true;
    result.originalPath = restoreTargetPath;
    result.quarantinedPath = entry.quarantinedPath;
    AppendQuarantineJournalEntry(rootPath_, L"restore", entry.recordId, entry.originalPath, entry.quarantinedPath,
                                 entry.localStatus, true,
                                 L"Fenrir restored the quarantined artifact after mandatory pre- and post-restore scanning.");
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    RuntimeDatabase(databasePath_).UpsertQuarantineApprovalRecord(QuarantineApprovalRecord{
        .recordId = result.recordId,
        .action = L"restore",
        .requestedBy = ReadEnvironmentVariable(L"USERNAME"),
        .approvedBy = {},
        .restorePath = result.originalPath.wstring(),
        .requestedAt = CurrentUtcTimestamp(),
        .decidedAt = CurrentUtcTimestamp(),
        .decision = L"denied",
        .reason = result.errorMessage});
    AppendQuarantineJournalEntry(rootPath_, L"restore", result.recordId, result.originalPath, result.quarantinedPath,
                                 L"restore-failed", false, result.errorMessage);
    return result;
  }
}

QuarantineActionResult QuarantineStore::DeleteRecord(const std::wstring& recordId) const {
  QuarantineActionResult result{
      .success = false,
      .recordId = recordId,
      .originalPath = {},
      .quarantinedPath = {},
      .errorMessage = {}};

  try {
    auto entry = LoadEntry(recordId);
    result.originalPath = entry.originalPath;
    result.quarantinedPath = entry.quarantinedPath;

    const auto secureDeleteEnabled =
        ParseBooleanValue(ReadEnvironmentVariable(L"ANTIVIRUS_SECURE_DELETE_QUARANTINE"), true);
    const auto secureDeletePasses =
        ParsePositiveInt(ReadEnvironmentVariable(L"ANTIVIRUS_SECURE_DELETE_PASSES"), 1);

    if (secureDeleteEnabled && !entry.quarantinedPath.empty() &&
        !SecureDeleteRegularFile(entry.quarantinedPath, secureDeletePasses)) {
      throw std::runtime_error("Unable to securely overwrite quarantined content before deletion");
    }

    std::error_code error;
    std::filesystem::remove(entry.quarantinedPath, error);
    if (error) {
      if (!entry.quarantinedPath.empty() && ScheduleDeleteOnReboot(entry.quarantinedPath)) {
        entry.localStatus = L"deleted-pending-reboot";
      } else {
        throw std::runtime_error("Unable to delete the quarantined file");
      }
    } else {
      entry.localStatus = L"deleted";
      entry.quarantinedPath.clear();
    }

    WriteMetadata(rootPath_, entry);
    RuntimeDatabase database(databasePath_);
    database.UpsertQuarantineRecord(QuarantineIndexRecord{
        .recordId = entry.recordId,
        .capturedAt = CurrentUtcTimestamp(),
        .originalPath = entry.originalPath,
        .quarantinedPath = entry.quarantinedPath,
        .sha256 = entry.sha256,
        .sizeBytes = entry.sizeBytes,
        .techniqueId = entry.techniqueId,
        .localStatus = entry.localStatus});
    database.UpsertQuarantineApprovalRecord(QuarantineApprovalRecord{
        .recordId = entry.recordId,
        .action = L"delete",
        .requestedBy = ReadEnvironmentVariable(L"USERNAME"),
        .approvedBy = ReadEnvironmentVariable(L"USERNAME"),
        .restorePath = {},
        .requestedAt = CurrentUtcTimestamp(),
        .decidedAt = CurrentUtcTimestamp(),
        .decision = L"approved",
        .reason = secureDeleteEnabled ? L"Secure quarantine delete approved and completed."
                                      : L"Quarantine delete approved and completed."});
    result.success = true;
    result.quarantinedPath = entry.quarantinedPath;
    AppendQuarantineJournalEntry(rootPath_, L"delete", entry.recordId, entry.originalPath, result.quarantinedPath,
                   entry.localStatus, true,
                   secureDeleteEnabled
                     ? L"Fenrir securely deleted the quarantined artifact record."
                     : L"Fenrir deleted the quarantined artifact record.");
    return result;
  } catch (const std::exception& error) {
    result.errorMessage = Utf8ToWide(error.what());
    RuntimeDatabase(databasePath_).UpsertQuarantineApprovalRecord(QuarantineApprovalRecord{
        .recordId = result.recordId,
        .action = L"delete",
        .requestedBy = ReadEnvironmentVariable(L"USERNAME"),
        .approvedBy = {},
        .restorePath = {},
        .requestedAt = CurrentUtcTimestamp(),
        .decidedAt = CurrentUtcTimestamp(),
        .decision = L"denied",
        .reason = result.errorMessage});
    AppendQuarantineJournalEntry(rootPath_, L"delete", result.recordId, result.originalPath, result.quarantinedPath,
                                 L"delete-failed", false, result.errorMessage);
    return result;
  }
}

}  // namespace antivirus::agent
