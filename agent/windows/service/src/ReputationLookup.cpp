#include <winsock2.h>  // Load Winsock2 before any transitive Windows.h include.
#include "ReputationLookup.h"
#include <windows.h>
#include <softpub.h>
#include <winhttp.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cwctype>
#include <fstream>
#include <mutex>
#include <optional>
#include <regex>
#include <string>
#include <unordered_map>

#include "AgentConfig.h"
#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct ParsedBaseUrl {
  std::wstring host;
  INTERNET_PORT port{INTERNET_DEFAULT_HTTPS_PORT};
  bool secure{true};
  std::wstring pathPrefix;
};

struct CachedReputationEntry {
  ReputationLookupResult result;
  std::chrono::system_clock::time_point expiresAt;
};

std::mutex gCacheMutex;
std::unordered_map<std::wstring, CachedReputationEntry> gCache;
std::once_flag gLocalIntelLoadOnce;

struct LocalSignerIntelEntry {
  std::wstring signer;
  std::wstring publisher;
  std::uint32_t prevalence{0};
};

struct LocalKnownGoodHashEntry {
  std::wstring sha256;
  std::wstring signer;
  std::wstring source;
  std::uint32_t prevalence{0};
};

std::unordered_map<std::wstring, LocalSignerIntelEntry> gLocalSignerIntel;
std::unordered_map<std::wstring, LocalKnownGoodHashEntry> gLocalKnownGoodHashes;

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring TrimCopy(std::wstring value) {
  const auto isTrimCharacter = [](const wchar_t ch) {
    return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n' || ch == L'/';
  };

  while (!value.empty() && isTrimCharacter(value.front())) {
    value.erase(value.begin());
  }
  while (!value.empty() && isTrimCharacter(value.back())) {
    value.pop_back();
  }
  return value;
}

bool IsHexSha256(const std::wstring& value) {
  if (value.size() != 64) {
    return false;
  }

  return std::all_of(value.begin(), value.end(), [](const wchar_t ch) {
    return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
  });
}

bool LooksLikeIpAddress(const std::wstring& value) {
  return value.find(L'.') != std::wstring::npos || value.find(L':') != std::wstring::npos;
}

bool LooksLikeUrl(const std::wstring& value) {
  const auto lower = ToLowerCopy(value);
  return lower.starts_with(L"http://") || lower.starts_with(L"https://");
}

ThreatIndicatorType InferIndicatorType(const std::wstring& value) {
  const auto trimmed = TrimCopy(value);
  const auto lower = ToLowerCopy(trimmed);
  if (IsHexSha256(lower)) {
    return ThreatIndicatorType::Sha256;
  }
  if (LooksLikeUrl(lower)) {
    return ThreatIndicatorType::Url;
  }
  if (LooksLikeIpAddress(lower)) {
    return ThreatIndicatorType::Ip;
  }
  if (lower.find(L'.') != std::wstring::npos) {
    return ThreatIndicatorType::Domain;
  }
  return ThreatIndicatorType::Unknown;
}

std::wstring CacheKey(const ThreatIndicatorType type, const std::wstring& indicator) {
  return ThreatIndicatorTypeToString(type) + L"|" + ToLowerCopy(TrimCopy(indicator));
}

std::vector<std::wstring> SplitTabColumns(const std::wstring& line) {
  std::vector<std::wstring> columns;
  std::wstring current;
  for (const auto ch : line) {
    if (ch == L'\t') {
      columns.push_back(TrimCopy(current));
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  columns.push_back(TrimCopy(current));
  return columns;
}

void LoadLocalIntelCatalogs() {
  const auto config = LoadAgentConfig();

  const auto loadSignerCatalog = [](const std::filesystem::path& catalogPath) {
    if (catalogPath.empty()) {
      return;
    }

    std::ifstream input(catalogPath, std::ios::binary);
    if (!input.is_open()) {
      return;
    }

    std::string utf8Line;
    while (std::getline(input, utf8Line)) {
      if (utf8Line.empty() || utf8Line.starts_with("#")) {
        continue;
      }

      const auto line = Utf8ToWide(utf8Line);
      const auto columns = SplitTabColumns(line);
      if (columns.empty() || columns[0].empty()) {
        continue;
      }

      auto prevalence = 0u;
      if (columns.size() >= 3) {
        try {
          prevalence = static_cast<std::uint32_t>(std::stoul(columns[2]));
        } catch (...) {
          prevalence = 0;
        }
      }

      const auto normalizedSigner = ToLowerCopy(columns[0]);
      gLocalSignerIntel[normalizedSigner] = LocalSignerIntelEntry{
          .signer = columns[0],
          .publisher = columns.size() >= 2 ? columns[1] : L"",
          .prevalence = prevalence};
    }
  };

  const auto loadHashCatalog = [](const std::filesystem::path& catalogPath) {
    if (catalogPath.empty()) {
      return;
    }

    std::ifstream input(catalogPath, std::ios::binary);
    if (!input.is_open()) {
      return;
    }

    std::string utf8Line;
    while (std::getline(input, utf8Line)) {
      if (utf8Line.empty() || utf8Line.starts_with("#")) {
        continue;
      }

      const auto line = Utf8ToWide(utf8Line);
      const auto columns = SplitTabColumns(line);
      if (columns.empty() || columns[0].empty()) {
        continue;
      }

      const auto normalizedHash = ToLowerCopy(columns[0]);
      if (!IsHexSha256(normalizedHash)) {
        continue;
      }

      auto prevalence = 0u;
      if (columns.size() >= 4) {
        try {
          prevalence = static_cast<std::uint32_t>(std::stoul(columns[3]));
        } catch (...) {
          prevalence = 0;
        }
      }

      gLocalKnownGoodHashes[normalizedHash] = LocalKnownGoodHashEntry{
          .sha256 = normalizedHash,
          .signer = columns.size() >= 2 ? columns[1] : L"",
          .source = columns.size() >= 3 ? columns[2] : L"local-known-good",
          .prevalence = prevalence};
    }
  };

  loadSignerCatalog(config.cleanwareSignerListPath);
  loadHashCatalog(config.knownGoodHashListPath);
}

void EnsureLocalIntelCatalogsLoaded() {
  std::call_once(gLocalIntelLoadOnce, [] { LoadLocalIntelCatalogs(); });
}

std::wstring ResolveBaseUrl() {
  const auto envValue = ReadEnvironmentVariable(L"FENRIR_THREAT_INTEL_BASE_URL");
  if (!envValue.empty()) {
    return TrimCopy(envValue);
  }
  return L"https://hashlookup.circl.lu";
}

ParsedBaseUrl ParseBaseUrl(std::wstring baseUrl) {
  ParsedBaseUrl parsed{};
  baseUrl = TrimCopy(std::move(baseUrl));

  if (baseUrl.starts_with(L"https://")) {
    baseUrl.erase(0, std::wstring(L"https://").size());
    parsed.secure = true;
  } else if (baseUrl.starts_with(L"http://")) {
    baseUrl.erase(0, std::wstring(L"http://").size());
    parsed.secure = false;
    parsed.port = INTERNET_DEFAULT_HTTP_PORT;
  }

  const auto slashPosition = baseUrl.find(L'/');
  const auto hostPort = slashPosition == std::wstring::npos ? baseUrl : baseUrl.substr(0, slashPosition);
  parsed.pathPrefix = slashPosition == std::wstring::npos ? L"" : baseUrl.substr(slashPosition);

  const auto portPosition = hostPort.find(L':');
  if (portPosition == std::wstring::npos) {
    parsed.host = hostPort;
    return parsed;
  }

  parsed.host = hostPort.substr(0, portPosition);
  try {
    const auto parsedPort = std::stoi(hostPort.substr(portPosition + 1));
    if (parsedPort > 0 && parsedPort <= 65535) {
      parsed.port = static_cast<INTERNET_PORT>(parsedPort);
    }
  } catch (...) {
  }
  return parsed;
}

struct HttpResponse {
  DWORD statusCode{0};
  std::string body;
};

std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + key + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (!std::regex_search(json, match, pattern)) {
    return std::nullopt;
  }

  std::string result;
  result.reserve(match[1].str().size());
  bool escaping = false;
  for (const auto ch : match[1].str()) {
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

std::optional<std::uint32_t> ExtractJsonUInt(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + key + "\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (!std::regex_search(json, match, pattern)) {
    return std::nullopt;
  }
  try {
    return static_cast<std::uint32_t>(std::stoul(match[1].str()));
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<HttpResponse> ExecuteHttpGet(const std::wstring& path) {
  const auto parsedBaseUrl = ParseBaseUrl(ResolveBaseUrl());
  if (parsedBaseUrl.host.empty()) {
    return std::nullopt;
  }

  std::wstring requestPath = parsedBaseUrl.pathPrefix;
  if (requestPath.empty() || requestPath.back() != L'/') {
    requestPath.push_back(L'/');
  }
  requestPath += path.starts_with(L"/") ? path.substr(1) : path;

  const auto session = WinHttpOpen(L"Fenrir ThreatIntel/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (session == nullptr) {
    return std::nullopt;
  }

  WinHttpSetTimeouts(session, 5000, 5000, 5000, 5000);
  const auto connection = WinHttpConnect(session, parsedBaseUrl.host.c_str(), parsedBaseUrl.port, 0);
  if (connection == nullptr) {
    WinHttpCloseHandle(session);
    return std::nullopt;
  }

  const auto request = WinHttpOpenRequest(connection, L"GET", requestPath.c_str(), nullptr, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          parsedBaseUrl.secure ? WINHTTP_FLAG_SECURE : 0);
  if (request == nullptr) {
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return std::nullopt;
  }

  const auto sent = WinHttpSendRequest(request, L"Accept: application/json\r\n", static_cast<DWORD>(-1),
                                       WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
  if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return std::nullopt;
  }

  DWORD statusCode = 0;
  DWORD statusCodeSize = sizeof(statusCode);
  WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);

  std::string body;
  for (;;) {
    DWORD availableBytes = 0;
    if (!WinHttpQueryDataAvailable(request, &availableBytes) || availableBytes == 0) {
      break;
    }
    std::string chunk(availableBytes, '\0');
    DWORD bytesRead = 0;
    if (!WinHttpReadData(request, chunk.data(), availableBytes, &bytesRead)) {
      WinHttpCloseHandle(request);
      WinHttpCloseHandle(connection);
      WinHttpCloseHandle(session);
      return std::nullopt;
    }
    chunk.resize(bytesRead);
    body.append(chunk);
  }

  WinHttpCloseHandle(request);
  WinHttpCloseHandle(connection);
  WinHttpCloseHandle(session);
  return HttpResponse{.statusCode = statusCode, .body = std::move(body)};
}

std::filesystem::path ResolveDatabasePath(const std::filesystem::path& databasePath) {
  if (!databasePath.empty()) {
    return databasePath;
  }
  return LoadAgentConfig().runtimeDatabasePath;
}

std::chrono::system_clock::time_point DefaultExpiryPoint(const ReputationLookupResult& result) {
  const auto now = std::chrono::system_clock::now();
  if (result.lookupSucceeded && result.malicious) {
    return now + std::chrono::hours(12);
  }
  if (result.lookupSucceeded && result.knownGood) {
    return now + std::chrono::hours(24);
  }
  if (result.lookupSucceeded) {
    return now + std::chrono::hours(6);
  }
  return now + std::chrono::minutes(30);
}

std::wstring IsoExpiryFromResult(const ReputationLookupResult& result) {
  const auto nowText = CurrentUtcTimestamp();
  const auto now = DefaultExpiryPoint(result);
  (void)nowText;
  const auto current = std::chrono::system_clock::now();
  const auto deltaHours =
      std::chrono::duration_cast<std::chrono::hours>(DefaultExpiryPoint(result) - current).count();
  SYSTEMTIME st{};
  GetSystemTime(&st);
  FILETIME ft{};
  SystemTimeToFileTime(&st, &ft);
  ULARGE_INTEGER ticks{};
  ticks.LowPart = ft.dwLowDateTime;
  ticks.HighPart = ft.dwHighDateTime;
  ticks.QuadPart += static_cast<ULONGLONG>(deltaHours > 0 ? deltaHours : 1) * 60ull * 60ull * 10000000ull;
  ft.dwLowDateTime = ticks.LowPart;
  ft.dwHighDateTime = ticks.HighPart;
  SYSTEMTIME out{};
  FileTimeToSystemTime(&ft, &out);
  wchar_t buffer[64];
  swprintf(buffer, std::size(buffer), L"%04u-%02u-%02uT%02u:%02u:%02uZ", out.wYear, out.wMonth, out.wDay, out.wHour,
           out.wMinute, out.wSecond);
  return buffer;
}

ReputationLookupResult BuildHeuristicDestinationResult(const ThreatIndicatorType type, const std::wstring& indicator) {
  ReputationLookupResult result{};
  result.attempted = true;
  result.lookupSucceeded = true;
  result.fromCache = false;
  result.indicatorType = type;
  result.indicatorKey = indicator;
  result.provider = L"fenrir-local";
  result.providerWeight = 80;
  result.source = L"local-heuristics";
  result.localOnly = true;

  const auto lower = ToLowerCopy(TrimCopy(indicator));
  const auto loopback = lower == L"127.0.0.1" || lower == L"::1" || lower == L"localhost";
  const auto rfc1918 = lower.starts_with(L"10.") || lower.starts_with(L"192.168.") || lower.starts_with(L"172.16.") ||
                       lower.starts_with(L"172.17.") || lower.starts_with(L"172.18.") || lower.starts_with(L"172.19.") ||
                       lower.starts_with(L"172.2") || lower.starts_with(L"fd");
  const auto suspiciousDomain =
      lower.ends_with(L".onion") || lower.find(L"pastebin") != std::wstring::npos || lower.find(L"ngrok") != std::wstring::npos;

  if (loopback || rfc1918) {
    result.knownGood = true;
    result.malicious = false;
    result.trustScore = 90;
    result.verdict = L"known_good_internal";
    result.summary = L"Destination is internal or loopback.";
    result.details = L"Fenrir treated the destination as local/internal network space.";
    result.expiresAt = IsoExpiryFromResult(result);
    return result;
  }

  if (suspiciousDomain) {
    result.knownGood = false;
    result.malicious = true;
    result.trustScore = 20;
    result.verdict = L"suspicious_destination";
    result.summary = L"Destination matches a high-risk local heuristic.";
    result.details = L"Fenrir classified the destination as suspicious based on local destination heuristics.";
    result.expiresAt = IsoExpiryFromResult(result);
    return result;
  }

  result.knownGood = false;
  result.malicious = false;
  result.trustScore = 50;
  result.verdict = L"unknown";
  result.summary = L"Destination has no strong local reputation signal.";
  result.details = L"Fenrir recorded the destination for later correlation and intelligence enrichment.";
  result.expiresAt = IsoExpiryFromResult(result);
  return result;
}

ReputationLookupResult BuildSha256Result(const std::wstring& sha256, const HttpResponse& response) {
  ReputationLookupResult result{};
  result.attempted = true;
  result.indicatorType = ThreatIndicatorType::Sha256;
  result.indicatorKey = sha256;
  result.provider = L"CIRCL hashlookup";
  result.providerWeight = 70;
  result.source = L"hashlookup";

  if (response.statusCode == 200) {
    result.lookupSucceeded = true;
    result.knownGood = true;
    result.malicious = false;
    result.trustScore = ExtractJsonUInt(response.body, "hashlookup:trust").value_or(100);
    result.verdict = L"known_good";
    if (const auto source = ExtractJsonString(response.body, "source"); source.has_value()) {
      result.source = Utf8ToWide(*source);
    }
    result.summary = L"Verified known file in CIRCL hashlookup.";
    result.details = L"The SHA-256 hash matched the public hashlookup corpus.";
    result.expiresAt = IsoExpiryFromResult(result);
    return result;
  }

  if (response.statusCode == 404) {
    result.lookupSucceeded = true;
    result.knownGood = false;
    result.malicious = false;
    result.trustScore = 50;
    result.verdict = L"unknown";
    result.summary = L"No public hashlookup match was found.";
    result.details = L"The SHA-256 hash was not present in the public hashlookup corpus.";
    result.expiresAt = IsoExpiryFromResult(result);
    return result;
  }

  result.lookupSucceeded = false;
  result.knownGood = false;
  result.malicious = false;
  result.trustScore = 0;
  result.verdict = L"unavailable";
  result.summary = L"Public reputation lookup was unavailable.";
  result.details = L"CIRCL hashlookup returned an unexpected response for the requested hash.";
  result.expiresAt = IsoExpiryFromResult(result);
  return result;
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

ReputationLookupResult ResultFromRecord(const ThreatIntelRecord& record) {
  const auto verdictLower = ToLowerCopy(record.verdict);
  return ReputationLookupResult{
      .attempted = true,
      .lookupSucceeded = true,
      .knownGood = verdictLower.find(L"known_good") != std::wstring::npos,
      .malicious = verdictLower.find(L"malicious") != std::wstring::npos ||
                   verdictLower.find(L"suspicious") != std::wstring::npos,
      .trustedSigner = verdictLower.find(L"trusted_signer") != std::wstring::npos,
      .observeOnly = verdictLower.find(L"observe") != std::wstring::npos,
      .fromCache = true,
      .localOnly = record.localOnly,
      .trustScore = record.trustScore,
      .providerWeight = record.providerWeight,
      .prevalence = 0,
      .indicatorType = record.indicatorType,
      .indicatorKey = record.indicatorKey,
      .provider = record.provider,
      .source = record.source,
      .publisher = {},
      .summary = record.summary,
      .details = record.details,
      .verdict = record.verdict,
      .expiresAt = record.expiresAt,
      .metadataJson = record.metadataJson};
}

ReputationLookupResult BuildKnownGoodHashResult(const std::wstring& sha256,
                                                const LocalKnownGoodHashEntry& entry) {
  ReputationLookupResult result{};
  result.attempted = true;
  result.lookupSucceeded = true;
  result.knownGood = true;
  result.malicious = false;
  result.fromCache = false;
  result.localOnly = true;
  result.trustScore = 98;
  result.providerWeight = 96;
  result.prevalence = entry.prevalence;
  result.indicatorType = ThreatIndicatorType::Sha256;
  result.indicatorKey = sha256;
  result.provider = L"fenrir-known-good";
  result.source = entry.source.empty() ? L"local-known-good" : entry.source;
  result.publisher = entry.signer;
  result.summary = L"Known-good hash matched local cleanware intelligence.";
  result.details = entry.signer.empty()
                       ? L"Fenrir matched the hash against the local known-good catalog."
                       : L"Fenrir matched the hash against the local known-good catalog for signer " + entry.signer +
                             L".";
  result.verdict = L"known_good_local";
  result.expiresAt = IsoExpiryFromResult(result);
  return result;
}

ReputationLookupResult BuildTrustedSignerResult(const std::wstring& signer, const LocalSignerIntelEntry& entry) {
  ReputationLookupResult result{};
  result.attempted = true;
  result.lookupSucceeded = true;
  result.knownGood = true;
  result.malicious = false;
  result.trustedSigner = true;
  result.fromCache = false;
  result.localOnly = true;
  result.trustScore = 96;
  result.providerWeight = 94;
  result.prevalence = entry.prevalence;
  result.indicatorType = ThreatIndicatorType::Unknown;
  result.indicatorKey = signer;
  result.provider = L"fenrir-cleanware-signer";
  result.source = L"local-cleanware-signers";
  result.publisher = entry.publisher;
  result.summary = L"Signer matched local cleanware intelligence.";
  result.details = entry.publisher.empty()
                       ? L"Fenrir matched the signer against trusted cleanware signer intelligence."
                       : L"Fenrir matched the signer against trusted cleanware intelligence for publisher " +
                             entry.publisher + L".";
  result.verdict = L"trusted_signer_cleanware";
  result.expiresAt = IsoExpiryFromResult(result);
  return result;
}

void UpdateThreatPrevalence(const std::filesystem::path& databasePath, const ReputationLookupResult& result) {
  if (result.indicatorType == ThreatIndicatorType::Unknown || result.indicatorKey.empty()) {
    return;
  }

  RuntimeDatabase database(databasePath);
  ThreatPrevalenceRecord current{};
  const auto now = CurrentUtcTimestamp();
  const auto existing = database.TryGetThreatPrevalenceRecord(result.indicatorType, result.indicatorKey, current);
  if (!existing) {
    database.UpsertThreatPrevalenceRecord(ThreatPrevalenceRecord{
        .indicatorType = result.indicatorType,
        .indicatorKey = result.indicatorKey,
        .sightingCount = 1,
        .firstSeenAt = now,
        .lastSeenAt = now,
        .lastSource = result.source});
    return;
  }

  current.sightingCount += 1;
  current.lastSeenAt = now;
  current.lastSource = result.source;
  database.UpsertThreatPrevalenceRecord(current);
}

int ReputationPrecedenceScore(const ReputationLookupResult& result) {
  if (!result.attempted) {
    return 0;
  }

  auto score = static_cast<int>(result.providerWeight) * 4 + static_cast<int>(result.trustScore);
  if (result.malicious && !result.observeOnly) {
    score += 1'000;
  } else if (result.knownGood || result.trustedSigner) {
    score += 750;
  } else if (result.lookupSucceeded) {
    score += 350;
  }

  if (result.localOnly) {
    score += 20;
  }
  if (result.fromCache) {
    score += 5;
  }
  return score;
}

bool CandidatePreferred(const ReputationLookupResult& candidate, const ReputationLookupResult& baseline) {
  if (!candidate.attempted) {
    return false;
  }
  if (!baseline.attempted) {
    return true;
  }
  return ReputationPrecedenceScore(candidate) > ReputationPrecedenceScore(baseline);
}

void PersistResult(const std::filesystem::path& databasePath, const ReputationLookupResult& result) {
  RuntimeDatabase database(databasePath);
  database.PurgeExpiredThreatIntelRecords(CurrentUtcTimestamp());
  database.UpsertThreatIntelRecord(ThreatIntelRecord{
      .indicatorType = result.indicatorType,
      .indicatorKey = result.indicatorKey,
      .provider = result.provider.empty() ? L"fenrir-local" : result.provider,
      .source = result.source,
      .verdict = result.verdict.empty() ? L"unknown" : result.verdict,
      .trustScore = result.trustScore,
      .providerWeight = result.providerWeight,
      .summary = result.summary,
      .details = result.details,
      .metadataJson = result.metadataJson,
      .firstSeenAt = CurrentUtcTimestamp(),
      .lastSeenAt = CurrentUtcTimestamp(),
      .expiresAt = result.expiresAt.empty() ? IsoExpiryFromResult(result) : result.expiresAt,
      .signedPack = false,
      .localOnly = result.localOnly});

  UpdateThreatPrevalence(databasePath, result);
}

}  // namespace

ReputationLookupResult LookupThreatIntel(const ThreatIndicatorType indicatorType, const std::wstring& indicator,
                                         const std::filesystem::path& databasePath) {
  const auto normalizedIndicator = ToLowerCopy(TrimCopy(indicator));
  ReputationLookupResult invalid{};
  invalid.provider = L"fenrir-local";
  invalid.indicatorType = indicatorType;
  invalid.indicatorKey = normalizedIndicator;
  invalid.summary = L"Threat intelligence lookup was skipped.";
  invalid.details = L"A supported indicator value is required before reputation lookup can proceed.";
  if (normalizedIndicator.empty() || indicatorType == ThreatIndicatorType::Unknown) {
    return invalid;
  }

  const auto cacheKeyValue = CacheKey(indicatorType, normalizedIndicator);
  const auto now = std::chrono::system_clock::now();
  {
    std::lock_guard lock(gCacheMutex);
    const auto cached = gCache.find(cacheKeyValue);
    if (cached != gCache.end() && cached->second.expiresAt > now) {
      auto result = cached->second.result;
      result.fromCache = true;
      return result;
    }
  }

  const auto resolvedDatabasePath = ResolveDatabasePath(databasePath);
  ReputationLookupResult cachedCandidate{};
  bool hasCachedCandidate = false;
  try {
    RuntimeDatabase database(resolvedDatabasePath);
    database.PurgeExpiredThreatIntelRecords(CurrentUtcTimestamp());
    ThreatIntelRecord cachedRecord{};
    if (database.TryGetThreatIntelRecord(indicatorType, normalizedIndicator, cachedRecord) &&
        (cachedRecord.expiresAt.empty() || cachedRecord.expiresAt > CurrentUtcTimestamp())) {
      cachedCandidate = ResultFromRecord(cachedRecord);
      hasCachedCandidate = true;
    }
  } catch (...) {
  }

  ReputationLookupResult result = hasCachedCandidate ? cachedCandidate : ReputationLookupResult{};
  if (indicatorType == ThreatIndicatorType::Sha256) {
    if (!IsHexSha256(normalizedIndicator)) {
      return invalid;
    }

    const auto knownGoodCandidate = LookupKnownGoodHash(normalizedIndicator, resolvedDatabasePath);
    if (knownGoodCandidate.lookupSucceeded && knownGoodCandidate.knownGood &&
        CandidatePreferred(knownGoodCandidate, result)) {
      result = knownGoodCandidate;
    }

    if (!result.malicious || result.providerWeight < 90) {
      const auto response = ExecuteHttpGet(L"/lookup/sha256/" + normalizedIndicator);
      auto publicCandidate = response.has_value() ? BuildSha256Result(normalizedIndicator, *response)
                                                  : ReputationLookupResult{};
      if (!response.has_value()) {
        publicCandidate.attempted = true;
        publicCandidate.lookupSucceeded = false;
        publicCandidate.indicatorType = ThreatIndicatorType::Sha256;
        publicCandidate.indicatorKey = normalizedIndicator;
        publicCandidate.provider = L"CIRCL hashlookup";
        publicCandidate.providerWeight = 70;
        publicCandidate.source = L"hashlookup";
        publicCandidate.verdict = L"unavailable";
        publicCandidate.summary = L"Public reputation lookup was unavailable.";
        publicCandidate.details = L"CIRCL hashlookup could not be contacted for the requested hash.";
        publicCandidate.expiresAt = IsoExpiryFromResult(publicCandidate);
      }

      if (CandidatePreferred(publicCandidate, result)) {
        result = std::move(publicCandidate);
      }
    }
  } else {
    const auto heuristicCandidate = BuildHeuristicDestinationResult(indicatorType, normalizedIndicator);
    if (CandidatePreferred(heuristicCandidate, result)) {
      result = heuristicCandidate;
    }
  }

  if (!result.attempted) {
    result = invalid;
  }

  PersistResult(resolvedDatabasePath, result);
  {
    std::lock_guard lock(gCacheMutex);
    gCache[cacheKeyValue] = CachedReputationEntry{.result = result, .expiresAt = now + std::chrono::minutes(30)};
  }
  return result;
}

ReputationLookupResult LookupPublicFileReputation(const std::wstring& sha256, const std::filesystem::path& databasePath) {
  return LookupThreatIntel(ThreatIndicatorType::Sha256, sha256, databasePath);
}

ReputationLookupResult LookupKnownGoodHash(const std::wstring& sha256, const std::filesystem::path& databasePath) {
  const auto normalizedHash = ToLowerCopy(TrimCopy(sha256));
  ReputationLookupResult result{};
  result.attempted = true;
  result.indicatorType = ThreatIndicatorType::Sha256;
  result.indicatorKey = normalizedHash;
  result.provider = L"fenrir-known-good";
  result.source = L"local-known-good";

  if (!IsHexSha256(normalizedHash)) {
    result.lookupSucceeded = false;
    result.verdict = L"invalid";
    result.summary = L"Known-good hash lookup was skipped due to an invalid SHA-256 indicator.";
    result.details = L"A 64-character hexadecimal SHA-256 indicator is required.";
    return result;
  }

  const auto resolvedDatabasePath = ResolveDatabasePath(databasePath);
  try {
    RuntimeDatabase database(resolvedDatabasePath);
    KnownGoodHashRecord record{};
    if (database.TryGetKnownGoodHashRecord(normalizedHash, record) &&
        (record.expiresAt.empty() || record.expiresAt > CurrentUtcTimestamp())) {
      auto fromRecord = BuildKnownGoodHashResult(normalizedHash, LocalKnownGoodHashEntry{
                                                                     .sha256 = record.sha256,
                                                                     .signer = record.signerName,
                                                                     .source = record.source,
                                                                     .prevalence = record.prevalence});
      fromRecord.fromCache = true;
      if (!record.summary.empty()) {
        fromRecord.summary = record.summary;
      }
      if (!record.details.empty()) {
        fromRecord.details = record.details;
      }
      if (!record.expiresAt.empty()) {
        fromRecord.expiresAt = record.expiresAt;
      }
      return fromRecord;
    }
  } catch (...) {
  }

  EnsureLocalIntelCatalogsLoaded();
  if (const auto local = gLocalKnownGoodHashes.find(normalizedHash); local != gLocalKnownGoodHashes.end()) {
    auto matched = BuildKnownGoodHashResult(normalizedHash, local->second);
    try {
      RuntimeDatabase database(resolvedDatabasePath);
      database.UpsertKnownGoodHashRecord(KnownGoodHashRecord{
          .sha256 = normalizedHash,
          .source = matched.source,
          .summary = matched.summary,
          .details = matched.details,
          .signerName = local->second.signer,
          .firstSeenAt = CurrentUtcTimestamp(),
          .lastSeenAt = CurrentUtcTimestamp(),
          .expiresAt = matched.expiresAt,
          .prevalence = matched.prevalence});
    } catch (...) {
    }
    PersistResult(resolvedDatabasePath, matched);
    return matched;
  }

  result.lookupSucceeded = true;
  result.knownGood = false;
  result.malicious = false;
  result.localOnly = true;
  result.trustScore = 45;
  result.providerWeight = 40;
  result.verdict = L"unknown";
  result.summary = L"No local known-good hash match was found.";
  result.details = L"The SHA-256 hash was not found in the local cleanware known-good catalog.";
  result.expiresAt = IsoExpiryFromResult(result);
  return result;
}

ReputationLookupResult LookupSignerReputation(const std::wstring& signer, const std::filesystem::path& databasePath) {
  const auto normalizedSigner = ToLowerCopy(TrimCopy(signer));
  ReputationLookupResult result{};
  result.attempted = true;
  result.lookupSucceeded = true;
  result.indicatorType = ThreatIndicatorType::Unknown;
  result.indicatorKey = normalizedSigner;
  result.provider = L"fenrir-cleanware-signer";
  result.source = L"local-cleanware-signers";

  if (normalizedSigner.empty()) {
    result.lookupSucceeded = false;
    result.verdict = L"invalid";
    result.summary = L"Signer reputation lookup was skipped because signer metadata was empty.";
    result.details = L"Provide an Authenticode signer subject before requesting signer reputation intelligence.";
    return result;
  }

  const auto resolvedDatabasePath = ResolveDatabasePath(databasePath);
  try {
    RuntimeDatabase database(resolvedDatabasePath);
    TrustedSignerRecord record{};
    if (database.TryGetTrustedSignerRecord(normalizedSigner, record) &&
        (record.expiresAt.empty() || record.expiresAt > CurrentUtcTimestamp())) {
      auto fromRecord = BuildTrustedSignerResult(normalizedSigner, LocalSignerIntelEntry{
                                                                    .signer = record.signerName,
                                                                    .publisher = record.publisher,
                                                                    .prevalence = record.prevalence});
      fromRecord.fromCache = true;
      if (!record.summary.empty()) {
        fromRecord.summary = record.summary;
      }
      if (!record.details.empty()) {
        fromRecord.details = record.details;
      }
      if (!record.expiresAt.empty()) {
        fromRecord.expiresAt = record.expiresAt;
      }
      return fromRecord;
    }
  } catch (...) {
  }

  EnsureLocalIntelCatalogsLoaded();
  if (const auto local = gLocalSignerIntel.find(normalizedSigner); local != gLocalSignerIntel.end()) {
    auto matched = BuildTrustedSignerResult(normalizedSigner, local->second);
    try {
      RuntimeDatabase database(resolvedDatabasePath);
      database.UpsertTrustedSignerRecord(TrustedSignerRecord{
          .signerName = normalizedSigner,
          .publisher = local->second.publisher,
          .trustLevel = L"trusted",
          .source = matched.source,
          .summary = matched.summary,
          .details = matched.details,
          .firstSeenAt = CurrentUtcTimestamp(),
          .lastSeenAt = CurrentUtcTimestamp(),
          .expiresAt = matched.expiresAt,
          .prevalence = matched.prevalence,
          .allowSuppression = true});
    } catch (...) {
    }
    return matched;
  }

  result.knownGood = false;
  result.malicious = false;
  result.trustedSigner = false;
  result.localOnly = true;
  result.trustScore = 50;
  result.providerWeight = 40;
  result.verdict = L"unknown";
  result.summary = L"Signer was not found in local cleanware intelligence.";
  result.details = L"Fenrir did not find this signer in local trusted cleanware intelligence catalogs.";
  result.expiresAt = IsoExpiryFromResult(result);
  return result;
}

ReputationLookupResult LookupDestinationReputation(const std::wstring& indicator, const std::filesystem::path& databasePath) {
  return LookupThreatIntel(InferIndicatorType(indicator), indicator, databasePath);
}

ThreatIntelPackIngestResult IngestSignedThreatIntelPack(const std::filesystem::path& packPath,
                                                        const std::filesystem::path& databasePath) {
  ThreatIntelPackIngestResult result{};
  result.provider = L"local-intelligence-pack";

  std::error_code error;
  if (!std::filesystem::exists(packPath, error) || error) {
    result.errorMessage = L"Threat intelligence pack path does not exist.";
    return result;
  }

  result.signatureVerified = VerifyAuthenticodeSignature(packPath);
  if (!result.signatureVerified) {
    result.errorMessage = L"Threat intelligence pack failed Authenticode verification.";
    return result;
  }

  std::ifstream input(packPath, std::ios::binary);
  if (!input.is_open()) {
    result.errorMessage = L"Threat intelligence pack could not be opened.";
    return result;
  }

  const auto resolvedDatabasePath = ResolveDatabasePath(databasePath);
  RuntimeDatabase database(resolvedDatabasePath);

  std::string utf8Line;
  while (std::getline(input, utf8Line)) {
    if (utf8Line.empty() || utf8Line.starts_with("#")) {
      continue;
    }

    const auto line = Utf8ToWide(utf8Line);
    std::vector<std::wstring> parts;
    std::wstring current;
    for (const auto ch : line) {
      if (ch == L'\t') {
        parts.push_back(current);
        current.clear();
      } else {
        current.push_back(ch);
      }
    }
    parts.push_back(current);
    if (parts.size() < 8) {
      ++result.recordsRejected;
      continue;
    }

    const auto type = ThreatIndicatorTypeFromString(parts[0]);
    if (type == ThreatIndicatorType::Unknown || parts[1].empty()) {
      ++result.recordsRejected;
      continue;
    }

    std::uint32_t trustScore = 0;
    std::uint32_t providerWeight = 95;
    int ttlHours = 24;
    try {
      trustScore = static_cast<std::uint32_t>(std::stoul(parts[3]));
      providerWeight = static_cast<std::uint32_t>(std::stoul(parts[5]));
      ttlHours = std::max(std::stoi(parts[6]), 1);
    } catch (...) {
      ++result.recordsRejected;
      continue;
    }

    ReputationLookupResult lookupResult{
        .attempted = true,
        .lookupSucceeded = true,
        .knownGood = ToLowerCopy(parts[2]).find(L"known_good") != std::wstring::npos,
        .malicious = ToLowerCopy(parts[2]).find(L"malicious") != std::wstring::npos ||
                     ToLowerCopy(parts[2]).find(L"suspicious") != std::wstring::npos,
        .fromCache = false,
        .localOnly = true,
        .trustScore = trustScore,
        .providerWeight = providerWeight,
        .indicatorType = type,
        .indicatorKey = ToLowerCopy(parts[1]),
        .provider = parts[4].empty() ? L"local-intelligence-pack" : parts[4],
        .source = L"signed-pack",
        .summary = parts[7],
        .details = parts.size() >= 9 ? parts[8] : L"",
        .verdict = parts[2]};

    SYSTEMTIME st{};
    GetSystemTime(&st);
    FILETIME ft{};
    SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = ft.dwLowDateTime;
    ticks.HighPart = ft.dwHighDateTime;
    ticks.QuadPart += static_cast<ULONGLONG>(ttlHours) * 60ull * 60ull * 10000000ull;
    ft.dwLowDateTime = ticks.LowPart;
    ft.dwHighDateTime = ticks.HighPart;
    SYSTEMTIME out{};
    FileTimeToSystemTime(&ft, &out);
    wchar_t buffer[64];
    swprintf(buffer, std::size(buffer), L"%04u-%02u-%02uT%02u:%02u:%02uZ", out.wYear, out.wMonth, out.wDay, out.wHour,
             out.wMinute, out.wSecond);
    lookupResult.expiresAt = buffer;

    database.UpsertThreatIntelRecord(ThreatIntelRecord{
        .indicatorType = lookupResult.indicatorType,
        .indicatorKey = lookupResult.indicatorKey,
        .provider = lookupResult.provider,
        .source = lookupResult.source,
        .verdict = lookupResult.verdict,
        .trustScore = lookupResult.trustScore,
        .providerWeight = lookupResult.providerWeight,
        .summary = lookupResult.summary,
        .details = lookupResult.details,
        .metadataJson = L"{\"ingested\":true}",
        .firstSeenAt = CurrentUtcTimestamp(),
        .lastSeenAt = CurrentUtcTimestamp(),
        .expiresAt = lookupResult.expiresAt,
        .signedPack = true,
        .localOnly = true});
    ++result.recordsLoaded;
  }

  result.success = result.recordsLoaded > 0 && result.recordsRejected == 0;
  if (!result.success && result.errorMessage.empty() && result.recordsLoaded > 0) {
    result.errorMessage = L"Threat intelligence pack loaded partially with rejected records.";
  }
  return result;
}

std::wstring DescribeReputationLookup(const ReputationLookupResult& result) {
  if (!result.attempted) {
    return L"intel-skipped";
  }
  if (result.malicious) {
    return result.fromCache ? L"intel-malicious-cache" : L"intel-malicious";
  }
  if (result.knownGood) {
    return result.fromCache ? L"intel-known-good-cache" : L"intel-known-good";
  }
  if (result.lookupSucceeded) {
    return result.fromCache ? L"intel-unknown-cache" : L"intel-unknown";
  }
  return result.fromCache ? L"intel-unavailable-cache" : L"intel-unavailable";
}

}  // namespace antivirus::agent
