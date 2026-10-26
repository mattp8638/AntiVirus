#include "ControlPlaneClient.h"
#include "CryptoUtils.h"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cwctype>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct HttpResponse {
  DWORD statusCode{0};
  std::string body;
};

std::wstring JoinUrl(const std::wstring& baseUrl, const std::wstring& path) {
  if (baseUrl.empty()) {
    return path;
  }

  if (baseUrl.back() == L'/' && path.starts_with(L"/")) {
    return baseUrl.substr(0, baseUrl.size() - 1) + path;
  }

  if (baseUrl.back() != L'/' && !path.starts_with(L"/")) {
    return baseUrl + L"/" + path;
  }

  return baseUrl + path;
}

bool EndsWithInsensitive(const std::wstring& value, const std::wstring& suffix) {
  if (suffix.size() > value.size()) {
    return false;
  }

  const auto offset = value.size() - suffix.size();
  for (std::size_t index = 0; index < suffix.size(); ++index) {
    if (std::towlower(value[offset + index]) != std::towlower(suffix[index])) {
      return false;
    }
  }

  return true;
}

bool IsHexSha256(const std::wstring& value) {
  if (value.size() != 64) {
    return false;
  }

  return std::all_of(value.begin(), value.end(), [](const wchar_t ch) {
    return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
  });
}

std::wstring NormalizeControlPlaneBaseUrl(std::wstring baseUrl) {
  while (!baseUrl.empty() && (baseUrl.back() == L' ' || baseUrl.back() == L'\t' || baseUrl.back() == L'\r' ||
                              baseUrl.back() == L'\n' || baseUrl.back() == L'/')) {
    baseUrl.pop_back();
  }

  if (EndsWithInsensitive(baseUrl, L"/api/v1")) {
    baseUrl.resize(baseUrl.size() - std::wstring(L"/api/v1").size());
  }

  return baseUrl;
}

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

std::wstring TrimWide(std::wstring value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }
  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return UnescapeJsonString(match[1].str());
  }

  return std::nullopt;
}

std::optional<bool> ExtractJsonBool(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(true|false)");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return match[1].str() == "true";
  }

  return std::nullopt;
}

std::optional<int> ExtractJsonInt(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return std::stoi(match[1].str());
  }

  return std::nullopt;
}

std::optional<std::string> ExtractJsonObject(const std::string& json, const std::string& key) {
  const auto keyToken = "\"" + key + "\"";
  const auto keyPosition = json.find(keyToken);
  if (keyPosition == std::string::npos) {
    return std::nullopt;
  }

  const auto objectStart = json.find('{', keyPosition);
  if (objectStart == std::string::npos) {
    return std::nullopt;
  }

  bool insideString = false;
  bool escaping = false;
  int depth = 0;

  for (std::size_t index = objectStart; index < json.size(); ++index) {
    const auto ch = json[index];

    if (insideString) {
      if (escaping) {
        escaping = false;
      } else if (ch == '\\') {
        escaping = true;
      } else if (ch == '"') {
        insideString = false;
      }

      continue;
    }

    if (ch == '"') {
      insideString = true;
      continue;
    }

    if (ch == '{') {
      ++depth;
      continue;
    }

    if (ch == '}') {
      --depth;
      if (depth == 0) {
        return json.substr(objectStart, index - objectStart + 1);
      }
    }
  }

  return std::nullopt;
}

std::vector<std::string> ExtractJsonObjectArray(const std::string& json, const std::string& key) {
  std::vector<std::string> objects;

  const auto keyToken = "\"" + key + "\"";
  const auto keyPosition = json.find(keyToken);
  if (keyPosition == std::string::npos) {
    return objects;
  }

  const auto arrayStart = json.find('[', keyPosition);
  if (arrayStart == std::string::npos) {
    return objects;
  }

  bool insideString = false;
  bool escaping = false;
  int objectDepth = 0;
  std::size_t objectStart = std::string::npos;

  for (std::size_t index = arrayStart + 1; index < json.size(); ++index) {
    const auto ch = json[index];

    if (insideString) {
      if (escaping) {
        escaping = false;
      } else if (ch == '\\') {
        escaping = true;
      } else if (ch == '"') {
        insideString = false;
      }

      continue;
    }

    if (ch == '"') {
      insideString = true;
      continue;
    }

    if (ch == ']') {
      break;
    }

    if (ch == '{') {
      if (objectDepth == 0) {
        objectStart = index;
      }

      ++objectDepth;
      continue;
    }

    if (ch == '}') {
      --objectDepth;
      if (objectDepth == 0 && objectStart != std::string::npos) {
        objects.push_back(json.substr(objectStart, index - objectStart + 1));
        objectStart = std::string::npos;
      }
    }
  }

  return objects;
}

std::vector<std::string> ExtractJsonStringArray(const std::string& json, const std::string& key) {
  std::vector<std::string> values;

  const auto keyToken = "\"" + key + "\"";
  const auto keyPosition = json.find(keyToken);
  if (keyPosition == std::string::npos) {
    return values;
  }

  const auto arrayStart = json.find('[', keyPosition);
  if (arrayStart == std::string::npos) {
    return values;
  }

  bool insideString = false;
  bool escaping = false;
  std::string current;

  for (std::size_t index = arrayStart + 1; index < json.size(); ++index) {
    const auto ch = json[index];

    if (!insideString) {
      if (ch == ']') {
        break;
      }

      if (ch == '"') {
        insideString = true;
        current.clear();
      }

      continue;
    }

    if (escaping) {
      current.push_back(ch);
      escaping = false;
      continue;
    }

    if (ch == '\\') {
      current.push_back(ch);
      escaping = true;
      continue;
    }

    if (ch == '"') {
      values.push_back(UnescapeJsonString(current));
      insideString = false;
      current.clear();
      continue;
    }

    current.push_back(ch);
  }

  return values;
}

std::wstring RequireString(const std::optional<std::string>& value, const char* fieldName) {
  if (!value.has_value()) {
    throw std::runtime_error(std::string("Missing JSON string field: ") + fieldName);
  }

  return Utf8ToWide(*value);
}

bool RequireBool(const std::optional<bool>& value, const char* fieldName) {
  if (!value.has_value()) {
    throw std::runtime_error(std::string("Missing JSON bool field: ") + fieldName);
  }

  return *value;
}

PolicySnapshot ParsePolicySnapshot(const std::string& json) {
  PolicySnapshot policy = CreateDefaultPolicySnapshot();
  policy.policyId = RequireString(ExtractJsonString(json, "id"), "id");
  policy.policyName = RequireString(ExtractJsonString(json, "name"), "name");
  policy.revision = RequireString(ExtractJsonString(json, "revision"), "revision");
  policy.realtimeProtectionEnabled = RequireBool(ExtractJsonBool(json, "realtimeProtection"), "realtimeProtection");
  policy.cloudLookupEnabled = RequireBool(ExtractJsonBool(json, "cloudLookup"), "cloudLookup");
  policy.scriptInspectionEnabled = RequireBool(ExtractJsonBool(json, "scriptInspection"), "scriptInspection");
  policy.networkContainmentEnabled = RequireBool(ExtractJsonBool(json, "networkContainment"), "networkContainment");
  policy.quarantineOnMalicious = RequireBool(ExtractJsonBool(json, "quarantineOnMalicious"), "quarantineOnMalicious");
  if (const auto value = ExtractJsonInt(json, "scanMaliciousBlockThreshold"); value.has_value()) {
    policy.scanMaliciousBlockThreshold = static_cast<std::uint32_t>(std::clamp(*value, 1, 99));
  }
  if (const auto value = ExtractJsonInt(json, "scanMaliciousQuarantineThreshold"); value.has_value()) {
    policy.scanMaliciousQuarantineThreshold =
        static_cast<std::uint32_t>(std::clamp(*value, static_cast<int>(policy.scanMaliciousBlockThreshold), 99));
  }
  if (const auto value = ExtractJsonInt(json, "scanBenignDampeningScore"); value.has_value()) {
    policy.scanBenignDampeningScore = static_cast<std::uint32_t>(std::clamp(*value, 0, 80));
  }
  if (const auto value = ExtractJsonInt(json, "genericRuleScoreScalePercent"); value.has_value()) {
    policy.genericRuleScoreScalePercent = static_cast<std::uint32_t>(std::clamp(*value, 20, 100));
  }
  if (const auto value = ExtractJsonInt(json, "realtimeExecuteBlockThreshold"); value.has_value()) {
    policy.realtimeExecuteBlockThreshold = static_cast<std::uint32_t>(std::clamp(*value, 40, 99));
  }
  if (const auto value = ExtractJsonInt(json, "realtimeNonExecuteBlockThreshold"); value.has_value()) {
    policy.realtimeNonExecuteBlockThreshold = static_cast<std::uint32_t>(std::clamp(*value, 50, 99));
  }
  if (const auto value = ExtractJsonInt(json, "realtimeQuarantineThreshold"); value.has_value()) {
    const auto minThreshold = std::max<int>(static_cast<int>(policy.realtimeExecuteBlockThreshold),
                                            static_cast<int>(policy.realtimeNonExecuteBlockThreshold));
    policy.realtimeQuarantineThreshold = static_cast<std::uint32_t>(std::clamp(*value, minThreshold, 99));
  }
  if (const auto value = ExtractJsonInt(json, "realtimeObserveTelemetryThreshold"); value.has_value()) {
    policy.realtimeObserveTelemetryThreshold = static_cast<std::uint32_t>(std::clamp(*value, 1, 95));
  }
  if (const auto value = ExtractJsonBool(json, "realtimeObserveOnlyForNonExecute"); value.has_value()) {
    policy.realtimeObserveOnlyForNonExecute = *value;
  }
  if (const auto value = ExtractJsonBool(json, "terminateProcessTreeOnExecuteBlock"); value.has_value()) {
    policy.terminateProcessTreeOnExecuteBlock = *value;
  }
  if (const auto value = ExtractJsonBool(json, "enforceProcessStartVerdicts"); value.has_value()) {
    policy.enforceProcessStartVerdicts = *value;
  }
  if (const auto value = ExtractJsonBool(json, "quarantineAfterProcessKill"); value.has_value()) {
    policy.quarantineAfterProcessKill = *value;
  }
  if (const auto value = ExtractJsonBool(json, "failServiceStartupIfRealtimeCoverageMissing"); value.has_value()) {
    policy.failServiceStartupIfRealtimeCoverageMissing = *value;
  }
  if (const auto value = ExtractJsonBool(json, "requireMinifilterBrokerConnection"); value.has_value()) {
    policy.requireMinifilterBrokerConnection = *value;
  }
  if (const auto value = ExtractJsonBool(json, "archiveObserveOnly"); value.has_value()) {
    policy.archiveObserveOnly = *value;
  }
  if (const auto value = ExtractJsonBool(json, "networkObserveOnly"); value.has_value()) {
    policy.networkObserveOnly = *value;
  }
  if (const auto value = ExtractJsonBool(json, "cloudLookupObserveOnly"); value.has_value()) {
    policy.cloudLookupObserveOnly = *value;
  }
  if (const auto value = ExtractJsonBool(json, "requireSignerForSuppression"); value.has_value()) {
    policy.requireSignerForSuppression = *value;
  }
  if (const auto value = ExtractJsonBool(json, "allowUnsignedSuppressionPathExecutables"); value.has_value()) {
    policy.allowUnsignedSuppressionPathExecutables = *value;
  }
  if (const auto value = ExtractJsonBool(json, "enableCleanwareSignerDampening"); value.has_value()) {
    policy.enableCleanwareSignerDampening = *value;
  }
  if (const auto value = ExtractJsonBool(json, "enableKnownGoodHashDampening"); value.has_value()) {
    policy.enableKnownGoodHashDampening = *value;
  }
  // Web and destination protection (cloud "web" policy section).
  if (const auto value = ExtractJsonBool(json, "destinationProtectionEnabled"); value.has_value()) {
    policy.destinationProtectionEnabled = *value;
  }
  if (const auto value = ExtractJsonBool(json, "antiPhishingEnabled"); value.has_value()) {
    policy.antiPhishingEnabled = *value;
  }
  if (const auto value = ExtractJsonBool(json, "webProtectionEnabled"); value.has_value()) {
    policy.webProtectionEnabled = *value;
  }
  if (const auto value = ExtractJsonBool(json, "emailLinkProtectionEnabled"); value.has_value()) {
    policy.emailLinkProtectionEnabled = *value;
  }
  if (const auto value = ExtractJsonBool(json, "evaluateDomains"); value.has_value()) {
    policy.evaluateDomains = *value;
  }
  if (const auto value = ExtractJsonBool(json, "evaluateUrls"); value.has_value()) {
    policy.evaluateUrls = *value;
  }
  if (const auto value = ExtractJsonBool(json, "blockKnownMaliciousDestinations"); value.has_value()) {
    policy.blockKnownMaliciousDestinations = *value;
  }
  if (const auto value = ExtractJsonBool(json, "blockKnownPhishingDestinations"); value.has_value()) {
    policy.blockKnownPhishingDestinations = *value;
  }
  if (const auto value = ExtractJsonBool(json, "blockKnownScamDestinations"); value.has_value()) {
    policy.blockKnownScamDestinations = *value;
  }
  if (const auto value = ExtractJsonBool(json, "warnOnSuspiciousDestinations"); value.has_value()) {
    policy.warnOnSuspiciousDestinations = *value;
  }
  if (const auto value = ExtractJsonBool(json, "warnOnNewlyRegisteredDomains"); value.has_value()) {
    policy.warnOnNewlyRegisteredDomains = *value;
  }
  if (const auto value = ExtractJsonBool(json, "allowDegradedDestinationModeWhenOffline"); value.has_value()) {
    policy.allowDegradedDestinationModeWhenOffline = *value;
  }
  if (const auto value = ExtractJsonBool(json, "browserContextRequiredForWarnOnly"); value.has_value()) {
    policy.browserContextRequiredForWarnOnly = *value;
  }
  if (const auto value = ExtractJsonInt(json, "suspiciousDestinationWarnThreshold"); value.has_value()) {
    policy.suspiciousDestinationWarnThreshold = static_cast<std::uint32_t>(std::clamp(*value, 1, 99));
  }
  if (const auto value = ExtractJsonInt(json, "phishingWarnThreshold"); value.has_value()) {
    policy.phishingWarnThreshold = static_cast<std::uint32_t>(std::clamp(*value, 1, 99));
  }
  if (const auto value = ExtractJsonInt(json, "phishingBlockThreshold"); value.has_value()) {
    policy.phishingBlockThreshold = static_cast<std::uint32_t>(std::clamp(*value, 1, 99));
  }
  if (const auto value = ExtractJsonInt(json, "destinationCacheTtlMinutes"); value.has_value()) {
    policy.destinationCacheTtlMinutes = static_cast<std::uint32_t>(std::clamp(*value, 5, 10080));
  }
  policy.phishingBlockThreshold = std::max(policy.phishingBlockThreshold, policy.phishingWarnThreshold);
  for (const auto& root : ExtractJsonStringArray(json, "suppressionPathRoots")) {
    const auto wide = Utf8ToWide(root);
    if (!wide.empty()) {
      policy.suppressionPathRoots.push_back(wide);
    }
  }
  for (const auto& sha256 : ExtractJsonStringArray(json, "suppressionSha256")) {
    const auto wide = Utf8ToWide(sha256);
    if (!wide.empty()) {
      policy.suppressionSha256.push_back(wide);
    }
  }
  if (const auto modules = ExtractJsonObject(json, "modules"); modules.has_value()) {
    policy.modulesJson = *modules;
  }
  for (const auto& signer : ExtractJsonStringArray(json, "suppressionSignerNames")) {
    const auto wide = Utf8ToWide(signer);
    if (!wide.empty()) {
      policy.suppressionSignerNames.push_back(wide);
    }
  }
  return policy;
}

std::wstring ExtractQueryParameter(const std::wstring& url, const std::wstring& name) {
  const auto queryStart = url.find(L'?');
  if (queryStart == std::wstring::npos) {
    return {};
  }

  const auto key = name + L"=";
  auto searchOffset = queryStart + 1;
  while (searchOffset < url.size()) {
    const auto keyOffset = url.find(key, searchOffset);
    if (keyOffset == std::wstring::npos) {
      return {};
    }

    if (keyOffset == queryStart + 1 || url[keyOffset - 1] == L'&') {
      const auto valueStart = keyOffset + key.size();
      const auto valueEnd = url.find(L'&', valueStart);
      return url.substr(valueStart, valueEnd == std::wstring::npos ? std::wstring::npos : valueEnd - valueStart);
    }

    searchOffset = keyOffset + key.size();
  }

  return {};
}

std::wstring ExtractDeviceApiKeyFromCommandChannelUrl(const std::wstring& commandChannelUrl) {
  return ExtractQueryParameter(commandChannelUrl, L"deviceApiKey");
}

HttpResponse RequestJson(const wchar_t* method, const std::wstring& url, const std::string& body = {},
                         const std::wstring& deviceApiKey = {}, const std::wstring& sharedToken = {}) {
  URL_COMPONENTS components{};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);

  if (WinHttpCrackUrl(url.c_str(), 0, 0, &components) == FALSE) {
    throw std::runtime_error("WinHttpCrackUrl failed");
  }

  const std::wstring host(components.lpszHostName, components.dwHostNameLength);
  std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
  if (components.dwExtraInfoLength > 0) {
    path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
  }

  const auto secure = components.nScheme == INTERNET_SCHEME_HTTPS;
  const auto* agentName = L"FenrirAgent/0.1";

  auto session = WinHttpOpen(agentName, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                             WINHTTP_NO_PROXY_BYPASS, 0);
  if (session == nullptr) {
    throw std::runtime_error("WinHttpOpen failed");
  }

  auto connection = WinHttpConnect(session, host.c_str(), components.nPort, 0);
  if (connection == nullptr) {
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpConnect failed");
  }

  auto request = WinHttpOpenRequest(connection, method, path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                    WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
  if (request == nullptr) {
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpOpenRequest failed");
  }

  const auto bodySize = static_cast<DWORD>(body.size());
  std::wstring headers = L"Content-Type: application/json\r\n";
  if (!deviceApiKey.empty()) {
    headers += L"X-Device-Api-Key: " + deviceApiKey + L"\r\n";
  }
  if (!sharedToken.empty()) {
    headers += L"X-Fenrir-Token: " + sharedToken + L"\r\n";
  }

  if (WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1), body.empty() ? WINHTTP_NO_REQUEST_DATA
                                                                                          : const_cast<char*>(body.data()),
                         bodySize, bodySize, 0) == FALSE) {
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpSendRequest failed");
  }

  if (WinHttpReceiveResponse(request, nullptr) == FALSE) {
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpReceiveResponse failed");
  }

  DWORD statusCode = 0;
  DWORD statusCodeSize = sizeof(statusCode);
  if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                          &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX) == FALSE) {
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpQueryHeaders failed");
  }

  std::string responseBody;
  for (;;) {
    DWORD availableBytes = 0;
    if (WinHttpQueryDataAvailable(request, &availableBytes) == FALSE) {
      WinHttpCloseHandle(request);
      WinHttpCloseHandle(connection);
      WinHttpCloseHandle(session);
      throw std::runtime_error("WinHttpQueryDataAvailable failed");
    }

    if (availableBytes == 0) {
      break;
    }

    std::string chunk(availableBytes, '\0');
    DWORD downloadedBytes = 0;
    if (WinHttpReadData(request, chunk.data(), availableBytes, &downloadedBytes) == FALSE) {
      WinHttpCloseHandle(request);
      WinHttpCloseHandle(connection);
      WinHttpCloseHandle(session);
      throw std::runtime_error("WinHttpReadData failed");
    }

    chunk.resize(downloadedBytes);
    responseBody += chunk;
  }

  WinHttpCloseHandle(request);
  WinHttpCloseHandle(connection);
  WinHttpCloseHandle(session);

  if (statusCode < 200 || statusCode >= 300) {
    if (statusCode == 404 && responseBody.find("\"error\":\"device_not_found\"") != std::string::npos) {
      std::ostringstream message;
      message << "Control-plane rejected the cached device identity: " << responseBody;
      throw DeviceIdentityRejectedError(message.str());
    }

    std::ostringstream message;
    message << "HTTP request failed with status " << statusCode << ": " << responseBody;
    throw std::runtime_error(message.str());
  }

  return HttpResponse{.statusCode = statusCode, .body = std::move(responseBody)};
}

RemoteCommand ParseRemoteCommand(const std::string& json) {
  return RemoteCommand{
      .commandId = RequireString(ExtractJsonString(json, "id"), "id"),
      .type = RequireString(ExtractJsonString(json, "type"), "type"),
      .issuedBy = RequireString(ExtractJsonString(json, "issuedBy"), "issuedBy"),
      .createdAt = RequireString(ExtractJsonString(json, "createdAt"), "createdAt"),
      .updatedAt = RequireString(ExtractJsonString(json, "updatedAt"), "updatedAt"),
      .targetPath = Utf8ToWide(ExtractJsonString(json, "targetPath").value_or("")),
      .recordId = Utf8ToWide(ExtractJsonString(json, "recordId").value_or("")),
      .payloadJson = Utf8ToWide(ExtractJsonString(json, "payloadJson").value_or(""))};
}

ControlPlaneUpdateOffer ParseControlPlaneUpdateOffer(const std::string& json) {
  return ControlPlaneUpdateOffer{
      .packageId = Utf8ToWide(ExtractJsonString(json, "packageId").value_or("")),
      .packageType = RequireString(ExtractJsonString(json, "packageType"), "packageType"),
      .targetVersion = RequireString(ExtractJsonString(json, "targetVersion"), "targetVersion"),
      .manifestPath = RequireString(ExtractJsonString(json, "manifestPath"), "manifestPath"),
      .mandatory = ExtractJsonBool(json, "mandatory").value_or(false)};
}

std::vector<std::wstring> SplitPatternText(const std::wstring& value) {
  std::vector<std::wstring> patterns;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == L';' || ch == L',') {
      const auto trimmed = TrimWide(current);
      if (!trimmed.empty()) {
        patterns.push_back(trimmed);
      }
      current.clear();
      continue;
    }

    current.push_back(ch);
  }

  const auto trailing = TrimWide(current);
  if (!trailing.empty()) {
    patterns.push_back(trailing);
  }

  return patterns;
}

std::vector<std::wstring> LoadPatternList(const std::string& json) {
  std::vector<std::wstring> patterns;
  for (const auto& item : ExtractJsonStringArray(json, "patterns")) {
    const auto wide = Utf8ToWide(item);
    if (!wide.empty()) {
      patterns.push_back(wide);
    }
  }
  if (!patterns.empty()) {
    return patterns;
  }

  if (const auto patternList = ExtractJsonString(json, "patternList"); patternList.has_value()) {
    return SplitPatternText(Utf8ToWide(*patternList));
  }
  if (const auto pattern = ExtractJsonString(json, "pattern"); pattern.has_value()) {
    return SplitPatternText(Utf8ToWide(*pattern));
  }
  if (const auto indicators = ExtractJsonString(json, "indicators"); indicators.has_value()) {
    return SplitPatternText(Utf8ToWide(*indicators));
  }

  return patterns;
}

std::wstring RequireOrFallbackString(const std::string& json, const std::vector<std::string>& keys,
                                     const std::wstring& fallback) {
  for (const auto& key : keys) {
    if (const auto value = ExtractJsonString(json, key); value.has_value()) {
      const auto wide = TrimWide(Utf8ToWide(*value));
      if (!wide.empty()) {
        return wide;
      }
    }
  }
  return fallback;
}

SignatureRuleDelta ParseSignatureRuleDelta(const std::string& json) {
  SignatureRuleDelta rule;
  rule.scope = ToLowerCopy(RequireOrFallbackString(json, {"scope", "target", "matchScope"}, L"text"));
  rule.code = RequireOrFallbackString(json, {"code", "id", "ruleId"}, L"");
  rule.message = RequireOrFallbackString(json, {"message", "description", "summary"}, L"Cloud-fed detection rule");
  rule.tacticId = RequireOrFallbackString(json, {"tacticId", "tactic", "attackTactic"}, L"TA0002");
  rule.techniqueId = RequireOrFallbackString(json, {"techniqueId", "technique", "attackTechnique"}, L"T1204.002");
  rule.score = std::clamp(ExtractJsonInt(json, "score").value_or(26), 1, 99);
  rule.patterns = LoadPatternList(json);
  return rule;
}

std::wstring BuildFeedRuleCode(const std::wstring& prefix, const std::wstring& value) {
  auto normalized = ToLowerCopy(TrimWide(value));
  for (auto& ch : normalized) {
    if ((ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9') || ch == L'_') {
      continue;
    }
    ch = L'_';
  }
  if (normalized.size() > 20) {
    normalized.resize(20);
  }
  return prefix + normalized;
}

std::wstring BuildThreatIntelMetadataJson(const std::wstring& id, const std::wstring& family,
                                          const std::wstring& threat, const std::wstring& status) {
  std::wstring metadata = L"{";
  bool needsComma = false;
  const auto appendField = [&metadata, &needsComma](const wchar_t* key, const std::wstring& value) {
    if (value.empty()) {
      return;
    }
    if (needsComma) {
      metadata += L",";
    }
    metadata += L"\"" + std::wstring(key) + L"\":\"" + Utf8ToWide(EscapeJsonString(value)) + L"\"";
    needsComma = true;
  };
  appendField(L"id", id);
  appendField(L"malwareFamily", family);
  appendField(L"threat", threat);
  appendField(L"status", status);
  metadata += L"}";
  return metadata;
}

ThreatIntelRecord BuildFeedThreatIntelRecord(const ThreatIndicatorType indicatorType, const std::wstring& indicatorKey,
                                             const std::wstring& source, const std::wstring& summary,
                                             const std::wstring& details, const std::wstring& metadataJson,
                                             const std::wstring& firstSeenAt) {
  const auto now = CurrentUtcTimestamp();
  return ThreatIntelRecord{
      .indicatorType = indicatorType,
      .indicatorKey = ToLowerCopy(TrimWide(indicatorKey)),
      .provider = L"fenrir-signature-feed",
      .source = source.empty() ? L"signaturedb-fenrir" : source,
      .verdict = L"malicious",
      .trustScore = 10,
      .providerWeight = 96,
      .summary = summary,
      .details = details,
      .metadataJson = metadataJson,
      .firstSeenAt = firstSeenAt.empty() ? now : firstSeenAt,
      .lastSeenAt = now,
      .expiresAt = L"",
      .signedPack = false,
      .localOnly = true};
}

std::vector<SignatureRuleDelta> ParseFeedHashRules(const std::string& json) {
  std::vector<SignatureRuleDelta> rules;
  for (const auto& itemJson : ExtractJsonObjectArray(json, "hashes")) {
    const auto type = ToLowerCopy(TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "type").value_or("sha256"))));
    const auto value = ToLowerCopy(TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "value").value_or(""))));
    if (type != L"sha256" || !IsHexSha256(value)) {
      continue;
    }

    const auto family = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "malwareFamily").value_or("")));
    const auto source = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "source").value_or("signature-feed")));
    rules.push_back(SignatureRuleDelta{
        .scope = L"sha256",
        .code = BuildFeedRuleCode(L"FEED_SHA256_", value),
        .message = family.empty() ? L"Signature feed matched a malicious SHA-256 indicator."
                                  : L"Signature feed matched malicious SHA-256 indicator for " + family + L".",
        .tacticId = L"TA0002",
        .techniqueId = L"T1204.002",
        .score = 92,
        .patterns = {value}});
  }
  return rules;
}

std::vector<ThreatIntelRecord> ParseFeedThreatIntelRecords(const std::string& json) {
  std::vector<ThreatIntelRecord> records;

  for (const auto& itemJson : ExtractJsonObjectArray(json, "hashes")) {
    const auto type = ToLowerCopy(TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "type").value_or("sha256"))));
    const auto value = ToLowerCopy(TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "value").value_or(""))));
    if (type != L"sha256" || !IsHexSha256(value)) {
      continue;
    }

    const auto source = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "source").value_or("signaturedb-fenrir")));
    const auto family = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "malwareFamily").value_or("")));
    const auto firstSeen = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "firstSeen").value_or("")));
    const auto id = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "id").value_or("")));
    const auto summary = family.empty() ? L"Malicious SHA-256 indicator from the Fenrir signature feed."
                                        : L"Malicious SHA-256 indicator for " + family + L".";
    records.push_back(BuildFeedThreatIntelRecord(
        ThreatIndicatorType::Sha256, value, source, summary,
        L"The endpoint appended this hash from the hosted Fenrir signature definitions feed.",
        BuildThreatIntelMetadataJson(id, family, L"", L""), firstSeen));
  }

  for (const auto& itemJson : ExtractJsonObjectArray(json, "urls")) {
    const auto url = ToLowerCopy(TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "url").value_or(""))));
    const auto host = ToLowerCopy(TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "host").value_or(""))));
    const auto source = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "source").value_or("signaturedb-fenrir")));
    const auto threat = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "threat").value_or("")));
    const auto status = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "status").value_or("")));
    const auto firstSeen = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "firstSeen").value_or("")));
    const auto id = TrimWide(Utf8ToWide(ExtractJsonString(itemJson, "id").value_or("")));
    const auto summary = threat.empty() ? L"Malicious URL indicator from the Fenrir signature feed."
                                        : L"Malicious URL indicator for " + threat + L".";
    const auto metadata = BuildThreatIntelMetadataJson(id, L"", threat, status);

    if (!url.empty()) {
      records.push_back(BuildFeedThreatIntelRecord(
          ThreatIndicatorType::Url, url, source, summary,
          L"The endpoint appended this URL from the hosted Fenrir signature definitions feed.", metadata, firstSeen));
    }
    if (!host.empty()) {
      records.push_back(BuildFeedThreatIntelRecord(
          ThreatIndicatorType::Domain, host, source, L"Malicious domain indicator from the Fenrir signature feed.",
          L"The endpoint appended this host from a URL indicator in the hosted Fenrir signature definitions feed.",
          metadata, firstSeen));
    }
  }

  return records;
}

std::vector<SignatureRuleDelta> ParseSignatureRuleDeltas(const std::string& json) {
  std::vector<SignatureRuleDelta> rules;

  auto items = ExtractJsonObjectArray(json, "signatures");
  if (items.empty()) {
    items = ExtractJsonObjectArray(json, "signatureRules");
  }
  if (items.empty()) {
    items = ExtractJsonObjectArray(json, "rules");
  }
  if (items.empty()) {
    items = ExtractJsonObjectArray(json, "items");
  }

  for (const auto& item : items) {
    auto parsed = ParseSignatureRuleDelta(item);
    if (parsed.patterns.empty()) {
      continue;
    }
    if (parsed.code.empty()) {
      parsed.code = L"CLOUD_SIGNATURE_" + std::to_wstring(rules.size() + 1);
    }
    rules.push_back(std::move(parsed));
  }

  return rules;
}

std::vector<std::wstring> ParseYaraRules(const std::string& json) {
  std::vector<std::wstring> rules;

  for (const auto& item : ExtractJsonStringArray(json, "yaraRules")) {
    const auto wide = TrimWide(Utf8ToWide(item));
    if (!wide.empty()) {
      rules.push_back(wide);
    }
  }
  for (const auto& item : ExtractJsonStringArray(json, "yara")) {
    const auto wide = TrimWide(Utf8ToWide(item));
    if (!wide.empty()) {
      rules.push_back(wide);
    }
  }
  for (const auto& objectJson : ExtractJsonObjectArray(json, "yaraRules")) {
    const auto text = RequireOrFallbackString(objectJson, {"rule", "text", "source", "content"}, L"");
    if (!text.empty()) {
      rules.push_back(text);
    }
  }
  for (const auto& objectJson : ExtractJsonObjectArray(json, "yara")) {
    const auto text = RequireOrFallbackString(objectJson, {"rule", "text", "source", "content"}, L"");
    if (!text.empty()) {
      rules.push_back(text);
    }
  }
  for (const auto& objectJson : ExtractJsonObjectArray(json, "rules")) {
    const auto ruleType = ToLowerCopy(RequireOrFallbackString(objectJson, {"ruleType", "type"}, L""));
    if (ruleType != L"yara") {
      continue;
    }

    const auto text = RequireOrFallbackString(objectJson, {"rule", "text", "source", "content"}, L"");
    if (!text.empty()) {
      rules.push_back(text);
    }
  }

  std::sort(rules.begin(), rules.end());
  rules.erase(std::unique(rules.begin(), rules.end()), rules.end());
  return rules;
}

}  // namespace

ControlPlaneClient::ControlPlaneClient(std::wstring baseUrl) : baseUrl_(NormalizeControlPlaneBaseUrl(std::move(baseUrl))) {}

EnrollmentResult ControlPlaneClient::Enroll(const AgentState& state, const std::wstring& enrollmentToken) const {
  std::ostringstream body;
  body << "{"
       << "\"hostname\":\"" << EscapeJsonString(state.hostname) << "\","
       << "\"osVersion\":\"" << EscapeJsonString(state.osVersion) << "\","
       << "\"platform\":\"windows\","
       << "\"agentVersion\":\"" << EscapeJsonString(state.agentVersion) << "\","
       << "\"enrollmentToken\":\"" << EscapeJsonString(enrollmentToken) << "\","
       << "\"serialNumber\":\"" << EscapeJsonString(state.serialNumber) << "\""
       << "}";

  const auto response = RequestJson(L"POST", JoinUrl(baseUrl_, L"/api/v1/enroll"), body.str());
  const auto policyObject = ExtractJsonObject(response.body, "policy");
  if (!policyObject.has_value()) {
    throw std::runtime_error("Enrollment response did not include a policy object");
  }

  return EnrollmentResult{
      .deviceId = RequireString(ExtractJsonString(response.body, "deviceId"), "deviceId"),
      .issuedAt = RequireString(ExtractJsonString(response.body, "issuedAt"), "issuedAt"),
      .commandChannelUrl = RequireString(ExtractJsonString(response.body, "commandChannelUrl"), "commandChannelUrl"),
      .policy = ParsePolicySnapshot(*policyObject)};
}

std::wstring ControlPlaneClient::DeviceApiKey(const AgentState& state) {
  return ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);
}

std::wstring ControlPlaneClient::RealtimeUrl(const AgentState& state) const {
  auto base = baseUrl_;
  while (!base.empty() && base.back() == L'/') {
    base.pop_back();
  }
  if (base.size() > 7 && base.compare(base.size() - 7, 7, L"/api/v1") == 0) {
    base.resize(base.size() - 7);
  }
  if (base.rfind(L"https://", 0) == 0) {
    base = L"wss://" + base.substr(8);
  } else if (base.rfind(L"http://", 0) == 0) {
    base = L"ws://" + base.substr(7);
  }
  return base + L"/api/v1/devices/" + state.deviceId + L"/realtime";
}

HeartbeatResult ControlPlaneClient::SendHeartbeat(const AgentState& state, const std::string& metricsJson) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot send heartbeat without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  std::ostringstream body;
  body << "{"
       << "\"agentVersion\":\"" << EscapeJsonString(state.agentVersion) << "\","
       << "\"platformVersion\":\"" << EscapeJsonString(state.platformVersion) << "\","
       << "\"healthState\":\"" << EscapeJsonString(state.healthState) << "\","
       << "\"isolated\":" << (state.isolated ? "true" : "false");
  if (!metricsJson.empty()) {
    body << ",\"metrics\":" << metricsJson;
  }
  body << "}";

  const auto response =
      RequestJson(L"POST", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/heartbeat"), body.str(),
                  deviceApiKey);

  return HeartbeatResult{
      .receivedAt = RequireString(ExtractJsonString(response.body, "receivedAt"), "receivedAt"),
      .effectivePolicyRevision =
          RequireString(ExtractJsonString(response.body, "effectivePolicyRevision"), "effectivePolicyRevision"),
      .commandsPending = ExtractJsonInt(response.body, "commandsPending").value_or(0)};
}

PolicyCheckInResult ControlPlaneClient::CheckInPolicy(const AgentState& state) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot check in policy without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  std::ostringstream body;
  body << "{"
       << "\"currentPolicyRevision\":\"" << EscapeJsonString(state.policy.revision) << "\","
       << "\"agentVersion\":\"" << EscapeJsonString(state.agentVersion) << "\","
       << "\"platformVersion\":\"" << EscapeJsonString(state.platformVersion) << "\""
       << "}";

  const auto response =
      RequestJson(L"POST", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/policy-check-in"), body.str(),
                  deviceApiKey);
  const auto policyObject = ExtractJsonObject(response.body, "policy");
  if (!policyObject.has_value()) {
    throw std::runtime_error("Policy check-in response did not include a policy object");
  }

  return PolicyCheckInResult{
      .retrievedAt = RequireString(ExtractJsonString(response.body, "retrievedAt"), "retrievedAt"),
      .changed = RequireBool(ExtractJsonBool(response.body, "changed"), "changed"),
      .policy = ParsePolicySnapshot(*policyObject)};
}

TelemetryBatchResult ControlPlaneClient::SendTelemetryBatch(const AgentState& state,
                                                            const std::vector<TelemetryRecord>& records) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot send telemetry without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  if (records.empty()) {
    return TelemetryBatchResult{};
  }

  std::ostringstream body;
  body << "{\"events\":[";
  for (std::size_t index = 0; index < records.size(); ++index) {
    const auto& record = records[index];
    if (index != 0) {
      body << ',';
    }

    body << "{"
         << "\"eventId\":\"" << EscapeJsonString(record.eventId) << "\","
         << "\"eventType\":\"" << EscapeJsonString(record.eventType) << "\","
         << "\"source\":\"" << EscapeJsonString(record.source) << "\","
         << "\"summary\":\"" << EscapeJsonString(record.summary) << "\","
         << "\"occurredAt\":\"" << EscapeJsonString(record.occurredAt) << "\","
         << "\"payloadJson\":\"" << EscapeJsonString(record.payloadJson) << "\""
         << "}";
  }
  body << "]}";

  const auto response =
      RequestJson(L"POST", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/telemetry"), body.str(),
                  deviceApiKey);

  return TelemetryBatchResult{
      .receivedAt = RequireString(ExtractJsonString(response.body, "receivedAt"), "receivedAt"),
      .accepted = ExtractJsonInt(response.body, "accepted").value_or(0),
      .totalStored = ExtractJsonInt(response.body, "totalStored").value_or(0)};
}

CommandPollResult ControlPlaneClient::PollPendingCommands(const AgentState& state, const int limit, const std::wstring& types) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot poll commands without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  const auto response = RequestJson(
      L"GET", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/commands/pending?limit=" + std::to_wstring(limit) +
                                      (types.empty() ? std::wstring() : L"&types=" + types)),
      {}, deviceApiKey);

  CommandPollResult result{
      .polledAt = RequireString(ExtractJsonString(response.body, "polledAt"), "polledAt"),
      .items = {}};

  for (const auto& itemJson : ExtractJsonObjectArray(response.body, "items")) {
    result.items.push_back(ParseRemoteCommand(itemJson));
  }

  return result;
}

void ControlPlaneClient::CompleteCommand(const AgentState& state, const std::wstring& commandId,
                                         const std::wstring& status, const std::wstring& resultJson) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot complete a command without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  std::ostringstream body;
  body << "{"
       << "\"status\":\"" << EscapeJsonString(status) << "\"";

  if (!resultJson.empty()) {
    body << ",\"resultJson\":\"" << EscapeJsonString(resultJson) << "\"";
  }

  body << "}";

  static_cast<void>(RequestJson(
      L"POST", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/commands/" + commandId + L"/complete"),
      body.str(), deviceApiKey));
}

std::wstring ControlPlaneClient::UploadCommandArtifact(const AgentState& state, const std::wstring& commandId,
                                                     const std::wstring& filename, const std::string& data) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot upload a bundle without a device identifier");
  }
  std::wstring safeName;
  for (const auto ch : filename) {
    safeName += (std::iswalnum(ch) || ch == L'.' || ch == L'-' || ch == L'_') ? ch : L'_';
  }
  const auto sha256 = ComputeBufferSha256(reinterpret_cast<const unsigned char*>(data.data()), data.size());
  const auto response = RequestJson(
      L"POST",
      JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/commands/" + commandId + L"/artifact?filename=" + safeName +
                            L"&sha256=" + sha256),
      data, ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl));
  return RequireString(ExtractJsonString(response.body, "artifactId"), "artifactId");
}

UpdateCheckResult ControlPlaneClient::CheckForUpdates(const AgentState& state, const std::wstring& signaturesVersion,
                                                      const std::wstring& channel) const {
  std::ostringstream body;
  body << "{"
       << "\"agentVersion\":\"" << EscapeJsonString(state.agentVersion) << "\","
       << "\"platformVersion\":\"" << EscapeJsonString(state.platformVersion) << "\"";
  if (!signaturesVersion.empty()) {
    body << ",\"signaturesVersion\":\"" << EscapeJsonString(signaturesVersion) << "\"";
  }
  if (!channel.empty()) {
    body << ",\"channel\":\"" << EscapeJsonString(channel) << "\"";
  }
  body << "}";

  const auto response = RequestJson(L"POST", JoinUrl(baseUrl_, L"/api/v1/update-check"), body.str());

  UpdateCheckResult result{
      .checkedAt = Utf8ToWide(ExtractJsonString(response.body, "checkedAt").value_or(WideToUtf8(CurrentUtcTimestamp()))),
      .items = {}};

  auto updateItems = ExtractJsonObjectArray(response.body, "updates");
  if (updateItems.empty()) {
    updateItems = ExtractJsonObjectArray(response.body, "items");
  }

  for (const auto& itemJson : updateItems) {
    result.items.push_back(ParseControlPlaneUpdateOffer(itemJson));
  }

  return result;
}

MlModelManifest ControlPlaneClient::FetchMlModelManifest(const AgentState& state) const {
  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);
  const auto response = RequestJson(L"GET", JoinUrl(baseUrl_, L"/api/v1/agent/model/manifest"), {}, deviceApiKey);
  return MlModelManifest{.version = Utf8ToWide(ExtractJsonString(response.body, "version").value_or("")),
                         .sha256 = Utf8ToWide(ExtractJsonString(response.body, "sha256").value_or("")),
                         .size = ExtractJsonInt(response.body, "size").value_or(0)};
}

std::vector<unsigned char> ControlPlaneClient::DownloadMlModel(const AgentState& state) const {
  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);
  const auto response = RequestJson(L"GET", JoinUrl(baseUrl_, L"/api/v1/agent/model"), {}, deviceApiKey);
  return std::vector<unsigned char>(response.body.begin(), response.body.end());
}

SignatureDeltaResult ControlPlaneClient::FetchSignatureDelta(const std::wstring& currentSignatureVersion,
                                                             const std::wstring& currentYaraVersion,
                                                             const std::wstring& signatureFeedToken) const {
  std::ostringstream body;
  body << "{";
  bool needsComma = false;
  if (!currentSignatureVersion.empty()) {
    body << "\"signatureVersion\":\"" << EscapeJsonString(currentSignatureVersion) << "\"";
    needsComma = true;
  }
  if (!currentYaraVersion.empty()) {
    if (needsComma) {
      body << ",";
    }
    body << "\"yaraVersion\":\"" << EscapeJsonString(currentYaraVersion) << "\"";
  }
  body << "}";

  const std::vector<std::wstring> endpointCandidates{
      L"/api/v1/agent/bundle?hashesLimit=50000&urlsLimit=50000&rulesLimit=5000",
      L"/api/v1/signatures/delta",
      L"/api/v1/signature-db/delta",
      L"/api/v1/signatures",
      L"/api/v1/signature-db"};

  std::optional<HttpResponse> response;
  std::string lastError;
  for (const auto& endpoint : endpointCandidates) {
    try {
      response = RequestJson(L"POST", JoinUrl(baseUrl_, endpoint), body.str(), L"", signatureFeedToken);
      break;
    } catch (const std::exception& postError) {
      lastError = postError.what();
      try {
        response = RequestJson(L"GET", JoinUrl(baseUrl_, endpoint), {}, L"", signatureFeedToken);
        break;
      } catch (const std::exception& getError) {
        lastError = getError.what();
      }
    }
  }

  if (!response.has_value()) {
    throw std::runtime_error("Could not retrieve signature intelligence delta: " + lastError);
  }

  SignatureDeltaResult result{
      .checkedAt =
          Utf8ToWide(ExtractJsonString(response->body, "checkedAt").value_or(WideToUtf8(CurrentUtcTimestamp()))),
      .signatureVersion = Utf8ToWide(ExtractJsonString(response->body, "signatureVersion")
                                         .value_or(ExtractJsonString(response->body, "version").value_or(""))),
      .yaraVersion = Utf8ToWide(ExtractJsonString(response->body, "yaraVersion").value_or("")),
      .signatures = ParseSignatureRuleDeltas(response->body),
      .yaraRules = ParseYaraRules(response->body),
      .threatIntelRecords = ParseFeedThreatIntelRecords(response->body)};

  auto feedHashRules = ParseFeedHashRules(response->body);
  result.signatures.insert(result.signatures.end(), feedHashRules.begin(), feedHashRules.end());

  return result;
}

}  // namespace antivirus::agent
