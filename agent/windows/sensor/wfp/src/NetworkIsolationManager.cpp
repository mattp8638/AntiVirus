#include "NetworkIsolationManager.h"

#include <winsock2.h>
#include <Windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <winhttp.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../../../service/include/StringUtils.h"
#include "../../../service/include/DestinationRuntimeStore.h"

namespace antivirus::agent {
namespace {

constexpr GUID kAgentProviderKey = {0x51d9501d, 0x6b2f, 0x4cd0, {0xa1, 0x4f, 0x28, 0x13, 0x5e, 0x77, 0x8d, 0x10}};
constexpr GUID kIsolationSubLayerKey = {0x89b894f1, 0x25b0, 0x4dc6, {0x9b, 0xcb, 0x15, 0x7e, 0x4e, 0xf6, 0x40, 0x63}};
constexpr GUID kLayerAleAuthConnectV4 = {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
constexpr GUID kLayerAleAuthConnectV6 = {0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}};
constexpr GUID kLayerAleAuthRecvAcceptV4 = {0xe1cd9fe7, 0xf4b5, 0x4273, {0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}};
constexpr GUID kLayerAleAuthRecvAcceptV6 = {0xa3b42c97, 0x9f04, 0x4672, {0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}};
constexpr GUID kConditionFlags = {0x632ce23b, 0x5167, 0x435c, {0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}};
constexpr GUID kConditionAleAppId = {0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
constexpr GUID kConditionIpRemoteAddressV4 = {0x1febb610, 0x3bcc, 0x45e1, {0xbc, 0x36, 0x2e, 0x06, 0x7e, 0x2c, 0xb1, 0x86}};
constexpr GUID kConditionIpRemoteAddressV6 = {0x246e1d8c, 0x8bee, 0x4018, {0x9b, 0x98, 0x31, 0xd4, 0x58, 0x2f, 0x33, 0x61}};
#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC (0x00000001)
#endif
constexpr auto kDestinationReconcileInterval = std::chrono::minutes(5);

std::wstring SafeBlobToWideString(const FWP_BYTE_BLOB* blob) {
  if (blob == nullptr || blob->data == nullptr || blob->size == 0) {
    return {};
  }

  const auto* value = reinterpret_cast<const wchar_t*>(blob->data);
  std::wstring result(value, blob->size / sizeof(wchar_t));
  while (!result.empty() && result.back() == L'\0') {
    result.pop_back();
  }
  return result;
}

std::wstring SidToString(PSID sid) {
  if (sid == nullptr || IsValidSid(sid) == FALSE) {
    return {};
  }

  LPWSTR stringSid = nullptr;
  if (ConvertSidToStringSidW(sid, &stringSid) == FALSE || stringSid == nullptr) {
    return {};
  }

  const std::wstring result(stringSid);
  LocalFree(stringSid);
  return result;
}

std::wstring BaseNameFromPath(const std::wstring& pathValue) {
  if (pathValue.empty()) {
    return {};
  }

  const auto fileName = std::filesystem::path(pathValue).filename().wstring();
  return fileName.empty() ? pathValue : fileName;
}

std::wstring QueryProcessImagePath(const DWORD pid) {
  if (pid == 0) {
    return {};
  }

  const auto processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return {};
  }

  std::wstring buffer(4096, L'\0');
  DWORD pathLength = static_cast<DWORD>(buffer.size());
  if (QueryFullProcessImageNameW(processHandle, 0, buffer.data(), &pathLength) == FALSE) {
    CloseHandle(processHandle);
    return {};
  }

  CloseHandle(processHandle);
  buffer.resize(pathLength);
  return buffer;
}

std::wstring NormalizeAppIdPath(const std::wstring& pathValue) {
  if (pathValue.empty()) {
    return {};
  }

  auto normalized = pathValue;
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return normalized;
}

std::wstring AddressToString(const FWP_IP_VERSION ipVersion, const UINT32 addressV4, const FWP_BYTE_ARRAY16* addressV6) {
  wchar_t buffer[INET6_ADDRSTRLEN] = {};

  if (ipVersion == FWP_IP_VERSION_V4) {
    IN_ADDR address{};
    address.S_un.S_addr = addressV4;
    if (InetNtopW(AF_INET, &address, buffer, ARRAYSIZE(buffer)) != nullptr) {
      return buffer;
    }
    return {};
  }

  if (ipVersion == FWP_IP_VERSION_V6 && addressV6 != nullptr) {
    IN6_ADDR address{};
    std::memcpy(address.u.Byte, addressV6->byteArray16, sizeof(address.u.Byte));
    if (InetNtopW(AF_INET6, &address, buffer, ARRAYSIZE(buffer)) != nullptr) {
      return buffer;
    }
  }

  return {};
}

std::optional<UINT32> ParseIpv4Address(const std::wstring& addressText) {
  IN_ADDR address{};
  if (InetPtonW(AF_INET, addressText.c_str(), &address) != 1) {
    return std::nullopt;
  }

  return address.S_un.S_addr;
}

std::optional<FWP_BYTE_ARRAY16> ParseIpv6Address(const std::wstring& addressText) {
  IN6_ADDR address{};
  if (InetPtonW(AF_INET6, addressText.c_str(), &address) != 1) {
    return std::nullopt;
  }

  FWP_BYTE_ARRAY16 value{};
  std::memcpy(value.byteArray16, address.u.Byte, sizeof(value.byteArray16));
  return value;
}

UINT16 HostToNetworkOrder(const UINT16 value) { return htons(value); }
UINT16 NetworkToHostOrder(const UINT16 value) { return ntohs(value); }

std::optional<std::wstring> ExtractHostFromUrl(const std::wstring& url) {
  URL_COMPONENTSW components{};
  components.dwStructSize = sizeof(components);
  components.dwHostNameLength = static_cast<DWORD>(-1);

  std::wstring mutableUrl = url;
  if (WinHttpCrackUrl(mutableUrl.data(), static_cast<DWORD>(mutableUrl.size()), 0, &components) == FALSE ||
      components.dwHostNameLength == 0) {
    return std::nullopt;
  }

  return std::wstring(components.lpszHostName, components.dwHostNameLength);
}

std::vector<std::wstring> ResolveHostAddresses(const std::wstring& host) {
  std::vector<std::wstring> results;
  if (host.empty()) {
    return results;
  }

  ADDRINFOW hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  ADDRINFOW* resultList = nullptr;
  if (GetAddrInfoW(host.c_str(), nullptr, &hints, &resultList) != 0 || resultList == nullptr) {
    return results;
  }

  std::set<std::wstring> unique;
  for (auto* entry = resultList; entry != nullptr; entry = entry->ai_next) {
    wchar_t buffer[INET6_ADDRSTRLEN] = {};
    if (entry->ai_family == AF_INET) {
      const auto* sockaddr = reinterpret_cast<const SOCKADDR_IN*>(entry->ai_addr);
      if (InetNtopW(AF_INET, &sockaddr->sin_addr, buffer, ARRAYSIZE(buffer)) != nullptr) {
        unique.insert(buffer);
      }
    } else if (entry->ai_family == AF_INET6) {
      const auto* sockaddr = reinterpret_cast<const SOCKADDR_IN6*>(entry->ai_addr);
      if (InetNtopW(AF_INET6, &sockaddr->sin6_addr, buffer, ARRAYSIZE(buffer)) != nullptr) {
        unique.insert(buffer);
      }
    }
  }

  FreeAddrInfoW(resultList);
  results.assign(unique.begin(), unique.end());
  return results;
}

std::vector<std::wstring> BuildEffectiveAllowedRemoteAddresses(const AgentConfig& config) {
  std::set<std::wstring> results;
  for (const auto& address : config.isolationAllowedRemoteAddresses) {
    if (!address.empty()) {
      results.insert(address);
    }
  }

  const auto host = ExtractHostFromUrl(config.controlPlaneBaseUrl);
  if (host.has_value()) {
    if (*host == L"localhost") {
      results.insert(L"127.0.0.1");
      results.insert(L"::1");
    } else {
      const auto resolved = ResolveHostAddresses(*host);
      results.insert(resolved.begin(), resolved.end());
    }
  }

  return std::vector<std::wstring>(results.begin(), results.end());
}

struct SnapshotConnection {
  DWORD pid{0};
  std::wstring protocol;
  std::wstring state;
  std::wstring localAddress;
  UINT16 localPort{0};
  std::wstring remoteAddress;
  UINT16 remotePort{0};
  std::wstring processImagePath;
};

std::wstring TcpStateToString(const DWORD state) {
  switch (state) {
    case MIB_TCP_STATE_CLOSED: return L"closed";
    case MIB_TCP_STATE_LISTEN: return L"listen";
    case MIB_TCP_STATE_SYN_SENT: return L"syn-sent";
    case MIB_TCP_STATE_SYN_RCVD: return L"syn-recv";
    case MIB_TCP_STATE_ESTAB: return L"established";
    case MIB_TCP_STATE_FIN_WAIT1: return L"fin-wait-1";
    case MIB_TCP_STATE_FIN_WAIT2: return L"fin-wait-2";
    case MIB_TCP_STATE_CLOSE_WAIT: return L"close-wait";
    case MIB_TCP_STATE_CLOSING: return L"closing";
    case MIB_TCP_STATE_LAST_ACK: return L"last-ack";
    case MIB_TCP_STATE_TIME_WAIT: return L"time-wait";
    case MIB_TCP_STATE_DELETE_TCB: return L"delete-tcb";
    default: return L"unknown";
  }
}

std::wstring FileTimeToUtcString(const ULONGLONG rawValue) {
  if (rawValue == 0) {
    return {};
  }
  FILETIME fileTime{};
  fileTime.dwLowDateTime = static_cast<DWORD>(rawValue & 0xffffffffULL);
  fileTime.dwHighDateTime = static_cast<DWORD>((rawValue >> 32U) & 0xffffffffULL);
  SYSTEMTIME systemTime{};
  if (FileTimeToSystemTime(&fileTime, &systemTime) == FALSE) {
    return {};
  }
  wchar_t buffer[32] = {};
  swprintf(buffer, 32, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", systemTime.wYear, systemTime.wMonth,
           systemTime.wDay, systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds);
  return std::wstring(buffer);
}

bool IsInterestingNetworkProcess(const std::wstring& pathValue) {
  const auto imageName = NormalizeAppIdPath(BaseNameFromPath(pathValue));
  static const std::array<const wchar_t*, 10> interesting = {
      L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"wscript.exe", L"cscript.exe",
      L"mshta.exe", L"rundll32.exe", L"regsvr32.exe", L"outlook.exe", L"chrome.exe",
  };
  return std::any_of(interesting.begin(), interesting.end(),
                     [&imageName](const auto* candidate) { return imageName == candidate; });
}

struct FilterConditionHolder {
  FWPM_FILTER_CONDITION0 condition{};
  std::unique_ptr<FWP_BYTE_BLOB> byteBlob{};
  std::unique_ptr<FWP_V4_ADDR_AND_MASK> v4Mask{};
  std::unique_ptr<FWP_BYTE_ARRAY16> byteArray16{};
};

FilterConditionHolder BuildLoopbackCondition() {
  FilterConditionHolder holder{};
  holder.condition.fieldKey = kConditionFlags;
  holder.condition.matchType = FWP_MATCH_FLAGS_ALL_SET;
  holder.condition.conditionValue.type = FWP_UINT32;
  holder.condition.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
  return holder;
}

FilterConditionHolder BuildAppIdCondition(const std::wstring& applicationPath) {
  FilterConditionHolder holder{};
  holder.condition.fieldKey = kConditionAleAppId;
  holder.condition.matchType = FWP_MATCH_EQUAL_CASE_INSENSITIVE;
  FWP_BYTE_BLOB* appIdBlob = nullptr;
  const auto status = FwpmGetAppIdFromFileName0(applicationPath.c_str(), &appIdBlob);
  if (status != ERROR_SUCCESS || appIdBlob == nullptr) {
    throw std::runtime_error("Unable to compute a WFP AppId blob (status " + std::to_string(status) + ")");
  }
  holder.byteBlob.reset(appIdBlob);
  holder.condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
  holder.condition.conditionValue.byteBlob = holder.byteBlob.get();
  return holder;
}

FilterConditionHolder BuildRemoteAddressCondition(const std::wstring& remoteAddress, const bool ipv6) {
  FilterConditionHolder holder{};
  holder.condition.fieldKey = ipv6 ? kConditionIpRemoteAddressV6 : kConditionIpRemoteAddressV4;
  holder.condition.matchType = FWP_MATCH_EQUAL;
  if (ipv6) {
    const auto parsed = ParseIpv6Address(remoteAddress);
    if (!parsed.has_value()) {
      throw std::runtime_error("Unable to parse an IPv6 allow address");
    }
    holder.byteArray16 = std::make_unique<FWP_BYTE_ARRAY16>(*parsed);
    holder.condition.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
    holder.condition.conditionValue.byteArray16 = holder.byteArray16.get();
    return holder;
  }
  const auto parsed = ParseIpv4Address(remoteAddress);
  if (!parsed.has_value()) {
    throw std::runtime_error("Unable to parse an IPv4 allow address");
  }
  holder.condition.conditionValue.type = FWP_UINT32;
  holder.condition.conditionValue.uint32 = *parsed;
  return holder;
}

const GUID& LayerKeyForIndex(const int index) {
  switch (index) {
    case 0: return kLayerAleAuthConnectV4;
    case 1: return kLayerAleAuthConnectV6;
    case 2: return kLayerAleAuthRecvAcceptV4;
    default: return kLayerAleAuthRecvAcceptV6;
  }
}

bool LayerUsesIpv6(const int index) { return index == 1 || index == 3; }

std::wstring FilterNameFor(const std::wstring& prefix, const int index) {
  static const std::array<const wchar_t*, 4> suffixes = {L"connect-v4", L"connect-v6", L"recv-v4", L"recv-v6"};
  return prefix + L" " + suffixes[static_cast<std::size_t>(index)];
}

std::wstring ConnectionPayloadJson(const SnapshotConnection& connection) {
  return std::wstring(L"{\"pid\":") + std::to_wstring(connection.pid) + L",\"protocol\":\"" +
         Utf8ToWide(EscapeJsonString(connection.protocol)) + L"\",\"state\":\"" +
         Utf8ToWide(EscapeJsonString(connection.state)) + L"\",\"localAddress\":\"" +
         Utf8ToWide(EscapeJsonString(connection.localAddress)) + L"\",\"localPort\":" +
         std::to_wstring(connection.localPort) + L",\"remoteAddress\":\"" +
         Utf8ToWide(EscapeJsonString(connection.remoteAddress)) + L"\",\"remotePort\":" +
         std::to_wstring(connection.remotePort) + L",\"processImagePath\":\"" +
         Utf8ToWide(EscapeJsonString(connection.processImagePath)) + L"\"}";
}

std::optional<std::wstring> ExtractJsonStringField(const std::wstring& json, const std::wstring& key) {
  const auto token = std::wstring(L"\"") + key + L"\":\"";
  const auto start = json.find(token);
  if (start == std::wstring::npos) {
    return std::nullopt;
  }
  const auto valueStart = start + token.size();
  const auto end = json.find(L"\"", valueStart);
  if (end == std::wstring::npos) {
    return std::nullopt;
  }
  return json.substr(valueStart, end - valueStart);
}

bool IsTimestampExpired(const std::wstring& expiryTimestamp, const std::wstring& referenceTimestamp) {
  if (expiryTimestamp.empty()) {
    return false;
  }
  return expiryTimestamp < referenceTimestamp;
}

std::wstring BuildDestinationBlockKey(const std::wstring& remoteAddress,
                                      const std::wstring& sourceApplication,
                                      const std::wstring& destinationIdentity) {
  return NormalizeAppIdPath(remoteAddress) + L"|" + NormalizeAppIdPath(sourceApplication) + L"|" +
         NormalizeAppIdPath(destinationIdentity);
}

constexpr std::size_t kMaxActiveDestinationBlocks = 512;

}  // namespace

NetworkIsolationManager::NetworkIsolationManager(AgentConfig config) : config_(std::move(config)) {}
NetworkIsolationManager::~NetworkIsolationManager() { Stop(); }

void NetworkIsolationManager::Start() {
  const std::scoped_lock lock(stateMutex_);
  if (engineReady_) {
    return;
  }
  FWPM_SESSION0 session{};
  session.flags = FWPM_SESSION_FLAG_DYNAMIC;
  session.displayData.name = const_cast<wchar_t*>(L"AntiVirus WFP Session");
  session.displayData.description = const_cast<wchar_t*>(L"Endpoint isolation and network telemetry");
  const auto status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engineHandle_);
  if (status != ERROR_SUCCESS || engineHandle_ == nullptr) {
    QueueStateEvent(L"network.wfp.failed",
                    status == ERROR_ACCESS_DENIED
                        ? L"The WFP isolation manager could not open the filtering engine because the host lacks firewall-management privileges."
                        : L"The WFP isolation manager could not open the filtering engine.",
                    std::wstring(L"{\"error\":") + std::to_wstring(status) + L"}");
    engineHandle_ = nullptr;
    return;
  }
  FWP_VALUE0 enableNetEvents{};
  enableNetEvents.type = FWP_UINT32;
  enableNetEvents.uint32 = 1;
  FwpmEngineSetOption0(engineHandle_, FWPM_ENGINE_COLLECT_NET_EVENTS, &enableNetEvents);
  try {
    EnsureProviderAndSubLayer();
    SubscribeNetEvents();
    engineReady_ = true;
    RegisterDestinationEnforcementHandler(&NetworkIsolationManager::DestinationEnforcementThunk, this);
    ReconcileDestinationBlocksLocked(true);
    QueueStateEvent(L"network.wfp.started", L"The WFP isolation manager opened the filtering engine and subscribed to net events.",
                    L"{\"mode\":\"user-mode\"}");
  } catch (const std::exception& error) {
    QueueStateEvent(L"network.wfp.failed",
                    L"The WFP isolation manager could not complete provider or subscription setup.",
                    std::wstring(L"{\"errorMessage\":\"") + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}");
    Stop();
  }
}

void NetworkIsolationManager::Stop() {
  const std::scoped_lock lock(stateMutex_);
  RegisterDestinationEnforcementHandler(nullptr, nullptr);
  RemoveDestinationBlockFiltersLocked();
  RemoveIsolationFilters();
  UnsubscribeNetEvents();
  if (engineHandle_ != nullptr) {
    FwpmEngineClose0(engineHandle_);
    engineHandle_ = nullptr;
  }
  engineReady_ = false;
  isolationActive_ = false;
}

void NetworkIsolationManager::SetDeviceId(std::wstring deviceId) {
  const std::scoped_lock lock(stateMutex_);
  deviceId_ = std::move(deviceId);
}
bool NetworkIsolationManager::EngineReady() const { return engineReady_; }
bool NetworkIsolationManager::IsolationActive() const { return isolationActive_; }

std::vector<TelemetryRecord> NetworkIsolationManager::DrainTelemetry() {
  const std::scoped_lock lock(telemetryMutex_);
  auto telemetry = pendingTelemetry_;
  pendingTelemetry_.clear();
  return telemetry;
}

void NetworkIsolationManager::QueueTelemetry(const TelemetryRecord& record) {
  const std::scoped_lock lock(telemetryMutex_);
  pendingTelemetry_.push_back(record);
}

void NetworkIsolationManager::QueueStateEvent(const std::wstring& eventType, const std::wstring& summary,
                                              const std::wstring& payloadJson) {
  QueueTelemetry(TelemetryRecord{.eventId = GenerateGuidString(), .eventType = eventType, .source = L"network-wfp",
                                 .summary = summary, .occurredAt = CurrentUtcTimestamp(), .payloadJson = payloadJson});
}

bool NetworkIsolationManager::DestinationEnforcementThunk(void* context,
                                                          const DestinationEnforcementRequest& request,
                                                          std::wstring* errorMessage) {
  if (context == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Network isolation manager is unavailable.";
    }
    return false;
  }
  return reinterpret_cast<NetworkIsolationManager*>(context)->ApplyDestinationBlock(request, errorMessage);
}

bool NetworkIsolationManager::ApplyDestinationBlock(const DestinationEnforcementRequest& request,
                                                    std::wstring* errorMessage) {
  const std::scoped_lock lock(stateMutex_);
  if (!engineReady_) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The WFP engine is not available on this host context.";
    }
    return false;
  }
  if (request.remoteAddresses.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"No remote address was supplied for destination enforcement.";
    }
    return false;
  }
  const auto beginStatus = FwpmTransactionBegin0(engineHandle_, 0);
  if (beginStatus != ERROR_SUCCESS) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Unable to start a WFP transaction for destination enforcement.";
    }
    return false;
  }
  try {
    ReconcileDestinationBlocksLocked();
    AddDestinationBlockFiltersLocked(request);
    const auto commitStatus = FwpmTransactionCommit0(engineHandle_);
    if (commitStatus != ERROR_SUCCESS) {
      throw std::runtime_error("Unable to commit destination block filters");
    }
    return true;
  } catch (const std::exception& error) {
    FwpmTransactionAbort0(engineHandle_);
    if (errorMessage != nullptr) {
      *errorMessage = Utf8ToWide(error.what());
    }
    QueueStateEvent(L"network.destination.block.failed",
                    L"The endpoint could not apply the requested destination block filters.",
                    std::wstring(L"{\"errorMessage\":\"") + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}");
    return false;
  }
}

void NetworkIsolationManager::EnsureProviderAndSubLayer() {
  FWPM_PROVIDER0 provider{};
  provider.providerKey = kAgentProviderKey;
  provider.displayData.name = const_cast<wchar_t*>(L"AntiVirus Endpoint");
  provider.displayData.description = const_cast<wchar_t*>(L"Endpoint network isolation provider");
  const auto providerStatus = FwpmProviderAdd0(engineHandle_, &provider, nullptr);
  if (providerStatus != ERROR_SUCCESS && providerStatus != FWP_E_ALREADY_EXISTS) {
    throw std::runtime_error("Unable to register the WFP provider (status " + std::to_string(providerStatus) + ")");
  }
  FWPM_SUBLAYER0 subLayer{};
  subLayer.subLayerKey = kIsolationSubLayerKey;
  subLayer.displayData.name = const_cast<wchar_t*>(L"AntiVirus Isolation");
  subLayer.displayData.description = const_cast<wchar_t*>(L"Endpoint isolation filters");
  subLayer.providerKey = const_cast<GUID*>(&kAgentProviderKey);
  subLayer.weight = 0x100;
  const auto subLayerStatus = FwpmSubLayerAdd0(engineHandle_, &subLayer, nullptr);
  if (subLayerStatus != ERROR_SUCCESS && subLayerStatus != FWP_E_ALREADY_EXISTS) {
    throw std::runtime_error("Unable to register the WFP sublayer (status " + std::to_string(subLayerStatus) + ")");
  }
}

void NetworkIsolationManager::SubscribeNetEvents() {
  if (netEventHandle_ != nullptr) {
    return;
  }
  FWPM_NET_EVENT_SUBSCRIPTION0 subscription{};
  const auto status = FwpmNetEventSubscribe0(engineHandle_, &subscription, &NetworkIsolationManager::NetEventCallback,
                                             this, &netEventHandle_);
  if (status != ERROR_SUCCESS) {
    throw std::runtime_error("Unable to subscribe to WFP net events (status " + std::to_string(status) + ")");
  }
}

void NetworkIsolationManager::UnsubscribeNetEvents() {
  if (engineHandle_ != nullptr && netEventHandle_ != nullptr) {
    FwpmNetEventUnsubscribe0(engineHandle_, netEventHandle_);
    netEventHandle_ = nullptr;
  }
}

bool NetworkIsolationManager::ApplyIsolation(const bool isolate, std::wstring* errorMessage) {
  const std::scoped_lock lock(stateMutex_);
  if (!engineReady_) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The WFP engine is not available on this host context.";
    }
    return false;
  }
  const auto beginStatus = FwpmTransactionBegin0(engineHandle_, 0);
  if (beginStatus != ERROR_SUCCESS) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Unable to start a WFP transaction for isolation changes.";
    }
    return false;
  }
  try {
    RemoveIsolationFilters();
    if (isolate) {
      AddIsolationFilters();
    }
    const auto commitStatus = FwpmTransactionCommit0(engineHandle_);
    if (commitStatus != ERROR_SUCCESS) {
      throw std::runtime_error("Unable to commit isolation filters");
    }
    isolationActive_ = isolate;
    QueueStateEvent(isolate ? L"network.isolation.applied" : L"network.isolation.released",
                    isolate ? L"The endpoint applied WFP-backed host isolation filters."
                            : L"The endpoint removed WFP-backed host isolation filters.",
                    std::wstring(L"{\"filterCount\":") + std::to_wstring(activeFilterIds_.size()) + L"}");
    return true;
  } catch (const std::exception& error) {
    FwpmTransactionAbort0(engineHandle_);
    if (errorMessage != nullptr) {
      *errorMessage = Utf8ToWide(error.what());
    }
    QueueStateEvent(L"network.isolation.failed",
                    L"The endpoint could not apply the requested WFP isolation state.",
                    std::wstring(L"{\"errorMessage\":\"") + Utf8ToWide(EscapeJsonString(Utf8ToWide(error.what()))) + L"\"}");
    return false;
  }
}

void NetworkIsolationManager::RemoveIsolationFilters() {
  for (const auto filterId : activeFilterIds_) {
    FwpmFilterDeleteById0(engineHandle_, filterId);
  }
  activeFilterIds_.clear();
  activeFilterIdIndex_.clear();
}

void NetworkIsolationManager::RemoveDestinationBlockFilters() {
  const std::scoped_lock lock(stateMutex_);
  RemoveDestinationBlockFiltersLocked();
}

void NetworkIsolationManager::RemoveDestinationBlockFiltersLocked() {
  for (const auto& [key, block] : activeDestinationBlocks_) {
    for (const auto filterId : block.filterIds) {
      FwpmFilterDeleteById0(engineHandle_, filterId);
    }
  }
  activeDestinationBlocks_.clear();
  activeDestinationBlockKeyByFilterId_.clear();
}

void NetworkIsolationManager::AddIsolationFilters() {
  const auto allowRemoteAddresses = BuildEffectiveAllowedRemoteAddresses(config_);
  for (int layerIndex = 0; layerIndex < 4; ++layerIndex) {
    if (config_.isolationAllowLoopback) {
      auto loopbackCondition = BuildLoopbackCondition();
      FWPM_FILTER0 filter{};
      filter.displayData.name = const_cast<wchar_t*>(FilterNameFor(L"AntiVirus allow loopback", layerIndex).c_str());
      filter.layerKey = LayerKeyForIndex(layerIndex);
      filter.subLayerKey = kIsolationSubLayerKey;
      filter.weight.type = FWP_UINT8;
      filter.weight.uint8 = 15;
      filter.action.type = FWP_ACTION_PERMIT;
      filter.numFilterConditions = 1;
      filter.filterCondition = &loopbackCondition.condition;
      UINT64 filterId = 0;
      const auto status = FwpmFilterAdd0(engineHandle_, &filter, nullptr, &filterId);
      if (status != ERROR_SUCCESS) {
        throw std::runtime_error("Unable to add a loopback permit filter (status " + std::to_string(status) + ")");
      }
      activeFilterIds_.push_back(filterId);
      activeFilterIdIndex_.insert(filterId);
    }
    for (const auto& applicationPath : config_.isolationAllowedApplications) {
      auto appCondition = BuildAppIdCondition(applicationPath);
      FWPM_FILTER0 filter{};
      filter.displayData.name = const_cast<wchar_t*>(FilterNameFor(L"AntiVirus allow application", layerIndex).c_str());
      filter.layerKey = LayerKeyForIndex(layerIndex);
      filter.subLayerKey = kIsolationSubLayerKey;
      filter.weight.type = FWP_UINT8;
      filter.weight.uint8 = 14;
      filter.action.type = FWP_ACTION_PERMIT;
      filter.numFilterConditions = 1;
      filter.filterCondition = &appCondition.condition;
      UINT64 filterId = 0;
      const auto status = FwpmFilterAdd0(engineHandle_, &filter, nullptr, &filterId);
      if (status != ERROR_SUCCESS) {
        throw std::runtime_error("Unable to add an application permit filter (status " + std::to_string(status) + ")");
      }
      activeFilterIds_.push_back(filterId);
      activeFilterIdIndex_.insert(filterId);
    }
    for (const auto& remoteAddress : allowRemoteAddresses) {
      auto remoteCondition = BuildRemoteAddressCondition(remoteAddress, LayerUsesIpv6(layerIndex));
      FWPM_FILTER0 filter{};
      filter.displayData.name = const_cast<wchar_t*>(FilterNameFor(L"AntiVirus allow remote address", layerIndex).c_str());
      filter.layerKey = LayerKeyForIndex(layerIndex);
      filter.subLayerKey = kIsolationSubLayerKey;
      filter.weight.type = FWP_UINT8;
      filter.weight.uint8 = 13;
      filter.action.type = FWP_ACTION_PERMIT;
      filter.numFilterConditions = 1;
      filter.filterCondition = &remoteCondition.condition;
      UINT64 filterId = 0;
      const auto status = FwpmFilterAdd0(engineHandle_, &filter, nullptr, &filterId);
      if (status != ERROR_SUCCESS) {
        continue;
      }
      activeFilterIds_.push_back(filterId);
      activeFilterIdIndex_.insert(filterId);
    }
    FWPM_FILTER0 blockFilter{};
    blockFilter.displayData.name = const_cast<wchar_t*>(FilterNameFor(L"AntiVirus block all", layerIndex).c_str());
    blockFilter.layerKey = LayerKeyForIndex(layerIndex);
    blockFilter.subLayerKey = kIsolationSubLayerKey;
    blockFilter.weight.type = FWP_UINT8;
    blockFilter.weight.uint8 = 1;
    blockFilter.action.type = FWP_ACTION_BLOCK;
    UINT64 filterId = 0;
    const auto status = FwpmFilterAdd0(engineHandle_, &blockFilter, nullptr, &filterId);
    if (status != ERROR_SUCCESS) {
      throw std::runtime_error("Unable to add a terminating block filter (status " + std::to_string(status) + ")");
    }
    activeFilterIds_.push_back(filterId);
    activeFilterIdIndex_.insert(filterId);
  }
}

void NetworkIsolationManager::AddDestinationBlockFilters(const DestinationEnforcementRequest& request) {
  const std::scoped_lock lock(stateMutex_);
  AddDestinationBlockFiltersLocked(request);
}

void NetworkIsolationManager::RemoveDestinationBlockLocked(const std::wstring& key) {
  const auto existing = activeDestinationBlocks_.find(key);
  if (existing == activeDestinationBlocks_.end()) {
    return;
  }
  for (const auto filterId : existing->second.filterIds) {
    FwpmFilterDeleteById0(engineHandle_, filterId);
    activeDestinationBlockKeyByFilterId_.erase(filterId);
  }
  activeDestinationBlocks_.erase(existing);
}

void NetworkIsolationManager::PurgeExpiredDestinationBlocksLocked() {
  const auto referenceTimestamp = CurrentUtcTimestamp();
  std::vector<std::wstring> expiredKeys;
  for (const auto& [key, block] : activeDestinationBlocks_) {
    if (IsTimestampExpired(block.expiresAt, referenceTimestamp)) {
      expiredKeys.push_back(key);
    }
  }
  for (const auto& key : expiredKeys) {
    RemoveDestinationBlockLocked(key);
  }
  if (engineReady_) {
    DestinationRuntimeStore(config_.runtimeDatabasePath).PurgeExpiredIntelligenceRecords(referenceTimestamp);
  }
}

void NetworkIsolationManager::ReconcileDestinationBlocksLocked(const bool force) {
  const auto now = std::chrono::steady_clock::now();
  if (!force && lastDestinationReconcileAt_ != std::chrono::steady_clock::time_point{} &&
      now - lastDestinationReconcileAt_ < kDestinationReconcileInterval) {
    return;
  }

  const auto beforeCount = activeDestinationBlocks_.size();
  PurgeExpiredDestinationBlocksLocked();
  lastDestinationReconcileAt_ = now;

  if (force) {
    ReplayPersistedDestinationBlocksLocked();
  }

  const auto afterCount = activeDestinationBlocks_.size();
  if (beforeCount != afterCount) {
    QueueStateEvent(L"network.destination.block.reconciled",
                    L"Fenrir reconciled active destination block filters.",
                    std::wstring(L"{\"beforeCount\":") + std::to_wstring(beforeCount) +
                        L",\"afterCount\":" + std::to_wstring(afterCount) + L"}");
  }
}

void NetworkIsolationManager::ReplayPersistedDestinationBlocksLocked() {
  DestinationRuntimeStore store(config_.runtimeDatabasePath);
  const auto records = store.ListActiveBlockingRecords(256);
  std::size_t replayed = 0;
  for (const auto& record : records) {
    DestinationEnforcementRequest request{};
    request.requestId = record.normalizedIndicator;
    request.displayDestination = record.host.empty() ? record.normalizedIndicator : record.host;
    if (record.indicatorType == ThreatIndicatorType::Ip) {
      request.remoteAddresses.push_back(record.normalizedIndicator);
    } else if (!record.host.empty()) {
      request.remoteAddresses = ResolveHostAddresses(record.host);
    }
    request.sourceApplication =
        ExtractJsonStringField(record.metadataJson, L"sourceApplication").value_or(L"");
    request.summary = L"Fenrir replayed an active destination block after service restart.";
    request.reason = record.metadataJson;
    request.expiresAt = record.expiresAt;
    if (request.remoteAddresses.empty()) {
      continue;
    }
    AddDestinationBlockFiltersLocked(request);
    ++replayed;
  }
  if (replayed != 0) {
    QueueStateEvent(L"network.destination.block.replayed",
                    L"Fenrir replayed persisted destination blocks after service start.",
                    std::wstring(L"{\"replayedCount\":") + std::to_wstring(replayed) + L"}");
  }
}

void NetworkIsolationManager::AddDestinationBlockFiltersLocked(const DestinationEnforcementRequest& request) {
  if (activeDestinationBlocks_.size() >= kMaxActiveDestinationBlocks) {
    auto oldest = activeDestinationBlocks_.begin();
    for (auto it = activeDestinationBlocks_.begin(); it != activeDestinationBlocks_.end(); ++it) {
      if (it->second.lastTouchedAt < oldest->second.lastTouchedAt) {
        oldest = it;
      }
    }
    RemoveDestinationBlockLocked(oldest->first);
  }

  const auto destinationIdentity = !request.requestId.empty()
                                       ? request.requestId
                                       : (!request.displayDestination.empty() ? request.displayDestination : L"destination");

  for (const auto& remoteAddress : request.remoteAddresses) {
    const auto key = BuildDestinationBlockKey(remoteAddress, request.sourceApplication, destinationIdentity);
    RemoveDestinationBlockLocked(key);
    auto& block = activeDestinationBlocks_[key];
    block.key = key;
    block.remoteAddress = remoteAddress;
    block.sourceApplication = request.sourceApplication;
    block.reason = request.reason;
    block.displayDestination = request.displayDestination;
    block.expiresAt = request.expiresAt;
    block.filterIds.clear();
    block.addedAt = std::chrono::steady_clock::now();
    block.lastTouchedAt = block.addedAt;

    for (int layerIndex = 0; layerIndex < 2; ++layerIndex) {
      auto remoteCondition = BuildRemoteAddressCondition(remoteAddress, LayerUsesIpv6(layerIndex));
      std::array<FilterConditionHolder, 2> conditions{};
      conditions[0] = std::move(remoteCondition);
      std::size_t conditionCount = 1;
      if (!request.sourceApplication.empty()) {
        conditions[1] = BuildAppIdCondition(request.sourceApplication);
        conditionCount = 2;
      }
      FWPM_FILTER0 filter{};
      const auto name = FilterNameFor(L"AntiVirus block destination", layerIndex);
      filter.displayData.name = const_cast<wchar_t*>(name.c_str());
      filter.layerKey = LayerKeyForIndex(layerIndex);
      filter.subLayerKey = kIsolationSubLayerKey;
      filter.weight.type = FWP_UINT8;
      filter.weight.uint8 = 12;
      filter.action.type = FWP_ACTION_BLOCK;
      filter.numFilterConditions = static_cast<UINT32>(conditionCount);
      filter.filterCondition = &conditions[0].condition;
      UINT64 filterId = 0;
      const auto status = FwpmFilterAdd0(engineHandle_, &filter, nullptr, &filterId);
      if (status != ERROR_SUCCESS) {
        continue;
      }
      block.filterIds.push_back(filterId);
      activeDestinationBlockKeyByFilterId_[filterId] = key;
    }
    if (block.filterIds.empty()) {
      activeDestinationBlocks_.erase(key);
    }
  }
  QueueStateEvent(L"network.destination.block.applied",
                  request.summary.empty() ? L"Fenrir blocked a risky destination." : request.summary,
                  std::wstring(L"{\"displayDestination\":\"") + Utf8ToWide(EscapeJsonString(request.displayDestination)) +
                      L"\",\"requestId\":\"" + Utf8ToWide(EscapeJsonString(request.requestId)) +
                      L"\",\"sourceApplication\":\"" + Utf8ToWide(EscapeJsonString(request.sourceApplication)) +
                      L"\",\"remoteAddressCount\":" + std::to_wstring(request.remoteAddresses.size()) + L"}");
}

void CALLBACK NetworkIsolationManager::NetEventCallback(void* context, const FWPM_NET_EVENT1* event) {
  if (context == nullptr || event == nullptr) {
    return;
  }
  reinterpret_cast<NetworkIsolationManager*>(context)->HandleNetEvent(*event);
}

void NetworkIsolationManager::HandleNetEvent(const FWPM_NET_EVENT1& event) {
  const std::scoped_lock lock(stateMutex_);
  ReconcileDestinationBlocksLocked();
  if (event.type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || event.classifyDrop == nullptr) {
    return;
  }
  const auto filterId = event.classifyDrop->filterId;
  if (!activeFilterIdIndex_.contains(filterId) && !activeDestinationBlockKeyByFilterId_.contains(filterId)) {
    return;
  }
  const auto appId = SafeBlobToWideString(&event.header.appId);
  const auto userSid = SidToString(event.header.userId);
  const auto localAddress = event.header.ipVersion == FWP_IP_VERSION_V4
                                ? AddressToString(event.header.ipVersion, event.header.localAddrV4, nullptr)
                                : AddressToString(event.header.ipVersion, 0, &event.header.localAddrV6);
  const auto remoteAddress = event.header.ipVersion == FWP_IP_VERSION_V4
                                 ? AddressToString(event.header.ipVersion, event.header.remoteAddrV4, nullptr)
                                 : AddressToString(event.header.ipVersion, 0, &event.header.remoteAddrV6);
  const auto direction = event.classifyDrop->msFwpDirection == FWP_DIRECTION_INBOUND ? std::wstring(L"inbound") : std::wstring(L"outbound");
  const auto destinationBlock = activeDestinationBlockKeyByFilterId_.contains(filterId);
  std::wstring reason;
  std::wstring displayDestination;
  std::wstring sourceApplication;
  if (destinationBlock) {
    const auto keyIt = activeDestinationBlockKeyByFilterId_.find(filterId);
    if (keyIt != activeDestinationBlockKeyByFilterId_.end()) {
      const auto blockIt = activeDestinationBlocks_.find(keyIt->second);
      if (blockIt != activeDestinationBlocks_.end()) {
        reason = blockIt->second.reason;
        displayDestination = blockIt->second.displayDestination;
        sourceApplication = blockIt->second.sourceApplication;
        blockIt->second.lastTouchedAt = std::chrono::steady_clock::now();
      }
    }
  }
  std::wstringstream summary;
  if (destinationBlock) {
    summary << L"Fenrir blocked access to "
            << (displayDestination.empty() ? remoteAddress : displayDestination)
            << L" for " << (appId.empty() ? L"(unknown application)" : BaseNameFromPath(appId)) << L".";
  } else {
    summary << L"WFP isolation blocked " << direction << L" traffic for "
            << (appId.empty() ? L"(unknown application)" : BaseNameFromPath(appId)) << L" to " << remoteAddress << L":"
            << NetworkToHostOrder(event.header.remotePort) << L".";
  }
  std::wstring payload = L"{\"filterId\":";
  payload += std::to_wstring(filterId);
  payload += L",\"direction\":\"";
  payload += direction;
  payload += L"\",\"appId\":\"";
  payload += Utf8ToWide(EscapeJsonString(appId));
  payload += L"\",\"userSid\":\"";
  payload += Utf8ToWide(EscapeJsonString(userSid));
  payload += L"\",\"localAddress\":\"";
  payload += Utf8ToWide(EscapeJsonString(localAddress));
  payload += L"\",\"localPort\":";
  payload += std::to_wstring(NetworkToHostOrder(event.header.localPort));
  payload += L",\"remoteAddress\":\"";
  payload += Utf8ToWide(EscapeJsonString(remoteAddress));
  payload += L"\",\"remotePort\":";
  payload += std::to_wstring(NetworkToHostOrder(event.header.remotePort));
  payload += L",\"protocol\":";
  payload += std::to_wstring(event.header.ipProtocol);
  payload += L",\"destinationBlocked\":";
  payload += destinationBlock ? L"true" : L"false";
  payload += L",\"reason\":\"";
  payload += Utf8ToWide(EscapeJsonString(reason));
  payload += L"\",\"displayDestination\":\"";
  payload += Utf8ToWide(EscapeJsonString(displayDestination));
  payload += L"\",\"sourceApplication\":\"";
  payload += Utf8ToWide(EscapeJsonString(sourceApplication));
  payload += L"\"}";
  QueueTelemetry(TelemetryRecord{.eventId = GenerateGuidString(),
                                 .eventType = destinationBlock ? L"network.destination.blocked" : L"network.connection.blocked",
                                 .source = L"network-wfp",
                                 .summary = summary.str(),
                                 .occurredAt = FileTimeToUtcString((static_cast<ULONGLONG>(event.header.timeStamp.dwHighDateTime) << 32U) |
                                                                   event.header.timeStamp.dwLowDateTime),
                                 .payloadJson = payload});
}

std::vector<TelemetryRecord> NetworkIsolationManager::CollectConnectionSnapshotTelemetry(std::size_t maxRecords) const {
  std::vector<SnapshotConnection> connections;
  const auto collectTcp = [&connections](const ULONG family) {
    DWORD tableSize = 0;
    if (GetExtendedTcpTable(nullptr, &tableSize, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER || tableSize == 0) {
      return;
    }
    std::vector<BYTE> buffer(tableSize);
    if (GetExtendedTcpTable(buffer.data(), &tableSize, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_SUCCESS) {
      return;
    }
    if (family == AF_INET) {
      const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
      for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const auto& row = table->table[index];
        IN_ADDR localAddress{}; localAddress.S_un.S_addr = row.dwLocalAddr;
        IN_ADDR remoteAddress{}; remoteAddress.S_un.S_addr = row.dwRemoteAddr;
        wchar_t localBuffer[INET_ADDRSTRLEN] = {};
        wchar_t remoteBuffer[INET_ADDRSTRLEN] = {};
        InetNtopW(AF_INET, &localAddress, localBuffer, ARRAYSIZE(localBuffer));
        InetNtopW(AF_INET, &remoteAddress, remoteBuffer, ARRAYSIZE(remoteBuffer));
        connections.push_back(SnapshotConnection{.pid = row.dwOwningPid, .protocol = L"tcp4", .state = TcpStateToString(row.dwState), .localAddress = localBuffer, .localPort = NetworkToHostOrder(static_cast<UINT16>(row.dwLocalPort)), .remoteAddress = remoteBuffer, .remotePort = NetworkToHostOrder(static_cast<UINT16>(row.dwRemotePort)), .processImagePath = QueryProcessImagePath(row.dwOwningPid)});
      }
      return;
    }
    const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
      const auto& row = table->table[index];
      wchar_t localBuffer[INET6_ADDRSTRLEN] = {};
      wchar_t remoteBuffer[INET6_ADDRSTRLEN] = {};
      IN6_ADDR localAddress{}; std::memcpy(localAddress.u.Byte, row.ucLocalAddr, sizeof(localAddress.u.Byte));
      IN6_ADDR remoteAddress{}; std::memcpy(remoteAddress.u.Byte, row.ucRemoteAddr, sizeof(remoteAddress.u.Byte));
      InetNtopW(AF_INET6, &localAddress, localBuffer, ARRAYSIZE(localBuffer));
      InetNtopW(AF_INET6, &remoteAddress, remoteBuffer, ARRAYSIZE(remoteBuffer));
      connections.push_back(SnapshotConnection{.pid = row.dwOwningPid, .protocol = L"tcp6", .state = TcpStateToString(row.dwState), .localAddress = localBuffer, .localPort = NetworkToHostOrder(static_cast<UINT16>(row.dwLocalPort)), .remoteAddress = remoteBuffer, .remotePort = NetworkToHostOrder(static_cast<UINT16>(row.dwRemotePort)), .processImagePath = QueryProcessImagePath(row.dwOwningPid)});
    }
  };
  collectTcp(AF_INET);
  collectTcp(AF_INET6);
  std::stable_sort(connections.begin(), connections.end(), [](const SnapshotConnection& left, const SnapshotConnection& right) {
    const auto leftInteresting = IsInterestingNetworkProcess(left.processImagePath);
    const auto rightInteresting = IsInterestingNetworkProcess(right.processImagePath);
    if (leftInteresting != rightInteresting) return leftInteresting > rightInteresting;
    const auto leftEstablished = left.state == L"established";
    const auto rightEstablished = right.state == L"established";
    if (leftEstablished != rightEstablished) return leftEstablished > rightEstablished;
    return left.pid > right.pid;
  });
  if (maxRecords > 0 && connections.size() > maxRecords) {
    connections.resize(maxRecords);
  }
  std::vector<TelemetryRecord> telemetry;
  telemetry.reserve(connections.size());
  for (const auto& connection : connections) {
    std::wstringstream summary;
    summary << L"Observed " << connection.protocol << L" connection for "
            << (connection.processImagePath.empty() ? L"(unknown process)" : BaseNameFromPath(connection.processImagePath))
            << L" from " << connection.localAddress << L":" << connection.localPort;
    if (!connection.remoteAddress.empty()) {
      summary << L" to " << connection.remoteAddress << L":" << connection.remotePort;
    }
    summary << L" (" << connection.state << L").";
    telemetry.push_back(TelemetryRecord{.eventId = GenerateGuidString(), .eventType = L"network.connection.snapshot", .source = L"network-wfp", .summary = summary.str(), .occurredAt = CurrentUtcTimestamp(), .payloadJson = ConnectionPayloadJson(connection)});
  }
  return telemetry;
}

}  // namespace antivirus::agent
