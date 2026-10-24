#include "DeviceInventoryCollector.h"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <wtsapi32.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

constexpr wchar_t kUninstallKey64[] = LR"(SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall)";
constexpr wchar_t kUninstallKey32[] = LR"(SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall)";
constexpr wchar_t kCurrentUserUninstallKey[] = LR"(SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall)";

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring TrimCommandToken(std::wstring value) {
  while (!value.empty() && (value.front() == L'"' || value.front() == L' ')) {
    value.erase(value.begin());
  }

  const auto comma = value.find(L',');
  if (comma != std::wstring::npos) {
    value = value.substr(0, comma);
  }

  while (!value.empty() && (value.back() == L'"' || value.back() == L' ')) {
    value.pop_back();
  }

  return value;
}

std::wstring BuildSoftwareId(const std::wstring& displayName, const std::wstring& publisher,
                             const std::wstring& displayVersion, const std::wstring& installLocation) {
  const auto key = ToLowerCopy(displayName + L"|" + publisher + L"|" + displayVersion + L"|" + installLocation);
  const auto hashValue = static_cast<std::uint64_t>(std::hash<std::wstring>{}(key));
  std::wstringstream stream;
  stream << std::hex << hashValue;
  return stream.str();
}

std::optional<std::wstring> ReadRegistryStringValue(HKEY key, const wchar_t* valueName) {
  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || bytes == 0) {
    return std::nullopt;
  }

  if (type != REG_SZ && type != REG_EXPAND_SZ) {
    return std::nullopt;
  }

  std::wstring value(bytes / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &bytes) != ERROR_SUCCESS) {
    return std::nullopt;
  }

  while (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }

  return value.empty() ? std::nullopt : std::optional<std::wstring>(value);
}

std::optional<DWORD> ReadRegistryDwordValue(HKEY key, const wchar_t* valueName) {
  DWORD type = 0;
  DWORD value = 0;
  DWORD bytes = sizeof(value);
  if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &bytes) != ERROR_SUCCESS ||
      type != REG_DWORD) {
    return std::nullopt;
  }

  return value;
}

bool IsSkippableSoftwareEntry(const std::wstring& displayName, const std::wstring& releaseType,
                              const std::optional<DWORD> systemComponent) {
  if (displayName.empty()) {
    return true;
  }

  if (systemComponent.value_or(0) != 0) {
    return true;
  }

  const auto normalizedReleaseType = ToLowerCopy(releaseType);
  return normalizedReleaseType == L"security update" || normalizedReleaseType == L"update rollup" ||
         normalizedReleaseType == L"hotfix";
}

std::vector<std::wstring> DeriveExecutableNames(const std::wstring& displayIconPath) {
  std::vector<std::wstring> results;
  if (displayIconPath.empty()) {
    return results;
  }

  const auto normalizedPath = TrimCommandToken(displayIconPath);
  if (normalizedPath.empty()) {
    return results;
  }

  const auto fileName = std::filesystem::path(normalizedPath).filename().wstring();
  if (!fileName.empty()) {
    results.push_back(ToLowerCopy(fileName));
  }

  return results;
}

std::vector<std::wstring> DeriveExecutablePaths(const std::wstring& displayIconPath, const std::wstring& installLocation) {
  std::set<std::wstring> uniquePaths;

  const auto normalizedIconPath = TrimCommandToken(displayIconPath);
  if (!normalizedIconPath.empty()) {
    uniquePaths.insert(normalizedIconPath);
  }

  if (!installLocation.empty()) {
    std::error_code error;
    const std::filesystem::path installRoot(installLocation);
    if (std::filesystem::exists(installRoot, error) && std::filesystem::is_directory(installRoot, error)) {
      for (const auto& entry : std::filesystem::directory_iterator(installRoot, error)) {
        if (error) {
          break;
        }

        if (!entry.is_regular_file(error)) {
          continue;
        }

        if (ToLowerCopy(entry.path().extension().wstring()) == L".exe") {
          uniquePaths.insert(entry.path().wstring());
        }
      }
    }
  }

  return {uniquePaths.begin(), uniquePaths.end()};
}

void CollectSoftwareFromRegistry(HKEY root, const wchar_t* subKeyPath, REGSAM accessMask,
                                 std::vector<InstalledSoftwareInventoryItem>& items) {
  HKEY uninstallKey = nullptr;
  if (RegOpenKeyExW(root, subKeyPath, 0, KEY_READ | accessMask, &uninstallKey) != ERROR_SUCCESS) {
    return;
  }

  DWORD subKeyCount = 0;
  DWORD maxSubKeyLength = 0;
  if (RegQueryInfoKeyW(uninstallKey, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLength, nullptr, nullptr, nullptr,
                       nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
    RegCloseKey(uninstallKey);
    return;
  }

  std::vector<wchar_t> nameBuffer(maxSubKeyLength + 2, L'\0');
  for (DWORD index = 0; index < subKeyCount; ++index) {
    DWORD nameLength = static_cast<DWORD>(nameBuffer.size());
    if (RegEnumKeyExW(uninstallKey, index, nameBuffer.data(), &nameLength, nullptr, nullptr, nullptr, nullptr) !=
        ERROR_SUCCESS) {
      continue;
    }

    HKEY itemKey = nullptr;
    if (RegOpenKeyExW(uninstallKey, nameBuffer.data(), 0, KEY_READ | accessMask, &itemKey) != ERROR_SUCCESS) {
      continue;
    }

    const auto displayName = ReadRegistryStringValue(itemKey, L"DisplayName").value_or(L"");
    const auto releaseType = ReadRegistryStringValue(itemKey, L"ReleaseType").value_or(L"");
    const auto systemComponent = ReadRegistryDwordValue(itemKey, L"SystemComponent");
    if (IsSkippableSoftwareEntry(displayName, releaseType, systemComponent)) {
      RegCloseKey(itemKey);
      continue;
    }

    const auto displayVersion = ReadRegistryStringValue(itemKey, L"DisplayVersion").value_or(L"unknown");
    const auto publisher = ReadRegistryStringValue(itemKey, L"Publisher").value_or(L"unknown");
    const auto installLocation = ReadRegistryStringValue(itemKey, L"InstallLocation").value_or(L"");
    const auto uninstallCommand = ReadRegistryStringValue(itemKey, L"UninstallString").value_or(L"");
    const auto quietUninstallCommand = ReadRegistryStringValue(itemKey, L"QuietUninstallString").value_or(L"");
    const auto installDate = ReadRegistryStringValue(itemKey, L"InstallDate").value_or(L"");
    const auto displayIconPath = ReadRegistryStringValue(itemKey, L"DisplayIcon").value_or(L"");

    items.push_back(InstalledSoftwareInventoryItem{
        .softwareId = BuildSoftwareId(displayName, publisher, displayVersion, installLocation),
        .displayName = displayName,
        .displayVersion = displayVersion,
        .publisher = publisher,
        .installLocation = installLocation,
        .uninstallCommand = uninstallCommand,
        .quietUninstallCommand = quietUninstallCommand,
        .installDate = installDate,
        .displayIconPath = displayIconPath,
        .executableNames = DeriveExecutableNames(displayIconPath),
        .executablePaths = DeriveExecutablePaths(displayIconPath, installLocation)});

    RegCloseKey(itemKey);
  }

  RegCloseKey(uninstallKey);
}

std::vector<InstalledSoftwareInventoryItem> CollectInstalledSoftware() {
  std::vector<InstalledSoftwareInventoryItem> items;
  CollectSoftwareFromRegistry(HKEY_LOCAL_MACHINE, kUninstallKey64, KEY_WOW64_64KEY, items);
  CollectSoftwareFromRegistry(HKEY_LOCAL_MACHINE, kUninstallKey32, KEY_WOW64_32KEY, items);
  CollectSoftwareFromRegistry(HKEY_CURRENT_USER, kCurrentUserUninstallKey, 0, items);

  std::set<std::wstring> seen;
  std::vector<InstalledSoftwareInventoryItem> deduped;
  deduped.reserve(items.size());

  for (auto& item : items) {
    const auto key = ToLowerCopy(item.displayName + L"|" + item.publisher + L"|" + item.displayVersion + L"|" + item.installLocation);
    if (!seen.insert(key).second) {
      continue;
    }

    deduped.push_back(std::move(item));
  }

  std::sort(deduped.begin(), deduped.end(), [](const InstalledSoftwareInventoryItem& left,
                                               const InstalledSoftwareInventoryItem& right) {
    const auto nameDelta = left.displayName.compare(right.displayName);
    if (nameDelta != 0) {
      return nameDelta < 0;
    }

    return left.publisher < right.publisher;
  });

  return deduped;
}

bool IsLoopbackOrLocalOnlyIp(const std::wstring& value) {
  const auto normalized = ToLowerCopy(value);
  return normalized == L"127.0.0.1" || normalized == L"::1" || normalized.starts_with(L"127.") ||
         normalized.starts_with(L"169.254.");
}

std::vector<std::wstring> CollectPrivateIpAddresses() {
  ULONG bufferLength = 16 * 1024;
  std::vector<BYTE> buffer(bufferLength);

  auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES_LH*>(buffer.data());
  ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                                     GAA_FLAG_SKIP_DNS_SERVER,
                                      nullptr, addresses, &bufferLength);
  if (result == ERROR_BUFFER_OVERFLOW) {
    buffer.resize(bufferLength);
    addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES_LH*>(buffer.data());
    result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                               GAA_FLAG_SKIP_DNS_SERVER,
                                  nullptr, addresses, &bufferLength);
  }

  if (result != NO_ERROR) {
    return {};
  }

  std::set<std::wstring> uniqueAddresses;
  for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->OperStatus != IfOperStatusUp) {
      continue;
    }

    for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
      wchar_t bufferText[INET6_ADDRSTRLEN] = {};
      DWORD bufferSize = static_cast<DWORD>(std::size(bufferText));
      if (WSAAddressToStringW(unicast->Address.lpSockaddr, static_cast<DWORD>(unicast->Address.iSockaddrLength), nullptr,
                              bufferText, &bufferSize) != 0) {
        continue;
      }

      std::wstring ipAddress(bufferText);
      const auto zoneMarker = ipAddress.find(L'%');
      if (zoneMarker != std::wstring::npos) {
        ipAddress = ipAddress.substr(0, zoneMarker);
      }

      if (IsLoopbackOrLocalOnlyIp(ipAddress)) {
        continue;
      }

      uniqueAddresses.insert(ipAddress);
    }
  }

  return {uniqueAddresses.begin(), uniqueAddresses.end()};
}

std::wstring QueryActiveConsoleUser() {
  const auto sessionId = WTSGetActiveConsoleSessionId();
  if (sessionId == 0xffffffff) {
    return {};
  }

  LPWSTR userName = nullptr;
  DWORD userBytes = 0;
  LPWSTR domainName = nullptr;
  DWORD domainBytes = 0;

  std::wstring result;
  if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &userName, &userBytes) != FALSE &&
      userName != nullptr && userName[0] != L'\0') {
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSDomainName, &domainName, &domainBytes) !=
            FALSE &&
        domainName != nullptr && domainName[0] != L'\0') {
      result = std::wstring(domainName) + L"\\" + userName;
    } else {
      result = userName;
    }
  }

  if (userName != nullptr) {
    WTSFreeMemory(userName);
  }
  if (domainName != nullptr) {
    WTSFreeMemory(domainName);
  }

  return result;
}

std::wstring BuildInstalledSoftwarePayload(const std::vector<InstalledSoftwareInventoryItem>& items) {
  std::wstring payload = L"[";
  for (std::size_t index = 0; index < items.size(); ++index) {
    const auto& item = items[index];
    if (index > 0) {
      payload += L",";
    }

    payload += std::wstring(L"{\"id\":\"") + Utf8ToWide(EscapeJsonString(item.softwareId)) + L"\",\"displayName\":\"" +
               Utf8ToWide(EscapeJsonString(item.displayName)) + L"\",\"displayVersion\":\"" +
               Utf8ToWide(EscapeJsonString(item.displayVersion)) + L"\",\"publisher\":\"" +
               Utf8ToWide(EscapeJsonString(item.publisher)) + L"\",\"installLocation\":\"" +
               Utf8ToWide(EscapeJsonString(item.installLocation)) + L"\",\"uninstallCommand\":\"" +
               Utf8ToWide(EscapeJsonString(item.uninstallCommand)) + L"\",\"quietUninstallCommand\":\"" +
               Utf8ToWide(EscapeJsonString(item.quietUninstallCommand)) + L"\",\"installDate\":\"" +
               Utf8ToWide(EscapeJsonString(item.installDate)) + L"\",\"displayIconPath\":\"" +
               Utf8ToWide(EscapeJsonString(item.displayIconPath)) + L"\",\"blocked\":" +
               (item.blocked ? std::wstring(L"true") : std::wstring(L"false")) + L",\"updateState\":\"" +
               Utf8ToWide(EscapeJsonString(item.updateState)) + L"\",\"lastUpdateCheckAt\":\"" +
               Utf8ToWide(EscapeJsonString(item.lastUpdateCheckAt)) + L"\",\"updateSummary\":\"" +
               Utf8ToWide(EscapeJsonString(item.updateSummary)) + L"\",\"supportedPatchSource\":\"" +
               Utf8ToWide(EscapeJsonString(item.supportedPatchSource)) + L"\",\"manualPatchOnly\":" +
               (item.manualPatchOnly ? std::wstring(L"true") : std::wstring(L"false")) + L",\"patchUnsupported\":" +
               (item.patchUnsupported ? std::wstring(L"true") : std::wstring(L"false")) + L",\"executableNames\":[";

    for (std::size_t executableIndex = 0; executableIndex < item.executableNames.size(); ++executableIndex) {
      if (executableIndex > 0) {
        payload += L",";
      }
      payload += L"\"" + Utf8ToWide(EscapeJsonString(item.executableNames[executableIndex])) + L"\"";
    }

    payload += L"],\"executablePaths\":[";
    for (std::size_t executablePathIndex = 0; executablePathIndex < item.executablePaths.size(); ++executablePathIndex) {
      if (executablePathIndex > 0) {
        payload += L",";
      }
      payload += L"\"" + Utf8ToWide(EscapeJsonString(item.executablePaths[executablePathIndex])) + L"\"";
    }

    payload += L"]}";
  }

  payload += L"]";
  return payload;
}

}  // namespace

DeviceInventorySnapshot CollectDeviceInventorySnapshot() {
  return DeviceInventorySnapshot{
      .privateIpAddresses = CollectPrivateIpAddresses(),
      .lastLoggedOnUser = QueryActiveConsoleUser(),
      .installedSoftware = CollectInstalledSoftware()};
}

std::wstring BuildDeviceInventoryPayload(const DeviceInventorySnapshot& snapshot) {
  std::wstring payload = L"{\"privateIpAddresses\":[";
  for (std::size_t index = 0; index < snapshot.privateIpAddresses.size(); ++index) {
    if (index > 0) {
      payload += L",";
    }
    payload += L"\"" + Utf8ToWide(EscapeJsonString(snapshot.privateIpAddresses[index])) + L"\"";
  }

  payload += L"],\"lastLoggedOnUser\":\"" + Utf8ToWide(EscapeJsonString(snapshot.lastLoggedOnUser)) +
             L"\",\"installedSoftware\":" + BuildInstalledSoftwarePayload(snapshot.installedSoftware) + L"}";
  return payload;
}

}  // namespace antivirus::agent
