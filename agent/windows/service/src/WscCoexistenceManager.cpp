#include "WscCoexistenceManager.h"

#include <windows.h>

#include <vector>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct ServiceLaunchProtectedInfoCompat {
  DWORD dwLaunchProtected;
};

bool QueryServiceRunning(const wchar_t* serviceName, std::wstring* stateText) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    if (stateText != nullptr) {
      *stateText = L"scm_unavailable";
    }
    return false;
  }

  const auto service = OpenServiceW(manager, serviceName, SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    if (stateText != nullptr) {
      *stateText = L"missing";
    }
    CloseServiceHandle(manager);
    return false;
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  const auto ok = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                                       &bytesNeeded) != FALSE;
  CloseServiceHandle(service);
  CloseServiceHandle(manager);

  if (!ok) {
    if (stateText != nullptr) {
      *stateText = L"query_failed";
    }
    return false;
  }

  if (stateText != nullptr) {
    switch (status.dwCurrentState) {
      case SERVICE_RUNNING:
        *stateText = L"running";
        break;
      case SERVICE_START_PENDING:
        *stateText = L"start_pending";
        break;
      case SERVICE_STOP_PENDING:
        *stateText = L"stop_pending";
        break;
      case SERVICE_STOPPED:
        *stateText = L"stopped";
        break;
      default:
        *stateText = L"other";
        break;
    }
  }

  return status.dwCurrentState == SERVICE_RUNNING;
}

bool QueryLaunchProtectedState(const wchar_t* serviceName, std::wstring* stateText) {
  if (stateText != nullptr) {
    *stateText = L"unknown";
  }

  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    if (stateText != nullptr) {
      *stateText = L"scm_unavailable";
    }
    return false;
  }

  const auto service = OpenServiceW(manager, serviceName, SERVICE_QUERY_CONFIG);
  if (service == nullptr) {
    if (stateText != nullptr) {
      *stateText = L"missing";
    }
    CloseServiceHandle(manager);
    return false;
  }

  DWORD bytesNeeded = 0;
  QueryServiceConfig2W(service, SERVICE_CONFIG_LAUNCH_PROTECTED, nullptr, 0, &bytesNeeded);
  if (bytesNeeded == 0) {
    if (stateText != nullptr) {
      *stateText = L"query_failed";
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return false;
  }

  std::vector<BYTE> buffer(bytesNeeded, 0);
  const auto ok =
      QueryServiceConfig2W(service, SERVICE_CONFIG_LAUNCH_PROTECTED, buffer.data(), bytesNeeded, &bytesNeeded) != FALSE;
  if (ok) {
    const auto* info = reinterpret_cast<const ServiceLaunchProtectedInfoCompat*>(buffer.data());
    if (stateText != nullptr) {
      *stateText = info->dwLaunchProtected == SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT ? L"antimalware_light"
                                                                                          : L"not_protected";
    }
  } else if (stateText != nullptr) {
    *stateText = L"query_failed";
  }

  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return ok;
}

}  // namespace

WscCoexistenceSnapshot WscCoexistenceManager::CaptureSnapshot() const {
  WscCoexistenceSnapshot snapshot;

  std::wstring wscState;
  std::wstring defenderState;
  std::wstring agentState;
  std::wstring agentLaunchProtected;
  const auto wscRunning = QueryServiceRunning(L"wscsvc", &wscState);
  const auto defenderRunning = QueryServiceRunning(L"WinDefend", &defenderState);
  const auto agentRunning = QueryServiceRunning(L"AntiVirusAgent", &agentState);
  QueryLaunchProtectedState(L"AntiVirusAgent", &agentLaunchProtected);

  snapshot.available = !wscState.empty();
  snapshot.providerHealth = wscRunning ? L"security_center_running" : L"security_center_unavailable";
  snapshot.errorMessage =
      wscRunning ? L"Windows Security Center service is reachable on this endpoint."
                 : L"Windows Security Center service is not currently reachable from this endpoint context.";

  snapshot.products.push_back(WscProductEntry{
      .name = L"Windows Security Center",
      .state = wscState,
      .signatureStatus = L"n/a",
      .remediationPath = L"services.msc",
      .productGuid = L"wscsvc",
      .isDefault = wscRunning});

  snapshot.products.push_back(WscProductEntry{
      .name = L"Microsoft Defender Antivirus",
      .state = defenderState,
      .signatureStatus = L"n/a",
      .remediationPath = L"windowsdefender://",
      .productGuid = L"WinDefend",
      .isDefault = defenderRunning});

  snapshot.products.push_back(WscProductEntry{
      .name = L"AntiVirus Agent",
      .state = agentState,
      .signatureStatus = agentLaunchProtected,
      .remediationPath = L"services.msc",
      .productGuid = L"AntiVirusAgent",
      .isDefault = agentRunning});

  return snapshot;
}

std::wstring WscCoexistenceManager::ToJson(const WscCoexistenceSnapshot& snapshot) {
  std::wstring json = L"{\"available\":";
  json += snapshot.available ? L"true" : L"false";
  json += L",\"providerHealth\":\"" + Utf8ToWide(EscapeJsonString(snapshot.providerHealth)) + L"\"";
  json += L",\"errorMessage\":\"" + Utf8ToWide(EscapeJsonString(snapshot.errorMessage)) + L"\"";
  json += L",\"products\":[";

  for (std::size_t index = 0; index < snapshot.products.size(); ++index) {
    const auto& product = snapshot.products[index];
    if (index != 0) {
      json += L",";
    }

    json += L"{\"name\":\"" + Utf8ToWide(EscapeJsonString(product.name)) + L"\",\"state\":\"" +
            Utf8ToWide(EscapeJsonString(product.state)) + L"\",\"signatureStatus\":\"" +
            Utf8ToWide(EscapeJsonString(product.signatureStatus)) + L"\",\"remediationPath\":\"" +
            Utf8ToWide(EscapeJsonString(product.remediationPath)) + L"\",\"productGuid\":\"" +
            Utf8ToWide(EscapeJsonString(product.productGuid)) + L"\",\"isDefault\":" +
            (product.isDefault ? std::wstring(L"true") : std::wstring(L"false")) + L"}";
  }

  json += L"]}";
  return json;
}

}  // namespace antivirus::agent
