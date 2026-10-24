#include "ServiceInventory.h"

#include <Windows.h>
#include <winsvc.h>

#include <algorithm>
#include <cwctype>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>

namespace antivirus::agent {
namespace {

struct ServiceHandleCloser {
  void operator()(SC_HANDLE handle) const noexcept {
    if (handle != nullptr) {
      CloseServiceHandle(handle);
    }
  }
};

using ServiceHandle = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ServiceHandleCloser>;

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool ContainsAny(const std::wstring& value, const std::initializer_list<std::wstring_view> needles) {
  const auto lower = ToLowerCopy(value);
  return std::any_of(needles.begin(), needles.end(), [&lower](const auto needle) { return lower.find(needle) != std::wstring::npos; });
}

bool IsUserWritablePath(const std::wstring& value) {
  const auto lower = ToLowerCopy(value);
  return lower.find(L"\\users\\") != std::wstring::npos || lower.find(L"\\programdata\\") != std::wstring::npos ||
         lower.find(L"\\temp\\") != std::wstring::npos || lower.find(L"\\downloads\\") != std::wstring::npos ||
         lower.find(L"\\desktop\\") != std::wstring::npos || lower.find(L"\\appdata\\local\\temp\\") != std::wstring::npos;
}

std::wstring StartTypeToString(const DWORD startType) {
  switch (startType) {
    case SERVICE_BOOT_START:
      return L"boot";
    case SERVICE_SYSTEM_START:
      return L"system";
    case SERVICE_AUTO_START:
      return L"auto";
    case SERVICE_DEMAND_START:
      return L"manual";
    case SERVICE_DISABLED:
      return L"disabled";
    default:
      return L"unknown";
  }
}

std::wstring ServiceStateToString(const DWORD state) {
  switch (state) {
    case SERVICE_RUNNING:
      return L"running";
    case SERVICE_START_PENDING:
      return L"starting";
    case SERVICE_STOP_PENDING:
      return L"stopping";
    case SERVICE_STOPPED:
      return L"stopped";
    case SERVICE_PAUSED:
      return L"paused";
    default:
      return L"unknown";
  }
}

bool IsSuspiciousServiceName(const std::wstring& value) {
  return ContainsAny(value, {L"powershell", L"cmd", L"wscript", L"cscript", L"mshta", L"remote registry",
                             L"anydesk", L"teamviewer", L"psexec", L"vnc"});
}

bool IsRiskyService(const ServiceObservation& service) {
  return service.userWritablePath || service.suspiciousName ||
         (service.autoStart && service.binaryPath.empty()) ||
         (service.running && service.accountName.empty());
}

}  // namespace

std::vector<ServiceObservation> CollectServiceInventory(const std::size_t maxRecords) {
  std::vector<ServiceObservation> collected;

  ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
  if (!manager) {
    return collected;
  }

  DWORD bytesNeeded = 0;
  DWORD serviceCount = 0;
  DWORD resumeHandle = 0;
  EnumServicesStatusExW(manager.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0,
                        &bytesNeeded, &serviceCount, &resumeHandle, nullptr);
  if (bytesNeeded == 0) {
    return collected;
  }

  std::vector<BYTE> buffer(bytesNeeded);
  if (!EnumServicesStatusExW(manager.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(),
                             static_cast<DWORD>(buffer.size()), &bytesNeeded, &serviceCount, &resumeHandle, nullptr)) {
    return collected;
  }

  const auto* services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
  for (DWORD index = 0; index < serviceCount; ++index) {
    const auto& entry = services[index];
    ServiceObservation service{
        .serviceName = entry.lpServiceName != nullptr ? entry.lpServiceName : L"",
        .displayName = entry.lpDisplayName != nullptr ? entry.lpDisplayName : L"",
        .binaryPath = {},
        .accountName = {},
        .startType = L"unknown",
        .currentState = ServiceStateToString(entry.ServiceStatusProcess.dwCurrentState),
        .processId = entry.ServiceStatusProcess.dwProcessId,
        .autoStart = false,
        .running = entry.ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING,
        .userWritablePath = false,
        .suspiciousName = false,
        .risky = false};

    service.suspiciousName = IsSuspiciousServiceName(service.serviceName) || IsSuspiciousServiceName(service.displayName);

    ServiceHandle serviceHandle(OpenServiceW(manager.get(), service.serviceName.c_str(), SERVICE_QUERY_CONFIG));
    if (serviceHandle) {
      DWORD required = 0;
      QueryServiceConfigW(serviceHandle.get(), nullptr, 0, &required);
      if (required > 0) {
        std::vector<BYTE> configBuffer(required);
        if (QueryServiceConfigW(serviceHandle.get(), reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuffer.data()),
                                required, &required)) {
          const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(configBuffer.data());
          service.binaryPath = config->lpBinaryPathName != nullptr ? config->lpBinaryPathName : L"";
          service.accountName = config->lpServiceStartName != nullptr ? config->lpServiceStartName : L"";
          service.autoStart = config->dwStartType == SERVICE_AUTO_START;
          service.startType = StartTypeToString(config->dwStartType);
          service.userWritablePath = IsUserWritablePath(service.binaryPath);
        }
      }
    }

    service.risky = IsRiskyService(service);
    collected.push_back(std::move(service));
  }

  std::sort(collected.begin(), collected.end(), [](const ServiceObservation& left, const ServiceObservation& right) {
    if (left.risky != right.risky) {
      return left.risky > right.risky;
    }

    if (left.running != right.running) {
      return left.running > right.running;
    }

    return left.displayName < right.displayName;
  });

  if (maxRecords > 0 && collected.size() > maxRecords) {
    collected.resize(maxRecords);
  }

  return collected;
}

}  // namespace antivirus::agent