#include <winsock2.h>
#include <Windows.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#include "AgentService.h"
#include "AgentConfig.h"
#include "EnrollmentPersistence.h"
#include "HardeningManager.h"
#include "LocalStateStore.h"
#include "RuntimeTrustValidator.h"
#include "SelfTestRunner.h"
#include "StringUtils.h"
#include "UpdaterService.h"
#include "WscCoexistenceManager.h"

namespace {

constexpr wchar_t kServiceName[] = L"FenrirAgent";
constexpr wchar_t kServiceDisplayName[] = L"Fenrir Agent";
constexpr wchar_t kServiceDescription[] =
    L"Fenrir Windows endpoint protection agent for policy sync, telemetry, and on-demand scanning.";
constexpr wchar_t kAmsiProviderDllName[] = L"fenrir-amsi-provider.dll";
constexpr wchar_t kLocalSystemAccountName[] = L"LocalSystem";

SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
SERVICE_STATUS g_serviceStatus{};
antivirus::agent::AgentService* g_activeService = nullptr;
volatile LONG g_stopRequested = 0;

// Failed starts and unexpected termination must be visible in Windows Event Viewer.
void ReportServiceFailure(const std::wstring& detail) {
  const auto source = RegisterEventSourceW(nullptr, kServiceName);
  if (source == nullptr) return;
  const wchar_t* strings[] = {detail.c_str()};
  ReportEventW(source, EVENTLOG_ERROR_TYPE, 0, 0x1001, nullptr, 1, 0, strings, nullptr);
  DeregisterEventSource(source);
}


bool InvokeAdjacentDllRegistration(bool registerProvider);
bool WaitForServiceStop(SC_HANDLE service, DWORD timeoutMs);

void UpdateServiceStatus(const DWORD currentState, const DWORD win32ExitCode = NO_ERROR,
                         const DWORD waitHint = 0, const DWORD serviceSpecificExitCode = 0) {
  g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_serviceStatus.dwCurrentState = currentState;
  g_serviceStatus.dwWin32ExitCode = win32ExitCode;
  g_serviceStatus.dwWaitHint = waitHint;
  g_serviceStatus.dwServiceSpecificExitCode = serviceSpecificExitCode;
  g_serviceStatus.dwControlsAccepted =
      currentState == SERVICE_START_PENDING ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
  g_serviceStatus.dwCheckPoint =
      (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) ? 0 : g_serviceStatus.dwCheckPoint + 1;

  if (g_serviceStatusHandle != nullptr) {
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
  }
}

DWORD WINAPI ServiceControlHandler(const DWORD controlCode, DWORD, void*, void*) {
  switch (controlCode) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
      InterlockedExchange(&g_stopRequested, 1);
      UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 15'000);
      if (g_activeService != nullptr) {
        g_activeService->RequestStop();
      }
      return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
      if (g_serviceStatusHandle != nullptr) {
        SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
      }
      return NO_ERROR;
    default:
      return ERROR_CALL_NOT_IMPLEMENTED;
  }
}

void WINAPI ServiceEntry(DWORD, LPWSTR*) {
  g_serviceStatusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandler, nullptr);
  if (g_serviceStatusHandle == nullptr) {
    return;
  }

  InterlockedExchange(&g_stopRequested, 0);
  UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 5'000);

  antivirus::agent::AgentService service;
  g_activeService = &service;

  UpdateServiceStatus(SERVICE_RUNNING);
  const auto exitCode = service.Run(antivirus::agent::AgentRunMode::Service);
  const bool requestedStop = InterlockedCompareExchange(&g_stopRequested, 0, 0) != 0;
  const bool unexpectedExit = !requestedStop;
  if (exitCode != 0 || unexpectedExit) {
    ReportServiceFailure(L"FenrirAgent stopped " +
                         std::wstring(unexpectedExit ? L"without a Windows service stop/shutdown request" :
                                                    L"after a requested stop with an error") +
                         L" (agent exit code " + std::to_wstring(exitCode) +
                         L"). Review the installation, signature trust and agent runtime diagnostics.");
  }
  g_activeService = nullptr;
  // An unexpected clean exit must count as a service failure so Windows can
  // apply the configured restart policy instead of leaving the agent stopped.
  const DWORD failureCode = exitCode != 0 ? static_cast<DWORD>(exitCode) : 1;
  UpdateServiceStatus(SERVICE_STOPPED,
                      (exitCode == 0 && !unexpectedExit) ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR,
                      0, (exitCode == 0 && !unexpectedExit) ? 0 : failureCode);
}

std::wstring GetModulePath() {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (written == 0) {
    return {};
  }

  buffer.resize(written);
  return buffer;
}

std::wstring GetArgumentValue(int argc, wchar_t* argv[], const std::wstring& name) {
  for (int index = 1; index < argc - 1; ++index) {
    if (argv[index] == name) {
      return argv[index + 1];
    }
  }

  return {};
}

std::filesystem::path GetInstallRoot() {
  const auto modulePath = std::filesystem::path(GetModulePath());
  return modulePath.has_parent_path() ? modulePath.parent_path() : std::filesystem::current_path();
}

bool EnsureDirectoryReady(const std::filesystem::path& path, const wchar_t* label, std::wstring* errorMessage) {
  if (path.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = std::wstring(label) + L" is empty.";
    }
    return false;
  }

  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error || !std::filesystem::exists(path, error)) {
    if (errorMessage != nullptr) {
      *errorMessage = std::wstring(L"Could not prepare ") + label + L" at " + path.wstring();
    }
    return false;
  }

  return true;
}

bool PrepareRuntimeLayout(const antivirus::agent::AgentConfig& config, std::wstring* errorMessage) {
  const auto runtimeValidation = antivirus::agent::ValidateRuntimePaths(config);
  if (!runtimeValidation.trusted) {
    if (errorMessage != nullptr) {
      *errorMessage = runtimeValidation.message.empty() ? L"Runtime boundaries are not trusted."
                                                        : runtimeValidation.message;
    }
    return false;
  }

  const auto runtimeRoot = runtimeValidation.runtimeRootPath.empty() ? config.runtimeDatabasePath.parent_path()
                                                                      : runtimeValidation.runtimeRootPath;
  return EnsureDirectoryReady(runtimeRoot, L"runtime root", errorMessage) &&
         EnsureDirectoryReady(config.runtimeDatabasePath.parent_path(), L"runtime database root", errorMessage) &&
         EnsureDirectoryReady(config.stateFilePath.parent_path(), L"state root", errorMessage) &&
         EnsureDirectoryReady(config.telemetryQueuePath.parent_path(), L"telemetry queue root", errorMessage) &&
         EnsureDirectoryReady(config.updateRootPath, L"update root", errorMessage) &&
         EnsureDirectoryReady(config.journalRootPath, L"journal root", errorMessage) &&
         EnsureDirectoryReady(config.quarantineRootPath, L"quarantine root", errorMessage) &&
         EnsureDirectoryReady(config.evidenceRootPath, L"evidence root", errorMessage);
}

bool ConfigureServiceHardening(SC_HANDLE service) {
  SERVICE_DESCRIPTIONW description{};
  description.lpDescription = const_cast<LPWSTR>(kServiceDescription);
  ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);

  // Start with Windows (not delayed) so protection is running before users sign in.
  SERVICE_DELAYED_AUTO_START_INFO delayedStart{};
  delayedStart.fDelayedAutostart = FALSE;
  ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayedStart);

  SERVICE_SID_INFO sidInfo{};
  sidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
  ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sidInfo);

  // Restart after every crash, kill or error exit. Windows repeats the last action for every later
  // failure, so the service is never left stopped.
  SC_ACTION actions[3]{};
  actions[0].Type = SC_ACTION_RESTART;
  actions[0].Delay = 5'000;
  actions[1].Type = SC_ACTION_RESTART;
  actions[1].Delay = 15'000;
  actions[2].Type = SC_ACTION_RESTART;
  actions[2].Delay = 60'000;

  SERVICE_FAILURE_ACTIONSW failureActions{};
  failureActions.dwResetPeriod = 60 * 60;
  failureActions.cActions = static_cast<DWORD>(std::size(actions));
  failureActions.lpsaActions = actions;
  if (ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions) == FALSE) {
    std::wcerr << L"Unable to configure service restart recovery (error " << GetLastError() << L")." << std::endl;
    return false;
  }

  SERVICE_FAILURE_ACTIONS_FLAG failureActionsFlag{};
  failureActionsFlag.fFailureActionsOnNonCrashFailures = TRUE;
  if (ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failureActionsFlag) == FALSE) {
    std::wcerr << L"Unable to configure recovery for non-crash failures (error " << GetLastError() << L")." << std::endl;
    return false;
  }
  return true;
}

// Lifts the stop/reconfigure/delete lock (see ApplyServiceControlProtection) so Fenrir's own
// maintenance commands can manage the service. Harmless when the service is not installed.
void UnlockServiceControl() {
  const auto config = antivirus::agent::LoadAgentConfigForModule(nullptr);
  antivirus::agent::HardeningManager hardeningManager(config, GetInstallRoot());
  hardeningManager.ApplyServiceControlProtection(kServiceName, nullptr, nullptr, false);
}

void LockServiceControl() {
  const auto config = antivirus::agent::LoadAgentConfigForModule(nullptr);
  antivirus::agent::HardeningManager hardeningManager(config, GetInstallRoot());
  hardeningManager.ApplyServiceControlProtection(kServiceName, nullptr, nullptr, true);
}

bool InstallOrRepairService(const bool repair, const std::wstring& uninstallToken) {
  const auto modulePath = GetModulePath();
  if (modulePath.empty()) {
    std::wcerr << L"Could not determine the agent executable path." << std::endl;
    return false;
  }

  const auto serviceCommandLine = L"\"" + modulePath + L"\"";
  // Installation and repair must not bypass a protected existing deployment.
  // A new installation (no saved token) remains unaffected.
  const auto maintenanceConfig = antivirus::agent::LoadAgentConfigForModule(nullptr);
  antivirus::agent::HardeningManager maintenanceGuard(maintenanceConfig, GetInstallRoot());
  std::wstring maintenanceError;
  if (!maintenanceGuard.ValidateUninstallAuthorization(uninstallToken, &maintenanceError)) {
    std::wcerr << L"Agent maintenance was not authorised: " << maintenanceError << std::endl;
    return false;
  }
  UnlockServiceControl();
  struct RestoreServiceControl {
    ~RestoreServiceControl() { LockServiceControl(); }
  } restoreControl; // Reapply protection on every success or failure exit.
  const auto scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
  if (scManager == nullptr) {
    const auto error = GetLastError();
    std::wcerr << L"OpenSCManagerW failed with error " << error << std::endl;
    return false;
  }

  auto service = CreateServiceW(scManager, kServiceName, kServiceDisplayName,
                                SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START | DELETE | SERVICE_CHANGE_CONFIG |
                                    SERVICE_QUERY_CONFIG | READ_CONTROL | WRITE_DAC,
                                SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                serviceCommandLine.c_str(), nullptr, nullptr, nullptr, kLocalSystemAccountName, nullptr);
  if (service == nullptr) {
    const auto error = GetLastError();
    if (error == ERROR_SERVICE_EXISTS) {
      service = OpenServiceW(scManager, kServiceName,
                             SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START | DELETE | SERVICE_CHANGE_CONFIG |
                                 SERVICE_QUERY_CONFIG | READ_CONTROL | WRITE_DAC);
      if (service == nullptr) {
        const auto error = GetLastError();
        CloseServiceHandle(scManager);
        std::wcerr << L"OpenServiceW failed with error " << error << std::endl;
        return false;
      }
      if (ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                               serviceCommandLine.c_str(), nullptr, nullptr, nullptr, kLocalSystemAccountName, nullptr,
                               kServiceDisplayName) == FALSE) {
        std::wcerr << L"ChangeServiceConfigW failed with error " << GetLastError() << std::endl;
        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
        return false;
      }
    } else {
      CloseServiceHandle(scManager);
      std::wcerr << L"CreateServiceW failed with error " << error << std::endl;
      return false;
    }
  }

  if (!ConfigureServiceHardening(service)) {
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;  // Never report a persistent install without working SCM recovery settings.
  }

  auto config = antivirus::agent::LoadAgentConfigForModule(nullptr);
  std::wstring runtimeLayoutError;
  if (!PrepareRuntimeLayout(config, &runtimeLayoutError)) {
    std::wcerr << L"Runtime layout preparation failed: " << runtimeLayoutError << std::endl;
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;
  }

  antivirus::agent::HardeningManager hardeningManager(
      config, config.installRootPath.empty() ? GetInstallRoot() : config.installRootPath);
  std::wstring hardeningError;
  const auto hardeningApplied = hardeningManager.ApplyPostInstallHardening(uninstallToken, &hardeningError);
  if (!hardeningApplied) {
    std::wcerr << L"Post-install hardening failed: " << hardeningError << std::endl;
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;
  }

  std::wstring serviceControlHardeningError;
  if (!hardeningManager.ApplyServiceControlProtection(kServiceName, service, &serviceControlHardeningError)) {
    std::wcerr << L"Service stop-hardening failed: " << serviceControlHardeningError << std::endl;
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;
  }

  if (!config.elamDriverPath.empty()) {
    std::wstring protectedServiceError;
    if (!hardeningManager.ApplyProtectedServiceRegistration(kServiceName, service, config.elamDriverPath,
                                                            &protectedServiceError)) {
      std::wcerr << L"Protected-service registration failed: " << protectedServiceError << std::endl;
      CloseServiceHandle(service);
      CloseServiceHandle(scManager);
      return false;
    }
  }

  if (!InvokeAdjacentDllRegistration(true)) {
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;
  }

  antivirus::agent::WscCoexistenceManager wscManager;
  const auto wscSnapshot = wscManager.CaptureSnapshot();
  std::wcout << L"WSC coexistence status: "
             << (wscSnapshot.available ? wscSnapshot.providerHealth : wscSnapshot.errorMessage) << std::endl;

  const auto hardeningStatus = hardeningManager.QueryStatus(kServiceName);
  const auto runtimeTrust = antivirus::agent::ValidateRuntimeTrust(
      config, config.installRootPath.empty() ? GetInstallRoot() : config.installRootPath);
  if (!runtimeTrust.trusted) {
    std::wcerr << L"Runtime trust validation failed: "
               << (runtimeTrust.message.empty() ? L"Unknown runtime trust validation failure." : runtimeTrust.message)
               << std::endl;
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;
  }

  CloseServiceHandle(service);
  CloseServiceHandle(scManager);
  std::wcout << (repair ? L"Repaired " : L"Installed ") << kServiceDisplayName
             << L" with start-at-boot, restart-on-failure, stop protection, AMSI registration, tamper hardening, and "
             << (hardeningStatus.launchProtectedConfigured ? L"launch-protected antimalware service posture."
                                                           : L"standard service posture.")
             << std::endl;
  return true;
}

std::wstring GetSiblingPath(const std::wstring& fileName) {
  const auto modulePath = std::filesystem::path(GetModulePath());
  const auto directory = modulePath.has_parent_path() ? modulePath.parent_path() : std::filesystem::current_path();
  return (directory / fileName).wstring();
}

bool InvokeAdjacentDllRegistration(const bool registerProvider) {
  const auto dllPath = GetSiblingPath(kAmsiProviderDllName);
  const auto library = LoadLibraryW(dllPath.c_str());
  if (library == nullptr) {
    std::wcerr << L"Could not load " << dllPath << L" for AMSI provider registration." << std::endl;
    return false;
  }

  using RegistrationFunction = HRESULT(__stdcall*)();
  const auto exportName = registerProvider ? "DllRegisterServer" : "DllUnregisterServer";
  const auto registration = reinterpret_cast<RegistrationFunction>(GetProcAddress(library, exportName));
  if (registration == nullptr) {
    std::wcerr << L"Could not find " << antivirus::agent::Utf8ToWide(exportName) << L" in " << dllPath << std::endl;
    FreeLibrary(library);
    return false;
  }

  const auto hr = registration();
  FreeLibrary(library);
  if (FAILED(hr)) {
    std::wcerr << L"AMSI provider " << (registerProvider ? L"registration" : L"unregistration")
               << L" failed with HRESULT 0x" << std::hex << hr << std::dec << std::endl;
    return false;
  }

  std::wcout << L"AMSI provider " << (registerProvider ? L"registered" : L"unregistered") << L" successfully."
             << std::endl;
  return true;
}

bool WaitForServiceStop(SC_HANDLE service, const DWORD timeoutMs) {
  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  const ULONGLONG deadline = GetTickCount64() + timeoutMs;
  do {
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
      return false;
    }
    if (status.dwCurrentState == SERVICE_STOPPED) return true;
    Sleep(250);
  } while (GetTickCount64() < deadline);
  return false;
}

bool RequestAndWaitForServiceStop(SC_HANDLE service, const wchar_t* operation) {
  SERVICE_STATUS_PROCESS current{};
  DWORD bytesNeeded = 0;
  if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<LPBYTE>(&current), sizeof(current), &bytesNeeded)) {
    std::wcerr << operation << L": could not query the service status (" << GetLastError() << L")." << std::endl;
    return false;
  }
  if (current.dwCurrentState == SERVICE_STOPPED) return true;

  SERVICE_STATUS status{};
  if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
    const auto error = GetLastError();
    if (error != ERROR_SERVICE_NOT_ACTIVE) {
      std::wcerr << operation << L": Windows refused the service stop (" << error << L")." << std::endl;
      return false;
    }
  }
  if (!WaitForServiceStop(service, 30'000)) {
    std::wcerr << operation << L": the agent service did not reach STOPPED within 30 seconds." << std::endl;
    return false;
  }
  return true;
}

bool UninstallService(const std::wstring& uninstallToken) {
  const auto config = antivirus::agent::LoadAgentConfigForModule(nullptr);
  antivirus::agent::HardeningManager hardeningManager(config, GetInstallRoot());
  std::wstring validationError;
  if (!hardeningManager.ValidateUninstallAuthorization(uninstallToken, &validationError)) {
    std::wcerr << validationError << std::endl;
    return false;
  }

  UnlockServiceControl();
  struct RelockOnExit { ~RelockOnExit() { LockServiceControl(); } } relock;
  const auto scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scManager == nullptr) {
    std::wcerr << L"OpenSCManagerW failed with error " << GetLastError() << std::endl;
    return false;
  }

  const auto service = OpenServiceW(scManager, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const auto error = GetLastError();
    CloseServiceHandle(scManager);

    if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
      std::wcout << L"The service is not installed." << std::endl;
      return true;
    }

    std::wcerr << L"OpenServiceW failed with error " << error << std::endl;
    return false;
  }

  if (!RequestAndWaitForServiceStop(service, L"Uninstall")) {
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;  // Never mark a running service for deletion after reboot.
  }

  const auto deleted = DeleteService(service) != FALSE;
  if (!deleted) {
    std::wcerr << L"DeleteService failed with error " << GetLastError() << std::endl;
  }

  CloseServiceHandle(service);
  CloseServiceHandle(scManager);

  InvokeAdjacentDllRegistration(false);

  if (deleted) {
    std::wcout << L"Removed " << kServiceDisplayName << L"." << std::endl;
  }

  return deleted;
}

// --stop: the supported way to stop the protected service (Stop-Service is refused). Needs the
// uninstall token when uninstall protection is on. It starts again on reboot, with --install or
// --repair, or with Start-Service.
bool StopProtectedService(const std::wstring& uninstallToken) {
  const auto config = antivirus::agent::LoadAgentConfigForModule(nullptr);
  antivirus::agent::HardeningManager hardeningManager(config, GetInstallRoot());
  std::wstring validationError;
  if (!hardeningManager.ValidateUninstallAuthorization(uninstallToken, &validationError)) {
    std::wcerr << validationError << std::endl;
    return false;
  }
  UnlockServiceControl();
  struct RelockOnExit { ~RelockOnExit() { LockServiceControl(); } } relock;
  const auto scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scManager == nullptr) {
    std::wcerr << L"OpenSCManagerW failed with error " << GetLastError() << std::endl;
    return false;
  }
  const auto service = OpenServiceW(scManager, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    std::wcerr << L"OpenServiceW failed with error " << GetLastError() << std::endl;
    CloseServiceHandle(scManager);
    return false;
  }
  const auto stopped = RequestAndWaitForServiceStop(service, L"Authorised stop");
  CloseServiceHandle(service);
  CloseServiceHandle(scManager);
  if (!stopped) return false;
  std::wcout << L"Stopped " << kServiceDisplayName << L"." << std::endl;
  return true;
}

bool UpgradeInstalledService(const std::wstring& manifestPath) {
  if (manifestPath.empty()) {
    std::wcerr << L"--upgrade requires a manifest path." << std::endl;
    return false;
  }

  const auto config = antivirus::agent::LoadAgentConfigForModule(nullptr);
  UnlockServiceControl();
  struct Relock {
    ~Relock() { LockServiceControl(); }
  } relock;  // locked again however the upgrade ends
  const auto scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scManager == nullptr) {
    std::wcerr << L"OpenSCManagerW failed with error " << GetLastError() << std::endl;
    return false;
  }

  const auto service = OpenServiceW(scManager, kServiceName, SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    std::wcerr << L"OpenServiceW failed with error " << GetLastError() << std::endl;
    CloseServiceHandle(scManager);
    return false;
  }

  if (!RequestAndWaitForServiceStop(service, L"Upgrade")) {
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;  // Do not replace in-use binaries.
  }

  antivirus::agent::UpdaterService updater(config, GetInstallRoot());
  const auto result = updater.ApplyPackage(manifestPath, antivirus::agent::UpdateApplyMode::Maintenance);
  if (!result.success) {
    std::wcerr << L"Upgrade failed: " << result.errorMessage << std::endl;
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;
  }

  if (StartServiceW(service, 0, nullptr) == FALSE && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
    std::wcerr << L"StartServiceW failed with error " << GetLastError() << std::endl;
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return false;
  }

  CloseServiceHandle(service);
  CloseServiceHandle(scManager);
  std::wcout << L"Upgrade status: " << result.status << L" (transaction " << result.transactionId << L")" << std::endl;
  return true;
}

bool RollbackInstalledUpdate(const std::wstring& transactionId) {
  if (transactionId.empty()) {
    std::wcerr << L"--rollback-update requires a transaction identifier." << std::endl;
    return false;
  }

  const auto config = antivirus::agent::LoadAgentConfigForModule(nullptr);
  antivirus::agent::UpdaterService updater(config, GetInstallRoot());
  const auto result = updater.RollbackTransaction(transactionId);
  if (!result.success) {
    std::wcerr << L"Rollback failed: " << result.errorMessage << std::endl;
    return false;
  }

  std::wcout << L"Rollback status: " << result.status << std::endl;
  return true;
}

int PrintWscStatus() {
  antivirus::agent::WscCoexistenceManager manager;
  const auto snapshot = manager.CaptureSnapshot();
  std::wcout << antivirus::agent::WscCoexistenceManager::ToJson(snapshot) << std::endl;
  return snapshot.available ? 0 : 1;
}

int RunSelfTest() {
  const auto config = antivirus::agent::LoadAgentConfigForModule(nullptr);
  const auto report = antivirus::agent::RunSelfTest(config, GetInstallRoot());
  std::wcout << antivirus::agent::SelfTestReportToJson(report) << std::endl;
  return antivirus::agent::SelfTestExitCode(report);
}

BOOL WINAPI ConsoleControlHandler(const DWORD controlCode) {
  switch (controlCode) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      if (g_activeService != nullptr) {
        g_activeService->RequestStop();
        return TRUE;
      }
      return FALSE;
    default:
      return FALSE;
  }
}

int RunConsoleMode() {
  antivirus::agent::AgentService service;
  g_activeService = &service;
  SetConsoleCtrlHandler(ConsoleControlHandler, TRUE);
  const auto exitCode = service.Run(antivirus::agent::AgentRunMode::Console);
  SetConsoleCtrlHandler(ConsoleControlHandler, FALSE);
  g_activeService = nullptr;
  return exitCode;
}

// --server and --enroll-token come from the console's Deploy agents page.
bool SaveCloudSettingsFromArguments(int argc, wchar_t* argv[]) {
  const auto server = GetArgumentValue(argc, argv, L"--server");
  const auto enrollToken = GetArgumentValue(argc, argv, L"--enroll-token");
  if (server.empty() && enrollToken.empty()) {
    return true;
  }

  // Reinstalling, repairing, and reinstalling the same package must never
  // silently discard the device identity: that creates duplicate cloud devices.
  // Changing tenant/server requires a separate, explicit, authorised migration.
  const auto existingConfig = antivirus::agent::LoadAgentConfig();
  try {
    // Fail closed on missing/inaccessible state. Do not overwrite enrollment
    // before confirming whether the current device belongs to another tenant.
    std::error_code existsError;
    const bool databaseExists = std::filesystem::exists(existingConfig.runtimeDatabasePath, existsError);
    if (existsError) {
      std::wcerr << L"Could not inspect existing Fenrir device identity; installation stopped." << std::endl;
      return false;
    }
    bool enrolled = false;
    if (databaseExists) {
      const antivirus::agent::LocalStateStore stateStore(existingConfig.runtimeDatabasePath,
                                                          existingConfig.stateFilePath);
      const auto currentState = stateStore.LoadOrCreate();
      enrolled = !currentState.deviceId.empty();
    }
    if (antivirus::agent::EnrollmentChangeRequiresMigration(existingConfig.controlPlaneBaseUrl,
                                                             existingConfig.enrollmentToken,
                                                             server, enrollToken, enrolled)) {
      std::wcerr << L"Fenrir is already enrolled. A new server or deployment token cannot "
                    L"silently replace the existing device identity. An authorised "
                    L"migration workflow is required." << std::endl;
      return false;
    }
  } catch (const std::exception&) {
    std::wcerr << L"Could not verify existing Fenrir identity before enrollment change." << std::endl;
    return false;
  }

  if (!antivirus::agent::SaveCloudEnrollmentSettings(server, enrollToken)) {
    std::wcerr << L"Could not save Fenrir server settings. Run this from an Administrator prompt." << std::endl;
    return false;
  }
  std::wcout << L"Fenrir server settings saved; existing device identity preserved." << std::endl;
  return true;
}

void PrintUsage() {
  std::wcout << L"Usage: fenrir-agent-service.exe [--console|--install [--elam-driver <path>]|--repair [--elam-driver <path>]|--upgrade <manifest>|--rollback-update <transaction>|--uninstall [--token <token>]|--wsc-status|--self-test|--register-amsi-provider|--unregister-amsi-provider|--help]" << std::endl;
  std::wcout << L"  --console   Run the agent loop interactively instead of under the SCM." << std::endl;
  std::wcout << L"  --server <url> --enroll-token <token>  With --install or --console: connect this PC to your Fenrir cloud." << std::endl;
  std::wcout << L"  --install   Register the agent as an auto-start Windows service and apply hardening." << std::endl;
  std::wcout << L"  --repair    Reapply service hardening, AMSI registration, protected runtime settings, and runtime trust markers." << std::endl;
  std::wcout << L"  --upgrade   Stop the service, apply a verified update manifest, and restart the service." << std::endl;
  std::wcout << L"  --rollback-update  Roll back a recorded update transaction from the local update journal." << std::endl;
  std::wcout << L"  --stop      Stop the service (Stop-Service and services.msc are blocked). Use --token when uninstall protection is enabled." << std::endl;
  std::wcout << L"  --uninstall Remove the Windows service registration. Use --token when uninstall protection is enabled." << std::endl;
  std::wcout << L"  --wsc-status Print the local Windows Security Center coexistence snapshot." << std::endl;
  std::wcout << L"  --self-test Run a local endpoint validation sweep for packaging, hardening, AMSI, ETW, WFP, runtime store, and Phase 1 disk/execute blocking checks." << std::endl;
  std::wcout << L"  --token     Optional uninstall/installation protection token for hardened endpoints." << std::endl;
  std::wcout << L"  --elam-driver  Optional signed ELAM .sys path used to enable launch-protected antimalware service registration." << std::endl;
  std::wcout << L"  --register-amsi-provider   Register the adjacent AMSI provider DLL." << std::endl;
  std::wcout << L"  --unregister-amsi-provider Remove the AMSI provider DLL registration." << std::endl;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  const auto token = GetArgumentValue(argc, argv, L"--token");
  const auto elamDriver = GetArgumentValue(argc, argv, L"--elam-driver");
  if (!elamDriver.empty()) {
    SetEnvironmentVariableW(L"ANTIVIRUS_ELAM_DRIVER_PATH", elamDriver.c_str());
    SetEnvironmentVariableW(L"ANTIVIRUS_ELAM_DRIVER_REQUIRED", L"1");
  } else {
    SetEnvironmentVariableW(L"ANTIVIRUS_ELAM_DRIVER_REQUIRED", L"0");
  }
  if (argc > 1) {
    const std::wstring command = argv[1];
    if (command == L"--console") {
      if (!SaveCloudSettingsFromArguments(argc, argv)) {
        return 1;
      }
      return RunConsoleMode();
    }

    if (command == L"--install") {
      if (!SaveCloudSettingsFromArguments(argc, argv)) {
        return 1;
      }
      return InstallOrRepairService(false, token) ? 0 : 1;
    }

    if (command == L"--repair") {
      return InstallOrRepairService(true, token) ? 0 : 1;
    }

    if (command == L"--upgrade") {
      return UpgradeInstalledService(argc > 2 ? argv[2] : L"") ? 0 : 1;
    }

    if (command == L"--rollback-update") {
      return RollbackInstalledUpdate(argc > 2 ? argv[2] : L"") ? 0 : 1;
    }

    if (command == L"--stop") {
      return StopProtectedService(token) ? 0 : 1;
    }

    if (command == L"--uninstall") {
      return UninstallService(token) ? 0 : 1;
    }

    if (command == L"--wsc-status") {
      return PrintWscStatus();
    }

    if (command == L"--self-test") {
      return RunSelfTest();
    }

    if (command == L"--register-amsi-provider") {
      return InvokeAdjacentDllRegistration(true) ? 0 : 1;
    }

    if (command == L"--unregister-amsi-provider") {
      return InvokeAdjacentDllRegistration(false) ? 0 : 1;
    }

    if (command == L"--help") {
      PrintUsage();
      return 0;
    }

    std::wcerr << L"Unknown option: " << command << std::endl;
    PrintUsage();
    return 1;
  }

  SERVICE_TABLE_ENTRYW serviceTable[] = {
      {const_cast<LPWSTR>(kServiceName), ServiceEntry},
      {nullptr, nullptr}};

  if (StartServiceCtrlDispatcherW(serviceTable) != FALSE) {
    return 0;
  }

  if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
    return RunConsoleMode();
  }

  std::wcerr << L"StartServiceCtrlDispatcherW failed with error " << GetLastError() << std::endl;
  return 1;
}
