#include <windows.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <commctrl.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <functional>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "AgentConfig.h"
#include "DeviceInventoryCollector.h"
#include "EndpointClient.h"
#include "LocalSecurity.h"
#include "ProcessInventory.h"
#include "LocalScanRunner.h"
#include "LocalStateStore.h"
#include "PatchOrchestrator.h"
#include "ServiceInventory.h"
#include "StringUtils.h"
#include "WebView2.h"

namespace {

using antivirus::agent::EndpointClientSnapshot;
using antivirus::agent::LocalServiceState;
using Microsoft::WRL::ComPtr;

constexpr wchar_t kWindowClassName[] = L"FenrirEndpointClientWindow";
constexpr wchar_t kWindowTitle[] = L"Fenrir Protection Centre";
constexpr wchar_t kInstanceMutexName[] = L"Local\\FenrirEndpointClientSingleton";
constexpr wchar_t kRestoreWindowMessageName[] = L"FenrirEndpointClient.RestoreWindow";
constexpr wchar_t kPamRequestEventName[] = L"Global\\FenrirPamRequestReady";
constexpr wchar_t kPamRequestFileName[] = L"pam-request.json";
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kScanCompleteMessage = WM_APP + 2;
constexpr UINT kScanProgressMessage = WM_APP + 3;
constexpr UINT kPatchActionCompleteMessage = WM_APP + 4;
constexpr UINT_PTR kRefreshTimerId = 100;
constexpr UINT kRefreshIntervalMs = 10000;
constexpr UINT kFenrirPngResourceId = 101;

enum : int {
  IDC_BRAND_CARD = 1001,
  IDC_TITLE = 1002,
  IDC_SUBTITLE = 1003,
  IDC_STATUS_BADGE = 1004,
  IDC_PRIMARY_SECTION_TITLE = 1005,
  IDC_SECONDARY_SECTION_TITLE = 1006,
  IDC_SUMMARY_CARD = 1007,
  IDC_DETAILS_CARD = 1008,
  IDC_METRIC_THREATS = 1009,
  IDC_METRIC_QUARANTINE = 1010,
  IDC_METRIC_SERVICE = 1011,
  IDC_METRIC_SYNC = 1012,
  IDC_SCAN_STATUS = 1013,
  IDC_PROGRESS = 1014,
  IDC_THREATS_LIST = 1015,
  IDC_QUARANTINE_LIST = 1016,
  IDC_HISTORY_LIST = 1017,
  IDC_DETAIL_EDIT = 1018,
  IDC_BUTTON_REFRESH = 1101,
  IDC_BUTTON_QUICKSCAN = 1102,
  IDC_BUTTON_FULLSCAN = 1103,
  IDC_BUTTON_CUSTOMSCAN = 1104,
  IDC_BUTTON_STARTSERVICE = 1105,
  IDC_BUTTON_OPENQUARANTINE = 1106,
  IDC_BUTTON_RESTORE = 1107,
  IDC_BUTTON_DELETE = 1108,
  IDC_NAV_DASHBOARD = 1201,
  IDC_NAV_THREATS = 1202,
  IDC_NAV_QUARANTINE = 1203,
  IDC_NAV_SCANS = 1204,
  IDC_NAV_SERVICE = 1205,
  IDC_NAV_HISTORY = 1206,
  IDC_NAV_SETTINGS = 1207,
  IDM_TRAY_OPEN = 2001,
  IDM_TRAY_QUICKSCAN = 2002,
  IDM_TRAY_FULLSCAN = 2003,
  IDM_TRAY_PAM_POWERSHELL = 2004,
  IDM_TRAY_PAM_CMD = 2005,
  IDM_TRAY_PAM_DISKCLEANUP = 2006,
  IDM_TRAY_PAM_APP = 2007,
  IDM_TRAY_PAM_ELEVATE_2M = 2008,
  IDM_TRAY_PAM_WINDOWSUPDATE = 2009,
  IDM_TRAY_PAM_NETWORKRESET = 2010,
  IDM_TRAY_QUARANTINE = 2011,
  IDM_TRAY_EXIT = 2012
};

enum class ScanPreset {
  Quick,
  Full,
  Folder
};

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif
#ifndef DWMWA_TEXT_COLOR
#define DWMWA_TEXT_COLOR 36
#endif

enum class ClientPage : int {
  Dashboard = 0,
  Threats = 1,
  Quarantine = 2,
  Scans = 3,
  Updates = 4,
  Service = 5,
  History = 6,
  Settings = 7
};

struct ScanCompletePayload {
  std::wstring summary;
  bool success{true};
};

struct ScanProgressPayload {
  std::wstring status;
  std::uint32_t completedTargets{0};
  std::uint32_t totalTargets{0};
};

struct PatchActionCompletePayload {
  std::wstring summary;
  std::wstring targetId;
  bool informational{true};
  bool success{true};
  bool searchOnly{false};
  bool suppressDialog{false};
};

struct LaunchOptions {
  bool backgroundMode{false};
  bool manageExclusionsMode{false};
  bool applyExclusionsMode{false};
  bool applySoftwareUpdateMode{false};
  std::wstring applySoftwareUpdateId;
  std::vector<std::filesystem::path> applyExclusionsPaths;
};

std::wstring BuildPatchExecutionSummary(const antivirus::agent::PatchExecutionResult& result, bool searchOnly);
bool IsPatchResultInformational(const antivirus::agent::PatchExecutionResult& result);

HANDLE g_instanceMutex = nullptr;

struct UiContext {
  antivirus::agent::AgentConfig config;
  EndpointClientSnapshot snapshot;
  NOTIFYICONDATAW trayIcon{};
  HWND hwnd{};
  HWND brandCard{};
  HWND brandLogo{};
  HWND brandSummary{};
  HWND titleLabel{};
  HWND subtitleLabel{};
  HWND statusBadge{};
  HWND primarySectionTitle{};
  HWND secondarySectionTitle{};
  HWND summaryCard{};
  HWND detailsCard{};
  HWND metricThreats{};
  HWND metricQuarantine{};
  HWND metricService{};
  HWND metricSync{};
  HWND scanStatusLabel{};
  HWND progressBar{};
  HWND threatsList{};
  HWND quarantineList{};
  HWND historyList{};
  HWND detailEdit{};
  HWND refreshButton{};
  HWND quickScanButton{};
  HWND fullScanButton{};
  HWND customScanButton{};
  HWND startServiceButton{};
  HWND openQuarantineButton{};
  HWND restoreButton{};
  HWND deleteButton{};
  HWND navDashboardButton{};
  HWND navThreatsButton{};
  HWND navQuarantineButton{};
  HWND navScansButton{};
  HWND navServiceButton{};
  HWND navHistoryButton{};
  HWND navSettingsButton{};
  HFONT titleFont{};
  HFONT headingFont{};
  HFONT bodyFont{};
  HBRUSH windowBrush{};
  HBRUSH surfaceBrush{};
  HBRUSH summarySafeBrush{};
  HBRUSH summaryWarningBrush{};
  HBRUSH summaryDangerBrush{};
  HBRUSH detailsBrush{};
  HBRUSH metricInfoBrush{};
  HBRUSH metricSuccessBrush{};
  HBRUSH metricWarningBrush{};
  HBRUSH metricDangerBrush{};
  HBRUSH detailBrush{};
  HBRUSH listBrush{};
  HICON iconNeutralSmall{};
  HICON iconNeutralLarge{};
  HICON iconSafeSmall{};
  HICON iconSafeLarge{};
  HICON iconWarningSmall{};
  HICON iconWarningLarge{};
  HICON iconDangerSmall{};
  HICON iconDangerLarge{};
  bool trayAdded{false};
  bool allowExit{false};
  bool backgroundMode{false};
  bool manageExclusionsMode{false};
  bool snapshotPrimed{false};
  std::size_t lastObservedThreatCount{0};
  LocalServiceState lastObservedServiceState{LocalServiceState::Unknown};
  std::wstring lastThreatFingerprint;
  std::wstring scanStatusText{L"Ready."};
  std::uint32_t scanProgressCompleted{0};
  std::uint32_t scanProgressTotal{0};
  std::atomic_bool scanRunning{false};
  std::wstring activeScanLabel;
  std::atomic_bool patchActionRunning{false};
  std::wstring patchActionStatus{L"Idle"};
  std::wstring patchActionTarget;
  bool patchActionSearchOnly{false};
  ClientPage currentPage{ClientPage::Dashboard};
  bool webViewReady{false};
  bool webViewEnabled{false};
  bool webViewFallbackActive{false};
  std::wstring webViewFailureReason;
  std::wstring webViewLogoDataUri;
  HMODULE webViewLoaderModule{};
  ComPtr<ICoreWebView2Environment> webViewEnvironment;
  ComPtr<ICoreWebView2Controller> webViewController;
  ComPtr<ICoreWebView2> webView;
  EventRegistrationToken webMessageReceivedToken{};
};

UiContext* GetContext(HWND hwnd) {
  return reinterpret_cast<UiContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

class WebViewEnvironmentCompletedHandler final : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler {
 public:
  using CallbackType = std::function<HRESULT(HRESULT, ICoreWebView2Environment*)>;

  explicit WebViewEnvironmentCompletedHandler(CallbackType callback) : callback_(std::move(callback)) {}

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
    if (ppvObject == nullptr) {
      return E_POINTER;
    }

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler)) {
      *ppvObject = static_cast<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*>(this);
      AddRef();
      return S_OK;
    }

    *ppvObject = nullptr;
    return E_NOINTERFACE;
  }

  ULONG STDMETHODCALLTYPE AddRef() override { return ++refCount_; }

  ULONG STDMETHODCALLTYPE Release() override {
    const auto count = --refCount_;
    if (count == 0) {
      delete this;
    }
    return count;
  }

  HRESULT STDMETHODCALLTYPE Invoke(HRESULT errorCode, ICoreWebView2Environment* result) override {
    return callback_ ? callback_(errorCode, result) : S_OK;
  }

 private:
  std::atomic<ULONG> refCount_{1};
  CallbackType callback_;
};

class WebViewControllerCompletedHandler final : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler {
 public:
  using CallbackType = std::function<HRESULT(HRESULT, ICoreWebView2Controller*)>;

  explicit WebViewControllerCompletedHandler(CallbackType callback) : callback_(std::move(callback)) {}

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
    if (ppvObject == nullptr) {
      return E_POINTER;
    }

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler)) {
      *ppvObject = static_cast<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*>(this);
      AddRef();
      return S_OK;
    }

    *ppvObject = nullptr;
    return E_NOINTERFACE;
  }

  ULONG STDMETHODCALLTYPE AddRef() override { return ++refCount_; }

  ULONG STDMETHODCALLTYPE Release() override {
    const auto count = --refCount_;
    if (count == 0) {
      delete this;
    }
    return count;
  }

  HRESULT STDMETHODCALLTYPE Invoke(HRESULT errorCode, ICoreWebView2Controller* result) override {
    return callback_ ? callback_(errorCode, result) : S_OK;
  }

 private:
  std::atomic<ULONG> refCount_{1};
  CallbackType callback_;
};

class WebViewMessageReceivedHandler final : public ICoreWebView2WebMessageReceivedEventHandler {
 public:
  using CallbackType = std::function<HRESULT(ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs*)>;

  explicit WebViewMessageReceivedHandler(CallbackType callback) : callback_(std::move(callback)) {}

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
    if (ppvObject == nullptr) {
      return E_POINTER;
    }

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ICoreWebView2WebMessageReceivedEventHandler)) {
      *ppvObject = static_cast<ICoreWebView2WebMessageReceivedEventHandler*>(this);
      AddRef();
      return S_OK;
    }

    *ppvObject = nullptr;
    return E_NOINTERFACE;
  }

  ULONG STDMETHODCALLTYPE AddRef() override { return ++refCount_; }

  ULONG STDMETHODCALLTYPE Release() override {
    const auto count = --refCount_;
    if (count == 0) {
      delete this;
    }
    return count;
  }

  HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2* sender, ICoreWebView2WebMessageReceivedEventArgs* args) override {
    return callback_ ? callback_(sender, args) : S_OK;
  }

 private:
  std::atomic<ULONG> refCount_{1};
  CallbackType callback_;
};

void UpdateTrayIcon(UiContext& context);
void PublishWebViewState(UiContext& context);
void ResizeWebView(UiContext& context);
void HideNativeShellControls(UiContext& context, bool visible);
bool InitializeWebViewHost(UiContext& context);
void DestroyWebViewHost(UiContext& context);
void HandleWebViewMessage(UiContext& context, const std::wstring& message);
std::wstring BuildWebViewFallbackStatus(const UiContext& context);

std::wstring NullableText(const std::wstring& value, const wchar_t* fallback = L"(not available)") {
  return value.empty() ? std::wstring(fallback) : value;
}

UINT RestoreWindowMessageId() {
  static const UINT messageId = RegisterWindowMessageW(kRestoreWindowMessageName);
  return messageId;
}

bool HasSwitch(const std::vector<std::wstring>& arguments, const wchar_t* value) {
  return std::any_of(arguments.begin(), arguments.end(),
                     [value](const std::wstring& argument) { return _wcsicmp(argument.c_str(), value) == 0; });
}

bool IsCurrentUserAdmin() {
  return antivirus::agent::IsCurrentUserElevatedAdmin();
}

bool RequireAuthorizedLocalAction(HWND hwnd, const antivirus::agent::LocalAction action, const wchar_t* title) {
  const auto authorization = antivirus::agent::AuthorizeCurrentUser(action);
  if (authorization.allowed) {
    return true;
  }

  std::wstring message = authorization.reason;
  if (authorization.requestOnly) {
    message += L"\r\n\r\nUse an administrator account or a Fenrir-approved PAM flow for this action.";
  }

  MessageBoxW(hwnd, message.c_str(), title, MB_OK | MB_ICONWARNING);
  return false;
}

bool StartsWithSwitchPrefix(const std::wstring& value) {
  return !value.empty() && (value.front() == L'-' || value.front() == L'/');
}

std::wstring QuoteCommandLineArgument(const std::wstring& argument) {
  if (argument.empty()) {
    return L"\"\"";
  }

  const auto needsQuotes = argument.find_first_of(L" \t\r\n\v\"") != std::wstring::npos;
  if (!needsQuotes) {
    return argument;
  }

  std::wstring quoted;
  quoted.reserve(argument.size() + 2);
  quoted.push_back(L'"');

  std::size_t backslashCount = 0;
  for (const auto ch : argument) {
    if (ch == L'\\') {
      ++backslashCount;
      continue;
    }

    if (ch == L'"') {
      quoted.append(backslashCount * 2 + 1, L'\\');
      quoted.push_back(L'"');
      backslashCount = 0;
      continue;
    }

    if (backslashCount != 0) {
      quoted.append(backslashCount, L'\\');
      backslashCount = 0;
    }

    quoted.push_back(ch);
  }

  if (backslashCount != 0) {
    quoted.append(backslashCount * 2, L'\\');
  }

  quoted.push_back(L'"');
  return quoted;
}

int ApplyExclusionsFromLaunchOptions(const LaunchOptions& options) {
  if (options.applyExclusionsPaths.empty()) {
    return 1;
  }

  if (!antivirus::agent::SaveConfiguredScanExclusions(options.applyExclusionsPaths)) {
    return 1;
  }

  return antivirus::agent::RestartAgentService() ? 0 : 2;
}

int ApplySoftwareUpdateFromLaunchOptions(const LaunchOptions& options) {
  if (options.applySoftwareUpdateId.empty()) {
    return 1;
  }

  const auto config = antivirus::agent::LoadAgentConfigForModule(nullptr);
  const auto result = antivirus::agent::ExecuteSoftwarePatchThroughService(config, options.applySoftwareUpdateId);
  const auto summary = BuildPatchExecutionSummary(result, false);
  MessageBoxW(nullptr, summary.c_str(), kWindowTitle,
              MB_OK | (result.success || IsPatchResultInformational(result) ? MB_ICONINFORMATION : MB_ICONWARNING));
  return result.success || IsPatchResultInformational(result) ? 0 : 2;
}

LaunchOptions ParseLaunchOptions() {
  LaunchOptions options;
  int argumentCount = 0;
  const auto argumentValues = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
  if (argumentValues == nullptr) {
    return options;
  }

  std::vector<std::wstring> arguments;
  arguments.reserve(static_cast<std::size_t>(argumentCount));
  for (int index = 0; index < argumentCount; ++index) {
    arguments.emplace_back(argumentValues[index]);
  }
  LocalFree(argumentValues);

  options.backgroundMode =
      HasSwitch(arguments, L"--background") || HasSwitch(arguments, L"--tray") || HasSwitch(arguments, L"/background");
  options.manageExclusionsMode = HasSwitch(arguments, L"--manage-exclusions") ||
                                 HasSwitch(arguments, L"/manage-exclusions") || HasSwitch(arguments, L"--exclusions");

  options.applyExclusionsMode = HasSwitch(arguments, L"--apply-exclusions") || HasSwitch(arguments, L"/apply-exclusions");
  if (options.applyExclusionsMode) {
    options.backgroundMode = true;
  }

  options.applySoftwareUpdateMode =
      HasSwitch(arguments, L"--apply-software-update") || HasSwitch(arguments, L"/apply-software-update");
  if (options.applySoftwareUpdateMode) {
    options.backgroundMode = true;
  }

  bool capturePaths = false;
  bool captureSoftwareUpdateId = false;
  for (const auto& argument : arguments) {
    if (_wcsicmp(argument.c_str(), L"--apply-exclusions") == 0 ||
        _wcsicmp(argument.c_str(), L"/apply-exclusions") == 0) {
      capturePaths = true;
      captureSoftwareUpdateId = false;
      continue;
    }

    if (_wcsicmp(argument.c_str(), L"--apply-software-update") == 0 ||
        _wcsicmp(argument.c_str(), L"/apply-software-update") == 0) {
      captureSoftwareUpdateId = true;
      capturePaths = false;
      continue;
    }

    if (capturePaths && !StartsWithSwitchPrefix(argument)) {
      options.applyExclusionsPaths.emplace_back(argument);
    } else if (captureSoftwareUpdateId && !StartsWithSwitchPrefix(argument)) {
      options.applySoftwareUpdateId = argument;
      captureSoftwareUpdateId = false;
    }
  }

  return options;
}

bool IsWindowInteractive(const UiContext& context) {
  return IsWindowVisible(context.hwnd) != FALSE;
}

bool HasSelectedItem(HWND listView) {
  return listView != nullptr && ListView_GetNextItem(listView, -1, LVNI_SELECTED) >= 0;
}

std::wstring TrimCopy(std::wstring value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }

  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::vector<std::filesystem::path> ParseExclusionEditorText(const std::wstring& text) {
  std::vector<std::filesystem::path> exclusions;
  std::wstring current;
  std::wstringstream stream(text);
  while (std::getline(stream, current)) {
    current = TrimCopy(current);
    if (!current.empty()) {
      exclusions.emplace_back(current);
    }
  }

  return exclusions;
}

std::wstring BuildExclusionsEditorText() {
  std::wstringstream stream;
  const auto exclusions = antivirus::agent::LoadConfiguredScanExclusions();
  for (const auto& exclusion : exclusions) {
    stream << exclusion.wstring() << L"\r\n";
  }

  return stream.str();
}

std::wstring BuildExclusionEditorSummary() {
  std::wstringstream stream;
  stream << L"Exclusions are saved for the Fenrir protection service and applied at system level.\r\n"
         << L"Only add paths you trust, because excluded locations are skipped by scanning.";
  return stream.str();
}

std::wstring NormalizeExclusionKey(std::filesystem::path path) {
  path = path.lexically_normal();
  auto text = path.wstring();
  std::transform(text.begin(), text.end(), text.begin(), [](const wchar_t value) {
    return static_cast<wchar_t>(towlower(value));
  });
  return text;
}

bool AppendUniqueExclusion(std::vector<std::filesystem::path>& exclusions, const std::filesystem::path& candidate) {
  const auto key = NormalizeExclusionKey(candidate);
  if (key.empty()) {
    return false;
  }

  for (const auto& exclusion : exclusions) {
    if (NormalizeExclusionKey(exclusion) == key) {
      return false;
    }
  }

  exclusions.push_back(candidate);
  return true;
}

bool RemoveExclusionPath(std::vector<std::filesystem::path>& exclusions, const std::filesystem::path& candidate) {
  const auto key = NormalizeExclusionKey(candidate);
  if (key.empty()) {
    return false;
  }

  const auto originalSize = exclusions.size();
  exclusions.erase(std::remove_if(exclusions.begin(), exclusions.end(), [&key](const auto& existing) {
                    return NormalizeExclusionKey(existing) == key;
                  }),
                  exclusions.end());
  return exclusions.size() != originalSize;
}

std::optional<std::wstring> PickFile(HWND owner) {
  wchar_t filePath[MAX_PATH] = {};
  wchar_t filter[] = L"All files (*.*)\0*.*\0\0";
  OPENFILENAMEW dialog{};
  dialog.lStructSize = sizeof(dialog);
  dialog.hwndOwner = owner;
  dialog.lpstrFilter = filter;
  dialog.lpstrFile = filePath;
  dialog.nMaxFile = static_cast<DWORD>(std::size(filePath));
  dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
  dialog.lpstrTitle = L"Choose a file to exclude";

  if (!GetOpenFileNameW(&dialog)) {
    return std::nullopt;
  }

  return std::wstring(filePath);
}

std::vector<std::filesystem::path> ResolveProcessExclusionPaths(const DWORD pid) {
  const auto processes = antivirus::agent::CollectProcessInventory(0);
  for (const auto& process : processes) {
    if (process.pid == pid && !process.imagePath.empty()) {
      return {std::filesystem::path(process.imagePath)};
    }
  }

  return {};
}

std::vector<std::filesystem::path> ResolveSoftwareExclusionPaths(const std::wstring& softwareId) {
  const auto inventory = antivirus::agent::CollectDeviceInventorySnapshot();
  for (const auto& software : inventory.installedSoftware) {
    if (_wcsicmp(software.softwareId.c_str(), softwareId.c_str()) != 0) {
      continue;
    }

    std::vector<std::filesystem::path> exclusions;
    if (!software.installLocation.empty()) {
      exclusions.emplace_back(software.installLocation);
      for (const auto& executable : software.executableNames) {
        if (!executable.empty()) {
          exclusions.emplace_back(std::filesystem::path(software.installLocation) / executable);
        }
      }
    } else if (!software.displayIconPath.empty()) {
      exclusions.emplace_back(software.displayIconPath);
    }

    return exclusions;
  }

  return {};
}

std::wstring GetCurrentExecutablePath() {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (written == 0) {
    return {};
  }

  buffer.resize(written);
  return buffer;
}

std::filesystem::path GetWebViewUserDataFolder() {
  std::wstring localAppData(MAX_PATH, L'\0');
  const auto result = SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData.data());
  if (FAILED(result)) {
    return {};
  }

  localAppData.resize(wcslen(localAppData.c_str()));
  if (localAppData.empty()) {
    return {};
  }

  return std::filesystem::path(localAppData) / L"Fenrir Endpoint" / L"webview2";
}

bool LaunchExclusionsEditor(HWND owner) {
  const auto executablePath = GetCurrentExecutablePath();
  if (executablePath.empty()) {
    return false;
  }

  const auto result = reinterpret_cast<INT_PTR>(
      ShellExecuteW(owner, L"runas", executablePath.c_str(), L"--manage-exclusions", nullptr, SW_SHOWNORMAL));
  return result > 32;
}

bool LaunchElevatedSoftwareUpdate(HWND owner, const std::wstring& softwareId) {
  const auto executablePath = GetCurrentExecutablePath();
  if (executablePath.empty() || softwareId.empty()) {
    return false;
  }

  const auto parameters = std::wstring(L"--apply-software-update ") + QuoteCommandLineArgument(softwareId);
  const auto result = reinterpret_cast<INT_PTR>(
      ShellExecuteW(owner, L"runas", executablePath.c_str(), parameters.c_str(), nullptr, SW_SHOWNORMAL));
  return result > 32;
}

std::filesystem::path GetCurrentExecutableDirectory() {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (written == 0) {
    return std::filesystem::current_path();
  }

  buffer.resize(written);
  const auto executablePath = std::filesystem::path(buffer);
  return executablePath.has_parent_path() ? executablePath.parent_path() : std::filesystem::current_path();
}

std::wstring GetCurrentUserName() {
  std::array<wchar_t, 256> buffer{};
  DWORD size = static_cast<DWORD>(buffer.size());
  if (GetUserNameW(buffer.data(), &size) == FALSE) {
    return L"unknown";
  }

  if (size > 0 && buffer[size - 1] == L'\0') {
    --size;
  }
  return std::wstring(buffer.data(), size);
}

std::wstring EscapePamJsonValue(const std::wstring& value) {
  return antivirus::agent::Utf8ToWide(antivirus::agent::EscapeJsonString(value));
}

std::filesystem::path GetPerUserPamRequestPath() {
  const auto localAppData = antivirus::agent::ReadEnvironmentVariable(L"LOCALAPPDATA");
  if (localAppData.empty()) {
    return {};
  }

  return std::filesystem::path(localAppData) / L"FenrirAgent" / L"runtime" / kPamRequestFileName;
}

std::filesystem::path GetPamRequestPath(const UiContext& context) {
  const auto perUserPath = GetPerUserPamRequestPath();
  if (!perUserPath.empty()) {
    return perUserPath;
  }

  auto runtimeRoot = context.config.runtimeDatabasePath.parent_path();
  if (runtimeRoot.empty()) {
    runtimeRoot = GetCurrentExecutableDirectory() / L"runtime";
  }
  return runtimeRoot / kPamRequestFileName;
}

std::wstring GetSystemBinaryPath(const wchar_t* relativePath) {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
  if (written == 0) {
    return {};
  }

  buffer.resize(written);
  return (std::filesystem::path(buffer) / relativePath).wstring();
}

bool PromptForPamTarget(HWND owner, std::wstring* targetPath) {
  if (targetPath == nullptr) {
    return false;
  }

  std::array<wchar_t, 32768> buffer{};
  OPENFILENAMEW dialog{};
  dialog.lStructSize = sizeof(dialog);
  dialog.hwndOwner = owner;
  dialog.lpstrFilter =
      L"Applications and scripts (*.exe;*.com;*.bat;*.cmd;*.ps1)\0*.exe;*.com;*.bat;*.cmd;*.ps1\0All files (*.*)\0*.*\0\0";
  dialog.lpstrFile = buffer.data();
  dialog.nMaxFile = static_cast<DWORD>(buffer.size());
  dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
  dialog.lpstrTitle = L"Select an application to run with Fenrir PAM";

  if (!GetOpenFileNameW(&dialog)) {
    return false;
  }

  *targetPath = buffer.data();
  return !targetPath->empty();
}

bool QueuePamRequest(UiContext& context, const std::wstring& action, const std::wstring& targetPath,
                     const std::wstring& arguments, const std::wstring& reason, std::wstring* errorMessage) {
  if (targetPath.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir PAM did not receive a valid target path.";
    }
    return false;
  }

  const auto requestPath = GetPamRequestPath(context);
  std::error_code directoryError;
  std::filesystem::create_directories(requestPath.parent_path(), directoryError);
  if (directoryError) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not create the PAM runtime directory.";
    }
    return false;
  }

  const auto requestedAt = antivirus::agent::CurrentUtcTimestamp();
  const auto requester = GetCurrentUserName();
  const auto tempPath = requestPath.wstring() + L".new";

  const std::wstring payload =
      L"{\"requestedAt\":\"" + EscapePamJsonValue(requestedAt) + L"\",\"requester\":\"" +
      EscapePamJsonValue(requester) + L"\",\"action\":\"" + EscapePamJsonValue(action) + L"\",\"targetPath\":\"" +
      EscapePamJsonValue(targetPath) + L"\",\"arguments\":\"" + EscapePamJsonValue(arguments) + L"\",\"reason\":\"" +
      EscapePamJsonValue(reason) + L"\"}";

  {
    std::ofstream stream(std::filesystem::path(tempPath), std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir could not write the PAM request payload.";
      }
      return false;
    }

    const auto utf8Payload = antivirus::agent::WideToUtf8(payload);
    stream.write(utf8Payload.data(), static_cast<std::streamsize>(utf8Payload.size()));
    stream.flush();
    if (!stream.good()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Fenrir could not flush the PAM request payload.";
      }
      return false;
    }
  }

  if (MoveFileExW(tempPath.c_str(), requestPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
    DeleteFileW(tempPath.c_str());
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir could not finalize the PAM request payload.";
    }
    return false;
  }

  const auto requestEvent = CreateEventW(nullptr, FALSE, FALSE, kPamRequestEventName);
  if (requestEvent != nullptr) {
    SetEvent(requestEvent);
    CloseHandle(requestEvent);
  }

  return true;
}

bool SubmitPamRequestFromTray(HWND hwnd, UiContext& context, const std::wstring& action,
                              const std::wstring& targetPath, const std::wstring& arguments,
                              const std::wstring& reason) {
  std::wstring errorMessage;
  if (QueuePamRequest(context, action, targetPath, arguments, reason, &errorMessage)) {
    return true;
  }

  const auto message = errorMessage.empty() ? L"Fenrir could not queue this PAM request right now." : errorMessage;
  MessageBoxW(hwnd, message.c_str(), kWindowTitle, MB_OK | MB_ICONWARNING);
  return false;
}

bool SubmitPowerShellPamRequest(HWND hwnd, UiContext& context) {
  const auto targetPath = GetSystemBinaryPath(LR"(WindowsPowerShell\v1.0\powershell.exe)");
  if (targetPath.empty()) {
    MessageBoxW(hwnd, L"Fenrir could not resolve the PowerShell path for PAM elevation.",
                kWindowTitle, MB_OK | MB_ICONWARNING);
    return false;
  }

  return SubmitPamRequestFromTray(hwnd, context, L"run_powershell", targetPath, L"-NoLogo",
                                  L"User approved built-in PAM tool launch");
}

bool SubmitCommandPromptPamRequest(HWND hwnd, UiContext& context) {
  const auto targetPath = GetSystemBinaryPath(L"cmd.exe");
  if (targetPath.empty()) {
    MessageBoxW(hwnd, L"Fenrir could not resolve the Command Prompt path for PAM elevation.",
                kWindowTitle, MB_OK | MB_ICONWARNING);
    return false;
  }

  return SubmitPamRequestFromTray(hwnd, context, L"run_cmd", targetPath, L"",
                                  L"User approved built-in PAM tool launch");
}

bool SubmitDiskCleanupPamRequest(HWND hwnd, UiContext& context) {
  const auto targetPath = GetSystemBinaryPath(L"cleanmgr.exe");
  if (targetPath.empty()) {
    MessageBoxW(hwnd, L"Fenrir could not resolve Disk Cleanup for PAM elevation.",
                kWindowTitle, MB_OK | MB_ICONWARNING);
    return false;
  }

  return SubmitPamRequestFromTray(hwnd, context, L"run_disk_cleanup", targetPath, L"",
                                  L"User approved built-in PAM tool launch");
}

bool SubmitWindowsUpdatePamRequest(HWND hwnd, UiContext& context) {
  const auto targetPath = GetSystemBinaryPath(L"control.exe");
  if (targetPath.empty()) {
    MessageBoxW(hwnd, L"Fenrir could not resolve Windows Update controls for PAM elevation.",
                kWindowTitle, MB_OK | MB_ICONWARNING);
    return false;
  }

  return SubmitPamRequestFromTray(hwnd, context, L"run_windows_update", targetPath, L"",
                                  L"User requested Windows Update with PAM approval");
}

bool SubmitNetworkResetPamRequest(HWND hwnd, UiContext& context) {
  const auto targetPath = GetSystemBinaryPath(L"cmd.exe");
  if (targetPath.empty()) {
    MessageBoxW(hwnd, L"Fenrir could not resolve the network reset utility for PAM elevation.",
                kWindowTitle, MB_OK | MB_ICONWARNING);
    return false;
  }

  return SubmitPamRequestFromTray(hwnd, context, L"run_network_reset", targetPath, L"",
                                  L"User requested a network stack reset with PAM approval");
}

bool SubmitApplicationPamRequest(HWND hwnd, UiContext& context) {
  std::wstring targetPath;
  if (!PromptForPamTarget(hwnd, &targetPath)) {
    return false;
  }

  return SubmitPamRequestFromTray(hwnd, context, L"run_application", targetPath, L"",
                                  L"User approved one-time custom PAM elevation");
}

bool SubmitTimedPamRequest(HWND hwnd, UiContext& context) {
  std::wstring targetPath;
  if (!PromptForPamTarget(hwnd, &targetPath)) {
    return false;
  }

  const auto confirmation =
      MessageBoxW(hwnd,
                  (L"Fenrir will run this target with elevated rights for up to 2 minutes:\r\n\r\n" +
                   targetPath + L"\r\n\r\nContinue?")
                      .c_str(),
                  kWindowTitle, MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2);
  if (confirmation != IDOK) {
    return false;
  }

  return SubmitPamRequestFromTray(hwnd, context, L"run_application_timed", targetPath, L"",
                                  L"User approved a 2 minute process-scoped PAM elevation");
}

bool SaveExclusionsFromEditor(HWND hwnd, UiContext& context) {
  const auto length = GetWindowTextLengthW(context.detailEdit);
  std::wstring buffer(static_cast<std::size_t>(std::max(length, 0)) + 1, L'\0');
  GetWindowTextW(context.detailEdit, buffer.data(), static_cast<int>(buffer.size()));
  if (!buffer.empty() && buffer.back() == L'\0') {
    buffer.pop_back();
  }

  const auto exclusions = ParseExclusionEditorText(buffer);
  if (!antivirus::agent::SaveConfiguredScanExclusions(exclusions)) {
    MessageBoxW(hwnd, L"Unable to save exclusions to the Fenrir configuration.", kWindowTitle,
                MB_OK | MB_ICONERROR);
    return false;
  }

  if (!antivirus::agent::RestartAgentService()) {
    MessageBoxW(hwnd,
                L"Exclusions were saved, but Fenrir could not restart the protection service automatically. "
                L"Please restart the service or sign out and back in to apply the new exclusions.",
                kWindowTitle, MB_OK | MB_ICONWARNING);
    return true;
  }

  MessageBoxW(hwnd, L"Exclusions saved and protection was restarted to apply them.", kWindowTitle,
              MB_OK | MB_ICONINFORMATION);
  return true;
}

int CommitExclusions(HWND hwnd, const std::vector<std::filesystem::path>& exclusions) {
  if (exclusions.empty()) {
    return 1;
  }

  if (IsCurrentUserAdmin()) {
    if (!antivirus::agent::SaveConfiguredScanExclusions(exclusions)) {
      return 1;
    }
    return antivirus::agent::RestartAgentService() ? 0 : 2;
  }

  const auto executablePath = GetCurrentExecutablePath();
  if (executablePath.empty()) {
    return 1;
  }

  std::wstring parameters = L"--apply-exclusions";
  for (const auto& exclusion : exclusions) {
    parameters.push_back(L' ');
    parameters += QuoteCommandLineArgument(exclusion.wstring());
  }

  SHELLEXECUTEINFOW execute{};
  execute.cbSize = sizeof(execute);
  execute.fMask = SEE_MASK_NOCLOSEPROCESS;
  execute.hwnd = hwnd;
  execute.lpVerb = L"runas";
  execute.lpFile = executablePath.c_str();
  execute.lpParameters = parameters.c_str();
  execute.nShow = SW_HIDE;
  if (!ShellExecuteExW(&execute) || execute.hProcess == nullptr) {
    return 1;
  }

  const auto waitResult = WaitForSingleObject(execute.hProcess, INFINITE);
  DWORD exitCode = 1;
  if (waitResult == WAIT_OBJECT_0) {
    GetExitCodeProcess(execute.hProcess, &exitCode);
  }
  CloseHandle(execute.hProcess);
  return static_cast<int>(exitCode);
}

std::wstring ProtectionHeadline(const EndpointClientSnapshot& snapshot) {
  if (snapshot.openThreatCount != 0) {
    return L"Findings need attention";
  }

  if (snapshot.serviceState == LocalServiceState::Running &&
      _wcsicmp(snapshot.agentState.healthState.c_str(), L"healthy") == 0) {
    return L"Protected";
  }

  if (snapshot.serviceState == LocalServiceState::NotInstalled) {
    return L"Protection service is not installed";
  }

  if (snapshot.serviceState == LocalServiceState::Stopped) {
    return L"Protection service is stopped";
  }

  return L"Protection is degraded";
}

std::wstring ProtectionGuidance(const EndpointClientSnapshot& snapshot) {
  if (snapshot.serviceState == LocalServiceState::NotInstalled) {
    return L"Local scans are available, but always-on background protection will not run until the endpoint service is installed.";
  }

  if (snapshot.serviceState == LocalServiceState::Stopped) {
    return L"Start the protection service to restore continuous monitoring, telemetry upload, and command handling.";
  }

  if (snapshot.openThreatCount != 0) {
    return L"Recent malicious activity was detected locally. Review the Findings and Quarantine tabs, then decide whether anything should be restored or removed.";
  }

  if (_wcsicmp(snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
    return L"The endpoint is still reporting a degraded runtime state. Review the service state and recent local findings to confirm what needs attention.";
  }

  return L"Background protection is running and no unresolved local findings are currently recorded.";
}

bool IsScanSessionRecord(const antivirus::agent::ScanHistoryRecord& record);

std::wstring BuildSummaryCardText(const EndpointClientSnapshot& snapshot) {
  std::wstringstream stream;
  stream << L"Protection status\r\n"
         << ProtectionHeadline(snapshot) << L"\r\n\r\n"
         << (snapshot.openThreatCount == 0
                 ? (snapshot.activeQuarantineCount == 0 ? L"No unresolved findings are recorded."
                                                       : std::to_wstring(snapshot.activeQuarantineCount) + L" quarantined item(s) are contained.")
                 : std::to_wstring(snapshot.openThreatCount) + L" unresolved finding(s) need review.")
         << L"\r\nNext action: ";
  if (snapshot.serviceState == LocalServiceState::NotInstalled) {
    stream << L"Install the protection service";
  } else if (snapshot.serviceState == LocalServiceState::Stopped) {
    stream << L"Start the protection service";
  } else if (snapshot.openThreatCount != 0) {
    stream << L"Review findings and quarantine";
  } else if (_wcsicmp(snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
    stream << L"Review runtime health";
  } else {
    stream << L"Keep protection running";
  }
  return stream.str();
}

std::wstring BuildDetailsCardText(const EndpointClientSnapshot& snapshot) {
  std::wstring lastScan = L"(never)";
  for (const auto& record : snapshot.recentFindings) {
    if (IsScanSessionRecord(record)) {
      lastScan = NullableText(record.recordedAt, L"(never)");
      break;
    }
  }

  std::wstringstream stream;
  stream << L"Recent activity\r\n";
  if (snapshot.recentFindings.empty()) {
    stream << L"No recent events are recorded on this device.";
    return stream.str();
  }

  const auto maxItems = std::min<std::size_t>(snapshot.recentFindings.size(), 3);
  for (std::size_t index = 0; index < maxItems; ++index) {
    const auto& record = snapshot.recentFindings[index];
    const auto displayPath = record.subjectPath.empty() ? std::wstring(L"(memory or script content)")
                                                        : record.subjectPath.wstring();
    stream << L"\r\n";
    stream << record.recordedAt << L" • "
           << (record.disposition.empty() ? std::wstring(L"(unknown)") : record.disposition)
           << L" • " << displayPath;
    if (!record.source.empty()) {
      stream << L"\r\n" << record.source;
    }
  }

  const auto availableSoftwareUpdateCount = std::count_if(
      snapshot.softwarePatches.begin(), snapshot.softwarePatches.end(), [](const auto& patch) {
        return _wcsicmp(patch.updateState.c_str(), L"available") == 0 ||
               _wcsicmp(patch.updateState.c_str(), L"provider_ready") == 0;
      });
  stream << L"\r\n\r\nPatch posture\r\n"
         << snapshot.windowsUpdates.size() << L" Windows update(s), "
         << availableSoftwareUpdateCount << L" software update(s) available.";

  return stream.str();
}

std::wstring BuildMetricCardText(const std::wstring& label, const std::wstring& value, const std::wstring& detail = L"") {
  std::wstringstream stream;
  stream << label << L"\r\n" << value;
  if (!detail.empty()) {
    stream << L"\r\n" << detail;
  }
  return stream.str();
}

std::wstring ExtractSimpleJsonStringValue(const std::wstring& json, const std::wstring& key) {
  const auto marker = L"\"" + key + L"\":\"";
  const auto start = json.find(marker);
  if (start == std::wstring::npos) {
    return {};
  }

  std::wstring value;
  bool escaping = false;
  for (std::size_t index = start + marker.size(); index < json.size(); ++index) {
    const auto ch = json[index];
    if (escaping) {
      switch (ch) {
        case L'"':
        case L'\\':
        case L'/':
          value.push_back(ch);
          break;
        case L'n':
          value.push_back(L'\n');
          break;
        case L'r':
          value.push_back(L'\r');
          break;
        case L't':
          value.push_back(L'\t');
          break;
        default:
          value.push_back(ch);
          break;
      }
      escaping = false;
      continue;
    }
    if (ch == L'\\') {
      escaping = true;
      continue;
    }
    if (ch == L'"') {
      break;
    }
    value.push_back(ch);
  }
  return value;
}

std::wstring BuildPatchExecutionSummary(const antivirus::agent::PatchExecutionResult& result, const bool searchOnly) {
  std::wstringstream stream;
  stream << (searchOnly ? L"Software update check finished." : L"Software update action finished.")
         << L"\r\n\r\n"
         << L"Target: " << NullableText(result.targetId, L"(unknown)") << L"\r\n"
         << L"Provider: " << NullableText(result.provider, L"(unknown)") << L"\r\n"
         << L"Status: " << NullableText(result.status, L"(unknown)");

  if (!result.errorCode.empty()) {
    stream << L"\r\nError: " << result.errorCode;
  }
  const auto providerSummary = ExtractSimpleJsonStringValue(result.detailJson, L"summary");
  if (!providerSummary.empty()) {
    stream << L"\r\nDetail: " << providerSummary;
  } else {
    const auto errorDetail = ExtractSimpleJsonStringValue(result.detailJson, L"error");
    const auto messageDetail = ExtractSimpleJsonStringValue(result.detailJson, L"message");
    if (!errorDetail.empty()) {
      stream << L"\r\nDetail: " << errorDetail;
    } else if (!messageDetail.empty()) {
      stream << L"\r\nDetail: " << messageDetail;
    }
  }

  if (result.rebootRequired) {
    stream << L"\r\nReboot required: yes";
  }

  return stream.str();
}

bool IsPatchResultInformational(const antivirus::agent::PatchExecutionResult& result) {
  return result.success || _wcsicmp(result.status.c_str(), L"current") == 0 ||
         _wcsicmp(result.status.c_str(), L"available") == 0 ||
         _wcsicmp(result.status.c_str(), L"provider_ready") == 0 ||
         _wcsicmp(result.status.c_str(), L"manual") == 0 ||
         _wcsicmp(result.status.c_str(), L"unsupported") == 0;
}

std::wstring BuildSubtitleText() {
  return L"Minimal protection for this device with clear status, review, and response actions.";
}

bool IsScanSessionRecord(const antivirus::agent::ScanHistoryRecord& record) {
  return _wcsicmp(record.contentType.c_str(), L"scan-session") == 0;
}

bool DashboardDetailVisible(const UiContext& context) {
  return context.currentPage == ClientPage::Dashboard && HasSelectedItem(context.historyList);
}

std::wstring OverallStatusChip(const EndpointClientSnapshot& snapshot) {
  if (snapshot.serviceState == LocalServiceState::NotInstalled || snapshot.serviceState == LocalServiceState::Stopped) {
    return L"Protection off";
  }
  if (snapshot.openThreatCount != 0 || _wcsicmp(snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
    return L"Attention needed";
  }
  return L"Protected";
}

std::wstring BuildBrandCardText(const EndpointClientSnapshot& snapshot) {
  std::wstringstream stream;
  stream << NullableText(snapshot.agentState.hostname, L"Local device") << L"\r\n"
         << OverallStatusChip(snapshot) << L"\r\n"
         << L"Policy " << NullableText(snapshot.agentState.policy.revision, L"n/a");
  return stream.str();
}

std::wstring PageTitle(const ClientPage page) {
  switch (page) {
    case ClientPage::Threats:
      return L"Findings";
    case ClientPage::Quarantine:
      return L"Quarantine";
    case ClientPage::Scans:
      return L"Scans";
    case ClientPage::Updates:
      return L"Updates";
    case ClientPage::Service:
      return L"Service";
    case ClientPage::History:
      return L"History";
    case ClientPage::Settings:
      return L"Settings";
    case ClientPage::Dashboard:
    default:
      return L"Protection Centre";
  }
}

std::wstring PageKey(const ClientPage page) {
  switch (page) {
    case ClientPage::Threats:
      return L"threats";
    case ClientPage::Quarantine:
      return L"quarantine";
    case ClientPage::Scans:
      return L"scans";
    case ClientPage::Updates:
      return L"updates";
    case ClientPage::Service:
      return L"service";
    case ClientPage::History:
      return L"history";
    case ClientPage::Settings:
      return L"settings";
    case ClientPage::Dashboard:
    default:
      return L"dashboard";
  }
}

std::wstring PageSubtitle(const ClientPage page, const EndpointClientSnapshot& snapshot) {
  switch (page) {
    case ClientPage::Threats:
      return L"Investigate active detections, review evidence, and decide what needs action.";
    case ClientPage::Quarantine:
      return L"Review contained items, confirm whether anything should be restored, and keep the device clean.";
    case ClientPage::Scans:
      return L"Launch quick, full, or targeted scans and follow the latest scan activity from this device.";
    case ClientPage::Updates:
      return L"Inspect software and Windows update posture, then run guided check or install actions per application.";
    case ClientPage::Service:
      return L"Runtime health, upload queue, service posture, and local protection readiness.";
    case ClientPage::History:
      return L"Historical detections, scan sessions, and local agent actions for this endpoint.";
    case ClientPage::Settings:
      return L"Local configuration, trusted exclusions, runtime paths, and endpoint client preferences for this device.";
    case ClientPage::Dashboard:
    default:
      if (snapshot.serviceState == LocalServiceState::NotInstalled) {
        return L"Background protection is off because the endpoint service is not installed. Local scans are still available.";
      }
      return L"See protection status, recent activity, and the next best action for this endpoint.";
  }
}

std::wstring PrimarySectionTitle(const ClientPage page) {
  switch (page) {
    case ClientPage::Threats:
      return L"Finding queue";
    case ClientPage::Quarantine:
      return L"Quarantine inventory";
    case ClientPage::Scans:
      return L"Recent scans";
    case ClientPage::Updates:
      return L"Patch inventory";
    case ClientPage::History:
      return L"Activity timeline";
    case ClientPage::Service:
      return L"Protection overview";
    case ClientPage::Settings:
      return L"Local preferences";
    case ClientPage::Dashboard:
    default:
      return L"Recent activity";
  }
}

std::wstring SecondarySectionTitle(const ClientPage page) {
  switch (page) {
    case ClientPage::Quarantine:
      return L"Item detail";
    case ClientPage::Threats:
      return L"Finding detail";
    case ClientPage::Updates:
      return L"Update detail";
    case ClientPage::Service:
      return L"Runtime detail";
    case ClientPage::Settings:
      return L"Configuration detail";
    case ClientPage::Dashboard:
      return L"Selected event";
    case ClientPage::Scans:
    case ClientPage::History:
    default:
      return L"Detail";
  }
}

int NavButtonIdForPage(const ClientPage page) {
  switch (page) {
    case ClientPage::Dashboard:
      return IDC_NAV_DASHBOARD;
    case ClientPage::Threats:
      return IDC_NAV_THREATS;
    case ClientPage::Quarantine:
      return IDC_NAV_QUARANTINE;
    case ClientPage::Scans:
      return IDC_NAV_SCANS;
    case ClientPage::Updates:
      return IDC_NAV_SCANS;
    case ClientPage::Service:
      return IDC_NAV_SERVICE;
    case ClientPage::History:
      return IDC_NAV_HISTORY;
    case ClientPage::Settings:
    default:
      return IDC_NAV_SETTINGS;
  }
}

std::optional<ClientPage> PageForNavButtonId(const int controlId) {
  switch (controlId) {
    case IDC_NAV_DASHBOARD:
      return ClientPage::Dashboard;
    case IDC_NAV_THREATS:
      return ClientPage::Threats;
    case IDC_NAV_QUARANTINE:
      return ClientPage::Quarantine;
    case IDC_NAV_SCANS:
      return ClientPage::Scans;
    case IDC_NAV_SERVICE:
      return ClientPage::Service;
    case IDC_NAV_HISTORY:
      return ClientPage::History;
    case IDC_NAV_SETTINGS:
      return ClientPage::Settings;
    default:
      return std::nullopt;
  }
}

bool IsNavigationButton(const int controlId) {
  return PageForNavButtonId(controlId).has_value();
}

std::wstring FriendlyScanLabel(const ScanPreset preset) {
  switch (preset) {
    case ScanPreset::Quick:
      return L"Quick scan";
    case ScanPreset::Full:
      return L"Full scan";
    case ScanPreset::Folder:
    default:
      return L"Folder scan";
  }
}

std::wstring LowercaseCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring CompactPathForStatus(const std::filesystem::path& path) {
  if (path.empty()) {
    return {};
  }

  const auto fullPath = path.wstring();
  constexpr std::size_t kMaxStatusPathLength = 96;
  if (fullPath.size() <= kMaxStatusPathLength) {
    return fullPath;
  }

  const auto fileName = path.filename().wstring();
  if (fileName.empty()) {
    return fullPath.substr(0, kMaxStatusPathLength - 3) + L"...";
  }

  auto root = path.root_name().wstring();
  if (root.empty()) {
    root = path.root_path().wstring();
  }
  if (root.empty()) {
    root = L"...";
  }

  return root + L"\\...\\" + fileName;
}

void SetWindowTextSafe(HWND control, const std::wstring& text) {
  if (control != nullptr) {
    SetWindowTextW(control, text.c_str());
  }
}

COLORREF DarkTextColor() { return RGB(235, 241, 252); }
COLORREF MutedTextColor() { return RGB(145, 159, 185); }
COLORREF AccentBlue() { return RGB(49, 123, 242); }
COLORREF AccentBlueDark() { return RGB(153, 206, 255); }
COLORREF AccentGreen() { return RGB(31, 182, 123); }
COLORREF AccentGreenDark() { return RGB(173, 247, 213); }
COLORREF AccentAmber() { return RGB(224, 151, 39); }
COLORREF AccentAmberDark() { return RGB(255, 218, 158); }
COLORREF AccentRed() { return RGB(214, 72, 112); }
COLORREF AccentRedDark() { return RGB(255, 193, 206); }
COLORREF WindowBackgroundColor() { return RGB(8, 12, 18); }
COLORREF SurfaceColor() { return RGB(14, 18, 26); }
COLORREF SummarySafeColor() { return RGB(16, 20, 28); }
COLORREF SummaryWarningColor() { return RGB(16, 20, 28); }
COLORREF SummaryDangerColor() { return RGB(18, 22, 30); }
COLORREF DetailsCardColor() { return RGB(14, 18, 25); }
COLORREF MetricInfoColor() { return RGB(15, 19, 27); }
COLORREF MetricSuccessColor() { return RGB(15, 19, 27); }
COLORREF MetricWarningColor() { return RGB(15, 19, 27); }
COLORREF MetricDangerColor() { return RGB(15, 19, 27); }
COLORREF DetailColor() { return RGB(12, 16, 23); }
COLORREF ListBackColor() { return RGB(12, 16, 23); }
COLORREF ListAltBackColor() { return RGB(10, 14, 20); }
COLORREF BrandBaseColor() { return RGB(12, 16, 23); }
COLORREF BrandFrameColor() { return RGB(101, 132, 170); }
COLORREF BrandShieldColor() { return RGB(236, 241, 248); }
COLORREF BrandNeutralColor() { return RGB(150, 175, 205); }

COLORREF AdjustColor(const COLORREF color, const int delta) {
  const auto clampChannel = [delta](const BYTE channel) {
    return static_cast<BYTE>(std::clamp(static_cast<int>(channel) + delta, 0, 255));
  };

  return RGB(clampChannel(GetRValue(color)), clampChannel(GetGValue(color)), clampChannel(GetBValue(color)));
}

enum class BrandIconTone {
  Neutral,
  Safe,
  Warning,
  Danger
};

COLORREF ResolveBrandToneColor(BrandIconTone tone) {
  switch (tone) {
    case BrandIconTone::Safe:
      return AccentGreen();
    case BrandIconTone::Warning:
      return AccentAmber();
    case BrandIconTone::Danger:
      return AccentRed();
    case BrandIconTone::Neutral:
    default:
      return BrandNeutralColor();
  }
}

BrandIconTone ResolveBrandIconTone(const EndpointClientSnapshot& snapshot) {
  if (snapshot.openThreatCount != 0) {
    return BrandIconTone::Danger;
  }

  if (snapshot.serviceState == LocalServiceState::Running &&
      _wcsicmp(snapshot.agentState.healthState.c_str(), L"healthy") == 0) {
    return BrandIconTone::Safe;
  }

  if (snapshot.serviceState == LocalServiceState::NotInstalled ||
      snapshot.serviceState == LocalServiceState::Stopped) {
    return BrandIconTone::Danger;
  }

  return BrandIconTone::Warning;
}

HICON CreateBrandIcon(int size, BrandIconTone tone) {
  HDC screen = GetDC(nullptr);
  HDC canvas = CreateCompatibleDC(screen);

  BITMAPV5HEADER header{};
  header.bV5Size = sizeof(header);
  header.bV5Width = size;
  header.bV5Height = -size;
  header.bV5Planes = 1;
  header.bV5BitCount = 32;
  header.bV5Compression = BI_BITFIELDS;
  header.bV5RedMask = 0x00FF0000;
  header.bV5GreenMask = 0x0000FF00;
  header.bV5BlueMask = 0x000000FF;
  header.bV5AlphaMask = 0xFF000000;

  void* pixels = nullptr;
  HBITMAP colorBitmap = CreateDIBSection(canvas, reinterpret_cast<BITMAPINFO*>(&header), DIB_RGB_COLORS, &pixels, nullptr, 0);
  std::vector<std::uint8_t> maskBits(static_cast<std::size_t>(((size + 15) / 16) * 2 * size), 0);
  HBITMAP maskBitmap = CreateBitmap(size, size, 1, 1, maskBits.data());
  HGDIOBJ previousBitmap = SelectObject(canvas, colorBitmap);

  const RECT bounds{0, 0, size, size};
  HBRUSH baseBrush = CreateSolidBrush(BrandBaseColor());
  FillRect(canvas, &bounds, baseBrush);
  DeleteObject(baseBrush);

  HPEN framePen = CreatePen(PS_SOLID, std::max(1, size / 18), BrandFrameColor());
  HGDIOBJ previousPen = SelectObject(canvas, framePen);
  HBRUSH bodyBrush = CreateSolidBrush(BrandBaseColor());
  HGDIOBJ previousBrush = SelectObject(canvas, bodyBrush);
  const int inset = std::max(2, size / 10);
  const int radius = std::max(4, size / 4);
  RoundRect(canvas, inset, inset, size - inset, size - inset, radius, radius);
  SelectObject(canvas, previousBrush);
  DeleteObject(bodyBrush);
  SelectObject(canvas, previousPen);
  DeleteObject(framePen);

  HBRUSH shieldBrush = CreateSolidBrush(BrandShieldColor());
  previousBrush = SelectObject(canvas, shieldBrush);
  HPEN shieldPen = CreatePen(PS_SOLID, 1, BrandShieldColor());
  previousPen = SelectObject(canvas, shieldPen);
  POINT shield[6]{
    {size / 2, static_cast<LONG>(size * 0.21f)},
    {static_cast<LONG>(size * 0.70f), static_cast<LONG>(size * 0.31f)},
    {static_cast<LONG>(size * 0.70f), static_cast<LONG>(size * 0.47f)},
    {static_cast<LONG>(size * 0.66f), static_cast<LONG>(size * 0.63f)},
    {size / 2, static_cast<LONG>(size * 0.80f)},
    {static_cast<LONG>(size * 0.34f), static_cast<LONG>(size * 0.63f)}
  };
  Polygon(canvas, shield, 6);
  SelectObject(canvas, previousBrush);
  DeleteObject(shieldBrush);
  SelectObject(canvas, previousPen);
  DeleteObject(shieldPen);

  HPEN signalPen = CreatePen(PS_SOLID, std::max(2, size / 10), ResolveBrandToneColor(tone));
  previousPen = SelectObject(canvas, signalPen);
  MoveToEx(canvas, static_cast<int>(size * 0.37f), static_cast<int>(size * 0.52f), nullptr);
  LineTo(canvas, static_cast<int>(size * 0.45f), static_cast<int>(size * 0.52f));
  LineTo(canvas, static_cast<int>(size * 0.49f), static_cast<int>(size * 0.43f));
  LineTo(canvas, static_cast<int>(size * 0.54f), static_cast<int>(size * 0.60f));
  LineTo(canvas, static_cast<int>(size * 0.59f), static_cast<int>(size * 0.48f));
  LineTo(canvas, static_cast<int>(size * 0.66f), static_cast<int>(size * 0.48f));
  SelectObject(canvas, previousPen);
  DeleteObject(signalPen);

  HBRUSH signalBrush = CreateSolidBrush(ResolveBrandToneColor(tone));
  previousBrush = SelectObject(canvas, signalBrush);
  previousPen = SelectObject(canvas, GetStockObject(NULL_PEN));
  const int dotRadius = std::max(2, size / 12);
  const int dotX = static_cast<int>(size * 0.64f);
  const int dotY = static_cast<int>(size * 0.35f);
  Ellipse(canvas, dotX - dotRadius, dotY - dotRadius, dotX + dotRadius, dotY + dotRadius);
  SelectObject(canvas, previousBrush);
  DeleteObject(signalBrush);
  SelectObject(canvas, previousPen);

  ICONINFO iconInfo{};
  iconInfo.fIcon = TRUE;
  iconInfo.hbmMask = maskBitmap;
  iconInfo.hbmColor = colorBitmap;
  HICON icon = CreateIconIndirect(&iconInfo);

  SelectObject(canvas, previousBitmap);
  DeleteObject(maskBitmap);
  DeleteObject(colorBitmap);
  DeleteDC(canvas);
  ReleaseDC(nullptr, screen);
  return icon;
}

HICON LoadFenrirIcon(const int size) {
  return static_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(100), IMAGE_ICON, size, size,
                                       LR_DEFAULTCOLOR));
}

void CreateBrandIcons(UiContext& context) {
  context.iconNeutralSmall = LoadFenrirIcon(16);
  context.iconNeutralLarge = LoadFenrirIcon(32);
  context.iconSafeSmall = LoadFenrirIcon(16);
  context.iconSafeLarge = LoadFenrirIcon(32);
  context.iconWarningSmall = LoadFenrirIcon(16);
  context.iconWarningLarge = LoadFenrirIcon(32);
  context.iconDangerSmall = LoadFenrirIcon(16);
  context.iconDangerLarge = LoadFenrirIcon(32);
}

void DestroyBrandIcons(UiContext& context) {
  if (context.iconNeutralSmall != nullptr) {
    DestroyIcon(context.iconNeutralSmall);
  }
  if (context.iconNeutralLarge != nullptr) {
    DestroyIcon(context.iconNeutralLarge);
  }
  if (context.iconSafeSmall != nullptr) {
    DestroyIcon(context.iconSafeSmall);
  }
  if (context.iconSafeLarge != nullptr) {
    DestroyIcon(context.iconSafeLarge);
  }
  if (context.iconWarningSmall != nullptr) {
    DestroyIcon(context.iconWarningSmall);
  }
  if (context.iconWarningLarge != nullptr) {
    DestroyIcon(context.iconWarningLarge);
  }
  if (context.iconDangerSmall != nullptr) {
    DestroyIcon(context.iconDangerSmall);
  }
  if (context.iconDangerLarge != nullptr) {
    DestroyIcon(context.iconDangerLarge);
  }
}

HICON SelectTrayIcon(UiContext& context) {
  switch (ResolveBrandIconTone(context.snapshot)) {
    case BrandIconTone::Safe:
      return context.iconSafeSmall != nullptr ? context.iconSafeSmall : context.iconNeutralSmall;
    case BrandIconTone::Danger:
      return context.iconDangerSmall != nullptr ? context.iconDangerSmall : context.iconNeutralSmall;
    case BrandIconTone::Warning:
      return context.iconWarningSmall != nullptr ? context.iconWarningSmall : context.iconNeutralSmall;
    case BrandIconTone::Neutral:
    default:
      return context.iconNeutralSmall;
  }
}

HICON SelectWindowIcon(UiContext& context, bool large) {
  switch (ResolveBrandIconTone(context.snapshot)) {
    case BrandIconTone::Safe:
      return large ? context.iconSafeLarge : context.iconSafeSmall;
    case BrandIconTone::Danger:
      return large ? context.iconDangerLarge : context.iconDangerSmall;
    case BrandIconTone::Warning:
      return large ? context.iconWarningLarge : context.iconWarningSmall;
    case BrandIconTone::Neutral:
    default:
      return large ? context.iconNeutralLarge : context.iconNeutralSmall;
  }
}

void CreateThemeResources(UiContext& context) {
  context.windowBrush = CreateSolidBrush(WindowBackgroundColor());
  context.surfaceBrush = CreateSolidBrush(SurfaceColor());
  context.summarySafeBrush = CreateSolidBrush(SummarySafeColor());
  context.summaryWarningBrush = CreateSolidBrush(SummaryWarningColor());
  context.summaryDangerBrush = CreateSolidBrush(SummaryDangerColor());
  context.detailsBrush = CreateSolidBrush(DetailsCardColor());
  context.metricInfoBrush = CreateSolidBrush(MetricInfoColor());
  context.metricSuccessBrush = CreateSolidBrush(MetricSuccessColor());
  context.metricWarningBrush = CreateSolidBrush(MetricWarningColor());
  context.metricDangerBrush = CreateSolidBrush(MetricDangerColor());
  context.detailBrush = CreateSolidBrush(DetailColor());
  context.listBrush = CreateSolidBrush(ListBackColor());
}

void DestroyBrush(HBRUSH& brush) {
  if (brush != nullptr) {
    DeleteObject(brush);
    brush = nullptr;
  }
}

void DestroyThemeResources(UiContext& context) {
  DestroyBrush(context.windowBrush);
  DestroyBrush(context.surfaceBrush);
  DestroyBrush(context.summarySafeBrush);
  DestroyBrush(context.summaryWarningBrush);
  DestroyBrush(context.summaryDangerBrush);
  DestroyBrush(context.detailsBrush);
  DestroyBrush(context.metricInfoBrush);
  DestroyBrush(context.metricSuccessBrush);
  DestroyBrush(context.metricWarningBrush);
  DestroyBrush(context.metricDangerBrush);
  DestroyBrush(context.detailBrush);
  DestroyBrush(context.listBrush);
}

void ConfigureListViewColumns(HWND listView, const std::vector<std::pair<std::wstring, int>>& columns) {
  while (Header_GetItemCount(ListView_GetHeader(listView)) > 0) {
    ListView_DeleteColumn(listView, 0);
  }

  for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(columns[static_cast<std::size_t>(index)].first.c_str());
    column.cx = columns[static_cast<std::size_t>(index)].second;
    column.iSubItem = index;
    ListView_InsertColumn(listView, index, &column);
  }
}

void InsertListViewRow(HWND listView, const int rowIndex, const std::vector<std::wstring>& values) {
  for (int subItem = 0; subItem < static_cast<int>(values.size()); ++subItem) {
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = rowIndex;
    item.iSubItem = subItem;
    item.pszText = const_cast<LPWSTR>(values[static_cast<std::size_t>(subItem)].c_str());
    if (subItem == 0) {
      ListView_InsertItem(listView, &item);
    } else {
      ListView_SetItem(listView, &item);
    }
  }
}

std::wstring ThreatDisplayPath(const antivirus::agent::ScanHistoryRecord& record) {
  if (_wcsicmp(record.contentType.c_str(), L"scan-session") == 0) {
    return record.subjectPath.empty() ? std::wstring(L"[Scan session]") : record.subjectPath.wstring();
  }

  return record.subjectPath.empty() ? std::wstring(L"(memory or script content)") : record.subjectPath.wstring();
}

std::wstring HistorySourceLabel(const std::wstring& source) {
  if (_wcsicmp(source.c_str(), L"endpoint-ui.quick-scan") == 0) {
    return L"Quick scan";
  }
  if (_wcsicmp(source.c_str(), L"endpoint-ui.full-scan") == 0) {
    return L"Full scan";
  }
  if (_wcsicmp(source.c_str(), L"endpoint-ui.custom-scan") == 0) {
    return L"Folder scan";
  }
  return source.empty() ? std::wstring(L"(unknown)") : source;
}

std::wstring HistoryContextLabel(const antivirus::agent::ScanHistoryRecord& record) {
  if (!record.contextType.empty()) {
    return record.contextType;
  }
  if (_wcsicmp(record.contentType.c_str(), L"destination") == 0) {
    return L"web";
  }
  return L"local";
}

std::wstring HistoryDispositionLabel(const antivirus::agent::ScanHistoryRecord& record) {
  if (_wcsicmp(record.contentType.c_str(), L"scan-session") != 0) {
    return record.disposition.empty() ? std::wstring(L"(unknown)") : record.disposition;
  }

  if (_wcsicmp(record.disposition.c_str(), L"completed-clean") == 0) {
    return L"clean";
  }
  if (_wcsicmp(record.disposition.c_str(), L"completed-with-findings") == 0) {
    return L"findings";
  }
  return record.disposition.empty() ? std::wstring(L"completed") : record.disposition;
}

std::wstring BuildThreatDetailText(const antivirus::agent::ScanHistoryRecord& record) {
  std::wstringstream stream;
  stream << L"Finding detail\r\n\r\n"
         << L"Detected: " << NullableText(record.recordedAt) << L"\r\n"
         << L"Alert: " << NullableText(record.alertTitle, L"(none)") << L"\r\n"
         << L"Item: " << ThreatDisplayPath(record) << L"\r\n"
         << L"Disposition: " << NullableText(record.disposition) << L"\r\n"
         << L"Confidence: " << record.confidence << L"\r\n"
         << L"Context: " << NullableText(HistoryContextLabel(record), L"(unknown)") << L"\r\n"
         << L"Source app: " << NullableText(record.sourceApplication, L"(unknown)") << L"\r\n"
         << L"Origin: " << NullableText(record.originReference, L"(unknown)") << L"\r\n"
         << L"Tactic / Technique: " << NullableText(record.tacticId, L"(n/a)") << L" / "
         << NullableText(record.techniqueId, L"(n/a)") << L"\r\n"
         << L"Remediation: " << NullableText(record.remediationStatus, L"(none)") << L"\r\n"
         << L"SHA-256: " << NullableText(record.sha256, L"(unavailable)") << L"\r\n"
         << L"Evidence ID: " << NullableText(record.evidenceRecordId, L"(none)") << L"\r\n"
         << L"Quarantine ID: " << NullableText(record.quarantineRecordId, L"(none)");
  return stream.str();
}

std::wstring BuildQuarantineDetailText(const antivirus::agent::QuarantineIndexRecord& record) {
  std::wstringstream stream;
  stream << L"Quarantine detail\r\n\r\n"
         << L"Captured: " << NullableText(record.capturedAt) << L"\r\n"
         << L"Original path: " << record.originalPath.wstring() << L"\r\n"
         << L"Quarantined path: " << NullableText(record.quarantinedPath.wstring(), L"(removed from quarantine)") << L"\r\n"
         << L"Status: " << NullableText(record.localStatus) << L"\r\n"
         << L"Technique: " << NullableText(record.techniqueId, L"(n/a)") << L"\r\n"
         << L"Size: " << record.sizeBytes << L" bytes\r\n"
         << L"SHA-256: " << NullableText(record.sha256, L"(unavailable)") << L"\r\n"
         << L"Record ID: " << NullableText(record.recordId);
  return stream.str();
}

std::wstring BuildHistoryDetailText(const antivirus::agent::ScanHistoryRecord& record) {
  if (_wcsicmp(record.contentType.c_str(), L"scan-session") == 0) {
    std::wstringstream stream;
    stream << L"Scan activity\r\n\r\n"
           << L"Recorded: " << NullableText(record.recordedAt) << L"\r\n"
           << L"Scan type: " << HistorySourceLabel(record.source) << L"\r\n"
           << L"Scope: " << ThreatDisplayPath(record) << L"\r\n"
           << L"Result: " << HistoryDispositionLabel(record) << L"\r\n"
           << L"Summary: " << NullableText(record.reputation, L"(no summary available)") << L"\r\n"
           << L"Remediation: " << NullableText(record.remediationStatus, L"(none)");
    return stream.str();
  }

  std::wstringstream stream;
  stream << L"Detection history\r\n\r\n"
         << L"Recorded: " << NullableText(record.recordedAt) << L"\r\n"
         << L"Alert: " << NullableText(record.alertTitle, L"(none)") << L"\r\n"
         << L"Source: " << HistorySourceLabel(record.source) << L"\r\n"
         << L"Context: " << NullableText(HistoryContextLabel(record), L"(unknown)") << L"\r\n"
         << L"Source app: " << NullableText(record.sourceApplication, L"(unknown)") << L"\r\n"
         << L"Origin: " << NullableText(record.originReference, L"(unknown)") << L"\r\n"
         << L"Item: " << ThreatDisplayPath(record) << L"\r\n"
         << L"Disposition: " << HistoryDispositionLabel(record) << L"\r\n"
         << L"Reputation: " << NullableText(record.reputation, L"(unknown)") << L"\r\n"
         << L"Content type: " << NullableText(record.contentType, L"(unknown)") << L"\r\n"
         << L"Tactic / Technique: " << NullableText(record.tacticId, L"(n/a)") << L" / "
         << NullableText(record.techniqueId, L"(n/a)") << L"\r\n"
         << L"Remediation: " << NullableText(record.remediationStatus, L"(none)");
  return stream.str();
}

std::wstring BuildServiceOverviewText(const UiContext& context) {
  const auto processes = antivirus::agent::CollectProcessInventory(6);
  const auto services = antivirus::agent::CollectServiceInventory(6);
  const auto prioritizedProcessCount = std::count_if(processes.begin(), processes.end(), [](const auto& process) {
    return process.prioritized;
  });
  const auto riskyServiceCount = std::count_if(services.begin(), services.end(), [](const auto& service) {
    return service.risky;
  });
  const auto availableSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(), [](const auto& patch) {
        return _wcsicmp(patch.updateState.c_str(), L"available") == 0 ||
               _wcsicmp(patch.updateState.c_str(), L"provider_ready") == 0;
      });
  const auto manualSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(), [](const auto& patch) {
        return patch.manualOnly || _wcsicmp(patch.updateState.c_str(), L"manual") == 0;
      });

  std::wstringstream stream;
  stream << L"Runtime posture\r\n\r\n"
         << L"Device ID: " << NullableText(context.snapshot.agentState.deviceId, L"(not enrolled)") << L"\r\n"
         << L"Service state: " << antivirus::agent::LocalServiceStateToString(context.snapshot.serviceState) << L"\r\n"
         << L"Health state: " << NullableText(context.snapshot.agentState.healthState, L"(unknown)") << L"\r\n"
         << L"Policy: " << NullableText(context.snapshot.agentState.policy.policyName) << L" ("
         << NullableText(context.snapshot.agentState.policy.revision, L"n/a") << L")\r\n"
         << L"Last heartbeat: " << NullableText(context.snapshot.agentState.lastHeartbeatAt, L"(never)") << L"\r\n"
         << L"Last policy sync: " << NullableText(context.snapshot.agentState.lastPolicySyncAt, L"(never)") << L"\r\n"
         << L"Queued telemetry: " << context.snapshot.queuedTelemetryCount << L"\r\n"
      << L"PAM health: " << NullableText(context.snapshot.pamHealthState, L"(unknown)") << L"\r\n"
      << L"PAM queue: " << context.snapshot.pendingPamRequestCount << L" pending request(s)\r\n"
      << L"PAM history: " << context.snapshot.pamApprovedCount << L" approved / "
      << context.snapshot.pamDeniedCount << L" denied\r\n"
      << L"Local admin members: "
      << (context.snapshot.localAdminExposureKnown ? std::to_wstring(context.snapshot.localAdminMemberCount)
                     : std::wstring(L"(unavailable)"))
      << L"\r\n"
       << L"Admin exposure: "
       << (context.snapshot.localAdminExposureKnown
         ? (context.snapshot.localAdminExposure ? L"elevated risk" : L"reduced")
         : L"(unavailable)")
       << L"\r\n"
      << L"Windows update debt: " << context.snapshot.windowsUpdates.size() << L" pending update(s)\r\n"
      << L"Software updates: " << availableSoftwareUpdateCount << L" available / "
      << manualSoftwareUpdateCount << L" manual\r\n"
          << L"Processes observed: " << processes.size() << L" (" << prioritizedProcessCount << L" prioritized)\r\n"
          << L"Services observed: " << services.size() << L" (" << riskyServiceCount << L" flagged)\r\n"
         << L"Agent version: " << NullableText(context.config.agentVersion) << L"\r\n"
         << L"Platform version: " << NullableText(context.config.platformVersion) << L"\r\n"
         << L"Command channel: " << NullableText(context.snapshot.agentState.commandChannelUrl, L"(not assigned)");

        if (!processes.empty()) {
          const auto& process = processes.front();
          stream << L"\r\n\r\nHighlighted process\r\n"
            << L"Name: " << NullableText(process.imageName, L"(unknown)") << L"\r\n"
            << L"Path: " << NullableText(process.imagePath, L"(unknown)") << L"\r\n"
            << L"PID: " << process.pid;
        }

        if (!services.empty()) {
          const auto& service = services.front();
          stream << L"\r\n\r\nHighlighted service\r\n"
            << L"Name: " << NullableText(service.displayName, L"(unknown)") << L"\r\n"
            << L"Service: " << NullableText(service.serviceName, L"(unknown)") << L"\r\n"
            << L"Binary: " << NullableText(service.binaryPath, L"(unknown)") << L"\r\n"
            << L"State: " << NullableText(service.currentState, L"(unknown)") << L"\r\n"
            << L"Account: " << NullableText(service.accountName, L"(unknown)");
        }

  if (!context.snapshot.updateJournal.empty()) {
    const auto& latest = context.snapshot.updateJournal.front();
    stream << L"\r\n\r\nLatest update\r\n"
           << L"Package: " << NullableText(latest.packageId, L"(unknown)") << L"\r\n"
           << L"Target version: " << NullableText(latest.targetVersion, L"(unknown)") << L"\r\n"
           << L"Status: " << NullableText(latest.status, L"(unknown)") << L"\r\n"
           << L"Started: " << NullableText(latest.startedAt, L"(unknown)");
  }

  return stream.str();
}

std::wstring BuildUpdatesOverviewText(const UiContext& context) {
  const auto availableSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(), [](const auto& patch) {
        return _wcsicmp(patch.updateState.c_str(), L"available") == 0 ||
               _wcsicmp(patch.updateState.c_str(), L"provider_ready") == 0;
      });
  const auto manualSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(), [](const auto& patch) {
        return patch.manualOnly || _wcsicmp(patch.updateState.c_str(), L"manual") == 0;
      });
  const auto blockedSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(),
      [](const auto& patch) { return patch.blocked; });
  const auto unsupportedSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(), [](const auto& patch) {
        return !patch.supported || _wcsicmp(patch.updateState.c_str(), L"unsupported") == 0;
      });

  std::wstringstream stream;
  stream << L"Update posture\r\n\r\n"
         << L"Windows updates pending: " << context.snapshot.windowsUpdates.size() << L"\r\n"
         << L"Software records: " << context.snapshot.softwarePatches.size() << L"\r\n"
         << L"Ready to install: " << availableSoftwareUpdateCount << L"\r\n"
         << L"Manual workflows: " << manualSoftwareUpdateCount << L"\r\n"
         << L"Unsupported entries: " << unsupportedSoftwareUpdateCount << L"\r\n"
         << L"Blocked entries: " << blockedSoftwareUpdateCount << L"\r\n"
         << L"Patch history records: " << context.snapshot.patchHistory.size() << L"\r\n"
         << L"Reboot required: " << (context.snapshot.rebootCoordinator.rebootRequired ? L"yes" : L"no")
         << L"\r\n"
         << L"Reboot reasons: "
         << NullableText(context.snapshot.rebootCoordinator.rebootReasons, L"none");

  if (!context.snapshot.softwarePatches.empty()) {
    stream << L"\r\n\r\nTop software entries\r\n";
    const auto topCount = std::min<std::size_t>(5, context.snapshot.softwarePatches.size());
    for (std::size_t index = 0; index < topCount; ++index) {
      const auto& patch = context.snapshot.softwarePatches[index];
      stream << L"- " << NullableText(patch.displayName, L"(unknown)") << L" ["
             << NullableText(patch.updateState, L"unknown") << L"]";
      if (!patch.availableVersion.empty()) {
        stream << L" -> " << patch.availableVersion;
      }
      if (patch.manualOnly) {
        stream << L" (manual)";
      }
      if (patch.blocked) {
        stream << L" (blocked)";
      }
      stream << L"\r\n";
    }
  }

  if (!context.snapshot.windowsUpdates.empty()) {
    stream << L"\r\nWindows updates (top 3)\r\n";
    const auto topCount = std::min<std::size_t>(3, context.snapshot.windowsUpdates.size());
    for (std::size_t index = 0; index < topCount; ++index) {
      const auto& update = context.snapshot.windowsUpdates[index];
      stream << L"- " << NullableText(update.title, L"(unknown)");
      if (!update.kbArticles.empty()) {
        stream << L" (" << update.kbArticles << L")";
      }
      stream << L" [" << NullableText(update.status, L"unknown") << L"]\r\n";
    }
  }

  return stream.str();
}

std::wstring BuildSettingsOverviewText(const UiContext& context) {
  const auto exclusions = antivirus::agent::LoadConfiguredScanExclusions();
  std::wstringstream stream;
  stream << L"Local configuration\r\n\r\n"
         << L"Control plane: " << NullableText(context.config.controlPlaneBaseUrl) << L"\r\n"
         << L"Runtime database: " << context.config.runtimeDatabasePath.wstring() << L"\r\n"
         << L"State file: " << context.config.stateFilePath.wstring() << L"\r\n"
         << L"Telemetry queue: " << context.config.telemetryQueuePath.wstring() << L"\r\n"
         << L"Quarantine root: " << context.config.quarantineRootPath.wstring() << L"\r\n"
         << L"Evidence root: " << context.config.evidenceRootPath.wstring() << L"\r\n"
         << L"Custom exclusions: " << exclusions.size() << L" path(s)\r\n"
         << L"Quick scan schedule: every " << context.config.scheduledQuickScanIntervalMinutes << L" minute(s)\r\n"
         << L"Full scan schedule: every " << context.config.scheduledFullDriveScanIntervalMinutes << L" minute(s)\r\n"
         << L"Realtime port: " << NullableText(context.config.realtimeProtectionPortName) << L"\r\n"
         << L"Sync interval: " << context.config.syncIntervalSeconds << L" seconds\r\n"
         << L"Telemetry batch size: " << context.config.telemetryBatchSize << L"\r\n"
         << L"Isolation loopback: " << (context.config.isolationAllowLoopback ? L"allowed" : L"blocked") << L"\r\n"
         << L"Edit exclusions: administrator approval required";
  return stream.str();
}

std::wstring DefaultDetailText(const UiContext& context) {
  switch (context.currentPage) {
    case ClientPage::Threats:
      if (context.snapshot.recentThreats.empty()) {
        return L"Finding detail\r\n\r\nNo unresolved local findings are currently recorded on this device.";
      }
      return L"Finding detail\r\n\r\nSelect a finding to see its path, ATT&CK mapping, confidence, and remediation state.";
    case ClientPage::Quarantine:
      if (context.snapshot.quarantineItems.empty()) {
        return L"Quarantine detail\r\n\r\nNo items are currently being held in local quarantine.";
      }
      return L"Quarantine detail\r\n\r\nSelect a quarantined item to review where it came from and decide whether to restore or delete it.";
    case ClientPage::Updates:
      return BuildUpdatesOverviewText(context);
    case ClientPage::Service:
      return BuildServiceOverviewText(context);
    case ClientPage::Settings:
      if (context.manageExclusionsMode) {
        return BuildExclusionsEditorText();
      }
      return BuildSettingsOverviewText(context);
    case ClientPage::Dashboard:
      if (context.snapshot.recentFindings.empty()) {
        return L"Recent activity\r\n\r\nNo recent scans or detections are recorded yet. Use Quick scan to verify the device now.";
      }
      return L"Recent activity\r\n\r\nSelect an item to review what happened recently on this endpoint and what the agent did next.";
    case ClientPage::Scans:
      return L"Scan detail\r\n\r\nSelect a scan session to review its scope, outcome, and remediation summary.";
    case ClientPage::History:
    default:
      if (context.snapshot.recentFindings.empty()) {
        return L"Detection history\r\n\r\nNo local scans or detections have been recorded yet.";
      }
      return L"Detection history\r\n\r\nSelect a scan or historical finding to review what ran and how the agent handled it.";
  }
}

std::wstring ReplaceAll(std::wstring value, const std::wstring& token, const std::wstring& replacement) {
  std::size_t position = 0;
  while ((position = value.find(token, position)) != std::wstring::npos) {
    value.replace(position, token.size(), replacement);
    position += replacement.size();
  }

  return value;
}

std::wstring JsonEscape(std::wstring_view value) {
  std::wstring escaped;
  escaped.reserve(value.size() + 16);
  for (const auto ch : value) {
    switch (ch) {
      case L'\\':
        escaped += L"\\\\";
        break;
      case L'"':
        escaped += L"\\\"";
        break;
      case L'\b':
        escaped += L"\\b";
        break;
      case L'\f':
        escaped += L"\\f";
        break;
      case L'\n':
        escaped += L"\\n";
        break;
      case L'\r':
        escaped += L"\\r";
        break;
      case L'\t':
        escaped += L"\\t";
        break;
      case L'<':
        escaped += L"\\u003C";
        break;
      case L'>':
        escaped += L"\\u003E";
        break;
      case L'&':
        escaped += L"\\u0026";
        break;
      case L'\'':
        escaped += L"\\u0027";
        break;
      default:
        if (ch < 0x20) {
          wchar_t buffer[7]{};
          swprintf_s(buffer, L"\\u%04X", static_cast<unsigned>(ch));
          escaped += buffer;
        } else {
          escaped.push_back(ch);
        }
        break;
    }
  }

  return escaped;
}

int HexDigitValue(const wchar_t ch) {
  if (ch >= L'0' && ch <= L'9') {
    return static_cast<int>(ch - L'0');
  }
  if (ch >= L'a' && ch <= L'f') {
    return 10 + static_cast<int>(ch - L'a');
  }
  if (ch >= L'A' && ch <= L'F') {
    return 10 + static_cast<int>(ch - L'A');
  }
  return -1;
}

std::wstring UrlDecode(std::wstring_view value) {
  std::wstring decoded;
  decoded.reserve(value.size());
  for (std::size_t index = 0; index < value.size(); ++index) {
    const auto ch = value[index];
    if (ch == L'+') {
      decoded.push_back(L' ');
      continue;
    }

    if (ch == L'%' && index + 2 < value.size()) {
      const int hi = HexDigitValue(value[index + 1]);
      const int lo = HexDigitValue(value[index + 2]);
      if (hi >= 0 && lo >= 0) {
        decoded.push_back(static_cast<wchar_t>((hi << 4) | lo));
        index += 2;
        continue;
      }
    }

    decoded.push_back(ch);
  }

  return decoded;
}

std::vector<std::pair<std::wstring, std::wstring>> ParseWebMessage(const std::wstring& message) {
  std::vector<std::pair<std::wstring, std::wstring>> pairs;
  std::size_t start = 0;
  while (start < message.size()) {
    const auto end = message.find(L'&', start);
    const auto token = message.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
    const auto equals = token.find(L'=');
    if (equals == std::wstring::npos) {
      if (!token.empty()) {
        pairs.emplace_back(UrlDecode(token), std::wstring{});
      }
    } else {
      pairs.emplace_back(UrlDecode(token.substr(0, equals)), UrlDecode(token.substr(equals + 1)));
    }

    if (end == std::wstring::npos) {
      break;
    }
    start = end + 1;
  }

  return pairs;
}

std::wstring GetQueryValue(const std::vector<std::pair<std::wstring, std::wstring>>& pairs, const wchar_t* key) {
  for (const auto& [candidateKey, candidateValue] : pairs) {
    if (_wcsicmp(candidateKey.c_str(), key) == 0) {
      return candidateValue;
    }
  }
  return {};
}

std::optional<int> ParseBoundedInteger(const std::wstring& value, const int minimum, const int maximum) {
  if (value.empty()) {
    return std::nullopt;
  }

  std::size_t consumed = 0;
  int parsed = 0;
  try {
    parsed = std::stoi(value, &consumed, 10);
  } catch (...) {
    return std::nullopt;
  }

  if (consumed != value.size() || parsed < minimum || parsed > maximum) {
    return std::nullopt;
  }

  return parsed;
}

std::wstring LoadFenrirLogoDataUri() {
  const auto module = GetModuleHandleW(nullptr);
  const auto resource = FindResourceW(module, MAKEINTRESOURCEW(kFenrirPngResourceId), RT_RCDATA);
  if (resource == nullptr) {
    return {};
  }

  const auto loaded = LoadResource(module, resource);
  if (loaded == nullptr) {
    return {};
  }

  const auto size = SizeofResource(module, resource);
  const auto rawBytes = LockResource(loaded);
  if (rawBytes == nullptr || size == 0) {
    return {};
  }

  const auto* bytes = static_cast<const BYTE*>(rawBytes);
  DWORD encodedLength = 0;
  if (CryptBinaryToStringW(bytes, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &encodedLength) == FALSE ||
      encodedLength == 0) {
    return {};
  }

  std::wstring encoded(encodedLength, L'\0');
  if (CryptBinaryToStringW(bytes, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded.data(), &encodedLength) ==
      FALSE) {
    return {};
  }

  if (!encoded.empty() && encoded.back() == L'\0') {
    encoded.pop_back();
  }

  return L"data:image/png;base64," + encoded;
}

std::wstring BuildWebViewStateJson(const UiContext& context) {
  const auto exclusions = antivirus::agent::LoadConfiguredScanExclusions();
  const bool exclusionsMode = context.currentPage == ClientPage::Settings && context.manageExclusionsMode;
  const auto pageTitle = exclusionsMode ? std::wstring(L"Exclusions") : PageTitle(context.currentPage);
  const auto pageSubtitle = exclusionsMode
                                ? std::wstring(L"Add trusted file, folder, process, and application exclusions without leaving Fenrir.")
                                : PageSubtitle(context.currentPage, context.snapshot);

  std::wstring lastScan = L"(never)";
  for (const auto& record : context.snapshot.recentFindings) {
    if (IsScanSessionRecord(record)) {
      lastScan = NullableText(record.recordedAt, L"(never)");
      break;
    }
  }

  std::wstring nextAction;
  if (context.snapshot.serviceState == LocalServiceState::NotInstalled) {
    nextAction = L"Install the protection service";
  } else if (context.snapshot.serviceState == LocalServiceState::Stopped) {
    nextAction = L"Start the protection service";
  } else if (context.snapshot.openThreatCount != 0) {
    nextAction = L"Review findings and quarantine";
  } else if (_wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
    nextAction = L"Review runtime health";
  } else {
    nextAction = L"Keep protection running";
  }

  const auto serviceState = antivirus::agent::LocalServiceStateToString(context.snapshot.serviceState);
  std::wstring statusTone = L"info";
  if (context.snapshot.serviceState == LocalServiceState::NotInstalled ||
      context.snapshot.serviceState == LocalServiceState::Stopped) {
    statusTone = L"danger";
  } else if (context.snapshot.openThreatCount != 0 ||
             _wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
    statusTone = L"warning";
  } else {
    statusTone = L"good";
  }

  const auto availableSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(), [](const auto& patch) {
        return _wcsicmp(patch.updateState.c_str(), L"available") == 0 ||
               _wcsicmp(patch.updateState.c_str(), L"provider_ready") == 0;
      });
  const auto manualSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(), [](const auto& patch) {
        return patch.manualOnly || _wcsicmp(patch.updateState.c_str(), L"manual") == 0;
      });
  const auto unsupportedSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(), [](const auto& patch) {
        return !patch.supported || _wcsicmp(patch.updateState.c_str(), L"unsupported") == 0;
      });
  const auto blockedSoftwareUpdateCount = std::count_if(
      context.snapshot.softwarePatches.begin(), context.snapshot.softwarePatches.end(),
      [](const auto& patch) { return patch.blocked; });

  std::wstring detailText = DefaultDetailText(context);
  if (exclusionsMode) {
    detailText = L"Choose a source below and add only exclusions you trust.\r\n\r\nFile and folder exclusions use File Explorer pickers.\r\nProcess exclusions use the current process list.\r\nApplication exclusions use the installed software inventory.";
  } else if (context.currentPage == ClientPage::Dashboard) {
    detailText = BuildDetailsCardText(context.snapshot);
  } else if (context.currentPage == ClientPage::Threats && !context.snapshot.recentThreats.empty()) {
    detailText = BuildThreatDetailText(context.snapshot.recentThreats.front());
  } else if (context.currentPage == ClientPage::Quarantine && !context.snapshot.quarantineItems.empty()) {
    detailText = BuildQuarantineDetailText(context.snapshot.quarantineItems.front());
  } else if ((context.currentPage == ClientPage::Scans || context.currentPage == ClientPage::History) &&
             !context.snapshot.recentFindings.empty()) {
    detailText = BuildHistoryDetailText(context.snapshot.recentFindings.front());
  }

  const auto settingsEntries = std::vector<std::pair<std::wstring, std::wstring>>{
      {L"Control plane", NullableText(context.config.controlPlaneBaseUrl)},
      {L"Runtime database", context.config.runtimeDatabasePath.wstring()},
      {L"State file", context.config.stateFilePath.wstring()},
      {L"Telemetry queue", context.config.telemetryQueuePath.wstring()},
      {L"Quarantine root", context.config.quarantineRootPath.wstring()},
      {L"Evidence root", context.config.evidenceRootPath.wstring()},
      {L"Quick scan schedule", std::to_wstring(context.config.scheduledQuickScanIntervalMinutes) + L" minute(s)"},
      {L"Full scan schedule", std::to_wstring(context.config.scheduledFullDriveScanIntervalMinutes) + L" minute(s)"},
      {L"Realtime port", NullableText(context.config.realtimeProtectionPortName)},
      {L"Sync interval", std::to_wstring(context.config.syncIntervalSeconds) + L" seconds"},
         {L"Telemetry batch size", std::to_wstring(context.config.telemetryBatchSize)},
         {L"Isolation loopback", context.config.isolationAllowLoopback ? L"allowed" : L"blocked"},
         {L"Custom exclusions", std::to_wstring(antivirus::agent::LoadConfiguredScanExclusions().size()) + L" path(s)"},
  };

  const auto processInventory = exclusionsMode ? antivirus::agent::CollectProcessInventory(40) : std::vector<antivirus::agent::ProcessObservation>{};
  const auto deviceInventory = exclusionsMode ? antivirus::agent::CollectDeviceInventorySnapshot() : antivirus::agent::DeviceInventorySnapshot{};

  std::wstringstream json;
  json << L"{";
  json << L"\"pageKey\":\"" << JsonEscape(PageKey(context.currentPage)) << L"\",";
  json << L"\"pageTitle\":\"" << JsonEscape(pageTitle) << L"\",";
  json << L"\"pageSubtitle\":\"" << JsonEscape(pageSubtitle) << L"\",";
  json << L"\"statusChip\":\"" << JsonEscape(OverallStatusChip(context.snapshot)) << L"\",";
  json << L"\"statusTone\":\"" << statusTone << L"\",";
  json << L"\"headline\":\"" << JsonEscape(ProtectionHeadline(context.snapshot)) << L"\",";
  json << L"\"guidance\":\"" << JsonEscape(ProtectionGuidance(context.snapshot)) << L"\",";
  json << L"\"nextAction\":\"" << JsonEscape(nextAction) << L"\",";
  json << L"\"manageExclusionsMode\":" << (context.manageExclusionsMode ? 1 : 0) << L",";
  json << L"\"detailTitle\":\"" << JsonEscape(SecondarySectionTitle(context.currentPage)) << L"\",";
  json << L"\"detailSubtitle\":\"" << JsonEscape(DefaultDetailText(context).substr(0, std::min<std::size_t>(80, DefaultDetailText(context).size()))) << L"\",";
  json << L"\"detailText\":\"" << JsonEscape(detailText) << L"\",";
  json << L"\"scan\":{\"running\":" << (context.scanRunning ? 1 : 0)
       << L",\"status\":\"" << JsonEscape(context.scanStatusText) << L"\",\"completed\":" << context.scanProgressCompleted
       << L",\"total\":" << context.scanProgressTotal << L",\"label\":\"" << JsonEscape(context.activeScanLabel)
       << L"\"},";
    json << L"\"patchAction\":{\"running\":" << (context.patchActionRunning.load() ? 1 : 0)
      << L",\"status\":\"" << JsonEscape(context.patchActionStatus) << L"\",\"target\":\""
      << JsonEscape(context.patchActionTarget) << L"\",\"mode\":\""
      << JsonEscape(context.patchActionSearchOnly ? L"check" : L"update") << L"\"},";
  json << L"\"brand\":{\"logo\":\"" << JsonEscape(context.webViewLogoDataUri) << L"\",\"device\":\""
       << JsonEscape(NullableText(context.snapshot.agentState.hostname, L"Local device")) << L"\",\"status\":\""
       << JsonEscape(OverallStatusChip(context.snapshot)) << L"\",\"policy\":\""
       << JsonEscape(L"Policy " + NullableText(context.snapshot.agentState.policy.revision, L"n/a")) << L"\"},";
  json << L"\"runtime\":{\"serviceState\":\"" << JsonEscape(serviceState) << L"\",\"healthState\":\""
       << JsonEscape(NullableText(context.snapshot.agentState.healthState, L"unknown")) << L"\",\"deviceId\":\""
       << JsonEscape(NullableText(context.snapshot.agentState.deviceId, L"(not enrolled)")) << L"\",\"controlPlane\":\""
       << JsonEscape(NullableText(context.config.controlPlaneBaseUrl)) << L"\",\"lastHeartbeat\":\""
       << JsonEscape(NullableText(context.snapshot.agentState.lastHeartbeatAt, L"(never)")) << L"\",\"lastPolicySync\":\""
       << JsonEscape(NullableText(context.snapshot.agentState.lastPolicySyncAt, L"(never)")) << L"\",\"queuedTelemetry\":\""
       << context.snapshot.queuedTelemetryCount << L"\",\"lastScan\":\"" << JsonEscape(lastScan)
       << L"\",\"quickScanIntervalMinutes\":" << context.config.scheduledQuickScanIntervalMinutes
       << L",\"fullScanIntervalMinutes\":" << context.config.scheduledFullDriveScanIntervalMinutes << L"},";
    json << L"\"updates\":{\"windowsCount\":" << context.snapshot.windowsUpdates.size()
      << L",\"softwareCount\":" << context.snapshot.softwarePatches.size()
      << L",\"availableSoftwareCount\":" << availableSoftwareUpdateCount
      << L",\"manualSoftwareCount\":" << manualSoftwareUpdateCount
      << L",\"unsupportedSoftwareCount\":" << unsupportedSoftwareUpdateCount
      << L",\"blockedSoftwareCount\":" << blockedSoftwareUpdateCount
      << L",\"historyCount\":" << context.snapshot.patchHistory.size()
      << L",\"rebootRequired\":" << (context.snapshot.rebootCoordinator.rebootRequired ? 1 : 0)
      << L",\"rebootReasons\":\"" << JsonEscape(NullableText(context.snapshot.rebootCoordinator.rebootReasons, L"none"))
      << L"\"},";

  const auto appendCard = [&json](const std::wstring& label, const std::wstring& value, const std::wstring& detail,
                                  const std::wstring& tone) {
    json << L"{\"label\":\"" << JsonEscape(label) << L"\",\"value\":\"" << JsonEscape(value)
         << L"\",\"detail\":\"" << JsonEscape(detail) << L"\",\"tone\":\"" << JsonEscape(tone) << L"\"}";
  };

  json << L"\"cards\":[";
  appendCard(L"Open findings", std::to_wstring(context.snapshot.openThreatCount),
             context.snapshot.openThreatCount == 1 ? L"1 unresolved detection" :
                                                     std::to_wstring(context.snapshot.openThreatCount) + L" unresolved detections",
             context.snapshot.openThreatCount == 0 ? L"good" : L"danger");
  json << L",";
  appendCard(L"Quarantined", std::to_wstring(context.snapshot.activeQuarantineCount),
             context.snapshot.activeQuarantineCount == 1 ? L"1 item contained" :
                                                          std::to_wstring(context.snapshot.activeQuarantineCount) + L" items contained",
             context.snapshot.activeQuarantineCount == 0 ? L"info" : L"warning");
  json << L",";
  appendCard(L"Protection service", serviceState,
             NullableText(context.snapshot.agentState.healthState, L"unknown"), statusTone);
  json << L",";
  appendCard(L"Last check-in", NullableText(context.snapshot.agentState.lastHeartbeatAt, L"(never)"),
             std::to_wstring(context.snapshot.queuedTelemetryCount) + L" upload(s) queued", L"info");
  json << L"],";

  json << L"\"settings\":[";
  for (std::size_t index = 0; index < settingsEntries.size(); ++index) {
    if (index != 0) {
      json << L",";
    }
    json << L"{\"label\":\"" << JsonEscape(settingsEntries[index].first) << L"\",\"value\":\""
         << JsonEscape(settingsEntries[index].second) << L"\"}";
  }
  json << L"],";

  json << L"\"exclusions\":[";
  for (std::size_t index = 0; index < exclusions.size(); ++index) {
    if (index != 0) {
      json << L",";
    }
    const auto& path = exclusions[index];
    std::error_code error;
    const auto isDirectory = std::filesystem::is_directory(path, error);
    const auto kind = isDirectory ? L"Folder" : L"File";
    json << L"{\"path\":\"" << JsonEscape(path.wstring()) << L"\",\"kind\":\"" << JsonEscape(kind)
         << L"\",\"id\":\"" << JsonEscape(path.wstring()) << L"\"}";
  }
  json << L"],";

  json << L"\"processes\":[";
  for (std::size_t index = 0; index < processInventory.size(); ++index) {
    if (index != 0) {
      json << L",";
    }
    const auto& process = processInventory[index];
    json << L"{\"pid\":" << process.pid << L",\"parentPid\":" << process.parentPid << L",\"name\":\""
         << JsonEscape(NullableText(process.imageName, L"(unknown)")) << L"\",\"path\":\""
         << JsonEscape(NullableText(process.imagePath, L"")) << L"\",\"prioritized\":"
         << (process.prioritized ? 1 : 0) << L"}";
  }
  json << L"],";

  json << L"\"software\":[";
  for (std::size_t index = 0; index < deviceInventory.installedSoftware.size(); ++index) {
    if (index != 0) {
      json << L",";
    }
    const auto& software = deviceInventory.installedSoftware[index];
    json << L"{\"id\":\"" << JsonEscape(software.softwareId) << L"\",\"name\":\""
         << JsonEscape(NullableText(software.displayName, L"(unknown)")) << L"\",\"version\":\""
         << JsonEscape(NullableText(software.displayVersion, L"")) << L"\",\"publisher\":\""
         << JsonEscape(NullableText(software.publisher, L"")) << L"\",\"location\":\""
         << JsonEscape(NullableText(software.installLocation, L"")) << L"\",\"blocked\":"
         << (software.blocked ? 1 : 0) << L"}";
  }
  json << L"],";

  json << L"\"softwareUpdates\":[";
  for (std::size_t index = 0; index < context.snapshot.softwarePatches.size(); ++index) {
    if (index != 0) {
      json << L",";
    }
    const auto& patch = context.snapshot.softwarePatches[index];
    const auto canInstall = patch.supported && !patch.manualOnly && !patch.blocked;
    json << L"{\"id\":\"" << JsonEscape(patch.softwareId) << L"\",\"name\":\""
         << JsonEscape(NullableText(patch.displayName, L"(unknown)")) << L"\",\"version\":\""
         << JsonEscape(NullableText(patch.displayVersion, L"")) << L"\",\"availableVersion\":\""
         << JsonEscape(NullableText(patch.availableVersion, L"")) << L"\",\"publisher\":\""
         << JsonEscape(NullableText(patch.publisher, L"")) << L"\",\"provider\":\""
         << JsonEscape(NullableText(patch.provider, L"manual")) << L"\",\"state\":\""
         << JsonEscape(NullableText(patch.updateState, L"unknown")) << L"\",\"summary\":\""
         << JsonEscape(NullableText(patch.updateSummary, L"")) << L"\",\"supported\":"
         << (patch.supported ? 1 : 0) << L",\"manualOnly\":" << (patch.manualOnly ? 1 : 0)
         << L",\"blocked\":" << (patch.blocked ? 1 : 0) << L",\"highRisk\":" << (patch.highRisk ? 1 : 0)
         << L",\"rebootRequired\":" << (patch.rebootRequired ? 1 : 0) << L",\"canInstall\":"
         << (canInstall ? 1 : 0) << L"}";
  }
  json << L"],";

  json << L"\"windowsUpdates\":[";
  for (std::size_t index = 0; index < context.snapshot.windowsUpdates.size(); ++index) {
    if (index != 0) {
      json << L",";
    }
    const auto& update = context.snapshot.windowsUpdates[index];
    json << L"{\"id\":\"" << JsonEscape(update.updateId) << L"\",\"title\":\""
         << JsonEscape(NullableText(update.title, L"(unknown)")) << L"\",\"kb\":\""
         << JsonEscape(NullableText(update.kbArticles, L"")) << L"\",\"severity\":\""
         << JsonEscape(NullableText(update.severity, L"")) << L"\",\"classification\":\""
         << JsonEscape(NullableText(update.classification, L"")) << L"\",\"status\":\""
         << JsonEscape(NullableText(update.status, L"unknown")) << L"\",\"rebootRequired\":"
         << (update.rebootRequired ? 1 : 0) << L"}";
  }
  json << L"],";

  const auto appendRecentFinding = [&json](const antivirus::agent::ScanHistoryRecord& record) {
    const auto item = ThreatDisplayPath(record);
    const auto attack = record.techniqueId.empty() ? record.tacticId : record.tacticId + L" / " + record.techniqueId;
    json << L"{\"time\":\"" << JsonEscape(NullableText(record.recordedAt)) << L"\",\"item\":\""
         << JsonEscape(item) << L"\",\"result\":\"" << JsonEscape(HistoryDispositionLabel(record))
         << L"\",\"source\":\"" << JsonEscape(HistorySourceLabel(record.source)) << L"\",\"technique\":\""
         << JsonEscape(attack.empty() ? std::wstring(L"(n/a)") : attack) << L"\",\"remediation\":\""
         << JsonEscape(NullableText(record.remediationStatus, L"(none)")) << L"\",\"kind\":\""
         << JsonEscape(record.contentType.empty() ? L"detection" : record.contentType) << L"\",\"id\":\""
         << JsonEscape(record.recordedAt + L"|" + item) << L"\",\"detail\":\""
         << JsonEscape(BuildHistoryDetailText(record)) << L"\"}";
  };

  json << L"\"history\":[";
  for (std::size_t index = 0; index < context.snapshot.recentFindings.size(); ++index) {
    if (index != 0) {
      json << L",";
    }
    appendRecentFinding(context.snapshot.recentFindings[index]);
  }
  json << L"],";

  json << L"\"threats\":[";
  for (std::size_t index = 0; index < context.snapshot.recentThreats.size(); ++index) {
    if (index != 0) {
      json << L",";
    }
    const auto& record = context.snapshot.recentThreats[index];
    const auto attack = record.techniqueId.empty() ? record.tacticId : record.tacticId + L" / " + record.techniqueId;
    json << L"{\"time\":\"" << JsonEscape(NullableText(record.recordedAt)) << L"\",\"item\":\""
         << JsonEscape(ThreatDisplayPath(record)) << L"\",\"action\":\"" << JsonEscape(record.disposition)
         << L"\",\"confidence\":\"" << record.confidence << L"\",\"attack\":\""
         << JsonEscape(attack.empty() ? std::wstring(L"(n/a)") : attack) << L"\",\"remediation\":\""
         << JsonEscape(NullableText(record.remediationStatus, L"(none)")) << L"\",\"source\":\""
         << JsonEscape(NullableText(record.source, L"(unknown)")) << L"\",\"sha256\":\""
         << JsonEscape(NullableText(record.sha256, L"(unavailable)")) << L"\",\"id\":\""
         << JsonEscape(record.evidenceRecordId.empty() ? record.recordedAt + L"|" + ThreatDisplayPath(record)
                                                       : record.evidenceRecordId)
         << L"\",\"detail\":\"" << JsonEscape(BuildThreatDetailText(record)) << L"\"}";
  }
  json << L"],";

  json << L"\"quarantine\":[";
  for (std::size_t index = 0; index < context.snapshot.quarantineItems.size(); ++index) {
    if (index != 0) {
      json << L",";
    }
    const auto& record = context.snapshot.quarantineItems[index];
    json << L"{\"time\":\"" << JsonEscape(NullableText(record.capturedAt)) << L"\",\"item\":\""
         << JsonEscape(record.originalPath.wstring()) << L"\",\"status\":\"" << JsonEscape(record.localStatus)
         << L"\",\"technique\":\""
         << JsonEscape(record.techniqueId.empty() ? std::wstring(L"(n/a)") : record.techniqueId)
         << L"\",\"sha256\":\"" << JsonEscape(record.sha256.empty() ? std::wstring(L"(unavailable)") : record.sha256)
         << L"\",\"id\":\"" << JsonEscape(record.recordId) << L"\",\"detail\":\""
         << JsonEscape(BuildQuarantineDetailText(record)) << L"\"}";
  }
  json << L"]}";
  return json.str();
}

std::wstring BuildWebViewHtml(const UiContext& context) {
  std::wstring html = LR"HTML(
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Fenrir Protection Centre</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #070b11;
      --surface: rgba(12, 17, 25, 0.9);
      --surface-soft: rgba(15, 21, 31, 0.88);
      --border: rgba(255,255,255,0.06);
      --text: #edf3ff;
      --muted: #90a0b7;
      --accent: #7aa7ff;
      --good: #52c98f;
      --warning: #e4a450;
      --danger: #e36f7b;
      --shadow: none;
      --radius: 18px;
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; width: 100%; height: 100%; }
    body {
      overflow: hidden;
      font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(900px 420px at 18% 0%, rgba(116,167,255,.11), transparent 52%),
        radial-gradient(780px 360px at 92% 16%, rgba(76,195,138,.08), transparent 48%),
        linear-gradient(180deg, #05080d 0%, #070b11 100%);
    }
    button { font: inherit; }
    .layout {
      display: flex;
      flex-direction: column;
      gap: 12px;
      padding: 16px;
      height: 100%;
    }
    .rail, .card, .panel {
      background: linear-gradient(180deg, rgba(16, 21, 31, .92), rgba(9, 13, 20, .96));
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }
    .rail {
      display: flex;
      flex-direction: row;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      min-height: 0;
      padding: 12px 16px;
    }
    .brand { padding: 0; display: flex; flex-direction: row; align-items: center; gap: 12px; min-width: 0; }
    .brand img { width: 42px; height: 42px; object-fit: contain; border-radius: 12px; flex: 0 0 auto; }
    .brand .name { display: none; }
    .brand .device { font-size: 15px; font-weight: 700; letter-spacing: -.01em; }
    .brand .meta, .foot { color: var(--muted); font-size: 12px; line-height: 1.45; white-space: pre-line; }
    .nav { display: none; }
    .nav button, .tabs button, .actions button {
      border: 1px solid transparent;
      border-radius: 999px;
      background: rgba(255,255,255,.02);
      color: var(--text);
      cursor: pointer;
      transition: transform .12s ease, background .12s ease, border-color .12s ease;
    }
    .nav button { text-align: left; padding: 12px 14px; color: var(--muted); }
    .nav button.active { color: var(--text); background: rgba(122,167,255,.11); border-color: rgba(122,167,255,.2); }
    .tabs, .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .tabs { padding-top: 2px; }
    .tabs button, .actions button { padding: 10px 16px; font-size: 12px; letter-spacing: .01em; }
    .tabs button.active { background: rgba(122,167,255,.11); border-color: rgba(122,167,255,.2); }
    .actions button.primary { background: rgba(122,167,255,.12); border-color: rgba(122,167,255,.2); }
    .actions button.good { background: rgba(82,201,143,.12); border-color: rgba(82,201,143,.2); }
    .actions button.warning { background: rgba(228,164,80,.12); border-color: rgba(228,164,80,.2); }
    .actions button.danger { background: rgba(227,111,123,.12); border-color: rgba(227,111,123,.2); }
    .nav button:disabled,
    .tabs button:disabled,
    .actions button:disabled,
    .inline-actions button:disabled {
      opacity: .45;
      cursor: not-allowed;
      transform: none;
    }
    .main { display: flex; flex-direction: column; min-width: 0; min-height: 0; gap: 12px; }
    .header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
    .eyebrow { text-transform: uppercase; letter-spacing: .16em; color: var(--muted); font-size: 10px; }
    h1 { margin: 4px 0 8px; font-size: 34px; line-height: 1.02; letter-spacing: -.035em; }
    .subtitle { margin: 0; color: var(--muted); font-size: 13px; line-height: 1.5; max-width: 920px; }
    .chip {
      display: inline-flex; align-items: center; justify-content: center;
      min-height: 30px; padding: 0 12px; border-radius: 999px;
      font-size: 12px; font-weight: 700; border: 1px solid rgba(255,255,255,.11);
      background: rgba(255,255,255,.03); white-space: nowrap;
    }
    .chip.good { background: rgba(76,195,138,.12); color: #9de3bf; }
    .chip.warning { background: rgba(224,163,79,.12); color: #ffd48a; }
    .chip.danger { background: rgba(228,109,122,.14); color: #ffbcc4; }
    .chip.info { background: rgba(116,167,255,.12); color: #b9d0ff; }
    .hero { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(0, 0.95fr); gap: 12px; }
    .card { padding: 18px; min-width: 0; overflow: hidden; }
    .card h2 { margin: 8px 0 10px; font-size: 24px; line-height: 1.06; letter-spacing: -.03em; }
    .kv { display: grid; grid-template-columns: 132px minmax(0, 1fr); gap: 8px 12px; margin-top: 8px; }
    .kv .key { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .12em; padding-top: 7px; }
    .kv .value { color: var(--text); font-size: 13px; line-height: 1.45; padding-top: 5px; word-break: break-word; }
    .metrics { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; }
    .metric {
      border: 1px solid var(--border); border-radius: 16px; padding: 14px 15px;
      background: rgba(255,255,255,.015);
    }
    .metric .label { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .14em; }
    .metric .value { margin: 8px 0 4px; font-size: 24px; font-weight: 700; letter-spacing: -.03em; }
    .metric .detail { color: var(--muted); font-size: 13px; line-height: 1.35; }
    .page-body { display: flex; flex-direction: column; gap: 12px; min-height: 0; flex: 1; overflow: auto; padding-bottom: 4px; }
    .section {
      border: 1px solid rgba(255,255,255,.05);
      border-radius: 18px;
      background: rgba(255,255,255,.015);
      padding: 16px;
    }
    .section-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
    .section-title { margin: 0; font-size: 18px; line-height: 1.08; letter-spacing: -.02em; }
    .section-text { margin-top: 6px; color: var(--muted); font-size: 13px; line-height: 1.5; max-width: 76ch; }
    .hero-status { margin-top: 14px; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }
    .hero-chip {
      display: flex; flex-direction: column; gap: 5px;
      border: 1px solid rgba(255,255,255,.05);
      border-radius: 16px;
      padding: 12px 13px;
      background: rgba(255,255,255,.015);
    }
    .hero-chip .label { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .14em; }
    .hero-chip .value { font-size: 20px; font-weight: 700; letter-spacing: -.03em; }
    .hero-chip .detail { color: var(--muted); font-size: 12px; line-height: 1.4; }
    .record-list { display: flex; flex-direction: column; gap: 8px; }
    .record {
      width: 100%;
      appearance: none;
      border: 1px solid rgba(255,255,255,.05);
      border-radius: 14px;
      background: rgba(255,255,255,.015);
      color: inherit;
      cursor: pointer;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      padding: 14px 15px;
      text-align: left;
    }
    .record:hover { background: rgba(122,167,255,.06); }
    .record.selected { background: rgba(122,167,255,.10); border-color: rgba(122,167,255,.18); }
    .record-title { font-size: 13px; font-weight: 700; line-height: 1.3; }
    .record-meta { margin-top: 4px; color: var(--muted); font-size: 12px; line-height: 1.4; white-space: pre-line; }
    .record-badges { display: flex; flex-wrap: wrap; gap: 6px; align-items: flex-start; justify-content: flex-end; max-width: 48%; }
    .record-badges .chip { min-height: 26px; padding: 0 10px; }
    .subtabs { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
    .subtabs button {
      padding: 10px 14px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,.05);
      background: rgba(255,255,255,.015);
      color: var(--muted);
    }
    .subtabs button.active { color: var(--text); background: rgba(122,167,255,.11); border-color: rgba(122,167,255,.2); }
    .exclusion-shell { display: grid; grid-template-columns: minmax(0, 0.92fr) minmax(0, 1.08fr); gap: 12px; align-items: start; }
    .filter-row { display: flex; gap: 10px; align-items: center; margin-top: 12px; }
    .filter-row input {
      flex: 1;
      min-width: 0;
      padding: 12px 14px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.08);
      background: rgba(255,255,255,.02);
      color: var(--text);
      outline: none;
    }
    .source-list { display: flex; flex-direction: column; gap: 8px; margin-top: 12px; }
    .source-card {
      width: 100%;
      appearance: none;
      border: 1px solid rgba(255,255,255,.05);
      border-radius: 14px;
      background: rgba(255,255,255,.015);
      color: inherit;
      cursor: pointer;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      padding: 14px 15px;
      text-align: left;
    }
    .source-card:hover { background: rgba(122,167,255,.06); }
    .source-title { font-size: 13px; font-weight: 700; line-height: 1.3; }
    .source-meta { margin-top: 4px; color: var(--muted); font-size: 12px; line-height: 1.4; white-space: pre-line; }
    .source-badges { display: flex; flex-wrap: wrap; gap: 6px; align-items: flex-start; justify-content: flex-end; max-width: 48%; }
    .source-badges .chip { min-height: 26px; padding: 0 10px; }
    .inline-actions { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    .inline-actions button { padding: 8px 12px; border-radius: 999px; font-size: 12px; }
    .pager { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-top: 12px; }
    .pager .meta { color: var(--muted); font-size: 12px; }
    .pager .actions { margin: 0; }
    .status-row { margin-top: 12px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .detail-card { border: 1px solid rgba(255,255,255,.05); border-radius: 18px; background: rgba(255,255,255,.015); padding: 14px; }
    .detail-card .title { font-size: 14px; font-weight: 700; margin-bottom: 6px; }
    .detail-card .text { color: var(--muted); font-size: 13px; line-height: 1.45; white-space: pre-wrap; }
    .detail-grid { display: grid; grid-template-columns: 132px minmax(0, 1fr); gap: 8px 12px; margin-top: 8px; }
    .detail-grid .key { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .12em; padding-top: 6px; }
    .detail-grid .value { color: var(--text); font-size: 13px; line-height: 1.45; padding-top: 4px; word-break: break-word; }
    .empty { color: var(--muted); font-size: 13px; line-height: 1.55; padding: 18px 14px; }
    progress { width: 100%; height: 8px; border: 0; border-radius: 999px; overflow: hidden; background: rgba(255,255,255,.05); }
    progress::-webkit-progress-bar { background: rgba(255,255,255,.05); }
    progress::-webkit-progress-value { background: linear-gradient(90deg, rgba(116,167,255,.95), rgba(76,195,138,.95)); }
    @media (max-width: 1280px) {
      body { overflow: auto; }
      .layout { height: auto; }
      .rail { flex-direction: column; align-items: flex-start; }
      .hero, .metrics { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <aside class="rail">
      <div class="brand">
        <img src="__FENRIR_LOGO_URI__" alt="Fenrir" />
        <div class="device" id="brandDevice"></div>
        <div class="meta" id="brandMeta"></div>
      </div>
      <div class="nav" id="nav"></div>
      <div class="foot" id="foot"></div>
    </aside>
    <main class="main">
      <header class="header">
        <div>
          <div class="eyebrow">Protection Centre</div>
          <h1 id="pageTitle"></h1>
          <p class="subtitle" id="pageSubtitle"></p>
        </div>
        <div class="chip info" id="statusChip"></div>
      </header>
      <div class="tabs" id="tabs"></div>
      <div class="actions" id="actions"></div>
      <section id="pageBody" class="page-body"></section>
    </main>
  </div>
  <script>
    const initialState = __FENRIR_INITIAL_STATE__;
    let appState = initialState;
    const selection = Object.create(null);
    let exclusionMode = 'current';
    let exclusionSearch = '';
    let updateFilter = 'actionable';
    let updateSort = 'priority';
    let updateSearch = '';
    let updatePageIndex = 0;
    const updatesPageSize = 8;
    const pages = [
      { key: 'dashboard', label: 'Home' },
      { key: 'threats', label: 'Findings' },
      { key: 'quarantine', label: 'Quarantine' },
      { key: 'scans', label: 'Scans' },
      { key: 'updates', label: 'Updates' },
      { key: 'history', label: 'History' },
      { key: 'settings', label: 'Settings' }
    ];

    function esc(value) {
      return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function send(message) {
      if (window.chrome && window.chrome.webview) {
        window.chrome.webview.postMessage(message);
      }
    }

    function actionMessage(action, fields = {}) {
      return new URLSearchParams({ action, ...fields }).toString();
    }

    function rowsFor(pageKey) {
      if (pageKey === 'dashboard' || pageKey === 'history') return appState.history || [];
      if (pageKey === 'threats') return appState.threats || [];
      if (pageKey === 'quarantine') return appState.quarantine || [];
      if (pageKey === 'scans') return (appState.history || []).filter((item) => item.kind === 'scan-session');
      if (pageKey === 'updates') return appState.softwareUpdates || [];
      return appState.settings || [];
    }

    function activeItem(pageKey) {
      const rows = rowsFor(pageKey);
      const index = Number.isInteger(selection[pageKey]) ? selection[pageKey] : -1;
      return index >= 0 && index < rows.length ? rows[index] : (rows[0] || null);
    }

    function buildNav() {
      const nav = document.getElementById('nav');
      nav.innerHTML = pages.map((page) =>
        `<button class="${page.key === appState.pageKey ? 'active' : ''}" data-nav="${page.key}">${esc(page.label)}</button>`
      ).join('');
    }

    function buildTabs() {
      const tabs = document.getElementById('tabs');
      tabs.innerHTML = pages.map((page) =>
        `<button class="${page.key === appState.pageKey ? 'active' : ''}" data-nav="${page.key}">${esc(page.label)}</button>`
      ).join('');
    }

    function buildActions() {
      const page = appState.pageKey;
      const patchBusy = Boolean(appState.patchAction && appState.patchAction.running);
      const patchDisabled = patchBusy ? ' disabled' : '';
      const actions = [];
      if (page === 'dashboard') {
        actions.push(`<button class="primary" data-action="scan" data-preset="quick">Quick scan</button>`);
        actions.push(`<button data-action="softwareUpdatesRefresh"${patchDisabled}>Refresh updates</button>`);
        actions.push(`<button data-action="requestWindowsUpdatePam">Windows Update (PAM)</button>`);
        actions.push(`<button data-action="openQuarantine">Review quarantine</button>`);
        actions.push(`<button data-action="refresh">Refresh</button>`);
      } else if (page === 'threats') {
        actions.push(`<button data-action="refresh">Refresh</button>`);
        actions.push(`<button data-action="openQuarantine">Review quarantine</button>`);
      } else if (page === 'quarantine') {
        actions.push(`<button data-action="refresh">Refresh</button>`);
      } else if (page === 'scans') {
        actions.push(`<button class="primary" data-action="scan" data-preset="quick">Quick scan</button>`);
        actions.push(`<button data-action="scan" data-preset="full">Full scan</button>`);
        actions.push(`<button data-action="scan" data-preset="folder">Scan folder</button>`);
        actions.push(`<button data-action="refresh">Refresh</button>`);
      } else if (page === 'updates') {
        actions.push(`<button class="primary" data-action="softwareUpdatesRefresh"${patchDisabled}>Refresh updates</button>`);
        actions.push(`<button data-action="requestWindowsUpdatePam">Request Windows Update (PAM)</button>`);
        actions.push(`<button data-action="requestNetworkResetPam">Request network reset (PAM)</button>`);
        actions.push(`<button data-nav="dashboard">Back to dashboard</button>`);
      } else if (page === 'history') {
        actions.push(`<button data-action="refresh">Refresh</button>`);
      } else if (page === 'settings') {
        if (appState.manageExclusionsMode) {
          actions.push(`<button class="warning" data-action="exclusionsDone">Back to settings</button>`);
          actions.push(`<button class="primary" data-action="exclusionsAddFile">Add file</button>`);
          actions.push(`<button class="primary" data-action="exclusionsAddFolder">Add folder</button>`);
          actions.push(`<button data-exclusion-mode="process">Process</button>`);
          actions.push(`<button data-exclusion-mode="application">Application</button>`);
          actions.push(`<button data-action="refresh">Refresh</button>`);
        } else {
          actions.push(`<button data-action="setQuickScanInterval">Quick scan schedule</button>`);
          actions.push(`<button data-action="setFullScanInterval">Full scan schedule</button>`);
          actions.push(`<button class="warning" data-action="openExclusions">Manage exclusions</button>`);
          actions.push(`<button data-action="refresh">Refresh</button>`);
        }
      }
      if (appState.runtime && (appState.runtime.serviceState === 'not installed' || appState.runtime.serviceState === 'stopped')) {
        actions.push(`<button class="good" data-action="startService">Start protection</button>`);
      }
      const current = page === 'quarantine' ? selectedItem('quarantine') : null;
      if (current) {
        actions.push(`<button class="good" data-action="quarantineRestore" data-id="${esc(current.id)}">Restore selected</button>`);
        actions.push(`<button class="danger" data-action="quarantineDelete" data-id="${esc(current.id)}">Delete selected</button>`);
      }
      return actions.join('');
    }

    function buildHeroActions() {
      const page = appState.pageKey;
      const patchBusy = Boolean(appState.patchAction && appState.patchAction.running);
      const patchDisabled = patchBusy ? ' disabled' : '';
      if (page === 'dashboard') {
        return [
          `<button class="primary" data-nav="updates">Open updates workspace</button>`,
          `<button data-action="softwareUpdatesRefresh"${patchDisabled}>Refresh software inventory</button>`,
          `<button class="primary" data-action="navigate" data-page="threats">Review findings</button>`,
          `<button data-action="navigate" data-page="quarantine">Open quarantine</button>`,
          `<button data-action="scan" data-preset="quick">Run quick scan</button>`
        ].join('');
      }
      if (page === 'quarantine') {
        const current = activeItem('quarantine');
        return current ? [
          `<button class="good" data-action="quarantineRestore" data-id="${esc(current.id)}">Restore</button>`,
          `<button class="danger" data-action="quarantineDelete" data-id="${esc(current.id)}">Delete</button>`
        ].join('') : '';
      }
      if (page === 'settings') {
        return `<button class="warning" data-action="openExclusions">Edit exclusions</button>`;
      }
      return `<button class="primary" data-action="refresh">Refresh status</button>`;
    }

    function buildMetrics() {
      return (appState.cards || []).map((card) => `
        <div class="metric">
          <div class="label">${esc(card.label)}</div>
          <div class="value">${esc(card.value)}</div>
          <div class="detail">${esc(card.detail)}</div>
        </div>
      `).join('');
    }

    function softwareUpdateTone(item) {
      const state = String(item?.state || '').toLowerCase();
      if (item?.blocked) return 'danger';
      if (state === 'available') return 'warning';
      if (state === 'failed' || state === 'missing_recipe') return 'danger';
      if (state === 'provider_ready' || state === 'completed' || state === 'current') return 'good';
      return 'info';
    }

    function softwareUpdatePriority(item) {
      const state = String(item?.state || '').toLowerCase();
      if (item?.blocked) return 0;
      if (state === 'available') return 1;
      if (state === 'provider_ready') return 2;
      if (item?.highRisk) return 3;
      if (item?.manualOnly) return 4;
      if (state === 'failed' || state === 'missing_recipe') return 5;
      return 6;
    }

    function sortSoftwareUpdates(updates, mode) {
      return [...updates].sort((left, right) => {
        const leftName = String(left?.name || '').toLowerCase();
        const rightName = String(right?.name || '').toLowerCase();
        const leftState = String(left?.state || '').toLowerCase();
        const rightState = String(right?.state || '').toLowerCase();
        const leftPublisher = String(left?.publisher || '').toLowerCase();
        const rightPublisher = String(right?.publisher || '').toLowerCase();

        if (mode === 'name') {
          return leftName.localeCompare(rightName);
        }
        if (mode === 'state') {
          const stateCompare = leftState.localeCompare(rightState);
          return stateCompare !== 0 ? stateCompare : leftName.localeCompare(rightName);
        }
        if (mode === 'publisher') {
          const publisherCompare = leftPublisher.localeCompare(rightPublisher);
          return publisherCompare !== 0 ? publisherCompare : leftName.localeCompare(rightName);
        }
        if (mode === 'risk') {
          if (Boolean(left?.highRisk) !== Boolean(right?.highRisk)) {
            return left?.highRisk ? -1 : 1;
          }
        }

        const priorityCompare = softwareUpdatePriority(left) - softwareUpdatePriority(right);
        return priorityCompare !== 0 ? priorityCompare : leftName.localeCompare(rightName);
      });
    }

    function matchesUpdateFilter(item, mode) {
      const state = String(item?.state || '').toLowerCase();
      if (mode === 'actionable') return Boolean(item?.canInstall) || state === 'available' || state === 'provider_ready';
      if (mode === 'manual') return Boolean(item?.manualOnly) || state === 'manual';
      if (mode === 'blocked') return Boolean(item?.blocked);
      if (mode === 'unsupported') return !Boolean(item?.supported) || state === 'unsupported';
      if (mode === 'highrisk') return Boolean(item?.highRisk);
      return true;
    }

    function buildUpdatesDataset() {
      const query = updateSearch.trim().toLowerCase();
      const all = appState.softwareUpdates || [];
      const filtered = all.filter((item) => {
        if (!matchesUpdateFilter(item, updateFilter)) {
          return false;
        }
        if (!query) {
          return true;
        }
        return String(item.name || '').toLowerCase().includes(query) ||
               String(item.publisher || '').toLowerCase().includes(query) ||
               String(item.provider || '').toLowerCase().includes(query) ||
               String(item.state || '').toLowerCase().includes(query) ||
               String(item.summary || '').toLowerCase().includes(query);
      });

      const sorted = sortSoftwareUpdates(filtered, updateSort);
      const pageCount = Math.max(1, Math.ceil(sorted.length / updatesPageSize));
      if (updatePageIndex >= pageCount) {
        updatePageIndex = pageCount - 1;
      }
      const startIndex = updatePageIndex * updatesPageSize;
      const items = sorted.slice(startIndex, startIndex + updatesPageSize);
      return {
        totalCount: sorted.length,
        pageCount,
        pageIndex: updatePageIndex,
        startIndex,
        endIndex: startIndex + items.length,
        items
      };
    }

    function buildSoftwareUpdateCards(items = null, options = {}) {
      const updates = Array.isArray(items) ? items : (appState.softwareUpdates || []);
      const ordered = options.keepOrder ? [...updates] : sortSoftwareUpdates(updates, 'priority');
      const limit = Number.isInteger(options.limit) ? options.limit : 0;
      const visible = limit > 0 ? ordered.slice(0, limit) : ordered;
      if (!visible.length) {
        return `<div class="empty">No software update inventory is available yet. Select Refresh updates to build a local patch view.</div>`;
      }

      const patchBusy = Boolean(appState.patchAction && appState.patchAction.running);
      const patchDisabled = patchBusy ? ' disabled' : '';
      return `${visible.map((item) => {
        const fromVersion = item.version || '(unknown)';
        const toVersion = item.availableVersion || '';
        const state = item.state || 'unknown';
        const stateTone = softwareUpdateTone(item);
        const canInstall = Boolean(item.canInstall);
        const primaryAction = canInstall
          ? `<button class="primary" data-action="softwareUpdate" data-software-id="${esc(item.id)}"${patchDisabled}>Update now</button>`
          : '';

        return `<div class="record">
          <div>
            <div class="record-title">${esc(item.name || 'Unknown software')}</div>
            <div class="record-meta">${esc(item.publisher || '(unknown publisher)')}\n${esc(toVersion ? `${fromVersion} -> ${toVersion}` : fromVersion)}\n${esc(item.summary || '')}</div>
          </div>
          <div class="record-badges">
            ${badgeForTone(stateTone, state)}
            ${badgeForTone(item.highRisk ? 'warning' : 'info', item.highRisk ? 'High risk' : 'Standard risk')}
            ${badgeForTone(item.manualOnly ? 'warning' : 'info', item.manualOnly ? 'Manual workflow' : (item.provider || 'provider'))}
          </div>
          <div class="inline-actions" style="margin-top: 10px; grid-column: 1 / -1; justify-content: flex-start;">
            <button data-action="softwareCheck" data-software-id="${esc(item.id)}"${patchDisabled}>Check</button>
            ${primaryAction}
          </div>
        </div>`;
      }).join('')}${limit > 0 && updates.length > visible.length ? `<div class="empty">Showing ${visible.length} of ${updates.length} software entries. Open the Updates page for full inventory controls.</div>` : ''}`;
    }

    function buildWindowsUpdateSummary(limit = 3) {
      const updates = appState.windowsUpdates || [];
      const top = updates.slice(0, limit);
      if (!top.length) {
        return `Windows Update inventory is currently empty for this device.`;
      }

      return top.map((item) => {
        const kb = item.kb ? ` (${item.kb})` : '';
        const reboot = item.rebootRequired ? 'reboot required' : 'no reboot';
        return `${item.title}${kb} - ${item.classification || 'update'} / ${item.status || 'unknown'} / ${reboot}`;
      }).join('\n');
    }

    function buildSoftwareUpdatesBody() {
      const posture = appState.updates || {};
      const patchAction = appState.patchAction || {};
      const patchBusy = Boolean(patchAction.running);
      const patchDisabled = patchBusy ? ' disabled' : '';
      return `
        <section class="section">
          <div class="section-head">
            <div>
              <div class="eyebrow">Software updates</div>
              <div class="section-title">Patch posture and per-app actions</div>
              <div class="section-text">Review available updates, manual-only software, and reboot posture directly from the endpoint dashboard.</div>
            </div>
            <div class="chip ${posture.rebootRequired ? 'warning' : 'info'}">${posture.rebootRequired ? 'Reboot pending' : 'No reboot pending'}</div>
          </div>
          <div class="status-row">
            <div class="chip ${patchBusy ? 'warning' : 'info'}">${patchBusy ? 'Update task running' : 'Update task idle'}</div>
            ${patchBusy ? `<div class="chip info">${esc(patchAction.status || '')}</div>` : ''}
            <button data-nav="updates">Open full updates page</button>
          </div>
          <div class="hero-status" style="margin-top: 14px;">
            <div class="hero-chip"><div class="label">Windows updates</div><div class="value">${esc(posture.windowsCount ?? 0)}</div><div class="detail">Queued from local Windows Update inventory</div></div>
            <div class="hero-chip"><div class="label">Software available</div><div class="value">${esc(posture.availableSoftwareCount ?? 0)}</div><div class="detail">Auto-capable updates ready to run</div></div>
            <div class="hero-chip"><div class="label">Manual workflows</div><div class="value">${esc(posture.manualSoftwareCount ?? 0)}</div><div class="detail">Require analyst or user-guided steps</div></div>
            <div class="hero-chip"><div class="label">Unsupported / blocked</div><div class="value">${esc((posture.unsupportedSoftwareCount ?? 0) + (posture.blockedSoftwareCount ?? 0))}</div><div class="detail">Coverage gaps and blocked software posture</div></div>
          </div>
          <div class="actions" style="margin-top: 14px;">
            <button data-action="softwareUpdatesRefresh"${patchDisabled}>Refresh updates</button>
            <button data-action="requestWindowsUpdatePam">Request Windows Update (PAM)</button>
            <button data-action="requestNetworkResetPam">Request network reset (PAM)</button>
          </div>
          <div class="source-list" style="margin-top: 14px;">${buildSoftwareUpdateCards(null, { limit: 6 })}</div>
          <div class="detail-card" style="margin-top: 14px;">
            <div class="title">Windows update highlights</div>
            <div class="text">${esc(buildWindowsUpdateSummary())}</div>
          </div>
        </section>`;
    }

    function buildUpdatesPageBody() {
      const posture = appState.updates || {};
      const patchAction = appState.patchAction || {};
      const patchBusy = Boolean(patchAction.running);
      const patchDisabled = patchBusy ? ' disabled' : '';
      const data = buildUpdatesDataset();
      const rangeLabel = data.totalCount === 0 ? '0 of 0' : `${data.startIndex + 1}-${data.endIndex} of ${data.totalCount}`;
      const prevDisabled = data.pageIndex <= 0 ? ' disabled' : '';
      const nextDisabled = data.pageIndex >= data.pageCount - 1 ? ' disabled' : '';

      return `
        <section class="section">
          <div class="section-head">
            <div>
              <div class="eyebrow">Updates</div>
              <div class="section-title">Software update command center</div>
              <div class="section-text">Filter, sort, and execute software update checks or installs from a single workspace.</div>
            </div>
            <div class="chip ${patchBusy ? 'warning' : 'info'}">${patchBusy ? 'Task running' : 'Ready'}</div>
          </div>
          <div class="status-row">
            <div class="chip ${posture.rebootRequired ? 'warning' : 'info'}">${posture.rebootRequired ? 'Reboot pending' : 'No reboot pending'}</div>
            ${patchAction.status ? `<div class="chip info">${esc(patchAction.status)}</div>` : ''}
          </div>
          <div class="filter-row">
            <input id="updateSearch" value="${esc(updateSearch)}" placeholder="Search software, publisher, provider, or state..." />
          </div>
          <div class="subtabs">
            <button class="${updateFilter === 'actionable' ? 'active' : ''}" data-update-filter="actionable">Actionable</button>
            <button class="${updateFilter === 'manual' ? 'active' : ''}" data-update-filter="manual">Manual</button>
            <button class="${updateFilter === 'highrisk' ? 'active' : ''}" data-update-filter="highrisk">High risk</button>
            <button class="${updateFilter === 'blocked' ? 'active' : ''}" data-update-filter="blocked">Blocked</button>
            <button class="${updateFilter === 'unsupported' ? 'active' : ''}" data-update-filter="unsupported">Unsupported</button>
            <button class="${updateFilter === 'all' ? 'active' : ''}" data-update-filter="all">All</button>
          </div>
          <div class="subtabs">
            <button class="${updateSort === 'priority' ? 'active' : ''}" data-update-sort="priority">Sort: Priority</button>
            <button class="${updateSort === 'name' ? 'active' : ''}" data-update-sort="name">Sort: Name</button>
            <button class="${updateSort === 'state' ? 'active' : ''}" data-update-sort="state">Sort: State</button>
            <button class="${updateSort === 'publisher' ? 'active' : ''}" data-update-sort="publisher">Sort: Publisher</button>
            <button class="${updateSort === 'risk' ? 'active' : ''}" data-update-sort="risk">Sort: Risk</button>
          </div>
          <div class="actions" style="margin-top: 10px;">
            <button class="primary" data-action="softwareUpdatesRefresh"${patchDisabled}>Refresh updates</button>
            <button data-action="requestWindowsUpdatePam">Request Windows Update (PAM)</button>
            <button data-action="requestNetworkResetPam">Request network reset (PAM)</button>
          </div>
          <div class="source-list" style="margin-top: 12px;">${buildSoftwareUpdateCards(data.items, { keepOrder: true })}</div>
          <div class="pager">
            <div class="meta">Showing ${esc(rangeLabel)}${data.totalCount > 0 ? ` - page ${data.pageIndex + 1} of ${data.pageCount}` : ''}</div>
            <div class="actions">
              <button data-update-page="prev"${prevDisabled}>Previous</button>
              <button data-update-page="next"${nextDisabled}>Next</button>
            </div>
          </div>
        </section>
        <section class="section">
          <div class="section-head">
            <div>
              <div class="eyebrow">Windows updates</div>
              <div class="section-title">Local Windows Update queue</div>
              <div class="section-text">A condensed view of current Windows Update inventory and reboot impact.</div>
            </div>
            <div class="chip info">${esc(posture.windowsCount ?? 0)} record(s)</div>
          </div>
          <div class="detail-card" style="margin-top: 14px;">
            <div class="title">Windows update summary</div>
            <div class="text">${esc(buildWindowsUpdateSummary(8))}</div>
          </div>
        </section>`;
    }

    function buildRuntimeKv() {
      const runtime = appState.runtime || {};
      const updates = appState.updates || {};
      const patchAction = appState.patchAction || {};
      const pairs = [
        ['Device ID', runtime.deviceId],
        ['Service state', runtime.serviceState],
        ['Health state', runtime.healthState],
        ['Policy', appState.brand ? appState.brand.policy : ''],
        ['Last heartbeat', runtime.lastHeartbeat],
        ['Last policy sync', runtime.lastPolicySync],
        ['Queued telemetry', runtime.queuedTelemetry],
        ['Windows updates', updates.windowsCount ?? 0],
        ['Software updates available', updates.availableSoftwareCount ?? 0],
        ['Update job', patchAction.running ? (patchAction.status || 'running') : 'idle'],
        ['Patch history records', updates.historyCount ?? 0],
        ['Last scan', runtime.lastScan],
        ['Control plane', runtime.controlPlane]
      ];
      return pairs.map(([key, value]) => `<div class="key">${esc(key)}</div><div class="value">${esc(value)}</div>`).join('');
    }

    function selectedItem(pageKey) {
      const rows = rowsFor(pageKey);
      const index = Number.isInteger(selection[pageKey]) ? selection[pageKey] : -1;
      return index >= 0 && index < rows.length ? rows[index] : (rows[0] || null);
    }

    function badgeForTone(tone, text) {
      if (!String(text ?? '').trim()) {
        return '';
      }
      return `<span class="chip ${esc(tone || 'info')}">${esc(text)}</span>`;
    }

    function buildRecordCards(pageKey) {
      const rows = rowsFor(pageKey);
      if (!rows.length) {
        return `<div class="empty">No items are currently recorded for this view.</div>`;
      }

      return `<div class="record-list">${
        rows.map((item, index) => {
          const selected = Number.isInteger(selection[pageKey]) && selection[pageKey] === index;
          if (pageKey === 'threats') {
            return `<button type="button" class="record ${selected ? 'selected' : ''}" data-select="${index}">
              <div>
                <div class="record-title">${esc(item.item)}</div>
                <div class="record-meta">${esc(item.time)}\n${esc(item.source)}</div>
              </div>
              <div class="record-badges">
                ${badgeForTone(item.action === 'block' ? 'danger' : 'warning', item.action)}
                ${badgeForTone('info', `Confidence ${item.confidence}`)}
              </div>
            </button>`;
          }
          if (pageKey === 'quarantine') {
            return `<button type="button" class="record ${selected ? 'selected' : ''}" data-select="${index}">
              <div>
              <div class="record-title">${esc(item.item)}</div>
                <div class="record-meta">${esc(item.time)}\n${esc(item.status)} · ${esc(item.technique)}</div>
              </div>
              <div class="record-badges">
                ${badgeForTone(item.status === 'restored' ? 'good' : 'warning', item.status)}
                ${badgeForTone('info', `${String(item.sha256 || '').slice(0, 12)}…`)}
              </div>
            </button>`;
          }
          const label = item.result || item.kind || 'event';
          return `<button type="button" class="record ${selected ? 'selected' : ''}" data-select="${index}">
            <div>
              <div class="record-title">${esc(item.item || item.result || 'Selected item')}</div>
              <div class="record-meta">${esc(item.time)}\n${esc(item.source || item.detail || '')}</div>
            </div>
            <div class="record-badges">
              ${badgeForTone(item.result === 'blocked' || item.result === 'block' ? 'danger' : 'info', label)}
              ${badgeForTone('info', item.technique || item.kind || '')}
            </div>
          </button>`;
        }).join('')
      }</div>`;
    }

    function buildSelectedDetail(pageKey) {
      if (pageKey === 'settings') {
        return `
          <div class="detail-card">
            <div class="title">${esc(appState.detailTitle)}</div>
            <div class="text">${esc(appState.detailText)}</div>
          </div>
          <div class="detail-card">
            <div class="title">Local configuration</div>
            <div class="detail-grid">${
              (appState.settings || []).map((item) => `
                <div class="key">${esc(item.label)}</div><div class="value">${esc(item.value)}</div>
              `).join('')
            }</div>
            <div class="actions" style="margin-top: 14px;">
              <button class="warning" data-action="openExclusions">Manage exclusions</button>
            </div>
          </div>`;
      }

      const current = selectedItem(pageKey);
      if (!current) {
        return `<div class="detail-card"><div class="title">${esc(appState.detailTitle)}</div><div class="text">${esc(appState.detailText)}</div></div>`;
      }

      const rows = [];
      if (pageKey === 'quarantine') {
        rows.push(['Captured', current.time], ['Original path', current.item], ['Status', current.status], ['Technique', current.technique], ['SHA-256', current.sha256]);
      } else if (pageKey === 'threats') {
        rows.push(['Detected', current.time], ['Item', current.item], ['Action', current.action], ['Confidence', current.confidence], ['ATT&CK', current.attack], ['Remediation', current.remediation], ['Source', current.source], ['SHA-256', current.sha256]);
      } else {
        rows.push(['Recorded', current.time], ['Result', current.result], ['Item', current.item], ['Source', current.source], ['Technique', current.technique], ['Remediation', current.remediation], ['Kind', current.kind]);
      }

      const buttons = pageKey === 'quarantine' ? `
        <div class="actions" style="margin-top: 14px;">
          <button class="good" data-action="quarantineRestore" data-id="${esc(current.id)}">Restore</button>
          <button class="danger" data-action="quarantineDelete" data-id="${esc(current.id)}">Delete</button>
        </div>` : '';

      return `
        <div class="detail-card">
          <div class="title">${esc(current.item || current.result || 'Selected item')}</div>
          <div class="text">${esc(current.detail || appState.detailText)}</div>
        </div>
        <div class="detail-card">
          <div class="detail-grid">${rows.map(([key, value]) => `<div class="key">${esc(key)}</div><div class="value">${esc(value)}</div>`).join('')}</div>
          ${buttons}
        </div>`;
    }

    function buildSettingsOverviewBody() {
      return `
        <section class="section">
          <div class="section-head">
            <div>
              <div class="eyebrow">Settings</div>
              <div class="section-title">Local configuration</div>
              <div class="section-text">Control plane, runtime paths, exclusions, and endpoint preferences.</div>
            </div>
            <div class="chip info">Protected</div>
          </div>
          <div style="margin-top: 14px;">${buildSelectedDetail('settings')}</div>
        </section>`;
    }

    function buildExclusionEntryCard(item) {
      return `
        <div class="record">
          <div>
            <div class="record-title">${esc(item.path)}</div>
            <div class="record-meta">${esc(item.kind || 'Path')} exclusion</div>
          </div>
          <div class="inline-actions">
            <button class="danger" data-action="exclusionsRemove" data-path="${esc(item.path)}">Remove</button>
          </div>
        </div>`;
    }

    function buildProcessCard(item) {
      return `
        <button type="button" class="source-card" data-action="exclusionsAddProcess" data-pid="${esc(item.pid)}">
          <div>
            <div class="source-title">${esc(item.name || 'Process')}</div>
            <div class="source-meta">${esc(item.path || '(path unavailable)')}\nPID ${esc(item.pid)}</div>
          </div>
          <div class="source-badges">
            ${badgeForTone(item.prioritized ? 'warning' : 'info', item.prioritized ? 'Prioritized' : 'Process')}
          </div>
        </button>`;
    }

    function buildSoftwareCard(item) {
      return `
        <button type="button" class="source-card" data-action="exclusionsAddApplication" data-software-id="${esc(item.id)}">
          <div>
            <div class="source-title">${esc(item.name || 'Application')}</div>
            <div class="source-meta">${esc(item.publisher || '(unknown publisher)')}\n${esc(item.version || '')}\n${esc(item.location || '(no install location)')}</div>
          </div>
          <div class="source-badges">
            ${badgeForTone(item.blocked ? 'danger' : 'info', item.blocked ? 'Blocked' : 'Installed')}
          </div>
        </button>`;
    }

    function buildExclusionsBody() {
      const exclusions = appState.exclusions || [];
      const query = exclusionSearch.trim().toLowerCase();
      const filteredExclusions = exclusions.filter((item) => {
        if (!query) return true;
        return String(item.path || '').toLowerCase().includes(query) ||
               String(item.kind || '').toLowerCase().includes(query);
      });
      const processes = (appState.processes || []).filter((item) => {
        if (!query) return true;
        return String(item.name || '').toLowerCase().includes(query) ||
               String(item.path || '').toLowerCase().includes(query) ||
               String(item.pid || '').includes(query);
      });
      const software = (appState.software || []).filter((item) => {
        if (!query) return true;
        return String(item.name || '').toLowerCase().includes(query) ||
               String(item.publisher || '').toLowerCase().includes(query) ||
               String(item.location || '').toLowerCase().includes(query) ||
               String(item.version || '').toLowerCase().includes(query);
      });

      let rightPanel = '';
      if (exclusionMode === 'current') {
        rightPanel = `
          <div class="detail-card">
            <div class="title">Current exclusions</div>
            <div class="text">These paths are trusted by Fenrir and are skipped during scans.</div>
            <div class="source-list" style="margin-top: 12px;">${
              filteredExclusions.length ? filteredExclusions.map((item) => buildExclusionEntryCard(item)).join('') :
                `<div class="empty">No exclusions are configured yet.</div>`
            }</div>
          </div>`;
      } else if (exclusionMode === 'file') {
        rightPanel = `
          <div class="detail-card">
            <div class="title">File exclusion</div>
            <div class="text">Choose a single file to trust. Fenrir will store its full path and skip it in scans.</div>
            <div class="inline-actions" style="margin-top: 12px;">
              <button class="primary" data-action="exclusionsAddFile">Choose file</button>
            </div>
          </div>`;
      } else if (exclusionMode === 'folder') {
        rightPanel = `
          <div class="detail-card">
            <div class="title">Folder exclusion</div>
            <div class="text">Choose a folder to trust. Everything under that path will be skipped by scanning.</div>
            <div class="inline-actions" style="margin-top: 12px;">
              <button class="primary" data-action="exclusionsAddFolder">Choose folder</button>
            </div>
          </div>`;
      } else if (exclusionMode === 'process') {
        rightPanel = `
          <div class="detail-card">
            <div class="title">Process exclusion</div>
            <div class="text">Pick from the current running processes Fenrir sees on this device.</div>
            <div class="filter-row"><input id="exclusionSearch" value="${esc(exclusionSearch)}" placeholder="Search running processes..." /></div>
            <div class="source-list">${
              processes.length ? processes.map((item) => buildProcessCard(item)).join('') :
                `<div class="empty">No matching processes were found.</div>`
            }</div>
          </div>`;
      } else if (exclusionMode === 'application') {
        rightPanel = `
          <div class="detail-card">
            <div class="title">Application exclusion</div>
            <div class="text">Pick from the installed software list collected on this endpoint.</div>
            <div class="filter-row"><input id="exclusionSearch" value="${esc(exclusionSearch)}" placeholder="Search installed software..." /></div>
            <div class="source-list">${
              software.length ? software.map((item) => buildSoftwareCard(item)).join('') :
                `<div class="empty">No matching software was found.</div>`
            }</div>
          </div>`;
      }

      const currentCount = exclusions.length;
      return `
        <section class="section">
          <div class="section-head">
            <div>
              <div class="eyebrow">Exclusions</div>
              <div class="section-title">Trusted paths and application targets</div>
              <div class="section-text">Use file, folder, process, and application sources to build exclusions without leaving Fenrir.</div>
            </div>
            <div class="chip ${currentCount === 0 ? 'info' : 'warning'}">${currentCount} trusted path(s)</div>
          </div>
          <div class="subtabs">
            <button class="${exclusionMode === 'current' ? 'active' : ''}" data-exclusion-mode="current">Current list</button>
            <button class="${exclusionMode === 'file' ? 'active' : ''}" data-exclusion-mode="file">File</button>
            <button class="${exclusionMode === 'folder' ? 'active' : ''}" data-exclusion-mode="folder">Folder</button>
            <button class="${exclusionMode === 'process' ? 'active' : ''}" data-exclusion-mode="process">Process</button>
            <button class="${exclusionMode === 'application' ? 'active' : ''}" data-exclusion-mode="application">Application</button>
          </div>
          <div class="exclusion-shell" style="margin-top: 14px;">
            <div class="detail-card">
              <div class="title">Configured exclusions</div>
              <div class="text">These exclusions are stored for the Fenrir service and applied at system level.</div>
              <div class="source-list" style="margin-top: 12px;">${
                filteredExclusions.length ? filteredExclusions.map((item) => buildExclusionEntryCard(item)).join('') :
                  `<div class="empty">No exclusions are configured yet.</div>`
              }</div>
            </div>
            ${rightPanel}
          </div>
        </section>`;
    }

    function buildDashboardBody() {
      const recent = (appState.history || []).slice(0, 5);
      return `
        <section class="section">
          <div class="section-head">
            <div>
              <div class="eyebrow">Protection status</div>
              <div class="section-title">${esc(appState.headline || '')}</div>
              <div class="section-text">${esc(appState.guidance || '')}</div>
            </div>
            <div class="chip ${esc(appState.statusTone || 'info')}">${esc(appState.statusChip || '')}</div>
          </div>
          <div class="actions" style="margin-top: 14px;">${buildHeroActions()}</div>
          <div class="hero-status" style="margin-top: 14px;">${buildMetrics()}</div>
        </section>
        ${buildSoftwareUpdatesBody()}
        <section class="section">
          <div class="section-head">
            <div>
              <div class="eyebrow">Recent activity</div>
              <div class="section-title">What changed recently</div>
              <div class="section-text">Only the most important actions and detections are shown here.</div>
            </div>
            <div class="chip info">${recent.length} items</div>
          </div>
          <div class="record-list" style="margin-top: 14px;">${
            recent.map((item, index) => {
              const title = item.item || item.result || 'Event';
              return `<button type="button" class="record ${index === 0 ? 'selected' : ''}" data-select="${index}">
                <div>
                  <div class="record-title">${esc(title)}</div>
                  <div class="record-meta">${esc(item.time)}\n${esc(item.source || item.kind || '')}</div>
                </div>
                <div class="record-badges">
                  ${badgeForTone(item.result === 'blocked' || item.result === 'block' ? 'danger' : 'info', item.result || 'event')}
                  ${badgeForTone('info', item.technique || item.remediation || '')}
                </div>
              </button>`;
            }).join('')
          }</div>
        </section>
        <section class="section">
          <div class="section-head">
            <div>
              <div class="eyebrow">Runtime snapshot</div>
              <div class="section-title">Local protection state</div>
              <div class="section-text">Service, policy, telemetry, and sync status for this endpoint.</div>
            </div>
          </div>
          <div class="kv" style="margin-top: 12px;">${buildRuntimeKv()}</div>
        </section>`;
    }

    function buildPageBody(pageKey) {
      if (pageKey === 'dashboard') {
        return buildDashboardBody();
      }

      if (pageKey === 'threats') {
        return `
          <section class="section">
            <div class="section-head">
              <div>
                <div class="eyebrow">Findings</div>
                <div class="section-title">Active detections</div>
                <div class="section-text">Keep this page focused on items that still need a decision.</div>
              </div>
              <div class="chip ${esc(appState.statusTone || 'info')}">${esc(appState.threats?.length ? `${appState.threats.length} detected` : 'No current detections')}</div>
            </div>
            <div style="margin-top: 14px;">${buildRecordCards('threats')}</div>
          </section>
          <section class="section">
            <div class="section-head">
              <div>
                <div class="eyebrow">Selected finding</div>
                <div class="section-title">Why Fenrir flagged it</div>
                <div class="section-text">Selected item details, ATT&CK mapping, and recommended next steps.</div>
              </div>
            </div>
            <div style="margin-top: 14px;">${buildSelectedDetail('threats')}</div>
          </section>`;
      }

      if (pageKey === 'quarantine') {
        return `
          <section class="section">
            <div class="section-head">
              <div>
                <div class="eyebrow">Quarantine</div>
                <div class="section-title">Contained items</div>
                <div class="section-text">Restore only when you are confident the file is safe.</div>
              </div>
              <div class="chip info">${esc(appState.quarantine?.length ? `${appState.quarantine.length} contained` : 'Empty')}</div>
            </div>
            <div style="margin-top: 14px;">${buildRecordCards('quarantine')}</div>
          </section>
          <section class="section">
            <div class="section-head">
              <div>
                <div class="eyebrow">Selected item</div>
                <div class="section-title">Original path and remediation</div>
                <div class="section-text">Use the actions below to restore or delete the selected entry.</div>
              </div>
            </div>
            <div style="margin-top: 14px;">${buildSelectedDetail('quarantine')}</div>
          </section>`;
      }

      if (pageKey === 'scans') {
        const currentScan = appState.scan || {};
        return `
          <section class="section">
            <div class="section-head">
              <div>
                <div class="eyebrow">Scans</div>
                <div class="section-title">Launch and track scans</div>
                <div class="section-text">Quick, full, and folder scans all report progress here.</div>
              </div>
              <div class="chip ${currentScan.running ? 'warning' : 'info'}">${currentScan.running ? 'Scan running' : 'Idle'}</div>
            </div>
            <div class="actions" style="margin-top: 14px;">${buildActions()}</div>
            <div class="detail-card" style="margin-top: 14px;">
              <div class="title">${esc(currentScan.label || 'No active scan')}</div>
              <div class="text">${esc(currentScan.status || appState.detailText || 'Ready.')}</div>
              <div style="margin-top: 12px;"><progress value="${Number(currentScan.completed || 0)}" max="${Math.max(Number(currentScan.total || 100), 1)}"></progress></div>
            </div>
          </section>
          <section class="section">
            <div class="section-head">
              <div>
                <div class="eyebrow">Recent scan history</div>
                <div class="section-title">Latest sessions</div>
                <div class="section-text">Recent scans are recorded as a simple activity stream.</div>
              </div>
            </div>
            <div style="margin-top: 14px;">${buildRecordCards('scans')}</div>
          </section>`;
      }

      if (pageKey === 'updates') {
        return buildUpdatesPageBody();
      }

      if (pageKey === 'history') {
        return `
          <section class="section">
            <div class="section-head">
              <div>
                <div class="eyebrow">History</div>
                <div class="section-title">Activity timeline</div>
                <div class="section-text">Important protection and response events, ordered by recency.</div>
              </div>
              <div class="chip info">${esc((appState.history || []).length)} events</div>
            </div>
            <div style="margin-top: 14px;">${buildRecordCards('history')}</div>
          </section>
          <section class="section">
            <div class="section-head">
              <div>
                <div class="eyebrow">Selected event</div>
                <div class="section-title">Evidence and remediation</div>
                <div class="section-text">The selected event’s context is shown below.</div>
              </div>
            </div>
            <div style="margin-top: 14px;">${buildSelectedDetail('history')}</div>
          </section>`;
      }

      if (pageKey === 'settings') {
        if (appState.manageExclusionsMode) {
          return buildExclusionsBody();
        }
        return buildSettingsOverviewBody();
      }

      return buildDashboardBody();
    }

    function listColumns(pageKey) {
      if (pageKey === 'threats') return ['Time', 'Item', 'Action', 'Confidence', 'ATT&CK', 'Remediation'];
      if (pageKey === 'quarantine') return ['Captured', 'Original path', 'Status', 'Technique', 'SHA-256'];
      if (pageKey === 'scans' || pageKey === 'history' || pageKey === 'dashboard') return ['Time', 'Result', 'Item', 'Source', 'Technique', 'Remediation'];
      return ['Label', 'Value'];
    }

    function buildList(pageKey) {
      const rows = rowsFor(pageKey);
      if (pageKey === 'settings') {
        return `<div class="list-grid">${
          (appState.settings || []).map((item) => `
            <div class="list-card">
              <div class="title">${esc(item.label)}</div>
              <div class="meta">${esc(item.value)}</div>
            </div>`).join('')
        }</div>`;
      }

      if (!rows.length) {
        return `<div class="empty">No items are currently recorded for this view.</div>`;
      }

      const header = listColumns(pageKey).map((column) => `<th>${esc(column)}</th>`).join('');
      const body = rows.map((item, index) => {
        const selected = Number.isInteger(selection[pageKey]) && selection[pageKey] === index;
        if (pageKey === 'threats') {
          return `<tr class="${selected ? 'selected' : ''}" data-select="${index}">
            <td>${esc(item.time)}</td>
            <td>${esc(item.item)}<span class="secondary">${esc(item.source)}</span></td>
            <td>${esc(item.action)}</td>
            <td>${esc(item.confidence)}</td>
            <td>${esc(item.attack)}</td>
            <td>${esc(item.remediation)}</td>
          </tr>`;
        }
        if (pageKey === 'quarantine') {
          return `<tr class="${selected ? 'selected' : ''}" data-select="${index}">
            <td>${esc(item.time)}</td>
            <td>${esc(item.item)}<span class="secondary">${esc(item.detail)}</span></td>
            <td>${esc(item.status)}</td>
            <td>${esc(item.technique)}</td>
            <td>${esc(item.sha256)}</td>
          </tr>`;
        }
        return `<tr class="${selected ? 'selected' : ''}" data-select="${index}">
          <td>${esc(item.time)}</td>
          <td>${esc(item.result)}</td>
          <td>${esc(item.item)}<span class="secondary">${esc(item.kind || item.detail || '')}</span></td>
          <td>${esc(item.source)}</td>
          <td>${esc(item.technique)}</td>
          <td>${esc(item.remediation)}</td>
        </tr>`;
      }).join('');

      return `<table><thead><tr>${header}</tr></thead><tbody>${body}</tbody></table>`;
    }

    function buildDetail(pageKey) {
      if (pageKey === 'settings') {
        return `
          <div class="detail-card">
            <div class="title">${esc(appState.detailTitle)}</div>
            <div class="text">${esc(appState.detailText)}</div>
          </div>
          <div class="detail-card">
            <div class="title">Local configuration</div>
            <div class="kv">${
              (appState.settings || []).map((item) => `
                <div class="key">${esc(item.label)}</div><div class="value">${esc(item.value)}</div>
              `).join('')
            }</div>
            <div class="actions" style="margin-top: 14px;">
              <button class="warning" data-action="openExclusions">Edit exclusions</button>
            </div>
          </div>`;
      }

      const current = activeItem(pageKey);
      if (!current) {
        return `<div class="detail-card"><div class="title">${esc(appState.detailTitle)}</div><div class="text">${esc(appState.detailText)}</div></div>`;
      }

      const rows = [];
      if (pageKey === 'quarantine') {
        rows.push(['Captured', current.time], ['Original path', current.item], ['Status', current.status], ['Technique', current.technique], ['SHA-256', current.sha256]);
      } else if (pageKey === 'threats') {
        rows.push(['Detected', current.time], ['Item', current.item], ['Action', current.action], ['Confidence', current.confidence], ['ATT&CK', current.attack], ['Remediation', current.remediation], ['Source', current.source], ['SHA-256', current.sha256]);
      } else {
        rows.push(['Recorded', current.time], ['Result', current.result], ['Item', current.item], ['Source', current.source], ['Technique', current.technique], ['Remediation', current.remediation], ['Kind', current.kind]);
      }

      const buttons = pageKey === 'quarantine' ? `
        <div class="actions" style="margin-top: 14px;">
          <button class="good" data-action="quarantineRestore" data-id="${esc(current.id)}">Restore</button>
          <button class="danger" data-action="quarantineDelete" data-id="${esc(current.id)}">Delete</button>
        </div>` : '';

      return `
        <div class="detail-card">
          <div class="title">${esc(current.item || current.result || 'Selected item')}</div>
          <div class="text">${esc(current.detail || appState.detailText)}</div>
        </div>
        <div class="detail-card">
          <div class="kv">${rows.map(([key, value]) => `<div class="key">${esc(key)}</div><div class="value">${esc(value)}</div>`).join('')}</div>
          ${buttons}
        </div>`;
    }

    function render(pageState) {
      appState = pageState;
      if (!pageState.manageExclusionsMode || pageState.pageKey !== 'settings') {
        exclusionMode = 'current';
        exclusionSearch = '';
      }
      document.getElementById('brandDevice').textContent = pageState.brand?.device || '';
      document.getElementById('brandMeta').textContent = `${pageState.brand?.status || ''}\n${pageState.brand?.policy || ''}`;
      document.getElementById('pageTitle').textContent = pageState.pageTitle || '';
      document.getElementById('pageSubtitle').textContent = pageState.pageSubtitle || '';
      const chip = document.getElementById('statusChip');
      chip.className = `chip ${pageState.statusTone || 'info'}`;
      chip.textContent = pageState.statusChip || '';
      document.getElementById('actions').innerHTML = buildActions();
      buildNav();
      buildTabs();
      document.getElementById('foot').textContent = `${pageState.runtime?.queuedTelemetry || ''} queued upload(s) • ${pageState.runtime?.controlPlane || ''}`;
      const pageBody = document.getElementById('pageBody');
      if (pageBody) {
        pageBody.innerHTML = buildPageBody(pageState.pageKey || 'dashboard');
      }
    }

    document.addEventListener('click', (event) => {
      const target = event.target.closest('[data-nav], [data-action], [data-select], [data-exclusion-mode], [data-update-filter], [data-update-sort], [data-update-page]');
      if (!target) return;
      if (target.dataset.exclusionMode) {
        exclusionMode = target.dataset.exclusionMode;
        if (exclusionMode === 'current') {
          exclusionSearch = '';
        }
        render(appState);
        return;
      }
      if (target.dataset.updateFilter) {
        updateFilter = target.dataset.updateFilter;
        updatePageIndex = 0;
        render(appState);
        return;
      }
      if (target.dataset.updateSort) {
        updateSort = target.dataset.updateSort;
        updatePageIndex = 0;
        render(appState);
        return;
      }
      if (target.dataset.updatePage) {
        const data = buildUpdatesDataset();
        if (target.dataset.updatePage === 'prev' && data.pageIndex > 0) {
          updatePageIndex = data.pageIndex - 1;
        }
        if (target.dataset.updatePage === 'next' && data.pageIndex < data.pageCount - 1) {
          updatePageIndex = data.pageIndex + 1;
        }
        render(appState);
        return;
      }
      if (target.dataset.nav) {
        send(actionMessage('navigate', { page: target.dataset.nav }));
        return;
      }
      if (target.dataset.select) {
        selection[appState.pageKey] = Number(target.dataset.select);
        render(appState);
        return;
      }
      if (target.dataset.action) {
        if (target.dataset.action === 'setQuickScanInterval' || target.dataset.action === 'setFullScanInterval') {
          const isQuick = target.dataset.action === 'setQuickScanInterval';
          const currentValue = Number(isQuick ? appState.runtime?.quickScanIntervalMinutes : appState.runtime?.fullScanIntervalMinutes);
          const fallbackValue = isQuick ? 1440 : 10080;
          const minValue = isQuick ? 15 : 60;
          const maxValue = isQuick ? 10080 : 43200;
          const promptTitle = isQuick
            ? 'Set quick scan interval (minutes). 1440 = once every 24 hours.'
            : 'Set full scan interval (minutes). 10080 = once every 7 days.';
          const input = window.prompt(promptTitle, String(Number.isFinite(currentValue) ? currentValue : fallbackValue));
          if (input === null) return;
          const minutes = Number.parseInt(input, 10);
          if (!Number.isFinite(minutes) || minutes < minValue || minutes > maxValue) {
            window.alert(`Enter a whole number between ${minValue} and ${maxValue} minutes.`);
            return;
          }
          const payload = { action: target.dataset.action, minutes: String(minutes) };
          send(new URLSearchParams(payload).toString());
          return;
        }

        const payload = { action: target.dataset.action };
        if (target.dataset.preset) payload.preset = target.dataset.preset;
        if (target.dataset.page) payload.page = target.dataset.page;
        if (target.dataset.id) payload.id = target.dataset.id;
        if (target.dataset.softwareId) payload['software-id'] = target.dataset.softwareId;
        if (target.dataset.path) payload.path = target.dataset.path;
        send(new URLSearchParams(payload).toString());
      }
    });

    document.addEventListener('input', (event) => {
      const target = event.target;
      if (target && target.id === 'exclusionSearch') {
        exclusionSearch = target.value || '';
        render(appState);
        return;
      }
      if (target && target.id === 'updateSearch') {
        updateSearch = target.value || '';
        updatePageIndex = 0;
        render(appState);
      }
    });

    if (window.chrome && window.chrome.webview) {
      window.chrome.webview.addEventListener('message', (event) => render(event.data));
    }

    render(initialState);
  </script>
</body>
</html>
)HTML";

  html = ReplaceAll(std::move(html), L"__FENRIR_LOGO_URI__", context.webViewLogoDataUri);
  html = ReplaceAll(std::move(html), L"__FENRIR_INITIAL_STATE__", BuildWebViewStateJson(context));
  return html;
}

std::wstring HresultToHex(const HRESULT value) {
  std::wstringstream stream;
  stream << L"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0')
         << static_cast<unsigned long>(value);
  return stream.str();
}

std::wstring BuildWebViewFallbackStatus(const UiContext& context) {
  if (!context.webViewFailureReason.empty()) {
    return context.webViewFailureReason;
  }

  return L"Modern Fenrir UI is unavailable because Microsoft Edge WebView2 Runtime is missing. Install WebView2 Runtime and restart Fenrir Protection Centre.";
}

void HideNativeShellControls(UiContext& context, const bool visible) {
  const auto showCommand = visible ? SW_SHOW : SW_HIDE;
  const std::array<HWND, 34> controls{
      context.brandCard,          context.brandLogo,           context.brandSummary,        context.titleLabel,
      context.subtitleLabel,      context.statusBadge,         context.primarySectionTitle, context.secondarySectionTitle,
      context.summaryCard,        context.detailsCard,         context.metricThreats,       context.metricQuarantine,
      context.metricService,      context.metricSync,         context.scanStatusLabel,     context.progressBar,
      context.threatsList,        context.quarantineList,      context.historyList,         context.detailEdit,
      context.refreshButton,      context.quickScanButton,     context.fullScanButton,      context.customScanButton,
      context.startServiceButton,  context.openQuarantineButton, context.restoreButton,      context.deleteButton,
      context.navDashboardButton,  context.navThreatsButton,    context.navQuarantineButton, context.navScansButton,
      context.navHistoryButton,   context.navSettingsButton};

  for (const auto control : controls) {
    if (control != nullptr) {
      ShowWindow(control, showCommand);
    }
  }
}

void ResizeWebView(UiContext& context) {
  if (!context.webViewReady || context.webViewController == nullptr) {
    return;
  }

  RECT client{};
  GetClientRect(context.hwnd, &client);
  context.webViewController->put_Bounds(client);
}

void PublishWebViewState(UiContext& context) {
  if (!context.webViewReady || context.webView == nullptr) {
    return;
  }

  const auto json = BuildWebViewStateJson(context);
  context.webView->PostWebMessageAsJson(json.c_str());
}

void DestroyWebViewHost(UiContext& context) {
  context.webViewReady = false;
  if (context.webView != nullptr && context.webMessageReceivedToken.value != 0) {
    context.webView->remove_WebMessageReceived(context.webMessageReceivedToken);
    context.webMessageReceivedToken.value = 0;
  }
  context.webView.Reset();
  context.webViewController.Reset();
  context.webViewEnvironment.Reset();
  if (context.webViewLoaderModule != nullptr) {
    FreeLibrary(context.webViewLoaderModule);
    context.webViewLoaderModule = nullptr;
  }
}

bool InitializeWebViewHost(UiContext& context) {
  if (context.webViewReady || context.webViewEnabled) {
    return true;
  }

  context.webViewFallbackActive = false;
  context.webViewFailureReason.clear();

  const auto currentExecutable = GetCurrentExecutablePath();
  if (currentExecutable.empty()) {
    context.webViewFallbackActive = true;
    context.webViewFailureReason = L"Modern Fenrir UI is unavailable because the client executable path could not be resolved.";
    return false;
  }

  const auto loaderPath = std::filesystem::path(currentExecutable).parent_path() / L"WebView2Loader.dll";
  if (!std::filesystem::exists(loaderPath)) {
    context.webViewFallbackActive = true;
    context.webViewFailureReason =
        L"Modern Fenrir UI is unavailable because WebView2Loader.dll is missing from the install directory.";
    return false;
  }

  context.webViewLoaderModule = LoadLibraryW(loaderPath.c_str());
  if (context.webViewLoaderModule == nullptr) {
    context.webViewFallbackActive = true;
    context.webViewFailureReason = L"Modern Fenrir UI is unavailable because WebView2Loader.dll could not be loaded.";
    return false;
  }

  using CreateEnvironmentFn = HRESULT(WINAPI*)(PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions*,
                                              ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);
  const auto createEnvironment = reinterpret_cast<CreateEnvironmentFn>(
      GetProcAddress(context.webViewLoaderModule, "CreateCoreWebView2EnvironmentWithOptions"));
  if (createEnvironment == nullptr) {
    context.webViewFallbackActive = true;
    context.webViewFailureReason =
        L"Modern Fenrir UI is unavailable because the WebView2 loader export could not be resolved.";
    DestroyWebViewHost(context);
    return false;
  }

  context.webViewLogoDataUri = LoadFenrirLogoDataUri();
  context.webViewEnabled = true;
  const auto userDataFolder = GetWebViewUserDataFolder();
  if (userDataFolder.empty()) {
    context.webViewFallbackActive = true;
    context.webViewFailureReason =
        L"Modern Fenrir UI is unavailable because the WebView2 user-data location could not be prepared.";
    DestroyWebViewHost(context);
    return false;
  }
  std::error_code error;
  std::filesystem::create_directories(userDataFolder, error);

  const auto hwnd = context.hwnd;
  ComPtr<WebViewEnvironmentCompletedHandler> environmentHandler =
      new WebViewEnvironmentCompletedHandler([hwnd](HRESULT errorCode, ICoreWebView2Environment* environment) -> HRESULT {
        auto* callbackContext = GetContext(hwnd);
        if (callbackContext == nullptr) {
          return S_OK;
        }

        if (FAILED(errorCode) || environment == nullptr) {
          callbackContext->webViewFallbackActive = true;
          callbackContext->webViewFailureReason =
              L"Modern Fenrir UI is unavailable because WebView2 runtime initialization failed (" +
              HresultToHex(errorCode) +
              L"). Install Microsoft Edge WebView2 Runtime and restart Fenrir Protection Centre.";
          callbackContext->webViewEnabled = false;
          DestroyWebViewHost(*callbackContext);
          return S_OK;
        }

        callbackContext->webViewEnvironment = environment;
        ComPtr<WebViewControllerCompletedHandler> controllerHandler =
            new WebViewControllerCompletedHandler([hwnd](HRESULT controllerError, ICoreWebView2Controller* controller) -> HRESULT {
              auto* controllerContext = GetContext(hwnd);
              if (controllerContext == nullptr) {
                return S_OK;
              }

              if (FAILED(controllerError) || controller == nullptr) {
                controllerContext->webViewFallbackActive = true;
                controllerContext->webViewFailureReason =
                    L"Modern Fenrir UI is unavailable because WebView2 controller creation failed (" +
                    HresultToHex(controllerError) +
                    L"). Install Microsoft Edge WebView2 Runtime and restart Fenrir Protection Centre.";
                controllerContext->webViewEnabled = false;
                DestroyWebViewHost(*controllerContext);
                return S_OK;
              }

              controllerContext->webViewController = controller;
              controllerContext->webViewController->put_IsVisible(TRUE);
              controllerContext->webViewController->get_CoreWebView2(&controllerContext->webView);
              if (controllerContext->webView == nullptr) {
                controllerContext->webViewFallbackActive = true;
                controllerContext->webViewFailureReason =
                    L"Modern Fenrir UI is unavailable because the WebView2 runtime host did not return a browser instance.";
                controllerContext->webViewEnabled = false;
                DestroyWebViewHost(*controllerContext);
                return S_OK;
              }

              if (ComPtr<ICoreWebView2Settings> settings;
                  controllerContext->webView->get_Settings(&settings) == S_OK && settings != nullptr) {
                settings->put_AreDevToolsEnabled(FALSE);
                settings->put_AreDefaultContextMenusEnabled(FALSE);
                settings->put_IsStatusBarEnabled(FALSE);
              }

              ComPtr<ICoreWebView2Controller2> controller2;
              if (controllerContext->webViewController != nullptr &&
                  SUCCEEDED(controllerContext->webViewController->QueryInterface(
                      IID_ICoreWebView2Controller2, reinterpret_cast<void**>(controller2.GetAddressOf()))) &&
                  controller2 != nullptr) {
                COREWEBVIEW2_COLOR background{};
                background.R = 7;
                background.G = 11;
                background.B = 17;
                background.A = 255;
                controller2->put_DefaultBackgroundColor(background);
              }

              ComPtr<WebViewMessageReceivedHandler> messageHandler =
                  new WebViewMessageReceivedHandler([hwnd](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                    auto* messageContext = GetContext(hwnd);
                    if (messageContext == nullptr || args == nullptr) {
                      return S_OK;
                    }

                    LPWSTR message = nullptr;
                    if (args->TryGetWebMessageAsString(&message) == S_OK && message != nullptr) {
                      HandleWebViewMessage(*messageContext, message);
                      CoTaskMemFree(message);
                    }
                    return S_OK;
                  });
              controllerContext->webView->add_WebMessageReceived(messageHandler.Get(),
                                                                  &controllerContext->webMessageReceivedToken);

              controllerContext->webViewFallbackActive = false;
              controllerContext->webViewFailureReason.clear();
              controllerContext->webViewReady = true;
              HideNativeShellControls(*controllerContext, false);
              ResizeWebView(*controllerContext);
              controllerContext->webView->NavigateToString(BuildWebViewHtml(*controllerContext).c_str());
              PublishWebViewState(*controllerContext);
              return S_OK;
            });

        environment->CreateCoreWebView2Controller(hwnd, controllerHandler.Get());
        return S_OK;
      });

  const auto userDataFolderPath = userDataFolder.wstring();
  const auto result = createEnvironment(nullptr, userDataFolderPath.c_str(), nullptr, environmentHandler.Get());
  if (FAILED(result)) {
    context.webViewFallbackActive = true;
    context.webViewFailureReason =
        L"Modern Fenrir UI is unavailable because WebView2 runtime startup failed (" +
        HresultToHex(result) +
        L"). Install Microsoft Edge WebView2 Runtime and restart Fenrir Protection Centre.";
    DestroyWebViewHost(context);
    return false;
  }

  return true;
}

void PopulateThreatsList(UiContext& context) {
  ListView_DeleteAllItems(context.threatsList);
  int row = 0;
  for (const auto& record : context.snapshot.recentThreats) {
    const auto attack = record.techniqueId.empty() ? record.tacticId : record.tacticId + L" / " + record.techniqueId;
    InsertListViewRow(context.threatsList, row++,
                      {record.recordedAt,
                       record.alertTitle.empty() ? ThreatDisplayPath(record) : record.alertTitle,
                       record.disposition,
                       std::to_wstring(record.confidence),
                       HistoryContextLabel(record),
                       record.remediationStatus.empty() ? std::wstring(L"(none)") : record.remediationStatus});
  }
}

void PopulateQuarantineList(UiContext& context) {
  ListView_DeleteAllItems(context.quarantineList);
  int row = 0;
  for (const auto& record : context.snapshot.quarantineItems) {
    InsertListViewRow(context.quarantineList, row++,
                      {record.capturedAt,
                       record.originalPath.wstring(),
                       record.localStatus,
                       record.techniqueId.empty() ? std::wstring(L"(n/a)") : record.techniqueId,
                       record.sha256.empty() ? std::wstring(L"(unavailable)") : record.sha256});
  }
}

void PopulateHistoryList(UiContext& context) {
  ListView_DeleteAllItems(context.historyList);
  int row = 0;
  for (const auto& record : context.snapshot.recentFindings) {
    if (context.currentPage == ClientPage::Scans && !IsScanSessionRecord(record)) {
      continue;
    }

    InsertListViewRow(context.historyList, row++,
                      {record.recordedAt,
                       HistoryDispositionLabel(record),
                      record.alertTitle.empty() ? ThreatDisplayPath(record) : record.alertTitle,
                      HistoryContextLabel(record),
                      record.originReference.empty() ? HistorySourceLabel(record.source) : record.originReference,
                      record.remediationStatus.empty() ? std::wstring(L"(none)") : record.remediationStatus});
  }
}

std::wstring BuildThreatFingerprint(const EndpointClientSnapshot& snapshot) {
  if (snapshot.recentThreats.empty()) {
    return {};
  }

  const auto& record = snapshot.recentThreats.front();
  return record.recordedAt + L"|" + record.subjectPath.wstring() + L"|" + record.disposition + L"|" +
         record.techniqueId + L"|" + record.sha256;
}

bool ServiceStateNeedsNotification(const LocalServiceState state) {
  switch (state) {
    case LocalServiceState::Running:
    case LocalServiceState::StartPending:
      return false;
    case LocalServiceState::NotInstalled:
    case LocalServiceState::Stopped:
    case LocalServiceState::StopPending:
    case LocalServiceState::Paused:
    case LocalServiceState::Unknown:
    default:
      return true;
  }
}

std::wstring BuildThreatNotificationBody(const EndpointClientSnapshot& snapshot) {
  if (snapshot.recentThreats.empty()) {
    return L"The endpoint has local detections that need attention.";
  }

  const auto& record = snapshot.recentThreats.front();
  std::wstringstream stream;
  const auto displayPath = record.subjectPath.empty() ? std::wstring{} : record.subjectPath.wstring();
  const auto displayTarget = record.subjectPath.filename().empty() ? record.subjectPath.wstring()
                                                                   : record.subjectPath.filename().wstring();
  stream << L"Blocked: " << NullableText(displayTarget, L"Suspicious content") << L".";
  if (!displayPath.empty()) {
    stream << L"\r\nLocation: " << displayPath;
  }
  if (snapshot.openThreatCount > 1) {
    stream << L"\r\n" << snapshot.openThreatCount
           << L" blocked item(s) need review. Open Fenrir to decide whether they should stay quarantined or be removed.";
  } else {
    stream << L"\r\nReview the item in Fenrir to decide whether it should stay quarantined or be removed.";
  }
  return stream.str();
}

std::wstring BuildServiceNotificationBody(const EndpointClientSnapshot& snapshot) {
  std::wstringstream stream;
  stream << L"Background protection changed to "
         << antivirus::agent::LocalServiceStateToString(snapshot.serviceState) << L".";
  if (!snapshot.agentState.healthState.empty()) {
    stream << L" Runtime health is " << snapshot.agentState.healthState << L".";
  }
  return stream.str();
}

void ShowTrayNotification(UiContext& context, const std::wstring& title, const std::wstring& body,
                          const DWORD infoFlags) {
  UpdateTrayIcon(context);
  context.trayIcon.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON | NIF_INFO;
  wcsncpy_s(context.trayIcon.szInfoTitle, title.c_str(), _TRUNCATE);
  wcsncpy_s(context.trayIcon.szInfo, body.c_str(), _TRUNCATE);
  context.trayIcon.dwInfoFlags = infoFlags | NIIF_LARGE_ICON;
  context.trayIcon.uTimeout = 10000;
  Shell_NotifyIconW(NIM_MODIFY, &context.trayIcon);
}

void UpdateNotificationBaseline(UiContext& context, const EndpointClientSnapshot& snapshot) {
  context.lastObservedThreatCount = snapshot.openThreatCount;
  context.lastObservedServiceState = snapshot.serviceState;
  context.lastThreatFingerprint = BuildThreatFingerprint(snapshot);
  context.snapshotPrimed = true;
}

void EvaluateNotifications(UiContext& context, const EndpointClientSnapshot& snapshot) {
  const auto notificationsVisible = !IsWindowInteractive(context);
  const auto threatFingerprint = BuildThreatFingerprint(snapshot);

  bool notifyThreats = false;
  bool notifyService = false;
  if (!context.snapshotPrimed) {
    notifyThreats = context.backgroundMode && snapshot.openThreatCount != 0;
    notifyService = context.backgroundMode && ServiceStateNeedsNotification(snapshot.serviceState);
  } else if (notificationsVisible) {
    notifyThreats = snapshot.openThreatCount != 0 &&
                    (snapshot.openThreatCount > context.lastObservedThreatCount ||
                     (!threatFingerprint.empty() && threatFingerprint != context.lastThreatFingerprint));
    notifyService = snapshot.serviceState != context.lastObservedServiceState &&
                    ServiceStateNeedsNotification(snapshot.serviceState);
  }

  if (notifyThreats) {
    ShowTrayNotification(context,
                         snapshot.openThreatCount == 1 ? L"Finding detected on this device" : L"Multiple findings detected",
                         BuildThreatNotificationBody(snapshot), NIIF_WARNING);
  } else if (notifyService) {
    ShowTrayNotification(context, L"Protection service needs attention", BuildServiceNotificationBody(snapshot),
                         NIIF_WARNING);
  }

  UpdateNotificationBaseline(context, snapshot);
}

void UpdateTrayIcon(UiContext& context) {
  context.trayIcon.cbSize = sizeof(context.trayIcon);
  context.trayIcon.hWnd = context.hwnd;
  context.trayIcon.uID = 1;
  context.trayIcon.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON;
  context.trayIcon.uCallbackMessage = kTrayMessage;
  context.trayIcon.hIcon = SelectTrayIcon(context);

  const auto tooltip = ProtectionHeadline(context.snapshot) + L" | " + NullableText(context.snapshot.agentState.hostname);
  wcsncpy_s(context.trayIcon.szTip, tooltip.c_str(), _TRUNCATE);

  Shell_NotifyIconW(context.trayAdded ? NIM_MODIFY : NIM_ADD, &context.trayIcon);
  if (!context.trayAdded) {
    context.trayIcon.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &context.trayIcon);
  }
  context.trayAdded = true;
  SendMessageW(context.hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(SelectWindowIcon(context, false)));
  SendMessageW(context.hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(SelectWindowIcon(context, true)));
}

void ApplyDarkWindowChrome(HWND hwnd) {
  const BOOL darkMode = TRUE;
  DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkMode, sizeof(darkMode));
#if defined(DWMWA_CAPTION_COLOR)
  const COLORREF captionColor = WindowBackgroundColor();
  DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &captionColor, sizeof(captionColor));
#endif
#if defined(DWMWA_TEXT_COLOR)
  const COLORREF textColor = DarkTextColor();
  DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &textColor, sizeof(textColor));
#endif
}

void UpdatePageChrome(UiContext& context) {
  SetWindowTextSafe(context.brandSummary, BuildBrandCardText(context.snapshot));
  SetWindowTextSafe(context.titleLabel, PageTitle(context.currentPage));
  SetWindowTextSafe(context.subtitleLabel, PageSubtitle(context.currentPage, context.snapshot));
  SetWindowTextSafe(context.statusBadge, OverallStatusChip(context.snapshot));
  SetWindowTextSafe(context.primarySectionTitle, PrimarySectionTitle(context.currentPage));
  SetWindowTextSafe(context.secondarySectionTitle, SecondarySectionTitle(context.currentPage));

  const std::array<HWND, 6> navButtons{
      context.navDashboardButton, context.navThreatsButton, context.navQuarantineButton,
      context.navScansButton,      context.navHistoryButton, context.navSettingsButton};
  for (const auto button : navButtons) {
    if (button != nullptr) {
      InvalidateRect(button, nullptr, TRUE);
    }
  }
}

COLORREF ResolveMetricThreatFill(const UiContext& context) {
  return context.snapshot.openThreatCount == 0 ? MetricSuccessColor() : MetricDangerColor();
}

COLORREF ResolveServiceFill(const UiContext& context) {
  if (context.snapshot.serviceState == LocalServiceState::Running &&
      _wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") == 0) {
    return MetricSuccessColor();
  }

  if (context.snapshot.serviceState == LocalServiceState::NotInstalled ||
      context.snapshot.serviceState == LocalServiceState::Stopped) {
    return MetricDangerColor();
  }

  return MetricWarningColor();
}

HBRUSH ResolveStaticBrush(UiContext& context, HWND control) {
  if (control == context.titleLabel || control == context.subtitleLabel) {
    return context.windowBrush;
  }

  if (control == context.primarySectionTitle || control == context.secondarySectionTitle) {
    return context.windowBrush;
  }

  if (control == context.statusBadge) {
    if (context.snapshot.serviceState == LocalServiceState::NotInstalled ||
        context.snapshot.serviceState == LocalServiceState::Stopped) {
      return context.metricDangerBrush;
    }
    if (context.snapshot.openThreatCount != 0 || _wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
      return context.metricWarningBrush;
    }
    return context.metricSuccessBrush;
  }

  if (control == context.brandCard) {
    return context.detailsBrush;
  }

  if (control == context.brandLogo || control == context.brandSummary) {
    return context.detailsBrush;
  }

  if (control == context.summaryCard) {
    return context.surfaceBrush;
  }

  if (control == context.detailsCard) {
    return context.detailsBrush;
  }

  if (control == context.metricThreats) {
    return ResolveMetricThreatFill(context) == MetricDangerColor() ? context.metricDangerBrush : context.metricSuccessBrush;
  }

  if (control == context.metricQuarantine) {
    return context.snapshot.activeQuarantineCount == 0 ? context.metricInfoBrush : context.metricWarningBrush;
  }

  if (control == context.metricService) {
    const auto fill = ResolveServiceFill(context);
    if (fill == MetricSuccessColor()) {
      return context.metricSuccessBrush;
    }
    if (fill == MetricDangerColor()) {
      return context.metricDangerBrush;
    }
    return context.metricWarningBrush;
  }

  if (control == context.metricSync) {
    return context.metricInfoBrush;
  }

  if (control == context.scanStatusLabel) {
    return context.windowBrush;
  }

  return context.surfaceBrush;
}

COLORREF ResolveStaticTextColor(UiContext& context, HWND control) {
  if (control == context.subtitleLabel) {
    return MutedTextColor();
  }

  if (control == context.primarySectionTitle || control == context.secondarySectionTitle) {
    return MutedTextColor();
  }

  if (control == context.statusBadge) {
    if (context.snapshot.serviceState == LocalServiceState::NotInstalled ||
        context.snapshot.serviceState == LocalServiceState::Stopped) {
      return AccentRedDark();
    }
    if (context.snapshot.openThreatCount != 0 || _wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
      return AccentAmberDark();
    }
    return AccentGreenDark();
  }

  if (control == context.brandCard) {
    return DarkTextColor();
  }

  if (control == context.brandSummary) {
    return DarkTextColor();
  }

  if (control == context.summaryCard) {
    return DarkTextColor();
  }

  if (control == context.metricThreats) {
    return context.snapshot.openThreatCount == 0 ? AccentGreenDark() : AccentRedDark();
  }

  if (control == context.metricQuarantine) {
    return context.snapshot.activeQuarantineCount == 0 ? AccentBlueDark() : AccentAmberDark();
  }

  if (control == context.metricService) {
    if (context.snapshot.serviceState == LocalServiceState::Running &&
        _wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") == 0) {
      return AccentGreenDark();
    }
    if (context.snapshot.serviceState == LocalServiceState::NotInstalled ||
        context.snapshot.serviceState == LocalServiceState::Stopped) {
      return AccentRedDark();
    }
    return AccentAmberDark();
  }

  if (control == context.metricSync) {
    return AccentBlueDark();
  }

  if (control == context.scanStatusLabel) {
    return context.scanRunning ? AccentBlueDark() : MutedTextColor();
  }

  if (control == context.titleLabel) {
    return DarkTextColor();
  }

  return DarkTextColor();
}

COLORREF ResolveButtonFill(const UiContext& context, const int controlId, const UINT itemState) {
  const auto disabled = (itemState & ODS_DISABLED) != 0;
  const auto pressed = (itemState & ODS_SELECTED) != 0;

  if (IsNavigationButton(controlId)) {
    const auto selectedPage = PageForNavButtonId(controlId);
    const auto selected = selectedPage.has_value() && selectedPage.value() == context.currentPage;
    if (disabled) {
      return RGB(18, 24, 35);
    }
    if (selected) {
      return pressed ? RGB(25, 34, 48) : RGB(20, 28, 40);
    }
    return pressed ? RGB(17, 23, 34) : WindowBackgroundColor();
  }

  COLORREF base = RGB(36, 52, 74);
  switch (controlId) {
    case IDC_BUTTON_QUICKSCAN:
      base = RGB(47, 102, 184);
      break;
    case IDC_BUTTON_FULLSCAN:
      base = RGB(69, 82, 166);
      break;
    case IDC_BUTTON_CUSTOMSCAN:
      base = RGB(54, 123, 162);
      break;
    case IDC_BUTTON_REFRESH:
      base = RGB(43, 52, 68);
      break;
    case IDC_BUTTON_STARTSERVICE:
      base = RGB(34, 119, 94);
      break;
    case IDC_BUTTON_OPENQUARANTINE:
      base = RGB(160, 112, 43);
      break;
    case IDC_BUTTON_RESTORE:
      base = RGB(34, 119, 94);
      break;
    case IDC_BUTTON_DELETE:
      base = RGB(168, 63, 92);
      break;
    default:
      break;
  }

  if (disabled) {
    return RGB(31, 37, 48);
  }

  if (pressed) {
    return RGB(std::max(0, static_cast<int>(GetRValue(base)) - 25),
               std::max(0, static_cast<int>(GetGValue(base)) - 25),
               std::max(0, static_cast<int>(GetBValue(base)) - 25));
  }

  return base;
}

COLORREF ResolveButtonTextColor(const UINT itemState) {
  return (itemState & ODS_DISABLED) != 0 ? RGB(112, 124, 144) : RGB(244, 247, 255);
}

void DrawOwnerButton(const DRAWITEMSTRUCT* draw, UiContext& context) {
  RECT rect = draw->rcItem;
  if (IsNavigationButton(static_cast<int>(draw->CtlID))) {
    const auto selectedPage = PageForNavButtonId(static_cast<int>(draw->CtlID));
    const auto selected = selectedPage.has_value() && selectedPage.value() == context.currentPage;
    const auto fillColor = selected ? SurfaceColor() : WindowBackgroundColor();
    HBRUSH brush = CreateSolidBrush(fillColor);
    FillRect(draw->hDC, &rect, brush);
    DeleteObject(brush);

    wchar_t text[128]{};
    GetWindowTextW(draw->hwndItem, text, static_cast<int>(std::size(text)));
    SetBkMode(draw->hDC, TRANSPARENT);
    SetTextColor(draw->hDC, selected ? DarkTextColor() : MutedTextColor());
    SelectObject(draw->hDC, selected ? context.headingFont : context.bodyFont);
    RECT textRect = rect;
    if (selected) {
      RECT underline{rect.left + 12, rect.bottom - 4, rect.right - 12, rect.bottom - 2};
      HBRUSH underlineBrush = CreateSolidBrush(AccentBlue());
      FillRect(draw->hDC, &underline, underlineBrush);
      DeleteObject(underlineBrush);
    }
    DrawTextW(draw->hDC, text, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    return;
  }

  const auto fillColor = ResolveButtonFill(context, static_cast<int>(draw->CtlID), draw->itemState);
  const auto borderColor = AdjustColor(fillColor, 16);

  HBRUSH brush = CreateSolidBrush(fillColor);
  HPEN pen = CreatePen(PS_SOLID, 1, borderColor);
  HGDIOBJ oldPen = SelectObject(draw->hDC, pen);
  HGDIOBJ oldBrush = SelectObject(draw->hDC, brush);
  RoundRect(draw->hDC, rect.left, rect.top, rect.right, rect.bottom, 10, 10);
  SelectObject(draw->hDC, oldBrush);
  SelectObject(draw->hDC, oldPen);
  DeleteObject(brush);
  DeleteObject(pen);

  RECT accentRect{
      rect.left + 10,
      rect.top + 9,
      rect.left + 16,
      rect.bottom - 9,
  };
  HBRUSH accentBrush = CreateSolidBrush(AdjustColor(fillColor, 22));
  FillRect(draw->hDC, &accentRect, accentBrush);
  DeleteObject(accentBrush);

  wchar_t text[128]{};
  GetWindowTextW(draw->hwndItem, text, static_cast<int>(std::size(text)));
  SetBkMode(draw->hDC, TRANSPARENT);
  SetTextColor(draw->hDC, ResolveButtonTextColor(draw->itemState));
  SelectObject(draw->hDC, context.bodyFont);
  RECT textRect = rect;
  textRect.left += 24;
  DrawTextW(draw->hDC, text, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

  if ((draw->itemState & ODS_FOCUS) != 0) {
    RECT focusRect = rect;
    InflateRect(&focusRect, -4, -4);
    DrawFocusRect(draw->hDC, &focusRect);
  }
}

void UpdateActionButtons(UiContext& context) {
  if (context.webViewReady) {
    HideNativeShellControls(context, false);
    return;
  }

  const bool needsServiceStart =
      context.snapshot.serviceState == LocalServiceState::NotInstalled || context.snapshot.serviceState == LocalServiceState::Stopped;
  EnableWindow(context.startServiceButton, needsServiceStart);
  const auto dashboardMode = context.currentPage == ClientPage::Dashboard;
  const auto threatsMode = context.currentPage == ClientPage::Threats;
  const auto quarantineMode = context.currentPage == ClientPage::Quarantine;
  const auto scansMode = context.currentPage == ClientPage::Scans;
  const auto updatesMode = context.currentPage == ClientPage::Updates;
  const auto historyMode = context.currentPage == ClientPage::History;
  const auto settingsMode = context.currentPage == ClientPage::Settings;

  if (settingsMode) {
    SetWindowTextW(context.openQuarantineButton,
                   context.manageExclusionsMode ? L"Save exclusions" : L"Edit exclusions");
  } else {
    SetWindowTextW(context.openQuarantineButton, L"Review quarantine");
  }

  ShowWindow(context.quickScanButton, (dashboardMode || scansMode) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.fullScanButton, (dashboardMode || scansMode) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.customScanButton, (dashboardMode || scansMode) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.refreshButton,
             (!context.manageExclusionsMode &&
            (dashboardMode || threatsMode || quarantineMode || scansMode || updatesMode || historyMode || settingsMode))
                 ? SW_SHOW
                 : SW_HIDE);
  ShowWindow(context.startServiceButton, (!context.manageExclusionsMode && needsServiceStart) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.openQuarantineButton, (settingsMode || dashboardMode || threatsMode) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.restoreButton, quarantineMode ? SW_SHOW : SW_HIDE);
  ShowWindow(context.deleteButton, quarantineMode ? SW_SHOW : SW_HIDE);
  EnableWindow(context.restoreButton, quarantineMode && IsCurrentUserAdmin());
}

void UpdateDetailPane(UiContext& context) {
  std::wstring detailText = DefaultDetailText(context);

  if (context.currentPage == ClientPage::Threats) {
    const auto index = ListView_GetNextItem(context.threatsList, -1, LVNI_SELECTED);
    if (index >= 0 && static_cast<std::size_t>(index) < context.snapshot.recentThreats.size()) {
      detailText = BuildThreatDetailText(context.snapshot.recentThreats[static_cast<std::size_t>(index)]);
    }
  } else if (context.currentPage == ClientPage::Quarantine) {
    const auto index = ListView_GetNextItem(context.quarantineList, -1, LVNI_SELECTED);
    if (index >= 0 && static_cast<std::size_t>(index) < context.snapshot.quarantineItems.size()) {
      detailText = BuildQuarantineDetailText(context.snapshot.quarantineItems[static_cast<std::size_t>(index)]);
    }
  } else if (context.currentPage == ClientPage::Dashboard || context.currentPage == ClientPage::Scans ||
             context.currentPage == ClientPage::History) {
    const auto index = ListView_GetNextItem(context.historyList, -1, LVNI_SELECTED);
    if (index >= 0 && static_cast<std::size_t>(index) < context.snapshot.recentFindings.size()) {
      std::size_t visibleIndex = 0;
      for (const auto& record : context.snapshot.recentFindings) {
        if (context.currentPage == ClientPage::Scans && !IsScanSessionRecord(record)) {
          continue;
        }
        if (visibleIndex == static_cast<std::size_t>(index)) {
          detailText = BuildHistoryDetailText(record);
          break;
        }
        ++visibleIndex;
      }
    }
  }

  SetWindowTextSafe(context.detailEdit, detailText);
  UpdateActionButtons(context);
}

void UpdateVisibleList(UiContext& context) {
  const auto showThreats = context.currentPage == ClientPage::Threats;
  const auto showQuarantine = context.currentPage == ClientPage::Quarantine;
  const auto showHistory = context.currentPage == ClientPage::Dashboard || context.currentPage == ClientPage::Scans ||
                           context.currentPage == ClientPage::History;
  ShowWindow(context.threatsList, showThreats ? SW_SHOW : SW_HIDE);
  ShowWindow(context.quarantineList, showQuarantine ? SW_SHOW : SW_HIDE);
  ShowWindow(context.historyList, showHistory ? SW_SHOW : SW_HIDE);
  UpdateDetailPane(context);
}

void RefreshSnapshot(UiContext& context) {
  try {
    const auto refreshedSnapshot = antivirus::agent::LoadEndpointClientSnapshot(context.config);
    context.snapshot = refreshedSnapshot;

    UpdatePageChrome(context);
    SetWindowTextSafe(context.summaryCard, BuildSummaryCardText(context.snapshot));
    auto detailsText = BuildDetailsCardText(context.snapshot);
    if (context.webViewFallbackActive && !context.manageExclusionsMode) {
      detailsText += L"\r\n\r\nModern UI notice\r\n";
      detailsText += BuildWebViewFallbackStatus(context);
    }
    SetWindowTextSafe(context.detailsCard, detailsText);
    SetWindowTextSafe(context.metricThreats,
                      BuildMetricCardText(L"Open findings", std::to_wstring(context.snapshot.openThreatCount),
                                          context.snapshot.openThreatCount == 1 ? L"1 unresolved detection"
                                                                               : std::to_wstring(context.snapshot.openThreatCount) + L" unresolved detections"));
    SetWindowTextSafe(context.metricQuarantine,
                      BuildMetricCardText(L"Quarantine", std::to_wstring(context.snapshot.activeQuarantineCount),
                                          context.snapshot.activeQuarantineCount == 1 ? L"1 item contained"
                                                                                      : std::to_wstring(context.snapshot.activeQuarantineCount) + L" items contained"));
    SetWindowTextSafe(context.metricService,
                      BuildMetricCardText(L"Protection service",
                                          antivirus::agent::LocalServiceStateToString(context.snapshot.serviceState),
                                          NullableText(context.snapshot.agentState.healthState, L"(unknown)")));
    SetWindowTextSafe(context.metricSync,
                      BuildMetricCardText(L"Last check-in",
                                          NullableText(context.snapshot.agentState.lastHeartbeatAt, L"(never)"),
                                          std::to_wstring(context.snapshot.queuedTelemetryCount) + L" upload(s) queued"));

    PopulateThreatsList(context);
    PopulateQuarantineList(context);
    PopulateHistoryList(context);
    UpdateVisibleList(context);
    if (context.manageExclusionsMode && context.currentPage == ClientPage::Settings) {
      SendMessageW(context.detailEdit, EM_SETREADONLY, FALSE, 0);
      SetWindowTextSafe(context.secondarySectionTitle, L"Exclusions editor");
      SetWindowTextSafe(context.detailEdit, BuildExclusionsEditorText());
      SetWindowTextSafe(context.scanStatusLabel, BuildExclusionEditorSummary());
      SetWindowTextW(context.openQuarantineButton, L"Save exclusions");
    } else if (context.webViewFallbackActive && !context.scanRunning.load()) {
      const auto fallbackStatus = BuildWebViewFallbackStatus(context);
      SetWindowTextSafe(context.scanStatusLabel, fallbackStatus);
      context.scanStatusText = fallbackStatus;
    }
    UpdateTrayIcon(context);
    EvaluateNotifications(context, refreshedSnapshot);
    PublishWebViewState(context);
  } catch (const std::exception& error) {
    UpdatePageChrome(context);
    SetWindowTextSafe(context.summaryCard, L"Unable to load local protection state.");
    SetWindowTextSafe(context.detailsCard, antivirus::agent::Utf8ToWide(error.what()));
    SetWindowTextSafe(context.metricThreats, BuildMetricCardText(L"Open findings", L"unavailable"));
    SetWindowTextSafe(context.metricQuarantine, BuildMetricCardText(L"Quarantine", L"unavailable"));
    SetWindowTextSafe(context.metricService, BuildMetricCardText(L"Protection service", L"unknown"));
    SetWindowTextSafe(context.metricSync, BuildMetricCardText(L"Last check-in", L"unknown"));
    ListView_DeleteAllItems(context.threatsList);
    ListView_DeleteAllItems(context.quarantineList);
    ListView_DeleteAllItems(context.historyList);
    SetWindowTextSafe(context.detailEdit, L"Local protection details could not be loaded.");
    UpdateTrayIcon(context);
    PublishWebViewState(context);
  }
}

void UpdateScanProgress(UiContext& context, const std::wstring& statusText, const std::uint32_t completedTargets,
                        const std::uint32_t totalTargets) {
  context.scanStatusText = statusText;
  context.scanProgressCompleted = completedTargets;
  context.scanProgressTotal = totalTargets;
  SetWindowTextSafe(context.scanStatusLabel, statusText);
  ShowWindow(context.progressBar, SW_SHOW);

  const auto total = std::max<std::uint32_t>(totalTargets, 1);
  SendMessageW(context.progressBar, PBM_SETRANGE32, 0, total);
  SendMessageW(context.progressBar, PBM_SETPOS, std::min(completedTargets, total), 0);
  PublishWebViewState(context);
}

void SetPatchActionRunning(UiContext& context, const bool running, const std::wstring& statusText,
                           const std::wstring& targetId, const bool searchOnly) {
  context.patchActionRunning.store(running);
  context.patchActionStatus = statusText;
  context.patchActionTarget = targetId;
  context.patchActionSearchOnly = searchOnly;
  PublishWebViewState(context);
}

void SetScanRunning(UiContext& context, const bool running, const std::wstring& statusText) {
  context.scanRunning.store(running);
  context.scanStatusText = statusText;
  context.scanProgressCompleted = 0;
  context.scanProgressTotal = running ? 100 : 0;
  SetWindowTextSafe(context.scanStatusLabel, statusText);
  ShowWindow(context.progressBar, running ? SW_SHOW : SW_HIDE);
  if (running) {
    SendMessageW(context.progressBar, PBM_SETSTATE, PBST_NORMAL, 0);
    SendMessageW(context.progressBar, PBM_SETRANGE32, 0, 100);
    SendMessageW(context.progressBar, PBM_SETPOS, 0, 0);
  } else {
    SendMessageW(context.progressBar, PBM_SETPOS, 0, 0);
  }

  EnableWindow(context.quickScanButton, !running);
  EnableWindow(context.fullScanButton, !running);
  EnableWindow(context.customScanButton, !running);
  EnableWindow(context.refreshButton, !running);
  PublishWebViewState(context);
}

std::optional<std::wstring> PickFolder(HWND owner) {
  BROWSEINFOW browseInfo{};
  browseInfo.hwndOwner = owner;
  browseInfo.lpszTitle = L"Choose a folder to scan";
  browseInfo.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI | BIF_NEWDIALOGSTYLE;

  const auto pidl = SHBrowseForFolderW(&browseInfo);
  if (pidl == nullptr) {
    return std::nullopt;
  }

  std::wstring selected(MAX_PATH, L'\0');
  const auto ok = SHGetPathFromIDListW(pidl, selected.data());
  CoTaskMemFree(pidl);
  if (!ok) {
    return std::nullopt;
  }

  selected.resize(wcslen(selected.c_str()));
  return selected;
}

void RunScanAsync(HWND hwnd, UiContext& context, const ScanPreset preset, const std::optional<std::filesystem::path>& customPath) {
  if (context.scanRunning.exchange(true)) {
    return;
  }

  context.activeScanLabel = FriendlyScanLabel(preset);
  const auto statusText = L"Preparing " + LowercaseCopy(context.activeScanLabel) + L" scope...";

  SetScanRunning(context, true, statusText);
  const auto config = context.config;
  const auto scanLabel = context.activeScanLabel;

  std::thread([hwnd, config, preset, customPath, scanLabel]() {
    auto* payload = new ScanCompletePayload{};
    try {
      antivirus::agent::LocalStateStore stateStore(config.runtimeDatabasePath, config.stateFilePath);
      const auto state = stateStore.LoadOrCreate();

      std::vector<std::filesystem::path> targets;
      std::wstring source;
      switch (preset) {
        case ScanPreset::Quick:
          targets = antivirus::agent::BuildQuickScanTargets();
          source = L"endpoint-ui.quick-scan";
          break;
        case ScanPreset::Full:
          targets = {std::filesystem::path(LR"(C:\)")};
          source = L"endpoint-ui.full-scan";
          break;
        case ScanPreset::Folder:
          targets = customPath.has_value() ? std::vector<std::filesystem::path>{*customPath} : std::vector<std::filesystem::path>{};
          source = L"endpoint-ui.custom-scan";
          break;
      }

      const auto result = antivirus::agent::ExecuteLocalScan(
          config, state, targets,
          antivirus::agent::LocalScanExecutionOptions{.queueTelemetry = true, .applyRemediation = true, .source = source},
          [hwnd, scanLabel](const antivirus::agent::LocalScanProgressUpdate& progress) {
            auto* progressPayload = new ScanProgressPayload{};
            std::wstringstream status;
            if (progress.totalTargets == 0) {
              status << scanLabel << L" complete • no scannable files were discovered.";
            } else if (progress.completedTargets >= progress.totalTargets) {
              status << scanLabel << L" finalizing results...";
            } else {
              status << scanLabel << L" in progress • " << (progress.completedTargets + 1) << L" of "
                     << progress.totalTargets << L" checked";
              const auto displayTarget = CompactPathForStatus(progress.currentTarget);
              if (!displayTarget.empty()) {
                status << L" • " << displayTarget;
              }
              if (progress.findingCount != 0) {
                status << L" • " << progress.findingCount << L" finding(s)";
              }
            }

            progressPayload->status = status.str();
            progressPayload->completedTargets = static_cast<std::uint32_t>(progress.completedTargets);
            progressPayload->totalTargets = static_cast<std::uint32_t>(progress.totalTargets);
            if (IsWindow(hwnd)) {
              PostMessageW(hwnd, kScanProgressMessage, 0, reinterpret_cast<LPARAM>(progressPayload));
            } else {
              delete progressPayload;
            }
          });

      std::wstringstream summary;
      if (result.findings.empty()) {
        summary << scanLabel << L" complete. No findings were found.";
      } else {
        summary << scanLabel << L" complete. " << result.findings.size() << L" finding(s) blocked during "
                << result.targetCount << L" target(s) checked.";
        if (result.remediationFailed) {
          summary << L" Some remediation actions failed and need review.";
        } else {
          summary << L" Fenrir blocked the detections and applied quarantine where policy allowed it.";
        }
      }

      payload->summary = summary.str();
      payload->success = !result.remediationFailed;
    } catch (const std::exception& error) {
      payload->summary = std::wstring(L"Scan failed: ") + antivirus::agent::Utf8ToWide(error.what());
      payload->success = false;
    }

    if (IsWindow(hwnd)) {
      PostMessageW(hwnd, kScanCompleteMessage, 0, reinterpret_cast<LPARAM>(payload));
    } else {
      delete payload;
    }
  }).detach();
}

void RunSoftwarePatchActionAsync(HWND hwnd, UiContext& context, std::wstring softwareId, const bool searchOnly) {
  if (softwareId.empty()) {
    return;
  }

  if (context.patchActionRunning.exchange(true)) {
    MessageBoxW(context.hwnd, L"A software update action is already running. Wait for it to complete.",
                kWindowTitle, MB_OK | MB_ICONINFORMATION);
    return;
  }

  const auto actionLabel = searchOnly ? std::wstring(L"Checking updates for ") : std::wstring(L"Installing updates for ");
  SetPatchActionRunning(context, true, actionLabel + softwareId + L"...", softwareId, searchOnly);

  const auto config = context.config;
  std::thread([hwnd, config, softwareId = std::move(softwareId), searchOnly]() mutable {
    auto* payload = new PatchActionCompletePayload{};
    payload->targetId = softwareId;
    payload->searchOnly = searchOnly;
    try {
      const auto result = searchOnly ? antivirus::agent::PatchOrchestrator(config).UpdateSoftware(softwareId, true)
                                     : antivirus::agent::ExecuteSoftwarePatchThroughService(config, softwareId);
      payload->summary = BuildPatchExecutionSummary(result, searchOnly);
      payload->success = result.success;
      payload->informational = IsPatchResultInformational(result);
      if (!result.targetId.empty()) {
        payload->targetId = result.targetId;
      }
    } catch (const std::exception& error) {
      payload->summary = std::wstring(L"Software update action failed: ") + antivirus::agent::Utf8ToWide(error.what());
      payload->success = false;
      payload->informational = false;
    }

    if (IsWindow(hwnd)) {
      PostMessageW(hwnd, kPatchActionCompleteMessage, 0, reinterpret_cast<LPARAM>(payload));
    } else {
      delete payload;
    }
  }).detach();
}

void HideToTray(HWND hwnd) {
  ShowWindow(hwnd, SW_HIDE);
}

void RestoreFromTray(HWND hwnd) {
  ShowWindow(hwnd, SW_SHOW);
  ShowWindow(hwnd, SW_RESTORE);
  SetForegroundWindow(hwnd);
}

void SelectPage(UiContext& context, const ClientPage page) {
  context.currentPage = page;
  UpdatePageChrome(context);
  PopulateHistoryList(context);
  UpdateVisibleList(context);
  PublishWebViewState(context);
}

void OpenQuarantineFolder(const UiContext&) {
  // Quarantine is intentionally managed inside Fenrir. Direct folder access is disabled.
}

void ShowTrayMenu(UiContext& context) {
  HMENU menu = CreatePopupMenu();
  if (menu == nullptr) {
    return;
  }

  HMENU pamMenu = CreatePopupMenu();
  if (pamMenu == nullptr) {
    DestroyMenu(menu);
    return;
  }

  AppendMenuW(menu, MF_STRING, IDM_TRAY_OPEN, L"Open Fenrir dashboard");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, IDM_TRAY_FULLSCAN, L"Run full scan");
  AppendMenuW(menu, MF_STRING, IDM_TRAY_QUICKSCAN, L"Run quick scan");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(pamMenu, MF_STRING, IDM_TRAY_PAM_POWERSHELL, L"PowerShell");
  AppendMenuW(pamMenu, MF_STRING, IDM_TRAY_PAM_CMD, L"Command Prompt");
  AppendMenuW(pamMenu, MF_STRING, IDM_TRAY_PAM_DISKCLEANUP, L"Disk Cleanup");
  AppendMenuW(pamMenu, MF_STRING, IDM_TRAY_PAM_WINDOWSUPDATE, L"Windows Update");
  AppendMenuW(pamMenu, MF_STRING, IDM_TRAY_PAM_NETWORKRESET, L"Network stack reset");
  AppendMenuW(pamMenu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(pamMenu, MF_STRING, IDM_TRAY_PAM_APP, L"Run application as admin...");
  AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(pamMenu), L"Run as admin");
  AppendMenuW(menu, MF_STRING, IDM_TRAY_PAM_ELEVATE_2M, L"Elevate as admin (2 minutes)");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, IDM_TRAY_QUARANTINE, L"Open quarantine");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"Exit Fenrir");

  POINT cursor{};
  GetCursorPos(&cursor);
  SetForegroundWindow(context.hwnd);
  const auto command = TrackPopupMenuEx(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RETURNCMD,
                                        cursor.x, cursor.y, context.hwnd, nullptr);
  PostMessageW(context.hwnd, WM_NULL, 0, 0);
  if (command != 0) {
    SendMessageW(context.hwnd, WM_COMMAND, command, 0);
  }
  DestroyMenu(menu);
}

void UpdateListColumnWidths(HWND listView, const std::vector<int>& widths) {
  for (int index = 0; index < static_cast<int>(widths.size()); ++index) {
    ListView_SetColumnWidth(listView, index, widths[static_cast<std::size_t>(index)]);
  }
}

void LayoutControls(UiContext& context) {
  if (context.webViewReady) {
    HideNativeShellControls(context, false);
    ResizeWebView(context);
    return;
  }

  RECT client{};
  GetClientRect(context.hwnd, &client);

  const int padding = 20;
  const int width = client.right - client.left;
  const int height = client.bottom - client.top;
  const int railWidth = 176;
  const int railGap = 20;
  const int railX = padding;
  const int railY = padding;
  const int railHeight = height - (padding * 2);
  const int contentX = railX + railWidth + railGap;
  const int contentWidth = width - contentX - padding;

  const int brandHeight = 118;
  const int navButtonHeight = 34;
  const int navGap = 5;
  const int navTop = railY + brandHeight + 16;

  MoveWindow(context.brandCard, railX, railY, railWidth, brandHeight, TRUE);
  MoveWindow(context.brandLogo, (railWidth - 36) / 2, 14, 36, 36, TRUE);
  MoveWindow(context.brandSummary, 12, 58, railWidth - 24, brandHeight - 66, TRUE);

  const int titleHeight = 42;
  const int subtitleHeight = 24;
  MoveWindow(context.titleLabel, contentX, padding, contentWidth - 170, titleHeight, TRUE);
  MoveWindow(context.subtitleLabel, contentX, padding + titleHeight + 2, contentWidth - 220, subtitleHeight, TRUE);
  MoveWindow(context.statusBadge, contentX + contentWidth - 164, padding + 8, 164, 36, TRUE);

  const int navY = padding + titleHeight + subtitleHeight + 18;
  const int navTabGap = 8;
  const int navTabCount = 6;
  const int navTabWidth = (contentWidth - (navTabGap * (navTabCount - 1))) / navTabCount;
  MoveWindow(context.navDashboardButton, contentX, navY, navTabWidth, navButtonHeight, TRUE);
  MoveWindow(context.navThreatsButton, contentX + (navTabWidth + navTabGap) * 1, navY, navTabWidth, navButtonHeight, TRUE);
  MoveWindow(context.navQuarantineButton, contentX + (navTabWidth + navTabGap) * 2, navY, navTabWidth, navButtonHeight, TRUE);
  MoveWindow(context.navScansButton, contentX + (navTabWidth + navTabGap) * 3, navY, navTabWidth, navButtonHeight, TRUE);
  MoveWindow(context.navHistoryButton, contentX + (navTabWidth + navTabGap) * 4, navY, navTabWidth, navButtonHeight, TRUE);
  MoveWindow(context.navSettingsButton, contentX + (navTabWidth + navTabGap) * 5, navY, navTabWidth, navButtonHeight, TRUE);

  const bool dashboardPage = context.currentPage == ClientPage::Dashboard;
  const bool threatsPage = context.currentPage == ClientPage::Threats;
  const bool quarantinePage = context.currentPage == ClientPage::Quarantine;
  const bool scansPage = context.currentPage == ClientPage::Scans;
  const bool updatesPage = context.currentPage == ClientPage::Updates;
  const bool servicePage = context.currentPage == ClientPage::Service;
  const bool historyPage = context.currentPage == ClientPage::History;
  const bool settingsPage = context.currentPage == ClientPage::Settings;

  const bool showHero = dashboardPage;
  const bool showMetrics = dashboardPage;
  const bool showLists = threatsPage || quarantinePage || scansPage || historyPage;
  const bool showPrimaryList = showLists;
  const bool showDetailPane = showLists || updatesPage || servicePage || settingsPage;

  ShowWindow(context.summaryCard, showHero ? SW_SHOW : SW_HIDE);
  ShowWindow(context.detailsCard, showHero ? SW_SHOW : SW_HIDE);
  ShowWindow(context.metricThreats, showMetrics ? SW_SHOW : SW_HIDE);
  ShowWindow(context.metricQuarantine, showMetrics ? SW_SHOW : SW_HIDE);
  ShowWindow(context.metricService, SW_HIDE);
  ShowWindow(context.metricSync, showMetrics ? SW_SHOW : SW_HIDE);
  ShowWindow(context.primarySectionTitle, showPrimaryList ? SW_SHOW : SW_HIDE);
  ShowWindow(context.secondarySectionTitle, showDetailPane ? SW_SHOW : SW_HIDE);

  int currentTop = navY + navButtonHeight + 18;
  const int heroGap = 16;
  const int heroHeight = showHero ? 132 : 0;
  if (showHero) {
    const int heroLeftWidth = static_cast<int>(contentWidth * 0.61);
    const int heroRightWidth = contentWidth - heroLeftWidth - heroGap;
    MoveWindow(context.summaryCard, contentX, currentTop, heroLeftWidth, heroHeight, TRUE);
    MoveWindow(context.detailsCard, contentX + heroLeftWidth + heroGap, currentTop, heroRightWidth, heroHeight, TRUE);
    currentTop += heroHeight + 16;
  }

  if (showMetrics) {
    const int metricGap = 12;
    const int metricHeight = 76;
    const int metricWidth = (contentWidth - (metricGap * 2)) / 3;
    MoveWindow(context.metricThreats, contentX, currentTop, metricWidth, metricHeight, TRUE);
    MoveWindow(context.metricQuarantine, contentX + metricWidth + metricGap, currentTop, metricWidth, metricHeight, TRUE);
    MoveWindow(context.metricSync, contentX + ((metricWidth + metricGap) * 2), currentTop, metricWidth, metricHeight, TRUE);
    currentTop += metricHeight + 16;
  }

  const int buttonWidth = 132;
  const int buttonHeight = 38;
  const int actionGap = 10;
  const int rightActionWidth = 196;
  MoveWindow(context.quickScanButton, contentX, currentTop, buttonWidth, buttonHeight, TRUE);
  MoveWindow(context.fullScanButton, contentX + (buttonWidth + actionGap), currentTop, buttonWidth, buttonHeight, TRUE);
  MoveWindow(context.customScanButton, contentX + ((buttonWidth + actionGap) * 2), currentTop, buttonWidth, buttonHeight, TRUE);
  MoveWindow(context.refreshButton, contentX + ((buttonWidth + actionGap) * 3), currentTop, buttonWidth, buttonHeight, TRUE);
  MoveWindow(context.startServiceButton, contentX + ((buttonWidth + actionGap) * 4), currentTop, 160, buttonHeight, TRUE);
  MoveWindow(context.openQuarantineButton, contentX + contentWidth - rightActionWidth, currentTop, rightActionWidth, buttonHeight, TRUE);

  currentTop += buttonHeight + 12;
  MoveWindow(context.scanStatusLabel, contentX, currentTop, contentWidth - 260, 24, TRUE);
  MoveWindow(context.progressBar, contentX + contentWidth - 240, currentTop + 3, 240, 16, TRUE);

  currentTop += 34;
  const bool showProgressArea = dashboardPage || scansPage || context.scanRunning;
  ShowWindow(context.scanStatusLabel, showProgressArea ? SW_SHOW : SW_HIDE);
  ShowWindow(context.progressBar, showProgressArea ? SW_SHOW : SW_HIDE);

  if (dashboardPage) {
    ShowWindow(context.primarySectionTitle, SW_HIDE);
    ShowWindow(context.secondarySectionTitle, SW_HIDE);
    ShowWindow(context.threatsList, SW_HIDE);
    ShowWindow(context.quarantineList, SW_HIDE);
    ShowWindow(context.historyList, SW_HIDE);
    ShowWindow(context.detailEdit, SW_HIDE);
    ShowWindow(context.restoreButton, SW_HIDE);
    ShowWindow(context.deleteButton, SW_HIDE);
    return;
  }

  if (showLists) {
    const int panelGap = 18;
    const int sectionTitleHeight = 22;
    const int contentBottom = height - padding;
    MoveWindow(context.primarySectionTitle, contentX, currentTop, contentWidth / 2, sectionTitleHeight, TRUE);
    MoveWindow(context.secondarySectionTitle, contentX + static_cast<int>(contentWidth * 0.62), currentTop,
               static_cast<int>(contentWidth * 0.38), sectionTitleHeight, TRUE);
    currentTop += sectionTitleHeight + 8;

    const int listWidth = static_cast<int>(contentWidth * 0.60);
    const int detailWidth = contentWidth - listWidth - panelGap;
    const int listHeight = contentBottom - currentTop;
    MoveWindow(context.threatsList, contentX, currentTop, listWidth, listHeight, TRUE);
    MoveWindow(context.quarantineList, contentX, currentTop, listWidth, listHeight, TRUE);
    MoveWindow(context.historyList, contentX, currentTop, listWidth, listHeight, TRUE);
    MoveWindow(context.detailEdit, contentX + listWidth + panelGap, currentTop, detailWidth, listHeight - 46, TRUE);
    MoveWindow(context.restoreButton, contentX + listWidth + panelGap + detailWidth - 254, currentTop + listHeight - 38, 120, 36, TRUE);
    MoveWindow(context.deleteButton, contentX + listWidth + panelGap + detailWidth - 124, currentTop + listHeight - 38, 120, 36, TRUE);

    UpdateListColumnWidths(context.threatsList, {170, listWidth - 690, 110, 100, 180, 130});
    UpdateListColumnWidths(context.quarantineList, {170, listWidth - 740, 120, 160, 270});
    UpdateListColumnWidths(context.historyList, {170, 110, listWidth - 710, 150, 140, 130});
  } else {
    ShowWindow(context.threatsList, SW_HIDE);
    ShowWindow(context.quarantineList, SW_HIDE);
    ShowWindow(context.historyList, SW_HIDE);
    if (showDetailPane) {
      ShowWindow(context.detailEdit, SW_SHOW);
      MoveWindow(context.secondarySectionTitle, contentX, currentTop, contentWidth, 22, TRUE);
      MoveWindow(context.detailEdit, contentX, currentTop + 30, contentWidth, height - (currentTop + 30) - padding, TRUE);
    } else {
      ShowWindow(context.detailEdit, SW_HIDE);
    }
  }
}

void PerformQuarantineAction(UiContext& context, const bool restore) {
  const auto index = ListView_GetNextItem(context.quarantineList, -1, LVNI_SELECTED);
  if (index < 0 || static_cast<std::size_t>(index) >= context.snapshot.quarantineItems.size()) {
    MessageBoxW(context.hwnd, L"Select a quarantined item first.", kWindowTitle, MB_OK | MB_ICONINFORMATION);
    return;
  }

  if (!RequireAuthorizedLocalAction(context.hwnd, antivirus::agent::LocalAction::QuarantineMutate, kWindowTitle)) {
    return;
  }

  const auto& item = context.snapshot.quarantineItems[static_cast<std::size_t>(index)];
  const auto result = restore ? antivirus::agent::RestoreQuarantinedItem(context.config, item.recordId)
                              : antivirus::agent::DeleteQuarantinedItem(context.config, item.recordId);
  if (!result.success) {
    const auto heading = restore ? L"Unable to restore the selected item." : L"Unable to delete the selected item.";
    auto detail = result.errorMessage.empty() ? std::wstring(L"Unknown error") : result.errorMessage;
    if (!result.approvalRequestId.empty()) {
      detail += L"\r\n\r\nApproval request: " + result.approvalRequestId +
                L"\r\nProvide this ID to an owner/admin to execute local.approval.execute.";
    }
    MessageBoxW(context.hwnd,
                (std::wstring(heading) + L"\r\n\r\n" + detail).c_str(),
                kWindowTitle, MB_OK | MB_ICONERROR);
    return;
  }

  RefreshSnapshot(context);
}

void HandleWebViewMessage(UiContext& context, const std::wstring& message) {
  const auto pairs = ParseWebMessage(message);
  const auto action = GetQueryValue(pairs, L"action");
  if (action.empty()) {
    return;
  }

  if (_wcsicmp(action.c_str(), L"navigate") == 0) {
    const auto page = GetQueryValue(pairs, L"page");
    if (_wcsicmp(page.c_str(), L"dashboard") == 0) {
      SelectPage(context, ClientPage::Dashboard);
    } else if (_wcsicmp(page.c_str(), L"threats") == 0) {
      SelectPage(context, ClientPage::Threats);
    } else if (_wcsicmp(page.c_str(), L"quarantine") == 0) {
      SelectPage(context, ClientPage::Quarantine);
    } else if (_wcsicmp(page.c_str(), L"scans") == 0) {
      SelectPage(context, ClientPage::Scans);
    } else if (_wcsicmp(page.c_str(), L"updates") == 0) {
      SelectPage(context, ClientPage::Updates);
    } else if (_wcsicmp(page.c_str(), L"history") == 0) {
      SelectPage(context, ClientPage::History);
    } else if (_wcsicmp(page.c_str(), L"settings") == 0) {
      SelectPage(context, ClientPage::Settings);
    }
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"refresh") == 0) {
    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"setQuickScanInterval") == 0 ||
      _wcsicmp(action.c_str(), L"setFullScanInterval") == 0) {
    if (!RequireAuthorizedLocalAction(context.hwnd, antivirus::agent::LocalAction::EditExclusions, kWindowTitle)) {
      return;
    }

    const auto minutesText = GetQueryValue(pairs, L"minutes");
    const auto quickAction = _wcsicmp(action.c_str(), L"setQuickScanInterval") == 0;
    const auto parsedMinutes = quickAction ? ParseBoundedInteger(minutesText, 15, 10080)
                                           : ParseBoundedInteger(minutesText, 60, 43200);
    if (!parsedMinutes.has_value()) {
      MessageBoxW(context.hwnd,
                  quickAction ? L"Quick scan interval must be a whole number between 15 and 10080 minutes."
                              : L"Full scan interval must be a whole number between 60 and 43200 minutes.",
                  kWindowTitle, MB_OK | MB_ICONWARNING);
      return;
    }

    auto scheduleSettings = antivirus::agent::LoadConfiguredScanScheduleSettings();
    if (quickAction) {
      scheduleSettings.quickScanIntervalMinutes = *parsedMinutes;
    } else {
      scheduleSettings.fullScanIntervalMinutes = *parsedMinutes;
    }

    if (!antivirus::agent::SaveConfiguredScanScheduleSettings(scheduleSettings)) {
      MessageBoxW(context.hwnd, L"Fenrir could not save the updated scan schedule settings.", kWindowTitle,
                  MB_OK | MB_ICONERROR);
      return;
    }

    const auto restarted = antivirus::agent::RestartAgentService();
    context.config = antivirus::agent::LoadAgentConfigForModule(nullptr);
    RefreshSnapshot(context);
    PublishWebViewState(context);

    std::wstringstream summary;
    summary << (quickAction ? L"Quick scan schedule updated: every " : L"Full scan schedule updated: every ")
            << *parsedMinutes << L" minute(s).";
    if (restarted) {
      summary << L"\r\nProtection service restarted to apply the new schedule immediately.";
    } else {
      summary << L"\r\nSchedule was saved, but Fenrir could not restart the protection service automatically.";
    }
    MessageBoxW(context.hwnd, summary.str().c_str(), kWindowTitle, MB_OK | (restarted ? MB_ICONINFORMATION : MB_ICONWARNING));
    return;
  }

  if (_wcsicmp(action.c_str(), L"softwareUpdatesRefresh") == 0) {
    if (context.patchActionRunning.load()) {
      MessageBoxW(context.hwnd, L"A software update action is currently running. Wait for it to finish before refreshing inventory.",
                  kWindowTitle, MB_OK | MB_ICONINFORMATION);
      return;
    }

    try {
      antivirus::agent::PatchOrchestrator orchestrator(context.config);
      const auto summary = orchestrator.RefreshPatchState();
      RefreshSnapshot(context);
      PublishWebViewState(context);

      std::wstringstream stream;
      stream << L"Patch inventory refreshed.\r\n\r\n"
             << L"Windows updates: " << summary.windowsUpdateCount << L"\r\n"
             << L"Software entries: " << summary.softwareCount << L"\r\n"
             << L"Recipe coverage: " << summary.recipeCount << L"\r\n"
             << L"Reboot pending: " << (summary.rebootPending ? L"yes" : L"no");
      MessageBoxW(context.hwnd, stream.str().c_str(), kWindowTitle, MB_OK | MB_ICONINFORMATION);
    } catch (const std::exception& error) {
      MessageBoxW(context.hwnd,
                  (L"Fenrir could not refresh software update posture.\r\n\r\n" +
                   antivirus::agent::Utf8ToWide(error.what()))
                      .c_str(),
                  kWindowTitle, MB_OK | MB_ICONERROR);
    }
    return;
  }

  if (_wcsicmp(action.c_str(), L"requestWindowsUpdatePam") == 0) {
    SubmitWindowsUpdatePamRequest(context.hwnd, context);
    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"requestNetworkResetPam") == 0) {
    SubmitNetworkResetPamRequest(context.hwnd, context);
    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"scan") == 0) {
    const auto preset = GetQueryValue(pairs, L"preset");
    if (_wcsicmp(preset.c_str(), L"quick") == 0) {
      RunScanAsync(context.hwnd, context, ScanPreset::Quick, std::nullopt);
    } else if (_wcsicmp(preset.c_str(), L"full") == 0) {
      RunScanAsync(context.hwnd, context, ScanPreset::Full, std::nullopt);
    } else if (_wcsicmp(preset.c_str(), L"folder") == 0) {
      const auto folder = PickFolder(context.hwnd);
      if (folder.has_value()) {
        RunScanAsync(context.hwnd, context, ScanPreset::Folder, std::filesystem::path(*folder));
      }
    }
    return;
  }

  if (_wcsicmp(action.c_str(), L"softwareCheck") == 0 ||
      _wcsicmp(action.c_str(), L"softwareUpdate") == 0) {
    const auto softwareId = GetQueryValue(pairs, L"software-id");
    if (softwareId.empty()) {
      return;
    }

    const auto searchOnly = _wcsicmp(action.c_str(), L"softwareCheck") == 0;
    if (!searchOnly &&
        !RequireAuthorizedLocalAction(context.hwnd, antivirus::agent::LocalAction::PatchInstall, kWindowTitle)) {
      return;
    }
    RunSoftwarePatchActionAsync(context.hwnd, context, softwareId, searchOnly);
    return;
  }

  if (_wcsicmp(action.c_str(), L"startService") == 0) {
    if (!RequireAuthorizedLocalAction(context.hwnd, antivirus::agent::LocalAction::StartServiceAction, kWindowTitle)) {
      return;
    }
    if (!antivirus::agent::StartAgentService()) {
      MessageBoxW(context.hwnd, L"Unable to start the protection service from the local client.", kWindowTitle,
                  MB_OK | MB_ICONWARNING);
    }
    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"openQuarantine") == 0) {
    SelectPage(context, ClientPage::Quarantine);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"openExclusions") == 0) {
    if (!RequireAuthorizedLocalAction(context.hwnd, antivirus::agent::LocalAction::EditExclusions, kWindowTitle)) {
      return;
    }
    context.manageExclusionsMode = true;
    SelectPage(context, ClientPage::Settings);
    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"exclusionsDone") == 0) {
    context.manageExclusionsMode = false;
    SelectPage(context, ClientPage::Settings);
    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"exclusionsAddFile") == 0) {
    const auto file = PickFile(context.hwnd);
    if (!file.has_value()) {
      return;
    }

    auto exclusions = antivirus::agent::LoadConfiguredScanExclusions();
    bool changed = AppendUniqueExclusion(exclusions, std::filesystem::path(*file));
    if (!changed) {
      MessageBoxW(context.hwnd, L"That file is already excluded.", kWindowTitle, MB_OK | MB_ICONINFORMATION);
      return;
    }

    const auto commitResult = CommitExclusions(context.hwnd, exclusions);
    if (commitResult == 0) {
      MessageBoxW(context.hwnd, L"File exclusion saved and protection was refreshed.", kWindowTitle,
                  MB_OK | MB_ICONINFORMATION);
    } else if (commitResult == 2) {
      MessageBoxW(context.hwnd,
                  L"File exclusion was saved, but Fenrir could not restart the protection service automatically.",
                  kWindowTitle, MB_OK | MB_ICONWARNING);
    } else {
      MessageBoxW(context.hwnd, L"Unable to save the selected file exclusion.", kWindowTitle, MB_OK | MB_ICONERROR);
      return;
    }

    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"exclusionsAddFolder") == 0) {
    const auto folder = PickFolder(context.hwnd);
    if (!folder.has_value()) {
      return;
    }

    auto exclusions = antivirus::agent::LoadConfiguredScanExclusions();
    bool changed = AppendUniqueExclusion(exclusions, std::filesystem::path(*folder));
    if (!changed) {
      MessageBoxW(context.hwnd, L"That folder is already excluded.", kWindowTitle, MB_OK | MB_ICONINFORMATION);
      return;
    }

    const auto commitResult = CommitExclusions(context.hwnd, exclusions);
    if (commitResult == 0) {
      MessageBoxW(context.hwnd, L"Folder exclusion saved and protection was refreshed.", kWindowTitle,
                  MB_OK | MB_ICONINFORMATION);
    } else if (commitResult == 2) {
      MessageBoxW(context.hwnd,
                  L"Folder exclusion was saved, but Fenrir could not restart the protection service automatically.",
                  kWindowTitle, MB_OK | MB_ICONWARNING);
    } else {
      MessageBoxW(context.hwnd, L"Unable to save the selected folder exclusion.", kWindowTitle,
                  MB_OK | MB_ICONERROR);
      return;
    }

    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"exclusionsAddProcess") == 0) {
    const auto pidText = GetQueryValue(pairs, L"pid");
    std::size_t parsed = 0;
    DWORD pid = 0;
    try {
      pid = static_cast<DWORD>(std::stoul(pidText, &parsed, 10));
    } catch (...) {
      return;
    }
    if (pid == 0 || parsed == 0) {
      return;
    }

    auto exclusions = antivirus::agent::LoadConfiguredScanExclusions();
    const auto processPaths = ResolveProcessExclusionPaths(static_cast<DWORD>(pid));
    bool changed = false;
    for (const auto& path : processPaths) {
      changed = AppendUniqueExclusion(exclusions, path) || changed;
    }

    if (!changed) {
      MessageBoxW(context.hwnd, L"No eligible process path could be added from the current process list.", kWindowTitle,
                  MB_OK | MB_ICONINFORMATION);
      return;
    }

    const auto commitResult = CommitExclusions(context.hwnd, exclusions);
    if (commitResult == 0) {
      MessageBoxW(context.hwnd, L"Process exclusion saved and protection was refreshed.", kWindowTitle,
                  MB_OK | MB_ICONINFORMATION);
    } else if (commitResult == 2) {
      MessageBoxW(context.hwnd,
                  L"Process exclusion was saved, but Fenrir could not restart the protection service automatically.",
                  kWindowTitle, MB_OK | MB_ICONWARNING);
    } else {
      MessageBoxW(context.hwnd, L"Unable to save the selected process exclusion.", kWindowTitle,
                  MB_OK | MB_ICONERROR);
      return;
    }

    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"exclusionsAddApplication") == 0) {
    const auto softwareId = GetQueryValue(pairs, L"software-id");
    if (softwareId.empty()) {
      return;
    }

    auto exclusions = antivirus::agent::LoadConfiguredScanExclusions();
    const auto softwarePaths = ResolveSoftwareExclusionPaths(softwareId);
    bool changed = false;
    for (const auto& path : softwarePaths) {
      changed = AppendUniqueExclusion(exclusions, path) || changed;
    }

    if (!changed) {
      MessageBoxW(context.hwnd, L"No eligible application path could be added from the installed software list.",
                  kWindowTitle, MB_OK | MB_ICONINFORMATION);
      return;
    }

    const auto commitResult = CommitExclusions(context.hwnd, exclusions);
    if (commitResult == 0) {
      MessageBoxW(context.hwnd, L"Application exclusion saved and protection was refreshed.", kWindowTitle,
                  MB_OK | MB_ICONINFORMATION);
    } else if (commitResult == 2) {
      MessageBoxW(context.hwnd,
                  L"Application exclusion was saved, but Fenrir could not restart the protection service automatically.",
                  kWindowTitle, MB_OK | MB_ICONWARNING);
    } else {
      MessageBoxW(context.hwnd, L"Unable to save the selected application exclusion.", kWindowTitle,
                  MB_OK | MB_ICONERROR);
      return;
    }

    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"exclusionsRemove") == 0) {
    const auto pathText = GetQueryValue(pairs, L"path");
    if (pathText.empty()) {
      return;
    }

    auto exclusions = antivirus::agent::LoadConfiguredScanExclusions();
    if (!RemoveExclusionPath(exclusions, std::filesystem::path(pathText))) {
      MessageBoxW(context.hwnd, L"That exclusion was not found in the current list.", kWindowTitle,
                  MB_OK | MB_ICONINFORMATION);
      return;
    }

    const auto commitResult = CommitExclusions(context.hwnd, exclusions);
    if (commitResult == 0) {
      MessageBoxW(context.hwnd, L"Exclusion removed and protection was refreshed.", kWindowTitle,
                  MB_OK | MB_ICONINFORMATION);
    } else if (commitResult == 2) {
      MessageBoxW(context.hwnd,
                  L"Exclusion was removed, but Fenrir could not restart the protection service automatically.",
                  kWindowTitle, MB_OK | MB_ICONWARNING);
    } else {
      MessageBoxW(context.hwnd, L"Unable to remove the selected exclusion.", kWindowTitle, MB_OK | MB_ICONERROR);
      return;
    }

    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"quarantineRestore") == 0) {
    const auto id = GetQueryValue(pairs, L"id");
    if (id.empty()) {
      return;
    }

    if (!RequireAuthorizedLocalAction(context.hwnd, antivirus::agent::LocalAction::QuarantineMutate, kWindowTitle)) {
      return;
    }

    const auto result = RestoreQuarantinedItem(context.config, id);
    if (!result.success) {
      auto detail = result.errorMessage.empty() ? std::wstring(L"Unable to restore the selected item.")
                                                : result.errorMessage;
      if (!result.approvalRequestId.empty()) {
        detail += L"\r\n\r\nApproval request: " + result.approvalRequestId +
                  L"\r\nProvide this ID to an owner/admin to execute local.approval.execute.";
      }
      MessageBoxW(context.hwnd, detail.c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
      return;
    }

    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }

  if (_wcsicmp(action.c_str(), L"quarantineDelete") == 0) {
    const auto id = GetQueryValue(pairs, L"id");
    if (id.empty()) {
      return;
    }

    if (!RequireAuthorizedLocalAction(context.hwnd, antivirus::agent::LocalAction::QuarantineMutate, kWindowTitle)) {
      return;
    }

    const auto result = DeleteQuarantinedItem(context.config, id);
    if (!result.success) {
      auto detail = result.errorMessage.empty() ? std::wstring(L"Unable to delete the selected item.")
                                                : result.errorMessage;
      if (!result.approvalRequestId.empty()) {
        detail += L"\r\n\r\nApproval request: " + result.approvalRequestId +
                  L"\r\nProvide this ID to an owner/admin to execute local.approval.execute.";
      }
      MessageBoxW(context.hwnd, detail.c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
      return;
    }

    RefreshSnapshot(context);
    PublishWebViewState(context);
    return;
  }
}

void InitializeListView(HWND listView) {
  SendMessageW(listView, CCM_SETUNICODEFORMAT, TRUE, 0);
  ListView_SetExtendedListViewStyle(listView, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
}

HWND CreateCard(HWND parent, const int id) {
  return CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                         0, 0, 0, 0, parent, reinterpret_cast<HMENU>(id), nullptr, nullptr);
}

LRESULT HandleListCustomDraw(const NMLVCUSTOMDRAW* customDraw) {
  switch (customDraw->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
      return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT: {
      auto* mutableDraw = const_cast<NMLVCUSTOMDRAW*>(customDraw);
      const bool selected = (customDraw->nmcd.uItemState & CDIS_SELECTED) != 0;
      mutableDraw->clrText = selected ? RGB(255, 255, 255) : DarkTextColor();
      mutableDraw->clrTextBk = selected ? RGB(25, 34, 48)
                                        : ((customDraw->nmcd.dwItemSpec % 2 == 0) ? ListBackColor() : ListAltBackColor());
      return CDRF_NEWFONT;
    }
    default:
      return CDRF_DODEFAULT;
  }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
  if (message == RestoreWindowMessageId()) {
    if (auto* context = GetContext(hwnd)) {
      RestoreFromTray(hwnd);
      SelectPage(*context, ClientPage::Dashboard);
      LayoutControls(*context);
    }
    return 0;
  }

  switch (message) {
    case kTrayMessage: {
      auto* context = GetContext(hwnd);
      const auto trayEvent = LOWORD(static_cast<DWORD>(lParam));
      if (trayEvent == WM_LBUTTONUP || trayEvent == WM_RBUTTONUP || trayEvent == WM_CONTEXTMENU) {
        if (context != nullptr) {
          ShowTrayMenu(*context);
        }
        return 0;
      }
      if (trayEvent == WM_LBUTTONDBLCLK || trayEvent == NIN_BALLOONUSERCLICK || trayEvent == NIN_SELECT ||
          trayEvent == NIN_KEYSELECT) {
        RestoreFromTray(hwnd);
        if (context != nullptr) {
          SelectPage(*context, ClientPage::Dashboard);
          LayoutControls(*context);
        }
        return 0;
      }
      break;
    }
    case WM_ERASEBKGND: {
      RECT client{};
      GetClientRect(hwnd, &client);
      auto* context = GetContext(hwnd);
      FillRect(reinterpret_cast<HDC>(wParam), &client, context != nullptr ? context->windowBrush : GetSysColorBrush(COLOR_WINDOW));
      return 1;
    }

    case WM_CTLCOLORSTATIC: {
      auto* context = GetContext(hwnd);
      auto* control = reinterpret_cast<HWND>(lParam);
      auto hdc = reinterpret_cast<HDC>(wParam);
      if (context == nullptr || control == nullptr) {
        break;
      }

      SetBkMode(hdc, OPAQUE);
      SetTextColor(hdc, ResolveStaticTextColor(*context, control));
      const auto brush = ResolveStaticBrush(*context, control);
      if (brush == context->windowBrush) {
        SetBkColor(hdc, WindowBackgroundColor());
      } else if (brush == context->detailsBrush) {
        SetBkColor(hdc, DetailsCardColor());
      } else if (brush == context->summarySafeBrush) {
        SetBkColor(hdc, SummarySafeColor());
      } else if (brush == context->summaryWarningBrush) {
        SetBkColor(hdc, SummaryWarningColor());
      } else if (brush == context->summaryDangerBrush) {
        SetBkColor(hdc, SummaryDangerColor());
      } else if (brush == context->metricInfoBrush) {
        SetBkColor(hdc, MetricInfoColor());
      } else if (brush == context->metricSuccessBrush) {
        SetBkColor(hdc, MetricSuccessColor());
      } else if (brush == context->metricWarningBrush) {
        SetBkColor(hdc, MetricWarningColor());
      } else if (brush == context->metricDangerBrush) {
        SetBkColor(hdc, MetricDangerColor());
      } else {
        SetBkColor(hdc, SurfaceColor());
      }
      return reinterpret_cast<INT_PTR>(brush);
    }

    case WM_CTLCOLOREDIT: {
      auto* context = GetContext(hwnd);
      auto* control = reinterpret_cast<HWND>(lParam);
      auto hdc = reinterpret_cast<HDC>(wParam);
      if (context == nullptr || control != context->detailEdit) {
        break;
      }

      SetBkMode(hdc, OPAQUE);
      SetBkColor(hdc, DetailColor());
      SetTextColor(hdc, DarkTextColor());
      return reinterpret_cast<INT_PTR>(context->detailBrush);
    }

    case WM_DRAWITEM: {
      auto* context = GetContext(hwnd);
      auto* draw = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
      if (context == nullptr || draw == nullptr || draw->CtlType != ODT_BUTTON) {
        break;
      }

      DrawOwnerButton(draw, *context);
      return TRUE;
    }

    case WM_CREATE: {
      auto* context = new UiContext{};
      context->config = antivirus::agent::LoadAgentConfigForModule(nullptr);
      context->hwnd = hwnd;
      const auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
      const auto* launchOptions = create != nullptr ? reinterpret_cast<LaunchOptions*>(create->lpCreateParams) : nullptr;
      context->backgroundMode = launchOptions != nullptr && launchOptions->backgroundMode;
      context->manageExclusionsMode = launchOptions != nullptr && launchOptions->manageExclusionsMode;
      SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(context));
      ApplyDarkWindowChrome(hwnd);

      NONCLIENTMETRICSW metrics{};
      metrics.cbSize = sizeof(metrics);
      SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0);
      wcscpy_s(metrics.lfMessageFont.lfFaceName, L"Segoe UI Variable Text");
      context->bodyFont = CreateFontIndirectW(&metrics.lfMessageFont);
      auto titleFont = metrics.lfMessageFont;
      titleFont.lfHeight = 32;
      titleFont.lfWeight = FW_BOLD;
      wcscpy_s(titleFont.lfFaceName, L"Segoe UI Variable");
      context->titleFont = CreateFontIndirectW(&titleFont);
      auto headingFont = metrics.lfMessageFont;
      headingFont.lfHeight = 17;
      headingFont.lfWeight = FW_SEMIBOLD;
      wcscpy_s(headingFont.lfFaceName, L"Segoe UI Variable");
      context->headingFont = CreateFontIndirectW(&headingFont);
      CreateThemeResources(*context);
      CreateBrandIcons(*context);
      SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(context->iconNeutralSmall));
      SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(context->iconNeutralLarge));

      context->brandCard = CreateCard(hwnd, IDC_BRAND_CARD);
      context->brandLogo = CreateWindowW(L"STATIC", nullptr, WS_CHILD | WS_VISIBLE | SS_ICON | SS_CENTERIMAGE,
                                         0, 0, 0, 0, context->brandCard, nullptr, nullptr, nullptr);
      context->brandSummary = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                                            0, 0, 0, 0, context->brandCard, nullptr, nullptr, nullptr);
      context->titleLabel = CreateWindowW(L"STATIC", kWindowTitle, WS_CHILD | WS_VISIBLE,
                                          0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_TITLE), nullptr, nullptr);
      context->subtitleLabel = CreateWindowW(L"STATIC", BuildSubtitleText().c_str(), WS_CHILD | WS_VISIBLE,
                                             0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SUBTITLE), nullptr, nullptr);
      context->statusBadge = CreateCard(hwnd, IDC_STATUS_BADGE);
      context->primarySectionTitle = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                                   0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PRIMARY_SECTION_TITLE), nullptr, nullptr);
      context->secondarySectionTitle = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                                     0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SECONDARY_SECTION_TITLE), nullptr, nullptr);
      context->summaryCard = CreateCard(hwnd, IDC_SUMMARY_CARD);
      context->detailsCard = CreateCard(hwnd, IDC_DETAILS_CARD);
      context->metricThreats = CreateCard(hwnd, IDC_METRIC_THREATS);
      context->metricQuarantine = CreateCard(hwnd, IDC_METRIC_QUARANTINE);
      context->metricService = CreateCard(hwnd, IDC_METRIC_SERVICE);
      context->metricSync = CreateCard(hwnd, IDC_METRIC_SYNC);
      context->navDashboardButton = CreateWindowW(L"BUTTON", L"Home", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                  0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_DASHBOARD), nullptr, nullptr);
      context->navThreatsButton = CreateWindowW(L"BUTTON", L"Findings", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_THREATS), nullptr, nullptr);
      context->navQuarantineButton = CreateWindowW(L"BUTTON", L"Quarantine", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                   0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_QUARANTINE), nullptr, nullptr);
      context->navScansButton = CreateWindowW(L"BUTTON", L"Scans", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_SCANS), nullptr, nullptr);
      context->navHistoryButton = CreateWindowW(L"BUTTON", L"History", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_HISTORY), nullptr, nullptr);
      context->navSettingsButton = CreateWindowW(L"BUTTON", L"Settings", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_SETTINGS), nullptr, nullptr);
      context->quickScanButton = CreateWindowW(L"BUTTON", L"Quick scan", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                               0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_QUICKSCAN), nullptr, nullptr);
      context->fullScanButton = CreateWindowW(L"BUTTON", L"Full scan", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_FULLSCAN), nullptr, nullptr);
      context->customScanButton = CreateWindowW(L"BUTTON", L"Scan folder", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_CUSTOMSCAN), nullptr, nullptr);
      context->refreshButton = CreateWindowW(L"BUTTON", L"Refresh status", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                             0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_REFRESH), nullptr, nullptr);
      context->startServiceButton = CreateWindowW(L"BUTTON", L"Start protection", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                  0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_STARTSERVICE), nullptr, nullptr);
      context->openQuarantineButton = CreateWindowW(L"BUTTON", L"Review quarantine", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                    0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_OPENQUARANTINE), nullptr, nullptr);
      context->scanStatusLabel = CreateWindowW(L"STATIC", L"Ready.", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                               0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SCAN_STATUS), nullptr, nullptr);
      context->progressBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr, WS_CHILD | PBS_SMOOTH,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PROGRESS), nullptr, nullptr);
      context->threatsList = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                              WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_THREATS_LIST), nullptr, nullptr);
      context->quarantineList = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_QUARANTINE_LIST), nullptr, nullptr);
      context->historyList = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                              WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_HISTORY_LIST), nullptr, nullptr);
      context->detailEdit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                                                                 ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_DETAIL_EDIT), nullptr, nullptr);
      context->restoreButton = CreateWindowW(L"BUTTON", L"Restore", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                             0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_RESTORE), nullptr, nullptr);
      context->deleteButton = CreateWindowW(L"BUTTON", L"Delete", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_DELETE), nullptr, nullptr);

      const std::vector<HWND> bodyControls = {
          context->brandCard,         context->brandLogo,       context->brandSummary,     context->subtitleLabel,
          context->statusBadge,        context->primarySectionTitle,
          context->secondarySectionTitle, context->summaryCard,  context->detailsCard,      context->metricThreats,
          context->metricQuarantine,  context->metricService,    context->metricSync,       context->navDashboardButton,
          context->navThreatsButton,  context->navQuarantineButton, context->navScansButton,
          context->navHistoryButton,  context->navSettingsButton, context->quickScanButton, context->fullScanButton,
          context->customScanButton,  context->refreshButton,    context->startServiceButton, context->openQuarantineButton,
          context->scanStatusLabel,   context->detailEdit,       context->restoreButton,    context->deleteButton};
      for (const auto control : bodyControls) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(context->bodyFont), TRUE);
      }
      SendMessageW(context->titleLabel, WM_SETFONT, reinterpret_cast<WPARAM>(context->titleFont), TRUE);
      SendMessageW(context->subtitleLabel, WM_SETFONT, reinterpret_cast<WPARAM>(context->headingFont), TRUE);
      SendMessageW(context->brandSummary, WM_SETFONT, reinterpret_cast<WPARAM>(context->bodyFont), TRUE);
      SendMessageW(context->brandLogo, STM_SETIMAGE, IMAGE_ICON, reinterpret_cast<LPARAM>(context->iconNeutralLarge));

      InitializeListView(context->threatsList);
      InitializeListView(context->quarantineList);
      InitializeListView(context->historyList);
      SetWindowTheme(context->threatsList, L"Explorer", nullptr);
      SetWindowTheme(context->quarantineList, L"Explorer", nullptr);
      SetWindowTheme(context->historyList, L"Explorer", nullptr);
      ListView_SetBkColor(context->threatsList, ListBackColor());
      ListView_SetTextBkColor(context->threatsList, ListBackColor());
      ListView_SetTextColor(context->threatsList, DarkTextColor());
      ListView_SetBkColor(context->quarantineList, ListBackColor());
      ListView_SetTextBkColor(context->quarantineList, ListBackColor());
      ListView_SetTextColor(context->quarantineList, DarkTextColor());
      ListView_SetBkColor(context->historyList, ListBackColor());
      ListView_SetTextBkColor(context->historyList, ListBackColor());
      ListView_SetTextColor(context->historyList, DarkTextColor());
      SendMessageW(context->progressBar, PBM_SETBKCOLOR, 0, static_cast<LPARAM>(DetailsCardColor()));
      SendMessageW(context->progressBar, PBM_SETBARCOLOR, 0, static_cast<LPARAM>(AccentBlue()));

      ConfigureListViewColumns(context->threatsList,
                               {{L"Detected", 170}, {L"Alert", 360}, {L"Action", 110},
                                {L"Confidence", 100}, {L"Context", 180}, {L"Remediation", 130}});
      ConfigureListViewColumns(context->quarantineList,
                               {{L"Captured", 170}, {L"Original path", 380}, {L"Status", 120},
                                {L"Technique", 160}, {L"SHA-256", 260}});
      ConfigureListViewColumns(context->historyList,
                               {{L"Recorded", 170}, {L"Result", 110}, {L"Alert", 360},
                                {L"Context", 150}, {L"Origin", 140}, {L"Remediation", 130}});

      SetScanRunning(*context, false, L"Ready.");
      RefreshSnapshot(*context);
      SelectPage(*context, context->manageExclusionsMode ? ClientPage::Settings : ClientPage::Dashboard);
      const auto webViewStarted = InitializeWebViewHost(*context);
      if (context->manageExclusionsMode && !webViewStarted) {
        SendMessageW(context->detailEdit, EM_SETREADONLY, FALSE, 0);
        SetWindowTextSafe(context->secondarySectionTitle, L"Exclusions editor");
        SetWindowTextSafe(context->scanStatusLabel, BuildExclusionEditorSummary());
        SetWindowTextSafe(context->detailEdit, BuildExclusionsEditorText());
      } else if (!webViewStarted) {
        const auto fallbackStatus = BuildWebViewFallbackStatus(*context);
        SetWindowTextSafe(context->scanStatusLabel, fallbackStatus);
        context->scanStatusText = fallbackStatus;
      }
      ShowWindow(context->navServiceButton, SW_HIDE);
      LayoutControls(*context);
      if (!context->manageExclusionsMode) {
        SetTimer(hwnd, kRefreshTimerId, kRefreshIntervalMs, nullptr);
      }
      return 0;
    }

    case WM_SIZE: {
      if (auto* context = GetContext(hwnd)) {
        if (context->webViewReady) {
          ResizeWebView(*context);
        } else {
          LayoutControls(*context);
        }
      }
      return 0;
    }

    case WM_TIMER: {
      if (wParam == kRefreshTimerId) {
        if (auto* context = GetContext(hwnd)) {
          RefreshSnapshot(*context);
        }
      }
      return 0;
    }

    case WM_NOTIFY: {
      auto* context = GetContext(hwnd);
      if (context == nullptr) {
        break;
      }

      const auto* header = reinterpret_cast<NMHDR*>(lParam);
      if (header == nullptr) {
        break;
      }

      if ((header->hwndFrom == context->threatsList || header->hwndFrom == context->quarantineList ||
           header->hwndFrom == context->historyList) &&
          header->code == NM_CUSTOMDRAW) {
        return HandleListCustomDraw(reinterpret_cast<NMLVCUSTOMDRAW*>(lParam));
      }

      if ((header->hwndFrom == context->threatsList || header->hwndFrom == context->quarantineList ||
           header->hwndFrom == context->historyList) &&
          header->code == LVN_ITEMCHANGED) {
        UpdateDetailPane(*context);
        if (context->currentPage == ClientPage::Dashboard) {
          LayoutControls(*context);
        }
        return 0;
      }
      break;
    }

    case WM_COMMAND: {
      auto* context = GetContext(hwnd);
      if (context == nullptr) {
        return 0;
      }

      switch (LOWORD(wParam)) {
        case IDC_NAV_DASHBOARD:
          SelectPage(*context, ClientPage::Dashboard);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_THREATS:
          SelectPage(*context, ClientPage::Threats);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_QUARANTINE:
          SelectPage(*context, ClientPage::Quarantine);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_SCANS:
          SelectPage(*context, ClientPage::Scans);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_SERVICE:
          SelectPage(*context, ClientPage::Service);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_HISTORY:
          SelectPage(*context, ClientPage::History);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_SETTINGS:
          SelectPage(*context, ClientPage::Settings);
          LayoutControls(*context);
          return 0;
        case IDC_BUTTON_REFRESH:
          RefreshSnapshot(*context);
          return 0;
        case IDC_BUTTON_QUICKSCAN:
          RunScanAsync(hwnd, *context, ScanPreset::Quick, std::nullopt);
          return 0;
        case IDC_BUTTON_FULLSCAN:
          RunScanAsync(hwnd, *context, ScanPreset::Full, std::nullopt);
          return 0;
        case IDC_BUTTON_CUSTOMSCAN: {
          const auto folder = PickFolder(hwnd);
          if (folder.has_value()) {
            RunScanAsync(hwnd, *context, ScanPreset::Folder, std::filesystem::path(*folder));
          }
          return 0;
        }
        case IDC_BUTTON_STARTSERVICE:
          if (!RequireAuthorizedLocalAction(hwnd, antivirus::agent::LocalAction::StartServiceAction, kWindowTitle)) {
            return 0;
          }
          if (!antivirus::agent::StartAgentService()) {
            MessageBoxW(hwnd, L"Unable to start the protection service from the local client.",
                        kWindowTitle, MB_OK | MB_ICONWARNING);
          }
          RefreshSnapshot(*context);
          return 0;
        case IDC_BUTTON_OPENQUARANTINE:
          if (context->currentPage == ClientPage::Settings) {
            if (context->manageExclusionsMode) {
              if (SaveExclusionsFromEditor(hwnd, *context)) {
                DestroyWindow(hwnd);
              }
              return 0;
            }

            if (!RequireAuthorizedLocalAction(hwnd, antivirus::agent::LocalAction::EditExclusions, kWindowTitle)) {
              return 0;
            }
            if (!LaunchExclusionsEditor(hwnd)) {
              MessageBoxW(hwnd, L"Unable to open the elevated exclusions editor.", kWindowTitle,
                          MB_OK | MB_ICONWARNING);
            }
            return 0;
          }

          SelectPage(*context, ClientPage::Quarantine);
          LayoutControls(*context);
          return 0;
        case IDC_BUTTON_RESTORE:
          PerformQuarantineAction(*context, true);
          return 0;
        case IDC_BUTTON_DELETE:
          PerformQuarantineAction(*context, false);
          return 0;
        case IDM_TRAY_OPEN:
          RestoreFromTray(hwnd);
          SelectPage(*context, ClientPage::Dashboard);
          LayoutControls(*context);
          return 0;
        case IDM_TRAY_QUICKSCAN:
          RunScanAsync(hwnd, *context, ScanPreset::Quick, std::nullopt);
          return 0;
        case IDM_TRAY_FULLSCAN:
          RunScanAsync(hwnd, *context, ScanPreset::Full, std::nullopt);
          return 0;
        case IDM_TRAY_PAM_POWERSHELL:
          SubmitPowerShellPamRequest(hwnd, *context);
          return 0;
        case IDM_TRAY_PAM_CMD:
          SubmitCommandPromptPamRequest(hwnd, *context);
          return 0;
        case IDM_TRAY_PAM_DISKCLEANUP:
          SubmitDiskCleanupPamRequest(hwnd, *context);
          return 0;
        case IDM_TRAY_PAM_WINDOWSUPDATE:
          SubmitWindowsUpdatePamRequest(hwnd, *context);
          return 0;
        case IDM_TRAY_PAM_NETWORKRESET:
          SubmitNetworkResetPamRequest(hwnd, *context);
          return 0;
        case IDM_TRAY_PAM_APP:
          SubmitApplicationPamRequest(hwnd, *context);
          return 0;
        case IDM_TRAY_PAM_ELEVATE_2M:
          SubmitTimedPamRequest(hwnd, *context);
          return 0;
        case IDM_TRAY_QUARANTINE:
          RestoreFromTray(hwnd);
          SelectPage(*context, ClientPage::Quarantine);
          LayoutControls(*context);
          return 0;
        case IDM_TRAY_EXIT:
          context->allowExit = true;
          DestroyWindow(hwnd);
          return 0;
        default:
          return 0;
      }
    }

    case kScanCompleteMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<ScanCompletePayload*>(lParam);
      if (context != nullptr && payload != nullptr) {
        context->scanRunning = false;
        context->activeScanLabel.clear();
        SetScanRunning(*context, false, payload->summary);
        RefreshSnapshot(*context);
        SelectPage(*context, context->snapshot.openThreatCount != 0 ? ClientPage::Threats : ClientPage::Scans);
        LayoutControls(*context);
        if (IsWindowInteractive(*context)) {
          MessageBoxW(hwnd, payload->summary.c_str(), kWindowTitle,
                      MB_OK | (payload->success ? MB_ICONINFORMATION : MB_ICONWARNING));
        } else {
          ShowTrayNotification(*context, payload->success ? L"Scan completed" : L"Scan needs attention",
                               payload->summary, payload->success ? NIIF_INFO : NIIF_WARNING);
        }
      }
      delete payload;
      return 0;
    }

    case kPatchActionCompleteMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<PatchActionCompletePayload*>(lParam);
      if (context != nullptr && payload != nullptr) {
        SetPatchActionRunning(*context, false, payload->summary, payload->targetId, payload->searchOnly);
        RefreshSnapshot(*context);
        if (IsWindowInteractive(*context) && !payload->suppressDialog) {
          MessageBoxW(hwnd, payload->summary.c_str(), kWindowTitle,
                      MB_OK | (payload->informational ? MB_ICONINFORMATION : MB_ICONWARNING));
        } else {
          const auto successTitle = payload->searchOnly ? L"Software check completed" : L"Software update completed";
          const auto warningTitle = payload->searchOnly ? L"Software check needs attention"
                                                        : L"Software update needs attention";
          ShowTrayNotification(*context, payload->success ? successTitle : warningTitle, payload->summary,
                               payload->informational ? NIIF_INFO : NIIF_WARNING);
        }
      }
      delete payload;
      return 0;
    }

    case kScanProgressMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<ScanProgressPayload*>(lParam);
      if (context != nullptr && payload != nullptr && context->scanRunning) {
        UpdateScanProgress(*context, payload->status, payload->completedTargets, payload->totalTargets);
      }
      delete payload;
      return 0;
    }

    case WM_CLOSE: {
      auto* context = GetContext(hwnd);
      if (context != nullptr && !context->allowExit) {
        HideToTray(hwnd);
        return 0;
      }

      DestroyWindow(hwnd);
      return 0;
    }

    case WM_DESTROY: {
      auto* context = GetContext(hwnd);
      if (context != nullptr) {
        KillTimer(hwnd, kRefreshTimerId);
        if (context->trayAdded) {
          Shell_NotifyIconW(NIM_DELETE, &context->trayIcon);
        }
        DestroyWebViewHost(*context);
        if (context->titleFont != nullptr) {
          DeleteObject(context->titleFont);
        }
        if (context->headingFont != nullptr) {
          DeleteObject(context->headingFont);
        }
        if (context->bodyFont != nullptr) {
          DeleteObject(context->bodyFont);
        }
        DestroyBrandIcons(*context);
        DestroyThemeResources(*context);
        delete context;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
      }

      if (g_instanceMutex != nullptr) {
        CloseHandle(g_instanceMutex);
        g_instanceMutex = nullptr;
      }

      PostQuitMessage(0);
      return 0;
    }
  }

  return DefWindowProcW(hwnd, message, wParam, lParam);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
  INITCOMMONCONTROLSEX controls{};
  controls.dwSize = sizeof(controls);
  controls.dwICC = ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_TAB_CLASSES;
  InitCommonControlsEx(&controls);
  OleInitialize(nullptr);
  const auto launchOptions = ParseLaunchOptions();

  if (launchOptions.applyExclusionsMode) {
    const auto exitCode = ApplyExclusionsFromLaunchOptions(launchOptions);
    OleUninitialize();
    return exitCode;
  }

  if (launchOptions.applySoftwareUpdateMode) {
    const auto exitCode = ApplySoftwareUpdateFromLaunchOptions(launchOptions);
    OleUninitialize();
    return exitCode;
  }

  const wchar_t* mutexName =
      launchOptions.manageExclusionsMode ? L"Local\\FenrirEndpointClientSingleton.ManageExclusions" : kInstanceMutexName;
  g_instanceMutex = CreateMutexW(nullptr, FALSE, mutexName);
  if (g_instanceMutex != nullptr && GetLastError() == ERROR_ALREADY_EXISTS) {
    if (!launchOptions.backgroundMode && !launchOptions.manageExclusionsMode) {
      PostMessageW(HWND_BROADCAST, RestoreWindowMessageId(), 0, 0);
    }
    CloseHandle(g_instanceMutex);
    g_instanceMutex = nullptr;
    OleUninitialize();
    return 0;
  }

  HICON classLargeIcon = CreateBrandIcon(32, BrandIconTone::Neutral);
  HICON classSmallIcon = CreateBrandIcon(16, BrandIconTone::Neutral);

  WNDCLASSEXW windowClass{};
  windowClass.cbSize = sizeof(windowClass);
  windowClass.lpfnWndProc = WindowProc;
  windowClass.hInstance = instance;
  windowClass.lpszClassName = kWindowClassName;
  windowClass.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
  windowClass.hIcon = classLargeIcon;
  windowClass.hIconSm = classSmallIcon;
  windowClass.hbrBackground = nullptr;
  RegisterClassExW(&windowClass);

  HWND hwnd = CreateWindowExW(0, kWindowClassName, kWindowTitle, WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, 1440, 980,
                              nullptr, nullptr, instance, const_cast<LaunchOptions*>(&launchOptions));
  if (hwnd == nullptr) {
    DestroyIcon(classLargeIcon);
    DestroyIcon(classSmallIcon);
    if (g_instanceMutex != nullptr) {
      CloseHandle(g_instanceMutex);
      g_instanceMutex = nullptr;
    }
    OleUninitialize();
    return 1;
  }

  ShowWindow(hwnd, launchOptions.backgroundMode ? SW_HIDE : (showCommand == 0 ? SW_SHOWDEFAULT : showCommand));
  UpdateWindow(hwnd);

  MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }

  DestroyIcon(classLargeIcon);
  DestroyIcon(classSmallIcon);
  OleUninitialize();
  return static_cast<int>(message.wParam);
}
