#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <strsafe.h>

#include <array>
#include <cstdlib>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

namespace {

constexpr wchar_t kWindowClassName[] = L"FenrirPamWindow";
constexpr wchar_t kWindowTitle[] = L"Fenrir PAM";
constexpr wchar_t kInstanceMutexName[] = L"Local\\FenrirPamSingleton";
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT_PTR kTrayIconId = 1;
constexpr int kTrayMenuOpenDashboard = 3001;
constexpr int kTrayMenuPowerShell = 3002;
constexpr int kTrayMenuCommandPrompt = 3003;
constexpr int kTrayMenuDiskCleanup = 3004;
constexpr int kTrayMenuRunApplication = 3005;
constexpr int kTrayMenuTimedElevate = 3006;
constexpr int kTrayMenuRefreshAudit = 3007;
constexpr int kTrayMenuExit = 3008;

struct PamContext {
  HWND hwnd{};
  NOTIFYICONDATAW trayIcon{};
  bool exiting{false};
  std::filesystem::path auditJournalPath;
};

HANDLE g_instanceMutex = nullptr;

PamContext* GetContext(HWND hwnd) {
  return reinterpret_cast<PamContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
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

std::filesystem::path GetDashboardPath() {
  return GetCurrentExecutableDirectory() / L"fenrir-endpoint-client.exe";
}

std::filesystem::path GetAuditJournalPath() {
  const auto programData = _wgetenv(L"PROGRAMDATA");
  const auto base = (programData != nullptr && *programData != L'\0')
                        ? std::filesystem::path(programData)
                        : std::filesystem::path(L"C:\\ProgramData");
  return base / L"FenrirAgent" / L"runtime" / L"privilege-requests.jsonl";
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

std::wstring QuoteJson(const std::wstring& value) {
  std::wstringstream stream;
  for (const auto ch : value) {
    switch (ch) {
      case L'\\': stream << L"\\\\"; break;
      case L'"': stream << L"\\\""; break;
      case L'\r': stream << L"\\r"; break;
      case L'\n': stream << L"\\n"; break;
      case L'\t': stream << L"\\t"; break;
      default: stream << ch; break;
    }
  }
  return stream.str();
}

std::wstring FormatTimestamp() {
  SYSTEMTIME time{};
  GetLocalTime(&time);
  wchar_t buffer[64]{};
  swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u:%02u",
             static_cast<unsigned>(time.wYear), static_cast<unsigned>(time.wMonth),
             static_cast<unsigned>(time.wDay), static_cast<unsigned>(time.wHour),
             static_cast<unsigned>(time.wMinute), static_cast<unsigned>(time.wSecond));
  return buffer;
}

std::string WideToUtf8(const std::wstring& value) {
  if (value.empty()) {
    return {};
  }

  const auto required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0,
                                            nullptr, nullptr);
  if (required <= 0) {
    return {};
  }

  std::string result(static_cast<std::size_t>(required), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), required, nullptr,
                      nullptr);
  return result;
}

bool EnsureDirectory(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  return !error;
}

bool AppendAuditEntry(const std::wstring& action, const std::wstring& target, const std::wstring& decision,
                      const std::wstring& reason) {
  const auto journalPath = GetAuditJournalPath();
  if (!EnsureDirectory(journalPath.parent_path())) {
    return false;
  }

  const std::wstring line =
      L"{\"timestamp\":\"" + QuoteJson(FormatTimestamp()) + L"\",\"action\":\"" + QuoteJson(action) +
      L"\",\"target\":\"" + QuoteJson(target) + L"\",\"decision\":\"" + QuoteJson(decision) +
      L"\",\"reason\":\"" + QuoteJson(reason) + L"\"}\r\n";

  const auto utf8 = WideToUtf8(line);
  if (utf8.empty()) {
    return false;
  }

  const auto file = CreateFileW(journalPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }

  DWORD written = 0;
  const auto ok = WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr) != FALSE &&
                  written == utf8.size();
  CloseHandle(file);
  return ok;
}

bool LaunchShellExecute(HWND owner, const std::filesystem::path& executable, const std::wstring& parameters,
                        const std::wstring& verb, const std::wstring& reason, const std::wstring& action) {
  const auto result = reinterpret_cast<INT_PTR>(ShellExecuteW(owner, verb.c_str(), executable.c_str(),
                                                               parameters.empty() ? nullptr : parameters.c_str(),
                                                               executable.parent_path().c_str(), SW_SHOWNORMAL));
  if (result <= 32) {
    return false;
  }

  AppendAuditEntry(action, executable.wstring(), L"approved", reason);
  return true;
}

bool LaunchDashboard(HWND owner) {
  return LaunchShellExecute(owner, GetDashboardPath(), L"", L"open", L"User opened the Fenrir dashboard",
                            L"open-dashboard");
}

bool LaunchSystemTool(HWND owner, const wchar_t* toolRelativePath, const wchar_t* parameters,
                      const wchar_t* actionLabel) {
  const auto executable = GetSystemBinaryPath(toolRelativePath);
  if (executable.empty()) {
    return false;
  }

  return LaunchShellExecute(owner, executable, parameters != nullptr ? parameters : L"", L"runas",
                            L"User approved built-in PAM tool launch", actionLabel);
}

bool PromptForElevationTarget(HWND owner, std::filesystem::path* targetPath) {
  if (targetPath == nullptr) {
    return false;
  }

  std::array<wchar_t, 32768> buffer{};
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = owner;
  ofn.lpstrFilter = L"Executables (*.exe;*.com;*.bat;*.cmd)\0*.exe;*.com;*.bat;*.cmd\0All files (*.*)\0*.*\0\0";
  ofn.lpstrFile = buffer.data();
  ofn.nMaxFile = static_cast<DWORD>(buffer.size());
  ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
  ofn.lpstrTitle = L"Select an application to elevate";

  if (!GetOpenFileNameW(&ofn)) {
    return false;
  }

  *targetPath = std::filesystem::path(buffer.data());
  return true;
}

bool LaunchApplicationAsAdmin(HWND owner, const std::wstring& reason, const std::wstring& actionLabel) {
  std::filesystem::path targetPath;
  if (!PromptForElevationTarget(owner, &targetPath)) {
    return false;
  }

  const auto response = MessageBoxW(
      owner,
      (L"Fenrir will launch this application with administrator rights once:\r\n\r\n" + targetPath.wstring() +
       L"\r\n\r\nApprove this one-time elevation?")
          .c_str(),
      kWindowTitle, MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2);
  if (response != IDOK) {
    AppendAuditEntry(actionLabel, targetPath.wstring(), L"denied", reason);
    return false;
  }

  return LaunchShellExecute(owner, targetPath, L"", L"runas", reason, actionLabel);
}

bool LaunchTimedElevation(HWND owner) {
  std::filesystem::path targetPath;
  if (!PromptForElevationTarget(owner, &targetPath)) {
    return false;
  }

  const auto response = MessageBoxW(
      owner,
      (L"Fenrir will approve this application for a 2 minute elevation window:\r\n\r\n" + targetPath.wstring() +
       L"\r\n\r\nApprove this one-time elevation?")
          .c_str(),
      kWindowTitle, MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2);
  if (response != IDOK) {
    AppendAuditEntry(L"timed-elevate", targetPath.wstring(), L"denied", L"User denied the 2 minute elevation");
    return false;
  }

  return LaunchShellExecute(owner, targetPath, L"", L"runas",
                            L"User approved a timed 2 minute elevation window", L"timed-elevate");
}

void RefreshAudit(HWND owner) {
  const auto journalPath = GetAuditJournalPath();
  if (!std::filesystem::exists(journalPath)) {
    MessageBoxW(owner, L"No PAM audit entries have been recorded yet.", kWindowTitle, MB_OK | MB_ICONINFORMATION);
    return;
  }

  ShellExecuteW(owner, L"open", L"notepad.exe", journalPath.c_str(), nullptr, SW_SHOWNORMAL);
}

void AddTrayIcon(PamContext& context) {
  context.trayIcon = {};
  context.trayIcon.cbSize = sizeof(context.trayIcon);
  context.trayIcon.hWnd = context.hwnd;
  context.trayIcon.uID = kTrayIconId;
  context.trayIcon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
  context.trayIcon.uCallbackMessage = kTrayMessage;
  context.trayIcon.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(100));
  StringCchCopyW(context.trayIcon.szTip, sizeof(context.trayIcon.szTip) / sizeof(context.trayIcon.szTip[0]),
                 kWindowTitle);
  Shell_NotifyIconW(NIM_ADD, &context.trayIcon);
}

void RemoveTrayIcon(PamContext& context) {
  if (context.trayIcon.hWnd != nullptr) {
    Shell_NotifyIconW(NIM_DELETE, &context.trayIcon);
  }
}

void ShowTrayMenu(PamContext& context) {
  HMENU menu = CreatePopupMenu();
  if (menu == nullptr) {
    return;
  }

  AppendMenuW(menu, MF_STRING, kTrayMenuOpenDashboard, L"Open Fenrir dashboard");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, kTrayMenuPowerShell, L"Run PowerShell as admin");
  AppendMenuW(menu, MF_STRING, kTrayMenuCommandPrompt, L"Run Command Prompt as admin");
  AppendMenuW(menu, MF_STRING, kTrayMenuDiskCleanup, L"Run Disk Cleanup as admin");
  AppendMenuW(menu, MF_STRING, kTrayMenuRunApplication, L"Run application as admin...");
  AppendMenuW(menu, MF_STRING, kTrayMenuTimedElevate, L"Elevate as admin (2 minutes)");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, kTrayMenuRefreshAudit, L"Refresh audit");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, kTrayMenuExit, L"Exit Fenrir PAM");

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

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
  switch (message) {
    case kTrayMessage: {
      auto* context = GetContext(hwnd);
      if (context != nullptr) {
        if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU || lParam == NIN_POPUPOPEN) {
          ShowTrayMenu(*context);
        } else if (lParam == WM_LBUTTONDBLCLK || lParam == NIN_SELECT || lParam == NIN_KEYSELECT) {
          LaunchDashboard(hwnd);
        }
      }
      return 0;
    }
    case WM_COMMAND: {
      auto* context = GetContext(hwnd);
      if (context == nullptr) {
        return 0;
      }

      switch (LOWORD(wParam)) {
        case kTrayMenuOpenDashboard:
          LaunchDashboard(hwnd);
          return 0;
        case kTrayMenuPowerShell:
          LaunchSystemTool(hwnd, L"WindowsPowerShell\\v1.0\\powershell.exe", L"-NoProfile -NoExit",
                           L"powershell");
          return 0;
        case kTrayMenuCommandPrompt:
          LaunchSystemTool(hwnd, L"cmd.exe", L"/k", L"cmd");
          return 0;
        case kTrayMenuDiskCleanup:
          LaunchSystemTool(hwnd, L"cleanmgr.exe", L"", L"disk-cleanup");
          return 0;
        case kTrayMenuRunApplication:
          LaunchApplicationAsAdmin(hwnd, L"User approved built-in PAM tool launch", L"custom-elevation");
          return 0;
        case kTrayMenuTimedElevate:
          LaunchTimedElevation(hwnd);
          return 0;
        case kTrayMenuRefreshAudit:
          RefreshAudit(hwnd);
          return 0;
        case kTrayMenuExit:
          context->exiting = true;
          DestroyWindow(hwnd);
          return 0;
        default:
          return 0;
      }
    }
    case WM_CLOSE: {
      auto* context = GetContext(hwnd);
      if (context != nullptr && !context->exiting) {
        ShowWindow(hwnd, SW_HIDE);
        return 0;
      }
      DestroyWindow(hwnd);
      return 0;
    }
    case WM_DESTROY: {
      auto* context = GetContext(hwnd);
      if (context != nullptr) {
        RemoveTrayIcon(*context);
      }
      PostQuitMessage(0);
      return 0;
    }
    default:
      return DefWindowProcW(hwnd, message, wParam, lParam);
  }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
  g_instanceMutex = CreateMutexW(nullptr, TRUE, kInstanceMutexName);
  if (g_instanceMutex == nullptr) {
    return 1;
  }
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(g_instanceMutex);
    g_instanceMutex = nullptr;
    return 0;
  }

  PamContext context{};
  context.auditJournalPath = GetAuditJournalPath();

  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = WindowProc;
  wc.hInstance = instance;
  wc.lpszClassName = kWindowClassName;
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(100));
  wc.hIconSm = wc.hIcon;
  RegisterClassExW(&wc);

  HWND hwnd = CreateWindowExW(0, kWindowClassName, kWindowTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                              CW_USEDEFAULT, CW_USEDEFAULT, nullptr, nullptr, instance, nullptr);
  if (hwnd == nullptr) {
    return 1;
  }

  SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&context));
  context.hwnd = hwnd;
  AddTrayIcon(context);

  ShowWindow(hwnd, SW_HIDE);
  UpdateWindow(hwnd);

  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  if (g_instanceMutex != nullptr) {
    ReleaseMutex(g_instanceMutex);
    CloseHandle(g_instanceMutex);
    g_instanceMutex = nullptr;
  }

  return static_cast<int>(msg.wParam);
}
