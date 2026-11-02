#include "BackstageDesktop.h"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

namespace fenrir::remote {

namespace {

std::wstring Quote(const std::wstring& path) { return L"\"" + path + L"\""; }

std::wstring SystemDir() {
  wchar_t path[MAX_PATH]{};
  const UINT size = GetSystemDirectoryW(path, MAX_PATH);
  return size > 0 && size < MAX_PATH ? std::wstring(path, size) : L"C:\\Windows\\System32";
}

std::wstring WindowsDir() {
  wchar_t path[MAX_PATH]{};
  const UINT size = GetWindowsDirectoryW(path, MAX_PATH);
  return size > 0 && size < MAX_PATH ? std::wstring(path, size) : L"C:\\Windows";
}

std::string Narrow(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), size, nullptr, nullptr);
  return out;
}

std::string Escape(const std::string& value) {
  std::string out;
  for (const char ch : value) {
    if (ch == '"' || ch == '\\') {
      out.push_back('\\');
      out.push_back(ch);
    } else if (static_cast<unsigned char>(ch) < 0x20) {
      out.push_back(' ');
    } else {
      out.push_back(ch);
    }
  }
  return out;
}

DWORD CurrentSession() {
  DWORD session = 0xFFFFFFFF;
  ProcessIdToSessionId(GetCurrentProcessId(), &session);
  return session;
}

}  // namespace

std::string BackstageDesktop::Open() {
  if (desktop_ != nullptr) {
    return "";
  }
  // Only ever in session 0: the user's session must never get a desktop, a window or a desktop switch from us.
  if (CurrentSession() != 0) {
    return "the backstage desktop only runs in session 0 (the helper is in session " + std::to_string(CurrentSession()) + ")";
  }
  previousStation_ = GetProcessWindowStation();  // the service's non-interactive station; not ours to close
  station_ = OpenWindowStationW(L"WinSta0", FALSE, GENERIC_ALL);
  if (station_ == nullptr) {
    return "could not open session 0's window station (error " + std::to_string(GetLastError()) + ")";
  }
  if (!SetProcessWindowStation(station_)) {
    const DWORD error = GetLastError();
    CloseWindowStation(station_);
    station_ = nullptr;
    return "could not use session 0's window station (error " + std::to_string(error) + ")";
  }
  name_ = L"FenrirBackstage-" + std::to_wstring(GetCurrentProcessId());
  desktop_ = CreateDesktopW(name_.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);  // SYSTEM-only by default
  if (desktop_ == nullptr) {
    const DWORD error = GetLastError();
    Close();
    return "could not create the hidden desktop (error " + std::to_string(error) + ")";
  }
  previousInput_ = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
  // Session 0's input desktop is the one GDI draws and SendInput reaches. Nobody looks at session 0, so switching it
  // shows nothing to anyone; the user's own session keeps its desktop.
  if (!SwitchDesktop(desktop_)) {
    const DWORD error = GetLastError();
    Close();
    return "could not switch session 0 to the hidden desktop (error " + std::to_string(error) + ")";
  }
  job_ = CreateJobObjectW(nullptr, nullptr);
  if (job_ != nullptr) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job_, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
  }
  return "";
}

void BackstageDesktop::Close() {
  if (job_ != nullptr) {
    TerminateJobObject(job_, 0);  // every tool the technician started on the hidden desktop
    CloseHandle(job_);
    job_ = nullptr;
  }
  if (previousInput_ != nullptr) {
    SwitchDesktop(previousInput_);
    CloseDesktop(previousInput_);
    previousInput_ = nullptr;
  }
  if (desktop_ != nullptr) {
    CloseDesktop(desktop_);  // destroyed once no thread uses it (at the latest when the helper exits)
    desktop_ = nullptr;
  }
  if (station_ != nullptr) {
    if (previousStation_ != nullptr) SetProcessWindowStation(previousStation_);
    CloseWindowStation(station_);
    station_ = nullptr;
  }
}

std::string BackstageDesktop::Launch(const std::string& tool, const std::wstring& commandLine) {
  if (desktop_ == nullptr) {
    return "the hidden desktop is not open";
  }
  const auto sys = SystemDir();
  const auto mmc = [&](const wchar_t* snapIn) { return Quote(sys + L"\\mmc.exe") + L" " + Quote(sys + L"\\" + snapIn); };
  std::wstring command;
  if (tool == "taskmgr") command = Quote(sys + L"\\taskmgr.exe");
  else if (tool == "regedit") command = Quote(WindowsDir() + L"\\regedit.exe");
  else if (tool == "eventvwr") command = mmc(L"eventvwr.msc");
  else if (tool == "services") command = mmc(L"services.msc");
  else if (tool == "compmgmt") command = mmc(L"compmgmt.msc");
  else if (tool == "devmgmt") command = mmc(L"devmgmt.msc");
  else if (tool == "cmd") command = Quote(sys + L"\\cmd.exe");
  else if (tool == "powershell") command = Quote(sys + L"\\WindowsPowerShell\\v1.0\\powershell.exe") + L" -NoLogo";
  else if (tool == "run") {
    if (commandLine.empty() || commandLine.size() > 2048) return "give a command line of up to 2048 characters";
    command = commandLine;
  } else {
    return "unknown tool: " + tool;
  }
  return Start(command);
}

std::string BackstageDesktop::Start(std::wstring commandLine) {
  std::wstring desktop = L"WinSta0\\" + name_;
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.lpDesktop = desktop.data();
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_SHOWNORMAL;
  PROCESS_INFORMATION process{};
  std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
  mutableCommand.push_back(L'\0');
  const auto workingDir = SystemDir();
  if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, nullptr,
                      workingDir.c_str(), &startup, &process)) {
    return "could not start it (error " + std::to_string(GetLastError()) + ")";
  }
  if (job_ != nullptr) {
    AssignProcessToJobObject(job_, process.hProcess);
  }
  ResumeThread(process.hThread);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return "";
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace {

constexpr COLORREF kTestColour = RGB(255, 0, 170);

LRESULT CALLBACK TestWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
  if (message == WM_ERASEBKGND) {
    RECT rect{};
    GetClientRect(window, &rect);
    HBRUSH brush = CreateSolidBrush(kTestColour);
    FillRect(reinterpret_cast<HDC>(wParam), &rect, brush);
    DeleteObject(brush);
    return 1;
  }
  return DefWindowProcW(window, message, wParam, lParam);
}

struct WindowCount {
  DWORD skipThread{0};
  int visible{0};
};

BOOL CALLBACK CountWindow(HWND window, LPARAM data) {
  auto* count = reinterpret_cast<WindowCount*>(data);
  if (IsWindowVisible(window) && GetWindowThreadProcessId(window, nullptr) != count->skipThread) {
    ++count->visible;
  }
  return TRUE;
}

}  // namespace

int RunBackstageSelfTest(const std::wstring& resultPath) {
  std::ostringstream json;
  const DWORD session = CurrentSession();
  const DWORD console = WTSGetActiveConsoleSessionId();
  json << "{\"helperSession\":" << session << ",\"consoleSession\":" << static_cast<long long>(console == 0xFFFFFFFF ? -1 : console);
  BackstageDesktop desktop;
  const auto openError = desktop.Open();
  bool colourFound = false;
  if (!openError.empty()) {
    json << ",\"opened\":false,\"error\":\"" << Escape(openError) << "\"";
  } else {
    json << ",\"opened\":true,\"desktop\":\"" << Escape(Narrow(desktop.Name())) << "\"";
    HDESK handle = OpenDesktopW(desktop.Name().c_str(), 0, FALSE, GENERIC_ALL);
    std::atomic<DWORD> windowThread{0};
    std::atomic<bool> windowShown{false};
    std::thread window([&] {
      windowThread = GetCurrentThreadId();
      if (handle == nullptr || !SetThreadDesktop(handle)) return;
      WNDCLASSW cls{};
      cls.lpfnWndProc = TestWindowProc;
      cls.hInstance = GetModuleHandleW(nullptr);
      cls.lpszClassName = L"FenrirBackstageSelfTest";
      RegisterClassW(&cls);
      HWND test = CreateWindowExW(WS_EX_TOPMOST, cls.lpszClassName, L"Fenrir backstage self-test", WS_POPUP | WS_VISIBLE, 100,
                                  100, 400, 300, nullptr, nullptr, cls.hInstance, nullptr);
      if (test == nullptr) return;
      ShowWindow(test, SW_SHOW);
      UpdateWindow(test);
      windowShown = true;
      MSG message;
      while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        DispatchMessageW(&message);
      }
      DestroyWindow(test);
    });
    Sleep(1500);
    const auto launchError = desktop.Launch("taskmgr");
    Sleep(3000);
    WindowCount count{windowThread.load(), 0};
    if (handle != nullptr) EnumDesktopWindows(handle, CountWindow, reinterpret_cast<LPARAM>(&count));
    // Capture what the hidden desktop shows, from a thread attached to it (this one has no windows of its own).
    int found = 0, width = GetSystemMetrics(SM_CXSCREEN), height = GetSystemMetrics(SM_CYSCREEN);
    if (handle != nullptr && SetThreadDesktop(handle)) {
      width = GetSystemMetrics(SM_CXSCREEN);
      height = GetSystemMetrics(SM_CYSCREEN);
      HDC screen = GetDC(nullptr);
      HDC memory = CreateCompatibleDC(screen);
      BITMAPINFO info{};
      info.bmiHeader.biSize = sizeof(info.bmiHeader);
      info.bmiHeader.biWidth = width;
      info.bmiHeader.biHeight = -height;
      info.bmiHeader.biPlanes = 1;
      info.bmiHeader.biBitCount = 32;
      info.bmiHeader.biCompression = BI_RGB;
      void* bits = nullptr;
      HBITMAP bitmap = width > 0 && height > 0 ? CreateDIBSection(screen, &info, DIB_RGB_COLORS, &bits, nullptr, 0) : nullptr;
      if (bitmap != nullptr) {
        HGDIOBJ old = SelectObject(memory, bitmap);
        if (BitBlt(memory, 0, 0, width, height, screen, 0, 0, SRCCOPY | CAPTUREBLT)) {
          GdiFlush();
          const auto* pixel = static_cast<const std::uint8_t*>(bits);
          for (long long i = 0; i < static_cast<long long>(width) * height; ++i, pixel += 4) {
            if (pixel[2] == GetRValue(kTestColour) && pixel[1] == GetGValue(kTestColour) && pixel[0] == GetBValue(kTestColour)) ++found;
          }
        }
        SelectObject(memory, old);
        DeleteObject(bitmap);
      }
      DeleteDC(memory);
      ReleaseDC(nullptr, screen);
    }
    colourFound = found > 400 * 300 / 2;
    if (windowThread != 0) PostThreadMessageW(windowThread, WM_QUIT, 0, 0);
    window.join();
    json << ",\"testWindowShown\":" << (windowShown ? "true" : "false") << ",\"testColourPixels\":" << found
         << ",\"screen\":{\"w\":" << width << ",\"h\":" << height << "}"
         << ",\"taskManagerStarted\":" << (launchError.empty() ? "true" : "false")
         << ",\"otherVisibleWindows\":" << count.visible;
    if (!launchError.empty()) json << ",\"taskManagerError\":\"" << Escape(launchError) << "\"";
    desktop.Close();
    if (handle != nullptr) CloseDesktop(handle);
  }
  json << ",\"captureWorks\":" << (colourFound ? "true" : "false") << "}";
  std::ofstream(std::filesystem::path(resultPath), std::ios::binary | std::ios::trunc) << json.str();
  return colourFound ? 0 : 3;
}

}  // namespace fenrir::remote
