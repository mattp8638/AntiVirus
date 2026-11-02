#include "BackstageDesktop.h"

#include <algorithm>
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
  sendInputWorks_ = ProbeSendInput();
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
// Capture: every visible window draws itself, stacked bottom to top
// ---------------------------------------------------------------------------

namespace {

BOOL CALLBACK CollectWindow(HWND window, LPARAM data) {
  RECT rect{};
  if (IsWindowVisible(window) && !IsIconic(window) && GetWindowRect(window, &rect) && rect.right > rect.left &&
      rect.bottom > rect.top) {
    reinterpret_cast<std::vector<HWND>*>(data)->push_back(window);
  }
  return TRUE;
}

HBITMAP TopDownDib(HDC reference, int width, int height, void** bits) {
  BITMAPINFO info{};
  info.bmiHeader.biSize = sizeof(info.bmiHeader);
  info.bmiHeader.biWidth = width;
  info.bmiHeader.biHeight = -height;
  info.bmiHeader.biPlanes = 1;
  info.bmiHeader.biBitCount = 32;
  info.bmiHeader.biCompression = BI_RGB;
  return CreateDIBSection(reference, &info, DIB_RGB_COLORS, bits, nullptr, 0);
}

}  // namespace

bool BackstageDesktop::Capture(const RECT& area, std::vector<std::uint8_t>* pixels, int* width, int* height) const {
  const int w = area.right - area.left, h = area.bottom - area.top;
  *width = w;
  *height = h;
  if (desktop_ == nullptr || w <= 0 || h <= 0) {
    return false;
  }
  HDC screen = GetDC(nullptr);
  HDC canvas = CreateCompatibleDC(screen);
  void* bits = nullptr;
  HBITMAP bitmap = TopDownDib(screen, w, h, &bits);
  if (bitmap == nullptr) {
    DeleteDC(canvas);
    ReleaseDC(nullptr, screen);
    return false;
  }
  HGDIOBJ old = SelectObject(canvas, bitmap);
  RECT all{0, 0, w, h};
  HBRUSH background = CreateSolidBrush(RGB(32, 36, 44));
  FillRect(canvas, &all, background);
  DeleteObject(background);
  std::vector<HWND> windows;  // top of the z-order first
  EnumDesktopWindows(desktop_, CollectWindow, reinterpret_cast<LPARAM>(&windows));
  for (auto it = windows.rbegin(); it != windows.rend(); ++it) {
    RECT rect{};
    GetWindowRect(*it, &rect);
    const int ww = rect.right - rect.left, wh = rect.bottom - rect.top;
    if (rect.right <= area.left || rect.bottom <= area.top || rect.left >= area.right || rect.top >= area.bottom ||
        ww > 16384 || wh > 16384) {
      continue;
    }
    HDC windowDc = CreateCompatibleDC(screen);
    void* windowBits = nullptr;
    HBITMAP windowBitmap = TopDownDib(screen, ww, wh, &windowBits);
    if (windowBitmap != nullptr) {
      HGDIOBJ oldWindow = SelectObject(windowDc, windowBitmap);
      if (PrintWindow(*it, windowDc, 0)) {
        BitBlt(canvas, rect.left - area.left, rect.top - area.top, ww, wh, windowDc, 0, 0, SRCCOPY);
      }
      SelectObject(windowDc, oldWindow);
      DeleteObject(windowBitmap);
    }
    DeleteDC(windowDc);
  }
  POINT cursor{};
  if (GetCursorPos(&cursor)) {
    DrawIconEx(canvas, cursor.x - area.left, cursor.y - area.top, LoadCursorW(nullptr, MAKEINTRESOURCEW(32512)), 0, 0, 0, nullptr, DI_NORMAL);
  }
  GdiFlush();
  pixels->assign(static_cast<std::uint8_t*>(bits), static_cast<std::uint8_t*>(bits) + static_cast<std::size_t>(w) * h * 4);
  SelectObject(canvas, old);
  DeleteObject(bitmap);
  DeleteDC(canvas);
  ReleaseDC(nullptr, screen);
  return true;
}

// ---------------------------------------------------------------------------
// Input: SendInput when session 0 delivers it, otherwise posted window messages
// ---------------------------------------------------------------------------

namespace {

std::atomic<int> g_probeClicks{0};

LRESULT CALLBACK ProbeWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
  if (message == WM_LBUTTONDOWN) {
    ++g_probeClicks;
    return 0;
  }
  return DefWindowProcW(window, message, wParam, lParam);
}

}  // namespace

bool BackstageDesktop::ProbeSendInput() {
  g_probeClicks = 0;
  std::atomic<DWORD> thread{0};
  std::atomic<bool> ready{false};
  std::thread window([&] {
    thread = GetCurrentThreadId();
    if (!SetThreadDesktop(desktop_)) {
      ready = true;
      return;
    }
    WNDCLASSW cls{};
    cls.lpfnWndProc = ProbeWindowProc;
    cls.hInstance = GetModuleHandleW(nullptr);
    cls.lpszClassName = L"FenrirBackstageProbe";
    RegisterClassW(&cls);
    HWND probe = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, cls.lpszClassName, L"", WS_POPUP | WS_VISIBLE, 0, 0, 80, 80,
                                 nullptr, nullptr, cls.hInstance, nullptr);
    if (probe != nullptr) SetForegroundWindow(probe);
    ready = true;
    MSG message;
    while (GetMessageW(&message, nullptr, 0, 0) > 0) DispatchMessageW(&message);
    if (probe != nullptr) DestroyWindow(probe);
  });
  while (!ready) Sleep(10);
  Sleep(150);
  std::thread inject([&] {
    if (!SetThreadDesktop(desktop_)) return;
    const int cx = std::max(1, GetSystemMetrics(SM_CXSCREEN) - 1), cy = std::max(1, GetSystemMetrics(SM_CYSCREEN) - 1);
    INPUT inputs[3]{};
    inputs[0].type = inputs[1].type = inputs[2].type = INPUT_MOUSE;
    inputs[0].mi.dx = 40 * 65535 / cx;
    inputs[0].mi.dy = 40 * 65535 / cy;
    inputs[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
    inputs[2].mi.dwFlags = MOUSEEVENTF_LEFTUP;
    SendInput(3, inputs, sizeof(INPUT));
  });
  inject.join();
  for (int i = 0; i < 50 && g_probeClicks == 0; ++i) Sleep(10);
  const bool works = g_probeClicks > 0;
  if (thread != 0) PostThreadMessageW(thread, WM_QUIT, 0, 0);
  window.join();
  return works;
}

void BackstageDesktop::Mouse(int x, int y, int button, int action) {
  POINT point{x, y};
  if (action == 0) SetCursorPos(x, y);
  HWND target = WindowFromPoint(point);
  if (target == nullptr) return;
  if (action == 3 || action == 4) {
    PostMessageW(target, action == 3 ? WM_MOUSEWHEEL : WM_MOUSEHWHEEL, MAKEWPARAM(0, static_cast<short>(button * WHEEL_DELTA)),
                 MAKELPARAM(point.x, point.y));
    return;
  }
  // Title bars, borders and close buttons are the non-client area: they take WM_NC* messages in screen coordinates.
  DWORD_PTR hitResult = HTCLIENT;
  if (!SendMessageTimeoutW(target, WM_NCHITTEST, 0, MAKELPARAM(point.x, point.y), SMTO_ABORTIFHUNG, 200, &hitResult)) {
    hitResult = HTCLIENT;  // a hung window: treat the point as its client area
  }
  const LRESULT hit = static_cast<LRESULT>(hitResult);
  POINT client = point;
  ScreenToClient(target, &client);
  const LPARAM clientPos = MAKELPARAM(client.x, client.y), screenPos = MAKELPARAM(point.x, point.y);
  if (action == 0) {
    PostMessageW(target, hit == HTCLIENT ? WM_MOUSEMOVE : WM_NCMOUSEMOVE, hit == HTCLIENT ? 0 : static_cast<WPARAM>(hit),
                 hit == HTCLIENT ? clientPos : screenPos);
    return;
  }
  const bool down = action == 1;
  if (down) {
    HWND root = GetAncestor(target, GA_ROOT);
    if (root != nullptr) SetForegroundWindow(root);
    keyTarget_ = target;
  }
  UINT message;
  WPARAM flags;
  if (button == 2) {
    message = down ? WM_RBUTTONDOWN : WM_RBUTTONUP;
    flags = down ? MK_RBUTTON : 0;
  } else if (button == 1) {
    message = down ? WM_MBUTTONDOWN : WM_MBUTTONUP;
    flags = down ? MK_MBUTTON : 0;
  } else {
    message = down ? WM_LBUTTONDOWN : WM_LBUTTONUP;
    flags = down ? MK_LBUTTON : 0;
  }
  if (hit != HTCLIENT && button == 0) {
    PostMessageW(target, down ? WM_NCLBUTTONDOWN : WM_NCLBUTTONUP, static_cast<WPARAM>(hit), screenPos);
  } else {
    PostMessageW(target, message, flags, clientPos);
  }
  if (!down && button == 2 && hit == HTCLIENT) {
    PostMessageW(target, WM_CONTEXTMENU, reinterpret_cast<WPARAM>(target), screenPos);
  }
}

HWND BackstageDesktop::FocusTarget() const {
  HWND target = keyTarget_ != nullptr && IsWindow(keyTarget_) ? keyTarget_ : GetForegroundWindow();
  if (target == nullptr) return nullptr;
  GUITHREADINFO info{};
  info.cbSize = sizeof(info);
  if (GetGUIThreadInfo(GetWindowThreadProcessId(target, nullptr), &info) && info.hwndFocus != nullptr) {
    return info.hwndFocus;
  }
  return target;
}

void BackstageDesktop::Key(unsigned scan, bool extended, bool down) {
  // Modifiers are tracked here: posted keys do not change the target thread's keyboard state.
  if (scan == 0x2A || scan == 0x36) shift_ = down;
  if (scan == 0x1D) ctrl_ = down;
  if (scan == 0x38) alt_ = down;
  HWND focus = FocusTarget();
  if (focus == nullptr) return;
  const UINT vk = MapVirtualKeyW(scan | (extended ? 0xE000u : 0u), MAPVK_VSC_TO_VK_EX);
  if (vk == 0) return;
  // Printable keys become WM_CHAR from our own modifier state (the target's TranslateMessage would use its own, which
  // posted keys never set); everything else (arrows, Enter, Tab, F-keys, Delete...) is a key message.
  BYTE state[256]{};
  if (shift_) state[VK_SHIFT] = 0x80;
  if (ctrl_) state[VK_CONTROL] = 0x80;
  wchar_t text[4]{};
  const int produced = (!ctrl_ && !alt_ && vk != VK_RETURN && vk != VK_TAB && vk != VK_BACK && vk != VK_ESCAPE)
                           ? ToUnicode(vk, scan, state, text, 4, 0)
                           : 0;
  if (produced > 0) {
    if (down) {
      for (int i = 0; i < produced; ++i) PostMessageW(focus, WM_CHAR, text[i], 1);
    }
    return;
  }
  const LPARAM flags = 1 | (static_cast<LPARAM>(scan & 0xFF) << 16) | (extended ? (1 << 24) : 0) |
                       (down ? 0 : (static_cast<LPARAM>(3) << 30));
  PostMessageW(focus, down ? (alt_ ? WM_SYSKEYDOWN : WM_KEYDOWN) : (alt_ ? WM_SYSKEYUP : WM_KEYUP), vk, flags);
}

void BackstageDesktop::Char(wchar_t ch) {
  HWND focus = FocusTarget();
  if (focus != nullptr) PostMessageW(focus, WM_CHAR, ch == L'\n' ? L'\r' : ch, 1);
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace {

constexpr COLORREF kTestColour = RGB(255, 0, 170);
std::atomic<int> g_testClicks{0};

LRESULT CALLBACK TestWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
  if (message == WM_ERASEBKGND) {
    RECT rect{};
    GetClientRect(window, &rect);
    HBRUSH brush = CreateSolidBrush(kTestColour);
    FillRect(reinterpret_cast<HDC>(wParam), &rect, brush);
    DeleteObject(brush);
    return 1;
  }
  if (message == WM_LBUTTONDOWN) {
    ++g_testClicks;
    return 0;
  }
  return DefWindowProcW(window, message, wParam, lParam);
}

int CountColour(const std::vector<std::uint8_t>& pixels) {
  int found = 0;
  for (std::size_t i = 0; i + 3 < pixels.size(); i += 4) {
    if (pixels[i + 2] == GetRValue(kTestColour) && pixels[i + 1] == GetGValue(kTestColour) && pixels[i] == GetBValue(kTestColour)) {
      ++found;
    }
  }
  return found;
}

// The plain screen copy, for comparison: on Windows Server 2025 it comes back without the windows.
int ScreenCopyColourPixels(int width, int height) {
  HDC screen = GetDC(nullptr);
  HDC memory = CreateCompatibleDC(screen);
  void* bits = nullptr;
  HBITMAP bitmap = TopDownDib(screen, width, height, &bits);
  int found = -1;
  if (bitmap != nullptr) {
    HGDIOBJ old = SelectObject(memory, bitmap);
    if (BitBlt(memory, 0, 0, width, height, screen, 0, 0, SRCCOPY | CAPTUREBLT)) {
      GdiFlush();
      std::vector<std::uint8_t> pixels(static_cast<std::uint8_t*>(bits),
                                       static_cast<std::uint8_t*>(bits) + static_cast<std::size_t>(width) * height * 4);
      found = CountColour(pixels);
    }
    SelectObject(memory, old);
    DeleteObject(bitmap);
  }
  DeleteDC(memory);
  ReleaseDC(nullptr, screen);
  return found;
}

}  // namespace

int RunBackstageSelfTest(const std::wstring& resultPath) {
  std::ostringstream json;
  const DWORD session = CurrentSession();
  const DWORD console = WTSGetActiveConsoleSessionId();
  json << "{\"helperSession\":" << session << ",\"consoleSession\":" << static_cast<long long>(console == 0xFFFFFFFF ? -1 : console);
  BackstageDesktop desktop;
  const auto openError = desktop.Open();
  bool captureWorks = false, inputWorks = false;
  if (!openError.empty()) {
    json << ",\"opened\":false,\"error\":\"" << Escape(openError) << "\"";
  } else {
    json << ",\"opened\":true,\"desktop\":\"" << Escape(Narrow(desktop.Name())) << "\",\"sendInputWorks\":"
         << (desktop.SendInputWorks() ? "true" : "false");
    HDESK handle = desktop.Handle();
    std::atomic<DWORD> windowThread{0};
    std::atomic<bool> windowShown{false};
    g_testClicks = 0;
    std::thread window([&] {
      windowThread = GetCurrentThreadId();
      if (!SetThreadDesktop(handle)) return;
      WNDCLASSW cls{};
      cls.lpfnWndProc = TestWindowProc;
      cls.hInstance = GetModuleHandleW(nullptr);
      cls.lpszClassName = L"FenrirBackstageSelfTest";
      RegisterClassW(&cls);
      HWND test = CreateWindowExW(WS_EX_TOPMOST, cls.lpszClassName, L"Fenrir backstage self-test", WS_POPUP | WS_VISIBLE, 100,
                                  100, 400, 300, nullptr, nullptr, cls.hInstance, nullptr);
      if (test == nullptr) return;
      UpdateWindow(test);
      windowShown = true;
      MSG message;
      while (GetMessageW(&message, nullptr, 0, 0) > 0) DispatchMessageW(&message);
      DestroyWindow(test);
    });
    Sleep(1000);
    const auto launchError = desktop.Launch("taskmgr");
    Sleep(3000);
    int screenCopy = -1, composite = 0, width = 0, height = 0, visibleWindows = 0;
    bool postedClick = false;
    std::thread probe([&] {  // a thread attached to the hidden desktop, as the helper's screen and input threads are
      if (!SetThreadDesktop(handle)) return;
      width = GetSystemMetrics(SM_CXSCREEN);
      height = GetSystemMetrics(SM_CYSCREEN);
      std::vector<HWND> windows;
      EnumDesktopWindows(handle, CollectWindow, reinterpret_cast<LPARAM>(&windows));
      visibleWindows = static_cast<int>(windows.size());
      screenCopy = ScreenCopyColourPixels(width, height);
      std::vector<std::uint8_t> pixels;
      int w = 0, h = 0;
      if (desktop.Capture(RECT{0, 0, width, height}, &pixels, &w, &h)) composite = CountColour(pixels);
      // Input the way a session will send it: SendInput if Open found it works, otherwise posted messages.
      const int before = g_testClicks;
      if (desktop.SendInputWorks()) {
        const int cx = std::max(1, width - 1), cy = std::max(1, height - 1);
        INPUT inputs[3]{};
        inputs[0].type = inputs[1].type = inputs[2].type = INPUT_MOUSE;
        inputs[0].mi.dx = 300 * 65535 / cx;
        inputs[0].mi.dy = 250 * 65535 / cy;
        inputs[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
        inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
        inputs[2].mi.dwFlags = MOUSEEVENTF_LEFTUP;
        SendInput(3, inputs, sizeof(INPUT));
      } else {
        desktop.Mouse(300, 250, 0, 1);
        desktop.Mouse(300, 250, 0, 2);
      }
      for (int i = 0; i < 50 && g_testClicks == before; ++i) Sleep(10);
      postedClick = g_testClicks > before;
    });
    probe.join();
    captureWorks = composite > 400 * 300 / 2;
    inputWorks = postedClick;
    if (windowThread != 0) PostThreadMessageW(windowThread, WM_QUIT, 0, 0);
    window.join();
    json << ",\"testWindowShown\":" << (windowShown ? "true" : "false") << ",\"screenCopyColourPixels\":" << screenCopy
         << ",\"compositeColourPixels\":" << composite << ",\"clickReachedWindow\":" << (postedClick ? "true" : "false")
         << ",\"screen\":{\"w\":" << width << ",\"h\":" << height << "}"
         << ",\"taskManagerStarted\":" << (launchError.empty() ? "true" : "false") << ",\"visibleWindows\":" << visibleWindows;
    if (!launchError.empty()) json << ",\"taskManagerError\":\"" << Escape(launchError) << "\"";
    desktop.Close();
  }
  json << ",\"captureWorks\":" << (captureWorks ? "true" : "false") << ",\"inputWorks\":" << (inputWorks ? "true" : "false") << "}";
  std::ofstream(std::filesystem::path(resultPath), std::ios::binary | std::ios::trunc) << json.str();
  return captureWorks && inputWorks ? 0 : 3;
}

}  // namespace fenrir::remote
