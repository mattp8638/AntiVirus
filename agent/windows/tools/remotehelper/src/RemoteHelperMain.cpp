// fenrir-remote.exe: the Windows side of Fenrir remote access.
//
// The agent service starts this helper in the active console session (as
// SYSTEM, so it can also see the sign-in screen and UAC prompts). It dials the
// cloud relay and serves the channels in docs/REMOTE_PROTOCOL.md:
// desktop (GDI capture + SendInput), terminal (ConPTY), files, processes,
// services and chat, with a consent prompt and an on-screen session banner.

// ConPTY (CreatePseudoConsole) is declared for Windows 10 1809 and later.
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#undef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000006

#include <windows.h>
#include <objidl.h>  // GDI+ needs IStream and related COM interfaces first.
#include <gdiplus.h>
#include <psapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "ExtendedPolicy.h"
#include "RemoteKeymap.h"
#include "RemotePipeIo.h"
#include "RemoteTunnel.h"
#include "StringUtils.h"
#include "WebSocketClient.h"

using namespace antivirus::agent;

namespace {

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

std::string Q(const std::wstring& value) { return "\"" + EscapeJsonString(value) + "\""; }
std::string Q(const std::string& utf8) { return Q(Utf8ToWide(utf8)); }

const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const char* data, std::size_t size) {
  std::string out;
  out.reserve((size + 2) / 3 * 4);
  for (std::size_t i = 0; i < size; i += 3) {
    const std::uint32_t n = (static_cast<std::uint8_t>(data[i]) << 16) | (i + 1 < size ? static_cast<std::uint8_t>(data[i + 1]) << 8 : 0) |
                            (i + 2 < size ? static_cast<std::uint8_t>(data[i + 2]) : 0);
    out += kB64[(n >> 18) & 63];
    out += kB64[(n >> 12) & 63];
    out += i + 1 < size ? kB64[(n >> 6) & 63] : '=';
    out += i + 2 < size ? kB64[n & 63] : '=';
  }
  return out;
}

std::string Base64Decode(const std::string& text) {
  std::string out;
  std::uint32_t buffer = 0;
  int bits = 0;
  for (const char c : text) {
    const char* p = std::strchr(kB64, c);
    if (c == '=' || p == nullptr || c == '\0') {
      continue;
    }
    buffer = (buffer << 6) | static_cast<std::uint32_t>(p - kB64);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += static_cast<char>((buffer >> bits) & 0xFF);
    }
  }
  return out;
}

std::string Str(const json::Value& v, const char* key, const std::string& fallback = "") {
  const auto* item = v.Get(key);
  return item && item->String() ? *item->String() : fallback;
}

double Num(const json::Value& v, const char* key, double fallback = 0) {
  const auto* item = v.Get(key);
  return item && item->Number() ? *item->Number() : fallback;
}

bool Flag(const json::Value& v, const char* key, bool fallback) {
  const auto* item = v.Get(key);
  return item && item->Bool() ? *item->Bool() : fallback;
}

std::string RawJson(const json::Value& v, const char* key) {
  // Request ids are echoed back verbatim; they are numbers in the console.
  const auto* item = v.Get(key);
  if (!item) {
    return "null";
  }
  if (item->Number()) {
    std::ostringstream out;
    out << static_cast<long long>(*item->Number());
    return out.str();
  }
  if (item->String()) {
    return Q(*item->String());
  }
  return "null";
}

// ---------------------------------------------------------------------------
// Options (written by the service to a SYSTEM-only file, then deleted)
// ---------------------------------------------------------------------------

// One log file per session next to the (deleted) options file, e.g. runtime\\remote\\<session>.log,
// so a session that never connects can be diagnosed. The token is never written.
std::filesystem::path g_logPath;
std::mutex g_logMutex;

void HelperLog(const std::string& line) {
  if (g_logPath.empty()) {
    return;
  }
  SYSTEMTIME now{};
  GetSystemTime(&now);
  char stamp[32]{};
  snprintf(stamp, sizeof(stamp), "%04u-%02u-%02uT%02u:%02u:%02uZ ", now.wYear, now.wMonth, now.wDay, now.wHour,
           now.wMinute, now.wSecond);
  std::lock_guard lock(g_logMutex);
  std::ofstream out(g_logPath, std::ios::binary | std::ios::app);
  out << stamp << line << "\r\n";
}

struct Options {
  std::string sessionId, relayUrl, token, mode, technician, consent{"when_user_present"}, onConsentTimeout{"deny"};
  int consentTimeout{30}, maxFps{15}, quality{70}, idleMinutes{30};
  bool viewOnly{false}, allowTerminal{true}, allowFiles{true}, showBanner{true};
  std::string targetHost;  // tunnel sessions
  int targetPort{0};
  std::vector<int> allowedPorts;
};

bool LoadOptions(const std::wstring& path, Options* options) {
  std::ifstream in(std::filesystem::path(path), std::ios::binary);
  std::stringstream buffer;
  buffer << in.rdbuf();
  in.close();
  std::error_code ec;
  std::filesystem::remove(std::filesystem::path(path), ec);
  const auto root = json::Parse(buffer.str());
  if (!root || !root->IsObject()) {
    return false;
  }
  options->sessionId = Str(*root, "sessionId");
  options->relayUrl = Str(*root, "relayUrl");
  options->token = Str(*root, "token");
  options->mode = Str(*root, "mode", "desktop");
  options->technician = Str(*root, "technician", "A technician");
  options->consent = Str(*root, "consent", "when_user_present");
  options->onConsentTimeout = Str(*root, "onConsentTimeout", "deny");
  options->consentTimeout = static_cast<int>(Num(*root, "consentTimeoutSeconds", 30));
  options->maxFps = std::clamp(static_cast<int>(Num(*root, "maxFps", 15)), 1, 30);
  options->quality = std::clamp(static_cast<int>(Num(*root, "quality", 70)), 10, 95);
  options->idleMinutes = std::max(5, static_cast<int>(Num(*root, "idleTimeoutMinutes", 30)));
  options->viewOnly = Flag(*root, "viewOnly", false);
  options->allowTerminal = Flag(*root, "allowTerminal", true);
  options->allowFiles = Flag(*root, "allowFileTransfer", true);
  options->showBanner = Flag(*root, "showBanner", true);
  options->targetHost = Str(*root, "targetHost");
  options->targetPort = static_cast<int>(Num(*root, "targetPort", 0));
  if (const auto* ports = root->Get("allowedPorts")) {
    if (const auto* list = std::get_if<json::Array>(&ports->v)) {
      for (const auto& port : *list) options->allowedPorts.push_back(static_cast<int>(port.Number().value_or(0)));
    }
  }
  return !options->relayUrl.empty() && !options->token.empty();
}

// ---------------------------------------------------------------------------
// Desktop: follow the input desktop (Default, Winlogon, UAC) and capture it
// ---------------------------------------------------------------------------

void SyncInputDesktop() {
  HDESK input = OpenInputDesktop(0, FALSE, GENERIC_ALL);
  if (input == nullptr) {
    return;
  }
  wchar_t inputName[256]{}, currentName[256]{};
  DWORD needed = 0;
  GetUserObjectInformationW(input, UOI_NAME, inputName, sizeof(inputName), &needed);
  GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, currentName, sizeof(currentName), &needed);
  if (_wcsicmp(inputName, currentName) != 0 && SetThreadDesktop(input)) {
    return;  // keep the handle: the thread now uses it
  }
  CloseDesktop(input);
}

struct Monitor {
  RECT rect{};
  bool primary{false};
};

BOOL CALLBACK CollectMonitor(HMONITOR monitor, HDC, LPRECT, LPARAM data) {
  MONITORINFO info{};
  info.cbSize = sizeof(info);
  if (GetMonitorInfoW(monitor, &info)) {
    reinterpret_cast<std::vector<Monitor>*>(data)->push_back({info.rcMonitor, (info.dwFlags & MONITORINFOF_PRIMARY) != 0});
  }
  return TRUE;
}

std::vector<Monitor> Monitors() {
  std::vector<Monitor> out;
  EnumDisplayMonitors(nullptr, nullptr, CollectMonitor, reinterpret_cast<LPARAM>(&out));
  std::stable_sort(out.begin(), out.end(), [](const Monitor& a, const Monitor& b) { return a.primary && !b.primary; });
  if (out.empty()) {
    out.push_back({{0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)}, true});
  }
  return out;
}

// The area a viewer asked for: one monitor, or every monitor at once (index -1, the virtual desktop).
RECT TargetRect(int index) {
  if (index < 0) {
    const int x = GetSystemMetrics(SM_XVIRTUALSCREEN), y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    return RECT{x, y, x + GetSystemMetrics(SM_CXVIRTUALSCREEN), y + GetSystemMetrics(SM_CYVIRTUALSCREEN)};
  }
  const auto monitors = Monitors();
  return monitors[std::min<std::size_t>(static_cast<std::size_t>(index), monitors.size() - 1)].rect;
}

// Captures a monitor into a top-down BGRA buffer, with the mouse cursor drawn in.
bool CaptureMonitor(const RECT& rect, std::vector<std::uint8_t>* pixels, int* width, int* height) {
  const int w = rect.right - rect.left, h = rect.bottom - rect.top;
  if (w <= 0 || h <= 0) {
    return false;
  }
  HDC screen = GetDC(nullptr);
  if (!screen) {
    return false;
  }
  HDC memory = CreateCompatibleDC(screen);
  BITMAPINFO info{};
  info.bmiHeader.biSize = sizeof(info.bmiHeader);
  info.bmiHeader.biWidth = w;
  info.bmiHeader.biHeight = -h;
  info.bmiHeader.biPlanes = 1;
  info.bmiHeader.biBitCount = 32;
  info.bmiHeader.biCompression = BI_RGB;
  void* bits = nullptr;
  HBITMAP bitmap = CreateDIBSection(screen, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
  bool ok = false;
  if (bitmap) {
    HGDIOBJ old = SelectObject(memory, bitmap);
    ok = BitBlt(memory, 0, 0, w, h, screen, rect.left, rect.top, SRCCOPY | CAPTUREBLT) != FALSE;
    CURSORINFO cursor{};
    cursor.cbSize = sizeof(cursor);
    if (ok && GetCursorInfo(&cursor) && (cursor.flags & CURSOR_SHOWING)) {
      ICONINFO icon{};
      if (GetIconInfo(cursor.hCursor, &icon)) {
        DrawIconEx(memory, cursor.ptScreenPos.x - rect.left - static_cast<int>(icon.xHotspot),
                   cursor.ptScreenPos.y - rect.top - static_cast<int>(icon.yHotspot), cursor.hCursor, 0, 0, 0, nullptr, DI_NORMAL);
        if (icon.hbmMask) DeleteObject(icon.hbmMask);
        if (icon.hbmColor) DeleteObject(icon.hbmColor);
      }
    }
    GdiFlush();
    if (ok) {
      pixels->assign(static_cast<std::uint8_t*>(bits), static_cast<std::uint8_t*>(bits) + static_cast<std::size_t>(w) * h * 4);
    }
    SelectObject(memory, old);
    DeleteObject(bitmap);
  }
  DeleteDC(memory);
  ReleaseDC(nullptr, screen);
  *width = w;
  *height = h;
  return ok;
}

CLSID JpegEncoder() {
  UINT count = 0, size = 0;
  Gdiplus::GetImageEncodersSize(&count, &size);
  std::vector<std::uint8_t> buffer(size);
  auto* encoders = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buffer.data());
  Gdiplus::GetImageEncoders(count, size, encoders);
  for (UINT i = 0; i < count; ++i) {
    if (wcscmp(encoders[i].MimeType, L"image/jpeg") == 0) {
      return encoders[i].Clsid;
    }
  }
  return CLSID{};
}

bool EncodeJpeg(const std::uint8_t* pixels, int stride, int w, int h, ULONG quality, const CLSID& encoder, std::string* out) {
  // GDI+ reads the pixels in place; PixelFormat32bppRGB ignores the unused alpha byte.
  Gdiplus::Bitmap bitmap(w, h, stride, PixelFormat32bppRGB, const_cast<BYTE*>(pixels));
  IStream* stream = nullptr;
  if (CreateStreamOnHGlobal(nullptr, TRUE, &stream) != S_OK) {
    return false;
  }
  Gdiplus::EncoderParameters params{};
  params.Count = 1;
  params.Parameter[0].Guid = Gdiplus::EncoderQuality;
  params.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
  params.Parameter[0].NumberOfValues = 1;
  params.Parameter[0].Value = &quality;
  bool ok = bitmap.Save(stream, &encoder, &params) == Gdiplus::Ok;
  if (ok) {
    STATSTG stat{};
    stream->Stat(&stat, STATFLAG_NONAME);
    LARGE_INTEGER zero{};
    stream->Seek(zero, STREAM_SEEK_SET, nullptr);
    out->resize(static_cast<std::size_t>(stat.cbSize.QuadPart));
    ULONG read = 0;
    ok = stream->Read(out->data(), static_cast<ULONG>(out->size()), &read) == S_OK;
  }
  stream->Release();
  return ok;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

class Session;
Session* g_session = nullptr;

class Session {
 public:
  explicit Session(Options options) : options_(std::move(options)) {}

  int Run();
  void SendJson(const std::string& json) { socket_.SendText(json); }
  void End(const std::string& reason);
  void OnChatFromUser(const std::wstring& text);
  const Options& options() const { return options_; }
  bool Backstage() const { return options_.mode == "backstage"; }
  bool Tunnel() const { return options_.mode == "tunnel"; }
  // Backstage and tunnel sessions run in session 0 and never show or touch the user's desktop.
  bool Silent() const { return Backstage() || Tunnel(); }

 private:
  void Dispatch(const json::Value& m);
  void Info();
  void ScreenLoop();
  void HandleInput(const std::string& type, const json::Value& m);
  void HandleTerm(const std::string& type, const json::Value& m);
  void HandleFiles(const std::string& type, const json::Value& m);
  void HandleUpload(const std::string& data);
  void HandleProcs(const std::string& type, const json::Value& m);
  void HandleServices(const std::string& type, const json::Value& m);
  void Reply(const std::string& ch, const json::Value& m, const std::string& fields);
  void Fail(const std::string& ch, const json::Value& m, const std::string& error);
  void CloseTerminal();

  Options options_;
  WebSocketClient socket_;
  std::unique_ptr<fenrir::remote::TunnelStreams> tunnels_;
  std::atomic<bool> running_{true};
  std::atomic<long long> lastInput_{static_cast<long long>(GetTickCount64())};

  // Screen streaming state
  std::mutex screenMutex_;
  std::condition_variable screenCv_;
  bool streaming_{false}, full_{true};
  int inFlight_{0}, quality_{70}, fps_{15}, monitor_{0};
  std::thread screenThread_;

  // Terminal
  HPCON console_{nullptr};
  HANDLE termIn_{nullptr}, termOut_{nullptr};
  PROCESS_INFORMATION termProcess_{};
  std::thread termReader_;

  // Uploads: id -> file
  std::map<std::uint32_t, std::pair<std::wstring, HANDLE>> uploads_;
  std::map<std::uint32_t, std::uint64_t> uploadBytes_;

  // Process CPU sampling
  std::mutex procMutex_;
  std::map<DWORD, std::uint64_t> lastCpu_;
  std::uint64_t lastSampleAt_{0};
};

void Session::Reply(const std::string& ch, const json::Value& m, const std::string& fields) {
  SendJson("{\"ch\":\"" + ch + "\",\"req\":" + RawJson(m, "req") + (fields.empty() ? "" : "," + fields) + "}");
}

void Session::Fail(const std::string& ch, const json::Value& m, const std::string& error) {
  Reply(ch, m, "\"t\":\"done\",\"error\":" + Q(error));
}

void Session::End(const std::string& reason) {
  if (!running_.exchange(false)) {
    return;
  }
  HelperLog("Session ended: " + reason);
  socket_.SendText("{\"ch\":\"sys\",\"t\":\"end\",\"reason\":" + Q(reason) + "}");
  screenCv_.notify_all();
  socket_.Close(1000, reason);
}

void Session::Info() {
  wchar_t host[256]{};
  DWORD size = 255;
  GetComputerNameW(host, &size);
  std::wstring user;
  LPWSTR name = nullptr;
  DWORD bytes = 0;
  if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &name, &bytes) && name) {
    user = name;
    WTSFreeMemory(name);
  }
  std::ostringstream out;
  out << "{\"ch\":\"sys\",\"t\":\"info\",\"hostname\":" << Q(std::wstring(host)) << ",\"os\":\"windows\",\"user\":" << Q(user)
      << ",\"home\":\"\",\"quality\":" << options_.quality << ",\"maxFps\":" << options_.maxFps << ",\"capabilities\":[";
  // Backstage sessions run as SYSTEM in session 0: no screen, input, chat or Ctrl+Alt+Del, and nothing the user sees.
  out << (Tunnel() ? "\"tunnel\"" : Backstage() ? "\"processes\",\"services\",\"backstage\"" : "\"desktop\",\"processes\",\"services\",\"chat\",\"cad\"");
  if (options_.allowTerminal && !Tunnel()) out << ",\"terminal\"";
  if (options_.allowFiles && !Tunnel()) out << ",\"files\"";
  out << "],\"shells\":[\"powershell\",\"cmd\"],\"monitors\":[";
  const auto monitors = Silent() ? std::vector<Monitor>{} : Monitors();
  for (std::size_t i = 0; i < monitors.size(); ++i) {
    const auto& r = monitors[i].rect;
    out << (i ? "," : "") << "{\"index\":" << i << ",\"x\":" << r.left << ",\"y\":" << r.top << ",\"w\":" << (r.right - r.left)
        << ",\"h\":" << (r.bottom - r.top) << ",\"primary\":" << (monitors[i].primary ? "true" : "false") << "}";
  }
  out << "]}";
  SendJson(out.str());
}

void Session::ScreenLoop() {
  SyncInputDesktop();
  const auto encoder = JpegEncoder();
  std::vector<std::uint8_t> previous, current;
  int prevW = 0, prevH = 0, seq = 0;
  constexpr int kTile = 128;
  while (running_) {
    int quality, fps, monitorIndex;
    bool full;
    {
      std::unique_lock lock(screenMutex_);
      screenCv_.wait_for(lock, std::chrono::seconds(3), [&] { return !running_ || (streaming_ && inFlight_ < 2); });
      if (!running_) {
        return;
      }
      if (!streaming_) {
        continue;
      }
      if (inFlight_ >= 2) {
        inFlight_ = 0;  // a lost ack must not stall the stream
      }
      quality = quality_;
      fps = fps_;
      monitorIndex = monitor_;
      full = full_;
      full_ = false;
    }
    const auto started = GetTickCount64();
    SyncInputDesktop();  // follow switches to the sign-in screen or a UAC prompt
    const auto rect = TargetRect(monitorIndex);
    int w = 0, h = 0;
    if (!CaptureMonitor(rect, &current, &w, &h)) {
      Sleep(500);
      continue;
    }
    if (w != prevW || h != prevH || previous.size() != current.size()) {
      full = true;
    }
    int tiles = 0;
    const int stride = w * 4;
    for (int ty = 0; ty < h && running_; ty += kTile) {
      for (int tx = 0; tx < w; tx += kTile) {
        const int tw = std::min(kTile, w - tx), th = std::min(kTile, h - ty);
        bool changed = full;
        for (int y = ty; !changed && y < ty + th; ++y) {
          changed = memcmp(&previous[static_cast<std::size_t>(y) * stride + tx * 4], &current[static_cast<std::size_t>(y) * stride + tx * 4],
                           static_cast<std::size_t>(tw) * 4) != 0;
        }
        if (!changed) {
          continue;
        }
        std::string jpeg;
        if (!EncodeJpeg(&current[static_cast<std::size_t>(ty) * stride + tx * 4], stride, tw, th, static_cast<ULONG>(quality), encoder, &jpeg)) {
          continue;
        }
        std::string frame(13, '\0');
        auto put = [&](int offset, int value) {
          frame[offset] = static_cast<char>((value >> 8) & 0xFF);
          frame[offset + 1] = static_cast<char>(value & 0xFF);
        };
        frame[0] = 0x01;
        put(1, tx);
        put(3, ty);
        put(5, tw);
        put(7, th);
        put(9, w);
        put(11, h);
        frame += jpeg;
        if (!socket_.SendBinary(frame.data(), frame.size())) {
          running_ = false;
          return;
        }
        ++tiles;
      }
    }
    previous.swap(current);
    prevW = w;
    prevH = h;
    if (tiles) {
      {
        std::lock_guard lock(screenMutex_);
        ++inFlight_;
      }
      SendJson("{\"ch\":\"screen\",\"t\":\"frame.end\",\"seq\":" + std::to_string(++seq) + ",\"tiles\":" + std::to_string(tiles) + "}");
    }
    const auto elapsed = GetTickCount64() - started;
    const auto budget = 1000ull / static_cast<unsigned>(std::max(fps, 1));
    if (elapsed < budget) {
      Sleep(static_cast<DWORD>(budget - elapsed));
    }
  }
}

void SendKey(const std::string& code, bool down) {
  const auto scan = remote::ScanCodeForKey(code);
  if (scan.code == 0) {
    return;
  }
  INPUT input{};
  input.type = INPUT_KEYBOARD;
  input.ki.wScan = scan.code;
  input.ki.dwFlags = KEYEVENTF_SCANCODE | (scan.extended ? KEYEVENTF_EXTENDEDKEY : 0) | (down ? 0 : KEYEVENTF_KEYUP);
  SendInput(1, &input, sizeof(input));
}

void TypeText(const std::wstring& text) {
  std::vector<INPUT> inputs;
  for (wchar_t ch : text) {
    if (ch == L'\n') {
      ch = L'\r';
    }
    for (const bool up : {false, true}) {
      INPUT input{};
      input.type = INPUT_KEYBOARD;
      input.ki.wScan = ch;
      input.ki.dwFlags = KEYEVENTF_UNICODE | (up ? KEYEVENTF_KEYUP : 0);
      inputs.push_back(input);
    }
  }
  if (!inputs.empty()) {
    SendInput(static_cast<UINT>(inputs.size()), inputs.data(), sizeof(INPUT));
  }
}

// Asks the Fenrir service (a real service in session 0, where SendSAS is honoured) to send Ctrl+Alt+Del.
// Both reads and writes have a deadline; no direct helper fallback can claim a
// successful SAS just because the void SendSAS function returned.
std::string RequestSasFromService(const std::string& sessionId) {
  if (sessionId.empty() || sessionId.size() > 64 || sessionId.find_first_of("\\/:*?\"<>|") != std::string::npos) {
    return "error: invalid remote session id";
  }
  const auto name = L"\\\\.\\pipe\\fenrir-remote-sas-" + Utf8ToWide(sessionId);
  // WaitNamedPipe returns immediately if the broker has not created its first
  // instance yet. Retry that startup race within the same bounded deadline.
  HANDLE pipe = INVALID_HANDLE_VALUE;
  const ULONGLONG connectDeadline = GetTickCount64() + 3000;
  do {
    if (WaitNamedPipeW(name.c_str(), 100)) {
      pipe = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                         FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr);
      if (pipe != INVALID_HANDLE_VALUE) break;
    }
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY && error != ERROR_SEM_TIMEOUT) break;
    Sleep(25);
  } while (GetTickCount64() < connectDeadline);
  if (pipe == INVALID_HANDLE_VALUE) {
    return "error: the Ctrl+Alt+Del service channel is unavailable; update the Windows agent and reconnect";
  }
  DWORD mode = PIPE_READMODE_MESSAGE;
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!event || !SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
    if (event) CloseHandle(event);
    CloseHandle(pipe);
    return "error: could not prepare the Ctrl+Alt+Del service channel";
  }
  DWORD written = 0, read = 0;
  char reply[512] = {};
  // One deadline for the exchange, not a fresh timeout for every operation.
  const ULONGLONG deadline = GetTickCount64() + 5000;
  const auto remaining = [&]() -> DWORD {
    const auto now = GetTickCount64();
    return now < deadline ? static_cast<DWORD>(deadline - now) : 0;
  };
  OVERLAPPED operation{};
  operation.hEvent = event;
  const BOOL writing = WriteFile(pipe, "sas", 3, nullptr, &operation);
  const DWORD writeError = GetLastError();
  bool ok = remote::FinishPipeIo(pipe, operation, writing, writeError, remaining(), nullptr, written) && written == 3;
  if (ok) {
    operation = {};
    operation.hEvent = event;
    ResetEvent(event);
    const BOOL reading = ReadFile(pipe, reply, sizeof(reply) - 1, nullptr, &operation);
    const DWORD readError = GetLastError();
    ok = remote::FinishPipeIo(pipe, operation, reading, readError, remaining(), nullptr, read) && read > 0;
  }
  const std::string result = ok ? std::string(reply, read) : "error: no reply from the Fenrir service within 5 seconds";
  if (ok) {
    operation = {};
    operation.hEvent = event;
    ResetEvent(event);
    const BOOL acknowledging = WriteFile(pipe, "ack", 3, nullptr, &operation);
    const DWORD ackError = GetLastError();
    remote::FinishPipeIo(pipe, operation, acknowledging, ackError, remaining(), nullptr, written);
  }
  CloseHandle(event);
  CloseHandle(pipe);
  return result;
}

// Returns "" on success, otherwise the reason for the technician.
std::string SendCtrlAltDel(const std::string& sessionId) {
  const auto reply = RequestSasFromService(sessionId);
  if (reply == "ok") {
    return "";
  }
  return reply.rfind("error: ", 0) == 0 ? reply.substr(7) : "invalid reply from the Ctrl+Alt+Del service channel";
}

void Session::HandleInput(const std::string& type, const json::Value& m) {
  if (options_.viewOnly) {
    return;
  }
  SyncInputDesktop();
  int index;
  {
    std::lock_guard lock(screenMutex_);
    index = monitor_;
  }
  const auto rect = TargetRect(index);
  auto moveTo = [&](double x, double y) {
    const int vx = GetSystemMetrics(SM_XVIRTUALSCREEN), vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int vw = std::max(1, GetSystemMetrics(SM_CXVIRTUALSCREEN) - 1), vh = std::max(1, GetSystemMetrics(SM_CYVIRTUALSCREEN) - 1);
    INPUT input{};
    input.type = INPUT_MOUSE;
    input.mi.dx = static_cast<LONG>((rect.left + x - vx) * 65535.0 / vw);
    input.mi.dy = static_cast<LONG>((rect.top + y - vy) * 65535.0 / vh);
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
    SendInput(1, &input, sizeof(input));
  };
  if (type == "mm") {
    moveTo(Num(m, "x"), Num(m, "y"));
  } else if (type == "md" || type == "mu") {
    moveTo(Num(m, "x"), Num(m, "y"));
    const int button = static_cast<int>(Num(m, "b"));
    const bool down = type == "md";
    INPUT input{};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = button == 2 ? (down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP)
                       : button == 1 ? (down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP)
                                     : (down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP);
    SendInput(1, &input, sizeof(input));
  } else if (type == "wh") {
    INPUT input{};
    input.type = INPUT_MOUSE;
    const double dy = Num(m, "dy"), dx = Num(m, "dx");
    if (dy != 0) {
      input.mi.dwFlags = MOUSEEVENTF_WHEEL;
      input.mi.mouseData = static_cast<DWORD>(dy > 0 ? -WHEEL_DELTA : WHEEL_DELTA);
    } else {
      input.mi.dwFlags = MOUSEEVENTF_HWHEEL;
      input.mi.mouseData = static_cast<DWORD>(dx > 0 ? WHEEL_DELTA : -WHEEL_DELTA);
    }
    SendInput(1, &input, sizeof(input));
  } else if (type == "kd" || type == "ku") {
    SendKey(Str(m, "code"), type == "kd");
  } else if (type == "type") {
    TypeText(Utf8ToWide(Str(m, "text")));
  } else if (type == "clip.set") {
    const auto text = Utf8ToWide(Str(m, "text"));
    if (OpenClipboard(nullptr)) {
      EmptyClipboard();
      HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
      if (memory) {
        memcpy(GlobalLock(memory), text.c_str(), (text.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(memory);
        SetClipboardData(CF_UNICODETEXT, memory);
      }
      CloseClipboard();
    }
  } else if (type == "cad") {
    const auto failure = SendCtrlAltDel(options_.sessionId);
    HelperLog(failure.empty() ? "Ctrl+Alt+Del requested for this Windows session." : "Ctrl+Alt+Del failed: " + failure);
    SendJson("{\"ch\":\"sys\",\"t\":\"action.result\",\"action\":\"cad\",\"req\":" + RawJson(m, "req") +
             ",\"ok\":" + (failure.empty() ? "true" : "false") + ",\"message\":" +
             Q(failure.empty() ? "Ctrl+Alt+Del requested for this Windows session. Enter your Windows credentials when prompted."
                               : "Ctrl+Alt+Del could not be sent: " + failure) + "}");
  } else if (type == "lock") {
    LockWorkStation();
  }
}

// ---------------------------------------------------------------------------
// Terminal (ConPTY)
// ---------------------------------------------------------------------------

void Session::CloseTerminal() {
  if (termProcess_.hProcess) {
    TerminateProcess(termProcess_.hProcess, 0);
    CloseHandle(termProcess_.hProcess);
    CloseHandle(termProcess_.hThread);
    termProcess_ = {};
  }
  if (console_) {
    ClosePseudoConsole(console_);
    console_ = nullptr;
  }
  if (termIn_) {
    CloseHandle(termIn_);
    termIn_ = nullptr;
  }
  if (termReader_.joinable()) {
    termReader_.join();
  }
  if (termOut_) {
    CloseHandle(termOut_);
    termOut_ = nullptr;
  }
}

void Session::HandleTerm(const std::string& type, const json::Value& m) {
  if (!options_.allowTerminal) {
    SendJson("{\"ch\":\"term\",\"t\":\"error\",\"message\":\"Remote terminal is turned off by policy\"}");
    return;
  }
  if (type == "open") {
    CloseTerminal();
    HANDLE inRead = nullptr, outWrite = nullptr;
    if (!CreatePipe(&inRead, &termIn_, nullptr, 0) || !CreatePipe(&termOut_, &outWrite, nullptr, 0)) {
      SendJson("{\"ch\":\"term\",\"t\":\"error\",\"message\":\"Could not create the terminal pipes\"}");
      return;
    }
    COORD size{static_cast<SHORT>(std::clamp(static_cast<int>(Num(m, "cols", 120)), 20, 500)),
               static_cast<SHORT>(std::clamp(static_cast<int>(Num(m, "rows", 32)), 5, 300))};
    if (CreatePseudoConsole(size, inRead, outWrite, 0, &console_) != S_OK) {
      CloseHandle(inRead);
      CloseHandle(outWrite);
      SendJson("{\"ch\":\"term\",\"t\":\"error\",\"message\":\"ConPTY needs Windows 10 1809 or later\"}");
      return;
    }
    CloseHandle(inRead);
    CloseHandle(outWrite);
    const auto shell = Str(m, "shell") == "cmd" ? std::wstring(L"cmd.exe") : std::wstring(L"powershell.exe -NoLogo");
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    std::vector<std::uint8_t> attrBuffer(attrSize);
    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuffer.data());
    InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize);
    UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, console_, sizeof(console_), nullptr, nullptr);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attrs;
    std::vector<wchar_t> command(shell.begin(), shell.end());
    command.push_back(L'\0');
    wchar_t windowsDir[MAX_PATH]{};
    GetWindowsDirectoryW(windowsDir, MAX_PATH);
    const std::wstring workDir = std::wstring(windowsDir).substr(0, 3);
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT, nullptr, workDir.c_str(),
                        &startup.StartupInfo, &termProcess_)) {
      DeleteProcThreadAttributeList(attrs);
      SendJson("{\"ch\":\"term\",\"t\":\"error\",\"message\":\"Could not start the shell\"}");
      CloseTerminal();
      return;
    }
    DeleteProcThreadAttributeList(attrs);
    SendJson("{\"ch\":\"term\",\"t\":\"opened\",\"shell\":" + Q(shell) + "}");
    HANDLE output = termOut_;
    HANDLE process = termProcess_.hProcess;
    termReader_ = std::thread([this, output, process] {
      char buffer[16384];
      DWORD read = 0;
      while (ReadFile(output, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        if (!socket_.SendText("{\"ch\":\"term\",\"t\":\"out\",\"data\":\"" + Base64Encode(buffer, read) + "\"}")) {
          break;
        }
      }
      DWORD code = 0;
      GetExitCodeProcess(process, &code);
      socket_.SendText("{\"ch\":\"term\",\"t\":\"exit\",\"code\":" + std::to_string(code) + "}");
    });
    // When the shell exits, close the console so the reader sees end-of-file.
    std::thread([this, process] {
      WaitForSingleObject(process, INFINITE);
      if (console_) {
        ClosePseudoConsole(console_);
        console_ = nullptr;
      }
    }).detach();
  } else if (type == "in" && termIn_) {
    const auto data = Base64Decode(Str(m, "data"));
    DWORD written = 0;
    WriteFile(termIn_, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
  } else if (type == "resize" && console_) {
    ResizePseudoConsole(console_, COORD{static_cast<SHORT>(std::clamp(static_cast<int>(Num(m, "cols", 120)), 20, 500)),
                                        static_cast<SHORT>(std::clamp(static_cast<int>(Num(m, "rows", 32)), 5, 300))});
  } else if (type == "close") {
    CloseTerminal();
  }
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

std::uint64_t FileTimeToUnix(const FILETIME& ft) {
  const std::uint64_t value = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
  return value > 116444736000000000ull ? (value - 116444736000000000ull) / 10000000ull : 0;
}

void Session::HandleFiles(const std::string& type, const json::Value& m) {
  if (!options_.allowFiles) {
    Fail("files", m, "File transfer is turned off by policy");
    return;
  }
  std::wstring path = Utf8ToWide(Str(m, "path"));
  std::replace(path.begin(), path.end(), L'/', L'\\');
  if (type == "ls") {
    std::ostringstream entries;
    bool first = true;
    if (path.empty()) {
      wchar_t drives[512]{};
      GetLogicalDriveStringsW(511, drives);
      for (const wchar_t* d = drives; *d; d += wcslen(d) + 1) {
        entries << (first ? "" : ",") << "{\"name\":" << Q(std::wstring(d)) << ",\"dir\":true,\"size\":0,\"mtime\":0}";
        first = false;
      }
      Reply("files", m, "\"t\":\"ls\",\"path\":\"\",\"parent\":null,\"sep\":\"\\\\\",\"entries\":[" + entries.str() + "]");
      return;
    }
    if (path.size() == 2 && path[1] == L':') {
      path += L'\\';
    }
    WIN32_FIND_DATAW data{};
    const auto pattern = (path.back() == L'\\' ? path : path + L"\\") + L"*";
    HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
      Reply("files", m, "\"t\":\"ls\",\"path\":" + Q(path) + ",\"error\":\"Cannot open this folder\"");
      return;
    }
    do {
      if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) {
        continue;
      }
      const auto size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
      entries << (first ? "" : ",") << "{\"name\":" << Q(std::wstring(data.cFileName)) << ",\"dir\":"
              << ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "true" : "false") << ",\"size\":" << size
              << ",\"mtime\":" << FileTimeToUnix(data.ftLastWriteTime) << "}";
      first = false;
    } while (FindNextFileW(find, &data));
    FindClose(find);
    std::wstring trimmed = path;
    if (trimmed.size() > 3 && trimmed.back() == L'\\') {
      trimmed.pop_back();
    }
    const auto slash = trimmed.find_last_of(L'\\');
    std::string parent = "\"\"";  // drive roots go back to the drive list
    if (trimmed.size() > 3 && slash != std::wstring::npos) {
      parent = Q(slash <= 2 ? trimmed.substr(0, 3) : trimmed.substr(0, slash));
    }
    Reply("files", m, "\"t\":\"ls\",\"path\":" + Q(trimmed) + ",\"parent\":" + parent + ",\"sep\":\"\\\\\",\"entries\":[" + entries.str() + "]");
  } else if (type == "get") {
    const auto id = static_cast<std::uint32_t>(Num(m, "id"));
    std::thread([this, path, id] {
      HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        SendJson("{\"ch\":\"files\",\"t\":\"get.end\",\"id\":" + std::to_string(id) + ",\"error\":\"Cannot open the file\"}");
        return;
      }
      LARGE_INTEGER size{};
      GetFileSizeEx(file, &size);
      SendJson("{\"ch\":\"files\",\"t\":\"get.start\",\"id\":" + std::to_string(id) + ",\"size\":" + std::to_string(size.QuadPart) + "}");
      std::vector<char> buffer(5 + 60 * 1024);
      buffer[0] = 0x02;
      buffer[1] = static_cast<char>(id >> 24);
      buffer[2] = static_cast<char>(id >> 16);
      buffer[3] = static_cast<char>(id >> 8);
      buffer[4] = static_cast<char>(id);
      DWORD read = 0;
      while (running_ && ReadFile(file, buffer.data() + 5, 60 * 1024, &read, nullptr) && read > 0) {
        if (!socket_.SendBinary(buffer.data(), 5 + read)) {
          break;
        }
      }
      CloseHandle(file);
      SendJson("{\"ch\":\"files\",\"t\":\"get.end\",\"id\":" + std::to_string(id) + "}");
    }).detach();
  } else if (type == "put") {
    const auto id = static_cast<std::uint32_t>(Num(m, "id"));
    HANDLE file = CreateFileW((path + L".fenrir-part").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    uploads_[id] = {path, file};
    uploadBytes_[id] = 0;
  } else if (type == "put.end") {
    const auto id = static_cast<std::uint32_t>(Num(m, "id"));
    auto it = uploads_.find(id);
    std::string error;
    if (it == uploads_.end() || it->second.second == INVALID_HANDLE_VALUE) {
      error = "The file could not be created on the device";
    } else {
      CloseHandle(it->second.second);
      if (!MoveFileExW((it->second.first + L".fenrir-part").c_str(), it->second.first.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        error = "The file could not be saved (is it in use?)";
      }
    }
    if (it != uploads_.end()) {
      uploads_.erase(it);
    }
    SendJson("{\"ch\":\"files\",\"t\":\"put.ok\",\"id\":" + std::to_string(id) + (error.empty() ? "" : ",\"error\":" + Q(error)) + "}");
  } else if (type == "delete") {
    if (path.size() <= 3) {
      Fail("files", m, "Refusing to delete a drive root");
      return;
    }
    std::error_code ec;
    std::filesystem::remove_all(std::filesystem::path(path), ec);
    if (ec) {
      Fail("files", m, ec.message());
    } else {
      Reply("files", m, "\"t\":\"done\"");
    }
  } else if (type == "mkdir") {
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path), ec);
    if (ec) {
      Fail("files", m, ec.message());
    } else {
      Reply("files", m, "\"t\":\"done\"");
    }
  }
}

void Session::HandleUpload(const std::string& data) {
  if (data.size() <= 5 || !options_.allowFiles) {
    return;
  }
  const std::uint32_t id = (static_cast<std::uint8_t>(data[1]) << 24) | (static_cast<std::uint8_t>(data[2]) << 16) |
                           (static_cast<std::uint8_t>(data[3]) << 8) | static_cast<std::uint8_t>(data[4]);
  auto it = uploads_.find(id);
  if (it == uploads_.end() || it->second.second == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD written = 0;
  WriteFile(it->second.second, data.data() + 5, static_cast<DWORD>(data.size() - 5), &written, nullptr);
  uploadBytes_[id] += written;
}

// ---------------------------------------------------------------------------
// Processes and services
// ---------------------------------------------------------------------------

std::wstring ProcessUser(HANDLE process, std::map<std::wstring, std::wstring>* cache) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
    return L"";
  }
  std::vector<std::uint8_t> buffer(256);
  DWORD size = 0;
  std::wstring result;
  if (GetTokenInformation(token, TokenUser, buffer.data(), static_cast<DWORD>(buffer.size()), &size)) {
    auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR sidText = nullptr;
    if (ConvertSidToStringSidW(user->User.Sid, &sidText)) {
      auto it = cache->find(sidText);
      if (it != cache->end()) {
        result = it->second;
      } else {
        wchar_t name[256]{}, domain[256]{};
        DWORD nameSize = 255, domainSize = 255;
        SID_NAME_USE use{};
        if (LookupAccountSidW(nullptr, user->User.Sid, name, &nameSize, domain, &domainSize, &use)) {
          result = name;
        }
        (*cache)[sidText] = result;
      }
      LocalFree(sidText);
    }
  }
  CloseHandle(token);
  return result;
}

void Session::HandleProcs(const std::string& type, const json::Value& m) {
  if (type == "list") {
    std::lock_guard procLock(procMutex_);
    std::map<std::wstring, std::wstring> users;
    std::map<DWORD, std::uint64_t> cpu;
    const auto now = GetTickCount64();
    const double elapsedMs = lastSampleAt_ ? static_cast<double>(now - lastSampleAt_) : 0;
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    std::ostringstream items;
    bool first = true;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry)) {
      double cpuPercent = 0, memMb = 0;
      std::wstring user, path;
      if (HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID)) {
        FILETIME created{}, exited{}, kernel{}, userTime{};
        if (GetProcessTimes(process, &created, &exited, &kernel, &userTime)) {
          const auto total = ((static_cast<std::uint64_t>(kernel.dwHighDateTime) << 32) | kernel.dwLowDateTime) +
                             ((static_cast<std::uint64_t>(userTime.dwHighDateTime) << 32) | userTime.dwLowDateTime);
          cpu[entry.th32ProcessID] = total;
          if (auto it = lastCpu_.find(entry.th32ProcessID); it != lastCpu_.end() && elapsedMs > 0 && total >= it->second) {
            cpuPercent = static_cast<double>(total - it->second) / 10000.0 / elapsedMs * 100.0 / system.dwNumberOfProcessors;
          }
        }
        PROCESS_MEMORY_COUNTERS counters{};
        if (K32GetProcessMemoryInfo(process, &counters, sizeof(counters))) {
          memMb = static_cast<double>(counters.WorkingSetSize) / (1 << 20);
        }
        wchar_t image[MAX_PATH * 2]{};
        DWORD size = MAX_PATH * 2;
        if (QueryFullProcessImageNameW(process, 0, image, &size)) {
          path = image;
        }
        user = ProcessUser(process, &users);
        CloseHandle(process);
      }
      items << (first ? "" : ",") << "{\"pid\":" << entry.th32ProcessID << ",\"name\":" << Q(std::wstring(entry.szExeFile)) << ",\"user\":" << Q(user)
            << ",\"cpu\":" << cpuPercent << ",\"memMb\":" << memMb << ",\"path\":" << Q(path) << "}";
      first = false;
    }
    CloseHandle(snapshot);
    lastCpu_ = std::move(cpu);
    lastSampleAt_ = now;
    Reply("procs", m, "\"t\":\"list\",\"items\":[" + items.str() + "]");
  } else if (type == "kill") {
    const auto pid = static_cast<DWORD>(Num(m, "pid"));
    if (pid <= 4 || pid == GetCurrentProcessId()) {
      Fail("procs", m, "That process cannot be ended");
      return;
    }
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!process || !TerminateProcess(process, 1)) {
      if (process) CloseHandle(process);
      Fail("procs", m, "Access denied or the process already exited");
      return;
    }
    CloseHandle(process);
    Reply("procs", m, "\"t\":\"done\"");
  }
}

void Session::HandleServices(const std::string& type, const json::Value& m) {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
  if (!scm) {
    Fail("svc", m, "Cannot open the service manager");
    return;
  }
  if (type == "list") {
    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &needed, &count, &resume, nullptr);
    std::vector<std::uint8_t> buffer(needed + 4096);
    std::ostringstream items;
    bool first = true;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(), static_cast<DWORD>(buffer.size()), &needed,
                              &count, &resume, nullptr)) {
      const auto* services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
      for (DWORD i = 0; i < count; ++i) {
        std::string startType = "manual";
        if (SC_HANDLE service = OpenServiceW(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG)) {
          std::vector<std::uint8_t> config(8192);
          DWORD size = 0;
          if (QueryServiceConfigW(service, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data()), static_cast<DWORD>(config.size()), &size)) {
            const auto start = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data())->dwStartType;
            startType = start == SERVICE_AUTO_START ? "automatic" : start == SERVICE_DISABLED ? "disabled" : "manual";
          }
          CloseServiceHandle(service);
        }
        const auto state = services[i].ServiceStatusProcess.dwCurrentState;
        items << (first ? "" : ",") << "{\"name\":" << Q(std::wstring(services[i].lpServiceName)) << ",\"display\":"
              << Q(std::wstring(services[i].lpDisplayName)) << ",\"status\":\""
              << (state == SERVICE_RUNNING ? "running" : state == SERVICE_STOPPED ? "stopped" : "pending") << "\",\"startType\":\"" << startType << "\"}";
        first = false;
      }
    }
    Reply("svc", m, "\"t\":\"list\",\"items\":[" + items.str() + "]");
  } else if (type == "control") {
    const auto name = Utf8ToWide(Str(m, "name"));
    const auto action = Str(m, "action");
    SC_HANDLE service = OpenServiceW(scm, name.c_str(), SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
      Fail("svc", m, "Service not found or access denied");
    } else {
      SERVICE_STATUS status{};
      bool ok = true;
      if (action == "stop" || action == "restart") {
        ok = ControlService(service, SERVICE_CONTROL_STOP, &status) || GetLastError() == ERROR_SERVICE_NOT_ACTIVE;
        for (int i = 0; ok && i < 60 && QueryServiceStatus(service, &status) && status.dwCurrentState != SERVICE_STOPPED; ++i) {
          Sleep(500);
        }
      }
      if (ok && (action == "start" || action == "restart")) {
        ok = StartServiceW(service, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
      }
      CloseServiceHandle(service);
      if (ok) {
        Reply("svc", m, "\"t\":\"done\"");
      } else {
        Fail("svc", m, "The service did not accept the request (error " + std::to_string(GetLastError()) + ")");
      }
    }
  }
  CloseServiceHandle(scm);
}

// ---------------------------------------------------------------------------
// Banner + chat window (runs on its own UI thread)
// ---------------------------------------------------------------------------

HWND g_banner = nullptr, g_chatLog = nullptr, g_chatInput = nullptr, g_chatWindow = nullptr;
constexpr UINT WM_FENRIR_CHAT = WM_APP + 1;
constexpr int ID_END = 101, ID_SEND = 102, ID_CHAT = 103;

void AppendChat(const std::wstring& line) {
  if (!g_chatLog) return;
  const int length = GetWindowTextLengthW(g_chatLog);
  SendMessageW(g_chatLog, EM_SETSEL, length, length);
  SendMessageW(g_chatLog, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>((line + L"\r\n").c_str()));
}

LRESULT CALLBACK ChatProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
    case WM_CREATE: {
      g_chatLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                  8, 8, 364, 220, hwnd, nullptr, nullptr, nullptr);
      g_chatInput = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 8, 236, 284, 26, hwnd, nullptr, nullptr, nullptr);
      CreateWindowExW(0, L"BUTTON", L"Send", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 300, 236, 72, 26, hwnd, reinterpret_cast<HMENU>(ID_SEND), nullptr, nullptr);
      return 0;
    }
    case WM_COMMAND:
      if (LOWORD(wParam) == ID_SEND) {
        wchar_t text[1024]{};
        GetWindowTextW(g_chatInput, text, 1023);
        if (*text && g_session) {
          AppendChat(std::wstring(L"You: ") + text);
          g_session->OnChatFromUser(text);
          SetWindowTextW(g_chatInput, L"");
        }
      }
      return 0;
    case WM_CLOSE:
      ShowWindow(hwnd, SW_HIDE);
      return 0;
  }
  return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK BannerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
    case WM_CREATE: {
      CreateWindowExW(0, L"BUTTON", L"End session", WS_CHILD | WS_VISIBLE, 300, 6, 100, 24, hwnd, reinterpret_cast<HMENU>(ID_END), nullptr, nullptr);
      CreateWindowExW(0, L"BUTTON", L"Chat", WS_CHILD | WS_VISIBLE, 406, 6, 60, 24, hwnd, reinterpret_cast<HMENU>(ID_CHAT), nullptr, nullptr);
      return 0;
    }
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = BeginPaint(hwnd, &ps);
      SetBkMode(dc, TRANSPARENT);
      SetTextColor(dc, RGB(255, 255, 255));
      RECT rect{10, 0, 296, 36};
      const auto text = L"Remote support: " + Utf8ToWide(g_session ? g_session->options().technician : std::string());
      DrawTextW(dc, text.c_str(), -1, &rect, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
      EndPaint(hwnd, &ps);
      return 0;
    }
    case WM_COMMAND:
      if (LOWORD(wParam) == ID_END && g_session) {
        g_session->End("ended by the user");
      } else if (LOWORD(wParam) == ID_CHAT && g_chatWindow) {
        ShowWindow(g_chatWindow, SW_SHOW);
        SetForegroundWindow(g_chatWindow);
      }
      return 0;
    case WM_FENRIR_CHAT: {
      auto* text = reinterpret_cast<std::wstring*>(lParam);
      if (g_chatWindow) {
        ShowWindow(g_chatWindow, SW_SHOW);
        SetForegroundWindow(g_chatWindow);
      }
      AppendChat(L"Technician: " + *text);
      delete text;
      return 0;
    }
  }
  return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void UiThread(bool showBanner) {
  WNDCLASSW banner{};
  banner.lpfnWndProc = BannerProc;
  banner.hInstance = GetModuleHandleW(nullptr);
  banner.lpszClassName = L"FenrirRemoteBanner";
  banner.hbrBackground = CreateSolidBrush(RGB(37, 99, 235));
  banner.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
  RegisterClassW(&banner);
  WNDCLASSW chat{};
  chat.lpfnWndProc = ChatProc;
  chat.hInstance = GetModuleHandleW(nullptr);
  chat.lpszClassName = L"FenrirRemoteChat";
  chat.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
  chat.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
  RegisterClassW(&chat);
  const int width = 476;
  g_banner = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"FenrirRemoteBanner", L"Fenrir remote support", WS_POPUP,
                             (GetSystemMetrics(SM_CXSCREEN) - width) / 2, 0, width, 36, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
  g_chatWindow = CreateWindowExW(WS_EX_TOPMOST, L"FenrirRemoteChat", L"Chat with IT support", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                                 GetSystemMetrics(SM_CXSCREEN) - 420, 80, 396, 310, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
  if (showBanner) {
    ShowWindow(g_banner, SW_SHOWNOACTIVATE);
  }
  MSG msg;
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    if (!IsDialogMessageW(g_chatWindow, &msg)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }
}

void Session::OnChatFromUser(const std::wstring& text) {
  std::wstring user;
  LPWSTR name = nullptr;
  DWORD bytes = 0;
  if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &name, &bytes) && name) {
    user = name;
    WTSFreeMemory(name);
  }
  SendJson("{\"ch\":\"chat\",\"t\":\"msg\",\"text\":" + Q(text) + ",\"from\":" + Q(user.empty() ? std::wstring(L"User") : user) + "}");
}

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

bool UserSignedIn() {
  LPWSTR name = nullptr;
  DWORD bytes = 0;
  bool signedIn = false;
  if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &name, &bytes) && name) {
    signedIn = *name != L'\0';
    WTSFreeMemory(name);
  }
  return signedIn;
}

bool AskConsent(const Options& options) {
  if (options.consent == "never" || (options.consent == "when_user_present" && !UserSignedIn())) {
    return true;
  }
  SyncInputDesktop();
  using MessageBoxTimeoutFn = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);
  const auto text = Utf8ToWide(options.technician) + L" from your IT provider wants to connect to this computer to help you.\n\nAllow remote access?";
  auto fn = reinterpret_cast<MessageBoxTimeoutFn>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "MessageBoxTimeoutW"));
  const UINT style = MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND | MB_SYSTEMMODAL;
  const int answer = fn ? fn(nullptr, text.c_str(), L"Remote support request", style, 0, static_cast<DWORD>(options.consentTimeout) * 1000)
                        : MessageBoxW(nullptr, text.c_str(), L"Remote support request", style);
  if (answer == IDYES) {
    return true;
  }
  constexpr int kTimeout = 32000;
  return answer == kTimeout && options.onConsentTimeout == "allow";
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

void Session::Dispatch(const json::Value& m) {
  const auto ch = Str(m, "ch"), t = Str(m, "t");
  if (!(ch == "screen" && t == "ack")) {
    lastInput_ = static_cast<long long>(GetTickCount64());
  }
  if (ch == "sys") {
    if (t == "ping") {
      SendJson("{\"ch\":\"sys\",\"t\":\"pong\",\"ts\":" + RawJson(m, "ts") + "}");
    } else if (t == "viewer.joined") {
      Info();
    } else if (t == "end") {
      End("ended by technician");
    }
  } else if (Tunnel()) {
    if (ch == "tunnel" && tunnels_) {
      const auto id = static_cast<std::uint32_t>(Num(m, "id", 0));
      if (t == "open") tunnels_->Open(id);
      else if (t == "close") tunnels_->Close(id, false);
    }
    return;  // a tunnel carries only its streams
  } else if (Backstage() && (ch == "screen" || ch == "input" || ch == "chat")) {
    return;  // the relay already drops these for backstage sessions; never touch the user's desktop
  } else if (ch == "screen") {
    std::lock_guard lock(screenMutex_);
    if (t == "start" || t == "settings") {
      streaming_ = true;
      full_ = true;
      if (const auto q = Num(m, "quality", 0); q >= 10 && q <= 100) quality_ = static_cast<int>(q);
      if (const auto f = Num(m, "fps", 0); f >= 1) fps_ = std::min(static_cast<int>(f), options_.maxFps);
      monitor_ = std::max(-1, static_cast<int>(Num(m, "monitor", monitor_)));  // -1: all screens
    } else if (t == "refresh") {
      full_ = true;
    } else if (t == "ack") {
      inFlight_ = std::max(0, inFlight_ - 1);
    } else if (t == "stop") {
      streaming_ = false;
    }
    screenCv_.notify_all();
  } else if (ch == "input") {
    HandleInput(t, m);
  } else if (ch == "term") {
    HandleTerm(t, m);
  } else if (ch == "files") {
    HandleFiles(t, m);
  } else if (ch == "procs") {
    std::thread([this, m, t] { HandleProcs(t, m); }).detach();
  } else if (ch == "svc") {
    std::thread([this, m, t] { HandleServices(t, m); }).detach();
  } else if (ch == "chat" && t == "msg" && g_banner) {
    PostMessageW(g_banner, WM_FENRIR_CHAT, 0, reinterpret_cast<LPARAM>(new std::wstring(Utf8ToWide(Str(m, "text")))));
  }
}

int Session::Run() {
  HelperLog("Starting " + (options_.mode.empty() ? std::string("desktop") : options_.mode) + " session " +
            options_.sessionId + " for " + options_.technician + "; connecting to " + options_.relayUrl);
  try {
    socket_.Connect(Utf8ToWide(options_.relayUrl + (options_.relayUrl.find('?') == std::string::npos ? "?token=" : "&token=") + options_.token));
  } catch (const std::exception& error) {
    HelperLog(std::string("Could not connect to the relay: ") + error.what() +
              ". Check that this PC can reach that address (FENRIR_PUBLIC_URL on the server).");
    return 2;
  }
  HelperLog("Connected to the relay.");
  quality_ = options_.quality;
  fps_ = options_.maxFps;
  if (options_.mode == "desktop" || options_.mode.empty()) {
    if (options_.consent != "never") {
      socket_.SendText("{\"ch\":\"sys\",\"t\":\"consent\",\"state\":\"pending\"}");
    }
    if (!AskConsent(options_)) {
      HelperLog("The signed-in user declined the connection, or the consent prompt timed out.");
      socket_.SendText("{\"ch\":\"sys\",\"t\":\"consent\",\"state\":\"denied\"}");
      End("the user declined the connection");
      return 3;
    }
    socket_.SendText("{\"ch\":\"sys\",\"t\":\"consent\",\"state\":\"granted\"}");
  }
  if (Tunnel()) {
    tunnels_ = std::make_unique<fenrir::remote::TunnelStreams>(
        options_.targetHost, options_.targetPort, options_.allowedPorts,
        [this](const std::string& text) { return socket_.SendText(text); },
        [this](const char* data, std::size_t size) { return socket_.SendBinary(data, size); });
  }
  if (!Silent()) {
    std::thread ui(UiThread, options_.showBanner);
    ui.detach();
  }
  Info();
  if (!Silent()) {
    screenThread_ = std::thread(&Session::ScreenLoop, this);
  }
  std::thread idle([this] {
    while (running_) {
      Sleep(15000);
      if (static_cast<long long>(GetTickCount64()) - lastInput_ > static_cast<long long>(options_.idleMinutes) * 60000) {
        End("idle timeout");
      }
    }
  });
  idle.detach();
  std::string message;
  bool binary = false;
  while (running_ && socket_.Receive(&message, &binary)) {
    if (binary) {
      if (!message.empty() && static_cast<std::uint8_t>(message[0]) == 0x03 && !Tunnel()) {
        HandleUpload(message);
      } else if (!message.empty() && static_cast<std::uint8_t>(message[0]) == 0x05 && tunnels_) {
        tunnels_->Data(message);
      }
      continue;
    }
    if (const auto parsed = json::Parse(message); parsed && parsed->IsObject()) {
      Dispatch(*parsed);
    }
  }
  running_ = false;
  screenCv_.notify_all();
  if (screenThread_.joinable()) {
    screenThread_.join();
  }
  CloseTerminal();
  if (tunnels_) tunnels_->CloseAll();
  for (auto& [id, upload] : uploads_) {
    if (upload.second != INVALID_HANDLE_VALUE) {
      CloseHandle(upload.second);
      DeleteFileW((upload.first + L".fenrir-part").c_str());
    }
  }
  return 0;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  std::wstring optionsPath;
  for (int i = 1; i + 1 < argc; ++i) {
    if (wcscmp(argv[i], L"--options") == 0) {
      optionsPath = argv[i + 1];
    }
  }
  LocalFree(argv);
  Options options;
  if (!optionsPath.empty()) {
    g_logPath = std::filesystem::path(optionsPath).replace_extension(L".log");
  }
  if (optionsPath.empty() || !LoadOptions(optionsPath, &options)) {
    HelperLog("Could not read the session options file.");
    return 1;
  }
  SetProcessDPIAware();
  CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  Gdiplus::GdiplusStartupInput gdiplusInput;
  ULONG_PTR gdiplusToken = 0;
  Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusInput, nullptr);
  Session session(options);
  g_session = &session;
  const int code = session.Run();
  HelperLog("Helper exiting with code " + std::to_string(code) + ".");
  g_session = nullptr;
  Gdiplus::GdiplusShutdown(gdiplusToken);
  CoUninitialize();
  ExitProcess(static_cast<UINT>(code));
}
