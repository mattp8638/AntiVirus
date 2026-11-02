// Backstage desktop: a hidden desktop in session 0 that a backstage remote session streams and controls.
//
// The backstage helper runs as SYSTEM in session 0, which nobody ever sees: the signed-in user works in their own
// session (1 or later). This creates a private desktop in session 0's interactive window station, makes it the
// session's input desktop, and starts administrative tools on it. Nothing is created, shown or changed in the user's
// session, so the user cannot tell a backstage session is happening.
//
// Session 0 has no compositor and Windows does not draw it to a screen, so a screen copy of it is blank (seen on
// Windows Server 2025). Capture() therefore asks each window to draw itself (PrintWindow) and stacks them. Input uses
// SendInput when a probe at Open() shows it reaches the desktop's windows, otherwise posted window messages.
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace fenrir::remote {

class BackstageDesktop {
 public:
  BackstageDesktop() = default;
  ~BackstageDesktop() { Close(); }
  BackstageDesktop(const BackstageDesktop&) = delete;
  BackstageDesktop& operator=(const BackstageDesktop&) = delete;

  // Creates the desktop, makes it session 0's input desktop and probes input. Returns "" on success, otherwise why not.
  std::string Open();
  bool IsOpen() const { return desktop_ != nullptr; }
  // Ends every program started on the desktop, switches session 0 back to its own desktop and removes ours.
  void Close();

  // Starts one of the known tools ("taskmgr", "regedit", "eventvwr", "services", "compmgmt", "devmgmt", "cmd",
  // "powershell") or, with tool "run", the given command line, on the hidden desktop as SYSTEM. Returns "" on success.
  std::string Launch(const std::string& tool, const std::wstring& commandLine = L"");

  // The area of the hidden desktop as top-down BGRA, every visible window drawn by itself, bottom to top. Call it from
  // a thread attached to the hidden desktop.
  bool Capture(const RECT& area, std::vector<std::uint8_t>* pixels, int* width, int* height) const;

  // Whether SendInput reaches windows on the hidden desktop (probed by Open). When it does not, use the methods below,
  // which post the equivalent window messages. Call them from a thread attached to the hidden desktop.
  bool SendInputWorks() const { return sendInputWorks_; }
  // action: 0 move, 1 button down, 2 button up, 3 vertical wheel, 4 horizontal wheel (button = +1 or -1 notches).
  // button for 1/2: 0 left, 1 middle, 2 right. x, y are desktop coordinates.
  void Mouse(int x, int y, int button, int action);
  void Key(unsigned scan, bool extended, bool down);
  void Char(wchar_t ch);

  HDESK Handle() const { return desktop_; }
  const std::wstring& Name() const { return name_; }

 private:
  std::string Start(std::wstring commandLine);
  bool ProbeSendInput();
  HWND FocusTarget() const;

  HWINSTA station_{nullptr};
  HWINSTA previousStation_{nullptr};
  HDESK desktop_{nullptr};
  HDESK previousInput_{nullptr};
  HANDLE job_{nullptr};
  std::wstring name_;
  bool sendInputWorks_{false};
  HWND keyTarget_{nullptr};
  bool shift_{false}, ctrl_{false}, alt_{false};
};

// Proves the mechanism on this machine: opens the hidden desktop, shows a test window and Task Manager on it, checks
// that a capture shows the test window and that a click reaches it, then cleans up. Writes a JSON result to resultPath
// and returns 0 when both capture and input work.
int RunBackstageSelfTest(const std::wstring& resultPath);

}  // namespace fenrir::remote
