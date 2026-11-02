// Backstage desktop: a hidden desktop in session 0 that a backstage remote session streams and controls.
//
// The backstage helper runs as SYSTEM in session 0, which nobody ever sees: the signed-in user works in their own
// session (1 or later). This creates a private desktop in session 0's interactive window station, makes it the
// session's input desktop (so GDI renders it and SendInput reaches it), and starts administrative tools on it. Nothing
// is created, shown or changed in the user's session, so the user cannot tell a backstage session is happening.
#pragma once

#include <windows.h>

#include <string>

namespace fenrir::remote {

class BackstageDesktop {
 public:
  BackstageDesktop() = default;
  ~BackstageDesktop() { Close(); }
  BackstageDesktop(const BackstageDesktop&) = delete;
  BackstageDesktop& operator=(const BackstageDesktop&) = delete;

  // Creates the desktop and makes it session 0's input desktop. Returns "" on success, otherwise why not.
  std::string Open();
  bool IsOpen() const { return desktop_ != nullptr; }
  // Ends every program started on the desktop, switches session 0 back to its own desktop and removes ours.
  void Close();

  // Starts one of the known tools ("taskmgr", "regedit", "eventvwr", "services", "compmgmt", "devmgmt", "cmd",
  // "powershell") or, with tool "run", the given command line, on the hidden desktop as SYSTEM. Returns "" on success.
  std::string Launch(const std::string& tool, const std::wstring& commandLine = L"");

  // Every program started here is in this job, so it ends with the session.
  HANDLE Job() const { return job_; }
  const std::wstring& Name() const { return name_; }

 private:
  std::string Start(std::wstring commandLine);

  HWINSTA station_{nullptr};
  HWINSTA previousStation_{nullptr};
  HDESK desktop_{nullptr};
  HDESK previousInput_{nullptr};
  HANDLE job_{nullptr};
  std::wstring name_;
};

// Proves the mechanism on this machine: opens the hidden desktop, shows a test window and starts Task Manager on it,
// captures the desktop and checks the test colour is in the picture, then cleans up. Writes a JSON result to
// resultPath and returns 0 when the capture worked.
int RunBackstageSelfTest(const std::wstring& resultPath);

}  // namespace fenrir::remote
