#pragma once

#include <filesystem>
#include <functional>
#include <string>

namespace fenrir::setup {

// What a full removal did. Anything that could not be deleted because Windows still holds it open is
// scheduled for deletion at the next restart and counted in pendingReboot.
struct RemovalReport {
  int removed{0};
  int pendingReboot{0};
  int warnings{0};
};

using RemovalLog = std::function<void(const std::wstring&)>;

// Enables the take-ownership, backup and restore privileges an elevated administrator holds but has disabled,
// so folders Fenrir locked to SYSTEM (quarantine, evidence) can be reclaimed and deleted.
void EnableRemovalPrivileges();

// Deletes a folder tree even when Fenrir hardened it: takes ownership, resets the permissions to
// Administrators + SYSTEM, clears read-only/system attributes, deletes, and schedules anything still in use for
// deletion at restart. Junctions and symbolic links are removed as links and never followed.
void ForceDeleteTree(const std::filesystem::path& root, RemovalReport& report, const RemovalLog& log);

// Removes every trace Fenrir leaves outside its install folder: data and quarantine folders (machine and every
// user profile), registry keys (machine, every user hive, services, AMSI, uninstall entry, Run values), the
// minifilter driver package, WFP filters, ETW sessions, firewall rules, scheduled tasks, the break-glass account
// and the Fenrir event-log source. Safe to run more than once.
void PurgeMachineState(const std::filesystem::path& installRoot, RemovalReport& report, const RemovalLog& log);

}  // namespace fenrir::setup
