#pragma once

// The technician's view of a Windows device: hardware, disks with SMART health, volumes and BitLocker, users and
// sessions, network, battery, security posture, event-log problems, services, startup items, printers, monitors
// and shares. Collected by an embedded PowerShell script (src/SystemProfileScript.ps1) running as SYSTEM.

#include <filesystem>
#include <string>

namespace antivirus::agent {

// Runs the collector and returns {"profile": {...}, "recoveryKeys": [...]} as UTF-8 JSON. Throws on failure.
// BitLocker recovery passwords are only in "recoveryKeys", which is sent to the cloud's encrypted key store.
std::string CollectSystemProfileJson(const std::filesystem::path& workRoot);

}  // namespace antivirus::agent
