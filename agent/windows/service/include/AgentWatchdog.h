#pragma once

// The agent watchdog: `fenrir-agent-service.exe --watchdog`, run by Windows Task Scheduler as SYSTEM every 5 minutes
// and a few minutes after boot (task "Fenrir\Agent watchdog"). It is a separate, short-lived process, so it works when
// the agent itself is stuck. Each run:
//
//  - repairs the service registration if it is missing (`--repair`), and Windows' restart-on-failure settings;
//  - starts the service if it is stopped;
//  - ends and restarts it if it is stuck starting or stopping for more than 10 minutes;
//  - ends and restarts it if it is running but its liveness record shows it stuck: the record not written for 10
//    minutes (the process is frozen), the main loop silent for an hour, or no answer from the server for 20 minutes
//    while this machine can reach the server itself;
//  - after 3 restarts in 6 hours that did not bring contact back, repairs the installation (at most every 12 hours).
//
// Restarts are at most one every 30 minutes, nothing happens during an install or upgrade (maintenance.flag), and
// every action is logged (runtime\watchdog.log) and reported by the agent to the console when it next starts.

#include <filesystem>
#include <string>

namespace antivirus::agent::watchdog {

constexpr wchar_t kTaskName[] = L"\\Fenrir\\Agent watchdog";

int Run();

// Registers (or updates) the scheduled task that runs the watchdog. Returns false with a reason on failure.
bool RegisterTask(const std::filesystem::path& serviceExe, std::wstring* error);

// Windows' restart-on-failure settings for the agent service (restart after every failure).
bool ApplyRecoverySettings(void* serviceHandle, std::wstring* error);

}  // namespace antivirus::agent::watchdog
