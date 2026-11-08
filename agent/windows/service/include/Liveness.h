#pragma once

// The agent's liveness record (runtime\liveness.json): when its main loop last made progress, when it last reached
// the server, and why it last restarted itself. The agent writes it every 30 seconds; the watchdog (--watchdog, run
// by a scheduled task) reads it to tell a healthy agent from one that is running but stuck, and restarts the latter.
// A thread inside the agent also restarts the process when the main loop stalls for too long.

#include <filesystem>
#include <optional>
#include <string>

namespace antivirus::agent::liveness {

struct Snapshot {
  long long pid{0};
  long long startedAt{0};        // unix seconds
  long long writtenAt{0};        // when this record was written (the writer thread is alive)
  long long loopAt{0};           // main loop progress
  long long contactOkAt{0};      // last answer from the server (any 2xx, or a pong on the live connection)
  long long contactAttemptAt{0}; // last attempt to reach it
  long long lastStatus{0};       // last HTTP status from the server (401/403: the device key is refused)
  long long writtenAwake{0};
  long long loopAwake{0};
  long long contactAttemptAwake{0};
  long long selfRestartAt{0};    // when the agent last restarted itself
  std::string lastError;
  std::string selfRestartReason;
};

long long Now();
long long AwakeSeconds();  // monotonic time since boot, excluding sleep and hibernation

inline bool Stalled(long long now, long long last, long long limit) {
  return last > 0 && now > last && now - last > limit;
}

// Agent side. Cheap, thread-safe, callable from anywhere.
void MarkLoop();
// The main loop's thread (set once by the sync loop). MarkProgress counts only when called on it, so long but
// supervised work on the main loop (a script or patch install waiting on its own time limit, an inline scan going
// file by file) is not mistaken for a stall, while background scans cannot hide a stuck main loop.
void SetMainThread();
void MarkProgress();
void MarkContactOk(unsigned long status = 200);
long long LastContactOk();
void MarkContactFailed(unsigned long status, const std::string& why);

// The writer restarts the process only when its main loop stops making progress while awake.
void Start(const std::filesystem::path& file, std::optional<Snapshot>* previous = nullptr);
void Stop();

std::optional<Snapshot> Read(const std::filesystem::path& file);
bool Write(const std::filesystem::path& file, const Snapshot& snapshot);

constexpr int kMainLoopStallMinutes = 45;

}  // namespace antivirus::agent::liveness
