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
  long long selfRestartAt{0};    // when the agent last restarted itself
  std::string lastError;
  std::string selfRestartReason;
};

long long Now();

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

// Starts the writer thread (every 30 s) and the stall detector (main loop silent for kMainLoopStallMinutes, or the
// server unreachable for kNoContactMinutes while trying, at most once every 2 hours: the process ends so Windows
// restarts it). previous is the record the last process left, read before it is overwritten.
void Start(const std::filesystem::path& file, std::optional<Snapshot>* previous = nullptr);
void Stop();

std::optional<Snapshot> Read(const std::filesystem::path& file);
bool Write(const std::filesystem::path& file, const Snapshot& snapshot);

constexpr int kMainLoopStallMinutes = 45;
constexpr int kNoContactMinutes = 30;
constexpr int kSelfRestartGapMinutes = 120;

}  // namespace antivirus::agent::liveness
