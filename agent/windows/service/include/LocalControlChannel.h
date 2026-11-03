#pragma once

#include <atomic>
#include <memory>
#include <functional>
#include <string>

#include "ControlPlaneClient.h"

namespace antivirus::agent {

constexpr wchar_t kFenrirLocalControlPipeName[] = LR"(\\.\pipe\FenrirEndpointLocalApi)";

class LocalControlChannel {
 public:
  using CommandExecutor = std::function<std::wstring(const RemoteCommand&)>;
  using StopPredicate = std::function<bool()>;

  LocalControlChannel(CommandExecutor executor, StopPredicate shouldStop);
  ~LocalControlChannel();

  LocalControlChannel(const LocalControlChannel&) = delete;
  LocalControlChannel& operator=(const LocalControlChannel&) = delete;

  void Start();
  // Asks the worker to finish and returns at once (safe from a service control handler, which must never block).
  void RequestStop();
  // RequestStop, then waits for the worker to finish.
  void Stop();

 private:
  void Run();

  struct State;
  CommandExecutor executor_;
  StopPredicate shouldStop_;
  std::unique_ptr<State> state_;
  bool running_{false};
  std::atomic<bool> stopRequested_{false};
};

}  // namespace antivirus::agent
