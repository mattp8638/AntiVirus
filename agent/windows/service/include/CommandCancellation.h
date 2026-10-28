#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace antivirus::agent::command_control {

struct Cancelled final : std::runtime_error {
  Cancelled() : std::runtime_error("Command cancelled by the operator") {}
};

struct State { std::atomic_bool requested{false}; };
extern thread_local std::shared_ptr<State> current;

inline bool Requested() { return current && current->requested.load(); }
inline void Check() { if (Requested()) throw Cancelled(); }

// The context belongs to one command thread. A remote desktop command, an AV
// background scan or the service itself must never be killed by another job.
class Scope {
 public:
  explicit Scope(std::shared_ptr<State> state) : previous_(current) { current = std::move(state); }
  ~Scope() { current = std::move(previous_); }
  Scope(const Scope&) = delete;
  Scope& operator=(const Scope&) = delete;
 private:
  std::shared_ptr<State> previous_;
};

class Monitor {
 public:
  explicit Monitor(std::function<bool()> poll, std::chrono::milliseconds interval = std::chrono::seconds(2))
      : state_(std::make_shared<State>()), scope_(state_) {
    // Verify cancellation before any work is started, including commands from
    // a previously fetched batch which may have been cancelled while waiting.
    state_->requested.store(poll());
    worker_ = std::thread([this, poll = std::move(poll), interval]() {
      std::unique_lock lock(mutex_);
      while (!done_ && !state_->requested.load()) {
        if (changed_.wait_for(lock, interval, [this] { return done_; })) break;
        lock.unlock();
        try { if (poll()) state_->requested.store(true); } catch (...) {
          // A network failure is not an acknowledgement. Retry while the job
          // runs; the console continues to show an unconfirmed stop request.
        }
        lock.lock();
      }
    });
  }
  ~Monitor() {
    { std::lock_guard lock(mutex_); done_ = true; }
    changed_.notify_all();
    if (worker_.joinable()) worker_.join();
  }
  Monitor(const Monitor&) = delete;
  Monitor& operator=(const Monitor&) = delete;
 private:
  std::shared_ptr<State> state_;
  Scope scope_;
  std::mutex mutex_;
  std::condition_variable changed_;
  bool done_{false};
  std::thread worker_;
};

}  // namespace antivirus::agent::command_control
