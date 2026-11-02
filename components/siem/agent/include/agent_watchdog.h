#pragma once

#include <atomic>
#include <chrono>
#include <thread>

namespace agent {

class HeartbeatWatchdog {
   public:
    explicit HeartbeatWatchdog(std::chrono::seconds timeout);
    ~HeartbeatWatchdog();

    void Start();
    void Stop();
    void NotifyHeartbeat();

   private:
    void Run();

    std::chrono::seconds timeout_;
    std::atomic<bool> running_{false};
    std::atomic<long long> last_tick_{0};
    std::thread worker_;
};

}  // namespace agent
