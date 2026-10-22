#include "agent_watchdog.h"

#include <chrono>
#include <iostream>

namespace agent {

namespace {
long long NowSeconds() {
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
    return seconds.count();
}
}  // namespace

HeartbeatWatchdog::HeartbeatWatchdog(std::chrono::seconds timeout)
    : timeout_(timeout) {}

HeartbeatWatchdog::~HeartbeatWatchdog() { Stop(); }

void HeartbeatWatchdog::Start() {
    if (running_.exchange(true)) {
        return;
    }
    last_tick_.store(NowSeconds());
    worker_ = std::thread(&HeartbeatWatchdog::Run, this);
}

void HeartbeatWatchdog::Stop() {
    if (!running_.exchange(false)) {
        return;
    }
    if (worker_.joinable()) {
        worker_.join();
    }
}

void HeartbeatWatchdog::NotifyHeartbeat() { last_tick_.store(NowSeconds()); }

void HeartbeatWatchdog::Run() {
    while (running_.load()) {
        std::this_thread::sleep_for(timeout_ / 2);
        long long last_tick = last_tick_.load();
        long long now = NowSeconds();
        if (now - last_tick > timeout_.count()) {
            std::cerr << "Heartbeat timeout detected." << std::endl;
        }
    }
}

}  // namespace agent
