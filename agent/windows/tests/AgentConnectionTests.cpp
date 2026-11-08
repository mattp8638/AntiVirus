#include "Liveness.h"
#include "WebSocketClient.h"

#include <chrono>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using antivirus::agent::liveness::Stalled;

int main(int argc, char** argv) {
  if (argc != 2) return 1;
  if (Stalled(100, 100, 60) || Stalled(160, 100, 60) || !Stalled(161, 100, 60) ||
      Stalled(10, 100, 60) || Stalled(100, 0, 60)) return 2;

  const std::string port(argv[1]);
  const auto url = L"ws://127.0.0.1:" + std::wstring(port.begin(), port.end());
  antivirus::agent::WebSocketClient client;
  const auto start = std::chrono::steady_clock::now();
  try {
    client.Connect(url + L"/stall", L"", 500);
    return 3;
  } catch (const std::runtime_error&) {
    if (std::chrono::steady_clock::now() - start > 8s) return 4;
  }
  for (int i = 0; i < 3; ++i) {
    client.Connect(url + L"/live");
    std::string message;
    bool binary = false;
    if (!client.Receive(&message, &binary) || binary || message != "ok") return 5;
    auto receiving = std::async(std::launch::async, [&] { return client.Receive(&message, &binary); });
    if (receiving.wait_for(100ms) != std::future_status::timeout) return 6;
    std::thread closer([&] { client.Close(); });
    client.Close();
    closer.join();
    if (receiving.get() || client.Connected()) return 7;
  }
}
