#include "CommandCancellation.h"
#include <iostream>

using namespace antivirus::agent::command_control;
using namespace std::chrono_literals;

static void CheckResult(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
int main() {
  try {
    auto state = std::make_shared<State>();
    {
      Scope scope(state);
      Check();
      state->requested.store(true);
      bool caught = false;
      try { Check(); } catch (const Cancelled&) { caught = true; }
      CheckResult(caught, "cancelled command was allowed to continue");
      bool unrelatedCancelled = true;
      std::thread independent([&] { unrelatedCancelled = Requested(); });
      independent.join();
      CheckResult(!unrelatedCancelled, "another thread inherited a command cancellation");
    }
    CheckResult(!Requested(), "command cancellation escaped its scope");
    int polls = 0;
    {
      Monitor monitor([&] {
        ++polls;
        if (polls == 2) throw std::runtime_error("temporary network loss");
        return polls >= 3;
      }, 5ms);
      for (int i = 0; i < 100 && !Requested(); ++i) std::this_thread::sleep_for(2ms);
      CheckResult(Requested(), "monitor did not retry cancellation after network loss");
    }
    std::cout << "command cancellation context tests passed\n";
    return 0;
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
