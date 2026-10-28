#include "CommandCancellation.h"
namespace antivirus::agent::command_control {
thread_local std::shared_ptr<State> current;
}
