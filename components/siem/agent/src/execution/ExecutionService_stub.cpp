#include "ExecutionService_stub.h"
namespace agent_execution {
ExecutionResult ExecutionService::RunScript(const ScriptJob&) {
    ExecutionResult result{};
    // Stub: always return success
    result.exit_code = 0;
    result.stdout_data = "stubbed execution output";
    result.stderr_data = "";
    result.completed_at = std::chrono::system_clock::now();
    return result;
}
}
