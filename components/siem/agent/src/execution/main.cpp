// Execution Service
// Responsibilities: Script execution, patching, installs, config enforcement, remote ops
#include <iostream>
#include <iomanip>
#include <sstream>
#include "agent_config.h"
#include "agent_execution.h"
#include "../../include/agent_rmm.h"
#include "../../ipc/named_pipe_ipc.h"
#include <windows.h>

namespace {
std::string BuildIsoTimestamp(const std::chrono::system_clock::time_point& time_point) {
    auto now_time = std::chrono::system_clock::to_time_t(time_point);
    std::tm utc_tm{};
#if defined(_WIN32)
    gmtime_s(&utc_tm, &now_time);
#else
    gmtime_r(&now_time, &utc_tm);
#endif
    std::ostringstream stream;
    stream << std::put_time(&utc_tm, "%FT%TZ");
    return stream.str();
}
}  // namespace

int main(int argc, char* argv[]) {
    // Attempt to connect to the core agent named pipe before running jobs
    // Validate pipe name (must not contain invalid characters)
    std::wstring pipe_name = L"tamsil_agent_pipe";
    for (wchar_t c : pipe_name) {
        if (!(iswalnum(c) || c == L'_' || c == L'-')) {
            std::wcerr << L"[ExecutionService] Invalid character in pipe name. Falling back to 'tamsil_agent_pipe'." << std::endl;
            pipe_name = L"tamsil_agent_pipe";
            break;
        }
    }
    agent_ipc::NamedPipeClient client(pipe_name);
    // Retry until the core server is available. In some launch scenarios the core
    // may start after this service; keep retrying and log attempts so operators
    // can see progress instead of exiting immediately.
    const int retry_delay_ms = 500;
    int attempt = 0;
    while (true) {
        if (client.Connect()) break;
        attempt++;
        std::cerr << "[ExecutionService] Failed to connect to pipe, retrying... (" << attempt << ")" << std::endl;
        Sleep(retry_delay_ms);
    }
    std::cout << "Execution Service connected to core agent pipe." << std::endl;
    // Example: Run a script job
    agent::Config config = agent::LoadConfig();
    agent_rmm::RmmTelemetryClient rmm_client(config);

    agent_execution::ExecutionService exec;
    agent_execution::ScriptJob job;
    job.job_id = "job-001";
    job.script_type = "PowerShell";
    job.script_content = "Write-Output 'Hello from agent'";
    job.args = {"-NoProfile"};
    job.scheduled_for = std::chrono::system_clock::now();
    auto started_at = std::chrono::system_clock::now();
    auto result = exec.RunScript(job);
    auto completed_at = result.completed_at;

    agent_rmm::RmmConfigProfile profile{};
    profile.name = "Baseline Security Profile";
    profile.profile_type = "hardening";
    profile.description = "Default hardening profile applied by the agent.";
    rmm_client.SendConfigProfile(profile);

    std::vector<agent_rmm::RmmPatchCatalogItem> catalog{
        {"Microsoft", "Windows", "patch-001", "2024-04-01", 4}
    };
    rmm_client.SendPatchCatalog(catalog);

    agent_rmm::RmmPatchJob patch_job{};
    patch_job.psa_case_id = "";
    patch_job.scheduled_for = "2024-04-01T09:00:00Z";
    patch_job.reboot_policy = "if_required";
    rmm_client.SendPatchJob(patch_job);

    agent_rmm::RmmScriptResult script_result{};
    script_result.job_id = job.job_id;
    script_result.stdout_data = result.stdout_data;
    script_result.stderr_data = result.stderr_data;
    script_result.exit_code = result.exit_code;
    script_result.hash = "sha256:placeholder";
    rmm_client.SendScriptResult(script_result);

    agent_rmm::RmmRemoteSession session{};
    session.asset_id = config.asset_id;
    session.initiated_by = "operator-local";
    session.session_type = "support";
    rmm_client.SendRemoteSession(session);
    std::cout << "Execution Service started. Example script job run." << std::endl;
    // TODO: Validate PSA authorisation, command signing, scope, safety
    // PowerShell, CMD, native binaries, patch management
    client.Close();
    return 0;
}
