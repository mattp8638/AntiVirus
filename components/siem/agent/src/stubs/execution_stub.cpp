// Minimal ExecutionService::RunScript stub to allow linking
#include "../../include/agent_execution.h"

namespace agent_execution {
    ExecutionResult ExecutionService::RunScript(const ScriptJob& job) {
        ExecutionResult r;
        r.job_id = job.job_id;
        r.exit_code = 0;
        r.stdout_data = "[stub] executed";
        r.stderr_data = "";
        r.completed_at = std::chrono::system_clock::now();
        return r;
    }

    PatchJobResult ExecutionService::ApplyPatchJob(const PatchJob& job) {
        PatchJobResult r;
        r.job_id = job.job_id;
        r.status = job.patches.empty() ? "failed" : "completed";
        r.result = job.patches.empty() ? "no_patches" : "installed";
        r.exit_code = job.patches.empty() ? 2 : 0;
        r.reboot_required = (job.reboot_policy == "required");
        r.stdout_summary = "[stub] patches applied";
        r.stderr_summary = "";
        r.started_at = std::chrono::system_clock::now();
        r.completed_at = std::chrono::system_clock::now();
        return r;
    }
}
