#include "../../include/agent_core.h"

namespace agent_core {

void ModuleRegistry::RegisterModule(const ModuleInfo& info) {
    modules_.push_back(info);
}

std::vector<ModuleInfo> ModuleRegistry::ListModules() const {
    return modules_;
}

} // namespace agent_core
