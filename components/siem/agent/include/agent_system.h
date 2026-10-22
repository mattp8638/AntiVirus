#pragma once

#include <string>

namespace agent {

std::string DetectHostname();
std::string DetectOsName();
std::string DetectTenantId();
std::string DetectIdentityId();
std::string DetectExecutableDir();

}  // namespace agent
