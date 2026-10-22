#include "agent_system.h"

#include <cstdlib>
#include <array>
#include <fstream>

#if defined(_WIN32)
#include <Windows.h>
#include <Lmcons.h>
#else
#include <sys/utsname.h>
#include <unistd.h>
#include <limits.h>
#endif

namespace agent {

std::string DetectHostname() {
#if defined(_WIN32)
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameA(buffer, &size) == 0) {
        return {};
    }
    return std::string(buffer, size);
#else
    std::array<char, 256> buffer{};
    if (gethostname(buffer.data(), buffer.size()) != 0) {
        return {};
    }
    return std::string(buffer.data());
#endif
}

std::string DetectOsName() {
#if defined(_WIN32)
    return "Windows";
#else
    struct utsname info {};
    if (uname(&info) != 0) {
        return {};
    }
    return std::string(info.sysname);
#endif
}

std::string DetectTenantId() {
#if defined(_WIN32)
    char buffer[UNLEN + 1];
    DWORD size = UNLEN + 1;
    if (GetUserNameA(buffer, &size) == 0) {
        return {};
    }
    return std::string(buffer, size - 1);
#else
    const char* user = std::getenv("USER");
    if (user != nullptr && user[0] != '\0') {
        return std::string(user);
    }
    return {};
#endif
}

namespace {
std::string ReadMachineIdFile(const char* path) {
    std::ifstream file(path);
    if (!file) {
        return {};
    }
    std::string id;
    std::getline(file, id);
    return id;
}
}  // namespace

std::string DetectIdentityId() {
#if defined(_WIN32)
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameA(buffer, &size) == 0) {
        return {};
    }
    return std::string(buffer, size);
#else
    std::string id = ReadMachineIdFile("/etc/machine-id");
    if (!id.empty()) {
        return id;
    }
    id = ReadMachineIdFile("/var/lib/dbus/machine-id");
    if (!id.empty()) {
        return id;
    }
    return {};
#endif
}

std::string DetectExecutableDir() {
#if defined(_WIN32)
    char path[MAX_PATH];
    DWORD length = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (length == 0 || length == MAX_PATH) {
        return {};
    }
    std::string full_path(path, length);
#else
    char path[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length <= 0) {
        return {};
    }
    path[length] = '\0';
    std::string full_path(path);
#endif
    auto last_slash = full_path.find_last_of("/\\");
    if (last_slash == std::string::npos) {
        return {};
    }
    return full_path.substr(0, last_slash);
}

}  // namespace agent
