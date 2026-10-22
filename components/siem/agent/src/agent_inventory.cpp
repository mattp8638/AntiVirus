#include "agent_inventory.h"

#include <chrono>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <sys/statvfs.h>
#include <sys/utsname.h>
#endif

#include "../include/agent_rmm.h"

namespace agent {

namespace {
std::string SanitiseFilenameToken(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (const char c : input) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') {
            output.push_back(c);
        } else {
            output.push_back('_');
        }
    }
    if (output.empty()) {
        return "unnamed";
    }
    return output;
}

std::string JsonEscape(const std::string& input) {
    std::ostringstream escaped;
    for (char c : input) {
        switch (c) {
            case '"':
                escaped << "\\\"";
                break;
            case '\\':
                escaped << "\\\\";
                break;
            case '\n':
                escaped << "\\n";
                break;
            case '\r':
                escaped << "\\r";
                break;
            case '\t':
                escaped << "\\t";
                break;
            default:
                escaped << c;
                break;
        }
    }
    return escaped.str();
}

std::string BuildTimestampIso8601() {
    auto now = std::chrono::system_clock::now();
    auto now_time = std::chrono::system_clock::to_time_t(now);
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

struct HardwareInfo {
    std::optional<std::string> manufacturer;
    std::optional<std::string> model;
    std::optional<std::string> serial_number;
    std::optional<std::string> cpu_model;
    std::optional<int> cpu_cores;
    std::optional<int> memory_mb;
    std::optional<int> storage_gb;
};

struct OsInfo {
    std::string os_name;
    std::string os_version;
    std::optional<std::string> kernel_version;
    std::optional<std::string> architecture;
};

struct SoftwareItem {
    std::string name;
    std::optional<std::string> vendor;
    std::optional<std::string> version;
    std::optional<std::string> install_date;
    std::optional<std::string> source;
};

struct LocalUser {
    std::string username;
    std::optional<std::string> display_name;
    std::optional<std::string> uid;
    bool is_admin;
};

struct LocalGroup {
    std::string name;
    std::optional<std::string> gid;
    std::vector<std::string> members;
};

std::optional<std::string> ReadFileValue(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }
    std::string value;
    std::getline(file, value);
    if (value.empty()) {
        return std::nullopt;
    }
    return value;
}

std::string OptionalToString(const std::optional<std::string>& value, const std::string& fallback) {
    if (value && !value->empty()) {
        return *value;
    }
    return fallback;
}

std::optional<std::string> ExtractOsReleaseValue(const std::string& key) {
    std::ifstream file("/etc/os-release");
    if (!file.is_open()) {
        return std::nullopt;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind(key + "=", 0) != 0) {
            continue;
        }
        std::string value = line.substr(key.size() + 1);
        if (!value.empty() && value.front() == '"') {
            value.erase(0, 1);
        }
        if (!value.empty() && value.back() == '"') {
            value.pop_back();
        }
        if (value.empty()) {
            return std::nullopt;
        }
        return value;
    }
    return std::nullopt;
}

std::vector<std::string> SplitString(const std::string& input, char delimiter) {
    std::vector<std::string> parts;
    std::ostringstream current;
    for (char c : input) {
        if (c == delimiter) {
            parts.push_back(current.str());
            current.str("");
            current.clear();
        } else {
            current << c;
        }
    }
    parts.push_back(current.str());
    return parts;
}

HardwareInfo CollectHardware() {
    HardwareInfo info{};
#if defined(_WIN32)
    info.cpu_cores = static_cast<int>(std::thread::hardware_concurrency());
    return info;
#else
    info.manufacturer = ReadFileValue("/sys/devices/virtual/dmi/id/sys_vendor");
    info.model = ReadFileValue("/sys/devices/virtual/dmi/id/product_name");
    info.serial_number = ReadFileValue("/sys/devices/virtual/dmi/id/product_serial");

    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.rfind("model name", 0) == 0) {
            auto parts = SplitString(line, ':');
            if (parts.size() > 1) {
                info.cpu_model = parts[1];
                if (!info.cpu_model->empty() && info.cpu_model->front() == ' ') {
                    info.cpu_model->erase(0, 1);
                }
            }
            break;
        }
    }

    std::ifstream meminfo("/proc/meminfo");
    while (std::getline(meminfo, line)) {
        if (line.rfind("MemTotal:", 0) == 0) {
            auto parts = SplitString(line, ' ');
            for (const auto& part : parts) {
                if (part.empty() || !std::isdigit(static_cast<unsigned char>(part[0]))) {
                    continue;
                }
                info.memory_mb = static_cast<int>(std::stol(part) / 1024);
                break;
            }
            break;
        }
    }

    auto cores = std::thread::hardware_concurrency();
    if (cores > 0) {
        info.cpu_cores = static_cast<int>(cores);
    }

    struct statvfs stats {};
    if (statvfs("/", &stats) == 0) {
        unsigned long long total =
            static_cast<unsigned long long>(stats.f_blocks) *
            static_cast<unsigned long long>(stats.f_frsize);
        info.storage_gb = static_cast<int>(total / (1024ULL * 1024ULL * 1024ULL));
    }

    return info;
#endif
}

OsInfo CollectOs(const Config& config) {
    OsInfo info{};
    info.os_name = config.os_name.empty() ? "unknown" : config.os_name;
    info.os_version = "unknown";
#if defined(_WIN32)
    return info;
#else
    auto version_id = ExtractOsReleaseValue("VERSION_ID");
    auto pretty_name = ExtractOsReleaseValue("PRETTY_NAME");
    if (version_id && !version_id->empty()) {
        info.os_version = *version_id;
    } else if (pretty_name && !pretty_name->empty()) {
        info.os_version = *pretty_name;
    }
    struct utsname uname_info {};
    if (uname(&uname_info) == 0) {
        info.kernel_version = uname_info.release;
        info.architecture = uname_info.machine;
    }
    return info;
#endif
}

std::vector<SoftwareItem> CollectSoftwareInventory() {
    std::vector<SoftwareItem> items;
#if defined(_WIN32)
    return items;
#else
    std::ifstream status("/var/lib/dpkg/status");
    if (!status.is_open()) {
        return items;
    }
    std::string line;
    std::string package_name;
    std::string version;
    std::string status_line;

    auto flush_entry = [&]() {
        if (package_name.empty()) {
            return;
        }
        if (status_line.find("install ok installed") == std::string::npos) {
            package_name.clear();
            version.clear();
            status_line.clear();
            return;
        }
        SoftwareItem item{};
        item.name = package_name;
        item.version = version.empty() ? std::nullopt : std::optional<std::string>(version);
        item.source = std::string("dpkg");
        items.push_back(item);
        package_name.clear();
        version.clear();
        status_line.clear();
    };

    while (std::getline(status, line)) {
        if (line.empty()) {
            flush_entry();
            continue;
        }
        if (line.rfind("Package:", 0) == 0) {
            package_name = line.substr(8);
            if (!package_name.empty() && package_name.front() == ' ') {
                package_name.erase(0, 1);
            }
        } else if (line.rfind("Version:", 0) == 0) {
            version = line.substr(8);
            if (!version.empty() && version.front() == ' ') {
                version.erase(0, 1);
            }
        } else if (line.rfind("Status:", 0) == 0) {
            status_line = line.substr(7);
            if (!status_line.empty() && status_line.front() == ' ') {
                status_line.erase(0, 1);
            }
        }
    }
    flush_entry();

    return items;
#endif
}

std::vector<LocalUser> CollectLocalUsers() {
    std::vector<LocalUser> users;
#if defined(_WIN32)
    return users;
#else
    std::ifstream passwd("/etc/passwd");
    if (!passwd.is_open()) {
        return users;
    }
    std::string line;
    while (std::getline(passwd, line)) {
        if (line.empty()) {
            continue;
        }
        auto fields = SplitString(line, ':');
        if (fields.size() < 5) {
            continue;
        }
        LocalUser user{};
        user.username = fields[0];
        user.uid = fields[2].empty() ? std::nullopt : std::optional<std::string>(fields[2]);
        user.display_name =
            fields[4].empty() ? std::nullopt : std::optional<std::string>(fields[4]);
        user.is_admin = (fields[2] == "0");
        users.push_back(user);
    }
    return users;
#endif
}

std::vector<LocalGroup> CollectLocalGroups() {
    std::vector<LocalGroup> groups;
#if defined(_WIN32)
    return groups;
#else
    std::ifstream group_file("/etc/group");
    if (!group_file.is_open()) {
        return groups;
    }
    std::string line;
    while (std::getline(group_file, line)) {
        if (line.empty()) {
            continue;
        }
        auto fields = SplitString(line, ':');
        if (fields.size() < 4) {
            continue;
        }
        LocalGroup group{};
        group.name = fields[0];
        group.gid = fields[2].empty() ? std::nullopt : std::optional<std::string>(fields[2]);
        if (!fields[3].empty()) {
            group.members = SplitString(fields[3], ',');
        }
        groups.push_back(group);
    }
    return groups;
#endif
}

void AppendOptionalString(
    std::ostringstream& stream,
    const std::string& key,
    const std::optional<std::string>& value,
    bool trailing_comma = true
) {
    stream << "\"" << key << "\":";
    if (value && !value->empty()) {
        stream << "\"" << JsonEscape(*value) << "\"";
    } else {
        stream << "null";
    }
    if (trailing_comma) {
        stream << ",";
    }
}

void AppendString(
    std::ostringstream& stream,
    const std::string& key,
    const std::string& value,
    bool trailing_comma = true
) {
    stream << "\"" << key << "\":\"" << JsonEscape(value) << "\"";
    if (trailing_comma) {
        stream << ",";
    }
}

void AppendOptionalInt(
    std::ostringstream& stream,
    const std::string& key,
    const std::optional<int>& value,
    bool trailing_comma = true
) {
    stream << "\"" << key << "\":";
    if (value) {
        stream << *value;
    } else {
        stream << "null";
    }
    if (trailing_comma) {
        stream << ",";
    }
}

bool EnqueueUplinkInventoryPayload(
    const std::string& queue_dir,
    const std::string& category,
    const std::string& path,
    const std::string& payload
) {
    if (queue_dir.empty() || payload.empty() || path.empty()) {
        std::cerr << "[Inventory] Missing queue directory, path, or payload for uplink." << std::endl;
        return false;
    }

    std::filesystem::path queue_path(queue_dir);
    std::filesystem::create_directories(queue_path);

    const auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string safe_category = SanitiseFilenameToken(category);
    std::filesystem::path payload_path = queue_path / ("inventory_" + safe_category + "_" + std::to_string(now_epoch) + ".json");

    std::ofstream out(payload_path);
    if (!out) {
        std::cerr << "[Inventory] Unable to write uplink queue item: " << payload_path << std::endl;
        return false;
    }

    std::string json;
    json.reserve(payload.size() + path.size() + 64);
    json += "{";
    json += "\"kind\":\"inventory\",";
    json += "\"path\":\"" + JsonEscape(path) + "\",";
    json += "\"payload_json\":\"" + JsonEscape(payload) + "\"";
    json += "}";

    out << json;
    out.close();
    return true;
}
}  // namespace

bool SendInventorySnapshot(const Config& config) {
    std::string collected_at = BuildTimestampIso8601();
    HardwareInfo hardware_info = CollectHardware();
    OsInfo os_info = CollectOs(config);
    std::vector<SoftwareItem> software_items = CollectSoftwareInventory();
    std::vector<LocalUser> local_users = CollectLocalUsers();
    std::vector<LocalGroup> local_groups = CollectLocalGroups();
    agent_rmm::RmmTelemetryClient rmm_client(config);

    agent_rmm::RmmDeviceInventory device_inventory{};
    device_inventory.asset_id = config.asset_id;
    device_inventory.hostname = config.hostname;
    device_inventory.os_name = os_info.os_name;
    device_inventory.os_version = os_info.os_version;
    device_inventory.serial_number = OptionalToString(hardware_info.serial_number, "unknown");
    device_inventory.collected_at = std::chrono::system_clock::now();
    rmm_client.SendDeviceInventory(device_inventory);

    std::ostringstream hardware;
    hardware << '{'
             << "\"tenant_id\":\"" << JsonEscape(config.tenant_id) << "\"," 
             << "\"asset_id\":\"" << JsonEscape(config.asset_id) << "\"," 
             << "\"collected_at\":\"" << collected_at << "\"," 
             << "\"hostname\":\"" << JsonEscape(config.hostname) << "\"," 
             ;
    AppendOptionalString(hardware, "manufacturer", hardware_info.manufacturer);
    AppendOptionalString(hardware, "model", hardware_info.model);
    AppendOptionalString(hardware, "serial_number", hardware_info.serial_number);
    AppendOptionalString(hardware, "cpu_model", hardware_info.cpu_model);
    AppendOptionalInt(hardware, "cpu_cores", hardware_info.cpu_cores);
    AppendOptionalInt(hardware, "memory_mb", hardware_info.memory_mb);
    AppendOptionalInt(hardware, "storage_gb", hardware_info.storage_gb, false);
    hardware
             << '}';

    std::ostringstream os;
    os << '{'
       << "\"tenant_id\":\"" << JsonEscape(config.tenant_id) << "\","
       << "\"asset_id\":\"" << JsonEscape(config.asset_id) << "\","
       << "\"collected_at\":\"" << collected_at << "\","
       << "\"hostname\":\"" << JsonEscape(config.hostname) << "\","
       ;
    AppendString(os, "os_name", os_info.os_name);
    AppendString(os, "os_version", os_info.os_version);
    AppendOptionalString(os, "kernel_version", os_info.kernel_version);
    AppendOptionalString(os, "architecture", os_info.architecture);
    os << "\"install_date\":null";
    os << '}';

    std::ostringstream software;
    software << '{'
             << "\"tenant_id\":\"" << JsonEscape(config.tenant_id) << "\","
             << "\"asset_id\":\"" << JsonEscape(config.asset_id) << "\","
             << "\"collected_at\":\"" << collected_at << "\","
             << "\"hostname\":\"" << JsonEscape(config.hostname) << "\","
             << "\"items\":[";
    for (size_t i = 0; i < software_items.size(); ++i) {
        const auto& item = software_items[i];
        software << '{';
        AppendString(software, "name", item.name);
        AppendOptionalString(software, "vendor", item.vendor, true);
        AppendOptionalString(software, "version", item.version, true);
        AppendOptionalString(software, "install_date", item.install_date, true);
        AppendOptionalString(software, "source", item.source, false);
        software << '}';
        if (i + 1 < software_items.size()) {
            software << ',';
        }
    }
    software << "]"
             << '}';

    std::ostringstream users;
    users << '{'
          << "\"tenant_id\":\"" << JsonEscape(config.tenant_id) << "\","
          << "\"asset_id\":\"" << JsonEscape(config.asset_id) << "\","
          << "\"collected_at\":\"" << collected_at << "\","
          << "\"hostname\":\"" << JsonEscape(config.hostname) << "\","
          << "\"users\":[";
    for (size_t i = 0; i < local_users.size(); ++i) {
        const auto& user = local_users[i];
        users << '{';
        AppendString(users, "username", user.username);
        AppendOptionalString(users, "display_name", user.display_name, true);
        AppendOptionalString(users, "uid", user.uid, true);
        users << "\"is_admin\":" << (user.is_admin ? "true" : "false") << ',';
        users << "\"last_login_at\":null";
        users << '}';
        if (i + 1 < local_users.size()) {
            users << ',';
        }
    }
    users << "]"
          << '}';

    std::ostringstream groups;
    groups << '{'
           << "\"tenant_id\":\"" << JsonEscape(config.tenant_id) << "\","
           << "\"asset_id\":\"" << JsonEscape(config.asset_id) << "\","
           << "\"collected_at\":\"" << collected_at << "\","
           << "\"hostname\":\"" << JsonEscape(config.hostname) << "\","
           << "\"groups\":[";
    for (size_t i = 0; i < local_groups.size(); ++i) {
        const auto& group = local_groups[i];
        groups << '{';
        AppendString(groups, "name", group.name);
        AppendOptionalString(groups, "gid", group.gid, true);
        groups << "\"members\":[";
        for (size_t j = 0; j < group.members.size(); ++j) {
            groups << "\"" << JsonEscape(group.members[j]) << "\"";
            if (j + 1 < group.members.size()) {
                groups << ',';
            }
        }
        groups << "]";
        groups << '}';
        if (i + 1 < local_groups.size()) {
            groups << ',';
        }
    }
    groups << "]"
           << '}';

    const char* queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR");
    std::string queue_path = queue_dir ? queue_dir : "uplink_queue";
    bool hardware_ok = EnqueueUplinkInventoryPayload(queue_path, "hardware", "/hardware", hardware.str());
    bool os_ok = EnqueueUplinkInventoryPayload(queue_path, "os", "/os", os.str());
    bool software_ok = EnqueueUplinkInventoryPayload(queue_path, "software", "/software", software.str());
    bool users_ok = EnqueueUplinkInventoryPayload(queue_path, "users", "/users", users.str());
    bool groups_ok = EnqueueUplinkInventoryPayload(queue_path, "groups", "/groups", groups.str());

    return hardware_ok && os_ok && software_ok && users_ok && groups_ok;
}

}  // namespace agent
