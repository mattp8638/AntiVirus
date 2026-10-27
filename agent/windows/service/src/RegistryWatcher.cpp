#include "RegistryWatcher.h"

#include <algorithm>
#include <chrono>
#include <cwctype>

#include "StringUtils.h"

namespace antivirus::agent {

namespace {

std::wstring J(const std::wstring& value) { return L"\"" + Utf8ToWide(EscapeJsonString(value)) + L"\""; }

std::wstring Lower(std::wstring value) {
  for (auto& c : value) c = static_cast<wchar_t>(std::towlower(c));
  return value;
}

std::wstring DataToString(const DWORD type, const BYTE* data, const DWORD size) {
  if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
    std::wstring text(reinterpret_cast<const wchar_t*>(data), size / sizeof(wchar_t));
    while (!text.empty() && text.back() == L'\0') text.pop_back();
    std::replace(text.begin(), text.end(), L'\0', L' ');  // REG_MULTI_SZ entries
    return text;
  }
  if (type == REG_DWORD && size >= 4) {
    DWORD value = 0;
    memcpy(&value, data, 4);
    return std::to_wstring(value);
  }
  if (type == REG_QWORD && size >= 8) {
    unsigned long long value = 0;
    memcpy(&value, data, 8);
    return std::to_wstring(value);
  }
  return L"(" + std::to_wstring(size) + L" bytes)";
}

std::map<std::wstring, std::wstring> ReadValues(HKEY key, const std::set<std::wstring>& only) {
  std::map<std::wstring, std::wstring> out;
  std::vector<wchar_t> name(16384);
  std::vector<BYTE> data(64 * 1024);
  for (DWORD index = 0; index < 4096; ++index) {
    DWORD nameLength = static_cast<DWORD>(name.size());
    DWORD dataLength = static_cast<DWORD>(data.size());
    DWORD type = 0;
    const auto status = RegEnumValueW(key, index, name.data(), &nameLength, nullptr, &type, data.data(), &dataLength);
    if (status == ERROR_NO_MORE_ITEMS) break;
    if (status != ERROR_SUCCESS) continue;
    std::wstring valueName(name.data(), nameLength);
    if (!only.empty() && only.count(Lower(valueName)) == 0) continue;
    out[valueName.empty() ? L"(Default)" : valueName] = DataToString(type, data.data(), dataLength).substr(0, 2048);
  }
  return out;
}

std::vector<std::wstring> SubkeyNames(HKEY key) {
  std::vector<std::wstring> out;
  wchar_t name[256];
  for (DWORD index = 0; index < 20000; ++index) {
    DWORD length = 256;
    if (RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
    out.emplace_back(name, length);
  }
  return out;
}

}  // namespace

RegistryWatcher::~RegistryWatcher() { Stop(); }

void RegistryWatcher::Apply(const bool enabled) {
  {
    const std::scoped_lock lock(mutex_);
    enabled_ = enabled;
  }
  if (enabled && !thread_.joinable()) {
    stop_ = false;
    thread_ = std::thread([this] { Loop(); });
  } else if (!enabled && thread_.joinable()) {
    Stop();
  }
}

void RegistryWatcher::Stop() {
  stop_ = true;
  if (thread_.joinable()) thread_.join();
}

std::vector<TelemetryRecord> RegistryWatcher::DrainTelemetry() {
  const std::scoped_lock lock(mutex_);
  auto out = std::move(telemetry_);
  telemetry_.clear();
  return out;
}

std::vector<std::wstring> RegistryWatcher::LoadedUserHives() const {
  std::vector<std::wstring> out;
  for (const auto& name : SubkeyNames(HKEY_USERS)) {
    if ((name.rfind(L"S-1-5-21-", 0) == 0 || name.rfind(L"S-1-12-1-", 0) == 0) && name.find(L"_Classes") == std::wstring::npos) {
      out.push_back(name);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

void RegistryWatcher::BuildWatches() {
  CloseWatches();
  auto add = [this](HKEY root, const std::wstring& rootLabel, const std::wstring& path, Kind kind,
                    std::set<std::wstring> only = {}) {
    Watch watch;
    watch.root = root;
    watch.label = rootLabel + L"\\" + path;
    watch.path = path;
    watch.kind = kind;
    watch.onlyValues = std::move(only);
    watches_.push_back(std::move(watch));
  };
  const std::wstring run = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
  add(HKEY_LOCAL_MACHINE, L"HKLM", run, Kind::Values);
  add(HKEY_LOCAL_MACHINE, L"HKLM", run + L"Once", Kind::Values);
  add(HKEY_LOCAL_MACHINE, L"HKLM", L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", Kind::Values);
  add(HKEY_LOCAL_MACHINE, L"HKLM", L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", Kind::Values);
  add(HKEY_LOCAL_MACHINE, L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", Kind::Values);
  add(HKEY_LOCAL_MACHINE, L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", Kind::Values,
      {L"shell", L"userinit", L"taskman", L"appsetup", L"vmapplet"});
  add(HKEY_LOCAL_MACHINE, L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", Kind::Values,
      {L"appinit_dlls", L"loadappinit_dlls", L"load", L"run"});
  add(HKEY_LOCAL_MACHINE, L"HKLM", L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", Kind::Values,
      {L"bootexecute", L"setupexecute", L"execute"});
  add(HKEY_LOCAL_MACHINE, L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
      Kind::Debuggers);
  add(HKEY_LOCAL_MACHINE, L"HKLM", L"SYSTEM\\CurrentControlSet\\Services", Kind::Subkeys);
  hives_ = LoadedUserHives();
  for (const auto& sid : hives_) {
    add(HKEY_USERS, L"HKU\\" + sid, sid + L"\\" + run, Kind::Values);
    add(HKEY_USERS, L"HKU\\" + sid, sid + L"\\" + run + L"Once", Kind::Values);
    add(HKEY_USERS, L"HKU\\" + sid, sid + L"\\Environment", Kind::Values, {L"userinitmprlogonscript"});
  }
  for (auto& watch : watches_) {
    if (RegOpenKeyExW(watch.root, watch.path.c_str(), 0, KEY_READ | KEY_NOTIFY, &watch.key) != ERROR_SUCCESS) {
      watch.key = nullptr;  // the key does not exist on this PC (e.g. Policies\Explorer\Run)
      continue;
    }
    watch.event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    watch.snapshot = Snapshot(watch);
    Arm(watch);
  }
  // Labels for per-user watches show HKU\<sid>\Software\... rather than repeating the SID.
  for (auto& watch : watches_) {
    if (watch.root == HKEY_USERS) watch.label = L"HKU\\" + watch.path;
  }
}

void RegistryWatcher::CloseWatches() {
  for (auto& watch : watches_) {
    if (watch.key) RegCloseKey(watch.key);
    if (watch.event) CloseHandle(watch.event);
  }
  watches_.clear();
}

bool RegistryWatcher::Arm(Watch& watch) {
  if (!watch.key || !watch.event) return false;
  const bool subtree = watch.kind == Kind::Debuggers;
  const DWORD filter = watch.kind == Kind::Subkeys ? REG_NOTIFY_CHANGE_NAME
                                                   : REG_NOTIFY_CHANGE_LAST_SET | (subtree ? REG_NOTIFY_CHANGE_NAME : 0);
  return RegNotifyChangeKeyValue(watch.key, subtree ? TRUE : FALSE, filter, watch.event, TRUE) == ERROR_SUCCESS;
}

std::map<std::wstring, std::wstring> RegistryWatcher::Snapshot(const Watch& watch) const {
  if (watch.kind == Kind::Values) return ReadValues(watch.key, watch.onlyValues);
  std::map<std::wstring, std::wstring> out;
  if (watch.kind == Kind::Subkeys) {
    for (const auto& name : SubkeyNames(watch.key)) out[name] = L"";
    return out;
  }
  // IFEO: only programs with a Debugger (or the silent-exit monitor flag) matter.
  for (const auto& name : SubkeyNames(watch.key)) {
    HKEY sub = nullptr;
    if (RegOpenKeyExW(watch.key, name.c_str(), 0, KEY_READ, &sub) != ERROR_SUCCESS) continue;
    for (const auto& [valueName, data] : ReadValues(sub, {L"debugger", L"globalflag"})) {
      if (Lower(valueName) == L"globalflag" && data != L"512") continue;  // 0x200: FLG_MONITOR_SILENT_PROCESS_EXIT
      out[name + L"\\" + valueName] = data;
    }
    RegCloseKey(sub);
  }
  return out;
}

void RegistryWatcher::Report(const Watch& watch, const std::vector<registrywatch::Change>& changes) {
  const std::scoped_lock lock(mutex_);
  for (const auto& change : changes) {
    if (telemetry_.size() >= 1000) break;
    std::wstring type, summary, payload;
    const auto target = watch.label + L"\\" + change.name;
    if (watch.kind == Kind::Subkeys) {
      if (change.kind != registrywatch::Change::Kind::Added) continue;  // removed services are not persistence
      std::wstring imagePath;
      HKEY sub = nullptr;
      if (RegOpenKeyExW(watch.key, change.name.c_str(), 0, KEY_READ, &sub) == ERROR_SUCCESS) {
        const auto values = ReadValues(sub, {L"imagepath"});
        if (!values.empty()) imagePath = values.begin()->second;
        RegCloseKey(sub);
      }
      type = L"registry.service.created";
      summary = L"New service installed: " + change.name;
      payload = L"{\"targetObject\":" + J(target) + L",\"details\":" + J(imagePath) + L",\"serviceName\":" + J(change.name) +
                L",\"change\":\"added\"}";
    } else if (change.kind == registrywatch::Change::Kind::Removed) {
      type = L"registry.value.deleted";
      summary = L"Autostart entry removed: " + change.name;
      payload = L"{\"targetObject\":" + J(target) + L",\"previous\":" + J(change.previous) + L",\"change\":\"removed\"}";
    } else {
      const bool added = change.kind == registrywatch::Change::Kind::Added;
      type = L"registry.value.set";
      summary = (added ? L"Autostart entry added: " : L"Autostart entry changed: ") + change.name;
      payload = L"{\"targetObject\":" + J(target) + L",\"details\":" + J(change.data) + L",\"previous\":" + J(change.previous) +
                L",\"change\":\"" + (added ? L"added" : L"modified") + L"\"}";
    }
    telemetry_.push_back({GenerateGuidString(), type, L"registry-watcher", summary, CurrentUtcTimestamp(), payload});
  }
}

void RegistryWatcher::Loop() {
  BuildWatches();
  auto lastHiveCheck = std::chrono::steady_clock::now();
  while (!stop_.load()) {
    std::vector<HANDLE> handles;
    std::vector<std::size_t> owners;
    for (std::size_t i = 0; i < watches_.size() && handles.size() < MAXIMUM_WAIT_OBJECTS; ++i) {
      if (watches_[i].event) {
        handles.push_back(watches_[i].event);
        owners.push_back(i);
      }
    }
    const auto signalled = handles.empty() ? WAIT_TIMEOUT
                                           : WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE, 1000);
    if (handles.empty()) std::this_thread::sleep_for(std::chrono::seconds(1));
    if (signalled >= WAIT_OBJECT_0 && signalled < WAIT_OBJECT_0 + handles.size()) {
      auto& watch = watches_[owners[signalled - WAIT_OBJECT_0]];
      // Changes often come in bursts (an installer writing several values): let them settle.
      std::this_thread::sleep_for(std::chrono::milliseconds(300));
      auto now = Snapshot(watch);
      const auto changes = registrywatch::Diff(watch.snapshot, now);
      watch.snapshot = std::move(now);
      Arm(watch);
      if (!changes.empty()) Report(watch, changes);
    }
    // Users signing in or out load and unload their registry hives.
    if (std::chrono::steady_clock::now() - lastHiveCheck > std::chrono::minutes(2)) {
      lastHiveCheck = std::chrono::steady_clock::now();
      if (LoadedUserHives() != hives_) BuildWatches();
    }
  }
  CloseWatches();
}

}  // namespace antivirus::agent
