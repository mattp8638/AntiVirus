#pragma once

// edr.collectRegistryEvents: watches the registry's autostart locations (Run/RunOnce, services, Winlogon,
// AppInit, BootExecute, IFEO debuggers, per-user Run keys of signed-in users) with change notifications and
// reports what was added, changed or removed as registry.* telemetry (TargetObject/Details, as Sysmon does,
// so the cloud's persistence rules apply).

#include <windows.h>

#include <atomic>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "TelemetryRecord.h"

namespace antivirus::agent {

namespace registrywatch {

struct Change {
  std::wstring name;     // value name (or subkey name)
  std::wstring data;     // new data (empty when removed)
  std::wstring previous;  // old data (empty when added)
  enum class Kind { Added, Modified, Removed } kind{Kind::Added};
};

// Differences between two snapshots (name -> data).
inline std::vector<Change> Diff(const std::map<std::wstring, std::wstring>& before,
                                const std::map<std::wstring, std::wstring>& after) {
  std::vector<Change> out;
  for (const auto& [name, data] : after) {
    const auto it = before.find(name);
    if (it == before.end()) {
      out.push_back({name, data, L"", Change::Kind::Added});
    } else if (it->second != data) {
      out.push_back({name, data, it->second, Change::Kind::Modified});
    }
  }
  for (const auto& [name, data] : before) {
    if (after.find(name) == after.end()) out.push_back({name, L"", data, Change::Kind::Removed});
  }
  return out;
}

}  // namespace registrywatch

class RegistryWatcher {
 public:
  RegistryWatcher() = default;
  ~RegistryWatcher();
  RegistryWatcher(const RegistryWatcher&) = delete;
  RegistryWatcher& operator=(const RegistryWatcher&) = delete;

  void Apply(bool enabled);
  void Stop();
  std::vector<TelemetryRecord> DrainTelemetry();

 private:
  enum class Kind { Values, Subkeys, Debuggers };
  struct Watch {
    HKEY root{nullptr};
    std::wstring label;  // "HKLM\\SOFTWARE\\..." as reported
    std::wstring path;
    Kind kind{Kind::Values};
    std::set<std::wstring> onlyValues;  // lower case; empty = all values
    HKEY key{nullptr};
    HANDLE event{nullptr};
    std::map<std::wstring, std::wstring> snapshot;
  };

  void Loop();
  void BuildWatches();
  void CloseWatches();
  bool Arm(Watch& watch);
  std::map<std::wstring, std::wstring> Snapshot(const Watch& watch) const;
  void Report(const Watch& watch, const std::vector<registrywatch::Change>& changes);
  std::vector<std::wstring> LoadedUserHives() const;

  std::mutex mutex_;
  bool enabled_{false};
  std::vector<TelemetryRecord> telemetry_;
  std::vector<Watch> watches_;
  std::vector<std::wstring> hives_;
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

}  // namespace antivirus::agent
