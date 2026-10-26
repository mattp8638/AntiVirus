#pragma once

#include <filesystem>
#include <vector>

#include "TelemetryRecord.h"

namespace antivirus::agent {

class TelemetryQueueStore {
 public:
  TelemetryQueueStore(std::filesystem::path databasePath, std::filesystem::path legacyQueueFilePath = {});

  std::vector<TelemetryRecord> LoadPending() const;
  // Replaces the whole queue. Only safe for single-writer migrations; use Append/Remove otherwise.
  void SavePending(const std::vector<TelemetryRecord>& events) const;
  void Append(const std::vector<TelemetryRecord>& events) const;
  void Remove(const std::vector<std::wstring>& eventIds) const;
  std::size_t Trim(std::size_t keepNewest) const;

 private:
  std::filesystem::path databasePath_;
  std::filesystem::path legacyQueueFilePath_;
};

}  // namespace antivirus::agent
