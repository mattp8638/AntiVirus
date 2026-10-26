#include "TelemetryQueueStore.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

#include "RuntimeDatabase.h"
#include "StringUtils.h"

namespace antivirus::agent {

TelemetryQueueStore::TelemetryQueueStore(std::filesystem::path databasePath, std::filesystem::path legacyQueueFilePath)
    : databasePath_(std::move(databasePath)), legacyQueueFilePath_(std::move(legacyQueueFilePath)) {}

std::vector<TelemetryRecord> TelemetryQueueStore::LoadPending() const {
  RuntimeDatabase database(databasePath_);
  auto records = database.LoadTelemetryQueue();
  if (!records.empty() || legacyQueueFilePath_.empty() || !std::filesystem::exists(legacyQueueFilePath_)) {
    return records;
  }

  std::ifstream input(legacyQueueFilePath_);
  if (!input.is_open()) {
    return records;
  }

  std::string line;
  while (std::getline(input, line)) {
    const auto trimmed = TrimCopy(line);
    if (trimmed.empty()) {
      continue;
    }

    std::istringstream stream(trimmed);
    std::string eventId;
    std::string eventType;
    std::string source;
    std::string summary;
    std::string occurredAt;
    std::string payloadJson;

    if (!(stream >> std::quoted(eventId) >> std::quoted(eventType) >> std::quoted(source) >> std::quoted(summary) >>
          std::quoted(occurredAt) >> std::quoted(payloadJson))) {
      continue;
    }

    records.push_back(TelemetryRecord{
        .eventId = Utf8ToWide(eventId),
        .eventType = Utf8ToWide(eventType),
        .source = Utf8ToWide(source),
        .summary = Utf8ToWide(summary),
        .occurredAt = Utf8ToWide(occurredAt),
        .payloadJson = Utf8ToWide(payloadJson)});
  }

  if (!records.empty()) {
    database.ReplaceTelemetryQueue(records);
  }

  return records;
}

void TelemetryQueueStore::SavePending(const std::vector<TelemetryRecord>& events) const {
  RuntimeDatabase(databasePath_).ReplaceTelemetryQueue(events);
}

void TelemetryQueueStore::Append(const std::vector<TelemetryRecord>& events) const {
  RuntimeDatabase(databasePath_).AppendTelemetryQueue(events);
}

void TelemetryQueueStore::Remove(const std::vector<std::wstring>& eventIds) const {
  RuntimeDatabase(databasePath_).DeleteTelemetryEvents(eventIds);
}

std::size_t TelemetryQueueStore::Trim(const std::size_t keepNewest) const {
  return RuntimeDatabase(databasePath_).TrimTelemetryQueue(keepNewest);
}

}  // namespace antivirus::agent
