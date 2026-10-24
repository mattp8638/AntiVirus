#include "EventEnvelope.h"
#include "StringUtils.h"  // Single canonical UTF-8 converter; prevents duplicate link symbols.

#include <Windows.h>

#include <iomanip>
#include <sstream>

namespace antivirus::agent {

std::string EventKindToString(EventKind kind) {
  switch (kind) {
    case EventKind::FileCreate:
      return "FileCreate";
    case EventKind::FileOpen:
      return "FileOpen";
    case EventKind::FileWrite:
      return "FileWrite";
    case EventKind::FileExecute:
      return "FileExecute";
    case EventKind::ProcessStart:
      return "ProcessStart";
    case EventKind::ScriptScan:
      return "ScriptScan";
    case EventKind::NetworkConnect:
      return "NetworkConnect";
    default:
      return "Unknown";
  }
}

std::string FormatTimestamp(std::chrono::system_clock::time_point tp) {
  auto time = std::chrono::system_clock::to_time_t(tp);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % 1000;
  std::tm tm{};
  gmtime_s(&tm, &time);
  
  std::stringstream ss;
  ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
  ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z";
  return ss.str();
}

std::string EventEnvelope::ToJson() const {
  std::stringstream ss;
  
  // Normalize the event type based on the schema
  std::string schemaEventType;
  if (kind == EventKind::ProcessStart) {
    schemaEventType = "ProcessStart";
  } else if (kind == EventKind::NetworkConnect) {
    schemaEventType = "NetworkConnect";
  } else if (kind == EventKind::FileWrite) {
    schemaEventType = "FileWrite";
  } else {
    schemaEventType = EventKindToString(kind);
  }

  ss << "{\n";
  ss << "  \"eventId\": \"" << WideToUtf8(correlationId) << "\",\n";
  ss << "  \"deviceId\": \"" << WideToUtf8(deviceId) << "\",\n";
  ss << "  \"timestamp\": \"" << FormatTimestamp(occurredAt) << "\",\n";
  ss << "  \"eventType\": \"" << schemaEventType << "\",\n";
  ss << "  \"payload\": {\n";
  ss << "    \"eventType\": \"" << schemaEventType << "\",\n";
  
  if (kind == EventKind::ProcessStart) {
    ss << "    \"processName\": \"" << WideToUtf8(process.imagePath) << "\",\n";
    ss << "    \"pid\": 0,\n"; // PID would need to be added to ProcessContext
    ss << "    \"commandLine\": \"" << WideToUtf8(process.commandLine) << "\"\n";
  } else if (kind == EventKind::NetworkConnect) {
    ss << "    \"processName\": \"" << WideToUtf8(process.imagePath) << "\",\n";
    ss << "    \"pid\": 0,\n";
    ss << "    \"destinationIp\": \"" << WideToUtf8(targetPath) << "\",\n";
    ss << "    \"destinationPort\": 0,\n";
    ss << "    \"protocol\": \"unknown\"\n";
  } else if (kind == EventKind::FileWrite) {
    ss << "    \"processName\": \"" << WideToUtf8(process.imagePath) << "\",\n";
    ss << "    \"pid\": 0,\n";
    ss << "    \"filePath\": \"" << WideToUtf8(targetPath) << "\"\n";
  } else {
    // Fallback for other events
    ss << "    \"targetPath\": \"" << WideToUtf8(targetPath) << "\"\n";
  }
  
  ss << "  }\n";
  ss << "}\n";
  
  return ss.str();
}

}  // namespace antivirus::agent
