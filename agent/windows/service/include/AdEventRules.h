#pragma once

// Portable (no Windows headers) part of Active Directory monitoring: parsing the XML Windows renders for a
// Security event and deciding which events leave a domain controller. Unit-tested natively.

#include <map>
#include <optional>
#include <string>

namespace antivirus::agent::admonitor {

struct SecurityEvent {
  unsigned long eventId{0};
  unsigned long long recordId{0};
  std::wstring timeCreated;
  std::wstring computer;
  std::map<std::wstring, std::wstring> data;
};

// Parses the XML Windows renders for one event (EvtRenderEventXml). Exposed for tests.
std::optional<SecurityEvent> ParseEventXml(const std::wstring& xml);

struct Classified {
  std::wstring eventType;  // ad.* telemetry type; empty = not worth sending
  std::wstring summary;
  std::wstring extraJson;  // extra JSON members (without braces), may be empty
};

// Decides whether an event leaves the DC and how it is labelled. Exposed for tests.
Classified Classify(const SecurityEvent& event);

// Well-known privileged group from a SID (domain RIDs 512/518/519/520/526/527, builtin 544/548/549/550/551).
std::wstring PrivilegedGroupName(const std::wstring& sid);

}  // namespace antivirus::agent::admonitor
