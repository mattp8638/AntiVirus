#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace antivirus::agent {

struct ServiceObservation {
  std::wstring serviceName;
  std::wstring displayName;
  std::wstring binaryPath;
  std::wstring accountName;
  std::wstring startType;
  std::wstring currentState;
  DWORD processId{0};
  bool autoStart{false};
  bool running{false};
  bool userWritablePath{false};
  bool suspiciousName{false};
  bool risky{false};
};

std::vector<ServiceObservation> CollectServiceInventory(std::size_t maxRecords = 0);

}  // namespace antivirus::agent