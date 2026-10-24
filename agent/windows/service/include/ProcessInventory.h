#pragma once

#include <cstdint>
#include <vector>

#include <windows.h>

#include <string>

namespace antivirus::agent {

struct ProcessObservation {
  DWORD pid{0};
  DWORD parentPid{0};
  std::wstring imageName;
  std::wstring imagePath;
  bool prioritized{false};
};

std::vector<ProcessObservation> CollectProcessInventory(std::size_t maxRecords = 0);

}  // namespace antivirus::agent
