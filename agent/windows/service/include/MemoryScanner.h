#pragma once

// edr.memoryScanning (advanced memory scanner): looks in running processes for Windows program images sitting in
// executable memory that no file backs, which is what reflective DLL injection, process hollowing and malware
// unpacking itself in memory leave behind. Each image found is copied to a protected work folder, scanned with the
// normal engine (signatures, rules, ML) and deleted. Just-in-time compiled code (browsers, .NET, Java) has no program
// header and is never reported.

#include <atomic>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "PolicySnapshot.h"
#include "ScanEngine.h"

namespace antivirus::agent::memscan {

struct Finding {
  unsigned long pid{0};
  std::wstring image;              // the process it was found in
  unsigned long long address{0};   // allocation base of the image in that process
  unsigned long long size{0};      // bytes copied
  unsigned long protection{0};     // protection of the executable region that led to it
  std::optional<ScanFinding> verdict;  // the copied image scanned with the engine (empty: engine found nothing)
};

struct Summary {
  int processes{0};  // processes examined
  int skipped{0};    // processes that could not be opened (protected processes, already exited)
  int images{0};     // unbacked program images found
  std::vector<Finding> findings;
};

// A Windows program header (MZ + PE signature at e_lfanew, a known machine type) at the start of data.
bool LooksLikePeImage(const unsigned char* data, std::size_t size);

// Scans every process it can open. workDir must be a folder only SYSTEM and administrators can write. Stops early
// when stop becomes true.
Summary ScanProcesses(const PolicySnapshot& policy, const std::filesystem::path& workDir, const std::atomic<bool>& stop);

}  // namespace antivirus::agent::memscan
