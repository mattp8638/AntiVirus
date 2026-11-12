#include "MemoryScanner.h"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <set>

#include "StringUtils.h"

namespace antivirus::agent::memscan {
namespace {

constexpr std::size_t kPage = 4096;
constexpr unsigned long long kMaxImageBytes = 32ULL * 1024 * 1024;
constexpr int kMaxImagesPerProcess = 8;

bool Executable(const DWORD protect) {
  if (protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
  const auto base = protect & 0xFF;
  return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

std::wstring ProcessImage(HANDLE process) {
  wchar_t buffer[MAX_PATH * 2]{};
  DWORD length = MAX_PATH * 2;
  return QueryFullProcessImageNameW(process, 0, buffer, &length) ? std::wstring(buffer, length) : std::wstring();
}

// Reads [base, base + size) page by page; pages that cannot be read stay zero.
std::vector<unsigned char> ReadImage(HANDLE process, const unsigned long long base, const unsigned long long size) {
  std::vector<unsigned char> out(static_cast<std::size_t>(size), 0);
  for (unsigned long long offset = 0; offset < size; offset += kPage) {
    SIZE_T read = 0;
    const auto chunk = static_cast<SIZE_T>(std::min<unsigned long long>(kPage, size - offset));
    ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + offset), out.data() + offset, chunk, &read);
  }
  return out;
}

}  // namespace

bool LooksLikePeImage(const unsigned char* data, const std::size_t size) {
  if (data == nullptr || size < 0x40 || data[0] != 'M' || data[1] != 'Z') return false;
  std::uint32_t lfanew = 0;
  std::memcpy(&lfanew, data + 0x3C, sizeof(lfanew));
  if (lfanew < 0x40 || lfanew > size - 24 || std::memcmp(data + lfanew, "PE\0\0", 4) != 0) return false;
  std::uint16_t machine = 0;
  std::memcpy(&machine, data + lfanew + 4, sizeof(machine));
  return machine == 0x014C || machine == 0x8664 || machine == 0xAA64;
}

Summary ScanProcesses(const PolicySnapshot& policy, const std::filesystem::path& workDir, const std::atomic<bool>& stop) {
  Summary summary;
  std::error_code ec;
  std::filesystem::create_directories(workDir, ec);
  const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return summary;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  const auto self = GetCurrentProcessId();
  for (BOOL more = Process32FirstW(snapshot, &entry); more && !stop.load(); more = Process32NextW(snapshot, &entry)) {
    const auto pid = entry.th32ProcessID;
    if (pid <= 4 || pid == self) continue;
    // Never read LSASS (reading its memory is what credential theft looks like, and Defender treats it so), nor the
    // core Windows processes or antivirus engines.
    static const wchar_t* kNeverRead[] = {L"lsass.exe", L"lsaiso.exe", L"csrss.exe", L"smss.exe", L"wininit.exe",
                                          L"winlogon.exe", L"services.exe", L"msmpeng.exe", L"nissrv.exe",
                                          L"securityhealthservice.exe", L"memcompression", L"registry", L"system"};
    bool sensitive = false;
    for (const auto* name : kNeverRead) sensitive = sensitive || _wcsicmp(entry.szExeFile, name) == 0;
    if (sensitive) continue;
    const auto process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == nullptr) {
      ++summary.skipped;
      continue;
    }
    ++summary.processes;
    const auto image = ProcessImage(process);
    std::set<unsigned long long> checkedAllocations;
    int imagesHere = 0;
    MEMORY_BASIC_INFORMATION info{};
    unsigned long long address = 0;
    while (imagesHere < kMaxImagesPerProcess && !stop.load() &&
           VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) == sizeof(info)) {
      const auto next = reinterpret_cast<unsigned long long>(info.BaseAddress) + info.RegionSize;
      if (next <= address) break;
      address = next;
      // Executable memory no file on disk backs (images Windows loaded are MEM_IMAGE and are left alone).
      if (info.State != MEM_COMMIT || info.Type == MEM_IMAGE || !Executable(info.Protect)) continue;
      const auto allocation = reinterpret_cast<unsigned long long>(info.AllocationBase);
      if (!checkedAllocations.insert(allocation).second) continue;
      unsigned char header[kPage]{};
      SIZE_T read = 0;
      if (!ReadProcessMemory(process, info.AllocationBase, header, sizeof(header), &read) || !LooksLikePeImage(header, read)) {
        continue;
      }
      ++imagesHere;
      ++summary.images;
      std::uint32_t lfanew = 0, sizeOfImage = 0;
      std::memcpy(&lfanew, header + 0x3C, sizeof(lfanew));
      if (lfanew + 0x50 + sizeof(sizeOfImage) <= read) std::memcpy(&sizeOfImage, header + lfanew + 0x50, sizeof(sizeOfImage));
      const auto size = std::clamp<unsigned long long>(sizeOfImage, kPage, kMaxImageBytes);
      Finding finding{.pid = pid, .image = image, .address = allocation, .size = size, .protection = info.Protect};
      const auto bytes = ReadImage(process, allocation, size);
      const auto dump = workDir / (L"mem-" + std::to_wstring(pid) + L"-" + std::to_wstring(allocation) + L".bin");
      {
        std::ofstream out(dump, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
      }
      try {
        finding.verdict = ScanFile(dump, policy);
      } catch (...) {
      }
      std::filesystem::remove(dump, ec);
      summary.findings.push_back(std::move(finding));
    }
    CloseHandle(process);
    Sleep(2);  // gentle: this runs alongside the user's work
  }
  CloseHandle(snapshot);
  return summary;
}

}  // namespace antivirus::agent::memscan
