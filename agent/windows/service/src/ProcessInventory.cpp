#include "ProcessInventory.h"

#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>

namespace antivirus::agent {
namespace {

bool IsPrioritizedProcess(const std::wstring& imageName) {
  static const std::wstring priorities[] = {L"powershell.exe", L"pwsh.exe",   L"cmd.exe",      L"wscript.exe",
                                            L"cscript.exe",    L"mshta.exe",  L"rundll32.exe", L"regsvr32.exe"};

  for (const auto& candidate : priorities) {
    if (_wcsicmp(candidate.c_str(), imageName.c_str()) == 0) {
      return true;
    }
  }

  return false;
}

std::wstring QueryProcessImagePath(const DWORD pid) {
  if (pid == 0) {
    return {};
  }

  const HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return {};
  }

  std::wstring buffer(4096, L'\0');
  DWORD length = static_cast<DWORD>(buffer.size());
  if (QueryFullProcessImageNameW(processHandle, 0, buffer.data(), &length) == FALSE) {
    CloseHandle(processHandle);
    return {};
  }

  CloseHandle(processHandle);
  buffer.resize(length);
  return buffer;
}

}  // namespace

std::vector<ProcessObservation> CollectProcessInventory(std::size_t maxRecords) {
  std::vector<ProcessObservation> collected;

  const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return collected;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);

  if (Process32FirstW(snapshot, &entry) != FALSE) {
    do {
      const std::wstring imageName(entry.szExeFile);
      collected.push_back(ProcessObservation{
          .pid = entry.th32ProcessID,
          .parentPid = entry.th32ParentProcessID,
          .imageName = imageName,
          .imagePath = QueryProcessImagePath(entry.th32ProcessID),
          .prioritized = IsPrioritizedProcess(imageName)});
    } while (Process32NextW(snapshot, &entry) != FALSE);
  }

  CloseHandle(snapshot);

  std::sort(collected.begin(), collected.end(), [](const ProcessObservation& left, const ProcessObservation& right) {
    if (left.prioritized != right.prioritized) {
      return left.prioritized > right.prioritized;
    }

    return left.pid > right.pid;
  });

  if (maxRecords > 0 && collected.size() > maxRecords) {
    collected.resize(maxRecords);
  }

  return collected;
}

}  // namespace antivirus::agent
