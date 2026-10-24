#include <windows.h>

#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "../../../service/include/AgentConfig.h"
#include "../../../service/include/StringUtils.h"
#include "../../../sensor/etw/include/ProcessEtwSensor.h"

namespace antivirus::agent {
namespace {

struct Options {
  bool json{false};
  int waitSeconds{2};
  std::wstring commandLine{L"cmd.exe /c exit 0"};
};

Options ParseOptions(const int argc, wchar_t** argv) {
  Options options;

  for (int index = 1; index < argc; ++index) {
    const std::wstring argument(argv[index]);
    if (argument == L"--json") {
      options.json = true;
      continue;
    }

    if (argument == L"--seconds" && index + 1 < argc) {
      options.waitSeconds = std::max(1, _wtoi(argv[++index]));
      continue;
    }

    if (argument == L"--command" && index + 1 < argc) {
      options.commandLine = argv[++index];
      continue;
    }
  }

  return options;
}

bool SpawnProcess(const std::wstring& commandLine) {
  std::wstring mutableCommandLine = commandLine;
  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  PROCESS_INFORMATION processInformation{};

  if (CreateProcessW(nullptr, mutableCommandLine.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startupInfo,
                     &processInformation) == FALSE) {
    return false;
  }

  WaitForSingleObject(processInformation.hProcess, 10'000);
  CloseHandle(processInformation.hThread);
  CloseHandle(processInformation.hProcess);
  return true;
}

void PrintUsage() {
  std::wcout << L"Usage: antivirus-etwtestcli [--json] [--seconds N] [--command \"cmd.exe /c exit 0\"]"
             << std::endl;
}

int RunMain(const int argc, wchar_t** argv) {
  for (int index = 1; index < argc; ++index) {
    if (std::wstring(argv[index]) == L"--help") {
      PrintUsage();
      return 0;
    }
  }

  const auto options = ParseOptions(argc, argv);
  auto config = LoadAgentConfig();
  config.syncIterations = 1;

  ProcessEtwSensor sensor(config);
  sensor.Start();
  std::this_thread::sleep_for(std::chrono::milliseconds(750));

  if (!SpawnProcess(options.commandLine)) {
    std::wcerr << L"Unable to spawn test command: " << options.commandLine << std::endl;
    sensor.Stop();
    return 1;
  }

  std::this_thread::sleep_for(std::chrono::seconds(options.waitSeconds));
  sensor.Stop();

  const auto telemetry = sensor.DrainTelemetry();
  std::size_t startCount = 0;
  std::size_t exitCount = 0;
  std::size_t imageLoadCount = 0;

  for (const auto& record : telemetry) {
    if (record.eventType == L"process.started") {
      ++startCount;
    } else if (record.eventType == L"process.exited") {
      ++exitCount;
    } else if (record.eventType == L"image.loaded") {
      ++imageLoadCount;
    }
  }

  if (options.json) {
    std::wcout << L"{\"records\":" << telemetry.size() << L",\"processStarted\":" << startCount
               << L",\"processExited\":" << exitCount << L",\"imageLoaded\":" << imageLoadCount << L"}"
               << std::endl;
  } else {
    std::wcout << L"Captured " << telemetry.size() << L" ETW telemetry record(s)." << std::endl;
    for (const auto& record : telemetry) {
      std::wcout << L"- [" << record.eventType << L"] " << record.summary;
      if (!record.payloadJson.empty()) {
        std::wcout << L" " << record.payloadJson;
      }
      std::wcout << std::endl;
    }
  }

  return (startCount > 0 && exitCount > 0) ? 0 : 2;
}

}  // namespace

}  // namespace antivirus::agent

int wmain(const int argc, wchar_t** argv) {
  return antivirus::agent::RunMain(argc, argv);
}
