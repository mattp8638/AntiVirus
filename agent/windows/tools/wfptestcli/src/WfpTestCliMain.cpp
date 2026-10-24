#include <winsock2.h>
#include <windows.h>

#include <iostream>
#include <string>

#include "../../../service/include/AgentConfig.h"
#include "../../../sensor/wfp/include/NetworkIsolationManager.h"

namespace antivirus::agent {
namespace {

struct Options {
  bool applyIsolation{false};
  bool json{false};
};

void PrintUsage() {
  std::wcout << L"Usage: antivirus-wfptestcli [--apply] [--json]" << std::endl;
}

Options ParseOptions(const int argc, wchar_t** argv) {
  Options options;

  for (int index = 1; index < argc; ++index) {
    const std::wstring argument(argv[index]);
    if (argument == L"--apply") {
      options.applyIsolation = true;
      continue;
    }

    if (argument == L"--json") {
      options.json = true;
      continue;
    }
  }

  return options;
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
  NetworkIsolationManager manager(config);
  manager.Start();

  std::wstring errorMessage;
  bool isolationApplied = false;
  if (options.applyIsolation) {
    isolationApplied = manager.ApplyIsolation(true, &errorMessage);
  }

  auto telemetry = manager.DrainTelemetry();
  if (options.applyIsolation && isolationApplied) {
    manager.ApplyIsolation(false, nullptr);
    const auto releaseTelemetry = manager.DrainTelemetry();
    telemetry.insert(telemetry.end(), releaseTelemetry.begin(), releaseTelemetry.end());
  }

  if (options.json) {
    std::wcout << L"{\"engineReady\":" << (manager.EngineReady() ? L"true" : L"false")
               << L",\"isolationApplied\":" << (isolationApplied ? L"true" : L"false")
               << L",\"telemetryRecords\":" << telemetry.size();
    if (!errorMessage.empty()) {
      std::wcout << L",\"errorMessage\":\"" << errorMessage << L"\"";
    }
    std::wcout << L"}" << std::endl;
  } else {
    std::wcout << L"WFP engine: " << (manager.EngineReady() ? L"ready" : L"unavailable") << std::endl;
    if (options.applyIsolation) {
      if (isolationApplied) {
        std::wcout << L"Isolation apply/release cycle completed." << std::endl;
      } else {
        std::wcout << L"Isolation apply failed: "
                   << (errorMessage.empty() ? std::wstring(L"(no error message)") : errorMessage) << std::endl;
      }
    }

    for (const auto& record : telemetry) {
      std::wcout << L"- [" << record.eventType << L"] " << record.summary;
      if (!record.payloadJson.empty()) {
        std::wcout << L" " << record.payloadJson;
      }
      std::wcout << std::endl;
    }
  }

  manager.Stop();
  return options.applyIsolation ? (isolationApplied ? 0 : 2) : (manager.EngineReady() ? 0 : 2);
}

}  // namespace
}  // namespace antivirus::agent

int wmain(const int argc, wchar_t** argv) {
  return antivirus::agent::RunMain(argc, argv);
}
