// fenrir-dnsproxy-smoke: exercises the Windows DNS proxy for real (Windows CI and manual checks).
//   serve <doh-url> <seconds> [closed]   run the proxy on 127.77.0.53:53, print stats when done
//   probe                                exit 0 when the proxy answers its health query
//   apply-rule | remove-rule             run the agent's NRPT scripts and print their JSON
#include <winsock2.h>
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include "DnsProxy.h"

using namespace antivirus::agent::dnsproxy;

namespace {

int RunScript(const std::string& script) {
  char temp[MAX_PATH]{};
  GetTempPathA(MAX_PATH, temp);
  const std::string path = std::string(temp) + "fenrir-dns-rule.ps1";
  std::ofstream(path, std::ios::binary | std::ios::trunc) << script;
  const std::string command = "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + path + "\"";
  FILE* pipe = _popen(command.c_str(), "r");
  if (!pipe) return 2;
  std::string output;
  char buffer[512];
  while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
  _pclose(pipe);
  std::remove(path.c_str());
  std::cout << output;
  return output.find("\"ok\":true") != std::string::npos ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage: fenrir-dnsproxy-smoke serve <doh-url> <seconds> [closed] | probe | apply-rule | remove-rule\n";
    return 2;
  }
  const std::string command = argv[1];
  if (command == "probe") return Probe(kListenAddress, 53, 2000) ? 0 : 1;
  if (command == "apply-rule") return RunScript(BuildApplyScript());
  if (command == "remove-rule") return RunScript(BuildRemoveScript());
  if (command == "serve" && argc >= 4) {
    Options options;
    const std::string url = argv[2];
    options.dohUrl.assign(url.begin(), url.end());
    options.failClosed = argc >= 5 && std::string(argv[4]) == "closed";
    options.localDomains = {"corp.fenrir-test"};
    options.onCachedBlock = [](const std::string& domain, const std::string& reason) {
      std::cout << "cached block: " << domain << " (" << reason << ")" << std::endl;
    };
    Proxy proxy(options);
    std::string error;
    if (!proxy.Start(&error)) {
      std::cerr << "start failed: " << error << std::endl;
      return 1;
    }
    std::cout << "ready" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(std::stoi(argv[3])));
    const auto s = proxy.Snapshot();
    proxy.Stop();
    std::cout << "{\"queries\":" << s.queries << ",\"cloud\":" << s.cloud << ",\"network\":" << s.network << ",\"cachedBlocks\":"
              << s.cachedBlocks << ",\"fallback\":" << s.fallback << ",\"refused\":" << s.refused << ",\"failures\":" << s.failures
              << "}" << std::endl;
    return 0;
  }
  std::cerr << "unknown command\n";
  return 2;
}
