#pragma once

// Policy firewall and network hardening for Windows (modules.firewall):
// Windows Firewall profiles and default actions, custom rules (group "Fenrir policy"),
// SMBv1 server off, and LLMNR / NetBIOS over TCP/IP off. Applied by a generated PowerShell
// script; building the script is pure so it can be unit tested anywhere.

#include <string>
#include <utility>
#include <vector>

namespace antivirus::agent::firewall {

struct Rule {
  std::string action;     // allow | block
  std::string direction;  // in | out
  std::string protocol;   // tcp | udp | any
  std::vector<std::pair<int, int>> ports;  // empty: any
  std::vector<std::string> remote;          // empty: any
};

struct Settings {
  bool present{false};  // false: the policy has no firewall section, so leave the host alone
  bool enabled{false};
  bool blockInbound{true};
  bool blockOutbound{false};
  bool blockSmbV1{false};
  bool blockLlmnrNetbios{false};
  std::vector<Rule> rules;
};

Settings Parse(const std::string& modulesJson);
bool ValidAddress(const std::string& value);
// installDirectory: every .exe in it is allowed outbound when outbound traffic is blocked.
std::string BuildScript(const Settings& settings, const std::string& installDirectoryUtf8);

}  // namespace antivirus::agent::firewall
