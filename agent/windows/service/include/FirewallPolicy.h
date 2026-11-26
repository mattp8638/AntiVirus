#pragma once

// Policy firewall and host hardening for Windows:
// modules.firewall: Windows Firewall profiles and default actions, custom rules (group "Fenrir policy"),
// SMBv1 server off, LLMNR / NetBIOS over TCP/IP off, and network attack protection (no source routing,
// ICMP redirects or router discovery).
// modules.web.bankingProtection: Edge and Chrome phishing warnings cannot be bypassed, and Chrome blocks
// third-party code injection.
// modules.updates.peerCaching: Windows Update shares downloads between devices on the LAN
// (Delivery Optimization) or not at all.
// Every registry value Fenrir sets has its previous value saved first, so turning a setting off restores it.
// Applied by a generated PowerShell script; building the script is pure so it can be unit tested anywhere.

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
  bool networkAttackProtection{false};
  std::vector<Rule> rules;
  // Other sections handled by the same script. "has": the section is in the policy, so manage it.
  bool hasWeb{false};
  bool bankingProtection{false};
  bool hasUpdates{false};
  bool peerCaching{true};

  bool AnythingToManage() const { return present || hasWeb || hasUpdates; }
};

Settings Parse(const std::string& modulesJson);
bool ValidAddress(const std::string& value);
// installDirectory: every .exe in it is allowed outbound when outbound traffic is blocked.
std::string BuildScript(const Settings& settings, const std::string& installDirectoryUtf8);

}  // namespace antivirus::agent::firewall
