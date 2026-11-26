#include "FirewallPolicy.h"

#include <algorithm>
#include <cmath>
#include <regex>

#include "ExtendedPolicy.h"

namespace antivirus::agent::firewall {
namespace {

std::string Quote(const std::string& value) {
  std::string out = "'";
  for (const char c : value) {
    out += c;
    if (c == '\'') out += '\'';
  }
  return out + "'";
}

bool BoolOr(const json::Value* section, const char* key, bool fallback) {
  if (!section) return fallback;
  const auto* value = section->Get(key);
  if (!value) return fallback;
  return value->Bool().value_or(fallback);
}

std::string StringOr(const json::Value* section, const char* key, const std::string& fallback) {
  if (!section) return fallback;
  const auto* value = section->Get(key);
  if (!value) return fallback;
  return value->String().value_or(fallback);
}

bool ParseRule(const json::Value& value, Rule* rule) {
  if (!value.IsObject()) return false;
  rule->action = StringOr(&value, "action", "");
  rule->direction = StringOr(&value, "direction", "");
  rule->protocol = StringOr(&value, "protocol", "");
  if ((rule->action != "allow" && rule->action != "block") || (rule->direction != "in" && rule->direction != "out") ||
      (rule->protocol != "tcp" && rule->protocol != "udp" && rule->protocol != "any")) {
    return false;
  }
  if (const auto* ports = value.Get("ports")) {
    const auto* list = std::get_if<json::Array>(&ports->v);
    if (!list) return false;
    for (const auto& item : *list) {
      const auto* pair = std::get_if<json::Array>(&item.v);
      if (!pair || pair->size() != 2) return false;
      const auto lo = (*pair)[0].Number(), hi = (*pair)[1].Number();
      if (!lo || !hi || *lo != std::floor(*lo) || *hi != std::floor(*hi) || *lo < 1 || *hi > 65535 || *lo > *hi) return false;
      rule->ports.emplace_back(static_cast<int>(*lo), static_cast<int>(*hi));
    }
  }
  if (!rule->ports.empty() && rule->protocol == "any") return false;
  if (const auto* remote = value.Get("remote")) {
    const auto* list = std::get_if<json::Array>(&remote->v);
    if (!list) return false;
    for (const auto& item : *list) {
      const auto text = item.String();
      if (!text || !ValidAddress(*text)) return false;
      rule->remote.push_back(*text);
    }
  }
  return true;
}

}  // namespace

bool ValidAddress(const std::string& value) {
  static const std::regex v4(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/(\d{1,2}))?$)");
  static const std::regex v6(R"(^[0-9a-fA-F:.]{2,45}(/(\d{1,3}))?$)");
  std::smatch m;
  if (std::regex_match(value, m, v4)) {
    for (int i = 1; i <= 4; ++i) {
      if (std::stoi(m[i].str()) > 255) return false;
    }
    return !m[6].matched || std::stoi(m[6].str()) <= 32;
  }
  if (std::regex_match(value, m, v6)) {
    const auto colons = std::count(value.begin(), value.end(), ':');
    return colons >= 2 && (!m[2].matched || std::stoi(m[2].str()) <= 128);
  }
  return false;
}

Settings Parse(const std::string& modulesJson) {
  Settings settings;
  const auto root = json::Parse(modulesJson);
  if (!root || !root->IsObject()) return settings;
  if (const auto* web = root->Get("web"); web && web->IsObject()) {
    settings.hasWeb = true;
    settings.bankingProtection = BoolOr(web, "bankingProtection", false);
  }
  if (const auto* updates = root->Get("updates"); updates && updates->IsObject()) {
    settings.hasUpdates = true;
    settings.peerCaching = BoolOr(updates, "peerCaching", true);
  }
  const auto* fw = root->Get("firewall");
  if (!fw || !fw->IsObject()) return settings;
  settings.present = true;
  settings.enabled = BoolOr(fw, "enabled", false);
  settings.blockInbound = StringOr(fw, "defaultInbound", "block") == "block";
  settings.blockOutbound = StringOr(fw, "defaultOutbound", "allow") == "block";
  settings.blockSmbV1 = BoolOr(fw, "blockSmbV1", false);
  settings.blockLlmnrNetbios = BoolOr(fw, "blockLlmnrNetbios", false);
  settings.networkAttackProtection = BoolOr(fw, "networkAttackProtection", false);
  if (const auto* rules = fw->Get("parsedRules")) {
    if (const auto* list = std::get_if<json::Array>(&rules->v)) {
      for (const auto& item : *list) {
        Rule rule;
        if (ParseRule(item, &rule)) settings.rules.push_back(std::move(rule));
      }
    }
  }
  return settings;
}

std::string BuildScript(const Settings& s, const std::string& installDirectory) {
  std::string out =
      "$ErrorActionPreference = 'Stop'\n"
      "$warnings = New-Object System.Collections.Generic.List[string]\n"
      "$group = 'Fenrir policy'\n"
      "$marker = 'HKLM:\\SOFTWARE\\Fenrir\\PolicyHardening'\n"
      "function Ensure-Key($path) { if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null } }\n"
      // Set-Managed saves a value's previous state (once) under $marker\Saved\<tag> before setting it;
      // Restore-Managed puts every saved value of a tag back and forgets them.
      "function Set-Managed($tag, $path, $name, [int]$value) {\n"
      "  $saved = \"$marker\\Saved\\$tag\"; Ensure-Key $saved; $id = \"$path|$name\"\n"
      "  if ($null -eq (Get-ItemProperty -LiteralPath $saved -Name $id -ErrorAction SilentlyContinue)) {\n"
      "    $cur = (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name\n"
      "    $prev = if ($null -eq $cur) { '<absent>' } else { [string]$cur }\n"
      "    New-ItemProperty -LiteralPath $saved -Name $id -Value $prev -PropertyType String -Force | Out-Null }\n"
      "  Ensure-Key $path; New-ItemProperty -LiteralPath $path -Name $name -Value $value -PropertyType DWord -Force | Out-Null\n"
      "}\n"
      "function Restore-Managed($tag) {\n"
      "  $saved = \"$marker\\Saved\\$tag\"; if (-not (Test-Path -LiteralPath $saved)) { return }\n"
      "  foreach ($p in (Get-ItemProperty -LiteralPath $saved).PSObject.Properties) {\n"
      "    if (@('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -contains $p.Name) { continue }\n"
      "    $i = $p.Name.LastIndexOf('|'); $path = $p.Name.Substring(0, $i); $name = $p.Name.Substring($i + 1)\n"
      "    if ($p.Value -eq '<absent>') { Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue }\n"
      "    else { New-ItemProperty -LiteralPath $path -Name $name -Value ([int]$p.Value) -PropertyType DWord -Force | Out-Null } }\n"
      "  Remove-Item -LiteralPath $saved -Recurse -Force\n"
      "}\n";
  if (s.present) {
    out += "try { Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule } catch { $warnings.Add('old rules: ' + $_.Exception.Message) }\n";
  }
  if (s.present && s.enabled) {
    out += "try { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction " +
           std::string(s.blockInbound ? "Block" : "Allow") + " -DefaultOutboundAction " + (s.blockOutbound ? "Block" : "Allow") +
           " } catch { $warnings.Add('profiles: ' + $_.Exception.Message) }\n";
    if (s.blockOutbound && !installDirectory.empty()) {
      // The agent, its remote helper and updater must keep reaching Fenrir Cloud.
      out += "try { Get-ChildItem -LiteralPath " + Quote(installDirectory) +
             " -Filter *.exe | ForEach-Object { New-NetFirewallRule -Group $group -DisplayName ('Fenrir agent: ' + $_.Name) "
             "-Direction Outbound -Action Allow -Program $_.FullName | Out-Null } } catch { $warnings.Add('agent rule: ' + $_.Exception.Message) }\n";
    }
    int index = 0;
    for (const auto& rule : s.rules) {
      ++index;
      std::string cmd = "New-NetFirewallRule -Group $group -DisplayName " +
                        Quote("Fenrir policy " + std::to_string(index) + ": " + rule.action + " " + rule.direction + " " + rule.protocol) +
                        " -Direction " + (rule.direction == "in" ? "Inbound" : "Outbound") + " -Action " +
                        (rule.action == "allow" ? "Allow" : "Block") + " -Protocol " +
                        (rule.protocol == "tcp" ? "TCP" : rule.protocol == "udp" ? "UDP" : "Any");
      if (!rule.ports.empty()) {
        std::string list;
        for (const auto& [lo, hi] : rule.ports) {
          list += (list.empty() ? "" : ",") + Quote(lo == hi ? std::to_string(lo) : std::to_string(lo) + "-" + std::to_string(hi));
        }
        cmd += (rule.direction == "in" ? " -LocalPort @(" : " -RemotePort @(") + list + ")";
      }
      if (!rule.remote.empty()) {
        std::string list;
        for (const auto& address : rule.remote) list += (list.empty() ? "" : ",") + Quote(address);
        cmd += " -RemoteAddress @(" + list + ")";
      }
      out += "try { " + cmd + " | Out-Null } catch { $warnings.Add('rule " + std::to_string(index) + ": ' + $_.Exception.Message) }\n";
    }
  }
  if (s.present && s.blockSmbV1) {
    // Turning the setting off later stops enforcing it; Fenrir never switches SMBv1 back on.
    out +=
        "try { Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -Type DWord -Value 0\n"
        "  try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false | Out-Null } catch { }\n"
        "} catch { $warnings.Add('SMBv1: ' + $_.Exception.Message) }\n";
  }
  const std::string netbt = "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces'";
  const std::string dnsClient = "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient'";
  if (!s.present) {
    // No firewall section: leave Windows Firewall, SMBv1, LLMNR and the network stack as they are.
  } else if (s.blockLlmnrNetbios) {
    out += "try { Ensure-Key " + dnsClient + "; Set-ItemProperty -Path " + dnsClient +
           " -Name EnableMulticast -Type DWord -Value 0\n"
           "  Get-ChildItem -Path " + netbt +
           " | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Type DWord -Value 2 }\n"
           "  Ensure-Key 'HKLM:\\SOFTWARE\\Fenrir'; Ensure-Key $marker; Set-ItemProperty -Path $marker -Name LlmnrNetbios -Type DWord -Value 1\n"
           "} catch { $warnings.Add('LLMNR/NetBIOS: ' + $_.Exception.Message) }\n";
  } else {
    // Undo only what Fenrir set.
    out += "try { if ((Get-ItemProperty -Path $marker -ErrorAction SilentlyContinue).LlmnrNetbios -eq 1) {\n"
           "  Remove-ItemProperty -Path " + dnsClient + " -Name EnableMulticast -ErrorAction SilentlyContinue\n"
           "  Get-ChildItem -Path " + netbt +
           " | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Type DWord -Value 0 }\n"
           "  Remove-ItemProperty -Path $marker -Name LlmnrNetbios } } catch { $warnings.Add('LLMNR/NetBIOS undo: ' + $_.Exception.Message) }\n";
  }
  const std::string tcpip = "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters'";
  const std::string tcpip6 = "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters'";
  if (s.present && s.networkAttackProtection) {
    // No source-routed packets, ICMP redirects or router discovery: blocks traffic hijacking on the local network.
    out += "try { Set-Managed 'NetworkAttack' " + tcpip + " 'DisableIPSourceRouting' 2\n"
           "  Set-Managed 'NetworkAttack' " + tcpip6 + " 'DisableIPSourceRouting' 2\n"
           "  Set-Managed 'NetworkAttack' " + tcpip + " 'EnableICMPRedirect' 0\n"
           "  Set-Managed 'NetworkAttack' " + tcpip + " 'PerformRouterDiscovery' 0\n"
           "} catch { $warnings.Add('network attack protection: ' + $_.Exception.Message) }\n";
  } else if (s.present) {
    out += "try { Restore-Managed 'NetworkAttack' } catch { $warnings.Add('network attack protection undo: ' + $_.Exception.Message) }\n";
  }
  const std::string edge = "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge'";
  const std::string chrome = "'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome'";
  if (s.hasWeb && s.bankingProtection) {
    // Fake banking and payment sites: warnings cannot be clicked through. Banking trojans: Chrome refuses
    // third-party code injected into the browser.
    out += "try { Set-Managed 'Banking' " + edge + " 'SmartScreenEnabled' 1\n"
           "  Set-Managed 'Banking' " + edge + " 'SmartScreenPuaEnabled' 1\n"
           "  Set-Managed 'Banking' " + edge + " 'PreventSmartScreenPromptOverride' 1\n"
           "  Set-Managed 'Banking' " + edge + " 'PreventSmartScreenPromptOverrideForFiles' 1\n"
           "  Set-Managed 'Banking' " + edge + " 'TyposquattingCheckerEnabled' 1\n"
           "  Set-Managed 'Banking' " + chrome + " 'SafeBrowsingProtectionLevel' 1\n"
           "  Set-Managed 'Banking' " + chrome + " 'DisableSafeBrowsingProceedAnyway' 1\n"
           "  Set-Managed 'Banking' " + chrome + " 'ThirdPartyBlockingEnabled' 1\n"
           "} catch { $warnings.Add('banking protection: ' + $_.Exception.Message) }\n";
  } else if (s.hasWeb) {
    out += "try { Restore-Managed 'Banking' } catch { $warnings.Add('banking protection undo: ' + $_.Exception.Message) }\n";
  }
  if (s.hasUpdates) {
    // Delivery Optimization download mode: 1 = also from devices on the same LAN, 0 = from Microsoft only.
    out += "try { Set-Managed 'PeerCaching' 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization' 'DODownloadMode' " +
           std::string(s.peerCaching ? "1" : "0") + " } catch { $warnings.Add('peer caching: ' + $_.Exception.Message) }\n";
  }
  out += "@{ ok = ($warnings.Count -eq 0); warnings = @($warnings) } | ConvertTo-Json -Compress\n";
  return out;
}

}  // namespace antivirus::agent::firewall
