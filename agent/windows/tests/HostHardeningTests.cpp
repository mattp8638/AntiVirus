// Host hardening built into the policy script (FirewallPolicy): network attack protection, banking protection and
// peer caching, each restorable. Portable: g++ on Linux, or MinGW/MSVC.
#include <cstdio>
#include <fstream>
#include <string>

#include "FirewallPolicy.h"

using namespace antivirus::agent;

static int failures = 0;
#define CHECK(cond)                                                    \
  do {                                                                 \
    if (!(cond)) {                                                     \
      std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);       \
      ++failures;                                                      \
    }                                                                  \
  } while (0)

static bool Has(const std::string& s, const std::string& part) { return s.find(part) != std::string::npos; }

int main(int argc, char** argv) {
  {  // Everything on
    const auto s = firewall::Parse(
        R"({"firewall":{"enabled":false,"networkAttackProtection":true},"web":{"bankingProtection":true},"updates":{"peerCaching":true}})");
    CHECK(s.present && s.networkAttackProtection && s.hasWeb && s.bankingProtection && s.hasUpdates && s.peerCaching);
    const auto script = firewall::BuildScript(s, "C:\\Fenrir");
    CHECK(Has(script, "Set-Managed 'NetworkAttack' 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' 'DisableIPSourceRouting' 2"));
    CHECK(Has(script, "Set-Managed 'NetworkAttack' 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' 'DisableIPSourceRouting' 2"));
    CHECK(Has(script, "'EnableICMPRedirect' 0") && Has(script, "'PerformRouterDiscovery' 0"));
    CHECK(Has(script, "Set-Managed 'Banking' 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' 'PreventSmartScreenPromptOverride' 1"));
    CHECK(Has(script, "Set-Managed 'Banking' 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' 'ThirdPartyBlockingEnabled' 1"));
    CHECK(Has(script, "'DisableSafeBrowsingProceedAnyway' 1"));
    CHECK(Has(script, "'DODownloadMode' 1"));
    CHECK(!Has(script, "Restore-Managed 'NetworkAttack'") && !Has(script, "Restore-Managed 'Banking'"));
    // The firewall itself is not managed (enabled:false): no profile changes.
    CHECK(!Has(script, "Set-NetFirewallProfile"));
    if (argc > 1) std::ofstream(argv[1]) << script;  // for a PowerShell syntax check when pwsh is available
  }
  {  // Everything off: each managed value is put back as it was
    const auto s = firewall::Parse(
        R"({"firewall":{"enabled":false,"networkAttackProtection":false},"web":{"bankingProtection":false},"updates":{"peerCaching":false}})");
    const auto script = firewall::BuildScript(s, "C:\\Fenrir");
    CHECK(Has(script, "Restore-Managed 'NetworkAttack'") && Has(script, "Restore-Managed 'Banking'"));
    CHECK(Has(script, "'DODownloadMode' 0"));  // peer caching off is enforced: Microsoft only
    CHECK(!Has(script, "'DisableIPSourceRouting' 2") && !Has(script, "'ThirdPartyBlockingEnabled' 1"));
    // Restore puts back saved values, and removes values that were absent before Fenrir.
    CHECK(Has(script, "'<absent>'") && Has(script, "Remove-ItemProperty -LiteralPath $path -Name $name"));
    CHECK(Has(script, "PSChildName"));  // the provider's own properties are never restored as values
  }
  {  // A policy without a firewall section leaves the firewall and network stack alone
    const auto s = firewall::Parse(R"({"web":{"bankingProtection":true}})");
    CHECK(!s.present && s.hasWeb && !s.hasUpdates && s.AnythingToManage());
    const auto script = firewall::BuildScript(s, "C:\\Fenrir");
    CHECK(!Has(script, "Remove-NetFirewallRule") && !Has(script, "NetworkAttack") && !Has(script, "NetbiosOptions"));
    CHECK(!Has(script, "DODownloadMode"));  // no updates section: Delivery Optimization untouched
    CHECK(Has(script, "'Banking'"));
    CHECK(!firewall::Parse(R"({"edr":{}})").AnythingToManage());
  }
  if (failures == 0) std::printf("host hardening tests passed\n");
  return failures == 0 ? 0 : 1;
}
