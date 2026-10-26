// Tests ExtendedPolicy parsing against real Fenrir Cloud policy documents and the device-control planner.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#include "DeviceControl.h"
#include "ExtendedPolicy.h"
#include "FirewallPolicy.h"
#include "LocalAdminRotation.h"
#include "RansomwareDetector.h"
#include "BruteForceTracker.h"

#include <random>

using namespace antivirus::agent;

static int failures = 0;
#define CHECK(cond)                                              \
  do {                                                           \
    if (!(cond)) {                                               \
      std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
      ++failures;                                                \
    }                                                            \
  } while (0)

static std::string Read(const char* path) {
  std::ifstream in(path);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

static bool HasOp(const devicecontrol::Plan& plan, const std::wstring& keySuffix, const std::wstring& name, bool remove,
                  unsigned long data) {
  for (const auto& op : plan.ops) {
    if (op.key.size() >= keySuffix.size() && op.key.compare(op.key.size() - keySuffix.size(), keySuffix.size(), keySuffix) == 0 &&
        op.valueName == name && op.remove == remove && (remove || op.data == data))
      return true;
  }
  return false;
}

int main(int argc, char** argv) {
  const std::string dir = argc > 1 ? argv[1] : "tests";
  {  // JSON parser edge cases
    CHECK(json::Parse(R"({"a":[1,2,{"b":"é😀"}],"c":true,"d":null})").has_value());
    CHECK(!json::Parse("{\"a\":}").has_value());
    CHECK(!json::Parse("{\"a\":1} trailing").has_value());
    CHECK(!json::Parse(std::string(100, '[') + std::string(100, ']')).has_value());  // depth limit
    const auto v = json::Parse(R"({"s":"café"})");
    CHECK(v && Utf8ToWideString(*v->Get("s")->String()) == L"café");
  }
  {  // Strict template from the cloud
    const auto policy = ExtendedPolicy::Parse(Read((dir + "/policy-strict.json").c_str()));
    CHECK(policy.present);
    CHECK(policy.mlSensitivity == L"aggressive");
    CHECK(policy.behavior.asr.at(L"blockLolbinAbuse") == behavior::RuleMode::Block);
    CHECK(policy.behavior.appControlMode == L"enforce-denylist");
    CHECK(policy.behavior.blockUnknownReputation);
    CHECK(policy.deviceControl.enabled && policy.deviceControl.usbStorage == L"read-only" && policy.deviceControl.encryptedUsbOnly);
    const auto plan = devicecontrol::BuildPlan(policy.deviceControl);
    CHECK(HasOp(plan, devicecontrol::kRemovableDisksClass, L"Deny_Write", false, 1));
    CHECK(HasOp(plan, devicecontrol::kRemovableDisksClass, L"Deny_Read", true, 0));
    CHECK(HasOp(plan, L"USBSTOR", L"Start", false, 3));
    CHECK(HasOp(plan, L"FVE", L"RDVDenyWriteAccess", false, 1));
    CHECK(!plan.notes.empty());  // bluetooth block is reported as not enforced
  }
  {  // Balanced template: no device restrictions, everything cleaned up
    const auto policy = ExtendedPolicy::Parse(Read((dir + "/policy-balanced.json").c_str()));
    CHECK(policy.behavior.asr.at(L"blockPsexecWmiProcessCreation") == behavior::RuleMode::Audit);
    const auto plan = devicecontrol::BuildPlan(policy.deviceControl);
    CHECK(HasOp(plan, devicecontrol::kRemovableDisksClass, L"Deny_Write", true, 0));
    CHECK(HasOp(plan, L"USBSTOR", L"Start", false, 3));
    CHECK(plan.notes.empty());
  }
  {  // Block mode disables the USB storage driver too
    DeviceControlSettings s;
    s.enabled = true;
    s.usbStorage = L"block";
    s.usbAllowedIds = {L"0781:5581"};
    const auto plan = devicecontrol::BuildPlan(s);
    CHECK(HasOp(plan, L"USBSTOR", L"Start", false, 4));
    CHECK(HasOp(plan, devicecontrol::kRemovableDisksClass, L"Deny_Read", false, 1));
    CHECK(plan.notes.size() == 1);  // per-device exceptions note
  }
  {  // Calendar scan schedules from the cloud
    const auto policy = ExtendedPolicy::Parse(
        R"({"antimalware":{"quickScanPlan":{"off":false,"days":[0,1,2,3,4],"minuteOfDay":540},)"
        R"("fullScanPlan":{"off":true,"days":[],"minuteOfDay":0}}})");
    CHECK(policy.quickScanPlan.present && !policy.quickScanPlan.off);
    CHECK(policy.quickScanPlan.days.size() == 5 && policy.quickScanPlan.minuteOfDay == 540);
    CHECK(policy.fullScanPlan.present && policy.fullScanPlan.off);
    CHECK(!ExtendedPolicy::Parse(R"({"antimalware":{}})").quickScanPlan.present);
    CHECK(!ExtendedPolicy::Parse(R"({"antimalware":{"quickScanPlan":{"days":[9]}}})").quickScanPlan.present);
  }
  {  // EDR collection switches drop routine telemetry only
    auto policy = ExtendedPolicy::Parse(R"({"edr":{"collectFileEvents":false,"collectScriptEvents":false},"experience":{"allowQuarantineRestore":true},"privilege":{"breakGlassAllowed":false}})");
    CHECK(!RoutineTelemetryAllowed(policy, L"file.modified", L"{}"));
    CHECK(RoutineTelemetryAllowed(policy, L"process.started", L"{}"));
    CHECK(!RoutineTelemetryAllowed(policy, L"amsi.scan", L"{\"blocked\":false}"));
    CHECK(RoutineTelemetryAllowed(policy, L"amsi.scan", L"{\"blocked\":true}"));
    CHECK(RoutineTelemetryAllowed(policy, L"scan.finding", L"{}"));
    CHECK(policy.allowQuarantineRestore && !policy.breakGlassAllowed);
    policy = ExtendedPolicy::Parse(R"({"edr":{"telemetryLevel":"minimal"}})");
    CHECK(!RoutineTelemetryAllowed(policy, L"process.started", L"{}"));
    CHECK(!RoutineTelemetryAllowed(policy, L"destination.observed", L"{}"));
    CHECK(RoutineTelemetryAllowed(policy, L"realtime.protection.action", L"{}"));
    CHECK(!policy.allowQuarantineRestore && policy.breakGlassAllowed);  // defaults
  }
  {  // Scan options
    const auto policy = ExtendedPolicy::Parse(R"({"antimalware":{"scanNetworkDrives":true,"scanCpuLimitPercent":2}})");
    CHECK(policy.scanNetworkDrives && policy.scanCpuLimitPercent == 5);
    CHECK(!ExtendedPolicy::Parse(R"({"antimalware":{}})").scanNetworkDrives);
    CHECK(ExtendedPolicy::Parse(R"({"antimalware":{}})").scanCpuLimitPercent == 100);
    CHECK(ScanThrottleRestMs(25, 100) == 300 && ScanThrottleRestMs(50, 40) == 40);
    CHECK(ScanThrottleRestMs(100, 1000) == 0 && ScanThrottleRestMs(0, 1000) == 0);
  }
  {  // Firewall and network hardening
    CHECK(firewall::ValidAddress("10.0.0.0/8") && firewall::ValidAddress("192.168.1.10") && firewall::ValidAddress("fd00::/8"));
    CHECK(!firewall::ValidAddress("10.0.0.256") && !firewall::ValidAddress("10.0.0.0/33") && !firewall::ValidAddress("a';calc;'"));
    CHECK(!firewall::ValidAddress("host.example.com") && !firewall::ValidAddress("::/129"));
    CHECK(!firewall::Parse(R"({"edr":{}})").present);
    const auto s = firewall::Parse(
        R"({"firewall":{"enabled":true,"defaultInbound":"block","defaultOutbound":"block","blockSmbV1":true,"blockLlmnrNetbios":false,)"
        R"("parsedRules":[{"action":"allow","direction":"in","protocol":"tcp","ports":[[3389,3389],[8000,8100]],"remote":["10.0.0.0/8"]},)"
        R"({"action":"block","direction":"out","protocol":"any","ports":[],"remote":["203.0.113.0/24"]},)"
        R"({"action":"allow","direction":"in","protocol":"any","ports":[[80,80]],"remote":[]},)"
        R"({"action":"allow","direction":"in","protocol":"tcp","ports":[],"remote":["1.2.3.4'; Remove-Item C:/ -Recurse; '"]}]}})");
    CHECK(s.present && s.enabled && s.blockInbound && s.blockOutbound && s.blockSmbV1 && !s.blockLlmnrNetbios);
    CHECK(s.rules.size() == 2);  // port on "any" and the injected address are dropped
    const auto script = firewall::BuildScript(s, "C:\\Program Files\\Fenrir's Agent");
    CHECK(script.find("-DefaultInboundAction Block -DefaultOutboundAction Block") != std::string::npos);
    CHECK(script.find("-Direction Inbound -Action Allow -Protocol TCP -LocalPort @('3389','8000-8100') -RemoteAddress @('10.0.0.0/8')") != std::string::npos);
    CHECK(script.find("-Direction Outbound -Action Block -Protocol Any -RemoteAddress @('203.0.113.0/24')") != std::string::npos);
    CHECK(script.find("Get-ChildItem -LiteralPath 'C:\\Program Files\\Fenrir''s Agent'") != std::string::npos);
    CHECK(script.find("SMB1 -Type DWord -Value 0") != std::string::npos);
    CHECK(script.find("NetbiosOptions -Type DWord -Value 0") != std::string::npos);  // undo path, marker-gated
    CHECK(script.find("Remove-Item C") == std::string::npos);
    auto off = s;
    off.enabled = false;
    off.blockLlmnrNetbios = true;
    const auto offScript = firewall::BuildScript(off, "C:\\Fenrir");
    CHECK(offScript.find("Set-NetFirewallProfile") == std::string::npos && offScript.find("New-NetFirewallRule") == std::string::npos);
    CHECK(offScript.find("Remove-NetFirewallRule") != std::string::npos);  // stale Fenrir rules still go
    CHECK(offScript.find("EnableMulticast -Type DWord -Value 0") != std::string::npos);
    CHECK(offScript.find("New-Item -Path $path -Force") != std::string::npos && offScript.find("Test-Path") != std::string::npos);
  }
  {  // Local admin passwords: length, every character class, and no repeats between calls
    const auto a = laps::GeneratePassword(24), b = laps::GeneratePassword(24);
    CHECK(a.size() == 24 && a != b);
    CHECK(a.find_first_of(L"ABCDEFGHJKLMNPQRSTUVWXYZ") != std::wstring::npos && a.find_first_of(L"abcdefghijkmnopqrstuvwxyz") != std::wstring::npos);
    CHECK(a.find_first_of(L"23456789") != std::wstring::npos && a.find_first_of(L"!#$%&*+-=?@_~") != std::wstring::npos);
    CHECK(a.find_first_of(L"O0Il1") == std::wstring::npos);
  }
  {  // Ransomware settings from the policy
    const auto policy = ExtendedPolicy::Parse(R"({"ransomware":{"mode":"block-and-rollback","massEncryptionFilesPerMinute":2,"protectedFolders":["D:\\Data"],"protectedFoldersMode":"block","allowedApps":["backup.exe"],"snapshotIntervalHours":200}})");
    CHECK(policy.ransomware.mode == L"block-and-rollback" && policy.ransomware.Blocks() && policy.ransomware.RollsBack());
    CHECK(policy.ransomware.filesPerMinute == 5);         // clamped to the schema minimum
    CHECK(policy.ransomware.snapshotIntervalHours == 72);  // clamped to the maximum
    CHECK(policy.ransomware.protectedFolders.size() == 1 && policy.ransomware.protectedFolders[0] == L"D:\\Data");
    CHECK(policy.ransomware.allowedApps.size() == 1 && policy.ransomware.protectedFoldersMode == L"block");
    const auto defaults = ExtendedPolicy::Parse(R"({"ransomware":{"mode":"bogus"}})");
    CHECK(defaults.ransomware.mode == L"block" && defaults.ransomware.protectedFolders.size() == 3 && !defaults.ransomware.RollsBack());
    CHECK(defaults.ransomware.protectedFoldersMode == L"audit" && defaults.ransomware.filesPerMinute == 40);
    const auto audit = ExtendedPolicy::Parse(R"({"ransomware":{"mode":"audit"}})");
    CHECK(!audit.ransomware.Blocks());
    CHECK(audit.ransomware.credentialProtection && audit.ransomware.officeExecutableContent == behavior::RuleMode::Off);
    const auto cred = ExtendedPolicy::Parse(R"({"edr":{"enabled":false,"credentialProtection":true},"attackSurface":{"blockOfficeExecutableContent":"block"}})");
    CHECK(!cred.ransomware.credentialProtection && cred.ransomware.officeExecutableContent == behavior::RuleMode::Block);
  }
  {  // Ransomware detector: entropy and format checks
    using namespace ransomware;
    std::mt19937 rng(7);
    std::vector<unsigned char> random(8192);
    for (auto& b : random) b = static_cast<unsigned char>(rng());
    CHECK(ShannonEntropy(random.data(), random.size()) > 7.9);
    CHECK(LooksEncrypted(random.data(), random.size()));
    std::vector<unsigned char> small(random.begin(), random.begin() + 600);
    CHECK(LooksEncrypted(small.data(), small.size()));  // the bar follows the sample size
    CHECK(!LooksEncrypted(random.data(), 100));          // too small to judge
    auto zip = random;
    zip[0] = 'P'; zip[1] = 'K'; zip[2] = 3; zip[3] = 4;
    CHECK(!LooksEncrypted(zip.data(), zip.size()));       // Office documents are zip files
    auto mp4 = random;
    std::memcpy(mp4.data() + 4, "ftyp", 4);
    CHECK(!LooksEncrypted(mp4.data(), mp4.size()));
    std::string text;
    while (text.size() < 8192) text += "Quarterly report: revenue grew in every region this year.\n";
    CHECK(!LooksEncrypted(reinterpret_cast<const unsigned char*>(text.data()), text.size()));
    CHECK(EncryptionConfirmed(8, 5) && !EncryptionConfirmed(8, 4) && EncryptionConfirmed(2, 2) && !EncryptionConfirmed(2, 1));
    CHECK(!EncryptionConfirmed(0, 0));
  }
  {  // Ransomware detector: folders, allow list, canaries, bursts
    using namespace ransomware;
    const auto expanded = ExpandProtectedFolder(L"%USERPROFILE%\\Documents\\", {L"C:\\Users\\alice", L"C:\\Users\\bob\\"});
    CHECK(expanded.size() == 2 && expanded[0] == L"C:\\Users\\alice\\Documents" && expanded[1] == L"C:\\Users\\bob\\Documents");
    CHECK(ExpandProtectedFolder(L"  D:\\Finance\\ ", {}).at(0) == L"D:\\Finance");
    CHECK(ExpandProtectedFolder(L"", {L"C:\\Users\\a"}).empty());
    CHECK(PathUnder(L"\\Device\\HarddiskVolume3\\Users\\A\\Documents\\x.docx", L"\\device\\harddiskvolume3\\users\\a\\documents"));
    CHECK(!PathUnder(L"\\Device\\HarddiskVolume3\\Users\\A\\DocumentsOld\\x.docx", L"\\device\\harddiskvolume3\\users\\a\\documents"));
    CHECK(PathUnder(L"C:\\x\\y", L"C:\\"));
    CHECK(AppAllowed(L"C:\\Program Files\\Backup\\backup.exe", {L"BACKUP.EXE"}));
    CHECK(AppAllowed(L"C:\\Program Files\\Backup\\agent.exe", {L"c:\\program files\\backup\\"}));
    CHECK(AppAllowed(L"C:\\Tools\\sync.exe", {L"C:\\Tools\\sync.exe"}));
    CHECK(!AppAllowed(L"C:\\Tools\\evil.exe", {L"C:\\Tools\\sync.exe", L"sync.exe"}));

    const std::wstring docs = L"\\Device\\HarddiskVolume3\\Users\\alice\\Documents";
    const std::wstring share = L"\\Device\\HarddiskVolume4\\Shares\\Finance";
    DetectorConfig config;
    config.roots = {docs};
    config.shareRoots = {share};
    config.canaries = {docs + L"\\$fenrir-canary-budget-2024.docx"};
    config.filesPerMinute = 10;
    config.protectedFoldersWatch = true;
    config.allowedApps = {L"backup.exe"};
    config.selfPid = 99;
    Detector detector;
    detector.Configure(config);
    const std::wstring evil = L"C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe";

    // Canary: reported once a minute, never for the agent itself.
    auto obs = detector.OnWrite(500, evil, docs + L"\\$FENRIR-CANARY-BUDGET-2024.DOCX", 1000);
    CHECK(obs.size() == 1 && obs[0].kind == ObservationKind::Canary && obs[0].pid == 500);
    CHECK(detector.OnWrite(500, evil, docs + L"\\$fenrir-canary-budget-2024.docx", 2000).empty());
    CHECK(detector.OnWrite(99, evil, docs + L"\\$fenrir-canary-budget-2024.docx", 70000).empty());

    // Outside the protected folders: ignored.
    CHECK(detector.OnWrite(500, evil, L"\\Device\\HarddiskVolume3\\Temp\\a.txt", 3000).empty());

    // First write into a protected folder is reported once (protected folders in audit/block).
    obs = detector.OnWrite(600, evil, docs + L"\\a.docx", 10000);
    CHECK(obs.size() == 1 && obs[0].kind == ObservationKind::ProtectedFolderWrite);
    // Same file again does not count twice; nine more distinct files trip the burst at ten.
    CHECK(detector.OnWrite(600, evil, docs + L"\\a.docx", 10001).empty());
    for (int i = 0; i < 8; ++i) CHECK(detector.OnWrite(600, evil, docs + L"\\f" + std::to_wstring(i) + L".docx", 10010 + i).empty());
    obs = detector.OnWrite(600, evil, docs + L"\\sub\\last.xlsx", 10100);
    CHECK(obs.size() == 1 && obs[0].kind == ObservationKind::MassChange && obs[0].count == 10 && obs[0].paths.size() == 10);
    CHECK(obs.size() == 1 && obs[0].paths.back() == docs + L"\\sub\\last.xlsx");  // original case kept for restores
    // No repeat inside the same minute.
    CHECK(detector.OnWrite(600, evil, docs + L"\\g.docx", 10200).empty());

    // Writes spread out over more than a minute never add up.
    for (int i = 0; i < 30; ++i) {
      const auto o = detector.OnWrite(700, L"C:\\Apps\\slow.exe", docs + L"\\s" + std::to_wstring(i), 100000 + i * 7000);
      for (const auto& x : o) CHECK(x.kind != ObservationKind::MassChange);
    }

    // Allowed apps are never counted or reported.
    for (int i = 0; i < 20; ++i) CHECK(detector.OnWrite(800, L"D:\\Backup\\Backup.exe", docs + L"\\b" + std::to_wstring(i), 200000 + i).empty());

    // A reused process id with a different image starts afresh.
    for (int i = 0; i < 9; ++i) detector.OnWrite(900, L"C:\\a.exe", docs + L"\\r" + std::to_wstring(i), 300000 + i);
    obs = detector.OnWrite(900, L"C:\\b.exe", docs + L"\\r9", 300010);
    CHECK(obs.size() == 1 && obs[0].kind == ObservationKind::ProtectedFolderWrite);

    // SMB clients (System): only on shares or protected folders, flagged as remote, no folder report.
    for (int i = 0; i < 9; ++i) CHECK(detector.OnWrite(kSystemPid, L"System", share + L"\\q" + std::to_wstring(i), 400000 + i).empty());
    obs = detector.OnWrite(kSystemPid, L"System", share + L"\\q9", 400020);
    CHECK(obs.size() == 1 && obs[0].kind == ObservationKind::MassChange && obs[0].remote);
    CHECK(detector.OnWrite(kSystemPid, L"System", L"\\Device\\HarddiskVolume3\\Windows\\x.log", 400030).empty());
    // A share written by a local program is not watched (only protected folders are).
    CHECK(detector.OnWrite(1000, evil, share + L"\\local.txt", 400040).empty());

    // With network protection off (no share roots), System writes are ignored everywhere.
    config.shareRoots.clear();
    config.protectedFoldersWatch = false;
    detector.Configure(config);
    for (int i = 0; i < 12; ++i) CHECK(detector.OnWrite(kSystemPid, L"System", docs + L"\\n" + std::to_wstring(i), 500000 + i).empty());
    CHECK(detector.Watches(L"\\device\\harddiskvolume3\\users\\alice\\documents\\x"));
    CHECK(!detector.Watches(L"\\device\\harddiskvolume4\\shares\\finance\\x"));
  }
  {  // Brute-force blocking
    using namespace bruteforce;
    CHECK(NormaliseRemoteAddress(L"203.0.113.9") == L"203.0.113.9");
    CHECK(NormaliseRemoteAddress(L"::ffff:198.51.100.7") == L"198.51.100.7");
    CHECK(NormaliseRemoteAddress(L"2001:DB8::1") == L"2001:db8::1");
    CHECK(NormaliseRemoteAddress(L"-").empty() && NormaliseRemoteAddress(L"").empty() && NormaliseRemoteAddress(L"127.0.0.1").empty());
    CHECK(NormaliseRemoteAddress(L"::1").empty() && NormaliseRemoteAddress(L"1.2.3.256").empty() && NormaliseRemoteAddress(L"1.2.3").empty());
    CHECK(NormaliseRemoteAddress(L"1.2.3.4 dir=out").empty());  // nothing but an address can reach the firewall command
    Tracker tracker;
    const unsigned long long t0 = 1'000'000;
    for (int i = 0; i < kThreshold - 1; ++i) CHECK(!tracker.OnFailure(L"203.0.113.9", L"administrator", t0 + i));
    auto block = tracker.OnFailure(L"203.0.113.9", L"admin", t0 + 20);
    CHECK(block && block->address == L"203.0.113.9" && block->until == t0 + 20 + kBaseBlockSeconds && block->strikes == 1);
    CHECK(block && block->failures == kThreshold && block->accounts.size() == 2);
    CHECK(tracker.Blocked(L"203.0.113.9") && !tracker.OnFailure(L"203.0.113.9", L"x", t0 + 30));  // already blocked
    // Failures spread over more than the window never add up.
    for (int i = 0; i < 30; ++i) CHECK(!tracker.OnFailure(L"198.51.100.1", L"bob", t0 + i * 120));
    // Loopback and "-" (no address in the event) are ignored.
    for (int i = 0; i < 30; ++i) CHECK(!tracker.OnFailure(L"-", L"bob", t0 + i));
    CHECK(tracker.Expire(t0 + 100).empty());
    auto expired = tracker.Expire(t0 + 20 + kBaseBlockSeconds);
    CHECK(expired.size() == 1 && expired[0] == L"203.0.113.9" && !tracker.Blocked(L"203.0.113.9"));
    // A repeat offender is blocked four times longer.
    const auto t1 = t0 + 2 * kBaseBlockSeconds;
    std::optional<Block> again;
    for (int i = 0; i < kThreshold; ++i) again = tracker.OnFailure(L"203.0.113.9", L"admin", t1 + i);
    CHECK(again && again->strikes == 2 && again->until == t1 + kThreshold - 1 + 4 * kBaseBlockSeconds);
    // Restored blocks (after a restart) are active and cleared together.
    Tracker restored;
    restored.Restore({L"2001:db8::5", t0 + 500, 1, 0, {}});
    CHECK(restored.Blocked(L"2001:db8::5") && restored.Clear().size() == 1 && restored.Blocks().empty());
    CHECK(ExtendedPolicy::Parse(R"({"firewall":{"bruteForceProtection":false}})").bruteForceProtection == false);
    CHECK(ExtendedPolicy::Parse(R"({"firewall":{}})").bruteForceProtection == true);
    const auto tamperDefault = ExtendedPolicy::Parse(R"({"tamper":{}})");
    CHECK(tamperDefault.tamperServiceLocked && tamperDefault.tamperUninstallToken);
    const auto tamperOff = ExtendedPolicy::Parse(R"({"tamper":{"enabled":false,"protectServiceAndFiles":true}})");
    CHECK(!tamperOff.tamperServiceLocked && !tamperOff.tamperUninstallToken);
    const auto tamperMixed = ExtendedPolicy::Parse(R"({"tamper":{"protectServiceAndFiles":false}})");
    CHECK(!tamperMixed.tamperServiceLocked && tamperMixed.tamperUninstallToken);
  }
  {  // Local admin removal plan
    using laps::AdminMember;
    std::vector<AdminMember> members = {
        {L"PC1\\Administrator", L"S-1-5-21-1-2-3-500", false, false, true},  // built-in, disabled: kept
        {L"CONTOSO\\Domain Admins", L"S-1-5-21-9-9-9-512", true, true, false},  // group: kept
        {L"PC1\\alice", L"S-1-5-21-1-2-3-1001", false, true, false},
        {L"CONTOSO\\bob", L"S-1-5-21-9-9-9-1105", false, true, false},
        {L"PC1\\FenrirBreakGlass", L"S-1-5-21-1-2-3-1002", false, false, false},
        {L"PC1\\itadmin", L"S-1-5-21-1-2-3-1003", false, true, false},
    };
    auto plan = laps::PlanAdminRemoval(members, {L"FenrirBreakGlass", L"itadmin"});
    CHECK(plan.size() == 2 && plan[0] == 2 && plan[1] == 3);
    plan = laps::PlanAdminRemoval(members, {L"contoso\\BOB", L"S-1-5-21-1-2-3-1001", L"fenrirbreakglass", L"itadmin"});
    CHECK(plan.empty());  // names with or without domain, and SIDs, case-insensitive
    // Never leave nobody: only a disabled built-in account would remain.
    std::vector<AdminMember> lonely = {{L"PC1\\Administrator", L"S-1-5-21-1-2-3-500", false, false, true},
                                       {L"PC1\\alice", L"S-1-5-21-1-2-3-1001", false, true, false}};
    CHECK(laps::PlanAdminRemoval(lonely, {}).empty());
    lonely[0].enabled = true;  // the built-in account is enabled (and managed by LAPS): alice can go
    CHECK(laps::PlanAdminRemoval(lonely, {}).size() == 1);
    CHECK(ExtendedPolicy::Parse(R"({"privilege":{"removeLocalAdmins":true}})").removeLocalAdmins == false);  // needs enabled
    CHECK(ExtendedPolicy::Parse(R"({"privilege":{"enabled":true,"removeLocalAdmins":true}})").removeLocalAdmins);
  }
  CHECK(!ExtendedPolicy::Parse("not json").present);
  std::printf(failures ? "%d failure(s)\n" : "all policy/device-control tests passed\n", failures);
  return failures ? 1 : 0;
}
