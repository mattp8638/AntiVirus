// Tests ExtendedPolicy parsing against real Fenrir Cloud policy documents and the device-control planner.
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include "DeviceControl.h"
#include "ExtendedPolicy.h"
#include "FirewallPolicy.h"

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
  CHECK(!ExtendedPolicy::Parse("not json").present);
  std::printf(failures ? "%d failure(s)\n" : "all policy/device-control tests passed\n", failures);
  return failures ? 1 : 0;
}
