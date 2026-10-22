#include "BehaviorRules.h"

#include <algorithm>
#include <cwctype>
#include <initializer_list>
#include <string_view>

namespace antivirus::agent::behavior {
namespace {

std::wstring Lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  return value;
}

std::wstring BaseName(const std::wstring& path) {
  const auto pos = path.find_last_of(L"\\/");
  return Lower(pos == std::wstring::npos ? path : path.substr(pos + 1));
}

bool Contains(std::wstring_view haystack, std::wstring_view needle) { return haystack.find(needle) != std::wstring_view::npos; }

bool ContainsAny(std::wstring_view haystack, std::initializer_list<std::wstring_view> needles) {
  return std::any_of(needles.begin(), needles.end(), [&](std::wstring_view n) { return Contains(haystack, n); });
}

bool IsOneOf(const std::wstring& name, std::initializer_list<std::wstring_view> names) {
  return std::any_of(names.begin(), names.end(), [&](std::wstring_view n) { return name == n; });
}

bool UserWritablePath(const std::wstring& lowerPath) {
  return ContainsAny(lowerPath, {L"\\appdata\\", L"\\temp\\", L"\\downloads\\", L"\\users\\public\\", L"\\programdata\\",
                                 L"\\desktop\\", L"\\$recycle.bin\\"});
}

bool SystemPath(const std::wstring& lowerPath) {
  return lowerPath.rfind(L"c:\\windows\\", 0) == 0 || lowerPath.rfind(L"c:\\program files\\", 0) == 0 ||
         lowerPath.rfind(L"c:\\program files (x86)\\", 0) == 0;
}

// Collapses "-", "/", en/em dashes so "/enc" and "-enc" match the same patterns.
std::wstring NormalizeDashes(std::wstring cmd) {
  for (auto& c : cmd) {
    if (c == L'/' || c == 0x2013 || c == 0x2014 || c == 0x2015) c = L'-';
  }
  return cmd;
}

const std::initializer_list<std::wstring_view> kOffice = {L"winword.exe",  L"excel.exe",   L"powerpnt.exe", L"outlook.exe",
                                                          L"onenote.exe",  L"msaccess.exe", L"mspub.exe",    L"visio.exe",
                                                          L"winproj.exe"};
const std::initializer_list<std::wstring_view> kShells = {
    L"cmd.exe",      L"powershell.exe", L"pwsh.exe",     L"wscript.exe",  L"cscript.exe",     L"mshta.exe",
    L"rundll32.exe", L"regsvr32.exe",   L"certutil.exe", L"bitsadmin.exe", L"wmic.exe",       L"schtasks.exe",
    L"msbuild.exe",  L"installutil.exe", L"regasm.exe",  L"regsvcs.exe",  L"forfiles.exe",    L"hh.exe"};
const std::initializer_list<std::wstring_view> kScriptHosts = {L"wscript.exe", L"cscript.exe", L"mshta.exe",
                                                               L"powershell.exe", L"pwsh.exe"};
const std::initializer_list<std::wstring_view> kWebServers = {L"w3wp.exe",    L"httpd.exe", L"nginx.exe",  L"php-cgi.exe",
                                                              L"tomcat.exe",  L"tomcat9.exe", L"java.exe", L"node.exe",
                                                              L"umworkerprocess.exe"};
const std::initializer_list<std::wstring_view> kVulnerableDrivers = {
    L"rtcore64.sys", L"gdrv.sys", L"asrdrv101.sys", L"asrdrv102.sys", L"dbutil_2_3.sys", L"iqvw64e.sys", L"aswarpot.sys",
    L"mhyprot2.sys", L"kprocesshacker.sys", L"procexp152.sys", L"zamguard64.sys", L"truesight.sys", L"wnbios.sys"};

struct Ctx {
  std::wstring image, imageName, cmd, cmdDash, parent, parentName, parentCmd;
};

}  // namespace

RuleMode ParseRuleMode(const std::wstring& value) {
  const auto v = Lower(value);
  if (v == L"block") return RuleMode::Block;
  if (v == L"warn") return RuleMode::Warn;
  if (v == L"audit") return RuleMode::Audit;
  return RuleMode::Off;
}

const wchar_t* RuleModeName(RuleMode mode) {
  switch (mode) {
    case RuleMode::Block:
      return L"block";
    case RuleMode::Warn:
      return L"warn";
    case RuleMode::Audit:
      return L"audit";
    default:
      return L"off";
  }
}

RuleMode Strongest(const std::vector<Decision>& decisions) {
  RuleMode best = RuleMode::Off;
  for (const auto& d : decisions) {
    if (static_cast<int>(d.mode) > static_cast<int>(best)) best = d.mode;
  }
  return best;
}

std::vector<Decision> Evaluate(const ProcessFacts& p, const BehaviorPolicy& policy) {
  std::vector<Decision> out;
  Ctx c{Lower(p.imagePath), BaseName(p.imagePath), Lower(p.commandLine), NormalizeDashes(Lower(p.commandLine)),
        Lower(p.parentImagePath), BaseName(p.parentImagePath), Lower(p.parentCommandLine)};

  // Never act on our own processes or explicit exclusions.
  if (!policy.agentInstallRoot.empty() && c.image.rfind(Lower(policy.agentInstallRoot), 0) == 0) return out;
  for (const auto& name : policy.excludedProcesses) {
    if (c.imageName == Lower(name)) return out;
  }
  for (const auto& root : policy.excludedPathRoots) {
    if (!root.empty() && c.image.rfind(Lower(root), 0) == 0) return out;
  }

  auto asr = [&](const wchar_t* key, bool hit, const std::wstring& reason, const wchar_t* mitre) {
    if (!hit) return;
    const auto it = policy.asr.find(key);
    const auto mode = it == policy.asr.end() ? RuleMode::Off : it->second;
    if (mode != RuleMode::Off) out.push_back({std::wstring(L"attackSurface.") + key, mode, reason, mitre});
  };

  const bool officeParent = IsOneOf(c.parentName, kOffice);
  asr(L"blockOfficeChildProcesses", officeParent && (IsOneOf(c.imageName, kShells) || UserWritablePath(c.image)),
      c.parentName + L" started " + c.imageName, L"T1204.002");
  asr(L"blockAdobeReaderChildProcesses",
      IsOneOf(c.parentName, {L"acrord32.exe", L"acrobat.exe", L"foxitpdfreader.exe"}) && IsOneOf(c.imageName, kShells),
      c.parentName + L" started " + c.imageName, L"T1204.002");

  const bool encoded = (IsOneOf(c.imageName, {L"powershell.exe", L"pwsh.exe"}) &&
                        ContainsAny(c.cmdDash, {L" -enc ", L" -encodedcommand ", L" -ec ", L" -e "})) ||
                       ContainsAny(c.cmd, {L"frombase64string(", L"[char[]]", L"-join[char]", L"iex(", L"invoke-expression"}) ||
                       (IsOneOf(c.imageName, {L"wscript.exe", L"cscript.exe"}) && ContainsAny(c.cmd, {L".jse", L".vbe"}));
  asr(L"blockObfuscatedScripts", encoded, L"obfuscated or encoded script content", L"T1027");

  asr(L"blockScriptDownloadedPayloads",
      IsOneOf(c.parentName, kScriptHosts) && UserWritablePath(c.image) && c.imageName.size() > 4 &&
          c.imageName.substr(c.imageName.size() - 4) == L".exe",
      c.parentName + L" launched a payload from a user-writable folder", L"T1105");

  asr(L"blockEmailExecutables",
      ContainsAny(c.image, {L"\\content.outlook\\", L"\\inetcache\\content.mso\\"}) ||
          (IsOneOf(c.parentName, {L"outlook.exe", L"thunderbird.exe", L"olk.exe"}) && UserWritablePath(c.image)),
      L"executable launched from email", L"T1566.001");

  asr(L"blockCredentialStealingLsass",
      (Contains(c.cmd, L"lsass") && ContainsAny(c.cmd, {L"minidump", L"procdump", L"-ma ", L".dmp", L"sekurlsa"})) ||
          ContainsAny(c.cmd, {L"comsvcs.dll, minidump", L"comsvcs.dll,minidump", L"comsvcs.dll minidump"}),
      L"attempt to dump LSASS memory", L"T1003.001");

  asr(L"blockPsexecWmiProcessCreation",
      IsOneOf(c.parentName, {L"psexesvc.exe", L"wmiprvse.exe"}) &&
          !IsOneOf(c.imageName, {L"conhost.exe", L"wermgr.exe", L"werfault.exe"}),
      c.parentName + L" created " + c.imageName, L"T1047");

  asr(L"blockUntrustedUsbProcesses", p.onRemovableMedia && !(p.signatureVerified && !p.signer.empty()),
      L"unsigned program running from removable media", L"T1091");

  asr(L"blockWmiPersistence",
      ContainsAny(c.cmd, {L"__eventfilter", L"commandlineeventconsumer", L"activescripteventconsumer",
                          L"__filtertoconsumerbinding"}),
      L"WMI event subscription persistence", L"T1546.003");

  bool vulnerableDriver = false;
  for (const auto& driver : kVulnerableDrivers) {
    if (Contains(c.cmd, driver)) vulnerableDriver = true;
  }
  asr(L"blockVulnerableSignedDrivers", vulnerableDriver && ContainsAny(c.cmd, {L"sc ", L"sc.exe", L"create", L"start"}),
      L"loading a known vulnerable signed driver", L"T1068");

  const bool lolbin =
      (c.imageName == L"certutil.exe" && ContainsAny(c.cmdDash, {L"-urlcache", L"-decode", L"-verifyctl", L"-split"})) ||
      (c.imageName == L"mshta.exe" && ContainsAny(c.cmd, {L"http:", L"https:", L"javascript:", L"vbscript:"})) ||
      (c.imageName == L"regsvr32.exe" && Contains(c.cmd, L"scrobj.dll")) ||
      (c.imageName == L"rundll32.exe" && ContainsAny(c.cmd, {L"javascript:", L"http://", L"https://", L"\\\\"})) ||
      (c.imageName == L"bitsadmin.exe" && ContainsAny(c.cmdDash, {L"-transfer", L"-addfile"})) ||
      (c.imageName == L"msiexec.exe" && ContainsAny(c.cmd, {L"http://", L"https://"})) ||
      (c.imageName == L"installutil.exe" && Contains(c.cmdDash, L"-u")) ||
      (c.imageName == L"cmstp.exe" && Contains(c.cmdDash, L"-s")) ||
      (c.imageName == L"msbuild.exe" && UserWritablePath(c.cmd));
  asr(L"blockLolbinAbuse", lolbin, c.imageName + L" used to fetch or run remote/unusual content", L"T1218");

  asr(L"blockWebshellCreation",
      IsOneOf(c.parentName, kWebServers) &&
          IsOneOf(c.imageName, {L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"whoami.exe", L"net.exe", L"net1.exe",
                                L"certutil.exe", L"systeminfo.exe", L"nltest.exe", L"rundll32.exe"}),
      c.parentName + L" (web server) spawned " + c.imageName, L"T1505.003");

  const bool recoveryInhibition =
      (c.imageName == L"vssadmin.exe" && ContainsAny(c.cmd, {L"delete shadows", L"resize shadowstorage"})) ||
      (c.imageName == L"wmic.exe" && Contains(c.cmd, L"shadowcopy") && Contains(c.cmd, L"delete")) ||
      (Contains(c.cmd, L"win32_shadowcopy") && ContainsAny(c.cmd, {L"delete", L"remove-"})) ||
      (c.imageName == L"bcdedit.exe" && ContainsAny(c.cmd, {L"recoveryenabled no", L"ignoreallfailures"})) ||
      (c.imageName == L"wbadmin.exe" && ContainsAny(c.cmd, {L"delete catalog", L"delete systemstatebackup", L"delete backup"})) ||
      (c.imageName == L"cipher.exe" && Contains(c.cmdDash, L" -w:"));
  asr(L"advancedRansomwareProtection", recoveryInhibition, L"inhibiting system recovery (ransomware precursor)", L"T1490");
  if (recoveryInhibition && policy.blockShadowCopyDeletion) {
    out.push_back({L"ransomware.blockShadowCopyDeletion", RuleMode::Block, L"shadow copy or backup deletion", L"T1490"});
  }

  // Application control
  const auto mode = Lower(policy.appControlMode);
  if (mode != L"off") {
    const auto sha = Lower(p.sha256);
    const auto signer = Lower(p.signer);
    auto matches = [&](const std::vector<std::wstring>& list) {
      return std::any_of(list.begin(), list.end(), [&](const std::wstring& entry) {
        const auto e = Lower(entry);
        return !e.empty() && (e == c.imageName || e == sha || (!signer.empty() && e == signer) || c.image == e);
      });
    };
    const auto action = mode == L"audit" ? RuleMode::Audit : RuleMode::Block;
    if (matches(policy.blockedApps)) {
      out.push_back({L"applicationControl.blockedApps", action, c.imageName + L" is on the blocked list", L"T1204"});
    } else if (mode == L"enforce-allowlist") {
      const bool trustedSigner =
          p.signatureVerified && std::any_of(policy.allowedPublishers.begin(), policy.allowedPublishers.end(),
                                             [&](const std::wstring& pub) { return !signer.empty() && Lower(pub) == signer; });
      const bool trustedHash = std::any_of(policy.allowedHashes.begin(), policy.allowedHashes.end(),
                                           [&](const std::wstring& h) { return !sha.empty() && Lower(h) == sha; });
      const bool trustedSystem = SystemPath(c.image) && p.signatureVerified;
      if (!trustedSigner && !trustedHash && !trustedSystem) {
        out.push_back({L"applicationControl.allowlist", RuleMode::Block, c.imageName + L" is not on the allow list", L"T1204"});
      }
    }
    if (policy.blockUnknownReputation && !p.signatureVerified && UserWritablePath(c.image)) {
      out.push_back({L"applicationControl.blockUnknownReputation", action,
                     L"unsigned program with no reputation in a user-writable folder", L"T1204.002"});
    }
  }
  return out;
}

}  // namespace antivirus::agent::behavior
