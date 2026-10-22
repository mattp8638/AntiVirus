#pragma once

// Attack surface reduction rules, application control and ransomware-tamper
// rules evaluated on every process start. Pure logic (no Windows headers) so
// it is unit-tested on any platform; AgentService applies the decisions.

#include <map>
#include <string>
#include <vector>

namespace antivirus::agent::behavior {

enum class RuleMode { Off, Audit, Warn, Block };

RuleMode ParseRuleMode(const std::wstring& value);
const wchar_t* RuleModeName(RuleMode mode);

struct ProcessFacts {
  unsigned long pid{0};
  std::wstring imagePath;
  std::wstring commandLine;
  std::wstring parentImagePath;
  std::wstring parentCommandLine;
  std::wstring signer;          // empty when unsigned or unknown
  bool signatureVerified{false};
  std::wstring sha256;          // optional; only needed for hash rules
  bool onRemovableMedia{false};
};

struct BehaviorPolicy {
  // attackSurface.<rule> -> mode
  std::map<std::wstring, RuleMode> asr;
  bool blockShadowCopyDeletion{true};  // ransomware section; enforced even if ASR is off
  // applicationControl
  std::wstring appControlMode{L"off"};  // off | audit | enforce-denylist | enforce-allowlist
  std::vector<std::wstring> blockedApps;  // names, sha256s or signer names
  std::vector<std::wstring> allowedPublishers;
  std::vector<std::wstring> allowedHashes;
  bool blockUnknownReputation{false};
  // exclusions
  std::vector<std::wstring> excludedProcesses;  // image base names
  std::vector<std::wstring> excludedPathRoots;
  std::wstring agentInstallRoot;                // our own binaries are never blocked
};

struct Decision {
  std::wstring rule;      // e.g. attackSurface.blockOfficeChildProcesses
  RuleMode mode{RuleMode::Audit};
  std::wstring reason;
  std::wstring mitre;     // technique id
};

std::vector<Decision> Evaluate(const ProcessFacts& process, const BehaviorPolicy& policy);

// The strongest action across decisions (Block > Warn > Audit > Off).
RuleMode Strongest(const std::vector<Decision>& decisions);

}  // namespace antivirus::agent::behavior
