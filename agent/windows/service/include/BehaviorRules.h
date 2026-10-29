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
  std::wstring parentSha256;    // only computed when an exclusion names the parent's path
};

// A strict EDR exclusion from Fenrir Cloud (modules.edrExclusions.rules; cloud: edr_exclusions.py).
// process-chain: trusts a child only when the parent's path *and* SHA-256 match. hash: one exact file.
// Paths compare case-insensitively with '/' and '\' alike; wildcards only in the final component.
struct ExclusionRule {
  std::wstring id;
  std::wstring kind{L"process-chain"};
  std::wstring parentImage;
  std::vector<std::wstring> parentSha256;  // lower-case hex
  std::wstring childImage;
  std::vector<std::wstring> childSha256;
  std::wstring commandLineContains;
  std::vector<std::wstring> scopes;  // behavior | antimalware | sigma

  bool HasScope(const std::wstring& scope) const;
};

bool ExclusionPathMatches(const std::wstring& pattern, const std::wstring& path);
bool ExclusionMatches(const ExclusionRule& rule, const ProcessFacts& process);
// The first rule with this scope covering the process, or nullptr.
const ExclusionRule* MatchExclusion(const std::vector<ExclusionRule>& rules, const std::wstring& scope, const ProcessFacts& process);
// Hash the parent only when some rule names its path.
bool NeedsParentHash(const std::vector<ExclusionRule>& rules, const std::wstring& parentImagePath);
bool NeedsChildHash(const std::vector<ExclusionRule>& rules);

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
  std::vector<ExclusionRule> exclusions;        // strict process-chain / hash rules
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
