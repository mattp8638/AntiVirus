#pragma once

// Decides when a remote address that keeps failing to sign in (RDP, SMB, SSH) should be blocked, and for how
// long (firewall.bruteForceProtection). Pure logic so it can be unit tested; BruteForceGuard (Windows) and the
// Go agent apply the blocks.

#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace antivirus::agent::bruteforce {

constexpr int kThreshold = 10;                          // failures ...
constexpr unsigned long long kWindowSeconds = 600;      // ... inside ten minutes
constexpr unsigned long long kBaseBlockSeconds = 3600;  // first block: one hour, then x4 per repeat (max a day)
constexpr unsigned long long kMaxBlockSeconds = 86400;

// A remote address worth counting: an IPv4/IPv6 literal that is not loopback or unspecified.
// Returns the normalised form ("::ffff:1.2.3.4" becomes "1.2.3.4"), or empty when unusable.
std::wstring NormaliseRemoteAddress(const std::wstring& address);

struct Block {
  std::wstring address;
  unsigned long long until{0};
  int strikes{1};
  int failures{0};
  std::vector<std::wstring> accounts;  // account names tried (up to 10)
};

class Tracker {
 public:
  // Records one failed sign-in. Returns a block when this failure crosses the threshold.
  std::optional<Block> OnFailure(const std::wstring& address, const std::wstring& account, unsigned long long now);
  // Addresses whose block has ended (removed from the active list).
  std::vector<std::wstring> Expire(unsigned long long now);
  bool Blocked(const std::wstring& address) const { return blocks_.count(address) != 0; }
  // Re-loads a block saved before a restart.
  void Restore(const Block& block);
  const std::map<std::wstring, Block>& Blocks() const { return blocks_; }
  std::vector<std::wstring> Clear();  // feature switched off: everything to unblock

 private:
  std::map<std::wstring, std::deque<unsigned long long>> failures_;
  std::map<std::wstring, std::set<std::wstring>> accounts_;
  std::map<std::wstring, Block> blocks_;
  std::map<std::wstring, std::pair<int, unsigned long long>> strikes_;  // address -> (strikes, last block time)
};

}  // namespace antivirus::agent::bruteforce
