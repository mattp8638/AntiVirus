#pragma once

// First-seen record for applicationControl.blockNewlySeenExecutables: when this device first saw each program
// (by SHA-256, lower case). Kept in a small text file (one "sha256 unixSeconds" per line) so a restart does not
// make every program "new" again, and capped so it cannot grow without limit (oldest entries go first).
// Header-only and portable so it is unit tested anywhere; the caller does its own locking.

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace antivirus::agent {

class FirstSeenStore {
 public:
  static constexpr long long kNewlySeenSeconds = 24 * 3600;
  static constexpr std::size_t kMaxEntries = 50000;

  explicit FirstSeenStore(std::filesystem::path file = {}) : file_(std::move(file)) { Load(); }

  // Records sha if it is new and returns when it was first seen.
  long long Observe(std::wstring sha, long long nowUnix) {
    std::transform(sha.begin(), sha.end(), sha.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    if (sha.empty()) return 0;
    const auto it = seen_.find(sha);
    if (it != seen_.end()) return it->second;
    seen_[sha] = nowUnix;
    dirty_ = true;
    if (seen_.size() > kMaxEntries) {
      std::vector<std::pair<long long, std::wstring>> byAge;
      byAge.reserve(seen_.size());
      for (const auto& [k, v] : seen_) byAge.emplace_back(v, k);
      std::sort(byAge.begin(), byAge.end());
      for (std::size_t i = 0; i < seen_.size() - kMaxEntries && i < byAge.size(); ++i) seen_.erase(byAge[i].second);
    }
    return nowUnix;
  }

  static bool NewlySeen(long long firstSeenUnix, long long nowUnix) {
    return firstSeenUnix > 0 && nowUnix - firstSeenUnix < kNewlySeenSeconds;
  }

  // Writes the file when something changed (through a temporary file, so a crash never leaves half a record).
  bool Save() {
    if (!dirty_ || file_.empty()) return true;
    std::error_code ec;
    std::filesystem::create_directories(file_.parent_path(), ec);
    const auto tmp = file_.wstring() + L".tmp";
    {
      std::wofstream out{std::filesystem::path(tmp), std::ios::trunc};
      if (!out) return false;
      for (const auto& [sha, at] : seen_) out << sha << L' ' << at << L'\n';
      if (!out) return false;
    }
    std::filesystem::rename(tmp, file_, ec);
    if (ec) return false;
    dirty_ = false;
    return true;
  }

  std::size_t Size() const { return seen_.size(); }

 private:
  void Load() {
    if (file_.empty()) return;
    std::wifstream in(file_);
    std::wstring sha;
    long long at = 0;
    while (in >> sha >> at) {
      if (sha.size() == 64 && at > 0) seen_[sha] = at;
    }
  }

  std::filesystem::path file_;
  std::map<std::wstring, long long> seen_;
  bool dirty_{false};
};

}  // namespace antivirus::agent
