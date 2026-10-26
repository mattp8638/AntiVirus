#include "BruteForceTracker.h"

#include <algorithm>
#include <cwctype>

namespace antivirus::agent::bruteforce {

std::wstring NormaliseRemoteAddress(const std::wstring& raw) {
  std::wstring address;
  for (const auto c : raw) {
    if (c != L' ' && c != L'\t' && c != L'[' && c != L']') address += static_cast<wchar_t>(std::towlower(c));
  }
  if (address.rfind(L"::ffff:", 0) == 0 && address.find(L'.') != std::wstring::npos) address = address.substr(7);
  if (address.size() < 2 || address.size() > 45) return {};
  bool dot = false, colon = false;
  for (const auto c : address) {
    if (c == L'.') {
      dot = true;
    } else if (c == L':') {
      colon = true;
    } else if (!std::iswxdigit(c)) {
      return {};
    }
  }
  if (!dot && !colon) return {};
  if (dot && !colon) {  // IPv4: four decimal parts
    int parts = 0, value = -1;
    for (std::size_t i = 0; i <= address.size(); ++i) {
      if (i == address.size() || address[i] == L'.') {
        if (value < 0 || value > 255) return {};
        ++parts;
        value = -1;
      } else if (std::iswdigit(address[i])) {
        value = (value < 0 ? 0 : value * 10) + (address[i] - L'0');
        if (value > 255) return {};
      } else {
        return {};
      }
    }
    if (parts != 4 || address.rfind(L"127.", 0) == 0 || address == L"0.0.0.0" || address == L"255.255.255.255") return {};
    return address;
  }
  if (address == L"::1" || address == L"::") return {};
  return address;
}

std::optional<Block> Tracker::OnFailure(const std::wstring& rawAddress, const std::wstring& account,
                                        const unsigned long long now) {
  const auto address = NormaliseRemoteAddress(rawAddress);
  if (address.empty() || blocks_.count(address) != 0) return std::nullopt;
  auto& times = failures_[address];
  while (!times.empty() && times.front() + kWindowSeconds <= now) times.pop_front();
  times.push_back(now);
  auto& names = accounts_[address];
  if (!account.empty() && names.size() < 10) names.insert(account);
  if (static_cast<int>(times.size()) < kThreshold) {
    // Keep memory bounded when a scan sprays many addresses.
    if (failures_.size() > 10000) {
      for (auto it = failures_.begin(); it != failures_.end();) {
        if (it->second.empty() || it->second.back() + kWindowSeconds <= now) {
          accounts_.erase(it->first);
          it = failures_.erase(it);
        } else {
          ++it;
        }
      }
    }
    return std::nullopt;
  }
  auto& strike = strikes_[address];
  if (strike.second + kMaxBlockSeconds < now) strike.first = 0;  // a day without trouble starts afresh
  strike.first = std::min(strike.first + 1, 5);
  strike.second = now;
  unsigned long long duration = kBaseBlockSeconds;
  for (int i = 1; i < strike.first; ++i) duration *= 4;
  duration = std::min(duration, kMaxBlockSeconds);
  Block block{address, now + duration, strike.first, static_cast<int>(times.size()),
              std::vector<std::wstring>(names.begin(), names.end())};
  blocks_[address] = block;
  failures_.erase(address);
  accounts_.erase(address);
  return block;
}

std::vector<std::wstring> Tracker::Expire(const unsigned long long now) {
  std::vector<std::wstring> out;
  for (auto it = blocks_.begin(); it != blocks_.end();) {
    if (it->second.until <= now) {
      out.push_back(it->first);
      it = blocks_.erase(it);
    } else {
      ++it;
    }
  }
  return out;
}

void Tracker::Restore(const Block& block) {
  const auto address = NormaliseRemoteAddress(block.address);
  if (address.empty()) return;
  auto copy = block;
  copy.address = address;
  blocks_[address] = copy;
  strikes_[address] = {std::max(block.strikes, 1), block.until > kBaseBlockSeconds ? block.until - kBaseBlockSeconds : 0};
}

std::vector<std::wstring> Tracker::Clear() {
  std::vector<std::wstring> out;
  for (const auto& [address, block] : blocks_) out.push_back(address);
  blocks_.clear();
  failures_.clear();
  accounts_.clear();
  return out;
}

}  // namespace antivirus::agent::bruteforce
