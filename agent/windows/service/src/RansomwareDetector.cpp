#include "RansomwareDetector.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <cwctype>

namespace antivirus::agent::ransomware {

namespace {

constexpr unsigned long long kWindowMs = 60'000;
constexpr unsigned long long kFolderReportEveryMs = 10 * 60'000;
constexpr std::size_t kMaxBurstPaths = 500;
constexpr std::size_t kMaxTrackedProcesses = 4096;

bool StartsWith(const unsigned char* data, std::size_t size, const char* magic, std::size_t magicSize,
                std::size_t offset = 0) {
  return size >= offset + magicSize && std::memcmp(data + offset, magic, magicSize) == 0;
}

std::wstring TrimSlashes(std::wstring value) {
  while (value.size() > 3 && (value.back() == L'\\' || value.back() == L'/')) {
    value.pop_back();
  }
  return value;
}

}  // namespace

double ShannonEntropy(const unsigned char* data, const std::size_t size) {
  if (data == nullptr || size == 0) {
    return 0.0;
  }
  std::size_t counts[256]{};
  for (std::size_t i = 0; i < size; ++i) {
    ++counts[data[i]];
  }
  double entropy = 0.0;
  const auto total = static_cast<double>(size);
  for (const auto count : counts) {
    if (count != 0) {
      const double p = static_cast<double>(count) / total;
      entropy -= p * std::log2(p);
    }
  }
  return entropy;
}

bool HasKnownFormatHeader(const unsigned char* d, const std::size_t n) {
  if (d == nullptr || n < 4) {
    return false;
  }
  static const struct {
    const char* magic;
    std::size_t size;
    std::size_t offset;
  } kMagics[] = {
      {"PK\x03\x04", 4, 0},          // zip, docx/xlsx/pptx, jar, apk
      {"PK\x05\x06", 4, 0},          // empty zip
      {"%PDF", 4, 0},
      {"\xFF\xD8\xFF", 3, 0},        // jpeg
      {"\x89PNG", 4, 0},
      {"GIF8", 4, 0},
      {"RIFF", 4, 0},                // wav, avi, webp
      {"ID3", 3, 0},                 // mp3
      {"\xFF\xFB", 2, 0},            // mp3 frame
      {"OggS", 4, 0},
      {"fLaC", 4, 0},
      {"ftyp", 4, 4},                // mp4, mov, heic, m4a
      {"\x1A\x45\xDF\xA3", 4, 0},    // mkv, webm
      {"\x1F\x8B", 2, 0},            // gzip
      {"7z\xBC\xAF\x27\x1C", 6, 0},
      {"Rar!", 4, 0},
      {"\xFD" "7zXZ", 5, 0},         // xz
      {"\x28\xB5\x2F\xFD", 4, 0},    // zstd
      {"BZh", 3, 0},
      {"MSCF", 4, 0},                // cab
      {"MZ", 2, 0},                  // exe, dll
      {"\xD0\xCF\x11\xE0", 4, 0},    // OLE: doc, xls, msg, msi
      {"SQLite format 3", 15, 0},
      {"!BDN", 4, 0},                // Outlook pst
      {"8BPS", 4, 0},                // photoshop
      {"II*\0", 4, 0},               // tiff, many camera raw formats
      {"MM\0*", 4, 0},
      {"wOFF", 4, 0},
      {"wOF2", 4, 0},
      {"OTTO", 4, 0},
      {"\0\x01\0\0", 4, 0},          // ttf
      {"{\\rtf", 5, 0},
      {"<?xml", 5, 0},
      {"\x30\x82", 2, 0},            // DER certificates and keys
      {"-----BEGIN", 10, 0},
      {"\xEF\xBB\xBF", 3, 0},        // UTF-8 text with BOM
      {"\xFF\xFE", 2, 0},            // UTF-16 text
      {"ITSF", 4, 0},                // chm
      {"\x00\x00\x01\xBA", 4, 0},    // mpeg
      {"\x47\x40", 2, 0},            // mpeg-ts
      {"FWS", 3, 0},
      {"CWS", 3, 0},
      {"\x4C\x00\x00\x00\x01\x14\x02\x00", 8, 0},  // .lnk
      {"VHDX", 4, 0},
      {"conectix", 8, 0},            // vhd
      {"KDM", 3, 0},                 // vmdk
      {"\x00\x00\x00\x0C" "jP", 6, 0},  // jpeg 2000
  };
  for (const auto& m : kMagics) {
    if (StartsWith(d, n, m.magic, m.size, m.offset)) {
      return true;
    }
  }
  return false;
}

bool LooksEncrypted(const unsigned char* data, const std::size_t size) {
  if (data == nullptr || size < 512 || HasKnownFormatHeader(data, size)) {
    return false;
  }
  const std::size_t sample = std::min<std::size_t>(size, 64 * 1024);
  // Small samples under-estimate entropy (about 255 / (2 N ln 2) bits), so the bar follows the sample size.
  const double bias = 255.0 / (2.0 * static_cast<double>(sample) * std::log(2.0));
  return ShannonEntropy(data, sample) >= 8.0 - bias - 0.15;
}

bool EncryptionConfirmed(const int sampled, const int encrypted) {
  if (sampled <= 0 || encrypted <= 0) {
    return false;
  }
  if (sampled < 3) {
    return encrypted == sampled;
  }
  return encrypted * 10 >= sampled * 6;
}

std::wstring Lower(std::wstring value) {
  for (auto& c : value) {
    c = static_cast<wchar_t>(std::towlower(static_cast<wint_t>(c)));
  }
  return value;
}

std::vector<std::wstring> ExpandProtectedFolder(const std::wstring& entryIn, const std::vector<std::wstring>& profiles) {
  std::vector<std::wstring> out;
  auto entry = entryIn;
  while (!entry.empty() && (entry.front() == L' ' || entry.front() == L'"')) entry.erase(entry.begin());
  while (!entry.empty() && (entry.back() == L' ' || entry.back() == L'"')) entry.pop_back();
  if (entry.empty()) {
    return out;
  }
  const auto lowered = Lower(entry);
  for (const std::wstring marker : {L"%userprofile%", L"{profile}"}) {
    if (lowered.rfind(marker, 0) == 0) {
      const auto rest = entry.substr(marker.size());
      for (const auto& profile : profiles) {
        if (!profile.empty()) {
          out.push_back(TrimSlashes(TrimSlashes(profile) + rest));
        }
      }
      return out;
    }
  }
  out.push_back(TrimSlashes(entry));
  return out;
}

bool PathUnder(const std::wstring& path, const std::wstring& root) {
  if (root.empty() || path.size() < root.size()) {
    return false;
  }
  auto r = Lower(TrimSlashes(root));
  const auto p = Lower(path);
  if (p.compare(0, r.size(), r) != 0) {
    return false;
  }
  return p.size() == r.size() || p[r.size()] == L'\\' || r.back() == L'\\';
}

bool AppAllowed(const std::wstring& imagePath, const std::vector<std::wstring>& allowedApps) {
  if (imagePath.empty()) {
    return false;
  }
  const auto image = Lower(imagePath);
  const auto slash = image.find_last_of(L"\\/");
  const auto name = slash == std::wstring::npos ? image : image.substr(slash + 1);
  for (const auto& raw : allowedApps) {
    const auto entry = Lower(raw);
    if (entry.empty()) {
      continue;
    }
    if (entry.back() == L'\\' || entry.back() == L'/') {
      if (image.rfind(entry, 0) == 0) return true;
    } else if (entry.find_first_of(L"\\/") == std::wstring::npos) {
      if (entry == name) return true;
    } else if (entry == image) {
      return true;
    }
  }
  return false;
}

void Detector::Configure(DetectorConfig config) {
  for (auto& root : config.roots) root = Lower(TrimSlashes(root));
  for (auto& root : config.shareRoots) root = Lower(TrimSlashes(root));
  std::set<std::wstring> canaries;
  for (const auto& canary : config.canaries) canaries.insert(Lower(canary));
  config.canaries = std::move(canaries);
  for (auto& app : config.allowedApps) app = Lower(app);
  config.filesPerMinute = std::clamp(config.filesPerMinute, 5, 1000);
  config_ = std::move(config);
}

bool Detector::Watches(const std::wstring& lowerPath) const {
  if (config_.canaries.count(lowerPath) != 0) return true;
  for (const auto& root : config_.roots) {
    if (PathUnder(lowerPath, root)) return true;
  }
  for (const auto& root : config_.shareRoots) {
    if (PathUnder(lowerPath, root)) return true;
  }
  return false;
}

void Detector::Forget(const unsigned long pid) { windows_.erase(pid); }

std::vector<Observation> Detector::OnWrite(const unsigned long pid, const std::wstring& image, const std::wstring& path,
                                           const unsigned long long nowMs) {
  std::vector<Observation> out;
  if (pid == 0 || (config_.selfPid != 0 && pid == config_.selfPid)) {
    return out;
  }
  const auto lp = Lower(path);
  const bool remote = pid == kSystemPid;

  if (config_.canaries.count(lp) != 0) {
    auto& last = canaryReported_[lp];
    if (last == 0 || nowMs - last >= kWindowMs) {
      last = nowMs;
      out.push_back({ObservationKind::Canary, pid, remote ? L"SMB client (System)" : image, path, {}, 1, remote});
    }
    return out;
  }

  bool inRoots = false;
  for (const auto& root : config_.roots) {
    if (PathUnder(lp, root)) { inRoots = true; break; }
  }
  bool inShares = false;
  for (const auto& root : config_.shareRoots) {
    if (PathUnder(lp, root)) { inShares = true; break; }
  }
  if (remote ? (config_.shareRoots.empty() || !(inShares || inRoots)) : !inRoots) {
    return out;
  }
  if (!remote && AppAllowed(image, config_.allowedApps)) {
    return out;
  }

  if (windows_.size() > kMaxTrackedProcesses) {
    for (auto it = windows_.begin(); it != windows_.end();) {
      const bool idle = it->second.changes.empty() || nowMs - it->second.changes.back().first >= kWindowMs;
      it = idle ? windows_.erase(it) : std::next(it);
    }
  }
  auto& w = windows_[pid];
  if (w.image != image) {
    w = Window{};
    w.image = image;
  }

  if (!remote && config_.protectedFoldersWatch && inRoots &&
      (!w.folderReported || nowMs - w.lastFolderReportMs >= kFolderReportEveryMs)) {
    w.folderReported = true;
    w.lastFolderReportMs = nowMs;
    out.push_back({ObservationKind::ProtectedFolderWrite, pid, image, path, {}, 1, false});
  }

  while (!w.changes.empty() && w.changes.front().first + kWindowMs <= nowMs) {
    const auto it = w.seen.find(w.changes.front().second);
    if (it != w.seen.end() && it->second == w.changes.front().first) {
      w.seen.erase(it);
    }
    w.changes.pop_front();
  }
  if (w.seen.find(lp) == w.seen.end()) {
    w.seen.emplace(lp, nowMs);
    w.changes.emplace_back(nowMs, path);
  }
  const auto count = static_cast<int>(w.changes.size());
  if (count >= config_.filesPerMinute && (w.lastBurstMs == 0 || nowMs - w.lastBurstMs >= kWindowMs)) {
    w.lastBurstMs = nowMs;
    Observation burst{ObservationKind::MassChange, pid, remote ? L"SMB client (System)" : image, path, {}, count, remote};
    const auto start = w.changes.size() > kMaxBurstPaths ? w.changes.size() - kMaxBurstPaths : 0;
    for (auto i = start; i < w.changes.size(); ++i) {
      burst.paths.push_back(w.changes[i].second);
    }
    out.push_back(std::move(burst));
  }
  return out;
}

}  // namespace antivirus::agent::ransomware
