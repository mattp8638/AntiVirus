#pragma once

// Decision logic for the ransomware shield, kept free of Windows calls so it can be unit tested.
// RansomwareShield feeds it one record per file write (from the kernel file ETW provider) and acts on
// what it returns: canary files touched, unapproved apps writing into protected folders, and bursts of
// files rewritten by one process.

#include <cstddef>
#include <deque>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace antivirus::agent::ransomware {

// Shannon entropy of a buffer in bits per byte (0..8).
double ShannonEntropy(const unsigned char* data, std::size_t size);
// True for headers of common formats that are compressed or binary by design (zip/Office, PDF, images,
// audio, video, archives, executables, databases), so their high entropy says nothing about encryption.
bool HasKnownFormatHeader(const unsigned char* data, std::size_t size);
// True when the start of a file looks like ciphertext: no recognised format header and near-random bytes.
bool LooksEncrypted(const unsigned char* data, std::size_t size);
// Whether a set of sampled files confirms an encryption burst.
bool EncryptionConfirmed(int sampled, int encrypted);

// Expands one protected folder entry. %USERPROFILE% (and the {profile} marker) becomes every user profile,
// because the service runs as SYSTEM and its own profile is not where people keep documents.
std::vector<std::wstring> ExpandProtectedFolder(const std::wstring& entry, const std::vector<std::wstring>& profiles);

std::wstring Lower(std::wstring value);
// An allowed-apps entry matches an image by full path, by file name, or by folder (entry ending in '\').
bool AppAllowed(const std::wstring& imagePath, const std::vector<std::wstring>& allowedApps);
// True when path is inside root (both compared case-insensitively; root may or may not end in '\').
bool PathUnder(const std::wstring& path, const std::wstring& root);

constexpr unsigned long kSystemPid = 4;  // non-paging writes by System come from the SMB server

struct DetectorConfig {
  std::vector<std::wstring> roots;       // protected folders
  std::vector<std::wstring> shareRoots;  // local folders behind SMB shares (networkShareProtection)
  std::set<std::wstring> canaries;       // canary file paths, lower case
  int filesPerMinute{40};
  bool protectedFoldersWatch{false};     // protectedFoldersMode != off
  std::vector<std::wstring> allowedApps;  // lower case, variables already expanded
  unsigned long selfPid{0};
};

enum class ObservationKind { Canary, ProtectedFolderWrite, MassChange };

struct Observation {
  ObservationKind kind{ObservationKind::MassChange};
  unsigned long pid{0};
  std::wstring image;
  std::wstring path;                // the file that triggered it
  std::vector<std::wstring> paths;  // MassChange: distinct files changed in the last minute (newest last)
  int count{0};
  bool remote{false};               // written over SMB (System process)
};

class Detector {
 public:
  void Configure(DetectorConfig config);
  const DetectorConfig& Config() const { return config_; }
  // Path is the file's full path (any consistent form, e.g. \Device\HarddiskVolume3\Users\...).
  std::vector<Observation> OnWrite(unsigned long pid, const std::wstring& image, const std::wstring& path,
                                   unsigned long long nowMs);
  // True when the path is one the shield watches (protected folder, share or canary).
  bool Watches(const std::wstring& lowerPath) const;
  // Forget a process (it exited or was stopped).
  void Forget(unsigned long pid);
  std::size_t TrackedProcesses() const { return windows_.size(); }

 private:
  struct Window {
    std::wstring image;
    std::deque<std::pair<unsigned long long, std::wstring>> changes;  // first write per file inside the window
    std::unordered_map<std::wstring, unsigned long long> seen;
    unsigned long long lastBurstMs{0};
    unsigned long long lastFolderReportMs{0};
    bool folderReported{false};
  };
  DetectorConfig config_{};
  std::unordered_map<unsigned long, Window> windows_;
  std::unordered_map<std::wstring, unsigned long long> canaryReported_;
};

}  // namespace antivirus::agent::ransomware
