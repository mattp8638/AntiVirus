#pragma once

// Fenrir static PE malware model: EMBER v2 feature extraction plus a
// gradient-boosted tree evaluator. Portable C++20 (no Windows headers) so it
// is unit-tested on Linux too. Reference implementation: ml/fenrir_ml.

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace antivirus::agent::ml {

constexpr std::size_t kFeatureDim = 2381;

// Returns the 2381-float EMBER v2 vector for a whole file's bytes.
std::vector<float> ExtractFeatures(const std::vector<unsigned char>& bytes);
bool IsPortableExecutable(const std::vector<unsigned char>& bytes);

struct ModelThresholds {
  double fpr1{1.0};    // threshold giving ~1% false positives on validation data
  double fpr01{1.0};   // ~0.1%
  double fpr001{1.0};  // ~0.01%
};

class GbdtModel {
 public:
  // Parses the FGBT binary format written by ml/export_model.py. Returns nullopt on any malformed input.
  static std::optional<GbdtModel> Load(const std::vector<unsigned char>& bytes, std::string* error = nullptr);
  static std::optional<GbdtModel> LoadFile(const std::wstring& path, std::string* error = nullptr);

  double Score(const std::vector<float>& features) const;
  const ModelThresholds& Thresholds() const { return thresholds_; }
  const std::string& Version() const { return version_; }
  std::size_t TreeCount() const { return trees_.size(); }

  // Maps a policy sensitivity (cautious|balanced|aggressive|paranoid) to a score cut-off; nullopt = off.
  std::optional<double> ThresholdFor(const std::wstring& sensitivity) const;

 private:
  struct Tree {
    std::vector<std::int32_t> feature;
    std::vector<double> threshold;
    std::vector<std::int32_t> left;
    std::vector<std::int32_t> right;
    std::vector<double> leaf;
  };
  std::vector<Tree> trees_;
  ModelThresholds thresholds_;
  std::string version_;
};

struct MlVerdict {
  double score{0.0};
  bool evaluated{false};
  std::string reason;  // why it was not evaluated, if not
};

// Process-wide model location, set once by the service at start-up.
void SetDefaultModelPath(const std::wstring& path);
std::wstring DefaultModelPath();

// Returns the model at path, reloading only when the file changes. nullptr if missing or invalid.
std::shared_ptr<const GbdtModel> LoadCached(const std::wstring& path, std::string* error = nullptr);

// Loads the model once from <dir>\models\fenrir-pe.fgbt (or FENRIR_ML_MODEL) and scores a file's bytes.
MlVerdict ScoreFileBytes(const std::vector<unsigned char>& bytes, const std::wstring& modelPath);

}  // namespace antivirus::agent::ml
