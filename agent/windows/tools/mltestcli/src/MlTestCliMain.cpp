// fenrir-mltest: inspect the static ML model from the command line.
//   fenrir-mltest features <file>...        print EMBER v2 vectors as JSON lines
//   fenrir-mltest score <model.fgbt> <file>...  print model scores
// Portable: builds with MSVC, MinGW and Linux g++ (used by the parity tests).
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "MlStaticModel.h"

namespace ml = antivirus::agent::ml;

static std::vector<unsigned char> ReadAll(const char* path) {
  std::ifstream in(path, std::ios::binary);
  return std::vector<unsigned char>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

int main(int argc, char** argv) {
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s features <file>... | score <model.fgbt> <file>...\n", argv[0]);
    return 2;
  }
  const std::string mode = argv[1];
  if (mode == "features") {
    for (int i = 2; i < argc; ++i) {
      const auto v = ml::ExtractFeatures(ReadAll(argv[i]));
      std::printf("{\"file\":\"%s\",\"v\":[", argv[i]);
      for (std::size_t j = 0; j < v.size(); ++j) std::printf(j ? ",%.9g" : "%.9g", static_cast<double>(v[j]));
      std::printf("]}\n");
    }
    return 0;
  }
  if (mode == "score" && argc >= 4) {
    std::string error;
    const std::string modelPath = argv[2];
    const auto model = ml::GbdtModel::LoadFile(std::wstring(modelPath.begin(), modelPath.end()), &error);
    if (!model) {
      std::fprintf(stderr, "model load failed: %s\n", error.c_str());
      return 1;
    }
    for (int i = 3; i < argc; ++i) {
      const auto bytes = ReadAll(argv[i]);
      if (!ml::IsPortableExecutable(bytes)) {
        std::printf("%s\tnot-pe\n", argv[i]);
        continue;
      }
      std::printf("%s\t%.6f\n", argv[i], model->Score(ml::ExtractFeatures(bytes)));
    }
    return 0;
  }
  std::fprintf(stderr, "unknown mode\n");
  return 2;
}
