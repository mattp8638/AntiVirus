#include "BundleArchive.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>

namespace antivirus::agent {
namespace {

constexpr std::size_t kBlock = 512;

void Octal(char* field, std::size_t width, unsigned long long value) {
  // width includes the terminating NUL.
  std::snprintf(field, width, "%0*llo", static_cast<int>(width - 1), value);
}

bool SplitName(const std::string& path, std::string* prefix, std::string* name) {
  if (path.size() <= 100) {
    *prefix = "";
    *name = path;
    return true;
  }
  // ustar: prefix (<=155) + '/' + name (<=100), split on a directory separator.
  for (auto slash = path.rfind('/'); slash != std::string::npos && slash > 0; slash = path.rfind('/', slash - 1)) {
    if (slash <= 155 && path.size() - slash - 1 <= 100) {
      *prefix = path.substr(0, slash);
      *name = path.substr(slash + 1);
      return true;
    }
    if (slash == 0) break;
  }
  return false;
}

std::string Header(const std::string& prefix, const std::string& name, unsigned long long size, unsigned long long mtime) {
  std::string header(kBlock, '\0');
  char* h = header.data();
  std::memcpy(h, name.data(), name.size());
  Octal(h + 100, 8, 0644);
  Octal(h + 108, 8, 0);
  Octal(h + 116, 8, 0);
  Octal(h + 124, 12, size);
  Octal(h + 136, 12, mtime);
  std::memset(h + 148, ' ', 8);
  h[156] = '0';
  std::memcpy(h + 257, "ustar", 6);
  std::memcpy(h + 263, "00", 2);
  std::memcpy(h + 265, "fenrir", 6);
  std::memcpy(h + 297, "fenrir", 6);
  std::memcpy(h + 345, prefix.data(), prefix.size());
  unsigned int sum = 0;
  for (const unsigned char c : header) sum += c;
  std::snprintf(h + 148, 8, "%06o", sum);
  h[155] = ' ';
  return header;
}

}  // namespace

std::string BuildTarArchive(const std::filesystem::path& root, const std::size_t maxBytes, std::vector<std::string>* skipped) {
  std::vector<std::filesystem::path> files;
  std::error_code error;
  for (std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, error), end;
       !error && it != end; it.increment(error)) {
    if (it->is_regular_file(error)) {
      files.push_back(it->path());
    }
  }
  std::sort(files.begin(), files.end());
  const auto now = static_cast<unsigned long long>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  std::string out;
  for (const auto& file : files) {
    const auto relative = std::filesystem::relative(file, root, error).generic_u8string();
    const std::string path(relative.begin(), relative.end());
    std::string prefix;
    std::string name;
    std::ifstream in(file, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const auto padded = (data.size() + kBlock - 1) / kBlock * kBlock;
    if (path.empty() || !SplitName(path, &prefix, &name) || (!in.good() && !in.eof())) {
      if (skipped) skipped->push_back(path + ": cannot be archived");
      continue;
    }
    if (out.size() + kBlock + padded + 2 * kBlock > maxBytes) {
      if (skipped) skipped->push_back(path + ": archive size limit reached");
      continue;
    }
    out += Header(prefix, name, data.size(), now);
    out += data;
    out.append(padded - data.size(), '\0');
  }
  out.append(2 * kBlock, '\0');  // end-of-archive marker
  return out;
}

}  // namespace antivirus::agent
