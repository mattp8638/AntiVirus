#include "MlStaticModel.h"

#include <algorithm>
#include <array>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string_view>

namespace antivirus::agent::ml {
namespace {

// --------------------------------------------------------------------------- hashing (sklearn FeatureHasher)

std::int32_t Murmur3(std::string_view data) {
  constexpr std::uint32_t c1 = 0xcc9e2d51, c2 = 0x1b873593;
  std::uint32_t h = 0;
  const auto n = data.size();
  const auto blocks = n / 4;
  const auto* bytes = reinterpret_cast<const unsigned char*>(data.data());
  for (std::size_t i = 0; i < blocks; ++i) {
    std::uint32_t k = static_cast<std::uint32_t>(bytes[i * 4]) | (static_cast<std::uint32_t>(bytes[i * 4 + 1]) << 8) |
                      (static_cast<std::uint32_t>(bytes[i * 4 + 2]) << 16) |
                      (static_cast<std::uint32_t>(bytes[i * 4 + 3]) << 24);
    k *= c1;
    k = (k << 15) | (k >> 17);
    k *= c2;
    h ^= k;
    h = (h << 13) | (h >> 19);
    h = h * 5 + 0xe6546b64;
  }
  const auto* tail = bytes + blocks * 4;
  std::uint32_t k = 0;
  switch (n & 3) {
    case 3:
      k ^= static_cast<std::uint32_t>(tail[2]) << 16;
      [[fallthrough]];
    case 2:
      k ^= static_cast<std::uint32_t>(tail[1]) << 8;
      [[fallthrough]];
    case 1:
      k ^= tail[0];
      k *= c1;
      k = (k << 15) | (k >> 17);
      k *= c2;
      h ^= k;
  }
  h ^= static_cast<std::uint32_t>(n);
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return static_cast<std::int32_t>(h);
}

struct Item {
  std::string token;
  double value;
};

void HashInto(std::vector<double>& out, std::size_t offset, int n, const std::vector<Item>& items) {
  for (const auto& item : items) {
    const auto h = Murmur3(item.token);
    int index = 0;
    if (h == INT32_MIN) {
      index = (INT32_MAX - (n - 1)) % n;
    } else {
      index = static_cast<int>(std::abs(static_cast<long long>(h)) % n);
    }
    out[offset + index] += h >= 0 ? item.value : -item.value;
  }
}

// latin-1 bytes -> UTF-8 (matches Python's bytes.decode("latin-1").encode("utf-8"))
std::string Latin1ToUtf8(std::string_view raw) {
  std::string out;
  out.reserve(raw.size());
  for (const unsigned char c : raw) {
    if (c < 0x80) {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back(static_cast<char>(0xC0 | (c >> 6)));
      out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    }
  }
  return out;
}

// Iterate a UTF-8 string one code point at a time (EMBER hashes the entry section name per character).
std::vector<std::string> Utf8Chars(const std::string& s) {
  std::vector<std::string> out;
  for (std::size_t i = 0; i < s.size();) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    const std::size_t len = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : 4;
    out.push_back(s.substr(i, len));
    i += len;
  }
  return out;
}

// --------------------------------------------------------------------------- PE parsing

const std::map<std::uint16_t, const char*> kMachines = {
    {0x0, "UNKNOWN"}, {0x14c, "I386"}, {0x162, "R3000"}, {0x166, "R4000"}, {0x168, "R10000"}, {0x169, "WCEMIPSV2"},
    {0x184, "ALPHA"}, {0x1a2, "SH3"}, {0x1a3, "SH3DSP"}, {0x1a6, "SH4"}, {0x1a8, "SH5"}, {0x1c0, "ARM"}, {0x1c2, "THUMB"},
    {0x1c4, "ARMNT"}, {0x1d3, "AM33"}, {0x1f0, "POWERPC"}, {0x1f1, "POWERPCFP"}, {0x200, "IA64"}, {0x266, "MIPS16"},
    {0x366, "MIPSFPU"}, {0x466, "MIPSFPU16"}, {0x520, "TRICORE"}, {0xebc, "EBC"}, {0x8664, "AMD64"}, {0x9041, "M32R"},
    {0xaa64, "ARM64"}, {0xc0ee, "CEE"}};

struct Flag {
  std::uint32_t bit;
  const char* label;
};

constexpr std::array<Flag, 15> kHeaderChars = {{{0x1, "RELOCS_STRIPPED"}, {0x2, "EXECUTABLE_IMAGE"}, {0x4, "LINE_NUMS_STRIPPED"},
                                                 {0x8, "LOCAL_SYMS_STRIPPED"}, {0x10, "AGGRESSIVE_WS_TRIM"},
                                                 {0x20, "LARGE_ADDRESS_AWARE"}, {0x80, "BYTES_REVERSED_LO"},
                                                 {0x100, "CHARA_32BIT_MACHINE"}, {0x200, "DEBUG_STRIPPED"},
                                                 {0x400, "REMOVABLE_RUN_FROM_SWAP"}, {0x800, "NET_RUN_FROM_SWAP"},
                                                 {0x1000, "SYSTEM"}, {0x2000, "DLL"}, {0x4000, "UP_SYSTEM_ONLY"},
                                                 {0x8000, "BYTES_REVERSED_HI"}}};

const std::map<std::uint16_t, const char*> kSubsystems = {
    {0, "UNKNOWN"}, {1, "NATIVE"}, {2, "WINDOWS_GUI"}, {3, "WINDOWS_CUI"}, {5, "OS2_CUI"}, {7, "POSIX_CUI"},
    {8, "NATIVE_WINDOWS"}, {9, "WINDOWS_CE_GUI"}, {10, "EFI_APPLICATION"}, {11, "EFI_BOOT_SERVICE_DRIVER"},
    {12, "EFI_RUNTIME_DRIVER"}, {13, "EFI_ROM"}, {14, "XBOX"}, {16, "WINDOWS_BOOT_APPLICATION"}};

constexpr std::array<Flag, 11> kDllChars = {{{0x20, "HIGH_ENTROPY_VA"}, {0x40, "DYNAMIC_BASE"}, {0x80, "FORCE_INTEGRITY"},
                                              {0x100, "NX_COMPAT"}, {0x200, "NO_ISOLATION"}, {0x400, "NO_SEH"},
                                              {0x800, "NO_BIND"}, {0x1000, "APPCONTAINER"}, {0x2000, "WDM_DRIVER"},
                                              {0x4000, "GUARD_CF"}, {0x8000, "TERMINAL_SERVER_AWARE"}}};

constexpr std::array<Flag, 20> kSectionChars = {
    {{0x8, "TYPE_NO_PAD"}, {0x20, "CNT_CODE"}, {0x40, "CNT_INITIALIZED_DATA"}, {0x80, "CNT_UNINITIALIZED_DATA"},
     {0x100, "LNK_OTHER"}, {0x200, "LNK_INFO"}, {0x800, "LNK_REMOVE"}, {0x1000, "LNK_COMDAT"}, {0x8000, "GPREL"},
     {0x20000, "MEM_PURGEABLE"}, {0x40000, "MEM_LOCKED"}, {0x80000, "MEM_PRELOAD"}, {0x1000000, "LNK_NRELOC_OVFL"},
     {0x2000000, "MEM_DISCARDABLE"}, {0x4000000, "MEM_NOT_CACHED"}, {0x8000000, "MEM_NOT_PAGED"},
     {0x10000000, "MEM_SHARED"}, {0x20000000, "MEM_EXECUTE"}, {0x40000000, "MEM_READ"}, {0x80000000u, "MEM_WRITE"}}};

constexpr std::array<const char*, 15> kAlignments = {nullptr,          "ALIGN_1BYTES",    "ALIGN_2BYTES",   "ALIGN_4BYTES",
                                                     "ALIGN_8BYTES",   "ALIGN_16BYTES",   "ALIGN_32BYTES",  "ALIGN_64BYTES",
                                                     "ALIGN_128BYTES", "ALIGN_256BYTES",  "ALIGN_512BYTES", "ALIGN_1024BYTES",
                                                     "ALIGN_2048BYTES", "ALIGN_4096BYTES", "ALIGN_8192BYTES"};

struct Section {
  std::string name;  // UTF-8
  std::uint32_t rawSize{0}, rawOffset{0}, vsize{0}, rva{0}, characteristics{0};
  double entropy{0};
  std::vector<std::string> props;
  bool Has(const char* p) const { return std::find(props.begin(), props.end(), p) != props.end(); }
};

struct ImportLib {
  std::string name;
  std::vector<std::string> entries;
};

struct PeFile {
  std::uint16_t machine{0}, characteristics{0}, magic{0}, subsystem{0}, dllCharacteristics{0};
  std::uint32_t timestamp{0}, numberOfSymbols{0}, sizeofCode{0}, sizeofImage{0}, sizeofHeaders{0};
  std::uint8_t majorLinker{0}, minorLinker{0};
  std::uint16_t majorOs{0}, minorOs{0}, majorImage{0}, minorImage{0}, majorSub{0}, minorSub{0};
  std::uint64_t heapCommit{0};
  std::vector<std::pair<std::uint32_t, std::uint32_t>> dirs;  // rva, size
  std::vector<Section> sections;
  std::vector<ImportLib> imports;
  std::vector<std::string> exports;
};

class Reader {
 public:
  explicit Reader(const std::vector<unsigned char>& b) : b_(b) {}
  bool ok() const { return ok_; }
  std::uint8_t U8(long long o) { return Fits(o, 1) ? b_[static_cast<std::size_t>(o)] : Fail<std::uint8_t>(); }
  std::uint16_t U16(long long o) {
    return Fits(o, 2) ? static_cast<std::uint16_t>(b_[o] | (b_[o + 1] << 8)) : Fail<std::uint16_t>();
  }
  std::uint32_t U32(long long o) {
    if (!Fits(o, 4)) return Fail<std::uint32_t>();
    return static_cast<std::uint32_t>(b_[o]) | (static_cast<std::uint32_t>(b_[o + 1]) << 8) |
           (static_cast<std::uint32_t>(b_[o + 2]) << 16) | (static_cast<std::uint32_t>(b_[o + 3]) << 24);
  }
  std::uint64_t U64(long long o) {
    if (!Fits(o, 8)) return Fail<std::uint64_t>();
    return static_cast<std::uint64_t>(U32(o)) | (static_cast<std::uint64_t>(U32(o + 4)) << 32);
  }

 private:
  bool Fits(long long o, long long n) const { return o >= 0 && o + n <= static_cast<long long>(b_.size()); }
  template <typename T>
  T Fail() {
    ok_ = false;
    return T{};
  }
  const std::vector<unsigned char>& b_;
  bool ok_{true};
};

// NUL-terminated latin-1 string at o, as UTF-8. Returns false if o is out of range.
bool CString(const std::vector<unsigned char>& b, long long o, std::size_t limit, std::string* out) {
  if (o < 0 || o >= static_cast<long long>(b.size())) return false;
  const auto start = static_cast<std::size_t>(o);
  auto end = std::min(b.size(), start + limit);
  const auto* first = b.data() + start;
  const auto* nul = static_cast<const unsigned char*>(std::memchr(first, 0, end - start));
  if (nul != nullptr) end = start + static_cast<std::size_t>(nul - first);
  *out = Latin1ToUtf8(std::string_view(reinterpret_cast<const char*>(b.data() + start), end - start));
  return true;
}

double ByteEntropy(const unsigned char* data, std::size_t n) {
  if (n == 0) return 0.0;
  std::array<std::size_t, 256> counts{};
  for (std::size_t i = 0; i < n; ++i) counts[data[i]]++;
  double h = 0.0;
  for (const auto c : counts) {
    if (c) {
      const double p = static_cast<double>(c) / static_cast<double>(n);
      h -= p * std::log2(p);
    }
  }
  return h;
}

std::optional<PeFile> ParsePe(const std::vector<unsigned char>& data) {
  if (data.size() < 64 || data[0] != 'M' || data[1] != 'Z') return std::nullopt;
  Reader r(data);
  const long long lfanew = r.U32(0x3c);
  if (!r.ok() || lfanew + 4 > static_cast<long long>(data.size()) ||
      std::memcmp(data.data() + lfanew, "PE\0\0", 4) != 0) {
    return std::nullopt;
  }
  PeFile pe;
  const long long coff = lfanew + 4;
  pe.machine = r.U16(coff);
  int nsections = r.U16(coff + 2);
  pe.timestamp = r.U32(coff + 4);
  pe.numberOfSymbols = r.U32(coff + 12);
  const long long optSize = r.U16(coff + 16);
  pe.characteristics = r.U16(coff + 18);
  const long long opt = coff + 20;
  pe.magic = r.U16(opt);
  if (!r.ok() || (pe.magic != 0x10b && pe.magic != 0x20b)) return std::nullopt;
  const bool plus = pe.magic == 0x20b;
  pe.majorLinker = r.U8(opt + 2);
  pe.minorLinker = r.U8(opt + 3);
  pe.sizeofCode = r.U32(opt + 4);
  pe.majorOs = r.U16(opt + 40);
  pe.minorOs = r.U16(opt + 42);
  pe.majorImage = r.U16(opt + 44);
  pe.minorImage = r.U16(opt + 46);
  pe.majorSub = r.U16(opt + 48);
  pe.minorSub = r.U16(opt + 50);
  pe.sizeofImage = r.U32(opt + 56);
  pe.sizeofHeaders = r.U32(opt + 60);
  pe.subsystem = r.U16(opt + 68);
  pe.dllCharacteristics = r.U16(opt + 70);
  long long ndirsOff = 0, dirsOff = 0;
  if (plus) {
    pe.heapCommit = r.U64(opt + 96);
    ndirsOff = opt + 108;
    dirsOff = opt + 112;
  } else {
    pe.heapCommit = r.U32(opt + 84);
    ndirsOff = opt + 92;
    dirsOff = opt + 96;
  }
  if (!r.ok()) return std::nullopt;
  auto ndirs = static_cast<long long>(r.U32(ndirsOff));
  if (!r.ok()) return std::nullopt;
  ndirs = std::min<long long>(ndirs, 16);
  for (long long i = 0; i < ndirs; ++i) {
    const auto end = dirsOff + 8 * i + 8;
    if (end > opt + optSize || end > static_cast<long long>(data.size())) break;
    pe.dirs.emplace_back(r.U32(dirsOff + 8 * i), r.U32(dirsOff + 8 * i + 4));
  }

  const long long secOff = opt + optSize;
  nsections = std::min(nsections, 96);
  for (int i = 0; i < nsections; ++i) {
    const long long o = secOff + 40LL * i;
    if (o + 40 > static_cast<long long>(data.size())) break;
    std::size_t nameLen = 0;
    while (nameLen < 8 && data[o + nameLen] != 0) ++nameLen;
    Section s;
    s.name = Latin1ToUtf8(std::string_view(reinterpret_cast<const char*>(data.data() + o), nameLen));
    s.vsize = r.U32(o + 8);
    s.rva = r.U32(o + 12);
    s.rawSize = r.U32(o + 16);
    s.rawOffset = r.U32(o + 20);
    s.characteristics = r.U32(o + 36);
    const std::uint32_t contentSize = (s.vsize != 0 && s.vsize < s.rawSize) ? s.vsize : s.rawSize;
    const auto start = static_cast<unsigned long long>(s.rawOffset);
    if (s.rawSize != 0 && start < data.size()) {
      const auto end = std::min<unsigned long long>(data.size(), start + contentSize);
      s.entropy = ByteEntropy(data.data() + start, static_cast<std::size_t>(end - start));
    }
    for (const auto& f : kSectionChars) {
      if (s.characteristics & f.bit) s.props.emplace_back(f.label);
    }
    const auto align = (s.characteristics >> 20) & 0xF;
    if (align >= 1 && align <= 14) s.props.emplace_back(kAlignments[align]);
    pe.sections.push_back(std::move(s));
  }

  auto rvaToOff = [&pe](std::uint32_t rva, long long* off) {
    for (const auto& s : pe.sections) {
      const std::uint64_t span = std::max(s.vsize, s.rawSize);
      if (s.rva <= rva && static_cast<std::uint64_t>(rva) < static_cast<std::uint64_t>(s.rva) + span) {
        *off = static_cast<long long>(rva) - static_cast<long long>(s.rva) + static_cast<long long>(s.rawOffset);
        return true;
      }
    }
    if (rva < pe.sizeofHeaders) {
      *off = rva;
      return true;
    }
    return false;
  };

  // Imports
  if (pe.dirs.size() > 1 && pe.dirs[1].first != 0 && pe.dirs[1].second != 0) {
    long long o = 0;
    if (rvaToOff(pe.dirs[1].first, &o)) {
      for (int n = 0; n < 4096 && o >= 0 && o + 20 <= static_cast<long long>(data.size()); ++n) {
        Reader d(data);
        const auto oft = d.U32(o), nameRva = d.U32(o + 12), ft = d.U32(o + 16);
        if (oft == 0 && nameRva == 0 && ft == 0) break;
        o += 20;
        long long nameOff = 0;
        ImportLib lib;
        if (!rvaToOff(nameRva, &nameOff) || !CString(data, nameOff, 256, &lib.name)) continue;
        const auto thunk = oft ? oft : ft;
        long long t = 0;
        if (rvaToOff(thunk, &t)) {
          const int step = plus ? 8 : 4;
          for (int k = 0; k < 65536 && t >= 0 && t + step <= static_cast<long long>(data.size()); ++k) {
            Reader tr(data);
            const std::uint64_t value = plus ? tr.U64(t) : tr.U32(t);
            if (value == 0) break;
            t += step;
            const std::uint64_t ordinalFlag = plus ? (1ULL << 63) : (1ULL << 31);
            if (value & ordinalFlag) {
              lib.entries.push_back("ordinal" + std::to_string(value & 0xFFFF));
              continue;
            }
            long long hint = 0;
            std::string fn;
            if (rvaToOff(static_cast<std::uint32_t>(value & 0x7FFFFFFF), &hint) && CString(data, hint + 2, 10000, &fn)) {
              lib.entries.push_back(std::move(fn));
            }
          }
        }
        pe.imports.push_back(std::move(lib));
      }
    }
  }

  // Exports (named only)
  if (!pe.dirs.empty() && pe.dirs[0].first != 0 && pe.dirs[0].second != 0) {
    long long o = 0;
    if (rvaToOff(pe.dirs[0].first, &o)) {
      Reader er(data);
      auto nNames = static_cast<long long>(er.U32(o + 24));
      const auto namesRva = er.U32(o + 32);
      long long namesOff = 0;
      if (er.ok() && rvaToOff(namesRva, &namesOff)) {
        nNames = std::min<long long>(nNames, 65536);
        for (long long i = 0; i < nNames; ++i) {
          Reader nr(data);
          const auto rva = nr.U32(namesOff + 4 * i);
          if (!nr.ok()) break;
          long long off = 0;
          std::string name;
          if (rvaToOff(rva, &off) && CString(data, off, 10000, &name)) pe.exports.push_back(std::move(name));
        }
      }
    }
  }
  return pe;
}

// --------------------------------------------------------------------------- feature blocks

void ByteHistogram(const std::vector<unsigned char>& data, double* out) {
  std::array<std::size_t, 256> counts{};
  for (const auto b : data) counts[b]++;
  const double total = data.empty() ? 1.0 : static_cast<double>(data.size());
  for (int i = 0; i < 256; ++i) out[i] = static_cast<double>(counts[i]) / total;
}

void ByteEntropyHistogram(const std::vector<unsigned char>& data, double* out) {
  constexpr std::size_t kStep = 1024, kWindow = 2048;
  std::array<long long, 256> acc{};
  auto add = [&acc](const unsigned char* block, std::size_t n) {
    std::array<int, 16> c{};
    for (std::size_t i = 0; i < n; ++i) c[block[i] >> 4]++;
    double h = 0.0;
    for (const auto count : c) {
      if (count) {
        const double p = static_cast<double>(count) / static_cast<double>(kWindow);
        h -= p * std::log2(p);
      }
    }
    int bin = static_cast<int>(h * 2 * 2);
    if (bin > 15) bin = 15;
    for (int j = 0; j < 16; ++j) acc[bin * 16 + j] += c[j];
  };
  if (data.size() < kWindow) {
    add(data.data(), data.size());
  } else {
    for (std::size_t start = 0; start + kWindow <= data.size(); start += kStep) add(data.data() + start, kWindow);
  }
  long long total = 0;
  for (const auto v : acc) total += v;
  const double t = total ? static_cast<double>(total) : 1.0;
  for (int i = 0; i < 256; ++i) out[i] = static_cast<double>(acc[i]) / t;
}

bool EqualFoldAscii(const unsigned char* data, const char* pattern, std::size_t n) {
  for (std::size_t i = 0; i < n; ++i) {
    unsigned char a = data[i], b = static_cast<unsigned char>(pattern[i]);
    if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + 32);
    if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + 32);
    if (a != b) return false;
  }
  return true;
}

std::size_t CountNonOverlapping(const std::vector<unsigned char>& data, const char* pattern, bool fold) {
  const auto p = std::strlen(pattern);
  std::size_t n = 0;
  for (std::size_t i = 0; i + p <= data.size();) {
    const bool match = fold ? EqualFoldAscii(data.data() + i, pattern, p) : std::memcmp(data.data() + i, pattern, p) == 0;
    if (match) {
      ++n;
      i += p;
    } else {
      ++i;
    }
  }
  return n;
}

std::size_t CountUrls(const std::vector<unsigned char>& data) {
  std::size_t n = 0;
  for (std::size_t i = 0; i + 7 <= data.size(); ++i) {
    if (!EqualFoldAscii(data.data() + i, "http", 4)) continue;
    std::size_t j = i + 4;
    if (j < data.size() && (data[j] == 's' || data[j] == 'S')) ++j;
    if (j + 3 <= data.size() && std::memcmp(data.data() + j, "://", 3) == 0) {
      ++n;
      i = j + 2;
    }
  }
  return n;
}

void StringFeatures(const std::vector<unsigned char>& data, double* out) {
  std::array<long long, 96> dist{};
  long long numStrings = 0, totalLen = 0, run = 0;
  auto flush = [&](std::size_t end) {
    if (run >= 5) {
      ++numStrings;
      totalLen += run;
      for (std::size_t i = end - static_cast<std::size_t>(run); i < end; ++i) dist[data[i] - 0x20]++;
    }
    run = 0;
  };
  for (std::size_t i = 0; i < data.size(); ++i) {
    if (data[i] >= 0x20 && data[i] <= 0x7f) {
      ++run;
    } else {
      flush(i);
    }
  }
  flush(data.size());
  long long printables = 0;
  for (const auto c : dist) printables += c;
  double avg = 0.0, entropy = 0.0;
  if (numStrings > 0) {
    avg = static_cast<double>(totalLen) / static_cast<double>(numStrings);
    for (const auto c : dist) {
      if (c) {
        const double p = static_cast<double>(c) / static_cast<double>(printables);
        entropy -= p * std::log2(p);
      }
    }
  }
  const double div = printables ? static_cast<double>(printables) : 1.0;
  out[0] = static_cast<double>(numStrings);
  out[1] = avg;
  out[2] = static_cast<double>(printables);
  for (int i = 0; i < 96; ++i) out[3 + i] = static_cast<double>(dist[i]) / div;
  out[99] = entropy;
  out[100] = static_cast<double>(CountNonOverlapping(data, "c:\\", true));
  out[101] = static_cast<double>(CountUrls(data));
  out[102] = static_cast<double>(CountNonOverlapping(data, "HKEY_", false));
  out[103] = static_cast<double>(CountNonOverlapping(data, "MZ", false));
}

double DirPresent(const PeFile& pe, std::size_t i) {
  return pe.dirs.size() > i && pe.dirs[i].first != 0 && pe.dirs[i].second != 0 ? 1.0 : 0.0;
}

template <std::size_t N>
std::vector<Item> Labels(std::uint32_t value, const std::array<Flag, N>& flags) {
  std::vector<Item> out;
  for (const auto& f : flags) {
    if (value & f.bit) out.push_back({f.label, 1.0});
  }
  return out;
}

std::string ToLowerAscii(std::string s) {
  for (auto& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
  }
  return s;
}

}  // namespace

// Python's str.lower() also lowercases non-ASCII letters; DLL names are ASCII in practice.

bool IsPortableExecutable(const std::vector<unsigned char>& bytes) { return ParsePe(bytes).has_value(); }

std::vector<float> ExtractFeatures(const std::vector<unsigned char>& data) {
  std::vector<double> v(kFeatureDim, 0.0);
  ByteHistogram(data, v.data());
  ByteEntropyHistogram(data, v.data() + 256);
  StringFeatures(data, v.data() + 512);
  const auto parsed = ParsePe(data);
  if (!parsed) {
    v[616] = static_cast<double>(data.size());
  } else {
    const auto& pe = *parsed;
    std::size_t imported = 0;
    for (const auto& lib : pe.imports) imported += lib.entries.size();
    const double general[10] = {static_cast<double>(data.size()), static_cast<double>(pe.sizeofImage), DirPresent(pe, 6),
                                static_cast<double>(pe.exports.size()), static_cast<double>(imported), DirPresent(pe, 5),
                                DirPresent(pe, 2), DirPresent(pe, 4), DirPresent(pe, 9),
                                static_cast<double>(pe.numberOfSymbols)};
    std::copy(general, general + 10, v.begin() + 616);

    std::size_t o = 626;
    v[o] = pe.timestamp;
    const auto machine = kMachines.find(pe.machine);
    HashInto(v, o + 1, 10, {{machine == kMachines.end() ? "UNKNOWN" : machine->second, 1.0}});
    HashInto(v, o + 11, 10, Labels(pe.characteristics, kHeaderChars));
    const auto sub = kSubsystems.find(pe.subsystem);
    HashInto(v, o + 21, 10, {{sub == kSubsystems.end() ? "UNKNOWN" : sub->second, 1.0}});
    HashInto(v, o + 31, 10, Labels(pe.dllCharacteristics, kDllChars));
    HashInto(v, o + 41, 10, {{pe.magic == 0x20b ? "PE32_PLUS" : "PE32", 1.0}});
    const double hdr[11] = {static_cast<double>(pe.majorImage),    static_cast<double>(pe.minorImage),
                            static_cast<double>(pe.majorLinker),   static_cast<double>(pe.minorLinker),
                            static_cast<double>(pe.majorOs),       static_cast<double>(pe.minorOs),
                            static_cast<double>(pe.majorSub),      static_cast<double>(pe.minorSub),
                            static_cast<double>(pe.sizeofCode),    static_cast<double>(pe.sizeofHeaders),
                            static_cast<double>(pe.heapCommit)};
    std::copy(hdr, hdr + 11, v.begin() + o + 51);

    o = 688;
    double zero = 0, empty = 0, rx = 0, w = 0;
    std::vector<Item> sizes, ents, vsizes;
    std::string entry;
    bool foundEntry = false;
    for (const auto& s : pe.sections) {
      if (s.rawSize == 0) zero++;
      if (s.name.empty()) empty++;
      if (s.Has("MEM_READ") && s.Has("MEM_EXECUTE")) rx++;
      if (s.Has("MEM_WRITE")) w++;
      if (!foundEntry && s.Has("MEM_EXECUTE")) {
        entry = s.name;
        foundEntry = true;
      }
      sizes.push_back({s.name, static_cast<double>(s.rawSize)});
      ents.push_back({s.name, s.entropy});
      vsizes.push_back({s.name, static_cast<double>(s.vsize)});
    }
    v[o] = static_cast<double>(pe.sections.size());
    v[o + 1] = zero;
    v[o + 2] = empty;
    v[o + 3] = rx;
    v[o + 4] = w;
    HashInto(v, o + 5, 50, sizes);
    HashInto(v, o + 55, 50, ents);
    HashInto(v, o + 105, 50, vsizes);
    std::vector<Item> entryChars;
    for (auto& ch : Utf8Chars(entry)) entryChars.push_back({ch, 1.0});
    HashInto(v, o + 155, 50, entryChars);
    std::vector<Item> entryProps;
    for (const auto& s : pe.sections) {
      if (s.name == entry) {
        for (const auto& p : s.props) entryProps.push_back({p, 1.0});
      }
    }
    HashInto(v, o + 205, 50, entryProps);

    std::set<std::string> libSet;
    std::vector<Item> funcs;
    for (const auto& lib : pe.imports) {
      const auto lower = ToLowerAscii(lib.name);
      libSet.insert(lower);
      for (const auto& e : lib.entries) funcs.push_back({lower + ":" + e, 1.0});
    }
    std::vector<Item> libs;
    for (const auto& name : libSet) libs.push_back({name, 1.0});
    HashInto(v, 943, 256, libs);
    HashInto(v, 943 + 256, 1024, funcs);

    std::vector<Item> exports;
    for (const auto& e : pe.exports) exports.push_back({e, 1.0});
    HashInto(v, 2223, 128, exports);

    for (std::size_t i = 0; i < pe.dirs.size() && i < 15; ++i) {
      v[2351 + 2 * i] = pe.dirs[i].second;
      v[2351 + 2 * i + 1] = pe.dirs[i].first;
    }
  }
  std::vector<float> out(kFeatureDim);
  for (std::size_t i = 0; i < kFeatureDim; ++i) out[i] = static_cast<float>(v[i]);
  return out;
}

// --------------------------------------------------------------------------- model

namespace {

class ByteCursor {
 public:
  explicit ByteCursor(const std::vector<unsigned char>& b) : b_(b) {}
  bool ok() const { return ok_; }
  std::size_t remaining() const { return b_.size() - pos_; }
  template <typename T>
  T Read() {
    T value{};
    if (!ok_ || pos_ + sizeof(T) > b_.size()) {
      ok_ = false;
      return value;
    }
    std::memcpy(&value, b_.data() + pos_, sizeof(T));  // little-endian targets only (x86/x64/ARM64)
    pos_ += sizeof(T);
    return value;
  }
  template <typename T>
  bool ReadArray(std::vector<T>* out, std::uint32_t n) {
    if (!ok_ || static_cast<unsigned long long>(n) * sizeof(T) > remaining()) {
      ok_ = false;
      return false;
    }
    out->resize(n);
    std::memcpy(out->data(), b_.data() + pos_, n * sizeof(T));
    pos_ += n * sizeof(T);
    return true;
  }

 private:
  const std::vector<unsigned char>& b_;
  std::size_t pos_{0};
  bool ok_{true};
};

}  // namespace

std::optional<GbdtModel> GbdtModel::Load(const std::vector<unsigned char>& bytes, std::string* error) {
  auto fail = [error](const char* message) -> std::optional<GbdtModel> {
    if (error != nullptr) *error = message;
    return std::nullopt;
  };
  ByteCursor c(bytes);
  if (bytes.size() < 4 || std::memcmp(bytes.data(), "FGBT", 4) != 0) return fail("not an FGBT model");
  c.Read<std::uint32_t>();
  if (c.Read<std::uint32_t>() != 1) return fail("unsupported model version");
  if (c.Read<std::uint32_t>() != kFeatureDim) return fail("model expects a different feature set");
  const auto treeCount = c.Read<std::uint32_t>();
  GbdtModel model;
  model.thresholds_.fpr1 = c.Read<double>();
  model.thresholds_.fpr01 = c.Read<double>();
  model.thresholds_.fpr001 = c.Read<double>();
  const auto versionLen = c.Read<std::uint32_t>();
  std::vector<char> version;
  if (versionLen > 256 || !c.ReadArray(&version, versionLen)) return fail("bad version string");
  model.version_.assign(version.begin(), version.end());
  if (treeCount > 100000) return fail("too many trees");
  model.trees_.reserve(treeCount);
  for (std::uint32_t i = 0; i < treeCount; ++i) {
    const auto nodes = c.Read<std::uint32_t>();
    const auto leaves = c.Read<std::uint32_t>();
    if (!c.ok() || nodes > 1000000 || leaves == 0 || leaves > 1000001) return fail("bad tree header");
    Tree t;
    if (!c.ReadArray(&t.feature, nodes) || !c.ReadArray(&t.threshold, nodes) || !c.ReadArray(&t.left, nodes) ||
        !c.ReadArray(&t.right, nodes) || !c.ReadArray(&t.leaf, leaves)) {
      return fail("truncated tree");
    }
    for (std::uint32_t n = 0; n < nodes; ++n) {
      if (t.feature[n] < 0 || static_cast<std::size_t>(t.feature[n]) >= kFeatureDim) return fail("bad feature index");
      for (const auto child : {t.left[n], t.right[n]}) {
        const bool okChild = child >= 0 ? (child > static_cast<std::int32_t>(n) && static_cast<std::uint32_t>(child) < nodes)
                                        : static_cast<std::uint32_t>(~child) < leaves;
        if (!okChild) return fail("bad child index");
      }
    }
    model.trees_.push_back(std::move(t));
  }
  if (!c.ok()) return fail("truncated model");
  return model;
}

std::optional<GbdtModel> GbdtModel::LoadFile(const std::wstring& path, std::string* error) {
  std::ifstream in(std::filesystem::path(path), std::ios::binary);
  if (!in) {
    if (error != nullptr) *error = "model file not found";
    return std::nullopt;
  }
  std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return Load(bytes, error);
}

double GbdtModel::Score(const std::vector<float>& x) const {
  double total = 0.0;
  for (const auto& t : trees_) {
    if (t.feature.empty()) {
      total += t.leaf[0];
      continue;
    }
    std::int32_t node = 0;
    while (node >= 0) {  // children always point forward, so this terminates
      node = static_cast<double>(x[t.feature[node]]) <= t.threshold[node] ? t.left[node] : t.right[node];
    }
    total += t.leaf[~node];
  }
  return 1.0 / (1.0 + std::exp(-total));
}

std::optional<double> GbdtModel::ThresholdFor(const std::wstring& sensitivity) const {
  if (sensitivity == L"cautious") return thresholds_.fpr001;
  if (sensitivity == L"balanced") return thresholds_.fpr01;
  if (sensitivity == L"aggressive") return thresholds_.fpr1;
  if (sensitivity == L"paranoid") return thresholds_.fpr1 * 0.8;
  return std::nullopt;
}

namespace {
std::mutex& DefaultPathMutex() {
  static std::mutex m;
  return m;
}
std::wstring& DefaultPathValue() {
  static std::wstring value;
  return value;
}
}  // namespace

void SetDefaultModelPath(const std::wstring& path) {
  std::lock_guard lock(DefaultPathMutex());
  DefaultPathValue() = path;
}

std::wstring DefaultModelPath() {
  {
    std::lock_guard lock(DefaultPathMutex());
    if (!DefaultPathValue().empty()) return DefaultPathValue();
  }
  // Tools such as the scanner CLI can point at a model without the service.
  if (const char* env = std::getenv("FENRIR_ML_MODEL"); env != nullptr && *env != '\0') {
    const std::string value(env);
    return std::wstring(value.begin(), value.end());
  }
  return {};
}

std::shared_ptr<const GbdtModel> LoadCached(const std::wstring& path, std::string* error) {
  static std::mutex mutex;
  static std::wstring loadedPath;
  static std::shared_ptr<const GbdtModel> model;
  static std::filesystem::file_time_type loadedStamp{};
  std::lock_guard lock(mutex);
  std::error_code ec;
  const auto stamp = std::filesystem::last_write_time(std::filesystem::path(path), ec);
  if (ec) {
    if (error != nullptr) *error = "model not installed";
    return nullptr;
  }
  if (!model || loadedPath != path || stamp != loadedStamp) {
    auto loaded = GbdtModel::LoadFile(path, error);
    if (!loaded) return nullptr;
    model = std::make_shared<const GbdtModel>(std::move(*loaded));
    loadedPath = path;
    loadedStamp = stamp;
  }
  return model;
}

MlVerdict ScoreFileBytes(const std::vector<unsigned char>& bytes, const std::wstring& modelPath) {
  std::string error;
  const auto model = LoadCached(modelPath, &error);
  if (!model) return MlVerdict{.score = 0, .evaluated = false, .reason = error};
  if (!IsPortableExecutable(bytes)) return MlVerdict{.score = 0, .evaluated = false, .reason = "not a PE file"};
  return MlVerdict{.score = model->Score(ExtractFeatures(bytes)), .evaluated = true, .reason = {}};
}

}  // namespace antivirus::agent::ml
