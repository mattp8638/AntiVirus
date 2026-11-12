#include "ZipReader.h"

#include <algorithm>
#include <cstring>

namespace antivirus::agent::zipreader {
namespace {

// ------------------------------------------------------------------------------------------------ DEFLATE
// After Mark Adler's puff.c: canonical Huffman decoding a bit at a time. Small and strict rather than fast.

constexpr int kMaxBits = 15;

struct BitReader {
  const unsigned char* data;
  std::size_t size;
  std::size_t pos{0};
  std::uint32_t buffer{0};
  int count{0};
  bool failed{false};

  std::uint32_t Bits(int need) {
    while (count < need) {
      if (pos >= size) {
        failed = true;
        return 0;
      }
      buffer |= static_cast<std::uint32_t>(data[pos++]) << count;
      count += 8;
    }
    const auto value = buffer & ((1u << need) - 1u);
    buffer >>= need;
    count -= need;
    return value;
  }
};

struct Huffman {
  std::uint16_t counts[kMaxBits + 1]{};
  std::uint16_t symbols[320]{};
};

// False when the code is over-subscribed (incomplete codes are allowed, as zlib allows a single distance code).
bool Build(Huffman& h, const std::uint8_t* lengths, int n) {
  std::fill(std::begin(h.counts), std::end(h.counts), 0);
  for (int i = 0; i < n; ++i) ++h.counts[lengths[i]];
  if (h.counts[0] == n) return true;
  int left = 1;
  for (int len = 1; len <= kMaxBits; ++len) {
    left <<= 1;
    left -= h.counts[len];
    if (left < 0) return false;
  }
  std::uint16_t offsets[kMaxBits + 1]{};
  for (int len = 1; len < kMaxBits; ++len) offsets[len + 1] = static_cast<std::uint16_t>(offsets[len] + h.counts[len]);
  for (int i = 0; i < n; ++i) {
    if (lengths[i] != 0) h.symbols[offsets[lengths[i]]++] = static_cast<std::uint16_t>(i);
  }
  return true;
}

int Decode(BitReader& in, const Huffman& h) {
  int code = 0, first = 0, index = 0;
  for (int len = 1; len <= kMaxBits; ++len) {
    code |= static_cast<int>(in.Bits(1));
    if (in.failed) return -1;
    const int count = h.counts[len];
    if (code - count < first) return h.symbols[index + (code - first)];
    index += count;
    first += count;
    first <<= 1;
    code <<= 1;
  }
  return -1;
}

constexpr std::uint16_t kLengthBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                           31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr std::uint8_t kLengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr std::uint16_t kDistanceBase[30] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                                             193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
constexpr std::uint8_t kDistanceExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

bool Codes(BitReader& in, std::vector<unsigned char>& out, std::size_t maxOut, const Huffman& lengths, const Huffman& distances) {
  for (;;) {
    int symbol = Decode(in, lengths);
    if (symbol < 0) return false;
    if (symbol < 256) {
      if (out.size() >= maxOut) return false;
      out.push_back(static_cast<unsigned char>(symbol));
      continue;
    }
    if (symbol == 256) return true;
    symbol -= 257;
    if (symbol >= 29) return false;
    const std::size_t length = kLengthBase[symbol] + in.Bits(kLengthExtra[symbol]);
    const int distanceSymbol = Decode(in, distances);
    if (distanceSymbol < 0 || distanceSymbol >= 30) return false;
    const std::size_t distance = kDistanceBase[distanceSymbol] + in.Bits(kDistanceExtra[distanceSymbol]);
    if (in.failed || distance > out.size() || out.size() + length > maxOut) return false;
    const auto from = out.size() - distance;
    for (std::size_t i = 0; i < length; ++i) out.push_back(out[from + i]);  // may overlap: copy a byte at a time
  }
}

bool Stored(BitReader& in, std::vector<unsigned char>& out, std::size_t maxOut) {
  in.buffer = 0;  // skip to the byte boundary (fewer than 8 bits are ever buffered)
  in.count = 0;
  if (in.pos + 4 > in.size) return false;
  const std::size_t length = in.data[in.pos] | (in.data[in.pos + 1] << 8);
  const std::size_t inverse = in.data[in.pos + 2] | (in.data[in.pos + 3] << 8);
  in.pos += 4;
  if (length != (~inverse & 0xFFFFu) || in.pos + length > in.size || out.size() + length > maxOut) return false;
  out.insert(out.end(), in.data + in.pos, in.data + in.pos + length);
  in.pos += length;
  return true;
}

bool Fixed(BitReader& in, std::vector<unsigned char>& out, std::size_t maxOut) {
  static Huffman lengths, distances;
  static const bool built = [] {
    std::uint8_t l[288];
    int i = 0;
    for (; i < 144; ++i) l[i] = 8;
    for (; i < 256; ++i) l[i] = 9;
    for (; i < 280; ++i) l[i] = 7;
    for (; i < 288; ++i) l[i] = 8;
    Build(lengths, l, 288);
    std::uint8_t d[30];
    std::fill(std::begin(d), std::end(d), 5);
    Build(distances, d, 30);
    return true;
  }();
  (void)built;
  return Codes(in, out, maxOut, lengths, distances);
}

bool Dynamic(BitReader& in, std::vector<unsigned char>& out, std::size_t maxOut) {
  static constexpr std::uint8_t kOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
  const int literalCount = static_cast<int>(in.Bits(5)) + 257;
  const int distanceCount = static_cast<int>(in.Bits(5)) + 1;
  const int codeCount = static_cast<int>(in.Bits(4)) + 4;
  if (in.failed || literalCount > 286 || distanceCount > 30) return false;
  std::uint8_t lengths[320]{};
  for (int i = 0; i < codeCount; ++i) lengths[kOrder[i]] = static_cast<std::uint8_t>(in.Bits(3));
  Huffman codeLengths;
  if (in.failed || !Build(codeLengths, lengths, 19)) return false;
  int index = 0;
  while (index < literalCount + distanceCount) {
    int symbol = Decode(in, codeLengths);
    if (symbol < 0) return false;
    if (symbol < 16) {
      lengths[index++] = static_cast<std::uint8_t>(symbol);
      continue;
    }
    std::uint8_t value = 0;
    int repeat = 0;
    if (symbol == 16) {
      if (index == 0) return false;
      value = lengths[index - 1];
      repeat = 3 + static_cast<int>(in.Bits(2));
    } else if (symbol == 17) {
      repeat = 3 + static_cast<int>(in.Bits(3));
    } else {
      repeat = 11 + static_cast<int>(in.Bits(7));
    }
    if (in.failed || index + repeat > literalCount + distanceCount) return false;
    while (repeat-- > 0) lengths[index++] = value;
  }
  if (lengths[256] == 0) return false;  // no end-of-block code
  Huffman literalCodes, distanceCodes;
  if (!Build(literalCodes, lengths, literalCount) || !Build(distanceCodes, lengths + literalCount, distanceCount)) return false;
  return Codes(in, out, maxOut, literalCodes, distanceCodes);
}

std::uint16_t U16(const std::vector<unsigned char>& b, std::size_t at) {
  return static_cast<std::uint16_t>(b[at] | (b[at + 1] << 8));
}
std::uint32_t U32(const std::vector<unsigned char>& b, std::size_t at) {
  return static_cast<std::uint32_t>(b[at]) | (static_cast<std::uint32_t>(b[at + 1]) << 8) |
         (static_cast<std::uint32_t>(b[at + 2]) << 16) | (static_cast<std::uint32_t>(b[at + 3]) << 24);
}

}  // namespace

bool Inflate(const unsigned char* data, std::size_t size, std::vector<unsigned char>& out, std::size_t maxOut) {
  BitReader in{data, size};
  bool last = false;
  do {
    last = in.Bits(1) != 0;
    const auto type = in.Bits(2);
    if (in.failed) return false;
    bool ok = false;
    if (type == 0) {
      ok = Stored(in, out, maxOut);
    } else if (type == 1) {
      ok = Fixed(in, out, maxOut);
    } else if (type == 2) {
      ok = Dynamic(in, out, maxOut);
    }
    if (!ok || in.failed) return false;
  } while (!last);
  return true;
}

bool List(const std::vector<unsigned char>& b, std::vector<Entry>& entries, std::size_t maxEntries) {
  entries.clear();
  if (b.size() < 22) return false;
  // End of central directory: the last record with its signature, within the 64 KiB comment window.
  std::size_t eocd = std::string::npos;
  const std::size_t lowest = b.size() > 22 + 65535 ? b.size() - 22 - 65535 : 0;
  for (std::size_t at = b.size() - 22 + 1; at-- > lowest;) {
    if (U32(b, at) == 0x06054B50u) {
      eocd = at;
      break;
    }
  }
  if (eocd == std::string::npos) return false;
  const auto total = U16(b, eocd + 10);
  const auto directoryOffset = U32(b, eocd + 16);
  if (total == 0xFFFF || directoryOffset == 0xFFFFFFFFu) return false;  // ZIP64
  std::size_t at = directoryOffset;
  for (unsigned i = 0; i < total && entries.size() < maxEntries; ++i) {
    if (at + 46 > b.size() || U32(b, at) != 0x02014B50u) return !entries.empty();
    Entry entry;
    const auto flags = U16(b, at + 8);
    entry.method = U16(b, at + 10);
    entry.compressedSize = U32(b, at + 20);
    entry.uncompressedSize = U32(b, at + 24);
    const auto nameLength = U16(b, at + 28), extraLength = U16(b, at + 30), commentLength = U16(b, at + 32);
    entry.localHeaderOffset = U32(b, at + 42);
    if (at + 46 + nameLength > b.size()) return !entries.empty();
    entry.name.assign(reinterpret_cast<const char*>(b.data() + at + 46), nameLength);
    entry.encrypted = (flags & 1u) != 0;
    entry.directory = !entry.name.empty() && (entry.name.back() == '/' || entry.name.back() == '\\');
    entries.push_back(std::move(entry));
    at += 46ULL + nameLength + extraLength + commentLength;
  }
  return true;
}

bool Extract(const std::vector<unsigned char>& b, const Entry& entry, std::vector<unsigned char>& out, std::size_t maxOut) {
  out.clear();
  if (entry.encrypted || entry.directory || (entry.method != 0 && entry.method != 8)) return false;
  const std::size_t local = entry.localHeaderOffset;
  if (local + 30 > b.size() || U32(b, local) != 0x04034B50u) return false;
  const std::size_t start = local + 30 + U16(b, local + 26) + U16(b, local + 28);
  if (start > b.size() || entry.compressedSize > b.size() - start) return false;
  const auto* data = b.data() + start;
  if (entry.method == 0) {
    if (entry.compressedSize > maxOut) return false;
    out.assign(data, data + entry.compressedSize);
    return true;
  }
  out.reserve(std::min<std::size_t>(entry.uncompressedSize, maxOut));
  return Inflate(data, entry.compressedSize, out, maxOut);
}

}  // namespace antivirus::agent::zipreader
