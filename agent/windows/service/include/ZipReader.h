#pragma once

// Reading zip archives for scanning: the central directory, and each member's bytes (stored or DEFLATE).
// Portable (no Windows APIs) so it is unit-tested on any platform. ZIP64 archives are not read.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace antivirus::agent::zipreader {

// Raw DEFLATE (RFC 1951). False on corrupt data, or when the output would pass maxOut bytes.
bool Inflate(const unsigned char* in, std::size_t inSize, std::vector<unsigned char>& out, std::size_t maxOut);

struct Entry {
  std::string name;  // as stored (UTF-8 or the archive's code page)
  std::uint16_t method{0};  // 0 stored, 8 deflate; anything else is not extracted
  std::uint32_t compressedSize{0};
  std::uint32_t uncompressedSize{0};
  std::uint32_t localHeaderOffset{0};
  bool encrypted{false};
  bool directory{false};
};

// Reads the central directory. False when there is none (not a zip, truncated, ZIP64).
bool List(const std::vector<unsigned char>& archive, std::vector<Entry>& entries, std::size_t maxEntries = 10000);

// A member's content. False when it is encrypted, uses another method, is damaged or would pass maxOut bytes.
bool Extract(const std::vector<unsigned char>& archive, const Entry& entry, std::vector<unsigned char>& out, std::size_t maxOut);

}  // namespace antivirus::agent::zipreader
