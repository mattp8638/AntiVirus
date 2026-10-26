#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::agent {

// Packs every regular file under root into an uncompressed POSIX ustar archive (paths relative to
// root, '/' separators). Files that would push the archive past maxBytes, or whose names do not fit
// the ustar header, are left out and listed in *skipped (if given).
std::string BuildTarArchive(const std::filesystem::path& root, std::size_t maxBytes,
                            std::vector<std::string>* skipped = nullptr);

}  // namespace antivirus::agent
