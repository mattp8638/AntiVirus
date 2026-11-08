#pragma once

#include <optional>
#include <string_view>

namespace antivirus::agent {

// Find the first matching string field, including nested fields as supported by
// the existing readers. Return raw contents for each caller's existing decoder.
// This is a field extractor, not a validator for the whole document.
inline std::optional<std::string_view> FindRawJsonStringField(std::string_view json, std::string_view key) {
  const auto stringEnd = [&](std::size_t openingQuote) {
    for (auto pos = openingQuote + 1; pos < json.size(); ++pos) {
      if (json[pos] == '"') return pos;
      if (json[pos] == '\\') {
        if (++pos == json.size()) break;
      }
    }
    return std::string_view::npos;
  };

  std::size_t pos = 0;
  while ((pos = json.find('"', pos)) != std::string_view::npos) {
    const auto end = stringEnd(pos);
    if (end == std::string_view::npos) break;
    const auto token = json.substr(pos + 1, end - pos - 1);
    pos = end + 1;
    if (token != key) continue;
    const auto colon = json.find_first_not_of(" \t\r\n", pos);
    if (colon == std::string_view::npos || json[colon] != ':') continue;
    const auto opening = json.find_first_not_of(" \t\r\n", colon + 1);
    if (opening == std::string_view::npos || json[opening] != '"') continue;
    const auto closing = stringEnd(opening);
    if (closing == std::string_view::npos) break;
    return json.substr(opening + 1, closing - opening - 1);
  }
  return std::nullopt;
}

}  // namespace antivirus::agent
