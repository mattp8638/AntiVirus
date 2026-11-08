#pragma once

#include <regex>

namespace antivirus::agent {

// The packaged MinGW agent uses libstdc++. Its default depth-first matcher can
// exhaust a Windows thread stack on a single long field. These fixed patterns
// contain no backreferences and can use the iterative per-character executor.
inline constexpr auto kAgentRegexOptions = std::regex_constants::ECMAScript
#ifdef __GLIBCXX__
    | std::regex_constants::__polynomial
#endif
    ;

}  // namespace antivirus::agent
