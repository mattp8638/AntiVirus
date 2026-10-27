#pragma once

// Records why the agent crashed (exception code, faulting module and offset, and a short stack of
// module+offset frames) to <install>\runtime\crash-last.txt, so the restarted agent can send it to the console
// instead of the crash only being visible in Windows Event Viewer.

#include <filesystem>
#include <string>

namespace antivirus::agent::crash {

// Installs the handler. Call once, early, in the service process.
void Install();
// The last crash report as a JSON object (and deletes it), or empty when there was none.
std::wstring TakeLastReport();

}  // namespace antivirus::agent::crash
