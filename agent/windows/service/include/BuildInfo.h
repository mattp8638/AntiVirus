#pragma once

// FENRIR_BUILD_ID fingerprints the agent source. The cloud image build stamps it (cmake -DFENRIR_BUILD_ID=...);
// agents compare it with the server's build and upgrade themselves when they differ. Local builds are "dev"
// and never self-update.
#ifndef FENRIR_BUILD_ID
#define FENRIR_BUILD_ID "dev"
#endif

namespace antivirus::agent {
inline constexpr wchar_t kFenrirBuildId[] = L"" FENRIR_BUILD_ID;
}
