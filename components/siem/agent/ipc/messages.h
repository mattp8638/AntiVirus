// Legacy IPC header retained for reference only.
// Canonical schemas now live in ipc/proto/agent_ipc.proto and are compiled
// into Rust and C++ generated types. Do not handcraft structs here.
#pragma once

namespace agent_ipc {
    static constexpr unsigned int kSchemaVersion = 1;
}
