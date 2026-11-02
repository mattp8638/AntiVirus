# Agent Architecture (Rust Core + C++ Capabilities)

## Overview
This document defines the Windows-first, multi-service endpoint agent designed for SIEM, EDR, vulnerability management, compliance auditing, and RMM. The agent assumes hostile environments and audit scrutiny: authority is centralised in Rust, unsafe capabilities are isolated in C++.

## Responsibility Split (Non-negotiable)

### Rust (Agent Core, “the brain”)
Rust is responsible for:
- Agent identity and cryptographic trust
- Secure communication (mTLS, certificate pinning)
- Policy ingestion and validation
- Module orchestration
- IPC validation and routing
- Evidence packaging and hashing
- Compliance self-audit logic
- Update lifecycle
- Rate limiting and safety controls
- All parsing of untrusted input

Rust never:
- Hooks the kernel
- Injects input
- Reads ETW directly
- Executes OS commands directly

If it can crash, hang, or be exploited, it belongs in Rust.

### C++ (Capability Providers, “the hands”)
C++ is responsible only for:
- ETW subscription and decoding
- Process, file, registry observation
- Screen capture and input injection
- Remote session primitives
- Patch API invocation
- Script execution sandboxing
- File-system operations
- Task Manager primitives

C++ never:
- Decides whether something should run
- Parses JSON or policies
- Talks to the backend
- Stores long-term state
- Makes compliance claims

C++ modules are dumb, fast, and replaceable.

## Process Model (Windows-first)
You want multiple services, not threads.

Required services:
- **agent-core.exe** (Rust, LocalSystem)
- **agent-sensor.exe** (C++, LocalSystem)
- **agent-exec.exe** (C++, LocalSystem)
- **agent-user-helper.exe** (C++/Rust, User context)
- **agent-watchdog.exe** (Rust, minimal)

Each binary:
- Has its own ACLs
- Has a narrow IPC surface
- Can be restarted independently

## IPC Design (Critical)

### Transport
- Named pipes with strict ACLs
- Only agent-core can connect
- No shared memory without versioned schemas
- No ad-hoc strings

### Message format
- Protobuf (or FlatBuffers) is mandatory, not JSON
- C++ uses generated headers; Rust uses generated types

Rust validates everything:
- Message version
- Field presence
- Size limits
- Rate limits

If validation fails, the message is dropped and logged.

See `ipc/proto/agent_ipc.proto` for canonical schemas.

## Sensor Subsystem (C++ → Rust → SIEM/EDR)

### C++ Sensor responsibilities
- Subscribe to ETW providers
- Decode Windows Event Logs
- Capture process start/stop, command lines, file writes, registry changes, network connections
- Emit facts, not conclusions

Example C++ output struct:
```cpp
struct ProcessStart {
    uint32_t pid;
    uint32_t ppid;
    wchar_t image_path[260];
    wchar_t command_line[4096];
    FILETIME timestamp;
};
```

### Rust Core responsibilities
- Normalise sensor data
- Attach asset identity
- Forward to SIEM (raw + normalised)
- Forward to EDR engine (local rules)
- Persist minimal rolling buffers
- Hash and timestamp everything

## EDR Engine (Rust-first)
The EDR engine lives in Rust, not C++.

Why:
- Behavioural logic
- Rule evaluation
- State tracking
- Confidence scoring
- Evidence selection

Flow:
1. Sensor event arrives
2. Rust EDR engine evaluates rules
3. Detection object created
4. If allowed, Rust issues a signed command to C++ execution service
5. Evidence captured
6. Detection sent to SIEM and PSA

C++ never decides containment.

## RMM Execution (C++ Actuator, Rust Control)

Execution authority chain:
**PSA → Rust Core → Signed Command → C++ Exec → Result → Rust → PSA**

If the Rust core does not sign it, it does not happen.

### C++ Exec capabilities
- Run scripts (PowerShell, CMD)
- Apply patches
- Install/uninstall software
- Control services
- Manage processes
- File explorer primitives
- Remote control primitives

### Rust safety controls
- Scope validation
- Asset binding
- Time windows
- Rate limits
- Rollback awareness
- Evidence capture

Every execution produces:
- Stdout
- Stderr
- Exit code
- File deltas (if applicable)
- Timestamps
- Hashes

## Compliance Self-Audit (Rust)
This is pure Rust logic.

Why:
- Deterministic checks
- Strong typing of controls
- Evidence bundling
- No OS hooks required

Example checks:
- Firewall enabled
- Disk encryption active
- Secure boot enabled
- AV/EDR running
- Patch level within policy
- Logging enabled

Each check returns:
- Boolean result
- Evidence artefact (file, command output)
- Timestamp
- Control reference

Rust sends assertions + evidence, never “compliant”.

## Update Pipeline (Rust-controlled)
Update flow:
1. Backend publishes signed manifest
2. Rust core verifies signature
3. Rust stages update
4. Rust instructs watchdog
5. Components restart one by one
6. Health verified
7. Rollback if failure

C++ binaries never self-update.

## Build System (Practical)

### Rust
- Cargo
- `tokio` for async
- `rustls` for TLS
- `serde` for config
- `prost` (or FlatBuffers) for IPC

### C++
- MSVC toolchain
- CMake
- `/guard:cf`, `/GS`, `/sdl`
- ASLR enabled
- Stack protection enforced

### CI
- Build Rust first
- Generate IPC schemas
- Build C++ against them
- Sign everything
- Produce versioned artefacts

## Why this holds under pressure
This design survives because:
- Unsafe code is isolated
- Authority is centralised
- Evidence is first-class
- Policy is never local
- Updates are controlled
- Audits are explainable
- Bugs have limited blast radius

Most commercial agents fail because they blur these lines.

You are not doing that.

## Reality check
This is not the easiest way to build an agent.
It is the way that:
- Does not rot
- Does not panic under audits
- Does not become unmaintainable
- Does not require hero developers forever

You are designing this as if you expect it to be attacked, misunderstood, and audited.
That is exactly the right assumption.
