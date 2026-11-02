# Agent

Scope: Multi-service Windows-first endpoint agent split across Rust (core control plane) and C++ (capability providers).

## Responsibilities

### Rust (Agent Core, “the brain”)
Rust is responsible for:
- Agent identity and cryptographic trust.
- Secure communication (mTLS, certificate pinning).
- Policy ingestion and validation.
- Module orchestration and IPC routing.
- Evidence packaging, hashing, and compliance self-audits.
- Update lifecycle, rate limiting, and safety controls.
- All parsing of untrusted input.

Rust never:
- Hooks the kernel.
- Injects input.
- Reads ETW directly.
- Executes OS commands directly.

### C++ (Capability Providers, “the hands”)
C++ is responsible only for:
- ETW subscription/decoding and Windows event capture.
- Process, file, registry, and network observation.
- Screen capture and input injection.
- Script execution sandboxing and patch API invocation.
- File-system operations and Task Manager primitives.

C++ never:
- Decides whether something should run.
- Parses JSON or policies.
- Talks to the backend.
- Stores long-term state.
- Makes compliance claims.

## Services (Windows-first)
- **agent-core.exe** (Rust, LocalSystem)
- **agent-sensor.exe** (C++, LocalSystem)
- **agent-exec.exe** (C++, LocalSystem)
- **agent-user-helper.exe** (C++/Rust, User context)
- **agent-watchdog.exe** (Rust, minimal)

Each service has its own ACLs, narrow IPC surface, and can be restarted independently.

## Runtime configuration
- `config/agent_config.ini` is loaded from the executable directory by default (override with `AGENT_CONFIG_PATH`).
- `config/agent.env` provides a starter environment file for shared key and identity defaults.
- `AGENT_IPC_PIPE` overrides the named pipe endpoint used by Rust core and C++ providers.
- `AGENT_POLICY_PATH` or `AGENT_POLICY_JSON` provides the signed policy bundle (including time window + signature metadata) the Rust core validates before routing.
- `AGENT_POLICY_SIGNING_KEY` provides the shared signing key for policy HMAC validation; `AGENT_POLICY_SIGNING_KEY_ID` pins the expected key ID.
- `AGENT_POLICY_ALLOW_UNSIGNED=true` explicitly allows unsigned policy bundles for development only.

For architecture details, see `docs/agent-architecture.md`.
Policy bundle schema and signing details live in `docs/policy-bundle.md`.
