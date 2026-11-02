# Agent IPC & Message Schemas

All agent services communicate via:
- Named pipes with strict ACLs
- Versioned, typed schemas (Protobuf or FlatBuffers)
- No raw JSON blobs

## Transport rules
- Only agent-core can connect to provider services
- No shared memory without explicit, versioned schemas
- All payloads include size limits and schema versions

## Message types (examples)
- SensorEvent
- ExecutionCommand
- ExecutionResult
- EvidencePackage
- HealthHeartbeat
- ComplianceAssertion

Canonical schemas live in `proto/agent_ipc.proto`. C++ and Rust consume generated code, never handwritten structs.
