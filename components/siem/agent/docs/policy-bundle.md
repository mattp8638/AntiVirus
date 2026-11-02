# Policy Bundles (Rust Core)

Policy bundles are signed, time-scoped envelopes that the Rust core validates before routing commands or telemetry. They are JSON documents validated against strict schema rules and optional HMAC-SHA256 signatures.

## Required fields
- `schema_version` (u32): monotonically increasing schema version.
- `version` (string): human-readable policy version label.
- `issued_at_unix_time_ms` (u64): policy issuance time (milliseconds since Unix epoch).
- `expires_at_unix_time_ms` (u64): policy expiry time (milliseconds since Unix epoch).
- `signing_key_id` (string): identifier for the signing key.
- `signature` (string): base64-encoded HMAC-SHA256 signature.
- `execution` (object):
  - `allowed_actions` (array of strings, sorted, unique, lowercase, `-` or `_`).
  - `max_arguments` (usize): maximum argument count.
  - `max_argument_length` (usize): maximum length per argument.
- `telemetry_streams` (array of strings, sorted and unique).

## Environment variables
- `AGENT_POLICY_PATH`: path to JSON policy bundle.
- `AGENT_POLICY_JSON`: inline JSON policy bundle.
- `AGENT_POLICY_SIGNING_KEY`: shared secret for HMAC validation.
- `AGENT_POLICY_SIGNING_KEY_ID`: expected signing key identifier.
- `AGENT_POLICY_ALLOW_UNSIGNED=true`: allow unsigned bundles (development only).

## Signing payload (deterministic)
The HMAC signature is computed over the following pipe-delimited payload, in order:

```
schema_version=<schema_version>
|version=<version>
|issued_at=<issued_at_unix_time_ms>
|expires_at=<expires_at_unix_time_ms>
|signing_key_id=<signing_key_id>
|allowed_actions=<comma-separated allowed_actions>
|max_arguments=<max_arguments>
|max_argument_length=<max_argument_length>
|telemetry_streams=<comma-separated telemetry_streams>
```

Both `allowed_actions` and `telemetry_streams` must be sorted lexicographically to ensure stable signing.

## Example policy bundle
```json
{
  "schema_version": 1,
  "version": "policy-2025-01-01",
  "issued_at_unix_time_ms": 1735689600000,
  "expires_at_unix_time_ms": 1767225600000,
  "signing_key_id": "policy-key-01",
  "signature": "BASE64_HMAC_SHA256_SIGNATURE",
  "execution": {
    "allowed_actions": [
      "patch-apply",
      "script-run"
    ],
    "max_arguments": 8,
    "max_argument_length": 256
  },
  "telemetry_streams": [
    "agent",
    "sensor"
  ]
}
```

## Why this approach
Signed, time-bound policies ensure the Rust core is the sole authority for execution scope and telemetry routing, enforcing least privilege before any C++ capability providers are engaged. Deterministic signing payloads make verification reproducible across environments without embedding sensitive secrets in the policy itself.
