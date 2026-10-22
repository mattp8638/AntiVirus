# Identifier Schema Guidance

This document expands canonical identifier usage across the platform.

## Canonical IDs
- tenant_id
- asset_id
- identity_id
- event_id

## Generation Rules
- IDs are created in core-services or data-model layers only.
- Use ULID or UUIDv7 for sortable, globally unique identifiers.
- Agent-generated IDs must be signed and verified by core-services.

## Transport Encoding
- IDs are transmitted as lowercase strings in JSON payloads.
- Never embed raw identifiers in logs without redaction.

