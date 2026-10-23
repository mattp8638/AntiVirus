# Phase 1 hardening

Development starts at ef53f8b5610a18fc6b0e261b5dfac96d4b296ae8 on a new branch. No agent protocol or existing module is replaced.

## Implemented

- Event processing claims each batch in a single conditional database UPDATE. Ownership, handler savepoints and outcomes share a transaction. A rollback releases ownership and rolls back handler database effects. External effects still require idempotent handlers.
- Rate limits use hashed keys and database-backed sliding windows. A per-bucket write lock serializes checks. Attempts commit independently of authentication failure. Restarting a worker preserves limits; database failure does not fall back to local memory.
- Reauthentication proofs are bound to the exact bearer session and an opaque HMAC of current password, MFA state, role, tenant and active status. Newly issued sessions have random IDs. Existing session tokens remain accepted. MFA resets require fresh proof and cannot let an MSP admin reset platform-admin MFA.
- Vault keys are validated before startup migrations. Production Compose requires a persistent explicit key. Environment and mounted-key-file configurations remain supported. Old keys can decrypt during rotation; derived legacy-key acceptance can be disabled after rotation succeeds.
- Database migrations have an ordered version ledger and a transaction-wide lock (SQLite immediate transaction / PostgreSQL advisory lock). Version 1 adopts legacy tables and adds nullable columns without deleting rows. Version 2 introduces shared rate-limit buckets. Unknown newer versions fail startup. Future upgrades must append versions rather than alter applied migrations.

## Operator procedure

Back up the database and vault key material before upgrading. Startup applies the additive migrations. Retain the original signing secret when migrating values encrypted with its derived vault key. Configure a fresh independent FENRIR_VAULT_KEY (base64 of 32 random bytes), retain old explicit keys in FENRIR_VAULT_OLD_KEYS, and invoke the existing audited rotation endpoint using fresh password/MFA reauthentication. Verify failed=0 before removing old keys or setting FENRIR_VAULT_ALLOW_DERIVED_LEGACY=false. Keep secure offline copies of required keys for backup recovery. Changing the signing secret logs users out; do not rely on it as the persistent vault master key.

## Validation and remaining scope

Regression tests cover concurrent SQLite event workers and rate-limit checks, rollback recovery, rate-limit persistence, legacy database preservation and repeatable upgrades, proof binding and invalidation, malformed token expiry, explicit vault key validation and legacy key retirement. Existing cloud tests cover agent API contracts and existing modules. PostgreSQL and agent build validation use the existing platform CI workflow; local SQLite results do not establish PostgreSQL validation.

The six MSP expansion modules remain subsequent work: Documentation & Credential Vault, Microsoft 365 Management, Network Monitoring, SIEM/XDR improvements, GRC/ISMS, and Backup & Disaster Recovery. This change supplies shared foundations; it does not claim those modules are implemented.
