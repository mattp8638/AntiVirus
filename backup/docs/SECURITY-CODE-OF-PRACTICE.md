# Mapping to the NCSC Software Security Code of Practice

How Fenrir-Backup meets each provision of the UK Software Security Code of
Practice (DSIT / NCSC, 2025). Provision numbers follow the published Code;
check them against the current version when updating this file.

Status: **Done** (in place and enforced), **Partial**, or **Planned** (with
the phase or task that delivers it). This file is reviewed at every release.

## Principle 1 — Secure design and development

| # | Provision | How | Status |
|---|---|---|---|
| 1.1 | Follow an established secure development framework | Practices aligned with NIST SSDF (SP 800-218): design note before code for every phase (`docs/design/`), tests before code, reviewed pull requests, CI gates below. | Partial — branch protection and mandatory review to be enabled on `main` |
| 1.2 | Understand composition; assess third-party risk | Every dependency and licence listed in `THIRD_PARTY.md`; `cargo deny` enforces licence and source policy; `cargo audit` checks RustSec advisories on every push; minimal dependency set (crypto from RustCrypto/dalek/BLAKE3 teams). Copyleft dependencies need explicit approval. | Done; per-release SBOM Planned (release pipeline) |
| 1.3 | Clear testing process before distribution | Unit tests per crate; engine integration tests incl. fault injection (killed backup, dropped uploads, corrupt chunks); end-to-end CLI tests; Windows VSS smoke test on real Windows; fuzzing of all parsers of untrusted data (`fuzz/`). VM test matrix (`docs/TESTING.md`) gates releases. | Partial — VM matrix Planned |
| 1.4 | Secure by design and by default | Encryption always on (no plaintext repository mode); keys never leave the client; keyed chunk IDs; authenticated, signed manifests; create-only storage writes; destructive operations need explicit target + confirmation, enforced in the engine not just the UI; read-only device handles for backup; VSS COPY type by default so other tools' log chains are untouched; `#![forbid(unsafe_code)]` in `core-format` and `engine`, unsafe confined to OS FFI. | Done |

## Principle 2 — Build environment security

| # | Provision | How | Status |
|---|---|---|---|
| 2.1 | Protect the build environment against unauthorised access | Builds run on GitHub-hosted ephemeral runners; workflow token is read-only by default (`permissions: contents: read`); release signing keys will live in an HSM-backed signing service, never in the repository or on developer machines. | Partial — signing service Planned |
| 2.2 | Control and log changes to the build environment | Build definition is version-controlled (`.github/workflows/`); `Cargo.lock` committed and builds use `--locked`; third-party actions to be pinned by commit SHA. | Partial — SHA pinning Planned |

## Principle 3 — Secure deployment and maintenance

| # | Provision | How | Status |
|---|---|---|---|
| 3.1 | Distribute software securely | Authenticode-signed Windows binaries, SHA-256 checksums, CycloneDX SBOM per release; aim for reproducible builds (locked dependencies, `codegen-units = 1`, no build-time network beyond crates.io). Recovery ISO boots with the distribution's signed shim and kernel. | Planned — release pipeline |
| 3.2 | Vulnerability disclosure process | `SECURITY.md`: private reporting route, response times, safe-harbour statement. | Done |
| 3.3 | Detect, prioritise and manage vulnerabilities in components | `cargo audit` in CI on every push; Dependabot / scheduled audit for releases already shipped. | Partial — scheduled audit of released versions Planned |
| 3.4 | Report vulnerabilities to relevant parties | Issues found in dependencies are reported upstream and to RustSec; our own advisories published as GitHub Security Advisories with CVEs. | Done (process) |
| 3.5 | Timely security updates and notifications | Fixes released for supported lines per `SECURITY.md`; advisories announce affected versions and fixes. | Done (process) |

## Principle 4 — Communication with customers

| # | Provision | How | Status |
|---|---|---|---|
| 4.1 | State the level of support and maintenance | Support lifecycle table in `SECURITY.md`. | Done |
| 4.2 | At least one year's notice before end of support | Committed to in `SECURITY.md`. | Done |
| 4.3 | Information about notable incidents | Security advisories and release notes; for incidents affecting backup integrity, guidance on how to verify existing repositories (`fenrir-backup verify --full`). | Done (process) |

## Product controls relevant to ransomware resilience

Not provisions of the Code, but listed here because they are the security
promises of a backup product:

| Control | Status |
|---|---|
| Client-side encryption, Argon2id passphrase + offline recovery key | Done (Phase 1) |
| Integrity: AEAD on every object, keyed hash on every chunk, Ed25519-signed manifests | Done (Phase 1) |
| Verify: quick / sampled / full re-hash | Done (Phase 1) |
| Create-only writes; append-only server mode with separate admin credential | Done: create-only everywhere (S3: `If-None-Match`); NAS gateway clients can only add data; S3 keys without delete rights for machines that only back up |
| S3 Object Lock (compliance) retention | Done: every object locked on write, locks of objects in use extended by maintenance, deletion only after expiry (`docs/design/phase-4-storage.md`) |
| Change-ratio / entropy anomaly alert holding pruning | Done: anomaly puts the repository on hold until an administrator releases it (typed confirmation) |
| Repository locks so pruning never deletes data a running backup reuses | Done |
| Agent self-update verified by SHA-256 over the pinned connection | Done |
| Agent secrets protected with DPAPI (Windows) or root-only 0600 files (Linux, macOS); kernel keyring later | Done (management server release) |
| Management server never holds repository keys: passphrases sealed in the browser to each agent's X25519 key; recovery key generated in the browser | Done |
| Server: Argon2id admin passwords, login throttling, HttpOnly SameSite=Strict cookies, CSRF header, CSP and frame denial, audit log | Done |
| Agents pin a self-signed server certificate; installers verify agent binaries by SHA-256 before running them | Done |
| Role-based access for several administrators | Planned |
