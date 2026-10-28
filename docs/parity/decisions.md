# Parity decisions, assumptions and dependencies

## Benchmarks (frozen 27 October 2026)

| Area | Benchmark assumed | Notes |
|---|---|---|
| RMM | NinjaOne RMM platform, plus remote access, browser management, MDM and backup modules (current SaaS) | The owner named categories. The high-end edition with add-ons is assumed. |
| Antivirus/EDR | Bitdefender GravityZone Business Security Enterprise and its MSP add-ons | Feature parity is separate from detection efficacy (AV-23), which needs an independent lab. |
| Microsoft 365 | CIPP, full documented catalogue (docs.cipp.app) | The exact release is to be frozen during M365 discovery (Phase 5). Every action and template is enumerated then. |
| Exposure | ConnectSecure plus RoboShadow, the combined shipping scope | Where marketing and docs disagree, the actual product behaviour is recorded. |
| Governance | Adoptech platform (frameworks, policies, risk, suppliers, agreements, TrustHub) | Certification is a human/assessor outcome and is never claimed by software. |

"MVP shipped" and "full parity verified" are separate release states (see `release-gates.md`).

## Architecture decisions

- **D-01: Keep the stack.** The stack stays as it is: FastAPI, React/TypeScript, PostgreSQL, the Windows C++ agent, and the Go agent for Linux and macOS. It is a modular monolith with a scheduler lease and an outbox. Workers move out only when measured load or isolation requires it.
- **D-02: Build profiles (FIX-01).** `FENRIR_BUILD_PROFILE=production` is the default and refuses to build without the signing certificate, failing before cmake runs. The `lab` profile builds unsigned and is labelled `unsigned-lab` in `build.json`. `auto-update.sh` falls back to lab, with a warning, only when the profile is unset and no certificate exists. An explicit production profile with a missing certificate is an error. The certificate and password stay on the server and are never put in Git, image layers or logs.
- **D-03: Scan coverage (FIX-02).** A finding is closed only if its package was assessed in a successful response, or a newer inventory shows the package is gone. Every scan is recorded as complete, partial or failed. Missing KEV or detail data is a warning; it is never read as low risk.
- **D-04: Sessions (FIX-03).** Sessions are rows on the server (`user_sessions`), and every bearer token must name a live one. Password change, MFA changes, admin reset, deactivation and role change revoke sessions. Remote viewer tokens carry the console session and are cut off when it ends. Consequence: after the upgrade, every user signs in once more.
- **D-05: Audit chain (FIX-05).** A single head row is advanced by compare-and-swap, and rows carry a `seq`. Chains already broken by earlier races still report the break. Checkpoints and resealing are CORE-06.
- **D-08: Framework revisions (FIX-08).** A requirement's identity is its ID; its meaning is a hash of its title, text and answer type. Changes to guidance or evidence hints do not invalidate an answer. A "done" or "not applicable" answer given against different wording shows as `needs_review` and does not count as done. Saving the answer again confirms it against the current wording. Before any definition change, each affected customer's assessment is snapshotted as JSON (`grc_assessment_snapshots`). Historical exports come from that snapshot, not from a re-computation.

## Shipping constraints recorded in Phase 0

### D-06: FIX-06, Windows production prevention (externally blocked)

- The minifilter source and its package (`agent/windows/driver/minifilter`) were removed from the repository by the owner in commits `9a57283` and `da9c61f` (14 May 2026). The production image therefore builds with `ANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD=OFF`.
- What ships today is user-mode only: `RealtimeProtectionBroker` waits for a filter port that no installed driver provides. Process-start enforcement, AMSI, ETW and WFP isolation run in user mode, so blocking happens after a process starts, not before it executes.
- To ship this:
  1. The owner restores the driver source, or authorises a rewrite.
  2. An EV code-signing certificate in the company's name, plus a Microsoft Partner Center hardware account. Clients use attestation signing. Windows Server requires HLK/WHQL; an attestation-signed driver does not load there under default policy.
  3. HVCI-compatible build settings.
  4. Lab Windows 10/11 and Server VMs with Secure Boot and HVCI on.
- Do not disable Secure Boot, HVCI or driver signature enforcement, or use test-signing, to pass acceptance.
- Scheduled: AV-02 in Phase 4. Until then, the console must not report pre-execution prevention as active (AGT-10/AV-22).

### D-07: FIX-07, Go agent release authentication (partial)

- The Go agent (Linux and macOS) downloads its binary from the same server that supplies the SHA-256. Any build-ID difference triggers an update, so a downgrade is accepted. There are no rings, pause or rollback. `agent/linux/pkg/updater` is an unused legacy GitHub updater with no verification, to be removed with AGT-03.
- The Windows updater already requires a declared package signer, per-file SHA-256 and Authenticode (`UpdaterService.cpp`). It is not yet exercised against tampered input.
- Planned design (AGT-03/AGT-04, Phase 1):
  - An Ed25519 release key, held offline or in a KMS. It is never in Git or on the application server.
  - Its public key, and the next rotation key, are pinned in agent builds.
  - The signed manifest records: platform, architecture, channel, monotonically increasing release number, SHA-256, size, expiry and minimum agent version.
  - The agent rejects a bad signature, a wrong platform, an expired manifest, or a release number lower than the installed one unless a signed rollback authorisation exists.
  - Rollout uses rings with health gates and an emergency stop.
- Dependency: the owner performs a release-key ceremony and decides where the private key lives.

### Other external dependencies (owner action needed when reached)

| Dependency | Needed for |
|---|---|
| Production code-signing certificate on the server | AGT-02, signed production build |
| EV certificate, Partner Center hardware account, HLK lab | FIX-06, AV-02 |
| Apple Developer Program, Endpoint Security entitlement, notarisation | AV-03, macOS distribution |
| Isolated Microsoft test tenants (partner and customer) with licences; CSP/GDAP partner | M365-02 and all live M365 verification (AT-14 to AT-17) |
| Google Workspace test tenant | VULN-12, BDR-05 |
| Licensed breach/dark-web feed | VULN-18 |
| Sandbox provider; mail-flow provider | AV-15, AV-16 |
| Independent efficacy test lab | AV-23 |
| Staffed SOC/MDR arrangement | AV-24 |
| Backup engine/provider and immutable object storage | BDR-01 to BDR-06 |
| Android Enterprise EMM registration; Apple APNs/ABM/ADE | MDM-01, MDM-02 |
| Licences for proprietary standard text (ISO, PCI DSS) | GRC-02, GRC-03 |
