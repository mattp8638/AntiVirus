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

### D-07 status (Phase 1)

Implemented as designed, with one change: the release number is the git commit time of the last change under `agent/linux`. That number only increases, and rebuilding the same code doesn't create a new release. There are two ways to hold the key:

- **On the server (default):** `auto-update.sh` creates the key in `deploy/signing`, and the Docker build reads it as a BuildKit secret.
- **Off the server:** set `FENRIR_RELEASE_PUBLIC_KEYS`, sign the binaries elsewhere with `fenrir-release-sign`, and copy the manifests into `deploy/releases`, which is mounted read-only.

A missing key falls back to the hash-only check rather than failing the build. Otherwise a server still running the old `auto-update.sh` could never deploy the change that introduced the key.

### D-09: Customer users and tickets

Every signed-in customer user may raise a ticket, including read-only viewers, because asking for help is not a configuration change. For callers without service permissions, the server keeps only subject, description, impact/urgency/priority and device. Assignee, board, status and record type are dropped. Changing a ticket after it is created requires service permissions; customers comment through the portal. Boards and devices named in a ticket must belong to the caller's scope.

### D-10: MSP-level settings

Boards, workflow rules, unattached quotes, the inbound email token and other service-desk records with no customer account belong to the MSP. Only users whose scope includes the MSP tenant may create or change them; customer-side users and customer-scoped staff get 403. Records about a customer (tickets, configurations, contracts) stay MSP-owned with `account_tenant_id` set to the customer.

### D-11: Staged agent rollouts

Rollout rings reuse the existing `updates.channel` policy (canary, beta, stable, lts), so rings follow customer and group policy inheritance. Soak times are 2 hours for canary, 24 for beta and 72 for stable. A stage with no devices advances at once, so fleets that use no rings behave as before.

A device counts as failed when:

- it is still reporting the old build 60 minutes after it was offered the update, while it is online; or
- it stops checking in after being offered the update; or
- it sends `agent.update.rejected`.

The first failure pauses the rollout. Only platform administrators can pause, resume, advance or stop a rollout.

### D-12: API credentials

Integrations use `fsk_…` bearer tokens. Each token signs in as its own service user, with role `service`, which has no permissions of its own. The token's scope list decides what it may do:

- **Which permissions:** `read`, `respond`, `configure`, `crm`, `grc` or `billing`, and only ones its creator holds. Platform, tenant management, vault and Microsoft 365 administration can never be granted.
- **Where:** one customer subtree.
- **Never:** sign-in, the portal, or anything that needs a password re-check. So it cannot reveal secrets, approve sensitive actions, or create or rotate credentials.

Creating or rotating a credential requires a recent password check, and the token is shown once. The server keeps only a hash of the token.

### D-13: Audit assurance

**Checkpoints.** A checkpoint records the chain head (its position and hash). One is taken daily by the scheduler and more can be taken on demand. Each is published as an `audit.checkpoint` outbox event, so subscribed webhooks or a SIEM keep a copy outside the database. That copy is what catches an attacker who edits rows and then recomputes every hash after them.

**Verification.** Every break is reported, not just the first, and each one is classified:

- `modified`: the stored hash no longer matches the row's content.
- `deleted`: chain positions are missing.
- `relinked`: the row is intact but points somewhere unexpected.
- `checkpoint`: the chain no longer has the hash a checkpoint recorded.
- `legacy-race`: an intact row that chains onto a sibling and was written before migration 22. This is a software race, not tampering.

**Exports.** An export is JSON Lines. In a customer's export, other customers' rows keep only their chain fields. `scripts/verify_audit_export.py` checks an export offline, using only the Python standard library.

**Retention.** Retention is 365 to 3650 days, or keep everything. Rows are pruned only up to a checkpoint whose hash still matches; that checkpoint becomes the anchor verification starts from. A legal hold stops all pruning and needs a reason. Changing the policy needs a platform administrator and a fresh password check.

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
