# Security policy

Fenrir is free, self-hosted software with **no support, maintenance commitment or service level**. Read this before
relying on it.

## Reporting a vulnerability

Report it privately through this repository's **Security → Report a vulnerability** (GitHub private security advisories),
not in a public issue. Include the affected component (server, console, Windows/Linux/macOS/Android agent), the version or
commit, and steps to reproduce.

There is no promise of a fix, a reply or a time frame. If the project has been archived, nobody is watching the
reports: fix it in your own fork and, if you can, tell other users through your fork's advisories.

## What is checked automatically

Every change and release runs free tooling, with results under **Security → Code scanning** and in the workflow runs:

| Check | Workflow | What it does |
|---|---|---|
| CodeQL | `codeql.yml` | Static analysis of Python, TypeScript, Go, C/C++, Kotlin and the workflows themselves (security-extended queries). |
| OpenSSF Scorecard | `scorecard.yml` | Rates the repository's own practices: pinned actions, branch protection, token permissions, signed releases. |
| SBOM and dependency scan | `sbom.yml` | SPDX and CycloneDX bills of materials for the whole tree, scanned for known vulnerable dependencies; attached to each release. |
| Catalogue integrity | `catalogue.yml` | Community apps and scripts must match `catalogue/MANIFEST.sha256`; winget and Homebrew IDs must exist. |
| Dependency updates | `.github/dependabot.yml` | Weekly updates for Python, npm, Go, Gradle, Docker and Actions; security fixes as soon as an advisory is published. |
| Release provenance | `release.yml` | Each release's source archive has a SHA-256 and a signed build attestation: `gh attestation verify fenrir-<tag>.tar.gz -R <owner>/<repo>`. |
| Clean-software and stress suites | `acceptance.yml` | Windows and Linux agents on real runners: false positives, crash recovery, server outage, Defender alongside. |

## Running it safely

An RMM/EDR controls every device it manages. Whoever runs a Fenrir server is responsible for it:

- Keep the server patched (`deploy/install-auto-update.sh --stable`) and behind HTTPS.
- Every console account uses MFA (production mode enforces it); restrict who can reach the console.
- Keep `deploy/.env` (the vault key) and `deploy/signing/` (code-signing and release keys) offline and backed up. Anyone
  with the release key can push updates to your agents.
- Test scripts, patches and policies on a small group of devices first.
- Installers are signed with a certificate made on your own server, not a public one. Windows SmartScreen may warn on
  first download; deploy through your RMM, Group Policy or Intune (see `docs/DEPLOY_FROM_YOUR_RMM.md`) to avoid that.
