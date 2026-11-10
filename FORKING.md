# Forking Fenrir

Fenrir is Apache 2.0 software and is meant to be forked. The original repository may be archived; a fork is how the
project carries on. This page lists what a fork needs to change and what keeps working on its own.

## Works in a fork without changes

- **Servers run without any outside service.** Each server makes its own code-signing certificate and release key
  (`deploy/install.sh`), answers its own STUN for direct remote sessions, and serves its own agent downloads.
- **Updates follow your fork.** A server's automatic updates (`deploy/auto-update.sh`) pull from the git remote it was
  cloned from, so servers installed from your fork update from your fork's releases (`git tag vX.Y.Z` on main runs
  `release.yml`).
- **CI runs on GitHub's free runners:** tests, Windows and Linux acceptance on real machines, the 2,000-agent load test,
  CodeQL, OpenSSF Scorecard, SBOMs and the docs site.

## Change these

| What | Where | Why |
|---|---|---|
| Hard-coded service addresses | Run `python3 scripts/handoff/public_check.py` | Lists defaults that point at the original project's servers (threat feed, signing timestamp page, installer defaults). Point them at yours or remove them. Threat-feed sync is off unless `FENRIR_FEED_SYNC=true`. |
| Links to the original repository | `README.md`, `SECURITY.md`, `mkdocs.yml`, `docs/index.md` | So users report problems to you. |
| Product name and look, if you rebrand | `console/src/brand.tsx`, the Windows installer resources, the Android app id (`uk.co.fenrirsecurity.agent`) | Avoid confusion with the original. MSPs can already set their own name, logo and colours per server in Settings → Branding. |
| Upgrade code of the Windows MSI | `cloud/fenrir_cloud/rmm_deploy.py` (`UPGRADE_CODE`) | Only if your MSI should not upgrade the original's. |

## Keep these promises to your users

- Never commit signing keys, `.env` files, customer data or exports. The repository `.gitignore` and `deploy/preflight.sh`
  help with that.
- Keep the community catalogue's checksums (`catalogue/manifest.py --write` after reviewing a change): servers only load
  catalogue files that match.
- Say clearly in your README whether you offer support. The original does not.

## Contributing back

The original repository does not take contributions once it is archived. Coordinate with other forks instead: GitHub's
network graph (Insights → Forks) shows who is active.
