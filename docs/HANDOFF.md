# Hand-off checklist (repository owner)

The last steps to finish the project and leave it in a state others can pick up. Only the repository owner can do
these. Nothing here costs money; a custom domain for the docs site is optional.

## 1. Make sure it is publishable

- [ ] `python3 scripts/handoff/public_check.py --private "<your name>,<company>,<machine names>"` reports nothing
      under PRIVATE. Remove or neutralise anything it finds (test fixtures included).
- [ ] Decide on each STATIC address it lists: turn it into a setting with no default, or remove it.
- [ ] No secrets in history: GitHub → Security → Secret scanning shows no open alerts. If a real secret was ever
      committed, rotate it (rewriting history does not un-leak it).

## 2. Final green build

- [ ] On main, every workflow is green: tests, acceptance (Windows and Linux), installer, load test, CodeQL, catalogue.
- [ ] Settings → Pages → Source: **GitHub Actions**, then run the "Docs site" workflow once. Optionally add a custom
      domain under the same page.
- [ ] Settings → Code security: turn on **Private vulnerability reporting** (so reports have somewhere to go until the
      archive) and Dependabot alerts.

## 3. Final release

- [ ] Run `python3 scripts/handoff/mark_unmaintained.py --version vX.Y.Z` and commit the notice to main.
- [ ] Tag main: `git tag vX.Y.Z && git push origin vX.Y.Z`. `release.yml` tests the tagged commit and publishes the
      release; `sbom.yml` attaches the SBOMs to it.
- [ ] Edit the release notes: say it is the final release, link FORKING.md, and repeat that there is no support.

## 4. Archive

- [ ] Settings → General → Danger Zone → **Archive this repository**. It stays public and forkable, read-only.
      Existing servers keep working and keep their last release; they simply receive no further updates.
- [ ] Optionally pin a short note in the repository description: "Finished and archived. Fork to continue."

## What keeps running after the archive

- Every server is self-contained: its own HTTPS, signing keys, STUN, downloads and backups. Nothing depends on this
  repository or on any service you run.
- `catalogue.yml`, `scorecard.yml` and other scheduled workflows stop: GitHub does not run workflows in archived
  repositories.
