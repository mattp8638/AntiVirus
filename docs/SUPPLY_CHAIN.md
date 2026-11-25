# Supply chain: locked inputs, SBOMs, provenance, reproducible builds

How a Fenrir release can be traced back to its source and its dependencies (AGT-09).

## Locked dependency installs

| Ecosystem | Lock | How CI and the image install it |
|---|---|---|
| Python (server) | `cloud/requirements.lock` (runtime + PostgreSQL driver), `cloud/requirements-dev.lock` (+ pytest) | `pip install --require-hashes -r …lock` |
| Python (ML tests) | `ml/requirements-ci.lock` | `pip install --require-hashes -r …lock` |
| Console | `console/package-lock.json` | `npm ci` |
| Go agent | `agent/linux/go.sum` | Go module checksums (go.sum, sumdb) |
| Rust backup agent | `components/backup/Cargo.lock` | `cargo … --locked` |

Every Python lock pins each package, transitive ones included, to one version with SHA-256 hashes, so a changed or
substituted wheel fails the install instead of being used. The Python locks are resolved for Linux on Python 3.13.
The one install that cannot use them is the Windows acceptance job, because the Linux lock includes `uvloop` and
leaves out `colorama`. That line is marked `supply-chain: unlocked` with the reason.

`scripts/supply_chain_check.py` runs in the Fenrir Platform workflow and fails the build if:

- a workflow or Dockerfile installs Python packages from ranges, runs `npm install` instead of `npm ci`, or runs
  cargo without `--locked`;
- a lock entry has no hash;
- a lock no longer satisfies `requirements.txt`, because someone changed a range without regenerating the lock.

A lockfile failure is fixed by regenerating the lock, never by falling back to an unconstrained install. Each
exception must carry `supply-chain: unlocked (reason)` on its own line, so it is visible in review.

Regenerating the locks (pip-tools, Python 3.13, Linux):

```bash
cd cloud
pip-compile --generate-hashes --strip-extras --allow-unsafe -o requirements.lock requirements-deploy.in
pip-compile --generate-hashes --strip-extras --allow-unsafe -o requirements-dev.lock requirements-dev.in
cd ../ml
pip-compile --generate-hashes --strip-extras --allow-unsafe -o requirements-ci.lock requirements-ci.in
```

## SBOMs and vulnerability scan

`.github/workflows/sbom.yml` produces SPDX and CycloneDX SBOMs for every component and scans them for known
vulnerabilities. Workflow artefacts are kept for 90 days. On a release, the SBOMs are attached to the GitHub release
and kept for as long as the release exists.

## Provenance

The release workflow only builds a tag that is on `main`. It runs the server and console tests against the locked
dependencies, then publishes a source archive with its SHA-256 and a signed build-provenance attestation
(`actions/attest-build-provenance`, Sigstore with GitHub OIDC). To verify a download:

```bash
gh attestation verify fenrir-<tag>.tar.gz -R <owner>/<repo>
```

Agent releases are also signed with the Ed25519 release key and pinned into the agents (see `AUTO_UPDATE.md`).

## Reproducible packaging

`scripts/ci/reproducible_agent.sh` builds the Linux (amd64, arm64) and macOS (arm64) agents twice. Each build uses a
separate copy of the source in a different directory, a separate build cache and the release build's flags
(`-trimpath`, fixed `-ldflags`). The binaries must be byte-identical.

The image build computes `BUILD_ID` from the source and takes `FENRIR_RELEASE_SEQ` from the git time of the last
agent change. Given the same tag and release sequence, anyone can rebuild an agent and compare it with the published
SHA-256 in `linux-build.json`.

What this does not yet cover:

- Byte-for-byte reproducibility of the Windows installer and the console bundle has not been tested.
- Signed Windows and macOS binaries cannot be reproduced without the signing keys. Compare the unsigned payload
  instead.
