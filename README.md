# Fenrir Platform

Fenrir is a self-hosted project combining endpoint security, RMM, Microsoft 365 administration, vulnerability management and MSP operations. Its aim is to make integrated tooling available without compulsory per-device licence fees.

**Status: active development and controlled evaluation.** Implemented features are not all independently verified on real endpoints/providers. Windows protection is user mode; the Docker image does not deliver the production kernel minifilter or pre-execution prevention. The current build must not be advertised as a certified replacement for every commercial AV/RMM. Follow the [feature catalogue](docs/parity/catalogue.csv), [acceptance evidence](docs/parity/acceptance.md) and [release gates](docs/parity/release-gates.md).

Hosting, domains, publicly trusted code-signing certificates and optional providers can still cost money.

> **Free, as-is, unsupported.** Fenrir is released free of charge under the [Apache License 2.0](LICENSE). It is provided **"AS IS", without warranty of any kind**, and **no support is offered**: issues and pull requests may not be answered. You are responsible for testing it on your own systems before relying on it (see the [acceptance lab](docs/ACCEPTANCE_LAB.md)), for securing your own installation, and for anything it does on the devices and tenants you connect to it. See [Licence and support](#licence-and-support).

## Contents

- [Components](#components)
- [Requirements](#requirements)
- [New HTTPS installation](#new-https-installation)
- [Local evaluation without a signing certificate](#local-evaluation-without-a-signing-certificate)
- [First sign-in and use](#first-sign-in-and-use)
- [Agent installation](#agent-installation)
- [Updates](#updates)
- [Backup and restore](#backup-and-restore)
- [Troubleshooting](#troubleshooting)
- [Development and tests](#development-and-tests)
- [Public release and contribution](#public-release-and-contribution)
- [Licence and support](#licence-and-support)

## Components

| Area | Included workflows |
|---|---|
| Endpoint security | Windows agent, AMSI integration, detection rules, static malware model, alerts, incidents, response, quarantine and DNS protection. Prevention/efficacy limits remain tracked in the parity documents. |
| RMM | Inventory, metrics, monitoring, scripts, jobs, patching, software deployment, terminal, files and browser remote control. Capabilities differ by endpoint OS. See [stopping commands and removing jobs](docs/COMMAND_CANCELLATION.md). |
| Microsoft 365 | Customer connections, directory/licence views, security snapshots and reviewed administration. Graph permissions, admin consent and any necessary Microsoft licences are still required. |
| Exposure | Vulnerability inventory, CVE/EPSS/KEV intelligence, scan ingestion, external assets and remediation tracking. |
| MSP operations | Customers, service boards, tickets, dispatch, time, projects, CRM, quotes, agreements, billing and client portal. |
| GRC and operations | [UK and UK-targeted governance programmes](docs/GOVERNANCE.md), policies, evidence, risks, credential vault, network monitoring, backup status and recovery exercises. Actual backup/restore requires a configured provider. |

Deployment consists of **PostgreSQL + Fenrir Cloud**, which serves the compiled React console, agent downloads and WebSocket relay. The HTTPS example adds **Caddy**.

## Requirements

| Item | Requirement / planning guidance |
|---|---|
| Host | Linux VPS/server with sudo access. Ubuntu 24.04 LTS on amd64 is a practical starting point. |
| Capacity | For an initial source-build evaluation, plan roughly 4 vCPUs, 8 GB RAM and 80 GB SSD; 16 GB RAM gives more build headroom. These are estimates, not measured fleet-capacity guarantees. Event volume and retention determine storage needs. |
| Containers | Docker Engine, BuildKit/buildx and **Docker Compose 2.24.4+**. The HTTPS/local templates use `!override`. Use `docker compose`, not legacy `docker-compose`. |
| Tools | Git, curl, OpenSSL and Bash; Python 3 for the host backup/restore utilities. The image build supplies the application runtimes and Windows cross-toolchain. |
| Network | DNS hostname pointing at the server; TCP 80/443 for HTTPS, optional UDP 443 for HTTP/3, and restricted SSH access. Keep PostgreSQL private. |
| Outbound access | Container/package registries during builds; TLS/signing timestamp services; configured threat feeds, CVE sources and providers during operation. |
| Signing | Production Windows builds need a usable code-signing PFX/password. Signed Linux/macOS updates need a persistent Ed25519 release key. Preserve and back up both. |

Built user-mode artifacts include Windows x64, Linux amd64/arm64 and macOS amd64/arm64. This is not a declaration of equal feature coverage or a completed supported-platform acceptance matrix. Self-signed Windows certificates require deliberate trust on managed endpoints; public trust and SmartScreen reputation are separate matters.

## New HTTPS installation

These steps are for a **new installation**. On an existing server, preserve its database, configuration and keys and use [Updates](#updates). Never regenerate an existing installation's secrets just to upgrade it.

### 1. Prepare the server

Connect over SSH using an authorised sudo account. On Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y git curl openssl ca-certificates python3
```

Install Docker Engine, buildx and Compose using [Docker's Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/) or the official guide for your distribution. Verify:

```bash
sudo docker version
sudo docker compose version
sudo docker buildx version
sudo docker run --rm hello-world
```

Point a hostname such as `rmm.example.com` at the VPS. Remove incorrect AAAA/IPv6 records. Allow 80/443 in the provider and host firewalls while retaining SSH access. If another proxy owns those ports, integrate with it rather than starting a second proxy.

### 2. Clone and configure

```bash
git clone https://github.com/mattp8638/AntiVirus.git ~/AntiVirus
cd ~/AntiVirus
(
umask 077
mkdir -p deploy/signing deploy/releases
chmod 700 deploy/signing
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
)
```

Keep restrictive umasks inside the shown subshells. Leaving `umask 077` active during a later Git pull can create source files/directories that a non-root container cannot read. If the current SSH shell already has that setting, run `umask 022` before updating code; existing private file permissions stay unchanged. The image also normalizes its packaged application's permissions before switching to the runtime user.

Generate four **different** values and enter each in its matching `deploy/.env` setting:

```bash
openssl rand -hex 32       # POSTGRES_PASSWORD
openssl rand -hex 32       # FENRIR_SECRET_KEY
openssl rand -base64 32    # FENRIR_VAULT_KEY
openssl rand -hex 24       # FENRIR_ADMIN_PASSWORD
```

Also set these values, replacing the hostname and email:

```dotenv
FENRIR_PUBLIC_URL=https://rmm.example.com
FENRIR_DOMAIN=rmm.example.com
FENRIR_ADMIN_EMAIL=admin@example.com
FENRIR_OPEN_ENROLLMENT=false
FENRIR_BUILD_PROFILE=production
FENRIR_RELEASE_KEY=./signing/release-ed25519.pem
```

The public URL must be reachable by browsers and agents. The domain setting is a hostname only. Keep the generated secrets, not the template placeholders. Leave the release sequence empty initially unless you manage numbering yourself.

Keep `FENRIR_SECRET_KEY` stable: it signs console sessions. The vault key protects stored credentials and recovery secrets; losing it can make those values unreadable. Configure a working threat feed/intelligence source for meaningful protection; a configured URL is not proof that updates have arrived.

### 3. Set up signing

Generate the Linux/macOS release key once, retaining any existing key:

```bash
(
umask 077
test -s deploy/signing/release-ed25519.pem || \
  openssl genpkey -algorithm ed25519 -out deploy/signing/release-ed25519.pem
chmod 600 deploy/signing/release-ed25519.pem
)
```

From your workstation, upload the Windows certificate using your SSH account/server:

```powershell
scp "C:\path\Certificate.pfx" pmadmin@YOUR_SERVER:~/AntiVirus/deploy/signing/codesign.pfx
```

In the server's Bash terminal, enter its password without recording it in shell history:

```bash
(
umask 077
read -r -s -p 'PFX password (empty if none): ' fenrir_pfx_password
printf '\n'
printf '%s' "$fenrir_pfx_password" > deploy/signing/codesign.password
unset fenrir_pfx_password
chmod 600 deploy/signing/codesign.pfx deploy/signing/codesign.password
)
```

Signing material is passed through BuildKit secrets. Never commit it, put it in a Dockerfile or attach it to an issue. Keep an offline backup of the PFX/password and release key. See [code signing](docs/CODE_SIGNING.md) and [release signing/key rotation](docs/AUTO_UPDATE.md).

### 4. Configure HTTPS

For a new installation:

```bash
cp deploy/docker-compose.https.example.yml deploy/docker-compose.https.yml
cp deploy/Caddyfile.example deploy/Caddyfile
```

For an existing installation, merge the examples into its current proxy configuration instead of overwriting it. Caddy obtains/renews TLS certificates, redirects HTTP to HTTPS and proxies WebSockets. Its state lives in named volumes. The override replaces the base public HTTP binding with `127.0.0.1:8080`; do not expose PostgreSQL or rely solely on a firewall to hide Docker-published ports.

Define this helper in **each new Bash session**, from `~/AntiVirus`. The production commands below use it:

```bash
dc() {
  sudo env COMPOSE_BAKE=false docker compose \
    -f deploy/docker-compose.yml \
    -f deploy/docker-compose.https.yml \
    --env-file deploy/.env "$@"
}
```

`COMPOSE_BAKE=false` selects Compose's BuildKit path, including secrets, avoiding Bake filesystem-entitlement prompts for keys outside the checkout. Signing stays enabled.

### 5. Build and verify

```bash
dc config --quiet
dc up -d --build
dc ps
dc logs --tail=100 cloud worker caddy
curl --fail http://127.0.0.1:8080/health
curl --fail https://rmm.example.com/health
curl --fail https://rmm.example.com/ready
curl --fail https://rmm.example.com/health/background   # 200 about a minute after the worker starts
```

The first build compiles the console and agent installers and can take time. Sign in using the configured admin email/password. Open Devices, Monitoring and a customer report, and review **Settings → Platform** readiness findings. A build exit code or `200 /health` alone does not verify an entire workflow.

Production checks reject unsafe secrets and SQLite. `/ready` also checks the migration ledger and mapped device columns; container health and server updates use it. Bootstrap credentials create the first administrator; editing the bootstrap password later does not reset an existing account.

### Background worker and telemetry volume

The `cloud` container serves the console and the agents (`FENRIR_ROLE=web`). The `worker` container runs everything
scheduled: RMM schedules and automations, webhooks and the event outbox, the PSA mailbox, Microsoft 365, accounting and
GRC syncs, and retention (`FENRIR_ROLE=worker`, `python -m fenrir_cloud.worker`). A slow provider sync never delays a
console page or an agent check-in, and a crash in one never takes the other down. Commands the worker queues still
reach agents within a couple of seconds: the API wakes connected agents that have new work. To run everything in one
container instead, set `FENRIR_ROLE: all` on `cloud` and remove the `worker` service.

Point your uptime monitor at `/health/background` as well as `/ready`. It returns 503, naming the problem, when the
scheduler or the hourly maintenance has stopped completing, a job has been running for over 30 minutes, or the event
outbox is falling behind. **Settings → Platform** shows the same, with each job's last run and error.

Telemetry settings (in `deploy/.env`, passed through the Compose file's shared environment):

| Setting | Default | Meaning |
|---|---|---|
| `FENRIR_TELEMETRY_RETENTION_DAYS` | 90 | Every event is deleted after this. |
| `FENRIR_ROUTINE_RETENTION_DAYS` | 30 | Routine activity (process, image-load, network, DNS, file, registry and script-scan events at "info") is deleted sooner, unless a detection rule matched it. |
| `FENRIR_ROUTINE_EVENTS_PER_DEVICE_MINUTE` | 600 | Past this, a device's routine events are still checked against every detection rule but stored only if one matches. 0 turns the cap off. |

`GET /api/console/platform/telemetry-volume` lists the devices and event types sending most, if the database grows
faster than expected.

## Local evaluation without a signing certificate

Use a **separate checkout/database**. Complete the tools, unique-secret and release-key steps above. Set `FENRIR_PUBLIC_URL=http://localhost:8080` and `FENRIR_BUILD_PROFILE=lab`. No Windows PFX is needed.

```bash
sudo env COMPOSE_BAKE=false docker compose \
  -f deploy/docker-compose.yml \
  -f deploy/docker-compose.lab.yml \
  -f deploy/docker-compose.local.yml \
  --env-file deploy/.env up -d --build
```

Open `http://localhost:8080`. For a VPS, run this on your workstation and browse that address locally:

```bash
ssh -L 8080:127.0.0.1:8080 pmadmin@YOUR_SERVER
```

The local override keeps HTTP on loopback. Use the same three Compose files for subsequent evaluation commands. Unsigned Windows artifacts are labelled `unsigned-lab`; serving one additionally requires the explicit allow setting and matching digest in [code signing](docs/CODE_SIGNING.md). Do not disable installer verification. Use signed builds for customer endpoints.

## First sign-in and use

1. Change the administrator password, enable MFA in **Settings → Account**, and retain recovery codes.
2. Create customers in **Settings → Tenants**, then groups and appropriate policies. Assign operators only the required roles/custom roles and customer scope.
3. In **Deploy agents**, select the customer and generate an installer/token. Treat installers containing enrolment data as temporary credentials.
4. Start with a test endpoint. Verify its customer, hostname, platform, check-in, applied policy and inventory; approve it if required.
5. Configure monitoring, patch policies and maintenance windows. Run a harmless script on a test group and inspect both its job output and actual endpoint result before broad deployment.
6. Device pages group inventory under **System**, alerts/vulnerabilities/local administration under **Security**, patches/apps under **Software**, and jobs/actions/sessions under **Activity**.
7. Configure service boards, resources and agreements before using dispatch, automation, time and billing. Test the client portal with a customer-scoped account.
8. Configure real providers for Microsoft 365, SMTP/IMAP, network and backup modules. Microsoft actions need the displayed Graph permissions/admin consent and may require provider licences. A saved configuration does not establish that an operation succeeded.

Use incident/job evidence to verify outcomes. Secret reveals and sensitive actions may require password re-entry and are audited. Integrations should use scoped API credentials, not shared administrator tokens.

Where two-person approval is configured, high-impact actions are held for a different authorised operator to review in **Settings → Approvals**. An approval request is not an executed action: check the eventual job/endpoint result.

## Agent installation

| Platform | Installation and checks |
|---|---|
| Windows | Download the customer-specific `FenrirSetup.exe` from **Deploy agents** and run as administrator. It bundles the service, helper and associated user-mode components. Check the signer and successful check-in. See [Windows persistence](docs/WINDOWS_AGENT_PERSISTENCE.md). |
| Linux | Download the generated customer installer, inspect it and run `sudo sh /path/to/installer.sh`. It installs a systemd service. Desktop remote control needs X11; terminal/files are separate capabilities. |
| macOS | Use the generated macOS installer with administrator rights. It installs the Go agent as a LaunchDaemon; grant required OS permissions, including Full Disk Access where needed. This is not the older Swift prototype. |
| Android | Use phone enrolment and grant requested device/location permissions. Capabilities differ from desktop agents. |

Do not run a manual/prototype service beside an installed agent. Keep uninstall-protection credentials and use the normal maintenance/installer flow for upgrades.

Windows remote **Ctrl+Alt+Del** requires a matching updated service and `fenrir-remote.exe`, followed by a new remote session. Windows SAS policy must permit services. An acknowledgement confirms the request, not the screen transition; see [the SAS guide](docs/REMOTE_CTRL_ALT_DEL.md).

## Updates

Back up first. `main` is active development: evaluate a tested commit before customer rollout. Preserve `.env`, vault key and signing material.

For an operator-managed checkout already following `main`:

```bash
cd ~/AntiVirus
git status --short
git pull --ff-only origin main
dc build cloud
dc up -d
dc logs --tail=100 cloud
```

Review tracked edits or a different branch before switching/pulling. Do not use `git reset --hard` to bypass a conflict. Refresh the deployed console with **Ctrl+F5**.

Migrations run at startup and are recorded in `schema_migrations`. Migration **29** repairs missing `devices.agent_build` on older databases, including installations that recorded the earlier incomplete migration. Devices/enrolment identities are retained; an unknown build stays empty until the next heartbeat.

Optional unattended server updates, after manual hosting works:

```bash
sudo deploy/install-auto-update.sh main
sudo systemctl start fenrir-auto-update.service
sudo tail -f /var/log/fenrir-auto-update.log
```

The timer checks every ten minutes, includes the HTTPS override if present, preserves untracked configuration and stops on tracked edits. It reuses/creates the release key and follows the chosen build profile. Disable it with `sudo systemctl disable --now fenrir-auto-update.timer` when updates require operator review.

Agents follow update policy and rollout availability. Windows uses the installer; Linux/macOS with pinned release keys verify signed manifests and reject rollback/replay. Pilot small rings, inspect outcomes and preserve keys. Re-releasing old code needs a newer release number, not an old manifest; see [updates and key rotation](docs/AUTO_UPDATE.md).

Rolling back an image does not reverse database migrations. An older application may correctly reject a newer schema. Use a tested forward fix or restore a matching application/database/configuration backup.

## Backup and restore

Back up PostgreSQL, artifact storage and configuration together. Include `.env`, `deploy/signing/`, `deploy/releases/`, proxy files, custom update configuration and the exact application commit. Keep encrypted off-host copies and rehearse recovery on an isolated system.

The current repository also provides `deploy/backup.sh` and `deploy/restore.sh`. With the HTTPS setup, run the backup utility as follows:

```bash
sudo env FENRIR_COMPOSE_FILES="$PWD/deploy/docker-compose.https.yml" \
  deploy/backup.sh /var/backups/fenrir
```

It writes a folder containing a custom-format database dump, artifacts, optional release files and a checksum manifest. It deliberately excludes `.env`, signing keys and Caddy state: retain those separately. Record the application commit separately if the manifest reports `unknown` because sudo cannot read the checkout's Git metadata.

On an isolated, correctly configured restore target, the matching restore command is:

```bash
sudo env FENRIR_COMPOSE_FILES="$PWD/deploy/docker-compose.https.yml" \
  deploy/restore.sh /var/backups/fenrir/fenrir-backup-TIMESTAMP
```

Restore checks the manifest and vault-key fingerprint, asks for confirmation, replaces the target database/artifacts and checks audit integrity/decryption. Follow [the complete utility runbook](docs/BACKUP_AND_RESTORE.md). It replaces target data; do not use the production host for a practice restore. A consistent database dump alone does not make database/files mutually atomic during concurrent writes; arrange a maintenance window or quiesce ingestion when that guarantee is needed.

Example maintenance-window backup with the production `dc` helper:

```bash
(
set -e
umask 077
fenrir_backup_dir="$HOME/fenrir-backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$fenrir_backup_dir"
git rev-parse HEAD > "$fenrir_backup_dir/commit.txt"
dc stop cloud
dc exec -T db pg_dump -U fenrir -d fenrir -Fc > "$fenrir_backup_dir/database.dump"
dc run --rm --no-deps -T --entrypoint tar cloud -czf - -C /data . > "$fenrir_backup_dir/artifacts.tgz"
tar -czf "$fenrir_backup_dir/configuration.tgz" deploy/.env deploy/signing deploy/releases deploy/docker-compose.https.yml deploy/Caddyfile
dc run --rm --no-deps -T --entrypoint tar caddy -czf - -C /data . > "$fenrir_backup_dir/caddy-data.tgz"
dc start cloud
)
```

If installed, pause the timer with `sudo systemctl stop fenrir-auto-update.timer` before maintenance and resume it with `sudo systemctl start fenrir-auto-update.timer` afterwards. Check **every** command/archive and restart cloud if a backup command fails while it is stopped. Include any extra files such as `deploy/auto-update.env`. Archives contain secrets; never attach them to an issue.

Restore onto a **separate installation first**:

1. Clone the recorded commit; restore configuration/keys with their permissions. Define `dc` for that checkout and build its image. Keep production DNS/agents directed at the live service during rehearsal. Before starting cloud, add a restore-only Compose override setting `FENRIR_SCHEDULER`, `FENRIR_FEED_SYNC` and `FENRIR_VULN_INTEL` to `"false"`, and `FENRIR_SMTP_HOST`/`FENRIR_IMAP_HOST` to `""`; include it as the final `-f` file in `dc`. Never start the `worker` service during a rehearsal: it runs schedules, emails and agent commands. Keep the restored host isolated from managed endpoints/provider credentials until checks are complete.
2. Start only the database with `dc up -d db`; wait for `dc exec -T db pg_isready -U fenrir -d fenrir` to succeed.
3. On this restore target only:

   ```bash
   dc exec -T db pg_restore -U fenrir -d fenrir --clean --if-exists --no-owner --no-privileges < /path/to/database.dump
   dc run --rm --no-deps -T --user 0 --entrypoint tar cloud -xzf - -C /data . < /path/to/artifacts.tgz
   dc run --rm --no-deps -T --user 0 --entrypoint tar caddy -xzf - -C /data . < /path/to/caddy-data.tgz
   dc up -d db cloud caddy   # not the worker: see step 1
   ```

4. Verify health, sign-in, customer data, artifacts and a controlled vault reveal, then a test agent/provider workflow before switching traffic. Rehearse without running duplicate scheduled jobs, emails or commands against production endpoints.

Do not use `docker compose down -v` for troubleshooting: it deletes named volumes. Database backups without matching vault/signing keys cannot recover every secret or update relationship.

## Troubleshooting

Run from `~/AntiVirus` with the deployment's original Compose files and `.env`. Define `dc` again in a new SSH session:

```bash
git rev-parse --short HEAD
dc ps
dc logs --since=15m --tail=200 cloud worker db caddy
curl --fail http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/health/background
```

| Symptom | Check / solution |
|---|---|
| `fatal: not a git repository` | Run `cd ~/AntiVirus`, then `git status` before fetching. |
| `/health/background` returns 503 | Its `problems` list says what stopped. Check `dc ps worker` and `dc logs --tail=200 worker`; `dc restart worker` is safe at any time. A job named under `stuck` is still running after 30 minutes: its log lines say which provider it is waiting on. |
| `sudo: a password is required` | Use an interactive SSH terminal and an authorised sudo account. Enter its password at the prompt; have the server administrator correct missing access. |
| 500 on Devices, RMM, patching, dashboard or reports after upgrading | Read the cloud traceback. A missing `devices.agent_build` is repaired by migration 29. Rebuild/restart the updated cloud image; refreshing a browser cannot repair a database. See below. |
| Blank screen / React #31 | Older UI rendered an object as text. Deploy the console/profile fixes and Ctrl+F5. A visible API error still needs its backend cause fixed. |
| Production refuses startup | Read its readiness error: check PostgreSQL, stable non-placeholder secrets, vault settings and initial admin credentials. Do not bypass checks by changing production to development. |
| PFX missing/invalid | Check file permissions, password and production/lab profile. Use the separate lab override only for evaluation. |
| Bake requests `--allow=fs.read=...` | Use `COMPOSE_BAKE=false` as in the helper; keys remain outside the checkout and still use BuildKit secrets. |
| `unknown tag !override` | Upgrade Compose to 2.24.4+. Removing the tag can leave both public and loopback ports exposed. |
| TLS/connection failure | Check A/AAAA records, canonical URL, port ownership, provider firewall and Caddy logs. Do not deploy with certificate verification disabled. |
| Waiting for remote agent | Check online state, approval, policy, consent, helper installation and outbound HTTPS. Other proxies must pass WebSockets and suitable idle timeouts. Check the endpoint session log. |
| Ctrl+Alt+Del does nothing | Update service/helper together, reconnect, inspect visible action errors and check service SAS policy. Keep Windows sign-in requirements enabled. |
| Agent update rejected | Inspect manifest signature, platform/architecture, hash, sequence and rollout. Restore the original key or perform a controlled reinstall if it was lost. |
| WinGet package not matched / local patch refresh cannot create a script | Update both the Windows service and desktop client. Checks/refreshes now use the service broker; provider readiness is distinct from a confirmed update. See [Windows patching diagnostics](docs/WINDOWS_PATCHING.md). |
| Vault decryption fails | Restore the correct vault/old-key configuration. A freshly generated key cannot decrypt old secrets. |
| Editing bootstrap password has no effect | Change an existing account through account management; bootstrap settings only create the initial administrator. |
| Build exits/OOM | Check disk space and host memory/OOM logs. Native compilation needs headroom; use a larger build host if necessary. |
| Cloud restart loop with `PermissionError` importing `/app/cloud/fenrir_cloud/*.py` | An owner-only checkout was copied into a root-owned image. Apply the image permission fix, or use the scoped source-permission recovery below, then rebuild. Startup must succeed before migrations can run. |

### Unreadable packaged source recovery

If cloud logs show `PermissionError: [Errno 13] Permission denied: '/app/cloud/fenrir_cloud/crypto.py'` (or another packaged module), make the tracked public application files readable and their directories traversable, then rebuild with the existing `dc` helper:

```bash
cd ~/AntiVirus
umask 022
git ls-files -z cloud ml/fenrir_ml ml/models | xargs -0 -r chmod a+r
find cloud ml/fenrir_ml ml/models -type d -exec chmod a+rx {} +
dc up -d --build --no-deps --force-recreate --wait --wait-timeout 180 cloud
```

This targets application source/assets, leaving `deploy/.env`, signing keys and database volumes untouched. Do not recursively change permissions on the whole checkout or run the service as root. New images normalize `/app` permissions and retain the non-root runtime user; CI builds from an owner-only application checkout to exercise this case.

### Missing build-column recovery

Confirm the traceback names `devices.agent_build`. Inspect PostgreSQL without changing data:

```bash
dc exec -T db psql -U fenrir -d fenrir -c "SELECT version FROM schema_migrations ORDER BY version;"
dc exec -T db psql -U fenrir -d fenrir -c "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='devices' AND column_name='agent_build';"
```

Prefer deploying the repaired application, which applies migration 29. For urgent recovery while an image builds, **successfully back up first**, then apply the same narrow additive change:

```bash
(
set -e
umask 077
mkdir -p "$HOME/fenrir-backups"
fenrir_repair_backup="$HOME/fenrir-backups/before-column-repair-$(date -u +%Y%m%dT%H%M%SZ).dump"
dc exec -T db pg_dump -U fenrir -d fenrir -Fc > "$fenrir_repair_backup" && \
dc exec -T db psql -U fenrir -d fenrir -v ON_ERROR_STOP=1 \
  -c "ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_build VARCHAR(64) NOT NULL DEFAULT '';"
)
```

Do not drop tables, delete volumes or falsify migration history. Deploy the migration afterwards to record the repair. Diagnose a different traceback on its own merits rather than applying unrelated SQL.

For support, include the commit, endpoint, browser error, redacted Python traceback, database/schema version, fresh-install versus upgrade history, and reproduction steps. Redact customer data/tokens; never send dumps, signing material or vault keys.

## Development and tests

CI uses Python 3.13, Node 22, Go 1.24 and C++20. Windows builds use CMake/MSVC or MinGW. Use the workflows/platform build files for exact dependencies.

Local API/console development uses a virtual environment and SQLite, separate from production:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r cloud/requirements-dev.txt
cd console
npm ci
npm run build
cd ../cloud
FENRIR_ENV=development FENRIR_PUBLIC_URL=http://localhost:8080 \
  FENRIR_ADMIN_PASSWORD='a-local-test-password' FENRIR_FEED_SYNC=false FENRIR_VULN_INTEL=false \
  python -m uvicorn --factory fenrir_cloud.main:create_app --host 127.0.0.1 --port 8080
```

This serves the API and built console; it does not compile Windows installers. For hot UI development, run `npm run dev` from `console` in a second terminal; Vite proxies to 8080. With Go installed, `make agents` builds the Go payloads. Demo data is for a separate development database only: run `python -m fenrir_cloud.demo --help` from `cloud`.

From the repository root with the virtual environment active:

```bash
python -m pytest -q cloud/tests
cd console
npm run build
npm run test:shapes
npm run test:remote
npm run test:pages
FENRIR_UI_TEST_LEGACY=true npm run test:pages
cd ..
make -C agent/linux test
```

The page tests start an isolated Python API; `FENRIR_UI_PYTHON` can select its interpreter. Legacy mode repairs the missing-column schema before sweeping routes/tabs/details. Fixture provider/desktop transports do not establish live Microsoft changes, malware efficacy or SAS delivery. CI also runs PostgreSQL tests. **Never use production for `FENRIR_TEST_DATABASE_URL`: tests create/drop data.**

## Public release and contribution

Contributions should include reproduction steps and meaningful tests. Keep migrations additive and exercise upgrades with existing rows. Validate real endpoint/provider outcomes before marking capabilities verified.

Before relying on a release, review the dependency notices in [NOTICE](NOTICE), the supported-platform matrix and measured limits, and the relevant security/recovery/efficacy gates. Publish limitations alongside features; code presence or a mocked test is not observed parity with another product.

- [Architecture](docs/ARCHITECTURE.md), [RMM/PSA](docs/RMM_PSA.md), [RMM/PSA intelligence](docs/RMM_PSA_INTELLIGENCE.md), [zero-trust remote administration](docs/ZERO_TRUST_REMOTE_ADMINISTRATION.md), [continuous GRC](docs/CONTINUOUS_GRC.md), [remote protocol](docs/REMOTE_PROTOCOL.md)
- [Acceptance lab: prove it works before you rely on it](docs/ACCEPTANCE_LAB.md)
- [Code signing](docs/CODE_SIGNING.md), [driver/prevention limits](docs/DRIVER_SIGNING.md), [updates](docs/AUTO_UPDATE.md)
- [Parity decisions](docs/parity/decisions.md), [acceptance](docs/parity/acceptance.md), [release gates](docs/parity/release-gates.md)
- [Console rendering](docs/CONSOLE_RENDER_SAFETY.md), [Ctrl+Alt+Del](docs/REMOTE_CTRL_ALT_DEL.md)
- [Malware model](ml/README.md), [source-component history](components/README.md)
- Official references: [Docker installation](https://docs.docker.com/engine/install/ubuntu/), [Compose overrides](https://docs.docker.com/reference/compose-file/merge/), [build secrets](https://docs.docker.com/compose/how-tos/use-secrets/), [Caddy HTTPS](https://caddyserver.com/docs/automatic-https)

## Licence and support

Fenrir is licensed under the [Apache License, Version 2.0](LICENSE). Third-party attributions are in [NOTICE](NOTICE);
each bundled dependency keeps its own licence.

- **No support.** This is a free project with no support, maintenance commitment or service level. Questions, issues and
  pull requests may go unanswered.
- **No warranty.** As sections 7 and 8 of the licence state, the software is provided "AS IS", without warranties or
  conditions of any kind, and the authors are not liable for damages arising from its use. That includes damage done by
  scripts, patches, remote actions, policies or Microsoft 365 changes you run through it.
- **Your installation, your responsibility.** An RMM/EDR controls every device it manages. Keep the server patched and
  behind HTTPS, use MFA for every console account, restrict who can reach the console, protect the signing and vault keys,
  and test changes on a small group of devices first.
- **Security problems.** If you find a vulnerability, report it privately through GitHub's
  [security advisories](https://github.com/mattp8638/AntiVirus/security/advisories/new) rather than a public issue. There
  is no promise of a fix or a response time.
