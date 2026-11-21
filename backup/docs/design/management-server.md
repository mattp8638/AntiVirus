# Design note: management server, web UI, agent downloads, Hyper-V hosts

Status: in progress on this branch. This brings forward the spec's "central
server" item (§11) and makes the web UI the main way to run Fenrir-Backup.
The CLI stays, and covers everything for scripting and RMM use.

## Shape

```text
 Browser ──HTTPS──▶ fenrir-server ◀──HTTPS (agent polls)── fenrir-backup-agent (Windows / Linux / macOS / Hyper-V host)
                     │  SQLite: users, agents, jobs, plans,                   │
                     │  repositories, sealed secrets, image index             ▼
                     └─ serves the web UI and agent downloads          repository (local disk, SMB share, NAS)
```

* **fenrir-server** (`crates/server`): one binary, axum + SQLite, serves the
  REST API and the built web UI. No agent ever accepts inbound connections;
  agents poll, so they work behind NAT and host firewalls.
* **fenrir-backup-agent** (`crates/agent`): Windows service, systemd unit or launchd
  daemon. Enrolls once, then heartbeats every 15 s, receives jobs, runs them
  with `engine`, streams progress and results back.
* **Web UI** (`ui/`): React + TypeScript + Vite, built to static files the
  server serves.

## Downloads ("Add a machine")

The UI creates an **enrollment token** (random 32 bytes, stored hashed,
expiry 7 days by default, reusable until expiry or revocation) and offers,
per platform:

| Platform | Download | Installs as |
|---|---|---|
| Windows 10/11, Server | `install-fenrir-backup.ps1` | Windows service `FenrirBackupAgent` (LocalSystem) |
| Hyper-V host | `install-fenrir-backup-hyperv.ps1` | Same service, role `hyperv` |
| Linux (x86-64, arm64) | `install-fenrir-backup.sh` | systemd unit `fenrir-backup-agent.service` |
| macOS (Apple silicon, Intel) | `install-fenrir-backup-macos.sh` | launchd daemon `uk.fenrir-backup.agent` |

Each script is generated on request with: server URL, the server
certificate's SHA-256 pin, the enrollment token, the role, and the SHA-256
of each agent binary. It downloads the binary from the server, **refuses to
install unless the hash matches**, writes the config, registers the service
and enrolls. A one-line command is shown next to each download for
pasting into an elevated shell. Uninstall scripts are generated the same way.

Agent binaries are built by CI for each target and placed in the server's
`agents/<target>/` directory (shipped with the server package). The UI
shows a platform as unavailable if its binary is missing, rather than
offering a broken download.

## TLS and trust

* With `--tls-cert/--tls-key` the server uses that certificate.
* Otherwise it generates a self-signed certificate on first start (kept in
  its data directory) and **pins** it: installers and agents carry its
  SHA-256 and accept only that certificate. No CA or manual trust needed,
  and no man-in-the-middle window.
* `--http` (no TLS) exists only for running behind a TLS-terminating reverse
  proxy; the server warns loudly.

## Keys never reach the server

The spec requires that repository keys never leave the client. With a
central server, "client" means the agents and the administrator's browser:

1. At enrollment each agent generates an X25519 key pair; the private key
   stays on the machine (DPAPI-protected on Windows, root-only file on
   Linux/macOS), the public key goes to the server.
2. When an administrator creates a repository or grants a machine access,
   the **browser** encrypts the repository passphrase to each chosen agent's
   public key (X25519 → HKDF-SHA256 → AES-256-GCM, WebCrypto). The server
   stores only these sealed blobs and relays them to the agent.
3. The browser also generates the repository ID and the recovery key, and
   offers the recovery key file for download before anything is sent. The
   agent initialises the repository with that recovery key
   (`Repository::init_with`), so the recovery key never exists on the
   server either.

Consequence, stated in the UI: if the passphrase and recovery key are both
lost, nobody, including the server operator, can read the backups.

Sealed blob format (JSON): `{"v":1,"epk":b64(32),"nonce":b64(12),"ct":b64}`;
`key = HKDF-SHA256(ikm = X25519(eph, agent), salt = epk || agent_pk,
info = "fenrir-agent-seal-v1")`; AES-256-GCM with no AAD.

## Authentication

* Administrators: username + password (Argon2id), session cookie
  (`HttpOnly`, `SameSite=Strict`, `Secure` under TLS), 12 h idle expiry.
  Mutating requests must carry `X-Fenrir-Csrf: 1` (a custom header a
  cross-site form cannot send). First start shows a one-time setup page to
  create the first administrator. Roles beyond "admin" come later.
* Agents: bearer token issued at enrollment, stored hashed (SHA-256) on the
  server. An administrator can revoke an agent.
* Login is rate-limited per username and source address.

## Jobs

`backup` (system / disks / Hyper-V VMs), `verify`, `init_repository`,
`refresh_images`. The server queues jobs; the agent takes one at a time.
Plans (schedules) create backup jobs: every N hours, or daily/weekly at a
time, per machine or per group of machines, with a repository and options
(rate limit, verify-after, which VMs). Missed runs while a machine was
offline run once at next contact, not once per missed slot.

## Hyper-V hosts

The agent on a Hyper-V host lists VMs (name, ID, state, generation, disks)
and reports them; the UI shows them under the host with per-VM selection.
Backing up a VM:

1. Create a **recovery checkpoint** through WMI
   (`Msvm_VirtualSystemSnapshotService.CreateSnapshot`, SnapshotType
   32768, ConsistencyLevel application-consistent). Hyper-V quiesces the
   guest through its integration services (VSS inside Windows guests,
   fsfreeze in Linux guests with the daemons installed) and redirects
   writes to new `.avhdx` files. The original virtual disks are now frozen.
2. Read each frozen virtual disk with Fenrir's own VHDX reader
   (`crates/vdisk`, implemented from the published MS-VHDX specification),
   which follows differencing chains and reports only allocated blocks, so
   unallocated space is never read.
3. Store one image per VM: one disk per virtual disk, machine ID
   `hyperv-vm:<VM GUID>`, plus a `vm` section in the manifest (generation,
   CPU, memory, Secure Boot, disk controller locations, network switch
   names) used later to recreate the VM.
4. Remove the checkpoint (Hyper-V merges the `.avhdx` back).

A VM with existing user checkpoints is supported: the reader resolves the
whole chain. If integration services are missing, Hyper-V falls back to a
crash-consistent checkpoint and the image is marked `crash`.
Incremental runs re-read allocated blocks and upload only changed chunks;
Hyper-V Resilient Change Tracking is a later optimisation and never the
source of truth.

## macOS scope

The macOS agent enrolls, reports inventory, runs verify jobs and can image
non-system disks. Full macOS system images are not useful: since macOS 11
the system volume is a cryptographically sealed snapshot that only Apple's
installer can recreate, and the data volume is FileVault-encrypted APFS.
macOS protection therefore needs **file-level** backup of the data volume
from an APFS snapshot; that is a new engine mode, planned next, and the UI
says so instead of pretending.

## Format change

Manifest body gains an optional `vm` object (§5.3 of FORMAT.md). Optional
fields are allowed within version 1; older readers ignore it.
`Repository::init_with` lets a caller supply the repository ID and recovery
key; the stored format is unchanged.

## Tests

* vdisk: synthetic fixed, dynamic and differencing VHDX files built in the
  tests, read back and compared; corrupt headers rejected.
* server: in-process API tests: setup, login, CSRF, enrollment, token
  expiry/revocation, heartbeat and job dispatch, plan scheduling, installer
  generation contains the pin and hashes.
* sealing: a vector produced by Node's WebCrypto (same API the browser
  uses) is opened by the Rust agent code.
* end to end: server + Linux agent on this machine: enroll with the
  generated installer config, create a repository from sealed secrets,
  run a backup of a disk image, see it in the UI.
* Windows-only pieces (service, Hyper-V WMI) are compile-checked and get a
  CI job on a Windows runner; a Hyper-V VM backup needs a nested-virt
  host and runs in the VM matrix.
