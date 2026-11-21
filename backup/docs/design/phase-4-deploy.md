# Design note: deployment-readiness milestone

Status: in progress. Brings forward the parts of Phase 4 (retention,
pruning, anomaly protection), Phase 5 (restore to virtual disk / VM) and
§11 (notifications) that an unattended deployment cannot do without, plus
agent self-update. S3 with Object Lock, append-only server mode, live Linux
snapshots and the recovery environment follow in later milestones.

## 1. Repository locks

Pruning deletes chunks that no manifest references. A backup that finds a
chunk already stored skips uploading it, so if a prune deletes that chunk
between the check and the new manifest being written, the new image is
broken. Locks rule this out.

* `locks/<lock-id>.<seq>.json`: `{ "kind": "shared" | "exclusive",
  "hostname", "pid", "created", "refreshed" }` (Unix seconds), written
  create-only. Refreshing writes `<seq+1>` and then deletes `<seq>`, so a
  live lock is never absent.
* Backup, verify-free reads, restore and forget take a **shared** lock;
  prune takes an **exclusive** lock.
* Acquire = write own lock, then list locks. Shared fails if a fresh
  exclusive lock exists; exclusive fails if any other fresh lock exists.
  Both sides write before they check, so of two racing writers at least
  one sees the other and backs off.
* Holders refresh every 2 minutes. A lock not refreshed for 30 minutes is
  stale (crashed process) and is ignored; an exclusive acquirer deletes
  stale locks. Clock skew between machines is tolerated up to that margin.
* Locks are released (deleted) when the job ends.

Lock keys follow the format's key rules; `locks/` is added to FORMAT.md.

## 2. Retention ("forget") and pruning

Policy, per backup plan (all counts optional, zero = rule off):

| Rule | Keeps |
|---|---|
| `keep_last` | the N newest images |
| `keep_daily` | newest image of each of the last N days that have one |
| `keep_weekly` | ... ISO weeks |
| `keep_monthly` | ... calendar months |
| `keep_yearly` | ... years |

Periods are in UTC. An image is kept if any rule keeps it; the newest
image of a machine is always kept; a plan without a policy keeps
everything. Images are grouped by machine ID, so each Hyper-V VM has its
own history.

* **Forget** (agent job `apply_retention`): computes the policy for the
  given machine IDs, deletes the manifests of images not kept, reports the
  removed IDs. Shared lock. Chunks are untouched, so forget alone frees no
  space but is instant and safe.
* **Prune** (agent job `prune`): exclusive lock; loads *every* manifest;
  if any manifest cannot be read and verified the prune **aborts** (its
  references are unknown); otherwise deletes chunks no manifest
  references. Reports chunks and bytes freed. `dry_run` reports only.

The server queues `apply_retention` after each successful plan backup and
a weekly `prune` per repository on its *maintenance machine* (default: the
machine that created it; changeable).

## 3. Anomaly hold (ransomware guard)

Engine stats gain `bytes_new_raw` (plaintext size of newly stored
chunks). For each successful backup the server computes:

* change ratio = `chunks_new / chunks_total`;
* incompressibility = `bytes_new_stored / bytes_new_raw` (≈1.0 for
  encrypted or random data, typically 0.3–0.7 for normal changes).

Baseline = median change ratio of the machine's previous 10 images. The
image is flagged as an anomaly when it has at least 5 previous images and
`ratio > max(0.25, 3 × baseline)` **and** incompressibility `> 0.9`; or,
with no history, when `ratio > 0.5` and incompressibility `> 0.95`.
On a flag the repository goes **on hold**: no forget or prune job is
queued or dispatched for it until an administrator reviews and releases
the hold. Backups continue, so the good images from before the event
remain and newer ones accumulate. An administrator can also place a hold
by hand (e.g. legal hold).

## 4. Notifications

Settings (stored on the server; SMTP password is the one server-side
secret, used only for mail): SMTP host/port/TLS mode/user/password/from/to,
and webhook URL with format `generic` (JSON), `slack` or `teams`.

Events: backup failed; backup completed with warnings (optional);
anomaly detected / repository on hold; machine offline for more than N
hours (once per offline period); no successful backup for N days on a
machine with an enabled plan (once per day). Sent from a background task;
failures are logged and shown in the settings page. A "send test" button
checks the configuration.

## 5. Restore

New agent job `restore` with a target:

* `vhdx { directory }`: each image disk written as a dynamic VHDX
  (only non-zero 32 MiB blocks allocated). Attach it in Hyper-V, or
  double-click it in Windows Explorer to browse and copy files: this is the
  file-level restore path until native browsing arrives.
* `hyperv_vm { name, directory, switch, start }` (Hyper-V hosts): writes
  the VHDX files, then creates a new VM with the original generation,
  CPU, memory and Secure Boot setting, attaches the disks on the original
  controller order and connects the adapters to the chosen switch. Never
  touches an existing VM: the name must be free.
* `disk { device }`: raw write to a block device or file through the
  engine's existing safety checks (not mounted, big enough, explicit
  confirmation). The UI requires typing the device path to confirm.

The VHDX writer follows [MS-VHDX]; tests check its output with the
independent `qemu-img` implementation when available, and check our
reader against VHDX files created by `qemu-img`.

## 6. Agent self-update

Agents report their build target and the SHA-256 of their own executable.
When the server holds a different build for that target (and automatic
updates are on, the default), the heartbeat response offers it. An idle
agent downloads it over the pinned connection, verifies the hash, swaps
its executable atomically (Windows: rename the running file aside), and
restarts through its service manager. A failed download or hash mismatch
leaves the running agent untouched.

## Tests

Engine: GFS selection on fixed calendars; forget/prune keep every chunk
of retained images and free the rest; prune aborts on an unreadable
manifest; locks: shared/exclusive exclusion, stale takeover, refresh never
leaves a gap. VHDX writer: round trip through our reader and through
`qemu-img convert`. Server: retention queued after plan backups and not
during a hold, anomaly flagging, notifications rendered and delivered to a
local test SMTP/webhook listener, update offers. End to end in Docker:
backup → retention → prune → restore to VHDX → bytes compared.
