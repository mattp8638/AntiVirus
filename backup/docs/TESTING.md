# Testing

## What runs today (every push)

| Layer | Where | Covers |
|---|---|---|
| Unit tests | each crate | crypto wrap/unwrap, object tamper detection (every byte flipped), key slots, recovery key files, GPT/MBR parsing incl. 4Kn, damaged primary GPT, EBR chains, random/mutated tables; manifest sign/verify/validate; local backend create-only semantics; Windows structure parsing (bitmaps, retrieval pointers, disk extents, EFI load options); composite disk routing |
| Engine integration | `crates/engine/tests` | backup→restore byte comparison on a synthetic GPT disk; partition table byte-exact incl. backup GPT; free-space garbage never stored; incremental stores only changed chunks; zero chunks skipped and zero-filled on dirty targets; full verify finds a corrupted chunk, quick verify finds a missing one; restore refuses corrupt data; **fault injection**: backend failing mid-backup → no manifest, rerun completes and reuses chunks; cancellation; restore safety (confirmation mismatch, too-small target); MBR disk; multi-disk image |
| CLI end-to-end | `crates/cli/tests` | real binary with `--json`: init, backup, list, show, dry-run, verify, restore with and without `--yes`, wrong passphrase, recovery key unlock, corrupted chunk → exit 3 |
| Reference reader | `crates/core-format/tests` | `fenrir-reader export` rebuilds a sparse disk written via the library API |
| VHDX reader | `crates/vdisk/tests` | dynamic and differencing VHDX files built by a spec-following test writer: reads match, parent-linkage mismatch refused, damaged/dirty-log files refused, random corruption never panics, engine reads only allocated blocks and restores byte-exact |
| Server API | `crates/server/tests` | first-run setup, login throttling, CSRF header, enrollment tokens and revocation, installers carry URL/pin/token/hashes and resist Host-header injection, HTTP/2 authority, sealed secrets never stored in plaintext, one job at a time, lost-job detection, plans never pile up, cross-agent isolation, re-enrollment with a new key drops access |
| Sealing interop | `crates/protocol` | a blob sealed by `ui/src/seal.ts` on WebCrypto opens in the Rust agent |
| Hyper-V parsing | `crates/agent` | PowerShell/WMI output (single and multi-element), script injection refused |
| Locks, retention, prune | `crates/core-format`, `crates/engine` | shared/exclusive exclusion, stale takeover, gap-free refresh; GFS selection over a full year of daily images; forget + prune free space while the retained image still verifies and restores byte-exact; prune refuses when any manifest is unreadable; backup and prune exclude each other |
| VHDX writer | `crates/vdisk` | round trips; **qemu-img** (independent implementation) checks our VHDX and reads it back byte for byte; our reader reads qemu's dynamic and fixed VHDX; restore of an image as VHDX |
| Server additions | `crates/server/tests` | retention queued after plan backups; anomaly flag puts the repository on hold, held jobs stay queued until release; failure and ransomware alerts delivered to a real local webhook listener; restore validation (capability, access, typed confirmation); SMTP password never returned; update offers incl. glibc→static move |
| Windows VSS smoke | CI `windows-vss-smoke` | real VSS snapshot set with writers on a Windows runner, NTFS bitmap, pagefile exclusion, probe reads through shadow devices, abort |
| Fuzzing | `fuzz/`, CI `fuzz-smoke` | manifest envelope/body, sealed objects, partition tables, key files (60 s per target per push; longer runs before release) |
| Supply chain | CI `supply-chain` | `cargo audit`, `cargo deny` (licences, sources, advisories) |

Deployment-readiness end-to-end run (Docker image, Chromium driving the
UI): alerts configured in the UI and a test delivered to a webhook; Linux
agent installed by the generated one-liner; repository created in the
wizard; a plan with "keep last 2" run three times, retention leaving
exactly two images; space reclamation deleting the orphaned data; restore
through the UI as VHDX, checked by `qemu-img check` and compared byte for
byte with the disk at backup time; simulated mass encryption flagged, the
repository put on hold with an alert, retention held until the typed
release; an agent running a different build replacing itself with the
server's build and restarting cleanly.

Earlier end-to-end (management server first release): the real
server with a self-signed pinned certificate, the UI driven in Chromium,
the generated Linux one-liner piped to `sh` (pinned `curl`, hash check,
enrollment), a repository created through the UI wizard with
browser-sealed secrets and a browser-generated recovery key, a disk backup
plus an incremental that stores 0 new bytes, and the recovery key opening
the repository with the CLI. Hyper-V backups need a Hyper-V host and run in
the VM matrix.

Run locally:

```bash
cargo test --workspace
```

```bash
cargo clippy --workspace --all-targets
```

Cross-check the Windows code from Linux (needs `gcc-mingw-w64-x86-64`):

```bash
cargo clippy -p cli -p snapshot-win --target x86_64-pc-windows-gnu
```

## VM test matrix (release gate; infrastructure not yet built)

Guests:

* Windows 11, UEFI, Secure Boot, BitLocker on
* Windows Server 2022, UEFI
* Windows 10, BIOS/MBR
* Ubuntu LTS, ext4
* Fedora, btrfs

For each guest:

1. Full backup; change files; incremental backup.
2. Restore to a blank disk of the same size; boot; compare SHA-256 of a
   fixed set of user files against the source.
3. Restore to a larger disk (Phase 2/5).
4. Restore to a VM with a different storage controller (Phase 5).
5. Boot-as-VM (Phase 3); file-level restore (Phase 5).

Fault injection on real guests: kill the agent mid-backup, drop the network
mid-upload, corrupt a chunk on storage; the next run must detect and recover.
The engine tests above already cover the same faults against a synthetic
disk.

Planned implementation: libvirt/QEMU on a self-hosted runner for KVM guests
and a Hyper-V host for Windows guests, driven by a test harness in
`tests/vm/` that provisions from cloud images / evaluation ISOs the
operator supplies (no Microsoft media is redistributed).
