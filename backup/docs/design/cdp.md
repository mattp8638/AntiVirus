# Continuous data protection (true CDP)

Frequent backups (every 5–60 minutes, `docs/design/phase-3-frequent.md`) lose up to an interval of work. CDP records
**every write** to a volume as it happens, so the volume can be restored to any second (to the granularity of the
timestamp marks, one per second by default) since its base image.

## Linux: device-mapper `log-writes`

The kernel's `dm-log-writes` target (upstream since 4.1; `Documentation/admin-guide/device-mapper/log-writes.rst`)
passes I/O through to a data device and appends every write, discard, flush and named **mark** to a log device, in
order. Fenrir uses it unchanged; no kernel code of its own.

```
  file system ──> /dev/mapper/fenrir-cdp-<name> (log-writes) ──> the logical volume (data)
                                         └────────────────────────> journal A or B (LVs in the same VG)
```

* `cdp enable` (volume unmounted): two journal LVs `<lv>-fenrir-cdp-a/-b` and the log-writes device over the volume.
  From then on the file system is mounted from `/dev/mapper/fenrir-cdp-<name>` (and in `/etc/fstab`). The state
  (journals, which is in use, sequence numbers, the base) is kept in `/var/lib/fenrir-backup/cdp-<name>.json`.
* `cdp run` (a service): every `--mark-every` seconds a mark `fenrir-t<unix seconds>` is written into the journal
  (`dmsetup message … mark`). Every `--rotate-every` seconds, or when the journal is 70% full, the journals are
  **swapped**: a final mark, the device suspended (in-flight writes finish, new ones wait), its table reloaded with
  the other journal, resumed — a pause of milliseconds. The finished journal (only its used part) is then stored as
  an image (OS family `cdp-journal`, details `{seq, bytes, first, last}`) in the repository: encrypted,
  deduplicated, retained like any image.
* A **base image** is taken at the first swap and then every `--base-every` seconds: right after the swap (with the
  device running again: nothing but the table reload happens while it is suspended, as LVM would wait on a suspended
  device), an LVM snapshot of the volume is made and then a timestamp mark is written. Replaying the new journal from
  its start onto that snapshot gives the volume exactly as at any mark from that one on, because block writes
  re-applied in order end in the same state (writes the snapshot already holds are written again, followed by any
  later ones). The base is therefore valid from its mark on; earlier seconds restore from the previous base. It is
  backed up as an image (`cdp-base`, `{seq, unix}`) and the snapshot removed.
* If `cdp run` stops (reboot, crash), the kernel keeps journalling; the next run ships that journal first. A full
  journal stops logging (`logging_disabled`) rather than blocking writes; the next swap ships it, and the next base
  image closes the gap (a restore cannot pass a journal whose logging stopped — see below).

## Restore (`cdp restore --at T --target …`)

1. The newest base with a time ≤ T is restored to the target (a file or a selected device; `--yes` required, as for
   every destructive restore).
2. The journals from that base on are fetched in sequence order and replayed onto it: each write and discard is
   applied in the order the kernel logged it, up to the **last mark at or before T**. Writes after that mark have no
   known time and are left out. A missing sequence number (pruned, never shipped) stops the restore with an error
   saying how far back it can go.
3. The result is the volume as it was at that second: crash-consistent, like a power cut at that moment (ext4 and
   XFS replay their own journals on mount).

`cdp points` lists the bases and journals with their time ranges: the window of restorable seconds.

## Format notes (`crates/cdp/src/journal.rs`)

A journal is the kernel's format: a super block sector {magic `0x6a736677736872`, version 1, entry count, sector
size}, then entries of one sector each {sector, number of sectors, flags, data length} followed by a write's data.
Marks carry their name in the entry sector. The reader checks the magic, version and sector size and only reads as
many entries as the super block counts (the kernel updates it on every mark and FUA, so the final mark at a swap
makes it exact).

## Retention

Journals depend on their base and on every journal before them. Retention keeps CDP images as a chain: a base and
its journals are kept or forgotten together, by the base's age (keep N bases). Points older than the oldest base
kept cannot be restored.

## Windows

The same model needs a volume filter driver (journal writes to a reserved area, marks from user mode, swap by
flipping the active area). Drivers on Windows must be signed by Microsoft (attestation signing, an EV certificate),
which this project cannot do in CI; until a signed driver exists, Windows machines use frequent VSS backups. The
journal format above is deliberately the same so that restore needs no changes.

## Tests

* `crates/cdp/src/journal.rs`: journals written in the kernel's format, replayed to marks and to times.
* `ci/e2e-cdp.sh` (CI job `cdp`): the real kernel target on an LVM volume, ext4 mounted through it, a file written
  three times while `cdp run` marks every second and swaps every 8 seconds; restores to the second after each version
  give exactly that version (byte-identical) and a clean file system, including across a journal swap.
