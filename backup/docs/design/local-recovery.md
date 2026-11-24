# Local recovery partition (Windows)

Recovery media (phase-2.md, the Windows PE builder) restore a machine that no longer starts, but someone has to
have the stick. A local recovery partition puts the same capability on the machine itself: a **Fenrir Recovery**
entry in the boot menu starts a small recovery system that connects to the server as a recovery session, from
which the machine is restored from its backups, onto the same disk or a replacement, on the same hardware or
different hardware (the storage-driver fix-up and driver injection of phase-5-hardware.md apply).

## What is installed

* **A partition** of about 1 GB, taken from the end of C: (`Resize-Partition`), formatted NTFS, labelled
  *Fenrir Recovery*, then marked as a Windows recovery partition: GPT type `de94bba4-06d1-4d40-a16a-bfd50179d6ac`
  with attributes `0x8000000000000001` (hidden, no drive letter, platform-required), or MBR type `0x27`. Its own
  partition, so it starts even when C: is damaged or BitLocker-encrypted.
* **A recovery image**, `\Fenrir\boot.wim`, built from a copy of this machine's own Windows Recovery Environment
  (`winre.wim`, part of every Windows 10/11; located with `reagentc /info`). Nothing Microsoft-licensed is
  redistributed: the base comes from the machine it runs on. Added to it:
  * the agent (`fenrir-backup-agent.exe`, the same build that runs the service) and `X:\fenrir\recovery.json`;
  * this machine's network, storage and disk-controller driver packages (`Get-WindowsDriver -Online`, classes Net,
    SCSIAdapter, HDC, exported with `pnputil`), added to the image with DISM so it reaches the network and disks,
    and kept in `X:\fenrir\drivers` for the restored Windows;
  * `startnet.cmd` (network, then the agent in recovery mode, and a status window), with Windows RE's own
    `winpeshl.ini` removed so that Windows PE runs it.
* **Boot entries**: a RAM disk device (`\Fenrir\boot.sdi`) and a Windows PE loader entry *Fenrir Recovery*
  (`ramdisk=[R:]\Fenrir\boot.wim`), added at the end of the boot menu, whose timeout is raised to 5 s if it was
  lower. Optionally (**start it automatically**) it becomes the Windows entry's `recoverysequence`, so Windows
  starts it instead of Windows RE after failed starts; the previous value is kept and restored on removal.

## The enrolment code

The recovery system enrols as a recovery session with an enrolment code for role `recovery`, valid a year and
specific to the machine (`local-recovery:<agent id>`); the server makes a new one, and revokes the previous one,
each time the image is built or the partition removed. The agent adds its own server address and certificate
pin. A recovery session can do nothing until an administrator gives it access to a repository, so the code on the
unencrypted partition lets someone with the disk in hand start a session, not read a backup.

## Keeping it current

The machine reports the partition in its inventory (size, when built, agent version inside, code expiry). The
server rebuilds it in place (**Refresh**) after the agent updates and when the code has less than 60 days left; a
rebuild needs no repartitioning, only a larger image than the partition holds (then remove and install again).

## Safety

* Installing and removing repartition the system disk: the job carries the machine's name, typed by the
  administrator, and the agent refuses it unless it matches (as `--yes` does for the agent's own command).
* Room: C: must keep 2 GB above the smallest size Windows allows it to shrink to.
* Everything the agent created is recorded (`local-recovery.json` in its state folder) as soon as it exists, so
  removal can undo a partial install. Removal deletes only the partition at the recorded offset and size, deletes
  the two boot entries, restores the recovery sequence, and gives the space back to C: when it follows it.
* Building and installing happen in Windows; the recovery system never writes to the disk except through a restore
  the administrator starts (typed confirmation, as for any disk restore).

## Restoring onto the same disk

The recovery system runs from RAM (`X:`), so the disk holding its partition can be overwritten. A backup taken after
local recovery was installed contains the partition too, so the restored disk has it again; a backup taken before
does not, and the boot menu entry left by the restore points nowhere until local recovery is installed again.

## Command line and tests

`fenrir-backup-agent local-recovery install --settings recovery.json [--size-mb N] [--auto-start] --yes` and
`local-recovery remove --yes` do the same by hand. CI (`local-recovery` job, `ci/windows-local-recovery.ps1`)
installs it on a Windows runner (from its Windows RE, or the ADK's Windows PE when the runner has none), checks the
partition, boot entries and image contents, removes it and checks that everything is as before. Starting the
recovery system itself needs a reboot, which hosted CI cannot do; the image is the same Windows PE the recovery
media use, whose restore path is tested end to end.
