# recovery-env

Build scripts for the Fenrir-Backup recovery environment (Phase 2):

* Debian stable live image, UEFI with Secure Boot via Debian's signed shim
  and kernel, plus legacy BIOS. Contains `fenrir-backup`, a text UI and the local
  web UI.
* Optional PowerShell script that builds a WinPE image locally with the
  user's own Microsoft ADK. WinPE is never redistributed.
* Outputs: ISO, USB writer, and a "rescue kit" USB layout.

Not started. This directory is not a Cargo crate; it may use copyleft
tools (live-build, GRUB) because it only assembles an image. Its own
component list will be kept in `recovery-env/THIRD_PARTY.md`.
