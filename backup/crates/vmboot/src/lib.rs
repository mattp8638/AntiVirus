//! Boot a backup image as a QEMU/KVM VM straight from the repository, and
//! decide whether it booted.
//!
//! Each image disk is exported read-only over NBD (`nbd-server`); QEMU
//! runs on qcow2 overlays backed by those exports, so the backup is never
//! written. Networking is QEMU user mode with `restrict=on`: the guest can
//! reach nothing outside, and the host reaches it only through loopback
//! port forwards.

#[cfg(unix)]
mod kvm;
pub mod png;
pub mod probe;
#[cfg(unix)]
mod qmp;

#[cfg(unix)]
pub use kvm::*;
