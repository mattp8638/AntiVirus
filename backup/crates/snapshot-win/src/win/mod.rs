//! Windows-only implementation.

pub mod disks;
pub mod ioctl;
pub mod paths;
pub mod source;
pub mod system;
pub mod vss;

pub use source::{prepare_system_backup, SystemBackup, VssOptions};
