//! Windows image source: a VSS snapshot set with writers (application
//! consistent), NTFS used-cluster bitmaps, exclusion of paging and
//! hibernation files, and raw reads of partitions VSS cannot snapshot
//! (ESP, MSR).
//!
//! The FFI lives in `win` and only builds on Windows; the parsing and disk
//! composition logic is portable and unit-tested on every platform.

pub use engine::composite;
pub mod apps;
pub mod parse;

#[cfg(windows)]
pub mod win;

#[cfg(windows)]
pub use win::{prepare_system_backup, SystemBackup, VssOptions};
