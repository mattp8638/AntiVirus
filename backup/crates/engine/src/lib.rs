//! Backup, restore and verify on top of `core-format`.
//!
//! Platform code (VSS, LVM, ...) lives in the snapshot crates and reaches
//! the engine only through the `DiskSource` trait.

#![forbid(unsafe_code)]

pub mod backup;
pub mod bootfix;
pub mod clone;
pub mod composite;
pub mod control;
pub mod copy;
pub mod fit;
pub mod grow;
pub mod layout;
pub mod restore;
pub mod retention;
pub mod source;
pub mod target;
pub mod verify;

pub use backup::{
    backup, plan_image, probe_reads, BackupOptions, BackupReport, ChangedSince, ImageMeta,
    PlannedDisk, Progress,
};
pub use control::JobControl;
pub use restore::{restore_disk, RestoreOptions, RestoreReport};
pub use source::{CapturePlan, DiskInfo, DiskSource, PartitionPlan, ReadAtSource};
pub use target::{DestructiveConfirmation, FileTarget, WriteTarget};
pub use verify::{verify, VerifyLevel, VerifyReport};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Format(#[from] core_format::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A safety rule refused the operation. Nothing was written.
    #[error("refused for safety: {0}")]
    Safety(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("cancelled")]
    Cancelled,
    /// A chunk the change tracker reported as unchanged was read and
    /// differs from the base image: the tracker missed a write. The image
    /// was not written; back up again reading the disks in full.
    #[error("change tracking missed a write: {0}")]
    ChangeTrackingMissed(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;

/// Shared lock for readers. A prune in progress is an error (it may be
/// deleting what we are about to read); a repository we cannot write a lock
/// to (read-only media) is read without one.
pub(crate) fn reader_lock(
    repo: &core_format::Repository,
) -> crate::Result<Option<core_format::lock::RepoLock>> {
    match repo.lock(core_format::lock::LockKind::Shared) {
        Ok(l) => Ok(Some(l)),
        Err(e @ core_format::Error::Busy(_)) => Err(e.into()),
        Err(_) => Ok(None),
    }
}
