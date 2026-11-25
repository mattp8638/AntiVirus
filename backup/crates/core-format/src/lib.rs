//! Fenrir-Backup repository format.
//!
//! This crate is the single source of truth for the on-disk/on-bucket
//! format documented in `docs/FORMAT.md`. It has no platform-specific code
//! and performs no writes outside the `Backend` it is given.

#![forbid(unsafe_code)]

pub mod backend;
pub mod chunk;
pub mod crypto;
pub mod error;
pub mod extent;
pub mod fsdetect;
pub mod group;
pub mod io;
pub mod keys;
pub mod lock;
pub mod manifest;
pub mod object;
pub mod partition;
pub mod repo;
pub mod timefmt;

pub use backend::{Backend, LocalBackend, PutOutcome};
pub use chunk::{ChunkId, DEFAULT_CHUNK_SIZE};
pub use error::{Error, Result};
pub use extent::Extent;
pub use keys::RecoveryKey;
pub use manifest::ManifestBody;
pub use repo::{InitOptions, Repository};
