use thiserror::Error;

/// Errors from the repository format layer.
///
/// Variants are coarse on purpose: callers (CLI, agent) map them to exit
/// codes and user messages, so they must say *what kind* of failure it was.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("object not found: {0}")]
    NotFound(String),

    #[error("not a Fenrir-Backup repository: {0}")]
    NotARepository(String),

    #[error("unsupported format version: {what} version {version}")]
    UnsupportedVersion { what: &'static str, version: u32 },

    #[error("wrong passphrase or recovery key")]
    WrongKey,

    #[error("repository is locked: unlock it with a passphrase or recovery key first")]
    Locked,

    /// Data failed authentication or its hash did not match. Always means
    /// corruption or tampering; never retried silently.
    #[error("integrity failure: {0}")]
    Integrity(String),

    #[error("malformed data: {0}")]
    Malformed(String),

    /// Another process holds a conflicting repository lock.
    #[error("repository busy: {0}")]
    Busy(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The storage keeps the object immutable (S3 Object Lock) until the
    /// given time; it cannot be deleted yet.
    #[error("kept by the storage's object lock: {0}")]
    Retained(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn malformed(msg: impl Into<String>) -> Self {
        Error::Malformed(msg.into())
    }
    pub fn integrity(msg: impl Into<String>) -> Self {
        Error::Integrity(msg.into())
    }
}
