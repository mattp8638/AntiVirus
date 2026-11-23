//! Exit codes. These are a stable interface for scripts and RMM tools;
//! never renumber, only add. Documented in docs/CLI.md.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Ok = 0,
    /// Unclassified failure.
    Error = 1,
    /// Bad arguments or missing configuration.
    Usage = 2,
    /// Verification found missing or corrupt data, or data failed
    /// authentication while reading.
    VerifyFailed = 3,
    /// Wrong passphrase / recovery key, or no key supplied.
    KeyError = 4,
    /// Repository or image not found.
    NotFound = 5,
    /// A destructive operation needs --yes. Nothing was changed.
    ConfirmationRequired = 6,
    /// Refused by a safety check (target in use, too small, ...). Nothing
    /// was changed.
    Safety = 7,
    /// Cancelled by the user or service.
    Cancelled = 8,
    /// Another process holds the repository (a prune, or a backup while
    /// pruning). Nothing was changed; retry later.
    Busy = 9,
    /// Succeeded, with warnings (e.g. a VSS writer failed, so part of the
    /// image is crash-consistent only).
    OkWithWarnings = 10,
}

impl ExitCode {
    pub fn name(&self) -> &'static str {
        match self {
            ExitCode::Ok => "ok",
            ExitCode::Error => "error",
            ExitCode::Usage => "usage",
            ExitCode::VerifyFailed => "verify_failed",
            ExitCode::KeyError => "key_error",
            ExitCode::NotFound => "not_found",
            ExitCode::ConfirmationRequired => "confirmation_required",
            ExitCode::Safety => "safety",
            ExitCode::Cancelled => "cancelled",
            ExitCode::Busy => "busy",
            ExitCode::OkWithWarnings => "ok_with_warnings",
        }
    }
}

#[derive(Debug)]
pub struct CliError {
    pub code: ExitCode,
    pub message: String,
}

impl CliError {
    pub fn new(code: ExitCode, message: impl Into<String>) -> Self {
        CliError {
            code,
            message: message.into(),
        }
    }
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ExitCode::Usage, message)
    }
}

impl From<core_format::Error> for CliError {
    fn from(e: core_format::Error) -> Self {
        use core_format::Error as E;
        let code = match &e {
            E::WrongKey | E::Locked => ExitCode::KeyError,
            E::NotFound(_) | E::NotARepository(_) => ExitCode::NotFound,
            E::Integrity(_) => ExitCode::VerifyFailed,
            E::Busy(_) => ExitCode::Busy,
            E::InvalidArgument(_) => ExitCode::Usage,
            _ => ExitCode::Error,
        };
        CliError::new(code, e.to_string())
    }
}

impl From<engine::EngineError> for CliError {
    fn from(e: engine::EngineError) -> Self {
        use engine::EngineError as E;
        match e {
            E::Format(f) => f.into(),
            E::Safety(m) => CliError::new(ExitCode::Safety, format!("refused for safety: {m}")),
            E::InvalidInput(m) => CliError::usage(m),
            E::Cancelled => CliError::new(ExitCode::Cancelled, "cancelled"),
            E::Io(e) => CliError::new(ExitCode::Error, e.to_string()),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::new(ExitCode::Error, e.to_string())
    }
}
