//! Structured application errors.

use crate::config::ConfigError;
use crate::exit::ExitCode;
use thiserror::Error;

/// Convenience result alias for DevGuard operations.
pub type Result<T> = std::result::Result<T, DevGuardError>;

/// Top-level DevGuard error type.
#[derive(Debug, Error)]
pub enum DevGuardError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid usage: {0}")]
    Usage(String),

    #[error("{0}")]
    Message(String),
}

impl DevGuardError {
    /// Map an error to a process exit code.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            DevGuardError::Usage(_) => ExitCode::Usage,
            DevGuardError::Config(_) => ExitCode::Operational,
            DevGuardError::Io(_) => ExitCode::Operational,
            DevGuardError::Json(_) => ExitCode::Operational,
            DevGuardError::Message(_) => ExitCode::Operational,
        }
    }
}
