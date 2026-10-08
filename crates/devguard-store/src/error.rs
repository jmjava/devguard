//! Errors from opening or writing the DevGuard SQLite store.

use thiserror::Error;

/// Failure while opening, migrating, or writing the store.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("{0}")]
    Message(String),
}

/// Convenience result alias for store operations.
pub type Result<T> = std::result::Result<T, StoreError>;
