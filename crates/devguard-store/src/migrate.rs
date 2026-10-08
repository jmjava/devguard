//! Schema migrations for the DevGuard SQLite file.
//!
//! Version 1 creates `runs`, `observations`, and `snapshots`. The
//! `user_version` pragma records the applied version inside the database.

use rusqlite::Connection;

use crate::error::{Result, StoreError};

/// Current schema version written to `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 1;

const MIGRATION_001: &str = include_str!("../migrations/001_initial.sql");

/// Apply any pending migrations.
///
/// Opening the same file twice leaves the schema and existing rows in place.
pub fn migrate(conn: &Connection) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::Message(format!(
            "database schema version {version} is newer than this DevGuard build ({SCHEMA_VERSION})"
        )));
    }
    if version < 1 {
        tx.execute_batch(MIGRATION_001)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    tx.commit()?;
    Ok(())
}
