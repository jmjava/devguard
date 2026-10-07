//! Provider/collector contract used by host, health, security, and GPU adapters.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Outcome of a single collector invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionStatus {
    Complete,
    Partial,
    Unavailable,
}

/// Wrapper returned by every collector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Collection<T> {
    pub observed_at: DateTime<Utc>,
    pub status: CollectionStatus,
    pub data: Option<T>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Tool or source that produced this collection (e.g. `nvidia-smi`, `sysinfo`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl<T> Collection<T> {
    pub fn complete(data: T, source: impl Into<String>) -> Self {
        Self {
            observed_at: Utc::now(),
            status: CollectionStatus::Complete,
            data: Some(data),
            warnings: Vec::new(),
            source: Some(source.into()),
        }
    }

    pub fn partial(data: T, source: impl Into<String>, warnings: Vec<String>) -> Self {
        Self {
            observed_at: Utc::now(),
            status: CollectionStatus::Partial,
            data: Some(data),
            warnings,
            source: Some(source.into()),
        }
    }

    pub fn unavailable(source: impl Into<String>, warning: impl Into<String>) -> Self {
        Self {
            observed_at: Utc::now(),
            status: CollectionStatus::Unavailable,
            data: None,
            warnings: vec![warning.into()],
            source: Some(source.into()),
        }
    }
}

/// Contract for read-only metric and inventory collectors.
pub trait Collector {
    type Output: Serialize;

    fn id(&self) -> &'static str;

    fn collect(&self) -> Result<Collection<Self::Output>, CollectError>;
}

/// Errors raised while collecting observations.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("collector `{collector}` unavailable: {reason}")]
    Unavailable { collector: String, reason: String },

    #[error("collector `{collector}` failed: {reason}")]
    Failed { collector: String, reason: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_has_no_data() {
        let c: Collection<()> = Collection::unavailable("nvidia-smi", "not installed");
        assert_eq!(c.status, CollectionStatus::Unavailable);
        assert!(c.data.is_none());
        assert_eq!(c.source.as_deref(), Some("nvidia-smi"));
    }
}
