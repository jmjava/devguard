//! Versioned JSON envelope for machine-readable CLI output.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current JSON schema version for CLI envelopes.
pub const SCHEMA_VERSION: u32 = 1;

/// Top-level JSON document written to stdout when `--json` is set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonEnvelope<T> {
    pub schema_version: u32,
    pub command: String,
    pub observed_at: DateTime<Utc>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> JsonEnvelope<T> {
    pub fn success(command: impl Into<String>, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command: command.into(),
            observed_at: Utc::now(),
            ok: true,
            data: Some(data),
            warnings: Vec::new(),
            error: None,
        }
    }

    pub fn success_with_warnings(
        command: impl Into<String>,
        data: T,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command: command.into(),
            observed_at: Utc::now(),
            ok: true,
            data: Some(data),
            warnings,
            error: None,
        }
    }

    pub fn failure(command: impl Into<String>, error: impl Into<String>) -> JsonEnvelope<()> {
        JsonEnvelope {
            schema_version: SCHEMA_VERSION,
            command: command.into(),
            observed_at: Utc::now(),
            ok: false,
            data: None,
            warnings: Vec::new(),
            error: Some(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_includes_schema_version() {
        let envelope = JsonEnvelope::success("doctor", json!({"checks": []}));
        let value = serde_json::to_value(&envelope).expect("serialize");
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["command"], "doctor");
        assert_eq!(value["ok"], true);
        assert!(value["data"].is_object());
        assert!(value.get("error").is_none() || value["error"].is_null());
    }

    #[test]
    fn failure_envelope_omits_data() {
        let envelope = JsonEnvelope::<()>::failure("config validate", "missing config");
        let value = serde_json::to_value(&envelope).expect("serialize");
        assert_eq!(value["ok"], false);
        assert!(value.get("data").is_none() || value["data"].is_null());
        assert_eq!(value["error"], "missing config");
    }
}
