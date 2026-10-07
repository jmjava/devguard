//! Process exit codes (SPEC §4).

/// DevGuard exit codes.
///
/// - `0` success / scan complete without configured threshold breaches
/// - `1` operational error
/// - `2` completed with policy findings
/// - `3` partial / unknown coverage
/// - `64` invalid CLI usage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    Operational = 1,
    Findings = 2,
    Partial = 3,
    Usage = 64,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

impl From<ExitCode> for i32 {
    fn from(value: ExitCode) -> Self {
        value.as_i32()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_values_match_spec() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::Operational.as_i32(), 1);
        assert_eq!(ExitCode::Findings.as_i32(), 2);
        assert_eq!(ExitCode::Partial.as_i32(), 3);
        assert_eq!(ExitCode::Usage.as_i32(), 64);
    }
}
