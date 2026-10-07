//! Redaction helpers so secrets never appear in logs or default output.

use std::borrow::Cow;

/// Environment variable name fragments treated as sensitive.
pub const SENSITIVE_ENV_HINTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "AUTH",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "SESSION",
];

const REDACTED: &str = "[REDACTED]";

/// Return whether an environment variable name looks sensitive.
pub fn is_sensitive_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SENSITIVE_ENV_HINTS.iter().any(|hint| upper.contains(hint))
}

/// Redact a value associated with a potentially sensitive name.
pub fn redact_env_value<'a>(name: &str, value: &'a str) -> Cow<'a, str> {
    if is_sensitive_env_name(name) {
        Cow::Borrowed(REDACTED)
    } else {
        Cow::Borrowed(value)
    }
}

/// Best-effort redaction of common secret-bearing patterns in free text.
pub fn redact_text(input: &str) -> String {
    let mut out = redact_url_credentials(input);
    for key in [
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "authorization",
        "private_key",
    ] {
        out = redact_key_value(&out, key);
    }
    out
}

fn redact_url_credentials(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(rel) = find_subslice(&bytes[i..], b"://") {
            let scheme_end = i + rel + 3;
            result.push_str(&input[i..scheme_end]);
            if let Some(at) = bytes[scheme_end..].iter().position(|&b| b == b'@') {
                let creds = &input[scheme_end..scheme_end + at];
                if creds.contains(':') && !creds.contains('/') && !creds.contains(' ') {
                    result.push_str(REDACTED);
                    result.push('@');
                    i = scheme_end + at + 1;
                    continue;
                }
            }
            i = scheme_end;
        } else {
            result.push_str(&input[i..]);
            break;
        }
    }
    result
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn redact_key_value(input: &str, key: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let key_lower = key.to_ascii_lowercase();
    let mut result = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while let Some(rel) = lower[cursor..].find(&key_lower) {
        let key_start = cursor + rel;
        let key_end = key_start + key.len();
        result.push_str(&input[cursor..key_end]);

        let after = &input[key_end..];
        let mut chars = after.char_indices().peekable();
        while matches!(chars.peek(), Some((_, ' ' | '\t'))) {
            let (idx, ch) = chars.next().unwrap();
            result.push(ch);
            let _ = idx;
        }

        let Some((_, sep)) = chars.next() else {
            cursor = key_end;
            continue;
        };
        if sep != '=' && sep != ':' {
            cursor = key_end;
            continue;
        }
        result.push(sep);

        while matches!(chars.peek(), Some((_, ' ' | '\t'))) {
            let (_, ch) = chars.next().unwrap();
            result.push(ch);
        }

        let value_rel_start = chars.peek().map(|(idx, _)| *idx).unwrap_or(after.len());
        let mut value_rel_end = value_rel_start;
        while let Some((idx, ch)) = chars.peek().copied() {
            if ch.is_whitespace() || ch == '"' || ch == '\'' {
                break;
            }
            value_rel_end = idx + ch.len_utf8();
            chars.next();
        }

        result.push_str(REDACTED);
        cursor = key_end + value_rel_end;
    }

    result.push_str(&input[cursor..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sensitive_env_names() {
        assert!(is_sensitive_env_name("GITHUB_TOKEN"));
        assert!(is_sensitive_env_name("db_password"));
        assert!(is_sensitive_env_name("AWS_SECRET_ACCESS_KEY"));
        assert!(!is_sensitive_env_name("HOME"));
        assert!(!is_sensitive_env_name("PATH"));
    }

    #[test]
    fn redacts_env_values() {
        assert_eq!(redact_env_value("API_TOKEN", "super-secret"), REDACTED);
        assert_eq!(redact_env_value("HOME", "/home/user"), "/home/user");
    }

    #[test]
    fn redacts_url_credentials() {
        let input = "clone https://user:s3cret@github.com/org/repo.git";
        let redacted = redact_text(input);
        assert!(!redacted.contains("s3cret"));
        assert!(redacted.contains(REDACTED));
        assert!(redacted.contains("github.com/org/repo.git"));
    }

    #[test]
    fn redacts_password_assignments() {
        let input = "password=hunter2 token: abc123 rest";
        let redacted = redact_text(input);
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("abc123"));
        assert!(redacted.contains(REDACTED));
    }

    #[test]
    fn leaves_benign_text_alone() {
        let input = "kernel 6.12.0 listening on 0.0.0.0:22";
        assert_eq!(redact_text(input), input);
    }
}
