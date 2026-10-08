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
///
/// Assignments (`password=`, `token:`), credential URLs, GitHub tokens,
/// AWS access-key ids, OpenAI-looking keys, and bearer tokens become
/// `[REDACTED]`.
pub fn redact_text(input: &str) -> String {
    let mut out = redact_url_credentials(input);
    out = redact_token_shapes(&out);
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
        if let Some((secret_start, secret_end)) = assignment_span(input, key_end) {
            result.push_str(&input[cursor..secret_start]);
            result.push_str(REDACTED);
            cursor = secret_end;
            continue;
        }
        result.push_str(&input[cursor..key_end]);
        cursor = key_end;
    }

    result.push_str(&input[cursor..]);
    result
}

/// Byte range of an assignment value after `key_end`, not including quotes.
fn assignment_span(input: &str, key_end: usize) -> Option<(usize, usize)> {
    let bytes = input.as_bytes();
    let mut index = skip_ascii_ws(bytes, key_end);
    if matches!(bytes.get(index), Some(b'"' | b'\'')) {
        index += 1;
        index = skip_ascii_ws(bytes, index);
    }
    if !matches!(bytes.get(index), Some(b'=' | b':')) {
        return None;
    }
    index += 1;
    index = skip_ascii_ws(bytes, index);
    if let Some(quote) = bytes.get(index).copied() {
        if quote == b'"' || quote == b'\'' {
            let secret_start = index + 1;
            let mut secret_end = secret_start;
            while secret_end < bytes.len() && bytes[secret_end] != quote {
                secret_end += 1;
            }
            return Some((secret_start, secret_end));
        }
    }
    let secret_start = index;
    let mut secret_end = secret_start;
    while secret_end < bytes.len()
        && !bytes[secret_end].is_ascii_whitespace()
        && bytes[secret_end] != b'"'
        && bytes[secret_end] != b'\''
    {
        secret_end += 1;
    }
    Some((secret_start, secret_end))
}

fn skip_ascii_ws(bytes: &[u8], mut index: usize) -> usize {
    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }
    index
}

fn redact_token_shapes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = String::with_capacity(input.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if is_token_boundary(bytes, index) {
            if let Some((head, secret_len)) = bearer_span(&input[index..]) {
                result.push_str(&input[index..index + head]);
                result.push_str(REDACTED);
                index += head + secret_len;
                continue;
            }
            if let Some(len) = shaped_secret_len(&input[index..]) {
                result.push_str(REDACTED);
                index += len;
                continue;
            }
        }
        let Some(ch) = input[index..].chars().next() else {
            break;
        };
        result.push(ch);
        index += ch.len_utf8();
    }
    result
}

fn is_token_boundary(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_ident_byte(bytes[index - 1])
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn bearer_span(text: &str) -> Option<(usize, usize)> {
    let word = text.get(..6)?;
    if !word.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let bytes = text.as_bytes();
    if bytes.get(6).is_some_and(|byte| is_ident_byte(*byte)) {
        return None;
    }
    let mut index = 6usize;
    let ws_start = index;
    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }
    if index == ws_start {
        return None;
    }
    let secret_len = bytes[index..]
        .iter()
        .take_while(|byte| is_bearer_secret_byte(**byte))
        .count();
    if secret_len < 8 {
        return None;
    }
    Some((index, secret_len))
}

fn is_bearer_secret_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=')
}

fn shaped_secret_len(text: &str) -> Option<usize> {
    github_token_len(text)
        .or_else(|| aws_access_key_len(text))
        .or_else(|| openai_key_len(text))
}

fn github_token_len(text: &str) -> Option<usize> {
    if let Some(rest) = text.strip_prefix("github_pat_") {
        let extra = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if extra >= 20 {
            return Some("github_pat_".len() + extra);
        }
        return None;
    }
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            let extra = rest
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric())
                .count();
            if extra >= 20 {
                return Some(prefix.len() + extra);
            }
        }
    }
    None
}

fn aws_access_key_len(text: &str) -> Option<usize> {
    let rest = text
        .strip_prefix("AKIA")
        .or_else(|| text.strip_prefix("ASIA"))?;
    let bytes = rest.as_bytes();
    if bytes.len() < 16 {
        return None;
    }
    if !bytes[..16]
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return None;
    }
    if bytes
        .get(16)
        .is_some_and(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return None;
    }
    Some(20)
}

fn openai_key_len(text: &str) -> Option<usize> {
    let rest = text.strip_prefix("sk-")?;
    let (mark, body) = if let Some(body) = rest.strip_prefix("proj-") {
        (5, body)
    } else if let Some(body) = rest.strip_prefix("svcacct-") {
        (8, body)
    } else {
        (0, rest)
    };
    let extra = body
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
        .count();
    if extra < 20 {
        return None;
    }
    Some("sk-".len() + mark + extra)
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

    fn assert_secret_hidden(redacted: &str, secret: &str) {
        assert!(
            !redacted.contains(secret),
            "redacted output still contains a fixture secret"
        );
        assert!(
            redacted.contains(REDACTED),
            "redacted output is missing the placeholder"
        );
    }

    #[test]
    fn redacts_url_credentials() {
        let secret = "s3cret";
        let input = format!("clone https://user:{secret}@github.com/org/repo.git");
        let redacted = redact_text(&input);
        assert_secret_hidden(&redacted, secret);
        assert!(redacted.contains("github.com/org/repo.git"));
    }

    #[test]
    fn redacts_password_assignments() {
        let password = "hunter2";
        let token = "abc123";
        let input = format!("password={password} token: {token} rest");
        let redacted = redact_text(&input);
        assert_secret_hidden(&redacted, password);
        assert_secret_hidden(&redacted, token);
        assert!(redacted.contains("rest"));
    }

    #[test]
    fn redacts_quoted_password_assignments() {
        let secret = "quoted-fixture";
        let input = format!("password=\"{secret}\" and \"password\": \"{secret}\"");
        let redacted = redact_text(&input);
        assert_secret_hidden(&redacted, secret);
        assert!(redacted.contains("password=\"[REDACTED]\""));
    }

    #[test]
    fn redacts_token_shapes_in_a_fixture_report() {
        let github = format!("ghp_{}", "a".repeat(36));
        let fine = format!("github_pat_{}", "b".repeat(22));
        let aws = format!("AKIA{}", "0".repeat(16));
        let openai = format!("sk-{}", "c".repeat(32));
        let project = format!("sk-proj-{}", "d".repeat(24));
        let bearer = "e".repeat(24);
        let password = "fixture-pass";
        let input = format!(
            "report github={github} fine={fine} aws={aws} openai={openai} project={project} Authorization: Bearer {bearer} password={password} tail"
        );
        let redacted = redact_text(&input);
        for secret in [
            github.as_str(),
            fine.as_str(),
            aws.as_str(),
            openai.as_str(),
            project.as_str(),
            bearer.as_str(),
            password,
        ] {
            assert_secret_hidden(&redacted, secret);
        }
        assert!(redacted.contains("report"));
        assert!(redacted.contains("tail"));
    }

    #[test]
    fn leaves_benign_text_alone() {
        let input = "kernel 6.12.0 listening on 0.0.0.0:22";
        assert_eq!(redact_text(input), input);
    }

    #[test]
    fn leaves_short_lookalikes_alone() {
        let input = "ghp_short AKIA123 sk-short Bearer x task-list";
        assert_eq!(redact_text(input), input);
    }
}
