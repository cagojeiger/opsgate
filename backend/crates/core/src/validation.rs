//! Small reusable input-validation primitives.
//!
//! Keep this module generic and secret-safe: error messages should name fields
//! and limits, but must not echo caller-provided values.

use crate::{Error, Result};

pub fn trim_required(field: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::validation(format!("{field} is required")));
    }
    Ok(trimmed.to_owned())
}

pub fn reject_crlf(field: &str, value: &str) -> Result<()> {
    if value.contains(['\r', '\n']) {
        return Err(Error::validation(format!("{field} must not contain CR/LF")));
    }
    Ok(())
}

pub fn validate_text_len(field: &str, value: &str, min: usize, max: usize) -> Result<()> {
    let len = value.chars().count();
    if len < min || len > max {
        return Err(Error::validation(format!(
            "{field} must be {min}-{max} characters"
        )));
    }
    Ok(())
}

pub fn validate_count(field: &str, count: usize, max: usize) -> Result<()> {
    if count > max {
        return Err(Error::validation(format!("{field} count must be <= {max}")));
    }
    Ok(())
}

pub fn validate_reason(reason: &str) -> Result<String> {
    validate_bounded_text("reason", reason, 8, 512)
}

pub fn validate_purpose(purpose: &str) -> Result<String> {
    validate_bounded_text("purpose", purpose, 8, 512)
}

pub fn clamp_i64(value: Option<i64>, default: i64, min: i64, max: i64) -> i64 {
    value.unwrap_or(default).clamp(min, max)
}

pub fn validate_max_bytes(
    value: Option<usize>,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize> {
    let value = value.unwrap_or(default);
    if value < min || value > max {
        return Err(Error::validation(format!(
            "max_bytes must be in range [{min},{max}]"
        )));
    }
    Ok(value)
}

pub fn validate_http_path(path: &str) -> Result<String> {
    let path = trim_required("path", path)?;
    reject_crlf("path", &path)?;
    if !path.starts_with('/') {
        return Err(Error::validation("path must start with /"));
    }
    if path.contains("..") {
        return Err(Error::validation("path traversal not allowed"));
    }
    if path.contains("//") {
        return Err(Error::validation("double slash not allowed"));
    }
    if path.contains(['?', '#']) {
        return Err(Error::validation("path must not contain ? or #"));
    }
    Ok(path)
}

pub fn validate_http_header_name(name: &str, max_len: usize) -> Result<String> {
    let name = trim_required("header name", name)?;
    validate_text_len("header name", &name, 1, max_len)?;
    if !valid_http_token(&name) {
        return Err(Error::validation("invalid header name"));
    }
    Ok(name)
}

pub fn validate_http_header_value(value: &str, max_len: usize) -> Result<String> {
    reject_crlf("header value", value)?;
    validate_text_len("header value", value, 0, max_len)?;
    Ok(value.to_owned())
}

pub fn valid_http_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_http_token_char)
}

fn is_http_token_char(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

fn validate_bounded_text(field: &str, value: &str, min: usize, max: usize) -> Result<String> {
    let value = trim_required(field, value)?;
    reject_crlf(field, &value)?;
    validate_text_len(field, &value, min, max)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_text_trims_and_rejects_crlf_without_echoing_value() -> Result<()> {
        assert_eq!(validate_reason("  rotate safely  ")?, "rotate safely");
        let msg = validate_reason("secret-token\nleak")
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(msg.contains("reason"));
        assert!(!msg.contains("secret-token"));
        Ok(())
    }

    #[test]
    fn max_bytes_requires_range() -> Result<()> {
        assert_eq!(validate_max_bytes(None, 4096, 256, 1024 * 1024)?, 4096);
        assert!(validate_max_bytes(Some(1), 4096, 256, 1024 * 1024).is_err());
        Ok(())
    }

    #[test]
    fn http_path_accepts_only_relative_absolute_paths() -> Result<()> {
        assert_eq!(validate_http_path(" /api/v1/pods ")?, "/api/v1/pods");
        assert!(validate_http_path("api/v1").is_err());
        assert!(validate_http_path("/api/../secret").is_err());
        assert!(validate_http_path("/api//v1").is_err());
        assert!(validate_http_path("/api?v=1").is_err());
        assert!(validate_http_path("/api#frag").is_err());
        Ok(())
    }

    #[test]
    fn header_validation_is_token_and_crlf_safe() -> Result<()> {
        assert_eq!(
            validate_http_header_name("X-Request-Id", 128)?,
            "X-Request-Id"
        );
        assert!(validate_http_header_name("bad header", 128).is_err());
        assert!(validate_http_header_name("X-Too-Long", 4).is_err());

        assert_eq!(
            validate_http_header_value("application/json", 32)?,
            "application/json"
        );
        let msg = validate_http_header_value("secret-token\nleak", 128)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(msg.contains("header value"));
        assert!(!msg.contains("secret-token"));
        Ok(())
    }

    #[test]
    fn count_validation_reports_only_field_and_limit() {
        assert!(validate_count("headers", 16, 16).is_ok());
        let msg = validate_count("headers", 17, 16)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(msg.contains("headers"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn clamp_i64_uses_default_and_bounds() {
        assert_eq!(clamp_i64(None, 50, 1, 100), 50);
        assert_eq!(clamp_i64(Some(-5), 50, 1, 100), 1);
        assert_eq!(clamp_i64(Some(500), 50, 1, 100), 100);
    }
}
