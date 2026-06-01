use opsgate_core::{Error, Result};

use super::CredentialPolicy;

pub fn validate_allowed_headers_do_not_overlap_secret(
    policy: &CredentialPolicy,
    secret_header_names: &[String],
) -> Result<()> {
    for allowed in &policy.allowed_request_headers {
        for secret in secret_header_names {
            if allowed.eq_ignore_ascii_case(secret) {
                return Err(Error::validation(format!(
                    "allowed_request_headers must not include secret header {secret:?}"
                )));
            }
        }
    }
    Ok(())
}

pub fn contains_fold(items: &[String], want: &str) -> bool {
    items.iter().any(|item| item.eq_ignore_ascii_case(want))
}

pub fn valid_header_name(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty() && name.bytes().all(is_token_char)
}

fn is_token_char(byte: u8) -> bool {
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

pub fn header_blocked(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower.starts_with("x-forwarded-")
        || matches!(
            lower.as_str(),
            "authorization"
                | "connection"
                | "content-length"
                | "content-type"
                | "cookie"
                | "host"
                | "keep-alive"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        )
}

pub fn secret_header_blocked(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower.starts_with("x-forwarded-")
        || matches!(
            lower.as_str(),
            "connection"
                | "content-length"
                | "content-type"
                | "host"
                | "keep-alive"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        )
}

pub fn canonical_header_name(name: &str) -> String {
    name.trim()
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut out = first.to_uppercase().collect::<String>();
                    out.push_str(&chars.as_str().to_ascii_lowercase());
                    out
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_transport_and_auth_headers() {
        assert!(header_blocked("X-Forwarded-For"));
        assert!(header_blocked("Authorization"));
        assert!(header_blocked("Content-Type"));
        assert!(!header_blocked("If-None-Match"));
    }

    #[test]
    fn validates_header_names() {
        assert!(valid_header_name("X-Request-Id"));
        assert!(!valid_header_name("bad header"));
        assert!(!valid_header_name(""));
    }
}
