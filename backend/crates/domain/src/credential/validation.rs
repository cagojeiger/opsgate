use secrecy::ExposeSecret;
use url::Url;

use opsgate_core::{Error, Result};

use super::header::{
    canonical_header_name, secret_header_blocked, valid_header_name,
    validate_allowed_headers_do_not_overlap_secret,
};
use super::{
    CredentialCategory, CredentialPolicy, CredentialSecret, RegisterCredentialInput,
    normalize_policy_for_category, validate_policy_for_category,
};

const DEFAULT_ENV: &str = "dev";
const MAX_SECRET_HEADER_VALUE_LEN: usize = 8192;

pub fn normalize_register_input(mut input: RegisterCredentialInput) -> RegisterCredentialInput {
    input.provider = input.provider.trim().to_owned();
    input.alias = input.alias.trim().to_owned();
    input.endpoint = input.endpoint.trim().to_owned();
    input.description = input.description.trim().to_owned();
    input.env = default_string(input.env.trim(), DEFAULT_ENV);
    input.tags = normalize_tags(input.tags);
    input.policy = normalize_policy_for_category(input.policy, input.category);
    if let CredentialSecret::Http { headers } = &mut input.secret {
        for header in headers {
            header.name = canonical_header_name(&header.name);
        }
    }
    input.tls_server_ca = input
        .tls_server_ca
        .map(|ca| ca.trim().to_owned())
        .filter(|ca| !ca.is_empty());
    input
}

pub fn validate_register_input(input: &RegisterCredentialInput) -> Result<()> {
    validate_common(input)?;
    validate_policy_for_category(&input.policy, input.category)?;
    match (&input.category, &input.secret) {
        (CredentialCategory::Http, CredentialSecret::Http { headers }) => {
            validate_http_endpoint(&input.endpoint)?;
            validate_http_secret(headers)?;
            let names = headers
                .iter()
                .map(|header| header.name.clone())
                .collect::<Vec<_>>();
            validate_allowed_headers_do_not_overlap_secret(&input.policy, &names)?;
            if let Some(ca) = &input.tls_server_ca {
                opsgate_core::tls::parse_certificate_pem_bundle(ca)?;
            }
        }
        (CredentialCategory::Sql, CredentialSecret::Sql { username, password }) => {
            validate_postgres_endpoint(&input.endpoint)?;
            validate_sql_secret(username.expose_secret(), password.expose_secret())?;
        }
        _ => {
            return Err(Error::validation(
                "credential secret kind must match credential category",
            ));
        }
    }
    Ok(())
}

fn validate_common(input: &RegisterCredentialInput) -> Result<()> {
    require_non_empty("provider", &input.provider)?;
    require_non_empty("alias", &input.alias)?;
    require_non_empty("endpoint", &input.endpoint)?;
    require_no_line_breaks("alias", &input.alias)?;
    require_no_line_breaks("provider", &input.provider)?;
    require_no_line_breaks("env", &input.env)?;
    Ok(())
}

pub fn validate_http_endpoint(raw: &str) -> Result<Url> {
    let url =
        Url::parse(raw).map_err(|error| Error::validation(format!("http endpoint: {error}")))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(Error::validation(
            "http endpoint must be https:// with a host",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::validation(
            "http endpoint must not include query or fragment",
        ));
    }
    Ok(url)
}

pub fn validate_postgres_endpoint(raw: &str) -> Result<Url> {
    let url = Url::parse(raw)
        .map_err(|error| Error::validation(format!("postgres endpoint: {error}")))?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err(Error::validation(
            "postgres endpoint must use postgres:// or postgresql://",
        ));
    }
    if url.host_str().is_none() {
        return Err(Error::validation("postgres endpoint requires host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::validation(
            "postgres endpoint must not include username or password",
        ));
    }
    if url.fragment().is_some() {
        return Err(Error::validation(
            "postgres endpoint must not include fragment",
        ));
    }
    for key in url.query_pairs().map(|(key, _value)| key) {
        if key != "sslmode" {
            return Err(Error::validation(format!(
                "unsupported postgres endpoint query parameter {key:?}"
            )));
        }
    }
    Ok(url)
}

fn validate_http_secret(headers: &[super::SecretHeader]) -> Result<()> {
    if headers.is_empty() {
        return Err(Error::validation("secret.headers is required"));
    }
    for header in headers {
        let name = header.name.trim();
        if name.is_empty() || name != header.name || !valid_header_name(name) {
            return Err(Error::validation(format!(
                "invalid secret header name {:?}",
                header.name
            )));
        }
        if secret_header_blocked(name) {
            return Err(Error::validation(format!(
                "secret header {name:?} is blocked"
            )));
        }
        let value = header.value.expose_secret();
        if value.trim().is_empty() {
            return Err(Error::validation(
                "secret headers require non-empty name and value",
            ));
        }
        if value.len() > MAX_SECRET_HEADER_VALUE_LEN || value.contains(['\r', '\n']) {
            return Err(Error::validation(format!(
                "invalid value for secret header {name:?}"
            )));
        }
    }
    Ok(())
}

fn validate_sql_secret(username: &str, password: &str) -> Result<()> {
    if username.trim().is_empty() || password.trim().is_empty() {
        return Err(Error::validation(
            "sql secret requires username and password",
        ));
    }
    if username.contains(['\0', '\r', '\n']) || password.contains(['\0', '\r', '\n']) {
        return Err(Error::validation(
            "sql secret username/password must not contain control line breaks",
        ));
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(Error::validation(format!("{field} is required")))
    } else {
        Ok(())
    }
}

fn require_no_line_breaks(field: &str, value: &str) -> Result<()> {
    if value.contains(['\r', '\n']) {
        Err(Error::validation(format!("{field} must not contain CR/LF")))
    } else {
        Ok(())
    }
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for tag in tags {
        let normalized = tag.trim().to_ascii_lowercase();
        if !normalized.is_empty() && !out.iter().any(|existing| existing == &normalized) {
            out.push(normalized);
        }
    }
    out
}

fn default_string(value: &str, default: &str) -> String {
    if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    }
}

#[allow(dead_code)]
fn _assert_policy_send_sync(_: &CredentialPolicy) {}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::credential::{CredentialPolicy, SecretHeader};

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    #[test]
    fn normalizes_http_register_input() {
        let input = RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: " k8s ".to_owned(),
            alias: " prod ".to_owned(),
            endpoint: " https://example.com ".to_owned(),
            secret: CredentialSecret::Http {
                headers: vec![SecretHeader {
                    name: "x-api-key".to_owned(),
                    value: secret("token"),
                }],
            },
            description: " desc ".to_owned(),
            env: "".to_owned(),
            tags: vec![" Prod ".to_owned(), "prod".to_owned()],
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            tls_server_ca: Some("".to_owned()),
        };
        let input = normalize_register_input(input);
        assert_eq!(input.env, "dev");
        assert_eq!(input.tags, ["prod"]);
        assert_eq!(input.policy.allowed_methods, ["GET"]);
        assert!(validate_register_input(&input).is_ok());
    }

    #[test]
    fn rejects_http_endpoint_query_and_secret_overlap() {
        let input = normalize_register_input(RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            endpoint: "https://example.com?token=nope".to_owned(),
            secret: CredentialSecret::Http {
                headers: vec![SecretHeader {
                    name: "X-Api-Key".to_owned(),
                    value: secret("token"),
                }],
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy {
                allowed_request_headers: vec!["x-api-key".to_owned()],
                ..CredentialPolicy::default()
            },
            allow_private_network: false,
            tls_server_ca: None,
        });
        assert!(validate_register_input(&input).is_err());
    }

    #[test]
    fn rejects_postgres_endpoint_with_credentials() {
        let err = validate_postgres_endpoint("postgres://user:pass@example.com/db").err();
        assert!(err.is_some());
    }
}
