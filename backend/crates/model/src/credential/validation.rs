use secrecy::ExposeSecret;
use url::Url;

use opsgate_core::{Error, Result};

use super::header::{
    canonical_header_name, secret_header_blocked, valid_header_name,
    validate_allowed_headers_do_not_overlap_secret,
};
use super::{
    CredentialCategory, CredentialSecret, CredentialTarget, RegisterCredentialInput,
    normalize_policy_for_category, validate_policy_for_category,
};

const DEFAULT_ENV: &str = "dev";
const MAX_SECRET_HEADERS: usize = 16;
const MAX_SECRET_HEADER_VALUE_LEN: usize = 8192;
const MAX_TAGS: usize = 16;

pub fn normalize_register_input(mut input: RegisterCredentialInput) -> RegisterCredentialInput {
    input.provider = input.provider.trim().to_owned();
    if input.category == CredentialCategory::Sql && input.provider.is_empty() {
        input.provider = "postgres".to_owned();
    }
    input.alias = input.alias.trim().to_owned();
    match &mut input.target {
        CredentialTarget::Http { origin, base_path } => {
            *origin = origin.trim().trim_end_matches('/').to_owned();
            *base_path = normalize_base_path(base_path);
        }
        CredentialTarget::Sql { database_url } => {
            *database_url = database_url.trim().to_owned();
        }
    }
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
    match (&input.category, &input.target, &input.secret) {
        (
            CredentialCategory::Http,
            CredentialTarget::Http { origin, base_path },
            CredentialSecret::Http { headers },
        ) => {
            validate_http_origin(
                origin,
                input.allow_private_network,
                input.allow_insecure_transport,
            )?;
            validate_http_base_path(base_path)?;
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
        (
            CredentialCategory::Sql,
            CredentialTarget::Sql { database_url },
            CredentialSecret::Sql { username, password },
        ) => {
            if input.provider != "postgres" {
                return Err(Error::validation(
                    "sql category currently supports provider=postgres only",
                ));
            }
            validate_postgres_database_url(
                database_url,
                input.allow_private_network,
                input.allow_insecure_transport,
            )?;
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
    if input.target.category() != input.category {
        return Err(Error::validation(
            "credential target kind must match credential category",
        ));
    }
    validate_provider(&input.provider)?;
    validate_alias(&input.alias)?;
    validate_env(&input.env)?;
    validate_tags(&input.tags)?;
    Ok(())
}

pub fn validate_provider(provider: &str) -> Result<()> {
    validate_pattern(
        "provider",
        provider,
        1,
        63,
        is_provider_first,
        is_provider_rest,
        "^[a-z][a-z0-9_-]{0,62}$",
    )
}

pub fn validate_alias(alias: &str) -> Result<()> {
    validate_pattern(
        "alias",
        alias,
        2,
        127,
        is_lower_ascii,
        is_alias_rest,
        "^[a-z][a-z0-9_.-]{1,126}$",
    )
}

pub fn validate_env(env: &str) -> Result<()> {
    if matches!(env, "prod" | "stage" | "dev" | "local") {
        Ok(())
    } else {
        Err(Error::validation(
            "env must be one of prod, stage, dev, local",
        ))
    }
}

pub fn validate_tag(tag: &str) -> Result<()> {
    validate_pattern(
        "tag",
        tag,
        1,
        63,
        is_lower_ascii,
        is_tag_rest,
        "^[a-z][a-z0-9_.:-]{0,62}$",
    )
}

pub fn validate_tags(tags: &[String]) -> Result<()> {
    if tags.len() > MAX_TAGS {
        return Err(Error::validation(format!(
            "tags count must be <= {MAX_TAGS}"
        )));
    }
    for tag in tags {
        validate_tag(tag)?;
    }
    Ok(())
}

pub fn validate_http_origin(
    raw: &str,
    allow_private_network: bool,
    allow_insecure_transport: bool,
) -> Result<Url> {
    let url =
        Url::parse(raw).map_err(|error| Error::validation(format!("http origin: {error}")))?;
    if url.host_str().is_none() {
        return Err(Error::validation("http origin requires host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::validation(
            "http origin must not include username or password",
        ));
    }
    match url.scheme() {
        "https" => {}
        "http" if allow_private_network && allow_insecure_transport => {}
        "http" => {
            return Err(Error::validation(
                "http origin requires allow_private_network=true and allow_insecure_transport=true",
            ));
        }
        _ => {
            return Err(Error::validation(
                "http origin must use http:// or https://",
            ));
        }
    }
    if !matches!(url.path(), "" | "/") {
        return Err(Error::validation("http origin must not include path"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::validation(
            "http origin must not include query or fragment",
        ));
    }
    Ok(url)
}

pub fn validate_http_base_path(base_path: &str) -> Result<()> {
    if !base_path.starts_with('/') {
        return Err(Error::validation("http base_path must start with /"));
    }
    if base_path.contains(['\0', '\r', '\n', '?', '#'])
        || base_path.contains("..")
        || base_path.contains("//")
    {
        return Err(Error::validation(
            "http base_path must not contain query, fragment, //, .., or control characters",
        ));
    }
    Ok(())
}

pub fn validate_postgres_database_url(
    raw: &str,
    allow_private_network: bool,
    allow_insecure_transport: bool,
) -> Result<Url> {
    let url = Url::parse(raw)
        .map_err(|error| Error::validation(format!("postgres database_url: {error}")))?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err(Error::validation(
            "postgres database_url must use postgres:// or postgresql://",
        ));
    }
    if url.host_str().is_none() {
        return Err(Error::validation("postgres database_url requires host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::validation(
            "postgres database_url must not include username or password",
        ));
    }
    if url.fragment().is_some() {
        return Err(Error::validation(
            "postgres database_url must not include fragment",
        ));
    }
    let mut sslmode = None;
    for (key, value) in url.query_pairs() {
        if key != "sslmode" {
            return Err(Error::validation(format!(
                "unsupported postgres database_url query parameter {key:?}"
            )));
        }
        sslmode = Some(value.to_ascii_lowercase());
    }
    match sslmode.as_deref() {
        Some("require") => {}
        Some("verify-full") => {
            return Err(Error::validation(
                "postgres database_url sslmode=verify-full is unsupported by guarded SQL targets",
            ));
        }
        _ if allow_private_network && allow_insecure_transport => {}
        _ => {
            return Err(Error::validation(
                "postgres database_url requires sslmode=require unless allow_private_network=true and allow_insecure_transport=true",
            ));
        }
    }
    Ok(url)
}

fn validate_http_secret(headers: &[super::SecretHeader]) -> Result<()> {
    if headers.is_empty() {
        return Err(Error::validation("secret.headers is required"));
    }
    if headers.len() > MAX_SECRET_HEADERS {
        return Err(Error::validation(format!(
            "secret.headers count must be <= {MAX_SECRET_HEADERS}"
        )));
    }
    let mut seen = Vec::<String>::new();
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
        let lower_name = name.to_ascii_lowercase();
        if seen.iter().any(|existing| existing == &lower_name) {
            return Err(Error::validation(format!(
                "duplicate secret header {name:?}"
            )));
        }
        seen.push(lower_name);
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

pub fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for tag in tags {
        let normalized = tag.trim().to_ascii_lowercase();
        if !normalized.is_empty() && !out.iter().any(|existing| existing == &normalized) {
            out.push(normalized);
        }
    }
    out.sort();
    out
}

fn default_string(value: &str, default: &str) -> String {
    if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    }
}

fn normalize_base_path(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || value == "/" {
        "/".to_owned()
    } else {
        value.trim_end_matches('/').to_owned()
    }
}

fn validate_pattern(
    field: &str,
    value: &str,
    min_len: usize,
    max_len: usize,
    first: fn(u8) -> bool,
    rest: fn(u8) -> bool,
    pattern: &str,
) -> Result<()> {
    let bytes = value.as_bytes();
    let valid = bytes.len() >= min_len
        && bytes.len() <= max_len
        && bytes.first().is_some_and(|byte| first(*byte))
        && bytes.iter().skip(1).all(|byte| rest(*byte));
    if valid {
        Ok(())
    } else {
        Err(Error::validation(format!("{field} must match {pattern}")))
    }
}

fn is_provider_first(byte: u8) -> bool {
    is_lower_ascii(byte)
}

fn is_provider_rest(byte: u8) -> bool {
    is_lower_ascii(byte) || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
}

fn is_alias_rest(byte: u8) -> bool {
    is_lower_ascii(byte) || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
}

fn is_tag_rest(byte: u8) -> bool {
    is_alias_rest(byte) || byte == b':'
}

fn is_lower_ascii(byte: u8) -> bool {
    byte.is_ascii_lowercase()
}

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
            target: CredentialTarget::Http {
                origin: " https://example.com ".to_owned(),
                base_path: String::new(),
            },
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
            allow_insecure_transport: false,
            tls_server_ca: Some("".to_owned()),
        };
        let input = normalize_register_input(input);
        assert_eq!(input.env, "dev");
        assert_eq!(input.tags, ["prod"]);
        assert_eq!(input.policy.allowed_methods, ["GET"]);
        assert!(validate_register_input(&input).is_ok());
    }

    #[test]
    fn rejects_http_origin_query_and_secret_overlap() {
        let input = normalize_register_input(RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            target: CredentialTarget::Http {
                origin: "https://example.com?token=nope".to_owned(),
                base_path: String::new(),
            },
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
            allow_insecure_transport: false,
            tls_server_ca: None,
        });
        assert!(validate_register_input(&input).is_err());
    }

    #[test]
    fn rejects_http_origin_path_fragment_and_credentials() {
        for origin in [
            "https://example.com/api",
            "https://example.com#fragment",
            "https://user@example.com",
            "https://user:pass@example.com",
        ] {
            assert!(
                validate_http_origin(origin, false, false).is_err(),
                "{origin} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_invalid_http_base_path_boundaries() {
        for base_path in [
            "api",
            "/api/../secret",
            "/api//v1",
            "/api?token=x",
            "/api#frag",
        ] {
            assert!(
                validate_http_base_path(base_path).is_err(),
                "{base_path} should be rejected"
            );
        }
        assert!(validate_http_base_path("/api/v1").is_ok());
    }

    #[test]
    fn rejects_postgres_fragment_and_unsupported_query_parameters() {
        for database_url in [
            "postgres://db.example.com/app?connect_timeout=10",
            "postgres://db.example.com/app?ssl-mode=require",
            "postgres://db.example.com/app#fragment",
        ] {
            assert!(
                validate_postgres_database_url(database_url, false, false).is_err(),
                "{database_url} should be rejected"
            );
        }
    }

    #[test]
    fn allows_authorization_as_secret_header_but_not_caller_header_overlap() {
        let input = normalize_register_input(RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            target: CredentialTarget::Http {
                origin: "https://example.com".to_owned(),
                base_path: String::new(),
            },
            secret: CredentialSecret::Http {
                headers: vec![SecretHeader {
                    name: "Authorization".to_owned(),
                    value: secret("Bearer secret-token"),
                }],
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: None,
        });
        assert!(validate_register_input(&input).is_ok());
    }

    #[test]
    fn rejects_transport_controlled_secret_headers() {
        for name in ["Host", "Content-Type", "X-Forwarded-For"] {
            let input = normalize_register_input(RegisterCredentialInput {
                category: CredentialCategory::Http,
                provider: "k8s".to_owned(),
                alias: "prod".to_owned(),
                target: CredentialTarget::Http {
                    origin: "https://example.com".to_owned(),
                    base_path: String::new(),
                },
                secret: CredentialSecret::Http {
                    headers: vec![SecretHeader {
                        name: name.to_owned(),
                        value: secret("secret-token"),
                    }],
                },
                description: String::new(),
                env: String::new(),
                tags: Vec::new(),
                policy: CredentialPolicy::default(),
                allow_private_network: false,
                allow_insecure_transport: false,
                tls_server_ca: None,
            });
            assert!(
                validate_register_input(&input).is_err(),
                "{name} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_duplicate_and_too_many_secret_headers() {
        let duplicate = normalize_register_input(RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            target: CredentialTarget::Http {
                origin: "https://example.com".to_owned(),
                base_path: String::new(),
            },
            secret: CredentialSecret::Http {
                headers: vec![
                    SecretHeader {
                        name: "X-Api-Key".to_owned(),
                        value: secret("first-token"),
                    },
                    SecretHeader {
                        name: "x-api-key".to_owned(),
                        value: secret("second-token"),
                    },
                ],
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: None,
        });
        let msg = validate_register_input(&duplicate)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(msg.contains("duplicate secret header"));
        assert!(!msg.contains("first-token"));
        assert!(!msg.contains("second-token"));

        let too_many = normalize_register_input(RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            target: CredentialTarget::Http {
                origin: "https://example.com".to_owned(),
                base_path: String::new(),
            },
            secret: CredentialSecret::Http {
                headers: (0..=MAX_SECRET_HEADERS)
                    .map(|index| SecretHeader {
                        name: format!("X-Secret-{index}"),
                        value: secret("secret-token"),
                    })
                    .collect(),
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: None,
        });
        let msg = validate_register_input(&too_many)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(msg.contains("secret.headers count"));
        assert!(!msg.contains("secret-token"));
    }

    #[test]
    fn validation_errors_do_not_echo_secret_values() {
        let input = normalize_register_input(RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            target: CredentialTarget::Http {
                origin: "https://example.com".to_owned(),
                base_path: String::new(),
            },
            secret: CredentialSecret::Http {
                headers: vec![SecretHeader {
                    name: "X-Api-Key".to_owned(),
                    value: secret("secret-token\nleak"),
                }],
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: None,
        });
        let msg = validate_register_input(&input)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(msg.contains("X-Api-Key"));
        assert!(!msg.contains("secret-token"));
    }

    #[test]
    fn rejects_secret_kind_mismatch() {
        let input = normalize_register_input(RegisterCredentialInput {
            category: CredentialCategory::Sql,
            provider: "postgres".to_owned(),
            alias: "db".to_owned(),
            target: CredentialTarget::Sql {
                database_url: "postgres://db.example.com/app?sslmode=require".to_owned(),
            },
            secret: CredentialSecret::Http {
                headers: vec![SecretHeader {
                    name: "X-Api-Key".to_owned(),
                    value: secret("secret-token"),
                }],
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: None,
        });
        assert!(validate_register_input(&input).is_err());
    }

    #[test]
    fn rejects_postgres_verify_full_until_guarded_tls_identity_is_supported() {
        let err = validate_postgres_database_url(
            "postgres://db.example.test/app?sslmode=verify-full",
            false,
            false,
        )
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
        assert!(err.contains("verify-full is unsupported"));
    }

    #[test]
    fn rejects_postgres_database_url_with_credentials() {
        let err =
            validate_postgres_database_url("postgres://user:pass@example.com/db", false, false)
                .err();
        assert!(err.is_some());
    }

    #[test]
    fn insecure_transports_require_explicit_private_opt_in() {
        assert!(validate_http_origin("http://service.local", true, true).is_ok());
        assert!(validate_http_origin("http://service.local", true, false).is_err());
        assert!(validate_http_origin("http://service.local", false, true).is_err());

        assert!(
            validate_postgres_database_url("postgres://db.local/app?sslmode=disable", true, true)
                .is_ok()
        );
        assert!(
            validate_postgres_database_url("postgres://db.local/app?sslmode=disable", true, false)
                .is_err()
        );
        assert!(
            validate_postgres_database_url("postgres://db.local/app?sslmode=disable", false, true)
                .is_err()
        );
        assert!(
            validate_postgres_database_url("postgres://db.local/app?sslmode=require", false, false)
                .is_ok()
        );
    }

    #[test]
    fn register_validation_gates_insecure_transports() {
        let http = RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "internal-api".to_owned(),
            target: CredentialTarget::Http {
                origin: "http://service.local".to_owned(),
                base_path: String::new(),
            },
            secret: CredentialSecret::Http {
                headers: vec![SecretHeader {
                    name: "Authorization".to_owned(),
                    value: secret("Bearer token"),
                }],
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: true,
            allow_insecure_transport: true,
            tls_server_ca: None,
        };
        assert!(validate_register_input(&normalize_register_input(http.clone())).is_ok());
        let mut missing_transport = http.clone();
        missing_transport.allow_insecure_transport = false;
        assert!(validate_register_input(&normalize_register_input(missing_transport)).is_err());
        let mut missing_private = http;
        missing_private.allow_private_network = false;
        assert!(validate_register_input(&normalize_register_input(missing_private)).is_err());

        let sql = RegisterCredentialInput {
            category: CredentialCategory::Sql,
            provider: "postgres".to_owned(),
            alias: "internal-db".to_owned(),
            target: CredentialTarget::Sql {
                database_url: "postgres://db.local/app?sslmode=disable".to_owned(),
            },
            secret: CredentialSecret::Sql {
                username: secret("user"),
                password: secret("pass"),
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: true,
            allow_insecure_transport: true,
            tls_server_ca: None,
        };
        assert!(validate_register_input(&normalize_register_input(sql.clone())).is_ok());
        let mut missing_transport = sql.clone();
        missing_transport.allow_insecure_transport = false;
        assert!(validate_register_input(&normalize_register_input(missing_transport)).is_err());
        let mut require_tls = sql;
        require_tls.target = CredentialTarget::Sql {
            database_url: "postgres://db.local/app?sslmode=require".to_owned(),
        };
        require_tls.allow_private_network = false;
        require_tls.allow_insecure_transport = false;
        assert!(validate_register_input(&normalize_register_input(require_tls)).is_ok());
    }

    #[test]
    fn rejects_invalid_provider_alias_env_and_tags() {
        for provider in [
            "K8s",
            "1k8s",
            "bad space",
            "a234567890123456789012345678901234567890123456789012345678901234",
        ] {
            assert!(
                validate_provider(provider).is_err(),
                "{provider} should be rejected"
            );
        }
        for alias in ["a", "1prod", "Prod", "bad space", "prod\napi"] {
            assert!(validate_alias(alias).is_err(), "{alias} should be rejected");
        }
        assert!(validate_env("qa").is_err());
        assert!(validate_tag("Bad").is_err());
        assert!(validate_tag("bad space").is_err());
        let too_many_tags = vec!["prod".to_owned(); 17];
        assert!(validate_tags(&too_many_tags).is_err());
    }

    #[test]
    fn normalizes_tags_lowercase_deduped_and_sorted() {
        let tags = normalize_tags(vec![
            " Prod ".to_owned(),
            "db".to_owned(),
            "prod".to_owned(),
            "alpha".to_owned(),
        ]);

        assert_eq!(tags, ["alpha", "db", "prod"]);
        assert!(validate_tags(&tags).is_ok());
    }

    #[test]
    fn sql_register_requires_postgres_provider() {
        let input = normalize_register_input(RegisterCredentialInput {
            category: CredentialCategory::Sql,
            provider: "mysql".to_owned(),
            alias: "db-prod".to_owned(),
            target: CredentialTarget::Sql {
                database_url: "postgres://db.example.com/app?sslmode=require".to_owned(),
            },
            secret: CredentialSecret::Sql {
                username: secret("user"),
                password: secret("pass"),
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: None,
        });

        assert!(validate_register_input(&input).is_err());
    }
}
