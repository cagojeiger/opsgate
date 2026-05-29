//! Runtime configuration loaded and validated from layered sources.
//!
//! Load order is: built-in defaults < optional TOML files < environment.
//! Validation is fail-fast: a bad value aborts boot with a precise message
//! rather than surfacing as a confusing runtime error later.

use std::net::SocketAddr;
use std::time::Duration;

use config::{Config as LayeredConfig, Environment, File, FileFormat};
use secrecy::SecretString;
use serde::{Deserialize, Deserializer};
use url::Url;
use validator::{Validate, ValidationError};

use crate::error::{Error, Result};

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9091";
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_JWKS_CACHE_TTL_SECS: u64 = 300;

/// Server + database configuration.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind_addr: SocketAddr,
    /// Postgres connection string.
    #[validate(length(min = 1))]
    pub database_url: String,
    /// Max connections in the sqlx pool.
    #[validate(range(min = 1, max = 256))]
    pub db_max_connections: u32,
    /// Base URL for authgate, with trailing slash trimmed.
    #[validate(custom(function = "validate_http_url_value"))]
    pub authgate_url: String,
    /// Public URL for opsgate as seen by browsers/MCP clients, with trailing slash trimmed.
    #[serde(rename = "public_url")]
    #[validate(custom(function = "validate_http_url_value"))]
    pub opsgate_public_url: String,
    /// Public OAuth client id registered in authgate.
    #[validate(length(min = 1))]
    pub oauth_client_id: String,
    /// Exact redirect URL registered in authgate.
    #[validate(custom(function = "validate_http_url_value"))]
    pub oauth_redirect_url: String,
    /// Resource/audience URL for REST and MCP, with trailing slash trimmed.
    #[validate(custom(function = "validate_http_url_value"))]
    pub resource_url: String,
    /// Base64-encoded 32-byte master key for sealing credential secrets.
    pub master_key: SecretString,
    /// Shared JWKS cache TTL.
    #[serde(
        rename = "jwks_cache_ttl_secs",
        deserialize_with = "duration_from_secs"
    )]
    #[validate(custom(function = "validate_jwks_cache_ttl"))]
    pub jwks_cache_ttl: Duration,
    /// Whether login flow cookies must carry the Secure flag.
    #[serde(skip)]
    pub secure_cookies: bool,
}

impl Config {
    /// Load configuration from optional files and the process environment.
    ///
    /// Supported file layers, if present:
    /// - `config/default.toml`
    /// - `config/local.toml`
    ///
    /// `OPSGATE_`-prefixed environment variables have highest precedence.
    pub fn load() -> Result<Self> {
        load_from_sources(true, Environment::with_prefix("OPSGATE"))
    }

    fn normalize(&mut self) {
        self.authgate_url = trim_trailing_slashes(&self.authgate_url);
        self.opsgate_public_url = trim_trailing_slashes(&self.opsgate_public_url);
        self.resource_url = trim_trailing_slashes(&self.resource_url);
        self.secure_cookies = secure_cookies_for_redirect(&self.oauth_redirect_url);
    }
}

fn load_from_sources(include_files: bool, environment: Environment) -> Result<Config> {
    let mut builder = LayeredConfig::builder()
        .set_default("bind_addr", DEFAULT_BIND_ADDR)
        .map_err(map_config_error)?
        .set_default("db_max_connections", DEFAULT_DB_MAX_CONNECTIONS)
        .map_err(map_config_error)?
        .set_default("jwks_cache_ttl_secs", DEFAULT_JWKS_CACHE_TTL_SECS)
        .map_err(map_config_error)?;

    if include_files {
        builder = builder
            .add_source(File::new("config/default", FileFormat::Toml).required(false))
            .add_source(File::new("config/local", FileFormat::Toml).required(false));
    }

    let mut config = builder
        .add_source(environment.try_parsing(true))
        .build()
        .map_err(map_config_error)?
        .try_deserialize::<Config>()
        .map_err(map_config_error)?;

    config.validate().map_err(map_validation_error)?;
    config.normalize();
    Ok(config)
}

fn map_config_error(error: config::ConfigError) -> Error {
    Error::validation(format!("configuration error: {error}"))
}

fn trim_trailing_slashes(value: &str) -> String {
    value.trim_end_matches('/').to_owned()
}

fn duration_from_secs<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Duration::from_secs(u64::deserialize(deserializer)?))
}

fn validate_http_url_value(value: &str) -> std::result::Result<(), ValidationError> {
    let url = Url::parse(value).map_err(|_error| ValidationError::new("http_url"))?;
    let allowed_scheme = matches!(url.scheme(), "http" | "https");
    if allowed_scheme && url.host_str().is_some() {
        Ok(())
    } else {
        Err(ValidationError::new("http_url"))
    }
}

fn validate_jwks_cache_ttl(value: &Duration) -> std::result::Result<(), ValidationError> {
    let seconds = value.as_secs();
    if (30..=3600).contains(&seconds) {
        Ok(())
    } else {
        Err(ValidationError::new("range"))
    }
}

fn secure_cookies_for_redirect(oauth_redirect_url: &str) -> bool {
    oauth_redirect_url.starts_with("https://")
}

fn map_validation_error(error: validator::ValidationErrors) -> Error {
    let mut fields = error
        .field_errors()
        .into_iter()
        .flat_map(|(field, errors)| {
            errors
                .iter()
                .map(move |error| format!("{field}:{}", error.code))
        })
        .collect::<Vec<_>>();
    fields.sort();

    if fields.is_empty() {
        Error::validation("configuration validation error")
    } else {
        Error::validation(format!(
            "configuration validation error: {}",
            fields.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Duration;

    use config::Environment;
    use secrecy::SecretString;
    use validator::Validate;

    use super::{Config, load_from_sources};

    fn valid_config() -> Config {
        Config {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 9091)),
            database_url: "postgres://example".to_owned(),
            db_max_connections: 10,
            authgate_url: "https://auth.test".to_owned(),
            opsgate_public_url: "http://localhost:9091".to_owned(),
            oauth_client_id: "opsgate-web".to_owned(),
            oauth_redirect_url: "http://localhost:9091/callback".to_owned(),
            resource_url: "http://localhost:9091/mcp".to_owned(),
            master_key: SecretString::from(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            ),
            jwks_cache_ttl: Duration::from_secs(300),
            secure_cookies: false,
        }
    }

    fn test_env(vars: &[(&str, &str)]) -> Environment {
        Environment::with_prefix("OPSGATE").source(Some(
            vars.iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<HashMap<_, _>>(),
        ))
    }

    #[test]
    fn environment_layer_accepts_prefixed_variable_names() -> crate::Result<()> {
        let config = load_from_sources(
            false,
            test_env(&[
                ("OPSGATE_DATABASE_URL", "postgres://env"),
                ("OPSGATE_AUTHGATE_URL", "https://auth.env"),
                ("OPSGATE_PUBLIC_URL", "http://localhost:9091"),
                ("OPSGATE_OAUTH_CLIENT_ID", "opsgate-web"),
                (
                    "OPSGATE_OAUTH_REDIRECT_URL",
                    "http://localhost:9091/callback",
                ),
                ("OPSGATE_RESOURCE_URL", "http://localhost:9091/mcp"),
                (
                    "OPSGATE_MASTER_KEY",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                ),
                ("OPSGATE_DB_MAX_CONNECTIONS", "7"),
                ("PATH", "/bin"),
                ("DATABASE_URL", "postgres://ignored"),
            ]),
        )?;

        assert_eq!(config.bind_addr.to_string(), super::DEFAULT_BIND_ADDR);
        assert_eq!(config.database_url, "postgres://env");
        assert_eq!(config.db_max_connections, 7);
        assert_eq!(
            config.jwks_cache_ttl.as_secs(),
            super::DEFAULT_JWKS_CACHE_TTL_SECS
        );
        Ok(())
    }

    #[test]
    fn normalize_builds_valid_config() -> crate::Result<()> {
        let mut config = valid_config();
        config.validate().map_err(super::map_validation_error)?;
        config.normalize();
        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:9091");
        assert_eq!(config.db_max_connections, 10);
        assert_eq!(config.jwks_cache_ttl.as_secs(), 300);
        assert!(!config.secure_cookies);
        Ok(())
    }

    #[test]
    fn validate_rejects_out_of_range_values() {
        let mut config = valid_config();
        config.db_max_connections = 0;
        assert!(config.validate().is_err());

        let mut config = valid_config();
        config.jwks_cache_ttl = Duration::from_secs(1);
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_errors_do_not_echo_values() -> crate::Result<()> {
        let mut config = valid_config();
        config.authgate_url = "not a url with secret-token".to_owned();

        let err = match config.validate().map_err(super::map_validation_error) {
            Ok(()) => {
                return Err(crate::Error::validation(
                    "invalid URL should fail validation",
                ));
            }
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(msg.contains("authgate_url:http_url"));
        assert!(!msg.contains("secret-token"));
        Ok(())
    }
}
