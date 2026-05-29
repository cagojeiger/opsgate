//! Runtime configuration loaded and validated from environment variables.
//!
//! Validation is fail-fast: a bad value aborts boot with a precise message
//! rather than surfacing as a confusing runtime error later.

use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::{Error, Result};

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9091";
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 10;
const DB_MAX_CONNECTIONS_LIMIT: u32 = 256;
const DEFAULT_JWKS_CACHE_TTL_SECS: u64 = 300;
const MIN_JWKS_CACHE_TTL_SECS: u64 = 30;
const MAX_JWKS_CACHE_TTL_SECS: u64 = 3600;

/// Server + database configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind_addr: SocketAddr,
    /// Postgres connection string.
    pub database_url: String,
    /// Max connections in the sqlx pool.
    pub db_max_connections: u32,
    /// Base URL for authgate, with trailing slash trimmed.
    pub authgate_url: String,
    /// Public URL for opsgate as seen by browsers/MCP clients, with trailing slash trimmed.
    pub opsgate_public_url: String,
    /// Public OAuth client id registered in authgate.
    pub oauth_client_id: String,
    /// Exact redirect URL registered in authgate.
    pub oauth_redirect_url: String,
    /// Resource/audience URL for REST and MCP, with trailing slash trimmed.
    pub resource_url: String,
    /// Shared JWKS cache TTL.
    pub jwks_cache_ttl: Duration,
    /// Whether login flow cookies must carry the Secure flag.
    pub secure_cookies: bool,
}

impl Config {
    /// Load configuration from the process environment.
    pub fn from_env() -> Result<Self> {
        let bind_addr = env_socket_addr("BIND_ADDR", DEFAULT_BIND_ADDR)?;
        let database_url = env_required("DATABASE_URL")?;
        let db_max_connections = env_u32_in_range(
            "DB_MAX_CONNECTIONS",
            DEFAULT_DB_MAX_CONNECTIONS,
            1,
            DB_MAX_CONNECTIONS_LIMIT,
        )?;
        let authgate_url = env_required_trimmed_http_url("AUTHGATE_URL")?;
        let opsgate_public_url = env_required_trimmed_http_url("OPSGATE_PUBLIC_URL")?;
        let oauth_client_id = env_required("OAUTH_CLIENT_ID")?;
        let oauth_redirect_url = env_required_http_url_verbatim("OAUTH_REDIRECT_URL")?;
        let resource_url = env_required_trimmed_http_url("RESOURCE_URL")?;
        let jwks_cache_ttl_secs = env_u64_in_range(
            "JWKS_CACHE_TTL_SECS",
            DEFAULT_JWKS_CACHE_TTL_SECS,
            MIN_JWKS_CACHE_TTL_SECS,
            MAX_JWKS_CACHE_TTL_SECS,
        )?;
        let secure_cookies = secure_cookies_for_redirect(&oauth_redirect_url);

        Ok(Self {
            bind_addr,
            database_url,
            db_max_connections,
            authgate_url,
            opsgate_public_url,
            oauth_client_id,
            oauth_redirect_url,
            resource_url,
            jwks_cache_ttl: Duration::from_secs(jwks_cache_ttl_secs),
            secure_cookies,
        })
    }
}

fn env_required(name: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(Error::validation(format!("{name} must not be empty"))),
        Err(env::VarError::NotPresent) => Err(Error::validation(format!("{name} must be set"))),
        Err(env::VarError::NotUnicode(_)) => {
            Err(Error::validation(format!("{name} must be valid UTF-8")))
        }
    }
}

fn env_required_http_url_verbatim(name: &str) -> Result<String> {
    let value = env_required(name)?;
    validate_http_url(name, &value)?;
    Ok(value)
}

fn env_required_trimmed_http_url(name: &str) -> Result<String> {
    let value = trim_trailing_slashes(&env_required(name)?);
    validate_http_url(name, &value)?;
    Ok(value)
}

fn trim_trailing_slashes(value: &str) -> String {
    value.trim_end_matches('/').to_owned()
}

fn validate_http_url(name: &str, value: &str) -> Result<()> {
    let has_scheme = value.starts_with("http://") || value.starts_with("https://");
    let has_host = value
        .split_once("://")
        .map(|(_scheme, rest)| !rest.is_empty() && !rest.starts_with('/'))
        .unwrap_or(false);
    if has_scheme && has_host {
        Ok(())
    } else {
        Err(Error::validation(format!(
            "{name} must be an http(s) URL with a host"
        )))
    }
}

fn secure_cookies_for_redirect(oauth_redirect_url: &str) -> bool {
    oauth_redirect_url.starts_with("https://")
}

fn env_socket_addr(name: &str, default: &str) -> Result<SocketAddr> {
    env_string(name, default)?
        .parse()
        .map_err(|error| Error::validation(format!("{name} must be a socket address: {error}")))
}

fn env_u32_in_range(name: &str, default: u32, min: u32, max: u32) -> Result<u32> {
    let value: u32 = env_string(name, &default.to_string())?
        .parse()
        .map_err(|error| {
            Error::validation(format!("{name} must be an unsigned integer: {error}"))
        })?;

    if !(min..=max).contains(&value) {
        return Err(Error::validation(format!(
            "{name} must be between {min} and {max}"
        )));
    }

    Ok(value)
}

fn env_u64_in_range(name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let value: u64 = env_string(name, &default.to_string())?
        .parse()
        .map_err(|error| {
            Error::validation(format!("{name} must be an unsigned integer: {error}"))
        })?;

    if !(min..=max).contains(&value) {
        return Err(Error::validation(format!(
            "{name} must be between {min} and {max}"
        )));
    }

    Ok(value)
}

fn env_string(name: &str, default: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(env::VarError::NotUnicode(_)) => {
            Err(Error::validation(format!("{name} must be valid UTF-8")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{secure_cookies_for_redirect, trim_trailing_slashes, validate_http_url};

    #[test]
    fn secure_cookies_follow_redirect_scheme() {
        assert!(secure_cookies_for_redirect("https://example.test/callback"));
        assert!(!secure_cookies_for_redirect(
            "http://localhost:9091/callback"
        ));
    }

    #[test]
    fn trims_trailing_slashes() {
        assert_eq!(
            trim_trailing_slashes("https://auth.test///"),
            "https://auth.test"
        );
    }

    #[test]
    fn url_validator_requires_http_url_with_host() {
        assert!(validate_http_url("X", "https://auth.test").is_ok());
        assert!(validate_http_url("X", "http://localhost:9091/mcp").is_ok());
        assert!(validate_http_url("X", "ftp://auth.test").is_err());
        assert!(validate_http_url("X", "https://").is_err());
    }
}
