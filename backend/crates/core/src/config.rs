//! Runtime configuration loaded and validated from environment variables.
//!
//! Validation is fail-fast: a bad value aborts boot with a precise message
//! rather than surfacing as a confusing runtime error later.

use std::env;
use std::net::SocketAddr;

use crate::error::{Error, Result};

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 10;
const DB_MAX_CONNECTIONS_LIMIT: u32 = 256;

/// Server + database configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind_addr: SocketAddr,
    /// Postgres connection string.
    pub database_url: String,
    /// Max connections in the sqlx pool.
    pub db_max_connections: u32,
}

impl Config {
    /// Load configuration from the process environment.
    ///
    /// `DATABASE_URL` is required; everything else has a sane default.
    pub fn from_env() -> Result<Self> {
        let bind_addr = env_socket_addr("BIND_ADDR", DEFAULT_BIND_ADDR)?;
        let database_url = env_required("DATABASE_URL")?;
        let db_max_connections = env_u32_in_range(
            "DB_MAX_CONNECTIONS",
            DEFAULT_DB_MAX_CONNECTIONS,
            1,
            DB_MAX_CONNECTIONS_LIMIT,
        )?;

        Ok(Self {
            bind_addr,
            database_url,
            db_max_connections,
        })
    }
}

fn env_required(name: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(Error::validation(format!("{name} must be set"))),
    }
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

fn env_string(name: &str, default: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(env::VarError::NotUnicode(_)) => {
            Err(Error::validation(format!("{name} must be valid UTF-8")))
        }
    }
}
