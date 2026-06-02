use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use opsgate_core::{Error, Result};

use crate::network_guard::{ensure_target_ip_allowed, target_ip_is_blocked};
use sqlx::postgres::{PgConnectOptions, PgSslMode};

#[derive(Debug, Clone)]
pub struct GuardedPostgresTarget {
    database_url: String,
    connect_addr: SocketAddr,
    allow_private_network: bool,
    allow_insecure_transport: bool,
}

impl GuardedPostgresTarget {
    pub fn connect_options(
        &self,
        username: &str,
        password: &str,
        database: Option<&str>,
    ) -> Result<TargetPgConnectOptions> {
        let mut options = PgConnectOptions::from_str(&self.database_url)
            .map_err(|error| Error::validation(format!("postgres database_url: {error}")))?;
        if let Some(database) = database {
            options = options.database(database);
        }
        validate_ssl_mode(
            options.get_ssl_mode(),
            self.allow_private_network,
            self.allow_insecure_transport,
        )?;
        let database = options.get_database().unwrap_or_default().to_owned();
        let options = options
            .host(&self.connect_addr.ip().to_string())
            .port(self.connect_addr.port())
            .username(username)
            .password(password);
        Ok(TargetPgConnectOptions { database, options })
    }

    #[cfg(test)]
    fn connect_addr(&self) -> SocketAddr {
        self.connect_addr
    }
}

pub async fn prepare_postgres_target(
    database_url: &str,
    allow_private_network: bool,
    allow_insecure_transport: bool,
) -> Result<GuardedPostgresTarget> {
    let url = url::Url::parse(database_url)
        .map_err(|error| Error::validation(format!("postgres database_url: {error}")))?;
    validate_postgres_transport(&url, allow_private_network, allow_insecure_transport)?;
    let host = url
        .host()
        .ok_or_else(|| Error::validation("postgres database_url requires host"))?;
    let port = url.port_or_known_default().unwrap_or(5432);
    let connect_addr = match host {
        url::Host::Ipv4(ip) => {
            select_postgres_addr(port, vec![IpAddr::V4(ip)], allow_private_network)?
        }
        url::Host::Ipv6(ip) => {
            select_postgres_addr(port, vec![IpAddr::V6(ip)], allow_private_network)?
        }
        url::Host::Domain(host) => {
            let ips = tokio::net::lookup_host((host, port))
                .await
                .map_err(|error| Error::validation(format!("resolve target host: {error}")))?
                .map(|addr| addr.ip())
                .collect::<Vec<_>>();
            select_postgres_addr(port, ips, allow_private_network)?
        }
    };
    Ok(GuardedPostgresTarget {
        database_url: database_url.to_owned(),
        connect_addr,
        allow_private_network,
        allow_insecure_transport,
    })
}

fn validate_postgres_transport(
    url: &url::Url,
    allow_private_network: bool,
    allow_insecure_transport: bool,
) -> Result<()> {
    let mut ssl_mode = None;
    for (key, value) in url.query_pairs() {
        if matches!(&*key, "sslmode" | "ssl-mode") {
            let mode = PgSslMode::from_str(&value).map_err(|error| {
                Error::validation(format!("postgres database_url sslmode: {error}"))
            })?;
            ssl_mode = Some(mode);
            continue;
        }
        return Err(Error::validation(format!(
            "unsupported postgres database_url query parameter {key:?}"
        )));
    }
    validate_ssl_mode(
        ssl_mode.unwrap_or(PgSslMode::Prefer),
        allow_private_network,
        allow_insecure_transport,
    )
}

fn validate_ssl_mode(
    mode: PgSslMode,
    allow_private_network: bool,
    allow_insecure_transport: bool,
) -> Result<()> {
    match mode {
        PgSslMode::Require => Ok(()),
        PgSslMode::VerifyFull => Err(Error::validation(
            "postgres database_url sslmode=verify-full is unsupported by guarded SQL targets",
        )),
        _ if allow_private_network && allow_insecure_transport => Ok(()),
        _ => Err(Error::validation(
            "postgres database_url requires sslmode=require unless allow_private_network=true and allow_insecure_transport=true",
        )),
    }
}

fn select_postgres_addr(
    port: u16,
    ips: Vec<IpAddr>,
    allow_private_network: bool,
) -> Result<SocketAddr> {
    let first = ips
        .first()
        .copied()
        .ok_or_else(|| Error::validation("resolve target host: no IPs"))?;
    if !allow_private_network
        && let Some(blocked) = ips.into_iter().find(|ip| target_ip_is_blocked(*ip))
    {
        ensure_target_ip_allowed(blocked, allow_private_network)?;
    }
    Ok(SocketAddr::new(first, port))
}

pub struct TargetPgConnectOptions {
    pub database: String,
    pub options: PgConnectOptions,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn guarded_postgres_target_blocks_private_literal() -> Result<()> {
        let err = prepare_postgres_target(
            "postgres://127.0.0.1:5432/app?sslmode=require",
            false,
            false,
        )
        .await
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
        assert!(err.contains("private/link-local/loopback"));
        Ok(())
    }

    #[tokio::test]
    async fn guarded_postgres_target_blocks_ipv4_mapped_private_literal() -> Result<()> {
        let err = prepare_postgres_target(
            "postgres://[::ffff:127.0.0.1]:5432/app?sslmode=require",
            false,
            false,
        )
        .await
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
        assert!(err.contains("private/link-local/loopback"));
        Ok(())
    }

    #[tokio::test]
    async fn guarded_postgres_target_allows_private_when_enabled() -> Result<()> {
        let target = prepare_postgres_target("postgres://127.0.0.1:15432/app", true, true).await?;
        assert_eq!(
            target.connect_addr(),
            SocketAddr::from(([127, 0, 0, 1], 15432))
        );
        Ok(())
    }

    #[test]
    fn dns_result_guard_blocks_private_ip() {
        let err = select_postgres_addr(
            5432,
            vec![
                IpAddr::from([93, 184, 216, 34]),
                IpAddr::from([10, 0, 0, 10]),
            ],
            false,
        )
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
        assert!(err.contains("private/link-local/loopback"));
    }

    #[tokio::test]
    async fn prepare_rejects_verify_full_before_dns_resolution() {
        let err = prepare_postgres_target(
            "postgres://definitely-not-resolved.invalid/app?sslmode=verify-full",
            false,
            false,
        )
        .await
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
        assert!(err.contains("verify-full is unsupported"));
        assert!(!err.contains("resolve target host"));
    }

    #[test]
    fn connect_options_reject_verify_full_before_ip_overwrite() {
        let target = GuardedPostgresTarget {
            database_url: "postgres://db.example.test:6543/app?sslmode=verify-full".to_owned(),
            connect_addr: SocketAddr::from(([93, 184, 216, 34], 6543)),
            allow_private_network: false,
            allow_insecure_transport: false,
        };
        let err = target
            .connect_options("user", "password", None)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(err.contains("verify-full is unsupported"));
    }

    #[test]
    fn connect_options_use_guarded_target_addr() -> Result<()> {
        let target = GuardedPostgresTarget {
            database_url: "postgres://db.example.test:6543/app?sslmode=require".to_owned(),
            connect_addr: SocketAddr::from(([93, 184, 216, 34], 6543)),
            allow_private_network: false,
            allow_insecure_transport: false,
        };
        let connect = target.connect_options("user", "password", None)?;
        assert_eq!(connect.options.get_host(), "93.184.216.34");
        assert_eq!(connect.options.get_port(), 6543);
        assert_eq!(connect.database, "app");
        assert_eq!(connect.options.get_database(), Some("app"));
        Ok(())
    }

    #[test]
    fn insecure_ssl_modes_require_explicit_private_transport_opt_in() -> Result<()> {
        let rejected = GuardedPostgresTarget {
            database_url: "postgres://db.example.test:6543/app?sslmode=disable".to_owned(),
            connect_addr: SocketAddr::from(([93, 184, 216, 34], 6543)),
            allow_private_network: true,
            allow_insecure_transport: false,
        };
        let err = rejected
            .connect_options("user", "password", None)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(err.contains("allow_insecure_transport"));

        let allowed = GuardedPostgresTarget {
            database_url: "postgres://db.example.test:6543/app?sslmode=disable".to_owned(),
            connect_addr: SocketAddr::from(([93, 184, 216, 34], 6543)),
            allow_private_network: true,
            allow_insecure_transport: true,
        };
        let connect = allowed.connect_options("user", "password", None)?;
        assert_eq!(connect.options.get_host(), "93.184.216.34");
        Ok(())
    }
}
