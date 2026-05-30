use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use opsgate_core::{Error, Result};

use super::ssrf::{ensure_target_ip_allowed, target_ip_is_blocked};
use sqlx::postgres::{PgConnectOptions, PgSslMode};

#[derive(Debug, Clone)]
pub(crate) struct GuardedPostgresTarget {
    endpoint: String,
    connect_addr: SocketAddr,
}

impl GuardedPostgresTarget {
    pub(crate) fn connect_options(
        &self,
        username: &str,
        password: &str,
    ) -> Result<PgConnectOptions> {
        let options = PgConnectOptions::from_str(&self.endpoint)
            .map_err(|error| Error::validation(format!("postgres endpoint: {error}")))?;
        if matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
            return Err(Error::validation(
                "postgres endpoint sslmode=verify-full is unsupported by guarded SQL targets",
            ));
        }
        let options = options
            .host(&self.connect_addr.ip().to_string())
            .port(self.connect_addr.port())
            .username(username)
            .password(password);
        Ok(options)
    }

    #[cfg(test)]
    fn connect_addr(&self) -> SocketAddr {
        self.connect_addr
    }
}

pub(crate) async fn prepare_postgres_target(
    endpoint: &str,
    allow_private_network: bool,
) -> Result<GuardedPostgresTarget> {
    let url = url::Url::parse(endpoint)
        .map_err(|error| Error::validation(format!("postgres endpoint: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::validation("postgres endpoint requires host"))?;
    let port = url.port_or_known_default().unwrap_or(5432);
    let connect_addr = if let Ok(ip) = host.parse::<IpAddr>() {
        select_postgres_addr(host, port, vec![ip], allow_private_network)?
    } else {
        let ips = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| Error::validation(format!("resolve target host: {error}")))?
            .map(|addr| addr.ip())
            .collect::<Vec<_>>();
        select_postgres_addr(host, port, ips, allow_private_network)?
    };
    Ok(GuardedPostgresTarget {
        endpoint: endpoint.to_owned(),
        connect_addr,
    })
}

fn select_postgres_addr(
    _host: &str,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn guarded_postgres_target_blocks_private_literal() -> Result<()> {
        let err = prepare_postgres_target("postgres://127.0.0.1:5432/app", false)
            .await
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(err.contains("private/link-local/loopback"));
        Ok(())
    }

    #[tokio::test]
    async fn guarded_postgres_target_allows_private_when_enabled() -> Result<()> {
        let target = prepare_postgres_target("postgres://127.0.0.1:15432/app", true).await?;
        assert_eq!(
            target.connect_addr(),
            SocketAddr::from(([127, 0, 0, 1], 15432))
        );
        Ok(())
    }

    #[test]
    fn dns_result_guard_blocks_private_ip() {
        let err = select_postgres_addr(
            "db.example.test",
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

    #[test]
    fn connect_options_reject_verify_full_before_ip_overwrite() {
        let target = GuardedPostgresTarget {
            endpoint: "postgres://db.example.test:6543/app?sslmode=verify-full".to_owned(),
            connect_addr: SocketAddr::from(([93, 184, 216, 34], 6543)),
        };
        let err = target
            .connect_options("user", "password")
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(err.contains("verify-full is unsupported"));
    }

    #[test]
    fn connect_options_use_guarded_target_addr() -> Result<()> {
        let target = GuardedPostgresTarget {
            endpoint: "postgres://db.example.test:6543/app?sslmode=disable".to_owned(),
            connect_addr: SocketAddr::from(([93, 184, 216, 34], 6543)),
        };
        let options = target.connect_options("user", "password")?;
        assert_eq!(options.get_host(), "93.184.216.34");
        assert_eq!(options.get_port(), 6543);
        assert_eq!(options.get_database(), Some("app"));
        Ok(())
    }
}
