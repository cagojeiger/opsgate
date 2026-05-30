use std::net::{IpAddr, SocketAddr};

use opsgate_core::net::ssrf::is_blocked_target_ip;
use opsgate_core::{Error, Result};

pub(crate) async fn validate_postgres_target_ips(endpoint: &str) -> Result<()> {
    let url = url::Url::parse(endpoint)
        .map_err(|error| Error::validation(format!("postgres endpoint: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::validation("postgres endpoint requires host"))?;
    let port = url.port_or_known_default().unwrap_or(5432);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_target_ip(ip) {
            return Err(Error::validation(
                "target IP is private/link-local/loopback",
            ));
        }
        return Ok(());
    }
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| Error::validation(format!("resolve target host: {error}")))?;
    let ips = addrs.map(|addr: SocketAddr| addr.ip()).collect::<Vec<_>>();
    if ips.is_empty() {
        return Err(Error::validation("resolve target host: no IPs"));
    }
    if ips.into_iter().any(is_blocked_target_ip) {
        return Err(Error::validation(
            "target IP is private/link-local/loopback",
        ));
    }
    Ok(())
}
