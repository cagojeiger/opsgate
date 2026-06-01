//! Shared target SSRF/IP guard helpers.

use std::net::IpAddr;

use opsgate_core::{Error, Result};

pub const BLOCKED_TARGET_IP_MESSAGE: &str = "target IP is private/link-local/loopback";

pub fn target_ip_is_blocked(ip: IpAddr) -> bool {
    let blocked = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001:2::/48",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ];
    blocked
        .iter()
        .filter_map(|cidr| cidr.parse::<ipnet::IpNet>().ok())
        .any(|net| net.contains(&ip))
}

pub fn ensure_target_ip_allowed(ip: IpAddr, allow_private_network: bool) -> Result<()> {
    if !allow_private_network && target_ip_is_blocked(ip) {
        return Err(Error::validation(BLOCKED_TARGET_IP_MESSAGE));
    }
    Ok(())
}
