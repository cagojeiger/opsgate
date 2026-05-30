//! Shared target SSRF/IP guard helpers.

use std::net::IpAddr;

use opsgate_core::net::ssrf::is_blocked_target_ip;
use opsgate_core::{Error, Result};

pub(crate) const BLOCKED_TARGET_IP_MESSAGE: &str = "target IP is private/link-local/loopback";

pub(crate) fn target_ip_is_blocked(ip: IpAddr) -> bool {
    is_blocked_target_ip(ip)
}

pub(crate) fn ensure_target_ip_allowed(ip: IpAddr, allow_private_network: bool) -> Result<()> {
    if !allow_private_network && target_ip_is_blocked(ip) {
        return Err(Error::validation(BLOCKED_TARGET_IP_MESSAGE));
    }
    Ok(())
}
