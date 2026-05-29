use std::net::IpAddr;

use ipnet::IpNet;

const BLOCKED_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "0.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "::1/128",
    "::/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

pub fn is_blocked_target_ip(ip: IpAddr) -> bool {
    BLOCKED_CIDRS
        .iter()
        .filter_map(|cidr| cidr.parse::<IpNet>().ok())
        .any(|network| network.contains(&ip))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::is_blocked_target_ip;

    #[test]
    fn blocks_private_and_metadata_ranges() {
        let blocked = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        for ip in blocked {
            assert!(is_blocked_target_ip(ip), "{ip} should be blocked");
        }
    }

    #[test]
    fn allows_public_ranges() {
        let allowed = [
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        ];
        for ip in allowed {
            assert!(!is_blocked_target_ip(ip), "{ip} should be allowed");
        }
    }
}
