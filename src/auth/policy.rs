//! Peer IP policy (spec §5.1): the relay must never be usable to reach
//! loopback, private, link-local, unspecified, multicast or broadcast hosts.
//!
//! On top of the built-in rules the operator can configure (coturn-style):
//!   ALLOWED_PEER_IPS  exceptions that override every deny rule
//!   DENIED_PEER_IPS   extra ranges to refuse
//! Entries are comma separated: single IP, CIDR (10.0.0.0/8) or range (10.0.0.0-10.255.255.255).
//! Evaluation order: allowed -> built-in rules (unless ALLOW_PRIVATE_PEERS) -> denied.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Inclusive address range (IPv4 or IPv6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpRange {
    V4(u32, u32),
    V6(u128, u128),
}

impl IpRange {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpRange::V4(lo, hi), IpAddr::V4(v4)) => {
                let n = u32::from(v4);
                *lo <= n && n <= *hi
            }
            (IpRange::V6(lo, hi), IpAddr::V6(v6)) => {
                let n = u128::from(v6);
                *lo <= n && n <= *hi
            }
            _ => false,
        }
    }
}

impl FromStr for IpRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let ip = |t: &str| -> Result<IpAddr, String> {
            t.trim().parse::<IpAddr>().map_err(|_| format!("invalid IP address in {s:?}"))
        };

        if let Some((a, b)) = s.split_once('-') {
            return match (ip(a)?, ip(b)?) {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    let (a, b) = (u32::from(a), u32::from(b));
                    if a <= b {
                        Ok(IpRange::V4(a, b))
                    } else {
                        Err(format!("range start is after its end in {s:?}"))
                    }
                }
                (IpAddr::V6(a), IpAddr::V6(b)) => {
                    let (a, b) = (u128::from(a), u128::from(b));
                    if a <= b {
                        Ok(IpRange::V6(a, b))
                    } else {
                        Err(format!("range start is after its end in {s:?}"))
                    }
                }
                _ => Err(format!("mixed address families in {s:?}")),
            };
        }

        if let Some((addr, prefix)) = s.split_once('/') {
            let prefix: u32 = prefix
                .trim()
                .parse()
                .map_err(|_| format!("invalid prefix length in {s:?}"))?;
            return match ip(addr)? {
                IpAddr::V4(v4) => {
                    if prefix > 32 {
                        return Err(format!("IPv4 prefix must be 0..=32 in {s:?}"));
                    }
                    let mask = if prefix == 0 { 0u32 } else { u32::MAX << (32 - prefix) };
                    let start = u32::from(v4) & mask;
                    Ok(IpRange::V4(start, start | !mask))
                }
                IpAddr::V6(v6) => {
                    if prefix > 128 {
                        return Err(format!("IPv6 prefix must be 0..=128 in {s:?}"));
                    }
                    let mask = if prefix == 0 { 0u128 } else { u128::MAX << (128 - prefix) };
                    let start = u128::from(v6) & mask;
                    Ok(IpRange::V6(start, start | !mask))
                }
            };
        }

        match s.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => Ok(IpRange::V4(u32::from(v4), u32::from(v4))),
            Ok(IpAddr::V6(v6)) => Ok(IpRange::V6(u128::from(v6), u128::from(v6))),
            Err(_) => Err(format!("expected an IP address, CIDR or range, got {s:?}")),
        }
    }
}

/// The complete peer policy used by CreatePermission / ChannelBind.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    /// DEV ONLY: disables the built-in deny rules.
    pub allow_private: bool,
    pub allowed: Vec<IpRange>,
    pub denied: Vec<IpRange>,
}

impl PeerPolicy {
    /// `Some(reason)` if the peer must be refused.
    pub fn check(&self, ip: IpAddr) -> Option<&'static str> {
        let ip = normalize(ip);
        if self.allowed.iter().any(|r| r.contains(ip)) {
            return None;
        }
        if !self.allow_private {
            if let Some(reason) = forbidden_reason(ip) {
                return Some(reason);
            }
        }
        if self.denied.iter().any(|r| r.contains(ip)) {
            return Some("denied-by-config");
        }
        None
    }
}

/// ::ffff:a.b.c.d is judged as the embedded IPv4 address.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Built-in rules: the reason why `ip` must not be used as a relay peer, or `None`.
pub fn forbidden_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_private() {
        Some("private")
    } else if ip.is_link_local() {
        Some("link-local")
    } else if ip.is_unspecified() || ip.octets()[0] == 0 {
        Some("unspecified")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if ip.is_broadcast() {
        Some("broadcast")
    } else {
        None
    }
}

fn forbidden_v6(ip: Ipv6Addr) -> Option<&'static str> {
    // ::ffff:a.b.c.d must be judged by its embedded IPv4 address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return forbidden_v4(v4);
    }
    let first = ip.segments()[0];
    if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_unspecified() {
        Some("unspecified")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if first & 0xfe00 == 0xfc00 {
        Some("unique-local")
    } else if first & 0xffc0 == 0xfe80 {
        Some("link-local")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> bool {
        forbidden_reason(s.parse().unwrap()).is_some()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_internal_ipv4() {
        for ip in [
            "127.0.0.1", "127.255.255.254", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "169.254.169.254", "0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.255", "255.255.255.255",
        ] {
            assert!(blocked(ip), "{ip} should be blocked");
        }
    }

    #[test]
    fn allows_public_ipv4() {
        for ip in ["8.8.8.8", "203.0.113.10", "172.15.0.1", "172.32.0.1", "192.169.0.1", "1.1.1.1"] {
            assert!(!blocked(ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn blocks_internal_ipv6() {
        for ip in ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"] {
            assert!(blocked(ip), "{ip} should be blocked");
        }
    }

    #[test]
    fn allows_public_ipv6() {
        for ip in ["2001:4860:4860::8888", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(!blocked(ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn parses_cidr_range_and_single() {
        let cidr: IpRange = "10.1.2.0/24".parse().unwrap();
        assert!(cidr.contains(ip("10.1.2.0")) && cidr.contains(ip("10.1.2.255")));
        assert!(!cidr.contains(ip("10.1.3.0")) && !cidr.contains(ip("10.1.1.255")));

        let range: IpRange = "192.168.0.0-192.168.0.9".parse().unwrap();
        assert!(range.contains(ip("192.168.0.0")) && range.contains(ip("192.168.0.9")));
        assert!(!range.contains(ip("192.168.0.10")));

        let single: IpRange = "203.0.113.7".parse().unwrap();
        assert!(single.contains(ip("203.0.113.7")) && !single.contains(ip("203.0.113.8")));

        let v6: IpRange = "fd00::/8".parse().unwrap();
        assert!(v6.contains(ip("fd12::1")) && !v6.contains(ip("fe80::1")));

        let all: IpRange = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("8.8.8.8")) && !all.contains(ip("::1")));

        let host: IpRange = "1.2.3.4/32".parse().unwrap();
        assert!(host.contains(ip("1.2.3.4")) && !host.contains(ip("1.2.3.5")));
    }

    #[test]
    fn rejects_invalid_ranges() {
        for bad in ["", "nope", "10.0.0.0/33", "::/129", "10.0.0.9-10.0.0.1", "10.0.0.1-::1", "10.0.0.0/x"] {
            assert!(bad.parse::<IpRange>().is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn allowed_overrides_builtin_and_denied_extends_it() {
        let p = PeerPolicy {
            allow_private: false,
            allowed: vec!["10.1.2.0/24".parse().unwrap()],
            denied: vec!["8.8.8.0-8.8.8.255".parse().unwrap(), "203.0.113.7".parse().unwrap()],
        };
        assert_eq!(p.check(ip("10.1.2.3")), None); // exception beats the built-in "private" rule
        assert_eq!(p.check(ip("10.9.9.9")), Some("private"));
        assert_eq!(p.check(ip("8.8.8.8")), Some("denied-by-config"));
        assert_eq!(p.check(ip("203.0.113.7")), Some("denied-by-config"));
        assert_eq!(p.check(ip("1.1.1.1")), None);
        assert_eq!(p.check(ip("::ffff:10.1.2.3")), None); // IPv4-mapped is normalized
    }

    #[test]
    fn allow_private_keeps_configured_denials() {
        let p = PeerPolicy {
            allow_private: true,
            allowed: vec![],
            denied: vec!["10.0.0.0/8".parse().unwrap()],
        };
        assert_eq!(p.check(ip("127.0.0.1")), None);
        assert_eq!(p.check(ip("10.0.0.1")), Some("denied-by-config"));
    }
}
