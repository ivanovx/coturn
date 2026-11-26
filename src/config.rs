//! Environment-based configuration (spec §3.2 / §6.1).

use crate::auth::hmac_auth::HmacAlgo;
use crate::auth::policy::IpRange;
use crate::error::ConfigError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

pub const MAX_LIFETIME_SECS: u32 = 600;
pub const MAX_CREDENTIAL_GRACE_SECS: u64 = 86_400;
const MIN_SECRET_LEN: usize = 16;

#[derive(Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub external_ip: Option<IpAddr>,
    pub relay_min_port: u16,
    pub relay_max_port: u16,
    pub max_allocations: usize,
    pub max_allocations_per_user: usize,
    pub allocation_lifetime_secs: u32,
    /// Shared secret for the HMAC time-limited credentials (required).
    pub auth_secret: String,
    /// Accepted password algorithms (first = used by `mint-credentials`).
    /// `sha1` is what coturn's `use-auth-secret` uses.
    pub auth_algos: Vec<HmacAlgo>,
    /// How long after expiry the credentials still work for an EXISTING allocation.
    pub credential_grace_secs: u64,
    /// TURN realm advertised in 401/438 challenges.
    pub realm: String,
    /// DEV ONLY: disable the built-in peer deny rules (loopback/private/link-local...).
    pub allow_private_peers: bool,
    /// Exceptions that override every deny rule (like coturn `allowed-peer-ip`).
    pub allowed_peer_ips: Vec<IpRange>,
    /// Extra denied ranges (like coturn `denied-peer-ip`).
    pub denied_peer_ips: Vec<IpRange>,
    pub channel_cap: usize,
    pub metrics_addr: Option<SocketAddr>,
}

// Manual Debug so the secret never ends up in logs.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen_addr", &self.listen_addr)
            .field("external_ip", &self.external_ip)
            .field("relay_min_port", &self.relay_min_port)
            .field("relay_max_port", &self.relay_max_port)
            .field("max_allocations", &self.max_allocations)
            .field("max_allocations_per_user", &self.max_allocations_per_user)
            .field("allocation_lifetime_secs", &self.allocation_lifetime_secs)
            .field("auth_secret", &"<redacted>")
            .field("auth_algos", &self.auth_algos)
            .field("credential_grace_secs", &self.credential_grace_secs)
            .field("realm", &self.realm)
            .field("allow_private_peers", &self.allow_private_peers)
            .field("allowed_peer_ips", &self.allowed_peer_ips.len())
            .field("denied_peer_ips", &self.denied_peer_ips.len())
            .field("channel_cap", &self.channel_cap)
            .field("metrics_addr", &self.metrics_addr)
            .finish()
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable constructor: `get` replaces `std::env::var`.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());

        let auth_secret = get("AUTH_SECRET").ok_or_else(|| ConfigError::Invalid {
            key: "AUTH_SECRET",
            value: String::new(),
            reason: "is required".to_string(),
        })?;

        let cfg = Config {
            listen_addr: parse_or(&get, "LISTEN_ADDR", "0.0.0.0:3478".parse().unwrap())?,
            external_ip: parse_opt(&get, "EXTERNAL_IP")?,
            relay_min_port: parse_or(&get, "RELAY_MIN_PORT", 49152)?,
            relay_max_port: parse_or(&get, "RELAY_MAX_PORT", 49352)?,
            max_allocations: parse_or(&get, "MAX_ALLOCATIONS", 2000)?,
            max_allocations_per_user: parse_or(&get, "MAX_ALLOCATIONS_PER_USER", 16)?,
            allocation_lifetime_secs: parse_or(&get, "ALLOCATION_LIFETIME_SECS", 300)?,
            auth_secret,
            auth_algos: parse_algos(&get)?,
            credential_grace_secs: parse_or(&get, "CREDENTIAL_GRACE_SECS", 3600)?,
            realm: get("REALM").unwrap_or_else(|| "relay".to_string()),
            allow_private_peers: parse_or(&get, "ALLOW_PRIVATE_PEERS", false)?,
            allowed_peer_ips: parse_ranges(&get, "ALLOWED_PEER_IPS")?,
            denied_peer_ips: parse_ranges(&get, "DENIED_PEER_IPS")?,
            channel_cap: parse_or(&get, "CHANNEL_CAP", 512)?,
            metrics_addr: parse_opt(&get, "METRICS_ADDR")?,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let bad = |key: &'static str, value: String, reason: &str| ConfigError::Invalid {
            key,
            value,
            reason: reason.to_string(),
        };

        if self.auth_secret.len() < MIN_SECRET_LEN {
            return Err(bad("AUTH_SECRET", "<redacted>".into(), "must be at least 16 characters"));
        }
        if self.credential_grace_secs > MAX_CREDENTIAL_GRACE_SECS {
            return Err(bad(
                "CREDENTIAL_GRACE_SECS",
                self.credential_grace_secs.to_string(),
                "must be at most 86400",
            ));
        }
        if self.realm.len() > 255 {
            return Err(bad("REALM", self.realm.clone(), "must be at most 255 bytes"));
        }
        if self.relay_min_port < 1024 {
            return Err(bad("RELAY_MIN_PORT", self.relay_min_port.to_string(), "must be >= 1024"));
        }
        if self.relay_min_port > self.relay_max_port {
            return Err(bad(
                "RELAY_MAX_PORT",
                self.relay_max_port.to_string(),
                "must be >= RELAY_MIN_PORT",
            ));
        }
        if self.max_allocations == 0 {
            return Err(bad("MAX_ALLOCATIONS", "0".into(), "must be > 0"));
        }
        if self.max_allocations_per_user == 0 || self.max_allocations_per_user > self.max_allocations {
            return Err(bad(
                "MAX_ALLOCATIONS_PER_USER",
                self.max_allocations_per_user.to_string(),
                "must be in 1..=MAX_ALLOCATIONS",
            ));
        }
        if self.allocation_lifetime_secs == 0 || self.allocation_lifetime_secs > MAX_LIFETIME_SECS {
            return Err(bad(
                "ALLOCATION_LIFETIME_SECS",
                self.allocation_lifetime_secs.to_string(),
                "must be in 1..=600",
            ));
        }
        if self.channel_cap == 0 {
            return Err(bad("CHANNEL_CAP", "0".into(), "must be > 0"));
        }
        Ok(())
    }

    /// Every allocation needs its own relay port, so the port range caps the real capacity.
    pub fn effective_max_allocations(&self) -> usize {
        let ports = (self.relay_max_port - self.relay_min_port) as usize + 1;
        self.max_allocations.min(ports)
    }
}

fn parse_or<T>(
    get: &impl Fn(&str) -> Option<String>,
    key: &'static str,
    default: T,
) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    Ok(parse_opt(get, key)?.unwrap_or(default))
}

fn parse_opt<T>(get: &impl Fn(&str) -> Option<String>, key: &'static str) -> Result<Option<T>, ConfigError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match get(key) {
        None => Ok(None),
        Some(v) => match v.trim().parse::<T>() {
            Ok(x) => Ok(Some(x)),
            Err(e) => Err(ConfigError::Invalid {
                key,
                value: v,
                reason: e.to_string(),
            }),
        },
    }
}

/// AUTH_HMAC_ALGO: comma separated, e.g. "sha1" (coturn), "sha256" (default) or "sha1,sha256".
fn parse_algos(get: &impl Fn(&str) -> Option<String>) -> Result<Vec<HmacAlgo>, ConfigError> {
    let Some(raw) = get("AUTH_HMAC_ALGO") else {
        return Ok(vec![HmacAlgo::Sha256]);
    };
    let mut out: Vec<HmacAlgo> = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.parse::<HmacAlgo>() {
            Ok(a) => {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
            Err(reason) => {
                return Err(ConfigError::Invalid {
                    key: "AUTH_HMAC_ALGO",
                    value: raw.clone(),
                    reason,
                })
            }
        }
    }
    if out.is_empty() {
        return Err(ConfigError::Invalid {
            key: "AUTH_HMAC_ALGO",
            value: raw,
            reason: "must list at least one of sha1, sha256".to_string(),
        });
    }
    Ok(out)
}

/// ALLOWED_PEER_IPS / DENIED_PEER_IPS: comma separated IPs, CIDRs or `start-end` ranges.
fn parse_ranges(get: &impl Fn(&str) -> Option<String>, key: &'static str) -> Result<Vec<IpRange>, ConfigError> {
    let Some(raw) = get(key) else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpRange>().map_err(|reason| ConfigError::Invalid {
                key,
                value: s.to_string(),
                reason,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SECRET: &str = "0123456789abcdef0123";

    /// Builds a config; AUTH_SECRET defaults to a valid value unless overridden.
    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("AUTH_SECRET".into(), SECRET.into());
        for (k, v) in pairs {
            m.insert(k.to_string(), v.to_string());
        }
        Config::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn defaults_are_valid() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.listen_addr.port(), 3478);
        assert_eq!(c.relay_min_port, 49152);
        assert_eq!(c.allocation_lifetime_secs, 300);
        assert_eq!(c.realm, "relay");
        assert_eq!(c.auth_algos, vec![HmacAlgo::Sha256]);
        assert_eq!(c.credential_grace_secs, 3600);
        assert!(!c.allow_private_peers);
        assert!(c.allowed_peer_ips.is_empty() && c.denied_peer_ips.is_empty());
    }

    #[test]
    fn secret_is_required_and_long_enough() {
        assert!(Config::from_lookup(|_| None).is_err());
        assert!(cfg(&[("AUTH_SECRET", "short")]).is_err());
    }

    #[test]
    fn custom_values() {
        let c = cfg(&[
            ("LISTEN_ADDR", "127.0.0.1:5000"),
            ("EXTERNAL_IP", "203.0.113.10"),
            ("MAX_ALLOCATIONS", "10"),
            ("MAX_ALLOCATIONS_PER_USER", "2"),
            ("REALM", "example.org"),
            ("ALLOW_PRIVATE_PEERS", "true"),
        ])
        .unwrap();
        assert_eq!(c.listen_addr.port(), 5000);
        assert_eq!(c.external_ip, Some("203.0.113.10".parse().unwrap()));
        assert_eq!(c.max_allocations, 10);
        assert_eq!(c.realm, "example.org");
        assert!(c.allow_private_peers);
    }

    #[test]
    fn coturn_migration_settings() {
        let c = cfg(&[
            ("REALM", "telex"),
            ("RELAY_MIN_PORT", "49160"),
            ("RELAY_MAX_PORT", "49200"),
            ("AUTH_HMAC_ALGO", "sha1"),
        ])
        .unwrap();
        assert_eq!(c.realm, "telex");
        assert_eq!(c.auth_algos, vec![HmacAlgo::Sha1]);
        assert_eq!(c.effective_max_allocations(), 41); // 49160..=49200
    }

    #[test]
    fn algorithm_list_parsing() {
        let c = cfg(&[("AUTH_HMAC_ALGO", " SHA1 , sha256 , sha1 ")]).unwrap();
        assert_eq!(c.auth_algos, vec![HmacAlgo::Sha1, HmacAlgo::Sha256]);
        assert!(cfg(&[("AUTH_HMAC_ALGO", "md5")]).is_err());
        // A list with no usable entry is an error.
        assert!(cfg(&[("AUTH_HMAC_ALGO", " , ")]).is_err());
    }

    #[test]
    fn peer_ranges_parsing() {
        let c = cfg(&[
            ("ALLOWED_PEER_IPS", "10.1.2.0/24"),
            ("DENIED_PEER_IPS", "8.8.8.0-8.8.8.255, 203.0.113.7 ,fd00::/8"),
        ])
        .unwrap();
        assert_eq!(c.allowed_peer_ips.len(), 1);
        assert_eq!(c.denied_peer_ips.len(), 3);
        assert!(cfg(&[("DENIED_PEER_IPS", "10.0.0.0/99")]).is_err());
        assert!(cfg(&[("ALLOWED_PEER_IPS", "not-an-ip")]).is_err());
    }

    #[test]
    fn grace_is_bounded() {
        assert_eq!(cfg(&[("CREDENTIAL_GRACE_SECS", "0")]).unwrap().credential_grace_secs, 0);
        assert!(cfg(&[("CREDENTIAL_GRACE_SECS", "86401")]).is_err());
    }

    #[test]
    fn rejects_inverted_port_range() {
        assert!(cfg(&[("RELAY_MIN_PORT", "50000"), ("RELAY_MAX_PORT", "49999")]).is_err());
    }

    #[test]
    fn rejects_garbage_and_excessive_lifetime() {
        assert!(cfg(&[("LISTEN_ADDR", "nope")]).is_err());
        assert!(cfg(&[("ALLOCATION_LIFETIME_SECS", "601")]).is_err());
        assert!(cfg(&[("ALLOW_PRIVATE_PEERS", "maybe")]).is_err());
    }

    #[test]
    fn debug_redacts_secret() {
        let c = cfg(&[]).unwrap();
        assert!(!format!("{c:?}").contains(SECRET));
    }
}
