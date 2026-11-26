//! Time-limited credentials + TURN long-term-credential verification.
//!
//! Scheme (coturn "use-auth-secret" / TURN REST API compatible):
//!   username = "<expiry_unix>:<user_id>"      (a bare "<expiry_unix>" is accepted too)
//!   password = base64(HMAC-<algo>(AUTH_SECRET, username))
//! `algo` is SHA-1 for coturn compatibility or SHA-256; the server can accept
//! several at once (AUTH_HMAC_ALGO=sha1,sha256) to migrate a backend gradually.
//! The client then runs the standard TURN long-term mechanism (USERNAME, REALM,
//! NONCE, MESSAGE-INTEGRITY = HMAC-SHA1 keyed with MD5(username:realm:password)),
//! so unmodified WebRTC stacks work. The server derives the password
//! statelessly, so it needs no user database.
//!
//! Nonces are stateless too: "<unix_ts_hex>.<hmac16hex>" (always HMAC-SHA256).

use crate::protocol::stun::{self, Attribute, StunMessage};
use crate::protocol::turn::attr;
use crate::types::TurnError;
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::str::FromStr;

pub const NONCE_LIFETIME_SECS: u64 = 600;
const NONCE_FUTURE_SKEW_SECS: u64 = 60;

/// Hash used for the temporary password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgo {
    Sha1,
    Sha256,
}

impl FromStr for HmacAlgo {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sha1" => Ok(HmacAlgo::Sha1),
            "sha256" => Ok(HmacAlgo::Sha256),
            other => Err(format!("unknown algorithm {other:?} (expected sha1 or sha256)")),
        }
    }
}

/// Result of a successful authentication.
pub struct Authenticated {
    /// Identity used for per-user quotas and allocation ownership.
    pub user_id: String,
    /// Long-term key; also signs the success response (MESSAGE-INTEGRITY).
    pub key: [u8; 16],
}

#[derive(Clone)]
pub struct HmacAuth {
    secret: Vec<u8>,
    realm: String,
    /// Accepted password algorithms. The first one is used to mint credentials.
    algos: Vec<HmacAlgo>,
    /// Requests on an existing allocation may use credentials that expired up to this long ago.
    grace_secs: u64,
}

impl HmacAuth {
    /// SHA-256 only, no grace period.
    pub fn new(secret: &str, realm: &str) -> Self {
        HmacAuth {
            secret: secret.as_bytes().to_vec(),
            realm: realm.to_string(),
            algos: vec![HmacAlgo::Sha256],
            grace_secs: 0,
        }
    }

    pub fn with_algos(mut self, algos: Vec<HmacAlgo>) -> Self {
        if !algos.is_empty() {
            self.algos = algos;
        }
        self
    }

    pub fn with_grace_secs(mut self, secs: u64) -> Self {
        self.grace_secs = secs;
        self
    }

    /// Password for `username` with the primary (first) algorithm.
    pub fn password_for(&self, username: &str) -> String {
        self.password_for_algo(username, self.algos[0])
    }

    pub fn password_for_algo(&self, username: &str, algo: HmacAlgo) -> String {
        STANDARD.encode(hmac_tag(algo, &self.secret, username.as_bytes()))
    }

    /// What the messenger backend does: mint (username, password) valid until `expiry_unix`.
    /// Also exposed through `stun-turn-relay mint-credentials`.
    pub fn issue_credentials(&self, user_id: &str, expiry_unix: u64) -> (String, String) {
        let username = format!("{expiry_unix}:{user_id}");
        let password = self.password_for(&username);
        (username, password)
    }

    pub fn make_nonce(&self, now_unix: u64) -> String {
        let ts_hex = format!("{now_unix:x}");
        let tag = self.nonce_mac(&ts_hex);
        format!("{ts_hex}.{}", hex_encode(&tag[..8]))
    }

    pub fn check_nonce(&self, nonce: &str, now_unix: u64) -> bool {
        let Some((ts_hex, mac_hex)) = nonce.split_once('.') else {
            return false;
        };
        let Ok(ts) = u64::from_str_radix(ts_hex, 16) else {
            return false;
        };
        let Some(mac) = hex_decode(mac_hex) else {
            return false;
        };
        if mac.len() != 8 {
            return false;
        }
        let mut m = Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        m.update(format!("nonce:{ts_hex}").as_bytes());
        if m.verify_truncated_left(&mac).is_err() {
            return false;
        }
        ts <= now_unix.saturating_add(NONCE_FUTURE_SKEW_SECS) && now_unix.saturating_sub(ts) <= NONCE_LIFETIME_SECS
    }

    /// REALM + fresh NONCE attributes for 401 / 438 responses.
    pub fn challenge(&self, now_unix: u64) -> Vec<Attribute> {
        vec![
            Attribute {
                kind: attr::REALM,
                value: Bytes::copy_from_slice(self.realm.as_bytes()),
            },
            Attribute {
                kind: attr::NONCE,
                value: Bytes::from(self.make_nonce(now_unix).into_bytes()),
            },
        ]
    }

    /// Strict verification (used for Allocate): the credentials must not be expired.
    /// `Unauthorized` -> 401, `StaleNonce` -> 438 (both get a fresh challenge).
    pub fn authenticate(&self, msg: &StunMessage, raw: &[u8], now_unix: u64) -> Result<Authenticated, TurnError> {
        self.verify(msg, raw, now_unix, 0, None)
    }

    /// Verification for requests on an EXISTING allocation (Refresh, CreatePermission,
    /// ChannelBind): the credentials must belong to the allocation's owner and may have
    /// expired up to `grace_secs` ago, so long calls survive a short credential TTL.
    /// Expired credentials can never create a new allocation.
    pub fn authenticate_session(
        &self,
        msg: &StunMessage,
        raw: &[u8],
        now_unix: u64,
        owner_user_id: &str,
    ) -> Result<Authenticated, TurnError> {
        self.verify(msg, raw, now_unix, self.grace_secs, Some(owner_user_id))
    }

    fn verify(
        &self,
        msg: &StunMessage,
        raw: &[u8],
        now_unix: u64,
        grace_secs: u64,
        owner: Option<&str>,
    ) -> Result<Authenticated, TurnError> {
        if msg.attribute(stun::attr::MESSAGE_INTEGRITY).is_none() {
            return Err(TurnError::Unauthorized);
        }
        let (Some(u), Some(r), Some(n)) = (
            msg.attribute(attr::USERNAME),
            msg.attribute(attr::REALM),
            msg.attribute(attr::NONCE),
        ) else {
            return Err(TurnError::Unauthorized);
        };
        let username = std::str::from_utf8(&u.value).map_err(|_| TurnError::Unauthorized)?;
        let realm = std::str::from_utf8(&r.value).map_err(|_| TurnError::Unauthorized)?;
        let nonce = std::str::from_utf8(&n.value).map_err(|_| TurnError::Unauthorized)?;

        if !self.check_nonce(nonce, now_unix) {
            return Err(TurnError::StaleNonce);
        }
        if realm != self.realm {
            return Err(TurnError::Unauthorized);
        }

        let (expiry, user_id) = parse_username(username).ok_or(TurnError::Unauthorized)?;
        if expiry.saturating_add(grace_secs) <= now_unix {
            return Err(TurnError::Unauthorized);
        }
        if let Some(owner) = owner {
            if owner != user_id {
                return Err(TurnError::Unauthorized);
            }
        }

        for &algo in &self.algos {
            let password = self.password_for_algo(username, algo);
            let key = long_term_key(username, &self.realm, &password);
            if verify_integrity(&key, raw) {
                return Ok(Authenticated { user_id, key });
            }
        }
        Err(TurnError::Unauthorized)
    }

    fn nonce_mac(&self, ts_hex: &str) -> Vec<u8> {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        m.update(format!("nonce:{ts_hex}").as_bytes());
        m.finalize().into_bytes().to_vec()
    }
}

/// "<expiry>:<user_id>" or a bare "<expiry>" (coturn allows the timestamp alone;
/// then the whole username is the identity).
fn parse_username(username: &str) -> Option<(u64, String)> {
    match username.split_once(':') {
        Some((ts, rest)) => {
            let expiry = ts.parse::<u64>().ok()?;
            let user_id = if rest.is_empty() { username } else { rest };
            Some((expiry, user_id.to_string()))
        }
        None => Some((username.parse::<u64>().ok()?, username.to_string())),
    }
}

fn hmac_tag(algo: HmacAlgo, secret: &[u8], data: &[u8]) -> Vec<u8> {
    match algo {
        HmacAlgo::Sha1 => {
            let mut m = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        HmacAlgo::Sha256 => {
            let mut m = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
}

/// key = MD5(username ":" realm ":" password)  (RFC 5389 §15.4, no SASLprep).
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let digest = Md5::digest(format!("{username}:{realm}:{password}").as_bytes());
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest);
    key
}

/// HMAC-SHA1 over `data` (MESSAGE-INTEGRITY).
pub fn message_integrity(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut m = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    let tag = m.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time MESSAGE-INTEGRITY check of a raw STUN message.
pub fn verify_integrity(key: &[u8], raw: &[u8]) -> bool {
    let Some((data, mac)) = stun::integrity_parts(raw) else {
        return false;
    };
    let mut m = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(&data);
    m.verify_slice(&mac).is_ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::stun::Class;

    const REALM: &str = "realm.test";
    const SECRET: &str = "unit-test-secret-0123456789";
    const NOW: u64 = 1_800_000_000;

    fn auth() -> HmacAuth {
        HmacAuth::new(SECRET, REALM)
    }

    fn at(kind: u16, v: &str) -> Attribute {
        Attribute {
            kind,
            value: Bytes::copy_from_slice(v.as_bytes()),
        }
    }

    /// Client side: signs a request for `username` with the password derived by `signer`.
    fn signed_with_username(signer: &HmacAuth, username: &str, nonce_ts: u64) -> Bytes {
        let key = long_term_key(username, REALM, &signer.password_for(username));
        StunMessage {
            class: Class::Request,
            method: 0x003,
            transaction_id: [1; 12],
            attributes: vec![
                at(attr::USERNAME, username),
                at(attr::REALM, REALM),
                at(attr::NONCE, &signer.make_nonce(nonce_ts)),
            ],
        }
        .encode_with_integrity(&key, false)
    }

    fn signed_request(a: &HmacAuth, user_id: &str, expiry: u64, nonce_ts: u64) -> Bytes {
        let (username, _) = a.issue_credentials(user_id, expiry);
        signed_with_username(a, &username, nonce_ts)
    }

    fn check(a: &HmacAuth, raw: &Bytes) -> Result<Authenticated, TurnError> {
        let msg = StunMessage::parse(raw).unwrap();
        a.authenticate(&msg, raw, NOW)
    }

    fn check_session(a: &HmacAuth, raw: &Bytes, owner: &str) -> Result<Authenticated, TurnError> {
        let msg = StunMessage::parse(raw).unwrap();
        a.authenticate_session(&msg, raw, NOW, owner)
    }

    #[test]
    fn nonce_roundtrip_expiry_and_tamper() {
        let a = auth();
        let n = a.make_nonce(NOW);
        assert!(a.check_nonce(&n, NOW));
        assert!(a.check_nonce(&n, NOW + NONCE_LIFETIME_SECS));
        assert!(!a.check_nonce(&n, NOW + NONCE_LIFETIME_SECS + 1));
        assert!(!a.check_nonce(&a.make_nonce(NOW + 3600), NOW)); // from the future
        assert!(!a.check_nonce("garbage", NOW));
        assert!(!a.check_nonce(&format!("{}x", n), NOW));
        // Nonce minted with another secret is rejected.
        assert!(!HmacAuth::new("another-secret-0123456789", REALM).check_nonce(&n, NOW));
    }

    #[test]
    fn password_matches_published_hmac_vectors() {
        // RFC 2202 (HMAC-SHA1, case 2) and RFC 4231 (HMAC-SHA256, case 2):
        // key "Jefe", data "what do ya want for nothing?".
        let a = HmacAuth::new("Jefe", REALM);
        let data = "what do ya want for nothing?";
        let sha1 = STANDARD.encode(hex_decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").unwrap());
        let sha256 = STANDARD
            .encode(hex_decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap());
        assert_eq!(a.password_for_algo(data, HmacAlgo::Sha1), sha1);
        assert_eq!(a.password_for_algo(data, HmacAlgo::Sha256), sha256);
        assert_eq!(a.password_for(data), sha256); // default primary algorithm
        assert_eq!(a.with_algos(vec![HmacAlgo::Sha1]).password_for(data), sha1);
    }

    #[test]
    fn algorithm_parsing() {
        assert_eq!("sha1".parse::<HmacAlgo>(), Ok(HmacAlgo::Sha1));
        assert_eq!(" SHA256 ".parse::<HmacAlgo>(), Ok(HmacAlgo::Sha256));
        assert!("md5".parse::<HmacAlgo>().is_err());
    }

    #[test]
    fn valid_request_authenticates() {
        let a = auth();
        let raw = signed_request(&a, "alice", NOW + 100, NOW);
        assert_eq!(check(&a, &raw).unwrap().user_id, "alice");
    }

    #[test]
    fn user_id_may_contain_colons() {
        let a = auth();
        let raw = signed_request(&a, "user:with:colons", NOW + 100, NOW);
        assert_eq!(check(&a, &raw).unwrap().user_id, "user:with:colons");
    }

    #[test]
    fn bare_timestamp_username_is_accepted() {
        // coturn: "If you don't have a suitable id, the timestamp alone can be used."
        let a = auth();
        let username = (NOW + 100).to_string();
        let raw = signed_with_username(&a, &username, NOW);
        assert_eq!(check(&a, &raw).unwrap().user_id, username);
        // Not a number at all -> rejected.
        let raw = signed_with_username(&a, "alice", NOW);
        assert_eq!(check(&a, &raw).err(), Some(TurnError::Unauthorized));
    }

    #[test]
    fn sha1_only_sha256_only_and_migration_mode() {
        let sha1 = HmacAuth::new(SECRET, REALM).with_algos(vec![HmacAlgo::Sha1]);
        let sha256 = HmacAuth::new(SECRET, REALM).with_algos(vec![HmacAlgo::Sha256]);
        let both = HmacAuth::new(SECRET, REALM).with_algos(vec![HmacAlgo::Sha1, HmacAlgo::Sha256]);

        let from_sha1_backend = signed_request(&sha1, "alice", NOW + 100, NOW);
        let from_sha256_backend = signed_request(&sha256, "alice", NOW + 100, NOW);

        assert!(check(&sha1, &from_sha1_backend).is_ok());
        assert_eq!(check(&sha1, &from_sha256_backend).err(), Some(TurnError::Unauthorized));
        assert!(check(&sha256, &from_sha256_backend).is_ok());
        assert_eq!(check(&sha256, &from_sha1_backend).err(), Some(TurnError::Unauthorized));
        assert!(check(&both, &from_sha1_backend).is_ok());
        assert!(check(&both, &from_sha256_backend).is_ok());
    }

    #[test]
    fn expired_credentials_are_rejected() {
        let a = auth();
        let raw = signed_request(&a, "alice", NOW - 1, NOW);
        assert_eq!(check(&a, &raw).err(), Some(TurnError::Unauthorized));
    }

    #[test]
    fn existing_session_gets_grace_but_only_for_its_owner() {
        let a = HmacAuth::new(SECRET, REALM).with_grace_secs(60);
        let expired_10s = signed_request(&a, "alice", NOW - 10, NOW);
        let expired_100s = signed_request(&a, "alice", NOW - 100, NOW);

        // Strict check (new allocation): expired credentials are refused.
        assert_eq!(check(&a, &expired_10s).err(), Some(TurnError::Unauthorized));
        // Existing allocation owned by alice: within the grace window it is accepted.
        assert_eq!(check_session(&a, &expired_10s, "alice").unwrap().user_id, "alice");
        // Beyond the grace window it is refused again.
        assert_eq!(check_session(&a, &expired_100s, "alice").err(), Some(TurnError::Unauthorized));
        // Somebody else's allocation: refused even with valid credentials.
        let fresh_bob = signed_request(&a, "bob", NOW + 100, NOW);
        assert_eq!(check_session(&a, &fresh_bob, "alice").err(), Some(TurnError::Unauthorized));
        // Grace 0 disables the feature.
        assert_eq!(
            check_session(&auth(), &expired_10s, "alice").err(),
            Some(TurnError::Unauthorized)
        );
    }

    #[test]
    fn stale_nonce_is_438() {
        let a = auth();
        let raw = signed_request(&a, "alice", NOW + 100, NOW - 10_000);
        assert_eq!(check(&a, &raw).err(), Some(TurnError::StaleNonce));
    }

    #[test]
    fn wrong_secret_and_tampering_are_rejected() {
        let a = auth();
        let other = HmacAuth::new("another-secret-0123456789", REALM);
        // Signed with a different secret, but the nonce is valid for `a`.
        let (username, password) = other.issue_credentials("alice", NOW + 100);
        let key = long_term_key(&username, REALM, &password);
        let raw = StunMessage {
            class: Class::Request,
            method: 0x003,
            transaction_id: [1; 12],
            attributes: vec![
                at(attr::USERNAME, &username),
                at(attr::REALM, REALM),
                at(attr::NONCE, &a.make_nonce(NOW)),
            ],
        }
        .encode_with_integrity(&key, false);
        assert_eq!(check(&a, &raw).err(), Some(TurnError::Unauthorized));

        // Flip a header byte (transaction id): MESSAGE-INTEGRITY covers it.
        let mut bytes = signed_request(&a, "alice", NOW + 100, NOW).to_vec();
        bytes[10] ^= 0xFF;
        assert_eq!(check(&a, &Bytes::from(bytes)).err(), Some(TurnError::Unauthorized));
    }

    #[test]
    fn missing_integrity_or_fields_is_401() {
        let a = auth();
        let raw = StunMessage {
            class: Class::Request,
            method: 0x003,
            transaction_id: [1; 12],
            attributes: vec![],
        }
        .encode(false);
        assert_eq!(check(&a, &raw).err(), Some(TurnError::Unauthorized));
    }

    #[test]
    fn integrity_survives_fingerprint() {
        let a = auth();
        let (username, password) = a.issue_credentials("alice", NOW + 100);
        let key = long_term_key(&username, REALM, &password);
        let msg = StunMessage::binding_success([3; 12], "198.51.100.1:1234".parse().unwrap());
        let raw = msg.encode_with_integrity(&key, true);
        StunMessage::parse(&raw).unwrap(); // fingerprint valid
        assert!(verify_integrity(&key, &raw));
        assert!(!verify_integrity(b"wrong-key", &raw));
    }
}
