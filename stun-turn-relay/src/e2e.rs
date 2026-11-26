//! End-to-end tests over loopback: real sockets, registry, allocation actors,
//! long-term credentials, ChannelBind/ChannelData and the peer IP policy.

use crate::auth::hmac_auth::{long_term_key, verify_integrity, HmacAlgo, HmacAuth};
use crate::config::Config;
use crate::protocol::stun::{self, decode_xor_address, encode_xor_address, Attribute, Class, StunMessage};
use crate::protocol::turn::{self, attr, method};
use crate::registry;
use crate::telemetry::Telemetry;
use crate::transport::control::ControlCtx;
use crate::transport::udp::Transport;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

const SECRET: &str = "test-secret-0123456789abcdef";
const REALM: &str = "relay.test";

struct TestServer {
    addr: SocketAddr,
    _shutdown: watch::Sender<bool>, // must stay alive: dropping it stops the transport
}

/// Starts a full server on loopback. Peers on loopback are allowed unless `extra` overrides it.
async fn start(range: (u16, u16), extra: &[(&str, &str)]) -> TestServer {
    let mut m: HashMap<String, String> = HashMap::new();
    m.insert("LISTEN_ADDR".into(), "127.0.0.1:0".into());
    m.insert("EXTERNAL_IP".into(), "127.0.0.1".into());
    m.insert("RELAY_MIN_PORT".into(), range.0.to_string());
    m.insert("RELAY_MAX_PORT".into(), range.1.to_string());
    m.insert("AUTH_SECRET".into(), SECRET.into());
    m.insert("REALM".into(), REALM.into());
    m.insert("ALLOW_PRIVATE_PEERS".into(), "true".into());
    for (k, v) in extra {
        m.insert(k.to_string(), v.to_string());
    }
    let cfg = Config::from_lookup(|k| m.get(k).cloned()).unwrap();

    let socket = Arc::new(UdpSocket::bind(cfg.listen_addr).await.unwrap());
    let addr = socket.local_addr().unwrap();
    let (telemetry, _t) = Telemetry::spawn(64);
    let (registry, _r) = registry::spawn(&cfg, socket.clone(), telemetry.clone());
    let ctx = Arc::new(ControlCtx::new(&cfg, socket, registry, telemetry));
    let (tx, rx) = watch::channel(false);
    tokio::spawn(Transport::new(ctx).run(rx));
    TestServer { addr, _shutdown: tx }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn txn(n: u8) -> [u8; 12] {
    [n; 12]
}

fn a(kind: u16, value: &[u8]) -> Attribute {
    Attribute {
        kind,
        value: Bytes::copy_from_slice(value),
    }
}

fn peer_attr(addr: SocketAddr, t: u8) -> Attribute {
    a(attr::XOR_PEER_ADDRESS, &encode_xor_address(addr, &txn(t)))
}

/// Unauthenticated request.
fn build(class: Class, m: u16, t: u8, attributes: Vec<Attribute>) -> Bytes {
    StunMessage {
        class,
        method: m,
        transaction_id: txn(t),
        attributes,
    }
    .encode(false)
}

/// Client-side credentials: what the messenger backend would hand to the app.
struct Session {
    username: String,
    key: [u8; 16],
    nonce: String,
}

impl Session {
    fn new(secret: &str, user_id: &str, expiry: u64, nonce: &str) -> Session {
        let auth = HmacAuth::new(secret, REALM);
        let (username, password) = auth.issue_credentials(user_id, expiry);
        Session {
            key: long_term_key(&username, REALM, &password),
            username,
            nonce: nonce.to_string(),
        }
    }

    fn valid(user_id: &str, nonce: &str) -> Session {
        Session::new(SECRET, user_id, now() + 3600, nonce)
    }

    /// Authenticated request: USERNAME + REALM + NONCE + MESSAGE-INTEGRITY.
    fn req(&self, m: u16, t: u8, mut attributes: Vec<Attribute>) -> Bytes {
        attributes.push(a(attr::USERNAME, self.username.as_bytes()));
        attributes.push(a(attr::REALM, REALM.as_bytes()));
        attributes.push(a(attr::NONCE, self.nonce.as_bytes()));
        StunMessage {
            class: Class::Request,
            method: m,
            transaction_id: txn(t),
            attributes,
        }
        .encode_with_integrity(&self.key, false)
    }

    fn allocate(&self, t: u8) -> Bytes {
        self.req(
            method::ALLOCATE,
            t,
            vec![a(attr::REQUESTED_TRANSPORT, &[turn::TRANSPORT_UDP, 0, 0, 0])],
        )
    }

    fn create_permission(&self, t: u8, peers: &[SocketAddr]) -> Bytes {
        self.req(method::CREATE_PERMISSION, t, peers.iter().map(|p| peer_attr(*p, t)).collect())
    }

    fn channel_bind(&self, t: u8, channel: u16, peer: SocketAddr) -> Bytes {
        self.req(
            method::CHANNEL_BIND,
            t,
            vec![a(attr::CHANNEL_NUMBER, &turn::encode_channel_number(channel)), peer_attr(peer, t)],
        )
    }

    fn refresh(&self, t: u8, lifetime: u32) -> Bytes {
        self.req(method::REFRESH, t, vec![a(attr::LIFETIME, &lifetime.to_be_bytes())])
    }
}

async fn recv_raw(sock: &UdpSocket) -> Bytes {
    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("timeout waiting for datagram")
        .unwrap();
    Bytes::copy_from_slice(&buf[..n])
}

async fn recv_msg(sock: &UdpSocket) -> StunMessage {
    StunMessage::parse(&recv_raw(sock).await).unwrap()
}

async fn rpc_raw(sock: &UdpSocket, server: SocketAddr, req: Bytes) -> (StunMessage, Bytes) {
    sock.send_to(&req, server).await.unwrap();
    let raw = recv_raw(sock).await;
    (StunMessage::parse(&raw).unwrap(), raw)
}

async fn rpc(sock: &UdpSocket, server: SocketAddr, req: Bytes) -> StunMessage {
    rpc_raw(sock, server, req).await.0
}

fn error_code_of(msg: &StunMessage) -> u16 {
    assert_eq!(msg.class, Class::ErrorResponse, "expected an error response");
    turn::decode_error_code(&msg.attribute(attr::ERROR_CODE).unwrap().value).unwrap()
}

fn assert_success(msg: &StunMessage) {
    assert_eq!(msg.class, Class::SuccessResponse, "expected success, got {msg:?}");
}

fn relayed_addr_of(msg: &StunMessage) -> SocketAddr {
    assert_success(msg);
    decode_xor_address(&msg.attribute(attr::XOR_RELAYED_ADDRESS).unwrap().value, &msg.transaction_id).unwrap()
}

fn lifetime_of(msg: &StunMessage) -> u32 {
    turn::decode_lifetime(&msg.attribute(attr::LIFETIME).unwrap().value).unwrap()
}

fn nonce_of(msg: &StunMessage) -> String {
    String::from_utf8(msg.attribute(attr::NONCE).expect("NONCE in challenge").value.to_vec()).unwrap()
}

/// An unauthenticated request is answered with 401 + REALM + NONCE; return that nonce.
async fn fetch_nonce(sock: &UdpSocket, server: SocketAddr) -> String {
    let r = rpc(sock, server, build(Class::Request, method::REFRESH, 200, vec![])).await;
    assert_eq!(error_code_of(&r), 401);
    nonce_of(&r)
}

#[tokio::test]
async fn full_relay_flow() {
    let srv = start((52000, 52050), &[]).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();

    // STUN Binding needs no credentials.
    let r = rpc(&client, srv.addr, build(Class::Request, stun::method::BINDING, 1, vec![])).await;
    let mapped = r.attribute(stun::attr::XOR_MAPPED_ADDRESS).unwrap();
    assert_eq!(
        decode_xor_address(&mapped.value, &r.transaction_id).unwrap(),
        client.local_addr().unwrap()
    );

    // First Allocate without credentials -> 401 with REALM + NONCE.
    let unauth = build(
        Class::Request,
        method::ALLOCATE,
        2,
        vec![a(attr::REQUESTED_TRANSPORT, &[turn::TRANSPORT_UDP, 0, 0, 0])],
    );
    let r = rpc(&client, srv.addr, unauth).await;
    assert_eq!(error_code_of(&r), 401);
    assert_eq!(&r.attribute(attr::REALM).unwrap().value[..], REALM.as_bytes());
    let s = Session::valid("alice", &nonce_of(&r));

    // Authenticated Allocate: default lifetime, response signed with MESSAGE-INTEGRITY.
    let (r, raw) = rpc_raw(&client, srv.addr, s.allocate(3)).await;
    let relayed = relayed_addr_of(&r);
    assert_eq!(lifetime_of(&r), 300);
    assert!(verify_integrity(&s.key, &raw), "success response must carry valid MESSAGE-INTEGRITY");

    // A second Allocate from the same 5-tuple -> 437.
    assert_eq!(error_code_of(&rpc(&client, srv.addr, s.allocate(4)).await), 437);

    // Peer traffic without a permission is dropped.
    peer.send_to(b"early", relayed).await.unwrap();
    assert!(timeout(Duration::from_millis(200), recv_raw(&client)).await.is_err());

    // CreatePermission, then client -> peer via Send indication.
    assert_success(&rpc(&client, srv.addr, s.create_permission(5, &[peer_addr])).await);
    let send = build(
        Class::Indication,
        method::SEND,
        6,
        vec![peer_attr(peer_addr, 6), a(attr::DATA, b"hello")],
    );
    client.send_to(&send, srv.addr).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = timeout(Duration::from_secs(2), peer.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(from, relayed);

    // peer -> client arrives as a Data indication (no channel bound yet).
    peer.send_to(b"world", relayed).await.unwrap();
    let ind = recv_msg(&client).await;
    assert_eq!(ind.class, Class::Indication);
    assert_eq!(ind.method, method::DATA);
    let p = ind.attribute(attr::XOR_PEER_ADDRESS).unwrap();
    assert_eq!(decode_xor_address(&p.value, &ind.transaction_id).unwrap(), peer_addr);
    assert_eq!(&ind.attribute(attr::DATA).unwrap().value[..], b"world");

    // ChannelBind 0x4000 -> peer.
    assert_success(&rpc(&client, srv.addr, s.channel_bind(7, 0x4000, peer_addr)).await);
    // Conflicts: same peer on another channel, or the channel on another peer -> 400.
    assert_eq!(error_code_of(&rpc(&client, srv.addr, s.channel_bind(8, 0x4001, peer_addr)).await), 400);
    let other: SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert_eq!(error_code_of(&rpc(&client, srv.addr, s.channel_bind(9, 0x4000, other)).await), 400);
    // Re-binding the same pair is a refresh.
    assert_success(&rpc(&client, srv.addr, s.channel_bind(10, 0x4000, peer_addr)).await);

    // client -> peer via ChannelData.
    client
        .send_to(&turn::encode_channel_data(0x4000, b"chan"), srv.addr)
        .await
        .unwrap();
    let (n, from) = timeout(Duration::from_secs(2), peer.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"chan");
    assert_eq!(from, relayed);

    // peer -> client now arrives as ChannelData.
    peer.send_to(b"back", relayed).await.unwrap();
    let raw = recv_raw(&client).await;
    assert!(turn::is_channel_data(&raw));
    let (ch, payload) = turn::parse_channel_data(&raw).unwrap();
    assert_eq!(ch, 0x4000);
    assert_eq!(&payload[..], b"back");

    // Refresh is capped at 600 s; lifetime 0 deletes the allocation.
    assert_eq!(lifetime_of(&rpc(&client, srv.addr, s.refresh(11, 1000)).await), 600);
    assert_eq!(lifetime_of(&rpc(&client, srv.addr, s.refresh(12, 0)).await), 0);

    // The 5-tuple and the port are free again.
    sleep(Duration::from_millis(200)).await;
    relayed_addr_of(&rpc(&client, srv.addr, s.allocate(13)).await);
}

#[tokio::test]
async fn quotas_and_validation() {
    let srv = start((52100, 52150), &[("MAX_ALLOCATIONS", "2"), ("MAX_ALLOCATIONS_PER_USER", "1")]).await;
    let c1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let nonce = fetch_nonce(&c1, srv.addr).await;
    let bob = Session::valid("bob", &nonce);
    let carol = Session::valid("carol", &nonce);
    let dave = Session::valid("dave", &nonce);
    let erin = Session::valid("erin", &nonce);

    relayed_addr_of(&rpc(&c1, srv.addr, bob.allocate(1)).await);

    // Same user_id (even with fresh credentials), second allocation -> 486.
    let bob_again = Session::valid("bob", &nonce);
    assert_eq!(error_code_of(&rpc(&c2, srv.addr, bob_again.allocate(2)).await), 486);

    // Another user fits; a third one exceeds the global limit -> 508.
    relayed_addr_of(&rpc(&c2, srv.addr, carol.allocate(3)).await);
    assert_eq!(error_code_of(&rpc(&c3, srv.addr, dave.allocate(4)).await), 508);

    // Refresh / CreatePermission / ChannelBind without an allocation -> 437.
    assert_eq!(error_code_of(&rpc(&c4, srv.addr, dave.refresh(5, 100)).await), 437);
    let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
    assert_eq!(error_code_of(&rpc(&c4, srv.addr, dave.create_permission(6, &[peer])).await), 437);
    assert_eq!(error_code_of(&rpc(&c4, srv.addr, dave.channel_bind(7, 0x4000, peer)).await), 437);

    // Non-UDP REQUESTED-TRANSPORT -> 400.
    let bad = erin.req(method::ALLOCATE, 8, vec![a(attr::REQUESTED_TRANSPORT, &[6, 0, 0, 0])]);
    assert_eq!(error_code_of(&rpc(&c4, srv.addr, bad).await), 400);
}

#[tokio::test]
async fn authentication_failures() {
    let srv = start((52200, 52250), &[]).await;
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let nonce = fetch_nonce(&c, srv.addr).await;

    // Credentials minted with a different secret -> 401 (+ fresh challenge).
    let forged = Session::new("other-secret-0123456789abcdef", "alice", now() + 3600, &nonce);
    let r = rpc(&c, srv.addr, forged.allocate(1)).await;
    assert_eq!(error_code_of(&r), 401);
    assert!(r.attribute(attr::REALM).is_some() && r.attribute(attr::NONCE).is_some());

    // Expired credentials -> 401.
    let expired = Session::new(SECRET, "alice", now() - 10, &nonce);
    assert_eq!(error_code_of(&rpc(&c, srv.addr, expired.allocate(2)).await), 401);

    // Garbage nonce -> 438 with a fresh nonce.
    let garbage = Session::valid("alice", "garbage");
    let r = rpc(&c, srv.addr, garbage.allocate(3)).await;
    assert_eq!(error_code_of(&r), 438);
    let fresh = nonce_of(&r);

    // Genuinely stale nonce -> 438.
    let stale_nonce = HmacAuth::new(SECRET, REALM).make_nonce(now() - 10_000);
    let stale = Session::valid("alice", &stale_nonce);
    assert_eq!(error_code_of(&rpc(&c, srv.addr, stale.allocate(4)).await), 438);

    // Retrying with the fresh nonce works.
    let ok = Session::valid("alice", &fresh);
    relayed_addr_of(&rpc(&c, srv.addr, ok.allocate(5)).await);
}

#[tokio::test]
async fn forbidden_peers_are_rejected() {
    let srv = start((52300, 52350), &[("ALLOW_PRIVATE_PEERS", "false")]).await;
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let nonce = fetch_nonce(&c, srv.addr).await;
    let s = Session::valid("alice", &nonce);
    relayed_addr_of(&rpc(&c, srv.addr, s.allocate(1)).await);

    let loopback: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let private: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let metadata: SocketAddr = "169.254.169.254:80".parse().unwrap();
    let public: SocketAddr = "8.8.8.8:3478".parse().unwrap();

    // Any forbidden peer -> 403 for CreatePermission (all-or-nothing) and ChannelBind.
    assert_eq!(error_code_of(&rpc(&c, srv.addr, s.create_permission(2, &[loopback])).await), 403);
    assert_eq!(error_code_of(&rpc(&c, srv.addr, s.create_permission(3, &[public, private])).await), 403);
    assert_eq!(error_code_of(&rpc(&c, srv.addr, s.channel_bind(4, 0x4000, metadata)).await), 403);

    // Public peers are fine.
    assert_success(&rpc(&c, srv.addr, s.create_permission(5, &[public])).await);
    assert_success(&rpc(&c, srv.addr, s.channel_bind(6, 0x4000, public)).await);
}

#[tokio::test]
async fn loadtest_smoke() {
    let srv = start((52400, 52450), &[]).await;
    let report = crate::loadtest::run_with(&crate::loadtest::Params {
        server: srv.addr,
        secret: SECRET.to_string(),
        realm: REALM.to_string(),
        algo: HmacAlgo::Sha256,
        peer_ip: "127.0.0.1".parse().unwrap(),
        clients: 3,
        seconds: 1,
        pps: 50,
        payload: 160,
    })
    .await;
    assert_eq!(report.clients_ok, 3, "all simulated clients must allocate and bind");
    assert_eq!(report.sent, 150);
    assert!(report.received > 100, "echo path must work, got {}", report.received);
}

impl Session {
    /// Like `new`, but the password is derived with a specific algorithm
    /// (what a coturn-compatible backend does with `sha1`).
    fn with_algo(secret: &str, user_id: &str, expiry: u64, nonce: &str, algo: HmacAlgo) -> Session {
        let auth = HmacAuth::new(secret, REALM).with_algos(vec![algo]);
        let (username, password) = auth.issue_credentials(user_id, expiry);
        Session {
            key: long_term_key(&username, REALM, &password),
            username,
            nonce: nonce.to_string(),
        }
    }
}

#[tokio::test]
async fn hmac_algorithm_compatibility() {
    let sha1_srv = start((52500, 52550), &[("AUTH_HMAC_ALGO", "sha1")]).await;
    let both_srv = start((52600, 52650), &[("AUTH_HMAC_ALGO", "sha1,sha256")]).await;
    let c1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // A coturn-style (HMAC-SHA1) backend works against a sha1 server...
    let n = fetch_nonce(&c1, sha1_srv.addr).await;
    let coturn_style = Session::with_algo(SECRET, "alice", now() + 3600, &n, HmacAlgo::Sha1);
    relayed_addr_of(&rpc(&c1, sha1_srv.addr, coturn_style.allocate(1)).await);

    // ...but SHA-256 credentials are refused by it.
    let n = fetch_nonce(&c2, sha1_srv.addr).await;
    let sha256 = Session::with_algo(SECRET, "bob", now() + 3600, &n, HmacAlgo::Sha256);
    assert_eq!(error_code_of(&rpc(&c2, sha1_srv.addr, sha256.allocate(2)).await), 401);

    // Migration mode accepts both at the same time.
    let n = fetch_nonce(&c3, both_srv.addr).await;
    let old = Session::with_algo(SECRET, "carol", now() + 3600, &n, HmacAlgo::Sha1);
    relayed_addr_of(&rpc(&c3, both_srv.addr, old.allocate(3)).await);
    let new = Session::with_algo(SECRET, "dave", now() + 3600, &n, HmacAlgo::Sha256);
    relayed_addr_of(&rpc(&c4, both_srv.addr, new.allocate(4)).await);
}

#[tokio::test]
async fn expired_credentials_session_grace_and_ownership() {
    let with_grace = start((52700, 52750), &[("CREDENTIAL_GRACE_SECS", "3600")]).await;
    let no_grace = start((52800, 52850), &[("CREDENTIAL_GRACE_SECS", "0")]).await;
    let c1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let n_grace = fetch_nonce(&c1, with_grace.addr).await;
    let n_strict = fetch_nonce(&c2, no_grace.addr).await;

    // Credentials valid for only ~2 s.
    let expiry = now() + 2;
    let alice_grace = Session::new(SECRET, "alice", expiry, &n_grace);
    let alice_strict = Session::new(SECRET, "alice", expiry, &n_strict);
    relayed_addr_of(&rpc(&c1, with_grace.addr, alice_grace.allocate(1)).await);
    relayed_addr_of(&rpc(&c2, no_grace.addr, alice_strict.allocate(1)).await);

    sleep(Duration::from_millis(3200)).await; // the credentials are expired now

    // With a grace period the call keeps working: Refresh on the existing allocation succeeds.
    assert_eq!(lifetime_of(&rpc(&c1, with_grace.addr, alice_grace.refresh(2, 300)).await), 300);
    // ...but expired credentials can never create a NEW allocation.
    let expired_again = Session::new(SECRET, "alice", expiry, &n_grace);
    assert_eq!(error_code_of(&rpc(&c3, with_grace.addr, expired_again.allocate(3)).await), 401);
    // Another user cannot touch alice's allocation, even with fresh credentials.
    let mallory = Session::valid("mallory", &n_grace);
    assert_eq!(error_code_of(&rpc(&c1, with_grace.addr, mallory.refresh(4, 300)).await), 401);
    // Without a grace period the same Refresh is rejected.
    assert_eq!(error_code_of(&rpc(&c2, no_grace.addr, alice_strict.refresh(2, 300)).await), 401);
}

#[tokio::test]
async fn configurable_peer_ranges() {
    let srv = start(
        (52900, 52950),
        &[
            ("ALLOW_PRIVATE_PEERS", "false"),
            ("ALLOWED_PEER_IPS", "10.1.2.0/24"),
            ("DENIED_PEER_IPS", "8.8.8.0-8.8.8.255, 203.0.113.7"),
        ],
    )
    .await;
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let nonce = fetch_nonce(&c, srv.addr).await;
    let s = Session::valid("alice", &nonce);
    relayed_addr_of(&rpc(&c, srv.addr, s.allocate(1)).await);

    let peer = |a: &str| -> SocketAddr { a.parse().unwrap() };
    // Explicit exception beats the built-in "private" rule; the rest of 10/8 stays blocked.
    assert_success(&rpc(&c, srv.addr, s.create_permission(2, &[peer("10.1.2.3:5000")])).await);
    assert_eq!(error_code_of(&rpc(&c, srv.addr, s.create_permission(3, &[peer("10.9.9.9:5000")])).await), 403);
    // Configured denials (range and single address).
    assert_eq!(error_code_of(&rpc(&c, srv.addr, s.create_permission(4, &[peer("8.8.8.8:5000")])).await), 403);
    assert_eq!(error_code_of(&rpc(&c, srv.addr, s.channel_bind(5, 0x4000, peer("203.0.113.7:1"))).await), 403);
    // Everything else public is fine.
    assert_success(&rpc(&c, srv.addr, s.create_permission(6, &[peer("1.1.1.1:3478")])).await);
}
