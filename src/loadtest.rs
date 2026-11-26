//! Dev tool (`stun-turn-relay loadtest ...`): simulates N clients doing
//! Allocate -> ChannelBind -> ChannelData against a running relay. An
//! in-process "peer" echoes every packet, so each client measures the full
//! client -> relay -> peer -> relay -> client round trip (RTT, jitter, loss).
//! Run it from another machine for realistic numbers, and watch the server's
//! memory with `docker stats` while it runs.

use crate::auth::hmac_auth::{long_term_key, HmacAlgo, HmacAuth};
use crate::protocol::stun::{encode_xor_address, Attribute, Class, StunMessage};
use crate::protocol::turn::{self, attr, method};
use bytes::Bytes;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::{interval, timeout, timeout_at, Instant as TokioInstant, MissedTickBehavior};

const CHANNEL: u16 = 0x4000;

#[derive(Clone)]
pub struct Params {
    pub server: SocketAddr,
    pub secret: String,
    pub realm: String,
    /// Password algorithm the server expects (first entry of its AUTH_HMAC_ALGO).
    pub algo: HmacAlgo,
    /// IP the relay will send to (must be reachable from the relay and allowed by its IP policy).
    pub peer_ip: IpAddr,
    pub clients: u32,
    pub seconds: u32,
    pub pps: u32,
    pub payload: usize,
}

#[derive(Default)]
pub struct Report {
    pub clients_ok: u32,
    pub clients_failed: u32,
    pub sent: u64,
    pub received: u64,
    pub rtts_us: Vec<u32>,
    jitter_sum_us: u64,
    jitter_n: u64,
}

struct ClientResult {
    sent: u64,
    rtts_us: Vec<u32>,
    jitter_sum_us: u64,
    jitter_n: u64,
}

struct Creds {
    username: String,
    key: [u8; 16],
    realm: String,
    nonce: String,
}

impl Creds {
    fn request(&self, t: [u8; 12], m: u16, mut attributes: Vec<Attribute>) -> Bytes {
        attributes.push(attr_of(attr::USERNAME, self.username.as_bytes()));
        attributes.push(attr_of(attr::REALM, self.realm.as_bytes()));
        attributes.push(attr_of(attr::NONCE, self.nonce.as_bytes()));
        StunMessage {
            class: Class::Request,
            method: m,
            transaction_id: t,
            attributes,
        }
        .encode_with_integrity(&self.key, false)
    }
}

fn attr_of(kind: u16, value: &[u8]) -> Attribute {
    Attribute {
        kind,
        value: Bytes::copy_from_slice(value),
    }
}

fn txn(idx: u32, step: u8) -> [u8; 12] {
    let mut t = [0u8; 12];
    t[..4].copy_from_slice(&idx.to_be_bytes());
    t[4] = step;
    t
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn rpc(sock: &UdpSocket, server: SocketAddr, req: Bytes) -> Option<StunMessage> {
    sock.send_to(&req, server).await.ok()?;
    let mut buf = vec![0u8; 2048];
    let n = timeout(Duration::from_secs(2), sock.recv(&mut buf)).await.ok()?.ok()?;
    StunMessage::parse(&Bytes::copy_from_slice(&buf[..n])).ok()
}

async fn run_client(idx: u32, p: Arc<Params>, peer: SocketAddr, start: Instant) -> Option<ClientResult> {
    let bind = if p.server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = Arc::new(UdpSocket::bind(bind).await.ok()?);

    // 1. Unauthenticated request -> 401 with NONCE.
    let challenge = rpc(
        &sock,
        p.server,
        StunMessage {
            class: Class::Request,
            method: method::REFRESH,
            transaction_id: txn(idx, 0),
            attributes: vec![],
        }
        .encode(false),
    )
    .await?;
    let nonce = String::from_utf8(challenge.attribute(attr::NONCE)?.value.to_vec()).ok()?;

    // 2. Credentials, exactly as the messenger backend would mint them.
    let auth = HmacAuth::new(&p.secret, &p.realm).with_algos(vec![p.algo]);
    let (username, password) = auth.issue_credentials(&format!("loadtest-{idx}"), unix_now() + 3600);
    let creds = Creds {
        key: long_term_key(&username, &p.realm, &password),
        username,
        realm: p.realm.clone(),
        nonce,
    };

    // 3. Allocate.
    let resp = rpc(
        &sock,
        p.server,
        creds.request(
            txn(idx, 1),
            method::ALLOCATE,
            vec![attr_of(attr::REQUESTED_TRANSPORT, &[turn::TRANSPORT_UDP, 0, 0, 0])],
        ),
    )
    .await?;
    if resp.class != Class::SuccessResponse {
        return None;
    }

    // 4. ChannelBind to the echo peer (also installs the permission).
    let t = txn(idx, 2);
    let resp = rpc(
        &sock,
        p.server,
        creds.request(
            t,
            method::CHANNEL_BIND,
            vec![
                attr_of(attr::CHANNEL_NUMBER, &turn::encode_channel_number(CHANNEL)),
                attr_of(attr::XOR_PEER_ADDRESS, &encode_xor_address(peer, &t)),
            ],
        ),
    )
    .await?;
    if resp.class != Class::SuccessResponse {
        return None;
    }

    // 5. Receiver: collects RTTs until one second after the sender finishes.
    let total = p.seconds as u64 * p.pps as u64;
    let end = TokioInstant::now() + Duration::from_secs(p.seconds as u64 + 1);
    let rx_sock = sock.clone();
    let receiver = tokio::spawn(async move {
        let mut rtts: Vec<u32> = Vec::new();
        let (mut jitter_sum, mut jitter_n) = (0u64, 0u64);
        let mut last: Option<u32> = None;
        let mut buf = vec![0u8; 2048];
        loop {
            match timeout_at(end, rx_sock.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if !turn::is_channel_data(&buf[..n]) {
                        continue;
                    }
                    let Ok((_, payload)) = turn::parse_channel_data(&Bytes::copy_from_slice(&buf[..n])) else {
                        continue;
                    };
                    if payload.len() < 16 {
                        continue;
                    }
                    let sent_us = u64::from_be_bytes(payload[8..16].try_into().unwrap());
                    let now_us = start.elapsed().as_micros() as u64;
                    let rtt = now_us.saturating_sub(sent_us).min(u32::MAX as u64) as u32;
                    if let Some(prev) = last {
                        jitter_sum += (rtt as i64 - prev as i64).unsigned_abs();
                        jitter_n += 1;
                    }
                    last = Some(rtt);
                    rtts.push(rtt);
                }
                _ => break,
            }
        }
        (rtts, jitter_sum, jitter_n)
    });

    // 6. Sender: one ChannelData frame per tick.
    let mut tick = interval(Duration::from_micros(1_000_000 / p.pps.max(1) as u64));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut payload = vec![0u8; p.payload.max(16)];
    let mut sent = 0u64;
    for seq in 0..total {
        tick.tick().await;
        payload[..8].copy_from_slice(&seq.to_be_bytes());
        payload[8..16].copy_from_slice(&(start.elapsed().as_micros() as u64).to_be_bytes());
        let frame = turn::encode_channel_data(CHANNEL, &payload);
        if sock.send_to(&frame, p.server).await.is_ok() {
            sent += 1;
        }
    }

    let (rtts_us, jitter_sum_us, jitter_n) = receiver.await.ok()?;

    // 7. Best-effort cleanup: lifetime 0 frees the allocation immediately.
    let _ = rpc(
        &sock,
        p.server,
        creds.request(
            txn(idx, 3),
            method::REFRESH,
            vec![attr_of(attr::LIFETIME, &0u32.to_be_bytes())],
        ),
    )
    .await;

    Some(ClientResult {
        sent,
        rtts_us,
        jitter_sum_us,
        jitter_n,
    })
}

pub async fn run_with(params: &Params) -> Report {
    let p = Arc::new(params.clone());
    let mut report = Report::default();

    let Ok(peer_sock) = UdpSocket::bind("0.0.0.0:0").await else {
        report.clients_failed = p.clients;
        return report;
    };
    let peer_sock = Arc::new(peer_sock);
    let peer_port = peer_sock.local_addr().map(|a| a.port()).unwrap_or(0);
    let peer = SocketAddr::new(p.peer_ip, peer_port);

    let echo = peer_sock.clone();
    let echo_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], from).await;
        }
    });

    let start = Instant::now();
    let handles: Vec<_> = (0..p.clients)
        .map(|idx| tokio::spawn(run_client(idx, p.clone(), peer, start)))
        .collect();

    for h in handles {
        match h.await {
            Ok(Some(r)) => {
                report.clients_ok += 1;
                report.sent += r.sent;
                report.received += r.rtts_us.len() as u64;
                report.jitter_sum_us += r.jitter_sum_us;
                report.jitter_n += r.jitter_n;
                report.rtts_us.extend(r.rtts_us);
            }
            _ => report.clients_failed += 1,
        }
    }
    echo_task.abort();
    report
}

fn percentile(sorted: &[u32], q: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

impl Report {
    pub fn print(&self, p: &Params) {
        let mut rtts = self.rtts_us.clone();
        rtts.sort_unstable();
        let ms = |us: u32| us as f64 / 1000.0;
        let lost = self.sent.saturating_sub(self.received);
        let loss_pct = if self.sent == 0 {
            0.0
        } else {
            lost as f64 * 100.0 / self.sent as f64
        };
        let jitter_ms = if self.jitter_n == 0 {
            0.0
        } else {
            self.jitter_sum_us as f64 / self.jitter_n as f64 / 1000.0
        };
        println!("target:        {}", p.server);
        println!(
            "clients:       {} ok, {} failed (of {})",
            self.clients_ok, self.clients_failed, p.clients
        );
        println!(
            "load:          {} pps x {} B per client for {} s (~{:.1} Mbit/s total, one direction)",
            p.pps,
            p.payload.max(16),
            p.seconds,
            self.clients_ok as f64 * p.pps as f64 * p.payload.max(16) as f64 * 8.0 / 1_000_000.0
        );
        println!("packets:       sent {}, echoed {}, lost {} ({loss_pct:.2}%)", self.sent, self.received, lost);
        println!(
            "rtt (ms):      p50 {:.2}  p95 {:.2}  p99 {:.2}  max {:.2}",
            ms(percentile(&rtts, 0.50)),
            ms(percentile(&rtts, 0.95)),
            ms(percentile(&rtts, 0.99)),
            ms(rtts.last().copied().unwrap_or(0))
        );
        println!("jitter (ms):   {jitter_ms:.3} (mean |RTT[i] - RTT[i-1]|)");
        println!("note: watch the relay's memory with `docker stats` while this runs.");
    }
}

pub async fn run_cli(args: &[String]) -> ExitCode {
    const USAGE: &str = "usage: stun-turn-relay loadtest <server_addr> [clients=50] [seconds=10] [pps=50] [payload=160]\n\
env:   AUTH_SECRET (required, same as the server), REALM (default: relay),\n\
       AUTH_HMAC_ALGO (first entry is used, default: sha256),\n\
       LOADTEST_PEER_IP (default: 127.0.0.1; the relay must be allowed to reach it,\n\
       e.g. run the server with ALLOW_PRIVATE_PEERS=true for loopback/private peers)";

    fn num<T: std::str::FromStr>(args: &[String], i: usize, default: T) -> Option<T> {
        match args.get(i) {
            Some(s) => s.parse().ok(),
            None => Some(default),
        }
    }

    let Some(server) = args.first().and_then(|s| s.parse::<SocketAddr>().ok()) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (Some(clients), Some(seconds), Some(pps), Some(payload)) = (
        num(args, 1, 50u32),
        num(args, 2, 10u32),
        num(args, 3, 50u32),
        num(args, 4, 160usize),
    ) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if clients == 0 || seconds == 0 || pps == 0 || pps > 1000 || payload > 1400 {
        eprintln!("invalid arguments (clients/seconds >= 1, 1 <= pps <= 1000, payload <= 1400)\n{USAGE}");
        return ExitCode::from(2);
    }
    let Ok(secret) = std::env::var("AUTH_SECRET") else {
        eprintln!("AUTH_SECRET is required\n{USAGE}");
        return ExitCode::from(2);
    };
    let realm = std::env::var("REALM").unwrap_or_else(|_| "relay".to_string());
    let algo = match std::env::var("AUTH_HMAC_ALGO") {
        Ok(s) => match s.split(',').next().unwrap_or("").parse::<HmacAlgo>() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("invalid AUTH_HMAC_ALGO: {e}");
                return ExitCode::from(2);
            }
        },
        Err(_) => HmacAlgo::Sha256,
    };
    let peer_ip = match std::env::var("LOADTEST_PEER_IP") {
        Ok(s) => match s.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("invalid LOADTEST_PEER_IP");
                return ExitCode::from(2);
            }
        },
        Err(_) => IpAddr::from([127, 0, 0, 1]),
    };

    let params = Params {
        server,
        secret,
        realm,
        algo,
        peer_ip,
        clients,
        seconds,
        pps,
        payload,
    };
    println!("running load test ({clients} clients, {seconds} s)...");
    let report = run_with(&params).await;
    report.print(&params);
    if report.clients_ok == 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
