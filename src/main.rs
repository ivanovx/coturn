mod allocation;
mod auth;
mod config;
mod error;
mod loadtest;
mod protocol;
mod registry;
mod telemetry;
mod transport;
mod types;

#[cfg(test)]
mod e2e;

use auth::hmac_auth::HmacAuth;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use transport::control::ControlCtx;
use transport::udp::Transport;

const USAGE: &str = "usage: stun-turn-relay                                   run the server (configured via environment)\n\
       stun-turn-relay mint-credentials <user_id> [ttl_secs]   print time-limited TURN credentials (needs AUTH_SECRET)\n\
       stun-turn-relay loadtest <server_addr> [clients] [seconds] [pps] [payload]";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {}
        Some("mint-credentials") => return mint_credentials(&args[1..]),
        Some("loadtest") => return loadtest::run_cli(&args[1..]).await,
        Some(_) => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("{e}");
            return ExitCode::from(2);
        }
    };
    info!(?cfg, "starting stun-turn-relay");

    if cfg.external_ip.is_none() && cfg.listen_addr.ip().is_unspecified() {
        warn!("EXTERNAL_IP is not set and LISTEN_ADDR is unspecified: XOR-RELAYED-ADDRESS will be unusable for clients");
    }
    let usable = cfg.effective_max_allocations();
    if usable < cfg.max_allocations {
        warn!(
            max_allocations = cfg.max_allocations,
            relay_ports = usable,
            "the relay port range allows only {usable} concurrent allocations (one UDP port each); widen RELAY_MIN_PORT..RELAY_MAX_PORT for more"
        );
    }
    if cfg.allow_private_peers {
        warn!("ALLOW_PRIVATE_PEERS=true: relaying to loopback/private networks is allowed. Development only!");
    }

    let socket = match UdpSocket::bind(cfg.listen_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!(addr = %cfg.listen_addr, error = %e, "failed to bind UDP socket");
            return ExitCode::FAILURE;
        }
    };
    info!(addr = %cfg.listen_addr, "listening (STUN + TURN over UDP)");

    // Optional metrics endpoint (disabled unless METRICS_ADDR is set).
    let metrics_listener = match cfg.metrics_addr {
        Some(addr) => match TcpListener::bind(addr).await {
            Ok(l) => {
                info!(%addr, "metrics endpoint enabled (/metrics, /healthz); keep it on an internal network");
                Some(l)
            }
            Err(e) => {
                error!(%addr, error = %e, "failed to bind metrics listener");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let (telemetry, telemetry_task) = telemetry::Telemetry::spawn(1024);
    let (registry, registry_task) = registry::spawn(&cfg, socket.clone(), telemetry.clone());
    let ctx = Arc::new(ControlCtx::new(&cfg, socket, registry.clone(), telemetry.clone()));
    let transport = Transport::new(ctx);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics_task = metrics_listener
        .map(|l| tokio::spawn(telemetry::http::serve(l, telemetry.metrics(), shutdown_rx.clone())));
    let server = tokio::spawn(transport.run(shutdown_rx));

    shutdown_signal().await;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    // Stop accepting packets first, then close allocations, then flush telemetry.
    let exit = match server.await {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(e)) => {
            error!(error = %e, "transport error");
            ExitCode::FAILURE
        }
        Err(e) => {
            error!(error = %e, "transport task panicked");
            ExitCode::FAILURE
        }
    };

    registry.shutdown_all().await;
    drop(registry);
    drop(telemetry);
    let _ = registry_task.await;
    if let Some(t) = metrics_task {
        let _ = tokio::time::timeout(Duration::from_secs(1), t).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), telemetry_task).await;
    exit
}

/// What the messenger backend does per call; handy for manual testing.
fn mint_credentials(args: &[String]) -> ExitCode {
    let Some(user_id) = args.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let ttl: u64 = match args.get(1) {
        None => 3600,
        Some(s) => match s.parse() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("invalid ttl_secs: {s}");
                return ExitCode::from(2);
            }
        },
    };
    let cfg = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expiry = now + ttl;
    let (username, password) = HmacAuth::new(&cfg.auth_secret, &cfg.realm)
        .with_algos(cfg.auth_algos.clone())
        .issue_credentials(user_id, expiry);
    println!("username={username}");
    println!("password={password}");
    println!("realm={}", cfg.realm);
    println!("expires_unix={expiry}");
    ExitCode::SUCCESS
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
