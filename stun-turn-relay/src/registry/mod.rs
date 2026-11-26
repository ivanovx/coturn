//! `RegistryActor`: allocation admission (global / per-user quotas), relay
//! port pool, lifecycle bookkeeping. Control plane only; the data plane looks
//! allocations up through the shared `DashMap` (spec §2.2) and never goes
//! through this actor.

use crate::allocation::{self, AllocationParams};
use crate::config::{Config, MAX_LIFETIME_SECS};
use crate::telemetry::{Telemetry, TelemetryEvent};
use crate::types::*;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{timeout, timeout_at, Instant};
use tracing::{debug, warn};

const CMD_CAP: usize = 256;
const EVENT_CAP: usize = 1024;

struct RegistryConfig {
    bind_ip: IpAddr,
    advertised_ip: IpAddr,
    min_port: u16,
    max_port: u16,
    max_allocations: usize,
    max_per_user: usize,
    default_lifetime_secs: u32,
    channel_cap: usize,
}

/// Cheap, cloneable front-end to the registry.
#[derive(Clone)]
pub struct RegistryHandle {
    tx: mpsc::Sender<RegistryCmd>,
    routes: Arc<DashMap<SocketAddr, AllocationHandle>>,
}

impl RegistryHandle {
    /// Hot-path lookup by client address (5-tuple).
    pub fn lookup(&self, client_addr: SocketAddr) -> Option<AllocationHandle> {
        self.routes.get(&client_addr).map(|r| r.value().clone())
    }

    pub async fn allocate(
        &self,
        client_addr: SocketAddr,
        username: String,
        requested_lifetime_secs: u32,
    ) -> Result<AllocationInfo, TurnError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(RegistryCmd::Allocate {
                client_addr,
                username,
                requested_lifetime_secs,
                reply,
            })
            .await
            .map_err(|_| TurnError::InternalError)?;
        rx.await.map_err(|_| TurnError::InternalError)?
    }

    /// Stops every allocation and the registry itself; resolves once they are closed.
    pub async fn shutdown_all(&self) {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(RegistryCmd::ShutdownAll { reply }).await.is_ok() {
            let _ = rx.await;
        }
    }
}

pub fn spawn(cfg: &Config, main_socket: Arc<UdpSocket>, telemetry: Telemetry) -> (RegistryHandle, JoinHandle<()>) {
    let bind_ip = cfg.listen_addr.ip();
    let rcfg = RegistryConfig {
        bind_ip,
        advertised_ip: cfg.external_ip.unwrap_or(bind_ip),
        min_port: cfg.relay_min_port,
        max_port: cfg.relay_max_port,
        max_allocations: cfg.max_allocations,
        max_per_user: cfg.max_allocations_per_user,
        default_lifetime_secs: cfg.allocation_lifetime_secs,
        channel_cap: cfg.channel_cap,
    };

    let routes = Arc::new(DashMap::new());
    let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CAP);
    let (event_tx, event_rx) = mpsc::channel(EVENT_CAP);

    let actor = RegistryActor {
        next_port: rcfg.min_port,
        cfg: rcfg,
        cmd_rx,
        event_rx,
        event_tx,
        routes: routes.clone(),
        main_socket,
        telemetry,
        allocs: HashMap::new(),
        per_user: HashMap::new(),
        in_use_ports: HashSet::new(),
        next_id: 1,
    };
    let task = tokio::spawn(actor.run());
    (RegistryHandle { tx: cmd_tx, routes }, task)
}

struct AllocRecord {
    client_addr: SocketAddr,
    username: String,
    port: u16,
    handle: AllocationHandle,
}

struct RegistryActor {
    cfg: RegistryConfig,
    cmd_rx: mpsc::Receiver<RegistryCmd>,
    event_rx: mpsc::Receiver<RegistryEvent>,
    event_tx: mpsc::Sender<RegistryEvent>,
    routes: Arc<DashMap<SocketAddr, AllocationHandle>>,
    main_socket: Arc<UdpSocket>,
    telemetry: Telemetry,
    allocs: HashMap<AllocationId, AllocRecord>,
    per_user: HashMap<String, usize>,
    in_use_ports: HashSet<u16>,
    next_port: u16,
    next_id: u64,
}

impl RegistryActor {
    async fn run(mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd_rx.recv() => match cmd {
                    None => {
                        self.shutdown_all().await;
                        break;
                    }
                    Some(RegistryCmd::Allocate { client_addr, username, requested_lifetime_secs, reply }) => {
                        let res = self.allocate(client_addr, username, requested_lifetime_secs).await;
                        let _ = reply.send(res);
                    }
                    Some(RegistryCmd::ShutdownAll { reply }) => {
                        self.shutdown_all().await;
                        let _ = reply.send(());
                        break;
                    }
                },
                Some(ev) = self.event_rx.recv() => self.on_event(ev),
            }
        }
    }

    async fn allocate(
        &mut self,
        client_addr: SocketAddr,
        username: String,
        requested: u32,
    ) -> Result<AllocationInfo, TurnError> {
        // One allocation per 5-tuple (RFC 5766 §6.2 -> 437).
        if self.routes.contains_key(&client_addr) {
            return Err(TurnError::AllocationMismatch);
        }
        if self.allocs.len() >= self.cfg.max_allocations {
            return Err(TurnError::InsufficientCapacity);
        }
        if self.per_user.get(&username).copied().unwrap_or(0) >= self.cfg.max_per_user {
            return Err(TurnError::QuotaExceeded);
        }

        let (relayed, port) = self.bind_relay_socket().await.ok_or(TurnError::InsufficientCapacity)?;

        let lifetime_secs = if requested == 0 {
            self.cfg.default_lifetime_secs
        } else {
            requested.min(MAX_LIFETIME_SECS)
        };
        let relayed_addr = SocketAddr::new(self.cfg.advertised_ip, port);

        let id = AllocationId(self.next_id);
        self.next_id += 1;
        let (tx, cmd_rx) = mpsc::channel(self.cfg.channel_cap);
        let handle = AllocationHandle {
            id,
            tx,
            user_id: Arc::from(username.as_str()),
        };

        tokio::spawn(allocation::run(AllocationParams {
            id,
            client_addr,
            username: username.clone(),
            relayed,
            main_socket: self.main_socket.clone(),
            lifetime_secs,
            cmd_rx,
            events: self.event_tx.clone(),
            metrics: self.telemetry.metrics(),
        }));

        self.routes.insert(client_addr, handle.clone());
        *self.per_user.entry(username.clone()).or_insert(0) += 1;
        self.allocs.insert(
            id,
            AllocRecord {
                client_addr,
                username: username.clone(),
                port,
                handle,
            },
        );
        self.telemetry.metrics().active_allocations.fetch_add(1, Ordering::Relaxed);
        self.telemetry.metrics().allocations_total.fetch_add(1, Ordering::Relaxed);
        self.telemetry.emit(TelemetryEvent::AllocationOpened {
            allocation_id: id,
            client_addr,
            relayed_addr,
            username,
        });

        Ok(AllocationInfo {
            id,
            relayed_addr,
            lifetime_secs,
        })
    }

    /// Walks the port range round-robin; ports busy for outside reasons are skipped.
    async fn bind_relay_socket(&mut self) -> Option<(UdpSocket, u16)> {
        let range = (self.cfg.max_port - self.cfg.min_port) as u32 + 1;
        for _ in 0..range {
            let port = self.next_port;
            self.next_port = if port >= self.cfg.max_port {
                self.cfg.min_port
            } else {
                port + 1
            };
            if self.in_use_ports.contains(&port) {
                continue;
            }
            if let Ok(sock) = UdpSocket::bind(SocketAddr::new(self.cfg.bind_ip, port)).await {
                self.in_use_ports.insert(port);
                return Some((sock, port));
            }
        }
        warn!("relay port range exhausted");
        None
    }

    fn on_event(&mut self, ev: RegistryEvent) {
        match ev {
            RegistryEvent::AllocationClosed {
                allocation_id,
                client_addr,
                username,
                bytes_relayed,
            } => {
                // Only remove the route if it still points at *this* allocation.
                self.routes.remove_if(&client_addr, |_, h| h.id == allocation_id);
                if let Some(rec) = self.allocs.remove(&allocation_id) {
                    self.in_use_ports.remove(&rec.port);
                    if let Some(n) = self.per_user.get_mut(&rec.username) {
                        *n -= 1;
                        if *n == 0 {
                            self.per_user.remove(&rec.username);
                        }
                    }
                    self.telemetry.metrics().active_allocations.fetch_sub(1, Ordering::Relaxed);
                }
                self.telemetry.emit(TelemetryEvent::AllocationClosed {
                    allocation_id,
                    username,
                    bytes_relayed,
                });
            }
        }
    }

    /// Fans out `Shutdown` and waits (bounded) for every allocation to report back.
    async fn shutdown_all(&mut self) {
        debug!(count = self.allocs.len(), "shutting down allocations");
        for rec in self.allocs.values() {
            let _ = timeout(Duration::from_secs(1), rec.handle.tx.send(AllocationCmd::Shutdown)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while !self.allocs.is_empty() {
            match timeout_at(deadline, self.event_rx.recv()).await {
                Ok(Some(ev)) => self.on_event(ev),
                _ => break,
            }
        }
    }
}
