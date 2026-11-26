//! `AllocationActor`: one tokio task per TURN allocation. Owns the relayed
//! socket and all per-allocation state (permissions, channel bindings,
//! lifetime, counters), so no mutexes are needed.

use crate::config::MAX_LIFETIME_SECS;
use crate::protocol::stun::{encode_xor_address, Attribute, Class, StunMessage};
use crate::protocol::turn::{attr, encode_channel_data, method};
use crate::telemetry::Metrics;
use crate::transport::udp::MAX_DATAGRAM;
use crate::types::{AllocationCmd, AllocationId, RegistryEvent, TurnError};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use tracing::debug;

/// Permission lifetime (RFC 5766 §8).
pub const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
/// Channel binding lifetime (RFC 5766 §11).
pub const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);
const MAX_PERMISSIONS: usize = 256;
const MAX_CHANNELS: usize = 128;

pub struct AllocationParams {
    pub id: AllocationId,
    pub client_addr: SocketAddr,
    pub username: String,
    pub relayed: UdpSocket,
    /// The main listening socket: traffic back to the client goes out through it.
    pub main_socket: Arc<UdpSocket>,
    pub lifetime_secs: u32,
    pub cmd_rx: mpsc::Receiver<AllocationCmd>,
    pub events: mpsc::Sender<RegistryEvent>,
    pub metrics: Arc<Metrics>,
}

struct Actor {
    id: AllocationId,
    client_addr: SocketAddr,
    username: String,
    relayed: UdpSocket,
    main_socket: Arc<UdpSocket>,
    cmd_rx: mpsc::Receiver<AllocationCmd>,
    metrics: Arc<Metrics>,
    expires_at: Instant,
    permissions: HashMap<IpAddr, Instant>,
    /// channel -> (peer, binding expiry)
    channels: HashMap<u16, (SocketAddr, Instant)>,
    /// reverse index: peer -> channel
    peer_channels: HashMap<SocketAddr, u16>,
    bytes_relayed: u64,
    seq: u32,
}

/// Runs the allocation until its lifetime expires, it is shut down, or it is
/// refreshed with lifetime 0. Always reports `AllocationClosed` at the end.
pub async fn run(p: AllocationParams) {
    let AllocationParams {
        id,
        client_addr,
        username,
        relayed,
        main_socket,
        lifetime_secs,
        cmd_rx,
        events,
        metrics,
    } = p;

    let mut actor = Actor {
        id,
        client_addr,
        username,
        relayed,
        main_socket,
        cmd_rx,
        metrics,
        expires_at: Instant::now() + Duration::from_secs(lifetime_secs as u64),
        permissions: HashMap::new(),
        channels: HashMap::new(),
        peer_channels: HashMap::new(),
        bytes_relayed: 0,
        seq: 0,
    };

    actor.event_loop().await;

    let closed = RegistryEvent::AllocationClosed {
        allocation_id: id,
        client_addr,
        username: actor.username.clone(),
        bytes_relayed: actor.bytes_relayed,
    };
    // The registry may already be gone during shutdown.
    let _ = events.send(closed).await;
    // `actor` (and the relayed socket) is dropped here.
}

impl Actor {
    async fn event_loop(&mut self) {
        // +1 byte to detect oversized datagrams instead of silently truncating.
        let mut buf = vec![0u8; MAX_DATAGRAM + 1];

        loop {
            tokio::select! {
                _ = sleep_until(self.expires_at) => {
                    debug!(id = self.id.0, "allocation lifetime expired");
                    break;
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        None | Some(AllocationCmd::Shutdown) => break,
                        Some(c) => {
                            if !self.on_cmd(c).await {
                                break;
                            }
                        }
                    }
                }
                res = self.relayed.recv_from(&mut buf) => {
                    match res {
                        Ok((n, from)) if n <= MAX_DATAGRAM => {
                            self.on_peer_packet(&buf[..n], from).await;
                        }
                        Ok(_) => self.drop_packet(),
                        Err(e) => debug!(id = self.id.0, error = %e, "relayed recv_from failed"),
                    }
                }
            }
        }
    }

    /// Returns `false` when the actor should stop.
    async fn on_cmd(&mut self, cmd: AllocationCmd) -> bool {
        match cmd {
            AllocationCmd::Refresh { lifetime_secs, reply } => {
                if lifetime_secs == 0 {
                    // RFC 5766 §7.2: lifetime 0 deletes the allocation.
                    let _ = reply.send(0);
                    return false;
                }
                let granted = lifetime_secs.min(MAX_LIFETIME_SECS);
                self.expires_at = Instant::now() + Duration::from_secs(granted as u64);
                let _ = reply.send(granted);
                true
            }
            AllocationCmd::CreatePermission { peer_ip, reply } => {
                let _ = reply.send(self.add_permission(peer_ip));
                true
            }
            AllocationCmd::ChannelBind {
                channel,
                peer_addr,
                reply,
            } => {
                let _ = reply.send(self.bind_channel(channel, peer_addr));
                true
            }
            AllocationCmd::SendToPeer { peer_addr, payload } => {
                self.send_to_peer(peer_addr, payload).await;
                true
            }
            AllocationCmd::SendOnChannel { channel, payload } => {
                match self.peer_for_channel(channel) {
                    Some(peer) => self.send_to_peer(peer, payload).await,
                    None => self.drop_packet(),
                }
                true
            }
            AllocationCmd::Shutdown => false,
        }
    }

    fn add_permission(&mut self, ip: IpAddr) -> Result<(), TurnError> {
        let now = Instant::now();
        self.permissions.retain(|_, exp| *exp > now);
        if self.permissions.len() >= MAX_PERMISSIONS && !self.permissions.contains_key(&ip) {
            return Err(TurnError::QuotaExceeded);
        }
        self.permissions.insert(ip, now + PERMISSION_LIFETIME);
        Ok(())
    }

    /// RFC 5766 §11.2: a channel maps to exactly one peer address and vice versa;
    /// re-binding the same pair refreshes it. A successful bind also installs /
    /// refreshes the permission for the peer IP.
    fn bind_channel(&mut self, channel: u16, peer: SocketAddr) -> Result<(), TurnError> {
        let now = Instant::now();

        // Drop expired bindings first so their channel numbers / peers become free.
        self.channels.retain(|_, (_, exp)| *exp > now);
        let channels = &self.channels;
        self.peer_channels.retain(|_, ch| channels.contains_key(&*ch));

        if let Some((bound_peer, _)) = self.channels.get(&channel) {
            if *bound_peer != peer {
                return Err(TurnError::BadRequest);
            }
        }
        if let Some(bound_channel) = self.peer_channels.get(&peer) {
            if *bound_channel != channel {
                return Err(TurnError::BadRequest);
            }
        }
        if !self.channels.contains_key(&channel) && self.channels.len() >= MAX_CHANNELS {
            return Err(TurnError::QuotaExceeded);
        }

        self.add_permission(peer.ip())?;
        self.channels.insert(channel, (peer, now + CHANNEL_LIFETIME));
        self.peer_channels.insert(peer, channel);
        Ok(())
    }

    fn peer_for_channel(&self, channel: u16) -> Option<SocketAddr> {
        let now = Instant::now();
        self.channels
            .get(&channel)
            .filter(|(_, exp)| *exp > now)
            .map(|(peer, _)| *peer)
    }

    fn channel_for_peer(&self, peer: SocketAddr) -> Option<u16> {
        let channel = *self.peer_channels.get(&peer)?;
        self.peer_for_channel(channel).map(|_| channel)
    }

    fn permitted(&self, ip: IpAddr) -> bool {
        self.permissions.get(&ip).is_some_and(|exp| *exp > Instant::now())
    }

    fn drop_packet(&self) {
        self.metrics.dropped_packets.fetch_add(1, Ordering::Relaxed);
    }

    fn account(&mut self, n: usize) {
        self.bytes_relayed += n as u64;
        self.metrics.total_relayed_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// client -> peer (Send indication or ChannelData). `payload` is a zero-copy
    /// slice of the original datagram.
    async fn send_to_peer(&mut self, peer_addr: SocketAddr, payload: Bytes) {
        if !self.permitted(peer_addr.ip()) {
            self.drop_packet();
            return;
        }
        match self.relayed.send_to(&payload, peer_addr).await {
            Ok(n) => self.account(n),
            Err(e) => {
                debug!(id = self.id.0, %peer_addr, error = %e, "send to peer failed");
                self.drop_packet();
            }
        }
    }

    /// peer -> client: ChannelData if the peer has a live channel binding,
    /// otherwise a Data indication.
    async fn on_peer_packet(&mut self, data: &[u8], from: SocketAddr) {
        if !self.permitted(from.ip()) {
            self.drop_packet();
            return;
        }

        let out = match self.channel_for_peer(from) {
            Some(channel) => encode_channel_data(channel, data),
            None => {
                // Indications need no unique transaction id for matching; allocation
                // id + sequence number keeps them distinct without an RNG dependency.
                let seq = self.seq;
                self.seq = seq.wrapping_add(1);
                let mut txn = [0u8; 12];
                txn[..8].copy_from_slice(&self.id.0.to_be_bytes());
                txn[8..].copy_from_slice(&seq.to_be_bytes());

                StunMessage {
                    class: Class::Indication,
                    method: method::DATA,
                    transaction_id: txn,
                    attributes: vec![
                        Attribute {
                            kind: attr::XOR_PEER_ADDRESS,
                            value: encode_xor_address(from, &txn),
                        },
                        Attribute {
                            kind: attr::DATA,
                            value: Bytes::copy_from_slice(data),
                        },
                    ],
                }
                .encode(false)
            }
        };

        match self.main_socket.send_to(&out, self.client_addr).await {
            Ok(_) => self.account(data.len()),
            Err(e) => {
                debug!(id = self.id.0, error = %e, "send to client failed");
                self.drop_packet();
            }
        }
    }
}
