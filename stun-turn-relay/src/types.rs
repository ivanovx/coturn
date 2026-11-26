//! Shared message and domain types (spec §4).

use bytes::Bytes;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

pub use crate::error::TurnError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationId(pub u64);

#[derive(Debug, Clone)]
pub struct AllocationHandle {
    pub id: AllocationId,
    pub tx: mpsc::Sender<AllocationCmd>,
    /// Owner of the allocation (the `user_id` part of the credentials).
    pub user_id: Arc<str>,
}

#[derive(Debug, Clone)]
pub struct AllocationInfo {
    pub id: AllocationId,
    pub relayed_addr: SocketAddr,
    pub lifetime_secs: u32,
}

/// Commands handled sequentially by one `AllocationActor`.
#[derive(Debug)]
pub enum AllocationCmd {
    Refresh {
        lifetime_secs: u32,
        reply: oneshot::Sender<u32>,
    },
    CreatePermission {
        peer_ip: IpAddr,
        reply: oneshot::Sender<Result<(), TurnError>>,
    },
    ChannelBind {
        channel: u16,
        peer_addr: SocketAddr,
        reply: oneshot::Sender<Result<(), TurnError>>,
    },
    SendToPeer {
        peer_addr: SocketAddr,
        payload: Bytes,
    },
    SendOnChannel {
        channel: u16,
        payload: Bytes,
    },
    Shutdown,
}

#[derive(Debug)]
pub enum RegistryCmd {
    Allocate {
        client_addr: SocketAddr,
        username: String,
        requested_lifetime_secs: u32,
        reply: oneshot::Sender<Result<AllocationInfo, TurnError>>,
    },
    ShutdownAll {
        reply: oneshot::Sender<()>,
    },
}

#[derive(Debug)]
pub enum RegistryEvent {
    AllocationClosed {
        allocation_id: AllocationId,
        client_addr: SocketAddr,
        username: String,
        bytes_relayed: u64,
    },
}
