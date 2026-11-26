//! TURN control-plane request handlers (Allocate, Refresh, CreatePermission,
//! ChannelBind) with long-term-credential authentication, plus the Send
//! indication fast path.

use crate::auth::hmac_auth::{Authenticated, HmacAuth};
use crate::auth::policy::PeerPolicy;
use crate::config::Config;
use crate::protocol::stun::{self, decode_xor_address, encode_xor_address, Attribute, Class, StunMessage};
use crate::protocol::turn::{self, attr, method};
use crate::registry::RegistryHandle;
use crate::telemetry::{Metrics, Telemetry, TelemetryEvent};
use crate::types::{AllocationCmd, TurnError};
use bytes::Bytes;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tracing::debug;

pub struct ControlCtx {
    pub socket: Arc<UdpSocket>,
    pub registry: RegistryHandle,
    pub telemetry: Telemetry,
    pub auth: HmacAuth,
    pub default_lifetime_secs: u32,
    pub peer_policy: PeerPolicy,
}

impl ControlCtx {
    pub fn new(cfg: &Config, socket: Arc<UdpSocket>, registry: RegistryHandle, telemetry: Telemetry) -> Self {
        ControlCtx {
            socket,
            registry,
            telemetry,
            auth: HmacAuth::new(&cfg.auth_secret, &cfg.realm)
                .with_algos(cfg.auth_algos.clone())
                .with_grace_secs(cfg.credential_grace_secs),
            default_lifetime_secs: cfg.allocation_lifetime_secs,
            peer_policy: PeerPolicy {
                allow_private: cfg.allow_private_peers,
                allowed: cfg.allowed_peer_ips.clone(),
                denied: cfg.denied_peer_ips.clone(),
            },
        }
    }

    /// SSRF protection (spec §5.1): built-in deny rules plus the configured allow/deny ranges.
    fn check_peer(&self, client_addr: SocketAddr, ip: IpAddr) -> Result<(), TurnError> {
        if let Some(reason) = self.peer_policy.check(ip) {
            self.telemetry.metrics().policy_blocked.fetch_add(1, Ordering::Relaxed);
            self.telemetry.emit(TelemetryEvent::PolicyBlocked {
                client_addr,
                target_ip: ip,
                reason,
            });
            return Err(TurnError::ForbiddenPeer);
        }
        Ok(())
    }
}

type HandlerResult = Result<Vec<Attribute>, TurnError>;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn handle_request(ctx: Arc<ControlCtx>, msg: StunMessage, raw: Bytes, src: SocketAddr) {
    let now = unix_now();

    // Every TURN request needs valid credentials; failures get a fresh REALM + NONCE challenge.
    // Requests on an existing allocation are checked against its owner and may use credentials
    // that expired up to CREDENTIAL_GRACE_SECS ago (long calls). Allocate is always strict.
    let existing = if msg.method == method::ALLOCATE {
        None
    } else {
        ctx.registry.lookup(src)
    };
    let auth_result = match &existing {
        Some(h) => ctx.auth.authenticate_session(&msg, &raw, now, &h.user_id),
        None => ctx.auth.authenticate(&msg, &raw, now),
    };
    let auth = match auth_result {
        Ok(a) => a,
        Err(e) => {
            debug!(%src, method = msg.method, error = %e, "authentication failed");
            ctx.telemetry.metrics().auth_failures.fetch_add(1, Ordering::Relaxed);
            let bytes = turn::error_response_with(msg.method, msg.transaction_id, e, ctx.auth.challenge(now));
            let _ = ctx.socket.send_to(&bytes, src).await;
            return;
        }
    };

    let result = match msg.method {
        method::ALLOCATE => allocate(&ctx, &msg, &auth, src).await,
        method::REFRESH => refresh(&ctx, &msg, src).await,
        method::CREATE_PERMISSION => create_permission(&ctx, &msg, src).await,
        method::CHANNEL_BIND => channel_bind(&ctx, &msg, src).await,
        _ => Err(TurnError::BadRequest),
    };

    let bytes = match result {
        Ok(attributes) => StunMessage {
            class: Class::SuccessResponse,
            method: msg.method,
            transaction_id: msg.transaction_id,
            attributes,
        }
        .encode_with_integrity(&auth.key, true),
        Err(e) => {
            debug!(%src, method = msg.method, error = %e, "TURN request rejected");
            turn::error_response(msg.method, msg.transaction_id, e)
        }
    };
    let _ = ctx.socket.send_to(&bytes, src).await;
}

async fn allocate(ctx: &ControlCtx, msg: &StunMessage, auth: &Authenticated, src: SocketAddr) -> HandlerResult {
    let transport = msg.attribute(attr::REQUESTED_TRANSPORT).ok_or(TurnError::BadRequest)?;
    if transport.value.first() != Some(&turn::TRANSPORT_UDP) {
        return Err(TurnError::BadRequest);
    }

    let requested = requested_lifetime(ctx, msg)?;
    let info = ctx.registry.allocate(src, auth.user_id.clone(), requested).await?;

    Ok(vec![
        Attribute {
            kind: attr::XOR_RELAYED_ADDRESS,
            value: encode_xor_address(info.relayed_addr, &msg.transaction_id),
        },
        Attribute {
            kind: attr::LIFETIME,
            value: turn::encode_lifetime(info.lifetime_secs),
        },
        Attribute {
            kind: stun::attr::XOR_MAPPED_ADDRESS,
            value: encode_xor_address(src, &msg.transaction_id),
        },
    ])
}

async fn refresh(ctx: &ControlCtx, msg: &StunMessage, src: SocketAddr) -> HandlerResult {
    let handle = ctx.registry.lookup(src).ok_or(TurnError::AllocationMismatch)?;
    let requested = requested_lifetime(ctx, msg)?;

    let (reply, rx) = oneshot::channel();
    handle
        .tx
        .send(AllocationCmd::Refresh {
            lifetime_secs: requested,
            reply,
        })
        .await
        .map_err(|_| TurnError::AllocationMismatch)?;
    let granted = rx.await.map_err(|_| TurnError::AllocationMismatch)?;

    Ok(vec![Attribute {
        kind: attr::LIFETIME,
        value: turn::encode_lifetime(granted),
    }])
}

async fn create_permission(ctx: &ControlCtx, msg: &StunMessage, src: SocketAddr) -> HandlerResult {
    let handle = ctx.registry.lookup(src).ok_or(TurnError::AllocationMismatch)?;

    let peers: Vec<IpAddr> = msg
        .attributes
        .iter()
        .filter(|a| a.kind == attr::XOR_PEER_ADDRESS)
        .map(|a| {
            decode_xor_address(&a.value, &msg.transaction_id)
                .map(|s| s.ip())
                .map_err(|_| TurnError::BadRequest)
        })
        .collect::<Result<_, _>>()?;
    if peers.is_empty() {
        return Err(TurnError::BadRequest);
    }
    // Check every peer before installing any permission.
    for ip in &peers {
        ctx.check_peer(src, *ip)?;
    }

    for peer_ip in peers {
        let (reply, rx) = oneshot::channel();
        handle
            .tx
            .send(AllocationCmd::CreatePermission { peer_ip, reply })
            .await
            .map_err(|_| TurnError::AllocationMismatch)?;
        rx.await.map_err(|_| TurnError::AllocationMismatch)??;
    }
    Ok(vec![])
}

async fn channel_bind(ctx: &ControlCtx, msg: &StunMessage, src: SocketAddr) -> HandlerResult {
    let handle = ctx.registry.lookup(src).ok_or(TurnError::AllocationMismatch)?;

    let channel = msg.attribute(attr::CHANNEL_NUMBER).ok_or(TurnError::BadRequest)?;
    let channel = turn::decode_channel_number(&channel.value).map_err(|_| TurnError::BadRequest)?;

    let peer = msg.attribute(attr::XOR_PEER_ADDRESS).ok_or(TurnError::BadRequest)?;
    let peer_addr = decode_xor_address(&peer.value, &msg.transaction_id).map_err(|_| TurnError::BadRequest)?;
    if peer_addr.port() == 0 {
        return Err(TurnError::BadRequest);
    }
    ctx.check_peer(src, peer_addr.ip())?;

    let (reply, rx) = oneshot::channel();
    handle
        .tx
        .send(AllocationCmd::ChannelBind {
            channel,
            peer_addr,
            reply,
        })
        .await
        .map_err(|_| TurnError::AllocationMismatch)?;
    rx.await.map_err(|_| TurnError::AllocationMismatch)??;
    Ok(vec![])
}

fn requested_lifetime(ctx: &ControlCtx, msg: &StunMessage) -> Result<u32, TurnError> {
    match msg.attribute(attr::LIFETIME) {
        Some(a) => turn::decode_lifetime(&a.value).map_err(|_| TurnError::BadRequest),
        None => Ok(ctx.default_lifetime_secs),
    }
}

/// Send indication (client -> peer): no response, never blocks. Silent drops
/// are the RFC-mandated behavior for invalid indications. Peer filtering is
/// implicit: a permission can only exist for a peer that passed `check_peer`.
pub fn handle_send_indication(registry: &RegistryHandle, metrics: &Metrics, msg: StunMessage, src: SocketAddr) {
    let Some(handle) = registry.lookup(src) else {
        return;
    };
    let (Some(peer), Some(data)) = (msg.attribute(attr::XOR_PEER_ADDRESS), msg.attribute(attr::DATA)) else {
        return;
    };
    let Ok(peer_addr) = decode_xor_address(&peer.value, &msg.transaction_id) else {
        return;
    };

    let cmd = AllocationCmd::SendToPeer {
        peer_addr,
        payload: data.value.clone(), // refcount bump, no copy
    };
    if handle.tx.try_send(cmd).is_err() {
        metrics.dropped_packets.fetch_add(1, Ordering::Relaxed);
    }
}

/// ChannelData (client -> peer): the hottest path. One lookup, one `try_send`, no copy.
pub fn handle_channel_data(registry: &RegistryHandle, metrics: &Metrics, channel: u16, payload: Bytes, src: SocketAddr) {
    let Some(handle) = registry.lookup(src) else {
        return;
    };
    if handle
        .tx
        .try_send(AllocationCmd::SendOnChannel { channel, payload })
        .is_err()
    {
        metrics.dropped_packets.fetch_add(1, Ordering::Relaxed);
    }
}
