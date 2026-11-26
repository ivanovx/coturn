//! UDP entry socket: demultiplexes STUN Binding, TURN requests, Send
//! indications and ChannelData (RFC 5766 §11.5: first two bits `00` = STUN,
//! `01` = ChannelData).

use crate::protocol::stun::{self, Class, StunMessage};
use crate::protocol::turn::{self, method as tm};
use crate::registry::RegistryHandle;
use crate::telemetry::Metrics;
use crate::transport::control::{self, ControlCtx};
use crate::types::TurnError;
use bytes::Bytes;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Semaphore};
use tracing::{debug, warn};

/// Max accepted UDP datagram size (spec §5.3).
pub const MAX_DATAGRAM: usize = 2048;
/// Max concurrently running TURN control requests (flood protection).
const MAX_INFLIGHT_CONTROL: usize = 1024;

#[derive(Debug)]
pub enum Outcome {
    /// Send this datagram back to the source.
    Reply(Bytes),
    /// A TURN request / indication (with its raw bytes, needed for MESSAGE-INTEGRITY).
    Turn(StunMessage, Bytes),
    /// ChannelData frame: payload is a zero-copy slice of the datagram.
    ChannelData { channel: u16, payload: Bytes },
    Drop,
}

/// Pure classification of one datagram (easy to unit-test).
pub fn handle_datagram(data: Bytes, src: SocketAddr) -> Outcome {
    if turn::is_channel_data(&data) {
        return match turn::parse_channel_data(&data) {
            Ok((channel, payload)) => Outcome::ChannelData { channel, payload },
            Err(e) => {
                debug!(%src, error = %e, "dropping malformed ChannelData");
                Outcome::Drop
            }
        };
    }

    if !stun::looks_like_stun(&data) {
        debug!(%src, len = data.len(), "ignoring non-STUN datagram");
        return Outcome::Drop;
    }

    let msg = match StunMessage::parse(&data) {
        Ok(m) => m,
        Err(e) => {
            debug!(%src, error = %e, "dropping malformed STUN message");
            return Outcome::Drop;
        }
    };

    match (msg.class, msg.method) {
        (Class::Request, stun::method::BINDING) => {
            Outcome::Reply(StunMessage::binding_success(msg.transaction_id, src).encode(true))
        }
        (Class::Request, tm::ALLOCATE | tm::REFRESH | tm::CREATE_PERMISSION | tm::CHANNEL_BIND)
        | (Class::Indication, tm::SEND) => Outcome::Turn(msg, data),
        (Class::Request, _) => {
            Outcome::Reply(turn::error_response(msg.method, msg.transaction_id, TurnError::BadRequest))
        }
        _ => {
            debug!(%src, class = ?msg.class, method = msg.method, "ignoring STUN message");
            Outcome::Drop
        }
    }
}

pub struct Transport {
    ctx: Arc<ControlCtx>,
    socket: Arc<UdpSocket>,
    registry: RegistryHandle,
    metrics: Arc<Metrics>,
    control_slots: Arc<Semaphore>,
}

impl Transport {
    pub fn new(ctx: Arc<ControlCtx>) -> Self {
        Transport {
            socket: ctx.socket.clone(),
            registry: ctx.registry.clone(),
            metrics: ctx.telemetry.metrics(),
            control_slots: Arc::new(Semaphore::new(MAX_INFLIGHT_CONTROL)),
            ctx,
        }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        // +1 byte so oversized datagrams can be detected instead of silently truncated.
        let mut buf = vec![0u8; MAX_DATAGRAM + 1];

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                res = self.socket.recv_from(&mut buf) => {
                    let (n, src) = match res {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(error = %e, "recv_from failed");
                            continue;
                        }
                    };
                    if n > MAX_DATAGRAM {
                        debug!(%src, "dropping oversized datagram");
                        continue;
                    }
                    let data = Bytes::copy_from_slice(&buf[..n]);

                    match handle_datagram(data, src) {
                        Outcome::Reply(resp) => {
                            if let Err(e) = self.socket.send_to(&resp, src).await {
                                warn!(%src, error = %e, "send_to failed");
                            }
                        }
                        Outcome::ChannelData { channel, payload } => {
                            control::handle_channel_data(&self.registry, &self.metrics, channel, payload, src);
                        }
                        Outcome::Turn(msg, raw) if msg.class == Class::Request => {
                            match self.control_slots.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let ctx = self.ctx.clone();
                                    tokio::spawn(async move {
                                        control::handle_request(ctx, msg, raw, src).await;
                                        drop(permit);
                                    });
                                }
                                Err(_) => {
                                    self.metrics.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Outcome::Turn(msg, _) => {
                            control::handle_send_indication(&self.registry, &self.metrics, msg, src);
                        }
                        Outcome::Drop => {}
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::stun::{attr, decode_xor_address, method};
    use crate::protocol::turn::decode_error_code;

    const TXN: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    fn msg(class: Class, method: u16) -> Bytes {
        StunMessage {
            class,
            method,
            transaction_id: TXN,
            attributes: vec![],
        }
        .encode(false)
    }

    fn src() -> SocketAddr {
        "203.0.113.5:54321".parse().unwrap()
    }

    #[test]
    fn binding_request_gets_reflexive_address() {
        let Outcome::Reply(resp) = handle_datagram(msg(Class::Request, method::BINDING), src()) else {
            panic!("expected reply");
        };
        let parsed = StunMessage::parse(&resp).unwrap();
        assert_eq!(parsed.class, Class::SuccessResponse);
        assert_eq!(parsed.transaction_id, TXN);
        let a = parsed.attribute(attr::XOR_MAPPED_ADDRESS).unwrap();
        assert_eq!(decode_xor_address(&a.value, &TXN).unwrap(), src());
        assert!(parsed.attribute(attr::FINGERPRINT).is_some());
    }

    #[test]
    fn garbage_and_binding_indication_are_dropped() {
        assert!(matches!(handle_datagram(Bytes::from_static(b"hello"), src()), Outcome::Drop));
        assert!(matches!(
            handle_datagram(msg(Class::Indication, method::BINDING), src()),
            Outcome::Drop
        ));
    }

    #[test]
    fn turn_messages_are_routed() {
        for m in [tm::ALLOCATE, tm::REFRESH, tm::CREATE_PERMISSION, tm::CHANNEL_BIND] {
            assert!(matches!(
                handle_datagram(msg(Class::Request, m), src()),
                Outcome::Turn(..)
            ));
        }
        assert!(matches!(
            handle_datagram(msg(Class::Indication, tm::SEND), src()),
            Outcome::Turn(..)
        ));
    }

    #[test]
    fn channel_data_is_demultiplexed() {
        let frame = turn::encode_channel_data(0x4005, b"rtp");
        match handle_datagram(frame, src()) {
            Outcome::ChannelData { channel, payload } => {
                assert_eq!(channel, 0x4005);
                assert_eq!(&payload[..], b"rtp");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Truncated frame is dropped.
        assert!(matches!(
            handle_datagram(Bytes::from_static(&[0x40, 0x00, 0x00, 0x20, 1]), src()),
            Outcome::Drop
        ));
    }

    #[test]
    fn unsupported_request_gets_400() {
        // 0x00A (Connect, RFC 6062) is not supported.
        let Outcome::Reply(resp) = handle_datagram(msg(Class::Request, 0x00A), src()) else {
            panic!("expected reply");
        };
        let parsed = StunMessage::parse(&resp).unwrap();
        assert_eq!(parsed.class, Class::ErrorResponse);
        let code = parsed.attribute(turn::attr::ERROR_CODE).unwrap();
        assert_eq!(decode_error_code(&code.value), Some(400));
    }
}
