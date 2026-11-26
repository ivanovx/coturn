//! TURN (RFC 5766/8656) constants, attribute helpers and ChannelData framing.
#![allow(dead_code)]

use crate::error::{CodecError, TurnError};
use crate::protocol::stun::{Attribute, Class, StunMessage, TXN_ID_LEN};
use bytes::{BufMut, Bytes, BytesMut};

pub mod method {
    pub const ALLOCATE: u16 = 0x003;
    pub const REFRESH: u16 = 0x004;
    pub const SEND: u16 = 0x006;
    pub const DATA: u16 = 0x007;
    pub const CREATE_PERMISSION: u16 = 0x008;
    pub const CHANNEL_BIND: u16 = 0x009;
}

pub mod attr {
    pub const USERNAME: u16 = 0x0006;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
}

/// IANA protocol number for UDP (REQUESTED-TRANSPORT).
pub const TRANSPORT_UDP: u8 = 17;

/// Valid ChannelData channel numbers (RFC 5766 §11).
pub const CHANNEL_MIN: u16 = 0x4000;
pub const CHANNEL_MAX: u16 = 0x7FFF;
const CHANNEL_HEADER_LEN: usize = 4;

pub fn encode_lifetime(secs: u32) -> Bytes {
    Bytes::copy_from_slice(&secs.to_be_bytes())
}

pub fn decode_lifetime(value: &[u8]) -> Result<u32, CodecError> {
    let b: [u8; 4] = value.try_into().map_err(|_| CodecError::BadAttribute)?;
    Ok(u32::from_be_bytes(b))
}

/// CHANNEL-NUMBER: 16-bit channel + 16 reserved bits.
pub fn decode_channel_number(value: &[u8]) -> Result<u16, CodecError> {
    if value.len() != 4 {
        return Err(CodecError::BadAttribute);
    }
    let ch = u16::from_be_bytes([value[0], value[1]]);
    if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&ch) {
        return Err(CodecError::BadAttribute);
    }
    Ok(ch)
}

pub fn encode_channel_number(channel: u16) -> Bytes {
    let c = channel.to_be_bytes();
    Bytes::copy_from_slice(&[c[0], c[1], 0, 0])
}

/// ChannelData frames start with `01` in the two top bits (first byte 0x40..=0x7F).
pub fn is_channel_data(buf: &[u8]) -> bool {
    buf.len() >= CHANNEL_HEADER_LEN && (0x40..=0x7F).contains(&buf[0])
}

/// Zero-copy parse: the payload is a slice of `data`. Over UDP, trailing padding
/// after the declared length is allowed and ignored.
pub fn parse_channel_data(data: &Bytes) -> Result<(u16, Bytes), CodecError> {
    if data.len() < CHANNEL_HEADER_LEN {
        return Err(CodecError::TooShort);
    }
    let channel = u16::from_be_bytes([data[0], data[1]]);
    if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel) {
        return Err(CodecError::BadHeader);
    }
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < CHANNEL_HEADER_LEN + len {
        return Err(CodecError::BadLength);
    }
    Ok((channel, data.slice(CHANNEL_HEADER_LEN..CHANNEL_HEADER_LEN + len)))
}

pub fn encode_channel_data(channel: u16, payload: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(CHANNEL_HEADER_LEN + payload.len());
    b.put_u16(channel);
    b.put_u16(payload.len() as u16);
    b.put_slice(payload);
    b.freeze()
}

/// Maps a domain error to a STUN/TURN error code + reason phrase.
pub fn error_code(err: TurnError) -> (u16, &'static str) {
    match err {
        TurnError::BadRequest => (400, "Bad Request"),
        TurnError::Unauthorized => (401, "Unauthorized"),
        TurnError::ForbiddenPeer => (403, "Forbidden"),
        TurnError::AllocationMismatch => (437, "Allocation Mismatch"),
        TurnError::StaleNonce => (438, "Stale Nonce"),
        TurnError::QuotaExceeded => (486, "Allocation Quota Reached"),
        TurnError::InternalError => (500, "Server Error"),
        TurnError::InsufficientCapacity => (508, "Insufficient Capacity"),
    }
}

pub fn encode_error_code(code: u16, reason: &str) -> Bytes {
    let mut b = BytesMut::with_capacity(4 + reason.len());
    b.put_u16(0);
    b.put_u8((code / 100) as u8);
    b.put_u8((code % 100) as u8);
    b.put_slice(reason.as_bytes());
    b.freeze()
}

pub fn decode_error_code(value: &[u8]) -> Option<u16> {
    if value.len() < 4 {
        return None;
    }
    Some((value[2] & 0x07) as u16 * 100 + value[3] as u16)
}

pub fn error_response(method: u16, txn: [u8; TXN_ID_LEN], err: TurnError) -> Bytes {
    error_response_with(method, txn, err, Vec::new())
}

/// Error response with extra attributes (e.g. REALM + NONCE for 401 / 438).
pub fn error_response_with(method: u16, txn: [u8; TXN_ID_LEN], err: TurnError, extra: Vec<Attribute>) -> Bytes {
    let (code, reason) = error_code(err);
    let mut attributes = vec![Attribute {
        kind: attr::ERROR_CODE,
        value: encode_error_code(code, reason),
    }];
    attributes.extend(extra);
    StunMessage {
        class: Class::ErrorResponse,
        method,
        transaction_id: txn,
        attributes,
    }
    .encode(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_roundtrip() {
        assert_eq!(decode_lifetime(&encode_lifetime(300)).unwrap(), 300);
        assert!(decode_lifetime(&[0, 1]).is_err());
    }

    #[test]
    fn error_code_encoding() {
        let v = encode_error_code(437, "Allocation Mismatch");
        assert_eq!(&v[..4], &[0, 0, 4, 37]);
        assert_eq!(decode_error_code(&v), Some(437));
    }

    #[test]
    fn error_response_is_parseable() {
        let bytes = error_response(method::ALLOCATE, [7; 12], TurnError::QuotaExceeded);
        let msg = StunMessage::parse(&bytes).unwrap();
        assert_eq!(msg.class, Class::ErrorResponse);
        assert_eq!(msg.method, method::ALLOCATE);
        let code = msg.attribute(attr::ERROR_CODE).unwrap();
        assert_eq!(decode_error_code(&code.value), Some(486));
    }

    #[test]
    fn channel_number_validation() {
        assert_eq!(decode_channel_number(&encode_channel_number(0x4000)).unwrap(), 0x4000);
        assert_eq!(decode_channel_number(&encode_channel_number(0x7FFF)).unwrap(), 0x7FFF);
        assert!(decode_channel_number(&encode_channel_number(0x3FFF)).is_err());
        assert!(decode_channel_number(&encode_channel_number(0x8000)).is_err());
        assert!(decode_channel_number(&[0x40, 0x00]).is_err());
    }

    #[test]
    fn channel_data_roundtrip_and_padding() {
        let framed = encode_channel_data(0x4001, b"media");
        assert!(is_channel_data(&framed));
        let (ch, payload) = parse_channel_data(&framed).unwrap();
        assert_eq!(ch, 0x4001);
        assert_eq!(&payload[..], b"media");

        // Trailing padding is ignored.
        let mut padded = framed.to_vec();
        padded.extend_from_slice(&[0, 0, 0]);
        let (_, payload) = parse_channel_data(&Bytes::from(padded)).unwrap();
        assert_eq!(&payload[..], b"media");
    }

    #[test]
    fn channel_data_rejects_malformed() {
        assert!(!is_channel_data(&[0x00, 0x01, 0x00, 0x00])); // STUN
        assert!(parse_channel_data(&Bytes::from_static(&[0x40, 0x00])).is_err());
        // Declared length larger than the datagram.
        assert_eq!(
            parse_channel_data(&Bytes::from_static(&[0x40, 0x00, 0x00, 0x10, 1, 2])),
            Err(CodecError::BadLength)
        );
        // Channel below the valid range.
        assert!(parse_channel_data(&Bytes::from_static(&[0x7F, 0xFF, 0x00, 0x00])).is_ok());
        assert!(!is_channel_data(&[0x80, 0x00, 0x00, 0x00]));
    }
}
