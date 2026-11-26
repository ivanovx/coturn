//! STUN (RFC 5389/8489) codec: header, attributes, XOR-MAPPED-ADDRESS, FINGERPRINT.
//! No parser here panics on malformed input.

use crate::error::CodecError;
use bytes::{BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_LEN: usize = 20;
pub const TXN_ID_LEN: usize = 12;
const FINGERPRINT_XOR: u32 = 0x5354_554E;

pub mod method {
    pub const BINDING: u16 = 0x001;
}

pub mod attr {
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const FINGERPRINT: u16 = 0x8028;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl Class {
    fn bits(self) -> u16 {
        match self {
            Class::Request => 0,
            Class::Indication => 1,
            Class::SuccessResponse => 2,
            Class::ErrorResponse => 3,
        }
    }
    fn from_bits(b: u16) -> Class {
        match b & 3 {
            0 => Class::Request,
            1 => Class::Indication,
            2 => Class::SuccessResponse,
            _ => Class::ErrorResponse,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub kind: u16,
    pub value: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    pub class: Class,
    pub method: u16,
    pub transaction_id: [u8; TXN_ID_LEN],
    pub attributes: Vec<Attribute>,
}

/// Cheap pre-check: first two bits zero + magic cookie. Distinguishes STUN
/// from ChannelData (first bits `01`) on the hot path.
pub fn looks_like_stun(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN && buf[0] & 0xC0 == 0 && buf[4..8] == MAGIC_COOKIE.to_be_bytes()
}

fn encode_type(class: Class, method: u16) -> u16 {
    let c = class.bits();
    (method & 0x000F)
        | ((method & 0x0070) << 1)
        | ((method & 0x0F80) << 2)
        | ((c & 1) << 4)
        | ((c & 2) << 7)
}

fn decode_type(t: u16) -> (Class, u16) {
    let method = (t & 0x000F) | ((t & 0x00E0) >> 1) | ((t & 0x3E00) >> 2);
    let class = ((t & 0x0010) >> 4) | ((t & 0x0100) >> 7);
    (Class::from_bits(class), method)
}

impl StunMessage {
    pub fn binding_success(txn: [u8; TXN_ID_LEN], mapped: SocketAddr) -> Self {
        StunMessage {
            class: Class::SuccessResponse,
            method: method::BINDING,
            transaction_id: txn,
            attributes: vec![Attribute {
                kind: attr::XOR_MAPPED_ADDRESS,
                value: encode_xor_address(mapped, &txn),
            }],
        }
    }

    pub fn attribute(&self, kind: u16) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.kind == kind)
    }

    /// Parses a full datagram (one datagram == exactly one STUN message).
    /// Zero-copy: attribute values are slices of `data`.
    pub fn parse(data: &Bytes) -> Result<Self, CodecError> {
        if data.len() < HEADER_LEN {
            return Err(CodecError::TooShort);
        }
        if data[0] & 0xC0 != 0 {
            return Err(CodecError::BadHeader);
        }
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(CodecError::BadMagicCookie);
        }
        if len % 4 != 0 || HEADER_LEN + len != data.len() {
            return Err(CodecError::BadLength);
        }
        let (class, method) = decode_type(msg_type);
        let mut transaction_id = [0u8; TXN_ID_LEN];
        transaction_id.copy_from_slice(&data[8..HEADER_LEN]);

        let mut attributes = Vec::new();
        let mut off = HEADER_LEN;
        while off < data.len() {
            if data.len() - off < 4 {
                return Err(CodecError::BadAttribute);
            }
            let kind = u16::from_be_bytes([data[off], data[off + 1]]);
            let alen = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            let vstart = off + 4;
            let vend = vstart + alen;
            let padded_end = vstart + ((alen + 3) & !3);
            if padded_end > data.len() {
                return Err(CodecError::BadAttribute);
            }
            if kind == attr::FINGERPRINT {
                // Must be 4 bytes and the last attribute.
                if alen != 4 || padded_end != data.len() {
                    return Err(CodecError::BadFingerprint);
                }
                let got = u32::from_be_bytes([data[vstart], data[vstart + 1], data[vstart + 2], data[vstart + 3]]);
                if crc32(&data[..off]) ^ FINGERPRINT_XOR != got {
                    return Err(CodecError::BadFingerprint);
                }
            }
            attributes.push(Attribute {
                kind,
                value: data.slice(vstart..vend),
            });
            off = padded_end;
        }

        Ok(StunMessage {
            class,
            method,
            transaction_id,
            attributes,
        })
    }

    /// Serializes the message; optionally appends FINGERPRINT as last attribute.
    pub fn encode(&self, with_fingerprint: bool) -> Bytes {
        self.encode_inner(None, with_fingerprint)
    }

    /// Like `encode`, but appends MESSAGE-INTEGRITY (HMAC-SHA1 keyed with `key`)
    /// before the optional FINGERPRINT.
    pub fn encode_with_integrity(&self, key: &[u8], with_fingerprint: bool) -> Bytes {
        self.encode_inner(Some(key), with_fingerprint)
    }

    fn encode_inner(&self, key: Option<&[u8]>, with_fingerprint: bool) -> Bytes {
        let attrs_len: usize = self.attributes.iter().map(|a| 4 + ((a.value.len() + 3) & !3)).sum();
        let mi_len = if key.is_some() { 24 } else { 0 };
        let fp_len = if with_fingerprint { 8 } else { 0 };

        let mut buf = BytesMut::with_capacity(HEADER_LEN + attrs_len + mi_len + fp_len);
        buf.put_u16(encode_type(self.class, self.method));
        // For MESSAGE-INTEGRITY the length field must already cover the MI attribute.
        buf.put_u16((attrs_len + mi_len) as u16);
        buf.put_u32(MAGIC_COOKIE);
        buf.put_slice(&self.transaction_id);

        for a in &self.attributes {
            buf.put_u16(a.kind);
            buf.put_u16(a.value.len() as u16);
            buf.put_slice(&a.value);
            for _ in 0..(((a.value.len() + 3) & !3) - a.value.len()) {
                buf.put_u8(0);
            }
        }

        if let Some(key) = key {
            let mac = crate::auth::hmac_auth::message_integrity(key, &buf);
            buf.put_u16(attr::MESSAGE_INTEGRITY);
            buf.put_u16(20);
            buf.put_slice(&mac);
        }

        if with_fingerprint {
            // For FINGERPRINT the length field must cover the FINGERPRINT attribute too.
            let total = (attrs_len + mi_len + fp_len) as u16;
            buf[2..4].copy_from_slice(&total.to_be_bytes());
            let crc = crc32(&buf) ^ FINGERPRINT_XOR;
            buf.put_u16(attr::FINGERPRINT);
            buf.put_u16(4);
            buf.put_u32(crc);
        }
        buf.freeze()
    }
}

/// Locates MESSAGE-INTEGRITY in an (already parsed/validated) raw message and returns
/// `(bytes the MAC covers, the MAC)`. The covered bytes are everything before the
/// attribute with the header length rewritten to end right after MESSAGE-INTEGRITY
/// (RFC 5389 §15.4), so a trailing FINGERPRINT does not affect verification.
pub fn integrity_parts(raw: &[u8]) -> Option<(Vec<u8>, [u8; 20])> {
    let mut off = HEADER_LEN;
    while off + 4 <= raw.len() {
        let kind = u16::from_be_bytes([raw[off], raw[off + 1]]);
        let alen = u16::from_be_bytes([raw[off + 2], raw[off + 3]]) as usize;
        let vstart = off + 4;
        if kind == attr::MESSAGE_INTEGRITY {
            if alen != 20 || vstart + 20 > raw.len() {
                return None;
            }
            let mut mac = [0u8; 20];
            mac.copy_from_slice(&raw[vstart..vstart + 20]);
            let mut data = raw[..off].to_vec();
            let new_len = (off - HEADER_LEN + 24) as u16;
            data[2..4].copy_from_slice(&new_len.to_be_bytes());
            return Some((data, mac));
        }
        off = vstart + ((alen + 3) & !3);
    }
    None
}

/// XOR-MAPPED-ADDRESS / XOR-RELAYED-ADDRESS value (RFC 5389 §15.2).
pub fn encode_xor_address(addr: SocketAddr, txn: &[u8; TXN_ID_LEN]) -> Bytes {
    let mut b = BytesMut::with_capacity(20);
    b.put_u8(0);
    let xport = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
    match addr.ip() {
        IpAddr::V4(ip) => {
            b.put_u8(0x01);
            b.put_u16(xport);
            b.put_u32(u32::from(ip) ^ MAGIC_COOKIE);
        }
        IpAddr::V6(ip) => {
            b.put_u8(0x02);
            b.put_u16(xport);
            let key = xor_key_v6(txn);
            let mut o = ip.octets();
            for (x, k) in o.iter_mut().zip(key.iter()) {
                *x ^= k;
            }
            b.put_slice(&o);
        }
    }
    b.freeze()
}

pub fn decode_xor_address(value: &[u8], txn: &[u8; TXN_ID_LEN]) -> Result<SocketAddr, CodecError> {
    if value.len() < 4 {
        return Err(CodecError::BadAddress);
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    match value[1] {
        0x01 if value.len() == 8 => {
            let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]) ^ MAGIC_COOKIE;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw)), port))
        }
        0x02 if value.len() == 20 => {
            let key = xor_key_v6(txn);
            let mut o = [0u8; 16];
            for i in 0..16 {
                o[i] = value[4 + i] ^ key[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        _ => Err(CodecError::BadAddress),
    }
}

fn xor_key_v6(txn: &[u8; TXN_ID_LEN]) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    key[4..].copy_from_slice(txn);
    key
}

/// CRC-32 (IEEE 802.3), bitwise; only runs once per STUN message.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXN: [u8; 12] = [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

    fn request() -> StunMessage {
        StunMessage {
            class: Class::Request,
            method: method::BINDING,
            transaction_id: TXN,
            attributes: vec![],
        }
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn message_type_encoding() {
        assert_eq!(encode_type(Class::Request, method::BINDING), 0x0001);
        assert_eq!(encode_type(Class::SuccessResponse, method::BINDING), 0x0101);
        assert_eq!(decode_type(0x0101), (Class::SuccessResponse, method::BINDING));
        // Allocate (0x003) error response = 0x0113
        assert_eq!(encode_type(Class::ErrorResponse, 0x003), 0x0113);
    }

    #[test]
    fn xor_mapped_ipv4_matches_rfc5769() {
        // RFC 5769 §2.2: 192.0.2.1:32853
        let addr: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let v = encode_xor_address(addr, &TXN);
        assert_eq!(&v[..], &[0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
        assert_eq!(decode_xor_address(&v, &TXN).unwrap(), addr);
    }

    #[test]
    fn xor_mapped_ipv6_roundtrip() {
        let addr: SocketAddr = "[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse().unwrap();
        let v = encode_xor_address(addr, &TXN);
        assert_eq!(v.len(), 20);
        assert_eq!(decode_xor_address(&v, &TXN).unwrap(), addr);
    }

    #[test]
    fn binding_request_roundtrip() {
        let bytes = request().encode(false);
        assert_eq!(bytes.len(), HEADER_LEN);
        assert!(looks_like_stun(&bytes));
        assert_eq!(StunMessage::parse(&bytes).unwrap(), request());
    }

    #[test]
    fn binding_success_roundtrip_with_fingerprint() {
        let addr: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let msg = StunMessage::binding_success(TXN, addr);
        let bytes = msg.encode(true);
        let parsed = StunMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.class, Class::SuccessResponse);
        let a = parsed.attribute(attr::XOR_MAPPED_ADDRESS).unwrap();
        assert_eq!(decode_xor_address(&a.value, &TXN).unwrap(), addr);
        assert!(parsed.attribute(attr::FINGERPRINT).is_some());
    }

    #[test]
    fn corrupted_fingerprint_is_rejected() {
        let addr: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let mut raw = StunMessage::binding_success(TXN, addr).encode(true).to_vec();
        raw[HEADER_LEN + 5] ^= 0xFF; // flip a payload byte
        assert_eq!(StunMessage::parse(&Bytes::from(raw)), Err(CodecError::BadFingerprint));
    }

    #[test]
    fn malformed_input_never_panics() {
        assert_eq!(StunMessage::parse(&Bytes::from_static(&[0u8; 5])), Err(CodecError::TooShort));

        let mut raw = request().encode(false).to_vec();
        raw[4] ^= 1;
        assert_eq!(StunMessage::parse(&Bytes::from(raw)), Err(CodecError::BadMagicCookie));

        let mut raw = request().encode(false).to_vec();
        raw[3] = 4; // claims 4 bytes of attributes that are not there
        assert_eq!(StunMessage::parse(&Bytes::from(raw)), Err(CodecError::BadLength));

        // ChannelData-looking packet
        let mut raw = vec![0x40, 0x01, 0, 0];
        raw.extend_from_slice(&[0u8; 16]);
        assert_eq!(StunMessage::parse(&Bytes::from(raw)), Err(CodecError::BadHeader));

        // attribute claims more bytes than available
        let mut raw = request().encode(false).to_vec();
        raw[3] = 4;
        raw.extend_from_slice(&[0x00, 0x20, 0x00, 0x40]);
        assert_eq!(StunMessage::parse(&Bytes::from(raw)), Err(CodecError::BadAttribute));

        assert!(decode_xor_address(&[0, 1, 2], &TXN).is_err());
    }

    #[test]
    fn attribute_padding_is_handled() {
        let msg = StunMessage {
            class: Class::Request,
            method: method::BINDING,
            transaction_id: TXN,
            attributes: vec![Attribute {
                kind: 0x8022, // SOFTWARE
                value: Bytes::from_static(b"abcde"),
            }],
        };
        let bytes = msg.encode(false);
        assert_eq!(bytes.len(), HEADER_LEN + 4 + 8);
        assert_eq!(StunMessage::parse(&bytes).unwrap(), msg);
    }
}
