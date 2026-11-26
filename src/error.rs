//! Domain error types: `CodecError`, `ConfigError`, `TurnError`.

use std::fmt;

/// Errors while parsing / serializing STUN/TURN messages.
/// Parsers return these instead of panicking on malformed network input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    TooShort,
    BadHeader,
    BadMagicCookie,
    BadLength,
    BadAttribute,
    BadFingerprint,
    BadAddress,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TooShort => "message too short",
            Self::BadHeader => "invalid STUN header",
            Self::BadMagicCookie => "invalid magic cookie",
            Self::BadLength => "invalid message length",
            Self::BadAttribute => "malformed attribute",
            Self::BadFingerprint => "FINGERPRINT mismatch",
            Self::BadAddress => "malformed address attribute",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CodecError {}

/// Configuration errors (env parsing / validation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Invalid {
        key: &'static str,
        value: String,
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { key, value, reason } => {
                write!(f, "invalid config {key}={value:?}: {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// TURN-level errors (used from Phase 2 on; defined now per spec §4).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnError {
    BadRequest,
    Unauthorized,
    StaleNonce,
    AllocationMismatch,
    ForbiddenPeer,
    QuotaExceeded,
    InsufficientCapacity,
    InternalError,
}

impl fmt::Display for TurnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TurnError {}
