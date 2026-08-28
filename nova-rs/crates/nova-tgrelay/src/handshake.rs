//! Shared shape of the two client handshakes on port 1372.
//!
//! **G22, encoded in the types rather than written in a comment.** A per-read
//! timeout bounds nothing: a client sending one byte every four seconds renews
//! it forever, and the listener binds `0.0.0.0`, so it is reachable from the
//! LAN. The only clock these state machines are given is *elapsed since the
//! handshake began* — there is no way to express a per-read timeout with this
//! API, which is the point.
//!
//! The size cap is the other half of the same rule and lives here too.

use std::time::Duration;

/// What a handshake is allowed to consume before it is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeLimits {
    /// Cap on buffered handshake bytes.
    pub max_bytes: usize,
    /// Budget for the whole handshake, not for one read.
    pub total_deadline: Duration,
}

impl HandshakeLimits {
    /// The values the Python relay uses: 8 KiB and 5 s.
    pub const DEFAULT_HTTP: Self = Self { max_bytes: 8192, total_deadline: Duration::from_secs(5) };

    /// SOCKS5 headers are tiny; the cap only has to stop a client that dribbles
    /// forever without ever completing a request.
    pub const DEFAULT_SOCKS: Self = Self { max_bytes: 1024, total_deadline: Duration::from_secs(5) };
}

/// One feed of the state machine. `Eof` is a distinct case rather than an empty
/// slice so "the peer closed" cannot be confused with "nothing arrived yet".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input<'a> {
    Bytes(&'a [u8]),
    Eof,
}

impl<'a> Input<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        match self {
            Self::Bytes(b) => b,
            Self::Eof => &[],
        }
    }

    pub fn is_eof(&self) -> bool {
        matches!(self, Self::Eof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_python_relay() {
        assert_eq!(HandshakeLimits::DEFAULT_HTTP.max_bytes, 8192);
        assert_eq!(HandshakeLimits::DEFAULT_HTTP.total_deadline, Duration::from_secs(5));
    }

    #[test]
    fn eof_is_not_an_empty_chunk() {
        assert!(Input::Eof.is_eof());
        assert!(!Input::Bytes(&[]).is_eof());
        assert_eq!(Input::Bytes(b"ab").bytes(), b"ab");
        assert_eq!(Input::Eof.bytes(), b"");
    }
}
