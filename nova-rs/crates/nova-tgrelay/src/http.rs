//! `CONNECT host:port` — the same destination as SOCKS5, over HTTP.
//!
//! This branch is not protocol completeness. Windows' system proxy takes only
//! the `PROXY` and `SOCKS` (SOCKS4) tokens out of a PAC; it does not understand
//! `SOCKS5` and skips it silently. A client set to "use system proxy settings"
//! therefore ended up at Opera on 1371 and never reached the relay at all. With
//! this branch the PAC can hand it `PROXY 127.0.0.1:1372` and one listener
//! serves both kinds of client.

use crate::authority::{split_http_authority, Authority};
use crate::handshake::{HandshakeLimits, Input};
use std::time::Duration;

const HEAD_END: &[u8] = b"\r\n\r\n";

/// The exact bytes the relay answers with. Kept as constants because a silently
/// hanging proxy costs hours to diagnose (G22) — every refusal must say
/// something, and what it says is part of the contract.
pub const REPLY_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// Why a handshake was refused. Each maps to one status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Ran out of the total budget — both "never sent a first byte" and
    /// "dribbled bytes until the deadline" land here, deliberately.
    Timeout,
    /// Header exceeded the size cap without terminating.
    HeadersTooLarge,
    /// Unparsable request line, or an authority that made no sense.
    BadRequest,
    /// An absolute-URI request instead of CONNECT: ordinary proxied HTTP, which
    /// the relay cannot do — it only tunnels. Answered explicitly rather than
    /// ignored.
    NotConnect { method: String },
}

impl Refusal {
    /// The status line for this refusal.
    pub fn status(&self) -> &'static str {
        match self {
            Self::Timeout => "408 Request Timeout",
            Self::HeadersTooLarge => "431 Request Header Fields Too Large",
            Self::BadRequest => "400 Bad Request",
            Self::NotConnect { .. } => "501 Not Implemented",
        }
    }

    /// The full response the relay writes.
    pub fn response(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"HTTP/1.1 ");
        out.extend_from_slice(self.status().as_bytes());
        out.extend_from_slice(b"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        out
    }
}

/// Result of feeding more bytes to the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Headers are still incomplete and within both limits.
    NeedMore,
    /// The peer closed before finishing. No reply is written — there is nobody
    /// left to read it.
    PeerClosed,
    /// Refused; write `refusal.response()` and drop the connection.
    Refused(Refusal),
    /// Tunnel accepted. Write [`REPLY_ESTABLISHED`], then start bridging.
    Established {
        authority: Authority,
        /// Bytes the client sent after the headers without waiting for the
        /// `200`. They are already tunnel payload and must not be dropped.
        rest: Vec<u8>,
    },
}

/// Incremental `CONNECT` handshake.
pub struct ConnectHandshake {
    buf: Vec<u8>,
    limits: HandshakeLimits,
    done: bool,
}

impl ConnectHandshake {
    pub fn new(limits: HandshakeLimits) -> Self {
        Self { buf: Vec::new(), limits, done: false }
    }

    /// Start with bytes already read by the listener's protocol sniff.
    pub fn with_prefetched(limits: HandshakeLimits, prefetched: &[u8]) -> Self {
        let mut hs = Self::new(limits);
        hs.buf.extend_from_slice(prefetched);
        hs
    }

    /// Feed the next read.
    ///
    /// `elapsed` is measured from the start of the handshake, never from the
    /// last read — see the module docs on [`crate::handshake`].
    pub fn feed(&mut self, input: Input<'_>, elapsed: Duration) -> Step {
        if self.done {
            return Step::NeedMore;
        }
        if input.is_eof() && !self.buf.windows(HEAD_END.len()).any(|w| w == HEAD_END) {
            self.done = true;
            return Step::PeerClosed;
        }
        self.buf.extend_from_slice(input.bytes());

        // Order matters and mirrors the original loop: completeness first, then
        // the size cap, then the deadline. A buffer that is both over-size and
        // past its deadline is answered 431, as before.
        match find_head_end(&self.buf) {
            Some(idx) => {
                self.done = true;
                let head = self.buf[..idx].to_vec();
                let rest = self.buf[idx + HEAD_END.len()..].to_vec();
                parse_request_line(&head, rest)
            }
            None => {
                if self.buf.len() >= self.limits.max_bytes {
                    self.done = true;
                    return Step::Refused(Refusal::HeadersTooLarge);
                }
                if elapsed >= self.limits.total_deadline {
                    self.done = true;
                    return Step::Refused(Refusal::Timeout);
                }
                Step::NeedMore
            }
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(HEAD_END.len()).position(|w| w == HEAD_END)
}

fn parse_request_line(head: &[u8], rest: Vec<u8>) -> Step {
    let first_line = head.split(|b| *b == b'\n').next().unwrap_or(&[]);
    // latin-1 with unmappable bytes dropped, matching the original decode.
    let line: String = first_line.iter().filter(|b| **b != b'\r').map(|b| *b as char).collect();
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Step::Refused(Refusal::BadRequest);
    };
    let method = method.to_ascii_uppercase();
    if method != "CONNECT" {
        return Step::Refused(Refusal::NotConnect { method });
    }
    match split_http_authority(target) {
        Some(authority) => Step::Established { authority, rest },
        None => Step::Refused(Refusal::BadRequest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: Duration = Duration::from_secs(0);

    fn hs() -> ConnectHandshake {
        ConnectHandshake::new(HandshakeLimits::DEFAULT_HTTP)
    }

    #[test]
    fn a_complete_connect_is_accepted_in_one_feed() {
        let mut h = hs();
        let step = h.feed(Input::Bytes(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"), ZERO);
        match step {
            Step::Established { authority, rest } => {
                assert_eq!(authority.host(), "example.com");
                assert_eq!(authority.port(), 443);
                assert!(rest.is_empty());
            }
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn payload_sent_before_the_200_is_preserved() {
        // A client that does not wait for the reply has already started the
        // tunnel; losing these bytes loses the session.
        let mut h = hs();
        let step = h.feed(Input::Bytes(b"CONNECT a.example:443 HTTP/1.1\r\n\r\n\x16\x03\x01early"), ZERO);
        match step {
            Step::Established { rest, .. } => assert_eq!(rest, b"\x16\x03\x01early"),
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn headers_split_across_reads_are_reassembled() {
        let mut h = hs();
        assert_eq!(h.feed(Input::Bytes(b"CONNECT a.example"), ZERO), Step::NeedMore);
        assert_eq!(h.feed(Input::Bytes(b":443 HTTP/1.1\r\n"), ZERO), Step::NeedMore);
        match h.feed(Input::Bytes(b"\r\n"), ZERO) {
            Step::Established { authority, .. } => assert_eq!(authority.port(), 443),
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn g22_a_dribbling_client_is_cut_off_by_the_total_budget() {
        // One byte at a time, each arriving "in time" for a per-read timeout,
        // but the total budget still expires. This is the case a per-read
        // timeout cannot catch — and the reason feed() takes elapsed-since-start.
        let mut h = hs();
        for i in 0..4u64 {
            assert_eq!(h.feed(Input::Bytes(b"x"), Duration::from_secs(i)), Step::NeedMore);
        }
        assert_eq!(h.feed(Input::Bytes(b"x"), Duration::from_secs(5)), Step::Refused(Refusal::Timeout));
    }

    #[test]
    fn a_client_that_never_speaks_gets_the_same_408() {
        let mut h = hs();
        assert_eq!(h.feed(Input::Bytes(b""), Duration::from_secs(6)), Step::Refused(Refusal::Timeout));
    }

    #[test]
    fn oversized_headers_are_refused_with_431() {
        let mut h = hs();
        let big = vec![b'x'; 8192];
        assert_eq!(h.feed(Input::Bytes(&big), ZERO), Step::Refused(Refusal::HeadersTooLarge));
    }

    #[test]
    fn the_size_cap_is_checked_before_the_deadline() {
        // Both limits blown at once: the original answers 431, not 408.
        let mut h = hs();
        let big = vec![b'x'; 9000];
        assert_eq!(h.feed(Input::Bytes(&big), Duration::from_secs(99)), Step::Refused(Refusal::HeadersTooLarge));
    }

    #[test]
    fn a_complete_header_wins_over_the_size_cap() {
        // Terminated headers are parsed even when the buffer is over the cap:
        // the cap exists to stop unterminated growth.
        let mut h = hs();
        let mut wire = b"CONNECT a.example:443 HTTP/1.1\r\nX: ".to_vec();
        wire.extend(std::iter::repeat_n(b'y', 9000));
        wire.extend_from_slice(b"\r\n\r\n");
        match h.feed(Input::Bytes(&wire), ZERO) {
            Step::Established { authority, .. } => assert_eq!(authority.host(), "a.example"),
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn a_non_connect_method_gets_501_and_names_itself() {
        let mut h = hs();
        match h.feed(Input::Bytes(b"POST http://x.example/ HTTP/1.1\r\n\r\n"), ZERO) {
            Step::Refused(Refusal::NotConnect { method }) => assert_eq!(method, "POST"),
            other => panic!("expected NotConnect, got {other:?}"),
        }
    }

    #[test]
    fn a_lowercase_method_is_still_recognised() {
        let mut h = hs();
        match h.feed(Input::Bytes(b"connect a.example:443 HTTP/1.1\r\n\r\n"), ZERO) {
            Step::Established { authority, .. } => assert_eq!(authority.host(), "a.example"),
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn a_one_word_request_line_is_a_400() {
        let mut h = hs();
        assert_eq!(h.feed(Input::Bytes(b"CONNECT\r\n\r\n"), ZERO), Step::Refused(Refusal::BadRequest));
    }

    #[test]
    fn an_unparsable_authority_is_a_400() {
        let mut h = hs();
        assert_eq!(
            h.feed(Input::Bytes(b"CONNECT [::1 HTTP/1.1\r\n\r\n"), ZERO),
            Step::Refused(Refusal::BadRequest)
        );
    }

    #[test]
    fn eof_before_the_headers_end_writes_nothing() {
        let mut h = hs();
        assert_eq!(h.feed(Input::Bytes(b"CONNECT a.exa"), ZERO), Step::NeedMore);
        assert_eq!(h.feed(Input::Eof, ZERO), Step::PeerClosed);
    }

    #[test]
    fn prefetched_bytes_from_the_sniff_are_not_lost() {
        let mut h = ConnectHandshake::with_prefetched(HandshakeLimits::DEFAULT_HTTP, b"CONN");
        match h.feed(Input::Bytes(b"ECT a.example:443 HTTP/1.1\r\n\r\n"), ZERO) {
            Step::Established { authority, .. } => assert_eq!(authority.host(), "a.example"),
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn every_refusal_produces_a_reply_none_hangs_silently() {
        for refusal in [
            Refusal::Timeout,
            Refusal::HeadersTooLarge,
            Refusal::BadRequest,
            Refusal::NotConnect { method: "GET".into() },
        ] {
            let reply = refusal.response();
            assert!(reply.starts_with(b"HTTP/1.1 "), "{refusal:?}");
            assert!(reply.ends_with(b"\r\n\r\n"), "{refusal:?}");
            assert!(!refusal.status().is_empty());
        }
    }

    #[test]
    fn the_success_reply_is_byte_exact() {
        assert_eq!(REPLY_ESTABLISHED, b"HTTP/1.1 200 Connection established\r\n\r\n");
    }
}
