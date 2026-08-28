//! SOCKS5 handshake on port 1372.
//!
//! Ported as an incremental state machine, and that is not cosmetic. The Python
//! original puts a 5 s timeout on *each* `readexactly`, which is exactly the
//! shape G22 warns about: a client sending one byte every four seconds renews
//! the timeout forever and holds the task for as long as it likes, on a listener
//! bound to `0.0.0.0`. The HTTP branch was fixed to a total deadline; this one
//! never was. Here the machine is only ever told how long the *whole* handshake
//! has taken, so the old shape cannot be written.

use crate::handshake::{HandshakeLimits, Input};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

const VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const NO_ACCEPTABLE: &[u8] = b"\x05\xff";
const GENERAL_FAILURE: &[u8] = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00";
const CMD_UNSUPPORTED: &[u8] = b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00";
const ATYP_UNSUPPORTED: &[u8] = b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00";

/// The success reply: bound to loopback on the relay's own port.
pub fn established_reply(relay_port: u16) -> Vec<u8> {
    let mut out = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    out.extend_from_slice(&relay_port.to_be_bytes());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// First byte was not 0x05.
    NotSocks5,
    /// The client offered no "no authentication" method.
    NoAcceptableMethods,
    /// Anything other than CONNECT.
    CommandNotSupported,
    /// An address type the relay does not carry.
    AddressTypeNotSupported,
    /// Ran out of the total budget, or of the byte cap. SOCKS5 has no status
    /// code for either, so the client is refused the same way it would be for an
    /// unusable method — but it is always *answered*, never left hanging.
    Timeout,
    /// The request parsed but named nowhere usable — an empty hostname, or port
    /// 0. **A deliberate deviation from the Python**, which returns such a
    /// target to its caller and only checks the host. Nothing legitimate asks
    /// for port 0, and `Authority` cannot represent it, so it is refused here
    /// rather than carried around as a half-valid value.
    InvalidTarget,
}

impl Refusal {
    pub fn response(&self) -> &'static [u8] {
        match self {
            Self::NotSocks5 | Self::NoAcceptableMethods | Self::Timeout => NO_ACCEPTABLE,
            Self::InvalidTarget => GENERAL_FAILURE,
            Self::CommandNotSupported => CMD_UNSUPPORTED,
            Self::AddressTypeNotSupported => ATYP_UNSUPPORTED,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    NeedMore,
    PeerClosed,
    Refused(Refusal),
    Established { host: String, port: u16 },
}

/// What one `feed()` produced: bytes to send, and where the handshake now is.
///
/// The two travel together because they must. An earlier version hung `write`
/// off `Step::NeedMore` alone, and a client that sent its whole request in one
/// packet then lost the method-selection reply entirely: the machine walked the
/// greeting *and* the request inside a single `feed()` and returned
/// `Established`, dropping the `\x05\x00` it had produced on the way. The client
/// waited for twelve bytes and got ten. Refusals had the same hole. Only a
/// socket-level test caught it — the unit tests fed bytes piecemeal, so they
/// always saw the write on its own step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    /// Send these before anything else, whatever `step` says.
    pub write: Vec<u8>,
    pub step: Step,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Greeting,
    Methods { count: usize },
    Request,
    Address { atyp: u8 },
    Port,
    Done,
}

pub struct SocksHandshake {
    buf: Vec<u8>,
    cursor: usize,
    state: State,
    host: Option<String>,
    limits: HandshakeLimits,
}

impl SocksHandshake {
    pub fn new(limits: HandshakeLimits) -> Self {
        Self { buf: Vec::new(), cursor: 0, state: State::Greeting, host: None, limits }
    }

    pub fn with_prefetched(limits: HandshakeLimits, prefetched: &[u8]) -> Self {
        let mut hs = Self::new(limits);
        hs.buf.extend_from_slice(prefetched);
        hs
    }

    /// `elapsed` is measured from the start of the handshake, never from the
    /// last read.
    pub fn feed(&mut self, input: Input<'_>, elapsed: Duration) -> Progress {
        if self.state == State::Done {
            return Progress { write: Vec::new(), step: Step::NeedMore };
        }
        if input.is_eof() {
            self.state = State::Done;
            return Progress { write: Vec::new(), step: Step::PeerClosed };
        }
        self.buf.extend_from_slice(input.bytes());

        // advance() recurses through every non-terminal transition itself, so a
        // single call either reaches a decision or runs out of bytes. Whatever it
        // produced on the way out travels with the decision, never instead of it.
        let mut write = Vec::new();
        if let Some(step) = self.advance(&mut write) {
            self.state = State::Done;
            return Progress { write, step };
        }
        if self.buffered() >= self.limits.max_bytes || elapsed >= self.limits.total_deadline {
            self.state = State::Done;
            return Progress { write, step: Step::Refused(Refusal::Timeout) };
        }
        Progress { write, step: Step::NeedMore }
    }

    fn buffered(&self) -> usize {
        self.buf.len() - self.cursor
    }

    fn peek(&self, n: usize) -> Option<&[u8]> {
        self.buf.get(self.cursor..self.cursor + n)
    }

    fn consume(&mut self, n: usize) {
        self.cursor += n;
    }

    /// Advance one step. `Some(step)` is terminal; `None` means "need more
    /// bytes" *or* that a non-terminal transition happened — the caller loops.
    fn advance(&mut self, write: &mut Vec<u8>) -> Option<Step> {
        match self.state {
            State::Greeting => {
                let head = self.peek(2)?;
                let (ver, count) = (head[0], head[1] as usize);
                self.consume(2);
                if ver != VERSION {
                    return Some(Step::Refused(Refusal::NotSocks5));
                }
                self.state = State::Methods { count };
                self.advance(write)
            }
            State::Methods { count } => {
                let methods = self.peek(count)?.to_vec();
                self.consume(count);
                if !methods.contains(&0x00) {
                    return Some(Step::Refused(Refusal::NoAcceptableMethods));
                }
                write.extend_from_slice(b"\x05\x00");
                self.state = State::Request;
                self.advance(write)
            }
            State::Request => {
                let req = self.peek(4)?;
                let (ver, cmd, atyp) = (req[0], req[1], req[3]);
                self.consume(4);
                if ver != VERSION || cmd != CMD_CONNECT {
                    return Some(Step::Refused(Refusal::CommandNotSupported));
                }
                self.state = State::Address { atyp };
                self.advance(write)
            }
            State::Address { atyp } => {
                let host = match atyp {
                    ATYP_IPV4 => {
                        let raw = self.peek(4)?;
                        let addr = Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
                        self.consume(4);
                        addr.to_string()
                    }
                    ATYP_DOMAIN => {
                        let len = *self.peek(1)?.first()? as usize;
                        // Peek the length *and* the name together: consuming the
                        // length byte before the name has arrived would corrupt
                        // the state on a split read.
                        let raw = self.peek(1 + len)?[1..].to_vec();
                        self.consume(1 + len);
                        // ASCII, unmappable bytes dropped — the original decode.
                        raw.iter().filter(|b| b.is_ascii()).map(|b| *b as char).collect()
                    }
                    ATYP_IPV6 => {
                        let raw = self.peek(16)?;
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(raw);
                        self.consume(16);
                        Ipv6Addr::from(octets).to_string()
                    }
                    _ => return Some(Step::Refused(Refusal::AddressTypeNotSupported)),
                };
                self.host = Some(host);
                self.state = State::Port;
                self.advance(write)
            }
            State::Port => {
                let raw = self.peek(2)?;
                let port = u16::from_be_bytes([raw[0], raw[1]]);
                self.consume(2);
                Some(Step::Established { host: self.host.take().unwrap_or_default(), port })
            }
            State::Done => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: Duration = Duration::from_secs(0);

    fn hs() -> SocksHandshake {
        SocksHandshake::new(HandshakeLimits::DEFAULT_SOCKS)
    }

    fn greeting() -> Vec<u8> {
        vec![0x05, 0x01, 0x00]
    }

    fn request_domain(host: &str, port: u16) -> Vec<u8> {
        let mut out = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        out.extend_from_slice(host.as_bytes());
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    #[test]
    fn a_domain_request_completes_and_selects_no_auth() {
        let mut h = hs();
        let mut wire = greeting();
        wire.extend(request_domain("example.com", 443));
        match h.feed(Input::Bytes(&wire), ZERO).step {
            Step::Established { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn the_method_selection_reply_is_handed_back_before_the_request_arrives() {
        let mut h = hs();
        let progress = h.feed(Input::Bytes(&greeting()), ZERO);
        assert_eq!(progress.step, Step::NeedMore);
        assert_eq!(progress.write, b"\x05\x00");
    }

    #[test]
    fn a_request_arriving_whole_still_yields_the_method_selection_reply() {
        // The regression that only a socket-level test caught: greeting and
        // request in one packet walked straight to Established, and the
        // `\x05\x00` produced on the way was dropped. The client then waited for
        // twelve bytes and got ten.
        let mut h = hs();
        let mut wire = greeting();
        wire.extend(request_domain("a.example", 443));
        let progress = h.feed(Input::Bytes(&wire), ZERO);
        assert!(matches!(progress.step, Step::Established { .. }));
        assert_eq!(progress.write, b"\x05\x00", "the method-selection reply must travel with the decision");
    }

    #[test]
    fn a_refusal_after_the_greeting_also_carries_the_method_selection_reply() {
        let mut h = hs();
        let mut wire = greeting();
        wire.extend_from_slice(&[0x05, 0x02, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80]);
        let progress = h.feed(Input::Bytes(&wire), ZERO);
        assert_eq!(progress.step, Step::Refused(Refusal::CommandNotSupported));
        assert_eq!(progress.write, b"\x05\x00");
    }

    #[test]
    fn ipv4_and_ipv6_addresses_are_rendered_the_same_way_python_does() {
        let mut h = hs();
        let mut wire = greeting();
        wire.extend_from_slice(&[0x05, 0x01, 0x00, ATYP_IPV4, 149, 154, 167, 99]);
        wire.extend_from_slice(&443u16.to_be_bytes());
        match h.feed(Input::Bytes(&wire), ZERO).step {
            Step::Established { host, .. } => assert_eq!(host, "149.154.167.99"),
            other => panic!("got {other:?}"),
        }

        let mut h6 = hs();
        let mut wire6 = greeting();
        wire6.extend_from_slice(&[0x05, 0x01, 0x00, ATYP_IPV6]);
        wire6.extend_from_slice(&[0u8; 15]);
        wire6.push(1);
        wire6.extend_from_slice(&80u16.to_be_bytes());
        match h6.feed(Input::Bytes(&wire6), ZERO).step {
            // Compressed form, as str(IPv6Address(...)) gives.
            Step::Established { host, .. } => assert_eq!(host, "::1"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn a_request_arriving_one_byte_at_a_time_still_parses() {
        // The split that would corrupt a naive parser: the domain length byte
        // arrives in one read and the name in the next.
        let mut h = hs();
        let mut wire = greeting();
        wire.extend(request_domain("a.example", 8443));
        for byte in &wire[..wire.len() - 1] {
            match h.feed(Input::Bytes(&[*byte]), ZERO).step {
                Step::NeedMore => {}
                other => panic!("premature decision: {other:?}"),
            }
        }
        match h.feed(Input::Bytes(&wire[wire.len() - 1..]), ZERO).step {
            Step::Established { host, port } => {
                assert_eq!(host, "a.example");
                assert_eq!(port, 8443);
            }
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn g22_a_dribbling_client_is_cut_off_by_the_total_budget() {
        // The defect this port fixes: with a per-read timeout each of these
        // reads is "in time" and the handshake never ends.
        let mut h = hs();
        for i in 0..5u64 {
            match h.feed(Input::Bytes(&[0x05]), Duration::from_secs(i)).step {
                Step::NeedMore => {}
                other => panic!("unexpected at t={i}: {other:?}"),
            }
        }
        assert_eq!(h.feed(Input::Bytes(&[0x00]), Duration::from_secs(5)).step, Step::Refused(Refusal::Timeout));
    }

    #[test]
    fn a_stalled_greeting_is_stopped_by_the_deadline_not_by_the_cap() {
        // Written first as a byte-cap test, which was wrong and the test said so:
        // a 255-method greeting *completes* at 255 bytes and is refused as
        // NoAcceptableMethods long before any cap. In SOCKS5 the parser always
        // consumes what it accepts, so the buffer cannot grow without bound —
        // the deadline is the real bound, and the cap is belt and braces.
        let mut h = hs();
        let mut step = h.feed(Input::Bytes(&[0x05, 0xff]), ZERO);
        for i in 0..100u64 {
            assert!(matches!(step.step, Step::NeedMore), "at {i}: {step:?}");
            step = h.feed(Input::Bytes(&[0x01]), Duration::from_millis(i * 10));
        }
        assert_eq!(h.feed(Input::Bytes(&[0x01]), Duration::from_secs(5)).step, Step::Refused(Refusal::Timeout));
    }

    #[test]
    fn the_largest_well_formed_handshake_fits_the_byte_cap() {
        // 2 + 255 methods + 4 + 1 + 255 domain + 2 = 519 bytes. The cap must sit
        // above that, or a legitimate client with a long method list and a long
        // hostname would be refused.
        let largest = 2 + 255 + 4 + 1 + 255 + 2;
        assert!(
            HandshakeLimits::DEFAULT_SOCKS.max_bytes > largest,
            "cap {} must exceed the largest legal handshake {largest}",
            HandshakeLimits::DEFAULT_SOCKS.max_bytes
        );
    }

    #[test]
    fn a_255_method_greeting_is_answered_on_its_own_terms() {
        // The case the wrong test above assumed would hit the cap.
        let mut h = hs();
        let mut wire = vec![0x05, 0xff];
        wire.extend(std::iter::repeat_n(0x01, 255));
        assert_eq!(h.feed(Input::Bytes(&wire), ZERO).step, Step::Refused(Refusal::NoAcceptableMethods));
    }

    #[test]
    fn a_client_offering_only_authenticated_methods_is_refused() {
        let mut h = hs();
        assert_eq!(
            h.feed(Input::Bytes(&[0x05, 0x01, 0x02]), ZERO).step,
            Step::Refused(Refusal::NoAcceptableMethods)
        );
    }

    #[test]
    fn zero_methods_is_refused_rather_than_treated_as_no_auth() {
        let mut h = hs();
        assert_eq!(h.feed(Input::Bytes(&[0x05, 0x00]), ZERO).step, Step::Refused(Refusal::NoAcceptableMethods));
    }

    #[test]
    fn a_non_socks5_version_is_refused() {
        let mut h = hs();
        assert_eq!(h.feed(Input::Bytes(&[0x04, 0x01, 0x00]), ZERO).step, Step::Refused(Refusal::NotSocks5));
    }

    #[test]
    fn bind_and_udp_associate_are_refused_as_unsupported_commands() {
        for cmd in [0x02u8, 0x03] {
            let mut h = hs();
            let mut wire = greeting();
            wire.extend_from_slice(&[0x05, cmd, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80]);
            assert_eq!(
                h.feed(Input::Bytes(&wire), ZERO).step,
                Step::Refused(Refusal::CommandNotSupported),
                "cmd {cmd:#x}"
            );
        }
    }

    #[test]
    fn an_unknown_address_type_is_refused() {
        let mut h = hs();
        let mut wire = greeting();
        wire.extend_from_slice(&[0x05, 0x01, 0x00, 0x09, 1, 2, 3, 4, 0, 80]);
        assert_eq!(h.feed(Input::Bytes(&wire), ZERO).step, Step::Refused(Refusal::AddressTypeNotSupported));
    }

    #[test]
    fn eof_ends_the_handshake_without_a_reply() {
        let mut h = hs();
        assert_eq!(h.feed(Input::Eof, ZERO).step, Step::PeerClosed);
    }

    #[test]
    fn every_refusal_has_a_wire_reply() {
        for refusal in [
            Refusal::NotSocks5,
            Refusal::NoAcceptableMethods,
            Refusal::CommandNotSupported,
            Refusal::AddressTypeNotSupported,
            Refusal::Timeout,
            Refusal::InvalidTarget,
        ] {
            let reply = refusal.response();
            assert!(!reply.is_empty(), "{refusal:?}");
            assert_eq!(reply[0], VERSION, "{refusal:?}");
        }
    }

    #[test]
    fn the_success_reply_carries_the_relay_port_big_endian() {
        assert_eq!(established_reply(1372), vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x05, 0x5C]);
    }

    #[test]
    fn prefetched_bytes_from_the_sniff_are_not_lost() {
        // The listener has already read the 0x05 that told it this is SOCKS5.
        let mut h = SocksHandshake::with_prefetched(HandshakeLimits::DEFAULT_SOCKS, &[0x05]);
        let mut wire = vec![0x01, 0x00];
        wire.extend(request_domain("a.example", 443));
        match h.feed(Input::Bytes(&wire), ZERO).step {
            Step::Established { host, .. } => assert_eq!(host, "a.example"),
            other => panic!("expected Established, got {other:?}"),
        }
    }
}
