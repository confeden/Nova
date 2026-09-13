//! SOCKS5's UDP datagram header.
//!
//! Layer 23, the codec half of `tgrelay/udp_transport.py`. Telegram's voice and
//! video legs are UDP, and carrying them through WARP means wrapping each
//! datagram the way RFC 1928 §7 describes:
//!
//! ```text
//! RSV(2)=0 FRAG(1) ATYP(1) ADDR PORT(2) DATA…
//! ```
//!
//! **A fragmented datagram is refused, not forwarded.** `FRAG != 0` means the
//! proxy split a datagram across several packets, and nothing here reassembles
//! them. Passing one on as though it were whole hands the caller a truncated
//! datagram with no indication that it is one — the same shape as the WebSocket
//! fragmentation defect (S28), which is exactly why this one says no.

use crate::socks_addr::{decode_authority, encode_target, AddrError};
use crate::Authority;

/// `RSV` and `FRAG`, then the address.
pub const HEADER_PREFIX_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpError {
    /// Fewer bytes than a header needs.
    Short,
    /// `FRAG` was not zero.
    Fragmented(u8),
    Address(AddrError),
}

impl From<AddrError> for UdpError {
    fn from(e: AddrError) -> Self {
        Self::Address(e)
    }
}

/// One datagram, unwrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// Who it came from, as the proxy reported them.
    pub peer: Authority,
    pub payload: Vec<u8>,
}

/// Wrap `payload` for `target`.
pub fn encode(target: &Authority, payload: &[u8]) -> Result<Vec<u8>, UdpError> {
    let addr = encode_target(target.host())?;
    let mut out = Vec::with_capacity(HEADER_PREFIX_LEN + addr.len() + 2 + payload.len());
    // RSV, then FRAG — always zero on the way out. This side never fragments.
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    out.extend_from_slice(&addr);
    out.extend_from_slice(&target.port().to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Unwrap a datagram the proxy sent back.
pub fn decode(packet: &[u8]) -> Result<Datagram, UdpError> {
    if packet.len() < HEADER_PREFIX_LEN {
        return Err(UdpError::Short);
    }
    if packet[2] != 0 {
        return Err(UdpError::Fragmented(packet[2]));
    }
    let (peer, at) = decode_authority(packet[3], packet, HEADER_PREFIX_LEN)?;
    Ok(Datagram { peer, payload: packet[at..].to_vec() })
}

/// Where the datagrams actually go, given what `UDP ASSOCIATE` answered.
///
/// **A proxy that answers `0.0.0.0` means "the address you are already talking
/// to".** Sending to the unspecified address would go nowhere; some SOCKS5
/// servers answer this way rather than naming an interface, and taking them
/// literally is a UDP path that silently carries nothing.
pub fn relay_host(reported: &str, proxy_host: &str) -> String {
    let reported = reported.trim();
    let unspecified = reported.parse::<std::net::IpAddr>().map(|ip| ip.is_unspecified()).unwrap_or(false);
    if unspecified || reported.is_empty() {
        proxy_host.trim().to_string()
    } else {
        reported.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str, port: u16) -> Authority {
        Authority::new(host, port).expect("authority")
    }

    #[test]
    fn a_datagram_round_trips() {
        let to = target("149.154.167.51", 443);
        let wire = encode(&to, b"voice").expect("encode");
        assert_eq!(&wire[..4], &[0x00, 0x00, 0x00, 0x01], "RSV, FRAG, ATYP=IPv4");
        let back = decode(&wire).expect("decode");
        assert_eq!(back.peer, to);
        assert_eq!(back.payload, b"voice");
    }

    #[test]
    fn a_named_target_travels_as_a_domain() {
        let to = target("web.telegram.org", 443);
        let wire = encode(&to, b"x").expect("encode");
        assert_eq!(wire[3], 0x03);
        assert_eq!(decode(&wire).expect("decode").peer, to);
    }

    #[test]
    fn an_ipv6_target_round_trips() {
        let to = target("2001:67c:4e8:f002::1", 443);
        let wire = encode(&to, b"x").expect("encode");
        assert_eq!(wire[3], 0x04);
        assert_eq!(decode(&wire).expect("decode").peer.port(), 443);
    }

    #[test]
    fn an_empty_payload_is_a_legal_datagram() {
        // UDP has no notion of an empty message being a close, and a keepalive
        // is often exactly this.
        let wire = encode(&target("1.2.3.4", 53), b"").expect("encode");
        let back = decode(&wire).expect("decode");
        assert!(back.payload.is_empty());
    }

    #[test]
    fn a_fragmented_datagram_is_refused_rather_than_forwarded() {
        // Nothing here reassembles fragments. Passing one on as though it were
        // whole hands the caller a truncated datagram with no sign that it is
        // one — the same shape as S28, one protocol over.
        let mut wire = encode(&target("1.2.3.4", 53), b"half").expect("encode");
        wire[2] = 1;
        assert_eq!(decode(&wire), Err(UdpError::Fragmented(1)));
        wire[2] = 0x80;
        assert_eq!(decode(&wire), Err(UdpError::Fragmented(0x80)));
    }

    #[test]
    fn a_short_packet_is_named_rather_than_read_past() {
        for len in 0..HEADER_PREFIX_LEN {
            assert_eq!(decode(&vec![0u8; len]), Err(UdpError::Short), "len {len}");
        }
        // Long enough for the prefix, too short for the address.
        assert_eq!(decode(&[0, 0, 0, 0x01, 1, 2]), Err(UdpError::Address(AddrError::Truncated)));
        // Address complete, port missing.
        assert_eq!(decode(&[0, 0, 0, 0x01, 1, 2, 3, 4]), Err(UdpError::Address(AddrError::Truncated)));
    }

    #[test]
    fn an_unspecified_relay_address_means_the_proxy_itself() {
        // Some SOCKS5 servers answer ASSOCIATE with `0.0.0.0` rather than naming
        // an interface. Taking that literally is a UDP path that carries nothing
        // and says nothing.
        assert_eq!(relay_host("0.0.0.0", "127.0.0.1"), "127.0.0.1");
        assert_eq!(relay_host("::", "127.0.0.1"), "127.0.0.1");
        assert_eq!(relay_host("   ", "127.0.0.1"), "127.0.0.1");
        assert_eq!(relay_host("10.0.0.9", "127.0.0.1"), "10.0.0.9", "a real answer is believed");
    }

    #[test]
    fn the_payload_boundary_is_where_the_port_ends() {
        // Off by two here and every datagram carries its own port as the first
        // two bytes of audio.
        let wire = encode(&target("1.2.3.4", 0x1234), &[0xAA, 0xBB]).expect("encode");
        assert_eq!(wire[wire.len() - 4..], [0x12, 0x34, 0xAA, 0xBB]);
        assert_eq!(decode(&wire).expect("decode").payload, [0xAA, 0xBB]);
    }
}
