//! The address field SOCKS5 uses in both its TCP requests and its UDP headers.
//!
//! One copy, because the two paths must agree: a target encoded one way in a
//! CONNECT and another way in a datagram header reaches two different places,
//! and nothing would say so.
//!
//! **Deviation from the Python, in both directions.** It calls
//! `.encode("idna")` on the way out and `.decode("idna", "ignore")` on the way
//! back. Matching that needs a Unicode dependency for a relay that only ever
//! addresses Telegram, whose names are all ASCII — so a non-ASCII host is
//! refused at the encode rather than mangled, and a domain that arrives
//! non-ASCII is refused rather than silently truncated by `errors="ignore"`.
//! Refusing says where the problem is; the alternative fails at the far end.

use crate::Authority;

/// `ATYP` values RFC 1928 defines.
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrError {
    /// A name this encoder will not put on the wire.
    NonAsciiHost,
    /// Longer than the single length byte can describe.
    HostTooLong,
    /// The bytes ran out before the address did.
    Truncated,
    UnknownAtyp(u8),
    /// A port of zero, or an empty host: not something [`Authority`] can hold.
    UnusableTarget,
}

/// `ATYP` plus the address bytes, ready to be followed by a big-endian port.
pub fn encode_target(host: &str) -> Result<Vec<u8>, AddrError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(match ip {
            std::net::IpAddr::V4(v4) => {
                let mut out = vec![ATYP_IPV4];
                out.extend_from_slice(&v4.octets());
                out
            }
            std::net::IpAddr::V6(v6) => {
                let mut out = vec![ATYP_IPV6];
                out.extend_from_slice(&v6.octets());
                out
            }
        });
    }
    if !host.is_ascii() {
        return Err(AddrError::NonAsciiHost);
    }
    let lowered = host.to_ascii_lowercase();
    if lowered.len() > 255 {
        return Err(AddrError::HostTooLong);
    }
    let mut out = vec![ATYP_DOMAIN, lowered.len() as u8];
    out.extend_from_slice(lowered.as_bytes());
    Ok(out)
}

/// Read an address of kind `atyp` starting at `offset`.
///
/// Returns the host and the offset just past it — the port follows.
pub fn decode_target(atyp: u8, bytes: &[u8], offset: usize) -> Result<(String, usize), AddrError> {
    match atyp {
        ATYP_IPV4 => {
            let end = offset + 4;
            let slice: [u8; 4] = bytes.get(offset..end).ok_or(AddrError::Truncated)?.try_into().expect("4");
            Ok((std::net::Ipv4Addr::from(slice).to_string(), end))
        }
        ATYP_IPV6 => {
            let end = offset + 16;
            let slice: [u8; 16] = bytes.get(offset..end).ok_or(AddrError::Truncated)?.try_into().expect("16");
            Ok((std::net::Ipv6Addr::from(slice).to_string(), end))
        }
        ATYP_DOMAIN => {
            let len = *bytes.get(offset).ok_or(AddrError::Truncated)? as usize;
            let start = offset + 1;
            let end = start + len;
            let raw = bytes.get(start..end).ok_or(AddrError::Truncated)?;
            let host = std::str::from_utf8(raw).map_err(|_| AddrError::NonAsciiHost)?;
            if !host.is_ascii() {
                return Err(AddrError::NonAsciiHost);
            }
            Ok((host.to_ascii_lowercase(), end))
        }
        other => Err(AddrError::UnknownAtyp(other)),
    }
}

/// Read an address and the port that follows it.
pub fn decode_authority(atyp: u8, bytes: &[u8], offset: usize) -> Result<(Authority, usize), AddrError> {
    let (host, at) = decode_target(atyp, bytes, offset)?;
    let port_bytes: [u8; 2] = bytes.get(at..at + 2).ok_or(AddrError::Truncated)?.try_into().expect("2");
    let port = u16::from_be_bytes(port_bytes);
    let authority = Authority::new(host, port).ok_or(AddrError::UnusableTarget)?;
    Ok((authority, at + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_encoded_by_what_they_are() {
        assert_eq!(encode_target("127.0.0.1"), Ok(vec![ATYP_IPV4, 127, 0, 0, 1]));
        let v6 = encode_target("::1").expect("v6");
        assert_eq!(v6[0], ATYP_IPV6);
        assert_eq!(v6.len(), 17);
        let name = encode_target("Web.Telegram.ORG").expect("name");
        assert_eq!(name[0], ATYP_DOMAIN);
        assert_eq!(name[1] as usize, "web.telegram.org".len());
        assert_eq!(&name[2..], b"web.telegram.org");
    }

    #[test]
    fn a_name_this_encoder_will_not_send_is_refused_not_mangled() {
        assert_eq!(encode_target("телеграм.рф"), Err(AddrError::NonAsciiHost));
        assert_eq!(encode_target(&"a".repeat(256)), Err(AddrError::HostTooLong));
        assert!(encode_target(&"a".repeat(255)).is_ok());
    }

    #[test]
    fn what_is_encoded_decodes_back() {
        for host in ["127.0.0.1", "::1", "web.telegram.org"] {
            let mut wire = encode_target(host).expect("encode");
            let atyp = wire.remove(0);
            let (back, at) = decode_target(atyp, &wire, 0).expect("decode");
            assert_eq!(back, host.to_ascii_lowercase(), "{host}");
            assert_eq!(at, wire.len());
        }
    }

    #[test]
    fn a_truncated_address_is_named_rather_than_read_past() {
        assert_eq!(decode_target(ATYP_IPV4, &[1, 2, 3], 0), Err(AddrError::Truncated));
        assert_eq!(decode_target(ATYP_IPV6, &[0u8; 15], 0), Err(AddrError::Truncated));
        assert_eq!(decode_target(ATYP_DOMAIN, &[], 0), Err(AddrError::Truncated));
        // A length byte that promises more than is there.
        assert_eq!(decode_target(ATYP_DOMAIN, &[9, b'a', b'b'], 0), Err(AddrError::Truncated));
    }

    #[test]
    fn an_unknown_atyp_is_refused() {
        assert_eq!(decode_target(0x02, &[0u8; 32], 0), Err(AddrError::UnknownAtyp(2)));
    }

    #[test]
    fn a_domain_that_arrives_non_ascii_is_refused_not_truncated() {
        // The Python decodes with `errors="ignore"`, which drops the bytes it
        // cannot read and returns a shorter name that looks valid.
        let mut wire = vec![4u8];
        wire.extend_from_slice("тест".as_bytes()[..4].as_ref());
        assert_eq!(decode_target(ATYP_DOMAIN, &wire, 0), Err(AddrError::NonAsciiHost));
    }

    #[test]
    fn an_authority_carries_its_port_and_refuses_a_zero() {
        let mut wire = encode_target("149.154.167.51").expect("encode");
        let atyp = wire.remove(0);
        let mut with_port = wire.clone();
        with_port.extend_from_slice(&443u16.to_be_bytes());
        let (authority, at) = decode_authority(atyp, &with_port, 0).expect("decode");
        assert_eq!(authority.host(), "149.154.167.51");
        assert_eq!(authority.port(), 443);
        assert_eq!(at, with_port.len());

        let mut zero_port = wire;
        zero_port.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(decode_authority(atyp, &zero_port, 0), Err(AddrError::UnusableTarget));
    }
}
