//! What is on the other end of a socket, decided from its first bytes.

/// Record type `handshake` followed by the legacy record version. TLS 1.3 still
/// writes 0x0301 or 0x0303 there, so two prefixes cover it.
const TLS_CLIENT_HELLO_PREFIXES: [&[u8]; 2] = [b"\x16\x03\x01", b"\x16\x03\x03"];

/// Telegram Desktop races an obfuscated TCP transport against a plain HTTP one.
/// The HTTP leg opens port 80 with a real request line, so its first 64 bytes
/// never decrypt into a protocol tag.
const HTTP_TRANSPORT_PREFIXES: [&[u8]; 5] = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS "];

/// Not everything arriving at a Telegram address is MTProto: the Telegram
/// Desktop updater dials `updates.tdesktop.com`, which resolves inside the DC2
/// range, and opens ordinary TLS there. Such a socket cannot go through
/// `/apiws` — that path carries MTProto, not an arbitrary stream — so it is
/// tunnelled as-is rather than dropped.
pub fn looks_like_tls_client_hello(data: &[u8]) -> bool {
    let head = &data[..data.len().min(3)];
    TLS_CLIENT_HELLO_PREFIXES.iter().any(|prefix| head.starts_with(prefix))
}

pub fn looks_like_http_request(data: &[u8]) -> bool {
    let head = &data[..data.len().min(8)];
    HTTP_TRANSPORT_PREFIXES.iter().any(|prefix| head.starts_with(prefix))
}

/// What the 1372 listener does with a new client, decided on the first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProtocol {
    Socks5,
    HttpConnect,
    /// Neither. Must be refused immediately.
    Unsupported,
}

/// First-byte dispatch for the 1372 listener.
///
/// `None` means nothing has arrived yet — the caller is still waiting, which is
/// not the same as a client that sent something unrecognisable.
///
/// G21: a bare `else` in a protocol dispatch swallows garbage. Bytes that are
/// neither `0x05` nor an uppercase letter get refused at once instead of being
/// left to expire against the header timeout, because a silently hanging proxy
/// costs hours to diagnose (G22).
pub fn classify_client(first: Option<u8>) -> Option<ClientProtocol> {
    let byte = first?;
    Some(match byte {
        0x05 => ClientProtocol::Socks5,
        b'A'..=b'Z' => ClientProtocol::HttpConnect,
        _ => ClientProtocol::Unsupported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_client_hello_is_recognised_for_both_legacy_versions() {
        assert!(looks_like_tls_client_hello(b"\x16\x03\x01\x00\x01"));
        assert!(looks_like_tls_client_hello(b"\x16\x03\x03\x00\x01"));
    }

    #[test]
    fn tls_sniff_rejects_other_records_and_short_reads() {
        assert!(!looks_like_tls_client_hello(b""));
        assert!(!looks_like_tls_client_hello(b"\x16\x03"), "a truncated prefix is not a match");
        assert!(!looks_like_tls_client_hello(b"\x17\x03\x03"), "application data, not handshake");
        assert!(!looks_like_tls_client_hello(b"\x16\x03\x02"), "0x0302 is not one of the two");
    }

    #[test]
    fn http_transport_leg_is_recognised() {
        for probe in [
            &b"GET /api HTTP/1.1"[..],
            &b"POST /x HTTP/1.1"[..],
            &b"HEAD / HTTP/1.1"[..],
            &b"PUT / HTTP/1.1"[..],
            &b"OPTIONS * HTTP/1.1"[..],
        ] {
            assert!(looks_like_http_request(probe), "{probe:?}");
        }
    }

    #[test]
    fn http_sniff_needs_the_trailing_space() {
        // "GETX" is not a request line, and the space is what tells them apart.
        assert!(!looks_like_http_request(b"GETX /"));
        assert!(!looks_like_http_request(b""));
        assert!(!looks_like_http_request(b"\x16\x03\x01"));
    }

    #[test]
    fn first_byte_dispatch_matches_the_listener() {
        assert_eq!(classify_client(Some(0x05)), Some(ClientProtocol::Socks5));
        assert_eq!(classify_client(Some(b'C')), Some(ClientProtocol::HttpConnect));
        assert_eq!(classify_client(Some(b'G')), Some(ClientProtocol::HttpConnect));
    }

    #[test]
    fn g21_garbage_is_refused_rather_than_left_to_the_timeout() {
        // Lowercase is not a method start; neither is a stray binary byte.
        assert_eq!(classify_client(Some(b'c')), Some(ClientProtocol::Unsupported));
        assert_eq!(classify_client(Some(0x04)), Some(ClientProtocol::Unsupported));
        assert_eq!(classify_client(Some(0xFF)), Some(ClientProtocol::Unsupported));
        assert_eq!(classify_client(Some(b'0')), Some(ClientProtocol::Unsupported));
    }

    #[test]
    fn nothing_read_yet_is_distinct_from_unsupported() {
        assert_eq!(classify_client(None), None);
    }
}
