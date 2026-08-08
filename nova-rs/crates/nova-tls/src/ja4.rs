//! Reading a ClientHello the way a filtering network reads it.
//!
//! Every claim about "looking like a browser" is unverifiable without this.
//! Shaping a handshake and then asserting it worked because a connection
//! succeeded proves nothing — the connection might have succeeded anyway. So
//! the shaping work starts here, with the measurement, and the measurement runs
//! offline against ClientHellos captured from real browsers that already sit in
//! this repository under `fake/`.
//!
//! JA4 is the fingerprint in question: a short string over the version, the
//! cipher list, the extension list and the signature algorithms, with GREASE
//! removed so that a browser deliberately randomising those values still
//! produces one stable identity.
//!
//! Nothing here does I/O. Bytes in, fingerprint out.

use sha2::{Digest, Sha256};

/// What went wrong while reading a ClientHello.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Ja4Error {
    #[error("buffer ends mid-structure: wanted {wanted} bytes at offset {at}, {available} left")]
    Truncated { at: usize, wanted: usize, available: usize },
    #[error("not a TLS handshake record (first byte {0:#04x}, expected 0x16)")]
    NotHandshake(u8),
    #[error("not a ClientHello (handshake type {0:#04x}, expected 0x01)")]
    NotClientHello(u8),
}

/// GREASE values, which a client sends precisely so that nobody treats them as
/// meaningful. Counting them would make an intentionally random value part of
/// the identity, which is the one thing a fingerprint must never do.
///
/// All sixteen share the pattern `0x?a?a` with both bytes equal.
pub fn is_grease(value: u16) -> bool {
    let [hi, lo] = value.to_be_bytes();
    hi == lo && (hi & 0x0f) == 0x0a
}

/// The parts of a ClientHello that JA4 is computed from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHello {
    /// Highest version offered, from `supported_versions` when present and from
    /// the legacy field otherwise.
    pub version: u16,
    /// True when a `server_name` extension is present.
    pub has_sni: bool,
    /// Cipher suites in wire order, GREASE removed.
    pub ciphers: Vec<u16>,
    /// Extension types in wire order, GREASE removed.
    pub extensions: Vec<u16>,
    /// Signature algorithms in wire order, GREASE removed.
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocols in wire order.
    pub alpn: Vec<String>,
    /// Named groups in wire order, GREASE removed.
    pub groups: Vec<u16>,
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Ja4Error> {
        let available = self.buf.len().saturating_sub(self.at);
        if available < n {
            return Err(Ja4Error::Truncated { at: self.at, wanted: n, available });
        }
        let slice = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, Ja4Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Ja4Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<usize, Ja4Error> {
        let bytes = self.take(3)?;
        Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.at)
    }
}

fn u16_list(body: &[u8]) -> Vec<u16> {
    body.chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .filter(|value| !is_grease(*value))
        .collect()
}

/// Parse a ClientHello, with or without its enclosing TLS record header.
///
/// Both forms are accepted because both occur: bytes captured off the wire
/// arrive with the record header, and bytes handed over by a TLS library's
/// callback usually do not.
pub fn parse_client_hello(input: &[u8]) -> Result<ClientHello, Ja4Error> {
    let body = if input.first() == Some(&0x16) {
        let mut record = Reader::new(input);
        record.u8()?; // content type, already checked
        record.u16()?; // legacy record version, not the negotiated one
        let length = record.u16()? as usize;
        // Trust the shorter of the declared length and what is actually here:
        // a capture truncated mid-record should fail inside the handshake with
        // a useful offset, not immediately on the record header.
        let available = record.remaining();
        record.take(length.min(available))?
    } else {
        input
    };

    let mut r = Reader::new(body);
    let handshake_type = r.u8()?;
    if handshake_type != 0x01 {
        return Err(if input.first() == Some(&0x16) {
            Ja4Error::NotClientHello(handshake_type)
        } else if handshake_type == 0x16 {
            Ja4Error::NotHandshake(handshake_type)
        } else {
            Ja4Error::NotClientHello(handshake_type)
        });
    }
    r.u24()?; // handshake length

    let mut hello = ClientHello { version: r.u16()?, ..Default::default() };
    r.take(32)?; // random
    let session_id_len = r.u8()? as usize;
    r.take(session_id_len)?;

    let cipher_len = r.u16()? as usize;
    hello.ciphers = u16_list(r.take(cipher_len)?);

    let compression_len = r.u8()? as usize;
    r.take(compression_len)?;

    // Extensions are optional in the wire format even though every real client
    // sends them.
    if r.remaining() < 2 {
        return Ok(hello);
    }
    let extensions_len = r.u16()? as usize;
    let available = r.remaining();
    let extensions = r.take(extensions_len.min(available))?;

    let mut e = Reader::new(extensions);
    while e.remaining() >= 4 {
        let ext_type = e.u16()?;
        let ext_len = e.u16()? as usize;
        let available = e.remaining();
        let ext_body = e.take(ext_len.min(available))?;
        if is_grease(ext_type) {
            continue;
        }
        hello.extensions.push(ext_type);
        match ext_type {
            0x0000 => hello.has_sni = true,
            0x000a if ext_body.len() >= 2 => hello.groups = u16_list(&ext_body[2..]),
            0x000d if ext_body.len() >= 2 => hello.signature_algorithms = u16_list(&ext_body[2..]),
            0x0010 if ext_body.len() >= 2 => hello.alpn = parse_alpn(&ext_body[2..]),
            0x002b if !ext_body.is_empty() => {
                // supported_versions carries the real intent; the legacy field
                // has said 0x0303 for years regardless of what is offered.
                if let Some(best) = u16_list(&ext_body[1..]).into_iter().max() {
                    hello.version = best;
                }
            }
            _ => {}
        }
    }
    Ok(hello)
}

fn parse_alpn(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < body.len() {
        let len = body[at] as usize;
        at += 1;
        if at + len > body.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&body[at..at + len]).into_owned());
        at += len;
    }
    out
}

fn version_label(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn truncated_sha256(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    digest.iter().take(6).map(|byte| format!("{byte:02x}")).collect()
}

fn hex_list(values: &[u16]) -> String {
    values.iter().map(|value| format!("{value:04x}")).collect::<Vec<_>>().join(",")
}

impl ClientHello {
    /// The JA4 fingerprint string, `a_b_c`.
    pub fn ja4(&self) -> String {
        format!("{}_{}_{}", self.ja4_a(), self.ja4_b(), self.ja4_c())
    }

    /// Version, SNI presence, counts and ALPN — the human-readable part.
    ///
    /// Worth keeping separate: it is the half that can be compared by eye, and
    /// most of the ways a synthetic hello gives itself away (wrong count, no
    /// ALPN, no SNI) are visible here without touching a hash.
    pub fn ja4_a(&self) -> String {
        let alpn = match self.alpn.first() {
            Some(first) if !first.is_empty() => {
                let bytes = first.as_bytes();
                // First and last byte of the first protocol. `h2` gives "h2",
                // `http/1.1` gives "h1".
                format!("{}{}", bytes[0] as char, bytes[bytes.len() - 1] as char)
            }
            _ => "00".to_owned(),
        };
        format!(
            "t{}{}{:02}{:02}{}",
            version_label(self.version),
            if self.has_sni { "d" } else { "i" },
            self.ciphers.len().min(99),
            self.extensions.len().min(99),
            alpn,
        )
    }

    /// Hash over the cipher list, sorted.
    ///
    /// Sorted because a client is free to reorder its ciphers between
    /// connections without changing what it is.
    pub fn ja4_b(&self) -> String {
        let mut ciphers = self.ciphers.clone();
        ciphers.sort_unstable();
        truncated_sha256(&hex_list(&ciphers))
    }

    /// Hash over the extension list and the signature algorithms.
    ///
    /// The extension list is sorted and drops `server_name` and ALPN, both of
    /// which vary with the request rather than with the client. The signature
    /// algorithms keep their wire order — there the order is a property of the
    /// implementation.
    pub fn ja4_c(&self) -> String {
        let mut extensions: Vec<u16> =
            self.extensions.iter().copied().filter(|t| *t != 0x0000 && *t != 0x0010).collect();
        extensions.sort_unstable();
        truncated_sha256(&format!("{}_{}", hex_list(&extensions), hex_list(&self.signature_algorithms)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_is_recognised_by_pattern_not_by_table() {
        for value in [0x0a0au16, 0x1a1a, 0x2a2a, 0x8a8a, 0xdada, 0xfafa] {
            assert!(is_grease(value), "{value:#06x}");
        }
        for value in [0x1301u16, 0xc02b, 0x0000, 0x000d, 0x0a1a, 0x1a0a, 0xabab] {
            assert!(!is_grease(value), "{value:#06x}");
        }
    }

    /// A minimal but structurally valid ClientHello, built by hand so the
    /// expected fingerprint can be reasoned about rather than recorded.
    fn synthetic_hello(with_sni: bool) -> Vec<u8> {
        let mut ext = Vec::new();
        if with_sni {
            // server_name: one host_name entry, "a".
            ext.extend_from_slice(&[0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x01, b'a']);
        }
        // A GREASE extension, which must be ignored entirely.
        ext.extend_from_slice(&[0x1a, 0x1a, 0x00, 0x00]);
        // signature_algorithms: 0x0403, 0x0804.
        ext.extend_from_slice(&[0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);
        // ALPN: "h2".
        ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);
        // supported_versions: TLS 1.3 plus a GREASE value.
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x0a, 0x0a, 0x03, 0x04]);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // no session id
        body.extend_from_slice(&[0x00, 0x06]); // cipher list length
        body.extend_from_slice(&[0x1a, 0x1a, 0x13, 0x01, 0x13, 0x02]); // GREASE + two real
        body.extend_from_slice(&[0x01, 0x00]); // one compression method
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_a_hand_built_hello() {
        let hello = parse_client_hello(&synthetic_hello(true)).expect("parses");
        // GREASE removed from every list it appears in.
        assert_eq!(hello.ciphers, vec![0x1301, 0x1302]);
        assert!(!hello.extensions.contains(&0x1a1a));
        assert_eq!(hello.signature_algorithms, vec![0x0403, 0x0804]);
        assert_eq!(hello.alpn, vec!["h2".to_owned()]);
        assert!(hello.has_sni);
        // supported_versions wins over the legacy field.
        assert_eq!(hello.version, 0x0304);
    }

    #[test]
    fn the_readable_half_says_what_it_should() {
        let hello = parse_client_hello(&synthetic_hello(true)).expect("parses");
        // TLS 1.3, has SNI, 2 ciphers, 4 non-GREASE extensions, ALPN h2.
        assert_eq!(hello.ja4_a(), "t13d0204h2");
    }

    #[test]
    fn a_missing_sni_shows_up_as_a_different_fingerprint() {
        let with = parse_client_hello(&synthetic_hello(true)).expect("parses");
        let without = parse_client_hello(&synthetic_hello(false)).expect("parses");
        assert!(with.ja4_a().contains('d'));
        assert!(without.ja4_a().contains('i'));
        assert_ne!(with.ja4(), without.ja4());
        // …but only in the readable half: SNI is excluded from the hash on
        // purpose, because it varies per request rather than per client.
        assert_eq!(with.ja4_c(), without.ja4_c());
    }

    #[test]
    fn cipher_order_does_not_change_the_identity() {
        // A client may reorder its ciphers between connections without becoming
        // a different client.
        let a = ClientHello { ciphers: vec![0x1301, 0x1302, 0xc02b], ..Default::default() };
        let b = ClientHello { ciphers: vec![0xc02b, 0x1301, 0x1302], ..Default::default() };
        assert_eq!(a.ja4_b(), b.ja4_b());
    }

    #[test]
    fn signature_algorithm_order_does_change_it() {
        // Unlike ciphers, this order is a property of the implementation.
        let a = ClientHello { signature_algorithms: vec![0x0403, 0x0804], ..Default::default() };
        let b = ClientHello { signature_algorithms: vec![0x0804, 0x0403], ..Default::default() };
        assert_ne!(a.ja4_c(), b.ja4_c());
    }

    #[test]
    fn a_bare_handshake_without_a_record_header_also_parses() {
        let full = synthetic_hello(true);
        let bare = &full[5..];
        assert_eq!(parse_client_hello(&full).unwrap(), parse_client_hello(bare).unwrap());
    }

    #[test]
    fn truncation_is_reported_rather_than_guessed_at(
    ) {
        let full = synthetic_hello(true);
        // Every prefix either parses or says where it ran out. None may panic.
        for cut in 1..full.len() {
            let _ = parse_client_hello(&full[..cut]);
        }
        assert!(matches!(parse_client_hello(&full[..10]), Err(Ja4Error::Truncated { .. })));
    }

    #[test]
    fn something_that_is_not_a_clienthello_is_refused() {
        assert!(matches!(parse_client_hello(&[0x02, 0, 0, 0]), Err(Ja4Error::NotClientHello(0x02))));
        assert!(parse_client_hello(&[]).is_err());
    }
}
