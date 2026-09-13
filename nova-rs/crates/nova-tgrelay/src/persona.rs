//! What Nova looks like on the wire, and the WebSocket upgrade it sends.
//!
//! Layer 13 of the port. The I/O-free half of `_connect_websocket_once`
//! (`transparent_relay.py:1158`) plus all of `tgrelay/persona.py`: the header
//! sets, the request they build, and what a reply has to say before the tunnel
//! is allowed to carry anything.
//!
//! **Header order is not cosmetic.** Two things have to agree about which client
//! Nova is pretending to be — the shape of the ClientHello and the HTTP request
//! carried inside it — and a request whose headers are in an order no browser
//! uses is a tell on its own. The order below is reproduced exactly, and a test
//! pins the whole request byte for byte against what the Python emits.
//!
//! **The compression offer is made and then refused.** Every browser offers
//! `permessage-deflate`, and its absence is the kind of detail an endpoint can
//! notice. But nothing downstream can inflate a deflated frame, so a server that
//! takes us up on it is refused rather than misread — see [`judge`], and the
//! reserved-bit guard in [`crate::wsframe`] that catches the same thing one layer
//! down.

use std::collections::BTreeMap;

/// The header values that name a browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Persona {
    pub name: &'static str,
    pub user_agent: &'static str,
    pub accept_language: &'static str,
    pub accept_encoding: &'static str,
}

/// Measured, not composed: the headers Yandex Browser 26.6 (Chromium 148) sent
/// to a local listener on the owner's machine — the same build whose ClientHello
/// became `nova-tls/profiles/yandex-windows.json`. Both halves therefore name
/// one browser, which is the entire point. Refresh them together.
pub const YANDEX_WINDOWS: Persona = Persona {
    name: "yandex-windows",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/148.0.0.0 YaBrowser/26.6.0.0 Safari/537.36",
    accept_language: "ru,en;q=0.9",
    // `zstd` is in the real list. Dropping it to match an older guess would be a
    // difference from the browser for no reason.
    accept_encoding: "gzip, deflate, br, zstd",
};

/// Deliberately the string that was already in the code. Bumping it to a
/// plausible-looking newer release would be inventing a measurement: a user
/// agent naming a build that never shipped is a worse tell than a stale one.
pub const CHROME_WINDOWS: Persona = Persona {
    name: "chrome-windows",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/131.0.0.0 Safari/537.36",
    accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    accept_encoding: "gzip, deflate, br",
};

/// The shaped handshake emits `yandex-windows`, and the two layers must name the
/// same browser or the pairing is a tell in itself.
pub const DEFAULT_PERSONA: Persona = YANDEX_WINDOWS;

pub const ALL_PERSONAS: [Persona; 2] = [YANDEX_WINDOWS, CHROME_WINDOWS];

/// An unknown name falls back to the default rather than failing.
///
/// This is driven by learned state read off disk, and a stale name in a config
/// file should degrade quietly rather than stop Telegram from connecting.
pub fn persona_by_name(name: &str) -> Persona {
    let wanted = name.trim().to_ascii_lowercase();
    ALL_PERSONAS.into_iter().find(|p| p.name == wanted).unwrap_or(DEFAULT_PERSONA)
}

/// What every browser offers, and what this client cannot actually perform.
pub const DEFLATE_OFFER: &str = "permessage-deflate; client_max_window_bits";
/// The `Origin` a Telegram Web client would send.
pub const DEFAULT_ORIGIN: &str = "https://web.telegram.org";

/// The WebSocket upgrade request.
///
/// `host` names the route and must stay the real endpoint name: on the
/// Cloudflare path it is the `Host` header, not the SNI, that decides which
/// Worker answers.
pub fn upgrade_request(
    path: &str,
    host: &str,
    ws_key: &str,
    subprotocol: &str,
    origin: &str,
    offer_deflate: bool,
    persona: Persona,
) -> Vec<u8> {
    let mut lines = vec![
        format!("GET {path} HTTP/1.1"),
        format!("Host: {host}"),
        "Connection: Upgrade".to_string(),
        "Pragma: no-cache".to_string(),
        "Cache-Control: no-cache".to_string(),
        format!("User-Agent: {}", persona.user_agent),
        "Upgrade: websocket".to_string(),
        format!("Origin: {origin}"),
        "Sec-WebSocket-Version: 13".to_string(),
        format!("Accept-Encoding: {}", persona.accept_encoding),
        format!("Accept-Language: {}", persona.accept_language),
        format!("Sec-WebSocket-Key: {ws_key}"),
    ];
    if offer_deflate {
        lines.push(format!("Sec-WebSocket-Extensions: {DEFLATE_OFFER}"));
    }
    lines.push(format!("Sec-WebSocket-Protocol: {subprotocol}"));
    let mut out = lines.join("\r\n").into_bytes();
    out.extend_from_slice(b"\r\n\r\n");
    out
}

/// A parsed upgrade reply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpgradeResponse {
    /// `0` when the status line carried no readable number.
    pub status: u16,
    pub status_line: String,
    /// Lower-cased names; a value keeps its own colons.
    pub headers: BTreeMap<String, String>,
}

impl UpgradeResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    /// The server's proof that it really performed the handshake.
    ///
    /// **Not verified anywhere yet, in either language, and that is a gap worth
    /// knowing about.** RFC 6455 has the client check this against
    /// `base64(sha1(key + GUID))`; the Python never looks at it, so anything that
    /// answers `101` is treated as a WebSocket endpoint. On a path whose whole
    /// premise is that somebody may be interfering, "did the peer actually do the
    /// handshake" is a question worth asking. Verifying it needs SHA-1, which is
    /// why it is not done in this dependency-free crate.
    pub fn accept(&self) -> Option<&str> {
        self.header("sec-websocket-accept")
    }
}

/// Split header lines into a status and a map.
///
/// Tolerant on purpose: an endpoint that answers junk should produce a status of
/// `0` and a usable log line, not a parse error that hides what it said.
pub fn parse_response(lines: &[&str]) -> UpgradeResponse {
    let Some((status_line, rest)) = lines.split_first() else {
        return UpgradeResponse::default();
    };
    let status = status_line.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut headers = BTreeMap::new();
    for line in rest {
        // Split on the *first* colon only: a `Location` value contains colons of
        // its own and truncating one would send a redirect to the wrong place.
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    UpgradeResponse { status, status_line: (*status_line).to_string(), headers }
}

/// Whether the tunnel may carry anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeVerdict {
    /// `101`, and nothing was negotiated that this client cannot honour.
    Accepted,
    /// The peer said nothing at all.
    Empty,
    /// Anything other than `101`. `location` is carried because a redirect is
    /// the one status the caller can act on rather than just log.
    Refused { status: u16, status_line: String, location: Option<String> },
    /// `101`, but the server accepted the compression offer. Every frame from
    /// here on arrives deflated and nothing downstream can inflate it, so the
    /// attempt fails and the offer is withdrawn for that endpoint.
    DeflateNegotiated,
}

pub fn judge(response: &UpgradeResponse) -> UpgradeVerdict {
    if response.status_line.is_empty() && response.headers.is_empty() {
        return UpgradeVerdict::Empty;
    }
    if response.status != 101 {
        return UpgradeVerdict::Refused {
            status: response.status,
            status_line: response.status_line.clone(),
            location: response.header("location").map(str::to_string),
        };
    }
    let negotiated = response.header("sec-websocket-extensions").unwrap_or("").to_ascii_lowercase();
    if negotiated.contains("permessage-deflate") {
        return UpgradeVerdict::DeflateNegotiated;
    }
    UpgradeVerdict::Accepted
}

/// The statuses the Python treats as a redirect worth following.
pub const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

pub fn is_redirect(status: u16) -> bool {
    REDIRECT_STATUSES.contains(&status)
}

/// Where the sixteen random bytes of `Sec-WebSocket-Key` come from.
///
/// Injectable so a test can pin the exact request bytes. The field used to hold
/// a millisecond clock and a performance counter, which is both guessable and a
/// pattern repeating across every connection Nova opens — the opposite of what
/// the field is for.
pub trait WsKeySource {
    fn next_key(&mut self) -> [u8; 16];
}

/// A fixed key. **Tests only.**
#[derive(Debug, Clone, Copy)]
pub struct FixedWsKey(pub [u8; 16]);

impl WsKeySource for FixedWsKey {
    fn next_key(&mut self) -> [u8; 16] {
        self.0
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
///
/// Written out rather than taken as a dependency, because this crate is
/// deliberately dependency-free and base64 is an encoding, not cryptography: a
/// mistake in it makes the server reject the handshake outright, which is a
/// failure that announces itself. The RFC 4648 vectors are asserted below.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(BASE64[(n >> 18) as usize & 63] as char);
        out.push(BASE64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { BASE64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { BASE64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// The value of `Sec-WebSocket-Key`: sixteen random bytes, base64'd.
pub fn ws_key(source: &mut impl WsKeySource) -> String {
    base64_encode(&source.next_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_KEY: FixedWsKey = FixedWsKey([0u8; 16]);

    fn request(offer_deflate: bool, persona: Persona) -> Vec<u8> {
        let mut source = ZERO_KEY;
        upgrade_request(
            "/apiws",
            "kws2.nova-app.eu",
            &ws_key(&mut source),
            "sub-token-here",
            DEFAULT_ORIGIN,
            offer_deflate,
            persona,
        )
    }

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected, "{input:?}");
        }
    }

    #[test]
    fn sixteen_zero_bytes_encode_the_way_the_python_printed_them() {
        let mut source = ZERO_KEY;
        assert_eq!(ws_key(&mut source), "AAAAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(ws_key(&mut source).len(), 24, "RFC 6455 wants exactly this width");
    }

    #[test]
    fn the_default_request_is_byte_for_byte_what_the_python_emits() {
        // Captured by running `persona.upgrade_request` with the same arguments.
        let expected = concat!(
            "GET /apiws HTTP/1.1\r\n",
            "Host: kws2.nova-app.eu\r\n",
            "Connection: Upgrade\r\n",
            "Pragma: no-cache\r\n",
            "Cache-Control: no-cache\r\n",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ",
            "(KHTML, like Gecko) Chrome/148.0.0.0 YaBrowser/26.6.0.0 Safari/537.36\r\n",
            "Upgrade: websocket\r\n",
            "Origin: https://web.telegram.org\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Accept-Encoding: gzip, deflate, br, zstd\r\n",
            "Accept-Language: ru,en;q=0.9\r\n",
            "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n",
            "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n",
            "Sec-WebSocket-Protocol: sub-token-here\r\n\r\n",
        );
        assert_eq!(String::from_utf8(request(true, DEFAULT_PERSONA)).expect("ascii"), expected);
    }

    #[test]
    fn every_profile_and_offer_matches_the_length_the_python_reported() {
        // Lengths, not just the default request: the header *order* is the
        // fingerprint, and an off-by-one line would still parse.
        assert_eq!(request(true, YANDEX_WINDOWS).len(), 563);
        assert_eq!(request(false, YANDEX_WINDOWS).len(), 493);
        assert_eq!(request(true, CHROME_WINDOWS).len(), 562);
        assert_eq!(request(false, CHROME_WINDOWS).len(), 492);
    }

    #[test]
    fn withdrawing_the_offer_removes_exactly_one_header() {
        let with = String::from_utf8(request(true, DEFAULT_PERSONA)).expect("ascii");
        let without = String::from_utf8(request(false, DEFAULT_PERSONA)).expect("ascii");
        assert!(with.contains("Sec-WebSocket-Extensions: permessage-deflate"));
        assert!(!without.contains("Sec-WebSocket-Extensions"));
        // And the protocol header stays last either way — the order is the point.
        assert!(with.ends_with("Sec-WebSocket-Protocol: sub-token-here\r\n\r\n"));
        assert!(without.ends_with("Sec-WebSocket-Protocol: sub-token-here\r\n\r\n"));
    }

    #[test]
    fn an_unknown_persona_degrades_to_the_default() {
        assert_eq!(persona_by_name("Yandex-Windows"), YANDEX_WINDOWS);
        assert_eq!(persona_by_name("chrome-windows"), CHROME_WINDOWS);
        assert_eq!(persona_by_name("firefox-haiku"), DEFAULT_PERSONA);
        assert_eq!(persona_by_name(""), DEFAULT_PERSONA);
    }

    #[test]
    fn the_two_layers_name_the_same_browser() {
        // The shaped ClientHello is `yandex-windows`. If the default here ever
        // stops matching it, the pairing becomes a tell in itself.
        assert_eq!(DEFAULT_PERSONA.name, "yandex-windows");
    }

    #[test]
    fn the_status_line_is_read_the_way_the_python_reads_it() {
        for (lines, status) in [
            (vec![], 0u16),
            (vec!["HTTP/1.1 101 Switching Protocols"], 101),
            (vec!["HTTP/1.1 403 Forbidden"], 403),
            (vec!["garbage"], 0),
            (vec!["HTTP/1.1 notanumber Bad"], 0),
            (vec!["HTTP/1.1"], 0),
        ] {
            assert_eq!(parse_response(&lines).status, status, "{lines:?}");
        }
    }

    #[test]
    fn headers_are_lower_cased_trimmed_and_keep_their_own_colons() {
        let parsed = parse_response(&[
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "  Connection : Upgrade ",
            "nocolon",
            "Location: https://example.test:8443/x",
        ]);
        assert_eq!(parsed.header("upgrade"), Some("websocket"));
        assert_eq!(parsed.header("CONNECTION"), Some("Upgrade"));
        assert_eq!(parsed.header("nocolon"), None, "a line without a colon is not a header");
        assert_eq!(parsed.header("location"), Some("https://example.test:8443/x"));
    }

    #[test]
    fn a_clean_101_is_accepted() {
        let parsed = parse_response(&["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket"]);
        assert_eq!(judge(&parsed), UpgradeVerdict::Accepted);
    }

    #[test]
    fn a_101_that_negotiated_deflate_is_refused_rather_than_misread() {
        // The whole reason the offer is checked: every frame after this arrives
        // deflated, and the frame reader would hand the compressed bytes on as
        // though they were MTProto.
        for value in ["permessage-deflate", "PerMessage-Deflate; client_max_window_bits=15"] {
            let parsed = parse_response(&[
                "HTTP/1.1 101 Switching Protocols",
                &format!("Sec-WebSocket-Extensions: {value}"),
            ]);
            assert_eq!(judge(&parsed), UpgradeVerdict::DeflateNegotiated, "{value}");
        }
        // A different extension is not this one.
        let other = parse_response(&[
            "HTTP/1.1 101 Switching Protocols",
            "Sec-WebSocket-Extensions: x-webkit-deflate-frame",
        ]);
        assert_eq!(judge(&other), UpgradeVerdict::Accepted);
    }

    #[test]
    fn a_redirect_carries_its_location_out() {
        let parsed = parse_response(&["HTTP/1.1 302 Found", "Location: https://elsewhere.test/apiws"]);
        assert_eq!(
            judge(&parsed),
            UpgradeVerdict::Refused {
                status: 302,
                status_line: "HTTP/1.1 302 Found".to_string(),
                location: Some("https://elsewhere.test/apiws".to_string()),
            }
        );
        assert!(is_redirect(302) && is_redirect(308));
        assert!(!is_redirect(403) && !is_redirect(101));
    }

    #[test]
    fn silence_is_its_own_verdict() {
        assert_eq!(judge(&parse_response(&[])), UpgradeVerdict::Empty);
        // A status line of junk is *not* silence — the peer said something, and
        // what it said belongs in the log.
        assert!(matches!(judge(&parse_response(&["garbage"])), UpgradeVerdict::Refused { status: 0, .. }));
    }

    #[test]
    fn the_accept_header_is_readable_even_though_nobody_checks_it() {
        let parsed = parse_response(&[
            "HTTP/1.1 101 Switching Protocols",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        ]);
        assert_eq!(parsed.accept(), Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        // And its absence is not currently a refusal, which is the gap the
        // doc comment on `accept()` describes.
        let without = parse_response(&["HTTP/1.1 101 Switching Protocols"]);
        assert_eq!(without.accept(), None);
        assert_eq!(judge(&without), UpgradeVerdict::Accepted);
    }
}
