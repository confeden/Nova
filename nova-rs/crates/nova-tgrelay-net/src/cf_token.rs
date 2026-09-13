//! The signed subprotocol entry the owner's Worker checks.
//!
//! Layer 16. Ports `config.build_cf_ws_token` and `cf_ws_subprotocol_header`.
//!
//! **What the signature is for.** The Worker is reachable by anyone who knows
//! its hostname, and without a token it is an open proxy with the owner's name
//! on it. The token is an HMAC over `"<window>|<hostname>"`, so it is bound both
//! to a two-minute window — a captured one stops working within minutes — and to
//! the exact subdomain it was minted for, which stops one being replayed against
//! another.
//!
//! **The secret is a parameter and nothing else.** It is never read, cached or
//! logged here: loading it (env, then a key file beside the package) belongs to
//! whatever owns configuration, and keeping it off this module's surface is what
//! makes it hard to leak into a log line by accident. `Debug` is not derived on
//! anything that holds it.

use hmac::{Hmac, KeyInit, Mac};
use nova_tgrelay::persona::DEFLATE_OFFER;
use sha2::Sha256;

/// `CF_WS_TOKEN_VERSION`. Changing it invalidates every token at once, which is
/// the point of having it.
pub const TOKEN_VERSION: &str = "nova1";
/// `CF_WS_TOKEN_WINDOW`, in seconds.
pub const TOKEN_WINDOW_SECS: u64 = 120;
/// How much of the hex digest travels. Half a SHA-256 is far more than a replay
/// window this short needs.
pub const DIGEST_HEX_LEN: usize = 32;
/// The subprotocol every request carries, signed or not.
pub const BASE_SUBPROTOCOL: &str = "binary";

/// The window a timestamp falls in.
///
/// Unix seconds divided by the window, floored — so a token minted at the end of
/// a window is valid for whatever is left of it and no longer.
pub fn window_of(unix_seconds: u64) -> u64 {
    unix_seconds / TOKEN_WINDOW_SECS
}

/// The signed entry for `host`, or `None` when the host is not one of ours.
///
/// `owned` is the caller's answer to "is this a zone we control": a token minted
/// for somebody else's Worker is at best noise and at worst a fingerprint.
pub fn build_token(host: &str, unix_seconds: u64, secret: &[u8], owned: bool) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if !owned || host.is_empty() {
        return None;
    }
    let window = window_of(unix_seconds);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes a key of any length");
    // The host is inside the message, not just the key: that is what stops a
    // token minted for `kws2.` being replayed against `kws5-1.`.
    mac.update(format!("{window}|{host}").as_bytes());
    let digest: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>()
        [..DIGEST_HEX_LEN]
        .to_string();
    Some(format!("{TOKEN_VERSION}.{window}.{digest}"))
}

/// The `Sec-WebSocket-Protocol` value: always `binary`, signed when ours.
pub fn subprotocol_header(host: &str, unix_seconds: u64, secret: &[u8], owned: bool) -> String {
    match build_token(host, unix_seconds, secret, owned) {
        Some(token) => format!("{BASE_SUBPROTOCOL}, {token}"),
        None => BASE_SUBPROTOCOL.to_string(),
    }
}

/// Re-exported so a caller building an upgrade request has both halves of the
/// persona in one place.
pub const DEFLATE: &str = DEFLATE_OFFER;

#[cfg(test)]
mod tests {
    use super::*;

    /// The fallback that ships in the published source. **Not the owner's.** A
    /// clone of the repository produces well-formed tokens with this; they just
    /// do not match the secret configured on the live Worker.
    const PUBLIC_FALLBACK: &[u8] = b"nova-public-fallback";

    #[test]
    fn it_matches_the_tokens_the_python_mints() {
        // Produced by running the same HMAC with the published fallback secret.
        let cases = [
            ("kws2.nova-app.eu", 1_700_000_000u64, "nova1.14166666.ae4e3e7a9df3df46c523f93654eb5e32"),
            ("kws5-1.nova-app.eu", 1_700_000_000, "nova1.14166666.1f1f28ce0378dfc29cbae45e42fa73dc"),
            ("www.nova-app.eu", 1_700_000_000, "nova1.14166666.f520695e91e1ce58aaf7162bdd09fac2"),
            ("kws2.nova-app.eu", 1_700_000_119, "nova1.14166667.902dfced87610cfb189613008ff1b763"),
        ];
        for (host, now, expected) in cases {
            assert_eq!(build_token(host, now, PUBLIC_FALLBACK, true).as_deref(), Some(expected), "{host} {now}");
        }
    }

    #[test]
    fn one_subdomain_cannot_replay_anothers_token() {
        // The host is in the message for exactly this reason.
        let a = build_token("kws2.nova-app.eu", 1_700_000_000, PUBLIC_FALLBACK, true);
        let b = build_token("kws5-1.nova-app.eu", 1_700_000_000, PUBLIC_FALLBACK, true);
        assert_ne!(a, b);
        // Same window, so only the digest differs.
        assert!(a.as_deref().expect("token").starts_with("nova1.14166666."));
        assert!(b.as_deref().expect("token").starts_with("nova1.14166666."));
    }

    #[test]
    fn a_captured_token_stops_working_within_two_minutes() {
        let inside = build_token("kws2.nova-app.eu", 1_700_000_039, PUBLIC_FALLBACK, true);
        let after = build_token("kws2.nova-app.eu", 1_700_000_040, PUBLIC_FALLBACK, true);
        assert_ne!(inside, after, "the window turned over");
        assert_eq!(window_of(1_700_000_039), 14_166_666);
        assert_eq!(window_of(1_700_000_040), 14_166_667, "the boundary is a multiple of 120");
        // And it is stable everywhere inside a window.
        assert_eq!(
            build_token("kws2.nova-app.eu", 1_700_000_040, PUBLIC_FALLBACK, true),
            build_token("kws2.nova-app.eu", 1_700_000_159, PUBLIC_FALLBACK, true),
        );
    }

    #[test]
    fn a_different_secret_gives_a_different_token() {
        assert_ne!(
            build_token("kws2.nova-app.eu", 1_700_000_000, PUBLIC_FALLBACK, true),
            build_token("kws2.nova-app.eu", 1_700_000_000, b"another-secret", true),
        );
    }

    #[test]
    fn a_host_that_is_not_ours_is_never_signed() {
        // A token minted for somebody else's Worker is at best noise and at
        // worst a fingerprint.
        assert_eq!(build_token("kws2.pclead.co.uk", 1_700_000_000, PUBLIC_FALLBACK, false), None);
        assert_eq!(build_token("", 1_700_000_000, PUBLIC_FALLBACK, true), None);
        assert_eq!(build_token("   ", 1_700_000_000, PUBLIC_FALLBACK, true), None);
    }

    #[test]
    fn the_host_is_normalised_the_way_the_python_normalises_it() {
        // Trailing dot stripped, case folded — otherwise the Worker recomputes
        // the HMAC over a different string and refuses a valid request.
        let plain = build_token("kws2.nova-app.eu", 1_700_000_000, PUBLIC_FALLBACK, true);
        for variant in ["KWS2.Nova-App.eu", " kws2.nova-app.eu ", "kws2.nova-app.eu."] {
            assert_eq!(build_token(variant, 1_700_000_000, PUBLIC_FALLBACK, true), plain, "{variant}");
        }
    }

    #[test]
    fn the_subprotocol_is_binary_signed_or_not() {
        assert_eq!(
            subprotocol_header("kws2.nova-app.eu", 1_700_000_000, PUBLIC_FALLBACK, true),
            "binary, nova1.14166666.ae4e3e7a9df3df46c523f93654eb5e32"
        );
        assert_eq!(
            subprotocol_header("kws2.pclead.co.uk", 1_700_000_000, PUBLIC_FALLBACK, false),
            "binary",
            "an unsigned request still asks for the same subprotocol"
        );
    }

    #[test]
    fn the_digest_is_exactly_half_a_sha256_in_hex() {
        let token = build_token("kws2.nova-app.eu", 1_700_000_000, PUBLIC_FALLBACK, true).expect("token");
        let digest = token.rsplit('.').next().expect("digest");
        assert_eq!(digest.len(), DIGEST_HEX_LEN);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn the_hmac_underneath_is_the_real_one() {
        // RFC 4231 test case 1, so a broken HMAC cannot pass by being merely
        // self-consistent with the vectors above.
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0x0b; 20]).expect("key");
        mac.update(b"Hi There");
        let hex: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }
}
