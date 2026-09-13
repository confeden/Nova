//! Checking that the peer really performed the WebSocket handshake.
//!
//! **An addition, not a port.** RFC 6455 §4.2.2 has the client verify
//! `Sec-WebSocket-Accept` against `base64(sha1(key + GUID))`; the Python never
//! looks at it, so anything that answers `101` is treated as a WebSocket
//! endpoint and framing starts against it. On a path whose entire premise is
//! that somebody may be sitting in the middle, "did the peer actually do the
//! handshake" is a question worth asking — it is the same class of check as the
//! reserved-bit guard in [`nova_tgrelay::wsframe`], which exists because
//! *accepting* something we cannot interpret corrupts silently.
//!
//! It lives here rather than in `nova-tgrelay` because it needs SHA-1 and that
//! crate is deliberately dependency-free.
//!
//! **The verdict is returned, not enforced.** The caller decides what a wrong
//! `Accept` means, because this is behaviour the shipped relay does not have and
//! turning it into a refusal is a decision about live traffic, not about a port.
//! Backing it out is deleting this module and one dependency.

use nova_core::BlockSignature;
use nova_tgrelay::persona::{base64_encode, UpgradeResponse};
use nova_tgrelay::sni::{is_name_refusal, SniFailure};
use sha1::{Digest, Sha1};

/// The constant RFC 6455 §1.3 appends to the key before hashing. It exists so
/// that a server which merely echoes the request cannot pass for one that
/// understood it.
pub const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// What a well-behaved server must return for this `Sec-WebSocket-Key`.
pub fn expected_accept(ws_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(ws_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64_encode(&hasher.finalize())
}

/// Whether the peer proved it did the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptCheck {
    Correct,
    /// No `Sec-WebSocket-Accept` header at all. A conforming server always sends
    /// one, so its absence means the `101` came from something that is not
    /// speaking RFC 6455.
    Missing,
    /// Present and wrong — the strongest signal of the three, because it takes
    /// deliberate effort to answer `101` with a header that is not derived from
    /// the key that was sent.
    Wrong {
        got: String,
        expected: String,
    },
}

impl AcceptCheck {
    pub fn is_correct(&self) -> bool {
        matches!(self, Self::Correct)
    }

    /// A line for the log, or `None` when there is nothing to say.
    pub fn complaint(&self) -> Option<String> {
        match self {
            Self::Correct => None,
            Self::Missing => Some("[TgRelay] WSS upgrade answered 101 without Sec-WebSocket-Accept".to_string()),
            Self::Wrong { got, expected } => Some(format!(
                "[TgRelay] WSS upgrade answered 101 with Sec-WebSocket-Accept {got}, expected {expected}"
            )),
        }
    }
}

pub fn check_accept(response: &UpgradeResponse, ws_key: &str) -> AcceptCheck {
    let expected = expected_accept(ws_key);
    match response.accept() {
        None => AcceptCheck::Missing,
        // Compared as given: the value is base64 and case is significant in it,
        // so a case-insensitive compare would accept a header no conforming
        // server would send.
        Some(got) if got == expected => AcceptCheck::Correct,
        Some(got) => AcceptCheck::Wrong { got: got.to_string(), expected },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_tgrelay::persona::parse_response;

    /// The example worked through in RFC 6455 §1.3, verbatim.
    const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const RFC_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    #[test]
    fn it_reproduces_the_worked_example_from_the_rfc() {
        assert_eq!(expected_accept(RFC_KEY), RFC_ACCEPT);
    }

    #[test]
    fn a_different_key_gives_a_different_accept() {
        // Otherwise the check would pass for a server replaying somebody else's
        // handshake, which is most of what it is for.
        assert_ne!(expected_accept("AAAAAAAAAAAAAAAAAAAAAA=="), RFC_ACCEPT);
        assert_eq!(
            expected_accept("AAAAAAAAAAAAAAAAAAAAAA==").len(),
            RFC_ACCEPT.len(),
            "a base64 SHA-1 is always 28 characters"
        );
    }

    #[test]
    fn a_conforming_server_passes() {
        let response = parse_response(&[
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            &format!("Sec-WebSocket-Accept: {RFC_ACCEPT}"),
        ]);
        let check = check_accept(&response, RFC_KEY);
        assert!(check.is_correct());
        assert_eq!(check.complaint(), None);
    }

    #[test]
    fn a_101_with_no_accept_header_is_named() {
        let response = parse_response(&["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket"]);
        let check = check_accept(&response, RFC_KEY);
        assert_eq!(check, AcceptCheck::Missing);
        assert!(check.complaint().expect("a complaint").contains("without Sec-WebSocket-Accept"));
    }

    #[test]
    fn an_accept_derived_from_the_wrong_key_is_named_with_both_values() {
        let response = parse_response(&[
            "HTTP/1.1 101 Switching Protocols",
            &format!("Sec-WebSocket-Accept: {}", expected_accept("AAAAAAAAAAAAAAAAAAAAAA==")),
        ]);
        let check = check_accept(&response, RFC_KEY);
        assert!(matches!(check, AcceptCheck::Wrong { .. }));
        let complaint = check.complaint().expect("a complaint");
        assert!(complaint.contains("expected s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{complaint}");
    }

    #[test]
    fn the_comparison_is_case_sensitive() {
        // Base64 is case-significant. Folding case here would accept a value no
        // conforming server would ever send.
        let response = parse_response(&[
            "HTTP/1.1 101 Switching Protocols",
            &format!("Sec-WebSocket-Accept: {}", RFC_ACCEPT.to_lowercase()),
        ]);
        assert!(matches!(check_accept(&response, RFC_KEY), AcceptCheck::Wrong { .. }));
    }
}

/// Map a classified failure onto the only question the SNI decision asks.
///
/// The three shapes are `nova_tgrelay::sni::SniFailure`; this is the mapping the
/// Python spells out inline in `_note_sni_verdict`, and it is short because the
/// hard part — *which* failures could be the name's fault — is already settled
/// by the shared signature table.
///
/// - The hello going unanswered, or a certificate that did not match the name we
///   offered, is the one window where that name is still a suspect.
/// - `403` and `421` are what a CDN says when it does not accept the name it was
///   given for the host that was asked for.
/// - Everything else happened before the name was on the wire or after it had
///   already been accepted.
pub fn sni_failure(signature: BlockSignature, http_status: Option<u16>) -> SniFailure {
    if signature.wants_tls_profile_change() || signature == BlockSignature::TlsCertificateMismatch {
        return SniFailure::HelloUnanswered;
    }
    match http_status {
        Some(status) if is_name_refusal(status) => SniFailure::NameRefused,
        _ => SniFailure::Unrelated,
    }
}

#[cfg(test)]
mod sni_tests {
    use super::*;

    #[test]
    fn an_unanswered_hello_puts_the_name_under_suspicion() {
        assert_eq!(
            sni_failure(BlockSignature::TunnelHandshakeIgnored, None),
            SniFailure::HelloUnanswered
        );
        assert!(BlockSignature::TunnelHandshakeIgnored.wants_tls_profile_change(), "precondition");
    }

    #[test]
    fn a_certificate_that_did_not_match_the_name_counts_too() {
        // It is literally a complaint about the name that was offered.
        assert_eq!(
            sni_failure(BlockSignature::TlsCertificateMismatch, None),
            SniFailure::HelloUnanswered
        );
    }

    #[test]
    fn the_two_cdn_refusal_statuses_are_the_other_shape() {
        assert_eq!(sni_failure(BlockSignature::TunnelUpgradeRejected, Some(403)), SniFailure::NameRefused);
        assert_eq!(sni_failure(BlockSignature::TunnelUpgradeRejected, Some(421)), SniFailure::NameRefused);
    }

    #[test]
    fn a_429_is_proof_the_route_was_reached_not_a_name_refusal() {
        // The Worker's exhausted daily quota. Retiring the substitution on the
        // one status that proves it works would be exactly backwards.
        assert_eq!(sni_failure(BlockSignature::TunnelUpgradeRejected, Some(429)), SniFailure::Unrelated);
    }

    #[test]
    fn failures_on_either_side_of_the_name_leave_it_alone() {
        for signature in [
            BlockSignature::Blackholed,      // before the name was on the wire
            BlockSignature::ConnectionRefused,
            BlockSignature::TunnelStalled,   // after it had been accepted
            BlockSignature::TunnelSevered,
        ] {
            assert_eq!(sni_failure(signature, None), SniFailure::Unrelated, "{signature:?}");
        }
    }

    #[test]
    fn the_mapping_composes_with_the_rule_it_feeds() {
        // End to end: a substituted name, an unanswered hello, and the zone goes
        // back to its literal name.
        let failure = sni_failure(BlockSignature::TunnelHandshakeIgnored, None);
        assert!(nova_tgrelay::sni::retires_substitution("www.nova-app.eu", "kws2.nova-app.eu", failure));
        // …and the same failure on a connection that never substituted anything
        // changes nothing.
        assert!(!nova_tgrelay::sni::retires_substitution("kws2.nova-app.eu", "kws2.nova-app.eu", failure));
    }
}
