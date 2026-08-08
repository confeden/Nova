//! Turning "it did not work" into "this layer did not work".
//!
//! Nova's relay currently collapses every kind of failure into one boolean and
//! charges it to whatever it happened to be holding — the domain, the egress,
//! or both. That is wrong in a specific and expensive way: a resolver hiccup
//! retires a Worker domain that was fine, and a filtered ClientHello gets
//! blamed on an egress that was carrying traffic perfectly a second ago. Both
//! mistakes cost a working option, and the pool of working options is small.
//!
//! A connection passes through an ordered series of gates — resolve, connect,
//! handshake, upgrade, carry — and the last gate it *cleared* bounds what can
//! be concluded. Nothing before the ClientHello can say anything about the
//! ClientHello's shape. Nothing after a completed handshake can either, since
//! the handshake completing is proof the shape was accepted. That single
//! observation is what this crate exists to enforce.
//!
//! No I/O. The relay observes; this decides. That split is what lets the whole
//! decision table be tested without a network, and it is why the awkward cases
//! (a reset arriving exactly one round trip in) are settled here once instead
//! of in three call sites that drift apart.

#![forbid(unsafe_code)]

use nova_core::{BlockSignature, ProbeOutcome};

/// The last gate a tunnel attempt cleared.
///
/// Ordered, and the ordering is load-bearing: the classifier reasons in terms
/// of "did this attempt get far enough for the question to be meaningful".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reached {
    /// The name never became an address.
    Nothing,
    /// An address was obtained, but no TCP session was established.
    Resolved,
    /// TCP was established. Nothing has been written yet.
    Connected,
    /// The ClientHello was written and no ServerHello came back.
    HelloSent,
    /// TLS finished. From here on, the shape of our hello is a settled question.
    HandshakeDone,
    /// The WebSocket upgrade answered `101`.
    Upgraded,
    /// At least one byte arrived from the far side.
    Carrying,
}

impl Reached {
    /// True once a ClientHello has actually been put on the wire.
    ///
    /// Below this line the hello does not exist yet, so it cannot be at fault.
    pub fn hello_was_sent(self) -> bool {
        self >= Reached::HelloSent
    }

    /// True once the far side has demonstrably accepted our ClientHello.
    ///
    /// Above this line the hello has been judged and passed, so it cannot be at
    /// fault either. The window where the hello is a live suspect is exactly
    /// [`Reached::HelloSent`] — one value wide.
    pub fn hello_was_accepted(self) -> bool {
        self >= Reached::HandshakeDone
    }
}

/// How the attempt stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "ended")]
pub enum Ended {
    /// Still running, or closed cleanly after doing its job.
    Ok,
    /// Nothing arrived within the deadline.
    Timeout,
    /// TCP RST.
    Reset,
    /// The SYN was refused outright.
    Refused,
    /// A clean FIN at a point where a working peer would have kept talking.
    Closed,
    /// The certificate did not match the name we asked for.
    CertificateMismatch,
    /// An HTTP response arrived instead of the upgrade.
    HttpStatus { code: u16 },
    /// The resolver answered with an address that cannot belong to the service.
    ResolverStub,
}

/// Everything observed about one attempt, and nothing else.
///
/// Deliberately free of hostnames, egress labels and DC numbers: what those
/// identifiers should be charged with is the *caller's* decision, and it is a
/// decision this crate can only make worse by guessing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TunnelAttempt {
    pub reached: Reached,
    pub ended: Ended,
    /// Milliseconds between writing the ClientHello and `ended`.
    ///
    /// `None` when no hello was written. This is measured from the hello and
    /// not from the start of the attempt on purpose — the reset-timing rule
    /// compares against a round trip, and DNS plus TCP setup would swamp it.
    pub since_hello_ms: Option<u32>,
    /// The best round trip the relay has measured to this peer, if any.
    pub rtt_ms: Option<u32>,
    /// Bytes received from the far side.
    pub bytes_down: u64,
    /// Milliseconds the connection spent carrying traffic.
    pub carried_ms: u32,
}

impl TunnelAttempt {
    pub fn new(reached: Reached, ended: Ended) -> Self {
        Self { reached, ended, since_hello_ms: None, rtt_ms: None, bytes_down: 0, carried_ms: 0 }
    }

    pub fn since_hello_ms(mut self, ms: u32) -> Self {
        self.since_hello_ms = Some(ms);
        self
    }

    pub fn rtt_ms(mut self, ms: u32) -> Self {
        self.rtt_ms = Some(ms);
        self
    }

    pub fn carried(mut self, bytes_down: u64, carried_ms: u32) -> Self {
        self.bytes_down = bytes_down;
        self.carried_ms = carried_ms;
        self
    }
}

/// The numbers the decision table needs, in one place so they can be tuned
/// without hunting through branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Thresholds {
    /// Reset timing below this fraction of a round trip counts as "the DPI cut
    /// our request" rather than "the DPI read the server's reply".
    ///
    /// Expressed as a percentage of `rtt_ms` so the same rule holds on a 12 ms
    /// city link and a 300 ms satellite one.
    pub reset_is_immediate_pct_of_rtt: u32,
    /// Fallback for the same decision when no round trip has been measured yet.
    pub reset_is_immediate_ms: u32,
    /// A session that carried traffic for less than this did not really work.
    pub severed_within_ms: u32,
    /// …and neither did one that moved less than this many bytes.
    ///
    /// Both conditions must hold. A short-lived connection that still moved
    /// real volume did its job; a long-lived one that moved a handshake's worth
    /// of bytes did not.
    pub severed_under_bytes: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            reset_is_immediate_pct_of_rtt: 50,
            // Below the round trip of any real network path, so a reset this
            // fast cannot have originated at the peer.
            reset_is_immediate_ms: 40,
            severed_within_ms: 10_000,
            severed_under_bytes: 64 * 1024,
        }
    }
}

/// Classify one attempt.
///
/// Total: every combination of [`Reached`] and [`Ended`] produces a verdict,
/// including the incoherent ones (a certificate error reported by an attempt
/// that never resolved). Those are answered by the gate that was actually
/// cleared rather than by the claim, because an observer that contradicts
/// itself is more likely wrong about the detail than about the milestone.
pub fn classify(attempt: &TunnelAttempt, thresholds: &Thresholds) -> ProbeOutcome {
    // Success is the only verdict that needs the whole picture, so it is
    // settled first and everything after it is a failure of some kind.
    if attempt.ended == Ended::Ok && attempt.reached == Reached::Carrying {
        return ProbeOutcome::Success { latency_ms: attempt.since_hello_ms.unwrap_or(attempt.carried_ms) };
    }

    let signature = match attempt.reached {
        Reached::Nothing => match attempt.ended {
            Ended::ResolverStub => BlockSignature::DnsPoisoned,
            _ => BlockSignature::DnsFailure,
        },

        // An address in hand and no TCP session. Whether the SYN was answered
        // separates a firewall from a blackhole, and only the latter is a
        // reason to go looking for another egress.
        Reached::Resolved => match attempt.ended {
            Ended::ResolverStub => BlockSignature::DnsPoisoned,
            Ended::Refused | Ended::Reset => BlockSignature::ConnectionRefused,
            _ => BlockSignature::Blackholed,
        },

        // TCP is up and the hello has not gone out yet. Nothing here is about
        // the hello; a peer that dies at this point is a peer that died.
        Reached::Connected => match attempt.ended {
            Ended::Refused => BlockSignature::ConnectionRefused,
            Ended::Reset | Ended::Closed => BlockSignature::Blackholed,
            _ => BlockSignature::Unknown,
        },

        // The one window where the hello is a live suspect.
        Reached::HelloSent => match attempt.ended {
            Ended::CertificateMismatch => BlockSignature::TlsCertificateMismatch,
            Ended::Reset => reset_signature(attempt, thresholds),
            // Silence, or a polite close, in answer to a well-formed hello.
            // Somebody read it and decided not to continue.
            Ended::Timeout | Ended::Closed => BlockSignature::TunnelHandshakeIgnored,
            // An HTTP response to a ClientHello means a middlebox terminated
            // TLS that was never offered to it. That is interception, and the
            // certificate verdict is the one that names it.
            Ended::HttpStatus { .. } => BlockSignature::TlsCertificateMismatch,
            _ => BlockSignature::TunnelHandshakeIgnored,
        },

        // TLS is established: the hello has been judged and passed. From here
        // the suspects are the endpoint and the route behind it.
        Reached::HandshakeDone => match attempt.ended {
            Ended::CertificateMismatch => BlockSignature::TlsCertificateMismatch,
            Ended::HttpStatus { .. } => BlockSignature::TunnelUpgradeRejected,
            _ => BlockSignature::TunnelStalled,
        },

        // Upgraded and never spoke. The near leg is proven end to end, so the
        // break is past the endpoint.
        Reached::Upgraded => BlockSignature::TunnelStalled,

        // Bytes flowed. Everything static about this connection was accepted,
        // which leaves what a static check cannot see.
        Reached::Carrying => {
            if is_severed(attempt, thresholds) {
                BlockSignature::TunnelSevered
            } else {
                // Long enough and heavy enough to have done its job. Whatever
                // ended it, it was not interference worth re-tuning for.
                return ProbeOutcome::Success {
                    latency_ms: attempt.since_hello_ms.unwrap_or(attempt.carried_ms),
                };
            }
        }
    };

    ProbeOutcome::Failed { signature }
}

/// Which side a reset came from, judged by how fast it arrived.
///
/// A reset cannot come from the peer sooner than a round trip. Arriving well
/// inside one means it was injected between here and there, which is the
/// request-side case; arriving around one means whoever sent it had time to
/// read what the server said.
fn reset_signature(attempt: &TunnelAttempt, thresholds: &Thresholds) -> BlockSignature {
    let elapsed = match attempt.since_hello_ms {
        Some(ms) => ms,
        // No timing at all. Guessing either way would put half the resets into
        // a countermeasure family that cannot address them, and `Unknown`
        // already routes to request-side desync, which is the larger family.
        None => return BlockSignature::Unknown,
    };
    let budget = match attempt.rtt_ms {
        Some(rtt) => rtt.saturating_mul(thresholds.reset_is_immediate_pct_of_rtt) / 100,
        None => thresholds.reset_is_immediate_ms,
    };
    if elapsed <= budget { BlockSignature::RstImmediate } else { BlockSignature::RstAfterServerHello }
}

/// Whether a connection that carried traffic died too early to count as having
/// worked.
fn is_severed(attempt: &TunnelAttempt, thresholds: &Thresholds) -> bool {
    attempt.carried_ms < thresholds.severed_within_ms && attempt.bytes_down < thresholds.severed_under_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classified(attempt: &TunnelAttempt) -> Option<BlockSignature> {
        classify(attempt, &Thresholds::default()).signature()
    }

    #[test]
    fn the_hello_is_only_suspect_in_its_own_window() {
        // The whole point of the crate in one assertion: exactly one milestone
        // may produce a verdict that rotates the ClientHello profile.
        for reached in [
            Reached::Nothing,
            Reached::Resolved,
            Reached::Connected,
            Reached::HelloSent,
            Reached::HandshakeDone,
            Reached::Upgraded,
            Reached::Carrying,
        ] {
            for ended in [
                Ended::Timeout,
                Ended::Reset,
                Ended::Refused,
                Ended::Closed,
                Ended::CertificateMismatch,
                Ended::HttpStatus { code: 403 },
                Ended::ResolverStub,
                Ended::Ok,
            ] {
                let attempt = TunnelAttempt::new(reached, ended).since_hello_ms(500).rtt_ms(40);
                let rotates = classified(&attempt).is_some_and(|s| s.wants_tls_profile_change());
                if reached != Reached::HelloSent {
                    assert!(!rotates, "{reached:?}/{ended:?} rotated the profile");
                }
            }
        }
    }

    #[test]
    fn a_resolver_hiccup_does_not_touch_the_hello_or_the_egress() {
        // The exact misattribution that retires a healthy Worker domain.
        let sig = classified(&TunnelAttempt::new(Reached::Nothing, Ended::Timeout)).unwrap();
        assert_eq!(sig, BlockSignature::DnsFailure);
        assert!(!sig.wants_tls_profile_change());
        assert!(sig.is_not_our_fault(), "a dead resolver must not be charged to anything");
    }

    #[test]
    fn ignored_hello_asks_for_a_different_shape_not_a_different_domain() {
        let sig = classified(
            &TunnelAttempt::new(Reached::HelloSent, Ended::Timeout).since_hello_ms(5_000),
        )
        .unwrap();
        assert_eq!(sig, BlockSignature::TunnelHandshakeIgnored);
        assert!(sig.wants_tls_profile_change());
        assert!(!sig.needs_different_egress(), "the cheap reversible move is ours, not the route's");
    }

    #[test]
    fn reset_timing_splits_on_the_round_trip() {
        // 40 ms round trip: a reset at 5 ms cannot have come from the peer.
        let early =
            TunnelAttempt::new(Reached::HelloSent, Ended::Reset).since_hello_ms(5).rtt_ms(40);
        assert_eq!(classified(&early), Some(BlockSignature::RstImmediate));

        // …and one at 45 ms had time to have read the server's reply.
        let late =
            TunnelAttempt::new(Reached::HelloSent, Ended::Reset).since_hello_ms(45).rtt_ms(40);
        assert_eq!(classified(&late), Some(BlockSignature::RstAfterServerHello));

        // The two demand different countermeasures, which is why the split is
        // worth making at all.
        assert_ne!(
            BlockSignature::RstImmediate.countermeasure(),
            BlockSignature::RstAfterServerHello.countermeasure()
        );
    }

    #[test]
    fn the_same_reset_splits_differently_on_a_slow_link() {
        // 30 ms is immediate on a satellite link and late on a fibre one. A
        // fixed millisecond cutoff would misfile one of these two.
        let satellite =
            TunnelAttempt::new(Reached::HelloSent, Ended::Reset).since_hello_ms(30).rtt_ms(300);
        let fibre =
            TunnelAttempt::new(Reached::HelloSent, Ended::Reset).since_hello_ms(30).rtt_ms(12);
        assert_eq!(classified(&satellite), Some(BlockSignature::RstImmediate));
        assert_eq!(classified(&fibre), Some(BlockSignature::RstAfterServerHello));
    }

    #[test]
    fn a_reset_without_timing_is_not_guessed_at() {
        let blind = TunnelAttempt::new(Reached::HelloSent, Ended::Reset);
        assert_eq!(classified(&blind), Some(BlockSignature::Unknown));
    }

    #[test]
    fn a_rejected_upgrade_blames_the_endpoint() {
        let sig = classified(&TunnelAttempt::new(
            Reached::HandshakeDone,
            Ended::HttpStatus { code: 403 },
        ))
        .unwrap();
        assert_eq!(sig, BlockSignature::TunnelUpgradeRejected);
        assert!(sig.needs_different_egress());
        assert!(!sig.wants_tls_profile_change(), "TLS completed — the hello was accepted");
    }

    #[test]
    fn silence_after_a_working_upgrade_is_a_route_problem() {
        let sig = classified(&TunnelAttempt::new(Reached::Upgraded, Ended::Timeout)).unwrap();
        assert_eq!(sig, BlockSignature::TunnelStalled);
        assert!(sig.needs_different_egress());
    }

    #[test]
    fn an_http_answer_to_a_clienthello_is_interception() {
        // Nobody speaks HTTP to a TLS handshake unless they terminated it.
        let sig = classified(&TunnelAttempt::new(
            Reached::HelloSent,
            Ended::HttpStatus { code: 200 },
        ))
        .unwrap();
        assert_eq!(sig, BlockSignature::TlsCertificateMismatch);
        assert!(sig.needs_different_egress());
    }

    #[test]
    fn an_early_death_after_data_asks_for_a_different_shape_of_traffic() {
        let sig = classified(
            &TunnelAttempt::new(Reached::Carrying, Ended::Reset).carried(2_048, 900),
        )
        .unwrap();
        assert_eq!(sig, BlockSignature::TunnelSevered);
        assert!(sig.wants_traffic_reshape());
        assert!(!sig.wants_tls_profile_change());
    }

    #[test]
    fn a_session_that_did_its_job_is_not_a_failure() {
        // Four minutes and eight megabytes, then a reset. Something ended it,
        // but re-tuning the transport over this would be chasing noise.
        let outcome = classify(
            &TunnelAttempt::new(Reached::Carrying, Ended::Reset).carried(8 << 20, 240_000),
            &Thresholds::default(),
        );
        assert!(outcome.is_success());
    }

    #[test]
    fn volume_alone_rescues_a_short_session() {
        // Short but heavy: a completed download, not an interrupted one.
        let outcome = classify(
            &TunnelAttempt::new(Reached::Carrying, Ended::Closed).carried(4 << 20, 800),
            &Thresholds::default(),
        );
        assert!(outcome.is_success());
    }

    #[test]
    fn a_refused_syn_is_never_charged_to_nova() {
        let sig = classified(&TunnelAttempt::new(Reached::Resolved, Ended::Refused)).unwrap();
        assert_eq!(sig, BlockSignature::ConnectionRefused);
        assert!(sig.is_not_our_fault());
    }

    #[test]
    fn an_unanswered_syn_wants_another_route() {
        let sig = classified(&TunnelAttempt::new(Reached::Resolved, Ended::Timeout)).unwrap();
        assert_eq!(sig, BlockSignature::Blackholed);
        assert!(sig.needs_different_egress());
    }

    #[test]
    fn a_poisoned_answer_is_recognised_at_either_milestone() {
        for reached in [Reached::Nothing, Reached::Resolved] {
            assert_eq!(
                classified(&TunnelAttempt::new(reached, Ended::ResolverStub)),
                Some(BlockSignature::DnsPoisoned),
                "{reached:?}"
            );
        }
    }

    #[test]
    fn every_combination_produces_a_verdict() {
        // Totality. An unclassified pair would fall through to whatever the
        // caller's default is, and the caller's default is the blunt boolean
        // this crate exists to replace.
        for reached in [
            Reached::Nothing,
            Reached::Resolved,
            Reached::Connected,
            Reached::HelloSent,
            Reached::HandshakeDone,
            Reached::Upgraded,
            Reached::Carrying,
        ] {
            for ended in [
                Ended::Ok,
                Ended::Timeout,
                Ended::Reset,
                Ended::Refused,
                Ended::Closed,
                Ended::CertificateMismatch,
                Ended::HttpStatus { code: 502 },
                Ended::ResolverStub,
            ] {
                let attempt = TunnelAttempt::new(reached, ended).since_hello_ms(100).rtt_ms(50);
                let outcome = classify(&attempt, &Thresholds::default());
                assert!(
                    outcome.is_success() || outcome.signature().is_some(),
                    "{reached:?}/{ended:?} produced nothing"
                );
            }
        }
    }

    #[test]
    fn hello_window_predicates_agree_with_the_ordering() {
        assert!(!Reached::Connected.hello_was_sent());
        assert!(Reached::HelloSent.hello_was_sent());
        assert!(!Reached::HelloSent.hello_was_accepted());
        assert!(Reached::HandshakeDone.hello_was_accepted());
        assert!(Reached::Carrying.hello_was_accepted());
    }
}
