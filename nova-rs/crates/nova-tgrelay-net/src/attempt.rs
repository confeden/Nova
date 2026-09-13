//! Layer 25: walking the egresses for one WSS candidate, and who gets charged.
//!
//! The port of `_connect_websocket_target` (`transparent_relay.py:1093`). One
//! Worker domain, one egress after another, until a tunnel opens or the list
//! runs out.
//!
//! **Why the walk exists at all.** An egress can accept the TCP connection and
//! complete TLS while silently dropping the WebSocket upgrade — that is exactly
//! how a degraded WARP tunnel behaves, and it is what the live log shows as
//! `WSS egress warp-socks stopped answering the handshake`. Choosing the egress
//! inside the dialler cannot notice it, because by then the connection already
//! looks healthy. So the handshake is driven from here, one egress at a time.
//!
//! **The part worth reading twice is the attribution.** A failure has to be
//! charged to *a* layer, and charging it to the wrong one is expensive in a
//! specific way: every mistake spends a working option, and the supply of
//! working options is what the relay lives on. Three answers, and the order they
//! are asked in is the rule:
//!
//! 1. A real HTTP status came back → the egress carried a whole request and
//!    reply, so it works and the **domain** refused us. Stop: the next egress
//!    would collect the same refusal.
//! 2. The signature says the failure is nobody's fault here (a refused
//!    connection, a dead resolver) → charge **nothing**. The next egress will
//!    fail identically, so there is also nothing to learn from marking this one
//!    and moving on.
//! 3. TLS finished end to end and only then did the far side go quiet →
//!    **credit** the egress. It carried a whole handshake; it is the last thing
//!    that deserves the blame.
//! 4. Anything else → **penalise** the egress.
//!
//! [`charge`] is that table, on its own, testable without a socket. The walk is
//! a fold over it.
//!
//! **The single-egress case skips attribution entirely**, and that is the
//! Python's behaviour rather than an omission here — see
//! [`Attempted::charge`].

use nova_core::BlockSignature;
use nova_probe::{classify, Ended, Reached, Thresholds, TunnelAttempt};
use nova_tgrelay::egress::{Egress, PenaltyBox};
use std::future::Future;
use std::time::{Duration, Instant};

/// `WSS_MIN_ATTEMPT_TIMEOUT`: no single attempt gets less than this, however
/// many egresses the budget is split across.
///
/// Below it the split stops being a budget and becomes a guarantee of failure —
/// a proxy handshake plus a TLS handshake plus an HTTP round trip does not fit
/// in less, so every attempt would time out and every egress would be charged
/// for it.
pub const MIN_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long one egress may take, given the whole call's budget.
///
/// The caller's budget is what the CF race is willing to wait for; splitting it
/// is what stops probing a dead egress from stretching one candidate past the
/// point where the race has already moved on.
///
/// A list of one is not split: there is nothing to leave time for.
pub fn attempt_budget(total: Duration, egresses: usize) -> Duration {
    if egresses < 2 {
        return total;
    }
    (total / egresses as u32).max(MIN_ATTEMPT_TIMEOUT)
}

/// What one failed attempt reported about itself.
///
/// Deliberately not an error type: the walk needs the milestone and the ending
/// as *data*, and the Python only has them at all because `open_tls_stream`
/// annotates the exception on its way up (`nova_reached`, `nova_ended`). Here
/// the opener returns them, so nothing has to be recovered from a type test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// The last gate the attempt cleared.
    ///
    /// The Python's default when nothing was recorded is [`Reached::Resolved`],
    /// which is the gate that used to be assumed for everything — an untagged
    /// path behaves as it did before rather than silently acquiring a new
    /// verdict. Here the field is always present, so the opener chooses.
    pub reached: Reached,
    pub ended: Ended,
    /// Milliseconds between writing the ClientHello and the ending. Feeds the
    /// reset-timing rule; `None` when no hello went out.
    pub since_hello_ms: Option<u32>,
}

impl Failure {
    pub fn new(reached: Reached, ended: Ended) -> Self {
        Self { reached, ended, since_hello_ms: None }
    }

    pub fn since_hello_ms(mut self, ms: u32) -> Self {
        self.since_hello_ms = Some(ms);
        self
    }

    /// The HTTP status the far side answered with, when it answered with one.
    ///
    /// A zero is not a status. The Python spells this `status_code > 0` because
    /// `WsHandshakeError(0, "empty response")` uses the same field to mean "no
    /// response at all" — and that case must not take the refusal branch, or an
    /// egress that went silent would be credited as working.
    pub fn http_status(&self) -> Option<u16> {
        match self.ended {
            Ended::HttpStatus { code } if code > 0 => Some(code),
            _ => None,
        }
    }
}

/// Name the gate this attempt died at.
///
/// The port of `_attempt_signature` (`:1066`). Everything it needs was recorded
/// on the way up; this only applies the shared decision table in
/// [`nova_probe`], which is the same table `tgrelay/phase.py` mirrors, so a log
/// line, a persisted counter and a Rust verdict all say the same word.
pub fn signature(failure: &Failure) -> BlockSignature {
    let mut reached = failure.reached;
    if failure.http_status().is_some() {
        // An HTTP status is itself proof the handshake finished — nobody sends
        // one before TLS is up. Trusting the annotation over that would let a
        // missing tag turn a definitive refusal into a blackholed route, and
        // demote an egress that had just carried a full request and reply.
        reached = reached.max(Reached::HandshakeDone);
    }
    let mut attempt = TunnelAttempt::new(reached, failure.ended);
    attempt.since_hello_ms = failure.since_hello_ms;
    // `rtt_ms` is `None` here exactly as in the Python: this path has never
    // measured a round trip to the peer, so the reset-timing rule falls back to
    // its absolute threshold.
    classify(&attempt, &Thresholds::default())
        .signature()
        // Total by construction: `classify` only returns `Success` for an
        // attempt that ended `Ok` while `Carrying`, and a `Failure` is neither.
        .unwrap_or(BlockSignature::Unknown)
}

/// What the walk does with the egress after an attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// Say nothing about it. The failure is not evidence about this egress, and
    /// the next one in the list will fail identically.
    Nobody,
    /// Forgive it. TLS completed end to end through it before the far side went
    /// quiet, so it carried a whole handshake.
    Credit,
    /// Send it to the back of the queue.
    Penalise,
    /// Forgive it and stop walking: the domain refused us, and it will refuse
    /// the next egress the same way.
    Refused,
}

impl Charge {
    /// Whether this answer ends the walk.
    pub fn stops_the_walk(self) -> bool {
        matches!(self, Self::Refused)
    }
}

/// Which layer a failed attempt is charged to.
///
/// Total, and stated as its own function because it is the whole decision. The
/// four branches are the Python's four, in the Python's order.
pub fn charge(failure: &Failure) -> Charge {
    if failure.http_status().is_some() {
        return Charge::Refused;
    }
    if signature(failure).is_not_our_fault() {
        return Charge::Nobody;
    }
    // Read from the *reported* milestone, not from the one `signature` bumped
    // for an HTTP status — that branch has already returned.
    if failure.reached >= Reached::HandshakeDone {
        return Charge::Credit;
    }
    Charge::Penalise
}

/// One egress, tried and failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempted {
    pub label: String,
    pub signature: BlockSignature,
    /// What the walk did about it, or `None` when it never asked.
    ///
    /// `None` is the single-egress case. With one egress there is nothing to
    /// reorder, so the Python takes a shortcut past the whole attribution block
    /// — it neither credits nor penalises, and a single-egress deployment
    /// therefore never populates the penalty box at all. Kept as a distinct
    /// answer rather than folded into [`Charge::Nobody`], because "we decided
    /// not to blame it" and "we never asked" are different claims about the
    /// evidence, and only the second one is a candidate for changing later.
    pub charge: Option<Charge>,
}

/// An open tunnel, and what carried it.
#[derive(Debug)]
pub struct Opened<T> {
    pub value: T,
    /// The egress label — what the health tables are keyed by and what the
    /// `via` field of every WSS log line says.
    pub label: String,
    /// True when the egress that worked was not the first one tried.
    ///
    /// The Python logs `went through {label} instead of the preferred egress`
    /// on exactly this condition. Reported rather than logged here: this crate
    /// owns no logger.
    pub switched: bool,
    /// Every egress tried before the one that worked, in order.
    pub failed: Vec<Attempted>,
}

/// Why no tunnel was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// The caller handed over an empty list.
    ///
    /// The Python arrives at the same place from further in: the empty list is
    /// passed down and `terminator.open_shaped_stream` raises
    /// `no upstream attempts available` from inside it. Named here instead,
    /// because it is a bug on the calling side rather than a network condition.
    NoEgress,
    /// A real HTTP status: the egress works, the domain refused us.
    ///
    /// The domain is what deserves the bench for this, and benching it is the
    /// *caller's* job — this layer knows one domain and cannot see the health
    /// table that ranks it against the others.
    Refused { status: u16, label: String, signature: BlockSignature, earlier: Vec<Attempted> },
    /// Every egress was tried and none of them opened a tunnel.
    AllFailed { failed: Vec<Attempted> },
}

impl WalkError {
    /// The signature of the last thing that went wrong, for the caller's SNI
    /// verdict and log line.
    pub fn last_signature(&self) -> Option<BlockSignature> {
        match self {
            Self::NoEgress => None,
            Self::Refused { signature, .. } => Some(*signature),
            Self::AllFailed { failed } => failed.last().map(|a| a.signature),
        }
    }
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEgress => write!(f, "no upstream attempts available"),
            Self::Refused { status, label, .. } => write!(f, "{label} delivered HTTP {status}"),
            Self::AllFailed { failed } => write!(f, "all {} egresses failed the upgrade", failed.len()),
        }
    }
}

impl std::error::Error for WalkError {}

/// Open one WSS candidate through the first egress that manages it.
///
/// `open` is handed each egress and the budget for that one attempt; it returns
/// the tunnel or [`Failure`]. Keeping it a parameter is what lets every branch
/// of the attribution table be exercised without a socket — and the real opener
/// is `_connect_websocket_once`, which is TLS through the terminator plus the
/// HTTP upgrade, layers 13-16.
///
/// `penalties` is updated as the walk runs rather than at the end, matching the
/// Python: a concurrently running walk for another domain should see a dead
/// egress as soon as it is known, not one round of the race later.
pub async fn connect_first_working<T, O, Fut>(
    egresses: &[Egress],
    total_budget: Duration,
    penalties: &mut PenaltyBox,
    mut open: O,
) -> Result<Opened<T>, WalkError>
where
    O: FnMut(Egress, Duration) -> Fut,
    Fut: Future<Output = Result<T, Failure>>,
{
    if egresses.is_empty() {
        return Err(WalkError::NoEgress);
    }
    // The shortcut is not an optimisation. With one egress there is nowhere to
    // switch to, so the Python runs the attempt on the full budget and skips
    // attribution; reproducing that keeps a single-egress deployment behaving
    // as it does today instead of quietly acquiring a penalty box.
    let attribute = egresses.len() >= 2;
    let budget = attempt_budget(total_budget, egresses.len());

    let mut failed: Vec<Attempted> = Vec::new();
    for (index, egress) in egresses.iter().enumerate() {
        let label = egress.label().to_string();
        match open(egress.clone(), budget).await {
            Ok(value) => {
                if attribute {
                    penalties.clear(&label);
                }
                return Ok(Opened { value, label, switched: index > 0, failed });
            }
            Err(failure) => {
                let signature = signature(&failure);
                let decision = charge(&failure);
                if attribute {
                    match decision {
                        Charge::Credit | Charge::Refused => {
                            penalties.clear(&label);
                        }
                        Charge::Penalise => {
                            penalties.penalise(&label, Instant::now());
                        }
                        Charge::Nobody => {}
                    }
                }
                if decision.stops_the_walk() {
                    return Err(WalkError::Refused {
                        // Some by construction: `Refused` is returned for
                        // nothing else.
                        status: failure.http_status().unwrap_or(0),
                        label,
                        signature,
                        earlier: failed,
                    });
                }
                failed.push(Attempted { label, signature, charge: attribute.then_some(decision) });
            }
        }
    }
    Err(WalkError::AllFailed { failed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_tgrelay::egress::Egress;

    fn egresses(labels: &[&str]) -> Vec<Egress> {
        labels.iter().map(|l| Egress::direct(l)).collect()
    }

    // --- the budget -------------------------------------------------------

    #[test]
    fn the_budget_is_split_across_the_egresses_it_has_to_cover() {
        assert_eq!(attempt_budget(Duration::from_secs(9), 3), Duration::from_secs(3));
    }

    #[test]
    fn a_split_never_drops_below_the_floor() {
        // 7 s over 6 egresses is 1.17 s, which is not enough for a proxy
        // handshake plus TLS plus an HTTP round trip. Splitting to that would
        // turn the budget into a guarantee that every egress is charged.
        assert_eq!(attempt_budget(Duration::from_secs(7), 6), MIN_ATTEMPT_TIMEOUT);
    }

    #[test]
    fn one_egress_gets_the_whole_budget_rather_than_a_share_of_it() {
        assert_eq!(attempt_budget(Duration::from_secs(7), 1), Duration::from_secs(7));
        assert_eq!(attempt_budget(Duration::from_secs(7), 0), Duration::from_secs(7));
    }

    #[test]
    fn a_budget_that_is_not_split_is_not_floored_either() {
        // Written because a mutation proved the test above did not bite: with a
        // budget already over the floor, guarding the single-egress case and
        // not guarding it produce the same number. The floor exists to stop a
        // *split* from handing out an unusable share; with nothing to split
        // there is nothing to protect against, and raising the caller's own 1 s
        // to 2 s would be this layer overruling the plan that set it.
        assert_eq!(attempt_budget(Duration::from_secs(1), 1), Duration::from_secs(1));
        assert_eq!(attempt_budget(Duration::from_secs(1), 2), MIN_ATTEMPT_TIMEOUT);
    }

    // --- the attribution table -------------------------------------------

    #[test]
    fn a_real_http_status_charges_the_domain_and_ends_the_walk() {
        let f = Failure::new(Reached::HandshakeDone, Ended::HttpStatus { code: 403 });
        assert_eq!(charge(&f), Charge::Refused);
        assert!(charge(&f).stops_the_walk());
        assert_eq!(f.http_status(), Some(403));
    }

    #[test]
    fn a_status_of_zero_is_not_a_status() {
        // `WsHandshakeError(0, "empty response")` reuses the field to mean "no
        // response at all". Taking the refusal branch there would credit an
        // egress that had just gone silent, and stop the walk that should have
        // moved to the next one.
        let f = Failure::new(Reached::HandshakeDone, Ended::HttpStatus { code: 0 });
        assert_eq!(f.http_status(), None);
        assert_ne!(charge(&f), Charge::Refused);
    }

    #[test]
    fn a_refused_connection_is_charged_to_nobody() {
        // Somebody else's outage must not slowly poison the relay's best option.
        let f = Failure::new(Reached::Resolved, Ended::Refused);
        assert_eq!(signature(&f), BlockSignature::ConnectionRefused);
        assert_eq!(charge(&f), Charge::Nobody);
    }

    #[test]
    fn a_dead_resolver_is_charged_to_nobody_either() {
        let f = Failure::new(Reached::Nothing, Ended::Timeout);
        assert_eq!(signature(&f), BlockSignature::DnsFailure);
        assert_eq!(charge(&f), Charge::Nobody);
    }

    #[test]
    fn an_egress_that_carried_a_whole_handshake_is_credited_not_blamed() {
        // This is the `empty response` case that dominates the live log: TLS
        // finished, the upgrade was written, and the far side said nothing.
        // The egress is the last thing that deserves the blame for that.
        let f = Failure::new(Reached::HandshakeDone, Ended::Closed);
        assert_eq!(charge(&f), Charge::Credit);
    }

    #[test]
    fn an_egress_that_died_before_the_handshake_finished_is_penalised() {
        let f = Failure::new(Reached::Connected, Ended::Timeout);
        assert_eq!(charge(&f), Charge::Penalise);
    }

    #[test]
    fn the_credit_test_reads_the_reported_milestone_and_not_the_bumped_one() {
        // `signature` raises `reached` to HandshakeDone for an HTTP status,
        // because a status proves TLS finished. That bump must not leak into
        // the credit test: it would turn every pre-handshake failure that
        // happens to carry a status into a credit. The refusal branch returns
        // first, so the only way to see this is to state it.
        let f = Failure::new(Reached::Connected, Ended::HttpStatus { code: 421 });
        assert_eq!(
            signature(&f),
            signature(&Failure::new(Reached::HandshakeDone, Ended::HttpStatus { code: 421 }))
        );
        assert_eq!(charge(&f), Charge::Refused, "not Credit, and not Penalise");
    }

    // --- the walk ---------------------------------------------------------

    #[tokio::test]
    async fn the_first_egress_that_works_wins_and_is_forgiven() {
        let mut penalties = PenaltyBox::default();
        penalties.penalise("warp-socks", Instant::now());

        let opened = connect_first_working(
            &egresses(&["warp-socks", "opera-http"]),
            Duration::from_secs(6),
            &mut penalties,
            |egress, _budget| async move { Ok::<_, Failure>(format!("tunnel via {}", egress.label())) },
        )
        .await
        .expect("the first egress answered");

        assert_eq!(opened.value, "tunnel via warp-socks");
        assert_eq!(opened.label, "warp-socks");
        assert!(!opened.switched);
        assert!(opened.failed.is_empty());
        assert!(!penalties.is_penalised("warp-socks", Instant::now()), "success is what forgives an egress");
    }

    #[tokio::test]
    async fn a_dead_egress_is_benched_and_the_next_one_carries_the_tunnel() {
        let mut penalties = PenaltyBox::default();
        let opened = connect_first_working(
            &egresses(&["warp-socks", "opera-http"]),
            Duration::from_secs(6),
            &mut penalties,
            |egress, _budget| async move {
                if egress.label() == "warp-socks" {
                    Err(Failure::new(Reached::Connected, Ended::Timeout))
                } else {
                    Ok("tunnel")
                }
            },
        )
        .await
        .expect("the second egress answered");

        assert_eq!(opened.label, "opera-http");
        assert!(opened.switched, "this is the line that says which egress actually carried it");
        assert_eq!(opened.failed.len(), 1);
        assert_eq!(opened.failed[0].charge, Some(Charge::Penalise));
        assert!(penalties.is_penalised("warp-socks", Instant::now()));
        assert!(!penalties.is_penalised("opera-http", Instant::now()));
    }

    #[tokio::test]
    async fn each_egress_gets_its_share_of_the_budget_and_not_the_whole_thing() {
        let mut penalties = PenaltyBox::default();
        let mut seen: Vec<Duration> = Vec::new();
        let _ = connect_first_working::<(), _, _>(
            &egresses(&["a", "b", "c"]),
            Duration::from_secs(9),
            &mut penalties,
            |_egress, budget| {
                seen.push(budget);
                async move { Err(Failure::new(Reached::Connected, Ended::Timeout)) }
            },
        )
        .await;
        assert_eq!(seen, vec![Duration::from_secs(3); 3]);
    }

    #[tokio::test]
    async fn a_domain_that_refuses_us_stops_the_walk_instead_of_touring_the_egresses() {
        // Walking on would collect the same 403 from every egress, and each one
        // would look like a failure the egress was responsible for.
        let mut penalties = PenaltyBox::default();
        penalties.penalise("warp-socks", Instant::now());
        let mut tried = 0usize;

        let error = connect_first_working::<(), _, _>(
            &egresses(&["warp-socks", "opera-http", "direct"]),
            Duration::from_secs(6),
            &mut penalties,
            |_egress, _budget| {
                tried += 1;
                async move { Err(Failure::new(Reached::HandshakeDone, Ended::HttpStatus { code: 403 })) }
            },
        )
        .await
        .expect_err("a refusal is not a tunnel");

        assert_eq!(tried, 1, "the second egress is never dialled");
        assert!(matches!(error, WalkError::Refused { status: 403, .. }));
        assert!(
            !penalties.is_penalised("warp-socks", Instant::now()),
            "the egress delivered a whole request and reply, so it is credited"
        );
    }

    #[tokio::test]
    async fn a_failure_that_is_nobodys_fault_leaves_the_penalty_box_alone() {
        let mut penalties = PenaltyBox::default();
        let error = connect_first_working::<(), _, _>(
            &egresses(&["warp-socks", "opera-http"]),
            Duration::from_secs(6),
            &mut penalties,
            |_egress, _budget| async move { Err(Failure::new(Reached::Resolved, Ended::Refused)) },
        )
        .await
        .expect_err("nothing opened");

        match error {
            WalkError::AllFailed { failed } => {
                assert_eq!(failed.len(), 2);
                assert!(failed.iter().all(|a| a.charge == Some(Charge::Nobody)));
            }
            other => panic!("expected AllFailed, got {other:?}"),
        }
        assert!(!penalties.is_penalised("warp-socks", Instant::now()));
        assert!(!penalties.is_penalised("opera-http", Instant::now()));
    }

    #[tokio::test]
    async fn a_single_egress_is_never_credited_and_never_benched() {
        // The Python's shortcut, stated as a test because it is surprising: a
        // deployment with one egress learns nothing about it, in either
        // direction. Folding this into the general path would be a behaviour
        // change, not a cleanup.
        let mut penalties = PenaltyBox::default();
        penalties.penalise("warp-socks", Instant::now());

        let error = connect_first_working::<(), _, _>(
            &egresses(&["warp-socks"]),
            Duration::from_secs(6),
            &mut penalties,
            |_egress, budget| {
                assert_eq!(budget, Duration::from_secs(6), "and it gets the whole budget");
                async move { Err(Failure::new(Reached::Connected, Ended::Timeout)) }
            },
        )
        .await
        .expect_err("nothing opened");

        match error {
            WalkError::AllFailed { failed } => {
                assert_eq!(failed[0].charge, None, "the table was never consulted");
                // The signature is still produced: the SNI verdict needs it,
                // and the Python records that one even on this path.
                assert_eq!(failed[0].signature, signature(&Failure::new(Reached::Connected, Ended::Timeout)));
            }
            other => panic!("expected AllFailed, got {other:?}"),
        }
        assert!(penalties.is_penalised("warp-socks", Instant::now()), "the earlier penalty is untouched");
    }

    #[tokio::test]
    async fn a_single_egress_that_works_does_not_clear_its_penalty_either() {
        let mut penalties = PenaltyBox::default();
        penalties.penalise("warp-socks", Instant::now());
        let opened = connect_first_working(
            &egresses(&["warp-socks"]),
            Duration::from_secs(6),
            &mut penalties,
            |_egress, _budget| async move { Ok::<_, Failure>("tunnel") },
        )
        .await
        .expect("it opened");
        assert!(!opened.switched);
        assert!(penalties.is_penalised("warp-socks", Instant::now()));
    }

    #[tokio::test]
    async fn an_empty_list_is_named_rather_than_discovered_three_layers_down() {
        let mut penalties = PenaltyBox::default();
        let error = connect_first_working::<(), _, _>(
            &[],
            Duration::from_secs(6),
            &mut penalties,
            |_egress, _budget| async move { Ok(()) },
        )
        .await
        .expect_err("there was nothing to dial");
        assert_eq!(error, WalkError::NoEgress);
        assert_eq!(error.to_string(), "no upstream attempts available");
    }

    #[tokio::test]
    async fn every_failure_is_reported_and_not_just_the_last_one() {
        // The Python feeds `_note_sni_verdict` on every one of them. A port
        // that kept only the last would silently drop evidence the neutral-SNI
        // table is built from.
        let mut penalties = PenaltyBox::default();
        let mut n = 0u32;
        let error = connect_first_working::<(), _, _>(
            &egresses(&["a", "b", "c"]),
            Duration::from_secs(9),
            &mut penalties,
            |_egress, _budget| {
                n += 1;
                let reached = if n == 1 { Reached::Nothing } else { Reached::Connected };
                async move { Err(Failure::new(reached, Ended::Timeout)) }
            },
        )
        .await
        .expect_err("nothing opened");

        match error {
            WalkError::AllFailed { failed } => {
                assert_eq!(
                    failed.iter().map(|a| a.label.as_str()).collect::<Vec<_>>(),
                    ["a", "b", "c"],
                    "in the order they were tried"
                );
                assert_eq!(failed[0].signature, BlockSignature::DnsFailure);
                assert_eq!(failed[0].charge, Some(Charge::Nobody));
                assert_eq!(failed[1].charge, Some(Charge::Penalise));
            }
            other => panic!("expected AllFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_failures_before_a_refusal_survive_in_the_error() {
        let mut penalties = PenaltyBox::default();
        let mut n = 0u32;
        let error = connect_first_working::<(), _, _>(
            &egresses(&["a", "b"]),
            Duration::from_secs(6),
            &mut penalties,
            |_egress, _budget| {
                n += 1;
                let failure = if n == 1 {
                    Failure::new(Reached::Connected, Ended::Timeout)
                } else {
                    Failure::new(Reached::HandshakeDone, Ended::HttpStatus { code: 421 })
                };
                async move { Err(failure) }
            },
        )
        .await
        .expect_err("nothing opened");

        match &error {
            WalkError::Refused { status, label, earlier, .. } => {
                assert_eq!((*status, label.as_str()), (421, "b"));
                assert_eq!(earlier.len(), 1);
                assert_eq!(earlier[0].label, "a");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
        assert_eq!(
            error.last_signature(),
            Some(signature(&Failure::new(Reached::HandshakeDone, Ended::HttpStatus { code: 421 },)))
        );
    }
}
