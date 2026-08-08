//! Choosing the shape of the relay's own ClientHello by measuring it.
//!
//! Which TLS fingerprint a filtering network tolerates is a property of that
//! network, and nobody can know it from a README. The claim this lever exists
//! to settle is the one taken from another project's notes: that a Yandex-shaped
//! hello gets through where a Chrome-shaped one does not. It might be true here,
//! it might not, and the cost of assuming is a working option retired for
//! nothing.
//!
//! So the shape becomes an arm, and evidence decides. The machinery is the same
//! discounted Thompson sampling as [`crate::Learner`], deliberately: a shape
//! that stopped working three ISP rulesets ago should fade the same way a
//! strategy does.
//!
//! # What counts as evidence
//!
//! Almost nothing does, and that is the point. Of everything that can go wrong
//! with a tunnel, exactly two outcomes say anything about the shape of the
//! hello:
//!
//! - a success, because the hello was accepted;
//! - [`BlockSignature::TunnelHandshakeIgnored`], because the hello went out and
//!   nothing came back.
//!
//! Every other failure happened either before the hello existed (DNS, a dead
//! route, a refused connection) or after it had already been accepted (a
//! rejected upgrade, a silent endpoint, a severed stream). Charging any of them
//! would spend a shape on evidence that cannot be about shapes — and the pool of
//! shapes is small enough that a handful of misattributions empties it.
//!
//! # Why hysteresis
//!
//! Switching shape is not free the way switching a strategy is. A client whose
//! fingerprint changes every few minutes is itself an anomaly, and mid-session
//! reconnections cost the user latency. So a challenger has to beat the
//! incumbent by a margin rather than merely win one draw.

use std::collections::BTreeMap;

use nova_core::{ProbeOutcome, Seconds};
use rand::SeedableRng;

use crate::posterior::Posterior;

/// The shape the relay used before any of this existed: CPython over OpenSSL.
///
/// A real arm, not a placeholder. It is what ships today, it demonstrably
/// carries traffic on most networks, and if a shaped hello turns out to fare
/// worse somewhere then falling back to it is the correct answer rather than an
/// admission of defeat. Having it in the pool is also what makes the comparison
/// possible at all: without it there is nothing to be better than.
pub const FALLBACK_SHAPE: &str = "openssl-python";

/// How much better a challenger must look before the shape actually changes.
///
/// Zero would flip on noise. Too high would pin a shape that has stopped
/// working. A tenth of the success-rate scale is roughly "clearly better on the
/// evidence so far" without being "better on one lucky draw".
const SWITCH_MARGIN: f32 = 0.10;

/// What [`ShapeLearner::record`] did with an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charged {
    /// Counted as a success for the shape.
    Success,
    /// Counted against the shape: its hello went unanswered.
    Failure,
    /// Deliberately ignored — this outcome says nothing about the shape.
    Ignored,
}

/// Posteriors over ClientHello shapes for one network.
#[derive(Debug)]
pub struct ShapeLearner {
    arms: BTreeMap<String, Posterior>,
    incumbent: Option<String>,
    rng: rand::rngs::StdRng,
}

impl ShapeLearner {
    /// Start with one arm per shape the build can actually emit.
    ///
    /// The caller supplies the list, because what is emittable is a property of
    /// how the binary was built — `nova-tls` refuses a profile it cannot
    /// reproduce exactly, and an arm that can never be played would collect no
    /// evidence while diluting every draw.
    pub fn new(shapes: &[&str], now: Seconds) -> Self {
        Self::with_rng(shapes, now, rand::rngs::StdRng::from_os_rng())
    }

    fn with_rng(shapes: &[&str], now: Seconds, rng: rand::rngs::StdRng) -> Self {
        let mut arms = BTreeMap::new();
        for shape in shapes {
            arms.insert((*shape).to_owned(), Posterior::new(now));
        }
        arms.entry(FALLBACK_SHAPE.to_owned()).or_insert_with(|| Posterior::new(now));
        Self { arms, incumbent: None, rng }
    }

    /// Deterministic construction, for tests.
    pub fn seeded(shapes: &[&str], now: Seconds, seed: u64) -> Self {
        Self::with_rng(shapes, now, rand::rngs::StdRng::seed_from_u64(seed))
    }

    /// The shape currently in force, if one has been chosen.
    pub fn incumbent(&self) -> Option<&str> {
        self.incumbent.as_deref()
    }

    /// Shapes with evidence, best first, for a log line or a diagnostic screen.
    pub fn ranking(&self, now: Seconds) -> Vec<(String, f32, f32)> {
        let mut rows: Vec<(String, f32, f32)> = self
            .arms
            .iter()
            .map(|(id, p)| (id.clone(), p.mean_at(now), p.mass_at(now)))
            .collect();
        rows.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        rows
    }

    /// Fold one tunnel attempt into the shape's posterior.
    ///
    /// Returns what was actually charged, so a caller can log the distinction
    /// between "this shape lost a point" and "this told us nothing" — which is
    /// the distinction the whole module rests on.
    pub fn record(&mut self, shape: &str, outcome: &ProbeOutcome, now: Seconds) -> Charged {
        let verdict = match outcome {
            ProbeOutcome::Success { .. } => Charged::Success,
            _ => match outcome.signature() {
                // The one window where the hello is a live suspect.
                Some(sig) if sig.wants_tls_profile_change() => Charged::Failure,
                _ => Charged::Ignored,
            },
        };
        if verdict == Charged::Ignored {
            return verdict;
        }
        self.arms
            .entry(shape.to_owned())
            .or_insert_with(|| Posterior::new(now))
            .observe(verdict == Charged::Success, 1.0, now);
        verdict
    }

    /// The shape to use now.
    ///
    /// Thompson sampling, with the incumbent kept unless a challenger is
    /// clearly ahead. Pure arithmetic — no I/O, safe to call per connection.
    pub fn choose(&mut self, now: Seconds) -> String {
        let mut best: Option<(String, f32)> = None;
        for (id, posterior) in &self.arms {
            let draw = posterior.sample(now, &mut self.rng);
            if best.as_ref().is_none_or(|(_, b)| draw > *b) {
                best = Some((id.clone(), draw));
            }
        }
        let (challenger, _) = best.expect("the fallback shape is always present");

        let Some(current) = self.incumbent.clone() else {
            self.incumbent = Some(challenger.clone());
            return challenger;
        };
        if challenger == current {
            return current;
        }

        // Compare on what the evidence says, not on the draw that won: a draw
        // is noisy by construction, and changing fingerprint mid-session is
        // itself something worth avoiding.
        let current_mean = self.arms.get(&current).map(|p| p.mean_at(now)).unwrap_or(0.0);
        let challenger_mean = self.arms[&challenger].mean_at(now);
        if challenger_mean > current_mean + SWITCH_MARGIN {
            self.incumbent = Some(challenger.clone());
            tracing::info!(from = %current, to = %challenger, "tls shape changed on evidence");
            return challenger;
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_core::BlockSignature;

    const YANDEX: &str = "yandex-windows";

    fn ignored_hello() -> ProbeOutcome {
        ProbeOutcome::Failed { signature: BlockSignature::TunnelHandshakeIgnored }
    }

    fn ok() -> ProbeOutcome {
        ProbeOutcome::Success { latency_ms: 40 }
    }

    #[test]
    fn the_fallback_shape_is_always_an_arm() {
        // Without it there is nothing for a shaped hello to be better than, and
        // no way back if it turns out to be worse.
        let learner = ShapeLearner::seeded(&[YANDEX], 0, 1);
        assert!(learner.arms.contains_key(FALLBACK_SHAPE));
        assert!(learner.arms.contains_key(YANDEX));
    }

    #[test]
    fn only_two_outcomes_say_anything_about_the_shape() {
        let mut learner = ShapeLearner::seeded(&[YANDEX], 0, 1);
        assert_eq!(learner.record(YANDEX, &ok(), 1), Charged::Success);
        assert_eq!(learner.record(YANDEX, &ignored_hello(), 2), Charged::Failure);

        // Everything else happened before the hello existed or after it was
        // accepted. Charging any of it would empty a small pool for nothing.
        for signature in [
            BlockSignature::DnsFailure,
            BlockSignature::DnsPoisoned,
            BlockSignature::Blackholed,
            BlockSignature::ConnectionRefused,
            BlockSignature::TunnelUpgradeRejected,
            BlockSignature::TunnelStalled,
            BlockSignature::TunnelSevered,
            BlockSignature::RstImmediate,
            BlockSignature::SniTimeout,
            BlockSignature::TlsCertificateMismatch,
        ] {
            let outcome = ProbeOutcome::Failed { signature };
            assert_eq!(
                learner.record(YANDEX, &outcome, 3),
                Charged::Ignored,
                "{signature:?} was charged to the shape"
            );
        }
    }

    #[test]
    fn exactly_one_signature_is_chargeable() {
        // Mirrors the guarantee in nova-core: if a second signature ever starts
        // asking for a profile change, this module must be revisited rather
        // than silently start counting it.
        let chargeable: Vec<_> = BlockSignature::ALL
            .into_iter()
            .filter(|s| s.wants_tls_profile_change())
            .collect();
        assert_eq!(chargeable, vec![BlockSignature::TunnelHandshakeIgnored]);
    }

    #[test]
    fn a_shape_that_works_is_kept() {
        let mut learner = ShapeLearner::seeded(&[YANDEX], 0, 7);
        let first = learner.choose(1);
        for tick in 2..40 {
            learner.record(&first, &ok(), tick);
        }
        for tick in 40..80 {
            assert_eq!(learner.choose(tick), first, "a working shape was abandoned");
        }
    }

    #[test]
    fn a_shape_the_network_rejects_is_abandoned_for_one_that_works() {
        // The scenario the lever exists for: one shape's hello goes unanswered
        // while the other carries traffic.
        let mut learner = ShapeLearner::seeded(&[YANDEX], 0, 11);
        for tick in 1..30 {
            learner.record(YANDEX, &ignored_hello(), tick);
            learner.record(FALLBACK_SHAPE, &ok(), tick);
        }
        let mut chosen = String::new();
        for tick in 30..60 {
            chosen = learner.choose(tick);
        }
        assert_eq!(chosen, FALLBACK_SHAPE);
        let ranking = learner.ranking(60);
        assert_eq!(ranking[0].0, FALLBACK_SHAPE);
    }

    #[test]
    fn it_works_in_the_other_direction_too() {
        // Nothing here privileges the shaped hello. If the old stack is the one
        // being filtered, the learner must move to the shaped one — otherwise
        // this is a preference dressed up as a measurement.
        let mut learner = ShapeLearner::seeded(&[YANDEX], 0, 13);
        for tick in 1..30 {
            learner.record(FALLBACK_SHAPE, &ignored_hello(), tick);
            learner.record(YANDEX, &ok(), tick);
        }
        let mut chosen = String::new();
        for tick in 30..60 {
            chosen = learner.choose(tick);
        }
        assert_eq!(chosen, YANDEX);
    }

    #[test]
    fn one_bad_attempt_does_not_change_the_fingerprint() {
        // A client whose shape changes every few minutes is its own anomaly,
        // and each change costs the user a reconnection.
        let mut learner = ShapeLearner::seeded(&[YANDEX], 0, 17);
        let held = learner.choose(1);
        for tick in 2..60 {
            learner.record(&held, &ok(), tick);
        }
        learner.record(&held, &ignored_hello(), 60);
        for tick in 61..70 {
            assert_eq!(learner.choose(tick), held, "flipped on a single failure");
        }
    }

    #[test]
    fn a_run_of_failures_does_change_it() {
        // The counterpart: hysteresis must not become paralysis.
        let mut learner = ShapeLearner::seeded(&[YANDEX], 0, 19);
        let held = learner.choose(1);
        for tick in 2..30 {
            learner.record(&held, &ok(), tick);
        }
        let other = if held == FALLBACK_SHAPE { YANDEX } else { FALLBACK_SHAPE };
        for tick in 30..120 {
            learner.record(&held, &ignored_hello(), tick);
            learner.record(other, &ok(), tick);
        }
        let mut chosen = String::new();
        for tick in 120..160 {
            chosen = learner.choose(tick);
        }
        assert_eq!(chosen, other, "hysteresis became paralysis");
    }

    #[test]
    fn noise_alone_never_moves_the_shape() {
        // Both arms equally good: whatever is in force should stay, because
        // there is no evidence to act on and changing costs something.
        let mut learner = ShapeLearner::seeded(&[YANDEX], 0, 23);
        let held = learner.choose(1);
        for tick in 2..200 {
            learner.record(YANDEX, &ok(), tick);
            learner.record(FALLBACK_SHAPE, &ok(), tick);
        }
        let mut changes = 0;
        let mut previous = held;
        for tick in 200..400 {
            let now = learner.choose(tick);
            if now != previous {
                changes += 1;
                previous = now;
            }
        }
        assert_eq!(changes, 0, "the shape moved without evidence");
    }

    #[test]
    fn an_unknown_shape_reported_by_the_relay_still_records() {
        // The relay is the one that names the shape it used. A build shipping a
        // profile this learner was not told about must not lose the evidence.
        let mut learner = ShapeLearner::seeded(&[], 0, 29);
        assert_eq!(learner.record("firefox-windows", &ok(), 1), Charged::Success);
        assert!(learner.arms.contains_key("firefox-windows"));
    }
}
