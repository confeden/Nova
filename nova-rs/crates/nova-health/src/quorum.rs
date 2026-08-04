//! Turning several canary results into one health verdict.
//!
//! The distinction this exists to draw is "the transport is down" versus "that
//! one site is down". A single canary cannot tell them apart, and the Python
//! watchdog's use of one endpoint is why a Cloudflare hiccup could take Nova's
//! whole WARP route offline.

use nova_core::{BlockSignature, ProbeOutcome};

/// Verdict over a set of canary results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Enough canaries answered.
    Up,
    /// Enough canaries failed, in a way attributable to the transport.
    Down,
    /// Not enough usable evidence — too few results, or every failure was one
    /// the transport cannot be blamed for.
    Inconclusive,
}

/// Fraction of canaries that must fail before the transport is blamed.
///
/// A simple majority. Requiring *all* of them makes the detector miss partial
/// outages, which are the common case when a tunnel's routes are half-broken;
/// requiring only one makes it fire on every unrelated site outage.
const FAIL_FRACTION: f32 = 0.5;

/// Minimum results needed for any verdict at all.
const MIN_SAMPLES: usize = 2;

/// Evaluate a batch of canary outcomes.
///
/// Outcomes whose signature is "not our fault" are excluded from both the
/// numerator and the denominator rather than counted as successes: a canary
/// whose origin is down carries no information about the transport, and
/// treating it as a success would mask a real outage.
pub fn evaluate(outcomes: &[ProbeOutcome]) -> Health {
    let usable: Vec<&ProbeOutcome> =
        outcomes.iter().filter(|o| !o.signature().is_some_and(BlockSignature::is_not_our_fault)).collect();

    if usable.len() < MIN_SAMPLES {
        return Health::Inconclusive;
    }
    let failures = usable.iter().filter(|o| !o.is_success()).count();
    let fraction = failures as f32 / usable.len() as f32;
    // A minority failing is normal internet weather, not a transport fault.
    if fraction > FAIL_FRACTION { Health::Down } else { Health::Up }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> ProbeOutcome {
        ProbeOutcome::Success { latency_ms: 30 }
    }

    fn fail(sig: BlockSignature) -> ProbeOutcome {
        ProbeOutcome::Failed { signature: sig }
    }

    #[test]
    fn all_healthy_is_up() {
        assert_eq!(evaluate(&[ok(), ok(), ok()]), Health::Up);
    }

    #[test]
    fn all_failing_is_down() {
        let out =
            [fail(BlockSignature::Blackholed), fail(BlockSignature::SniTimeout), fail(BlockSignature::Blackholed)];
        assert_eq!(evaluate(&out), Health::Down);
    }

    #[test]
    fn one_dead_site_does_not_condemn_the_transport() {
        let out = [ok(), ok(), fail(BlockSignature::SniTimeout)];
        assert_eq!(evaluate(&out), Health::Up, "a minority failure is that site's problem");
    }

    #[test]
    fn majority_failure_condemns_it() {
        let out = [ok(), fail(BlockSignature::Blackholed), fail(BlockSignature::Blackholed)];
        assert_eq!(evaluate(&out), Health::Down);
    }

    #[test]
    fn unattributable_failures_are_excluded_not_counted_as_success() {
        // Two canaries whose origins are down, one genuinely blackholed. If the
        // origin-down pair counted as successes this would read as Up and mask
        // a real outage; excluding them leaves one usable sample, which is not
        // enough to decide.
        let out = [
            fail(BlockSignature::CloudflareOriginDown),
            fail(BlockSignature::ConnectionRefused),
            fail(BlockSignature::Blackholed),
        ];
        assert_eq!(evaluate(&out), Health::Inconclusive);
    }

    #[test]
    fn too_few_samples_is_inconclusive() {
        assert_eq!(evaluate(&[]), Health::Inconclusive);
        assert_eq!(evaluate(&[ok()]), Health::Inconclusive);
        assert_eq!(evaluate(&[fail(BlockSignature::Blackholed)]), Health::Inconclusive);
    }
}
