//! How the Worker candidates are grouped before they are raced.
//!
//! Layer 17, and the pure half of `_connect_cf_ws_route`. The racing itself is
//! orchestration and needs the whole connect path; this is the part that decides
//! *what* races *what*, and it is where the interesting rule lives.
//!
//! **The owned media siblings are never raced against each other.** For media,
//! each domain in the zone Nova controls becomes a batch of one, so the
//! persisted last-good score picks the first and its sibling is a sequential
//! fallback rather than a simultaneous one. Racing them halves nothing and
//! doubles the Worker invocations, which are the metered resource — the same
//! quota whose exhaustion shows up as the `429` that N10 measured.
//!
//! Everything else is raced `race_width` at a time, in the order the health
//! table produced.
//!
//! The batch shapes asserted below were produced by **executing** the batching
//! block out of `_connect_cf_ws_route` — the statements taken verbatim by AST and
//! run over the same inputs — not by reading it.

use std::time::Duration;

/// `CF_CONNECT_RACE_WIDTH`, clamped the way the Python clamps it: at least one,
/// at most six.
pub const DEFAULT_RACE_WIDTH: usize = 3;
pub const MAX_RACE_WIDTH: usize = 6;

/// `CF_MEDIA_CONNECT_BUDGET` — the whole race for media gets this long, however
/// many batches it takes. Media is latency-critical and has a plain-TCP
/// fallback; a slow race there costs more than a missed candidate.
pub const MEDIA_CONNECT_BUDGET: Duration = Duration::from_secs(3);

/// Per-attempt connect timeout.
///
/// Media is quickest because it is racing wide and has somewhere to fall back
/// to; `primary_only` is the bootstrap, which must not sit on a dead name while
/// the client waits; the general case is the most patient of the three.
pub fn attempt_timeout(media: bool, primary_only: bool) -> Duration {
    if media {
        Duration::from_millis(2500)
    } else if primary_only {
        Duration::from_millis(3500)
    } else {
        Duration::from_secs(7)
    }
}

/// What to dial, in what groups, and for how long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RacePlan {
    /// Dialled together; the first to answer wins and the rest are cancelled.
    pub batches: Vec<Vec<String>>,
    /// How long any one attempt may take.
    pub attempt_timeout: Duration,
    /// A ceiling on the whole race, or `None` when there is none. Only media
    /// has one.
    pub total_budget: Option<Duration>,
}

impl RacePlan {
    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    /// Every candidate, in the order it will be tried.
    pub fn candidates(&self) -> Vec<&str> {
        self.batches.iter().flatten().map(String::as_str).collect()
    }
}

/// Drop the domains the caller has already given up on this round.
///
/// The exclusion set is how a retry avoids re-picking the route that just failed
/// it, without touching the health table — which is the right split, because a
/// route being wrong *for this attempt* is not the same as it being unhealthy.
pub fn exclude(domains: &[String], excluded: &[&str]) -> Vec<String> {
    let excluded: Vec<String> = excluded.iter().map(|d| d.trim().to_ascii_lowercase()).collect();
    domains.iter().filter(|d| !excluded.contains(&d.trim().to_ascii_lowercase())).cloned().collect()
}

/// Group an ordered candidate list into the batches the race will use.
///
/// `owned_bases` names the zones Nova controls; only their media siblings get
/// the one-at-a-time treatment.
pub fn plan(
    ordered: &[String],
    media: bool,
    primary_only: bool,
    owned_bases: &[&str],
    race_width: usize,
) -> RacePlan {
    let width = race_width.clamp(1, MAX_RACE_WIDTH).min(ordered.len().max(1));
    let mut batches: Vec<Vec<String>> = Vec::new();
    let mut remaining: Vec<String> = ordered.to_vec();

    if media {
        let owned: Vec<String> = remaining.iter().filter(|d| is_owned(d, owned_bases)).cloned().collect();
        remaining.retain(|d| !is_owned(d, owned_bases));
        // One each, and *before* the rest: the score has already put the better
        // of them first, and this preserves that ordering as a sequence.
        batches.extend(owned.into_iter().map(|d| vec![d]));
    }
    batches.extend(remaining.chunks(width).map(<[String]>::to_vec));

    RacePlan {
        batches,
        attempt_timeout: attempt_timeout(media, primary_only),
        total_budget: media.then_some(MEDIA_CONNECT_BUDGET),
    }
}

fn is_owned(domain: &str, owned_bases: &[&str]) -> bool {
    let domain = domain.trim().to_ascii_lowercase();
    owned_bases.iter().any(|base| {
        let base = base.trim().to_ascii_lowercase();
        !base.is_empty() && (domain == base || domain.ends_with(&format!(".{base}")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNED: &[&str] = &["nova-app.eu"];

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn shape(plan: &RacePlan) -> Vec<Vec<&str>> {
        plan.batches.iter().map(|b| b.iter().map(String::as_str).collect()).collect()
    }

    #[test]
    fn the_plain_case_races_three_at_a_time_in_the_order_given() {
        let ordered = names(&["a.nova-app.eu", "b.pclead.co.uk", "c.offshor.co.uk", "d.cakeisalie.co.uk"]);
        let plan = plan(&ordered, false, false, OWNED, DEFAULT_RACE_WIDTH);
        assert_eq!(
            shape(&plan),
            vec![vec!["a.nova-app.eu", "b.pclead.co.uk", "c.offshor.co.uk"], vec!["d.cakeisalie.co.uk"]]
        );
        assert_eq!(plan.attempt_timeout, Duration::from_secs(7));
        assert_eq!(plan.total_budget, None, "only media is on a clock");
    }

    #[test]
    fn media_never_races_the_owned_siblings_against_each_other() {
        // Racing them doubles the Worker invocations, which are the metered
        // resource, and gains nothing: the score already put the better first.
        let ordered = names(&["kws2-1.nova-app.eu", "kws5-1.nova-app.eu", "kws2-1.pclead.co.uk"]);
        let plan = plan(&ordered, true, false, OWNED, DEFAULT_RACE_WIDTH);
        assert_eq!(
            shape(&plan),
            vec![vec!["kws2-1.nova-app.eu"], vec!["kws5-1.nova-app.eu"], vec!["kws2-1.pclead.co.uk"]]
        );
    }

    #[test]
    fn the_owned_ones_keep_their_order_and_come_first() {
        let ordered = names(&["x.pclead.co.uk", "kws5-1.nova-app.eu", "kws2-1.nova-app.eu"]);
        let plan = plan(&ordered, true, false, OWNED, DEFAULT_RACE_WIDTH);
        assert_eq!(
            plan.candidates(),
            ["kws5-1.nova-app.eu", "kws2-1.nova-app.eu", "x.pclead.co.uk"],
            "the score's order among the owned survives, and they are tried before the pool"
        );
    }

    #[test]
    fn a_plain_race_does_not_single_out_the_owned_zone() {
        // The rule is about media only: the plain path has no `-1` sibling
        // problem and no reason to give up the parallelism.
        let ordered = names(&["kws2.nova-app.eu", "kws5.nova-app.eu", "kws2.pclead.co.uk"]);
        let plan = plan(&ordered, false, false, OWNED, DEFAULT_RACE_WIDTH);
        assert_eq!(shape(&plan).len(), 1, "all three at once");
    }

    #[test]
    fn the_three_attempt_timeouts_are_the_pythons() {
        assert_eq!(attempt_timeout(true, false), Duration::from_millis(2500));
        assert_eq!(attempt_timeout(true, true), Duration::from_millis(2500), "media wins over bootstrap");
        assert_eq!(attempt_timeout(false, true), Duration::from_millis(3500));
        assert_eq!(attempt_timeout(false, false), Duration::from_secs(7));
    }

    #[test]
    fn only_media_gets_a_ceiling_on_the_whole_race() {
        let ordered = names(&["a.pclead.co.uk"]);
        assert_eq!(plan(&ordered, true, false, OWNED, 3).total_budget, Some(MEDIA_CONNECT_BUDGET));
        assert_eq!(plan(&ordered, false, false, OWNED, 3).total_budget, None);
    }

    #[test]
    fn the_width_is_clamped_at_both_ends() {
        let ordered = names(&["a.x", "b.x", "c.x", "d.x", "e.x", "f.x", "g.x", "h.x"]);
        assert_eq!(shape(&plan(&ordered, false, false, OWNED, 0))[0].len(), 1, "never zero-wide");
        // At six the Python produced [6, 2]; the whole shape, not just the head.
        assert_eq!(
            shape(&plan(&ordered, false, false, OWNED, 99)),
            vec![vec!["a.x", "b.x", "c.x", "d.x", "e.x", "f.x"], vec!["g.x", "h.x"]]
        );
    }

    #[test]
    fn nothing_to_race_is_an_empty_plan_rather_than_an_empty_batch() {
        // An empty batch would be dialled and would answer nothing, which reads
        // downstream as "every candidate failed" rather than "there were none".
        let plan = plan(&[], false, false, OWNED, DEFAULT_RACE_WIDTH);
        assert!(plan.is_empty());
        assert!(plan.candidates().is_empty());
    }

    #[test]
    fn exclusions_are_case_insensitive_and_keep_the_rest_in_order() {
        let domains = names(&["kws2.nova-app.eu", "kws2.pclead.co.uk", "kws2.offshor.co.uk"]);
        assert_eq!(
            exclude(&domains, &["KWS2.PCLead.co.uk", "  kws2.offshor.co.uk "]),
            names(&["kws2.nova-app.eu"])
        );
        assert_eq!(exclude(&domains, &[]), domains, "no exclusions, no change");
    }

    #[test]
    fn an_exclusion_is_about_this_attempt_and_not_about_health() {
        // Stated as a test because the two are easy to conflate: a route being
        // wrong for this retry does not make it unhealthy, and pushing it into
        // the bench here would demote it for everyone.
        let domains = names(&["kws2.nova-app.eu", "kws2.pclead.co.uk"]);
        let after = exclude(&domains, &["kws2.nova-app.eu"]);
        assert_eq!(after, names(&["kws2.pclead.co.uk"]));
        // The original list is untouched — nothing here has side effects.
        assert_eq!(domains.len(), 2);
    }

    #[test]
    fn every_candidate_appears_exactly_once_however_it_is_grouped() {
        let ordered =
            names(&["kws2-1.nova-app.eu", "kws5-1.nova-app.eu", "a.pclead.co.uk", "b.offshor.co.uk", "c.x.co"]);
        for media in [true, false] {
            let plan = plan(&ordered, media, false, OWNED, DEFAULT_RACE_WIDTH);
            let mut seen = plan.candidates();
            seen.sort_unstable();
            let mut expected: Vec<&str> = ordered.iter().map(String::as_str).collect();
            expected.sort_unstable();
            assert_eq!(seen, expected, "media={media}");
        }
    }
}
