//! Which Worker domain to race first, and which to leave out.
//!
//! Layer 8 of the port out of `tgrelay/transparent_relay.py`: `_cf_domain_score`,
//! `_cf_bad_domain_until`, `_cf_order_domains`, `_cf_filter_bad_domains`,
//! `_cf_note_bad_domain`, `_cf_note_good_route_label`, `_cf_empty_route_ttl`.
//!
//! **This is a per-domain health table, and P14 is worth re-reading against it.**
//! The open note says a real fix for "a reconnecting client re-picks the same
//! dead zones" needs a per-domain dimension inside `cf`, because the first-byte
//! circuit is keyed `(dc, media, route_kind)` and demoting there would take the
//! healthy zone down with the dead ones. That is true of the *circuit*. It is not
//! the whole picture: this table is per domain, it already exists, and
//! `_cf_note_bad_route_label` already fires on exactly the empty close P14
//! describes — 30 s for a plain route, 60 s for `nova-app.eu`, 45 s for whichever
//! domain last worked. So the question for the next session is not "how do we add
//! a per-domain dimension" but "why did the one we have not stop the cycling".
//! Do not build the second mechanism before answering that.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// `CF_RECENT_GOOD_TTL` — a score older than this stops counting.
pub const SCORE_FRESHNESS: Duration = Duration::from_secs(900);
/// `CF_EMPTY_DOMAIN_TTL` — a plain route that closed empty.
pub const EMPTY_TTL: Duration = Duration::from_secs(30);
/// `CF_EMPTY_PRIMARY_TTL` — the owner's own zone gets longer, because there is
/// nowhere better to fall back to and re-racing it costs the whole round.
pub const EMPTY_PRIMARY_TTL: Duration = Duration::from_secs(60);
/// `CF_EMPTY_RECENT_GOOD_TTL` — the domain that last carried this pair. It going
/// empty is more surprising, so it is stood down for longer rather than less.
pub const EMPTY_RECENT_GOOD_TTL: Duration = Duration::from_secs(45);
/// `CF_MEDIA_BAD_TTL` — media races are wide and cheap, so a bad media domain is
/// forgiven quickly.
pub const MEDIA_BAD_TTL: Duration = Duration::from_secs(6);

/// The score ceiling. Reached by a domain that has carried real volume several
/// times; without it a long-lived favourite would become unseatable.
const SCORE_CEILING: f64 = 100.0;
/// The most one tunnel can add, however much it carried.
const MAX_GAIN: f64 = 25.0;

/// How much one successful tunnel is worth.
///
/// `min(25, 2 + bit_length(down) / 2)` — logarithmic in the byte count, so a
/// handshake-sized reply is worth something and a 10 MB download is worth about
/// three times as much rather than ten thousand times. The floor of 2 is what
/// makes reachability itself count.
pub fn score_gain(down: u64) -> f64 {
    let bits = if down == 0 { 0 } else { down.ilog2() + 1 };
    (2.0 + f64::from(bits) / 2.0).min(MAX_GAIN)
}

/// How long a domain that closed empty is left out of the race.
///
/// `is_primary` is "this is the owner's own zone", not "it is first in the list".
pub fn empty_route_ttl(is_media: bool, is_primary: bool, was_last_good: bool) -> Duration {
    if is_media {
        return MEDIA_BAD_TTL;
    }
    let mut ttl = EMPTY_TTL;
    if is_primary {
        ttl = ttl.max(EMPTY_PRIMARY_TTL);
    }
    if was_last_good {
        ttl = ttl.max(EMPTY_RECENT_GOOD_TTL);
    }
    ttl
}

#[derive(Debug, Clone, Copy)]
struct Score {
    value: f64,
    seen: Instant,
}

/// Per-domain memory: how well each Worker zone has served, and which are
/// currently benched.
#[derive(Debug, Clone, Default)]
pub struct CfDomainHealth {
    scores: HashMap<String, Score>,
    benched_until: HashMap<String, Instant>,
}

fn key(domain: &str) -> String {
    domain.trim().to_ascii_lowercase()
}

/// Pull the domain out of a route label (`domain@ip via egress`).
pub fn domain_of(route_label: &str) -> String {
    key(route_label.split(" via ").next().unwrap_or("").split('@').next().unwrap_or(""))
}

impl CfDomainHealth {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_benched(&self, domain: &str, now: Instant) -> bool {
        self.benched_until.get(&key(domain)).is_some_and(|t| *t > now)
    }

    /// The score, or `0.0` once it has gone stale.
    pub fn fresh_score(&self, domain: &str, now: Instant) -> f64 {
        self.scores
            .get(&key(domain))
            .filter(|s| now.duration_since(s.seen) <= SCORE_FRESHNESS)
            .map_or(0.0, |s| s.value)
    }

    /// A tunnel through this domain carried bytes.
    ///
    /// Un-benches it as well as raising the score: a domain that just worked is
    /// not on probation, whatever it did a minute ago.
    pub fn note_good(&mut self, domain: &str, down: u64, now: Instant) {
        let k = key(domain);
        if k.is_empty() || down == 0 {
            return;
        }
        self.benched_until.remove(&k);
        let previous = self.scores.get(&k).map_or(0.0, |s| s.value);
        let value = (previous + score_gain(down)).min(SCORE_CEILING);
        self.scores.insert(k, Score { value, seen: now });
    }

    /// Put a score back exactly as it was, at the moment it was earned.
    ///
    /// Distinct from [`Self::note_good`] on purpose: that one *adds* a gain, so
    /// restoring a cache with it would inflate every score by one tunnel's worth
    /// on every restart.
    pub fn restore_score(&mut self, domain: &str, value: f64, seen: Instant) {
        let k = key(domain);
        if k.is_empty() || value <= 0.0 {
            return;
        }
        self.scores.insert(k, Score { value: value.min(SCORE_CEILING), seen });
    }

    /// Every score still inside its freshness window, for persisting.
    pub fn live_scores(&self, now: Instant) -> Vec<(String, f64, Instant)> {
        self.scores
            .iter()
            .filter(|(_, s)| now.duration_since(s.seen) <= SCORE_FRESHNESS && s.value > 0.0)
            .map(|(domain, s)| (domain.clone(), s.value, s.seen))
            .collect()
    }

    /// A tunnel through this domain failed or closed empty.
    ///
    /// The score is **halved rather than zeroed**, so a zone with a long record
    /// survives one bad round and a zone with none is out after one. And `seen`
    /// is refreshed even though this is bad news: the halved score has to stay
    /// live for the freshness window, or the next comparison would read it as
    /// "never measured" and treat the domain as untried.
    pub fn note_bad(&mut self, domain: &str, ttl: Duration, now: Instant) {
        let k = key(domain);
        if k.is_empty() {
            return;
        }
        self.benched_until.insert(k.clone(), now + ttl);
        let previous = self.scores.get(&k).map_or(0.0, |s| s.value);
        self.scores.insert(k, Score { value: (previous * 0.5).max(0.0), seen: now });
    }

    /// Drop the benched domains, keeping the caller's order.
    pub fn filter_benched(&self, domains: &[String], now: Instant) -> Vec<String> {
        domains.iter().filter(|d| !self.is_benched(d, now)).cloned().collect()
    }

    /// The race order: benched dropped, then the domain that last carried this
    /// pair, then by score, then by the caller's own order.
    ///
    /// The caller's order is the *last* tiebreaker rather than the first, which
    /// is the whole point — the configured list is a starting guess and the
    /// measurements outrank it.
    pub fn order(&self, domains: &[String], last_good: Option<&str>, now: Instant) -> Vec<String> {
        let mut kept = self.filter_benched(domains, now);
        let last_good = last_good.map(key).filter(|d| !d.is_empty());
        let position: HashMap<String, usize> = kept.iter().enumerate().map(|(i, d)| (d.clone(), i)).collect();
        kept.sort_by(|a, b| {
            let rank = |d: &String| {
                (
                    u8::from(last_good.as_deref() == Some(key(d).as_str())),
                    self.fresh_score(d, now),
                    position.get(d).copied().unwrap_or(usize::MAX),
                )
            };
            let (a_good, a_score, a_pos) = rank(a);
            let (b_good, b_score, b_pos) = rank(b);
            b_good.cmp(&a_good).then(b_score.total_cmp(&a_score)).then(a_pos.cmp(&b_pos))
        });
        kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn as_str(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn a_route_label_yields_its_domain() {
        assert_eq!(domain_of("kws2.nova-app.eu via warp-socks"), "kws2.nova-app.eu");
        assert_eq!(domain_of("KWS2-1.PCLead.co.uk@104.21.0.1 via direct"), "kws2-1.pclead.co.uk");
        assert_eq!(domain_of(""), "");
        assert_eq!(domain_of(" via opera-http"), "");
    }

    #[test]
    fn the_gain_is_logarithmic_in_what_was_carried() {
        // Reachability alone is worth something…
        assert_eq!(score_gain(1), 2.5);
        assert_eq!(score_gain(4096), 8.5);
        // …and a large download is worth a few times that, not thousands.
        assert_eq!(score_gain(10 * 1024 * 1024), 14.0);
        assert_eq!(score_gain(u64::MAX), MAX_GAIN);
        // A tunnel that carried nothing is not a success at all; `note_good`
        // refuses it before this is ever consulted.
        assert_eq!(score_gain(0), 2.0);
    }

    #[test]
    fn a_tunnel_that_carried_nothing_is_not_recorded_as_good() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_good("kws2.nova-app.eu", 0, now);
        assert_eq!(health.fresh_score("kws2.nova-app.eu", now), 0.0);
    }

    #[test]
    fn scores_accumulate_up_to_a_ceiling() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        for _ in 0..100 {
            health.note_good("kws2.nova-app.eu", 4096, now);
        }
        assert_eq!(health.fresh_score("kws2.nova-app.eu", now), SCORE_CEILING);
    }

    #[test]
    fn a_bad_round_halves_the_score_rather_than_erasing_it() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_good("kws2.nova-app.eu", 4096, now); // 8.5
        health.note_bad("kws2.nova-app.eu", EMPTY_TTL, now);
        assert_eq!(health.fresh_score("kws2.nova-app.eu", now), 4.25);
        // A zone with no record is out after one.
        health.note_bad("kws2.offshor.co.uk", EMPTY_TTL, now);
        assert_eq!(health.fresh_score("kws2.offshor.co.uk", now), 0.0);
    }

    #[test]
    fn a_halved_score_stays_live_instead_of_reading_as_never_measured() {
        // `note_bad` refreshes `seen`. Without that, a domain benched near the
        // end of its freshness window would come back looking untried, and an
        // untried domain outranks a measured-but-poor one on nothing but hope.
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_good("kws2.nova-app.eu", 4096, now);
        let late = now + SCORE_FRESHNESS - Duration::from_secs(1);
        health.note_bad("kws2.nova-app.eu", EMPTY_TTL, late);
        assert_eq!(health.fresh_score("kws2.nova-app.eu", late + Duration::from_secs(60)), 4.25);
    }

    #[test]
    fn a_stale_score_stops_counting() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_good("kws2.nova-app.eu", 4096, now);
        assert_eq!(health.fresh_score("kws2.nova-app.eu", now + SCORE_FRESHNESS), 8.5);
        assert_eq!(health.fresh_score("kws2.nova-app.eu", now + SCORE_FRESHNESS + Duration::from_secs(1)), 0.0);
    }

    #[test]
    fn a_domain_that_works_again_is_un_benched_at_once() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_bad("kws2.pclead.co.uk", EMPTY_TTL, now);
        assert!(health.is_benched("kws2.pclead.co.uk", now));
        health.note_good("kws2.pclead.co.uk", 1, now);
        assert!(!health.is_benched("kws2.pclead.co.uk", now));
    }

    #[test]
    fn the_bench_expires_on_its_own() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_bad("kws2.pclead.co.uk", EMPTY_TTL, now);
        assert!(health.is_benched("kws2.pclead.co.uk", now + Duration::from_secs(29)));
        assert!(!health.is_benched("kws2.pclead.co.uk", now + Duration::from_secs(31)));
    }

    #[test]
    fn benched_domains_are_dropped_from_the_race() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_bad("kws2.pclead.co.uk", EMPTY_TTL, now);
        let all = names(&["kws2.nova-app.eu", "kws2.pclead.co.uk", "kws2.offshor.co.uk"]);
        assert_eq!(as_str(&health.order(&all, None, now)), ["kws2.nova-app.eu", "kws2.offshor.co.uk"]);
    }

    #[test]
    fn with_nothing_measured_the_configured_order_stands() {
        let now = Instant::now();
        let health = CfDomainHealth::new();
        let all = names(&["kws2.nova-app.eu", "kws2.pclead.co.uk", "kws2.offshor.co.uk"]);
        assert_eq!(health.order(&all, None, now), all);
    }

    #[test]
    fn measurements_outrank_the_configured_order() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_good("kws2.offshor.co.uk", 1_000_000, now);
        let all = names(&["kws2.nova-app.eu", "kws2.pclead.co.uk", "kws2.offshor.co.uk"]);
        assert_eq!(
            as_str(&health.order(&all, None, now)),
            ["kws2.offshor.co.uk", "kws2.nova-app.eu", "kws2.pclead.co.uk"]
        );
    }

    #[test]
    fn the_last_good_domain_outranks_even_a_better_score() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_good("kws2.offshor.co.uk", 10_000_000, now);
        health.note_good("kws2.pclead.co.uk", 1, now);
        let all = names(&["kws2.nova-app.eu", "kws2.pclead.co.uk", "kws2.offshor.co.uk"]);
        assert_eq!(
            as_str(&health.order(&all, Some("KWS2.PCLead.co.uk"), now)),
            ["kws2.pclead.co.uk", "kws2.offshor.co.uk", "kws2.nova-app.eu"]
        );
    }

    #[test]
    fn a_last_good_domain_that_is_benched_does_not_come_back_through_the_side_door() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_bad("kws2.pclead.co.uk", EMPTY_TTL, now);
        let all = names(&["kws2.nova-app.eu", "kws2.pclead.co.uk"]);
        assert_eq!(as_str(&health.order(&all, Some("kws2.pclead.co.uk"), now)), ["kws2.nova-app.eu"]);
    }

    #[test]
    fn an_empty_close_benches_the_owners_zone_for_longest() {
        assert_eq!(empty_route_ttl(false, false, false), EMPTY_TTL);
        assert_eq!(empty_route_ttl(false, true, false), EMPTY_PRIMARY_TTL);
        assert_eq!(empty_route_ttl(false, false, true), EMPTY_RECENT_GOOD_TTL);
        assert_eq!(empty_route_ttl(false, true, true), EMPTY_PRIMARY_TTL, "the longest of the two wins");
        // Media races are wide and cheap; a bad domain there is forgiven fast.
        assert_eq!(empty_route_ttl(true, true, true), MEDIA_BAD_TTL);
    }

    #[test]
    fn an_empty_domain_name_is_ignored_rather_than_stored() {
        let now = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_bad("   ", EMPTY_TTL, now);
        health.note_good("", 4096, now);
        assert!(!health.is_benched("", now));
        assert_eq!(health.fresh_score("", now), 0.0);
    }
}
