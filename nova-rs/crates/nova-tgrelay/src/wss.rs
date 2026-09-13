//! Which WSS route to try, and when to stop trying.
//!
//! Layer 6 of the port out of `tgrelay/transparent_relay.py`. Two things live
//! here, both I/O-free:
//!
//! - **The candidate domains** for a `(dc, media)` pair, over Telegram Web and
//!   over our own Worker zones. The two lists follow different rules for media
//!   and the difference is deliberate — see [`cf_domains`].
//! - **The first-byte circuit breaker.** A WSS route that completes its upgrade
//!   and then delivers nothing is the relay's most common failure, and retrying
//!   it in a tight loop is what makes a cold start feel dead. After N such
//!   tunnels the route is paused for a while. Both N and "a while" come from a
//!   three-way nested conditional in the Python that no test could reach;
//!   [`trip_threshold`] and [`disable_ttl`] are that conditional as a table, with
//!   all eight combinations asserted.

use crate::egress::Dc;
use crate::route::WssRouteKind;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// DC 203 is DC 2 wearing a different number. Every domain builder folds it
/// before formatting, so `kws203.…` is a name that never gets constructed.
const DC_203: u16 = 203;
const DC_203_FOLDS_TO: u16 = 2;

fn fold_dc(dc: Dc) -> u16 {
    if dc.get() == DC_203 {
        DC_203_FOLDS_TO
    } else {
        dc.get()
    }
}

/// Telegram Web's own upstreams for a `(dc, media)` pair.
///
/// **Media keeps the plain sibling here, and drops it in [`cf_domains`].** That
/// is not an inconsistency: on our Worker the `-1` name is what selects
/// Telegram's media upstream, so the plain sibling silently routes a media
/// session to a non-media upstream. `kwsN.web.telegram.org` is Telegram's own
/// host and answers for itself.
pub fn web_domains(dc: Dc, media: bool) -> Vec<String> {
    let n = fold_dc(dc);
    if media {
        vec![format!("kws{n}-1.web.telegram.org"), format!("kws{n}.web.telegram.org")]
    } else {
        vec![format!("kws{n}.web.telegram.org")]
    }
}

/// Worker-zone upstreams, one or two names per base, in the order given.
///
/// **The plain sibling is excluded for media in every zone.** The Worker picks
/// Telegram's media upstream from the `-1` hostname, so `kwsN.<zone>` hands a
/// media session to a non-media upstream: the handshake succeeds and then
/// nothing ever arrives.
///
/// This used to exclude the sibling for `nova-app.eu` alone, which made the
/// other zones actively harmful — their `-1` names have no DNS record, so a
/// media race offered exactly one resolvable candidate per zone, the broken
/// sibling, and it won by answering first every time. Measured:
/// `kws2.pclead.co.uk` answers 101 in ~350 ms and then delivers `down=0`, while
/// `kws2-1.pclead.co.uk` does not resolve at all. Dropping it costs zone
/// diversity for media until those zones get their `-1` records (I9, N7);
/// carrying it cost media entirely.
pub fn cf_domains(dc: Dc, bases: &[&str], media: bool) -> Vec<String> {
    let n = fold_dc(dc);
    let mut out: Vec<String> = Vec::new();
    for base in bases {
        let base = base.trim().to_ascii_lowercase();
        if base.is_empty() {
            continue;
        }
        let name = if media { format!("kws{n}-1.{base}") } else { format!("kws{n}.{base}") };
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// What the breaker is allowed to know about the wider situation.
///
/// Both flags come from outside this module because both are about
/// configuration and history rather than about this route: whether the owner's
/// own Worker zone is configured at all, and whether *some* Worker domain
/// carried bytes for this `(dc, media)` pair recently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitContext {
    /// `_has_custom_cfproxy_domain()` — is `nova-app.eu` among the bases? With
    /// it there is somewhere else to go, so the breaker can afford to be quick.
    pub has_custom_cf: bool,
    /// `_cf_has_recent_good(dc, media, max_age=180)`.
    pub has_recent_good: bool,
}

/// How many empty tunnels in a row open the circuit.
///
/// The Python writes this as
/// `2 if (media and has_cf) else (4 if recent_good else (3 if has_cf else 2))`,
/// which is unreachable from a test and reads as arbitrary. It is not: the
/// number is *patience*, and patience is bought with alternatives. Media with a
/// Worker configured has the most to gain from moving on and the least to lose,
/// so it moves after two. A pair that worked recently gets the most patience —
/// four — because the likely explanation is a blip, not a dead route.
pub fn trip_threshold(media: bool, ctx: CircuitContext) -> u32 {
    if media && ctx.has_custom_cf {
        2
    } else if ctx.has_recent_good {
        4
    } else if ctx.has_custom_cf {
        3
    } else {
        2
    }
}

/// How long the circuit stays open.
///
/// `3 if (recent_good or (media and has_cf)) else (8 if media else 15)`. The
/// short pause is for the cases where something else is known to work, so the
/// cost of being wrong is one round trip; the long one is for the case where
/// opening the circuit means falling back to raw TCP.
pub fn disable_ttl(media: bool, ctx: CircuitContext) -> Duration {
    if ctx.has_recent_good || (media && ctx.has_custom_cf) {
        Duration::from_secs(3)
    } else if media {
        Duration::from_secs(8)
    } else {
        Duration::from_secs(15)
    }
}

/// The circuit just opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tripped {
    pub ttl: Duration,
    /// The line to log, already worded. See [`FirstByteCircuit::note`].
    pub message: String,
}

#[derive(Debug, Clone, Copy)]
struct Failures {
    count: u32,
    first_seen: Instant,
}

type Key = (u16, bool, WssRouteKind);

/// One breaker per `(dc, media, route_kind)`.
///
/// The `route_kind` dimension is load-bearing. Before it existed the key was
/// `(dc, media)` alone, and two empty replies from the weaker route tripped the
/// breaker for the healthy one on the same DC — visible in the log as a
/// `web.telegram.org` pair at `down=0` followed immediately by the Worker zone
/// being paused.
#[derive(Debug, Clone)]
pub struct FirstByteCircuit {
    /// Failures older than this stop counting towards a trip.
    window: Duration,
    fails: HashMap<Key, Failures>,
    disabled_until: HashMap<Key, Instant>,
}

impl Default for FirstByteCircuit {
    fn default() -> Self {
        Self::new(Duration::from_secs(45))
    }
}

impl FirstByteCircuit {
    pub fn new(window: Duration) -> Self {
        Self { window, fails: HashMap::new(), disabled_until: HashMap::new() }
    }

    /// Is this exact route paused?
    pub fn is_disabled(&self, dc: Dc, media: bool, kind: WssRouteKind, now: Instant) -> bool {
        self.disabled_until.get(&(dc.get(), media, kind)).is_some_and(|t| *t > now)
    }

    /// Is WSS worth attempting at all for this pair?
    ///
    /// Yes while **any** kind is still live. One dead route must not speak for
    /// the other — that is the same mistake the `route_kind` split was
    /// introduced to end, one level up.
    pub fn is_disabled_for_any_kind(&self, dc: Dc, media: bool, now: Instant) -> bool {
        WssRouteKind::ALL.iter().all(|kind| self.is_disabled(dc, media, *kind, now))
    }

    /// File what a finished WSS tunnel delivered.
    ///
    /// `down > 0` clears the route outright: one working tunnel is enough, and
    /// counting it as anything less would leave a healthy route half-condemned.
    /// Otherwise the failure is counted inside a sliding window, and the count
    /// resets when it trips so the next trip needs a fresh run of failures.
    pub fn note(
        &mut self,
        dc: Dc,
        media: bool,
        kind: WssRouteKind,
        down: u64,
        ctx: CircuitContext,
        now: Instant,
    ) -> Option<Tripped> {
        let key = (dc.get(), media, kind);
        if down > 0 {
            self.fails.remove(&key);
            self.disabled_until.remove(&key);
            return None;
        }

        let entry = self.fails.get(&key).copied();
        let stale = entry.is_none_or(|f| now.duration_since(f.first_seen) > self.window);
        let mut failures = if stale { Failures { count: 0, first_seen: now } } else { entry.expect("checked") };
        failures.count += 1;

        if failures.count < trip_threshold(media, ctx) {
            self.fails.insert(key, failures);
            return None;
        }

        let ttl = disable_ttl(media, ctx);
        self.disabled_until.insert(key, now + ttl);
        self.fails.insert(key, Failures { count: 0, first_seen: now });
        // Two different situations wear the same symptom, and the operator has
        // to be able to tell them apart in the log: with a Worker configured the
        // relay simply waits, without one it drops to raw TCP over WARP.
        let action = if ctx.has_custom_cf {
            "pausing WSS retries without raw TCP fallback"
        } else {
            "using TCP fallback via WARP"
        };
        let route = match kind {
            WssRouteKind::Cf => "cf",
            WssRouteKind::Web => "web",
        };
        Some(Tripped {
            ttl,
            // `media={bool(is_media)}` in an f-string prints Python's `True`
            // and `False`. The relay's own log lines are grep targets, so the
            // capitals are part of the contract, not a style choice.
            message: format!(
                "[TgRelay] WSS first-byte circuit: dc={} media={} route={} disabled_for={}s; {}.",
                dc.get(),
                if media { "True" } else { "False" },
                route,
                ttl.as_secs(),
                action
            ),
        })
    }

    /// Forget everything. The relay does this when the egress set changes under
    /// it: verdicts earned against one set of routes say nothing about another.
    pub fn clear(&mut self) {
        self.fails.clear();
        self.disabled_until.clear();
    }
}

/// Which Worker domain last carried bytes for a `(dc, media)` pair.
///
/// **Simplified from the Python, and the simplification is the point.**
/// `_cf_last_good_domain` stores `now + CF_RECENT_GOOD_TTL` and
/// `_cf_has_recent_good` then asks `until > now + (TTL - max_age)`. Substituting
/// the stored value, that reduces to `written_at > now - max_age` — "was there
/// one within `max_age`" — but the arithmetic reads like a bug and cannot be
/// checked by eye. The instant is stored directly here and the question is asked
/// directly.
#[derive(Debug, Clone)]
pub struct RecentGood {
    ttl: Duration,
    seen: HashMap<(u16, bool), (String, Instant)>,
}

impl Default for RecentGood {
    fn default() -> Self {
        Self::new(Duration::from_secs(900))
    }
}

impl RecentGood {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, seen: HashMap::new() }
    }

    pub fn note(&mut self, dc: Dc, media: bool, domain: &str, now: Instant) {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return;
        }
        self.seen.insert((dc.get(), media), (domain, now));
    }

    /// The domain, while the entry is still within its TTL.
    pub fn domain(&self, dc: Dc, media: bool, now: Instant) -> Option<&str> {
        let (domain, seen) = self.seen.get(&(dc.get(), media))?;
        (now.duration_since(*seen) <= self.ttl).then_some(domain.as_str())
    }

    /// `_cf_has_recent_good`.
    pub fn within(&self, dc: Dc, media: bool, max_age: Duration, now: Instant) -> bool {
        self.seen
            .get(&(dc.get(), media))
            .is_some_and(|(_, seen)| now.duration_since(*seen) <= max_age.min(self.ttl))
    }
}

/// The window `_note_wss_first_byte_result` asks about.
pub const RECENT_GOOD_MAX_AGE: Duration = Duration::from_secs(180);

#[cfg(test)]
mod tests {
    use super::*;

    fn dc(n: u16) -> Dc {
        Dc::new(n).expect("dc")
    }

    fn ctx(has_custom_cf: bool, has_recent_good: bool) -> CircuitContext {
        CircuitContext { has_custom_cf, has_recent_good }
    }

    #[test]
    fn dc_203_is_dc_2_everywhere_a_name_is_built() {
        assert_eq!(web_domains(dc(203), false), ["kws2.web.telegram.org"]);
        assert_eq!(cf_domains(dc(203), &["nova-app.eu"], false), ["kws2.nova-app.eu"]);
    }

    #[test]
    fn telegram_web_offers_the_plain_sibling_for_media_and_the_worker_does_not() {
        assert_eq!(
            web_domains(dc(2), true),
            ["kws2-1.web.telegram.org", "kws2.web.telegram.org"],
            "Telegram's own host answers for itself"
        );
        assert_eq!(
            cf_domains(dc(2), &["nova-app.eu"], true),
            ["kws2-1.nova-app.eu"],
            "the Worker reads the media upstream off the -1 name"
        );
    }

    #[test]
    fn worker_bases_keep_their_order_and_are_deduplicated() {
        let bases = ["nova-app.eu", "  PCLead.co.uk ", "nova-app.eu", "", "   "];
        assert_eq!(cf_domains(dc(4), &bases, false), ["kws4.nova-app.eu", "kws4.pclead.co.uk"]);
    }

    #[test]
    fn no_bases_means_no_worker_candidates() {
        assert!(cf_domains(dc(2), &[], false).is_empty());
        assert!(cf_domains(dc(2), &["", "  "], true).is_empty());
    }

    /// The whole nested conditional, spelled out. If any of these change, it was
    /// a decision, not a refactor.
    #[test]
    fn the_threshold_and_ttl_table_is_exactly_what_the_python_computes() {
        //           media, has_cf, recent_good -> threshold, ttl seconds
        let table = [
            (true, true, true, 2u32, 3u64),
            (true, true, false, 2, 3),
            (true, false, true, 4, 3),
            (true, false, false, 2, 8),
            (false, true, true, 4, 3),
            (false, true, false, 3, 15),
            (false, false, true, 4, 3),
            (false, false, false, 2, 15),
        ];
        for (media, cf, good, threshold, ttl) in table {
            let c = ctx(cf, good);
            assert_eq!(trip_threshold(media, c), threshold, "threshold for {media} {cf} {good}");
            assert_eq!(disable_ttl(media, c), Duration::from_secs(ttl), "ttl for {media} {cf} {good}");
        }
    }

    #[test]
    fn media_with_a_worker_is_the_quickest_to_give_up_and_the_quickest_to_retry() {
        // The pair that has somewhere else to go moves on after two and comes
        // back after three seconds. Stated as its own test because it is the
        // reason the table is not uniform.
        let c = ctx(true, false);
        assert_eq!(trip_threshold(true, c), 2);
        assert_eq!(disable_ttl(true, c), Duration::from_secs(3));
        assert_eq!(trip_threshold(false, c), 3);
        assert_eq!(disable_ttl(false, c), Duration::from_secs(15));
    }

    #[test]
    fn the_circuit_opens_only_on_the_threshold_failure() {
        let now = Instant::now();
        let c = ctx(true, false);
        let mut circuit = FirstByteCircuit::default();
        assert!(circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now).is_none());
        assert!(circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now).is_none());
        assert!(!circuit.is_disabled(dc(2), false, WssRouteKind::Cf, now));
        let tripped = circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now).expect("tripped");
        assert_eq!(tripped.ttl, Duration::from_secs(15));
        assert!(circuit.is_disabled(dc(2), false, WssRouteKind::Cf, now));
        assert!(!circuit.is_disabled(dc(2), false, WssRouteKind::Cf, now + Duration::from_secs(16)));
    }

    #[test]
    fn one_byte_down_lifts_the_pause() {
        let now = Instant::now();
        let c = ctx(true, false);
        let mut circuit = FirstByteCircuit::default();
        for _ in 0..3 {
            circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now);
        }
        assert!(circuit.is_disabled(dc(2), false, WssRouteKind::Cf, now));
        assert!(circuit.note(dc(2), false, WssRouteKind::Cf, 1, c, now).is_none());
        assert!(!circuit.is_disabled(dc(2), false, WssRouteKind::Cf, now));
    }

    #[test]
    fn one_byte_down_also_wipes_a_count_that_had_not_reached_the_threshold() {
        // The pause and the counter are separate state, and only this shape can
        // tell whether both were cleared: a trip zeroes the counter on its way
        // out, so clearing after a trip proves nothing. Threshold here is 3.
        //
        // Written after a mutation that dropped `self.fails.remove(&key)` passed
        // the previous version of this test untouched.
        let now = Instant::now();
        let c = ctx(true, false);
        let mut circuit = FirstByteCircuit::default();
        circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now);
        circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now);
        circuit.note(dc(2), false, WssRouteKind::Cf, 4096, c, now);
        assert!(circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now).is_none());
        assert!(
            !circuit.is_disabled(dc(2), false, WssRouteKind::Cf, now),
            "a working tunnel must not leave two failures banked against the route"
        );
    }

    #[test]
    fn failures_spread_past_the_window_never_add_up() {
        let now = Instant::now();
        let c = ctx(true, false); // threshold 3
        let mut circuit = FirstByteCircuit::default();
        let mut at = now;
        for _ in 0..10 {
            assert!(circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, at).is_none());
            at += Duration::from_secs(46);
        }
        assert!(!circuit.is_disabled(dc(2), false, WssRouteKind::Cf, at));
    }

    #[test]
    fn tripping_resets_the_counter_so_the_next_trip_needs_a_fresh_run() {
        let now = Instant::now();
        let c = ctx(true, false); // threshold 3, ttl 15
        let mut circuit = FirstByteCircuit::default();
        for _ in 0..3 {
            circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now);
        }
        let after = now + Duration::from_secs(16);
        assert!(!circuit.is_disabled(dc(2), false, WssRouteKind::Cf, after));
        assert!(circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, after).is_none());
        assert!(!circuit.is_disabled(dc(2), false, WssRouteKind::Cf, after));
    }

    #[test]
    fn one_dead_kind_does_not_speak_for_the_other() {
        let now = Instant::now();
        let c = ctx(true, false);
        let mut circuit = FirstByteCircuit::default();
        for _ in 0..3 {
            circuit.note(dc(2), false, WssRouteKind::Web, 0, c, now);
        }
        assert!(circuit.is_disabled(dc(2), false, WssRouteKind::Web, now));
        assert!(!circuit.is_disabled(dc(2), false, WssRouteKind::Cf, now));
        assert!(
            !circuit.is_disabled_for_any_kind(dc(2), false, now),
            "WSS is still worth attempting while cf is live"
        );
        for _ in 0..3 {
            circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now);
        }
        assert!(circuit.is_disabled_for_any_kind(dc(2), false, now));
    }

    #[test]
    fn media_and_plain_are_separate_circuits_on_the_same_dc() {
        let now = Instant::now();
        let c = ctx(true, false);
        let mut circuit = FirstByteCircuit::default();
        for _ in 0..3 {
            circuit.note(dc(2), true, WssRouteKind::Cf, 0, c, now);
        }
        assert!(circuit.is_disabled(dc(2), true, WssRouteKind::Cf, now));
        assert!(!circuit.is_disabled(dc(2), false, WssRouteKind::Cf, now));
    }

    #[test]
    fn the_log_line_says_true_and_false_the_way_python_prints_them() {
        let now = Instant::now();
        let c = ctx(true, false);
        let mut circuit = FirstByteCircuit::default();
        let mut tripped = None;
        for _ in 0..2 {
            tripped = circuit.note(dc(4), true, WssRouteKind::Cf, 0, c, now);
        }
        let tripped = tripped.expect("tripped");
        assert_eq!(
            tripped.message,
            "[TgRelay] WSS first-byte circuit: dc=4 media=True route=cf disabled_for=3s; \
             pausing WSS retries without raw TCP fallback."
        );
    }

    #[test]
    fn without_a_worker_the_line_names_the_tcp_fallback_instead() {
        let now = Instant::now();
        let c = ctx(false, false);
        let mut circuit = FirstByteCircuit::default();
        let mut tripped = None;
        for _ in 0..2 {
            tripped = circuit.note(dc(1), false, WssRouteKind::Web, 0, c, now);
        }
        assert_eq!(
            tripped.expect("tripped").message,
            "[TgRelay] WSS first-byte circuit: dc=1 media=False route=web disabled_for=15s; \
             using TCP fallback via WARP."
        );
    }

    #[test]
    fn clearing_forgets_both_the_counters_and_the_pauses() {
        let now = Instant::now();
        let c = ctx(true, false);
        let mut circuit = FirstByteCircuit::default();
        for _ in 0..3 {
            circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now);
        }
        circuit.clear();
        assert!(!circuit.is_disabled(dc(2), false, WssRouteKind::Cf, now));
        assert!(circuit.note(dc(2), false, WssRouteKind::Cf, 0, c, now).is_none());
    }

    #[test]
    fn recent_good_answers_the_question_it_was_actually_asked() {
        let now = Instant::now();
        let mut good = RecentGood::default();
        assert!(!good.within(dc(2), false, RECENT_GOOD_MAX_AGE, now));
        good.note(dc(2), false, "KWS2.Nova-App.eu", now);
        assert_eq!(good.domain(dc(2), false, now), Some("kws2.nova-app.eu"));
        assert!(good.within(dc(2), false, RECENT_GOOD_MAX_AGE, now + Duration::from_secs(179)));
        assert!(!good.within(dc(2), false, RECENT_GOOD_MAX_AGE, now + Duration::from_secs(181)));
        // Still remembered as *the* domain long after it stops counting as
        // recent — the two questions have different windows on purpose.
        assert_eq!(good.domain(dc(2), false, now + Duration::from_secs(600)), Some("kws2.nova-app.eu"));
        assert_eq!(good.domain(dc(2), false, now + Duration::from_secs(901)), None);
    }

    #[test]
    fn an_empty_domain_is_not_a_good_route() {
        let now = Instant::now();
        let mut good = RecentGood::default();
        good.note(dc(2), false, "   ", now);
        assert!(!good.within(dc(2), false, RECENT_GOOD_MAX_AGE, now));
    }
}
