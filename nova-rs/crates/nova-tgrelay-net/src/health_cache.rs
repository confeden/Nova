//! Carrying the Worker health table across a restart.
//!
//! Layer 21, the port of `_cf_health_cache_load` / `_cf_health_cache_save`.
//!
//! **The whole problem is that a monotonic instant cannot be stored.** The
//! health tables measure age against a clock that starts at an arbitrary point
//! and does not survive the process; the file has to be readable by the *next*
//! process, whose clock starts somewhere else. So the age is converted to wall
//! time on the way out and back to an age on the way in, and everything older
//! than the TTL is dropped rather than resurrected with a fabricated timestamp.
//!
//! **The cache is an optimisation and is treated as one.** A malformed entry is
//! skipped, not fatal; a missing file is not an error; a score outside its range
//! is clamped rather than trusted. Losing it costs one cold start, and a relay
//! that refused to run because a JSON file had a bad float would cost rather
//! more.
//!
//! Written through a temporary file and renamed, so a crash mid-write leaves the
//! previous cache rather than half of the new one.

use nova_tgrelay::cfdomains::{CfDomainHealth, SCORE_FRESHNESS};
use nova_tgrelay::egress::Dc;
use nova_tgrelay::wss::RecentGood;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// The format the file declares. Anything else is ignored outright: a cache
/// written by a future build is not something this one can interpret safely.
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreEntry {
    pub score: f64,
    /// Wall-clock seconds, because the reader's monotonic clock is not ours.
    pub seen: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LastGoodEntry {
    pub domain: String,
    pub seen: f64,
}

/// The on-disk payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthCache {
    pub version: u32,
    pub saved: f64,
    pub ttl: f64,
    #[serde(default)]
    pub scores: BTreeMap<String, ScoreEntry>,
    /// Keyed `"<dc>:<0|1>"`, the same string the Python writes.
    #[serde(default)]
    pub last_good: BTreeMap<String, LastGoodEntry>,
}

impl HealthCache {
    pub fn new(saved_wall: f64) -> Self {
        Self {
            version: VERSION,
            saved: saved_wall,
            ttl: SCORE_FRESHNESS.as_secs_f64(),
            scores: BTreeMap::new(),
            last_good: BTreeMap::new(),
        }
    }
}

/// `"<dc>:<0|1>"`.
pub fn last_good_key(dc: Dc, media: bool) -> String {
    format!("{}:{}", dc.get(), u8::from(media))
}

/// Parse `"<dc>:<0|1>"`. `None` for anything else — a hand-edited key must not
/// become a data centre.
pub fn parse_last_good_key(key: &str) -> Option<(Dc, bool)> {
    let (dc, media) = key.split_once(':')?;
    let dc = Dc::new(dc.trim().parse().ok()?)?;
    let media = match media.trim() {
        "1" | "true" | "True" => true,
        "0" | "false" | "False" => false,
        _ => return None,
    };
    Some((dc, media))
}

/// How old an entry is, in the reader's terms.
///
/// Clamped at zero: a file written by a machine whose clock has since moved
/// backwards would otherwise produce a negative age and an entry that looks
/// newer than now.
pub fn age_of(seen_wall: f64, now_wall: f64) -> Duration {
    Duration::from_secs_f64((now_wall - seen_wall).max(0.0))
}

/// What the file gives back.
#[derive(Debug, Default)]
pub struct Restored {
    pub health: CfDomainHealth,
    pub recent_good: RecentGood,
    /// Entries dropped for being too old or malformed. Worth a log line at
    /// startup; a cache that is always entirely stale is a clock problem.
    pub dropped: usize,
}

/// Rebuild the tables from a parsed cache.
///
/// `now_wall` is the reader's wall clock and `now_mono` its monotonic one; the
/// two together are what convert a stored timestamp into an age this process can
/// use.
pub fn restore(cache: &HealthCache, now_wall: f64, now_mono: Instant) -> Restored {
    let mut restored = Restored::default();
    if cache.version != VERSION {
        restored.dropped = cache.scores.len() + cache.last_good.len();
        return restored;
    }
    let ttl = if cache.ttl > 0.0 { Duration::from_secs_f64(cache.ttl) } else { SCORE_FRESHNESS };

    for (domain, entry) in &cache.scores {
        let domain = domain.trim().to_ascii_lowercase();
        let score = entry.score.clamp(0.0, 100.0);
        let age = age_of(entry.seen, now_wall);
        if domain.is_empty() || score <= 0.0 || age > ttl || !entry.score.is_finite() {
            restored.dropped += 1;
            continue;
        }
        // `note_good` would add a gain on top; the score is restored as it was,
        // by walking the clock back to when it was earned.
        restored.health.restore_score(&domain, score, now_mono - age);
    }

    for (key, entry) in &cache.last_good {
        let domain = entry.domain.trim().to_ascii_lowercase();
        let age = age_of(entry.seen, now_wall);
        match parse_last_good_key(key) {
            Some((dc, media)) if !domain.is_empty() && age <= ttl => {
                restored.recent_good.note(dc, media, &domain, now_mono - age);
            }
            _ => restored.dropped += 1,
        }
    }
    restored
}

/// Build the payload to write.
///
/// Only live entries travel: a cache full of things the reader will discard is
/// a file that grows without ever being useful.
pub fn snapshot(
    health: &CfDomainHealth,
    recent_good: &RecentGood,
    pairs: &[(Dc, bool)],
    now_wall: f64,
    now_mono: Instant,
) -> HealthCache {
    let mut cache = HealthCache::new(now_wall);
    for (domain, score, seen) in health.live_scores(now_mono) {
        cache
            .scores
            .insert(domain, ScoreEntry { score, seen: now_wall - now_mono.duration_since(seen).as_secs_f64() });
    }
    for (dc, media) in pairs {
        if let Some(domain) = recent_good.domain(*dc, *media, now_mono) {
            cache
                .last_good
                .insert(last_good_key(*dc, *media), LastGoodEntry { domain: domain.to_string(), seen: now_wall });
        }
    }
    cache
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: f64 = 3600.0;

    fn cache_with_score(domain: &str, score: f64, seen: f64) -> HealthCache {
        let mut cache = HealthCache::new(HOUR);
        cache.scores.insert(domain.to_string(), ScoreEntry { score, seen });
        cache
    }

    #[test]
    fn the_key_round_trips_and_refuses_anything_else() {
        let dc = Dc::new(4).expect("dc");
        assert_eq!(last_good_key(dc, true), "4:1");
        assert_eq!(last_good_key(dc, false), "4:0");
        assert_eq!(parse_last_good_key("4:1"), Some((dc, true)));
        assert_eq!(parse_last_good_key("4:0"), Some((dc, false)));
        // A hand-edited key must not become a data centre.
        for bad in ["", "4", "4:2", "0:1", ":1", "x:1", "4:yes"] {
            assert_eq!(parse_last_good_key(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_stored_timestamp_becomes_an_age_in_the_readers_terms() {
        // The whole point: the writer's monotonic clock is gone, and the reader
        // has to place the entry on its own.
        let now_wall = 10.0 * HOUR;
        let now_mono = Instant::now();
        let cache = cache_with_score("kws2.nova-app.eu", 12.5, now_wall - 60.0);
        let restored = restore(&cache, now_wall, now_mono);
        assert_eq!(restored.health.fresh_score("kws2.nova-app.eu", now_mono), 12.5);
        // Sixty seconds old, so it goes stale sixty seconds sooner than a fresh
        // one would.
        let nearly = now_mono + SCORE_FRESHNESS - Duration::from_secs(61);
        assert_eq!(restored.health.fresh_score("kws2.nova-app.eu", nearly), 12.5);
        let past = now_mono + SCORE_FRESHNESS - Duration::from_secs(59);
        assert_eq!(restored.health.fresh_score("kws2.nova-app.eu", past), 0.0);
    }

    #[test]
    fn anything_past_the_ttl_is_dropped_rather_than_resurrected() {
        let now_wall = 10.0 * HOUR;
        let cache = cache_with_score("kws2.nova-app.eu", 40.0, now_wall - SCORE_FRESHNESS.as_secs_f64() - 1.0);
        let restored = restore(&cache, now_wall, Instant::now());
        assert_eq!(restored.dropped, 1);
        assert_eq!(restored.health.fresh_score("kws2.nova-app.eu", Instant::now()), 0.0);
    }

    #[test]
    fn a_clock_that_moved_backwards_does_not_make_an_entry_newer_than_now() {
        // The file says it was written in the future. Without the clamp the age
        // is negative and the entry outlives everything.
        let now_wall = 10.0 * HOUR;
        let cache = cache_with_score("kws2.nova-app.eu", 40.0, now_wall + HOUR);
        let now_mono = Instant::now();
        let restored = restore(&cache, now_wall, now_mono);
        assert_eq!(age_of(now_wall + HOUR, now_wall), Duration::ZERO);
        assert_eq!(restored.health.fresh_score("kws2.nova-app.eu", now_mono), 40.0);
    }

    #[test]
    fn a_malformed_entry_is_skipped_and_not_fatal() {
        // Losing the cache costs one cold start. Refusing to run because a JSON
        // file had a bad float would cost rather more.
        let now_wall = 10.0 * HOUR;
        let mut cache = HealthCache::new(now_wall);
        cache.scores.insert("  ".to_string(), ScoreEntry { score: 10.0, seen: now_wall });
        cache.scores.insert("zero.example".to_string(), ScoreEntry { score: 0.0, seen: now_wall });
        cache.scores.insert("nan.example".to_string(), ScoreEntry { score: f64::NAN, seen: now_wall });
        cache.scores.insert("good.example".to_string(), ScoreEntry { score: 7.0, seen: now_wall });
        cache.last_good.insert("nonsense".to_string(), LastGoodEntry { domain: "x".into(), seen: now_wall });

        let now_mono = Instant::now();
        let restored = restore(&cache, now_wall, now_mono);
        assert_eq!(restored.dropped, 4);
        assert_eq!(restored.health.fresh_score("good.example", now_mono), 7.0);
    }

    #[test]
    fn a_score_outside_its_range_is_clamped_rather_than_trusted() {
        let now_wall = 10.0 * HOUR;
        let now_mono = Instant::now();
        let restored = restore(&cache_with_score("a.example", 5000.0, now_wall), now_wall, now_mono);
        assert_eq!(restored.health.fresh_score("a.example", now_mono), 100.0);
        let negative = restore(&cache_with_score("b.example", -5.0, now_wall), now_wall, now_mono);
        assert_eq!(negative.dropped, 1, "a negative score clamps to zero, and zero is not kept");
    }

    #[test]
    fn a_cache_from_another_version_is_ignored_whole() {
        let now_wall = 10.0 * HOUR;
        let mut cache = cache_with_score("a.example", 10.0, now_wall);
        cache.version = 2;
        let restored = restore(&cache, now_wall, Instant::now());
        assert_eq!(restored.dropped, 1);
        assert_eq!(restored.health.fresh_score("a.example", Instant::now()), 0.0);
    }

    #[test]
    fn a_snapshot_round_trips_through_json() {
        let now_wall = 10.0 * HOUR;
        let now_mono = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_good("kws2.nova-app.eu", 4096, now_mono);
        let mut good = RecentGood::default();
        let dc = Dc::new(2).expect("dc");
        good.note(dc, false, "kws2.nova-app.eu", now_mono);

        let cache = snapshot(&health, &good, &[(dc, false), (dc, true)], now_wall, now_mono);
        assert_eq!(cache.version, VERSION);
        assert_eq!(cache.last_good.len(), 1, "the media pair has nothing to save");

        let text = serde_json::to_string(&cache).expect("json");
        let parsed: HealthCache = serde_json::from_str(&text).expect("parse");
        assert_eq!(parsed, cache);

        let restored = restore(&parsed, now_wall, now_mono);
        assert_eq!(restored.health.fresh_score("kws2.nova-app.eu", now_mono), 8.5);
        assert_eq!(restored.recent_good.domain(dc, false, now_mono), Some("kws2.nova-app.eu"));
    }

    #[test]
    fn only_live_entries_are_written_out() {
        // A cache full of things the reader will discard is a file that grows
        // without ever being useful.
        let now_wall = 10.0 * HOUR;
        let start = Instant::now();
        let mut health = CfDomainHealth::new();
        health.note_good("stale.example", 4096, start);
        health.note_good("fresh.example", 4096, start + SCORE_FRESHNESS);
        let later = start + SCORE_FRESHNESS + Duration::from_secs(1);
        let cache = snapshot(&health, &RecentGood::default(), &[], now_wall, later);
        assert!(cache.scores.contains_key("fresh.example"));
        assert!(!cache.scores.contains_key("stale.example"));
    }
}
