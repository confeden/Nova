//! Which name to put in the clear, and when to stop substituting it.
//!
//! Layer 14. Ports `_cf_neutral_candidates`, `_cf_neutral_sni`,
//! `_cf_note_neutral_sni_bad` and the decision half of `_note_sni_verdict`.
//!
//! **Why this exists at all.** The route has to be named somewhere in the
//! request, and it is named in the SNI: `kws2.nova-app.eu` travels in plaintext
//! on every tunnel Nova opens. One rule over `^kws\d+\.` retires the entire
//! domain pool at once, and no amount of work on the TLS fingerprint behind it
//! changes that — the name is read before the fingerprint matters. Cloudflare
//! routes Workers on the `Host` header, which is inside TLS, and tolerates the
//! SNI disagreeing with it as long as both names belong to the same zone. So the
//! route keeps travelling in `Host` and the SNI becomes an unremarkable
//! subdomain.
//!
//! **One candidate, and it is `www.` — not a shortlist.** Measured against the
//! live Worker with the route in `Host`: SNI `kws5-1.nova-app.eu` → 429, SNI
//! `www.nova-app.eu` → 429, SNI `nova-app.eu` → **403**. The 429 is the Worker's
//! exhausted daily quota, i.e. the request reached our route; the 403 is the edge
//! declining before that. The apex does not work, and `cdn.`/`static.`/`assets.`
//! do not resolve at all. The Python still calls `random.choice` over that
//! one-item list; the randomness is vestigial and is not reproduced. N10, and
//! ADR 0004 which said otherwise and has been corrected.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a zone stays on its literal name after the substitution is refused.
pub const LITERAL_FALLBACK_TTL: Duration = Duration::from_secs(900);

/// The names that may be offered in place of a route.
///
/// Exactly one today. `www.` has its own DNS record and sits inside the
/// universal certificate, so verification can be switched on later without
/// revisiting this. Kept as a list because the Python has one and because the
/// stickiness below only means something when it grows.
pub fn neutral_candidates(base: &str) -> Vec<String> {
    vec![format!("www.{base}")]
}

/// The name this process will offer for `base`.
pub fn neutral_candidate(base: &str) -> String {
    neutral_candidates(base).swap_remove(0)
}

/// What a failed WSS attempt looked like, in the only terms this decision needs.
///
/// The caller maps its own signature vocabulary onto these three; keeping the
/// mapping outside means this crate needs no verdict types to state the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniFailure {
    /// The handshake went unanswered, or the certificate did not match the name.
    /// **The one window where the name we offered is still a suspect.**
    HelloUnanswered,
    /// The CDN answered, and it said what a CDN says when it does not accept the
    /// name it was given for the host that was asked for: `403` or `421`.
    NameRefused,
    /// Anything else. It happened before the name was on the wire or after the
    /// name had already been accepted, and rolling back on those would give up a
    /// real gain over unrelated noise.
    Unrelated,
}

/// Which name goes in the SNI, and the memory of when not to substitute.
///
/// **One name per zone for the life of the process, not one per connection.** A
/// client that talks to a single content host looks like every other client; one
/// that sprays five names a minute is its own signature.
#[derive(Debug, Clone, Default)]
pub struct NeutralSni {
    enabled: bool,
    chosen: HashMap<String, String>,
    literal_until: HashMap<String, Instant>,
    ttl_override: Option<Duration>,
}

impl NeutralSni {
    /// On by default, matching `NOVA_TG_RELAY_NEUTRAL_SNI`.
    pub fn new() -> Self {
        Self { enabled: true, ..Self::default() }
    }

    pub fn disabled() -> Self {
        Self { enabled: false, ..Self::default() }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl_override = Some(ttl);
        self
    }

    fn ttl(&self) -> Duration {
        self.ttl_override.unwrap_or(LITERAL_FALLBACK_TTL)
    }

    /// The name to offer when connecting to `domain`.
    ///
    /// `owned_base` is the zone Nova controls that `domain` belongs to, or
    /// `None`. **`None` returns the domain unchanged, and that is the important
    /// case**: Telegram's own `kwsN.web.telegram.org` really does route on the
    /// SNI, and the third-party Workers in the public pool have never been
    /// measured — breaking somebody else's infrastructure on a hunch is worse
    /// than a legible name.
    pub fn sni_for(&mut self, domain: &str, owned_base: Option<&str>, now: Instant) -> String {
        let domain = domain.trim().to_ascii_lowercase();
        if !self.enabled || domain.is_empty() {
            return domain;
        }
        let Some(base) = owned_base.map(|b| b.trim().to_ascii_lowercase()).filter(|b| !b.is_empty()) else {
            return domain;
        };
        if self.literal_until.get(&base).is_some_and(|until| *until > now) {
            return domain;
        }
        self.chosen.entry(base.clone()).or_insert_with(|| neutral_candidate(&base)).clone()
    }

    /// Fall back to the literal name for this zone for a while.
    ///
    /// The substitution is an optimisation, not a requirement, so the first sign
    /// that a network dislikes it is enough to stop paying for it. Returns the
    /// line to log **only on the transition** — a zone already on its literal
    /// name has nothing new to say.
    pub fn note_refused(&mut self, base: &str, now: Instant) -> Option<String> {
        let base = base.trim().to_ascii_lowercase();
        if base.is_empty() {
            return None;
        }
        let already = self.literal_until.get(&base).is_some_and(|until| *until > now);
        let ttl = self.ttl();
        self.literal_until.insert(base.clone(), now + ttl);
        if already {
            return None;
        }
        Some(format!(
            "[TgRelay] Neutral SNI was not accepted for {base}; using the literal route name for {}s.",
            ttl.as_secs()
        ))
    }

    /// True while this zone is on its literal name.
    pub fn is_literal(&self, base: &str, now: Instant) -> bool {
        self.literal_until.get(&base.trim().to_ascii_lowercase()).is_some_and(|until| *until > now)
    }
}

/// Whether a failure should retire the substituted name.
///
/// `used` is what actually went out in the SNI. **A failure on a connection that
/// carried the literal name says nothing about the substitution** — that guard is
/// the whole reason the SNI is recorded on the exception in the first place.
pub fn retires_substitution(used: &str, domain: &str, failure: SniFailure) -> bool {
    let used = used.trim().to_ascii_lowercase();
    let domain = domain.trim().to_ascii_lowercase();
    if used.is_empty() || used == domain {
        return false;
    }
    matches!(failure, SniFailure::HelloUnanswered | SniFailure::NameRefused)
}

/// The two HTTP statuses a CDN uses to decline a name.
pub const NAME_REFUSED_STATUSES: [u16; 2] = [403, 421];

pub fn is_name_refusal(status: u16) -> bool {
    NAME_REFUSED_STATUSES.contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNED: &str = "nova-app.eu";

    #[test]
    fn the_only_candidate_is_www() {
        // Not a shortlist. The apex is refused with 403 and the other prefixes
        // do not resolve; picking among them was retiring the substitution for
        // fifteen minutes on roughly every second start.
        assert_eq!(neutral_candidate(OWNED), "www.nova-app.eu");
    }

    #[test]
    fn a_zone_we_own_gets_the_neutral_name() {
        let now = Instant::now();
        let mut sni = NeutralSni::new();
        assert_eq!(sni.sni_for("kws2.nova-app.eu", Some(OWNED), now), "www.nova-app.eu");
    }

    #[test]
    fn anything_we_do_not_own_keeps_its_own_name() {
        // Telegram's edge really does route on the SNI, and the public-pool
        // Workers have never been measured.
        let now = Instant::now();
        let mut sni = NeutralSni::new();
        assert_eq!(sni.sni_for("kws2.web.telegram.org", None, now), "kws2.web.telegram.org");
        assert_eq!(sni.sni_for("kws2.pclead.co.uk", None, now), "kws2.pclead.co.uk");
        assert_eq!(sni.sni_for("KWS2.Nova-App.eu", Some("  "), now), "kws2.nova-app.eu");
    }

    #[test]
    fn the_switch_turns_the_whole_thing_off() {
        let now = Instant::now();
        let mut sni = NeutralSni::disabled();
        assert_eq!(sni.sni_for("kws2.nova-app.eu", Some(OWNED), now), "kws2.nova-app.eu");
    }

    #[test]
    fn one_name_per_zone_whatever_the_route_inside_it() {
        let now = Instant::now();
        let mut sni = NeutralSni::new();
        let first = sni.sni_for("kws2.nova-app.eu", Some(OWNED), now);
        let later = sni.sni_for("kws5-1.nova-app.eu", Some(OWNED), now + Duration::from_secs(600));
        assert_eq!(first, later);
    }

    #[test]
    fn the_stickiness_is_vacuous_while_there_is_one_candidate() {
        // Said out loud because a mutation proved it: removing the per-zone map
        // entirely passes every test here, since one candidate means any
        // implementation returns the same string every time.
        //
        // The map is kept for the moment a second name is added. A client that
        // talks to one content host looks like every other client; one that
        // sprays five names a minute is its own signature — and the Python made
        // exactly that mistake, calling `random.choice` over a two-item list and
        // taking the apex about half the time, which retired the substitution
        // for fifteen minutes on roughly every second start (N10).
        //
        // **If this assertion ever fails, the test above has to become real**:
        // drive `sni_for` twice and prove the second call did not re-pick.
        assert_eq!(neutral_candidates(OWNED).len(), 1, "stickiness is now testable — go and test it");
    }

    #[test]
    fn a_refusal_falls_back_to_the_literal_name_and_says_so_once() {
        let now = Instant::now();
        let mut sni = NeutralSni::new();
        assert_eq!(sni.sni_for("kws2.nova-app.eu", Some(OWNED), now), "www.nova-app.eu");

        let line = sni.note_refused(OWNED, now).expect("a line on the transition");
        assert_eq!(
            line,
            "[TgRelay] Neutral SNI was not accepted for nova-app.eu; using the literal route name for 900s."
        );
        assert_eq!(sni.sni_for("kws2.nova-app.eu", Some(OWNED), now), "kws2.nova-app.eu");

        // Already on the literal name: nothing new to say, but the clock is
        // pushed out again.
        assert_eq!(sni.note_refused(OWNED, now + Duration::from_secs(10)), None);
        assert!(sni.is_literal(OWNED, now + Duration::from_secs(905)));
    }

    #[test]
    fn the_fallback_expires_and_the_substitution_returns() {
        let now = Instant::now();
        let mut sni = NeutralSni::new();
        sni.note_refused(OWNED, now);
        let after = now + LITERAL_FALLBACK_TTL + Duration::from_secs(1);
        assert!(!sni.is_literal(OWNED, after));
        assert_eq!(sni.sni_for("kws2.nova-app.eu", Some(OWNED), after), "www.nova-app.eu");
        // And it is news again.
        assert!(sni.note_refused(OWNED, after).is_some());
    }

    #[test]
    fn one_zone_falling_back_does_not_touch_another() {
        let now = Instant::now();
        let mut sni = NeutralSni::new();
        sni.note_refused(OWNED, now);
        assert!(sni.is_literal(OWNED, now));
        assert!(!sni.is_literal("other.example", now));
    }

    #[test]
    fn an_empty_base_is_not_a_zone() {
        let now = Instant::now();
        let mut sni = NeutralSni::new();
        assert_eq!(sni.note_refused("   ", now), None);
        assert!(!sni.is_literal("", now));
    }

    #[test]
    fn a_failure_on_the_literal_name_says_nothing_about_the_substitution() {
        // The guard the whole `nova_sni` annotation exists for: without it, a
        // connection that never substituted anything could retire the
        // substitution for fifteen minutes.
        assert!(!retires_substitution("kws2.nova-app.eu", "kws2.nova-app.eu", SniFailure::HelloUnanswered));
        assert!(!retires_substitution("", "kws2.nova-app.eu", SniFailure::NameRefused));
        assert!(!retires_substitution("KWS2.Nova-App.eu", "kws2.nova-app.eu", SniFailure::NameRefused));
    }

    #[test]
    fn only_the_two_shapes_that_could_be_the_names_fault_retire_it() {
        for failure in [SniFailure::HelloUnanswered, SniFailure::NameRefused] {
            assert!(retires_substitution("www.nova-app.eu", "kws2.nova-app.eu", failure), "{failure:?}");
        }
        assert!(!retires_substitution("www.nova-app.eu", "kws2.nova-app.eu", SniFailure::Unrelated));
    }

    #[test]
    fn a_cdn_declines_a_name_with_403_or_421_and_nothing_else() {
        assert!(is_name_refusal(403) && is_name_refusal(421));
        for other in [200u16, 101, 429, 500, 302] {
            assert!(!is_name_refusal(other), "{other}");
        }
        // 429 in particular: the Worker's quota is exhausted, which means the
        // request *reached* our route. Treating it as a name refusal would
        // retire the substitution for the one status that proves it works.
        assert!(!is_name_refusal(429));
    }
}
