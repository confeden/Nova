//! Cache of per-host conclusions plus the routing action they imply.

use std::collections::BTreeMap;

use nova_core::{BlockSignature, Countermeasure, Domain, Seconds, Transport, TransportKind};

use crate::detect::{Classification, Confidence};

/// What to do about a host that turned out to be Cloudflare-fronted and blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Leave the configured route alone.
    Keep,
    /// Send this host over a tunnel, because the ISP is filtering the path to
    /// the Cloudflare edge by address.
    Reroute { to: TransportKind, reason: &'static str },
}

/// One remembered conclusion.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub classification: Classification,
    pub confidence: Confidence,
    /// Uptime tick at which this was decided.
    pub decided_at: Seconds,
    /// Consecutive confirmations, used to extend the lifetime of a stable
    /// answer so a site that has been Cloudflare for a month is not re-probed
    /// every two hours.
    pub confirmations: u32,
}

impl Entry {
    /// How long a conclusion stays valid.
    ///
    /// A site moving on or off Cloudflare is rare, so the base lifetime is
    /// long; but a *blocked* conclusion expires quickly because the block is
    /// the volatile half — the ISP may lift it, and Nova should notice within
    /// minutes rather than hours and stop paying for an unnecessary tunnel.
    pub fn lifetime(&self) -> Seconds {
        let base: Seconds = match self.classification {
            Classification::FrontedAndBlocked => 900,
            Classification::FrontedOriginDown => 300,
            Classification::Fronted | Classification::NotFronted => 24 * 3600,
            Classification::Unknown => 60,
        };
        // Each confirmation doubles the lifetime, to a ceiling of a week.
        base.saturating_mul(1 << self.confirmations.min(3)).min(7 * 24 * 3600)
    }

    pub fn is_fresh(&self, now: Seconds) -> bool {
        now.saturating_sub(self.decided_at) < self.lifetime()
    }
}

/// Bounded cache of host conclusions.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Cache {
    entries: BTreeMap<Domain, Entry>,
}

impl Cache {
    /// Hard ceiling on remembered hosts.
    ///
    /// Keyed by [`Domain::learning_key`], so a CDN that hands out thousands of
    /// per-request hostnames collapses to one entry and cannot evict everything
    /// else. Without that collapsing, a single video session would flush the
    /// cache.
    pub const CAPACITY: usize = 2_048;

    pub fn get(&self, host: &Domain, now: Seconds) -> Option<&Entry> {
        self.entries.get(&key_for(host)).filter(|e| e.is_fresh(now))
    }

    pub fn insert(&mut self, host: &Domain, classification: Classification, confidence: Confidence, now: Seconds) {
        let key = key_for(host);
        let confirmations = match self.entries.get(&key) {
            Some(prev) if prev.classification == classification => prev.confirmations.saturating_add(1),
            _ => 0,
        };
        self.entries.insert(key, Entry { classification, confidence, decided_at: now, confirmations });
        if self.entries.len() > Self::CAPACITY {
            self.evict_stalest(now);
        }
    }

    fn evict_stalest(&mut self, now: Seconds) {
        self.entries.retain(|_, e| e.is_fresh(now));
        while self.entries.len() > Self::CAPACITY {
            // Drop the entry closest to expiry. Linear, but only reached when
            // the cache is full and every entry is still fresh, which needs
            // 2048 distinct registrable domains inside one lifetime window.
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.decided_at.saturating_add(e.lifetime()))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.entries.remove(&victim);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forget everything. Exposed for the UI's "reset auto-detection" control,
    /// which exists so a user who disagrees with Nova's guesses has a way out
    /// that is not "reinstall".
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

fn key_for(host: &Domain) -> Domain {
    Domain::parse(host.learning_key()).unwrap_or_else(|_| host.clone())
}

/// Decide the routing action for a classified host.
///
/// `warp_available` and `bypass_available` come from the health tracker, so the
/// policy never routes into a transport that is itself down — the mistake that
/// would turn one broken site into two.
pub fn decide(
    classification: Classification,
    confidence: Confidence,
    current: &Transport,
    warp_available: bool,
    bypass_available: bool,
    observed: Option<BlockSignature>,
) -> Action {
    if !classification.warrants_reroute() || !confidence.is_actionable() {
        return Action::Keep;
    }
    if current.kind().is_tunnelled() {
        // Already leaving through a tunnel and still blocked: the tunnel is not
        // the problem, so switching to another one is guesswork. Leave it to the
        // transport health machinery, which has evidence this policy does not.
        return Action::Keep;
    }
    // WARP first. The ISP filters Cloudflare's *published CDN* prefixes, and
    // WARP egresses from Cloudflare's own network on the far side of that
    // filter, so it is the one transport guaranteed to bypass this specific
    // block rather than merely disguise it.
    if warp_available {
        return Action::Reroute { to: TransportKind::Warp, reason: "cloudflare edge blocked by ISP; WARP egress" };
    }
    // Second choice, but only when the observed failure is one DPI desync can
    // actually address. The dominant Russian mechanism against Cloudflare is a
    // volumetric throttle that engages *after* the TLS handshake completes;
    // winws rewrites the ClientHello, which by then has already gone through.
    // Offering DPI bypass against that would look like a fix and be a placebo,
    // so the failure has to look request-side before it is worth trying.
    let desync_can_help = observed.is_none_or(|sig| sig.countermeasure() == Countermeasure::RequestSideDesync);
    if bypass_available && desync_can_help {
        return Action::Reroute {
            to: TransportKind::DirectBypass,
            reason: "cloudflare edge blocked at request stage and WARP unavailable; DPI bypass",
        };
    }
    Action::Keep
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(s: &str) -> Domain {
        Domain::parse(s).unwrap()
    }

    const HIGH: Confidence = Confidence::CERTAIN;

    #[test]
    fn blocked_cloudflare_goes_to_warp_when_it_is_up() {
        let action = decide(
            Classification::FrontedAndBlocked,
            HIGH,
            &Transport::Direct,
            true,
            true,
            Some(BlockSignature::RstImmediate),
        );
        assert!(matches!(action, Action::Reroute { to: TransportKind::Warp, .. }));
    }

    #[test]
    fn falls_back_to_dpi_bypass_when_warp_is_down() {
        let action = decide(
            Classification::FrontedAndBlocked,
            HIGH,
            &Transport::Direct,
            false,
            true,
            Some(BlockSignature::RstImmediate),
        );
        assert!(matches!(action, Action::Reroute { to: TransportKind::DirectBypass, .. }));
    }

    #[test]
    fn dpi_bypass_is_not_offered_against_a_post_handshake_throttle() {
        // The dominant Russian mechanism against Cloudflare since mid-2025 is a
        // volumetric throttle that engages after the handshake. winws rewrites
        // the ClientHello, which is already through by then. Sending traffic to
        // DPI bypass here would be a placebo that also costs a winws restart.
        let action = decide(
            Classification::FrontedAndBlocked,
            HIGH,
            &Transport::Direct,
            false,
            true,
            Some(BlockSignature::RstAfterServerHello),
        );
        assert_eq!(action, Action::Keep, "desync cannot address a response-side block");
    }

    #[test]
    fn never_reroutes_into_a_transport_that_is_itself_down() {
        assert_eq!(
            decide(
                Classification::FrontedAndBlocked,
                HIGH,
                &Transport::Direct,
                false,
                false,
                Some(BlockSignature::RstImmediate)
            ),
            Action::Keep
        );
    }

    #[test]
    fn a_low_confidence_guess_never_changes_routing() {
        assert!(Confidence::ACT_THRESHOLD.is_actionable(), "the threshold itself must pass");
        let weak = Confidence::new(0.6);
        assert!(!weak.is_actionable());
        let action = decide(
            Classification::FrontedAndBlocked,
            weak,
            &Transport::Direct,
            true,
            true,
            Some(BlockSignature::RstImmediate),
        );
        assert_eq!(action, Action::Keep);
    }

    #[test]
    fn a_working_cloudflare_site_is_left_alone() {
        assert_eq!(
            decide(
                Classification::Fronted,
                HIGH,
                &Transport::Direct,
                true,
                true,
                Some(BlockSignature::RstImmediate)
            ),
            Action::Keep
        );
        assert_eq!(
            decide(
                Classification::FrontedOriginDown,
                HIGH,
                &Transport::Direct,
                true,
                true,
                Some(BlockSignature::RstImmediate)
            ),
            Action::Keep
        );
        assert_eq!(
            decide(
                Classification::NotFronted,
                HIGH,
                &Transport::Direct,
                true,
                true,
                Some(BlockSignature::RstImmediate)
            ),
            Action::Keep
        );
    }

    #[test]
    fn already_tunnelled_traffic_is_not_bounced_between_tunnels() {
        let action = decide(
            Classification::FrontedAndBlocked,
            HIGH,
            &Transport::Warp,
            true,
            true,
            Some(BlockSignature::RstImmediate),
        );
        assert_eq!(action, Action::Keep);
    }

    #[test]
    fn cache_collapses_per_request_hostnames_onto_one_entry() {
        let mut cache = Cache::default();
        for i in 0..5_000 {
            let h = host(&format!("rr{i}---sn-abc.googlevideo.com"));
            cache.insert(&h, Classification::Fronted, HIGH, 0);
        }
        assert_eq!(cache.len(), 1, "a wildcard CDN must not be able to flush the cache");
        assert!(cache.get(&host("rr9999---sn-xyz.googlevideo.com"), 0).is_some());
    }

    #[test]
    fn cache_respects_capacity() {
        let mut cache = Cache::default();
        for i in 0..Cache::CAPACITY + 500 {
            cache.insert(&host(&format!("site{i}.example{i}.com")), Classification::Fronted, HIGH, 0);
        }
        assert!(cache.len() <= Cache::CAPACITY, "cache grew to {}", cache.len());
    }

    #[test]
    fn a_blocked_conclusion_expires_far_sooner_than_a_stable_one() {
        let mut cache = Cache::default();
        // Distinct registrable domains: entries under one parent deliberately
        // share a verdict, so a single site cannot demonstrate both lifetimes.
        cache.insert(&host("www.blockedsite.com"), Classification::FrontedAndBlocked, HIGH, 0);
        cache.insert(&host("www.stablesite.com"), Classification::Fronted, HIGH, 0);
        let later = 2 * 3600;
        assert!(cache.get(&host("www.blockedsite.com"), later).is_none(), "block must be re-checked");
        assert!(cache.get(&host("www.stablesite.com"), later).is_some(), "stable answer must persist");
    }

    #[test]
    fn subdomains_share_one_verdict_by_design() {
        let mut cache = Cache::default();
        cache.insert(&host("a.example.com"), Classification::Fronted, HIGH, 0);
        assert!(
            cache.get(&host("b.example.com"), 0).is_some(),
            "one lookup for a.example.com must answer for its siblings, which is what keeps CDN hosts cheap"
        );
    }

    #[test]
    fn repeated_confirmation_extends_the_lifetime() {
        let mut cache = Cache::default();
        let h = host("stable.example.com");
        for round in 0..4 {
            cache.insert(&h, Classification::Fronted, HIGH, round * 100);
        }
        let entry = cache.get(&h, 400).unwrap();
        assert!(entry.confirmations >= 3);
        assert_eq!(entry.lifetime(), 7 * 24 * 3600, "a repeatedly confirmed answer should reach the ceiling");
    }

    #[test]
    fn clearing_the_cache_forgets_everything() {
        let mut cache = Cache::default();
        cache.insert(&host("a.example.com"), Classification::Fronted, HIGH, 0);
        cache.clear();
        assert!(cache.is_empty());
    }
}
