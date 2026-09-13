//! When to ask an egress whether it carries native MTProto, and when not to.
//!
//! Layer 24, the policy half of `_native_probe_loop`. The packet it sends is
//! layer 19; this decides which questions are worth asking.
//!
//! **Why ask at all.** Learning only from broken WSS connections left the better
//! path invisible while the worse one kept succeeding — WSS works, so nothing
//! ever discovers that the native route would have worked too, and worked
//! faster. A probe is one short connection per `(dc, egress)`.
//!
//! **Why a settled setup makes no traffic.** Only pairs whose state is *unknown*
//! are asked about. A proven pair and a proven-silent one are both settled, and
//! re-asking would spend connections to learn what the TTL already knows.

use crate::egress::{Dc, Egress, NativeHealth};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// `NATIVE_PROBE_INTERVAL` — the rhythm when there is nothing urgent.
pub const INTERVAL: Duration = Duration::from_secs(45);
/// `NATIVE_PROBE_RETRY` — the rhythm when a sweep answered nothing.
pub const RETRY: Duration = Duration::from_secs(6);

/// One question: does this egress carry native MTProto to this DC?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub dc: Dc,
    pub label: String,
}

/// The pairs still worth asking about.
///
/// Sorted by DC and then by the egress order given, so a sweep is reproducible —
/// which matters when reading two logs side by side.
pub fn pending(seen_dcs: &BTreeSet<Dc>, egresses: &[Egress], health: &NativeHealth, now: Instant) -> Vec<Probe> {
    let mut out = Vec::new();
    for dc in seen_dcs {
        for egress in egresses {
            if health.state(*dc, egress.label(), now).is_none() {
                out.push(Probe { dc: *dc, label: egress.label().to_string() });
            }
        }
    }
    out
}

/// How long to wait before the next sweep.
///
/// **A sweep where nothing answered means the egresses are still coming up after
/// a restart**, not that the network is settled — so it comes back in six
/// seconds rather than leaving the relay on WSS for a full interval. `answered`
/// is how many probes came back with a definite *yes*; a definite no is still an
/// answer about the network, but it does not mean an egress is ready.
pub fn next_delay(probes_sent: usize, answered_yes: usize) -> Duration {
    if probes_sent == 0 || answered_yes > 0 {
        INTERVAL
    } else {
        RETRY
    }
}

/// The DCs a client has been seen talking to.
///
/// Kept rather than sweeping every data centre Telegram has: a probe to a DC
/// this user never touches is a connection spent on a question nobody asked.
#[derive(Debug, Clone, Default)]
pub struct SeenDcs {
    dcs: BTreeSet<Dc>,
}

impl SeenDcs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn note(&mut self, dc: Dc) -> bool {
        self.dcs.insert(dc)
    }

    pub fn all(&self) -> &BTreeSet<Dc> {
        &self.dcs
    }

    pub fn is_empty(&self) -> bool {
        self.dcs.is_empty()
    }

    /// Seed from the previous session's health cache.
    ///
    /// **Without this the first sweep has nothing to ask about**, live
    /// connections reach the decision first, and each one pays the full
    /// first-byte timeout on a dead egress before anything is learned — which is
    /// exactly the stall this loop exists to prevent.
    pub fn seed(&mut self, dcs: impl IntoIterator<Item = Dc>) {
        self.dcs.extend(dcs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::ProxyProtocol;
    use crate::Authority;

    fn dc(n: u16) -> Dc {
        Dc::new(n).expect("dc")
    }

    fn egresses() -> Vec<Egress> {
        vec![
            Egress::proxy(ProxyProtocol::Socks5, "warp-socks", Authority::new("127.0.0.1", 1370).unwrap()),
            Egress::proxy(ProxyProtocol::HttpConnect, "opera-http", Authority::new("127.0.0.1", 1371).unwrap()),
        ]
    }

    fn seen(dcs: &[u16]) -> BTreeSet<Dc> {
        dcs.iter().map(|n| dc(*n)).collect()
    }

    #[test]
    fn every_unknown_pair_is_asked_about() {
        let now = Instant::now();
        let health = NativeHealth::default();
        let probes = pending(&seen(&[2, 4]), &egresses(), &health, now);
        assert_eq!(probes.len(), 4, "two data centres times two egresses");
        assert_eq!(probes[0].dc, dc(2));
        assert_eq!(probes[0].label, "warp-socks");
    }

    #[test]
    fn a_settled_pair_is_never_asked_again() {
        // A proven pair and a proven-silent one are both settled; re-asking
        // spends a connection to learn what the TTL already knows.
        let now = Instant::now();
        let mut health = NativeHealth::default();
        health.record(dc(2), "warp-socks", true, now);
        health.record(dc(2), "opera-http", false, now);
        assert!(pending(&seen(&[2]), &egresses(), &health, now).is_empty());
    }

    #[test]
    fn a_verdict_that_has_expired_is_unknown_again() {
        let now = Instant::now();
        let mut health = NativeHealth::default();
        health.record(dc(2), "warp-socks", false, now);
        health.record(dc(2), "opera-http", false, now);
        assert!(pending(&seen(&[2]), &egresses(), &health, now).is_empty());
        // The bad TTL is two minutes.
        let later = now + Duration::from_secs(121);
        assert_eq!(pending(&seen(&[2]), &egresses(), &health, later).len(), 2);
    }

    #[test]
    fn only_the_data_centres_this_client_uses_are_swept() {
        // A probe to a DC this user never touches is a connection spent on a
        // question nobody asked.
        let now = Instant::now();
        let health = NativeHealth::default();
        assert!(pending(&BTreeSet::new(), &egresses(), &health, now).is_empty());
        assert_eq!(pending(&seen(&[5]), &egresses(), &health, now).len(), 2);
    }

    #[test]
    fn a_sweep_that_answered_nothing_comes_back_quickly() {
        // Not because the network is settled but because the egresses are
        // probably still coming up after a restart, and a full interval on WSS
        // is exactly the stall the loop exists to prevent.
        assert_eq!(next_delay(4, 0), RETRY);
        assert_eq!(next_delay(4, 1), INTERVAL);
        // Nothing to ask is settled, not urgent.
        assert_eq!(next_delay(0, 0), INTERVAL);
        assert!(RETRY < INTERVAL);
    }

    #[test]
    fn the_sweep_order_is_reproducible() {
        // Two logs from two runs should line up.
        let now = Instant::now();
        let health = NativeHealth::default();
        let first = pending(&seen(&[4, 2, 5]), &egresses(), &health, now);
        let again = pending(&seen(&[5, 2, 4]), &egresses(), &health, now);
        assert_eq!(first, again);
        assert_eq!(first.iter().map(|p| p.dc.get()).collect::<Vec<_>>(), [2, 2, 4, 4, 5, 5]);
    }

    #[test]
    fn a_seed_gives_the_first_sweep_something_to_ask() {
        let mut seen = SeenDcs::new();
        assert!(seen.is_empty());
        seen.seed([dc(2), dc(4)]);
        assert_eq!(seen.all().len(), 2);
        // Noting one already known changes nothing.
        assert!(!seen.note(dc(2)));
        assert!(seen.note(dc(5)));
        assert_eq!(seen.all().len(), 3);
    }
}
