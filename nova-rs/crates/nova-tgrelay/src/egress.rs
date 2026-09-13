//! Choosing a way out — the policy half.
//!
//! Layer 5 of the port out of `tgrelay/transparent_relay.py`. The relay is
//! handed an ordered list of egresses by Nova and has to decide which to dial
//! first, which to skip, and what a finished tunnel says about the one it used.
//! None of that touches a socket, and all of it was previously spread across
//! five module-level dictionaries and a 30-line block inside the connect path.
//!
//! Two health tables, deliberately separate, because they answer different
//! questions and a shared one would let either poison the other:
//!
//! - [`NativeHealth`] — *does this egress carry Telegram's own protocol to this
//!   DC?* Keyed by `(dc, label)`. WSS exists because the provider kills direct
//!   MTProto, but that is a property of the network and not of every egress: an
//!   HTTP proxy can carry it untouched, and then the WebSocket detour through
//!   Cloudflare is two extra network legs for nothing. Measured on the target
//!   network, the same `req_pq`/`resPQ` exchange takes 0.64 s natively through
//!   Opera against 1.25 s over WSS.
//! - [`PenaltyBox`] — *did this egress just fail a WSS handshake?* Keyed by
//!   label alone. WARP keeps answering TCP and TLS long after it has stopped
//!   carrying WebSocket upgrades, and the connect cannot tell.

use crate::Authority;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A Telegram data centre number. Never zero: the relay uses `0` throughout to
/// mean "no DC known", and every health call in the Python begins by testing for
/// it. Making it unrepresentable moves that test to the one place a DC is
/// derived instead of repeating it at each use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dc(u16);

impl Dc {
    pub fn new(number: u16) -> Option<Self> {
        (number != 0).then_some(Self(number))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

/// How a proxy egress expects to be spoken to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    /// `05 01 00`, then a CONNECT request. Nova's WARP backend on 1370.
    Socks5,
    /// `CONNECT host:port HTTP/1.1`. Nova's Opera backend on 1371.
    HttpConnect,
}

impl ProxyProtocol {
    /// The `kind` string Nova puts in the attempt dict.
    pub fn as_kind(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::HttpConnect => "http",
        }
    }
}

/// One way out, named.
///
/// A proxy always carries its address and a direct route never does. The Python
/// keeps both in one dict and defaults a missing proxy host to `127.0.0.1` and a
/// missing port to `0`, so an attempt with no address at all survives
/// construction and fails at connect time as "port 0 is not a port".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Egress {
    Direct { label: String, timeout: Option<Duration> },
    Proxy { protocol: ProxyProtocol, label: String, at: Authority, timeout: Option<Duration> },
}

impl Egress {
    /// `str(attempt.get("label") or kind or "unknown")` — the label falls back to
    /// the kind, so an unnamed attempt still has something to log and to key
    /// health by.
    fn labelled(label: &str, fallback: &str) -> String {
        let trimmed = label.trim();
        if trimmed.is_empty() {
            fallback.to_string()
        } else {
            trimmed.to_string()
        }
    }

    pub fn direct(label: &str) -> Self {
        Self::Direct { label: Self::labelled(label, "direct"), timeout: None }
    }

    pub fn proxy(protocol: ProxyProtocol, label: &str, at: Authority) -> Self {
        Self::Proxy { protocol, label: Self::labelled(label, protocol.as_kind()), at, timeout: None }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        match &mut self {
            Self::Direct { timeout: slot, .. } | Self::Proxy { timeout: slot, .. } => *slot = Some(timeout),
        }
        self
    }

    /// Only sets a timeout where none was given — `rendered.setdefault("timeout", 1.2)`.
    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        match &mut self {
            Self::Direct { timeout: slot, .. } | Self::Proxy { timeout: slot, .. } => {
                slot.get_or_insert(timeout);
            }
        }
        self
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Direct { label, .. } | Self::Proxy { label, .. } => label,
        }
    }

    pub fn timeout(&self) -> Option<Duration> {
        match self {
            Self::Direct { timeout, .. } | Self::Proxy { timeout, .. } => *timeout,
        }
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }
}

/// Health is keyed case-insensitively (`str(label).strip().lower()` in the
/// Python) while the label is logged as given.
fn health_key(label: &str) -> String {
    label.trim().to_ascii_lowercase()
}

/// How long a verdict about an egress stands.
///
/// Asymmetric on purpose: a working route is believed for ten minutes, a silent
/// one is re-tried after two. Being slow to forgive costs throughput on a
/// network that recovered; being slow to forget costs nothing but a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeTtl {
    pub good: Duration,
    pub bad: Duration,
}

impl Default for NativeTtl {
    fn default() -> Self {
        Self { good: Duration::from_secs(600), bad: Duration::from_secs(120) }
    }
}

#[derive(Debug, Clone, Copy)]
struct Verdict {
    ok: bool,
    expires: Instant,
}

/// Which egresses are known to carry native MTProto to which DC.
#[derive(Debug, Clone, Default)]
pub struct NativeHealth {
    ttl: NativeTtl,
    entries: HashMap<(u16, String), Verdict>,
}

impl NativeHealth {
    pub fn new(ttl: NativeTtl) -> Self {
        Self { ttl, entries: HashMap::new() }
    }

    /// `Some(true)` proven, `Some(false)` proven silent, `None` untested or
    /// expired.
    pub fn state(&self, dc: Dc, label: &str, now: Instant) -> Option<bool> {
        let entry = self.entries.get(&(dc.get(), health_key(label)))?;
        (entry.expires > now).then_some(entry.ok)
    }

    /// File what a finished tunnel proved.
    ///
    /// Returns `Some(ok)` when the verdict is new or has flipped — that, and only
    /// that, is when the Python emits a line. **The comparison is against the
    /// stored entry even if it has expired**, not against [`Self::state`]. That
    /// looks like an oversight and is not: keying the log off the live state
    /// would re-announce "carries Telegram directly" every time a good verdict
    /// aged out and was immediately re-proven, which on a working route is every
    /// ten minutes forever.
    pub fn record(&mut self, dc: Dc, label: &str, ok: bool, now: Instant) -> Option<bool> {
        let ttl = if ok { self.ttl.good } else { self.ttl.bad };
        let previous = self.entries.insert((dc.get(), health_key(label)), Verdict { ok, expires: now + ttl });
        match previous {
            Some(p) if p.ok == ok => None,
            _ => Some(ok),
        }
    }

    /// True when some egress in `labels` is proven for this DC — the question
    /// `_native_preferred` asks before preferring the native path at all.
    pub fn any_proven(&self, dc: Dc, labels: &[&str], now: Instant) -> bool {
        labels.iter().any(|l| self.state(dc, l, now) == Some(true))
    }

    /// True while at least one egress is proven **or still untested**. An
    /// untested egress is worth a try; one proven silent is not.
    pub fn any_worth_trying(&self, dc: Dc, labels: &[&str], now: Instant) -> bool {
        !labels.is_empty() && labels.iter().any(|l| self.state(dc, l, now) != Some(false))
    }
}

/// Egresses that recently failed a WSS handshake, and when they are forgiven.
#[derive(Debug, Clone)]
pub struct PenaltyBox {
    ttl: Duration,
    until: HashMap<String, Instant>,
}

impl Default for PenaltyBox {
    fn default() -> Self {
        Self::new(Duration::from_secs(90))
    }
}

impl PenaltyBox {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, until: HashMap::new() }
    }

    pub fn is_penalised(&self, label: &str, now: Instant) -> bool {
        self.until.get(&health_key(label)).is_some_and(|t| *t > now)
    }

    /// Send it to the back of the queue.
    ///
    /// Returns `true` when this is a *fresh* penalty — an existing one being
    /// extended says nothing new. The Python logs only on the fresh one, and the
    /// wording matters as much as the frequency: Nova's console pins any line
    /// containing "fail" as an alert, and switching egress is routine
    /// self-healing that belongs in the file, not in a red banner.
    pub fn penalise(&mut self, label: &str, now: Instant) -> bool {
        let key = health_key(label);
        let fresh = self.until.get(&key).is_none_or(|t| *t <= now);
        self.until.insert(key, now + self.ttl);
        fresh
    }

    /// Forgive it. `true` when it had actually been penalised, which is the
    /// recovery line.
    pub fn clear(&mut self, label: &str) -> bool {
        self.until.remove(&health_key(label)).is_some()
    }
}

/// Proven egresses first, untested next, recently silent last.
///
/// Without this the relay keeps picking WARP — which answers TCP but never
/// delivers a byte from Telegram — and then records the native path as dead for
/// the whole DC, hiding the egress that actually works.
///
/// Stable within each group, so the order Nova gave survives inside a tier.
pub fn order_by_native(egresses: &mut [Egress], dc: Dc, health: &NativeHealth, now: Instant) {
    egresses.sort_by_key(|e| match health.state(dc, e.label(), now) {
        Some(true) => 0u8,
        None => 1,
        Some(false) => 2,
    });
}

/// Healthy egresses first, penalised ones after. Stable, same reason.
pub fn order_by_penalty(egresses: &mut [Egress], penalties: &PenaltyBox, now: Instant) {
    egresses.sort_by_key(|e| u8::from(penalties.is_penalised(e.label(), now)));
}

/// Whether Nova has cleared the direct route for this list.
///
/// The test is "is `direct` the *first* entry", and it is the provider's own
/// signal rather than a heuristic: Nova builds the list and puts direct at the
/// head exactly when direct is allowed here. Anywhere else it is some other
/// profile's tail-end fallback, and dialling it for Telegram means dialling the
/// one path the ISP is known to kill.
fn direct_is_allowed(all: &[Egress]) -> bool {
    all.first().is_some_and(Egress::is_direct)
}

/// `_telegram_upstream_attempts`: the list as given, minus direct unless the
/// provider put it first.
pub fn telegram_egresses(all: &[Egress]) -> Vec<Egress> {
    let allow_direct = direct_is_allowed(all);
    all.iter().filter(|e| allow_direct || !e.is_direct()).cloned().collect()
}

/// The 1.2 s the Python pins on direct inside the Cloudflare-proxy path.
pub const CFPROXY_DIRECT_TIMEOUT: Duration = Duration::from_millis(1200);

/// `_cfproxy_upstream_attempts`: as above, but direct gets a short leash and an
/// empty result still yields a direct attempt when direct was allowed.
pub fn cfproxy_egresses(all: &[Egress]) -> Vec<Egress> {
    let allow_direct = direct_is_allowed(all);
    let selected: Vec<Egress> = all
        .iter()
        .filter(|e| allow_direct || !e.is_direct())
        .map(|e| if e.is_direct() { e.clone().with_default_timeout(CFPROXY_DIRECT_TIMEOUT) } else { e.clone() })
        .collect();
    if !selected.is_empty() {
        return selected;
    }
    if allow_direct {
        return vec![Egress::direct("direct").with_timeout(CFPROXY_DIRECT_TIMEOUT)];
    }
    Vec::new()
}

/// The label the relay pins a target to after a tunnel succeeds through it.
pub const WARP_SOCKS: &str = "warp-socks";

/// A target last carried by WARP keeps WARP at the head for five minutes.
///
/// Only WARP is ever pinned, and only forwards. Direct Telegram is provider
/// shaped on the target networks, so it is never promoted to first place on the
/// strength of a transient stall somewhere else.
#[derive(Debug, Clone)]
pub struct RoutePreference {
    ttl: Duration,
    pinned: HashMap<(String, u16), (String, Instant)>,
}

impl Default for RoutePreference {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

impl RoutePreference {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, pinned: HashMap::new() }
    }

    fn key(target: &Authority) -> (String, u16) {
        (target.host().to_string(), target.port())
    }

    /// Record which egress carried this target. Only [`WARP_SOCKS`] is kept.
    pub fn remember(&mut self, target: &Authority, label: &str, now: Instant) {
        if health_key(label) != WARP_SOCKS {
            return;
        }
        self.pinned.insert(Self::key(target), (WARP_SOCKS.to_string(), now + self.ttl));
    }

    pub fn pinned_label(&self, target: &Authority, now: Instant) -> Option<&str> {
        let (label, until) = self.pinned.get(&Self::key(target))?;
        (*until > now).then_some(label.as_str())
    }

    /// Reorder for this target: pinned egress first, other proxies after it, and
    /// direct dropped entirely unless there is nothing else left to dial.
    ///
    /// Returns the list unchanged when nothing is pinned.
    pub fn apply(&self, egresses: &[Egress], target: &Authority, now: Instant) -> Vec<Egress> {
        let Some(pinned) = self.pinned_label(target, now) else {
            return egresses.to_vec();
        };
        let mut preferred = Vec::new();
        let mut others = Vec::new();
        let mut direct = Vec::new();
        for e in egresses {
            if e.is_direct() {
                direct.push(e.clone());
            } else if health_key(e.label()) == pinned {
                preferred.push(e.clone());
            } else {
                others.push(e.clone());
            }
        }
        preferred.extend(others);
        // `attempts = proxy_attempts or direct_attempts` — direct is the whole
        // list or none of it, never a tail. Handing the dialler an empty list
        // would raise where falling back to the provider's defaults was meant.
        if preferred.is_empty() {
            direct
        } else {
            preferred
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(port: u16) -> Authority {
        Authority::new("127.0.0.1", port).expect("authority")
    }

    fn warp() -> Egress {
        Egress::proxy(ProxyProtocol::Socks5, "warp-socks", at(1370))
    }

    fn opera() -> Egress {
        Egress::proxy(ProxyProtocol::HttpConnect, "opera-http", at(1371))
    }

    fn labels(egresses: &[Egress]) -> Vec<&str> {
        egresses.iter().map(Egress::label).collect()
    }

    fn dc(n: u16) -> Dc {
        Dc::new(n).expect("dc")
    }

    #[test]
    fn zero_is_not_a_data_centre() {
        assert!(Dc::new(0).is_none());
        assert_eq!(dc(2).get(), 2);
    }

    #[test]
    fn an_unnamed_egress_falls_back_to_its_kind() {
        assert_eq!(Egress::direct("").label(), "direct");
        assert_eq!(Egress::proxy(ProxyProtocol::Socks5, "  ", at(1370)).label(), "socks5");
        assert_eq!(Egress::proxy(ProxyProtocol::HttpConnect, "", at(1371)).label(), "http");
    }

    #[test]
    fn with_default_timeout_does_not_overwrite_one_that_was_given() {
        let e = Egress::direct("direct").with_timeout(Duration::from_secs(9));
        assert_eq!(e.with_default_timeout(CFPROXY_DIRECT_TIMEOUT).timeout(), Some(Duration::from_secs(9)));
        assert_eq!(
            Egress::direct("direct").with_default_timeout(CFPROXY_DIRECT_TIMEOUT).timeout(),
            Some(CFPROXY_DIRECT_TIMEOUT)
        );
    }

    #[test]
    fn health_is_case_insensitive_but_the_label_keeps_its_case() {
        let now = Instant::now();
        let mut health = NativeHealth::default();
        health.record(dc(2), "WARP-Socks", true, now);
        assert_eq!(health.state(dc(2), "warp-socks", now), Some(true));
        assert_eq!(Egress::proxy(ProxyProtocol::Socks5, "WARP-Socks", at(1370)).label(), "WARP-Socks");
    }

    #[test]
    fn a_verdict_expires_and_the_asymmetry_is_deliberate() {
        let now = Instant::now();
        let ttl = NativeTtl::default();
        let mut health = NativeHealth::new(ttl);
        health.record(dc(2), "opera-http", true, now);
        health.record(dc(2), "warp-socks", false, now);
        // The bad verdict is re-tried long before the good one is doubted.
        let later = now + ttl.bad + Duration::from_secs(1);
        assert_eq!(health.state(dc(2), "warp-socks", later), None);
        assert_eq!(health.state(dc(2), "opera-http", later), Some(true));
        assert_eq!(health.state(dc(2), "opera-http", now + ttl.good + Duration::from_secs(1)), None);
    }

    #[test]
    fn health_is_per_dc_not_per_egress() {
        let now = Instant::now();
        let mut health = NativeHealth::default();
        health.record(dc(2), "warp-socks", true, now);
        assert_eq!(health.state(dc(4), "warp-socks", now), None);
    }

    #[test]
    fn only_a_changed_verdict_is_worth_announcing() {
        let now = Instant::now();
        let mut health = NativeHealth::default();
        assert_eq!(health.record(dc(2), "warp-socks", false, now), Some(false));
        assert_eq!(health.record(dc(2), "warp-socks", false, now), None);
        assert_eq!(health.record(dc(2), "warp-socks", true, now), Some(true));
    }

    #[test]
    fn an_expired_verdict_re_proven_the_same_way_is_still_not_news() {
        // Otherwise a route that simply keeps working re-announces itself every
        // time its ten minutes are up, forever.
        let now = Instant::now();
        let mut health = NativeHealth::default();
        health.record(dc(2), "opera-http", true, now);
        let after_expiry = now + NativeTtl::default().good + Duration::from_secs(1);
        assert_eq!(health.state(dc(2), "opera-http", after_expiry), None, "precondition: it expired");
        assert_eq!(health.record(dc(2), "opera-http", true, after_expiry), None);
    }

    #[test]
    fn any_worth_trying_stops_only_when_every_egress_is_proven_silent() {
        let now = Instant::now();
        let mut health = NativeHealth::default();
        let all = ["warp-socks", "opera-http"];
        assert!(health.any_worth_trying(dc(2), &all, now), "untested counts as worth trying");
        assert!(!health.any_proven(dc(2), &all, now));
        health.record(dc(2), "warp-socks", false, now);
        assert!(health.any_worth_trying(dc(2), &all, now));
        health.record(dc(2), "opera-http", false, now);
        assert!(!health.any_worth_trying(dc(2), &all, now));
        assert!(!health.any_worth_trying(dc(2), &[], now), "nothing to try is not worth trying");
    }

    #[test]
    fn the_penalty_box_announces_the_first_mark_and_not_the_extensions() {
        let now = Instant::now();
        let mut box_ = PenaltyBox::default();
        assert!(box_.penalise("warp-socks", now));
        assert!(!box_.penalise("warp-socks", now + Duration::from_secs(10)));
        assert!(box_.is_penalised("warp-socks", now + Duration::from_secs(10)));
        // Expired, so the next mark is news again.
        assert!(box_.penalise("warp-socks", now + Duration::from_secs(300)));
    }

    #[test]
    fn forgiving_an_egress_that_was_never_penalised_is_not_a_recovery() {
        let now = Instant::now();
        let mut box_ = PenaltyBox::default();
        assert!(!box_.clear("opera-http"));
        box_.penalise("opera-http", now);
        assert!(box_.clear("opera-http"));
        assert!(!box_.is_penalised("opera-http", now));
    }

    #[test]
    fn native_ordering_is_proven_then_untested_then_silent() {
        let now = Instant::now();
        let mut health = NativeHealth::default();
        health.record(dc(2), "warp-socks", false, now);
        health.record(dc(2), "opera-http", true, now);
        let mut list = vec![warp(), Egress::direct("direct"), opera()];
        order_by_native(&mut list, dc(2), &health, now);
        assert_eq!(labels(&list), ["opera-http", "direct", "warp-socks"]);
    }

    #[test]
    fn ordering_is_stable_so_novas_own_order_survives_inside_a_tier() {
        let now = Instant::now();
        let health = NativeHealth::default();
        let mut list = vec![warp(), opera(), Egress::direct("direct")];
        order_by_native(&mut list, dc(2), &health, now);
        assert_eq!(labels(&list), ["warp-socks", "opera-http", "direct"]);
    }

    #[test]
    fn penalty_ordering_moves_the_failed_egress_to_the_back() {
        let now = Instant::now();
        let mut penalties = PenaltyBox::default();
        penalties.penalise("warp-socks", now);
        let mut list = vec![warp(), opera()];
        order_by_penalty(&mut list, &penalties, now);
        assert_eq!(labels(&list), ["opera-http", "warp-socks"]);
        // And back to the front once the penalty lapses.
        let later = now + Duration::from_secs(91);
        let mut list = vec![warp(), opera()];
        order_by_penalty(&mut list, &penalties, later);
        assert_eq!(labels(&list), ["warp-socks", "opera-http"]);
    }

    #[test]
    fn direct_is_dropped_unless_nova_put_it_first() {
        let trailing = vec![warp(), opera(), Egress::direct("direct")];
        assert_eq!(labels(&telegram_egresses(&trailing)), ["warp-socks", "opera-http"]);

        let leading = vec![Egress::direct("direct"), warp(), opera()];
        assert_eq!(labels(&telegram_egresses(&leading)), ["direct", "warp-socks", "opera-http"]);
    }

    #[test]
    fn the_cfproxy_list_puts_a_short_leash_on_direct_only() {
        let leading = vec![Egress::direct("direct"), warp()];
        let rendered = cfproxy_egresses(&leading);
        assert_eq!(rendered[0].timeout(), Some(CFPROXY_DIRECT_TIMEOUT));
        assert_eq!(rendered[1].timeout(), None);
    }

    #[test]
    fn a_cfproxy_list_with_direct_allowed_and_nothing_in_it_still_yields_direct() {
        assert!(cfproxy_egresses(&[]).is_empty(), "nothing allowed, nothing invented");
        let only_direct = vec![Egress::direct("direct")];
        assert_eq!(labels(&cfproxy_egresses(&only_direct)), ["direct"]);
    }

    #[test]
    fn only_warp_is_ever_pinned() {
        let now = Instant::now();
        let target = Authority::new("149.154.167.51", 443).expect("target");
        let mut pref = RoutePreference::default();
        pref.remember(&target, "opera-http", now);
        assert_eq!(pref.pinned_label(&target, now), None);
        pref.remember(&target, "warp-socks", now);
        assert_eq!(pref.pinned_label(&target, now), Some("warp-socks"));
    }

    #[test]
    fn a_pin_expires_and_is_per_target() {
        let now = Instant::now();
        let one = Authority::new("149.154.167.51", 443).expect("target");
        let other = Authority::new("149.154.167.51", 80).expect("target");
        let mut pref = RoutePreference::default();
        pref.remember(&one, "warp-socks", now);
        assert_eq!(pref.pinned_label(&other, now), None, "port is part of the key");
        assert_eq!(pref.pinned_label(&one, now + Duration::from_secs(301)), None);
    }

    #[test]
    fn a_pin_promotes_warp_and_drops_direct_entirely() {
        let now = Instant::now();
        let target = Authority::new("149.154.167.51", 443).expect("target");
        let mut pref = RoutePreference::default();
        pref.remember(&target, "warp-socks", now);
        let list = vec![Egress::direct("direct"), opera(), warp()];
        assert_eq!(labels(&pref.apply(&list, &target, now)), ["warp-socks", "opera-http"]);
    }

    #[test]
    fn a_pin_with_no_proxy_left_falls_back_to_direct_rather_than_to_nothing() {
        // `attempts = proxy_attempts or direct_attempts`. An empty list reaches
        // the dialler as an error instead of as "use the defaults".
        let now = Instant::now();
        let target = Authority::new("149.154.167.51", 443).expect("target");
        let mut pref = RoutePreference::default();
        pref.remember(&target, "warp-socks", now);
        let list = vec![Egress::direct("direct")];
        assert_eq!(labels(&pref.apply(&list, &target, now)), ["direct"]);
    }

    #[test]
    fn no_pin_leaves_the_list_exactly_as_it_was() {
        let now = Instant::now();
        let target = Authority::new("149.154.167.51", 443).expect("target");
        let pref = RoutePreference::default();
        let list = vec![Egress::direct("direct"), warp(), opera()];
        assert_eq!(pref.apply(&list, &target, now), list);
    }
}
