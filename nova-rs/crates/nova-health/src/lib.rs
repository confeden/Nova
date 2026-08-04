//! Transport health and automatic fallback.
//!
//! This crate answers one question for the routing engine: *given what we have
//! observed, which transport should this group actually use right now?*
//!
//! The motivating case is the one in the requirements — YouTube is configured
//! to leave via WARP; WARP dies; YouTube must keep working by going direct with
//! winws DPI bypass, and must return to WARP once WARP is healthy again,
//! without the user touching anything and without the route oscillating while
//! WARP is merely degraded.
//!
//! The pieces:
//!
//! - [`quorum::evaluate`] turns several canary probe results into one verdict,
//!   so a single dead site cannot condemn a working tunnel.
//! - [`breaker::Breaker`] holds that verdict over time with hysteresis, an
//!   explicit half-open trial state, and exponential backoff on repeat failure.
//! - [`Supervisor`] owns one breaker per transport and resolves a group's
//!   configured route into the transport that should carry it now.
//!
//! Everything is pure state machine: no sockets, no threads, no clock. The
//! caller supplies probe results and a monotonic tick, which makes the whole
//! failover path testable without a network.

#![forbid(unsafe_code)]

pub mod breaker;
pub mod quorum;

use std::collections::{BTreeMap, BTreeSet};

use nova_core::{GroupId, ProbeOutcome, Seconds, Transport, TransportKind, Verdict};

pub use breaker::{Breaker, State};
pub use quorum::{Health, evaluate};

/// Why a group is not on its configured transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// It is on its configured transport.
    AsConfigured,
    /// The configured transport's breaker is open.
    ConfiguredTransportDown { transport: TransportKind },
    /// The configured transport is down and so is every preferred fallback.
    NoHealthyTransport,
    /// The configured tunnel is down and the group forbids leaving untunnelled.
    ///
    /// Distinct from [`Reason::NoHealthyTransport`] because the caller must do
    /// something different: rather than passing traffic through a path we have
    /// no faith in, it has to blackhole the group, exactly as the Python PAC
    /// does today (`nova.pyw:4858` — "NO DIRECT fallback for RU to prevent IP
    /// leak").
    WouldLeak { transport: TransportKind },
}

/// Tracks every transport's health and resolves routes.
#[derive(Debug, Clone, Default)]
pub struct Supervisor {
    breakers: BTreeMap<TransportKind, Breaker>,
    /// Transports that are actually provisioned on this machine.
    ///
    /// A transport the user never configured is not a fallback candidate. Left
    /// implicit, an absent Opera profile would look "healthy" purely because no
    /// probe had ever failed against it, and traffic would be routed into
    /// nothing.
    enabled: BTreeSet<TransportKind>,
    /// Per-group constraints on what a fallback is allowed to do.
    ///
    /// Absent means [`FallbackPolicy::Adaptive`].
    policies: BTreeMap<GroupId, FallbackPolicy>,
    /// Groups currently displaced from their configured transport, with the
    /// transport they were displaced to. Kept so the UI can show it and so a
    /// return can be logged exactly once.
    displaced: BTreeMap<GroupId, TransportKind>,
}

/// How far a group is allowed to be moved when its transport fails.
///
/// The three cases are not a design preference; they are what the Python PAC
/// already encodes, and getting them wrong changes where the user's traffic
/// appears to come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackPolicy {
    /// Any healthy transport, including untunnelled DPI bypass. Correct when the
    /// tunnel exists to reach a blocked site — YouTube, Cloudflare-fronted
    /// hosts — because there the user's visible address was never the point.
    /// This is requirement 3's behaviour.
    Adaptive,
    /// Any healthy *tunnel*, never an untunnelled path. When no tunnel survives
    /// the group is blackholed.
    ///
    /// This is the `ru` group. `nova.pyw:4858`: *"NO DIRECT fallback for RU to
    /// prevent IP leak. Use a blackhole proxy."* winws would hide the hostname
    /// from the ISP while the destination still sees the real address, so
    /// treating DPI bypass as a substitute for a tunnel is a silent downgrade.
    TunnelOnly,
    /// Exactly one transport, or nothing.
    ///
    /// This is the `eu` group, pinned to Opera. `nova.pyw:4842`: *"EU domains
    /// are Opera-only. Do not fall back to WARP here: otherwise EU-listed
    /// browser traffic can silently use RU/WARP egress."* The point of the EU
    /// list is the egress country, and WARP is a tunnel that exits elsewhere —
    /// so for this group even a healthy tunnel is the wrong answer.
    Pinned(TransportKind),
}

impl Supervisor {
    /// Build a supervisor over the transports that are provisioned.
    ///
    /// [`TransportKind::DirectBypass`] is always included: winws ships with
    /// Nova, so the DPI-bypass path is the one fallback that is guaranteed to
    /// exist, which is what makes it a safe last resort.
    pub fn new(enabled: impl IntoIterator<Item = TransportKind>) -> Self {
        let mut enabled: BTreeSet<TransportKind> = enabled.into_iter().collect();
        enabled.insert(TransportKind::DirectBypass);
        let mut supervisor =
            Self { breakers: BTreeMap::new(), enabled, policies: BTreeMap::new(), displaced: BTreeMap::new() };
        supervisor.apply_default_policies();
        supervisor
    }

    /// The geo groups and the constraint each carries, applied by [`Supervisor::new`].
    ///
    /// Deliberately a default rather than something a caller opts into. The
    /// unsafe configuration must not be what you get by forgetting a call — a
    /// missed `require_tunnel` would silently expose the user's real address,
    /// and that is not a failure mode anyone would notice in testing.
    ///
    /// `u_ru` and `u_eu` are the user-editable halves of the same two lists
    /// (`list/u_ru.txt`, `list/u_eu.txt`), so they inherit the same constraint.
    pub const DEFAULT_POLICIES: [(&'static str, FallbackPolicy); 4] = [
        ("ru", FallbackPolicy::TunnelOnly),
        ("u_ru", FallbackPolicy::TunnelOnly),
        ("eu", FallbackPolicy::Pinned(TransportKind::Opera)),
        ("u_eu", FallbackPolicy::Pinned(TransportKind::Opera)),
    ];

    fn apply_default_policies(&mut self) {
        for (group, policy) in Self::DEFAULT_POLICIES {
            self.policies.insert(GroupId::new(group), policy);
        }
    }

    /// Override the constraint on one group.
    pub fn set_policy(&mut self, group: impl Into<GroupId>, policy: FallbackPolicy) {
        self.policies.insert(group.into(), policy);
    }

    pub fn policy(&self, group: &GroupId) -> FallbackPolicy {
        self.policies.get(group).copied().unwrap_or(FallbackPolicy::Adaptive)
    }

    /// Whether a candidate transport satisfies this group's constraint.
    fn policy_permits(&self, group: &GroupId, candidate: TransportKind) -> bool {
        match self.policy(group) {
            FallbackPolicy::Adaptive => true,
            FallbackPolicy::TunnelOnly => candidate.is_tunnelled(),
            FallbackPolicy::Pinned(required) => candidate == required,
        }
    }

    /// Mark a transport as provisioned or not, e.g. when the user enables Opera
    /// VPN or signs out of WARP.
    pub fn set_enabled(&mut self, transport: TransportKind, enabled: bool) {
        if enabled {
            self.enabled.insert(transport);
        } else if transport != TransportKind::DirectBypass {
            self.enabled.remove(&transport);
        }
    }

    pub fn is_enabled(&self, transport: TransportKind) -> bool {
        self.enabled.contains(&transport)
    }

    /// Advance every breaker's clock. Call once per scheduler tick.
    pub fn tick(&mut self, now: Seconds) {
        for breaker in self.breakers.values_mut() {
            breaker.tick(now);
        }
    }

    /// Feed a batch of canary results for one transport.
    ///
    /// Returns the health verdict so the caller can log it. `Inconclusive`
    /// results are not fed to the breaker at all: acting on evidence that was
    /// explicitly judged insufficient is how a breaker learns the wrong thing.
    pub fn observe(&mut self, transport: TransportKind, outcomes: &[ProbeOutcome], now: Seconds) -> Health {
        let health = quorum::evaluate(outcomes);
        match health {
            Health::Up => self.breaker_mut(transport).record(true, now),
            Health::Down => self.breaker_mut(transport).record(false, now),
            Health::Inconclusive => {}
        }
        health
    }

    /// Record a single real-traffic outcome against a transport.
    ///
    /// Passive evidence, so it only counts when it is unambiguous: a success
    /// proves the transport carries traffic, but one failure could be anything,
    /// and only the quorum path is allowed to open a breaker.
    pub fn observe_passive(&mut self, transport: TransportKind, outcome: &ProbeOutcome, now: Seconds) {
        if outcome.is_success() {
            self.breaker_mut(transport).record(true, now);
        }
    }

    /// Whether traffic may be sent over this transport: it must be provisioned
    /// *and* its breaker must not be open.
    pub fn is_usable(&self, transport: TransportKind) -> bool {
        self.enabled.contains(&transport) && self.breakers.get(&transport).is_none_or(Breaker::is_usable)
    }

    pub fn state(&self, transport: TransportKind) -> State {
        self.breakers.get(&transport).map_or(State::Closed, Breaker::state)
    }

    pub fn retry_in(&self, transport: TransportKind, now: Seconds) -> Option<Seconds> {
        self.breakers.get(&transport).and_then(|b| b.retry_in(now))
    }

    /// Force a transport back to trusted, e.g. after the user reconnects a VPN.
    pub fn reset(&mut self, transport: TransportKind, now: Seconds) {
        self.breaker_mut(transport).reset(now);
    }

    fn breaker_mut(&mut self, transport: TransportKind) -> &mut Breaker {
        self.breakers.entry(transport).or_default()
    }

    /// Resolve a group's configured transport into the one it should use now.
    ///
    /// `bypass_strategy` is the strategy the learner currently has in force for
    /// this group; it is attached to a `DirectBypass` fallback so the caller
    /// does not have to look it up again.
    pub fn resolve(
        &mut self,
        group: &GroupId,
        configured: &Transport,
        bypass_strategy: Option<nova_core::StrategyId>,
        now: Seconds,
    ) -> (Verdict, Reason) {
        let kind = configured.kind();
        if self.is_usable(kind) {
            if let Some(previous) = self.displaced.remove(group) {
                tracing::info!(%group, from = %previous, to = %kind, "returning to configured transport");
                return (
                    Verdict::new(configured.clone(), now, format!("{kind} recovered; returning from {previous}")),
                    Reason::AsConfigured,
                );
            }
            return (Verdict::new(configured.clone(), now, "configured transport healthy"), Reason::AsConfigured);
        }

        // Configured transport is out. Walk the preference order, skipping the
        // one that just failed and anything else that is also open.
        for candidate in TransportKind::FALLBACK_ORDER {
            if candidate == kind || !self.is_usable(candidate) {
                continue;
            }
            if !self.policy_permits(group, candidate) {
                continue;
            }
            let transport = match candidate {
                TransportKind::DirectBypass => Transport::DirectBypass { strategy: bypass_strategy.clone() },
                TransportKind::Warp => Transport::Warp,
                // A fallback to Opera needs a region, which only the config
                // knows. The routing engine substitutes the configured region;
                // an empty one here means "whatever is configured".
                TransportKind::Opera => Transport::Opera { region: String::new() },
                TransportKind::Direct => continue,
            };
            self.displaced.insert(group.clone(), candidate);
            let retry = self.retry_in(kind, now).unwrap_or(0);
            let verdict = Verdict::new(transport, now, format!("{kind} unavailable; using {candidate}"))
                .expiring(now.saturating_add(retry.max(1)));
            return (verdict, Reason::ConfiguredTransportDown { transport: kind });
        }

        // Nothing the policy allows survived. The caller must blackhole this
        // group rather than let it out: the whole point of constraining it was
        // where the traffic appears to come from.
        match self.policy(group) {
            FallbackPolicy::Adaptive => {}
            FallbackPolicy::TunnelOnly => {
                return (
                    Verdict::new(
                        configured.clone(),
                        now,
                        format!("{kind} down; {group} must not leave untunnelled"),
                    ),
                    Reason::WouldLeak { transport: kind },
                );
            }
            FallbackPolicy::Pinned(required) => {
                return (
                    Verdict::new(configured.clone(), now, format!("{required} down; {group} is pinned to it")),
                    Reason::WouldLeak { transport: kind },
                );
            }
        }

        // Nothing healthy. Stay on the configured transport rather than moving
        // traffic to a path we have equally little faith in: at least the user's
        // expectations and the failure reporting stay coherent.
        (Verdict::new(configured.clone(), now, "no healthy transport available"), Reason::NoHealthyTransport)
    }

    /// Groups currently routed somewhere other than their configuration.
    pub fn displaced(&self) -> impl Iterator<Item = (&GroupId, &TransportKind)> {
        self.displaced.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_core::{BlockSignature, StrategyId};

    fn ok() -> ProbeOutcome {
        ProbeOutcome::Success { latency_ms: 20 }
    }

    fn dead() -> ProbeOutcome {
        ProbeOutcome::Failed { signature: BlockSignature::Blackholed }
    }

    fn down_batch() -> Vec<ProbeOutcome> {
        vec![dead(), dead(), dead()]
    }

    fn up_batch() -> Vec<ProbeOutcome> {
        vec![ok(), ok(), ok()]
    }

    fn strategy() -> Option<StrategyId> {
        Some(StrategyId::new("hard_7_M65A"))
    }

    /// The requirement-3 scenario end to end.
    #[test]
    fn youtube_falls_back_to_direct_bypass_when_warp_dies_and_returns_after() {
        let mut sup = Supervisor::new([TransportKind::Warp]);
        let youtube = GroupId::new("youtube");
        let configured = Transport::Warp;
        let mut now = 0;

        // Healthy: stays on WARP.
        sup.observe(TransportKind::Warp, &up_batch(), now);
        let (verdict, reason) = sup.resolve(&youtube, &configured, strategy(), now);
        assert_eq!(verdict.transport, Transport::Warp);
        assert_eq!(reason, Reason::AsConfigured);

        // WARP dies.
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.tick(now);
            sup.observe(TransportKind::Warp, &down_batch(), now);
        }
        let (verdict, reason) = sup.resolve(&youtube, &configured, strategy(), now);
        assert_eq!(
            verdict.transport,
            Transport::DirectBypass { strategy: strategy() },
            "YouTube must keep working via direct + winws"
        );
        assert_eq!(reason, Reason::ConfiguredTransportDown { transport: TransportKind::Warp });
        assert_eq!(sup.displaced().count(), 1);

        // WARP comes back.
        now += Breaker::BASE_COOLDOWN + 1;
        sup.tick(now);
        sup.observe(TransportKind::Warp, &up_batch(), now);
        sup.observe(TransportKind::Warp, &up_batch(), now);
        let (verdict, reason) = sup.resolve(&youtube, &configured, strategy(), now);
        assert_eq!(verdict.transport, Transport::Warp, "must return to the configured transport");
        assert_eq!(reason, Reason::AsConfigured);
        assert_eq!(sup.displaced().count(), 0);
    }

    #[test]
    fn opera_failure_falls_back_to_warp_before_direct_bypass() {
        let mut sup = Supervisor::new([TransportKind::Warp, TransportKind::Opera]);
        let browser = GroupId::new("browser");
        let configured = Transport::Opera { region: "EU".to_owned() };
        let mut now = 0;
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.observe(TransportKind::Opera, &down_batch(), now);
        }
        let (verdict, _) = sup.resolve(&browser, &configured, strategy(), now);
        assert_eq!(verdict.transport.kind(), TransportKind::Warp, "a tunnel should be preferred over going direct");
    }

    #[test]
    fn when_every_tunnel_is_down_traffic_uses_dpi_bypass() {
        let mut sup = Supervisor::new([TransportKind::Warp, TransportKind::Opera]);
        let group = GroupId::new("browser");
        let configured = Transport::Warp;
        let mut now = 0;
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.observe(TransportKind::Warp, &down_batch(), now);
            sup.observe(TransportKind::Opera, &down_batch(), now);
        }
        let (verdict, _) = sup.resolve(&group, &configured, strategy(), now);
        assert_eq!(verdict.transport.kind(), TransportKind::DirectBypass);
    }

    #[test]
    fn a_tunnel_only_group_is_never_downgraded_to_an_untunnelled_path() {
        // The Python PAC blackholes RU/EU rather than going direct, on purpose
        // (nova.pyw:4858). Automatic fallback must not quietly undo that.
        let mut sup = Supervisor::new([TransportKind::Warp]);
        let ru = GroupId::new("ru");
        assert_eq!(sup.policy(&ru), FallbackPolicy::TunnelOnly, "ru must be protected by default");
        let mut now = 0;
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.observe(TransportKind::Warp, &down_batch(), now);
        }
        let (verdict, reason) = sup.resolve(&ru, &Transport::Warp, strategy(), now);
        assert_eq!(reason, Reason::WouldLeak { transport: TransportKind::Warp });
        assert!(!verdict.transport.kind().needs_dpi_bypass(), "leaked to direct+winws: {verdict:?}");
        assert_eq!(sup.displaced().count(), 0, "a blackholed group is not 'displaced'");
    }

    #[test]
    fn a_tunnel_only_group_may_still_move_between_tunnels() {
        let mut sup = Supervisor::new([TransportKind::Warp, TransportKind::Opera]);
        let ru = GroupId::new("ru");
        let mut now = 0;
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.observe(TransportKind::Warp, &down_batch(), now);
        }
        let (verdict, _) = sup.resolve(&ru, &Transport::Warp, strategy(), now);
        assert_eq!(verdict.transport.kind(), TransportKind::Opera, "a tunnel-to-tunnel move is still allowed");
    }

    #[test]
    fn an_unmarked_group_still_falls_back_to_dpi_bypass() {
        // YouTube's tunnel is about reachability, not about hiding the address,
        // so it must keep the requirement-3 behaviour.
        let mut sup = Supervisor::new([TransportKind::Warp]);
        let youtube = GroupId::new("youtube");
        assert_eq!(sup.policy(&youtube), FallbackPolicy::Adaptive);
        let mut now = 0;
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.observe(TransportKind::Warp, &down_batch(), now);
        }
        let (verdict, _) = sup.resolve(&youtube, &Transport::Warp, strategy(), now);
        assert_eq!(verdict.transport.kind(), TransportKind::DirectBypass);
    }

    #[test]
    fn eu_is_pinned_to_opera_and_never_borrows_warps_russian_egress() {
        // nova.pyw:4842 — "EU domains are Opera-only. Do not fall back to WARP
        // here: otherwise EU-listed browser traffic can silently use RU/WARP
        // egress." A healthy WARP is still the wrong answer for this group.
        let mut sup = Supervisor::new([TransportKind::Warp, TransportKind::Opera]);
        let eu = GroupId::new("eu");
        assert_eq!(sup.policy(&eu), FallbackPolicy::Pinned(TransportKind::Opera));
        let configured = Transport::Opera { region: "EU".to_owned() };
        let mut now = 0;
        // Opera dies; WARP is perfectly healthy.
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.observe(TransportKind::Opera, &down_batch(), now);
            sup.observe(TransportKind::Warp, &up_batch(), now);
        }
        let (verdict, reason) = sup.resolve(&eu, &configured, strategy(), now);
        assert_ne!(verdict.transport.kind(), TransportKind::Warp, "EU traffic must not exit via WARP");
        assert_ne!(verdict.transport.kind(), TransportKind::DirectBypass);
        assert_eq!(reason, Reason::WouldLeak { transport: TransportKind::Opera });
    }

    #[test]
    fn the_geo_groups_are_protected_without_anyone_opting_in() {
        // The dangerous configuration must not be the one you get by default.
        let sup = Supervisor::new([TransportKind::Warp, TransportKind::Opera]);
        for group in ["ru", "u_ru"] {
            assert_eq!(sup.policy(&GroupId::new(group)), FallbackPolicy::TunnelOnly, "{group}");
        }
        for group in ["eu", "u_eu"] {
            assert_eq!(sup.policy(&GroupId::new(group)), FallbackPolicy::Pinned(TransportKind::Opera), "{group}");
        }
        for group in ["youtube", "general", "telegram", "discord", "games"] {
            assert_eq!(sup.policy(&GroupId::new(group)), FallbackPolicy::Adaptive, "{group}");
        }
    }

    #[test]
    fn a_policy_can_be_relaxed_deliberately() {
        let mut sup = Supervisor::new([TransportKind::Warp]);
        let ru = GroupId::new("ru");
        sup.set_policy(ru.clone(), FallbackPolicy::Adaptive);
        let mut now = 0;
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.observe(TransportKind::Warp, &down_batch(), now);
        }
        let (verdict, _) = sup.resolve(&ru, &Transport::Warp, strategy(), now);
        assert_eq!(verdict.transport.kind(), TransportKind::DirectBypass, "an explicit override must take effect");
    }

    #[test]
    fn when_nothing_is_healthy_it_stays_put_rather_than_guessing() {
        let mut sup = Supervisor::new([TransportKind::Warp, TransportKind::Opera]);
        let group = GroupId::new("browser");
        let configured = Transport::Warp;
        let mut now = 0;
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            for kind in [TransportKind::Warp, TransportKind::Opera, TransportKind::DirectBypass] {
                sup.observe(kind, &down_batch(), now);
            }
        }
        let (verdict, reason) = sup.resolve(&group, &configured, strategy(), now);
        assert_eq!(verdict.transport, configured);
        assert_eq!(reason, Reason::NoHealthyTransport);
    }

    #[test]
    fn a_single_dead_canary_never_moves_a_group() {
        let mut sup = Supervisor::new([TransportKind::Warp]);
        let group = GroupId::new("youtube");
        let configured = Transport::Warp;
        let mut now = 0;
        for _ in 0..50 {
            now += 15;
            sup.tick(now);
            // One canary down, two up — that site's problem, not WARP's.
            sup.observe(TransportKind::Warp, &[ok(), ok(), dead()], now);
        }
        let (verdict, reason) = sup.resolve(&group, &configured, strategy(), now);
        assert_eq!(verdict.transport, Transport::Warp);
        assert_eq!(reason, Reason::AsConfigured);
    }

    #[test]
    fn inconclusive_evidence_is_not_fed_to_the_breaker() {
        let mut sup = Supervisor::new([TransportKind::Warp]);
        let mut now = 0;
        for _ in 0..50 {
            now += 15;
            sup.tick(now);
            let health = sup.observe(
                TransportKind::Warp,
                &[ProbeOutcome::Failed { signature: BlockSignature::CloudflareOriginDown }],
                now,
            );
            assert_eq!(health, Health::Inconclusive);
        }
        assert_eq!(sup.state(TransportKind::Warp), State::Closed);
    }

    #[test]
    fn fallback_verdicts_expire_so_the_engine_re_evaluates() {
        let mut sup = Supervisor::new([TransportKind::Warp]);
        let group = GroupId::new("youtube");
        let mut now = 0;
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.observe(TransportKind::Warp, &down_batch(), now);
        }
        let (verdict, _) = sup.resolve(&group, &Transport::Warp, strategy(), now);
        assert!(verdict.expires_at.is_some(), "a temporary displacement must carry an expiry");
        assert!(!verdict.is_expired(now));
    }

    #[test]
    fn a_manual_reset_restores_the_configured_route_at_once() {
        let mut sup = Supervisor::new([TransportKind::Warp]);
        let group = GroupId::new("youtube");
        let mut now = 0;
        for _ in 0..Breaker::FAILURES_TO_OPEN {
            now += 15;
            sup.observe(TransportKind::Warp, &down_batch(), now);
        }
        assert!(sup.resolve(&group, &Transport::Warp, strategy(), now).0.transport.kind() != TransportKind::Warp);
        sup.reset(TransportKind::Warp, now);
        let (verdict, reason) = sup.resolve(&group, &Transport::Warp, strategy(), now);
        assert_eq!(verdict.transport, Transport::Warp);
        assert_eq!(reason, Reason::AsConfigured);
    }
}
