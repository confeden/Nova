//! The orchestrator: turns observations into a strategy choice and a probe budget.

use std::collections::BTreeMap;

use nova_core::{BlockSignature, GroupId, ProbeOutcome, Seconds, StrategyId};

use crate::change::ChangePoint;
use crate::halving::Schedule;
use crate::{NetworkContext, Posterior};

/// Tunables. Defaults are the shipping values; every one of them is a cost
/// control rather than a quality knob, because quality comes from the algorithm
/// and cost is what the user notices.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LearnerConfig {
    /// Weight of an observation that came from real user traffic.
    ///
    /// Below 1.0 because passive samples are biased: a page that loads from
    /// cache reports success without exercising the network at all.
    pub passive_weight: f32,
    /// Weight of a deliberate probe, which is unbiased and therefore worth more.
    pub probe_weight: f32,
    /// Confidence the incumbent must lose before the learner will switch on
    /// bandit evidence alone. Prevents thrashing between two near-equal arms,
    /// which costs a winws restart each time.
    pub switch_margin: f32,
    /// Maximum probes the learner may request in one exploration burst.
    pub burst_budget: u32,
    /// Minimum seconds between two exploration bursts for the same group, even
    /// if the change detector keeps firing.
    pub burst_cooldown: Seconds,
}

impl Default for LearnerConfig {
    fn default() -> Self {
        Self { passive_weight: 0.35, probe_weight: 1.0, switch_margin: 0.08, burst_budget: 12, burst_cooldown: 600 }
    }
}

/// What the learner wants the engine to do next for a group.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Keep the current arm; no network spend.
    Hold { strategy: StrategyId },
    /// Switch the live strategy. Costs one winws reconfiguration.
    Switch { from: Option<StrategyId>, to: StrategyId, reason: String },
    /// Spend probes on these candidates before deciding.
    Probe { candidates: Vec<StrategyId>, reason: String },
    /// Nothing can be learned here — the failures are not DPI-shaped. The
    /// routing engine should change transport instead.
    Escalate { signature: BlockSignature },
}

/// Per-group learned state within one network context.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
struct GroupState {
    arms: BTreeMap<StrategyId, Posterior>,
    #[serde(default)]
    incumbent: Option<StrategyId>,
    #[serde(default)]
    detector: ChangePoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cold_start: Option<Schedule>,
    #[serde(default)]
    last_burst_at: Option<Seconds>,
    /// Consecutive non-DPI-addressable failures, used to escalate to the
    /// routing engine rather than burning probes on an unwinnable pool.
    #[serde(default)]
    egress_failures: u32,
}

/// The complete persisted learner state.
///
/// `BTreeMap` throughout so the serialised form is byte-stable: an unchanged
/// state writes an unchanged file, which lets the config writer skip the disk
/// I/O entirely and keeps diffs readable.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LearnerState {
    version: u32,
    contexts: BTreeMap<NetworkContext, BTreeMap<GroupId, GroupState>>,
}

impl LearnerState {
    const VERSION: u32 = 1;

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(raw: &str) -> Result<Self, serde_json::Error> {
        let mut state: Self = serde_json::from_str(raw)?;
        if state.version != Self::VERSION {
            // Forward-compatible by discarding: learned state is regenerable
            // and a mis-parsed posterior is worse than a cold start.
            state = Self::default();
        }
        Ok(state)
    }

    /// Build a state directly from per-group arm beliefs.
    ///
    /// The one supported way to inject externally-derived posteriors — see
    /// [`crate::import`]. No incumbent is set: which arm to run is a decision
    /// for [`Learner::decide`] given the beliefs, and asserting one here would
    /// bypass the switch margin and the change detector's baseline.
    pub fn from_arms(
        context: NetworkContext,
        arms: BTreeMap<GroupId, BTreeMap<StrategyId, Posterior>>,
    ) -> Self {
        let groups = arms
            .into_iter()
            .map(|(group, arms)| (group, GroupState { arms, ..GroupState::default() }))
            .collect();
        Self { version: Self::VERSION, contexts: BTreeMap::from([(context, groups)]) }
    }

    /// Belief about one arm, or `None` if it was never observed here.
    pub fn arm(&self, context: &NetworkContext, group: &GroupId, strategy: &StrategyId) -> Option<&Posterior> {
        self.contexts.get(context)?.get(group)?.arms.get(strategy)
    }

    /// Drop every arm the predicate rejects, and report how many went.
    ///
    /// The import brings in thousands of arms, most naming strategies no pool
    /// offers any more. Keeping them is not free: this file is rewritten
    /// whenever beliefs change, and an arm that nothing can select is pure
    /// write amplification. Evidence about *dead* strategies still has value,
    /// but it belongs to the generator's novelty filter, which is consulted
    /// once per candidate, rather than to the bandit's hot state.
    pub fn retain_arms(&mut self, mut keep: impl FnMut(&GroupId, &StrategyId) -> bool) -> usize {
        let mut dropped = 0;
        for groups in self.contexts.values_mut() {
            for (group, state) in groups.iter_mut() {
                let before = state.arms.len();
                state.arms.retain(|id, _| keep(group, id));
                dropped += before - state.arms.len();
            }
            groups.retain(|_, state| !state.arms.is_empty());
        }
        dropped
    }

    /// Fold another state's beliefs in, keeping whichever is better evidenced.
    ///
    /// Used to apply an import on top of a learner that has already run: the
    /// live belief wins on any arm both know about, because it was measured on
    /// this network today and the import was not.
    pub fn merge_beneath(&mut self, other: Self, now: Seconds) {
        for (context, groups) in other.contexts {
            let target = self.contexts.entry(context).or_default();
            for (group, state) in groups {
                let dst = target.entry(group).or_default();
                for (arm, posterior) in state.arms {
                    match dst.arms.get(&arm) {
                        Some(existing) if existing.mass_at(now) > 0.0 => {}
                        _ => {
                            dst.arms.insert(arm, posterior);
                        }
                    }
                }
            }
        }
    }
}

/// Strategy selector for one running Nova instance.
pub struct Learner {
    state: LearnerState,
    config: LearnerConfig,
    context: NetworkContext,
    rng: rand::rngs::StdRng,
}

impl Learner {
    pub fn new(state: LearnerState, config: LearnerConfig, context: NetworkContext) -> Self {
        use rand::SeedableRng;
        let mut state = state;
        state.version = LearnerState::VERSION;
        Self { state, config, context, rng: rand::rngs::StdRng::from_os_rng() }
    }

    #[cfg(test)]
    fn seeded(context: NetworkContext, seed: u64) -> Self {
        use rand::SeedableRng;
        Self {
            state: LearnerState { version: LearnerState::VERSION, contexts: BTreeMap::new() },
            config: LearnerConfig::default(),
            context,
            rng: rand::rngs::StdRng::seed_from_u64(seed),
        }
    }

    pub fn state(&self) -> &LearnerState {
        &self.state
    }

    pub fn context(&self) -> &NetworkContext {
        &self.context
    }

    fn group_mut(&mut self, group: &GroupId) -> &mut GroupState {
        self.state.contexts.entry(self.context.clone()).or_default().entry(group.clone()).or_default()
    }

    /// Seed this context's beliefs from the most similar known context.
    ///
    /// Returns the number of arms inherited. Called once when Nova notices it
    /// is on a network it has no state for; skipping it is safe but expensive.
    pub fn seed_from(&mut self, source: &NetworkContext, now: Seconds) -> usize {
        if source == &self.context {
            return 0;
        }
        let Some(source_groups) = self.state.contexts.get(source).cloned() else {
            return 0;
        };
        let target = self.state.contexts.entry(self.context.clone()).or_default();
        let mut inherited = 0;
        for (group, src) in source_groups {
            let dst = target.entry(group).or_default();
            for (arm, posterior) in &src.arms {
                dst.arms.entry(arm.clone()).or_insert_with(|| {
                    inherited += 1;
                    Posterior::transferred_from(posterior, now)
                });
            }
            // The incumbent transfers as a hint, but the detector does not: its
            // baseline belongs to the network it was measured on.
            if dst.incumbent.is_none() {
                dst.incumbent = src.incumbent.clone();
            }
        }
        inherited
    }

    /// Known contexts, for the caller to score with
    /// [`crate::NetworkFingerprint::similarity`] when choosing a transfer source.
    pub fn known_contexts(&self) -> impl Iterator<Item = &NetworkContext> {
        self.state.contexts.keys()
    }

    /// Fold one outcome into the beliefs of whichever arm produced it.
    ///
    /// `from_probe` distinguishes a deliberate measurement from incidental user
    /// traffic; see [`LearnerConfig::passive_weight`].
    pub fn record(
        &mut self,
        group: &GroupId,
        strategy: &StrategyId,
        outcome: &ProbeOutcome,
        from_probe: bool,
        now: Seconds,
    ) {
        // A failure that says nothing about our configuration must not be
        // charged to the arm. This is the single most important correctness
        // rule here: without it, a site being down teaches the learner that its
        // best strategy is broken.
        if let Some(sig) = outcome.signature()
            && sig.is_not_our_fault()
        {
            return;
        }

        // The same rule, for a failure that is emphatically ours but belongs to
        // somebody else's lever. Tunnel phases describe the relay's own TLS
        // connection, which winws never touches — no strategy in this pool can
        // shape a ClientHello the relay writes itself. Charging one for an
        // ignored handshake would let a filtered fingerprint slowly retire the
        // best browser strategy on the machine, and the strategy would never
        // have been able to help.
        if let Some(sig) = outcome.signature()
            && sig.is_tunnel_phase()
        {
            return;
        }

        let weight = if from_probe { self.config.probe_weight } else { self.config.passive_weight };
        let success = outcome.is_success();
        let is_incumbent;
        let new_reference;
        {
            let state = self.group_mut(group);
            state.arms.entry(strategy.clone()).or_insert_with(|| Posterior::new(now)).observe(success, weight, now);
            if let Some(sched) = state.cold_start.as_mut() {
                sched.record(strategy, success);
            }
            match outcome.signature() {
                Some(sig) if sig.needs_different_egress() => state.egress_failures += 1,
                _ if success => state.egress_failures = 0,
                _ => {}
            }
            is_incumbent = state.incumbent.as_ref() == Some(strategy);
            new_reference = state.arms[strategy].mean_at(now);
        }
        if is_incumbent {
            let state = self.group_mut(group);
            if state.detector.observe(success, now) {
                tracing::info!(%group, %strategy, "change point: incumbent strategy regressed");
                // Re-baseline on what the arm is actually delivering now, so a
                // permanently degraded network does not alarm forever.
                state.detector.rebase(new_reference.clamp(0.05, 0.95));
                state.last_burst_at = None;
            }
        }
    }

    /// Decide what to do for a group right now.
    ///
    /// Pure computation: no I/O, no sleeping, microseconds of arithmetic. The
    /// caller drives it from its own scheduler and is free to call it on every
    /// UI tick.
    pub fn decide(&mut self, group: &GroupId, pool: &[StrategyId], now: Seconds) -> Decision {
        if pool.is_empty() {
            return Decision::Escalate { signature: BlockSignature::Unknown };
        }

        // Escalate before spending anything when the evidence says the problem
        // is not one a strategy can solve.
        {
            let state = self.group_mut(group);
            if state.egress_failures >= 3 {
                state.egress_failures = 0;
                return Decision::Escalate { signature: BlockSignature::Blackholed };
            }
        }

        // Cold start: no beliefs at all and a pool large enough to be worth
        // narrowing before sampling.
        let needs_cold_start = {
            let state = self.group_mut(group);
            state.arms.is_empty() && pool.len() >= Schedule::MIN_POOL
        };
        if needs_cold_start {
            let state = self.group_mut(group);
            state.cold_start.get_or_insert_with(|| Schedule::new(pool.iter().cloned()));
        }
        if let Some(decision) = self.drive_cold_start(group) {
            return decision;
        }

        let config = self.config.clone();
        let state = self.group_mut(group);
        // Ensure every pool member has a belief so a newly shipped strategy is
        // reachable without waiting for a cold start that will never come.
        for id in pool {
            state.arms.entry(id.clone()).or_insert_with(|| Posterior::new(now));
        }

        let incumbent = state.incumbent.clone();
        let arms: Vec<(StrategyId, Posterior)> =
            pool.iter().filter_map(|id| state.arms.get(id).map(|p| (id.clone(), *p))).collect();

        // Thompson sampling: one draw per arm, pick the argmax.
        let mut best: Option<(StrategyId, f32)> = None;
        for (id, posterior) in &arms {
            let draw = posterior.sample(now, &mut self.rng);
            if best.as_ref().is_none_or(|(_, b)| draw > *b) {
                best = Some((id.clone(), draw));
            }
        }
        let (challenger, _) = best.expect("pool is non-empty");

        let state = self.group_mut(group);
        let Some(current) = incumbent else {
            state.incumbent = Some(challenger.clone());
            let reference = state.arms[&challenger].mean_at(now);
            state.detector.rebase(reference.clamp(0.05, 0.95));
            return Decision::Switch { from: None, to: challenger, reason: "no strategy in force yet".to_owned() };
        };

        if challenger == current {
            return Decision::Hold { strategy: current };
        }

        // Switching costs a winws reconfiguration and a brief interruption of
        // every live flow in the group, so require the challenger to be better
        // on a conservative comparison, not merely luckier on one draw.
        let challenger_floor = state.arms[&challenger].lower_bound(now, 1.0);
        let incumbent_mean = state.arms.get(&current).map_or(0.0, |p| p.mean_at(now));
        if challenger_floor > incumbent_mean + config.switch_margin {
            let reason =
                format!("{challenger} lower-bound {challenger_floor:.2} beats {current} mean {incumbent_mean:.2}");
            state.incumbent = Some(challenger.clone());
            state.detector.rebase(challenger_floor.clamp(0.05, 0.95));
            return Decision::Switch { from: Some(current), to: challenger, reason };
        }

        // Not confident enough to switch. Probe only if the change detector has
        // already said the incumbent is failing and the cooldown has lapsed —
        // on a healthy network this branch is never taken, which is what makes
        // steady-state cost zero.
        let alarmed = state.detector.pressure() >= 1.0;
        let cooled = state.last_burst_at.is_none_or(|t| now.saturating_sub(t) >= config.burst_cooldown);
        if alarmed && cooled {
            state.last_burst_at = Some(now);
            // Most-promising first, so a truncated burst spends its probes on
            // the arms most likely to end it early.
            let mut ranked: Vec<(StrategyId, f32)> =
                arms.iter().filter(|(id, _)| id != &current).map(|(id, p)| (id.clone(), p.mean_at(now))).collect();
            ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            ranked.truncate(config.burst_budget as usize);
            let candidates: Vec<StrategyId> = ranked.into_iter().map(|(id, _)| id).collect();
            return Decision::Probe {
                candidates,
                reason: format!("{current} regressed; exploring {} alternatives", config.burst_budget),
            };
        }

        Decision::Hold { strategy: current }
    }

    /// Returns a decision while a cold-start schedule is running, or `None` once
    /// it has narrowed enough for the bandit to take over.
    fn drive_cold_start(&mut self, group: &GroupId) -> Option<Decision> {
        let budget = self.config.burst_budget as usize;
        let state = self.group_mut(group);
        let sched = state.cold_start.as_mut()?;
        if sched.is_finished() {
            state.cold_start = None;
            return None;
        }
        if sched.round_complete() {
            sched.advance();
        }
        let mut candidates: Vec<StrategyId> = sched.pending().cloned().collect();
        if candidates.is_empty() {
            state.cold_start = None;
            return None;
        }
        let round = sched.round();
        let remaining = sched.remaining();
        candidates.truncate(budget);
        Some(Decision::Probe {
            candidates,
            reason: format!("cold start round {round}, {remaining} candidates remain"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(n: usize) -> Vec<StrategyId> {
        (0..n).map(|i| StrategyId::new(format!("s{i:03}"))).collect()
    }

    fn ok() -> ProbeOutcome {
        ProbeOutcome::Success { latency_ms: 50 }
    }

    fn blocked() -> ProbeOutcome {
        ProbeOutcome::Failed { signature: BlockSignature::RstImmediate }
    }

    fn learner() -> Learner {
        Learner::seeded(NetworkContext::new("as12389"), 7)
    }

    /// Drive the learner to convergence and report how many probes it asked for.
    fn converge(l: &mut Learner, group: &GroupId, pool: &[StrategyId], winner: &StrategyId) -> (u32, StrategyId) {
        let mut probes = 0;
        let mut now = 0;
        let mut settled = StrategyId::new("none");
        for _ in 0..400 {
            now += 5;
            match l.decide(group, pool, now) {
                Decision::Probe { candidates, .. } => {
                    for c in candidates {
                        probes += 1;
                        let outcome = if &c == winner { ok() } else { blocked() };
                        l.record(group, &c, &outcome, true, now);
                    }
                }
                Decision::Switch { to, .. } => {
                    settled = to.clone();
                    let outcome = if &to == winner { ok() } else { blocked() };
                    l.record(group, &to, &outcome, false, now);
                }
                Decision::Hold { strategy } => {
                    settled = strategy.clone();
                    let outcome = if &strategy == winner { ok() } else { blocked() };
                    l.record(group, &strategy, &outcome, false, now);
                }
                Decision::Escalate { .. } => break,
            }
        }
        (probes, settled)
    }

    #[test]
    fn finds_the_working_strategy_in_a_large_pool() {
        let mut l = learner();
        let group = GroupId::new("youtube");
        let p = pool(64);
        let winner = p[41].clone();
        let (probes, settled) = converge(&mut l, &group, &p, &winner);
        assert_eq!(settled, winner, "did not converge on the working strategy");
        assert!(probes < 200, "spent {probes} probes on a 64-arm pool");
    }

    #[test]
    fn a_healthy_group_costs_no_probes_at_all() {
        let mut l = learner();
        let group = GroupId::new("general");
        let p = pool(16);
        let winner = p[3].clone();
        converge(&mut l, &group, &p, &winner);

        // Now simulate a long healthy stretch driven purely by user traffic.
        let mut probes = 0;
        let mut now = 10_000;
        for _ in 0..2_000 {
            now += 30;
            match l.decide(&group, &p, now) {
                Decision::Probe { candidates, .. } => probes += candidates.len(),
                Decision::Hold { strategy } | Decision::Switch { to: strategy, .. } => {
                    let outcome = if strategy == winner { ok() } else { blocked() };
                    l.record(&group, &strategy, &outcome, false, now);
                }
                Decision::Escalate { .. } => {}
            }
        }
        assert_eq!(probes, 0, "a working network must not be probed at all");
    }

    #[test]
    fn reacts_when_the_winning_strategy_stops_working() {
        let mut l = learner();
        let group = GroupId::new("youtube");
        let p = pool(16);
        let first = p[2].clone();
        converge(&mut l, &group, &p, &first);

        // The ISP updates its DPI: the old winner dies, a different one works.
        let second = p[9].clone();
        let mut now = 50_000;
        let mut settled = first.clone();
        for _ in 0..600 {
            now += 5;
            match l.decide(&group, &p, now) {
                Decision::Probe { candidates, .. } => {
                    for c in candidates {
                        let outcome = if c == second { ok() } else { blocked() };
                        l.record(&group, &c, &outcome, true, now);
                    }
                }
                Decision::Switch { to, .. } => {
                    settled = to.clone();
                    let outcome = if to == second { ok() } else { blocked() };
                    l.record(&group, &to, &outcome, false, now);
                }
                Decision::Hold { strategy } => {
                    settled = strategy.clone();
                    let outcome = if strategy == second { ok() } else { blocked() };
                    l.record(&group, &strategy, &outcome, false, now);
                }
                Decision::Escalate { .. } => {}
            }
        }
        assert_eq!(settled, second, "learner did not adapt to the new block");
    }

    #[test]
    fn failures_that_are_not_our_fault_do_not_poison_the_incumbent() {
        let mut l = learner();
        let group = GroupId::new("general");
        let p = pool(16);
        let winner = p[5].clone();
        converge(&mut l, &group, &p, &winner);

        let before = l.state.contexts[&l.context][&group].arms[&winner].mean_at(60_000);
        for _ in 0..50 {
            l.record(
                &group,
                &winner,
                &ProbeOutcome::Failed { signature: BlockSignature::ConnectionRefused },
                false,
                60_000,
            );
        }
        let after = l.state.contexts[&l.context][&group].arms[&winner].mean_at(60_000);
        assert!((before - after).abs() < 1e-6, "site-down errors were charged to the strategy");
    }

    #[test]
    fn tunnel_phases_are_not_charged_to_a_strategy_that_cannot_reach_them() {
        // The relay shapes its own TLS before it is ever a packet, so winws has
        // no lever on it. Letting a filtered ClientHello count against the
        // incumbent would retire the best browser strategy on the machine over
        // a failure it was structurally incapable of fixing.
        let mut l = learner();
        let group = GroupId::new("general");
        let p = pool(16);
        let winner = p[5].clone();
        converge(&mut l, &group, &p, &winner);

        let before = l.state.contexts[&l.context][&group].arms[&winner].mean_at(60_000);
        for sig in BlockSignature::ALL.into_iter().filter(|s| s.is_tunnel_phase()) {
            for _ in 0..50 {
                l.record(&group, &winner, &ProbeOutcome::Failed { signature: sig }, false, 60_000);
            }
        }
        let after = l.state.contexts[&l.context][&group].arms[&winner].mean_at(60_000);
        assert!((before - after).abs() < 1e-6, "a tunnel phase was charged to a winws strategy");
    }

    #[test]
    fn tunnel_phases_do_not_drive_the_egress_escalation_either() {
        // `TunnelStalled` and `TunnelUpgradeRejected` do ask for another
        // egress — the relay's own. Feeding that into the browser groups'
        // escalation counter would move traffic for an unrelated subsystem.
        let mut l = learner();
        let group = GroupId::new("general");
        let p = pool(16);
        let arm = p[0].clone();
        for _ in 0..10 {
            l.record(
                &group,
                &arm,
                &ProbeOutcome::Failed { signature: BlockSignature::TunnelStalled },
                true,
                10,
            );
        }
        // Strongest form of the guarantee: ten tunnel failures did not even
        // bring the group into existence, so there is nothing they could have
        // biased. If the group does exist, its escalation counter must be cold.
        let escalations = l
            .state
            .contexts
            .get(&l.context)
            .and_then(|groups| groups.get(&group))
            .map_or(0, |state| state.egress_failures);
        assert_eq!(escalations, 0);
    }

    #[test]
    fn escalates_instead_of_probing_when_the_block_is_not_dpi_shaped() {
        let mut l = learner();
        let group = GroupId::new("cloudflare");
        let p = pool(16);
        let arm = p[0].clone();
        for _ in 0..3 {
            l.record(&group, &arm, &ProbeOutcome::Failed { signature: BlockSignature::Blackholed }, true, 10);
        }
        assert!(matches!(l.decide(&group, &p, 20), Decision::Escalate { .. }));
    }

    #[test]
    fn transfer_makes_a_new_network_cheap() {
        let mut home = learner();
        let group = GroupId::new("youtube");
        let p = pool(64);
        let winner = p[41].clone();
        converge(&mut home, &group, &p, &winner);

        let mut moved =
            Learner::new(home.state().clone(), LearnerConfig::default(), NetworkContext::new("as31133"));
        let inherited = moved.seed_from(&NetworkContext::new("as12389"), 100_000);
        assert!(inherited > 0, "nothing was inherited");

        let (probes, settled) = converge(&mut moved, &group, &p, &winner);
        assert_eq!(settled, winner);
        assert!(probes < 40, "warm start still spent {probes} probes");
    }

    #[test]
    fn state_survives_a_round_trip_through_json() {
        let mut l = learner();
        let group = GroupId::new("youtube");
        let p = pool(16);
        converge(&mut l, &group, &p, &p[1].clone());

        let json = l.state().to_json().unwrap();
        let restored = LearnerState::from_json(&json).unwrap();
        assert_eq!(&restored, l.state());
        assert!(json.len() < 16_384, "state is {} bytes, too fat to write often", json.len());
    }

    #[test]
    fn a_future_state_version_is_discarded_rather_than_misread() {
        let json = r#"{"version":999,"contexts":{}}"#;
        assert_eq!(LearnerState::from_json(json).unwrap(), LearnerState::default());
    }
}
