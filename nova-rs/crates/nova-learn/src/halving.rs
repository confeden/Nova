//! Successive halving for the cold-start case.
//!
//! Only reached when a context has nothing to inherit. The sweep the Python
//! learner performed gave every candidate the same number of probes: with a
//! 200-entry pool and 3 probes each that is 600 network round trips before the
//! first decision. Successive halving gives every candidate one probe, discards
//! the worse half, doubles the budget for the survivors, and repeats — the same
//! confidence about the winner for roughly `n · log2(n) / n` of the cost.
//!
//! For 200 candidates: 200 + 100 + 50 + 25 + 13 + 7 + 4 + 2 ≈ 400 probe-units
//! spread over 8 rounds, but the final rounds are the only expensive ones and
//! they touch a handful of arms. Crucially the schedule can be *suspended*
//! between rounds, so the probe budget is spread across minutes of idle time
//! rather than saturating the link in one burst.

use nova_core::StrategyId;

/// A resumable successive-halving run over a candidate pool.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Schedule {
    /// Candidates still in contention, with their score in this round.
    survivors: Vec<Entry>,
    round: u32,
    /// Probes each survivor gets in the current round.
    budget: u32,
    /// Stop once this few candidates remain; the bandit takes over from there
    /// because it can keep learning from passive traffic for free.
    floor: usize,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Entry {
    id: StrategyId,
    successes: u32,
    attempts: u32,
}

impl Schedule {
    /// Candidates below this count go straight to the bandit; halving has no
    /// advantage over simply sampling them.
    pub const MIN_POOL: usize = 8;

    /// Survivor count below which the per-candidate budget starts doubling.
    ///
    /// Textbook successive halving doubles the budget every round, keeping the
    /// per-round cost flat at `n` and the total at `n · log₂(n)` — which for a
    /// 200-strategy pool is *worse* than the uniform sweep it replaces. The
    /// asymmetry that actually pays is that eliminating an arm which fails its
    /// single probe needs no confirmation, while distinguishing two arms that
    /// both work does. So the budget stays at one until the field is small
    /// enough that extra samples are cheap, which turns the 200-arm total from
    /// ~940 probes into ~430.
    const BUDGET_GROWTH_THRESHOLD: usize = 16;

    /// Build a schedule, discarding duplicate ids.
    ///
    /// Not defensive programming — Nova's shipped corpus really does contain
    /// them: `general` appears three times in `strat/general.json` and
    /// `youtube_M4E2` three times in `strat/youtube.json`. Duplicates are fatal
    /// here rather than merely untidy, because [`Schedule::record`] credits the
    /// first matching entry, so the copies never accumulate attempts,
    /// [`Schedule::round_complete`] never becomes true, and the schedule probes
    /// forever without ever advancing.
    pub fn new(candidates: impl IntoIterator<Item = StrategyId>) -> Self {
        let mut seen = std::collections::BTreeSet::new();
        Self {
            survivors: candidates
                .into_iter()
                .filter(|id| seen.insert(id.clone()))
                .map(|id| Entry { id, successes: 0, attempts: 0 })
                .collect(),
            round: 0,
            budget: 1,
            floor: 4,
        }
    }

    /// Candidates that still need probing this round, in order.
    pub fn pending(&self) -> impl Iterator<Item = &StrategyId> {
        let budget = self.budget;
        self.survivors.iter().filter(move |e| e.attempts < budget).map(|e| &e.id)
    }

    /// Whether every survivor has met this round's budget.
    pub fn round_complete(&self) -> bool {
        self.survivors.iter().all(|e| e.attempts >= self.budget)
    }

    /// Whether the schedule has narrowed enough to hand over to the bandit.
    pub fn is_finished(&self) -> bool {
        self.survivors.len() <= self.floor
    }

    pub fn round(&self) -> u32 {
        self.round
    }

    pub fn remaining(&self) -> usize {
        self.survivors.len()
    }

    /// Record a probe result for one candidate.
    pub fn record(&mut self, id: &StrategyId, success: bool) {
        if let Some(entry) = self.survivors.iter_mut().find(|e| &e.id == id) {
            entry.attempts += 1;
            if success {
                entry.successes += 1;
            }
        }
    }

    /// Drop the worse half and double the per-candidate budget.
    ///
    /// A no-op unless the round is complete, so a caller that polls this is
    /// safe. Candidates that succeeded at least once are never cut below the
    /// floor by a candidate that never did, regardless of ordering.
    pub fn advance(&mut self) -> bool {
        if !self.round_complete() || self.is_finished() {
            return false;
        }
        self.survivors.sort_by(|a, b| {
            let rate = |e: &Entry| if e.attempts == 0 { 0.0 } else { e.successes as f32 / e.attempts as f32 };
            rate(b).partial_cmp(&rate(a)).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.id.cmp(&b.id))
        });
        let keep = (self.survivors.len() / 2).max(self.floor);
        self.survivors.truncate(keep);
        for entry in &mut self.survivors {
            entry.attempts = 0;
            entry.successes = 0;
        }
        self.round += 1;
        if self.survivors.len() <= Self::BUDGET_GROWTH_THRESHOLD {
            self.budget = (self.budget * 2).min(8);
        }
        true
    }

    /// The surviving candidates, best first, for hand-off to the bandit.
    pub fn finalists(&self) -> Vec<StrategyId> {
        self.survivors.iter().map(|e| e.id.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(n: usize) -> Vec<StrategyId> {
        (0..n).map(|i| StrategyId::new(format!("s{i:03}"))).collect()
    }

    #[test]
    fn narrows_to_the_floor_and_keeps_the_winner() {
        let winner = StrategyId::new("s042");
        let mut sched = Schedule::new(pool(64));
        let mut probes = 0;
        while !sched.is_finished() {
            while !sched.round_complete() {
                let todo: Vec<StrategyId> = sched.pending().cloned().collect();
                assert!(!todo.is_empty(), "an incomplete round must have work");
                for id in todo {
                    sched.record(&id, id == winner);
                    probes += 1;
                }
            }
            assert!(sched.advance(), "a completed round must advance");
        }
        assert!(sched.finalists().contains(&winner), "winner was eliminated");
        // The sweep it replaces would have been 64 candidates x 3 probes = 192.
        assert!(probes < 192, "halving used {probes} probes, no better than a sweep");
    }

    #[test]
    fn is_cheaper_than_a_uniform_sweep_at_realistic_pool_sizes() {
        let mut sched = Schedule::new(pool(200));
        let mut probes = 0;
        while !sched.is_finished() {
            while !sched.round_complete() {
                for id in sched.pending().cloned().collect::<Vec<_>>() {
                    // Every candidate mediocre, so no early exit helps.
                    sched.record(&id, false);
                    probes += 1;
                }
            }
            sched.advance();
        }
        assert!(probes < 600, "used {probes} probes vs 600 for a 3-deep sweep");
    }

    #[test]
    fn round_is_incomplete_until_every_survivor_is_probed() {
        let mut sched = Schedule::new(pool(16));
        assert!(!sched.round_complete());
        assert!(!sched.advance());
        for id in sched.pending().cloned().collect::<Vec<_>>() {
            sched.record(&id, true);
        }
        assert!(sched.round_complete());
        assert!(sched.advance());
        assert_eq!(sched.remaining(), 8);
    }

    #[test]
    fn never_truncates_below_the_floor() {
        let mut sched = Schedule::new(pool(5));
        assert!(!sched.is_finished(), "5 candidates is still above the floor of 4");
        for id in sched.pending().cloned().collect::<Vec<_>>() {
            sched.record(&id, false);
        }
        assert!(sched.advance());
        assert_eq!(sched.remaining(), 4, "halving 5 must stop at the floor, not go to 2");
        assert!(sched.is_finished());
    }

    #[test]
    fn a_pool_at_or_below_the_floor_needs_no_halving() {
        let sched = Schedule::new(pool(4));
        assert!(sched.is_finished());
        assert_eq!(sched.finalists().len(), 4);
    }

    #[test]
    fn duplicate_candidates_cannot_stall_the_schedule() {
        // strat/general.json really does list "general" three times. Before the
        // dedupe, record() credited only the first copy, round_complete() never
        // became true, and the schedule probed forever.
        let mut ids = pool(20);
        ids.push(StrategyId::new("s000"));
        ids.push(StrategyId::new("s000"));
        ids.push(StrategyId::new("s001"));
        let mut sched = Schedule::new(ids);
        assert_eq!(sched.remaining(), 20, "duplicates should have been dropped");

        let mut rounds = 0;
        while !sched.is_finished() {
            while !sched.round_complete() {
                for id in sched.pending().cloned().collect::<Vec<_>>() {
                    sched.record(&id, false);
                }
            }
            assert!(sched.advance());
            rounds += 1;
            assert!(rounds < 20, "schedule failed to terminate");
        }
    }
}
