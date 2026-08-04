//! Change-point detection on the success stream of the arm currently in force.
//!
//! This is what makes the steady-state probe budget zero. The learner does not
//! ask "is it time to re-check?" on a timer; it asks "has the thing I believed
//! stopped being true?", and only then spends network.

use nova_core::Seconds;

/// One-sided Page–Hinkley test for a downward shift in a Bernoulli mean.
///
/// Page–Hinkley accumulates the signed deviation of each observation from the
/// running reference mean, tracks the running maximum of that cumulative sum,
/// and fires when the current sum falls `lambda` below the maximum. It is
/// preferred here over a fixed-window failure counter because it separates a
/// genuine regime change from an unlucky run: three failures out of three on an
/// arm that has never failed is alarming, three out of three on an arm that
/// works 60% of the time is Tuesday.
///
/// Only downward shifts are tested. An arm getting *better* needs no reaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChangePoint {
    /// Reference success rate the detector is testing against.
    reference: f32,
    /// Tolerated drift before a deviation starts counting. Suppresses the slow
    /// false-positive creep that a pure cumulative sum accrues from noise alone.
    delta: f32,
    /// Detection threshold. Larger means slower but fewer false alarms.
    lambda: f32,
    cumulative: f32,
    /// Running minimum of `cumulative`. Page–Hinkley fires on the *excursion*
    /// above this floor, which is what makes it insensitive to the absolute
    /// baseline and therefore usable on both a 95%-reliable and a 60%-reliable
    /// arm with the same threshold.
    min_cumulative: f32,
    observations: u32,
    /// Observations required before the detector may fire, so a freshly reset
    /// detector cannot alarm on its first unlucky sample.
    warmup: u32,
    last_fired_at: Option<Seconds>,
}

impl Default for ChangePoint {
    fn default() -> Self {
        Self::new(0.9)
    }
}

impl ChangePoint {
    /// Minimum seconds between two alarms for the same arm.
    ///
    /// Without this the detector re-fires on every observation while a network
    /// is down, and each alarm costs a probe burst. Five minutes bounds the
    /// worst case to twelve bursts an hour during a sustained outage.
    pub const COOLDOWN: Seconds = 300;

    pub fn new(reference: f32) -> Self {
        Self {
            reference: reference.clamp(0.01, 0.99),
            delta: 0.05,
            lambda: 2.5,
            cumulative: 0.0,
            min_cumulative: 0.0,
            observations: 0,
            warmup: 5,
            last_fired_at: None,
        }
    }

    /// Rebase the detector on a new expected success rate.
    ///
    /// Called whenever the learner switches arms: the old arm's baseline says
    /// nothing about the new one, and carrying it over produces an immediate
    /// spurious alarm.
    pub fn rebase(&mut self, reference: f32) {
        let fired = self.last_fired_at;
        *self = Self::new(reference);
        self.last_fired_at = fired;
    }

    /// Feed one outcome. Returns `true` when a downward regime change is
    /// declared, at which point the detector resets itself.
    pub fn observe(&mut self, success: bool, now: Seconds) -> bool {
        let x = if success { 1.0 } else { 0.0 };
        // Each failure pushes the sum up by roughly `reference`; each success
        // pulls it down by roughly `1 - reference`. On an arm performing at its
        // baseline the drift is `-delta` per observation, so the sum sinks and
        // the excursion stays flat.
        self.cumulative += self.reference - x - self.delta;
        self.min_cumulative = self.min_cumulative.min(self.cumulative);
        self.observations += 1;

        if self.observations < self.warmup {
            return false;
        }
        if self.cumulative - self.min_cumulative <= self.lambda {
            return false;
        }
        if let Some(last) = self.last_fired_at
            && now.saturating_sub(last) < Self::COOLDOWN
        {
            // Still alarming, but the consumer has been told recently. Hold the
            // excursion rather than resetting, so the alarm re-fires the moment
            // the cooldown lapses if the condition persists.
            return false;
        }
        self.last_fired_at = Some(now);
        self.reset_accumulators();
        true
    }

    fn reset_accumulators(&mut self) {
        self.cumulative = 0.0;
        self.min_cumulative = 0.0;
        self.observations = 0;
    }

    /// How close the evidence is to triggering, in [0, 1]. Purely for the
    /// diagnostics view.
    pub fn pressure(&self) -> f32 {
        ((self.cumulative - self.min_cumulative) / self.lambda).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reliable_arm_never_alarms() {
        let mut cp = ChangePoint::new(0.95);
        let mut t = 0;
        for i in 0..2_000 {
            // 95% success, deterministic pattern.
            let success = i % 20 != 0;
            t += 10;
            assert!(!cp.observe(success, t), "false alarm at observation {i}");
        }
    }

    #[test]
    fn a_flaky_arm_at_its_own_baseline_never_alarms() {
        let mut cp = ChangePoint::new(0.6);
        let mut t = 0;
        for i in 0..2_000 {
            let success = i % 5 >= 2; // 60%
            t += 10;
            assert!(!cp.observe(success, t), "false alarm at observation {i}");
        }
    }

    #[test]
    fn a_collapse_is_detected_quickly() {
        let mut cp = ChangePoint::new(0.95);
        let mut t = 0;
        for _ in 0..50 {
            t += 10;
            cp.observe(true, t);
        }
        let mut fired_after = None;
        for i in 0..40 {
            t += 10;
            if cp.observe(false, t) {
                fired_after = Some(i + 1);
                break;
            }
        }
        let n = fired_after.expect("collapse must be detected");
        assert!(n <= 10, "took {n} failures to notice a total collapse");
    }

    #[test]
    fn cooldown_bounds_alarm_frequency() {
        let mut cp = ChangePoint::new(0.95);
        let mut fires = 0;
        // Sustained total outage, one observation per second for an hour.
        for t in 0..3_600 {
            if cp.observe(false, t) {
                fires += 1;
            }
        }
        assert!(fires <= 3_600 / ChangePoint::COOLDOWN as usize + 1, "fired {fires} times in an hour");
        assert!(fires >= 1, "a one-hour outage must alarm at least once");
    }

    #[test]
    fn rebasing_clears_accumulated_pressure() {
        let mut cp = ChangePoint::new(0.95);
        // Four failures: enough to build pressure, one short of the warmup that
        // would fire the alarm and reset the accumulators for us.
        for t in 0..4 {
            assert!(!cp.observe(false, t));
        }
        assert!(cp.pressure() > 0.0);
        cp.rebase(0.5);
        assert_eq!(cp.pressure(), 0.0);
    }
}
