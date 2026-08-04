//! Rate governor for continuous background exploration.
//!
//! # The shape of the problem
//!
//! The Python learner ran as a *campaign*: nothing for days, then ~9,500 probes
//! and ~130 winws restarts crammed into one window that pinned the CPU and made
//! the window unresponsive. Users experienced learning as an event that happened
//! *to* them.
//!
//! Continuous exploration inverts that. The same knowledge is acquired by a
//! trickle that never has a peak — a probe every half minute is roughly 2,800 a
//! day, more evidence than the old sweep gathered per cycle, spread thinly
//! enough that no single second is measurably busier than idle.
//!
//! The governor is what enforces "never has a peak". Two properties matter and
//! both are tested:
//!
//! - **Bounded rate.** Long-run probes per hour never exceed the configured
//!   ceiling, whatever the caller does.
//! - **No saved-up bursts.** An idle night must not buy the right to fire
//!   hundreds of probes the moment the user sits down. The bucket is
//!   deliberately shallow, which is the opposite of what a throughput-oriented
//!   token bucket would do.
//!
//! # Yielding to the user
//!
//! Exploration is never urgent. Anything the user is doing — a video call, a
//! download, a game — outranks it, so the governor scales its rate down by
//! observed activity and stops outright on a metered connection, where a probe
//! costs the user money rather than milliseconds.

use nova_core::Seconds;

/// How busy the machine and its network are, as far as the caller can tell.
///
/// Deliberately coarse. A finer signal would imply a precision the underlying
/// measurements do not have, and the only decision downstream is a multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Activity {
    /// No foreground network use; the machine is essentially idle.
    Idle,
    /// Normal browsing. Probes are unnoticeable but should not compete.
    Light,
    /// Sustained transfer, a call, or a game. Exploration stops being polite.
    Heavy,
    /// The user is paying per byte, or Windows reports the link as metered.
    Metered,
}

impl Activity {
    /// Multiplier applied to the base rate.
    ///
    /// `Heavy` is not zero: a network under load is exactly when a broken
    /// strategy is most visible, so a slow trickle of evidence there is more
    /// valuable than anywhere else. It is merely rare enough to be free.
    fn multiplier(self) -> f32 {
        match self {
            Activity::Idle => 1.0,
            Activity::Light => 0.5,
            Activity::Heavy => 0.1,
            Activity::Metered => 0.0,
        }
    }
}

/// Tunables for the background probe rate.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GovernorConfig {
    /// Probes per hour when fully idle.
    ///
    /// 120 is one every thirty seconds. Chosen because a single TLS probe is
    /// roughly 20 KB and 30 ms of work: at this rate background learning costs
    /// about 2.4 MB and 3.6 seconds of CPU per day, which is below the noise
    /// floor of an idle desktop.
    pub probes_per_hour: f32,
    /// Maximum tokens the bucket may hold.
    ///
    /// Small on purpose. This is the anti-burst property: no matter how long the
    /// machine idles, exploration can never resume with more than this many
    /// probes back to back.
    pub burst: f32,
    /// Minimum seconds between two winws reconfigurations.
    ///
    /// Separate from the probe budget because a reconfiguration briefly
    /// interrupts every live connection in the group, so its cost is measured in
    /// user annoyance rather than bandwidth. Ten minutes.
    pub min_seconds_between_swaps: Seconds,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self { probes_per_hour: 120.0, burst: 3.0, min_seconds_between_swaps: 600 }
    }
}

/// Token bucket over background exploration work.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Governor {
    config: GovernorConfig,
    tokens: f32,
    last_refill: Seconds,
    activity: Activity,
    last_swap_at: Option<Seconds>,
    /// Lifetime counter, for the diagnostics view.
    spent: u64,
}

impl Default for Governor {
    fn default() -> Self {
        Self::new(GovernorConfig::default(), 0)
    }
}

impl Governor {
    pub fn new(config: GovernorConfig, now: Seconds) -> Self {
        Self {
            config,
            // Start empty. A freshly launched Nova has plenty to do; spending
            // its first seconds on speculative probes competes with startup.
            tokens: 0.0,
            last_refill: now,
            activity: Activity::Light,
            last_swap_at: None,
            spent: 0,
        }
    }

    pub fn set_activity(&mut self, activity: Activity, now: Seconds) {
        self.refill(now);
        self.activity = activity;
    }

    pub fn activity(&self) -> Activity {
        self.activity
    }

    pub fn spent(&self) -> u64 {
        self.spent
    }

    fn refill(&mut self, now: Seconds) {
        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed == 0 {
            return;
        }
        self.last_refill = now;
        let rate = self.config.probes_per_hour * self.activity.multiplier() / 3600.0;
        self.tokens = (self.tokens + rate * elapsed as f32).min(self.config.burst);
    }

    /// Try to claim budget for `count` probes. All-or-nothing.
    ///
    /// Returns how many were granted, which is either `count` or zero — partial
    /// grants would leave the caller holding a half-executed exploration round.
    pub fn claim(&mut self, count: u32, now: Seconds) -> u32 {
        self.refill(now);
        let needed = count as f32;
        if needed <= self.tokens {
            self.tokens -= needed;
            self.spent += u64::from(count);
            count
        } else {
            0
        }
    }

    /// Whether a winws reconfiguration is allowed right now.
    ///
    /// Independent of the probe budget: a swap the evidence justifies should not
    /// be blocked because probes are scarce, and a cheap probe should not be
    /// blocked because a swap happened recently.
    pub fn may_swap(&self, now: Seconds) -> bool {
        self.last_swap_at.is_none_or(|t| now.saturating_sub(t) >= self.config.min_seconds_between_swaps)
    }

    pub fn record_swap(&mut self, now: Seconds) {
        self.last_swap_at = Some(now);
    }

    /// Seconds until at least one probe can be claimed, for the UI.
    pub fn seconds_until_ready(&self, now: Seconds) -> Option<Seconds> {
        let mut probe = self.clone();
        probe.refill(now);
        if probe.tokens >= 1.0 {
            return Some(0);
        }
        let rate = self.config.probes_per_hour * self.activity.multiplier() / 3600.0;
        if rate <= 0.0 {
            return None;
        }
        Some(((1.0 - probe.tokens) / rate).ceil() as Seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a governor for `hours` of simulated time, claiming one probe per
    /// second whenever allowed, and report how many were granted.
    fn probes_in(hours: u64, activity: Activity) -> u64 {
        let mut g = Governor::new(GovernorConfig::default(), 0);
        g.set_activity(activity, 0);
        let mut granted = 0;
        for t in 1..=(hours * 3600) {
            granted += u64::from(g.claim(1, t));
        }
        granted
    }

    #[test]
    fn idle_rate_matches_the_configured_ceiling() {
        let granted = probes_in(10, Activity::Idle);
        let per_hour = granted as f32 / 10.0;
        assert!((per_hour - 120.0).abs() < 5.0, "got {per_hour}/hour, expected ~120");
    }

    #[test]
    fn a_greedy_caller_cannot_exceed_the_ceiling() {
        // Claim as hard as possible every single second for a day.
        let mut g = Governor::new(GovernorConfig::default(), 0);
        g.set_activity(Activity::Idle, 0);
        let mut granted = 0u64;
        for t in 1..=86_400 {
            for _ in 0..10 {
                granted += u64::from(g.claim(1, t));
            }
        }
        assert!(granted <= 24 * 125, "greedy caller extracted {granted} probes in a day");
    }

    #[test]
    fn an_idle_night_does_not_buy_a_morning_burst() {
        // Eight hours idle, then measure what can be claimed in one instant.
        let mut g = Governor::new(GovernorConfig::default(), 0);
        g.set_activity(Activity::Idle, 0);
        let morning = 8 * 3600;
        let mut immediate = 0;
        while g.claim(1, morning) == 1 {
            immediate += 1;
            assert!(immediate < 1000, "bucket is unbounded");
        }
        assert!(immediate <= GovernorConfig::default().burst as u32, "burst of {immediate} after an idle night");
    }

    #[test]
    fn user_activity_scales_the_rate_down() {
        let idle = probes_in(10, Activity::Idle);
        let light = probes_in(10, Activity::Light);
        let heavy = probes_in(10, Activity::Heavy);
        assert!(idle > light, "idle {idle} should exceed light {light}");
        assert!(light > heavy, "light {light} should exceed heavy {heavy}");
        assert!(heavy > 0, "a busy network is where evidence matters most; it must not be silenced entirely");
    }

    #[test]
    fn a_metered_connection_stops_exploration_completely() {
        assert_eq!(probes_in(24, Activity::Metered), 0, "metered links must cost the user nothing");
        let mut g = Governor::new(GovernorConfig::default(), 0);
        g.set_activity(Activity::Metered, 0);
        assert_eq!(g.seconds_until_ready(10_000), None);
    }

    #[test]
    fn claims_are_all_or_nothing() {
        let mut g = Governor::new(GovernorConfig::default(), 0);
        g.set_activity(Activity::Idle, 0);
        // Accumulate to the 3-token cap.
        assert_eq!(g.claim(4, 3600), 0, "a claim larger than the bucket must be refused outright");
        assert_eq!(g.claim(3, 3600), 3);
        assert_eq!(g.claim(1, 3600), 0, "bucket should now be empty");
    }

    #[test]
    fn swap_throttling_is_independent_of_the_probe_budget() {
        let mut g = Governor::new(GovernorConfig::default(), 0);
        assert!(g.may_swap(0), "the first swap must not be blocked");
        g.record_swap(100);
        assert!(!g.may_swap(200));
        assert!(g.may_swap(100 + GovernorConfig::default().min_seconds_between_swaps));
        // Exhausting probes must not affect it.
        g.set_activity(Activity::Idle, 0);
        while g.claim(1, 5_000) == 1 {}
        assert!(g.may_swap(5_000), "probe scarcity must not block a justified swap");
    }

    #[test]
    fn a_day_of_background_learning_is_cheap() {
        // The claim made in the module docs, checked rather than asserted in
        // prose: ~2,800 probes a day at ~20 KB each is under 60 MB, and at ~30 ms
        // each is under two minutes of CPU spread over 24 hours.
        let granted = probes_in(24, Activity::Idle);
        let megabytes = granted as f32 * 20.0 / 1024.0;
        let cpu_seconds = granted as f32 * 0.03;
        assert!(granted > 2_500 && granted < 3_100, "{granted} probes/day");
        assert!(megabytes < 60.0, "{megabytes:.1} MB/day");
        assert!(cpu_seconds < 120.0, "{cpu_seconds:.0} s of CPU/day");
    }

    #[test]
    fn countdown_reports_a_sane_wait() {
        let mut g = Governor::new(GovernorConfig::default(), 0);
        g.set_activity(Activity::Idle, 0);
        // Empty bucket at t=0, refilling at 120/hour = one per 30 s.
        let wait = g.seconds_until_ready(0).unwrap();
        assert!((29..=31).contains(&wait), "expected ~30 s, got {wait}");
        assert_eq!(g.seconds_until_ready(3600), Some(0));
    }
}
