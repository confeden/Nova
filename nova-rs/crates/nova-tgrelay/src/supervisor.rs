//! When to bring the relay back up, and when to leave it down.
//!
//! Layer 11 of the port out of `tgrelay/transparent_relay.py::_thread_main`
//! (`:1993`). Three rules live in that loop and none of them could be reached
//! from a test, because reaching them meant crashing a real relay:
//!
//! - **An ordered exit is not a crash.** `stop()` sets a flag and the loop
//!   breaks; without that distinction the supervisor fights the shutdown by
//!   restarting what was just asked to stop.
//! - **A run that lasted long enough forgives everything before it.** Thirty
//!   seconds of service resets the backoff to one second, so an hourly hiccup
//!   never accumulates into a quarter-minute wait.
//! - **The log is throttled, not silenced.** The first failure and then every
//!   fifth: enough to see a port that stays occupied, not enough to bury the
//!   rest of the session under it.
//!
//! **One thing the port deletes rather than carries.** The Python sleeps its
//! backoff in 0.25 s slices, re-checking `_stopping` between them, because
//! `time.sleep` cannot be interrupted. A tokio supervisor waits on the delay and
//! the shutdown signal together, so the slicing has nothing to do and is gone.
//! It was a workaround for the runtime, not a rule about relays.

use std::time::Duration;

/// What to do now that one life of the relay has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    /// It exited in an ordered way. Leave it down.
    Stop,
    /// Wait, then run it again.
    After {
        delay: Duration,
        /// Which consecutive attempt the next one will be. Reset by a healthy
        /// run, so it counts *this* streak of failures rather than the session.
        attempt: u32,
        /// Whether this one is worth a line in the log.
        announce: bool,
    },
}

/// `_SUPERVISOR_BACKOFF_MAX`.
pub const BACKOFF_MAX: Duration = Duration::from_secs(15);
/// `_SUPERVISOR_HEALTHY_RUN`.
pub const HEALTHY_RUN: Duration = Duration::from_secs(30);
/// Where the backoff starts, and where a healthy run returns it to.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct RestartPolicy {
    initial: Duration,
    max: Duration,
    healthy_run: Duration,
    backoff: Duration,
    attempt: u32,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self::new(BACKOFF_INITIAL, BACKOFF_MAX, HEALTHY_RUN)
    }
}

impl RestartPolicy {
    pub fn new(initial: Duration, max: Duration, healthy_run: Duration) -> Self {
        Self { initial, max, healthy_run, backoff: initial, attempt: 0 }
    }

    /// How many consecutive failures the relay is on.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// One life ended after `uptime`. `crashed` is false for an ordered exit.
    pub fn record(&mut self, uptime: Duration, crashed: bool) -> Restart {
        self.attempt += 1;
        if !crashed {
            return Restart::Stop;
        }
        if uptime >= self.healthy_run {
            // It served for long enough that whatever came before is not part of
            // the same fault. Start over.
            self.backoff = self.initial;
            self.attempt = 1;
        }
        let delay = self.backoff;
        let attempt = self.attempt;
        // Doubled *after* the delay is taken, so the first restart is immediate
        // by the initial value rather than already doubled.
        self.backoff = (self.backoff * 2).min(self.max);
        Restart::After { delay, attempt, announce: attempt == 1 || attempt.is_multiple_of(5) }
    }

    /// The line the Python writes when it announces a restart.
    ///
    /// Russian and reproduced exactly: the relay's log lines are what a user
    /// sends in when something is wrong, and they are searched for literally.
    pub fn restart_line(uptime: Duration, attempt: u32, delay: Duration) -> String {
        format!(
            "[TgRelay] Релей упал после {:.0}с (попытка {}); перезапуск через {:.0}с.",
            uptime.as_secs_f64(),
            attempt,
            delay.as_secs_f64()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn an_ordered_exit_is_not_a_crash() {
        // Without this the supervisor fights `stop()` by restarting what was
        // just asked to stop.
        let mut policy = RestartPolicy::default();
        assert_eq!(policy.record(secs(120), false), Restart::Stop);
    }

    #[test]
    fn the_backoff_doubles_to_a_ceiling() {
        let mut policy = RestartPolicy::default();
        let delays: Vec<u64> = (0..8)
            .map(|_| match policy.record(secs(1), true) {
                Restart::After { delay, .. } => delay.as_secs(),
                Restart::Stop => panic!("crashed runs do not stop"),
            })
            .collect();
        assert_eq!(delays, [1, 2, 4, 8, 15, 15, 15, 15]);
    }

    #[test]
    fn a_healthy_run_forgives_everything_before_it() {
        let mut policy = RestartPolicy::default();
        for _ in 0..4 {
            policy.record(secs(1), true);
        }
        assert_eq!(policy.attempt(), 4);
        // Thirty seconds of service, then a crash: back to the beginning.
        match policy.record(HEALTHY_RUN, true) {
            Restart::After { delay, attempt, .. } => {
                assert_eq!(delay, BACKOFF_INITIAL);
                assert_eq!(attempt, 1);
            }
            Restart::Stop => panic!("crashed"),
        }
    }

    #[test]
    fn one_second_short_of_healthy_does_not_forgive() {
        let mut policy = RestartPolicy::default();
        policy.record(secs(1), true);
        match policy.record(HEALTHY_RUN - Duration::from_millis(1), true) {
            Restart::After { attempt, delay, .. } => {
                assert_eq!(attempt, 2);
                assert_eq!(delay, secs(2));
            }
            Restart::Stop => panic!("crashed"),
        }
    }

    #[test]
    fn the_first_failure_and_then_every_fifth_is_announced() {
        let mut policy = RestartPolicy::default();
        let announced: Vec<u32> = (1..=12)
            .filter_map(|_| match policy.record(secs(1), true) {
                Restart::After { attempt, announce: true, .. } => Some(attempt),
                _ => None,
            })
            .collect();
        // Enough to see a port that stays occupied, not enough to bury the
        // session under it.
        assert_eq!(announced, [1, 5, 10]);
    }

    #[test]
    fn a_healthy_run_makes_the_next_failure_worth_announcing_again() {
        let mut policy = RestartPolicy::default();
        for _ in 0..3 {
            policy.record(secs(1), true);
        }
        match policy.record(HEALTHY_RUN, true) {
            Restart::After { announce, .. } => assert!(announce, "attempt 1 again, so it is news"),
            Restart::Stop => panic!("crashed"),
        }
    }

    #[test]
    fn the_restart_line_is_reproduced_exactly() {
        assert_eq!(
            RestartPolicy::restart_line(Duration::from_millis(7_400), 3, secs(4)),
            "[TgRelay] Релей упал после 7с (попытка 3); перезапуск через 4с."
        );
    }

    #[test]
    fn the_uptime_in_the_line_rounds_the_way_python_formats_it() {
        // `:.0f` is round-half-to-even in both languages, and this line is a
        // literal search key.
        assert!(RestartPolicy::restart_line(Duration::from_millis(2_500), 1, secs(1)).contains("после 2с"));
        assert!(RestartPolicy::restart_line(Duration::from_millis(3_500), 1, secs(1)).contains("после 4с"));
    }
}
