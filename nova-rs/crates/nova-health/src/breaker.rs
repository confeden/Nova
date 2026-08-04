//! Circuit breaker over one transport.
//!
//! The Python failover was a threshold on consecutive failures with an
//! immediate switch back on the first success. That shape flaps: a transport
//! that is degraded rather than dead alternates fail/succeed, and every
//! alternation costs a PAC rewrite and a visible stall in the browser. The
//! breaker below fixes that with three mechanisms — a quorum over several
//! canaries, an explicit half-open probing state, and an open-duration that
//! grows on repeated failure.

use nova_core::Seconds;

/// Breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Transport is trusted; traffic flows normally.
    Closed,
    /// Transport is considered down; traffic is diverted to the fallback.
    Open,
    /// Cooldown elapsed. A limited number of trial requests are allowed through
    /// to find out whether it recovered, without committing all traffic to a
    /// transport that may still be broken.
    HalfOpen,
}

/// Health tracker for a single transport.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Breaker {
    state: State,
    /// Consecutive quorum-level failures while closed.
    failures: u32,
    /// Consecutive successes while half-open.
    trial_successes: u32,
    /// Trials attempted in the current half-open window.
    trials: u32,
    /// Uptime tick at which the breaker last entered `Open`.
    opened_at: Seconds,
    /// How many times it has opened without a stable closed period in between.
    /// Drives the backoff.
    consecutive_opens: u32,
    /// Uptime tick of the last state change, for the UI.
    changed_at: Seconds,
}

impl Default for Breaker {
    fn default() -> Self {
        Self {
            state: State::Closed,
            failures: 0,
            trial_successes: 0,
            trials: 0,
            opened_at: 0,
            consecutive_opens: 0,
            changed_at: 0,
        }
    }
}

impl Breaker {
    /// Quorum failures required to open.
    ///
    /// Three rather than one, because a single canary failing is far more often
    /// that site's problem than the transport's.
    pub const FAILURES_TO_OPEN: u32 = 3;

    /// Successful trials required to close from half-open.
    ///
    /// Two, so a transport that answers one request and then dies again does
    /// not drag all traffic back onto itself.
    pub const SUCCESSES_TO_CLOSE: u32 = 2;

    /// Trials allowed per half-open window before giving up and re-opening.
    pub const MAX_TRIALS: u32 = 4;

    /// Base cooldown before the first recovery attempt.
    pub const BASE_COOLDOWN: Seconds = 30;

    /// Ceiling on the exponential cooldown. Five minutes: long enough to stop
    /// hammering a dead tunnel, short enough that a user who fixes their VPN
    /// does not sit staring at a fallback route.
    pub const MAX_COOLDOWN: Seconds = 300;

    pub fn state(&self) -> State {
        self.state
    }

    pub fn changed_at(&self) -> Seconds {
        self.changed_at
    }

    /// Whether traffic should currently use this transport.
    ///
    /// `HalfOpen` deliberately answers `true`: the trial traffic has to go
    /// somewhere, and sending it over the transport under test is the only way
    /// to learn anything about it.
    pub fn is_usable(&self) -> bool {
        matches!(self.state, State::Closed | State::HalfOpen)
    }

    /// Whether the fallback route should be in force.
    pub fn is_tripped(&self) -> bool {
        self.state == State::Open
    }

    fn cooldown(&self) -> Seconds {
        let shift = self.consecutive_opens.saturating_sub(1).min(4);
        Self::BASE_COOLDOWN.saturating_mul(1 << shift).min(Self::MAX_COOLDOWN)
    }

    /// Seconds until the breaker will next allow a trial, or `None` if it is
    /// not open.
    pub fn retry_in(&self, now: Seconds) -> Option<Seconds> {
        if self.state != State::Open {
            return None;
        }
        let ready_at = self.opened_at.saturating_add(self.cooldown());
        Some(ready_at.saturating_sub(now))
    }

    /// Advance time. Must be called before consulting the state so an expired
    /// cooldown can move `Open` to `HalfOpen`.
    pub fn tick(&mut self, now: Seconds) {
        if self.state == State::Open && now.saturating_sub(self.opened_at) >= self.cooldown() {
            self.state = State::HalfOpen;
            self.trial_successes = 0;
            self.trials = 0;
            self.changed_at = now;
            tracing::debug!("breaker half-open: attempting recovery");
        }
    }

    /// Record the result of a quorum evaluation over the transport's canaries.
    ///
    /// `healthy` must already be a quorum decision, not a single probe — see
    /// [`crate::quorum`].
    pub fn record(&mut self, healthy: bool, now: Seconds) {
        match self.state {
            State::Closed => {
                if healthy {
                    self.failures = 0;
                    // A sustained healthy stretch clears the backoff, so an
                    // outage this morning does not make this evening's blip
                    // wait five minutes.
                    if now.saturating_sub(self.changed_at) > Self::MAX_COOLDOWN {
                        self.consecutive_opens = 0;
                    }
                } else {
                    self.failures += 1;
                    if self.failures >= Self::FAILURES_TO_OPEN {
                        self.trip(now);
                    }
                }
            }
            State::HalfOpen => {
                self.trials += 1;
                if healthy {
                    self.trial_successes += 1;
                    if self.trial_successes >= Self::SUCCESSES_TO_CLOSE {
                        self.state = State::Closed;
                        self.failures = 0;
                        self.changed_at = now;
                        tracing::info!("breaker closed: transport recovered");
                    }
                } else {
                    self.trip(now);
                }
                if self.state == State::HalfOpen && self.trials >= Self::MAX_TRIALS {
                    // Inconclusive window: neither confidently up nor down.
                    // Re-open rather than leaving traffic on a coin flip.
                    self.trip(now);
                }
            }
            State::Open => {
                // Results while open come from trial traffic that raced the
                // state change. A success is not enough to close from Open;
                // recovery must go through HalfOpen so the cooldown is honoured.
                if !healthy {
                    self.opened_at = now;
                }
            }
        }
    }

    fn trip(&mut self, now: Seconds) {
        let was_open = self.state == State::Open;
        self.state = State::Open;
        self.opened_at = now;
        self.failures = 0;
        self.trial_successes = 0;
        self.trials = 0;
        if !was_open {
            self.consecutive_opens = self.consecutive_opens.saturating_add(1);
            self.changed_at = now;
            tracing::warn!(cooldown = self.cooldown(), "breaker open: diverting to fallback");
        }
    }

    /// Force the breaker closed, e.g. because the user reconnected the VPN by
    /// hand and expects it to be used immediately.
    pub fn reset(&mut self, now: Seconds) {
        *self = Self { changed_at: now, ..Self::default() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(b: &mut Breaker, healthy: bool, times: u32, now: &mut Seconds) {
        for _ in 0..times {
            *now += 10;
            b.tick(*now);
            b.record(healthy, *now);
        }
    }

    #[test]
    fn a_single_failure_does_not_trip_it() {
        let mut b = Breaker::default();
        let mut now = 0;
        feed(&mut b, false, 1, &mut now);
        assert_eq!(b.state(), State::Closed);
        assert!(b.is_usable());
    }

    #[test]
    fn sustained_failure_trips_it() {
        let mut b = Breaker::default();
        let mut now = 0;
        feed(&mut b, false, Breaker::FAILURES_TO_OPEN, &mut now);
        assert_eq!(b.state(), State::Open);
        assert!(b.is_tripped());
        assert!(!b.is_usable());
    }

    #[test]
    fn recovery_goes_through_half_open_and_needs_two_successes() {
        let mut b = Breaker::default();
        let mut now = 0;
        feed(&mut b, false, 3, &mut now);
        assert_eq!(b.state(), State::Open);

        now += Breaker::BASE_COOLDOWN + 1;
        b.tick(now);
        assert_eq!(b.state(), State::HalfOpen, "cooldown lapse must allow a trial");

        b.record(true, now);
        assert_eq!(b.state(), State::HalfOpen, "one success must not be enough");
        b.record(true, now);
        assert_eq!(b.state(), State::Closed);
    }

    #[test]
    fn a_flapping_transport_does_not_flap_the_route() {
        let mut b = Breaker::default();
        let mut now = 0;
        let mut transitions = 0;
        let mut last = b.state();
        // Alternating success/failure for an hour — the pathological input the
        // old threshold logic turned into a route change every few seconds.
        for i in 0..360 {
            now += 10;
            b.tick(now);
            b.record(i % 2 == 0, now);
            if b.state() != last {
                transitions += 1;
                last = b.state();
            }
        }
        assert!(transitions < 20, "flapped {transitions} times in an hour");
    }

    #[test]
    fn repeated_outages_back_off_exponentially() {
        let mut b = Breaker::default();
        let mut now = 0;
        feed(&mut b, false, 3, &mut now);
        let first = b.retry_in(now).unwrap();

        // Recover, then immediately fail again.
        now += first + 1;
        b.tick(now);
        b.record(true, now);
        b.record(true, now);
        assert_eq!(b.state(), State::Closed);
        feed(&mut b, false, 3, &mut now);
        let second = b.retry_in(now).unwrap();

        assert!(second > first, "second outage cooldown {second} did not exceed the first {first}");
        assert!(second <= Breaker::MAX_COOLDOWN);
    }

    #[test]
    fn backoff_is_forgiven_after_a_long_healthy_stretch() {
        let mut b = Breaker::default();
        let mut now = 0;
        feed(&mut b, false, 3, &mut now);
        now += Breaker::BASE_COOLDOWN + 1;
        b.tick(now);
        b.record(true, now);
        b.record(true, now);
        assert_eq!(b.state(), State::Closed);

        // Hours of health.
        feed(&mut b, true, 400, &mut now);
        feed(&mut b, false, 3, &mut now);
        assert_eq!(b.retry_in(now), Some(Breaker::BASE_COOLDOWN), "backoff should have been forgiven");
    }

    #[test]
    fn an_inconclusive_half_open_window_reopens() {
        let mut b = Breaker::default();
        let mut now = 0;
        feed(&mut b, false, 3, &mut now);
        now += Breaker::BASE_COOLDOWN + 1;
        b.tick(now);
        assert_eq!(b.state(), State::HalfOpen);
        // Alternate so neither threshold is met.
        for i in 0..Breaker::MAX_TRIALS {
            b.record(i % 2 == 0, now);
        }
        assert_eq!(b.state(), State::Open, "an ambiguous window must not leave traffic on the transport");
    }

    #[test]
    fn a_manual_reset_restores_trust_immediately() {
        let mut b = Breaker::default();
        let mut now = 0;
        feed(&mut b, false, 3, &mut now);
        assert!(b.is_tripped());
        b.reset(now);
        assert_eq!(b.state(), State::Closed);
        assert_eq!(b.retry_in(now), None);
    }

    #[test]
    fn a_healthy_transport_never_trips() {
        let mut b = Breaker::default();
        let mut now = 0;
        feed(&mut b, true, 1_000, &mut now);
        assert_eq!(b.state(), State::Closed);
    }
}
