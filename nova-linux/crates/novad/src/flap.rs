use nova_common::models::ServiceId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Penalty state for a flapping route or strategy.
#[derive(Debug, Clone)]
pub struct FlapState {
    pub last_switch: Instant,
    pub penalty_until: Option<Instant>,
    pub consecutive_failures: u32,
}

impl Default for FlapState {
    fn default() -> Self {
        Self {
            last_switch: Instant::now() - Duration::from_secs(3600),
            penalty_until: None,
            consecutive_failures: 0,
        }
    }
}

/// Flap controller preventing route oscillation (inspired by nova_route_flap.py).
pub struct FlapController {
    states: HashMap<ServiceId, FlapState>,
    min_cooldown: Duration,
    hold_duration: Duration,
}

impl FlapController {
    pub fn new(min_cooldown_secs: u64, hold_duration_secs: u64) -> Self {
        Self {
            states: HashMap::new(),
            min_cooldown: Duration::from_secs(min_cooldown_secs),
            hold_duration: Duration::from_secs(hold_duration_secs),
        }
    }

    /// Checks if a service is allowed to mutate its strategy/backend right now.
    pub fn can_switch(&self, service: ServiceId) -> bool {
        if let Some(state) = self.states.get(&service) {
            let now = Instant::now();
            if let Some(until) = state.penalty_until {
                if now < until {
                    return false; // Still under hold penalty
                }
            }
            now.duration_since(state.last_switch) >= self.min_cooldown
        } else {
            true
        }
    }

    /// Records that a switch has occurred, applying cooldown.
    pub fn record_switch(&mut self, service: ServiceId) {
        let entry = self.states.entry(service).or_default();
        entry.last_switch = Instant::now();
        entry.consecutive_failures = 0;
        entry.penalty_until = None;
    }

    /// Records a failed probe, calculating flap penalty if occurring too frequently.
    pub fn record_failure(&mut self, service: ServiceId) -> bool {
        let entry = self.states.entry(service).or_default();
        entry.consecutive_failures += 1;

        let now = Instant::now();
        if now.duration_since(entry.last_switch) < self.min_cooldown {
            // Failure happened shortly after last switch: activate flap hold!
            entry.penalty_until = Some(now + self.hold_duration);
            return false; // Suppress switch, hold current route
        }
        true // Allow mutation
    }

    pub fn record_success(&mut self, service: ServiceId) {
        if let Some(entry) = self.states.get_mut(&service) {
            entry.consecutive_failures = 0;
            entry.penalty_until = None;
        }
    }
}
