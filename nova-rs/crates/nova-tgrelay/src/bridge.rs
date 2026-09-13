//! Pumping bytes between the client and the chosen egress — the policy half.
//!
//! Layer 4 of the port out of `tgrelay/transparent_relay.py::_bridge_streams`
//! (`:1338`). Everything here decides *whether* something should happen; the
//! socket work that carries it out lives in `nova-tgrelay-net`. The split is not
//! ceremony: both rules in this file were sources of real trouble in the Python
//! and neither could be asserted there without standing up an event loop and two
//! sockets.
//!
//! The two rules:
//!
//! - **The short leash.** WARP answers TCP and then never delivers a byte.
//!   Waiting out the default window on such an egress is what makes a cold start
//!   feel dead, so a route not yet proven for this DC is cut after ~1.5 s of
//!   silence. The cut is allowed *only* while nothing has come down — see
//!   [`FirstDownGuard`].
//! - **The traffic log.** It divides a byte delta by a period, and in the Python
//!   the period it slept for and the period it divided by could differ. See
//!   [`TrafficStats`].

use std::time::Duration;

/// Which end of the tunnel a chunk arrived from.
///
/// Named after the source, not the direction, because that is the only thing the
/// pump knows at the moment it counts: it has just read from one of two sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Read from the client on 1372. Counts as `up`.
    Client,
    /// Read from the egress. Counts as `down`.
    Upstream,
}

/// Bytes carried, in the relay's own vocabulary: `up` is client → egress,
/// `down` is egress → client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub up: u64,
    pub down: u64,
}

impl Counters {
    pub fn record(&mut self, side: Side, bytes: usize) {
        let n = bytes as u64;
        match side {
            Side::Client => self.up = self.up.saturating_add(n),
            Side::Upstream => self.down = self.down.saturating_add(n),
        }
    }
}

/// Why the tunnel ended.
///
/// The Python collapses all five into "the first of the two pipes finished" and
/// then suppresses whatever exception it carried, so the caller cannot tell an
/// orderly close from a reset. Keeping them apart costs nothing and is the
/// difference between a log line worth reading and one that is not.
///
/// Blame is by *socket*, not by direction, and that distinction is load-bearing:
/// each direction reads one socket and writes the other, so "the upstream→client
/// pump died" says nothing about which end broke. The egress's answer failing to
/// reach a client that reset is [`Self::ClientError`], and a test pins it —
/// naming it after the pump instead is how a working route ends up blamed in a
/// log for a client's disconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeEnd {
    /// The client sent FIN. There is no half-open mode: the first EOF in either
    /// direction ends the tunnel, exactly as `asyncio.wait(FIRST_COMPLETED)`
    /// plus the sibling's cancellation does in the Python.
    ClientEof,
    /// The egress sent FIN.
    UpstreamEof,
    /// The short leash fired: the window passed with nothing coming down.
    FirstDownTimeout,
    /// The client's socket failed — reading from it, or forwarding the egress's
    /// answer into it.
    ClientError,
    /// The egress's socket failed — reading from it, or forwarding the client's
    /// bytes into it.
    UpstreamError,
}

/// What a tunnel did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeOutcome {
    pub up: u64,
    pub down: u64,
    pub duration: Duration,
    pub end: BridgeEnd,
}

impl BridgeOutcome {
    /// The relay logs and records milliseconds, so the truncation happens in one
    /// place instead of at every call site.
    pub fn duration_ms(&self) -> u64 {
        self.duration.as_millis() as u64
    }
}

/// The verdict on a tunnel that has not yet been answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstDown {
    /// No leash was asked for; the tunnel is never cut on this account.
    Disabled,
    /// The window has not passed and nothing has come down yet.
    Waiting,
    /// Bytes came down. The leash is spent and must never be consulted again —
    /// a tunnel that has answered may then idle for as long as it likes (I9).
    Satisfied,
    /// The window passed with nothing down. Cut it.
    Expired,
}

/// The short leash on an egress that has not proven itself for this DC.
///
/// The rule that matters is the recheck: the Python arms a timeout on an
/// `asyncio.Event`, and even when that timeout fires it still refuses to cut
/// unless `counters["down"] <= 0`. Both halves are needed — the event can be set
/// in the same tick the timeout expires — so the decision is a *pure function of
/// the byte count*, and the window alone can never justify a cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstDownGuard {
    window: Option<Duration>,
}

impl FirstDownGuard {
    /// No leash: the tunnel is judged only by its ends.
    pub const fn disabled() -> Self {
        Self { window: None }
    }

    /// A zero window disables the leash rather than cutting instantly — the
    /// Python call site passes `0.0` to mean "not applicable", and reading it as
    /// "cut immediately" would kill every proven route.
    pub fn new(window: Duration) -> Self {
        if window.is_zero() {
            Self::disabled()
        } else {
            Self { window: Some(window) }
        }
    }

    /// The call site computes the window as a float (`1.15`, `1.5`, `0.0`).
    /// Anything that is not a positive finite number is "not applicable".
    pub fn from_secs_f64(window: f64) -> Self {
        if window.is_finite() && window > 0.0 {
            Self::new(Duration::from_secs_f64(window))
        } else {
            Self::disabled()
        }
    }

    /// When the driver should wake up, or `None` if it should not arm a timer.
    pub fn window(&self) -> Option<Duration> {
        self.window
    }

    pub fn verdict(&self, elapsed: Duration, down: u64) -> FirstDown {
        let Some(window) = self.window else { return FirstDown::Disabled };
        if down > 0 {
            FirstDown::Satisfied
        } else if elapsed >= window {
            FirstDown::Expired
        } else {
            FirstDown::Waiting
        }
    }
}

/// The periodic `traffic …` line, and the decision not to emit it.
///
/// **Deviation from the Python, deliberate.** `_traffic_stats_loop` sleeps
/// `max(2.0, interval)` and then divides the byte delta by the *raw* `interval`,
/// so any interval below 2 s reports a rate inflated by exactly the ratio
/// between the two. No caller passes one today (the only value in the tree is
/// the 8 s default), which is why it never showed up as a wrong number in a log.
/// Here the floor is applied once, in the constructor, and the stored value is
/// both what the driver sleeps for and what the rate divides by, so the two
/// cannot drift apart again.
///
/// The divisor stays the *interval* rather than the time since the last emitted
/// line, and that is also deliberate. A window in which nothing moved emits
/// nothing and leaves the baseline where it was, so the next delta covers two
/// windows — but all of those bytes necessarily arrived inside the second one,
/// and dividing by one interval is the arithmetic that says so.
#[derive(Debug, Clone)]
pub struct TrafficStats {
    label: String,
    interval: Duration,
    last: Counters,
}

impl TrafficStats {
    /// What every call site in the Python uses.
    pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(8);
    /// `max(2.0, …)` in `_traffic_stats_loop`: a tunnel is never asked about
    /// more often than this.
    pub const MIN_INTERVAL: Duration = Duration::from_secs(2);

    /// `None` for an empty label — the Python's `if not label … return`, which is
    /// how the WSS pre-warm path keeps its tunnels out of the traffic log.
    pub fn new(label: impl Into<String>, interval: Duration) -> Option<Self> {
        let label = label.into();
        if label.is_empty() {
            return None;
        }
        Some(Self { label, interval: interval.max(Self::MIN_INTERVAL), last: Counters::default() })
    }

    pub fn with_default_interval(label: impl Into<String>) -> Option<Self> {
        Self::new(label, Self::DEFAULT_INTERVAL)
    }

    /// How long the driver waits between [`Self::tick`] calls. Already floored.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// One period elapsed. Returns the line to log, or `None` when nothing moved.
    pub fn tick(&mut self, elapsed: Duration, now: Counters) -> Option<String> {
        let delta_up = now.up.saturating_sub(self.last.up);
        let delta_down = now.down.saturating_sub(self.last.down);
        if delta_up == 0 && delta_down == 0 {
            return None;
        }
        let per_second = self.interval.as_secs_f64();
        let rate_up = delta_up as f64 / per_second;
        let rate_down = delta_down as f64 / per_second;
        // `max(0.001, …)` in the Python. It only ever reaches a `{:.1}`, so it
        // changes no output; kept so the two read the same.
        let duration_s = elapsed.as_secs_f64().max(0.001);
        self.last = now;
        Some(format!(
            "[TgRelay] traffic {} duration_s={:.1} up={} down={} rate_up={:.0}B/s rate_down={:.0}B/s",
            self.label, duration_s, now.up, now.down, rate_up, rate_down
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: f64) -> Duration {
        Duration::from_secs_f64(n)
    }

    #[test]
    fn counters_are_named_after_the_direction_not_the_socket() {
        let mut c = Counters::default();
        c.record(Side::Client, 10);
        c.record(Side::Upstream, 3);
        c.record(Side::Client, 5);
        assert_eq!(c, Counters { up: 15, down: 3 });
    }

    #[test]
    fn a_zero_window_disables_the_leash_it_does_not_cut_instantly() {
        let guard = FirstDownGuard::from_secs_f64(0.0);
        assert_eq!(guard.window(), None);
        // The value the call site passes for a proven route. If this ever read
        // as "expired at once", every proven route would be cut on connect.
        assert_eq!(guard.verdict(secs(60.0), 0), FirstDown::Disabled);
    }

    #[test]
    fn a_negative_or_nonfinite_window_is_also_no_leash() {
        assert_eq!(FirstDownGuard::from_secs_f64(-1.0).window(), None);
        assert_eq!(FirstDownGuard::from_secs_f64(f64::NAN).window(), None);
        assert_eq!(FirstDownGuard::from_secs_f64(f64::INFINITY).window(), None);
    }

    #[test]
    fn the_call_sites_two_live_windows_survive_the_float() {
        assert_eq!(FirstDownGuard::from_secs_f64(1.15).window(), Some(secs(1.15)));
        assert_eq!(FirstDownGuard::from_secs_f64(1.5).window(), Some(secs(1.5)));
    }

    #[test]
    fn one_byte_down_spends_the_leash_even_past_the_window() {
        // The whole point of the recheck: the byte and the expiry can land in the
        // same tick, and the byte wins. An answered tunnel may then idle for
        // minutes, which is legitimate for Telegram (I9).
        let guard = FirstDownGuard::from_secs_f64(1.5);
        assert_eq!(guard.verdict(secs(9999.0), 1), FirstDown::Satisfied);
    }

    #[test]
    fn silence_through_the_window_expires_the_leash() {
        let guard = FirstDownGuard::from_secs_f64(1.5);
        assert_eq!(guard.verdict(secs(1.4), 0), FirstDown::Waiting);
        assert_eq!(guard.verdict(secs(1.5), 0), FirstDown::Expired);
        assert_eq!(guard.verdict(secs(1.6), 0), FirstDown::Expired);
    }

    #[test]
    fn upstream_bytes_alone_satisfy_it_client_bytes_do_not() {
        let guard = FirstDownGuard::from_secs_f64(1.5);
        // `up` is not a parameter at all — a client shouting into a dead egress
        // must not keep the tunnel alive. Encoded by giving `verdict` only the
        // down count.
        assert_eq!(guard.verdict(secs(2.0), 0), FirstDown::Expired);
    }

    #[test]
    fn an_empty_label_means_no_traffic_log() {
        assert!(TrafficStats::new("", TrafficStats::DEFAULT_INTERVAL).is_none());
        assert!(TrafficStats::with_default_interval("path=tcp-fallback").is_some());
    }

    #[test]
    fn a_window_with_no_movement_says_nothing() {
        let mut stats = TrafficStats::with_default_interval("l").unwrap();
        assert!(stats.tick(secs(8.0), Counters::default()).is_none());
        let moved = Counters { up: 1, down: 0 };
        assert!(stats.tick(secs(16.0), moved).is_some());
        assert!(stats.tick(secs(24.0), moved).is_none());
    }

    #[test]
    fn the_line_matches_the_python_format_byte_for_byte() {
        let mut stats = TrafficStats::with_default_interval(
            "path=tcp-fallback route=warp-socks target=149.154.167.51:443 media=False",
        )
        .unwrap();
        let line = stats.tick(secs(8.04), Counters { up: 800, down: 16_000 }).unwrap();
        assert_eq!(
            line,
            "[TgRelay] traffic path=tcp-fallback route=warp-socks target=149.154.167.51:443 media=False \
             duration_s=8.0 up=800 down=16000 rate_up=100B/s rate_down=2000B/s"
        );
    }

    #[test]
    fn the_rate_divides_by_the_interval_that_was_actually_slept() {
        // The Python divides by the raw interval while sleeping the floored one,
        // so this same input reports 4x on that side. 400 B over the 2 s it
        // really waited is 200 B/s, not 800.
        let mut stats = TrafficStats::new("l", secs(0.5)).unwrap();
        assert_eq!(stats.interval(), TrafficStats::MIN_INTERVAL);
        let line = stats.tick(secs(2.0), Counters { up: 400, down: 0 }).unwrap();
        assert!(line.contains("rate_up=200B/s"), "{line}");
    }

    #[test]
    fn a_silent_window_does_not_deflate_the_next_rate() {
        let mut stats = TrafficStats::with_default_interval("l").unwrap();
        assert!(stats.tick(secs(8.0), Counters::default()).is_none());
        // 8000 bytes, all of which arrived in the second window because the first
        // one reported none. 1000 B/s, not 500.
        let line = stats.tick(secs(16.0), Counters { up: 0, down: 8_000 }).unwrap();
        assert!(line.contains("rate_down=1000B/s"), "{line}");
    }

    #[test]
    fn the_totals_in_the_line_are_absolute_and_the_rates_are_deltas() {
        let mut stats = TrafficStats::with_default_interval("l").unwrap();
        stats.tick(secs(8.0), Counters { up: 80, down: 80 }).unwrap();
        let line = stats.tick(secs(16.0), Counters { up: 160, down: 240 }).unwrap();
        assert!(line.contains("up=160 down=240"), "{line}");
        assert!(line.contains("rate_up=10B/s rate_down=20B/s"), "{line}");
    }

    #[test]
    fn duration_ms_truncates_like_the_python_int_cast() {
        let outcome =
            BridgeOutcome { up: 0, down: 0, duration: Duration::from_micros(1_999), end: BridgeEnd::ClientEof };
        assert_eq!(outcome.duration_ms(), 1);
    }
}
