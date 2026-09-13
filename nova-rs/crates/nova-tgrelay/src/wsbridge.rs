//! The WSS tunnel's two decisions: what may be replayed, and when to give up.
//!
//! Layer 7 of the port out of `tgrelay/transparent_relay.py::_bridge_ws`
//! (`:1404`). The byte pumping itself needs a WebSocket client and is a later
//! slice; everything here is the part that is pure judgement and was, in the
//! Python, four closures sharing five mutable locals.
//!
//! The WSS bridge differs from the TCP one ([`crate::bridge`]) in two ways that
//! matter, and both are here:
//!
//! - **It can put the upload back.** While nothing has come down, the client's
//!   bytes are kept so a dead route can be abandoned and the same request
//!   replayed on the next one. That is what makes cutting a silent WSS route
//!   cheap, and it is also what makes cutting one *unsafe* the moment the buffer
//!   overflows — see [`ReplayBuffer`].
//! - **Silence downstream is not evidence on its own.** Telegram says nothing
//!   while it is accepting an upload, so the watchdog watches the *upstream*
//!   counter and extends itself for as long as the client is still sending. See
//!   [`FirstDownWatchdog`].

use std::time::Duration;

/// `MEDIA_WSS_MIN_PROGRESS` — a media tunnel has to deliver this much before it
/// counts as working. A handshake-sized trickle proves reachability and nothing
/// else, and treating it as success is how a route that cannot actually carry a
/// photo keeps being re-picked.
pub const MEDIA_MIN_PROGRESS: u64 = 4096;

/// `FIRST_DOWN_UPLOAD_IDLE_GRACE` — how long a silent downstream is tolerated
/// while the upload is still moving.
pub const DEFAULT_UPLOAD_IDLE_GRACE: Duration = Duration::from_secs(6);

/// The cap that applies when more than one byte is required.
///
/// A media tunnel needs [`MEDIA_MIN_PROGRESS`] bytes before it counts, so each
/// round of patience is far more likely to be spent on a route that will never
/// deliver them. Six seconds per round would make a dead media route cost most
/// of a minute; two makes it cost a few.
pub const MEDIA_GRACE_CAP: Duration = Duration::from_secs(2);

/// How the client's bytes are cut up before they go on the wire.
///
/// The relay either forwards a read as one frame or, on an MTProto tunnel, cuts
/// it on message boundaries so each frame carries whole messages. Behind a trait
/// because the cutting needs a keystream and the bridge does not: the bridge can
/// then be tested with [`NoSplit`] and no crypto in the picture at all.
pub trait UpstreamSplitter {
    fn split(&mut self, chunk: &[u8]) -> Vec<Vec<u8>>;
    /// Whatever is left when the client closes. The Python sends this tail
    /// before returning, and losing it truncates the last message.
    fn flush(&mut self) -> Vec<Vec<u8>>;
}

/// `splitter=None`: one frame per read, bytes untouched.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSplit;

impl UpstreamSplitter for NoSplit {
    fn split(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        if chunk.is_empty() { Vec::new() } else { vec![chunk.to_vec()] }
    }

    fn flush(&mut self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

impl<K: crate::frame::KeyStream> UpstreamSplitter for crate::frame::MsgSplitter<K> {
    fn split(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        crate::frame::MsgSplitter::split(self, chunk)
    }

    fn flush(&mut self) -> Vec<Vec<u8>> {
        crate::frame::MsgSplitter::flush(self)
    }
}

/// What the driver tells the caller while a tunnel runs.
///
/// One trait rather than two closures because the second method has to fire at a
/// precise moment and that is easy to lose: the relay credits a route the instant
/// enough bytes come down, not when the tunnel ends, because a tunnel that lives
/// for ten minutes would otherwise leave its route unrecorded for ten minutes.
pub trait WsBridgeObserver {
    fn log(&mut self, _line: &str) {}
    fn first_down(&mut self, _down: u64) {}
}

/// For callers that want neither.
impl WsBridgeObserver for () {}

/// The upload, kept so a dead route can be abandoned without losing the request.
///
/// Two states have to be distinguished and the Python keeps them in two
/// variables that are easy to update out of step: *how much* has been buffered,
/// and whether the buffer is still a faithful copy of everything sent. Once the
/// upload outgrows the limit the copy is thrown away and `complete` goes false
/// **for the rest of the tunnel** — from then on the stream cannot be replayed
/// at all, and the watchdog is required to stop being willing to cut it.
#[derive(Debug, Clone)]
pub struct ReplayBuffer {
    limit: usize,
    buf: Vec<u8>,
    complete: bool,
}

impl ReplayBuffer {
    /// A zero limit disables replay entirely.
    pub fn new(limit: usize) -> Self {
        Self { limit, buf: Vec::new(), complete: true }
    }

    pub fn is_enabled(&self) -> bool {
        self.limit > 0
    }

    /// Still a faithful copy of everything the client has sent.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Client → Telegram bytes.
    ///
    /// Only kept while nothing has come back: after the first downstream byte
    /// the exchange is under way and replaying its start would duplicate it.
    pub fn record_upload(&mut self, data: &[u8], down_so_far: u64) {
        if !self.is_enabled() || down_so_far > 0 {
            return;
        }
        if self.buf.len() + data.len() <= self.limit {
            self.buf.extend_from_slice(data);
        } else {
            // Not "keep what fits": a truncated replay is worse than none, since
            // it would be resent as if it were the whole request.
            self.complete = false;
            self.buf.clear();
        }
    }

    /// Telegram → client bytes. The first of them voids the replay for good.
    pub fn note_download(&mut self, down_before: u64) {
        if down_before == 0 {
            self.buf.clear();
        }
    }

    /// What may be put back on the next route.
    ///
    /// Empty unless replay is enabled, the copy is faithful, and nothing was
    /// delivered downstream. The last condition is belt and braces —
    /// [`Self::note_download`] has already emptied the buffer by then — and is
    /// kept because it states the rule the other two only imply.
    pub fn take(&self, down: u64, first_down_timed_out: bool) -> &[u8] {
        if self.is_enabled() && self.complete && (down == 0 || first_down_timed_out) {
            &self.buf
        } else {
            &[]
        }
    }
}

/// Everything the watchdog is allowed to look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsProgress {
    /// Client → Telegram bytes so far.
    pub up: u64,
    /// Telegram → client bytes so far.
    pub down: u64,
    /// [`ReplayBuffer::is_complete`].
    pub replay_complete: bool,
}

/// What the driver should do now that its wait has expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogStep {
    /// Stop watching for the rest of the tunnel. Either it has answered, or it
    /// has become one that must not be cut.
    StandDown,
    /// Wait this long and ask again.
    Wait(Duration),
    /// Tear it down, and report `first_down_timed_out` so the caller can tell
    /// this apart from a peer that closed on its own.
    Cut,
}

/// Decides when a WSS tunnel that has not answered should be abandoned.
///
/// Exists only when there is a replay buffer *and* a timeout: the Python creates
/// the task under `if replay_enabled and first_down_timeout > 0`, and without a
/// replay there would be nothing to gain by cutting — the request would simply
/// be lost.
#[derive(Debug, Clone)]
pub struct FirstDownWatchdog {
    required: u64,
    initial: Duration,
    grace: Duration,
    /// The `up` counter as of the previous check. `None` before the first one,
    /// which is what makes "the upload has not moved" unanswerable — and
    /// therefore not actionable — on the very first look.
    last_up: Option<u64>,
}

impl FirstDownWatchdog {
    /// `None` when no watchdog should run at all.
    pub fn new(
        first_down_timeout: Duration,
        minimum_down_bytes: u64,
        replay_enabled: bool,
        upload_idle_grace: Duration,
    ) -> Option<Self> {
        if first_down_timeout.is_zero() || !replay_enabled {
            return None;
        }
        let required = minimum_down_bytes.max(1);
        let grace = if required > 1 { upload_idle_grace.min(MEDIA_GRACE_CAP) } else { upload_idle_grace };
        Some(Self { required, initial: first_down_timeout, grace, last_up: None })
    }

    /// How many downstream bytes count as an answer.
    pub fn required_down(&self) -> u64 {
        self.required
    }

    /// The first wait, before anything has been observed.
    pub fn initial_wait(&self) -> Duration {
        self.initial
    }

    /// Every wait after the first.
    pub fn grace(&self) -> Duration {
        self.grace
    }

    /// A wait expired. Here is where the tunnel stands.
    ///
    /// The four questions, in the order the Python asks them:
    ///
    /// 1. **Has it answered?** `down >= required` ends the watch for good. A
    ///    tunnel that has delivered may then idle as long as it likes (I9).
    /// 2. **Did the upload move since the last look?** If not, the silence is
    ///    not explained by an upload in flight and the route is cut. Skipped on
    ///    the first look, where there is nothing to compare against.
    /// 3. **Can this stream still be replayed?** Nothing delivered and an
    ///    overflowed buffer means cutting would lose the request outright, so
    ///    the watch is abandoned instead. This ranks *below* question 2 because
    ///    a stalled upload is a decision the Python reaches before re-testing
    ///    replayability, and swapping them changes which tunnels survive.
    /// 4. **Was anything ever uploaded?** A tunnel with nothing in either
    ///    direction has no upload to be waiting on, so there is nothing to
    ///    extend for.
    pub fn step(&mut self, progress: WsProgress) -> WatchdogStep {
        if progress.down >= self.required {
            return WatchdogStep::StandDown;
        }
        if let Some(previous) = self.last_up
            && progress.up <= previous
        {
            return WatchdogStep::Cut;
        }
        if progress.down == 0 && !progress.replay_complete {
            return WatchdogStep::StandDown;
        }
        if progress.up == 0 {
            return WatchdogStep::Cut;
        }
        self.last_up = Some(progress.up);
        WatchdogStep::Wait(self.grace)
    }
}

/// What a WSS tunnel did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsBridgeOutcome {
    pub up: u64,
    pub down: u64,
    pub duration: Duration,
    /// The upload to put back on the next route, or empty.
    pub replay: Vec<u8>,
    /// **Reported outward on purpose.** The caller uses it to tell "we waited
    /// for the first byte and never got one" from "the peer closed at once
    /// having sent nothing". Those are opposite diagnoses — a slow or
    /// blackholed route against an outright refusal — and without the flag both
    /// came out as the same timeout line.
    pub first_down_timed_out: bool,
}

impl WsBridgeOutcome {
    pub fn duration_ms(&self) -> u64 {
        self.duration.as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(up: u64, down: u64, replay_complete: bool) -> WsProgress {
        WsProgress { up, down, replay_complete }
    }

    #[test]
    fn a_zero_limit_means_no_replay_at_all() {
        let mut replay = ReplayBuffer::new(0);
        assert!(!replay.is_enabled());
        replay.record_upload(b"request", 0);
        assert!(replay.is_empty());
        assert_eq!(replay.take(0, false), b"");
    }

    #[test]
    fn the_upload_is_kept_only_while_nothing_has_come_back() {
        let mut replay = ReplayBuffer::new(1024);
        replay.record_upload(b"first", 0);
        replay.record_upload(b"second", 0);
        assert_eq!(replay.take(0, false), b"firstsecond");
        // One byte down and the exchange is under way.
        replay.record_upload(b"third", 1);
        assert_eq!(replay.len(), 11);
    }

    #[test]
    fn an_overflow_throws_the_copy_away_rather_than_truncating_it() {
        let mut replay = ReplayBuffer::new(8);
        replay.record_upload(b"12345678", 0);
        assert!(replay.is_complete());
        assert_eq!(replay.take(0, false), b"12345678");
        replay.record_upload(b"9", 0);
        assert!(!replay.is_complete(), "the copy is no longer faithful");
        assert_eq!(replay.take(0, false), b"", "a truncated replay would be resent as the whole request");
    }

    #[test]
    fn an_overflowed_buffer_releases_the_bytes_it_can_never_replay() {
        // This is not observable through `take` — that already gates on
        // `complete` — so it needs asserting on its own, and a mutation dropping
        // the `clear()` went unnoticed until it did. The reason it matters is
        // memory, not behaviour: the busiest call site allows 1 MiB per WSS
        // tunnel, and a relay holds many at once.
        let mut replay = ReplayBuffer::new(8);
        replay.record_upload(b"12345678", 0);
        assert_eq!(replay.len(), 8);
        replay.record_upload(b"9", 0);
        assert!(replay.is_empty(), "bytes that can never be replayed are still held");
    }

    #[test]
    fn incompleteness_is_permanent_for_the_rest_of_the_tunnel() {
        let mut replay = ReplayBuffer::new(4);
        replay.record_upload(b"toolong", 0);
        assert!(!replay.is_complete());
        // Small enough to fit now, but the stream as a whole no longer is.
        replay.record_upload(b"ab", 0);
        assert!(!replay.is_complete());
        assert_eq!(replay.take(0, false), b"");
    }

    #[test]
    fn the_first_downstream_byte_voids_the_replay() {
        let mut replay = ReplayBuffer::new(1024);
        replay.record_upload(b"request", 0);
        replay.note_download(0);
        assert!(replay.is_empty());
        // Even with the timed-out flag, there is nothing left to put back —
        // those bytes already reached the client.
        assert_eq!(replay.take(5, true), b"");
    }

    #[test]
    fn a_later_download_does_not_re_clear_anything() {
        let mut replay = ReplayBuffer::new(1024);
        replay.record_upload(b"request", 0);
        replay.note_download(7); // not the first
        assert_eq!(replay.take(0, false), b"request");
    }

    #[test]
    fn a_delivered_stream_is_never_replayed() {
        let mut replay = ReplayBuffer::new(1024);
        replay.record_upload(b"request", 0);
        assert_eq!(replay.take(1, false), b"", "something arrived; replaying would duplicate it");
        assert_eq!(replay.take(0, false), b"request");
    }

    #[test]
    fn no_watchdog_without_both_a_replay_and_a_timeout() {
        assert!(FirstDownWatchdog::new(Duration::ZERO, 1, true, DEFAULT_UPLOAD_IDLE_GRACE).is_none());
        assert!(
            FirstDownWatchdog::new(Duration::from_secs(1), 1, false, DEFAULT_UPLOAD_IDLE_GRACE).is_none(),
            "cutting without a replay would just lose the request"
        );
        assert!(FirstDownWatchdog::new(Duration::from_secs(1), 1, true, DEFAULT_UPLOAD_IDLE_GRACE).is_some());
    }

    #[test]
    fn media_gets_a_shorter_grace_than_a_plain_tunnel() {
        let plain = FirstDownWatchdog::new(Duration::from_secs(1), 1, true, DEFAULT_UPLOAD_IDLE_GRACE)
            .expect("watchdog");
        let media =
            FirstDownWatchdog::new(Duration::from_secs(2), MEDIA_MIN_PROGRESS, true, DEFAULT_UPLOAD_IDLE_GRACE)
                .expect("watchdog");
        assert_eq!(plain.grace(), DEFAULT_UPLOAD_IDLE_GRACE);
        assert_eq!(media.grace(), MEDIA_GRACE_CAP);
        assert_eq!(plain.required_down(), 1);
        assert_eq!(media.required_down(), MEDIA_MIN_PROGRESS);
    }

    #[test]
    fn a_grace_already_below_the_cap_is_not_raised_to_it() {
        let media =
            FirstDownWatchdog::new(Duration::from_secs(2), 4096, true, Duration::from_millis(500)).expect("w");
        assert_eq!(media.grace(), Duration::from_millis(500));
    }

    #[test]
    fn zero_minimum_bytes_still_means_one() {
        let w = FirstDownWatchdog::new(Duration::from_secs(1), 0, true, DEFAULT_UPLOAD_IDLE_GRACE).expect("w");
        assert_eq!(w.required_down(), 1);
        assert_eq!(w.grace(), DEFAULT_UPLOAD_IDLE_GRACE, "one byte required is not the media case");
    }

    #[test]
    fn enough_downstream_ends_the_watch_for_good() {
        let mut w = FirstDownWatchdog::new(Duration::from_secs(1), 1, true, DEFAULT_UPLOAD_IDLE_GRACE).unwrap();
        assert_eq!(w.step(progress(0, 1, true)), WatchdogStep::StandDown);
    }

    #[test]
    fn a_media_trickle_below_the_bar_does_not_count_as_an_answer() {
        let mut w =
            FirstDownWatchdog::new(Duration::from_secs(2), MEDIA_MIN_PROGRESS, true, DEFAULT_UPLOAD_IDLE_GRACE)
                .unwrap();
        // Reachability proven, a photo not.
        assert_eq!(w.step(progress(0, MEDIA_MIN_PROGRESS - 1, true)), WatchdogStep::Cut);
        let mut w =
            FirstDownWatchdog::new(Duration::from_secs(2), MEDIA_MIN_PROGRESS, true, DEFAULT_UPLOAD_IDLE_GRACE)
                .unwrap();
        assert_eq!(w.step(progress(0, MEDIA_MIN_PROGRESS, true)), WatchdogStep::StandDown);
    }

    #[test]
    fn nothing_in_either_direction_is_cut_at_once() {
        let mut w = FirstDownWatchdog::new(Duration::from_secs(1), 1, true, DEFAULT_UPLOAD_IDLE_GRACE).unwrap();
        assert_eq!(w.step(progress(0, 0, true)), WatchdogStep::Cut);
    }

    #[test]
    fn a_quiet_downstream_is_tolerated_while_the_upload_moves() {
        let mut w = FirstDownWatchdog::new(Duration::from_secs(1), 1, true, DEFAULT_UPLOAD_IDLE_GRACE).unwrap();
        // Telegram says nothing while it accepts an upload; the client sending
        // is the evidence that this is that and not a dead route.
        assert_eq!(w.step(progress(1_000, 0, true)), WatchdogStep::Wait(DEFAULT_UPLOAD_IDLE_GRACE));
        assert_eq!(w.step(progress(2_000, 0, true)), WatchdogStep::Wait(DEFAULT_UPLOAD_IDLE_GRACE));
        assert_eq!(w.step(progress(3_000, 0, true)), WatchdogStep::Wait(DEFAULT_UPLOAD_IDLE_GRACE));
        // …and the moment it stops moving, the excuse is gone.
        assert_eq!(w.step(progress(3_000, 0, true)), WatchdogStep::Cut);
    }

    #[test]
    fn an_unreplayable_stream_is_abandoned_rather_than_cut() {
        // The upload outgrew the buffer, so there is nothing to put back on
        // another route. Cutting would lose the request outright; the watchdog
        // stands down instead and lets the tunnel live or die on its own.
        let mut w = FirstDownWatchdog::new(Duration::from_secs(1), 1, true, DEFAULT_UPLOAD_IDLE_GRACE).unwrap();
        assert_eq!(w.step(progress(9_999, 0, false)), WatchdogStep::StandDown);
    }

    #[test]
    fn a_stalled_upload_is_cut_even_when_the_replay_is_gone() {
        // Order matters: "the upload stopped moving" is asked before "can this
        // still be replayed", so a stream that stalls after overflowing is cut
        // rather than abandoned. Swapping the two changes which tunnels survive.
        let mut w = FirstDownWatchdog::new(Duration::from_secs(1), 1, true, DEFAULT_UPLOAD_IDLE_GRACE).unwrap();
        assert_eq!(w.step(progress(500, 0, true)), WatchdogStep::Wait(DEFAULT_UPLOAD_IDLE_GRACE));
        assert_eq!(w.step(progress(500, 0, false)), WatchdogStep::Cut);
    }

    #[test]
    fn an_answer_outranks_everything_else() {
        let mut w = FirstDownWatchdog::new(Duration::from_secs(1), 1, true, DEFAULT_UPLOAD_IDLE_GRACE).unwrap();
        w.step(progress(500, 0, true));
        // Stalled upload and a void replay, but bytes came down: stand down.
        assert_eq!(w.step(progress(500, 4, false)), WatchdogStep::StandDown);
    }

    #[test]
    fn the_outcome_keeps_the_two_silences_apart() {
        let waited = WsBridgeOutcome {
            up: 120,
            down: 0,
            duration: Duration::from_millis(1_500),
            replay: b"request".to_vec(),
            first_down_timed_out: true,
        };
        let refused = WsBridgeOutcome { first_down_timed_out: false, ..waited.clone() };
        assert_ne!(waited, refused);
        assert_eq!(waited.duration_ms(), 1_500);
    }
}
