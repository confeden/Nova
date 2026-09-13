//! Layer 10: the WSS tunnel over real streams.
//!
//! The I/O half of `tgrelay/transparent_relay.py::_bridge_ws` (`:1404`). The
//! judgement — what may be replayed, when to give up — is
//! `nova_tgrelay::wsbridge`, tested against the original over ten scripted
//! timelines. This drives it.
//!
//! **One thing the Python gets free from asyncio and this does not: frame
//! atomicity.** `StreamWriter.write()` appends the whole frame to a buffer
//! synchronously, so two tasks writing to one WebSocket cannot interleave, and
//! `_bridge_ws` relies on that without saying so — the upload pump and the pong
//! that answers a ping share `self.writer`. Tokio's `write_all` may yield in the
//! middle of a frame, and two of them on one stream would produce a spliced
//! header that the peer cannot parse and cannot report. The writer is therefore
//! behind a `tokio::sync::Mutex`, held for exactly one frame batch. That is a
//! correctness requirement, not tidiness.

use crate::wsconn::{WsError, WsEvent, WsReader, WsWriter};
use nova_tgrelay::wsbridge::{
    FirstDownWatchdog, ReplayBuffer, UpstreamSplitter, WatchdogStep, WsBridgeObserver, WsBridgeOutcome, WsProgress,
    DEFAULT_UPLOAD_IDLE_GRACE,
};
use nova_tgrelay::wsframe::MaskSource;
use nova_tgrelay::TrafficStats;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{interval_at, sleep_until, Duration, Instant};

/// What the tunnel is allowed to do.
pub struct WsBridgeOptions {
    /// `replay_limit`. Zero disables the replay and, with it, the watchdog.
    pub replay_limit: usize,
    /// `first_down_timeout`. Zero disables the watchdog.
    pub first_down_timeout: Duration,
    /// `minimum_down_bytes`. Media asks for [`nova_tgrelay::wsbridge::MEDIA_MIN_PROGRESS`].
    pub minimum_down_bytes: u64,
    pub upload_idle_grace: Duration,
    pub stats: Option<TrafficStats>,
    /// Read size on the client socket. The Python's `read(65536)`.
    pub buf_size: usize,
}

impl Default for WsBridgeOptions {
    fn default() -> Self {
        Self {
            replay_limit: 0,
            first_down_timeout: Duration::ZERO,
            minimum_down_bytes: 1,
            upload_idle_grace: DEFAULT_UPLOAD_IDLE_GRACE,
            stats: None,
            buf_size: 65536,
        }
    }
}

#[derive(Default)]
struct Counters {
    up: AtomicU64,
    down: AtomicU64,
}

impl Counters {
    fn up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }

    fn down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }

    fn snapshot(&self) -> nova_tgrelay::Counters {
        nova_tgrelay::Counters { up: self.up(), down: self.down() }
    }
}

/// Which direction stopped, and how.
///
/// Read and write are kept apart for the same reason as in the TCP bridge: a
/// pump spans both ends, so the failure belongs to whichever one the failing
/// call touched. "The upstream pump died" identifies nobody.
enum Stopped {
    /// The client closed, or the peer did.
    Eof,
    /// The end being read from failed.
    SourceFailed(WsError),
    /// The end being written to would not take the bytes.
    DestinationFailed(WsError),
}

/// Say out loud what ended a direction.
///
/// The Python suppresses these outright — `contextlib.suppress(…, Exception)`
/// over the finished task — so a WSS tunnel killed by a reset and one closed
/// cleanly leave the same trace: a `down=0` line and nothing else. That is the
/// difference between "the route is blocked" and "the client went away", and
/// reading it wrong sends the next investigation to the wrong side.
fn note_failure<O: WsBridgeObserver>(stopped: &Stopped, reading: &str, other: &str, observer: &Mutex<&mut O>) {
    let (side, op, error) = match stopped {
        Stopped::Eof => return,
        Stopped::SourceFailed(e) => (reading, "read", e),
        Stopped::DestinationFailed(e) => (other, "write", e),
    };
    observer
        .lock()
        .expect("observer")
        .log(&format!("[TgRelay] wss tunnel {side} {op} error: {error}"));
}

/// Client → Telegram.
#[allow(clippy::too_many_arguments)]
async fn client_to_ws<C, W, M, P>(
    mut client: C,
    writer: &AsyncMutex<WsWriter<W, M>>,
    splitter: &Mutex<P>,
    counters: &Counters,
    replay: &Mutex<ReplayBuffer>,
    buf_size: usize,
) -> Stopped
where
    C: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    M: MaskSource,
    P: UpstreamSplitter,
{
    let mut buf = vec![0u8; buf_size.max(1)];
    loop {
        let read = match client.read(&mut buf).await {
            Ok(0) => {
                // The client is done. Whatever the splitter is still holding has
                // to go out: dropping it truncates the last message, and the
                // Python sends this tail for exactly that reason.
                let tail = splitter.lock().expect("splitter").flush();
                if !tail.is_empty() {
                    let refs: Vec<&[u8]> = tail.iter().map(Vec::as_slice).collect();
                    if let Err(e) = writer.lock().await.send_batch(&refs).await {
                        return Stopped::DestinationFailed(e);
                    }
                }
                return Stopped::Eof;
            }
            Ok(n) => n,
            Err(e) => return Stopped::SourceFailed(WsError::Io(e)),
        };
        let chunk = &buf[..read];
        // Counted and buffered before it goes out, for the same reason as the
        // TCP bridge: a byte that arrived counts even if forwarding it fails.
        replay.lock().expect("replay").record_upload(chunk, counters.down());
        counters.up.fetch_add(read as u64, Ordering::Relaxed);

        let parts = splitter.lock().expect("splitter").split(chunk);
        if parts.is_empty() {
            continue;
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        if let Err(e) = writer.lock().await.send_batch(&refs).await {
            return Stopped::DestinationFailed(e);
        }
    }
}

/// Telegram → client.
#[allow(clippy::too_many_arguments)]
async fn ws_to_client<C, R, W, M, O>(
    mut client: C,
    reader: &mut WsReader<R>,
    writer: &AsyncMutex<WsWriter<W, M>>,
    counters: &Counters,
    replay: &Mutex<ReplayBuffer>,
    observer: &Mutex<&mut O>,
    required_down: u64,
    notified: &AtomicBool,
) -> Stopped
where
    C: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    M: MaskSource,
    O: WsBridgeObserver,
{
    loop {
        let event = match reader.next_event().await {
            Ok(None) => return Stopped::Eof,
            Ok(Some(event)) => event,
            Err(e) => return Stopped::SourceFailed(e),
        };
        let payload = match event {
            WsEvent::Ping(body) => {
                if let Err(e) = writer.lock().await.pong(&body).await {
                    return Stopped::SourceFailed(e);
                }
                continue;
            }
            WsEvent::Closed(code) => {
                writer.lock().await.close_echo(code).await;
                return Stopped::Eof;
            }
            WsEvent::Message(payload) => payload,
        };
        // **G23.** An empty WebSocket frame is legal and means "keep waiting".
        // Counting it would satisfy the first-down watchdog with nothing, and a
        // test double that returned it for "closed" once drove the Python bridge
        // into an infinite loop — the code was right and the double was wrong.
        if payload.is_empty() {
            continue;
        }

        let before = counters.down();
        replay.lock().expect("replay").note_download(before);
        counters.down.fetch_add(payload.len() as u64, Ordering::Relaxed);
        let now_down = before + payload.len() as u64;

        // Announced the moment the bar is cleared, not when the tunnel ends: a
        // tunnel that lives ten minutes would otherwise leave its route
        // uncredited for ten minutes.
        if now_down >= required_down && !notified.swap(true, Ordering::Relaxed) {
            observer.lock().expect("observer").first_down(now_down);
        }

        if let Err(e) = client.write_all(&payload).await {
            return Stopped::DestinationFailed(WsError::Io(e));
        }
        if let Err(e) = client.flush().await {
            return Stopped::DestinationFailed(WsError::Io(e));
        }
    }
}

/// Carry an MTProto tunnel between the client and a WebSocket until one stops.
///
/// **The client is borrowed, not consumed, and that is the whole point.** The
/// TCP bridge takes its streams by value because a tunnel ending there ends the
/// exchange; here it does not. Every real call site passes `close_writer=False`
/// — all three of them, so the parameter's `True` default is never used — and
/// the reason is the replay buffer: when a WSS route closes without delivering,
/// the caller re-dials somewhere else and sends the same upload again, to *the
/// same client*. Closing the client here would leave nobody to replay to and
/// make the entire replay mechanism dead on arrival.
///
/// The WebSocket halves *are* consumed. A tunnel that ended is not reusable, and
/// the Python drops it the same way — `_abort_ws_transport` rather than a
/// polite close.
#[allow(clippy::too_many_arguments)]
pub async fn bridge_ws<C, R, W, M, P, O>(
    client: &mut C,
    mut ws_reader: WsReader<R>,
    ws_writer: WsWriter<W, M>,
    splitter: P,
    options: WsBridgeOptions,
    observer: &mut O,
) -> WsBridgeOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    M: MaskSource,
    P: UpstreamSplitter,
    O: WsBridgeObserver,
{
    let started = Instant::now();
    let counters = Counters::default();
    let replay = Mutex::new(ReplayBuffer::new(options.replay_limit));
    let splitter = Mutex::new(splitter);
    let writer = AsyncMutex::new(ws_writer);
    let observer = Mutex::new(observer);
    let notified = AtomicBool::new(false);

    let mut watchdog = FirstDownWatchdog::new(
        options.first_down_timeout,
        options.minimum_down_bytes,
        replay.lock().expect("replay").is_enabled(),
        options.upload_idle_grace,
    );
    let required_down =
        watchdog.as_ref().map_or(options.minimum_down_bytes.max(1), FirstDownWatchdog::required_down);

    // Split a borrow, so the caller keeps the socket for the next route.
    let (client_rx, client_tx) = tokio::io::split(client);
    let up = client_to_ws(client_rx, &writer, &splitter, &counters, &replay, options.buf_size);
    let down =
        ws_to_client(client_tx, &mut ws_reader, &writer, &counters, &replay, &observer, required_down, &notified);
    tokio::pin!(up, down);

    let mut next_check = watchdog.as_ref().map(|w| started + w.initial_wait());
    let check_sleep = sleep_until(next_check.unwrap_or(started));
    tokio::pin!(check_sleep);

    let mut stats = options.stats;
    let mut ticker = stats.as_ref().map(|s| interval_at(started + s.interval(), s.interval()));

    let mut first_down_timed_out = false;

    loop {
        tokio::select! {
            stopped = &mut up => { note_failure(&stopped, "client", "route", &observer); break }
            stopped = &mut down => { note_failure(&stopped, "route", "client", &observer); break }
            () = &mut check_sleep, if next_check.is_some() => {
                let progress = WsProgress {
                    up: counters.up(),
                    down: counters.down(),
                    replay_complete: replay.lock().expect("replay").is_complete(),
                };
                match watchdog.as_mut().expect("armed only with a watchdog").step(progress) {
                    WatchdogStep::StandDown => next_check = None,
                    WatchdogStep::Wait(d) => {
                        let at = Instant::now() + d;
                        next_check = Some(at);
                        check_sleep.as_mut().reset(at);
                    }
                    WatchdogStep::Cut => {
                        first_down_timed_out = true;
                        break;
                    }
                }
            },
            _ = async { ticker.as_mut().expect("armed only when Some").tick().await }, if ticker.is_some() => {
                let snapshot = counters.snapshot();
                if let Some(stats) = stats.as_mut()
                    && let Some(line) = stats.tick(started.elapsed(), snapshot)
                {
                    observer.lock().expect("observer").log(&line);
                }
            },
        }
    }

    let down_total = counters.down();
    let replay_bytes = replay.lock().expect("replay").take(down_total, first_down_timed_out).to_vec();
    WsBridgeOutcome {
        up: counters.up(),
        down: down_total,
        duration: started.elapsed(),
        replay: replay_bytes,
        first_down_timed_out,
    }
}
