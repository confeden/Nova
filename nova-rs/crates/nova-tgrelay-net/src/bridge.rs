//! Layer 4: the tunnel itself — two directions of bytes over real sockets.
//!
//! Drives `nova_tgrelay::bridge`'s policy against the pair of streams layer 3
//! agreed on. The port of `tgrelay/transparent_relay.py::_bridge_streams`
//! (`:1338`); the WSS bridge (`_bridge_ws`, `:1404`) is a separate slice.
//!
//! Three things the Python does that are easy to lose in a rewrite, kept here on
//! purpose:
//!
//! 1. **The counter is bumped before the write, not after.** A byte that arrived
//!    counts even if forwarding it then fails — otherwise an egress that answers
//!    and immediately breaks the client socket looks, to the short leash and to
//!    the DC health record, exactly like an egress that never answered.
//! 2. **The first EOF ends both directions.** `asyncio.wait(FIRST_COMPLETED)`
//!    cancels the sibling pipe, and each pipe's `finally` closes the far writer,
//!    so both sockets are shut either way. Taking both streams by value here
//!    gives the same guarantee without asking the caller to remember it.
//! 3. **Cutting a tunnel is a close, not a reset.** `transport.abort()` drops
//!    asyncio's *userspace* write buffer and then closes; it does not send RST.
//!    Tokio has no such buffer — `write_all` hands bytes straight to the kernel —
//!    so dropping the stream is the faithful equivalent. Reaching for
//!    `set_linger(0)` here would be a behaviour change, and a harmful one: an RST
//!    discards whatever is already sitting in the peer's receive buffer, which is
//!    the exact trap layer 3's tests ran into.

use nova_tgrelay::bridge::{BridgeEnd, BridgeOutcome, Counters, FirstDown, FirstDownGuard, Side, TrafficStats};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{interval_at, sleep_until, Instant};

/// What the tunnel is allowed to do.
pub struct BridgeOptions {
    /// The short leash for an egress not yet proven for this DC.
    pub first_down: FirstDownGuard,
    /// The periodic `traffic …` line. `None` keeps the tunnel out of the log.
    pub stats: Option<TrafficStats>,
    /// Read size. The Python's `read(65536)`.
    pub buf_size: usize,
}

impl BridgeOptions {
    pub const DEFAULT_BUF_SIZE: usize = 65536;
}

impl Default for BridgeOptions {
    fn default() -> Self {
        Self { first_down: FirstDownGuard::disabled(), stats: None, buf_size: Self::DEFAULT_BUF_SIZE }
    }
}

/// The two counters, shared by the two pump futures and read by the leash and
/// the traffic log. Atomics rather than a `Cell` so the whole bridge future
/// stays `Send` and the caller can spawn one per connection.
#[derive(Default)]
struct SharedCounters {
    up: AtomicU64,
    down: AtomicU64,
}

impl SharedCounters {
    fn record(&self, side: Side, bytes: usize) {
        let cell = match side {
            Side::Client => &self.up,
            Side::Upstream => &self.down,
        };
        cell.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Counters {
        Counters { up: self.up.load(Ordering::Relaxed), down: self.down.load(Ordering::Relaxed) }
    }
}

/// How a direction stopped.
///
/// Read and write are kept apart because a pump spans both sockets: the failure
/// belongs to whichever end the failing call touched, not to the direction.
enum Stopped {
    /// The source sent FIN.
    Eof,
    /// The source could not be read.
    SourceFailed(io::Error),
    /// The destination would not take the bytes.
    DestinationFailed(io::Error),
}

/// One direction. Returns as soon as either socket stops cooperating; the caller
/// turns that into a verdict on a specific end.
async fn pump<R, W>(mut src: R, mut dst: W, side: Side, counters: &SharedCounters, buf_size: usize) -> Stopped
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buf_size];
    loop {
        let n = match src.read(&mut buf).await {
            Ok(0) => return Stopped::Eof,
            Ok(n) => n,
            Err(e) => return Stopped::SourceFailed(e),
        };
        counters.record(side, n);
        if let Err(e) = dst.write_all(&buf[..n]).await {
            return Stopped::DestinationFailed(e);
        }
        if let Err(e) = dst.flush().await {
            return Stopped::DestinationFailed(e);
        }
    }
}

/// Turn a stopped direction into a verdict on a specific socket, saying out loud
/// why when it was a failure.
///
/// The Python suppresses the exception (`contextlib.suppress(…, Exception)` over
/// the finished task), so a tunnel killed by a reset and one closed cleanly leave
/// the same trace — the `TCP fallback closed … down=0` line, and nothing else.
/// That is the difference between "the egress is blocked" and "the client went
/// away", and reading it wrong sends the next investigation to the wrong side.
fn verdict(stopped: Stopped, reading: Side, log: &mut dyn FnMut(&str)) -> BridgeEnd {
    let (blamed, op, error) = match stopped {
        Stopped::Eof => {
            return match reading {
                Side::Client => BridgeEnd::ClientEof,
                Side::Upstream => BridgeEnd::UpstreamEof,
            };
        }
        // The source is the socket being read, so a read failure is its own.
        Stopped::SourceFailed(e) => (reading, "read", e),
        // The destination is the *other* socket. This is the inversion the
        // `bytes_that_arrived_are_counted_even_when_forwarding_them_fails` test
        // pins: the upstream→client pump failing on its write is the client's
        // fault, not the egress's.
        Stopped::DestinationFailed(e) => (
            match reading {
                Side::Client => Side::Upstream,
                Side::Upstream => Side::Client,
            },
            "write",
            e,
        ),
    };
    let name = match blamed {
        Side::Client => "client",
        Side::Upstream => "egress",
    };
    log(&format!("[TgRelay] tunnel {name} {op} error: {error}"));
    match blamed {
        Side::Client => BridgeEnd::ClientError,
        Side::Upstream => BridgeEnd::UpstreamError,
    }
}

/// Carry bytes between the client and the egress until one of them stops.
///
/// Both streams are taken by value and dropped before this returns, so the
/// sockets are closed however the tunnel ended — see the module note.
///
/// Generic over the stream types rather than fixed to `TcpStream` so the same
/// code is exercised by `tokio::io::duplex` in a test and by a socket in
/// production; a bridge that is only ever tested through its own mock is not
/// tested.
pub async fn bridge_streams<C, U, F>(client: C, upstream: U, options: BridgeOptions, mut log: F) -> BridgeOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&str),
{
    let started = Instant::now();
    let counters = SharedCounters::default();
    // A zero-length buffer would make every read return `Ok(0)`, which reads as
    // EOF and would close the tunnel the moment it opened.
    let buf_size = options.buf_size.max(1);

    let (client_rx, client_tx) = tokio::io::split(client);
    let (upstream_rx, upstream_tx) = tokio::io::split(upstream);

    let up = pump(client_rx, upstream_tx, Side::Client, &counters, buf_size);
    let down = pump(upstream_rx, client_tx, Side::Upstream, &counters, buf_size);
    tokio::pin!(up, down);

    let leash = options.first_down;
    let mut leash_armed = leash.window().is_some();
    // Only ever polled while `leash_armed`, so the placeholder deadline of a
    // disabled leash is never waited on.
    let leash_deadline = started + leash.window().unwrap_or(Duration::ZERO);
    let leash_sleep = sleep_until(leash_deadline);
    tokio::pin!(leash_sleep);

    let mut stats = options.stats;
    let mut ticker = stats.as_ref().map(|s| interval_at(started + s.interval(), s.interval()));

    let end = loop {
        tokio::select! {
            stopped = &mut up => break verdict(stopped, Side::Client, &mut log),
            stopped = &mut down => break verdict(stopped, Side::Upstream, &mut log),
            () = &mut leash_sleep, if leash_armed => {
                match leash.verdict(started.elapsed(), counters.snapshot().down) {
                    FirstDown::Expired => break BridgeEnd::FirstDownTimeout,
                    // Answered in time, or never armed. Either way the leash is
                    // spent: an answered tunnel is allowed to idle (I9).
                    _ => leash_armed = false,
                }
            },
            _ = async { ticker.as_mut().expect("armed only when Some").tick().await }, if ticker.is_some() => {
                let snapshot = counters.snapshot();
                if let Some(stats) = stats.as_mut()
                    && let Some(line) = stats.tick(started.elapsed(), snapshot)
                {
                    log(&line);
                }
            },
        }
    };

    let totals = counters.snapshot();
    BridgeOutcome { up: totals.up, down: totals.down, duration: started.elapsed(), end }
}
