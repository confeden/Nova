//! Layer 11: the accept loop, and bringing the relay back after a crash.
//!
//! The I/O half of `_thread_main` (`:1993`), `_run_once` (`:2025`) and
//! `serve_until_stopped` (`:1570`). The schedule lives in
//! `nova_tgrelay::supervisor`; this runs it.
//!
//! **The shutdown order is the load-bearing part, and the Python learned it the
//! hard way.** `serve_forever()` answers cancellation with its own `close()` and
//! `wait_closed()`, and since CPython 3.12.1 `wait_closed()` waits for every
//! client transport to detach. Telegram holds its sockets for hours. So
//! "cancel the task and await it" *before* the clients are released is a wait as
//! long as the session: `stop()` times out on its join, nulls the server under a
//! coroutine that is still running, and the coroutine then dies on `None.close()`
//! and arrives at the supervisor as a startup error. An outer `wait_for` does not
//! save it — the cancellation is eaten by a `suppress` inside (G24).
//!
//! The rule that came out of that reproduction: **stop accepting first, then
//! release the clients, and only then wait for anything.** Here that is dropping
//! the listener and then `JoinSet::shutdown()`, which aborts before it awaits.
//! Waiting on live tunnels is never correct — they outlive the session by design.
//!
//! **Two workarounds the port deletes.** The Python sleeps its backoff in 0.25 s
//! slices so `stop()` stays responsive, because `time.sleep` cannot be
//! interrupted; here the delay and the shutdown signal are selected on together.
//! And the whole `InvalidStateError` resume machinery (`_LOOP_RESUME_LIMIT`,
//! `kb/open-issues.md#o2`) has nothing to attach to: it was a mitigation for one
//! asyncio event loop's `IocpProactor`, and there is no such loop here.

use nova_tgrelay::supervisor::{Restart, RestartPolicy};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration, Instant};

/// How a single life of the relay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// It was asked to stop, and did.
    Stopped,
    /// It fell over. The supervisor decides whether to bring it back.
    Crashed,
}

/// A run of the accept loop.
#[derive(Debug)]
pub enum ServeOutcome {
    /// The shutdown signal arrived.
    Stopped { accepted: u64 },
    /// Accepting failed too many times in a row to be a passing condition.
    Failed { accepted: u64, last: io::Error },
}

impl ServeOutcome {
    pub fn as_run_outcome(&self) -> RunOutcome {
        match self {
            Self::Stopped { .. } => RunOutcome::Stopped,
            Self::Failed { .. } => RunOutcome::Crashed,
        }
    }

    pub fn accepted(&self) -> u64 {
        match self {
            Self::Stopped { accepted } | Self::Failed { accepted, .. } => *accepted,
        }
    }
}

/// How many `accept()` failures in a row mean the listener is broken rather than
/// busy.
///
/// A transient one — the file-descriptor table full, a client that reset between
/// SYN and accept — must not end the relay, and must not be retried in a tight
/// loop either: that is how an accept loop turns one refused connection into a
/// pinned core.
pub const ACCEPT_FAILURES_BEFORE_GIVING_UP: u32 = 16;
/// The pause after a failed `accept()`.
pub const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(50);

/// Accept clients until told to stop, then let them go.
///
/// `handle` is spawned per connection. Its future is aborted at shutdown rather
/// than awaited — see the module note.
pub async fn serve<F, Fut>(listener: TcpListener, mut shutdown: watch::Receiver<bool>, handle: F) -> ServeOutcome
where
    F: Fn(TcpStream, SocketAddr) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut clients: JoinSet<()> = JoinSet::new();
    let mut accepted = 0u64;
    let mut consecutive_failures = 0u32;
    let mut last_error: Option<io::Error> = None;

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            result = listener.accept() => match result {
                Ok((stream, peer)) => {
                    consecutive_failures = 0;
                    accepted += 1;
                    clients.spawn(handle(stream, peer));
                }
                Err(e) => {
                    consecutive_failures += 1;
                    last_error = Some(e);
                    if consecutive_failures >= ACCEPT_FAILURES_BEFORE_GIVING_UP {
                        break;
                    }
                    sleep(ACCEPT_RETRY_PAUSE).await;
                }
            },
            // Reap finished tunnels so a long-lived listener does not accumulate
            // one `JoinHandle` per connection it has ever served.
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
        }
    }

    // Stop accepting *first*. Anything that arrives after this is refused by the
    // kernel, which is the honest answer once the relay is going away.
    drop(listener);
    // Then release the clients: abort, then await. Awaiting them first would be
    // a wait as long as the session.
    clients.shutdown().await;

    match (consecutive_failures >= ACCEPT_FAILURES_BEFORE_GIVING_UP, last_error) {
        (true, Some(last)) => ServeOutcome::Failed { accepted, last },
        _ => ServeOutcome::Stopped { accepted },
    }
}

/// Run the relay, and bring it back when it falls over.
///
/// Returns how many lives it ran. `run` is called afresh for each: the point of
/// the port is that a life owns nothing that survives it.
pub async fn supervise<F, Fut, L>(
    mut run: F,
    mut shutdown: watch::Receiver<bool>,
    mut policy: RestartPolicy,
    mut log: L,
) -> u32
where
    F: FnMut() -> Fut,
    Fut: Future<Output = RunOutcome>,
    L: FnMut(&str),
{
    let mut lives = 0u32;
    loop {
        if *shutdown.borrow() {
            return lives;
        }
        lives += 1;
        let started = Instant::now();
        let outcome = run().await;
        let uptime = started.elapsed();

        // Asked to stop while it was running: that is not a crash, and treating
        // it as one makes the supervisor fight the shutdown.
        if *shutdown.borrow() {
            return lives;
        }
        let Restart::After { delay, attempt, announce } = policy.record(uptime, outcome == RunOutcome::Crashed)
        else {
            return lives;
        };
        if announce {
            log(&RestartPolicy::restart_line(uptime, attempt, delay));
        }
        // The delay and the shutdown signal, waited on together. This is what
        // replaces the Python's 0.25 s slicing.
        tokio::select! {
            () = sleep(delay) => {}
            _ = shutdown.changed() => return lives,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;

    fn signal() -> (watch::Sender<bool>, watch::Receiver<bool>) {
        watch::channel(false)
    }

    #[tokio::test]
    async fn clients_are_accepted_until_the_signal_arrives() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (stop, rx) = signal();
        let seen = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&seen);

        let server = tokio::spawn(async move {
            serve(listener, rx, move |mut stream, _| {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.write_all(b"hi").await;
                }
            })
            .await
        });

        for _ in 0..3 {
            let _ = TcpStream::connect(addr).await.expect("connect");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.send(true).expect("signal");

        let outcome = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("the accept loop never returned")
            .expect("join");
        assert_eq!(outcome.accepted(), 3);
        assert_eq!(seen.load(Ordering::Relaxed), 3);
        assert_eq!(outcome.as_run_outcome(), RunOutcome::Stopped);
    }

    #[tokio::test]
    async fn a_tunnel_that_would_never_end_does_not_delay_the_shutdown() {
        // The exact failure the Python's ordering bug produced: Telegram holds
        // its sockets for hours, so waiting for a client to finish before
        // shutting down is a wait as long as the session. Judged by a timeout,
        // because the symptom is a hang and a hanging test reports nothing (G24).
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (stop, rx) = signal();

        let server = tokio::spawn(async move {
            serve(listener, rx, |_stream, _| async move {
                // Never returns, exactly like a live Telegram tunnel.
                std::future::pending::<()>().await;
            })
            .await
        });

        let _client = TcpStream::connect(addr).await.expect("connect");
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.send(true).expect("signal");

        let outcome = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("shutdown waited for a tunnel that never ends")
            .expect("join");
        assert_eq!(outcome.accepted(), 1);
    }

    #[tokio::test]
    async fn the_port_is_released_as_soon_as_the_relay_stops() {
        // Not cosmetic: the supervisor restarts on the same port, and a listener
        // still holding it turns one crash into a run of "address in use".
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (stop, rx) = signal();
        let server = tokio::spawn(async move { serve(listener, rx, |_, _| async {}).await });

        stop.send(true).expect("signal");
        tokio::time::timeout(Duration::from_secs(3), server).await.expect("join").expect("join");

        TcpListener::bind(addr).await.expect("the port is still held");
    }

    #[tokio::test(start_paused = true)]
    async fn a_crash_is_restarted_on_the_python_schedule() {
        let (_stop, rx) = signal();
        let lives = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&lives);
        let mut lines = Vec::new();

        let ran = supervise(
            move || {
                let counter = Arc::clone(&counter);
                async move {
                    if counter.fetch_add(1, Ordering::Relaxed) < 3 {
                        RunOutcome::Crashed
                    } else {
                        RunOutcome::Stopped
                    }
                }
            },
            rx,
            RestartPolicy::default(),
            |line| lines.push(line.to_string()),
        )
        .await;

        assert_eq!(ran, 4, "three crashes and then an ordered exit");
        assert_eq!(lines.len(), 1, "only the first failure is announced: {lines:?}");
        assert!(lines[0].contains("попытка 1"), "{lines:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_ordered_exit_is_not_restarted() {
        let (_stop, rx) = signal();
        let lives = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&lives);
        let ran = supervise(
            move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    RunOutcome::Stopped
                }
            },
            rx,
            RestartPolicy::default(),
            |_| {},
        )
        .await;
        assert_eq!(ran, 1);
        assert_eq!(lives.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn the_signal_cuts_the_backoff_short_instead_of_waiting_it_out() {
        // What the Python's 0.25 s slicing was for. Real time, not paused: the
        // assertion is that the wait ends early, and a paused clock would make
        // any wait end instantly and prove nothing.
        let (stop, rx) = signal();
        let started = Instant::now();
        let handle = tokio::spawn(async move {
            supervise(
                || async { RunOutcome::Crashed },
                rx,
                // Long enough that waiting it out would be unmistakable.
                RestartPolicy::new(Duration::from_secs(30), Duration::from_secs(30), Duration::from_secs(30)),
                |_| {},
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.send(true).expect("signal");

        let lives = tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .expect("the supervisor slept through the shutdown")
            .expect("join");
        assert_eq!(lives, 1);
        assert!(started.elapsed() < Duration::from_secs(5), "waited {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_crash_that_races_the_shutdown_is_not_restarted() {
        // A life can fall over and be told to stop in the same moment. Treating
        // that as a crash makes the supervisor fight the shutdown by bringing
        // back what was just asked to go away — which is what the Python's
        // `_stopping` check after `_run_once` exists to prevent.
        let (stop, rx) = signal();
        let lives = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&lives);
        let stop = Arc::new(stop);
        let signal_from_inside = Arc::clone(&stop);

        let mut lines = Vec::new();
        let ran = supervise(
            move || {
                let counter = Arc::clone(&counter);
                let stop = Arc::clone(&signal_from_inside);
                async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    stop.send(true).expect("signal");
                    RunOutcome::Crashed
                }
            },
            rx,
            RestartPolicy::default(),
            |line| lines.push(line.to_string()),
        )
        .await;
        assert_eq!(ran, 1, "the supervisor restarted a relay that had been told to stop");
        // The line matters as much as the restart. Without the check before the
        // policy is consulted, the relay still *says* it is coming back in one
        // second while going away for good — and the backoff still advances, so
        // the next real crash starts a step further along. A mutation removing
        // that check left the run count right and only this assertion failed.
        assert!(lines.is_empty(), "announced a restart it was never going to make: {lines:?}");
    }

    #[tokio::test]
    async fn a_relay_told_to_stop_before_it_starts_never_runs() {
        let (stop, rx) = signal();
        stop.send(true).expect("signal");
        let ran = supervise(|| async { panic!("must not run") }, rx, RestartPolicy::default(), |_| {}).await;
        assert_eq!(ran, 0);
    }
}
