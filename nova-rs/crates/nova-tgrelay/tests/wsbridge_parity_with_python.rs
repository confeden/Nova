//! Differential parity for the WSS bridge's watchdog and replay buffer.
//!
//! The expectations are not hand-written. `temp/wsbridge_oracle.py` drives the
//! real `_bridge_ws` out of `tgrelay/transparent_relay.py` over these exact
//! timelines, with fake sockets and a fake WebSocket, and prints what it
//! returned; the `EXPECTED` column below is that output pasted in.
//!
//! A table would not have been enough here. The watchdog is a state machine
//! whose answer depends on the *order* in which waits and byte arrivals
//! interleave, so the test carries a small driver that replays a timeline
//! through the policy types. That driver is also the specification for the
//! tokio one that will eventually run this in production: if writing it here was
//! awkward, the real one would be wrong.

use nova_tgrelay::wsbridge::{
    FirstDownWatchdog, ReplayBuffer, WatchdogStep, WsProgress, DEFAULT_UPLOAD_IDLE_GRACE,
};
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
enum Event {
    /// Client → Telegram.
    Up(usize),
    /// Telegram → client.
    Down(usize),
    /// The peer closed. Ends the tunnel wherever it lands.
    WsClose,
}

struct Scenario {
    name: &'static str,
    replay_limit: usize,
    first_down_timeout: Duration,
    minimum_down_bytes: u64,
    /// `(at_ms, event)`, in order.
    timeline: &'static [(u64, Event)],
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    up: u64,
    down: u64,
    timed_out: bool,
    replay: Vec<u8>,
}

/// Replay a timeline through the policy, the way the tokio driver will have to.
///
/// The only judgement in here is the interleaving rule: when an event and a
/// watchdog wait fall at the same instant the event is applied first, because
/// the pumps run as their own tasks and a timer that expires in the same tick
/// observes the counters after they moved. That is also what the Python does —
/// `asyncio.wait_for` on an `Event` returns as soon as the event is set.
fn simulate(scenario: &Scenario) -> Outcome {
    let mut replay = ReplayBuffer::new(scenario.replay_limit);
    let mut watchdog = FirstDownWatchdog::new(
        scenario.first_down_timeout,
        scenario.minimum_down_bytes,
        replay.is_enabled(),
        DEFAULT_UPLOAD_IDLE_GRACE,
    );
    let mut next_check = watchdog.as_ref().map(FirstDownWatchdog::initial_wait);

    let mut up: u64 = 0;
    let mut down: u64 = 0;
    let mut timed_out = false;
    let mut now = Duration::ZERO;
    let mut pending = scenario.timeline.iter().peekable();

    loop {
        let next_event = pending.peek().map(|(at, _)| Duration::from_millis(*at));
        let next_wake = match (next_event, next_check) {
            (None, None) => break, // nothing left to happen; the tunnel idles forever
            (Some(e), None) => e,
            (None, Some(c)) => c,
            (Some(e), Some(c)) => e.min(c),
        };
        now = next_wake;

        // Events first — see the note above.
        if next_event == Some(now) {
            let (_, event) = pending.next().expect("peeked");
            match event {
                Event::Up(n) => {
                    replay.record_upload(&vec![b'x'; *n], down);
                    up += *n as u64;
                }
                Event::Down(n) => {
                    replay.note_download(down);
                    down += *n as u64;
                }
                Event::WsClose => break,
            }
            continue;
        }

        let watchdog = watchdog.as_mut().expect("a check was scheduled");
        match watchdog.step(WsProgress { up, down, replay_complete: replay.is_complete() }) {
            WatchdogStep::StandDown => next_check = None,
            WatchdogStep::Wait(d) => next_check = Some(now + d),
            WatchdogStep::Cut => {
                timed_out = true;
                break;
            }
        }
    }
    let _ = now;

    Outcome { up, down, timed_out, replay: replay.take(down, timed_out).to_vec() }
}

/// Byte payloads are all `x` in the simulator; the oracle used distinguishable
/// letters, which does not matter to any rule under test — only the lengths do.
fn xs(n: usize) -> Vec<u8> {
    vec![b'x'; n]
}

fn scenarios() -> Vec<(Scenario, Outcome)> {
    vec![
        (
            Scenario {
                name: "silent route, nothing uploaded",
                replay_limit: 4096,
                first_down_timeout: Duration::from_millis(300),
                minimum_down_bytes: 1,
                timeline: &[],
            },
            Outcome { up: 0, down: 0, timed_out: true, replay: vec![] },
        ),
        (
            Scenario {
                name: "silent route, upload buffered and replayable",
                replay_limit: 4096,
                first_down_timeout: Duration::from_millis(300),
                minimum_down_bytes: 1,
                timeline: &[(50, Event::Up(7))],
            },
            Outcome { up: 7, down: 0, timed_out: true, replay: xs(7) },
        ),
        (
            Scenario {
                name: "silent route, upload overflowed the buffer",
                replay_limit: 4,
                first_down_timeout: Duration::from_millis(300),
                minimum_down_bytes: 1,
                timeline: &[(50, Event::Up(16)), (3000, Event::WsClose)],
            },
            // Not cut: with nothing to put back, cutting would lose the request.
            Outcome { up: 16, down: 0, timed_out: false, replay: vec![] },
        ),
        (
            Scenario {
                name: "upload keeps moving, then stops",
                replay_limit: 65536,
                first_down_timeout: Duration::from_millis(300),
                minimum_down_bytes: 1,
                timeline: &[(50, Event::Up(100)), (350, Event::Up(100)), (700, Event::Up(100))],
            },
            Outcome { up: 300, down: 0, timed_out: true, replay: xs(300) },
        ),
        (
            Scenario {
                name: "answered inside the window",
                replay_limit: 4096,
                first_down_timeout: Duration::from_millis(500),
                minimum_down_bytes: 1,
                timeline: &[(50, Event::Up(7)), (100, Event::Down(4)), (1000, Event::WsClose)],
            },
            Outcome { up: 7, down: 4, timed_out: false, replay: vec![] },
        ),
        (
            Scenario {
                name: "peer closes at once having sent nothing",
                replay_limit: 4096,
                first_down_timeout: Duration::from_secs(5),
                minimum_down_bytes: 1,
                timeline: &[(20, Event::Up(7)), (100, Event::WsClose)],
            },
            // The same silence as the first two scenarios and the opposite
            // diagnosis — a refusal, not a blackhole. This is the pair the
            // `first_down_timed_out` flag exists to keep apart.
            Outcome { up: 7, down: 0, timed_out: false, replay: xs(7) },
        ),
        (
            Scenario {
                name: "media: a trickle below the bar is not an answer",
                replay_limit: 65536,
                first_down_timeout: Duration::from_millis(300),
                minimum_down_bytes: 4096,
                timeline: &[(20, Event::Up(7)), (100, Event::Down(64))],
            },
            Outcome { up: 7, down: 64, timed_out: true, replay: vec![] },
        ),
        (
            Scenario {
                name: "media: enough bytes is an answer",
                replay_limit: 65536,
                first_down_timeout: Duration::from_millis(300),
                minimum_down_bytes: 4096,
                timeline: &[(20, Event::Up(7)), (100, Event::Down(4096)), (1000, Event::WsClose)],
            },
            Outcome { up: 7, down: 4096, timed_out: false, replay: vec![] },
        ),
        (
            Scenario {
                name: "no replay buffer: the watchdog never runs",
                replay_limit: 0,
                first_down_timeout: Duration::from_millis(300),
                minimum_down_bytes: 1,
                timeline: &[(20, Event::Up(7)), (2000, Event::WsClose)],
            },
            Outcome { up: 7, down: 0, timed_out: false, replay: vec![] },
        ),
        (
            Scenario {
                name: "no timeout: the watchdog never runs",
                replay_limit: 4096,
                first_down_timeout: Duration::ZERO,
                minimum_down_bytes: 1,
                timeline: &[(20, Event::Up(7)), (2000, Event::WsClose)],
            },
            Outcome { up: 7, down: 0, timed_out: false, replay: xs(7) },
        ),
    ]
}

#[test]
fn the_watchdog_and_replay_match_the_python_original() {
    for (scenario, expected) in scenarios() {
        let got = simulate(&scenario);
        assert_eq!(got, expected, "scenario {:?}", scenario.name);
    }
}

#[test]
fn the_corpus_separates_every_outcome_it_claims_to_test() {
    // A parity table where every row agrees proves nothing. These four pairs are
    // the distinctions the port exists to preserve.
    let all = scenarios();
    let by_name = |n: &str| -> Outcome {
        let (scenario, _) = all.iter().find(|(s, _)| s.name == n).expect("scenario");
        simulate(scenario)
    };

    // Cut versus abandoned, on identical silence.
    assert!(by_name("silent route, upload buffered and replayable").timed_out);
    assert!(!by_name("silent route, upload overflowed the buffer").timed_out);

    // Timed out versus refused, on identical silence.
    assert!(!by_name("peer closes at once having sent nothing").timed_out);

    // Replay present versus voided.
    assert!(!by_name("silent route, upload buffered and replayable").replay.is_empty());
    assert!(by_name("answered inside the window").replay.is_empty());

    // Below the media bar versus above it.
    assert!(by_name("media: a trickle below the bar is not an answer").timed_out);
    assert!(!by_name("media: enough bytes is an answer").timed_out);
}
