//! The WSS tunnel driven over real streams.
//!
//! The judgement is tested against values in `nova_tgrelay::wsbridge` and
//! against the Python original in `wsbridge_parity_with_python.rs`. This file is
//! for what only a stream shows: a splitter tail that never left, a ping
//! answered from the wrong half, two writers spliced into one frame, an empty
//! frame counted as an answer.

use nova_tgrelay::wsbridge::{NoSplit, UpstreamSplitter, WsBridgeObserver, MEDIA_MIN_PROGRESS};
use nova_tgrelay::wsframe::{apply_mask, build_frame, parse_header, FixedMask, Opcode};
use nova_tgrelay::TrafficStats;
use nova_tgrelay_net::wsbridge::{bridge_ws, WsBridgeOptions};
use nova_tgrelay_net::wsconn::WsConnection;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

const KEY: [u8; 4] = [1, 2, 3, 4];

/// What a server puts on the wire: unmasked, FIN as asked.
fn server_frame(opcode: Opcode, payload: &[u8], fin: bool) -> Vec<u8> {
    let mut f = build_frame(opcode, payload, None);
    if !fin {
        f[0] &= 0x7F;
    }
    f
}

/// Records everything the bridge said, so a test can assert on it afterwards.
#[derive(Default)]
struct Recorder {
    lines: Vec<String>,
    first_down: Option<u64>,
}

impl WsBridgeObserver for Recorder {
    fn log(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }

    fn first_down(&mut self, down: u64) {
        assert!(self.first_down.is_none(), "first_down fired twice");
        self.first_down = Some(down);
    }
}

/// A splitter that cuts every read in half, so "the splitter was consulted" and
/// "its tail was flushed" are both observable without a keystream.
#[derive(Default)]
struct HalvingSplitter {
    tail: Vec<u8>,
}

impl UpstreamSplitter for HalvingSplitter {
    fn split(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        // Keep the last byte back, so there is always something to flush.
        let (head, tail) = chunk.split_at(chunk.len().saturating_sub(1));
        self.tail.extend_from_slice(tail);
        if head.is_empty() {
            Vec::new()
        } else {
            vec![head.to_vec()]
        }
    }

    fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.tail.is_empty() {
            Vec::new()
        } else {
            vec![std::mem::take(&mut self.tail)]
        }
    }
}

/// Read every frame sitting on `stream`, unmasking as needed.
async fn drain_frames(stream: &mut DuplexStream, expected: usize) -> Vec<(Opcode, Vec<u8>)> {
    let mut wire = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut out = Vec::new();
    while out.len() < expected {
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .expect("the frames never arrived")
            .expect("read");
        if n == 0 {
            break;
        }
        wire.extend_from_slice(&chunk[..n]);
        out.clear();
        let mut at = 0usize;
        while let Ok(Some(header)) = parse_header(&wire[at..]) {
            let end = at + header.frame_len() as usize;
            if end > wire.len() {
                break;
            }
            let mut body = wire[at + header.header_len..end].to_vec();
            if let Some(key) = header.mask {
                apply_mask(&mut body, key);
            }
            out.push((header.opcode, body));
            at = end;
        }
    }
    out
}

/// Read everything still on `stream`, parse it, and report how many bytes the
/// parser could not account for. A non-zero leftover is a spliced frame.
async fn parse_all(stream: &mut DuplexStream) -> (Vec<(Opcode, Vec<u8>)>, usize) {
    let mut wire = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => wire.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => break,
        }
    }
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < wire.len() {
        let Ok(Some(header)) = parse_header(&wire[at..]) else { break };
        let end = at + header.frame_len() as usize;
        if end > wire.len() {
            break;
        }
        let mut body = wire[at + header.header_len..end].to_vec();
        if let Some(key) = header.mask {
            apply_mask(&mut body, key);
        }
        out.push((header.opcode, body));
        at = end;
    }
    (out, wire.len() - at)
}

fn ws_pair() -> (WsConnection<DuplexStream, FixedMask>, DuplexStream) {
    let (mine, theirs) = duplex(64 * 1024);
    (WsConnection::with_mask_source(mine, FixedMask(KEY)), theirs)
}

#[tokio::test]
async fn bytes_flow_both_ways_and_are_counted() {
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, mut peer) = ws_pair();
    let (reader, writer) = ws.split();

    let mut recorder = Recorder::default();
    let bridge =
        async { bridge_ws(&mut client_near, reader, writer, NoSplit, WsBridgeOptions::default(), &mut recorder).await };

    let script = async {
        let mut client_far = client_far;
        client_far.write_all(b"request").await.expect("write");
        let frames = drain_frames(&mut peer, 1).await;
        assert_eq!(frames, vec![(Opcode::Binary, b"request".to_vec())]);

        peer.write_all(&server_frame(Opcode::Binary, b"answer", true)).await.expect("write");
        let mut back = [0u8; 6];
        client_far.read_exact(&mut back).await.expect("read");
        assert_eq!(&back, b"answer");
        drop(client_far);
    };

    let (outcome, ()) = tokio::join!(bridge, script);
    assert_eq!(outcome.up, 7);
    assert_eq!(outcome.down, 6);
    assert!(!outcome.first_down_timed_out);
}

#[tokio::test]
async fn the_splitters_tail_is_flushed_when_the_client_closes() {
    // Dropping it truncates the last message, and MTProto's own framing means
    // the client sees a desynchronised stream rather than an error.
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, mut peer) = ws_pair();
    let (reader, writer) = ws.split();

    let mut recorder = Recorder::default();
    let bridge = async {
        bridge_ws(
            &mut client_near,
            reader,
            writer,
            HalvingSplitter::default(),
            WsBridgeOptions::default(),
            &mut recorder,
        )
        .await
    };
    let script = async {
        let mut client_far = client_far;
        client_far.write_all(b"abcd").await.expect("write");
        client_far.shutdown().await.expect("shutdown");
        drop(client_far);
        drain_frames(&mut peer, 2).await
    };

    let (outcome, frames) = tokio::join!(bridge, script);
    assert_eq!(outcome.up, 4);
    assert_eq!(
        frames,
        vec![(Opcode::Binary, b"abc".to_vec()), (Opcode::Binary, b"d".to_vec())],
        "the byte the splitter held back must still leave"
    );
}

#[tokio::test]
async fn a_ping_is_answered_and_no_frame_is_spliced() {
    // The two directions share one WebSocket writer. In asyncio that is safe by
    // accident, because `StreamWriter.write` buffers a whole frame
    // synchronously; here it takes a lock. Without the lock a pong could land in
    // the middle of a data frame, and the assertion that catches it is not the
    // frame *count* — reads coalesce, so that varies — but that the wire parses
    // end to end with nothing left over.
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, mut peer) = ws_pair();
    let (reader, writer) = ws.split();

    let mut recorder = Recorder::default();
    let bridge =
        async { bridge_ws(&mut client_near, reader, writer, NoSplit, WsBridgeOptions::default(), &mut recorder).await };
    let script = async {
        let mut client_far = client_far;
        peer.write_all(&server_frame(Opcode::Ping, b"hi", true)).await.expect("write");
        for _ in 0..20 {
            client_far.write_all(&[b'x'; 1024]).await.expect("write");
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(client_far);
    };

    let (outcome, ()) = tokio::join!(bridge, script);
    assert_eq!(outcome.up, 20 * 1024);

    let (frames, leftover) = parse_all(&mut peer).await;
    assert_eq!(leftover, 0, "a spliced frame would leave bytes the parser cannot use");
    let pongs: Vec<_> = frames.iter().filter(|(op, _)| *op == Opcode::Pong).collect();
    assert_eq!(pongs.len(), 1, "exactly one pong");
    assert_eq!(pongs[0].1, b"hi");
    let carried: usize =
        frames.iter().filter(|(op, _)| *op == Opcode::Binary).map(|(_, body)| body.len()).sum();
    assert_eq!(carried, 20 * 1024, "every byte the client sent reached the wire exactly once");
}

#[tokio::test]
async fn an_empty_frame_is_not_an_answer() {
    // G23: an empty WebSocket frame is legal and means "keep waiting". Counting
    // it would satisfy the watchdog with nothing at all.
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, mut peer) = ws_pair();
    let (reader, writer) = ws.split();

    let options = WsBridgeOptions {
        replay_limit: 4096,
        first_down_timeout: Duration::from_millis(120),
        ..WsBridgeOptions::default()
    };
    let mut recorder = Recorder::default();
    let bridge = async { bridge_ws(&mut client_near, reader, writer, NoSplit, options, &mut recorder).await };
    let script = async {
        let mut client_far = client_far;
        client_far.write_all(b"request").await.expect("write");
        for _ in 0..4 {
            peer.write_all(&server_frame(Opcode::Binary, b"", true)).await.expect("write");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        // Hold the client open so only the watchdog can end this.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(client_far);
    };

    let outcome = tokio::select! {
        outcome = bridge => outcome,
        () = script => panic!("the watchdog never fired"),
    };
    assert_eq!(outcome.down, 0, "empty frames carry nothing");
    assert!(outcome.first_down_timed_out);
    assert_eq!(outcome.replay, b"request", "the upload can still be put back");
    assert_eq!(recorder.first_down, None);
}

#[tokio::test]
async fn the_route_is_credited_the_moment_it_answers_not_when_it_ends() {
    // A tunnel that lives for minutes would otherwise leave its route
    // uncredited for minutes.
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, mut peer) = ws_pair();
    let (reader, writer) = ws.split();

    let observed = Arc::new(Mutex::new(None));
    struct Watch(Arc<Mutex<Option<u64>>>);
    impl WsBridgeObserver for Watch {
        fn first_down(&mut self, down: u64) {
            *self.0.lock().expect("lock") = Some(down);
        }
    }
    let mut watch = Watch(Arc::clone(&observed));

    let options = WsBridgeOptions { minimum_down_bytes: MEDIA_MIN_PROGRESS, ..WsBridgeOptions::default() };
    let bridge = async { bridge_ws(&mut client_near, reader, writer, NoSplit, options, &mut watch).await };
    let script = async {
        let client_far = client_far;
        // Below the media bar: not an answer.
        peer.write_all(&server_frame(Opcode::Binary, &[b'x'; 64], true)).await.expect("write");
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(*observed.lock().expect("lock"), None, "a trickle is not an answer");
        // Over it.
        peer.write_all(&server_frame(Opcode::Binary, &vec![b'x'; MEDIA_MIN_PROGRESS as usize], true))
            .await
            .expect("write");
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(*observed.lock().expect("lock"), Some(64 + MEDIA_MIN_PROGRESS));
        drop(client_far);
    };

    let (outcome, ()) = tokio::join!(bridge, script);
    assert_eq!(outcome.down, 64 + MEDIA_MIN_PROGRESS);
}

#[tokio::test]
async fn a_delivered_tunnel_keeps_nothing_to_replay() {
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, mut peer) = ws_pair();
    let (reader, writer) = ws.split();

    let options = WsBridgeOptions { replay_limit: 4096, ..WsBridgeOptions::default() };
    let mut recorder = Recorder::default();
    let bridge = async { bridge_ws(&mut client_near, reader, writer, NoSplit, options, &mut recorder).await };
    let script = async {
        let mut client_far = client_far;
        client_far.write_all(b"request").await.expect("write");
        tokio::time::sleep(Duration::from_millis(30)).await;
        peer.write_all(&server_frame(Opcode::Binary, b"ok", true)).await.expect("write");
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(client_far);
    };

    let (outcome, ()) = tokio::join!(bridge, script);
    assert_eq!(outcome.down, 2);
    assert!(outcome.replay.is_empty(), "replaying would duplicate what already arrived");
}

#[tokio::test]
async fn a_peer_that_closes_at_once_is_not_a_timeout() {
    // The same silence as a blackholed route and the opposite diagnosis. The
    // replay survives either way, but `first_down_timed_out` is what tells the
    // caller which happened.
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, mut peer) = ws_pair();
    let (reader, writer) = ws.split();

    let options = WsBridgeOptions {
        replay_limit: 4096,
        first_down_timeout: Duration::from_secs(5),
        ..WsBridgeOptions::default()
    };
    let mut recorder = Recorder::default();
    let bridge = async { bridge_ws(&mut client_near, reader, writer, NoSplit, options, &mut recorder).await };
    let script = async {
        let client_far = client_far;
        peer.write_all(&server_frame(Opcode::Close, &1000u16.to_be_bytes(), true)).await.expect("write");
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(client_far);
    };

    let outcome = tokio::time::timeout(Duration::from_secs(3), async {
        let (outcome, ()) = tokio::join!(bridge, script);
        outcome
    })
    .await
    .expect("the bridge waited out the whole timeout on a peer that had already closed");

    assert!(!outcome.first_down_timed_out);
    assert_eq!(outcome.down, 0);
    assert_eq!(outcome.replay, b"");
}

#[tokio::test(start_paused = true)]
async fn the_traffic_line_is_logged_while_bytes_move() {
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, peer) = ws_pair();
    let (reader, writer) = ws.split();

    let options = WsBridgeOptions {
        stats: TrafficStats::new("path=wss route=kws2.nova-app.eu", Duration::from_secs(2)),
        ..WsBridgeOptions::default()
    };
    let mut recorder = Recorder::default();
    let bridge = async { bridge_ws(&mut client_near, reader, writer, NoSplit, options, &mut recorder).await };
    let script = async {
        let mut client_far = client_far;
        client_far.write_all(&[b'x'; 200]).await.expect("write");
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(client_far);
        drop(peer);
    };

    let (outcome, ()) = tokio::join!(bridge, script);
    assert_eq!(outcome.up, 200);
    assert_eq!(recorder.lines.len(), 1, "{:?}", recorder.lines);
    assert!(recorder.lines[0].starts_with("[TgRelay] traffic path=wss route=kws2.nova-app.eu "));
    assert!(recorder.lines[0].contains("up=200 down=0"), "{:?}", recorder.lines);
}

#[tokio::test]
async fn the_route_is_credited_once_however_many_messages_follow() {
    // The guard that makes this true is one `swap` on an atomic, and losing it
    // is invisible unless a second message arrives above the bar. Written after
    // a mutation that removed it passed every other test here.
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, mut peer) = ws_pair();
    let (reader, writer) = ws.split();

    // `Recorder::first_down` panics on a second call.
    let mut recorder = Recorder::default();
    let bridge =
        async { bridge_ws(&mut client_near, reader, writer, NoSplit, WsBridgeOptions::default(), &mut recorder).await };
    let script = async {
        let client_far = client_far;
        for body in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            peer.write_all(&server_frame(Opcode::Binary, body, true)).await.expect("write");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(client_far);
    };

    let (outcome, ()) = tokio::join!(bridge, script);
    assert_eq!(outcome.down, 11);
    assert_eq!(recorder.first_down, Some(3), "credited on the first message and only then");
}

#[tokio::test]
async fn a_trickle_that_gets_cut_is_never_replayed() {
    // The one case where voiding the replay is observable: bytes came down, so
    // the client has already been served part of the answer, *and* the watchdog
    // cut the tunnel because they were below the media bar. Replaying the upload
    // now would send the request a second time against a response already half
    // delivered.
    //
    // Written after a mutation that voided the replay one line too late passed
    // every other test — everywhere else `take` filters it out on `down == 0`
    // anyway, and only `first_down_timed_out` reopens that gate.
    let (client_far, mut client_near) = duplex(64 * 1024);
    let (ws, mut peer) = ws_pair();
    let (reader, writer) = ws.split();

    let options = WsBridgeOptions {
        replay_limit: 4096,
        first_down_timeout: Duration::from_millis(120),
        minimum_down_bytes: MEDIA_MIN_PROGRESS,
        upload_idle_grace: Duration::from_millis(120),
        ..WsBridgeOptions::default()
    };
    let mut recorder = Recorder::default();
    let bridge = async { bridge_ws(&mut client_near, reader, writer, NoSplit, options, &mut recorder).await };
    let script = async {
        let mut client_far = client_far;
        client_far.write_all(b"request").await.expect("write");
        tokio::time::sleep(Duration::from_millis(20)).await;
        peer.write_all(&server_frame(Opcode::Binary, &[b'x'; 64], true)).await.expect("write");
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(client_far);
    };

    let outcome = tokio::select! {
        outcome = bridge => outcome,
        () = script => panic!("the watchdog never fired"),
    };
    assert!(outcome.first_down_timed_out);
    assert_eq!(outcome.down, 64, "below the media bar, so not an answer");
    assert!(outcome.replay.is_empty(), "part of the answer already reached the client");
}

#[tokio::test]
async fn the_client_survives_a_dead_route_so_the_upload_can_be_replayed_on_the_next_one() {
    // The reason `bridge_ws` borrows the client instead of consuming it, and the
    // reason the replay buffer exists at all. Every real call site in the Python
    // passes `close_writer=False`; a port that closed the client here would keep
    // returning a replay with nobody left to replay it to.
    let (mut client_far, mut client_near) = duplex(64 * 1024);
    let mut recorder = Recorder::default();
    let options = WsBridgeOptions { replay_limit: 4096, ..WsBridgeOptions::default() };

    // First route: takes the request, then closes without answering.
    let (dead, mut dead_peer) = ws_pair();
    let (dead_reader, dead_writer) = dead.split();
    let first = async {
        bridge_ws(&mut client_near, dead_reader, dead_writer, NoSplit, options, &mut recorder).await
    };
    let script = async {
        client_far.write_all(b"request").await.expect("write");
        tokio::time::sleep(Duration::from_millis(30)).await;
        dead_peer.write_all(&server_frame(Opcode::Close, &1000u16.to_be_bytes(), true)).await.expect("write");
    };
    let (outcome, ()) = tokio::join!(first, script);
    assert_eq!(outcome.down, 0);
    assert_eq!(outcome.replay, b"request", "there is something to put back");

    // Second route, same client. This is the step the borrow makes possible.
    let (live, mut live_peer) = ws_pair();
    let (live_reader, mut live_writer) = live.split();
    live_writer.send(&outcome.replay).await.expect("replay the upload");
    let mut recorder = Recorder::default();
    let second = async {
        bridge_ws(&mut client_near, live_reader, live_writer, NoSplit, WsBridgeOptions::default(), &mut recorder)
            .await
    };
    let script = async {
        let (replayed, _) = parse_all(&mut live_peer).await;
        assert_eq!(replayed, vec![(Opcode::Binary, b"request".to_vec())], "the same request, once more");
        live_peer.write_all(&server_frame(Opcode::Binary, b"answer", true)).await.expect("write");
        let mut back = [0u8; 6];
        client_far.read_exact(&mut back).await.expect("the client is still there to answer");
        assert_eq!(&back, b"answer");
        drop(client_far);
    };
    let (outcome, ()) = tokio::join!(second, script);
    assert_eq!(outcome.down, 6);
}
