//! The tunnel driven over real loopback sockets.
//!
//! The policy in `nova_tgrelay::bridge` is tested against values; this file
//! exists for what only a socket shows — a direction that stops being pumped, a
//! peer that is never told the tunnel ended, a payload larger than one read, a
//! leash that fires against the wrong counter.

use nova_tgrelay::bridge::{BridgeEnd, BridgeOutcome, FirstDownGuard, TrafficStats};
use nova_tgrelay_net::bridge::{bridge_streams, BridgeOptions};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Wait for the tunnel to return, but never forever.
///
/// Every failure mode of the leash is "it did not fire", and a bare `.await` on
/// a bridge that never returns is a test that reports nothing and stalls the
/// suite instead of failing it — the shape G24 already caught once in the
/// Python's shutdown tests. Proven necessary here: judging the leash against
/// `up` instead of `down` made one test hang until the harness was killed.
async fn finished(bridge: JoinHandle<BridgeOutcome>) -> BridgeOutcome {
    tokio::time::timeout(Duration::from_secs(5), bridge).await.expect("the tunnel never ended").expect("join")
}

/// Two connected loopback sockets. The first is the far end the test drives, the
/// second is the near end the bridge owns.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let dialing = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
    let (near, _) = listener.accept().await.expect("accept");
    let far = dialing.await.expect("join");
    (far, near)
}

/// A leash short enough to test without sleeping for seconds, in the same spirit
/// as the listener's `TEST_LIMITS`.
const LEASH: Duration = Duration::from_millis(120);

fn leashed() -> BridgeOptions {
    BridgeOptions { first_down: FirstDownGuard::new(LEASH), ..BridgeOptions::default() }
}

#[tokio::test]
async fn bytes_flow_in_both_directions_and_are_counted() {
    let (mut client_far, client_near) = tcp_pair().await;
    let (mut upstream_far, upstream_near) = tcp_pair().await;

    let bridge =
        tokio::spawn(
            async move { bridge_streams(client_near, upstream_near, BridgeOptions::default(), |_| {}).await },
        );

    client_far.write_all(b"up-payload").await.expect("client write");
    let mut seen = [0u8; 10];
    upstream_far.read_exact(&mut seen).await.expect("upstream read");
    assert_eq!(&seen, b"up-payload");

    upstream_far.write_all(b"down").await.expect("upstream write");
    let mut back = [0u8; 4];
    client_far.read_exact(&mut back).await.expect("client read");
    assert_eq!(&back, b"down");

    client_far.shutdown().await.expect("shutdown");
    let outcome = finished(bridge).await;
    assert_eq!(outcome.end, BridgeEnd::ClientEof);
    assert_eq!(outcome.up, 10);
    assert_eq!(outcome.down, 4);
}

#[tokio::test]
async fn a_payload_larger_than_one_read_arrives_whole_and_in_order() {
    const N: usize = 256 * 1024; // four times the 64 KiB read buffer
    let (mut client_far, client_near) = tcp_pair().await;
    let (upstream_far, upstream_near) = tcp_pair().await;

    let bridge =
        tokio::spawn(
            async move { bridge_streams(client_near, upstream_near, BridgeOptions::default(), |_| {}).await },
        );

    // Drained concurrently: without a reader the kernel buffers fill and the
    // writer below would block forever.
    let sink = tokio::spawn(async move {
        let mut upstream_far = upstream_far;
        let mut got = Vec::new();
        upstream_far.read_to_end(&mut got).await.expect("read to end");
        got
    });

    let payload: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
    client_far.write_all(&payload).await.expect("write");
    client_far.shutdown().await.expect("shutdown");

    let outcome = finished(bridge).await;
    let got = sink.await.expect("join sink");
    assert_eq!(outcome.end, BridgeEnd::ClientEof);
    assert_eq!(outcome.up, N as u64);
    assert_eq!(got.len(), N);
    assert!(got == payload, "payload was reordered or corrupted across reads");
}

#[tokio::test]
async fn the_client_closing_ends_the_tunnel_and_closes_the_egress() {
    let (client_far, client_near) = tcp_pair().await;
    let (mut upstream_far, upstream_near) = tcp_pair().await;

    let bridge =
        tokio::spawn(
            async move { bridge_streams(client_near, upstream_near, BridgeOptions::default(), |_| {}).await },
        );

    drop(client_far);
    let outcome = finished(bridge).await;
    assert_eq!(outcome.end, BridgeEnd::ClientEof);

    // The Python closes both writers — one in the finishing pipe's `finally`,
    // the other in the cancelled sibling's. The egress must not be left holding
    // a socket nobody will ever speak on again.
    let mut buf = [0u8; 1];
    assert_eq!(upstream_far.read(&mut buf).await.expect("egress read"), 0);
}

#[tokio::test]
async fn the_egress_closing_ends_the_tunnel_and_closes_the_client() {
    let (mut client_far, client_near) = tcp_pair().await;
    let (upstream_far, upstream_near) = tcp_pair().await;

    let bridge =
        tokio::spawn(
            async move { bridge_streams(client_near, upstream_near, BridgeOptions::default(), |_| {}).await },
        );

    drop(upstream_far);
    let outcome = finished(bridge).await;
    assert_eq!(outcome.end, BridgeEnd::UpstreamEof);

    let mut buf = [0u8; 1];
    assert_eq!(client_far.read(&mut buf).await.expect("client read"), 0);
}

#[tokio::test]
async fn the_short_leash_cuts_an_egress_that_accepts_and_says_nothing() {
    // WARP's failure mode: the TCP connection is established, and then not one
    // byte ever comes back. This is the case the leash exists for.
    let (mut client_far, client_near) = tcp_pair().await;
    let (_upstream_far, upstream_near) = tcp_pair().await;

    let bridge = tokio::spawn(async move { bridge_streams(client_near, upstream_near, leashed(), |_| {}).await });

    let outcome = finished(bridge).await;
    assert_eq!(outcome.end, BridgeEnd::FirstDownTimeout);
    assert_eq!(outcome.down, 0);
    assert!(outcome.duration >= LEASH, "cut before the window: {:?}", outcome.duration);

    // Cut, not abandoned: the client is told, so it can re-dial instead of
    // sitting on a socket that will never answer.
    let mut buf = [0u8; 1];
    assert_eq!(client_far.read(&mut buf).await.expect("client read"), 0);
}

#[tokio::test]
async fn client_traffic_alone_does_not_save_a_silent_egress() {
    let (mut client_far, client_near) = tcp_pair().await;
    let (_upstream_far, upstream_near) = tcp_pair().await;

    let bridge = tokio::spawn(async move { bridge_streams(client_near, upstream_near, leashed(), |_| {}).await });

    // A Telegram client retransmitting its handshake looks busy from the up
    // side. The leash must judge the egress, not the tunnel.
    for _ in 0..5 {
        client_far.write_all(b"still trying").await.expect("write");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let outcome = finished(bridge).await;
    assert_eq!(outcome.end, BridgeEnd::FirstDownTimeout);
    assert!(outcome.up > 0);
    assert_eq!(outcome.down, 0);
}

#[tokio::test]
async fn one_byte_down_inside_the_window_spends_the_leash_for_good() {
    let (_client_far, client_near) = tcp_pair().await;
    let (mut upstream_far, upstream_near) = tcp_pair().await;

    let bridge = tokio::spawn(async move { bridge_streams(client_near, upstream_near, leashed(), |_| {}).await });

    upstream_far.write_all(b"!").await.expect("write");
    // Well past the window, silent throughout. An answered tunnel is allowed to
    // idle — Telegram's do, for minutes (I9).
    tokio::time::sleep(LEASH * 4).await;
    drop(upstream_far);

    let outcome = finished(bridge).await;
    assert_eq!(outcome.end, BridgeEnd::UpstreamEof);
    assert_eq!(outcome.down, 1);
}

#[tokio::test]
async fn a_disabled_leash_never_cuts() {
    let (_client_far, client_near) = tcp_pair().await;
    let (mut upstream_far, upstream_near) = tcp_pair().await;

    // What the call site passes for a route already proven for this DC.
    let options = BridgeOptions { first_down: FirstDownGuard::from_secs_f64(0.0), ..BridgeOptions::default() };
    let bridge = tokio::spawn(async move { bridge_streams(client_near, upstream_near, options, |_| {}).await });

    tokio::time::sleep(LEASH * 4).await;
    assert!(!bridge.is_finished(), "a proven route was cut for being quiet");

    upstream_far.write_all(b"late").await.expect("write");
    drop(upstream_far);
    let outcome = finished(bridge).await;
    assert_eq!(outcome.end, BridgeEnd::UpstreamEof);
    assert_eq!(outcome.down, 4);
}

#[tokio::test(start_paused = true)]
async fn the_traffic_line_is_logged_while_bytes_move_and_not_otherwise() {
    // In-memory pipes and a paused clock: the interval floor is 2 s, and this
    // test is about which lines appear, not about wall time.
    let (mut client_far, client_near) = tokio::io::duplex(64 * 1024);
    let (upstream_far, upstream_near) = tokio::io::duplex(64 * 1024);

    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&lines);
    let options = BridgeOptions {
        stats: TrafficStats::new("path=tcp-fallback route=warp-socks", Duration::from_secs(2)),
        ..BridgeOptions::default()
    };
    let bridge = tokio::spawn(async move {
        bridge_streams(client_near, upstream_near, options, move |line| {
            sink.lock().expect("lock").push(line.to_string())
        })
        .await
    });

    client_far.write_all(&[b'x'; 200]).await.expect("write");
    tokio::time::sleep(Duration::from_secs(3)).await;
    {
        let logged = lines.lock().expect("lock");
        assert_eq!(logged.len(), 1, "expected exactly one line, got {logged:?}");
        assert!(logged[0].starts_with("[TgRelay] traffic path=tcp-fallback route=warp-socks "), "{logged:?}");
        assert!(logged[0].contains("up=200 down=0"), "{logged:?}");
        assert!(logged[0].contains("rate_up=100B/s"), "{logged:?}");
    }

    // Two more silent windows must add nothing.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(lines.lock().expect("lock").len(), 1);

    drop(upstream_far);
    let outcome = finished(bridge).await;
    assert_eq!(outcome.end, BridgeEnd::UpstreamEof);
    assert_eq!(outcome.up, 200);
}

#[tokio::test]
async fn an_unlabelled_tunnel_logs_nothing() {
    let (client_far, client_near) = tcp_pair().await;
    let (_upstream_far, upstream_near) = tcp_pair().await;

    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&lines);
    let options = BridgeOptions {
        // The Python's `if not label … return`: an empty label is how the
        // pre-warm path stays out of the traffic log.
        stats: TrafficStats::with_default_interval(""),
        first_down: FirstDownGuard::new(LEASH),
        ..BridgeOptions::default()
    };
    let bridge = tokio::spawn(async move {
        bridge_streams(client_near, upstream_near, options, move |line| {
            sink.lock().expect("lock").push(line.to_string())
        })
        .await
    });

    drop(client_far);
    let outcome = finished(bridge).await;
    assert_eq!(outcome.end, BridgeEnd::ClientEof);
    assert!(lines.lock().expect("lock").is_empty());
}

/// A client that never speaks and cannot be written to — a socket the peer reset
/// in the moment between the egress answering and the answer being forwarded.
///
/// A real socket cannot be talked into this state on demand, and the ordering it
/// pins is invisible without it: see the test below.
struct ResetClient;

impl tokio::io::AsyncRead for ResetClient {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Never readable and never EOF, so the only way out of the bridge is the
        // write below failing. Nothing waits on this waker: the other direction
        // is what ends the tunnel.
        Poll::Pending
    }
}

impl tokio::io::AsyncWrite for ResetClient {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn bytes_that_arrived_are_counted_even_when_forwarding_them_fails() {
    let (mut upstream_far, upstream_near) = tcp_pair().await;

    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&lines);
    let bridge = tokio::spawn(async move {
        bridge_streams(ResetClient, upstream_near, BridgeOptions::default(), move |line| {
            sink.lock().expect("lock").push(line.to_string())
        })
        .await
    });

    upstream_far.write_all(b"pong").await.expect("egress write");

    let outcome = finished(bridge).await;
    // Blamed by socket, not by pump: the direction that died is upstream→client,
    // but the end that broke is the client.
    assert_eq!(outcome.end, BridgeEnd::ClientError);
    // The point of counting before the write. `down` is what decides the short
    // leash and what `_native_record` stores as this DC's verdict on the route,
    // so counting after a failed write would file a working egress as one that
    // never answered — and the relay would go on avoiding it.
    assert_eq!(outcome.down, 4);

    // And it says so out loud. The Python suppresses this exception, which is why
    // a tunnel that was reset and one that closed cleanly read identically there.
    let logged = lines.lock().expect("lock");
    assert_eq!(logged.len(), 1, "{logged:?}");
    assert!(logged[0].starts_with("[TgRelay] tunnel client write error: "), "{logged:?}");
}
