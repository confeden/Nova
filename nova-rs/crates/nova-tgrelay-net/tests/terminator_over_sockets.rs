//! The terminator client against a helper that really speaks the protocol.
//!
//! The request shape is unit-tested against the server's own `Deserialize`
//! definitions. This file is for what only a socket shows: a greeting that never
//! comes, a reply that arrives glued to the first tunnel bytes, an egress list
//! walked past a refusal.

use nova_tgrelay::egress::{Egress, ProxyProtocol};
use nova_tgrelay::Authority;
use nova_tgrelay_net::terminator::{open_shaped_stream, TerminatorConfig, TerminatorError};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const GREETING: &[u8] = b"{\"nova\":\"tls-terminator/1\"}\n";
const OK_REPLY: &[u8] = b"{\"ok\":true,\"reached\":4,\"ended\":0,\"alpn\":\"http/1.1\"}\n";

fn target() -> Authority {
    Authority::new("kws2.nova-app.eu", 443).expect("authority")
}

fn warp(at: SocketAddr) -> Egress {
    Egress::proxy(
        ProxyProtocol::Socks5,
        "warp-socks",
        Authority::new(at.ip().to_string(), at.port()).expect("authority"),
    )
}

fn config(port: u16) -> TerminatorConfig {
    TerminatorConfig {
        port,
        token: "s3cret".to_string(),
        profile: Some("yandex-windows".to_string()),
        verify: false,
    }
}

/// Bind on loopback and hand the one accepted connection to `handler`.
///
/// The helper listens on a fixed port in production; here the kernel picks one
/// and the config is pointed at it.
async fn helper<F, Fut>(handler: F) -> (u16, tokio::task::JoinHandle<Fut::Output>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        handler(sock).await
    });
    (port, task)
}

/// Read the client's request line off `sock`, returning it parsed.
async fn read_request(sock: &mut BufReader<TcpStream>) -> serde_json::Value {
    let mut line = String::new();
    sock.read_line(&mut line).await.expect("request line");
    serde_json::from_str(line.trim_end()).expect("valid json")
}

#[tokio::test]
async fn a_shaped_tunnel_is_opened_and_carries_bytes() {
    let (port, served) = helper(|sock| async move {
        let mut sock = BufReader::new(sock);
        sock.get_mut().write_all(GREETING).await.expect("greeting");
        let request = read_request(&mut sock).await;
        sock.get_mut().write_all(OK_REPLY).await.expect("reply");
        // The socket now carries plaintext.
        let mut payload = [0u8; 7];
        sock.read_exact(&mut payload).await.expect("tunnel read");
        sock.get_mut().write_all(b"dc:answer").await.expect("tunnel write");
        (request, payload)
    })
    .await;

    let egress = warp("127.0.0.1:1370".parse().expect("addr"));
    let mut shaped =
        open_shaped_stream(&target(), "www.nova-app.eu", &[egress], &config(port), Duration::from_secs(5))
            .await
            .expect("shaped");

    assert_eq!(shaped.label, "warp-socks", "the label the relay chose, not one the helper invented");
    assert_eq!(shaped.alpn.as_deref(), Some("http/1.1"));
    assert!(shaped.leftover.is_empty());

    shaped.stream.write_all(b"CONNECT").await.expect("write");
    let mut back = [0u8; 9];
    shaped.stream.read_exact(&mut back).await.expect("read");
    assert_eq!(&back, b"dc:answer");

    let (request, payload) = served.await.expect("join");
    assert_eq!(request["sni"], "www.nova-app.eu");
    assert_eq!(request["egress"]["kind"], "socks5");
    assert_eq!(&payload, b"CONNECT");
}

#[tokio::test]
async fn a_reply_glued_to_the_first_tunnel_bytes_loses_nothing() {
    // The helper has no reason to wait, and TCP has no reason to keep the two
    // writes apart. `BufReader::into_inner` drops whatever it had already read,
    // so without taking the buffer first these bytes vanish with no error
    // anywhere — the same shape as the SOCKS over-read and the CONNECT
    // over-read this codebase has already been bitten by twice.
    let (port, served) = helper(|sock| async move {
        let mut sock = BufReader::new(sock);
        sock.get_mut().write_all(GREETING).await.expect("greeting");
        read_request(&mut sock).await;
        let mut glued = OK_REPLY.to_vec();
        glued.extend_from_slice(b"EARLY-TUNNEL-BYTES");
        sock.get_mut().write_all(&glued).await.expect("reply and payload in one write");
    })
    .await;

    let egress = warp("127.0.0.1:1370".parse().expect("addr"));
    let shaped = open_shaped_stream(&target(), "www.nova-app.eu", &[egress], &config(port), Duration::from_secs(5))
        .await
        .expect("shaped");

    assert_eq!(shaped.leftover, b"EARLY-TUNNEL-BYTES");
    served.await.expect("join");
}

#[tokio::test]
async fn a_refusal_carries_the_helpers_verdict_and_the_relays_label() {
    let (port, served) = helper(|sock| async move {
        let mut sock = BufReader::new(sock);
        sock.get_mut().write_all(GREETING).await.expect("greeting");
        read_request(&mut sock).await;
        sock.get_mut()
            .write_all(b"{\"ok\":false,\"reached\":3,\"ended\":2,\"error\":\"reset after hello\"}\n")
            .await
            .expect("reply");
    })
    .await;

    let egress = warp("127.0.0.1:1370".parse().expect("addr"));
    let error = open_shaped_stream(&target(), "www.nova-app.eu", &[egress], &config(port), Duration::from_secs(5))
        .await
        .expect_err("must fail");

    match error {
        TerminatorError::Refused { reached, ended, ref message, ref label } => {
            assert_eq!((reached, ended), (3, 2));
            assert_eq!(message, "reset after hello");
            assert_eq!(label, "warp-socks");
        }
        other => panic!("unexpected {other:?}"),
    }
    // `HelloSent` — the one window where our own ClientHello is still a suspect.
    assert_eq!(error.reached(), nova_probe::Reached::HelloSent);
    served.await.expect("join");
}

#[tokio::test]
async fn a_helper_that_closes_without_greeting_is_not_charged_to_the_network() {
    let (port, served) = helper(|sock| async move { drop(sock) }).await;

    let egress = warp("127.0.0.1:1370".parse().expect("addr"));
    let error = open_shaped_stream(&target(), "www.nova-app.eu", &[egress], &config(port), Duration::from_secs(5))
        .await
        .expect_err("must fail");

    assert!(matches!(error, TerminatorError::Helper(_)), "{error}");
    // The distinction the error type exists for: a dead helper says nothing
    // about the route that was being attempted, and charging it would demote a
    // perfectly good egress every time the helper restarts (G20).
    assert_eq!(error.reached(), nova_probe::Reached::Nothing);
    served.await.expect("join");
}

#[tokio::test]
async fn a_helper_that_is_not_listening_at_all_is_the_same_kind_of_failure() {
    // Bound and released, so the port is certainly free.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let egress = warp("127.0.0.1:1370".parse().expect("addr"));
    let error = open_shaped_stream(&target(), "www.nova-app.eu", &[egress], &config(port), Duration::from_secs(2))
        .await
        .expect_err("must fail");
    assert!(matches!(error, TerminatorError::Helper(_)), "{error}");
    assert_eq!(error.reached(), nova_probe::Reached::Nothing);
}

#[tokio::test]
async fn an_empty_egress_list_is_named_as_a_caller_bug() {
    let error = open_shaped_stream(&target(), "www.nova-app.eu", &[], &config(1374), Duration::from_secs(1))
        .await
        .expect_err("must fail");
    assert!(matches!(error, TerminatorError::NoEgress), "{error}");
}

#[tokio::test]
async fn the_list_is_walked_past_a_refusal() {
    // Two helpers standing in for one that refuses the first egress and accepts
    // the second: the client opens a fresh connection per attempt, so a per-port
    // fake is a faithful stand-in for a per-attempt one.
    let (refusing, first) = helper(|sock| async move {
        let mut sock = BufReader::new(sock);
        sock.get_mut().write_all(GREETING).await.expect("greeting");
        read_request(&mut sock).await;
        sock.get_mut()
            .write_all(b"{\"ok\":false,\"reached\":1,\"ended\":3,\"error\":\"connection refused\"}\n")
            .await
            .expect("reply");
    })
    .await;

    let egress = warp("127.0.0.1:1370".parse().expect("addr"));
    let error = open_shaped_stream(
        &target(),
        "www.nova-app.eu",
        std::slice::from_ref(&egress),
        &config(refusing),
        Duration::from_secs(5),
    )
    .await
    .expect_err("the only egress was refused");
    assert!(matches!(error, TerminatorError::Refused { .. }));
    first.await.expect("join");

    let (accepting, second) = helper(|sock| async move {
        let mut sock = BufReader::new(sock);
        sock.get_mut().write_all(GREETING).await.expect("greeting");
        read_request(&mut sock).await;
        sock.get_mut().write_all(OK_REPLY).await.expect("reply");
    })
    .await;
    let opera = Egress::proxy(
        ProxyProtocol::HttpConnect,
        "opera-http",
        Authority::new("127.0.0.1", 1371).expect("authority"),
    );
    let shaped =
        open_shaped_stream(&target(), "www.nova-app.eu", &[opera], &config(accepting), Duration::from_secs(5))
            .await
            .expect("shaped");
    assert_eq!(shaped.label, "opera-http");
    second.await.expect("join");
}

#[tokio::test]
async fn nothing_is_written_between_the_request_line_and_the_reply() {
    // The server reads the request through a `BufReader` it discards straight
    // after, so anything pipelined behind that line is dropped without a trace.
    // Here the guarantee is structural — the stream is not handed back until the
    // reply has arrived — and this is what proves it from the outside.
    let (port, served) = helper(|sock| async move {
        let mut sock = BufReader::new(sock);
        sock.get_mut().write_all(GREETING).await.expect("greeting");
        read_request(&mut sock).await;
        // Give a client that was going to pipeline every chance to do so.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let pending = sock.buffer().len();
        let mut extra = [0u8; 64];
        let more = match tokio::time::timeout(Duration::from_millis(100), sock.read(&mut extra)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        sock.get_mut().write_all(OK_REPLY).await.expect("reply");
        pending + more
    })
    .await;

    let egress = warp("127.0.0.1:1370".parse().expect("addr"));
    let shaped = open_shaped_stream(&target(), "www.nova-app.eu", &[egress], &config(port), Duration::from_secs(5))
        .await
        .expect("shaped");
    drop(shaped);

    assert_eq!(served.await.expect("join"), 0, "the client wrote past its request line");
}
