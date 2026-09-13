//! Dialling an egress, against proxies that really speak the protocol.
//!
//! The encoders and the status parser are unit-tested against byte slices. This
//! file is for what only a socket shows: bytes that should have been drained and
//! became tunnel payload, a deadline that renews itself per read, a failure
//! charged to the wrong gate.

use nova_probe::Reached;
use nova_tgrelay::egress::{Egress, ProxyProtocol};
use nova_tgrelay::Authority;
use nova_tgrelay_net::dial::{dial, DialError, DEFAULT_TIMEOUT};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Bind a loopback listener and run `handler` on the single connection it takes.
async fn serve<F, Fut>(handler: F) -> (SocketAddr, JoinHandle<Fut::Output>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        handler(sock).await
    });
    (addr, task)
}

/// An address nothing is listening on: bound to learn the port, then released.
async fn dead_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

fn authority(addr: SocketAddr) -> Authority {
    Authority::new(addr.ip().to_string(), addr.port()).expect("authority")
}

fn target(host: &str, port: u16) -> Authority {
    Authority::new(host, port).expect("target")
}

/// Read the SOCKS5 greeting and the CONNECT request, returning the request bytes.
async fn read_socks_request(sock: &mut TcpStream) -> Vec<u8> {
    let mut greeting = [0u8; 3];
    sock.read_exact(&mut greeting).await.expect("greeting");
    assert_eq!(greeting, [0x05, 0x01, 0x00], "no-auth greeting");
    sock.write_all(b"\x05\x00").await.expect("method selection");

    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await.expect("request head");
    let mut request = head.to_vec();
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.expect("domain length");
            request.extend_from_slice(&len);
            len[0] as usize
        }
        other => panic!("unexpected ATYP {other}"),
    };
    let mut rest = vec![0u8; addr_len + 2];
    sock.read_exact(&mut rest).await.expect("address and port");
    request.extend_from_slice(&rest);
    request
}

/// The reply every well-behaved SOCKS5 proxy sends: success, bound `0.0.0.0:0`.
const SOCKS_OK: &[u8] = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00";

#[tokio::test]
async fn a_direct_egress_carries_bytes_to_the_target() {
    let (addr, server) = serve(|mut sock| async move {
        sock.write_all(b"hello from the target").await.expect("write");
        let mut got = [0u8; 4];
        sock.read_exact(&mut got).await.expect("read");
        got
    })
    .await;

    let dialled = dial(&authority(addr), &[Egress::direct("direct")], DEFAULT_TIMEOUT).await.expect("dialled");
    assert_eq!(dialled.label, "direct");
    assert!(dialled.leftover.is_empty());

    let mut stream = dialled.stream;
    let mut greeting = [0u8; 21];
    stream.read_exact(&mut greeting).await.expect("read");
    assert_eq!(&greeting, b"hello from the target");
    stream.write_all(b"back").await.expect("write");
    assert_eq!(&server.await.expect("join"), b"back");
}

#[tokio::test]
async fn a_socks5_proxy_is_asked_for_the_target_by_name() {
    let (proxy, server) = serve(|mut sock| async move {
        let request = read_socks_request(&mut sock).await;
        sock.write_all(SOCKS_OK).await.expect("reply");
        request
    })
    .await;

    let egress = Egress::proxy(ProxyProtocol::Socks5, "warp-socks", authority(proxy));
    let dialled = dial(&target("web.telegram.org", 443), &[egress], DEFAULT_TIMEOUT).await.expect("dialled");
    assert_eq!(dialled.label, "warp-socks");

    let request = server.await.expect("join");
    let mut expected = vec![0x05, 0x01, 0x00, 0x03, 16];
    expected.extend_from_slice(b"web.telegram.org");
    expected.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(request, expected);
}

#[tokio::test]
async fn a_socks5_proxy_is_asked_for_an_ip_target_as_an_ip() {
    let (proxy, server) = serve(|mut sock| async move {
        let request = read_socks_request(&mut sock).await;
        sock.write_all(SOCKS_OK).await.expect("reply");
        request
    })
    .await;

    let egress = Egress::proxy(ProxyProtocol::Socks5, "warp-socks", authority(proxy));
    dial(&target("149.154.167.51", 443), &[egress], DEFAULT_TIMEOUT).await.expect("dialled");

    let request = server.await.expect("join");
    assert_eq!(request, vec![0x05, 0x01, 0x00, 0x01, 149, 154, 167, 51, 0x01, 0xBB]);
}

#[tokio::test]
async fn the_bound_address_is_drained_and_does_not_become_the_first_tunnel_byte() {
    // A proxy that answers with a *domain* bound address — the longest of the
    // three forms, and the one whose length has to be read before it can be
    // skipped. Getting this wrong hands the tunnel ten bytes of SOCKS reply
    // dressed up as Telegram's first frame.
    let (proxy, server) = serve(|mut sock| async move {
        read_socks_request(&mut sock).await;
        let mut reply = vec![0x05, 0x00, 0x00, 0x03, 9];
        reply.extend_from_slice(b"localhost");
        reply.extend_from_slice(&0u16.to_be_bytes());
        sock.write_all(&reply).await.expect("reply");
        sock.write_all(b"TUNNEL").await.expect("payload");
    })
    .await;

    let egress = Egress::proxy(ProxyProtocol::Socks5, "warp-socks", authority(proxy));
    let mut stream =
        dial(&target("web.telegram.org", 443), &[egress], DEFAULT_TIMEOUT).await.expect("dialled").stream;

    let mut first = [0u8; 6];
    stream.read_exact(&mut first).await.expect("tunnel read");
    assert_eq!(&first, b"TUNNEL");
    server.await.expect("join");
}

#[tokio::test]
async fn a_socks5_refusal_is_charged_to_connected_not_to_resolved() {
    let (proxy, server) = serve(|mut sock| async move {
        read_socks_request(&mut sock).await;
        // 0x05 = connection refused by destination host.
        sock.write_all(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00").await.expect("reply");
    })
    .await;

    let egress = Egress::proxy(ProxyProtocol::Socks5, "warp-socks", authority(proxy));
    let error = dial(&target("web.telegram.org", 443), &[egress], DEFAULT_TIMEOUT).await.expect_err("must fail");
    match error {
        // The Python cannot express this: it tags every attempt failure
        // `RESOLVED`, so "the proxy is not listening" and "the proxy answered
        // and said no" arrive as the same fact.
        DialError::AllFailed { reached, tried, .. } => {
            assert_eq!(reached, Reached::Connected);
            assert_eq!(tried, 1);
        }
        other => panic!("unexpected {other:?}"),
    }
    server.await.expect("join");
}

#[tokio::test]
async fn an_http_connect_proxy_is_spoken_to_and_its_over_read_is_kept() {
    let (proxy, server) = serve(|mut sock| async move {
        let mut request = vec![0u8; 0];
        let mut chunk = [0u8; 512];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock.read(&mut chunk).await.expect("read");
            assert_ne!(n, 0, "client closed mid-request");
            request.extend_from_slice(&chunk[..n]);
        }
        // Reply and the first tunnel bytes in one write, so they land in the
        // same read on the far side.
        sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nEARLY").await.expect("reply");
        String::from_utf8(request).expect("utf8")
    })
    .await;

    let egress = Egress::proxy(ProxyProtocol::HttpConnect, "opera-http", authority(proxy));
    let dialled = dial(&target("web.telegram.org", 443), &[egress], DEFAULT_TIMEOUT).await.expect("dialled");
    assert_eq!(dialled.label, "opera-http");
    // The Python discards this buffer whole. Nothing arrives there today only
    // because Telegram's client speaks first.
    assert_eq!(dialled.leftover, b"EARLY");

    let request = server.await.expect("join");
    assert!(request.starts_with("CONNECT web.telegram.org:443 HTTP/1.1\r\n"), "{request:?}");
    assert!(request.contains("Host: web.telegram.org:443\r\n"), "{request:?}");
    assert!(request.contains("User-Agent: NovaTelegramRelay/1\r\n"), "{request:?}");
}

#[tokio::test]
async fn a_non_200_from_the_proxy_fails_the_attempt() {
    let (proxy, server) = serve(|mut sock| async move {
        let mut chunk = [0u8; 512];
        let _ = sock.read(&mut chunk).await;
        sock.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await.expect("reply");
    })
    .await;

    let egress = Egress::proxy(ProxyProtocol::HttpConnect, "opera-http", authority(proxy));
    let error = dial(&target("web.telegram.org", 443), &[egress], DEFAULT_TIMEOUT).await.expect_err("must fail");
    match error {
        DialError::AllFailed { reached, last, .. } => {
            assert_eq!(reached, Reached::Connected);
            assert!(last.to_string().contains("407"), "{last}");
        }
        other => panic!("unexpected {other:?}"),
    }
    server.await.expect("join");
}

#[tokio::test]
async fn a_proxy_that_closes_instead_of_answering_says_so() {
    let (proxy, server) = serve(|mut sock| async move {
        let mut chunk = [0u8; 512];
        let _ = sock.read(&mut chunk).await;
        drop(sock);
    })
    .await;

    let egress = Egress::proxy(ProxyProtocol::HttpConnect, "opera-http", authority(proxy));
    let error = dial(&target("web.telegram.org", 443), &[egress], DEFAULT_TIMEOUT).await.expect_err("must fail");
    match error {
        DialError::AllFailed { last, .. } => {
            // The Python parses an empty buffer and reports `HTTP CONNECT
            // failed: ` with nothing after the colon, which reads like a
            // malformed status line rather than a closed socket.
            assert!(last.to_string().contains("closed before answering"), "{last}");
        }
        other => panic!("unexpected {other:?}"),
    }
    server.await.expect("join");
}

#[tokio::test]
async fn a_dribbling_proxy_cannot_renew_the_budget_one_byte_at_a_time() {
    // G22, on the client side of a proxy. CPython's socket timeout is
    // *per operation*, so `_recv_exact` hands this proxy a fresh five seconds
    // for every byte it produces and the attempt never ends on its own.
    //
    // Every byte below is **valid so far** and the reply is left one byte short.
    // That is what makes this a test of renewal rather than of a stalled read: a
    // malformed byte would end the attempt early for the wrong reason, and an
    // early first version of this test did exactly that and passed against a
    // per-read timeout.
    const DRIBBLE: Duration = Duration::from_millis(120);
    let (proxy, server) = serve(|mut sock| async move {
        let mut greeting = [0u8; 3];
        sock.read_exact(&mut greeting).await.expect("greeting");
        // `05 00`, one byte at a time.
        for byte in [0x05u8, 0x00] {
            tokio::time::sleep(DRIBBLE).await;
            if sock.write_all(&[byte]).await.is_err() {
                return;
            }
        }
        let mut head = [0u8; 4];
        if sock.read_exact(&mut head).await.is_err() {
            return;
        }
        // A well-formed IPv4 reply needs 4 + 6 bytes. Send 9 of the 10.
        for byte in [0x05u8, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00] {
            tokio::time::sleep(DRIBBLE).await;
            if sock.write_all(&[byte]).await.is_err() {
                return;
            }
        }
        // …and hold, never sending the tenth.
        tokio::time::sleep(Duration::from_secs(30)).await;
    })
    .await;

    let budget = Duration::from_millis(300);
    let egress = Egress::proxy(ProxyProtocol::Socks5, "warp-socks", authority(proxy)).with_timeout(budget);
    let started = tokio::time::Instant::now();
    let error = dial(&target("web.telegram.org", 443), &[egress], DEFAULT_TIMEOUT).await.expect_err("must fail");
    let elapsed = started.elapsed();

    assert!(matches!(error, DialError::AllFailed { .. }), "{error:?}");
    // Generous upper bound; the point is that it is bounded at all. Renewing per
    // read, this runs for the 1.3 s of dribble plus a whole fresh timeout on the
    // byte that never comes.
    assert!(elapsed < Duration::from_millis(1200), "attempt ran for {elapsed:?}");
    server.abort();
}

#[tokio::test]
async fn the_first_egress_that_works_wins_and_names_itself() {
    let dead = dead_port().await;
    let (proxy, server) = serve(|mut sock| async move {
        read_socks_request(&mut sock).await;
        sock.write_all(SOCKS_OK).await.expect("reply");
    })
    .await;

    let egresses = vec![
        Egress::proxy(ProxyProtocol::Socks5, "warp-socks", authority(dead)),
        Egress::proxy(ProxyProtocol::Socks5, "opera-socks", authority(proxy)),
    ];
    let dialled = dial(&target("web.telegram.org", 443), &egresses, DEFAULT_TIMEOUT).await.expect("dialled");
    assert_eq!(dialled.label, "opera-socks");
    server.await.expect("join");
}

#[tokio::test]
async fn the_furthest_gate_any_attempt_cleared_is_what_gets_reported() {
    // One egress never opens a session; the next opens one and is refused. The
    // second fact is the informative one, and a "last error wins" report would
    // lose it whenever the order happened to be the other way round.
    let dead = dead_port().await;
    let (proxy, server) = serve(|mut sock| async move {
        read_socks_request(&mut sock).await;
        sock.write_all(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00").await.expect("reply");
    })
    .await;

    let egresses = vec![
        Egress::proxy(ProxyProtocol::Socks5, "refusing", authority(proxy)),
        Egress::proxy(ProxyProtocol::Socks5, "dead", authority(dead)),
    ];
    let error = dial(&target("web.telegram.org", 443), &egresses, DEFAULT_TIMEOUT).await.expect_err("must fail");
    match error {
        DialError::AllFailed { reached, tried, .. } => {
            assert_eq!(reached, Reached::Connected);
            assert_eq!(tried, 2);
        }
        other => panic!("unexpected {other:?}"),
    }
    server.await.expect("join");
}

#[tokio::test]
async fn nothing_answering_anywhere_is_reported_as_resolved() {
    let dead = dead_port().await;
    let egresses = vec![Egress::direct("direct")];
    let error = dial(&authority(dead), &egresses, DEFAULT_TIMEOUT).await.expect_err("must fail");
    match error {
        DialError::AllFailed { reached, .. } => assert_eq!(reached, Reached::Resolved),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn an_empty_list_is_a_caller_bug_and_is_named_as_one() {
    // `attempts = proxy_attempts or direct_attempts` exists on the Python side
    // precisely so this never happens; when it does, it must not be mistaken for
    // a network condition.
    let error = dial(&target("web.telegram.org", 443), &[], DEFAULT_TIMEOUT).await.expect_err("must fail");
    assert!(matches!(error, DialError::NoEgress), "{error:?}");
}
