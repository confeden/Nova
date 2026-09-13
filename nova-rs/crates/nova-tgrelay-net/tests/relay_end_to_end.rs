//! The relay, composed. Both paths, end to end.
//!
//! Every layer has its own tests and none of them proves the layers fit
//! together. These do. A real client speaks SOCKS5 to a real listener; the relay
//! picks an egress from a real health table, dials it through a real SOCKS5
//! proxy and bridges to a real target — or frames the same bytes as RFC 6455 and
//! carries them over a WebSocket a peer reads by hand. Nothing is stubbed but
//! the far end of the wire.
//!
//! This is the closest thing to an answer to "does the port work" that exists
//! short of wiring it into Nova, and it is the shape the switch-over will need:
//! the relay is assembled here in about thirty lines. If that had been awkward,
//! it would have meant the layers were cut in the wrong places.

use nova_tgrelay::bridge::{BridgeEnd, FirstDownGuard};
use nova_tgrelay::egress::{
    order_by_native, telegram_egresses, Dc, Egress, NativeHealth, ProxyProtocol, RoutePreference,
};
use nova_tgrelay::Authority;
use nova_tgrelay_net::bridge::{bridge_streams, BridgeOptions};
use nova_tgrelay_net::dial::{dial, DEFAULT_TIMEOUT};
use nova_tgrelay::wsbridge::{NoSplit, WsBridgeObserver};
use nova_tgrelay::wsframe::{build_frame, parse_header, FixedMask, Opcode};
use nova_tgrelay_net::listener::{accept_client, TEST_LIMITS};
use nova_tgrelay_net::wsbridge::{bridge_ws, WsBridgeOptions};
use nova_tgrelay_net::wsconn::WsConnection;
use nova_tgrelay_net::ClientMode;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn authority(addr: SocketAddr) -> Authority {
    Authority::new(addr.ip().to_string(), addr.port()).expect("authority")
}

/// A SOCKS5 proxy that actually proxies: greets, reads the request, connects to
/// the named target and pumps bytes both ways.
async fn socks5_proxy() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.expect("accept");

        let mut greeting = [0u8; 3];
        client.read_exact(&mut greeting).await.expect("greeting");
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        client.write_all(b"\x05\x00").await.expect("method");

        let mut head = [0u8; 4];
        client.read_exact(&mut head).await.expect("request");
        assert_eq!(head[3], 0x01, "an IP target arrives as ATYP 1");
        let mut rest = [0u8; 6];
        client.read_exact(&mut rest).await.expect("address");
        let target =
            SocketAddr::from(([rest[0], rest[1], rest[2], rest[3]], u16::from_be_bytes([rest[4], rest[5]])));

        let mut upstream = TcpStream::connect(target).await.expect("proxy dials the target");
        client.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await.expect("reply");
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await.ok();
    });
    (addr, task)
}

/// The far end: answers whatever it is sent, prefixed.
async fn echo_target() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        loop {
            let n = match sock.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            let mut answer = b"dc:".to_vec();
            answer.extend_from_slice(&buf[..n]);
            if sock.write_all(&answer).await.is_err() {
                return;
            }
        }
    });
    (addr, task)
}

/// A SOCKS5 client request for `target`, as an IP.
fn socks_request(target: SocketAddr) -> Vec<u8> {
    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => panic!("loopback v4 only in this test"),
    };
    let mut out = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01];
    out.extend_from_slice(&ip);
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}

#[tokio::test]
async fn a_client_reaches_the_target_through_the_whole_ported_path() {
    let (target_addr, target) = echo_target().await;
    let (proxy_addr, proxy) = socks5_proxy().await;

    // The relay's own listener, on a port of the kernel's choosing.
    let relay = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let relay_addr = relay.local_addr().expect("addr");

    let dc = Dc::new(2).expect("dc");
    let health = NativeHealth::default();
    let preference = RoutePreference::default();

    let served = tokio::spawn(async move {
        let (sock, _) = relay.accept().await.expect("accept");

        // Layer 3: what is this client, and where does it want to go.
        let accepted = accept_client(sock, relay_addr.port(), TEST_LIMITS).await.expect("accepted");
        assert_eq!(accepted.mode, ClientMode::Socks5);

        // Layer 5: which way out. The provider offers direct first, so direct is
        // allowed; the health table has nothing to say yet, so the order stands.
        let offered = vec![
            Egress::direct("direct"),
            Egress::proxy(ProxyProtocol::Socks5, "warp-socks", authority(proxy_addr)),
        ];
        let mut egresses = telegram_egresses(&offered);
        egresses = preference.apply(&egresses, &accepted.authority, Instant::now());
        order_by_native(&mut egresses, dc, &health, Instant::now());
        // Put the proxy first so this test exercises the proxy path rather than
        // the direct one, which any listener could have done.
        egresses.reverse();

        let dialled = dial(&accepted.authority, &egresses, DEFAULT_TIMEOUT).await.expect("dialled");
        assert_eq!(dialled.label, "warp-socks");
        assert!(dialled.leftover.is_empty());

        // Layer 4: carry the bytes, with the short leash an unproven route gets.
        let options = BridgeOptions { first_down: FirstDownGuard::from_secs_f64(1.5), ..BridgeOptions::default() };
        let outcome = bridge_streams(accepted.stream, dialled.stream, options, |_| {}).await;
        (outcome, dialled.label)
    });

    // A client that speaks SOCKS5 and expects an echo.
    let mut client = TcpStream::connect(relay_addr).await.expect("connect");
    client.write_all(&socks_request(target_addr)).await.expect("request");

    let mut reply = [0u8; 12];
    client.read_exact(&mut reply).await.expect("socks reply");
    assert_eq!(&reply[..2], b"\x05\x00", "method selection");
    // `05 00 00 01` — version, REP=succeeded, reserved, ATYP=IPv4 — then the
    // bound address and the port the relay is listening on. The success byte is
    // index 3 and it is `00`; `01` there would be a general failure.
    assert_eq!(&reply[2..6], b"\x05\x00\x00\x01", "success");
    assert_eq!(u16::from_be_bytes([reply[10], reply[11]]), relay_addr.port());

    client.write_all(b"hello").await.expect("payload");
    let mut echoed = [0u8; 8];
    client.read_exact(&mut echoed).await.expect("echo");
    assert_eq!(&echoed, b"dc:hello", "the target's answer came back through every layer");

    client.shutdown().await.expect("shutdown");
    drop(client);

    let (outcome, label) = tokio::time::timeout(Duration::from_secs(5), served)
        .await
        .expect("the relay never finished")
        .expect("join");
    assert_eq!(label, "warp-socks");
    assert_eq!(outcome.end, BridgeEnd::ClientEof);
    assert_eq!(outcome.up, 5);
    assert_eq!(outcome.down, 8);

    proxy.abort();
    target.abort();
}

#[tokio::test]
async fn an_egress_that_accepts_and_says_nothing_is_cut_and_recorded() {
    // The failure the whole health machinery exists for: WARP answers TCP and
    // then delivers nothing. The leash cuts it, and what the tunnel carried is
    // what decides the DC's verdict on that route.
    let (proxy_addr, proxy) = socks5_proxy().await;
    // A "target" that accepts and never speaks.
    let silent = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let silent_addr = silent.local_addr().expect("addr");
    let silence = tokio::spawn(async move {
        let (_sock, _) = silent.accept().await.expect("accept");
        std::future::pending::<()>().await;
    });

    let relay = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let relay_addr = relay.local_addr().expect("addr");
    let dc = Dc::new(2).expect("dc");

    let served = tokio::spawn(async move {
        let (sock, _) = relay.accept().await.expect("accept");
        let accepted = accept_client(sock, relay_addr.port(), TEST_LIMITS).await.expect("accepted");
        let egresses = vec![Egress::proxy(ProxyProtocol::Socks5, "warp-socks", authority(proxy_addr))];
        let dialled = dial(&accepted.authority, &egresses, DEFAULT_TIMEOUT).await.expect("dialled");
        let options = BridgeOptions {
            first_down: FirstDownGuard::new(Duration::from_millis(150)),
            ..BridgeOptions::default()
        };
        let outcome = bridge_streams(accepted.stream, dialled.stream, options, |_| {}).await;
        (outcome, dialled.label)
    });

    let mut client = TcpStream::connect(relay_addr).await.expect("connect");
    client.write_all(&socks_request(silent_addr)).await.expect("request");
    let mut reply = [0u8; 12];
    client.read_exact(&mut reply).await.expect("socks reply");
    client.write_all(b"anyone there?").await.expect("payload");

    let (outcome, label) =
        tokio::time::timeout(Duration::from_secs(5), served).await.expect("the leash never fired").expect("join");
    assert_eq!(outcome.end, BridgeEnd::FirstDownTimeout);
    assert_eq!(outcome.down, 0);

    // And the client is told, rather than left on a socket nobody will serve.
    let mut buf = [0u8; 1];
    assert_eq!(client.read(&mut buf).await.expect("client read"), 0);

    // The verdict this tunnel earns for the route.
    let mut health = NativeHealth::default();
    assert_eq!(health.record(dc, &label, outcome.down > 0, Instant::now()), Some(false));
    assert_eq!(health.state(dc, "warp-socks", Instant::now()), Some(false));

    proxy.abort();
    silence.abort();
}

#[tokio::test]
async fn a_client_reaches_telegram_over_the_websocket_path() {
    // The other half of the composition: the same listener, but the tunnel goes
    // out as WebSocket frames instead of raw TCP. The peer here is a socket
    // speaking RFC 6455 by hand, so the framing under test is the real one.
    let relay = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let relay_addr = relay.local_addr().expect("addr");
    let (ws_far, ws_near) = tokio::io::duplex(64 * 1024);

    struct Silent;
    impl WsBridgeObserver for Silent {}

    let served = tokio::spawn(async move {
        let (sock, _) = relay.accept().await.expect("accept");
        let accepted = accept_client(sock, relay_addr.port(), TEST_LIMITS).await.expect("accepted");
        assert_eq!(accepted.authority.port(), 443, "a WSS tunnel is asked for by name and port");

        let ws = WsConnection::with_mask_source(ws_near, FixedMask([9, 9, 9, 9]));
        let (reader, writer) = ws.split();
        let mut client = accepted.stream;
        bridge_ws(&mut client, reader, writer, NoSplit, WsBridgeOptions::default(), &mut Silent).await
    });

    // The client asks for `web.telegram.org:443` in SOCKS5 and then speaks.
    let mut client = TcpStream::connect(relay_addr).await.expect("connect");
    let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 16];
    request.extend_from_slice(b"web.telegram.org");
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).await.expect("request");
    let mut reply = [0u8; 12];
    client.read_exact(&mut reply).await.expect("socks reply");
    assert_eq!(&reply[2..6], b"  ");

    client.write_all(b"mtproto").await.expect("payload");

    // The far end reads a masked binary frame and answers with an unmasked one.
    let mut ws_far = ws_far;
    let mut wire = vec![0u8; 13];
    ws_far.read_exact(&mut wire).await.expect("frame");
    let header = parse_header(&wire).expect("valid").expect("complete");
    assert_eq!(header.opcode, Opcode::Binary);
    let mut body = wire[header.header_len..].to_vec();
    nova_tgrelay::wsframe::apply_mask(&mut body, header.mask.expect("a client masks"));
    assert_eq!(body, b"mtproto");

    ws_far.write_all(&build_frame(Opcode::Binary, b"dc:mtproto", None)).await.expect("answer");
    let mut echoed = [0u8; 10];
    client.read_exact(&mut echoed).await.expect("echo");
    assert_eq!(&echoed, b"dc:mtproto");

    drop(client);
    let outcome = tokio::time::timeout(Duration::from_secs(5), served)
        .await
        .expect("the relay never finished")
        .expect("join");
    assert_eq!(outcome.up, 7);
    assert_eq!(outcome.down, 10);
    assert!(!outcome.first_down_timed_out);
}
