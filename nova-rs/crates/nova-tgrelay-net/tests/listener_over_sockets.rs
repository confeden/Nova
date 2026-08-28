//! The listener driven over real loopback sockets.
//!
//! Layers 1-2 are tested against byte slices; this file exists to catch what
//! only shows up with a socket in the middle — a handshake that never finishes
//! because the code waits for bytes the client already sent, a reply that is
//! computed but never written, a deadline that is measured from the wrong
//! moment.

use nova_tgrelay::handshake::HandshakeLimits;
use nova_tgrelay_net::listener::TEST_LIMITS;
use nova_tgrelay_net::{accept_client, ClientMode, Rejected};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const RELAY_PORT: u16 = 1372;

/// Spawn a listener, hand the accepted socket to `accept_client`, and give the
/// test the client end.
async fn pair(
    limits: HandshakeLimits,
) -> (TcpStream, tokio::task::JoinHandle<Result<nova_tgrelay_net::AcceptedClient, Rejected>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        accept_client(sock, RELAY_PORT, limits).await
    });
    let client = TcpStream::connect(addr).await.expect("connect");
    (client, server)
}

fn socks_request(host: &[u8], port: u16) -> Vec<u8> {
    let mut out = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, host.len() as u8];
    out.extend_from_slice(host);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

#[tokio::test]
async fn socks5_client_is_accepted_and_answered() {
    let (mut client, server) = pair(TEST_LIMITS).await;
    client.write_all(&socks_request(b"web.telegram.org", 443)).await.expect("write");

    let accepted = server.await.expect("join").expect("accepted");
    assert_eq!(accepted.mode, ClientMode::Socks5);
    assert_eq!(accepted.authority.host(), "web.telegram.org");
    assert_eq!(accepted.authority.port(), 443);
    assert!(accepted.rest.is_empty());

    // Method selection, then the bound-address reply carrying the relay port.
    let mut reply = [0u8; 12];
    client.read_exact(&mut reply).await.expect("reply");
    assert_eq!(&reply[..2], b"\x05\x00");
    assert_eq!(&reply[2..10], b"\x05\x00\x00\x01\x7f\x00\x00\x01");
    assert_eq!(u16::from_be_bytes([reply[10], reply[11]]), RELAY_PORT);
}

#[tokio::test]
async fn socks5_request_split_across_packets_still_completes() {
    // The split a state machine gets wrong: the domain length in one packet,
    // the name in the next.
    let (mut client, server) = pair(TEST_LIMITS).await;
    let wire = socks_request(b"a.example", 8443);
    let (head, tail) = wire.split_at(8);
    client.write_all(head).await.expect("write head");
    client.flush().await.expect("flush");
    tokio::time::sleep(Duration::from_millis(20)).await;
    client.write_all(tail).await.expect("write tail");

    let accepted = server.await.expect("join").expect("accepted");
    assert_eq!(accepted.authority.host(), "a.example");
    assert_eq!(accepted.authority.port(), 8443);
}

#[tokio::test]
async fn http_connect_client_is_accepted_and_early_payload_survives() {
    let (mut client, server) = pair(TEST_LIMITS).await;
    client
        .write_all(b"CONNECT 149.154.167.51:443 HTTP/1.1\r\nHost: x\r\n\r\n\x16\x03\x01early")
        .await
        .expect("write");

    let accepted = server.await.expect("join").expect("accepted");
    assert_eq!(accepted.mode, ClientMode::HttpConnect);
    assert_eq!(accepted.authority.host(), "149.154.167.51");
    assert_eq!(accepted.rest, b"\x16\x03\x01early", "bytes sent before the 200 are already tunnel payload");

    let mut reply = vec![0u8; 39];
    client.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply, b"HTTP/1.1 200 Connection established\r\n\r\n");
}

#[tokio::test]
async fn a_non_connect_method_gets_501() {
    let (mut client, server) = pair(TEST_LIMITS).await;
    client.write_all(b"POST http://x.example/ HTTP/1.1\r\n\r\n").await.expect("write");

    match server.await.expect("join") {
        Err(Rejected::Http(nova_tgrelay::http::Refusal::NotConnect { method })) => {
            assert_eq!(method, "POST");
        }
        other => panic!("expected NotConnect, got {other:?}", other = other.map(|_| "accepted")),
    }

    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.expect("reply");
    assert!(
        String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 501 "),
        "got {:?}",
        String::from_utf8_lossy(&reply)
    );
}

#[tokio::test]
async fn g21_a_binary_first_byte_is_refused_at_once_not_after_the_deadline() {
    let (mut client, server) = pair(TEST_LIMITS).await;
    let started = Instant::now();
    client.write_all(&[0xFE]).await.expect("write");

    match server.await.expect("join") {
        Err(Rejected::UnsupportedProtocol { first_byte }) => assert_eq!(first_byte, 0xFE),
        other => panic!("expected UnsupportedProtocol, got {:?}", other.map(|_| "accepted")),
    }
    let elapsed = started.elapsed();
    assert!(elapsed < TEST_LIMITS.total_deadline, "refusal must not wait for the deadline, took {elapsed:?}");

    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.expect("reply");
    assert_eq!(reply, b"\x05\xff", "the client must be told, not just dropped");
}

#[tokio::test]
async fn a_socks_client_that_stalls_mid_handshake_is_refused_within_the_budget() {
    let (mut client, server) = pair(TEST_LIMITS).await;
    let started = Instant::now();
    client.write_all(&[0x05, 0x01, 0x00]).await.expect("write");

    // Greeting accepted, request never sent. Hold the socket open.
    match server.await.expect("join") {
        Err(Rejected::Socks(nova_tgrelay::socks::Refusal::Timeout)) => {}
        other => panic!("expected Socks timeout, got {:?}", other.map(|_| "accepted")),
    }
    let elapsed = started.elapsed();
    assert!(elapsed < TEST_LIMITS.total_deadline * 4, "took {elapsed:?}, budget {:?}", TEST_LIMITS.total_deadline);

    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.expect("reply");
    assert!(reply.ends_with(b"\x05\xff"), "got {reply:?}");
}

#[tokio::test]
async fn an_http_client_that_dribbles_is_refused_with_408() {
    let (mut client, server) = pair(TEST_LIMITS).await;
    let writer = tokio::spawn(async move {
        // Three bytes with gaps, then silence. Each gap is far shorter than any
        // per-read timeout would be, so the old shape would still be waiting;
        // the total budget expires anyway. That is the whole of G22.
        //
        // The client must stop writing before the server gives up. A server that
        // closes while unread bytes are still arriving makes the kernel send RST,
        // and an RST discards the reply already sitting in the client's receive
        // buffer — so "the client got our 408" would be untestable, through no
        // fault of the code.
        for byte in b"CON" {
            if client.write_all(&[*byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        let mut reply = Vec::new();
        let _ = client.read_to_end(&mut reply).await;
        reply
    });

    match server.await.expect("join") {
        Err(Rejected::Http(nova_tgrelay::http::Refusal::Timeout)) => {}
        other => panic!("expected Http timeout, got {:?}", other.map(|_| "accepted")),
    }
    let reply = writer.await.expect("writer");
    assert!(
        String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 408 "),
        "got {:?}",
        String::from_utf8_lossy(&reply)
    );
}

#[tokio::test]
async fn a_client_that_says_nothing_and_closes_is_reported_as_closed() {
    let (client, server) = pair(TEST_LIMITS).await;
    drop(client);

    match server.await.expect("join") {
        Err(Rejected::PeerClosed) => {}
        other => panic!("expected PeerClosed, got {:?}", other.map(|_| "accepted")),
    }
}

#[tokio::test]
async fn socks_port_zero_is_refused_before_the_success_reply() {
    // Deliberate deviation from the Python, which hands port 0 back to its
    // caller. Telling a client its tunnel is open and only then finding the
    // target unusable would leave it waiting on nobody.
    let (mut client, server) = pair(TEST_LIMITS).await;
    client.write_all(&socks_request(b"a.example", 0)).await.expect("write");

    match server.await.expect("join") {
        Err(Rejected::Socks(nova_tgrelay::socks::Refusal::InvalidTarget)) => {}
        other => panic!("expected InvalidTarget, got {:?}", other.map(|_| "accepted")),
    }

    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.expect("reply");
    assert!(
        !reply.windows(8).any(|w| w == b"\x05\x00\x00\x01\x7f\x00\x00\x01"),
        "the success reply must not have been sent, got {reply:?}"
    );
}
