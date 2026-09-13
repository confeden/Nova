//! The WSS half, composed: DC → SNI → token → upgrade → terminator → tunnel.
//!
//! The TCP half is put together in `relay_end_to_end.rs`. This is the other one,
//! and it touches the layers that only exist because Cloudflare is in the middle:
//! which data centre the target belongs to, what name goes in the clear, the
//! signature the Worker checks, the upgrade request, the terminator that performs
//! the TLS, and the framing that follows.
//!
//! One fake plays both parts the relay talks to, because in production they are
//! the same socket: the terminator answers, and from that moment the same
//! connection is the tunnel to the Worker. Nothing here is stubbed except the
//! far end of the wire.

use nova_tgrelay::cfdomains::CfDomainHealth;
use nova_tgrelay::dc::{likely_media_target, preferred_ws_target, target_dc_hint};
use nova_tgrelay::egress::{Egress, ProxyProtocol};
use nova_tgrelay::persona::{
    judge, parse_response, upgrade_request, ws_key, FixedWsKey, UpgradeVerdict, DEFAULT_ORIGIN,
    DEFAULT_PERSONA,
};
use nova_tgrelay::sni::NeutralSni;
use nova_tgrelay::wsbridge::{NoSplit, WsBridgeObserver};
use nova_tgrelay::wsframe::{build_frame, FixedMask, Opcode};
use nova_tgrelay::wss::cf_domains;
use nova_tgrelay::Authority;
use nova_tgrelay_net::cf_token::subprotocol_header;
use nova_tgrelay_net::terminator::{open_shaped_stream, TerminatorConfig};
use nova_tgrelay_net::upgrade::{check_accept, expected_accept};
use nova_tgrelay_net::wsbridge::{bridge_ws, WsBridgeOptions};
use nova_tgrelay_net::wsconn::WsConnection;
use std::time::{Duration, Instant};
use tokio::io::{duplex, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const OWNED_BASE: &str = "nova-app.eu";
const SECRET: &[u8] = b"nova-public-fallback";
const NOW: u64 = 1_700_000_000;

struct Silent;
impl WsBridgeObserver for Silent {}

/// What the fake helper saw, so the test can assert on the whole exchange.
#[derive(Debug)]
struct Seen {
    terminator_request: serde_json::Value,
    upgrade: String,
}

/// A helper that answers as the terminator and then as the Worker.
async fn helper(accept_for: String) -> (u16, tokio::task::JoinHandle<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        let mut sock = BufReader::new(sock);

        // --- as the terminator -------------------------------------------
        sock.get_mut().write_all(b"{\"nova\":\"tls-terminator/1\"}\n").await.expect("greeting");
        let mut line = String::new();
        sock.read_line(&mut line).await.expect("request");
        let terminator_request: serde_json::Value = serde_json::from_str(line.trim_end()).expect("json");
        sock.get_mut()
            .write_all(b"{\"ok\":true,\"reached\":4,\"ended\":0,\"alpn\":\"http/1.1\"}\n")
            .await
            .expect("reply");

        // --- from here the same socket is the tunnel ----------------------
        let mut upgrade = Vec::new();
        let mut chunk = [0u8; 1024];
        while !upgrade.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock.read(&mut chunk).await.expect("read upgrade");
            assert_ne!(n, 0, "the client closed mid-upgrade");
            upgrade.extend_from_slice(&chunk[..n]);
        }
        let reply = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept_for}\r\nSec-WebSocket-Protocol: binary\r\n\r\n"
        );
        sock.get_mut().write_all(reply.as_bytes()).await.expect("101");

        // --- and then a WebSocket ----------------------------------------
        let mut frame = [0u8; 64];
        let n = sock.read(&mut frame).await.expect("frame");
        assert!(n > 0);
        sock.get_mut().write_all(&build_frame(Opcode::Binary, b"resPQ", None)).await.expect("answer");
        // Hold the socket open until the client is done with it.
        tokio::time::sleep(Duration::from_millis(200)).await;

        Seen { terminator_request, upgrade: String::from_utf8(upgrade).expect("ascii") }
    });
    (port, task)
}

#[tokio::test]
async fn a_telegram_address_reaches_a_worker_through_every_wss_layer() {
    let now = Instant::now();

    // 1. Which data centre is this, and is it media? (layer 20)
    let target_ip = "149.154.167.51";
    let dc = target_dc_hint(target_ip, false);
    assert_eq!(dc.map(nova_tgrelay::egress::Dc::get), Some(2));
    assert!(!likely_media_target(target_ip, 443, dc));
    // DC2 always terminates on .220.
    assert_eq!(preferred_ws_target(target_ip, dc, false), "149.154.167.220");

    // 2. Which Worker hostname carries it? (layer 6, ordered by layer 8)
    let domains = cf_domains(dc.expect("dc"), &[OWNED_BASE], false);
    assert_eq!(domains, ["kws2.nova-app.eu"]);
    let ordered = CfDomainHealth::new().order(&domains, None, now);
    let domain = ordered.first().expect("a candidate").clone();

    // 3. What name travels in the clear? (layer 14)
    let mut sni = NeutralSni::new();
    let offered = sni.sni_for(&domain, Some(OWNED_BASE), now);
    assert_eq!(offered, "www.nova-app.eu", "the route stays in Host, not in the SNI");

    // 4. The signature the Worker checks. (layer 16)
    let subprotocol = subprotocol_header(&domain, NOW, SECRET, true);
    assert!(subprotocol.starts_with("binary, nova1."));

    // 5. Open the shaped tunnel through the terminator. (layer 15)
    let key = ws_key(&mut FixedWsKey([7u8; 16]));
    let (port, served) = helper(expected_accept(&key)).await;
    let egress = Egress::proxy(ProxyProtocol::Socks5, "warp-socks", Authority::new("127.0.0.1", 1370).unwrap());
    let config = TerminatorConfig {
        port,
        token: "s3cret".to_string(),
        profile: Some(DEFAULT_PERSONA.name.to_string()),
        verify: false,
    };
    let target = Authority::new("149.154.167.220", 443).expect("target");
    let shaped =
        open_shaped_stream(&target, &offered, &[egress], &config, Duration::from_secs(5)).await.expect("shaped");
    assert_eq!(shaped.label, "warp-socks");
    assert!(shaped.leftover.is_empty());

    // 6. The upgrade request. (layer 13)
    let mut stream = shaped.stream;
    let request = upgrade_request("/apiws", &domain, &key, &subprotocol, DEFAULT_ORIGIN, true, DEFAULT_PERSONA);
    stream.write_all(&request).await.expect("upgrade");

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut byte).await.expect("read reply");
        assert_ne!(n, 0, "the helper closed mid-reply");
        head.push(byte[0]);
    }
    let text = String::from_utf8(head).expect("ascii");
    let lines: Vec<&str> = text.trim_end().split("\r\n").collect();
    let response = parse_response(&lines);
    assert_eq!(judge(&response), UpgradeVerdict::Accepted);
    // The check the Python does not do: did the peer actually perform the
    // handshake, or merely answer 101?
    assert!(check_accept(&response, &key).is_correct());

    // 7. Carry a tunnel over it. (layers 9 and 10)
    let (mut client_far, mut client_near) = duplex(64 * 1024);
    let ws = WsConnection::with_mask_source(stream, FixedMask([1, 2, 3, 4]));
    let (reader, writer) = ws.split();
    let bridge = async {
        bridge_ws(&mut client_near, reader, writer, NoSplit, WsBridgeOptions::default(), &mut Silent).await
    };
    let script = async {
        client_far.write_all(b"req_pq").await.expect("write");
        let mut back = [0u8; 5];
        client_far.read_exact(&mut back).await.expect("read");
        assert_eq!(&back, b"resPQ");
        drop(client_far);
    };
    let (outcome, ()) = tokio::join!(bridge, script);
    assert_eq!(outcome.up, 6);
    assert_eq!(outcome.down, 5);
    assert!(!outcome.first_down_timed_out);

    // And what the far end saw, checked once at the end.
    let seen = served.await.expect("join");
    assert_eq!(seen.terminator_request["sni"], "www.nova-app.eu");
    assert_eq!(seen.terminator_request["target"]["host"], "149.154.167.220");
    assert_eq!(seen.terminator_request["profile"], "yandex-windows");
    assert!(
        seen.upgrade.contains("Host: kws2.nova-app.eu\r\n"),
        "the route travels in Host while the SNI says www: {}",
        seen.upgrade
    );
    assert!(seen.upgrade.contains(&format!("Sec-WebSocket-Protocol: {subprotocol}\r\n")));
    assert!(seen.upgrade.contains("Sec-WebSocket-Extensions: permessage-deflate"));
}

#[tokio::test]
async fn a_worker_that_answers_101_without_doing_the_handshake_is_detected() {
    // The gap the shipped relay has: anything answering `101` is framed against.
    // Here the peer returns an `Accept` derived from somebody else's key.
    let key = ws_key(&mut FixedWsKey([7u8; 16]));
    let wrong = expected_accept("AAAAAAAAAAAAAAAAAAAAAA==");
    assert_ne!(wrong, expected_accept(&key));

    let response = parse_response(&[
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        &format!("Sec-WebSocket-Accept: {wrong}"),
    ]);
    // The relay's own verdict says yes…
    assert_eq!(judge(&response), UpgradeVerdict::Accepted);
    // …and the check the port adds says no, with both values in the complaint.
    let check = check_accept(&response, &key);
    assert!(!check.is_correct());
    assert!(check.complaint().expect("a complaint").contains(&wrong));
}
