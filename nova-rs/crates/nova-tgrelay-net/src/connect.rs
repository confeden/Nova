//! Layer 26: raising one WSS connection, from an address to a framed tunnel.
//!
//! The port of `_connect_websocket_once` (`transparent_relay.py:1158`). Its
//! pieces have all been ported for a while — the terminator (15), the neutral
//! SNI (14), the Worker token (16), the persona and the upgrade request (13),
//! the framing (9) — but only `tests/wss_path_end_to_end.rs` ever put them
//! together, so there was nothing an egress walk could actually call. This is
//! that callable piece, and [`attempt::connect_first_working`] is what calls it.
//!
//! Three deliberate differences from the Python, all of them rules this
//! codebase has already paid for once:
//!
//! 1. **One deadline for the whole reply, not one per line.** The Python does
//!    `asyncio.wait_for(reader.readline(), timeout=timeout)` inside its read
//!    loop, and a per-operation timeout bounds nothing: a peer that sends one
//!    header line just inside the budget holds the attempt open indefinitely.
//!    That is **G22 for the third time** — after the SOCKS handshake (S27) and
//!    the CONNECT reply in [`crate::dial`] — and the shape is identical every
//!    time. On the non-media path the budget is 7 s per attempt and there is no
//!    total ceiling above it, so the stall is unbounded rather than merely long.
//! 2. **The reply head is capped.** `response_lines` grows until a blank line
//!    arrives; a peer that streams headers forever is an allocation the far side
//!    controls. The same hole, and the same fix, as the frame-length cap in
//!    `tgrelay/raw_websocket.py`.
//! 3. **`since_hello_ms` is not invented.** The Python measures it from *before*
//!    `open_tls_stream` — DNS, TCP and the proxy handshake included — directly
//!    under a comment saying it is timed to exclude them. Here the ClientHello
//!    is written by another process entirely and the helper reports no duration,
//!    so the honest answer is `None`. Nothing is lost: the only two signatures
//!    that read the field are `rst_immediate` and `rst_after_server_hello`, and
//!    every consumer in the relay treats them identically.
//!
//! **The `Sec-WebSocket-Accept` check is performed and reported, not enforced** —
//! see [`crate::upgrade`] for why that decision is the caller's.

use crate::attempt::Failure;
use crate::terminator::{open_shaped_stream, TerminatorConfig, TerminatorError};
use crate::upgrade::{check_accept, AcceptCheck};
use nova_probe::{Ended, Reached};
use nova_tgrelay::egress::Egress;
use nova_tgrelay::persona::{
    judge, parse_response, upgrade_request, ws_key, Persona, UpgradeResponse, UpgradeVerdict, WsKeySource,
    DEFAULT_ORIGIN, DEFAULT_PERSONA,
};
use nova_tgrelay::Authority;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Duration, Instant};

/// The most the upgrade reply may be before it is treated as an attack rather
/// than a header block.
///
/// A real one is a few hundred bytes; Cloudflare's is under one KiB. 64 KiB is
/// far past anything legitimate and far short of anything that matters.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;

/// The `Sec-WebSocket-Key` source a real client uses.
///
/// RFC 6455 wants sixteen random bytes and browsers send exactly that. The
/// Python used to pack a millisecond clock and a performance counter here, which
/// is both guessable and a pattern that repeats across every connection Nova
/// opens — the opposite of what the field is for.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsWsKey;

impl WsKeySource for OsWsKey {
    fn next_key(&mut self) -> [u8; 16] {
        let mut key = [0u8; 16];
        getrandom::fill(&mut key).expect("the OS random source is unavailable");
        key
    }
}

/// One Worker candidate: where to connect, what to ask for, and under what name.
#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    /// The address TLS is made to. On the Telegram-Web path this is the DC's
    /// redirect IP; on the Cloudflare path it is the domain's own address.
    pub target: &'a Authority,
    /// The route. It travels in `Host` and **not** in the SNI — that split is
    /// the whole point of layer 14, and it is what decides which Worker answers.
    pub domain: &'a str,
    /// What goes on the wire in the clear.
    ///
    /// Passed in rather than derived: the neutral-SNI table carries a per-zone
    /// verdict history and a retirement clock, and this function is called once
    /// per attempt from inside a race.
    pub sni: &'a str,
    /// `Sec-WebSocket-Protocol`, the Worker's handshake signature included.
    pub subprotocol: &'a str,
    pub path: &'a str,
    pub origin: &'a str,
    /// Whether to offer `permessage-deflate`. Withdrawn per endpoint once one
    /// has been seen to accept it — nothing downstream can inflate a frame.
    pub offer_deflate: bool,
    pub persona: Persona,
}

impl<'a> Candidate<'a> {
    /// The shape every caller in the relay uses: `/apiws`, Telegram Web's
    /// origin, the default persona.
    pub fn new(target: &'a Authority, domain: &'a str, sni: &'a str, subprotocol: &'a str) -> Self {
        Self {
            target,
            domain,
            sni,
            subprotocol,
            path: "/apiws",
            origin: DEFAULT_ORIGIN,
            offer_deflate: true,
            persona: DEFAULT_PERSONA,
        }
    }

    pub fn without_deflate(mut self) -> Self {
        self.offer_deflate = false;
        self
    }
}

/// An upgraded WebSocket, before any framing has been read off it.
#[derive(Debug)]
pub struct Tunnel {
    pub stream: TcpStream,
    /// The egress label the *relay* chose — what the health tables are keyed by
    /// and what the `via` field of every WSS log line says.
    pub label: String,
    pub response: UpgradeResponse,
    /// Whether the peer proved it performed the handshake. Reported, not
    /// enforced; the shipped relay does not look at this at all.
    pub accept: AcceptCheck,
    /// Bytes that arrived after the header block and belong to the tunnel.
    ///
    /// Usually empty — this side speaks first — but the reply is read in chunks,
    /// so dropping the tail would lose the first frame of a peer that answers
    /// immediately. The caller must feed these to the framing before reading the
    /// socket, exactly as with [`crate::dial::Dialled::leftover`].
    pub leftover: Vec<u8>,
}

/// Open one candidate and take it as far as an upgraded WebSocket.
///
/// `budget` covers everything: the egress walk inside the terminator, its TLS
/// handshake, and the upgrade round trip.
pub async fn connect_once(
    candidate: &Candidate<'_>,
    egresses: &[Egress],
    config: &TerminatorConfig,
    budget: Duration,
    key_source: &mut impl WsKeySource,
) -> Result<Tunnel, Failure> {
    let deadline = Instant::now() + budget;

    let shaped = open_shaped_stream(candidate.target, candidate.sni, egresses, config, budget)
        .await
        .map_err(failure_from_terminator)?;
    let mut stream = shaped.stream;
    let label = shaped.label;

    // From here the handshake is a settled question: the far side read our
    // ClientHello and agreed to speak. Everything below is charged to
    // `HandshakeDone` for that reason, which is what makes it a *credit* to the
    // egress rather than a penalty — see `attempt::charge`.
    let key = ws_key(key_source);
    let request = upgrade_request(
        candidate.path,
        candidate.domain,
        &key,
        candidate.subprotocol,
        candidate.origin,
        candidate.offer_deflate,
        candidate.persona,
    );
    write_all_by(&mut stream, &request, deadline).await.map_err(after_handshake)?;

    let (head, leftover) = read_head(&mut stream, &shaped.leftover, deadline).await.map_err(after_handshake)?;
    let text = String::from_utf8_lossy(&head);
    let lines: Vec<&str> = text.trim_end_matches("\r\n\r\n").split("\r\n").filter(|l| !l.is_empty()).collect();
    let response = parse_response(&lines);

    match judge(&response) {
        UpgradeVerdict::Accepted => {}
        // "The peer sent nothing" is the empty close the live log is full of.
        // It is *not* an HTTP status: the Python spells it
        // `WsHandshakeError(0, "empty response")`, and taking it for a status
        // would credit a silent egress and end the walk.
        UpgradeVerdict::Empty => return Err(Failure::new(Reached::HandshakeDone, Ended::Closed)),
        UpgradeVerdict::Refused { status, .. } => {
            return Err(Failure::new(Reached::HandshakeDone, Ended::HttpStatus { code: status }));
        }
        // A `101` that negotiated compression is worse than a refusal: every
        // frame from here on arrives deflated and nothing downstream can inflate
        // it. Fail the attempt; the caller withdraws the offer for this endpoint
        // so the retry goes out without it.
        UpgradeVerdict::DeflateNegotiated => return Err(Failure::new(Reached::HandshakeDone, Ended::Closed)),
    }

    Ok(Tunnel { stream, label, accept: check_accept(&response, &key), response, leftover })
}

/// Whether this failure means the endpoint must be re-tried without the
/// compression offer.
///
/// The Python calls `note_deflate_unusable(domain)` inline; here the caller owns
/// that set, so the fact has to travel back out. Distinguishable from a plain
/// silent peer only through the response, which is why it is answered here
/// rather than reconstructed from a [`Failure`].
pub fn deflate_was_negotiated(response: &UpgradeResponse) -> bool {
    matches!(judge(response), UpgradeVerdict::DeflateNegotiated)
}

/// Everything past the TLS handshake is charged to `HandshakeDone`.
fn after_handshake(error: io::Error) -> Failure {
    Failure::new(Reached::HandshakeDone, ended_from_io(&error))
}

fn failure_from_terminator(error: TerminatorError) -> Failure {
    let ended = match &error {
        // `Reached::Nothing` + `Ended::Closed` is what the Python tags this
        // with, and it is deliberate: a helper that died says nothing about the
        // route, so nothing may be charged for it.
        TerminatorError::NoEgress => Ended::Closed,
        TerminatorError::Helper(e) => ended_from_io(e),
        TerminatorError::Refused { ended, .. } => ended_from_wire(*ended),
    };
    Failure::new(error.reached(), ended)
}

/// The helper's numbers are `phase.Ended`'s, verbatim.
fn ended_from_wire(value: u8) -> Ended {
    match value {
        1 => Ended::Timeout,
        2 => Ended::Reset,
        3 => Ended::Refused,
        5 => Ended::CertificateMismatch,
        7 => Ended::ResolverStub,
        // `6` is `HTTP_STATUS`, which the helper cannot produce — it performs a
        // TLS handshake and never reads an HTTP reply. `0` is `OK`, which is not
        // a failure. Both land on the same default the Python's
        // `ended_from_exception` uses for anything it cannot place.
        _ => Ended::Closed,
    }
}

/// `phase.ended_from_exception`'s `OSError` branch, in `io::ErrorKind` terms.
fn ended_from_io(error: &io::Error) -> Ended {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => Ended::Refused,
        io::ErrorKind::ConnectionReset => Ended::Reset,
        io::ErrorKind::TimedOut => Ended::Timeout,
        _ => Ended::Closed,
    }
}

async fn write_all_by(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    timeout_at(deadline, stream.write_all(bytes)).await.map_err(|_| timed_out("upgrade request"))?
}

/// Read until the blank line that ends the header block.
///
/// Returns the head and whatever came after it. `carried` is what the terminator
/// had already taken off the socket — dropping it here would lose the first
/// bytes of a peer that answers before we finish writing.
async fn read_head(stream: &mut TcpStream, carried: &[u8], deadline: Instant) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buffer = carried.to_vec();
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(at) = find_end(&buffer) {
            let rest = buffer.split_off(at + 4);
            return Ok((buffer, rest));
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return Err(io::Error::other(format!("upgrade reply exceeds {MAX_HEAD_BYTES} bytes")));
        }
        // One deadline for the whole block. Renewing it per read is the bug
        // named at the top of this file.
        let read = timeout_at(deadline, stream.read(&mut chunk)).await.map_err(|_| timed_out("upgrade reply"))?;
        match read? {
            // A clean close with nothing in hand is the "empty response" case;
            // one *mid*-header is a truncated reply, and both are answered the
            // same way by `judge`, which sees no status line.
            0 => return Ok((std::mem::take(&mut buffer), Vec::new())),
            n => buffer.extend_from_slice(&chunk[..n]),
        }
    }
}

fn find_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{what} did not complete within the budget"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_tgrelay::egress::ProxyProtocol;
    use nova_tgrelay::persona::FixedWsKey;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;

    /// A helper that answers as the terminator and then as the Worker, which is
    /// what happens in production: the same socket becomes the tunnel.
    async fn helper(reply: &'static str, tail: &'static [u8]) -> (u16, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let task = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            let mut sock = BufReader::new(sock);
            sock.get_mut().write_all(b"{\"nova\":\"tls-terminator/1\"}\n").await.expect("greeting");
            let mut line = String::new();
            sock.read_line(&mut line).await.expect("request");
            sock.get_mut()
                .write_all(b"{\"ok\":true,\"reached\":4,\"ended\":0,\"alpn\":\"http/1.1\"}\n")
                .await
                .expect("reply");

            let mut upgrade = Vec::new();
            let mut chunk = [0u8; 1024];
            while !upgrade.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut chunk).await.expect("read upgrade");
                if n == 0 {
                    break;
                }
                upgrade.extend_from_slice(&chunk[..n]);
            }
            // One write, on purpose: the point of the leftover test is a peer
            // whose first frame shares a segment with the header block, and two
            // writes would let the reader see the head on its own.
            let mut out = reply.as_bytes().to_vec();
            out.extend_from_slice(tail);
            if !out.is_empty() {
                sock.get_mut().write_all(&out).await.expect("write reply");
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
            String::from_utf8_lossy(&upgrade).into_owned()
        });
        (port, task)
    }

    fn config(port: u16) -> TerminatorConfig {
        TerminatorConfig { port, token: "s3cret".to_string(), profile: None, verify: false }
    }

    fn egresses() -> Vec<Egress> {
        vec![Egress::proxy(
            ProxyProtocol::Socks5,
            "warp-socks",
            Authority::new("127.0.0.1", 1370).expect("authority"),
        )]
    }

    fn accepted_reply(key: &str) -> String {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
            crate::upgrade::expected_accept(key)
        )
    }

    #[tokio::test]
    async fn a_hundred_and_one_yields_a_tunnel_with_the_route_in_host_and_www_in_the_sni() {
        let mut source = FixedWsKey([7u8; 16]);
        let key = ws_key(&mut source);
        let reply: &'static str = Box::leak(accepted_reply(&key).into_boxed_str());
        let (port, served) = helper(reply, b"").await;

        let target = Authority::new("149.154.167.220", 443).expect("target");
        let candidate = Candidate::new(&target, "kws2.nova-app.eu", "www.nova-app.eu", "binary, nova1.abc");
        let tunnel = connect_once(
            &candidate,
            &egresses(),
            &config(port),
            Duration::from_secs(5),
            &mut FixedWsKey([7u8; 16]),
        )
        .await
        .expect("the upgrade was accepted");

        assert_eq!(tunnel.label, "warp-socks");
        assert_eq!(tunnel.response.status, 101);
        assert!(tunnel.accept.is_correct());
        assert!(tunnel.leftover.is_empty());

        let seen = served.await.expect("join");
        assert!(seen.contains("Host: kws2.nova-app.eu\r\n"), "{seen}");
        assert!(seen.contains("Sec-WebSocket-Protocol: binary, nova1.abc\r\n"), "{seen}");
    }

    #[tokio::test]
    async fn bytes_that_arrive_behind_the_header_block_are_handed_back_and_not_dropped() {
        // The peer that answers `101` and its first frame in one write. Reading
        // the head in chunks takes those bytes off the socket, and losing them
        // costs the tunnel its first message with no error anywhere.
        let mut source = FixedWsKey([7u8; 16]);
        let key = ws_key(&mut source);
        let reply: &'static str = Box::leak(accepted_reply(&key).into_boxed_str());
        let (port, _served) = helper(reply, b"\x82\x05hello").await;

        let target = Authority::new("149.154.167.220", 443).expect("target");
        let candidate = Candidate::new(&target, "kws2.nova-app.eu", "www.nova-app.eu", "binary");
        let tunnel = connect_once(
            &candidate,
            &egresses(),
            &config(port),
            Duration::from_secs(5),
            &mut FixedWsKey([7u8; 16]),
        )
        .await
        .expect("upgraded");
        assert_eq!(tunnel.leftover, b"\x82\x05hello", "the first frame survives the head read");
    }

    #[tokio::test]
    async fn a_peer_that_says_nothing_is_a_closed_handshake_and_not_a_status() {
        let (port, _served) = helper("", b"").await;
        let target = Authority::new("149.154.167.220", 443).expect("target");
        let candidate = Candidate::new(&target, "kws2.nova-app.eu", "www.nova-app.eu", "binary");
        let failure = connect_once(
            &candidate,
            &egresses(),
            &config(port),
            Duration::from_secs(5),
            &mut FixedWsKey([7u8; 16]),
        )
        .await
        .expect_err("nothing came back");

        assert_eq!(failure, Failure::new(Reached::HandshakeDone, Ended::Closed));
        assert_eq!(failure.http_status(), None, "an empty close must not read as a refusal");
        // And therefore the egress that carried the handshake is credited.
        assert_eq!(crate::attempt::charge(&failure), crate::attempt::Charge::Credit);
    }

    #[tokio::test]
    async fn a_refusal_carries_its_status_out_so_the_walk_can_stop() {
        let (port, _served) = helper("HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\n", b"").await;
        let target = Authority::new("149.154.167.220", 443).expect("target");
        let candidate = Candidate::new(&target, "kws2.nova-app.eu", "www.nova-app.eu", "binary");
        let failure = connect_once(
            &candidate,
            &egresses(),
            &config(port),
            Duration::from_secs(5),
            &mut FixedWsKey([7u8; 16]),
        )
        .await
        .expect_err("403 is not a tunnel");

        assert_eq!(failure.http_status(), Some(403));
        assert_eq!(crate::attempt::charge(&failure), crate::attempt::Charge::Refused);
    }

    #[tokio::test]
    async fn a_hundred_and_one_that_negotiated_compression_fails_rather_than_carrying_bytes_we_cannot_read() {
        let mut source = FixedWsKey([7u8; 16]);
        let key = ws_key(&mut source);
        let reply: &'static str = Box::leak(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
                crate::upgrade::expected_accept(&key)
            )
            .into_boxed_str(),
        );
        let (port, _served) = helper(reply, b"").await;

        let target = Authority::new("149.154.167.220", 443).expect("target");
        let candidate = Candidate::new(&target, "kws2.nova-app.eu", "www.nova-app.eu", "binary");
        let failure = connect_once(
            &candidate,
            &egresses(),
            &config(port),
            Duration::from_secs(5),
            &mut FixedWsKey([7u8; 16]),
        )
        .await
        .expect_err("a deflated tunnel is unreadable");
        assert_eq!(failure, Failure::new(Reached::HandshakeDone, Ended::Closed));
    }

    #[tokio::test]
    async fn a_peer_dribbling_header_lines_runs_out_of_budget_instead_of_forever() {
        // The G22 shape: with a per-line timeout this attempt never ends. The
        // helper sends one header every 120 ms and never the blank line.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            let mut sock = BufReader::new(sock);
            sock.get_mut().write_all(b"{\"nova\":\"tls-terminator/1\"}\n").await.expect("greeting");
            let mut line = String::new();
            sock.read_line(&mut line).await.expect("request");
            sock.get_mut().write_all(b"{\"ok\":true,\"reached\":4,\"ended\":0}\n").await.expect("reply");
            let mut chunk = [0u8; 1024];
            let _ = sock.read(&mut chunk).await;
            sock.get_mut().write_all(b"HTTP/1.1 101 Switching Protocols\r\n").await.expect("status");
            for i in 0..100u32 {
                if sock.get_mut().write_all(format!("X-Pad-{i}: keep-alive\r\n").as_bytes()).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
        });

        let target = Authority::new("149.154.167.220", 443).expect("target");
        let candidate = Candidate::new(&target, "kws2.nova-app.eu", "www.nova-app.eu", "binary");
        let started = Instant::now();
        let failure = connect_once(
            &candidate,
            &egresses(),
            &config(port),
            Duration::from_millis(600),
            &mut FixedWsKey([7u8; 16]),
        )
        .await
        .expect_err("the budget ran out");

        assert_eq!(failure, Failure::new(Reached::HandshakeDone, Ended::Timeout));
        assert!(started.elapsed() < Duration::from_secs(3), "the deadline bounded the whole reply, not one read");
    }

    #[tokio::test]
    async fn a_header_block_that_never_ends_is_capped_rather_than_allocated() {
        // The peer chooses the size here, which is the same hole the frame-length
        // cap closed one layer down. Sent fast so the cap is what fires and not
        // the deadline.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            let mut sock = BufReader::new(sock);
            sock.get_mut().write_all(b"{\"nova\":\"tls-terminator/1\"}\n").await.expect("greeting");
            let mut line = String::new();
            sock.read_line(&mut line).await.expect("request");
            sock.get_mut().write_all(b"{\"ok\":true,\"reached\":4,\"ended\":0}\n").await.expect("reply");
            let mut chunk = [0u8; 1024];
            let _ = sock.read(&mut chunk).await;
            let mut flood = b"HTTP/1.1 101 Switching Protocols\r\n".to_vec();
            while flood.len() < MAX_HEAD_BYTES * 2 {
                flood.extend_from_slice(b"X-Pad: keep-going\r\n");
            }
            let _ = sock.get_mut().write_all(&flood).await;
        });

        let target = Authority::new("149.154.167.220", 443).expect("target");
        let candidate = Candidate::new(&target, "kws2.nova-app.eu", "www.nova-app.eu", "binary");
        let failure = connect_once(
            &candidate,
            &egresses(),
            &config(port),
            Duration::from_secs(10),
            &mut FixedWsKey([7u8; 16]),
        )
        .await
        .expect_err("a header block this size is not a reply");
        assert_eq!(failure, Failure::new(Reached::HandshakeDone, Ended::Closed));
    }

    #[tokio::test]
    async fn bytes_the_terminator_already_took_off_the_socket_start_the_head() {
        // The helper answers `101` before it has read the upgrade request, so
        // the terminator's own `BufReader` swallows the first bytes of the reply
        // while looking for the end of the JSON line. Losing those would leave
        // the head unparseable for a reason nothing logs.
        let mut source = FixedWsKey([7u8; 16]);
        let key = ws_key(&mut source);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let reply = accepted_reply(&key);
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            let mut sock = BufReader::new(sock);
            sock.get_mut().write_all(b"{\"nova\":\"tls-terminator/1\"}\n").await.expect("greeting");
            let mut line = String::new();
            sock.read_line(&mut line).await.expect("request");
            let mut out = b"{\"ok\":true,\"reached\":4,\"ended\":0}\n".to_vec();
            out.extend_from_slice(reply.as_bytes());
            sock.get_mut().write_all(&out).await.expect("reply and 101 together");
            tokio::time::sleep(Duration::from_millis(150)).await;
        });

        let target = Authority::new("149.154.167.220", 443).expect("target");
        let candidate = Candidate::new(&target, "kws2.nova-app.eu", "www.nova-app.eu", "binary");
        let tunnel = connect_once(
            &candidate,
            &egresses(),
            &config(port),
            Duration::from_secs(5),
            &mut FixedWsKey([7u8; 16]),
        )
        .await
        .expect("the 101 was already in the terminator's buffer");
        assert_eq!(tunnel.response.status, 101);
    }

    #[test]
    fn a_random_key_is_sixteen_bytes_and_does_not_repeat() {
        let mut source = OsWsKey;
        let first = ws_key(&mut source);
        let second = ws_key(&mut source);
        assert_eq!(first.len(), 24, "sixteen bytes, base64'd with padding");
        assert_ne!(first, second, "a key that repeats is the pattern the field exists to prevent");
    }
}
