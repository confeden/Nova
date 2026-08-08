//! A local service that performs the TLS handshake the relay cannot.
//!
//! The Python relay's outbound TLS is CPython's OpenSSL, whose ClientHello
//! matches no browser on any desktop. This process does the handshake instead,
//! in the shape of a captured browser profile, and hands the relay a plaintext
//! stream over loopback.
//!
//! Two decisions are worth stating, because both were arrived at by measuring
//! rather than by preference.
//!
//! **The egress chain moves here, not the shape alone.** The relay reaches its
//! destinations directly, through a SOCKS5 tunnel, or through an HTTP proxy,
//! with a different timeout for each. Splitting that across the boundary — dial
//! in Python, hand over the socket — needs a duplicated Windows socket handle
//! and unsafe code. Re-implementing three small client protocols here costs
//! less and keeps every failure on one side of the line.
//!
//! **The phase is reported, never inferred.** `tgrelay/phase.py` decides which
//! layer to blame by looking at the Python exception type — `ssl.SSLError`,
//! `ConnectionResetError`, a Windows error code. None of those can occur once
//! the socket Python holds is a loopback hop: every failure would arrive as a
//! plain EOF and collapse to one verdict, and that verdict happens to be the
//! one that rotates the TLS profile and retires the zone's neutral SNI for
//! fifteen minutes. So the reply below carries `reached` and `ended` as
//! explicit numbers, using the same values as `phase.Reached` and
//! `phase.Ended`.
//!
//! Wire protocol, one connection per tunnel:
//!
//! ```text
//! S->C  {"nova":"tls-terminator/1"}
//! C->S  {"token":"…","target":{"host":"…","port":443},"egress":{…},
//!        "sni":"…","profile":"yandex-windows",
//!        "connect_timeout_ms":1600,"handshake_timeout_ms":8000}
//! S->C  {"ok":true,"reached":4,"ended":0,"alpn":"http/1.1"}
//!       {"ok":false,"reached":1,"ended":3,"error":"connection refused"}
//! ```
//!
//! Then the connection carries plaintext in both directions until either side
//! closes. A loopback close is translated into an abrupt upstream teardown, so
//! that the relay's `transport.abort()` — which it uses deliberately to punish
//! a stalled route — still means what it meant.
//!
//! ```text
//! tls-terminator --port 1374 --token <secret>
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use nova_tls::{built_in_profile, shape};
use serde::Deserialize;

/// Mirrors `phase.Reached` in `tgrelay/phase.py`. The two must agree; the
/// Python side has a test that pins the table they share.
mod reached {
    pub const NOTHING: u8 = 0;
    pub const RESOLVED: u8 = 1;
    pub const CONNECTED: u8 = 2;
    pub const HELLO_SENT: u8 = 3;
    pub const HANDSHAKE_DONE: u8 = 4;
}

/// Mirrors `phase.Ended`.
mod ended {
    pub const OK: u8 = 0;
    pub const TIMEOUT: u8 = 1;
    pub const RESET: u8 = 2;
    pub const REFUSED: u8 = 3;
    pub const CLOSED: u8 = 4;
    pub const CERT_MISMATCH: u8 = 5;
    pub const HTTP_STATUS: u8 = 6;
}

#[derive(Debug, Deserialize)]
struct Target {
    host: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Egress {
    Direct,
    Socks5 { host: String, port: u16 },
    Http { host: String, port: u16 },
}

#[derive(Debug, Deserialize)]
struct Request {
    token: String,
    target: Target,
    egress: Egress,
    sni: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default = "default_connect_timeout")]
    connect_timeout_ms: u64,
    #[serde(default = "default_handshake_timeout")]
    handshake_timeout_ms: u64,
    /// Whether to verify the peer certificate. Absent means "keep the relay's
    /// current behaviour", which is not to.
    #[serde(default)]
    verify: bool,
}

fn default_connect_timeout() -> u64 {
    8_000
}

fn default_handshake_timeout() -> u64 {
    8_000
}

/// Built shapers, keyed by profile name and whether they verify.
///
/// An `SslConnector` compiles a cipher list, a group list and a signature
/// algorithm list every time it is built. Doing that per tunnel would spend
/// that work 48 times during the relay's cold start, inside a connect budget
/// that can be as low as 1.2 seconds.
///
/// The cache is also what makes the profile a per-connection choice rather than
/// a process-wide one, which is what the learner needs: it picks a shape per
/// attempt and the terminator must be able to honour that without a restart.
struct Shapers {
    built: std::sync::Mutex<std::collections::HashMap<(String, bool), Arc<shape::Shaper>>>,
    default_profile: String,
}

impl Shapers {
    fn new(default_profile: String) -> Self {
        Self { built: std::sync::Mutex::new(std::collections::HashMap::new()), default_profile }
    }

    fn get(&self, name: Option<&str>, verify: bool) -> Result<Arc<shape::Shaper>, Failure> {
        let name = name.unwrap_or(&self.default_profile).to_owned();
        let key = (name.clone(), verify);
        if let Ok(guard) = self.built.lock()
            && let Some(shaper) = guard.get(&key)
        {
            return Ok(Arc::clone(shaper));
        }
        let profile = built_in_profile(&name).ok_or_else(|| {
            Failure::new(reached::NOTHING, ended::CLOSED, format!("unknown profile {name:?}"))
        })?;
        let shaper = Arc::new(
            shape::Shaper::new(&profile, verify)
                .map_err(|err| Failure::new(reached::NOTHING, ended::CLOSED, err.to_string()))?,
        );
        if let Ok(mut guard) = self.built.lock() {
            guard.insert(key, Arc::clone(&shaper));
        }
        Ok(shaper)
    }
}

/// A failure that knows which gate it died at.
struct Failure {
    reached: u8,
    ended: u8,
    message: String,
}

impl Failure {
    fn new(reached: u8, ended: u8, message: impl Into<String>) -> Self {
        Self { reached, ended, message: message.into() }
    }
}

/// Classify an I/O error into the vocabulary the relay shares.
fn ended_of(err: &std::io::Error) -> u8 {
    use std::io::ErrorKind::*;
    match err.kind() {
        TimedOut | WouldBlock => ended::TIMEOUT,
        ConnectionRefused => ended::REFUSED,
        ConnectionReset => ended::RESET,
        ConnectionAborted | UnexpectedEof | BrokenPipe => ended::CLOSED,
        _ => match err.raw_os_error() {
            // Windows spells several of these without a matching ErrorKind.
            Some(10054) => ended::RESET,
            Some(10060) => ended::TIMEOUT,
            Some(10061) => ended::REFUSED,
            _ => ended::CLOSED,
        },
    }
}

fn main() {
    let mut port: u16 = 1374;
    let mut token = String::new();
    let mut default_profile = String::from("yandex-windows");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(1374);
                i += 2;
            }
            "--token" if i + 1 < args.len() => {
                token = args[i + 1].clone();
                i += 2;
            }
            "--profile" if i + 1 < args.len() => {
                default_profile = args[i + 1].clone();
                i += 2;
            }
            "--help" | "-h" => {
                println!("usage: tls-terminator --token <secret> [--port 1374] [--profile yandex-windows]");
                return;
            }
            other => {
                eprintln!("unknown argument {other:?}; try --help");
                std::process::exit(2);
            }
        }
    }

    if token.is_empty() {
        token = std::env::var("NOVA_TLS_TERMINATOR_TOKEN").unwrap_or_default();
    }
    if token.is_empty() {
        // Without a token this is an open TLS proxy for every process on the
        // machine. Loopback is not a permission boundary.
        eprintln!("refusing to start without --token or NOVA_TLS_TERMINATOR_TOKEN");
        std::process::exit(2);
    }

    let profile = match built_in_profile(&default_profile) {
        Some(profile) => profile,
        None => {
            eprintln!("unknown profile {default_profile:?}");
            std::process::exit(2);
        }
    };
    // Fail at startup, not on the first tunnel: a profile this build cannot
    // emit is a configuration mistake, and discovering it mid-session would
    // arrive at the relay looking like a network condition.
    if let Err(err) = shape::can_express(&profile) {
        eprintln!("profile {default_profile:?} cannot be emitted by this build: {err}");
        std::process::exit(2);
    }
    let divergence = shape::divergence(&profile);
    if !divergence.is_exact() {
        eprintln!(
            "note: {} differs from the browser it imitates — missing extensions {:?}, alpn downgraded: {}",
            profile.name, divergence.missing_extensions, divergence.alpn_downgraded
        );
    }

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("cannot listen on 127.0.0.1:{port}: {err}");
            std::process::exit(1);
        }
    };
    eprintln!("tls-terminator listening on 127.0.0.1:{port}, profile {}", profile.name);

    let token = Arc::new(token);
    let shapers = Arc::new(Shapers::new(profile.name.clone()));
    // A bound on concurrency rather than an async runtime. The relay's cold
    // start opens 48 tunnels at once and its own executor is sized to match, so
    // the ceiling is set above that: queueing here would be spent against the
    // caller's connect budget, which is as low as 1.2 seconds.
    let live = Arc::new(AtomicUsize::new(0));
    const MAX_LIVE: usize = 128;

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if live.load(Ordering::Relaxed) >= MAX_LIVE {
            // Refusing is better than queueing: the caller has a deadline and a
            // fallback, and a refused connection reaches it immediately.
            drop(stream);
            continue;
        }
        let token = Arc::clone(&token);
        let shapers = Arc::clone(&shapers);
        let live = Arc::clone(&live);
        live.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || {
            serve(stream, &token, &shapers);
            live.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn serve(mut client: TcpStream, token: &str, shapers: &Shapers) {
    let _ = client.set_nodelay(true);
    if client.write_all(b"{\"nova\":\"tls-terminator/1\"}\n").is_err() {
        return;
    }

    let request = match read_request(&client) {
        Ok(request) => request,
        Err(failure) => {
            reply_failure(&mut client, &failure);
            return;
        }
    };

    if request.token != token {
        // Deliberately terse and deliberately not a distinct phase: an
        // unauthorised caller is not a network condition and has nothing to
        // learn from us.
        let _ = client.write_all(b"{\"ok\":false,\"reached\":0,\"ended\":4,\"error\":\"unauthorised\"}\n");
        return;
    }

    match establish(&request, shapers) {
        Ok((upstream, alpn)) => {
            let payload = format!(
                "{{\"ok\":true,\"reached\":{},\"ended\":{},\"alpn\":{}}}\n",
                reached::HANDSHAKE_DONE,
                ended::OK,
                serde_json::to_string(&alpn).unwrap_or_else(|_| "null".into()),
            );
            if client.write_all(payload.as_bytes()).is_err() {
                return;
            }
            pump(client, upstream);
        }
        Err(failure) => reply_failure(&mut client, &failure),
    }
}

fn read_request(client: &TcpStream) -> Result<Request, Failure> {
    let mut reader = BufReader::new(match client.try_clone() {
        Ok(clone) => clone,
        Err(err) => return Err(Failure::new(reached::NOTHING, ended_of(&err), err.to_string())),
    });
    let mut line = String::new();
    // The control line is small and arrives immediately; anything slower is a
    // client that is not ours.
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    match reader.read_line(&mut line) {
        Ok(0) => return Err(Failure::new(reached::NOTHING, ended::CLOSED, "no request")),
        Ok(_) => {}
        Err(err) => return Err(Failure::new(reached::NOTHING, ended_of(&err), err.to_string())),
    }
    let _ = client.set_read_timeout(None);
    serde_json::from_str(&line)
        .map_err(|err| Failure::new(reached::NOTHING, ended::CLOSED, format!("bad request: {err}")))
}

fn reply_failure(client: &mut TcpStream, failure: &Failure) {
    let payload = format!(
        "{{\"ok\":false,\"reached\":{},\"ended\":{},\"error\":{}}}\n",
        failure.reached,
        failure.ended,
        serde_json::to_string(&failure.message).unwrap_or_else(|_| "\"\"".into()),
    );
    let _ = client.write_all(payload.as_bytes());
}

/// Dial the target through the requested egress and complete the handshake.
fn establish(
    request: &Request,
    shapers: &Shapers,
) -> Result<(boring::ssl::SslStream<TcpStream>, Option<String>), Failure> {
    let connect_timeout = Duration::from_millis(request.connect_timeout_ms.max(200));
    let handshake_timeout = Duration::from_millis(request.handshake_timeout_ms.max(200));

    let (mut socket, mut reached_gate) = match &request.egress {
        Egress::Direct => (dial(&request.target.host, request.target.port, connect_timeout)?, reached::CONNECTED),
        Egress::Socks5 { host, port } => (dial(host, *port, connect_timeout)?, reached::RESOLVED),
        Egress::Http { host, port } => (dial(host, *port, connect_timeout)?, reached::RESOLVED),
    };

    // The proxy leg shares the connect budget: a proxy that accepts TCP and
    // then stalls is the failure this timeout exists for.
    let _ = socket.set_read_timeout(Some(connect_timeout));
    let _ = socket.set_write_timeout(Some(connect_timeout));
    match &request.egress {
        Egress::Direct => {}
        Egress::Socks5 { .. } => {
            socks5_connect(&mut socket, &request.target)?;
            reached_gate = reached::CONNECTED;
        }
        Egress::Http { .. } => {
            http_connect(&mut socket, &request.target)?;
            reached_gate = reached::CONNECTED;
        }
    }
    debug_assert_eq!(reached_gate, reached::CONNECTED);

    let _ = socket.set_nodelay(true);
    let _ = socket.set_read_timeout(Some(handshake_timeout));
    let _ = socket.set_write_timeout(Some(handshake_timeout));

    let shaper = shapers.get(request.profile.as_deref(), request.verify)?;

    // Past this point the ClientHello is on the wire, which is the one window
    // where its shape is a live suspect.
    let stream = shaper.connect(&request.sni, socket).map_err(|err| {
        let text = err.to_string();
        let ended = if text.contains("certificate") || text.contains("CERTIFICATE") {
            ended::CERT_MISMATCH
        } else if text.contains("timed out") || text.contains("timeout") {
            ended::TIMEOUT
        } else {
            ended::CLOSED
        };
        Failure::new(reached::HELLO_SENT, ended, text)
    })?;

    let alpn = stream.ssl().selected_alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
    // Clear the handshake deadline: a tunnel is idle for long stretches by
    // design, and inheriting a handshake timeout would kill it mid-session.
    let _ = stream.get_ref().set_read_timeout(None);
    let _ = stream.get_ref().set_write_timeout(None);
    Ok((stream, alpn))
}

fn dial(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, Failure> {
    let mut addresses = match (host, port).to_socket_addrs() {
        Ok(addresses) => addresses,
        Err(err) => {
            // The name never became an address. Nothing downstream of this may
            // be blamed for it.
            return Err(Failure::new(reached::NOTHING, ended_of(&err), err.to_string()));
        }
    };
    let mut last: Option<std::io::Error> = None;
    for address in addresses.by_ref() {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last = Some(err),
        }
    }
    let err = last.unwrap_or_else(|| std::io::Error::other("no address resolved"));
    Err(Failure::new(reached::RESOLVED, ended_of(&err), err.to_string()))
}

fn socks5_connect(socket: &mut TcpStream, target: &Target) -> Result<(), Failure> {
    let fail = |err: std::io::Error| Failure::new(reached::RESOLVED, ended_of(&err), err.to_string());
    let protocol =
        |message: &str| Failure::new(reached::RESOLVED, ended::CLOSED, message.to_owned());

    socket.write_all(&[0x05, 0x01, 0x00]).map_err(fail)?;
    let mut greeting = [0u8; 2];
    socket.read_exact(&mut greeting).map_err(fail)?;
    if greeting != [0x05, 0x00] {
        return Err(protocol("SOCKS5 refused no-auth"));
    }

    let host = target.host.as_bytes();
    if host.len() > 255 {
        return Err(protocol("hostname too long for SOCKS5"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&target.port.to_be_bytes());
    socket.write_all(&request).map_err(fail)?;

    let mut head = [0u8; 4];
    socket.read_exact(&mut head).map_err(fail)?;
    if head[0] != 0x05 {
        return Err(protocol("bad SOCKS5 reply version"));
    }
    if head[1] != 0x00 {
        // The proxy answered and declined. That is the proxy's verdict about
        // the destination, not a fault of ours.
        return Err(Failure::new(
            reached::RESOLVED,
            if head[1] == 0x05 { ended::REFUSED } else { ended::CLOSED },
            format!("SOCKS5 CONNECT failed with code {}", head[1]),
        ));
    }
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).map_err(fail)?;
            len[0] as usize + 2
        }
        other => return Err(protocol(&format!("unknown SOCKS5 address type {other}"))),
    };
    let mut discard = vec![0u8; skip];
    socket.read_exact(&mut discard).map_err(fail)?;
    Ok(())
}

fn http_connect(socket: &mut TcpStream, target: &Target) -> Result<(), Failure> {
    let fail = |err: std::io::Error| Failure::new(reached::RESOLVED, ended_of(&err), err.to_string());
    let authority = format!("{}:{}", target.host, target.port);
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).map_err(fail)?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match socket.read(&mut byte) {
            Ok(0) => {
                return Err(Failure::new(reached::RESOLVED, ended::CLOSED, "proxy closed during CONNECT"));
            }
            Ok(_) => head.push(byte[0]),
            Err(err) => return Err(fail(err)),
        }
        if head.len() > 16 * 1024 {
            return Err(Failure::new(reached::RESOLVED, ended::CLOSED, "proxy response too large"));
        }
    }
    let text = String::from_utf8_lossy(&head);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        // The proxy spoke HTTP back, so it works and it said no.
        return Err(Failure::new(
            reached::RESOLVED,
            ended::HTTP_STATUS,
            format!("HTTP CONNECT returned {status}"),
        ));
    }
    Ok(())
}

/// One direction of the tunnel: bytes taken from one side, owed to the other.
struct Direction {
    pending: Vec<u8>,
    /// The far side has stopped sending; drain `pending` and then we are done.
    finished: bool,
}

impl Direction {
    fn new() -> Self {
        Self { pending: Vec::new(), finished: false }
    }

    fn done(&self) -> bool {
        self.finished && self.pending.is_empty()
    }
}

/// A read that only says "not yet".
fn would_block(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted)
        || matches!(err.raw_os_error(), Some(10035))
}

/// Move bytes between the relay and the upstream until either side stops.
///
/// One thread, both sockets non-blocking, driven by a poller. BoringSSL is
/// explicit that an `SSL` "may only be used on one thread at a time" and gives
/// no exception for a concurrent reader and writer, so the two-thread shape
/// needs a lock — and a lock does not work here: measured, the reader
/// reacquires it faster than the writer can ever take it, and the tunnel
/// carries the handshake and then nothing. With one thread there is no lock to
/// starve anyone with.
///
/// When the loopback side goes away the upstream is reset rather than closed
/// politely. The relay calls `transport.abort()` on purpose to drop a route
/// that has stalled; a graceful close here would turn that into a shutdown the
/// far end could sit on.
fn pump(client: TcpStream, mut upstream: boring::ssl::SslStream<TcpStream>) {
    const CLIENT: usize = 0;
    const UPSTREAM: usize = 1;
    // Big enough that a 64 KB relay read crosses in one go, which is the size
    // the relay's own buffers are set to.
    const CHUNK: usize = 64 * 1024;
    // Bound the amount owed in either direction, so a peer that stops reading
    // cannot make this process grow without limit.
    const HIGH_WATER: usize = 1024 * 1024;

    let _ = client.set_nonblocking(true);
    let _ = upstream.get_ref().set_nonblocking(true);

    let Ok(poller) = polling::Poller::new() else { return };
    // SAFETY: both sockets outlive the poller — they are dropped at the end of
    // this function, after `poller`, and neither is registered anywhere else.
    unsafe {
        if poller.add(&client, polling::Event::all(CLIENT)).is_err()
            || poller.add(upstream.get_ref(), polling::Event::all(UPSTREAM)).is_err()
        {
            return;
        }
    }

    let mut to_upstream = Direction::new();
    let mut to_client = Direction::new();
    let mut events = polling::Events::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut aborted = false;

    loop {
        if to_upstream.done() && to_client.done() {
            break;
        }
        // Ask only for what we can act on. Reading a side we already owe a
        // megabyte to would just move the backlog into this process.
        let mut want_client = polling::Event::none(CLIENT);
        want_client.readable = !to_upstream.finished && to_upstream.pending.len() < HIGH_WATER;
        want_client.writable = !to_client.pending.is_empty();
        let mut want_upstream = polling::Event::none(UPSTREAM);
        want_upstream.readable = !to_client.finished && to_client.pending.len() < HIGH_WATER;
        want_upstream.writable = !to_upstream.pending.is_empty();
        if poller.modify(&client, want_client).is_err()
            || poller.modify(upstream.get_ref(), want_upstream).is_err()
        {
            break;
        }

        events.clear();
        // A timeout rather than an indefinite wait: TLS can want to write while
        // reading, and the wakeup lets the loop retry without tracking every
        // such case explicitly.
        if poller.wait(&mut events, Some(Duration::from_secs(30))).is_err() {
            break;
        }

        let mut client_ready = (false, false);
        let mut upstream_ready = (false, false);
        for event in events.iter() {
            match event.key {
                CLIENT => client_ready = (event.readable, event.writable),
                UPSTREAM => upstream_ready = (event.readable, event.writable),
                _ => {}
            }
        }
        // On a bare timeout, retry both rather than spinning on nothing.
        if events.is_empty() {
            client_ready = (true, true);
            upstream_ready = (true, true);
        }

        if client_ready.0 && !to_upstream.finished {
            match (&client).read(&mut buffer) {
                Ok(0) => {
                    to_upstream.finished = true;
                    // The relay hung up. Whatever it owed upstream is moot, and
                    // an abort must stay an abort.
                    aborted = true;
                }
                Ok(n) => to_upstream.pending.extend_from_slice(&buffer[..n]),
                Err(err) if would_block(&err) => {}
                Err(_) => {
                    to_upstream.finished = true;
                    aborted = true;
                }
            }
        }

        if upstream_ready.0 && !to_client.finished {
            match upstream.read(&mut buffer) {
                Ok(0) => to_client.finished = true,
                Ok(n) => to_client.pending.extend_from_slice(&buffer[..n]),
                Err(err) if would_block(&err) => {}
                Err(_) => to_client.finished = true,
            }
        }

        if !to_upstream.pending.is_empty() && (upstream_ready.1 || events.is_empty()) {
            match upstream.write(&to_upstream.pending) {
                Ok(0) => to_upstream.finished = true,
                Ok(n) => {
                    to_upstream.pending.drain(..n);
                    let _ = upstream.flush();
                }
                Err(err) if would_block(&err) => {}
                Err(_) => to_upstream.finished = true,
            }
        }

        if !to_client.pending.is_empty() && (client_ready.1 || events.is_empty()) {
            match (&client).write(&to_client.pending) {
                Ok(0) => to_client.finished = true,
                Ok(n) => {
                    to_client.pending.drain(..n);
                }
                Err(err) if would_block(&err) => {}
                Err(_) => to_client.finished = true,
            }
        }

        // Once one side is finished and drained, the other has nowhere to go.
        if to_upstream.done() && to_client.finished {
            break;
        }
        if to_client.done() && to_upstream.finished {
            break;
        }
    }

    let raw = upstream.get_ref();
    if aborted {
        let _ = socket2::SockRef::from(raw).set_linger(Some(Duration::ZERO));
    }
    let _ = raw.shutdown(Shutdown::Both);
    let _ = client.shutdown(Shutdown::Both);
    let _ = poller.delete(&client);
    let _ = poller.delete(raw);
}
