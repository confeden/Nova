//! Layer 5: opening a tunnel through the first egress that works.
//!
//! The port of `tgrelay/transport.py::_open_tunnel_socket_sync` and its two
//! proxy handshakes. `nova_tgrelay::egress` decides the order; this walks it.
//!
//! Three deliberate differences from the Python, each one a rule this codebase
//! already learned the hard way somewhere else:
//!
//! 1. **One deadline per egress, covering connect *and* the proxy handshake.**
//!    The Python puts a socket timeout on the attempt, and a socket timeout in
//!    CPython is *per operation*: `_recv_exact` renews it on every `recv`, so a
//!    proxy dribbling one byte at a time holds the attempt open forever. That is
//!    G22 exactly, one layer over from where S27 fixed it.
//! 2. **What the CONNECT reply over-read is kept, not dropped.** `_recv_until`
//!    reads in 4 KiB chunks and can take bytes past `\r\n\r\n`; the Python then
//!    discards the whole buffer. Nothing arrives there today because Telegram's
//!    client speaks first, but the same shape is what `AcceptedClient::rest`
//!    exists to prevent on the other side of the relay.
//! 3. **How far it got is reported, not inferred from an exception type.** The
//!    Python decides `Reached::Nothing` vs `Reached::Resolved` by testing for
//!    `socket.gaierror`; here the resolve is its own step, so the answer is
//!    observed. A proxy that accepted TCP and then refused the CONNECT reaches
//!    `Connected`, which the Python cannot express at all.

use nova_probe::Reached;
use nova_tgrelay::egress::{Egress, ProxyProtocol};
use nova_tgrelay::socks_addr::encode_target;
use nova_tgrelay::Authority;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant};

/// An open tunnel and the name of what carried it.
#[derive(Debug)]
pub struct Dialled {
    pub stream: TcpStream,
    /// The egress label, as given — this is what the health tables are keyed by
    /// and what the `route=` field of every relay log line says.
    pub label: String,
    /// Bytes the proxy sent after its reply. Empty in every case seen so far;
    /// see the module note on why it is returned rather than dropped.
    pub leftover: Vec<u8>,
}

/// Why no tunnel was opened.
#[derive(Debug)]
pub enum DialError {
    /// The caller handed over an empty list. Distinct from "everything failed"
    /// because it is a bug on the calling side, not a network condition — the
    /// Python raises `OSError("no upstream attempts available")` here and the
    /// call sites are careful never to produce it.
    NoEgress,
    /// Every egress was tried.
    AllFailed {
        /// The furthest gate *any* attempt cleared. That, not the last error,
        /// is what bounds the conclusion: one egress failing to resolve says
        /// nothing once another got a TCP session up.
        reached: Reached,
        /// What ended the last attempt.
        last: io::Error,
        tried: usize,
    },
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEgress => write!(f, "no upstream attempts available"),
            Self::AllFailed { reached, last, tried } => {
                write!(f, "all {tried} egresses failed (reached {reached:?}): {last}")
            }
        }
    }
}

impl std::error::Error for DialError {}

/// The default per-egress budget when the egress carries none of its own.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// `max(0.2, …)` in the Python: no attempt is given less than this, however the
/// caller does its arithmetic.
pub const MIN_TIMEOUT: Duration = Duration::from_millis(200);
/// `_recv_until`'s cap on a CONNECT response.
const MAX_CONNECT_RESPONSE: usize = 65536;

/// One attempt's failure, and how far it had got.
struct Attempted {
    reached: Reached,
    error: io::Error,
}

fn failed(reached: Reached, error: io::Error) -> Attempted {
    Attempted { reached, error }
}

fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// What is left of an egress's budget, or `None` once it is spent.
struct Deadline(Instant);

impl Deadline {
    fn starting(now: Instant, budget: Duration) -> Self {
        Self(now + budget)
    }

    fn remaining(&self, now: Instant) -> Option<Duration> {
        self.0.checked_duration_since(now).filter(|d| !d.is_zero())
    }

    /// Run `future` against what is left. A spent budget is a timeout, not a
    /// zero-length wait that might still succeed by luck.
    async fn wrap<T>(&self, future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
        let Some(left) = self.remaining(Instant::now()) else {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        };
        match tokio::time::timeout(left, future).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::from(io::ErrorKind::TimedOut)),
        }
    }
}

/// Open a TCP session, keeping "the name never resolved" apart from "nothing
/// answered".
async fn connect(target: &Authority, deadline: &Deadline) -> Result<TcpStream, Attempted> {
    let addrs: Vec<_> = deadline
        .wrap(tokio::net::lookup_host((target.host(), target.port())))
        .await
        .map_err(|e| failed(Reached::Nothing, e))?
        .collect();
    if addrs.is_empty() {
        return Err(failed(Reached::Nothing, other(format!("no address for {}", target.host()))));
    }

    let mut last = other("no address attempted");
    for addr in addrs {
        match deadline.wrap(TcpStream::connect(addr)).await {
            Ok(stream) => {
                // The Python sets this on every tunnel socket. A relay forwards
                // small MTProto frames; Nagle would hold each one waiting for a
                // companion that is not coming.
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => last = e,
        }
    }
    Err(failed(Reached::Resolved, last))
}

async fn read_exact_within(stream: &mut TcpStream, n: usize, deadline: &Deadline) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    deadline.wrap(stream.read_exact(&mut buf)).await?;
    Ok(buf)
}

/// `_connect_via_socks5`, as a client.
async fn socks5_connect(stream: &mut TcpStream, target: &Authority, deadline: &Deadline) -> io::Result<()> {
    deadline.wrap(stream.write_all(b"\x05\x01\x00")).await?;
    let greeting = read_exact_within(stream, 2, deadline).await?;
    if greeting != [0x05, 0x00] {
        return Err(other(format!("SOCKS5 no-auth negotiation failed: {greeting:?}")));
    }

    let mut request = vec![0x05, 0x01, 0x00];
    request.extend_from_slice(
        &encode_target(target.host()).map_err(|e| other(format!("SOCKS5 target: {e:?}")))?,
    );
    request.extend_from_slice(&target.port().to_be_bytes());
    deadline.wrap(stream.write_all(&request)).await?;

    let header = read_exact_within(stream, 4, deadline).await?;
    if header[0] != 0x05 {
        return Err(other(format!("invalid SOCKS5 version in reply: {header:?}")));
    }
    if header[1] != 0x00 {
        return Err(other(format!("SOCKS5 CONNECT failed with code {}", header[1])));
    }

    // The bound address has to be drained or its bytes become the first bytes of
    // the tunnel.
    match header[3] {
        0x01 => read_exact_within(stream, 4 + 2, deadline).await?,
        0x04 => read_exact_within(stream, 16 + 2, deadline).await?,
        0x03 => {
            let len = read_exact_within(stream, 1, deadline).await?[0] as usize;
            read_exact_within(stream, len + 2, deadline).await?
        }
        atyp => return Err(other(format!("unknown SOCKS5 reply ATYP {atyp}"))),
    };
    Ok(())
}

/// `_connect_via_http`, as a client. Returns whatever arrived after the blank
/// line — see the module note.
async fn http_connect(stream: &mut TcpStream, target: &Authority, deadline: &Deadline) -> io::Result<Vec<u8>> {
    let authority = format!("{}:{}", target.host(), target.port());
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Proxy-Connection: Keep-Alive\r\n\
         User-Agent: NovaTelegramRelay/1\r\n\
         \r\n"
    );
    deadline.wrap(stream.write_all(request.as_bytes())).await?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = find_headers_end(&response) {
            break at;
        }
        if response.len() > MAX_CONNECT_RESPONSE {
            return Err(other("proxy response too large"));
        }
        let n = deadline.wrap(stream.read(&mut chunk)).await?;
        if n == 0 {
            // The Python breaks out of `_recv_until` here and lets the status
            // parse fail on an empty buffer. Said directly instead: a proxy that
            // closes is refusing, and pretending we got a malformed status line
            // sends the reader looking for one.
            return Err(other("proxy closed before answering CONNECT"));
        }
        response.extend_from_slice(&chunk[..n]);
    };

    let head = &response[..head_end];
    let status = status_code(head);
    if status != Some(200) {
        let first_line = head.split(|b| *b == b'\r').next().unwrap_or(head);
        return Err(other(format!("HTTP CONNECT failed: {}", String::from_utf8_lossy(first_line))));
    }
    Ok(response[head_end + 4..].to_vec())
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// `HTTP/1.1 200 Connection established` → `200`.
fn status_code(head: &[u8]) -> Option<u16> {
    let line = head.split(|b| *b == b'\r').next()?;
    let text = std::str::from_utf8(line).ok()?;
    text.split(' ').nth(1)?.parse().ok()
}

/// Try each egress in order and return the first tunnel that opens.
///
/// The order is the caller's — `nova_tgrelay::egress` produced it and this makes
/// no further judgements about it.
pub async fn dial(
    target: &Authority,
    egresses: &[Egress],
    default_timeout: Duration,
) -> Result<Dialled, DialError> {
    if egresses.is_empty() {
        return Err(DialError::NoEgress);
    }

    let mut furthest = Reached::Nothing;
    let mut last: Option<io::Error> = None;

    for egress in egresses {
        // `attempt.get("timeout") or timeout` in the Python: a zero is falsy
        // there and falls back to the caller's default, so a zero here must mean
        // "not set" and not "give it no time at all".
        let budget = egress
            .timeout()
            .filter(|t| !t.is_zero())
            .unwrap_or(default_timeout)
            .max(MIN_TIMEOUT);
        let deadline = Deadline::starting(Instant::now(), budget);

        let attempt = match egress {
            Egress::Direct { .. } => connect(target, &deadline).await.map(|stream| (stream, Vec::new())),
            Egress::Proxy { protocol, at, .. } => match connect(at, &deadline).await {
                Err(a) => Err(a),
                Ok(mut stream) => {
                    let handshake = match protocol {
                        ProxyProtocol::Socks5 => {
                            socks5_connect(&mut stream, target, &deadline).await.map(|()| Vec::new())
                        }
                        ProxyProtocol::HttpConnect => http_connect(&mut stream, target, &deadline).await,
                    };
                    match handshake {
                        Ok(leftover) => Ok((stream, leftover)),
                        // TCP to the proxy is up, so this attempt reached further
                        // than one that never opened a session at all.
                        Err(e) => Err(failed(Reached::Connected, e)),
                    }
                }
            },
        };

        match attempt {
            Ok((stream, leftover)) => {
                return Ok(Dialled { stream, label: egress.label().to_string(), leftover });
            }
            Err(Attempted { reached, error }) => {
                furthest = furthest.max(reached);
                last = Some(error);
            }
        }
    }

    Err(DialError::AllFailed {
        reached: furthest,
        last: last.unwrap_or_else(|| other("no upstream attempts available")),
        tried: egresses.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_line_is_read_the_way_the_python_reads_it() {
        assert_eq!(status_code(b"HTTP/1.1 200 Connection established"), Some(200));
        assert_eq!(status_code(b"HTTP/1.0 407 Proxy Authentication Required"), Some(407));
        assert_eq!(status_code(b"garbage"), None);
        assert_eq!(status_code(b""), None);
    }

    #[test]
    fn the_blank_line_is_found_even_when_it_straddles_a_read() {
        assert_eq!(find_headers_end(b"HTTP/1.1 200 OK\r\n\r\nrest"), Some(15));
        assert_eq!(find_headers_end(b"HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn a_spent_deadline_is_a_timeout_not_a_last_chance() {
        let now = Instant::now();
        let deadline = Deadline::starting(now, Duration::from_secs(1));
        assert!(deadline.remaining(now).is_some());
        assert!(deadline.remaining(now + Duration::from_secs(2)).is_none());
    }
}
