//! Accepting a client on 1372: sniff, dispatch, handshake, hand over.

use nova_tgrelay::handshake::{HandshakeLimits, Input};
use nova_tgrelay::{classify_client, http, socks, Authority, ClientProtocol};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// Which protocol the client used to ask for the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientMode {
    Socks5,
    HttpConnect,
}

/// A client that has been told its tunnel is open.
pub struct AcceptedClient {
    pub stream: TcpStream,
    pub mode: ClientMode,
    pub authority: Authority,
    /// Payload the client sent without waiting for the reply. Already tunnel
    /// bytes — layer 4 must send these upstream before anything it reads next.
    pub rest: Vec<u8>,
}

/// Why a client was turned away. The refusal has already been written to the
/// socket by the time this is returned — answering is not left to the caller,
/// because a proxy that goes quiet costs hours to diagnose (G22).
#[derive(Debug)]
pub enum Rejected {
    /// Closed before saying anything usable.
    PeerClosed,
    /// First byte was neither `0x05` nor an uppercase letter. Refused at once
    /// rather than left to expire against the header timeout (G21).
    UnsupportedProtocol {
        first_byte: u8,
    },
    Socks(socks::Refusal),
    Http(http::Refusal),
    Io(io::Error),
}

impl From<io::Error> for Rejected {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read once, bounded by what is left of the handshake budget.
///
/// Returns `Ok(None)` when the budget is gone — the caller turns that into the
/// protocol's own refusal, so the timeout answer is written in exactly one place
/// per protocol.
async fn read_within_budget(
    stream: &mut TcpStream,
    buf: &mut [u8],
    start: Instant,
    limits: HandshakeLimits,
) -> io::Result<Option<usize>> {
    let elapsed = start.elapsed();
    let Some(remaining) = limits.total_deadline.checked_sub(elapsed) else {
        return Ok(None);
    };
    if remaining.is_zero() {
        return Ok(None);
    }
    match tokio::time::timeout(remaining, stream.read(buf)).await {
        Ok(result) => result.map(Some),
        Err(_elapsed) => Ok(None),
    }
}

/// Sniff the first byte, dispatch, run the handshake, answer.
///
/// The whole path shares one budget that starts here, so the sniff cannot buy a
/// client extra time on top of its handshake.
pub async fn accept_client(
    mut stream: TcpStream,
    relay_port: u16,
    limits: HandshakeLimits,
) -> Result<AcceptedClient, Rejected> {
    let start = Instant::now();

    let mut first = [0u8; 1];
    let read = read_within_budget(&mut stream, &mut first, start, limits).await?;
    let first_byte = match read {
        Some(0) | None => {
            // Nothing arrived, or the budget went on waiting for it. There is no
            // protocol yet, so there is nothing meaningful to answer with.
            return Err(Rejected::PeerClosed);
        }
        Some(_) => first[0],
    };

    match classify_client(Some(first_byte)) {
        Some(ClientProtocol::Socks5) => run_socks(stream, first_byte, relay_port, limits, start).await,
        Some(ClientProtocol::HttpConnect) => run_http(stream, first_byte, limits, start).await,
        Some(ClientProtocol::Unsupported) | None => {
            // The Python reaches the same answer by handing the byte to the SOCKS
            // handshake, which rejects the version. Said directly here.
            let _ = stream.write_all(socks::Refusal::NotSocks5.response()).await;
            Err(Rejected::UnsupportedProtocol { first_byte })
        }
    }
}

async fn run_socks(
    mut stream: TcpStream,
    first_byte: u8,
    relay_port: u16,
    limits: HandshakeLimits,
    start: Instant,
) -> Result<AcceptedClient, Rejected> {
    let mut hs = socks::SocksHandshake::with_prefetched(limits, &[first_byte]);
    let mut buf = vec![0u8; 1024];
    let mut input = Input::Bytes(&[]);

    loop {
        let progress = hs.feed(input, start.elapsed());
        // Unconditionally, before the step is even looked at: the method
        // selection can be produced by the same feed() that reaches the decision,
        // and dropping it left the client short two bytes forever.
        if !progress.write.is_empty() {
            stream.write_all(&progress.write).await?;
        }
        match progress.step {
            socks::Step::NeedMore => {}
            socks::Step::PeerClosed => return Err(Rejected::PeerClosed),
            socks::Step::Refused(refusal) => {
                let _ = stream.write_all(refusal.response()).await;
                return Err(Rejected::Socks(refusal));
            }
            socks::Step::Established { host, port } => {
                // Validated before the success reply goes out: telling a client
                // its tunnel is open and then discovering the target is nonsense
                // would leave it waiting on a socket nobody is going to serve.
                let Some(authority) = Authority::new(host, port) else {
                    let refusal = socks::Refusal::InvalidTarget;
                    let _ = stream.write_all(refusal.response()).await;
                    return Err(Rejected::Socks(refusal));
                };
                stream.write_all(&socks::established_reply(relay_port)).await?;
                return Ok(AcceptedClient {
                    stream,
                    mode: ClientMode::Socks5,
                    authority,
                    // SOCKS5 is read exactly, never past the request, so nothing
                    // of the tunnel has been consumed yet.
                    rest: Vec::new(),
                });
            }
        }

        input = match read_within_budget(&mut stream, &mut buf, start, limits).await? {
            None => {
                // Budget gone. Answer, then report.
                let refusal = socks::Refusal::Timeout;
                let _ = stream.write_all(refusal.response()).await;
                return Err(Rejected::Socks(refusal));
            }
            Some(0) => Input::Eof,
            Some(n) => Input::Bytes(&buf[..n]),
        };
        // `input` borrows `buf`, so the next feed happens at the top of the loop
        // before `buf` can be written to again.
    }
}

async fn run_http(
    mut stream: TcpStream,
    first_byte: u8,
    limits: HandshakeLimits,
    start: Instant,
) -> Result<AcceptedClient, Rejected> {
    let mut hs = http::ConnectHandshake::with_prefetched(limits, &[first_byte]);
    let mut buf = vec![0u8; 1024];
    let mut input = Input::Bytes(&[]);

    loop {
        match hs.feed(input, start.elapsed()) {
            http::Step::NeedMore => {}
            http::Step::PeerClosed => return Err(Rejected::PeerClosed),
            http::Step::Refused(refusal) => {
                let _ = stream.write_all(&refusal.response()).await;
                return Err(Rejected::Http(refusal));
            }
            http::Step::Established { authority, rest } => {
                stream.write_all(http::REPLY_ESTABLISHED).await?;
                return Ok(AcceptedClient { stream, mode: ClientMode::HttpConnect, authority, rest });
            }
        }

        input = match read_within_budget(&mut stream, &mut buf, start, limits).await? {
            None => {
                let refusal = http::Refusal::Timeout;
                let _ = stream.write_all(&refusal.response()).await;
                return Err(Rejected::Http(refusal));
            }
            Some(0) => Input::Eof,
            Some(n) => Input::Bytes(&buf[..n]),
        };
    }
}

/// Convenience for callers that want the default 5 s / 8 KiB budget.
pub async fn accept_client_default(stream: TcpStream, relay_port: u16) -> Result<AcceptedClient, Rejected> {
    accept_client(stream, relay_port, HandshakeLimits::DEFAULT_HTTP).await
}

/// A budget short enough for tests to exercise the deadline without sleeping for
/// seconds, exposed so integration tests do not have to reinvent it.
pub const TEST_LIMITS: HandshakeLimits =
    HandshakeLimits { max_bytes: 8192, total_deadline: Duration::from_millis(300) };
