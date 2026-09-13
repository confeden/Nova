//! Layer 15: opening a shaped TLS tunnel through the terminator.
//!
//! The port of `tgrelay/terminator.py` — the client half of the loopback
//! protocol whose server is `nova-tls`'s `tls-terminator` binary. This is the
//! last piece of `_connect_websocket_once`, and with it the relay can raise a
//! WSS connection without Python.
//!
//! The wire protocol, taken from the server rather than from the Python client:
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
//! Then the same socket carries plaintext until either side closes.
//!
//! **The request line must be the last thing written before the reply is read.**
//! The server reads it through a `BufReader` it discards immediately after, so
//! anything pipelined behind it is dropped without a trace. Here that is
//! structural: [`open_shaped_stream`] does not hand the stream back until the
//! reply has arrived, so there is no window in which a caller could write early.
//!
//! **Why the egress list is walked here and not inside the helper.** The route
//! label the relay logs and learns from has to stay the label the relay chose;
//! a helper picking its own would report an egress the health tables never
//! selected.

use nova_probe::Reached;
use nova_tgrelay::egress::{Egress, ProxyProtocol};
use nova_tgrelay::Authority;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// How long the helper gets to accept a loopback connection and greet.
///
/// It answers immediately or not at all: it is a local process, and anything
/// slower than this is a helper that has died rather than one that is busy.
pub const HELPER_GREETING_TIMEOUT: Duration = Duration::from_secs(5);
/// Added to the connect and handshake budgets when waiting for the reply, since
/// the helper is doing both on our behalf inside that one wait.
pub const REPLY_SLACK: Duration = Duration::from_secs(2);
/// `max(0.2, …)` — no attempt is given less than this.
pub const MIN_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(200);

/// Where the helper is and what it will accept.
#[derive(Debug, Clone)]
pub struct TerminatorConfig {
    pub port: u16,
    /// Minted per run. Without it the helper is an open TLS proxy for every
    /// process on the machine, which is why it refuses to start without one.
    pub token: String,
    /// Which ClientHello shape to emit. `None` leaves the helper on its own
    /// default; naming it per attempt is what lets a learner try shapes without
    /// restarting the helper.
    pub profile: Option<String>,
    /// Whether the helper verifies the peer certificate. The relay's current
    /// behaviour is not to.
    pub verify: bool,
}

#[derive(Debug, Serialize)]
struct WireTarget<'a> {
    host: &'a str,
    port: u16,
}

/// Serialised exactly as the server's `#[serde(tag = "kind", rename_all =
/// "snake_case")]` enum expects: `direct`, `socks5`, `http`.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireEgress<'a> {
    Direct,
    Socks5 { host: &'a str, port: u16 },
    Http { host: &'a str, port: u16 },
}

#[derive(Debug, Serialize)]
struct WireRequest<'a> {
    token: &'a str,
    target: WireTarget<'a>,
    egress: WireEgress<'a>,
    sni: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
    connect_timeout_ms: u64,
    handshake_timeout_ms: u64,
    verify: bool,
}

/// The helper's answer.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct TerminatorReply {
    pub ok: bool,
    #[serde(default)]
    pub reached: u8,
    #[serde(default)]
    pub ended: u8,
    #[serde(default)]
    pub alpn: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// A tunnel the helper handshook on our behalf.
#[derive(Debug)]
pub struct Shaped {
    pub stream: TcpStream,
    /// The label the *relay* chose, not one the helper invented.
    pub label: String,
    pub alpn: Option<String>,
    /// Bytes the helper sent after its reply, already taken off the socket.
    ///
    /// Empty in every case seen so far — on this path the relay writes the
    /// upgrade request before the far side says anything — but the reply is read
    /// through a `BufReader`, and `into_inner` **drops whatever that buffer still
    /// holds**. Handing back the stream without these would lose them silently,
    /// which is the same over-read this codebase already fixed in the SOCKS
    /// handshake and the CONNECT reply.
    pub leftover: Vec<u8>,
}

#[derive(Debug)]
pub enum TerminatorError {
    NoEgress,
    /// Talking to the helper itself failed.
    ///
    /// **Not evidence about the network**, and must not be charged to a domain
    /// or an egress — the Python tags it `Reached::Nothing` for exactly that
    /// reason. A helper that died takes the whole relay's TLS masking with it
    /// (G20) and says nothing about the route that was being attempted.
    Helper(io::Error),
    /// The helper answered and refused, carrying its own verdict on how far the
    /// attempt got. That verdict *is* about the network.
    Refused {
        reached: u8,
        ended: u8,
        message: String,
        label: String,
    },
}

impl std::fmt::Display for TerminatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEgress => write!(f, "no upstream attempts available"),
            Self::Helper(e) => write!(f, "TLS helper: {e}"),
            Self::Refused { reached, ended, message, label } => {
                write!(f, "TLS helper refused via {label} (reached {reached}, ended {ended}): {message}")
            }
        }
    }
}

impl std::error::Error for TerminatorError {}

impl TerminatorError {
    /// How far the attempt got, in the shared vocabulary.
    pub fn reached(&self) -> Reached {
        match self {
            Self::NoEgress | Self::Helper(_) => Reached::Nothing,
            Self::Refused { reached, .. } => reached_from(*reached),
        }
    }
}

/// The numbers the helper sends are `phase.Reached`'s, verbatim.
fn reached_from(value: u8) -> Reached {
    match value {
        1 => Reached::Resolved,
        2 => Reached::Connected,
        3 => Reached::HelloSent,
        4 => Reached::HandshakeDone,
        5 => Reached::Upgraded,
        6 => Reached::Carrying,
        _ => Reached::Nothing,
    }
}

fn wire_egress(egress: &Egress) -> WireEgress<'_> {
    match egress {
        Egress::Direct { .. } => WireEgress::Direct,
        Egress::Proxy { protocol: ProxyProtocol::Socks5, at, .. } => {
            WireEgress::Socks5 { host: at.host(), port: at.port() }
        }
        Egress::Proxy { protocol: ProxyProtocol::HttpConnect, at, .. } => {
            WireEgress::Http { host: at.host(), port: at.port() }
        }
    }
}

/// The request line, newline included.
///
/// Exposed so a test can assert the bytes: the server on the other end is a
/// separate binary shipped separately, and a field renamed on one side only is
/// a failure that appears in production and nowhere else.
pub fn request_line(
    target: &Authority,
    egress: &Egress,
    sni: &str,
    config: &TerminatorConfig,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> String {
    let request = WireRequest {
        token: &config.token,
        target: WireTarget { host: target.host(), port: target.port() },
        egress: wire_egress(egress),
        sni,
        profile: config.profile.as_deref(),
        connect_timeout_ms: connect_timeout.max(MIN_ATTEMPT_TIMEOUT).as_millis() as u64,
        handshake_timeout_ms: handshake_timeout.max(MIN_ATTEMPT_TIMEOUT).as_millis() as u64,
        verify: config.verify,
    };
    let mut line = serde_json::to_string(&request).expect("a fixed struct of strings and numbers");
    line.push('\n');
    line
}

/// One egress, one loopback connection to the helper.
async fn dial_once(
    target: &Authority,
    egress: &Egress,
    sni: &str,
    config: &TerminatorConfig,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<Shaped, TerminatorError> {
    let helper = format!("127.0.0.1:{}", config.port);
    let stream = timeout(HELPER_GREETING_TIMEOUT, TcpStream::connect(&helper))
        .await
        .map_err(|_| TerminatorError::Helper(io::Error::from(io::ErrorKind::TimedOut)))?
        .map_err(TerminatorError::Helper)?;
    let _ = stream.set_nodelay(true);

    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    let read = timeout(HELPER_GREETING_TIMEOUT, reader.read_line(&mut greeting))
        .await
        .map_err(|_| TerminatorError::Helper(io::Error::from(io::ErrorKind::TimedOut)))?
        .map_err(TerminatorError::Helper)?;
    if read == 0 {
        return Err(TerminatorError::Helper(io::Error::other("TLS helper closed without a greeting")));
    }

    let line = request_line(target, egress, sni, config, connect_timeout, handshake_timeout);
    reader.get_mut().write_all(line.as_bytes()).await.map_err(TerminatorError::Helper)?;
    reader.get_mut().flush().await.map_err(TerminatorError::Helper)?;

    // The helper is doing the connect *and* the handshake inside this one wait.
    let budget = connect_timeout + handshake_timeout + REPLY_SLACK;
    let mut answer = String::new();
    let read = timeout(budget, reader.read_line(&mut answer))
        .await
        .map_err(|_| TerminatorError::Helper(io::Error::from(io::ErrorKind::TimedOut)))?
        .map_err(TerminatorError::Helper)?;
    if read == 0 {
        return Err(TerminatorError::Helper(io::Error::other("TLS helper closed before answering")));
    }
    let reply: TerminatorReply = serde_json::from_str(answer.trim_end())
        .map_err(|e| TerminatorError::Helper(io::Error::other(format!("bad reply: {e}"))))?;

    if !reply.ok {
        // Dropped abruptly rather than closed politely: the helper reads a
        // loopback close as "the relay gave up" and resets its upstream, which
        // is what should happen to a tunnel that never became one.
        return Err(TerminatorError::Refused {
            reached: reply.reached,
            ended: reply.ended,
            message: reply.error.unwrap_or_else(|| "TLS helper refused the tunnel".to_string()),
            label: egress.label().to_string(),
        });
    }

    // Taken *before* `into_inner`, which throws the buffer away.
    let leftover = reader.buffer().to_vec();
    let stream = reader.into_inner();
    Ok(Shaped { stream, label: egress.label().to_string(), alpn: reply.alpn, leftover })
}

/// Same contract as the plain dialler, one process further out.
///
/// Walks the egresses in the order given and returns the first tunnel the helper
/// manages to raise.
pub async fn open_shaped_stream(
    target: &Authority,
    sni: &str,
    egresses: &[Egress],
    config: &TerminatorConfig,
    default_timeout: Duration,
) -> Result<Shaped, TerminatorError> {
    if egresses.is_empty() {
        return Err(TerminatorError::NoEgress);
    }
    let mut last = None;
    for egress in egresses {
        let connect_timeout =
            egress.timeout().filter(|t| !t.is_zero()).unwrap_or(default_timeout).max(MIN_ATTEMPT_TIMEOUT);
        match dial_once(target, egress, sni, config, connect_timeout, default_timeout).await {
            Ok(shaped) => return Ok(shaped),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or(TerminatorError::NoEgress))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TerminatorConfig {
        TerminatorConfig {
            port: 1374,
            token: "s3cret".to_string(),
            profile: Some("yandex-windows".to_string()),
            verify: false,
        }
    }

    fn target() -> Authority {
        Authority::new("kws2.nova-app.eu", 443).expect("authority")
    }

    fn warp() -> Egress {
        Egress::proxy(ProxyProtocol::Socks5, "warp-socks", Authority::new("127.0.0.1", 1370).unwrap())
    }

    #[test]
    fn the_request_is_the_shape_the_helper_deserialises() {
        // The server is a separately shipped binary; a field renamed on one side
        // only fails in production and nowhere else.
        let line = request_line(
            &target(),
            &warp(),
            "www.nova-app.eu",
            &config(),
            Duration::from_millis(1600),
            Duration::from_millis(8000),
        );
        assert!(line.ends_with('\n'), "one line, newline-terminated");
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).expect("valid json");
        assert_eq!(parsed["token"], "s3cret");
        assert_eq!(parsed["target"]["host"], "kws2.nova-app.eu");
        assert_eq!(parsed["target"]["port"], 443);
        assert_eq!(parsed["egress"]["kind"], "socks5");
        assert_eq!(parsed["egress"]["host"], "127.0.0.1");
        assert_eq!(parsed["egress"]["port"], 1370);
        assert_eq!(parsed["sni"], "www.nova-app.eu");
        assert_eq!(parsed["profile"], "yandex-windows");
        assert_eq!(parsed["connect_timeout_ms"], 1600);
        assert_eq!(parsed["handshake_timeout_ms"], 8000);
        assert_eq!(parsed["verify"], false);
    }

    #[test]
    fn each_egress_kind_uses_the_name_the_server_enum_renames_to() {
        let cases = [
            (Egress::direct("direct"), "direct"),
            (warp(), "socks5"),
            (
                Egress::proxy(ProxyProtocol::HttpConnect, "opera-http", Authority::new("127.0.0.1", 1371).unwrap()),
                "http",
            ),
        ];
        for (egress, kind) in cases {
            let line =
                request_line(&target(), &egress, "x", &config(), Duration::from_secs(1), Duration::from_secs(1));
            let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).expect("json");
            assert_eq!(parsed["egress"]["kind"], kind);
            if kind == "direct" {
                assert!(parsed["egress"].get("host").is_none(), "direct carries no address");
            }
        }
    }

    #[test]
    fn a_missing_profile_is_omitted_rather_than_sent_as_null() {
        // The server's field is `Option<String>` with `#[serde(default)]`; a
        // literal `null` would deserialise the same way, but omitting it is what
        // "leave the helper on its own default" should look like on the wire.
        let mut config = config();
        config.profile = None;
        let line = request_line(&target(), &warp(), "x", &config, Duration::from_secs(1), Duration::from_secs(1));
        assert!(!line.contains("profile"), "{line}");
    }

    #[test]
    fn no_attempt_is_given_less_than_the_floor() {
        let line =
            request_line(&target(), &warp(), "x", &config(), Duration::from_millis(1), Duration::from_millis(0));
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).expect("json");
        assert_eq!(parsed["connect_timeout_ms"], 200);
        assert_eq!(parsed["handshake_timeout_ms"], 200);
    }

    #[test]
    fn the_replies_the_server_actually_sends_all_parse() {
        let ok: TerminatorReply =
            serde_json::from_str(r#"{"ok":true,"reached":4,"ended":0,"alpn":"http/1.1"}"#).expect("ok");
        assert!(ok.ok);
        assert_eq!(ok.alpn.as_deref(), Some("http/1.1"));
        assert_eq!(reached_from(ok.reached), Reached::HandshakeDone);

        let refused: TerminatorReply =
            serde_json::from_str(r#"{"ok":false,"reached":1,"ended":3,"error":"connection refused"}"#)
                .expect("refused");
        assert!(!refused.ok);
        assert_eq!(reached_from(refused.reached), Reached::Resolved);

        // The terse one the server sends for a bad token, written out by hand
        // there rather than serialised.
        let unauthorised: TerminatorReply =
            serde_json::from_str(r#"{"ok":false,"reached":0,"ended":4,"error":"unauthorised"}"#)
                .expect("unauthorised");
        assert_eq!(unauthorised.error.as_deref(), Some("unauthorised"));

        // And a success with no ALPN, which the server sends as a literal null.
        let no_alpn: TerminatorReply =
            serde_json::from_str(r#"{"ok":true,"reached":4,"ended":0,"alpn":null}"#).expect("no alpn");
        assert_eq!(no_alpn.alpn, None);
    }

    #[test]
    fn a_helper_failure_is_never_charged_to_the_network() {
        // The distinction the whole error type exists for: a dead helper takes
        // the relay's TLS masking with it (G20) and says nothing whatever about
        // the route that was being attempted.
        let helper = TerminatorError::Helper(io::Error::from(io::ErrorKind::ConnectionRefused));
        assert_eq!(helper.reached(), Reached::Nothing);

        let refused = TerminatorError::Refused {
            reached: 3,
            ended: 2,
            message: "reset".to_string(),
            label: "warp-socks".to_string(),
        };
        assert_eq!(refused.reached(), Reached::HelloSent, "the helper's verdict is the network's");
    }

    #[test]
    fn an_unknown_reached_number_degrades_to_nothing() {
        // A future helper could grow a value this build has never heard of.
        // Reading it as `Carrying` would credit a route with a success it never
        // had; `Nothing` concludes the least.
        assert_eq!(reached_from(99), Reached::Nothing);
        assert_eq!(reached_from(0), Reached::Nothing);
    }
}
