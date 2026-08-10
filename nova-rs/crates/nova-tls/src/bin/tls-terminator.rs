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
//! The request line must be the last thing the client writes before the reply
//! arrives. It is read through a `BufReader` that is discarded straight after,
//! so anything pipelined behind it is dropped without a trace.
//!
//! Then the connection carries plaintext in both directions until either side
//! closes. A loopback close is translated into an abrupt upstream teardown, so
//! that the relay's `transport.abort()` — which it uses deliberately to punish
//! a stalled route — still means what it meant. The reverse is not symmetric:
//! when the *upstream* closes, the loopback gets a plain shutdown, because that
//! EOF is the only way the relay ever learns the far side is gone.
//!
//! ```text
//! tls-terminator --port 1374 --token <secret>
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

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

    phase_watch::spawn_watchdog();
    let token = Arc::new(token);
    let shapers = Arc::new(Shapers::new(profile.name.clone()));
    // A bound on concurrency rather than an async runtime. The relay's cold
    // start opens 48 tunnels at once and its own executor is sized to match, so
    // the ceiling is set above that: queueing here would be spent against the
    // caller's connect budget, which is as low as 1.2 seconds.
    let live = Arc::new(AtomicUsize::new(0));
    const MAX_LIVE: usize = 128;

    let mut refused: u64 = 0;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                // Исчерпание дескрипторов возвращает ошибку на каждом accept, и
                // без паузы это горячий цикл на целом ядре — который сам же и не
                // даёт освободиться тем дескрипторам, которых не хватает.
                eprintln!("accept не удался: {err}");
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        if live.load(Ordering::Relaxed) >= MAX_LIVE {
            // Refusing is better than queueing: the caller has a deadline and a
            // fallback, and a refused connection reaches it immediately.
            //
            // Но молча отказывать нельзя: со стороны релея это неотличимо от
            // упавшего помощника (terminator.py говорит «TLS helper closed
            // without a greeting»), а упёршийся потолок — единственный видимый
            // снаружи признак утечки соединений. Степени двойки, чтобы шквал
            // отказов не залил лог.
            refused += 1;
            if refused.is_power_of_two() {
                eprintln!("отказ: занято {MAX_LIVE} соединений, отказов всего {refused}");
            }
            drop(stream);
            continue;
        }
        let token = Arc::clone(&token);
        let shapers = Arc::clone(&shapers);
        live.fetch_add(1, Ordering::Relaxed);
        let slot = LiveSlot(Arc::clone(&live));
        // Builder, а не thread::spawn: последний паникует, когда поток создать
        // не удалось, и уносит с собой цикл accept — то есть весь терминатор.
        let spawned = std::thread::Builder::new()
            .name(format!("tunnel-{}", live.load(Ordering::Relaxed)))
            .spawn(move || {
                let _slot = slot;
                serve(stream, &token, &shapers);
            });
        if let Err(err) = spawned {
            // Замыкание уничтожено вместе с `slot`, счётчик уже вернулся.
            eprintln!("не удалось создать поток соединения: {err}");
        }
    }
}

/// Возвращает слот в счётчик живых соединений, в том числе при панике.
///
/// Уменьшение счётчика последней строкой замыкания разматывающаяся паника
/// просто перепрыгивает — а профиль release собран с `panic = "unwind"`
/// намеренно. Один аварийный поток навсегда съедал единицу из `MAX_LIVE`, а
/// сотня таких превращала терминатор в процесс, который жив, слушает порт и
/// отказывает всем.
struct LiveSlot(Arc<AtomicUsize>);

impl Drop for LiveSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// Диагностика зависаний в теле итерации pump().
//
// Три попытки угадать место провалились: счётчик оборотов молчит, маркеры вокруг
// poller.wait дали 208 входов и 208 выходов. Значит поток стоит между выходом из
// ожидания и следующим входом — то есть в одном из четырёх вызовов ввода-вывода
// или в poller.modify. Вместо очередной догадки — метка фазы и сторож, который
// печатает фазу тех pump, у которых счётчик перестал меняться.
mod phase_watch {
    use super::*;

    pub const MODIFY: u8 = 1;
    pub const WAIT: u8 = 2;
    pub const CLIENT_READ: u8 = 3;
    pub const UPSTREAM_READ: u8 = 4;
    pub const UPSTREAM_WRITE: u8 = 5;
    pub const CLIENT_WRITE: u8 = 6;
    pub const TAIL: u8 = 7;

    /// Пятый бит маски — не интерес, а состояние: одна из сторон уже отвалилась.
    pub const HALF_CLOSED: u64 = 16;

    pub fn name(phase: u8) -> &'static str {
        match phase {
            MODIFY => "poller.modify",
            WAIT => "poller.wait",
            CLIENT_READ => "client.read",
            UPSTREAM_READ => "upstream.read (TLS)",
            UPSTREAM_WRITE => "upstream.write (TLS)",
            CLIENT_WRITE => "client.write",
            TAIL => "конец итерации",
            _ => "?",
        }
    }

    /// Верхние биты — счётчик смен фазы, нижние восемь — сама фаза. Сторожу
    /// достаточно сравнить два снимка целиком: не изменилось — значит стоит.
    pub struct Slot(pub AtomicU64, pub AtomicU64);

    impl Slot {
        pub fn set(&self, phase: u8) {
            let prev = self.0.load(Ordering::Relaxed);
            self.0.store(((prev >> 8) + 1) << 8 | phase as u64, Ordering::Relaxed);
        }

        /// Флаги интереса на момент входа в ожидание — чтобы «застрял в wait»
        /// сразу говорило, с какой маской он туда вошёл.
        pub fn set_want(&self, client: polling::Event, upstream: polling::Event, half_closed: bool) {
            let bits = (client.readable as u64)
                | (client.writable as u64) << 1
                | (upstream.readable as u64) << 2
                | (upstream.writable as u64) << 3
                | (half_closed as u64) << 4;
            self.1.store(bits, Ordering::Relaxed);
        }
    }

    pub fn want_text(bits: u64) -> String {
        format!(
            "client(r={},w={}) upstream(r={},w={}) полузакрыт={}",
            bits & 1 != 0,
            bits & 2 != 0,
            bits & 4 != 0,
            bits & 8 != 0,
            bits & HALF_CLOSED != 0
        )
    }

    static REGISTRY: OnceLock<Mutex<Vec<(usize, Arc<Slot>)>>> = OnceLock::new();

    fn registry() -> &'static Mutex<Vec<(usize, Arc<Slot>)>> {
        REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
    }

    /// Запись в реестре сторожа, снимающая себя сама.
    ///
    /// Снятие стояло отдельной строкой перед выходом из `pump()`, и паника её
    /// перепрыгивала: в реестре оставался слот мёртвого потока, `Vec` рос, а
    /// сторож либо печатал его вечно, либо (если фаза замерла на ожидании)
    /// молча носил вечно. Владение закрывает оба исхода без единой строки на
    /// стороне вызова.
    pub struct Registration {
        id: usize,
        pub slot: Arc<Slot>,
    }

    impl Drop for Registration {
        fn drop(&mut self) {
            if let Ok(mut guard) = registry().lock() {
                guard.retain(|(other, _)| *other != self.id);
            }
        }
    }

    pub fn register(id: usize) -> Registration {
        let slot = Arc::new(Slot(AtomicU64::new(0), AtomicU64::new(0)));
        if let Ok(mut guard) = registry().lock() {
            guard.push((id, Arc::clone(&slot)));
        }
        Registration { id, slot }
    }

    pub fn spawn_watchdog() {
        std::thread::spawn(|| {
            let mut previous: Vec<(usize, u64, u64)> = Vec::new();
            loop {
                std::thread::sleep(Duration::from_secs(30));
                let now: Vec<(usize, u64, u64)> = match registry().lock() {
                    Ok(guard) => guard.iter().map(|(id, s)| (*id, s.0.load(Ordering::Relaxed), s.1.load(Ordering::Relaxed))).collect(),
                    Err(_) => continue,
                };
                for (id, value, want) in &now {
                    if let Some((_, before, before_want)) =
                        previous.iter().find(|(other, _, _)| other == id)
                    {
                        // Ожидание — единственная фаза, где стоять долго
                        // нормально: туннель Telegram простаивает по многу
                        // минут. Отчёт о ней был бы сплошным шумом. Любой
                        // другой вызов, замерший на полминуты, — дефект.
                        let phase = (*value & 0xff) as u8;
                        let frozen = before == value && *value != 0;

                        // Полузакрытая пара — второй случай, и его нельзя
                        // ловить неподвижностью счётчика: такой поток не
                        // замирает, он просыпается по таймауту и честно крутит
                        // оборот, меняя фазу по четыре раза за круг. Признак
                        // здесь — само состояние, увиденное дважды подряд.
                        // Отсрочка рвёт такую пару за полминуты, поэтому два
                        // попадания через тридцать секунд означают, что рвать
                        // перестало работать. Ровно этого сторож и не видел,
                        // пока копился CLOSE_WAIT.
                        let stuck_half_closed =
                            (*want & HALF_CLOSED != 0) && (*before_want & HALF_CLOSED != 0);

                        if (frozen && phase != WAIT) || stuck_half_closed {
                            eprintln!(
                                "phase-stuck: id={id} фаза={} уже 30с (смен фазы={}) интерес: {}",
                                name(phase),
                                value >> 8,
                                want_text(*want)
                            );
                        }
                    }
                }
                previous = now;
            }
        });
    }
}

/// Держит источник в поллере только пока к нему есть интерес.
///
/// `Event::none()` оставляет сокет зарегистрированным с пустой маской, и на
/// сокете с висящим HUP это уводит windows-бэкенд `polling` в бесконечный
/// внутренний цикл внутри `wait()`. Снятие с регистрации закрывает этот путь.
fn reregister_source(
    poller: &polling::Poller,
    source: &TcpStream,
    want: polling::Event,
    registered: &mut bool,
) -> bool {
    let wanted = want.readable || want.writable;
    if wanted {
        let result = if *registered {
            poller.modify(source, want)
        } else {
            // SAFETY: источник живёт до конца pump(), удаляется там же.
            unsafe { poller.add(source, want) }
        };
        if result.is_err() {
            return false;
        }
        *registered = true;
    } else if *registered {
        if poller.delete(source).is_err() {
            return false;
        }
        *registered = false;
    }
    true
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
                // Клиент исчез между рукопожатием и подтверждением. По правилу
                // модуля уход петли — это обрыв, а не вежливое закрытие: иначе
                // далёкая сторона может сидеть на нашем FIN сколько захочет.
                // Окно узкое — `transport.abort()` шлёт FIN, а запись шести
                // десятков байт в такой сокет проходит, — так что сюда попадает
                // только настоящий RST.
                let _ = socket2::SockRef::from(upstream.get_ref())
                    .set_linger(Some(Duration::ZERO));
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

/// Условия выхода из `pump()`, собранные в одно место.
///
/// `Some(true)` — рвать upstream: релей ушёл, а вежливое закрытие превратило бы
/// его `transport.abort()` в shutdown, на котором далёкая сторона может сидеть.
/// `Some(false)` — закрыть вежливо: upstream кончился сам.
///
/// Собраны они здесь потому, что россыпь отдельных `if` в хвосте цикла спрятала
/// пропуск ровно одного из них. Из двух зеркальных условий было написано одно —
/// «релей ушёл, отдавать ему нечего». Обратное — «upstream закрылся, всё его
/// уже у релея» — не выполнялось ни одной из веток: `to_upstream.finished`
/// остаётся ложным, потому что клиент жив и просто молчит. Поток парковался в
/// тридцатисекундном ожидании навсегда, держа сокет upstream в CLOSE_WAIT.
/// Замерено: 48 таких потоков одновременно, у каждого два сокета, 243 сокета на
/// 116 потоков при десятке настоящих туннелей.
fn stop_reason(to_upstream: &Direction, to_client: &Direction) -> Option<bool> {
    // Обе стороны сказали последнее слово, и наверх отдавать больше нечего.
    if to_upstream.done() && to_client.finished {
        return Some(false);
    }
    // То же с другого конца: релею отдано всё, а он сам ещё пишет наверх.
    if to_client.done() && to_upstream.finished {
        return Some(false);
    }
    // Зеркало нижнего условия, и именно его не было. Upstream закрылся, всё,
    // что он прислал, уже у релея, и наверх ничего не осталось. Держать нечего:
    // писать в закрывшуюся сторону некуда, а сам релей про её уход не узнает,
    // пока мы не закроем петлю — полузакрытия в протоколе нет.
    if to_client.done() && to_upstream.pending.is_empty() {
        return Some(false);
    }
    // Релей отвалился, и отдавать ему нечего. Единственное условие пары,
    // которое было написано.
    if to_upstream.finished && to_client.pending.is_empty() {
        return Some(true);
    }
    None
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

    // A readiness that never becomes a byte. BoringSSL answers WANT_READ while
    // it waits for the rest of a record, and a peer that sent FIN mid-record is
    // reported readable forever: the poller wakes us, the read yields nothing,
    // the state does not change, and the loop spins at a full core. Measured in
    // the field at ~8.5 cores across a handful of such tunnels, with CLOSE_WAIT
    // sockets piling up next to them.
    //
    // Real readiness always produces either a byte or a terminal error, so a run
    // of woken-but-empty iterations means this tunnel is dead rather than idle.
    // Idle tunnels are not affected: they arrive here as timeouts, and timeouts
    // do not count.
    const STALLED_WAKEUPS: u32 = 64;
    let mut idle_wakeups: u32 = 0;

    // Крайний срок появляется только после того, как одна из сторон отвалилась,
    // и ни секундой раньше. Общего таймаута простоя тут быть не может: туннель
    // Telegram молчит по многу минут, и это законно. Но простаивающий живой
    // туннель — это два открытых сокета, а полузакрытая пара — уже нет:
    // взведённый `finished` означает, что сокет висит в CLOSE_WAIT (или что
    // запись в него провалилась), и ждать на нём можно только того, чего никто
    // не пришлёт. Вот по этому признаку мёртвое отличимо от простаивающего, не
    // трогая второе.
    //
    // Сеть безопасности, а не основная правка: с `stop_reason` ниже такая пара
    // выходит на том же обороте. Срок остаётся на случай, когда `pending`
    // некуда девать.
    const HALF_CLOSED_GRACE: Duration = Duration::from_secs(30);
    let mut half_closed_at: Option<Instant> = None;

    let mut to_upstream = Direction::new();
    let mut to_client = Direction::new();
    let mut events = polling::Events::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut aborted = false;

    // Diagnostic for a spin that survived the first fix. Counting whole
    // iterations rather than idle ones: the previous counter reset whenever any
    // one of the four blocks moved a byte, so a direction stuck on WANT_READ
    // stayed invisible as long as the other direction kept trickling.
    //
    // The per-iteration counter alone answered nothing: four threads sat at a
    // full core each and it never printed. Either the loop does not turn, or it
    // never returns from the wait. Start/end markers separate the two.
    static PUMP_SEQ: AtomicUsize = AtomicUsize::new(0);
    let pump_id = PUMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let registration = phase_watch::register(pump_id);
    let phase = &registration.slot;

    let mut client_registered = true;
    let mut upstream_registered = true;
    let mut iterations: u64 = 0;
    let mut reported: u64 = 0;
    let mut last_events: usize = 0;
    const REPORT_EVERY: u64 = 200_000;

    loop {
        if let Some(reset) = stop_reason(&to_upstream, &to_client) {
            aborted |= reset;
            break;
        }
        iterations += 1;
        // Пороги низкие намеренно: при 200 000 нельзя было отличить «цикл
        // крутится вхолостую» от «управление не вернулось из wait». Здоровый
        // туннель этих чисел не достигает — самый долгий завершившийся прошёл
        // 191 оборот.
        // Канарейка на будущее: здоровый туннель не делает и двух сотен
        // оборотов, так что двести тысяч — это уже раскрутка цикла.
        let report_now = iterations - reported >= REPORT_EVERY;
        if report_now {
            reported = iterations;
            eprintln!(
                "spin-diag: id={pump_id} iters={iterations} to_upstream(fin={}, pend={}) to_client(fin={}, pend={}) idle_wakeups={idle_wakeups} last_events={last_events}",
                to_upstream.finished,
                to_upstream.pending.len(),
                to_client.finished,
                to_client.pending.len(),
            );
        }
        // Ask only for what we can act on. Reading a side we already owe a
        // megabyte to would just move the backlog into this process.
        let mut want_client = polling::Event::none(CLIENT);
        want_client.readable = !to_upstream.finished && to_upstream.pending.len() < HIGH_WATER;
        want_client.writable = !to_client.pending.is_empty();
        let mut want_upstream = polling::Event::none(UPSTREAM);
        want_upstream.readable = !to_client.finished && to_client.pending.len() < HIGH_WATER;
        want_upstream.writable = !to_upstream.pending.is_empty();
        phase.set(phase_watch::MODIFY);
        phase.set_want(want_client, want_upstream, half_closed_at.is_some());
        // Источник без интереса снимается с регистрации, а не переводится в
        // Event::none(). Это и есть подозреваемый: сокет, у которого висит
        // HUP/ERR, но ни одно из событий не запрошено, — на нём windows-бэкенд
        // polling переоткрывает AFD-запрос по кругу внутри wait() и наружу не
        // возвращается. Ровно это показал сторож: все зависшие стоят в
        // poller.wait, счётчик оборотов при этом не растёт.
        //
        // Снятие с регистрации убирает такой сокет из опроса совсем; когда
        // интерес появится снова, он добавляется обратно.
        let client_ok = reregister_source(&poller, &client, want_client, &mut client_registered);
        let upstream_ok =
            reregister_source(&poller, upstream.get_ref(), want_upstream, &mut upstream_registered);
        if !client_ok || !upstream_ok {
            break;
        }

        events.clear();
        // Маркеры вокруг самого вызова: spin-diag молчит даже с порогом в тысячу
        // оборотов, а поток при этом жжёт целое ядро — значит управление не
        // возвращается. enter без парного exit докажет это адресно.
        // Ограничено первыми оборотами и каждым сотым: здоровый туннель делает
        // 3-18 оборотов, флуда не будет.
        // A timeout rather than an indefinite wait: TLS can want to write while
        // reading, and the wakeup lets the loop retry without tracking every
        // such case explicitly.
        // Пока обе стороны живы — тридцать секунд: будить простаивающий туннель
        // незачем. Как только одна отвалилась, шаг ожидания сжимается до
        // остатка отсрочки, иначе полузакрытая пара пережила бы свой срок ещё
        // на целый шаг.
        let wait_step = match half_closed_at {
            Some(since) => HALF_CLOSED_GRACE
                .saturating_sub(since.elapsed())
                .max(Duration::from_millis(200)),
            None => Duration::from_secs(30),
        };
        phase.set(phase_watch::WAIT);
        if poller.wait(&mut events, Some(wait_step)).is_err() {
            break;
        }
        last_events = events.len();

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

        // Anything that counts as the tunnel still being alive: a byte in either
        // direction, or a side reaching a definite end.
        let mut progressed = false;

        if client_ready.0 && !to_upstream.finished {
            phase.set(phase_watch::CLIENT_READ);
            match (&client).read(&mut buffer) {
                Ok(0) => {
                    to_upstream.finished = true;
                    progressed = true;
                    // The relay hung up. Whatever it owed upstream is moot, and
                    // an abort must stay an abort.
                    aborted = true;
                }
                Ok(n) => {
                    to_upstream.pending.extend_from_slice(&buffer[..n]);
                    progressed = true;
                }
                Err(err) if would_block(&err) => {}
                Err(_) => {
                    to_upstream.finished = true;
                    progressed = true;
                    aborted = true;
                }
            }
        }

        if upstream_ready.0 && !to_client.finished {
            phase.set(phase_watch::UPSTREAM_READ);
            match upstream.read(&mut buffer) {
                Ok(0) => {
                    to_client.finished = true;
                    progressed = true;
                }
                Ok(n) => {
                    to_client.pending.extend_from_slice(&buffer[..n]);
                    progressed = true;
                }
                Err(err) if would_block(&err) => {}
                Err(_) => {
                    to_client.finished = true;
                    progressed = true;
                }
            }
        }

        if !to_upstream.pending.is_empty() && (upstream_ready.1 || events.is_empty()) {
            phase.set(phase_watch::UPSTREAM_WRITE);
            match upstream.write(&to_upstream.pending) {
                Ok(0) => {
                    to_upstream.finished = true;
                    progressed = true;
                }
                Ok(n) => {
                    to_upstream.pending.drain(..n);
                    let _ = upstream.flush();
                    progressed = true;
                }
                Err(err) if would_block(&err) => {}
                Err(_) => {
                    to_upstream.finished = true;
                    progressed = true;
                }
            }
        }

        if !to_client.pending.is_empty() && (client_ready.1 || events.is_empty()) {
            phase.set(phase_watch::CLIENT_WRITE);
            match (&client).write(&to_client.pending) {
                Ok(0) => {
                    to_client.finished = true;
                    progressed = true;
                }
                Ok(n) => {
                    to_client.pending.drain(..n);
                    progressed = true;
                }
                Err(err) if would_block(&err) => {}
                Err(_) => {
                    to_client.finished = true;
                    progressed = true;
                }
            }
        }

        phase.set(phase_watch::TAIL);
        // Only woken iterations count. A timeout is how an idle-but-healthy
        // tunnel gets here, and it must not be mistaken for a stall.
        if progressed || events.is_empty() {
            idle_wakeups = 0;
        } else {
            idle_wakeups += 1;
            if idle_wakeups >= STALLED_WAKEUPS {
                // Neither side will finish on its own: reset upstream rather
                // than leave the pair in CLOSE_WAIT for the process lifetime.
                aborted = true;
                break;
            }
        }

        // Отсчёт от того оборота, где взвёлся первый `finished`, а не от начала
        // соединения.
        if to_upstream.finished || to_client.finished {
            let since = *half_closed_at.get_or_insert_with(Instant::now);
            if since.elapsed() >= HALF_CLOSED_GRACE {
                // Полузакрытая пара, не сошедшаяся за отсрочку: рвать, это уже
                // не туннель, а два повисших дескриптора. Если строка вообще
                // появилась в логе — значит `stop_reason` её не поймал, и
                // смотреть надо туда, а не на отсрочку.
                eprintln!("half-closed: id={pump_id} не сошлась за {HALF_CLOSED_GRACE:?}, рву");
                aborted = true;
                break;
            }
        }

        if let Some(reset) = stop_reason(&to_upstream, &to_client) {
            aborted |= reset;
            break;
        }
    }

    drop(registration);

    let raw = upstream.get_ref();
    if aborted {
        let _ = socket2::SockRef::from(raw).set_linger(Some(Duration::ZERO));
    }
    let _ = raw.shutdown(Shutdown::Both);
    let _ = client.shutdown(Shutdown::Both);
    let _ = poller.delete(&client);
    let _ = poller.delete(raw);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(finished: bool, pending: usize) -> Direction {
        Direction { pending: vec![0u8; pending], finished }
    }

    #[test]
    fn a_live_tunnel_is_never_stopped() {
        assert_eq!(stop_reason(&dir(false, 0), &dir(false, 0)), None);
        assert_eq!(stop_reason(&dir(false, 10), &dir(false, 10)), None);
    }

    #[test]
    fn client_gone_is_an_abort() {
        assert_eq!(stop_reason(&dir(true, 0), &dir(false, 0)), Some(true));
    }

    /// Зеркало предыдущего. Именно его отсутствие копило CLOSE_WAIT: поток
    /// парковался в ожидании клиента, который уже ничего не пришлёт, и держал
    /// оба сокета до конца жизни процесса.
    #[test]
    fn upstream_gone_is_a_polite_close() {
        assert_eq!(stop_reason(&dir(false, 0), &dir(true, 0)), Some(false));
    }

    /// Долг перед релеем важнее скорости выхода: пока есть что отдать, пара
    /// живёт. Без этого правка выбрасывала бы последний ответ upstream.
    #[test]
    fn bytes_owed_to_the_relay_are_delivered_before_stopping() {
        assert_eq!(stop_reason(&dir(false, 0), &dir(true, 4)), None);
    }

    /// И симметрично — то, что релей уже прислал, дописывается наверх.
    #[test]
    fn bytes_owed_upstream_are_delivered_before_stopping() {
        assert_eq!(stop_reason(&dir(false, 4), &dir(true, 0)), None);
    }

    #[test]
    fn both_sides_finished_and_drained_is_a_polite_close() {
        assert_eq!(stop_reason(&dir(true, 0), &dir(true, 0)), Some(false));
    }
}
