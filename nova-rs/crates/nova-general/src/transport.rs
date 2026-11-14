use crate::Result;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    os::windows::io::AsRawSocket,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use windows_sys::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, SO_EXCLUSIVEADDRUSE, SOL_SOCKET, WSAGetLastError, setsockopt,
};

pub(crate) const HIDDEN: u32 = 0x08000000;
pub(crate) const MAX_BODY: usize = 65536;
#[derive(Clone, Copy, Debug)]
pub(crate) struct Binding {
    pub ip: Ipv4Addr,
    pub index: u32,
    pub port: u16,
}
pub(crate) struct Response {
    pub code: u16,
    pub body: Vec<u8>,
    pub location: Option<String>,
    pub elapsed_ms: u128,
    pub range_satisfied: bool,
}
#[derive(Debug)]
struct BindError(std::io::Error);
impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source port reservation: {}", self.0)
    }
}
impl std::error::Error for BindError {}
pub(crate) fn port_busy(e: &(dyn std::error::Error + 'static)) -> bool {
    e.downcast_ref::<BindError>().is_some_and(|e| matches!(e.0.raw_os_error(), Some(10048 | 10013)))
        || e.downcast_ref::<std::io::Error>().is_some_and(|e| e.raw_os_error() == Some(10048))
}
pub(crate) fn public_ip(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240)
}
pub(crate) fn reserve(binding: Binding) -> Result<Socket> {
    if binding.index == 0 {
        return Err("physical interface index is missing".into());
    }
    let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    let exclusive = 1i32;
    let index = binding.index.to_be();
    for (level, option, value) in [
        (SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (&exclusive as *const i32).cast::<u8>()),
        (IPPROTO_IP, IP_UNICAST_IF, (&index as *const u32).cast::<u8>()),
    ] {
        if unsafe { setsockopt(s.as_raw_socket() as usize, level, option, value, 4) } != 0 {
            return Err(format!("socket interface/reservation option: {}", unsafe { WSAGetLastError() }).into());
        }
    }
    s.bind(&SocketAddrV4::new(binding.ip, binding.port).into()).map_err(BindError)?;
    Ok(s)
}
fn config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut c = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("provider has TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            c.resumption = rustls::client::Resumption::disabled();
            Arc::new(c)
        })
        .clone()
}
fn remaining(tcp: &TcpStream, deadline: Instant) -> Result<()> {
    let duration = deadline.checked_duration_since(Instant::now()).ok_or("probe deadline elapsed")?;
    tcp.set_read_timeout(Some(duration))?;
    tcp.set_write_timeout(Some(duration))?;
    Ok(())
}
fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers
        .lines()
        .find_map(|line| line.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}
fn unchunk(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut pos = 0;
    loop {
        let end = data[pos..]
            .windows(2)
            .position(|v| v == b"\r\n")
            .map(|n| n + pos)
            .ok_or("incomplete HTTP chunk size")?;
        let size_text = std::str::from_utf8(&data[pos..end])?.split(';').next().unwrap();
        let size = usize::from_str_radix(size_text.trim(), 16)?;
        pos = end + 2;
        if size == 0 {
            return Ok(output);
        }
        let end = pos.checked_add(size).ok_or("chunk length overflow")?;
        if end + 2 > data.len() || &data[end..end + 2] != b"\r\n" {
            return Err("incomplete HTTP chunk".into());
        }
        output.extend_from_slice(&data[pos..end]);
        pos = end + 2;
        if output.len() > MAX_BODY {
            return Err("DNS body exceeds limit".into());
        }
    }
}
pub(crate) fn request(s: Socket, binding: Binding, host: &str, ip: Ipv4Addr, path: &str) -> Result<Response> {
    if !public_ip(ip)
        || host.len() > 253
        || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || !path.starts_with('/')
        || path.contains(['\r', '\n'])
    {
        return Err("invalid public HTTPS target".into());
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs(7);
    s.connect_timeout(&SocketAddrV4::new(ip, 443).into(), Duration::from_secs(3))?;
    let tcp: TcpStream = s.into();
    tcp.set_nodelay(true)?;
    if tcp.local_addr()?.ip() != std::net::IpAddr::V4(binding.ip) {
        return Err("physical source binding changed".into());
    }
    let mut tls = StreamOwned::new(ClientConnection::new(config(), ServerName::try_from(host.to_owned())?)?, tcp);
    while tls.conn.is_handshaking() {
        remaining(&tls.sock, deadline)?;
        tls.conn.complete_io(&mut tls.sock)?;
    }
    remaining(&tls.sock, deadline)?;
    let accept = if host == "cloudflare-dns.com" { "application/dns-json" } else { "*/*" };
    write!(
        tls,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NovaGeneral/1\r\nAccept: {accept}\r\nRange: bytes=0-65535\r\nConnection: close\r\n\r\n"
    )?;
    tls.flush()?;
    let mut data = Vec::new();
    let mut header_end = None;
    let mut range = false;
    let mut buffer = [0u8; 8192];
    loop {
        remaining(&tls.sock, deadline)?;
        match tls.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                if let Some(end) = header_end {
                    let h = std::str::from_utf8(&data[..end])?;
                    if header_value(h, "content-length")
                        .and_then(|s| s.parse::<usize>().ok())
                        .is_some_and(|n| data.len() - end >= n)
                    {
                        break;
                    }
                }
                return Err("truncated TLS response".into());
            }
            Err(e) => return Err(e.into()),
        }
        if header_end.is_none() {
            header_end = data.windows(4).position(|v| v == b"\r\n\r\n").map(|n| n + 4);
            if header_end.is_none() && data.len() > 65536 {
                return Err("HTTP header limit exceeded".into());
            }
        }
        if let Some(end) = header_end {
            if data.len() - end >= MAX_BODY {
                range = true;
                break;
            }
            let headers = std::str::from_utf8(&data[..end])?;
            if header_value(headers, "content-length")
                .and_then(|n| n.parse::<usize>().ok())
                .is_some_and(|n| data.len() - end >= n)
            {
                break;
            }
            if header_value(headers, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
                && data.ends_with(b"\r\n0\r\n\r\n")
            {
                break;
            }
        }
    }
    let end = header_end.ok_or("no complete HTTP response")?;
    let headers = std::str::from_utf8(&data[..end])?;
    let code = headers.split_whitespace().nth(1).ok_or("missing HTTP status")?.parse()?;
    if !range
        && header_value(headers, "content-length")
            .and_then(|n| n.parse::<usize>().ok())
            .is_some_and(|n| data.len() - end < n)
    {
        return Err("incomplete HTTP body".into());
    }
    let location = header_value(headers, "location").map(str::to_owned);
    let chunked = header_value(headers, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let mut body = if chunked && !range { unchunk(&data[end..])? } else { data[end..].to_vec() };
    body.truncate(MAX_BODY);
    Ok(Response { code, body, location, elapsed_ms: started.elapsed().as_millis(), range_satisfied: range })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_tuple_conflicts_are_not_network_failures() {
        assert!(port_busy(&std::io::Error::from_raw_os_error(10048)));
        assert!(port_busy(&BindError(std::io::Error::from_raw_os_error(10013))));
        assert!(!port_busy(&std::io::Error::from_raw_os_error(10060)));
        assert!(!port_busy(&std::io::Error::from_raw_os_error(10013)));
    }
    #[test]
    fn chunked_json_requires_complete_framing() {
        assert_eq!(unchunk(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap(), b"abcde");
        assert!(unchunk(b"8\r\nshort").is_err());
    }
}
