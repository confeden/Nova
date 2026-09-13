"""Exit country of a local egress, measured through that egress.

Why a separate measurement at all: the route rule for the EU list (nova_vpn_slots) needs to know
whether the primary tunnel leaves Russia, and the backend name does not say it -- Cloudflare
geolocates its egress to the client, so WARP from a Russian address exits as RU (Nova Android,
`ExitColoPolicy.kt`), while Proton always exits abroad.

Where the answer comes from is Nova Android's rule, not a new one (its I10 / D20):

* address and country come from **one** answer, never from two sources;
* the owner's source is `https://whatismyip.help/txt` -- one line, `ip|ipv4|asn|CC|...`;
* the fallback is `https://www.cloudflare.com/cdn-cgi/trace` **by name**: literal 1.1.1.1 once
  left the tunnel on Android through a route carve-out and reported the provider's address.

Here the request goes explicitly through the local proxy (SOCKS5 with a domain name, or HTTP
CONNECT), so it cannot leave the tunnel. Only the country (and Cloudflare's `colo`) is kept: the
exit address is parsed to validate the answer and then dropped -- it is never returned, logged or
written, because temp/ travels with problem reports (I19).

Stdlib only, no Nova globals: tests run it against local fake proxies.
"""

import socket
import ssl
import struct
import time

__all__ = [
    "SOURCES", "parse_whatismyip", "parse_cf_trace", "probe_exit_country", "fetch_via_proxy",
    "ProbeError",
]

WHATISMYIP = ("whatismyip.help", "/txt", "whatismyip")
CLOUDFLARE_TRACE = ("www.cloudflare.com", "/cdn-cgi/trace", "cloudflare")
SOURCES = (WHATISMYIP, CLOUDFLARE_TRACE)

_MAX_RESPONSE = 64 * 1024
# Share of the remaining budget a source may use when another source still follows it.
FIRST_SOURCE_SHARE = 0.55
_MIN_TIMEOUT = 0.05
_USER_AGENT = "curl/8.9.1"


class ProbeError(Exception):
    """One source failed; the message is safe to log (no address, no credentials)."""


class _Deadline:
    def __init__(self, budget):
        try:
            seconds = float(budget)
        except (TypeError, ValueError):
            seconds = 5.0
        self._end = time.monotonic() + max(0.3, seconds)

    def left(self):
        return self._end - time.monotonic()

    def timeout(self):
        return max(_MIN_TIMEOUT, self.left())

    def check(self, what):
        if self.left() <= 0:
            raise ProbeError(f"{what}: время вышло")


def _looks_like_address(value):
    text = str(value or "").strip()
    if not text or any(ch.isspace() or ch in "<>" for ch in text):
        return False
    parts = text.split(".")
    if len(parts) == 4 and all(p.isdigit() and p for p in parts):
        return True
    return ":" in text and all(ch in "0123456789abcdefABCDEF:." for ch in text)


# Geolocation "unknown"/area markers are not an answer: the next source gets its turn.
_NOT_COUNTRIES = frozenset(("EU", "XX", "ZZ", "AP"))


def _country(value):
    text = str(value or "").strip().upper()
    ok = len(text) == 2 and text.isalpha() and text.isascii() and text not in _NOT_COUNTRIES
    return text if ok else ""


def parse_whatismyip(body):
    """`85.174.181.85|ipv4|12389|RU|HTTP/1.1|curl/8.19.0|` -> "RU"; "" when it is not that answer.

    Fields are counted from the start only: the last two echo request headers.
    """
    lines = [ln.strip() for ln in str(body or "").splitlines() if ln.strip()]
    if not lines:
        return ""
    parts = lines[0].split("|")
    if len(parts) < 4 or not _looks_like_address(parts[0]):
        return ""
    return _country(parts[3])


def parse_cf_trace(body):
    """`/cdn-cgi/trace` -> (country, colo); ("", "") when the body has no valid `ip=`."""
    ip = country = colo = ""
    for raw in str(body or "").splitlines():
        line = raw.strip()
        if line.startswith("ip="):
            ip = line[3:].strip()
        elif line.startswith("loc="):
            country = _country(line[4:])
        elif line.startswith("colo="):
            colo = line[5:].strip().upper()
    if not _looks_like_address(ip):
        return "", ""
    return country, colo if colo.isalnum() and len(colo) <= 5 else ""


def _recv_exact(sock, count, deadline, what):
    data = b""
    while len(data) < count:
        deadline.check(what)
        sock.settimeout(deadline.timeout())
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ProbeError(f"{what}: соединение закрыто")
        data += chunk
    return data


def _socks5_connect(sock, target_host, target_port, deadline):
    sock.settimeout(deadline.timeout())
    sock.sendall(b"\x05\x01\x00")
    if _recv_exact(sock, 2, deadline, "SOCKS5") != b"\x05\x00":
        raise ProbeError("SOCKS5: прокси не принял приветствие")
    host = str(target_host).encode("idna")
    if len(host) > 255:
        raise ProbeError("SOCKS5: имя слишком длинное")
    request = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", int(target_port))
    sock.settimeout(deadline.timeout())
    sock.sendall(request)
    head = _recv_exact(sock, 4, deadline, "SOCKS5")
    if head[0] != 0x05 or head[1] != 0x00:
        raise ProbeError(f"SOCKS5: отказ CONNECT (код {head[1]})")
    atyp = head[3]
    if atyp == 0x01:
        _recv_exact(sock, 6, deadline, "SOCKS5")
    elif atyp == 0x04:
        _recv_exact(sock, 18, deadline, "SOCKS5")
    elif atyp == 0x03:
        length = _recv_exact(sock, 1, deadline, "SOCKS5")[0]
        _recv_exact(sock, length + 2, deadline, "SOCKS5")
    else:
        raise ProbeError("SOCKS5: неизвестный тип адреса в ответе")


def _http_connect(sock, target_host, target_port, deadline):
    authority = f"{target_host}:{int(target_port)}"
    sock.settimeout(deadline.timeout())
    sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
    head = b""
    while b"\r\n\r\n" not in head:
        deadline.check("CONNECT")
        if len(head) > 16384:
            raise ProbeError("CONNECT: слишком длинный ответ прокси")
        sock.settimeout(deadline.timeout())
        chunk = sock.recv(4096)
        if not chunk:
            raise ProbeError("CONNECT: прокси закрыл соединение")
        head += chunk
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = status_line.split()
    if len(parts) < 2 or parts[1] != "200":
        code = parts[1] if len(parts) > 1 else "?"
        raise ProbeError(f"CONNECT: прокси ответил {code}")
    # Anything after the head already belongs to the tunnel; a CONNECT reply carries none.


def _dechunk(body):
    out = b""
    rest = body
    while rest:
        line, sep, rest = rest.partition(b"\r\n")
        if not sep:
            break
        try:
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        rest = rest[size + 2:]
    return out


def _read_http_response(sock, deadline):
    data = b""
    while len(data) < _MAX_RESPONSE:
        if deadline.left() <= 0:
            break
        sock.settimeout(deadline.timeout())
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        except ssl.SSLError as exc:
            # A server that closes without close_notify is common and harmless here.
            if data and "EOF" in str(exc).upper():
                break
            raise ProbeError(f"TLS: {exc.__class__.__name__}") from None
        if not chunk:
            break
        data += chunk
        head, sep, body = data.partition(b"\r\n\r\n")
        if sep:
            headers = head.decode("latin-1", "replace").lower()
            for line in headers.split("\r\n")[1:]:
                name, _, value = line.partition(":")
                if name.strip() == "content-length":
                    try:
                        if len(body) >= int(value.strip()):
                            return data
                    except ValueError:
                        pass
    return data


def fetch_via_proxy(proxy_kind, proxy_port, target_host, path, *, budget=8.0, proxy_host="127.0.0.1",
                    target_port=443, use_tls=True, ssl_context=None):
    """GET `path` on `target_host` through a local proxy; returns the body text. Raises ProbeError.

    `proxy_kind` is "socks5" or "http". `use_tls=False` exists for tests with a plain fake server.
    """
    deadline = _Deadline(budget)
    kind = str(proxy_kind or "").strip().lower()
    if kind not in ("socks5", "http"):
        raise ProbeError(f"неизвестный вид прокси {kind!r}")
    raw = None
    conn = None
    try:
        try:
            raw = socket.create_connection((str(proxy_host), int(proxy_port)), timeout=min(2.0, deadline.timeout()))
        except OSError as exc:
            raise ProbeError(f"локальный порт {int(proxy_port)} не принимает: {exc.__class__.__name__}") from None
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            if kind == "socks5":
                _socks5_connect(raw, target_host, target_port, deadline)
            else:
                _http_connect(raw, target_host, target_port, deadline)
        except (OSError, socket.timeout) as exc:
            raise ProbeError(f"туннель до {target_host}: {exc.__class__.__name__}") from None
        conn = raw
        if use_tls:
            context = ssl_context or ssl.create_default_context()
            try:
                raw.settimeout(deadline.timeout())
                conn = context.wrap_socket(raw, server_hostname=str(target_host))
            except (OSError, ssl.SSLError) as exc:
                raise ProbeError(f"TLS до {target_host}: {exc.__class__.__name__}") from None
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: {_USER_AGENT}\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        try:
            conn.settimeout(deadline.timeout())
            conn.sendall(request)
            data = _read_http_response(conn, deadline)
        except (OSError, socket.timeout) as exc:
            raise ProbeError(f"ответ {target_host}: {exc.__class__.__name__}") from None
    finally:
        for sock in (conn, raw):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        raise ProbeError(f"{target_host}: нет ответа HTTP")
    status = head.split(b"\r\n", 1)[0].split()
    if len(status) < 2 or status[1] != b"200":
        code = status[1].decode("latin-1", "replace") if len(status) > 1 else "?"
        raise ProbeError(f"{target_host}: HTTP {code}")
    if b"transfer-encoding: chunked" in head.lower():
        body = _dechunk(body)
    return body.decode("utf-8", "replace")


def probe_exit_country(proxy_kind, proxy_port, *, budget=12.0, proxy_host="127.0.0.1", sources=SOURCES,
                       use_tls=True, ssl_context=None):
    """{"country", "colo", "source"} from the first source that answers, else raises ProbeError.

    The budget is shared by the sources in order; the owner's source always goes first (D20). Every
    source but the last gets at most FIRST_SOURCE_SHARE of what is left: on a slow tunnel (MASQUE,
    where one TCP handshake can take 6 s) a hung first source must not leave the fallback no time.
    """
    deadline = _Deadline(budget)
    errors = []
    sources = list(sources)
    for index, (target_host, path, source) in enumerate(sources):
        left = deadline.left()
        if left <= 0.5:
            break
        share = left if index == len(sources) - 1 else max(0.5, left * FIRST_SOURCE_SHARE)
        try:
            body = fetch_via_proxy(proxy_kind, proxy_port, target_host, path, budget=share, proxy_host=proxy_host,
                                   use_tls=use_tls, ssl_context=ssl_context)
        except ProbeError as exc:
            errors.append(f"{source}: {exc}")
            continue
        if source == "cloudflare":
            country, colo = parse_cf_trace(body)
        else:
            country, colo = parse_whatismyip(body), ""
        if country:
            return {"country": country, "colo": colo, "source": source}
        errors.append(f"{source}: ответ без страны")
    raise ProbeError("; ".join(errors) or "нет времени на замер")
