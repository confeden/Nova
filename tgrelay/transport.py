import asyncio
import ipaddress
import socket
import ssl
from typing import Callable, Dict, List, Optional, Tuple

from . import terminator
from .phase import Reached


_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def _tag(exc: BaseException, reached: int) -> BaseException:
    """Record how far an attempt got, on the exception that ended it.

    Annotating rather than wrapping is deliberate: every caller in the relay
    catches `OSError` and `asyncio.TimeoutError` by type, and a wrapper would
    make all of them stop matching. A caller that does not know about the
    annotation is unaffected; one that does can tell a route that never opened
    from a ClientHello that nobody answered — which are the same `OSError`
    today, and want opposite responses.
    """
    if not hasattr(exc, "nova_reached"):
        try:
            exc.nova_reached = int(reached)
        except Exception:
            pass
    return exc

_upstream_provider = None


def set_upstream_provider(provider: Optional[Callable[[], List[Dict[str, object]]]]) -> None:
    global _upstream_provider
    _upstream_provider = provider


def _default_attempts() -> List[Dict[str, object]]:
    return [
        {"kind": "socks5", "host": "127.0.0.1", "port": 1370, "label": "warp-socks"},
        {"kind": "http", "host": "127.0.0.1", "port": 1371, "label": "opera-http"},
        {"kind": "direct", "label": "direct"},
    ]


def get_upstream_attempts() -> List[Dict[str, object]]:
    try:
        if callable(_upstream_provider):
            attempts = _upstream_provider() or []
            cleaned = []
            for attempt in attempts:
                if not isinstance(attempt, dict):
                    continue
                kind = str(attempt.get("kind") or "").strip().lower()
                if kind not in {"socks5", "http", "direct"}:
                    continue
                cleaned.append(attempt)
            if cleaned:
                return cleaned
    except Exception:
        pass
    return _default_attempts()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("unexpected EOF from upstream proxy")
        data.extend(chunk)
    return bytes(data)


def _recv_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise OSError("proxy response too large")
    return bytes(data)


def _encode_socks_target(host: str) -> Tuple[bytes, bytes]:
    host = str(host or "").strip()
    try:
        addr = ipaddress.ip_address(host)
        if addr.version == 4:
            return b"\x01", addr.packed
        return b"\x04", addr.packed
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise OSError("target hostname too long for SOCKS5")
        return b"\x03", bytes([len(encoded)]) + encoded


def _connect_via_socks5(sock: socket.socket, target_host: str, target_port: int) -> None:
    sock.sendall(b"\x05\x01\x00")
    greeting = _recv_exact(sock, 2)
    if greeting != b"\x05\x00":
        raise OSError(f"SOCKS5 no-auth negotiation failed: {greeting!r}")

    atyp, addr_bytes = _encode_socks_target(target_host)
    req = b"\x05\x01\x00" + atyp + addr_bytes + int(target_port).to_bytes(2, "big")
    sock.sendall(req)

    header = _recv_exact(sock, 4)
    if header[0] != 0x05:
        raise OSError(f"invalid SOCKS5 version in reply: {header!r}")
    if header[1] != 0x00:
        raise OSError(f"SOCKS5 CONNECT failed with code {header[1]}")

    atyp = header[3]
    if atyp == 0x01:
        _recv_exact(sock, 4 + 2)
    elif atyp == 0x03:
        ln = _recv_exact(sock, 1)[0]
        _recv_exact(sock, ln + 2)
    elif atyp == 0x04:
        _recv_exact(sock, 16 + 2)
    else:
        raise OSError(f"unknown SOCKS5 reply ATYP {atyp}")


def _connect_via_http(sock: socket.socket, target_host: str, target_port: int) -> None:
    authority = f"{target_host}:{int(target_port)}"
    req = (
        f"CONNECT {authority} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Proxy-Connection: Keep-Alive\r\n"
        "User-Agent: NovaTelegramRelay/1\r\n"
        "\r\n"
    ).encode("ascii", "ignore")
    sock.sendall(req)
    response = _recv_until(sock, b"\r\n\r\n")
    first_line = response.split(b"\r\n", 1)[0].decode("latin1", "replace")
    parts = first_line.split(" ", 2)
    status_code = 0
    try:
        if len(parts) >= 2:
            status_code = int(parts[1])
    except Exception:
        status_code = 0
    if status_code != 200:
        raise OSError(f"HTTP CONNECT failed: {first_line}")


def _open_tunnel_socket_sync(
    target_host: str,
    target_port: int,
    timeout: float,
    attempts: List[Dict[str, object]],
) -> Tuple[socket.socket, str]:
    last_error = None
    for attempt in attempts:
        kind = str(attempt.get("kind") or "").strip().lower()
        label = str(attempt.get("label") or kind or "unknown").strip() or "unknown"
        proxy_host = str(attempt.get("host") or "127.0.0.1").strip()
        proxy_port = int(attempt.get("port") or 0)
        try:
            attempt_timeout = max(0.2, float(attempt.get("timeout") or timeout))
        except Exception:
            attempt_timeout = float(timeout)
        sock = None
        try:
            if kind == "direct":
                sock = socket.create_connection((target_host, int(target_port)), timeout=attempt_timeout)
            else:
                sock = socket.create_connection((proxy_host, proxy_port), timeout=attempt_timeout)
                if kind == "socks5":
                    _connect_via_socks5(sock, target_host, int(target_port))
                elif kind == "http":
                    _connect_via_http(sock, target_host, int(target_port))
                else:
                    raise OSError(f"unsupported upstream kind: {kind}")
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            sock.setblocking(False)
            return sock, label
        except Exception as exc:
            last_error = exc
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass
            continue
    if last_error is None:
        last_error = OSError("no upstream attempts available")
    # A name that never became an address and a route that never opened are
    # both an `OSError` here, and they want different answers: one is the
    # resolver's problem and must not be charged to a domain or an egress, the
    # other is exactly what picking another egress is for.
    raise _tag(last_error, Reached.NOTHING if isinstance(last_error, socket.gaierror) else Reached.RESOLVED)


async def open_stream(
    target_host: str,
    target_port: int,
    timeout: float = 10.0,
    attempts: Optional[List[Dict[str, object]]] = None,
):
    chosen_attempts = get_upstream_attempts() if attempts is None else attempts
    sock, label = await asyncio.to_thread(
        _open_tunnel_socket_sync,
        target_host,
        int(target_port),
        float(timeout),
        chosen_attempts,
    )
    reader, writer = await asyncio.open_connection(sock=sock)
    return reader, writer, label


async def open_tls_stream(
    target_host: str,
    target_port: int = 443,
    server_hostname: Optional[str] = None,
    timeout: float = 10.0,
    attempts: Optional[List[Dict[str, object]]] = None,
):
    chosen_attempts = get_upstream_attempts() if attempts is None else attempts

    # When the shaping helper is running, the handshake happens there instead —
    # CPython's ClientHello is `t13d181100`, which identifies Nova and nothing
    # else. The contract is unchanged: same arguments, same three return values,
    # and failures still arrive as an annotated OSError. Off unless configured,
    # so this stays a lever rather than a migration.
    if terminator.is_enabled():
        return await terminator.open_shaped_stream(
            target_host,
            int(target_port),
            server_hostname=server_hostname,
            timeout=float(timeout),
            attempts=chosen_attempts,
        )

    sock, label = await asyncio.to_thread(
        _open_tunnel_socket_sync,
        target_host,
        int(target_port),
        float(timeout),
        chosen_attempts,
    )
    try:
        reader, writer = await asyncio.open_connection(
            sock=sock,
            ssl=_ssl_ctx,
            server_hostname=(server_hostname or target_host),
            ssl_handshake_timeout=float(timeout),
        )
    except BaseException as exc:
        # TCP is already up at this point, so whatever went wrong went wrong
        # after our ClientHello was on the wire. This is the only window in the
        # whole connection where the shape of that hello is a live suspect.
        try:
            sock.close()
        except Exception:
            pass
        raise _tag(exc, Reached.HELLO_SENT)
    return reader, writer, label
