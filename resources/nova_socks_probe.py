"""Cheap end-to-end liveness probe for a local SOCKS5 egress.

It answers exactly one question: do bytes leave through the proxy and come back?

**Why a CONNECT reply is not enough.** wireproxy answers the SOCKS5 CONNECT
optimistically, before anything has crossed the WireGuard tunnel, so the reply
arrives even when the data path is dead (`kb/open-issues.md#o5`). The probe must
therefore send a real request and read a real answer.

**Why not curl.** The previous implementation spawned `curl.exe` for
``https://cloudflare.com/cdn-cgi/trace`` on every call, and the WARP watchdog calls
it every 3 seconds: a Windows process creation, a TLS 1.3 handshake with
certificate verification, and a DNS lookup through the tunnel -- three expensive
things to learn one bit. Plain HTTP to a literal address drops all three. The
verdict is not weakened: WARP's egress *is* Cloudflare, so ``1.1.1.1`` sits exactly
as close as ``cloudflare.com`` did, and this is the same probe shape whose 30
consecutive failures identified the dead-data incident in O5.

Losing the DNS step is a deliberate improvement, not a gap: a slow resolver inside
the tunnel used to read as "traffic is dead" and trigger a pointless recovery.

The module is deliberately free of Nova globals, Tk and logging so it can be unit
tested against a fake SOCKS5 server (`tests/test_socks_probe.py`).
"""

import socket
import struct
import time

# 1.1.1.1 is Cloudflare's own anycast address, i.e. the near side of a WARP exit,
# and port 80 keeps the exchange to one round trip with no crypto. The response is
# usually a 301 to HTTPS -- irrelevant, a status line is already proof that the
# tunnel carried bytes in both directions.
DEFAULT_TARGET_IP = "1.1.1.1"
DEFAULT_TARGET_PORT = 80
DEFAULT_REQUEST = (
    b"GET /cdn-cgi/trace HTTP/1.1\r\n"
    b"Host: one.one.one.one\r\n"
    b"User-Agent: Nova/probe\r\n"
    b"Accept: */*\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
DEFAULT_EXPECT_PREFIX = b"HTTP/1."

# settimeout(0) switches a socket to non-blocking instead of "give up now", which
# would turn an expired deadline into a busy loop of BlockingIOError. Every
# settimeout() below goes through this floor.
_MIN_SOCKET_TIMEOUT = 0.05
_MIN_BUDGET = 0.3
# The local hop is loopback; a proxy that cannot accept within this is not running.
_LOCAL_CONNECT_CAP = 1.5


class Deadline:
    """Monotonic budget shared by every step of one probe."""

    def __init__(self, budget):
        try:
            seconds = float(budget)
        except (TypeError, ValueError):
            seconds = _MIN_BUDGET
        if seconds < _MIN_BUDGET:
            seconds = _MIN_BUDGET
        self._end = time.monotonic() + seconds

    def remaining(self):
        return self._end - time.monotonic()

    def expired(self):
        return self.remaining() <= 0.0

    def timeout(self, cap=None):
        """Socket timeout for the next operation, never zero."""
        left = self.remaining()
        if cap is not None and left > cap:
            left = cap
        if left < _MIN_SOCKET_TIMEOUT:
            left = _MIN_SOCKET_TIMEOUT
        return left


def _recv_exact(sock, count, deadline):
    """Read exactly `count` bytes, or None on short read / timeout / deadline."""
    chunks = []
    got = 0
    while got < count:
        if deadline.expired():
            return None
        sock.settimeout(deadline.timeout())
        chunk = sock.recv(count - got)
        if not chunk:
            return None
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _skip_bound_address(sock, atyp, deadline):
    """Drain the BND.ADDR/BND.PORT tail of a SOCKS5 reply.

    Left unread it would be mistaken for the target's answer. The old inline probe
    read a flat 10 bytes, which is right only for an IPv4 reply -- a proxy that
    answers with a domain or IPv6 bound address would have desynchronised it.
    """
    if atyp == 0x01:          # IPv4
        return _recv_exact(sock, 4 + 2, deadline) is not None
    if atyp == 0x04:          # IPv6
        return _recv_exact(sock, 16 + 2, deadline) is not None
    if atyp == 0x03:          # length-prefixed domain
        length = _recv_exact(sock, 1, deadline)
        if not length:
            return False
        return _recv_exact(sock, length[0] + 2, deadline) is not None
    return False


def socks5_connect(sock, target_ip, target_port, deadline):
    """SOCKS5 greeting + CONNECT to a literal IPv4 address.

    The address is sent as ATYP=IPv4 on purpose: asking the proxy to resolve a name
    would put a DNS round trip inside a liveness check, which is what made the
    previous probe flap.
    """
    sock.settimeout(deadline.timeout())
    sock.sendall(b"\x05\x01\x00")
    greeting = _recv_exact(sock, 2, deadline)
    if greeting != b"\x05\x00":
        return False

    request = (
        b"\x05\x01\x00\x01"
        + socket.inet_aton(str(target_ip))
        + struct.pack("!H", int(target_port))
    )
    sock.settimeout(deadline.timeout())
    sock.sendall(request)

    head = _recv_exact(sock, 4, deadline)
    if not head or head[0] != 0x05 or head[1] != 0x00:
        return False
    return _skip_bound_address(sock, head[3], deadline)


def probe_socks5_payload(
    port,
    budget=4.0,
    host="127.0.0.1",
    target_ip=DEFAULT_TARGET_IP,
    target_port=DEFAULT_TARGET_PORT,
    request=DEFAULT_REQUEST,
    expect_prefix=DEFAULT_EXPECT_PREFIX,
):
    """True when a payload made a full round trip through the SOCKS5 proxy.

    Never raises: every failure mode -- refused, half-open, silent after CONNECT,
    protocol garbage, budget exhausted -- is the same answer, "not usable".
    """
    deadline = Deadline(budget)
    sock = None
    try:
        sock = socket.create_connection(
            (str(host), int(port)),
            timeout=deadline.timeout(cap=_LOCAL_CONNECT_CAP),
        )
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        if not socks5_connect(sock, target_ip, target_port, deadline):
            return False

        sock.settimeout(deadline.timeout())
        sock.sendall(request)

        expected = bytes(expect_prefix or b"")
        seen = b""
        while len(seen) < len(expected):
            if deadline.expired():
                return False
            sock.settimeout(deadline.timeout())
            chunk = sock.recv(256)
            if not chunk:
                return False
            seen += chunk
        return seen.startswith(expected)
    except Exception:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
