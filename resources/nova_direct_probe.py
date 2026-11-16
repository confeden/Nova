"""One cheap probe: does `host` open DIRECTLY (through the winws strategy) over HTTPS?

Not a speed test and not a download: TCP connect, a verified TLS handshake with the host's own SNI and
one small `HEAD /` — up to BULK_BYTES in total, a 3.5 s budget plus a BULK_BUDGET_SEC read window. What it tells apart is what DPI does to a
blocked name: the SYN is refused or dropped (`tcp`), the ClientHello is silently dropped so the handshake
never ends (`tls`), the connection is reset (`reset`), a stub certificate comes back (`cert`), or the
handshake completes but nothing answers (`silent`, the throttling case), or the answer starts and then
freezes before BULK_BYTES have arrived (`cut`: the ~16 KB cut that a HEAD never sees, measured on 35 of
the 389 main.txt hosts). Any HTTP status line — 301, 403, 404 included — means the path works: the site
refusing a bot is not the network refusing Nova. A body shorter than BULK_BYTES that ends with the
connection closing is complete and counts as ok.
`ok` is None when the probe could not judge (no DNS, a local error): nothing is recorded for that.
Stdlib only, no Nova globals; sockets are injectable for the tests (I15).
"""

import socket
import ssl
import time

__all__ = ["probe", "classify_exception", "DEFAULT_BUDGET_SEC", "BULK_BYTES", "BULK_BUDGET_SEC"]

DEFAULT_BUDGET_SEC = 3.5
BULK_BYTES = 64 * 1024  # past the ~16 KB freeze with room to spare, still one small request
BULK_BUDGET_SEC = 4.0   # a healthy host delivers this in well under a second
_REQUEST = "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"


def classify_exception(stage, exc):
    """(ok, why) for an exception raised at `stage` in {"tcp", "tls", "http"}."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return False, "cert"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return False, {"tcp": "tcp", "tls": "tls", "http": "silent", "bulk": "cut"}.get(stage, "tcp")
    if stage == "bulk" and isinstance(exc, ssl.SSLError) and not isinstance(exc, ssl.SSLCertVerificationError):
        return False, "cut"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return False, "reset"
    if isinstance(exc, ConnectionRefusedError):
        return False, "tcp"
    if isinstance(exc, ssl.SSLError):
        return False, "tls"
    if isinstance(exc, OSError):
        # Unreachable network / host: the path is broken, which is a verdict; anything else is local.
        if getattr(exc, "winerror", None) in (10051, 10060, 10061, 10065) or getattr(exc, "errno", None) in (101, 110, 111, 113):
            return False, "tcp"
        return None, "local"
    return None, "local"


def _same_site_redirect(head, host):
    """The https host a 301/302/303/307/308 points at when it is `host`'s own site (www.x for x), else ""."""
    try:
        crlf = bytes((13, 10))
        first, _sep, rest = head.partition(crlf)
        parts = first.split()
        if len(parts) < 2 or parts[1] not in (b"301", b"302", b"303", b"307", b"308"):
            return ""
        for line in rest.split(crlf + crlf, 1)[0].split(crlf):
            name, _colon, value = line.partition(b":")
            if name.strip().lower() == b"location":
                url = value.strip().decode("ascii", "ignore")
                if not url.lower().startswith("https://"):
                    return ""
                target = url[8:].split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].lower()
                base = host.lower()
                return target if target != base and target.endswith("." + base) else ""
    except Exception:  # noqa: BLE001 - a malformed header is just "no redirect"
        pass
    return ""


def probe(host, port=443, budget=DEFAULT_BUDGET_SEC, *, resolver=None, connector=None, context=None,
          clock=time.monotonic, bulk=BULK_BYTES, bulk_budget=BULK_BUDGET_SEC, follow=1):
    """{"ok": True|False|None, "why": str, "ms": int} for one host. Never raises.

    `bulk` = 0 skips the body read (status line only, the old behaviour). `follow` = 1 chases one
    same-site redirect (x -> www.x)."""
    started = clock()

    def left():
        return max(0.2, float(budget) - (clock() - started))

    def done(ok, why):
        return {"ok": ok, "why": why, "ms": int((clock() - started) * 1000)}

    try:
        infos = (resolver or _resolve)(host, port)
    except (OSError, UnicodeError):
        return done(None, "dns")
    if not infos:
        return done(None, "dns")
    infos = sorted(infos, key=lambda item: item[0] != socket.AF_INET)  # IPv4 first: Nova steers away from v6
    ctx = context
    if ctx is None:
        # The chain must verify (a DPI stub page presents an untrusted one), the NAME need not: an apex
        # whose certificate is `*.example.com`, or a front that answers with its default vhost, still
        # proves the ClientHello went through and a real server answered.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
    sock = None
    stage = "tcp"
    try:
        sock = (connector or _connect)(infos[0], min(2.0, left()))
        stage = "tls"
        sock.settimeout(left())
        tls = ctx.wrap_socket(sock, server_hostname=host)
        sock = tls
        stage = "http"
        tls.settimeout(left())
        tls.sendall(_REQUEST.format(host=host).encode("ascii", "ignore"))
        head = tls.recv(65536)
        if not head.startswith(b"HTTP/"):
            # A handshake that completes and then yields something that is not HTTP is a middlebox.
            return done(False, "silent" if not head else "junk")
        target = _same_site_redirect(head, host) if follow else ""
        if target:
            # `x` answers with a bare redirect to `www.x`: the page people load, and the freeze, is there.
            sock.close()
            sock = None
            nxt = probe(target, port, budget, resolver=resolver, connector=connector, context=context,
                        clock=clock, bulk=bulk, bulk_budget=bulk_budget, follow=0)
            return done(nxt["ok"], nxt["why"])
        got = len(head)
        stage = "bulk"
        window_end = clock() + float(bulk_budget)
        while got < int(bulk or 0):
            remaining = window_end - clock()
            if remaining <= 0:
                return done(False, "cut")
            tls.settimeout(max(0.2, remaining))
            try:
                chunk = tls.recv(min(65536, int(bulk) - got))
            except ssl.SSLEOFError:
                break  # the server closed without close_notify: the body ended
            if not chunk:
                break  # connection closed: the whole body arrived
            got += len(chunk)
        return done(True, "ok")
    except Exception as exc:  # noqa: BLE001 - every failure is classified, none escapes
        ok, why = classify_exception(stage, exc)
        return done(ok, why)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _resolve(host, port):
    return socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)


def _connect(info, timeout):
    family, kind, proto, _canon, address = info
    sock = socket.socket(family, kind, proto)
    try:
        sock.settimeout(timeout)
        sock.connect(address)
    except Exception:
        sock.close()
        raise
    return sock
