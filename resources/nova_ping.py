"""Cheap reachability and latency of a VPN node — ICMP first, TCP as the fallback.

Why this exists beside `nova_latency` (TCP connect) and `nova_wg_probe` (a real WireGuard
handshake): the «Профили» window wants a latency figure for *every* row, refreshed while the window
is open, and neither of the other two can give it.

* `nova_wg_probe` is the only honest answer about a node, and it is exactly what must not be used in
  bulk. Every finished handshake takes a Proton key over from the live tunnel (G71), and the nodes
  probed hardest stop answering the key for 25+ minutes (G72); a fifty-node sweep was built,
  measured and removed the same day (N26). It stays for the one node being connected.
* `nova_latency` connects TCP 443. That works for Proton (Proton keeps OpenVPN TCP there — 61 ms to
  NO, 215 ms to US) and for MASQUE (443 is the CONNECT-IP endpoint), and says nothing at all about a
  Cloudflare WARP endpoint, whose `162.159.192.x:<random>` is UDP only.

ICMP covers exactly that gap. Measured on the owner's PC (RU ISP, 2026-09-20) with the code below:
`162.159.192.1` 60 ms, `162.159.192.101` 59 ms, `162.159.198.1` 27 ms, `1.1.1.1` 31 ms,
`8.8.8.8` 51 ms — every WARP endpoint address answers, and the call costs one UDP-sized packet.

`IcmpSendEcho` is used rather than a raw socket on purpose: `iphlpapi.dll` does the ICMP itself in
the kernel, so it needs **no administrator rights and no raw socket**, and it cannot be confused by
Nova's own WinDivert redirect, which works on TCP/UDP.

What a number here does and does not mean:

* it is the distance to the *address*, not proof that the tunnel would come up. A WARP endpoint IP
  is anycast and its port is not probed; a Proton node that answers ICMP can still be UDP-dead
  (Android G207: TCP 443 answered 78 of 80 nodes while most were dead). So it orders rows and marks
  the plainly unreachable — it never overrules a recorded attempt outcome;
* the sockets and the echo are Nova's own and go out on the direct route, so the figure describes
  the path to the node, not the tunnel that happens to be up.

ICMP is filtered on some paths; that is why a failure falls through to a TCP connect instead of
being reported as «unreachable», and why `method` travels with the result.
"""

import concurrent.futures
import ctypes
import socket
import struct
import threading
import time

__all__ = [
    "METHOD_ICMP", "METHOD_TCP", "Result",
    "icmp_available", "icmp_rtt", "tcp_rtt", "probe_host", "probe_hosts",
]

METHOD_ICMP = "icmp"
METHOD_TCP = "tcp"

DEFAULT_TIMEOUT_MS = 1200
DEFAULT_TCP_PORTS = (443,)
MAX_WORKERS = 8

# `IP_SUCCESS`. Everything else (11010 IP_REQ_TIMED_OUT, 11003 IP_DEST_HOST_UNREACHABLE, ...) is a
# failure as far as this module is concerned: the distinction between "filtered" and "dead" cannot be
# drawn from ICMP alone, and the TCP fallback is what decides it.
_IP_SUCCESS = 0


class Result(object):
    """One measurement: `ms` (None when nothing answered) and how it was obtained."""

    __slots__ = ("ms", "method")

    def __init__(self, ms=None, method=""):
        self.ms = ms
        self.method = method

    def __bool__(self):
        return self.ms is not None

    __nonzero__ = __bool__

    def __repr__(self):
        return "Result(ms=%r, method=%r)" % (self.ms, self.method)

    def __eq__(self, other):
        return isinstance(other, Result) and other.ms == self.ms and other.method == self.method

    def __hash__(self):
        return hash((self.ms, self.method))


class _IcmpEchoReply(ctypes.Structure):
    """`ICMP_ECHO_REPLY` of ipexport.h, flattened: only `Status` and `RoundTripTime` are read."""

    _fields_ = [
        ("Address", ctypes.c_uint32),
        ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options_Ttl", ctypes.c_ubyte),
        ("Options_Tos", ctypes.c_ubyte),
        ("Options_Flags", ctypes.c_ubyte),
        ("Options_OptionsSize", ctypes.c_ubyte),
        ("Options_OptionsData", ctypes.c_void_p),
    ]


_ICMP_LOCK = threading.Lock()
_ICMP_STATE = {"tried": False, "dll": None, "handle": None}

# The four data bytes ride back in the reply; they are only there so the packet is not empty.
_ECHO_PAYLOAD = b"nova"


def _icmp_handle():
    """The process-wide `IcmpCreateFile` handle, or None where ICMP is not available.

    One handle for the whole process: `IcmpSendEcho` is documented as thread-safe on a shared handle,
    and opening one per probe would make a fifty-row sweep fifty handle opens.
    """
    with _ICMP_LOCK:
        if not _ICMP_STATE["tried"]:
            _ICMP_STATE["tried"] = True
            try:
                dll = ctypes.WinDLL("iphlpapi.dll")
                dll.IcmpCreateFile.restype = ctypes.c_void_p
                dll.IcmpSendEcho.argtypes = [
                    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_ushort,
                    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong,
                ]
                dll.IcmpSendEcho.restype = ctypes.c_ulong
                handle = dll.IcmpCreateFile()
                # INVALID_HANDLE_VALUE comes back as -1 or as the unsigned form of it.
                if not handle or handle in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
                    handle = None
            except (AttributeError, OSError, ValueError):
                dll, handle = None, None
            _ICMP_STATE["dll"] = dll
            _ICMP_STATE["handle"] = handle
        return _ICMP_STATE["dll"], _ICMP_STATE["handle"]


def icmp_available():
    """True when this machine can send an ICMP echo through iphlpapi (Windows with the DLL)."""
    dll, handle = _icmp_handle()
    return bool(dll is not None and handle)


def _resolve_v4(host):
    """`host` -> one IPv4 literal, or "" when it does not resolve to IPv4.

    IPv6 is deliberately not probed: `Icmp6SendEcho2` needs a source address and a bound socket, and
    every endpoint Nova stores today is reachable over IPv4. A v6-only host falls through to TCP.
    """
    text = str(host or "").strip()
    if not text:
        return ""
    try:
        socket.inet_aton(text)
        return text
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(text, None, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return ""
    for info in infos:
        addr = info[4][0]
        if addr:
            return str(addr)
    return ""


def icmp_rtt(host, timeout_ms=DEFAULT_TIMEOUT_MS, resolve=None):
    """Milliseconds to `host` by ICMP echo (at least 1), or None when nothing answered.

    `resolve` is the seam the tests use; it takes the host and returns an IPv4 literal or "".
    """
    dll, handle = _icmp_handle()
    if dll is None or not handle:
        return None
    resolver = resolve or _resolve_v4
    address = resolver(host)
    if not address:
        return None
    try:
        dest = struct.unpack("<I", socket.inet_aton(address))[0]
    except (OSError, struct.error):
        return None
    size = ctypes.sizeof(_IcmpEchoReply) + len(_ECHO_PAYLOAD) + 8
    buffer = ctypes.create_string_buffer(size)
    try:
        answered = dll.IcmpSendEcho(
            handle, ctypes.c_uint32(dest), _ECHO_PAYLOAD, ctypes.c_ushort(len(_ECHO_PAYLOAD)),
            None, buffer, ctypes.c_ulong(size), ctypes.c_ulong(max(1, int(timeout_ms))),
        )
    except (OSError, ValueError, ctypes.ArgumentError):
        return None
    if not answered:
        return None
    reply = ctypes.cast(buffer, ctypes.POINTER(_IcmpEchoReply)).contents
    if int(reply.Status) != _IP_SUCCESS:
        return None
    # Windows reports whole milliseconds and 0 for a reply that came back inside one tick.
    return max(1, int(reply.RoundTripTime))


def tcp_rtt(host, port, timeout_ms=DEFAULT_TIMEOUT_MS, connect=None):
    """Milliseconds to establish TCP with `host:port` (at least 1), or None.

    Same measurement as `nova_latency.measure_tcp_rtt`; kept here so this module has no import of
    its own and so the timeout is stated in milliseconds like everything else on this path.
    """
    text = str(host or "").strip()
    if not text:
        return None
    opener = connect or socket.create_connection
    started = time.perf_counter()
    sock = None
    try:
        sock = opener((text, int(port)), timeout=max(0.05, float(timeout_ms) / 1000.0))
    except (OSError, ValueError, OverflowError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return max(1, int(round((time.perf_counter() - started) * 1000)))


def probe_host(host, tcp_ports=DEFAULT_TCP_PORTS, timeout_ms=DEFAULT_TIMEOUT_MS,
               icmp=None, tcp=None):
    """ICMP first, then each TCP port in turn. Returns a `Result`; `ms` is None when all failed.

    ICMP goes first because it is the only thing that reaches a WARP endpoint at all and because it
    costs one packet; TCP follows for the paths where ICMP is filtered. `icmp`/`tcp` are the seams
    the tests inject.
    """
    host = str(host or "").strip()
    if not host:
        return Result(None, "")
    icmp_fn = icmp or icmp_rtt
    ms = icmp_fn(host, timeout_ms)
    if ms is not None:
        return Result(int(ms), METHOD_ICMP)
    tcp_fn = tcp or tcp_rtt
    for port in tcp_ports or ():
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            continue
        if not (0 < port_number < 65536):
            continue
        ms = tcp_fn(host, port_number, timeout_ms)
        if ms is not None:
            return Result(int(ms), METHOD_TCP)
    return Result(None, "")


def probe_hosts(targets, timeout_ms=DEFAULT_TIMEOUT_MS, max_workers=MAX_WORKERS,
                should_stop=None, probe=None, pace_sec=0.0, sleep=None):
    """`{key: host}` or `{key: (host, ports)}` -> `{key: Result}`; one host is measured once.

    Bounded on purpose. `max_workers` is 8 rather than `nova_latency`'s 16 because this runs while
    the owner is looking at a window rather than while a connection is being made, and `pace_sec`
    puts a gap between the starts so a fifty-row sweep is a trickle instead of a burst — the whole
    point of the module is that a window refresh must not be felt.

    `should_stop()` is checked when a worker picks its host up (not at submit time: everything is
    queued at once, so a check there could never stop anything); abandoned hosts come back as an
    empty `Result`. The window closing is what calls it.
    """
    items = []
    for key, value in dict(targets or {}).items():
        if isinstance(value, (tuple, list)):
            host = str(value[0] or "").strip() if value else ""
            ports = tuple(value[1]) if len(value) > 1 and value[1] else DEFAULT_TCP_PORTS
        else:
            host, ports = str(value or "").strip(), DEFAULT_TCP_PORTS
        items.append((key, host, ports))

    plan = {}
    for _key, host, ports in items:
        if host and host not in plan:
            plan[host] = ports

    measured = {}
    if plan:
        probe_fn = probe or probe_host
        napper = sleep or time.sleep
        gate = threading.Lock()
        workers = max(1, min(int(max_workers), len(plan)))

        def measure(host, ports):
            if callable(should_stop) and should_stop():
                return Result(None, "")
            if pace_sec > 0:
                # Serialised: the gap is between *starts*, so `workers` probes are in flight at most
                # and they enter one at a time.
                with gate:
                    if callable(should_stop) and should_stop():
                        return Result(None, "")
                    napper(float(pace_sec))
            return probe_fn(host, ports, timeout_ms)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers,
                                                   thread_name_prefix="NovaPing") as pool:
            futures = {pool.submit(measure, host, ports): host for host, ports in plan.items()}
            for future in concurrent.futures.as_completed(futures):
                try:
                    measured[futures[future]] = future.result()
                except Exception:
                    measured[futures[future]] = Result(None, "")

    return {key: measured.get(host, Result(None, "")) for key, host, _ports in items}
