"""Distance to VPN nodes by TCP connect time -- the order «ближайший первым» is built from it.

Ported from Nova Android `ProtonLatency.kt`, with its reasons:

* the honest measurement would be a WireGuard handshake, but from Russia Proton answers it on
  none of fifty nodes, so ranking fell back to the API's `Load` and the queue started on another
  continent;
* a plain TCP connect to the node's entry address follows the same path, and Proton keeps OpenVPN
  TCP on 443 there: measured 61 ms to NO, 74 ms to NL, 150 ms to CA, 215 ms to US -- ordered
  exactly as geography predicts;
* ICMP is not used: it is often filtered on its own, and a TCP connect works wherever the network
  works at all.

It proves nothing about the key or about UDP reachability (Android G207: TCP 443 answered 78 of
80 nodes while most were UDP-dead), so it only orders; attempt outcomes decide first
(nova_profiles._proton_order).

The sockets are plain ones opened by Nova's own process, which no redirect intercepts, so the
number describes the direct path to the node rather than the tunnel that is up right now.
"""

import concurrent.futures
import ipaddress
import socket
import time

__all__ = ["DEFAULT_PORT", "endpoint_host", "measure_tcp_rtt", "measure_tcp_rtts"]

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 2.0
MAX_WORKERS = 16


def endpoint_host(endpoint):
    """`1.2.3.4:51820` / `[2001:db8::1]:443` / `host:88` -> the host part; "" when there is none."""
    text = str(endpoint or "").strip()
    if not text:
        return ""
    if text.startswith("["):
        host, sep, _rest = text[1:].partition("]")
        return host if sep else ""
    if text.count(":") > 1:
        # A bare IPv6 literal without a port.
        try:
            ipaddress.ip_address(text)
            return text
        except ValueError:
            return ""
    return text.partition(":")[0]


def measure_tcp_rtt(host, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT, connect=None):
    """Milliseconds to establish TCP with host:port (at least 1), or None when it did not connect."""
    host = str(host or "").strip()
    if not host:
        return None
    opener = connect or socket.create_connection
    started = time.perf_counter()
    sock = None
    try:
        sock = opener((host, int(port)), timeout=float(timeout))
    except (OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return max(1, int(round((time.perf_counter() - started) * 1000)))


def measure_tcp_rtts(targets, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT, max_workers=MAX_WORKERS,
                     should_stop=None, connect=None):
    """`{key: host}` -> `{key: ms or None}`, measured in parallel; one host is measured once.

    `should_stop()` returning True abandons the hosts not started yet (they come back as None).
    """
    items = [(key, str(host or "").strip()) for key, host in dict(targets or {}).items()]
    hosts = sorted({host for _key, host in items if host})
    results = {}
    if hosts:
        workers = max(1, min(int(max_workers), len(hosts)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="NovaRtt") as pool:
            def measure(host):
                # Checked when the worker picks the host up, not when it is queued: every host is
                # queued at once, so a check at submit time could never stop anything.
                if callable(should_stop) and should_stop():
                    return None
                return measure_tcp_rtt(host, port, timeout, connect)

            futures = {pool.submit(measure, host): host for host in hosts}
            for future in concurrent.futures.as_completed(futures):
                try:
                    results[futures[future]] = future.result()
                except Exception:
                    results[futures[future]] = None
    return {key: results.get(host) for key, host in items}
