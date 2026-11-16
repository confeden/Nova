"""Hedged direct -> main -> second route for browser HTTPS to hosts that are on no list (D75, S119).

A browser on «Auto» sends an unlisted https host with no verdict to the local CONNECT proxy
(tcp_proxy.py, port 1376). The proxy reads the client's ClientHello, then runs `race`:

- DIRECT starts at once (winws applies the general strategy to it, there is no separate «try a strategy»);
- the VPN chain (main, then second; the caller supplies only slots with a proven foreign exit) is
  started in parallel when direct is late: no SYN-ACK after `syn_hedge` s (a healthy connect has
  p99 1.05 s, S118), or no ServerHello `hello_hedge` s after the ClientHello went out (a healthy
  ALT4 handshake has p90 0.78 s), or the moment direct fails outright (DNS, RST, alert, close);
- the first path that returns a TLS handshake record wins, DIRECT on a tie; the loser is closed.

What the race learned is handed over as an observation (host, direct|vpn, why) in a small JSON file the
verdict worker of nova.pyw reads, so the host stops going through the proxy once it has a verdict. A
dead SYN is the only cheap proof of an IP block (N33: 8/8 unfixable); a dropped hello is not (70/81
opened by some strategy), so the two reasons stay apart ("tcp" vs "tls").

Nothing here touches Nova globals or the clock directly (I15): every dial is injected, the clock too.
"""

import asyncio
import contextlib
import ipaddress
import json
import os
import time

__all__ = [
    "Timings", "PathError", "RaceFailed", "RaceResult", "race", "parse_connect", "looks_like_tls_handshake",
    "looks_like_client_hello", "SynDeadCache", "DirectHealth", "HostMemory", "ObservedStore", "read_observed",
    "observation_for", "unlisted_proxy_enabled",
]

HEALTH_FRESH_SEC = 30.0
SYN_DEAD_RANGE_SEC = 600.0
SYN_DEAD_IP_SEC = 120.0
SYN_DEAD_RANGE_MIN_IPS = 2
HOST_MEMORY_SEC = 600.0
OBSERVED_MAX_ROWS = 400
OBSERVED_TTL_SEC = 24 * 3600.0
OBSERVED_FLUSH_GAP_SEC = 2.0


def unlisted_proxy_enabled(env=None):
    """NOVA_UNLISTED_PROXY=0 puts the PAC tail back to a plain DIRECT."""
    env = os.environ if env is None else env
    return str(env.get("NOVA_UNLISTED_PROXY", "1")).strip().lower() not in ("0", "false", "no", "off")


class Timings(object):
    """Seconds. `*_cap` bound a single path; the hedges decide when the VPN chain joins."""

    def __init__(self, syn_hedge=1.0, hello_hedge=1.2, direct_cap=10.0, vpn_cap=7.0, vpn_dial_cap=3.5, tick=0.02):
        self.syn_hedge = float(syn_hedge)
        self.hello_hedge = float(hello_hedge)
        self.direct_cap = float(direct_cap)
        self.vpn_cap = float(vpn_cap)
        self.vpn_dial_cap = float(vpn_dial_cap)
        self.tick = float(tick)


class PathError(Exception):
    """One path failed. `kind`: dns | tcp | tls | reset | alert | closed | slow."""

    def __init__(self, kind, detail=""):
        Exception.__init__(self, "%s %s" % (kind, detail) if detail else str(kind))
        self.kind = str(kind)


class RaceFailed(Exception):
    def __init__(self, direct_why, vpn_why):
        Exception.__init__(self, "direct=%s vpn=%s" % (direct_why or "-", vpn_why or "-"))
        self.direct_why = direct_why
        self.vpn_why = vpn_why


class RaceResult(object):
    def __init__(self, route, label, reader, writer, first, ms, direct_why, vpn_started, direct_ip=""):
        self.route = route              # "direct" | "vpn"
        self.label = label              # "direct" or the VPN label that won
        self.reader = reader
        self.writer = writer
        self.first = first              # bytes already read from the winner (the ServerHello flight)
        self.ms = int(ms)
        self.direct_why = direct_why    # None when direct won, else the reason direct lost
        self.vpn_started = bool(vpn_started)
        self.direct_ip = direct_ip


# -- wire helpers --------------------------------------------------------------------------------

def looks_like_tls_handshake(data):
    """First record of a server reply is Handshake 0x16, version 3.x (not an alert 0x15, not junk)."""
    return len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03


def looks_like_client_hello(data):
    return len(data) >= 6 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01


def parse_connect(head):
    """b'CONNECT host:port HTTP/1.x\\r\\n...' -> (host, port) or None. IPv6 literals as [::1]:443."""
    try:
        line = bytes(head).split(b"\r\n", 1)[0].decode("latin-1")
    except Exception:
        return None
    parts = line.split()
    if len(parts) != 3 or parts[0].upper() != "CONNECT" or not parts[2].upper().startswith("HTTP/"):
        return None
    target = parts[1]
    if target.startswith("["):
        end = target.find("]")
        if end < 0:
            return None
        host, rest = target[1:end], target[end + 1:]
        port_text = rest[1:] if rest.startswith(":") else ""
    else:
        host, _sep, port_text = target.rpartition(":")
    host = host.strip().strip(".").lower()
    if not host or not (port_text.isascii() and port_text.isdigit()) or not (0 < int(port_text) < 65536):
        return None
    if any(ch in host for ch in " /\\\t\r\n\x00"):
        return None
    return host, int(port_text)


def _is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _range_key(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.version == 4:
        return str(ipaddress.ip_network("%s/24" % ip, strict=False))
    return str(ipaddress.ip_network("%s/48" % ip, strict=False))


# -- small memories -------------------------------------------------------------------------------

class SynDeadCache(object):
    """Addresses whose SYN got no answer; two dead addresses in one /24 mark the whole range for a while."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._ips = {}      # ip -> ts
        self._ranges = {}   # range -> {ip: ts}

    def note(self, ip):
        key = _range_key(ip)
        if not key:
            return
        now = self._clock()
        self._ips[ip] = now
        self._ranges.setdefault(key, {})[ip] = now
        if len(self._ips) > 512:
            for stale in sorted(self._ips, key=self._ips.get)[:128]:
                self._ips.pop(stale, None)
        if len(self._ranges) > 256:
            for stale in sorted(self._ranges, key=lambda k: max(self._ranges[k].values()))[:64]:
                self._ranges.pop(stale, None)

    def alive(self, ip):
        """A connect to `ip` worked: neither it nor its range is dead any more."""
        key = _range_key(ip)
        self._ips.pop(ip, None)
        if key:
            self._ranges.pop(key, None)

    def dead(self, ip):
        now = self._clock()
        ts = self._ips.get(ip)
        if ts is not None and now - ts <= SYN_DEAD_IP_SEC:
            return True
        rows = self._ranges.get(_range_key(ip)) or {}
        fresh = [i for i, t in rows.items() if now - t <= SYN_DEAD_RANGE_SEC]
        return len(fresh) >= SYN_DEAD_RANGE_MIN_IPS


class DirectHealth(object):
    """Did ANY direct connect succeed lately? A SYN failure counts as an IP block only if so (outage guard)."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self.last_ok = None

    def ok(self):
        self.last_ok = self._clock()

    def fresh(self):
        return self.last_ok is not None and self._clock() - self.last_ok <= HEALTH_FRESH_SEC


class HostMemory(object):
    """host -> last route inside this process, so a browser's parallel connections do not each pay the hedge."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._rows = {}

    def note(self, host, route):
        self._rows[host] = (route, self._clock())
        if len(self._rows) > 1024:
            for stale in sorted(self._rows, key=lambda h: self._rows[h][1])[:256]:
                self._rows.pop(stale, None)

    def get(self, host):
        row = self._rows.get(host)
        if row is None or self._clock() - row[1] > HOST_MEMORY_SEC:
            return ""
        return row[0]

    def forget(self, host):
        self._rows.pop(host, None)


# -- observations handed to nova.pyw ----------------------------------------------------------------

def observation_for(result, health_fresh):
    """(route, why) to report for a finished race, or None when it proves nothing.

    A direct win is an `ok` sample. A VPN win with direct failing is a `bad` sample, except a SYN
    failure while no other direct connect worked lately (that is the network, not the site)."""
    if result is None:
        return None
    if result.route == "direct":
        return ("direct", "ok")
    why = result.direct_why or ""
    if not why:
        return None
    if why in ("tcp", "dns") and not health_fresh:
        return None
    return ("vpn", why)


class ObservedStore(object):
    """temp/unlisted-observed.json: {"hosts": {host: {"at": unix, "route": "direct|vpn", "why": str}}}.

    Written by the proxy helper, read by the verdict worker. Atomic replace, bounded, throttled."""

    def __init__(self, path, clock=time.time):
        self.path = str(path or "")
        self._clock = clock
        self.rows = {}
        self._dirty = False
        self._last_flush = 0.0

    def add(self, host, route, why=""):
        host = str(host or "").strip().lower()
        if host.startswith("www."):
            host = host[4:]
        if not host or "." not in host or _is_ip_literal(host):
            return False
        self.rows[host] = {"at": round(self._clock(), 1), "route": str(route), "why": str(why or "")[:16]}
        if len(self.rows) > OBSERVED_MAX_ROWS:
            for stale in sorted(self.rows, key=lambda h: self.rows[h]["at"])[:len(self.rows) - OBSERVED_MAX_ROWS]:
                del self.rows[stale]
        self._dirty = True
        return True

    def flush(self, force=False):
        now = self._clock()
        if not self.path or not self._dirty or (not force and now - self._last_flush < OBSERVED_FLUSH_GAP_SEC):
            return False
        cutoff = now - OBSERVED_TTL_SEC
        for stale in [h for h, r in self.rows.items() if r["at"] < cutoff]:
            del self.rows[stale]
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(json.dumps({"version": 1, "hosts": self.rows}, separators=(",", ":"), sort_keys=True))
            os.replace(tmp, self.path)
        except OSError:
            return False
        self._dirty = False
        self._last_flush = now
        return True


def read_observed(path, now=None, max_age=OBSERVED_TTL_SEC):
    """[(host, route, why, at)] oldest first; unreadable or malformed file -> []."""
    now = time.time() if now is None else now
    try:
        with open(path, "rb") as handle:
            data = json.loads(handle.read(2 * 1024 * 1024).decode("utf-8-sig"))
    except (OSError, ValueError):
        return []
    rows = data.get("hosts") if isinstance(data, dict) else None
    if not isinstance(rows, dict):
        return []
    out = []
    for host, row in rows.items():
        if not isinstance(row, dict) or row.get("route") not in ("direct", "vpn"):
            continue
        try:
            at = float(row.get("at") or 0.0)
        except (TypeError, ValueError):
            continue
        if now - at <= max_age:
            out.append((str(host), row["route"], str(row.get("why") or ""), at))
    out.sort(key=lambda r: r[3])
    return out


# -- the race --------------------------------------------------------------------------------------

class _Phase(object):
    """Where the direct path is, for the two hedges."""

    def __init__(self):
        self.connected_at = None
        self.hello_at = None
        self.ip = ""
        self.hedge_now = False   # the dialler already knows this address range is dead: no waiting


async def _close(writer):
    with contextlib.suppress(Exception):
        writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 0.5)


async def _verify(reader, writer, hello, cap, check_tls):
    """Send the hello, return the first reply bytes; raise PathError when the reply is not a handshake."""
    if hello:
        writer.write(hello)
        await writer.drain()
    try:
        first = await asyncio.wait_for(reader.read(65536), timeout=cap)
    except asyncio.TimeoutError:
        raise PathError("tls", "no reply in %.1fs" % cap)
    except (ConnectionError, OSError) as exc:
        raise PathError("reset", str(exc)[:40])
    if not first:
        raise PathError("closed", "closed before the first byte")
    if check_tls and not looks_like_tls_handshake(first):
        raise PathError("alert", "first reply %s" % first[:7].hex())
    return first


async def race(host, port, hello, *, direct_dial, vpn_labels, vpn_dial, timings=None, prefer_vpn=False,
               clock=time.monotonic):
    """Run direct and (late or on failure) the VPN chain; return the winner's open stream.

    direct_dial(host, port, phase) -> (reader, writer); sets phase.ip and raises PathError("dns"|"tcp"|...).
    vpn_dial(label, host, port) -> (reader, writer). vpn_labels: ordered labels, may be empty.
    prefer_vpn: this host was already judged blocked; the chain starts at once and direct is not tried.
    Raises RaceFailed when nothing opened."""
    timings = timings or Timings()
    check_tls = looks_like_client_hello(hello)
    phase = _Phase()
    t0 = clock()

    async def direct_path():
        reader, writer = await asyncio.wait_for(direct_dial(host, port, phase), timeout=timings.direct_cap) \
            if False else await _direct_connect(direct_dial, host, port, phase, timings.direct_cap)
        phase.connected_at = clock()
        try:
            phase.hello_at = clock()
            first = await _verify(reader, writer, hello, timings.direct_cap, check_tls)
        except BaseException:
            await _close(writer)
            raise
        return ("direct", "direct", reader, writer, first)

    async def vpn_path():
        last = None
        for label in vpn_labels:
            reader = writer = None
            try:
                reader, writer = await asyncio.wait_for(vpn_dial(label, host, port), timeout=timings.vpn_dial_cap)
                first = await _verify(reader, writer, hello, timings.vpn_cap, check_tls)
                return ("vpn", label, reader, writer, first)
            except asyncio.CancelledError:
                if writer is not None:
                    await _close(writer)
                raise
            except PathError as exc:
                last = exc
            except asyncio.TimeoutError:
                last = PathError("tcp", "%s dial timeout" % label)
            except Exception as exc:  # a label that cannot be dialled at all: next one
                last = PathError("tcp", "%s: %s" % (label, str(exc)[:60]))
            if writer is not None:
                await _close(writer)
        raise last if last is not None else PathError("tcp", "no VPN label")

    tasks = {}
    vpn_started = False

    def start_vpn():
        nonlocal vpn_started
        if not vpn_started and vpn_labels:
            vpn_started = True
            tasks["vpn"] = asyncio.ensure_future(vpn_path())

    if prefer_vpn and vpn_labels:
        start_vpn()
    else:
        tasks["direct"] = asyncio.ensure_future(direct_path())

    results = {}
    errors = {}
    winner = None
    try:
        while tasks and winner is None:
            now = clock()
            if not vpn_started and vpn_labels and "direct" in tasks:
                if phase.hedge_now:
                    start_vpn()
                elif phase.connected_at is None and now - t0 >= timings.syn_hedge:
                    start_vpn()
                elif phase.hello_at is not None and now - phase.hello_at >= timings.hello_hedge:
                    start_vpn()
            done, _pending = await asyncio.wait(set(tasks.values()), timeout=timings.tick,
                                                return_when=asyncio.FIRST_COMPLETED)
            for name in list(tasks):
                task = tasks[name]
                if task not in done:
                    continue
                del tasks[name]
                try:
                    results[name] = task.result()
                except asyncio.CancelledError:
                    errors[name] = PathError("closed", "cancelled")
                except PathError as exc:
                    errors[name] = exc
                except Exception as exc:
                    errors[name] = PathError("tcp", str(exc)[:60])
            if "direct" in results:
                winner = results["direct"]
            elif "vpn" in results:
                winner = results["vpn"]
            elif "direct" in errors and not vpn_started and vpn_labels:
                start_vpn()  # direct failed outright: no timer, go now
            elif "direct" in errors and not tasks and not vpn_labels:
                break
    finally:
        for task in tasks.values():
            task.cancel()
        for task in tasks.values():
            with contextlib.suppress(BaseException):
                await task
        # a loser that finished while the winner was chosen holds an open stream
        for name, res in results.items():
            if winner is not None and res is not winner:
                await _close(res[3])
    if winner is None:
        # nothing opened (also the case where the task set emptied with only errors)
        d = errors.get("direct")
        v = errors.get("vpn")
        raise RaceFailed(d.kind if d else None, v.kind if v else None)
    route, label, reader, writer, first = winner
    direct_why = None
    if route == "vpn":
        if "direct" in errors:
            direct_why = errors["direct"].kind
        elif prefer_vpn:
            direct_why = None  # not tried: proves nothing new
        else:
            direct_why = "tcp" if phase.connected_at is None else "tls"
    return RaceResult(route, label, reader, writer, first, (clock() - t0) * 1000.0, direct_why, vpn_started,
                      phase.ip)


async def _direct_connect(direct_dial, host, port, phase, cap):
    try:
        return await asyncio.wait_for(direct_dial(host, port, phase), timeout=cap)
    except asyncio.TimeoutError:
        raise PathError("tcp", "connect timeout")
