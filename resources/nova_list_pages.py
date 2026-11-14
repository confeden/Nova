"""Nova list in pages of fifty, scanned in batches of fifty, probed from the provider's connection.

Same rules as Nova Android (owner, 2026-11-12):

* The collector publishes `Github list/pages/index.json` plus `page-NNN.json`, newest verified
  first (collector.py `pages_of`, `list_rank`). A client never downloads the whole list: it reads
  the index and page 1, and page n+1 only when a scan of what it has finds fewer than
  `MIN_ALIVE` live nodes. `nova-list.json` stays published for old clients and is the fallback
  when no mirror has the index.
* A scan probes `BATCH_SIZE` nodes at a time in list order (the head is the freshest) and stops at
  `MIN_ALIVE` live ones, when nothing is left, when the caller's budget is spent, or on abort.
  Never the whole list.
* Probes go out over the physical adapter (`nova-proxy probe-list -interface NAME`), never through
  whatever VPN is up: a node reached through another tunnel answers with that tunnel's time.

Pure helpers plus two thin runners (the adapter lookup and the probe subprocess); nothing here
touches routes, adapters or system settings.
"""

import json
import re
import subprocess
import threading
import time

__all__ = [
    "PAGES_BASE_URL", "INDEX_URL", "PAGE_SIZE", "BATCH_SIZE", "MIN_ALIVE", "ALIVE_FRESH_SEC",
    "page_url", "parse_index", "parse_page", "scan", "ScanResult", "sort_by_ping",
    "physical_interface", "detect_physical_interface", "probe_runner",
]

PAGES_BASE_URL = "https://raw.githubusercontent.com/confeden/nova_updates/main/Github%20list/pages/"
INDEX_URL = PAGES_BASE_URL + "index.json"
PAGE_SIZE = 50
BATCH_SIZE = 50
MIN_ALIVE = 5
# A verdict younger than this is reused instead of probing again (not for a forced first batch).
ALIVE_FRESH_SEC = 10 * 60
# Hard ceilings so a hostile or broken index cannot make the client loop or allocate.
MAX_PAGES = 1000

_PAGE_NAME_RE = re.compile(r"^page-\d{3,4}\.json$")


def page_url(name):
    """URL of one page file named by the index; ValueError for anything that is not `page-NNN.json`."""
    name = str(name or "")
    if not _PAGE_NAME_RE.match(name):
        raise ValueError("invalid page name")
    return PAGES_BASE_URL + name


def _load_json(body):
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8-sig")
    return json.loads(body)


def parse_index(body):
    """`{"checked_at","count","page_size","pages","files"}` from index.json; ValueError when malformed."""
    try:
        document = _load_json(body)
        meta = document["nova_list_pages"]
        files = document["files"]
        if not isinstance(meta, dict) or meta["version"] != 1 or not isinstance(files, list):
            raise ValueError
        count, size, pages = int(meta["count"]), int(meta["page_size"]), int(meta["pages"])
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise ValueError("invalid Nova list index") from None
    if size < 1 or count < 0 or not 0 <= pages <= MAX_PAGES or pages != len(files):
        raise ValueError("invalid Nova list index")
    if pages != (-(-count // size) if count else 0):
        raise ValueError("invalid Nova list index")
    names = [str(name) for name in files]
    if len(set(names)) != len(names) or not all(_PAGE_NAME_RE.match(n) for n in names):
        raise ValueError("invalid Nova list index")
    return {"checked_at": str(meta.get("checked_at") or ""), "count": count, "page_size": size,
            "pages": pages, "files": names}


def parse_page(body, number=None, pages=None):
    """`(meta, proxies, ms)` of one page; ValueError unless complete, counted and (when given) numbered.

    A page has the shape of the whole-list `nova-list.json` plus `page`/`pages`; `ms` is the
    checker's latency aligned with `proxies` (padded with None when absent or short).
    """
    try:
        document = _load_json(body)
        meta = document["nova_list"]
        proxies = document["proxies"]
        if (not isinstance(meta, dict) or meta["version"] != 1 or meta.get("complete") is not True
                or not isinstance(proxies, list) or int(meta["count"]) != len(proxies)
                or not all(isinstance(p, dict) for p in proxies)):
            raise ValueError
        if number is not None and int(meta.get("page") or 0) != int(number):
            raise ValueError
        if pages is not None and int(meta.get("pages") or 0) != int(pages):
            raise ValueError
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise ValueError("invalid Nova list page") from None
    raw_ms = document.get("ms") if isinstance(document.get("ms"), list) else []
    ms = []
    for index in range(len(proxies)):
        value = raw_ms[index] if index < len(raw_ms) else None
        ms.append(int(value) if isinstance(value, (int, float)) and value > 0 else None)
    return meta, proxies, ms


class ScanResult(object):
    """What a batch scan saw. `results`: key -> ms (alive) or None (dead); unprobed keys are absent."""

    __slots__ = ("results", "order", "alive", "batches", "stop")

    def __init__(self):
        self.results = {}
        self.order = []
        self.alive = 0
        self.batches = 0
        self.stop = ""

    def __repr__(self):
        return "ScanResult(alive=%d, batches=%d, stop=%s)" % (self.alive, self.batches, self.stop)


def scan(load_batch, probe, *, known=None, force_first=False, batch_size=BATCH_SIZE,
         min_alive=MIN_ALIVE, budget_sec=None, should_abort=None, clock=time.monotonic, log=None):
    """Probe a list in batches, in list order, until `min_alive` nodes answer.

    `load_batch(i)` returns the keys of batch `i` (0-based, list order); an empty list or None means
    nothing is left (it may download the next page to answer). `probe(keys, should_stop)` returns
    `{key: ms or None}` for the keys it really probed. `known` holds fresh verdicts `{key: ms or
    None}` reused instead of probing; `force_first` ignores them for the first batch. Stops on
    "enough", "exhausted", "budget" or "aborted" (`ScanResult.stop`).
    """
    say = log if callable(log) else (lambda _message: None)
    known = dict(known or {})
    abort = should_abort if callable(should_abort) else (lambda: False)
    deadline = None if budget_sec is None else clock() + max(0.0, float(budget_sec))
    result = ScanResult()
    seen = set()

    def out_of_time():
        return deadline is not None and clock() >= deadline

    def should_stop():
        return bool(abort()) or out_of_time()

    index = 0
    while True:
        if abort():
            result.stop = "aborted"
            break
        if out_of_time():
            result.stop = "budget"
            break
        keys = load_batch(index)
        keys = [k for k in (keys or ()) if k not in seen][:max(1, int(batch_size))]
        if not keys:
            result.stop = "exhausted"
            break
        seen.update(keys)
        result.order.extend(keys)
        reuse = {} if (force_first and index == 0) else {k: known[k] for k in keys if k in known}
        pending = [k for k in keys if k not in reuse]
        result.results.update(reuse)
        if pending:
            try:
                measured = probe(pending, should_stop) or {}
            except Exception as exc:  # a probe failure is "not measured", never "dead"
                say("[Nova list] Проверка пачки не удалась: %s" % type(exc).__name__)
                measured = {}
            result.results.update({k: v for k, v in measured.items() if k in pending})
        result.batches += 1
        result.alive = sum(1 for v in result.results.values() if v is not None)
        if result.alive >= min_alive:
            result.stop = "enough"
            break
        index += 1
    result.alive = sum(1 for v in result.results.values() if v is not None)
    return result


def sort_by_ping(keys, results):
    """Alive by ascending ms, then not measured (in the given list order), then dead last."""
    results = results or {}
    alive, unknown, dead = [], [], []
    for position, key in enumerate(keys or ()):
        if key not in results:
            unknown.append(key)
        elif results[key] is None:
            dead.append(key)
        else:
            alive.append((float(results[key]), position, key))
    alive.sort()
    return [k for _ms, _pos, k in alive] + unknown + dead


# --------------------------------------------------------------------------------------------
# The physical adapter: the one carrying the default route to the Internet that is not a tunnel.

TUNNEL_NAME_RE = re.compile(
    r"TAP|TUN|Wintun|WireGuard|AmneziaWG|Amnezia|OpenVPN|Nova|Clash|Mihomo|Tailscale|ZeroTier|"
    r"Hyper-V|vEthernet|VMware|VirtualBox|Loopback|Cloudflare|WARP|Proton|Sing-Box|WireSock|SSTAP",
    re.IGNORECASE,
)


def physical_interface(adapters, routes=()):
    """Alias of the physical adapter, or "".

    `adapters`: nova_win_routes.list_adapters() rows (Up, IPv4; alias, description, gateway,
    index, metric). `routes`: nova_win_routes.default_route_gateways() rows (metric, gw, ifindex).
    Only adapters with a gateway (their own or a 0.0.0.0/0 route on their index) and no tunnel-like
    name or description qualify; the lowest route metric plus interface metric wins.
    """
    route_metric = {}
    route_gw = {}
    for row in routes or ():
        try:
            metric, gateway, ifindex = int(row[0]), str(row[1]), int(row[2])
        except (TypeError, ValueError, IndexError):
            continue
        if ifindex not in route_metric or metric < route_metric[ifindex]:
            route_metric[ifindex] = metric
            route_gw[ifindex] = gateway
    best = None
    for order, adapter in enumerate(adapters or ()):
        if not isinstance(adapter, dict):
            continue
        alias = str(adapter.get("alias") or "").strip()
        description = str(adapter.get("description") or "")
        if not alias or TUNNEL_NAME_RE.search("%s %s" % (alias, description)):
            continue
        try:
            ifindex = int(adapter.get("index"))
        except (TypeError, ValueError):
            ifindex = -1
        gateway = str(adapter.get("gateway") or route_gw.get(ifindex) or "")
        if not gateway or gateway == "0.0.0.0":
            continue
        try:
            metric = int(adapter.get("metric") or 0)
        except (TypeError, ValueError):
            metric = 0
        key = (route_metric.get(ifindex, 1 << 20) + metric, order)
        if best is None or key < best[0]:
            best = (key, alias)
    return best[1] if best else ""


_IFACE_CACHE = {"at": None, "value": "", "warned": False}
_IFACE_LOCK = threading.Lock()
IFACE_CACHE_SEC = 30.0


def detect_physical_interface(log=None, clock=time.monotonic, lister=None):
    """The physical adapter's alias, cached for `IFACE_CACHE_SEC`; "" (logged once) when none."""
    with _IFACE_LOCK:
        now = clock()
        at = _IFACE_CACHE["at"]
        if at is not None and 0 <= now - at < IFACE_CACHE_SEC:
            return _IFACE_CACHE["value"]
    try:
        if lister is None:
            import nova_win_routes
            adapters, routes = nova_win_routes.list_adapters(), nova_win_routes.default_route_gateways()
        else:
            adapters, routes = lister()
        value = physical_interface(adapters, routes)
    except Exception:
        value = ""
    with _IFACE_LOCK:
        _IFACE_CACHE.update(at=clock(), value=value)
        warn = not value and not _IFACE_CACHE["warned"]
        if warn:
            _IFACE_CACHE["warned"] = True
        elif value:
            _IFACE_CACHE["warned"] = False
    if warn and callable(log):
        log("[Nova list] Физический адаптер не найден — проверка узлов идёт без привязки к нему.")
    return value


def probe_command(engine, interface="", workers=16, timeout_sec=9):
    """argv of `nova-proxy probe-list`; `-interface` only when an adapter was found."""
    cmd = [str(engine), "probe-list", "-workers", str(int(workers)), "-timeout", str(int(timeout_sec))]
    if interface:
        cmd += ["-interface", str(interface)]
    return cmd


def parse_probe_output(lines, keys):
    """`{key: ms or None}` from probe-list JSON lines; stages that cannot judge a node are left out."""
    out = {}
    for line in lines:
        try:
            row = json.loads(line)
            index = int(row["index"])
        except (ValueError, KeyError, TypeError):
            continue
        if not 0 <= index < len(keys):
            continue
        if row.get("ok"):
            out[keys[index]] = max(1, int(row.get("ms") or 1))
        elif row.get("stage") in ("tcp", "https", "bulk"):
            out[keys[index]] = None
        # "invalid"/"dependency": the helper could not build the node — not a verdict on it.
    return out


def probe_runner(engine, proxy_of, *, interface_provider=None, workers=16, timeout_sec=9,
                 popen=subprocess.Popen):
    """A `probe(keys, should_stop)` for `scan` running `nova-proxy probe-list` once per batch.

    `proxy_of(key)` gives the Mihomo map to probe (None skips the key). The helper is killed when
    `should_stop()` turns true; what it already answered is kept.
    """

    def probe(keys, should_stop):
        items = []
        for key in keys:
            proxy = proxy_of(key)
            if isinstance(proxy, dict):
                items.append((key, proxy))
        if not items:
            return {}
        interface = interface_provider() if callable(interface_provider) else ""
        cmd = probe_command(engine, interface, workers=min(int(workers), len(items)), timeout_sec=timeout_sec)
        payload = json.dumps({"proxies": [proxy for _key, proxy in items]}).encode("utf-8")
        process = popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        lines = []
        reader = threading.Thread(target=lambda: lines.extend(process.stdout), daemon=True)
        try:
            try:
                process.stdin.write(payload)
                process.stdin.close()
            except OSError:
                pass
            reader.start()
            hard_stop = time.monotonic() + timeout_sec * (len(items) // max(1, workers) + 3) + 10
            while process.poll() is None:
                if should_stop() or time.monotonic() > hard_stop:
                    process.kill()
                    break
                time.sleep(0.1)
            reader.join(timeout=2.0)
        finally:
            if process.poll() is None:
                process.kill()
        return parse_probe_output(list(lines), [key for key, _proxy in items])

    return probe
