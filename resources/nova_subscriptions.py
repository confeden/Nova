"""Subscriptions: a URL that hands out many profiles, refreshed on its own.

Ported from Nova Android's `VlessSubscription` / `VlessSubscriptionFetcher` / `VlessSubscriptionManager`,
with the three rules it learned the hard way kept verbatim (see `plan_sync`). Two things are new here:

* a subscription may be **VLESS or AWG**. The body decides, not the settings: the same URL shape
  hands out `vless://` links, WireGuard configs and Amnezia `vpn://` keys, and asking the owner to
  classify their own link is asking them to guess;
* the fetch walks Nova's own egresses when the direct one fails. `raw.githubusercontent.com` is
  blocked from Russia, which is precisely where this is used, and Nova is a VPN — the tunnel it
  already holds is the natural way to reach the list. This is the ladder `nova_proton` uses.

What the network actually does, measured 2026-09-20 from the owner's machine:

* `Splitted-By-Protocol/vless.txt` of Epodonios/v2ray-configs is 1.97 MB and carries 5916 links
  (2434 REALITY); barry-far/V2ray-Config is the same size and largely the same nodes;
* a conditional GET with `If-None-Match` answers **304 with 0 bytes**, on raw.githubusercontent.com
  and on the jsDelivr mirror alike. So a refresh that finds nothing new is free, and the interval
  can be short without costing the owner traffic;
* the bodies come in all three shapes at once: plain link lists, whole-body base64, and lists with
  `#profile-title:` metadata in front. `nova_vless.parse_many` sorts that out.

The registry lives in `profiles/subscriptions.json` — under `profiles/`, not `temp/`, because a
subscription URL can carry a token, and `profiles/` is the folder that is never published and never
attached to a problem report (I19).
"""

import json
import os
import re
import threading
import time
from urllib.parse import quote, urlsplit

import requests

import nova_profiles

try:
    import nova_vless
except ImportError:  # pragma: no cover - a build that failed to ship the module
    nova_vless = None

__all__ = [
    "SUBSCRIPTIONS_FILENAME", "DEFAULT_INTERVAL_HOURS", "MIN_INTERVAL_HOURS", "MAX_INTERVAL_HOURS",
    "DEFAULT_USER_AGENT", "MAX_BODY_BYTES", "MAX_NODES", "DEFAULT_SOURCES",
    "KIND_AUTO", "KIND_VLESS", "KIND_AWG",
    "DEFAULT_KEEP", "MAX_TOTAL_VLESS",
    "subscriptions_path", "load", "save", "add", "remove", "set_enabled", "find",
    "normalize_record", "due", "mirror_urls", "fetch", "FetchResult", "plan_sync", "refresh",
]

SUBSCRIPTIONS_FILENAME = "subscriptions.json"

KIND_AUTO = "auto"
KIND_VLESS = "vless"
KIND_AWG = "awg"

# Twelve hours is Android's default and the reason holds here: lists change slowly, and a
# conditional request costs nothing, so the interval is chosen for freshness rather than for cost.
DEFAULT_INTERVAL_HOURS = 12
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 24 * 7

# The UA panels answer with a plain link list instead of Clash YAML. Not a disguise — it is the
# documented way to ask for the simple format, and every client sends one.
DEFAULT_USER_AGENT = "v2rayNG/1.10.6"

# Live aggregators publish a couple of megabytes; the cap is a backstop against a body that never
# ends, not a limit anyone should reach.
MAX_BODY_BYTES = 32 * 1024 * 1024
MAX_NODES = 20000
# Kept per subscription, and it really is per subscription: the first refresh of a four-source
# registry filled the whole allowance from the first list and the other three then reported
# "состав не изменился" and contributed nothing (seen live 2026-09-20 — iboxz 274, Delta-Kronecker
# 26, then zero and zero). Ownership is what makes the share real: a subscription may only add
# within its own quota and may only remove what it itself brought.
DEFAULT_KEEP = 120
# And a ceiling over all of them together. Every profile is a file the «Профили» window stats on
# each refresh, and of public nodes roughly one in five is reachable at all — past this the list
# costs more to look at than it is worth.
MAX_TOTAL_VLESS = 600

CONNECT_TIMEOUT_S = 12.0
READ_TIMEOUT_S = 45.0

# Measured 2026-09-20 from the owner's machine (RU ISP): every candidate downloaded, parsed and
# sampled for a real TLS handshake. What decided the four:
#
# * **iboxz is first on purpose.** It publishes through GitHub Pages, and `*.github.io` is the one
#   host of the lot that answers from Russia with no bypass at all (0.26 s) -- `raw.githubusercontent.com`
#   does not (G48: 0/3 TCP natively, while `github.com` itself is 68 ms). At a cold start Nova has
#   no tunnel yet, so a source that needs one is a source that fetches nothing.
# * **Delta-Kronecker** is the most independent pool: 5 % overlap with barry-far, pure REALITY,
#   and its author is already the one Nova fetches Tor bridges from.
# * **0xRadikal** is the widest (6275 VLESS, 1854 REALITY) and MIT.
# * **barry-far** is the freshest (~2 h) and had the best TLS rate from a Russian ISP, 22 %.
#
# Deliberately NOT here: Epodonios (its `Splitted-By-Protocol/vless.txt` is byte-for-byte the same
# pool as barry-far's -- 4267 of 4267 shared -- so it is a mirror, not a second source);
# mahdibland (no VLESS at all any more); Pawdroid, freefq, mfuu, ermaozi, yebekhe (dead, renamed or
# a handful of nodes).
#
# And a result worth keeping: **a provider's own "verified" list is worse here than its raw pool**
# -- 7 % against 22 % -- because those checks run from Iran and Russia blocks other subnets. Nova
# has to measure for itself, which is what `nova_profiles._vless_order` does with the numbers the
# «Профили» window collects.
DEFAULT_SOURCES = (
    {
        "name": "iboxz (без обхода)",
        "url": "https://iboxz.github.io/free-v2ray-collector/main/vless.txt",
        "kind": KIND_VLESS,
    },
    {
        "name": "Delta-Kronecker REALITY",
        "url": "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/reality/reality.txt",
        "kind": KIND_VLESS,
    },
    {
        "name": "0xRadikal VLESS",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt",
        "kind": KIND_VLESS,
    },
    {
        "name": "barry-far VLESS",
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
        "kind": KIND_VLESS,
    },
)

# The registry's own shape. Bumped when the meaning of a stored field changes, which lets a record
# written by an older Nova be corrected on load instead of being trusted.
_SHAPE = 2

_LOCK = threading.Lock()
_ID_RE = re.compile(r"[^a-z0-9]+")


def subscriptions_path(base_dir):
    return os.path.join(nova_profiles.profiles_dir(base_dir), SUBSCRIPTIONS_FILENAME)


def _now():
    return time.time()


def _as_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def make_id(url):
    """A stable id for a URL: readable in the file, and the same across restarts.

    The whole path goes into it, not only the file name. Both shipped sources publish
    `Splitted-By-Protocol/vless.txt` on raw.githubusercontent.com, so an id built from host + file
    name was the same for both — and the second one vanished into the registry's own de-duplication.
    """
    host, path = "", str(url or "")
    try:
        parts = urlsplit(str(url or ""))
        host, path = parts.hostname or "", parts.path or ""
    except ValueError:
        pass
    slug = _ID_RE.sub("-", ("%s-%s" % (host, path)).lower()).strip("-")
    # Long enough to stay unique between two lists of one repository, short enough to read.
    return slug[:80] or "sub"


def normalize_record(record):
    """One registry entry, every field present and of the right type. Returns None for junk."""
    if not isinstance(record, dict):
        return None
    url = str(record.get("url") or "").strip()
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    kind = str(record.get("kind") or KIND_AUTO).strip().lower()
    if kind not in (KIND_AUTO, KIND_VLESS, KIND_AWG):
        kind = KIND_AUTO
    interval = _as_int(record.get("interval_hours"), DEFAULT_INTERVAL_HOURS)
    interval = max(MIN_INTERVAL_HOURS, min(MAX_INTERVAL_HOURS, interval))
    identities = record.get("identities")
    identities = [str(i) for i in identities if str(i)] if isinstance(identities, list) else []
    # Ownership used to be "everything the answer held" rather than "everything that was written",
    # so a registry from that shape claims thousands of nodes it never put on disk -- and would
    # then remove another subscription's profiles as "gone from mine". The list is rebuilt from the
    # next refresh instead of guessed: rule 3 of plan_sync means that refresh removes nothing.
    stale_shape = _as_int(record.get("shape"), 0) < _SHAPE
    if stale_shape:
        identities = []
    return {
        "shape": _SHAPE,
        "id": str(record.get("id") or make_id(url)),
        "url": url,
        "name": str(record.get("name") or "").strip(),
        "kind": kind,
        "enabled": bool(record.get("enabled", True)),
        "interval_hours": interval,
        # `keep` meant "how many VLESS profiles in total" in the old shape and "how many of mine"
        # in this one, so a stored value from then is not the same quota and goes back to default.
        "keep": DEFAULT_KEEP if stale_shape
                else max(1, min(MAX_NODES, _as_int(record.get("keep"), DEFAULT_KEEP))),
        "etag": str(record.get("etag") or ""),
        "last_modified": str(record.get("last_modified") or ""),
        "last_checked_at": _as_float(record.get("last_checked_at"), 0.0),
        "last_ok_at": _as_float(record.get("last_ok_at"), 0.0),
        "last_status": str(record.get("last_status") or ""),
        "fail_streak": max(0, _as_int(record.get("fail_streak"), 0)),
        "node_count": max(0, _as_int(record.get("node_count"), 0)),
        # The nodes this subscription brought last time. Only these may be taken away by a refresh
        # (rule 2 of plan_sync), so this list is the whole reason the file is state, not a cache.
        "identities": identities[:MAX_NODES],
    }


def load(base_dir):
    """Every registered subscription. A missing or corrupt file gives the shipped defaults."""
    path = subscriptions_path(base_dir)
    try:
        with open(path, "rb") as handle:
            obj = json.loads(handle.read().decode("utf-8-sig"))
    except (OSError, ValueError):
        obj = None
    if isinstance(obj, dict):
        rows = obj.get("subscriptions")
    elif isinstance(obj, list):
        rows = obj
    else:
        rows = None
    if not isinstance(rows, list):
        # First run: the shipped sources are offered rather than an empty list, because a window
        # that says "no subscriptions" leaves the owner to find a link themselves.
        return [normalize_record(dict(src, id=make_id(src["url"]))) for src in DEFAULT_SOURCES]
    out = []
    seen = set()
    for row in rows:
        record = normalize_record(row)
        if record is None or record["id"] in seen:
            continue
        seen.add(record["id"])
        out.append(record)
    return out


def save(base_dir, records):
    """Write the registry atomically. Returns the normalized list that was written."""
    rows = [r for r in (normalize_record(row) for row in records or []) if r is not None]
    payload = {"v": 1, "written_at": int(_now()), "subscriptions": rows}
    path = subscriptions_path(base_dir)
    # No 0o600 here, and the omission is deliberate rather than forgotten. The file lives in
    # `profiles/`, whose Windows ACL is what protects every private thing Nova keeps -- WARP and
    # Proton keys, MASQUE credentials, the relay key. A POSIX mode is a no-op on NTFS: measured on
    # this machine, `os.open(..., 0o600)` leaves the file at 0o666 with the ACL inherited from the
    # folder, because CPython maps the mode to the read-only bit alone. `profiles/` is also the
    # folder that never goes into a problem report (I19), which `temp/` does -- that, not the mode,
    # is why a URL with a token in it may be written here at all. `kb/profiles.md`.
    with _LOCK:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    return rows


def find(records, sub_id):
    for record in records or []:
        if record.get("id") == sub_id:
            return record
    return None


def add(base_dir, url, name="", kind=KIND_AUTO, interval_hours=DEFAULT_INTERVAL_HOURS):
    """Register a subscription. An already-registered URL is returned unchanged, not duplicated."""
    records = load(base_dir)
    candidate = normalize_record({"url": url, "name": name, "kind": kind,
                                  "interval_hours": interval_hours})
    if candidate is None:
        return None, records
    for record in records:
        if record["url"].lower() == candidate["url"].lower():
            return record, records
    records.append(candidate)
    return candidate, save(base_dir, records)


def remove(base_dir, sub_id):
    records = [r for r in load(base_dir) if r.get("id") != sub_id]
    return save(base_dir, records)


def set_enabled(base_dir, sub_id, enabled):
    records = load(base_dir)
    record = find(records, sub_id)
    if record is None:
        return records
    record["enabled"] = bool(enabled)
    return save(base_dir, records)


def due(records, now=None, grace_sec=0.0):
    """The subscriptions a background refresh should take now, soonest-overdue first.

    A failure backs the next attempt off — 1, 2, 4 … times the interval, capped at a day — so a URL
    that has gone for good is not asked every twelve hours forever while the owner watches the log.
    """
    now = _now() if now is None else float(now)
    out = []
    for record in records or []:
        if not record.get("enabled", True):
            continue
        interval = max(MIN_INTERVAL_HOURS, _as_int(record.get("interval_hours"), DEFAULT_INTERVAL_HOURS))
        wait = interval * 3600.0
        streak = max(0, _as_int(record.get("fail_streak"), 0))
        if streak:
            wait = min(24 * 3600.0, wait * (2 ** min(streak, 5)))
        checked = _as_float(record.get("last_checked_at"), 0.0)
        if checked and (now - checked) < (wait - float(grace_sec)):
            continue
        out.append((checked, record))
    out.sort(key=lambda item: item[0])
    return [record for _checked, record in out]


_GITHUB_RAW_RE = re.compile(r"(?i)^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$")


def mirror_urls(url):
    """The same file under other names, in the order worth trying. Only GitHub raw has mirrors.

    Measured 2026-09-20 from a Russian ISP, and the order is the measurement rather than a guess:

    * `raw.githack.com` answered in 0.3-0.9 s and its md5 **matched** raw.githubusercontent.com on
      three files, so it is both reachable and current. It goes first. (It answers 403 to HEAD and
      200 to GET, which is why nothing on this path may use HEAD.)
    * `raw.githubusercontent.com` itself is the reference copy but is not reachable from here
      without a bypass (G48: 0/3 TCP), so it is second rather than first.
    * `cdn.jsdelivr.net` works, but caches with `s-maxage=43200` and was observed **12 hours
      behind** with a different md5. A stale node list is worse than a slow one, so it is last.
    * `rawcdn.githack.com` and the `ghproxy`-style mirrors are left out entirely: the first served a
      visibly older snapshot, the second family truncated at 15-23 KB or answered nothing at all.
    """
    url = str(url or "").strip()
    if not url:
        return ()
    match = _GITHUB_RAW_RE.match(url)
    if not match:
        return (url,)
    user, repo, ref, path = match.groups()
    quoted = quote(path, safe="/._-~")
    return (
        "https://raw.githack.com/%s/%s/%s/%s" % (user, repo, ref, quoted),
        url,
        "https://cdn.jsdelivr.net/gh/%s/%s@%s/%s" % (user, repo, ref, quoted),
    )


class FetchResult(object):
    """`status` is "ok" | "not_modified" | "failed"; everything else is filled per status."""

    __slots__ = ("status", "body", "etag", "last_modified", "message", "via", "url", "bytes")

    def __init__(self, status, body=b"", etag="", last_modified="", message="", via="", url="",
                 size=0):
        self.status = status
        self.body = body
        self.etag = etag
        self.last_modified = last_modified
        self.message = message
        self.via = via
        self.url = url
        self.bytes = size

    def __repr__(self):
        return "FetchResult(%s, %d bytes, via %s)" % (self.status, self.bytes, self.via or "direct")


def _session(proxy_url):
    session = requests.Session()
    # Never let the environment or the Windows registry proxy decide: "direct" must mean direct, and
    # a named proxy must mean exactly that proxy (same rule as nova_proton._Route).
    session.trust_env = False
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
    return session


def _read_capped(response, limit):
    """The body, refusing to grow past `limit`. Returns (bytes, truncated)."""
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            return b"".join(chunks)[:limit], True
    return b"".join(chunks), False


def fetch(url, etag="", last_modified="", proxies=(), direct=True, user_agent=DEFAULT_USER_AGENT,
          limit=MAX_BODY_BYTES, timeout=None, log=None, session_factory=None):
    """Download a subscription, over the first route and name that answers.

    Routes are tried direct first, then each proxy in `proxies` (Nova's own egresses); names are the
    URL and its mirrors. A 304 on any of them is the answer — nothing changed — and ends the walk.
    A route that answers with an HTTP error keeps the walk going, because the next mirror may not.
    """
    say = log if callable(log) else (lambda _message: None)
    timeout = timeout or (CONNECT_TIMEOUT_S, READ_TIMEOUT_S)
    factory = session_factory or _session
    names = mirror_urls(url)
    routes = ([None] if direct else []) + [str(p).strip() for p in (proxies or ()) if str(p).strip()]
    if not routes:
        return FetchResult("failed", message="нет ни одного маршрута для загрузки", url=url)

    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    if etag:
        headers["If-None-Match"] = etag
    elif last_modified:
        headers["If-Modified-Since"] = last_modified

    last_message = "не удалось загрузить"
    for route in routes:
        label = "напрямую" if route is None else "через прокси"
        session = factory(route)
        try:
            for name in names:
                try:
                    response = session.get(name, headers=headers, timeout=timeout, stream=True,
                                           allow_redirects=True)
                except requests.RequestException as exc:
                    last_message = _describe(exc)
                    continue
                with response:
                    if response.status_code == 304:
                        return FetchResult("not_modified", etag=etag, last_modified=last_modified,
                                           via=label, url=name)
                    if response.status_code != 200:
                        last_message = "HTTP %d" % response.status_code
                        continue
                    try:
                        body, truncated = _read_capped(response, limit)
                    except requests.RequestException as exc:
                        last_message = _describe(exc)
                        continue
                if truncated:
                    say("[Подписки] %s: тело длиннее %d МБ, прочитано начало." %
                        (name.rsplit("/", 1)[-1], limit // (1024 * 1024)))
                return FetchResult("ok", body=body,
                                   etag=response.headers.get("ETag", "") or "",
                                   last_modified=response.headers.get("Last-Modified", "") or "",
                                   via=label, url=name, size=len(body))
        finally:
            session.close()
    return FetchResult("failed", message=last_message, url=url)


def _describe(exc):
    """A short Russian reason for a requests failure, with no URL and no credentials in it."""
    if isinstance(exc, requests.exceptions.ProxyError):
        return "прокси недоступен"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "таймаут соединения"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "таймаут ответа"
    if isinstance(exc, requests.exceptions.SSLError):
        return "ошибка TLS"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "слишком много перенаправлений"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "нет соединения"
    return type(exc).__name__


def plan_sync(existing, fresh_identities, previous_identities, keep, pinned=()):
    """What to do with the local profiles after a download. Three rules, each behind a real defect.

    1. **Survivors stay where they are.** The connect queue has already ordered them by what works;
       re-sorting to the subscription's order would throw that away and float the dead back up.
    2. **Only what the subscription brought and then dropped is removed.** A node the owner pasted
       by hand is not the subscription's to take away.
    3. **The first download removes nothing.** There is no previous set to compare with, so every
       already-saved profile would look like "gone from the subscription".

    `existing` is `[(profile_id, identity)]` of the local VLESS profiles, `fresh_identities` the
    identities just downloaded in their download order, `previous_identities` what this subscription
    brought last time, `pinned` the ids the owner has protected.

    Returns `{"remove": [profile_id], "add": [identity], "keep": n}`.
    """
    keep = max(1, int(keep))
    pinned = {str(p) for p in (pinned or ())}
    fresh = []
    fresh_seen = set()
    for identity in fresh_identities or ():
        identity = str(identity)
        if identity and identity not in fresh_seen:
            fresh_seen.add(identity)
            fresh.append(identity)

    previous = {str(i) for i in (previous_identities or ())}
    gone = previous - fresh_seen

    remove = []
    kept_identities = set()
    kept = 0
    for profile_id, identity in existing or ():
        identity = str(identity)
        if identity in gone and profile_id not in pinned:
            remove.append(profile_id)
            continue
        kept += 1
        kept_identities.add(identity)

    add = []
    for identity in fresh:
        if kept + len(add) >= keep:
            break
        if identity in kept_identities:
            continue
        kept_identities.add(identity)
        add.append(identity)
    return {"remove": remove, "add": add, "keep": kept}


def refresh(base_dir, record, *, proxies=(), direct=True, log=None, fetcher=None, now=None):
    """Download one subscription and apply it to `profiles/`.

    Returns `(outcome, record, stats)` where outcome is
    "updated" | "unchanged" | "empty" | "failed". `record` is the entry to save back — the caller
    saves the whole registry, so one write covers a whole sweep.
    """
    say = log if callable(log) else (lambda _message: None)
    now = _now() if now is None else float(now)
    record = normalize_record(record)
    if record is None:
        return "failed", record, {}
    title = record["name"] or record["id"]

    get = fetcher or fetch
    result = get(record["url"], etag=record["etag"], last_modified=record["last_modified"],
                 proxies=proxies, direct=direct, log=say)

    record["last_checked_at"] = now
    if result.status == "failed":
        record["fail_streak"] = record["fail_streak"] + 1
        record["last_status"] = result.message or "не загрузилась"
        say("[Подписки] «%s» не загрузилась: %s." % (title, record["last_status"]))
        return "failed", record, {}
    if result.status == "not_modified":
        record["fail_streak"] = 0
        record["last_status"] = "не менялась"
        record["last_ok_at"] = now
        say("[Подписки] «%s» не менялась (304), профилей: %d." % (title, record["node_count"]))
        return "unchanged", record, {}

    record["etag"] = result.etag
    record["last_modified"] = result.last_modified
    record["fail_streak"] = 0

    nodes, stats = ([], {})
    if nova_vless is not None and record["kind"] in (KIND_AUTO, KIND_VLESS):
        nodes, stats = nova_vless.parse_many(result.body, limit=MAX_NODES)

    if nodes:
        outcome = _apply_vless(base_dir, record, nodes, say, title)
        return outcome, record, stats

    if record["kind"] == KIND_VLESS:
        record["last_status"] = "в ответе нет ссылок vless://"
        say("[Подписки] «%s»: в ответе нет ссылок vless:// (%d КБ)." % (title, result.bytes // 1024))
        return "empty", record, stats

    # Not VLESS: hand the body to the ordinary importer, which reads wg-quick blocks, Amnezia
    # vpn:// keys and MASQUE identities. AWG subscriptions are rarer and much smaller, so they go
    # through the same path as a pasted file rather than getting a diff of their own.
    text = nova_vless.decode_subscription_body(result.body) if nova_vless is not None \
        else result.body.decode("utf-8", "replace")
    # The label, never the URL. `parse_import_text` turns its source name into the profile's file
    # name, and a subscription URL is where a private token lives -- `.../link/<secret>` or
    # `?token=<secret>`. That would have written the secret into a file name in a folder the owner
    # opens with «Папка» and screenshots. The name is the owner's own or the readable id.
    label = record["name"] or record["id"]
    candidates = [c for c in nova_profiles.parse_import_text(text, label) if c.get("ok")]
    if not candidates:
        record["last_status"] = "в ответе нет профилей"
        say("[Подписки] «%s»: в ответе нет профилей (%d КБ)." % (title, result.bytes // 1024))
        return "empty", record, stats
    results = nova_profiles.import_candidates(base_dir, candidates,
                                              source=nova_profiles.ORIGIN_SUBSCRIPTION,
                                              subscription=record["id"])
    imported = sum(1 for r in results if r.get("status") == "imported")
    record["node_count"] = imported
    record["last_ok_at"] = now
    record["last_status"] = "профилей: %d" % imported
    say("[Подписки] «%s»: импортировано %d, уже были %d." %
        (title, imported, sum(1 for r in results if r.get("status") == "duplicate")))
    return ("updated" if imported else "unchanged"), record, stats


def _apply_vless(base_dir, record, nodes, say, title):
    """The VLESS half of `refresh`: diff against what this subscription brought last time.

    Only this subscription's own nodes are counted and touched. `record["identities"]` is the
    ownership record -- what it brought last time -- so a profile the owner pasted by hand, or one
    another subscription brought, is neither removed by this refresh nor charged against its quota.
    """
    owned_before = set(record["identities"])
    existing_owned = []
    total_vless = 0
    for listed in nova_profiles.list_profiles(base_dir):
        if listed.get("kind") != nova_profiles.KIND_VLESS:
            continue
        total_vless += 1
        identity = listed.get("fingerprint") or ""
        if identity in owned_before:
            existing_owned.append((listed["id"], identity))

    by_identity = {}
    for node in nodes:
        by_identity.setdefault(node.identity, node)

    # The quota is the smaller of this subscription's share and what the global ceiling still
    # allows, plus whatever this subscription is about to free by removing its own dead entries.
    foreign = total_vless - len(existing_owned)
    room = max(0, MAX_TOTAL_VLESS - foreign)
    plan = plan_sync(existing_owned, [n.identity for n in nodes], record["identities"],
                     min(record["keep"], room))

    removed = 0
    for profile_id in plan["remove"]:
        # delete_profile returns the path it removed and RAISES for anything it refuses: a bundled
        # profile, a MASQUE file nova-go has locked, a file the OS will not let go. A subscription
        # refresh must survive all three — one stubborn file is not a reason to abandon the other
        # two hundred — so each removal is on its own.
        try:
            nova_profiles.delete_profile(base_dir, profile_id)
        except (ValueError, OSError) as exc:
            say(f"[Подписки] Профиль «{profile_id}» не удалён: {exc}")
            continue
        removed += 1

    candidates = []
    for identity in plan["add"]:
        node = by_identity.get(identity)
        if node is None:
            continue
        candidates.append({
            "kind": nova_profiles.KIND_VLESS,
            "name": nova_vless.safe_profile_name(node),
            "text": nova_profiles.vless_profile_payload(node).decode("utf-8"),
            "ok": True,
            "issues": [],
        })
    results = nova_profiles.import_candidates(base_dir, candidates,
                                              source=nova_profiles.ORIGIN_SUBSCRIPTION,
                                              subscription=record["id"]) if candidates else []
    added = sum(1 for r in results if r.get("status") == "imported")

    # Ownership follows what is on disk, not what the answer held: a node the quota left out was
    # never written, and claiming it would let the next refresh "remove" a file that never existed
    # while letting the node itself be re-added for ever.
    removed_ids = set(plan["remove"])
    record["identities"] = sorted(
        {identity for pid, identity in existing_owned if pid not in removed_ids}
        | {identity for identity in plan["add"] if identity in by_identity}
    )[:MAX_NODES]
    record["node_count"] = plan["keep"] + added
    if len(nodes) > len(record["identities"]):
        say("[Подписки] «%s»: из %d узлов взято %d — предел этой подписки %d." %
            (title, len(nodes), len(record["identities"]), record["keep"]))
    record["last_ok_at"] = _now()
    if added or removed:
        record["last_status"] = "добавлено %d, удалено %d" % (added, removed)
        say("[Подписки] «%s»: узлов в ответе %d, добавлено %d, удалено %d, всего %d." %
            (title, len(nodes), added, removed, record["node_count"]))
        return "updated"
    record["last_status"] = "состав не изменился"
    say("[Подписки] «%s»: состав не изменился, узлов %d." % (title, record["node_count"]))
    return "unchanged"
