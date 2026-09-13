"""Proton VPN free-tier profiles: one per-device key, a credential-less session, AWG confs.

Port of Nova Android's Proton generator (`ProtonApi.kt`, `ProtonCrypto.kt`,
`ProtonProfileManager.kt`, `ProtonProfileStore.kt`). The whole flow is client-side:

1. `POST /auth/v4/sessions` -- an unauthenticated carrier session. On its own it cannot
   read logicals or register a key (`9106 MissingScopes`), so step 2 is mandatory.
2. `POST /auth/v4/credentialless` -- Proton's own "connect without an account" path.
   NOT idempotent: it ties the session to a user. A lost answer followed by a retry on
   another host yields "Session already tied to a user"; the cure is a fresh carrier
   session and exactly one retry (Android G56).
3. `GET /vpn/logicals?Tier=0` -- the free logical servers (capitalised schema).
4. `POST /vpn/v1/certificate` with `Mode: persistent` -- registers the ed25519 public
   key for a year. Proton derives the X25519 half itself, so the WireGuard private key
   `clamp(SHA-512(seed)[0:32])` works on every free server; the returned certificate is
   not needed by the tunnel.

Why a per-device key and never a bundled one: the free tier allows two simultaneous
connections per account, so a shared key would serve two users worldwide (Android P6).
Only the node list (public facts) is shipped, as `proton_nodes.json`.

Routes: direct first, then each proxy the caller passes (Nova's local Opera proxy, the
TLS relay `https://nova-pc-<ver>:<pw>@relay.nova-app.eu:8443` -- urllib3 2.x speaks TLS to
an HTTPS proxy). Proxy URLs carry the relay password, so they are never logged: every
log line uses `redact_proxy_url`, and exception text is scrubbed before it is logged.

Human verification (Proton code 9001) is surfaced and never solved or routed around.

Every run that reaches step 2 creates a new anonymous Proton account and gets a session-bound node
subset (a set with entirely new names), so a normal run first reuses a complete, fresh set without
the network and backs off after a failure (`should_issue`, `needs_renewal`). A newly registered key
stays *pending* in the account until the set written with it is on disk. Files in the folder are
replaced or removed only when they carry this install's private key: the name alone proves nothing.

Private material (the seed) lives in `profiles/AWG Proton/proton_account.json`, never under
`temp/` (I19). The module is free of Tk and nova.pyw globals so pytest imports it directly
(`tests/test_nova_proton.py`).
"""

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import random
import re
import secrets
import socket
import ssl
import threading
import time
from urllib.parse import unquote, urlsplit

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --- API -------------------------------------------------------------------------------------

# Both hosts serve the whole flow; the second one is for networks where the first is closed.
API_HOSTS = ("https://vpn-api.proton.me", "https://api.protonvpn.ch")
APP_VERSION = "android-vpn@5.4.44.0"
USER_AGENT_APP = "ProtonVPN/5.4.44.0"
CHALLENGE_FRAME_KEY = "vpn-android-v4-challenge-0"
CHALLENGE_VERSION = "2.0.7"
DEVICE_NAME = "Nova PC"
CERT_MODE = "persistent"

CONNECT_TIMEOUT_S = 10.0
READ_TIMEOUT_S = 25.0

# Proton's human-verification challenge. Surfaced as-is: solving or dodging it is not ours to do.
CODE_HUMAN_VERIFICATION = 9001

# --- Layout (mirrors nova_profiles; kept literal so this module imports on its own) -----------

PROFILES_DIRNAME = "profiles"
GROUP_PROTON = "AWG Proton"
ACCOUNT_FILENAME = "proton_account.json"
NODES_FILENAME = "proton_nodes.json"

# --- Profile set -----------------------------------------------------------------------------

TARGET_COUNT = 50
# A cert is treated as alive only while it has more than this left: a profile that silently
# stops handshaking is worse than one extra run (Android CERT_RENEW_MARGIN_MS).
CERT_RENEW_MARGIN_S = 30 * 24 * 3600

# The ports Proton nodes accept WireGuard on. Do not add 123/500: nodes do not listen there,
# and every such entry is a wasted attempt at the price of a full handshake timeout (S50).
# Ordered by the pass rate measured on this machine through wireproxy-awg on 2026-09-13
# (passed/tried): 443 3/4, 1194 2/2, 88 3/3, 5060 2/2, 1224 1/1, 80 1/2, 4569 untested,
# 51820 0/3 (handshake completes, no data), 4500 0/1. Ports go round-robin by set index, so the
# head of the set -- the profiles tried first -- gets the ports that actually carried traffic.
PORTS = (443, 1194, 88, 5060, 1224, 80, 4569, 51820, 4500)

# Reuse without touching the network (Android ProtonProfileStore LIVE_NODES_REFRESH_MS /
# NODES_REFRESH_MS): every run opens a new anonymous Proton account and gets a session-bound
# node subset, i.e. a completely new set of names, so a complete set is kept while it is fresh.
LIVE_NODES_REFRESH_S = 24 * 3600
BUNDLED_NODES_REFRESH_S = 6 * 3600

# After a failed run a normal (non-force) run does not go out again for this long: each attempt
# is a new carrier session and a new anonymous account, and a connect loop would escalate Proton's
# anti-abuse. A human-verification answer backs off longer.
FAILURE_COOLDOWN_S = 3600
HUMAN_VERIFICATION_COOLDOWN_S = 6 * 3600

# Every Proton client gets the same inner addresses. IPv6 is left out on purpose: Proton
# announces ::/0 but the v6 peer is a black hole (Android P41), and a SOCKS egress has no
# reason to hand v6 to the tunnel.
INTERFACE_ADDRESS = "10.2.0.2/32"
INTERFACE_DNS = "10.2.0.1"
INTERFACE_MTU = 1420
ALLOWED_IPS = "0.0.0.0/0"
PERSISTENT_KEEPALIVE = 25

# Junk bounds shared with the WARP generator (and-warpgen.md §2.2). Proton nodes are stock
# WireGuard and drop the junk datagrams, so only Jc/Jmin/Jmax vary; S1-S4 and H1-H4 stay at
# identity values, anything else would break the handshake.
JUNK_COUNT_MIN = 3
JUNK_COUNT_MAX = 8
JUNK_SIZE_FLOOR = 30
JUNK_SIZE_CEILING = 150

NODES_SOURCE_LIVE = "live"
NODES_SOURCE_BUNDLED = "bundled"

# --- Relay -----------------------------------------------------------------------------------

RELAY_REASON_HEADER = "x-nova-relay-reason"
RELAY_CURRENT_HEADER = "x-nova-relay-current"
RELAY_REASON_OUTDATED = "outdated-client"
RELAY_OUTDATED_MESSAGE = "ключ релея устарел — обновите Nova"

LOG_PREFIX = "[Proton]"

# Fixed 12-byte DER SubjectPublicKeyInfo header for ed25519 ("MCowBQYDK2VwAyEA" in base64).
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

# --- Fabricated device frame (Android ProtonProfileStore.buildDeviceProfile) -----------------

# Chosen once per install and persisted: a frame that changes call to call looks worse to
# Proton's anti-abuse than one that stays the same, and real values would be a fingerprint.
# Never RU, and never tuned to enlarge the node list -- the list is bound to the session (N30).
DEVICE_MODELS = (
    ("Pixel 7", "13"),
    ("SM-A536B", "13"),
    ("SM-S911B", "14"),
    ("Redmi Note 12", "13"),
    ("moto g84 5G", "14"),
)
DEVICE_LOCALES = (
    ("fr", "FR", "Europe/Paris", -60),
    ("de", "DE", "Europe/Berlin", -60),
    ("en", "GB", "Europe/London", 0),
    ("nl", "NL", "Europe/Amsterdam", -60),
    ("es", "ES", "Europe/Madrid", -60),
)
DEVICE_STORAGE_BYTES = (6.4e10, 1.28e11, 2.56e11)
DEVICE_KEYBOARDS = ("com.google.android.inputmethod.latin",)
DEVICE_NAME_HASH_RANGE = (1_000_000_000_000, 9_000_000_000_000_000)
_FORBIDDEN_REGIONS = frozenset({"RU"})

_UNSAFE_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f\x7f]')
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_I1_LITERAL = re.compile(r"^<b 0x[0-9a-fA-F]+>$")
# Stems Proton gives free logicals ("NL-FREE#128" -> "NL-FREE-128"). The exact pattern
# nova_profiles uses for origin "generated" in AWG Proton, so listing and cleanup agree. A name
# alone never proves a file is ours: cleanup also requires this install's private key inside.
GENERATED_NAME_RE = re.compile(r"(?i)[A-Z]{2,3}-FREE-[0-9]+")
_PRIVATE_KEY_LINE = re.compile(r"^[ \t]*PrivateKey[ \t]*=[ \t]*(\S+)[ \t]*\r?$", re.IGNORECASE | re.MULTILINE)
_CONF_PEEK_CHARS = 64 * 1024
_DRAFT_SUFFIX = ".tmp"

# Windows sharing violations (an editor, AV or a sync client holding the target) are transient.
_REPLACE_ATTEMPTS = 5
_REPLACE_RETRY_DELAY_S = 0.08

# Account fields of a key registered by a run whose profile set is not on disk yet.
_PENDING_FIELDS = ("pending_seed_b64", "pending_wg_public", "pending_cert_expires_at", "pending_registered_at")
_FAILURE_FIELDS = ("failed_at", "last_error", "last_code", "last_transport", "last_routes")

_RUN_LOCK = threading.Lock()


def is_generated_name(name):
    """True for a Proton free-logical profile name (`NL-FREE-128` or `NL-FREE-128.conf`)."""
    stem = str(name or "")
    if stem.lower().endswith(".conf"):
        stem = stem[:-5]
    return GENERATED_NAME_RE.fullmatch(stem) is not None


# =============================================================================================
# Crypto
# =============================================================================================

def random_seed():
    """32 random bytes: the single ed25519 seed behind every Proton profile of this install."""
    return secrets.token_bytes(32)


def derive_keys(seed32):
    """seed -> {"ed25519_pem", "wg_private", "wg_public"} (and-proton.md §4).

    The PEM is `ClientPublicKey` for `/vpn/v1/certificate`; the WireGuard private key is
    `clamp(SHA-512(seed)[0:32])`, i.e. libsodium's ed25519 -> curve25519 conversion, which
    Proton runs on the registered public half as well.
    """
    seed = bytes(seed32)
    if len(seed) != 32:
        raise ValueError("seed должен быть 32 байта")
    ed_public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    pem_body = base64.b64encode(ED25519_SPKI_PREFIX + ed_public).decode("ascii")
    pem = "-----BEGIN PUBLIC KEY-----\n" + pem_body + "\n-----END PUBLIC KEY-----\n"

    clamped = bytearray(hashlib.sha512(seed).digest()[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    wg_private = bytes(clamped)
    wg_public = X25519PrivateKey.from_private_bytes(wg_private).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return {
        "ed25519_pem": pem,
        "wg_private": base64.b64encode(wg_private).decode("ascii"),
        "wg_public": base64.b64encode(wg_public).decode("ascii"),
    }


def _decode_wg_key(text):
    """Base64 WireGuard key -> 32 bytes, or None."""
    try:
        raw = base64.b64decode(str(text or "").strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 else None


# =============================================================================================
# Device profile, junk, node list
# =============================================================================================

def build_device_profile(rng=None):
    """A fabricated, plausible Android device for the anti-abuse frame (persist it)."""
    rng = rng or random.SystemRandom()
    model, android_version = rng.choice(DEVICE_MODELS)
    language, region, timezone, offset = rng.choice(DEVICE_LOCALES)
    return {
        "model": model,
        "android_version": android_version,
        "language": language,
        "region_code": region,
        "timezone": timezone,
        "timezone_offset": offset,
        "storage_bytes": rng.choice(DEVICE_STORAGE_BYTES),
        "device_name_hash": rng.randrange(*DEVICE_NAME_HASH_RANGE),
        "keyboards": list(DEVICE_KEYBOARDS),
    }


def is_valid_device_profile(device):
    """True when a stored device frame is complete and not RU."""
    if not isinstance(device, dict):
        return False
    for key in ("model", "android_version", "language", "region_code", "timezone"):
        if not isinstance(device.get(key), str) or not device.get(key).strip():
            return False
    if device["region_code"].strip().upper() in _FORBIDDEN_REGIONS:
        return False
    if isinstance(device.get("timezone_offset"), bool) or not isinstance(device.get("timezone_offset"), int):
        return False
    if not isinstance(device.get("storage_bytes"), (int, float)) or isinstance(device.get("storage_bytes"), bool):
        return False
    name_hash = device.get("device_name_hash")
    if isinstance(name_hash, bool) or not isinstance(name_hash, int) or name_hash <= 0:
        return False
    keyboards = device.get("keyboards")
    if not isinstance(keyboards, list) or not all(isinstance(k, str) for k in keyboards):
        return False
    return True


def random_junk(rng=None):
    """{"jc", "jmin", "jmax"} with the WARP generator's bounds; different per profile (N5)."""
    rng = rng or random.SystemRandom()
    jc = rng.randint(JUNK_COUNT_MIN, JUNK_COUNT_MAX)
    jmin = rng.randint(JUNK_SIZE_FLOOR, JUNK_SIZE_FLOOR + 40)
    jmax = rng.randint(jmin + 20, min(jmin + 80, JUNK_SIZE_CEILING))
    return {"jc": jc, "jmin": jmin, "jmax": jmax}


def _opt_int(value, default):
    """org.json `optInt` semantics: numbers and numeric strings convert, anything else is default."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value == value and value not in (float("inf"), float("-inf")) else default
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text)
        except ValueError:
            try:
                return int(float(text))
            except (ValueError, OverflowError):
                return default
    return default


def _opt_float(value, default):
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _valid_ip(text):
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _make_node(name, country, city, entry_ip, peer_key, load, score):
    return {
        "name": name or "PROTON",
        "country": (country or "??").upper(),
        "city": city or "",
        "entry_ip": entry_ip,
        "peer_public_key": peer_key,
        "load": load,
        "score": score,
    }


def parse_logicals(payload):
    """`/vpn/logicals?Tier=0` JSON -> free nodes (Android `fetchFreeServers`).

    Keeps a logical only with Tier == 0 and Status == 1; inside it, the first physical with
    Status == 1, a valid EntryIP and a 32-byte X25519PublicKey (physicals of one logical share
    address and key, so more would only duplicate the list).
    """
    if not isinstance(payload, dict):
        return []
    logicals = payload.get("LogicalServers")
    if not isinstance(logicals, list):
        return []
    nodes = []
    for logical in logicals:
        if not isinstance(logical, dict):
            continue
        if _opt_int(logical.get("Tier"), -1) != 0:
            continue
        if _opt_int(logical.get("Status"), 0) != 1:
            continue
        physicals = logical.get("Servers")
        if not isinstance(physicals, list):
            continue
        for physical in physicals:
            if not isinstance(physical, dict):
                continue
            if _opt_int(physical.get("Status"), 0) != 1:
                continue
            entry_ip = _text(physical.get("EntryIP"))
            peer_key = _text(physical.get("X25519PublicKey"))
            if not entry_ip or not peer_key:
                continue
            if not _valid_ip(entry_ip) or _decode_wg_key(peer_key) is None:
                continue
            nodes.append(_make_node(
                _text(logical.get("Name")),
                _text(logical.get("ExitCountry")),
                _text(logical.get("City")),
                entry_ip,
                peer_key,
                _opt_int(logical.get("Load"), 100),
                _opt_float(logical.get("Score"), float("inf")),
            ))
            break
    return nodes


def load_bundled_nodes(path):
    """Shipped `proton_nodes.json` -> nodes. Raises OSError / ValueError when unusable."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    raw_nodes = data.get("nodes") if isinstance(data, dict) else None
    if not isinstance(raw_nodes, list):
        raise ValueError("в proton_nodes.json нет списка nodes")
    nodes = []
    for item in raw_nodes:
        if not isinstance(item, dict):
            continue
        entry_ip = _text(item.get("entry_ip"))
        peer_key = _text(item.get("peer_public_key"))
        if not _valid_ip(entry_ip) or _decode_wg_key(peer_key) is None:
            continue
        # The bundled list has no load: every node counts as equal and keeps the file order,
        # which is already round-robin by country (Android ProtonNodeCatalog).
        nodes.append(_make_node(
            _text(item.get("server_name")),
            _text(item.get("country")),
            _text(item.get("city")),
            entry_ip,
            peer_key,
            50,
            0.0,
        ))
    return nodes


def conf_filename(name):
    """Profile file name: `NL-FREE#128` -> `NL-FREE-128.conf`, Windows-safe."""
    stem = _UNSAFE_FILENAME_CHARS.sub("_", str(name or "").replace("#", "-")).strip().strip(".").strip()
    return (stem or "PROTON") + ".conf"


def order_nodes(nodes):
    """Least-loaded first inside each country, then round-robin across countries.

    Countries follow the order of their least-loaded node, so the head of the set is the best
    node of every country rather than twenty NL nodes in a row. Duplicates by address+key and
    by file name (case-insensitive: Windows) are dropped, the first one kept.
    """
    ranked = sorted(
        (n for n in nodes if isinstance(n, dict)),
        key=lambda n: (n.get("load", 100), n.get("score", float("inf"))),
    )
    buckets = {}
    seen_pairs = set()
    seen_files = set()
    for node in ranked:
        pair = (node.get("entry_ip"), node.get("peer_public_key"))
        filename = conf_filename(node.get("name")).lower()
        if pair in seen_pairs or filename in seen_files:
            continue
        seen_pairs.add(pair)
        seen_files.add(filename)
        buckets.setdefault(node.get("country") or "??", []).append(node)
    ordered = []
    queues = [list(bucket) for bucket in buckets.values()]
    while queues:
        next_round = []
        for queue in queues:
            ordered.append(queue.pop(0))
            if queue:
                next_round.append(queue)
        queues = next_round
    return ordered


def plan_profiles(nodes, count=TARGET_COUNT, *, taken=()):
    """Nodes -> [{"node", "port", "filename"}]: at most `count`, ports round-robin by index.

    One profile per node: file names come from the node name, so a second port on the same
    node would need a name the layout does not have. A node whose file name is in `taken`
    (case-insensitive; a file in the folder that this install did not write) is skipped and the
    next node fills its place, so a user's file is never overwritten and ports stay dense.
    """
    limit = max(0, int(count))
    blocked = {str(name).lower() for name in (taken or ())}
    plan = []
    for node in order_nodes(nodes):
        if len(plan) >= limit:
            break
        filename = conf_filename(node.get("name"))
        if filename.lower() in blocked:
            continue
        plan.append({
            "node": node,
            "port": PORTS[len(plan) % len(PORTS)],
            "filename": filename,
        })
    return plan


def _endpoint(host, port):
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]:{int(port)}"
    except ValueError:
        pass
    return f"{host}:{int(port)}"


def build_proton_conf(private_key, node, port, junk, i1=""):
    """The `.conf` text of one Proton profile (DESIGN §7), newline-terminated.

    `I1` is emitted only when it is a well-formed `<b 0x…>` literal: an empty or garbage I1
    kills the tunnel (N6), while no I1 merely drops the QUIC mask.
    """
    name = _CONTROL_CHARS.sub(" ", str(node.get("name") or "PROTON")).strip()
    city = _CONTROL_CHARS.sub(" ", str(node.get("city") or "")).strip()
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {INTERFACE_ADDRESS}",
        f"DNS = {INTERFACE_DNS}",
        f"MTU = {INTERFACE_MTU}",
        "S1 = 0",
        "S2 = 0",
        "S3 = 0",
        "S4 = 0",
        f"Jc = {int(junk['jc'])}",
        f"Jmin = {int(junk['jmin'])}",
        f"Jmax = {int(junk['jmax'])}",
        "H1 = 1",
        "H2 = 2",
        "H3 = 3",
        "H4 = 4",
    ]
    i1_value = str(i1 or "").strip()
    if i1_value and _I1_LITERAL.match(i1_value):
        lines.append(f"I1 = {i1_value}")
    lines.extend([
        "",
        "[Peer]",
        f"# {name} ({city})" if city else f"# {name}",
        f"PublicKey = {node['peer_public_key']}",
        f"AllowedIPs = {ALLOWED_IPS}",
        f"Endpoint = {_endpoint(node['entry_ip'], port)}",
        f"PersistentKeepalive = {PERSISTENT_KEEPALIVE}",
    ])
    return "\n".join(lines) + "\n"


# =============================================================================================
# Proxy hygiene
# =============================================================================================

def redact_proxy_url(url):
    """`scheme://host:port` with the userinfo removed -- the only form a proxy may be logged in."""
    try:
        parts = urlsplit(str(url or "").strip())
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "прокси"
    if not host:
        return "прокси"
    if ":" in host:
        host = f"[{host}]"
    scheme = parts.scheme or "http"
    return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"


class _Scrubber:
    """Removes proxy URLs and passwords from any text before it reaches a log line."""

    def __init__(self, proxies):
        self._pairs = []
        for url in proxies:
            text = str(url or "").strip()
            if not text:
                continue
            self._pairs.append((text, redact_proxy_url(text)))
            try:
                parts = urlsplit(text)
                password = parts.password
                username = parts.username
            except ValueError:
                continue
            if username and password is not None:
                self._pairs.append((f"{username}:{password}@", ""))
                self._pairs.append((f"{unquote(username)}:{unquote(password)}@", ""))
            for secret in (password, unquote(password) if password else None):
                if secret and len(secret) >= 4:
                    self._pairs.append((secret, "***"))
        # Longest first, so a full URL is replaced before the password inside it.
        self._pairs.sort(key=lambda pair: len(pair[0]), reverse=True)

    def __call__(self, text):
        out = str(text)
        for secret, replacement in self._pairs:
            if secret:
                out = out.replace(secret, replacement)
        return out


def _safe_log(log, scrub=None):
    def emit(message):
        if log is None:
            return
        text = scrub(message) if scrub else str(message)
        try:
            log(text)
        except Exception:
            # A broken log sink must not abort key registration half-way; the run's outcome
            # still reaches the caller through the returned summary.
            pass
    return emit


def _probe_proxy_rejection(proxy_url, target_host, target_port=443, timeout=CONNECT_TIMEOUT_S):
    """Raw CONNECT through the proxy to read the headers of its rejection.

    http.client drops the headers of a failed CONNECT before urllib3 raises, and the relay puts
    the one thing worth telling the user -- "this build's key is retired" -- into a header.
    Returns {"status": int, "headers": {lowercase name: value}}; raises OSError on failure.
    """
    parts = urlsplit(proxy_url)
    host = parts.hostname
    if not host:
        raise OSError("прокси без адреса")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = raw
    try:
        if parts.scheme == "https":
            try:
                import certifi
                context = ssl.create_default_context(cafile=certifi.where())
            except ImportError:
                context = ssl.create_default_context()
            sock = context.wrap_socket(raw, server_hostname=host)
            sock.settimeout(timeout)
        lines = [
            f"CONNECT {target_host}:{int(target_port)} HTTP/1.1",
            f"Host: {target_host}:{int(target_port)}",
        ]
        if parts.username is not None:
            credentials = f"{unquote(parts.username)}:{unquote(parts.password or '')}"
            token = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        received = b""
        while b"\r\n\r\n" not in received and len(received) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            received += chunk
    finally:
        try:
            sock.close()
        except OSError:
            pass
    head = received.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
    match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", head[0] if head else "")
    if not match:
        raise OSError("прокси ответил не HTTP")
    headers = {}
    for line in head[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return {"status": int(match.group(1)), "headers": headers}


# =============================================================================================
# API client
# =============================================================================================

class ProtonApiError(Exception):
    """A Proton API step failed. `transport` = nobody answered; otherwise Proton said no."""

    def __init__(self, message, *, status=None, code=None, error="", transport=False,
                 relay_outdated=False):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.error = error
        self.transport = transport
        self.relay_outdated = relay_outdated


class _Route:
    def __init__(self, proxy_url=None):
        self.proxy_url = proxy_url
        self.label = "напрямую" if proxy_url is None else f"через {redact_proxy_url(proxy_url)}"
        self.session = requests.Session()
        # Never let the environment or the Windows registry proxy pick the path: "direct" must
        # mean direct, and each proxy route must mean exactly that proxy.
        self.session.trust_env = False
        if proxy_url is not None:
            self.session.proxies = {"http": proxy_url, "https": proxy_url}
        self.rejected = False  # 407 from this proxy: do not ask it again during this run


def _clean_api_text(value, limit=200):
    return _CONTROL_CHARS.sub(" ", str(value or "")).strip()[:limit]


def _host_of(base):
    return base.split("://", 1)[-1]


def _proxy_tunnel_status(exc):
    """HTTP status a proxy gave to CONNECT, parsed from the ProxyError text; None if it never answered."""
    match = re.search(r"Tunnel connection failed: (\d{3})", str(exc))
    return int(match.group(1)) if match else None


def describe_transport_error(exc):
    """Short Russian reason for a requests exception (no URLs, no credentials)."""
    text = str(exc)
    detail = ""
    code_match = re.search(r"(WinError \d+|Errno -?\d+)", text)
    if code_match:
        detail = f" [{code_match.group(1)}]"
    if isinstance(exc, requests.exceptions.ProxyError):
        status = _proxy_tunnel_status(exc)
        if status is not None:
            return f"прокси ответил {status}"
        return "прокси недоступен" + detail
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return f"таймаут соединения ({int(CONNECT_TIMEOUT_S)} с)"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return f"таймаут ответа ({int(READ_TIMEOUT_S)} с)"
    if isinstance(exc, requests.exceptions.SSLError):
        return "ошибка TLS"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "нет соединения" + detail
    return type(exc).__name__


class ProtonClient:
    """Proton API over an ordered set of routes: direct first, then the caller's proxies.

    The first route+host that answers becomes the starting point for the next call of the run:
    on a network where the direct path is closed, paying its timeout on every step would make
    the whole run minutes long (Android `preferredDirectHost` / `relayProven`).
    """

    def __init__(self, device, *, log=None, proxies=(), direct=True, hosts=None, scrub=None):
        self.device = device
        self._hosts = tuple(hosts if hosts is not None else API_HOSTS)
        self._log = _safe_log(log, scrub or _Scrubber(proxies))
        self._routes = []
        if direct:
            self._routes.append(_Route(None))
        for proxy in proxies:
            url = str(proxy or "").strip()
            if not url:
                continue
            try:
                parts = urlsplit(url)
                valid = parts.scheme in ("http", "https") and bool(parts.hostname)
                if valid:
                    parts.port  # raises ValueError on a malformed port
            except ValueError:
                valid = False
            if not valid:
                self._log(f"{LOG_PREFIX} прокси {redact_proxy_url(url)} пропущен: нужен http:// или https://")
                continue
            self._routes.append(_Route(url))
        self._preferred = None  # (route index, host)
        self.last_route_label = ""
        self.relay_outdated = False

    def close(self):
        for route in self._routes:
            route.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    # -- plumbing ---------------------------------------------------------------------------

    def _headers(self, auth, has_body):
        headers = {
            "x-pm-appversion": APP_VERSION,
            "x-pm-apiversion": "3",
            "Accept": "application/vnd.protonmail.v1+json",
            "User-Agent": f"{USER_AGENT_APP} (Android {self.device['android_version']}; {self.device['model']})",
        }
        if has_body:
            headers["Content-Type"] = "application/json"
        if auth:
            headers["x-pm-uid"] = auth["uid"]
            headers["Authorization"] = f"Bearer {auth['access_token']}"
        return headers

    def _attempt_order(self):
        order = []
        for route_index, route in enumerate(self._routes):
            hosts = list(self._hosts)
            if self._preferred and self._preferred[0] == route_index and self._preferred[1] in hosts:
                hosts.remove(self._preferred[1])
                hosts.insert(0, self._preferred[1])
            order.append((route_index, route, hosts))
        if self._preferred:
            order.sort(key=lambda item: item[0] != self._preferred[0])
        return order

    def _handle_proxy_rejection(self, route, label):
        """A 407 from a proxy: find out whether it means "retired key" and say so in words."""
        route.rejected = True
        try:
            answer = _probe_proxy_rejection(route.proxy_url, _host_of(self._hosts[0]))
        except (OSError, ValueError) as exc:
            return f"прокси отклонил авторизацию (407), причину прочитать не удалось: {type(exc).__name__}"
        headers = answer["headers"]
        if answer["status"] == 407 and headers.get(RELAY_REASON_HEADER, "").lower() == RELAY_REASON_OUTDATED:
            self.relay_outdated = True
            current = _clean_api_text(headers.get(RELAY_CURRENT_HEADER, ""), 32)
            suffix = f" (актуальная версия {current})" if current else ""
            return RELAY_OUTDATED_MESSAGE + suffix
        return "прокси отклонил авторизацию (407)"

    def call(self, method, path, body=None, auth=None):
        """One API call over all routes. Returns the JSON object or raises ProtonApiError.

        An answer from Proton with an error Code is final for the call (another route reaches
        the same backend and would repeat it, and routing around 9001 or a rate limit is not
        ours to do). Only "nobody answered" -- transport errors, 5xx, non-JSON pages -- moves on.
        """
        label = path.split("?", 1)[0]
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = self._headers(auth, payload is not None)
        failures = []
        started = time.monotonic()
        for route_index, route, hosts in self._attempt_order():
            if route.rejected:
                continue
            for host in hosts:
                try:
                    response = route.session.request(
                        method,
                        host + path,
                        data=payload,
                        headers=headers,
                        timeout=(CONNECT_TIMEOUT_S, READ_TIMEOUT_S),
                        allow_redirects=False,
                    )
                    content = response.content
                except requests.exceptions.ProxyError as exc:
                    proxy_status = _proxy_tunnel_status(exc)
                    if proxy_status == 407:
                        reason = self._handle_proxy_rejection(route, label)
                    else:
                        reason = describe_transport_error(exc)
                    self._log(f"{LOG_PREFIX} {label}: {_host_of(host)} {route.label} — {reason}")
                    failures.append(reason)
                    if proxy_status is None or proxy_status == 407:
                        # Dead proxy or refused credentials: the other host goes through the
                        # same proxy and would get the same answer.
                        break
                    continue
                except requests.exceptions.RequestException as exc:
                    reason = describe_transport_error(exc)
                    self._log(f"{LOG_PREFIX} {label}: {_host_of(host)} {route.label} — {reason}")
                    failures.append(reason)
                    continue

                status = response.status_code
                data = None
                try:
                    data = json.loads(content.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    data = None
                if 200 <= status < 300 and isinstance(data, dict):
                    elapsed_ms = int((time.monotonic() - started) * 1000)
                    if failures or self._preferred != (route_index, host):
                        self._log(
                            f"{LOG_PREFIX} {label}: ответ {route.label} ({_host_of(host)}) за {elapsed_ms} мс"
                        )
                    self._preferred = (route_index, host)
                    self.last_route_label = route.label
                    return data
                if isinstance(data, dict) and ("Code" in data or "Error" in data) and status < 500:
                    code = _opt_int(data.get("Code"), None)
                    error = _clean_api_text(data.get("Error"))
                    if code == CODE_HUMAN_VERIFICATION:
                        message = (
                            f"Proton требует проверку человеком (Code {code}) — Nova её не проходит, "
                            "выпуск остановлен; попробуйте позже"
                        )
                    else:
                        message = f"Proton ответил HTTP {status}, Code {code}: {error or 'без описания'}"
                    self._log(f"{LOG_PREFIX} {label}: {message} ({route.label}, {_host_of(host)})")
                    raise ProtonApiError(message, status=status, code=code, error=error)
                reason = f"HTTP {status}" + (", не JSON" if data is None else "")
                self._log(f"{LOG_PREFIX} {label}: {_host_of(host)} {route.label} — {reason}")
                failures.append(reason)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        last = failures[-1] if failures else "нет ни одного маршрута"
        if self.relay_outdated and RELAY_OUTDATED_MESSAGE not in last:
            last = f"{last}; {RELAY_OUTDATED_MESSAGE}"
        message = f"API Proton недоступен ({label}, {elapsed_ms} мс): {last}"
        raise ProtonApiError(message, transport=True, relay_outdated=self.relay_outdated)

    # -- the four steps ---------------------------------------------------------------------

    def create_session(self):
        """Step 1: unauthenticated carrier session."""
        data = self.call("POST", "/auth/v4/sessions", body={})
        auth = {
            "uid": _text(data.get("UID")),
            "access_token": _text(data.get("AccessToken")),
            "refresh_token": _text(data.get("RefreshToken")),
        }
        if not auth["uid"] or not auth["access_token"]:
            raise ProtonApiError("Proton выдал сессию без UID или токена")
        return auth

    def _credentialless_once(self):
        carrier = self.create_session()
        device = self.device
        frame = {
            "v": CHALLENGE_VERSION,
            "appLang": device["language"],
            "timezone": device["timezone"],
            "deviceName": int(device["device_name_hash"]),
            "regionCode": device["region_code"],
            "timezoneOffset": int(device["timezone_offset"]),
            "isJailbreak": False,
            "preferredContentSize": "1.0",
            "storageCapacity": float(device["storage_bytes"]),
            "isDarkmodeOn": True,
            "keyboards": list(device["keyboards"]),
        }
        body = {"Payload": {CHALLENGE_FRAME_KEY: frame}}
        data = self.call("POST", "/auth/v4/credentialless", body=body, auth=carrier)
        scopes = data.get("Scopes")
        scopes = [str(s) for s in scopes] if isinstance(scopes, list) else []
        if "vpn" not in scopes:
            raise ProtonApiError(f"сессия без scope vpn (получено: {','.join(scopes) or 'ничего'})")
        auth = {
            "uid": _text(data.get("UID")),
            "access_token": _text(data.get("AccessToken")),
            "refresh_token": _text(data.get("RefreshToken")),
        }
        if not auth["uid"] or not auth["access_token"]:
            raise ProtonApiError("Proton выдал сессию без UID или токена")
        return auth

    def create_credentialless_session(self):
        """Step 2, surviving a lost answer: on "already tied" take a fresh carrier, retry once."""
        try:
            return self._credentialless_once()
        except ProtonApiError as exc:
            if exc.transport or "already tied" not in f"{exc.error} {exc.message}".lower():
                raise
            self._log(
                f"{LOG_PREFIX} сессия уже привязана — ответ на прошлую попытку потерялся, а запрос дошёл; "
                "беру новую сессию и повторяю один раз"
            )
            return self._credentialless_once()

    def fetch_free_servers(self, auth):
        """Step 3: free logicals, parsed."""
        return parse_logicals(self.call("GET", "/vpn/logicals?Tier=0", auth=auth))

    def register_key(self, auth, public_key_pem):
        """Step 4: register the ed25519 key; returns ExpirationTime in epoch seconds."""
        data = self.call(
            "POST",
            "/vpn/v1/certificate",
            body={"ClientPublicKey": public_key_pem, "Mode": CERT_MODE, "DeviceName": DEVICE_NAME},
            auth=auth,
        )
        expires = _opt_int(data.get("ExpirationTime"), 0)
        if expires > 100_000_000_000:  # milliseconds, defensively
            expires //= 1000
        if expires <= 0:
            raise ProtonApiError("сертификат без ExpirationTime")
        return expires


# =============================================================================================
# Files
# =============================================================================================

def profile_group_dir(base_dir):
    return os.path.join(str(base_dir), PROFILES_DIRNAME, GROUP_PROTON)


class AccountReadError(OSError, ValueError):
    """`proton_account.json` exists but could not be read right now (sharing violation, access).

    Not corruption: the seed is probably intact, so nothing may start a new identity or rewrite
    the file over it. It is also a ValueError so callers written against the old contract
    ("ValueError when corrupt") keep working; new code checks OSError first.
    """


def _os_reason(exc):
    winerror = getattr(exc, "winerror", None)
    return f"{type(exc).__name__} [WinError {winerror}]" if winerror else type(exc).__name__


def _replace_with_retry(src, dst):
    """os.replace, retried briefly: on Windows a reader without FILE_SHARE_DELETE blocks it for a moment."""
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(src, dst)
            return
        except FileNotFoundError:
            raise
        except OSError:
            if attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACE_RETRY_DELAY_S)


def _remove_quietly(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


def _write_json_atomic(path, obj):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=1)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        _replace_with_retry(tmp, path)
    except BaseException:
        # The draft of the account holds the seed: never leave it next to the real file.
        _remove_quietly(tmp)
        raise


def read_account(group_dir):
    """`proton_account.json` -> dict, None when absent.

    Raises ValueError when corrupt, and AccountReadError (an OSError that is also a ValueError)
    when the file is there but cannot be read now -- that one must not be treated as corrupt.
    """
    path = os.path.join(group_dir, ACCOUNT_FILENAME)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AccountReadError(f"{ACCOUNT_FILENAME} занят или не читается: {_os_reason(exc)}") from exc
    except ValueError as exc:
        raise ValueError(f"{ACCOUNT_FILENAME} не читается: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{ACCOUNT_FILENAME} не объект JSON")
    return data


def _account_seed(account, field="seed_b64"):
    if not isinstance(account, dict):
        return None
    try:
        seed = base64.b64decode(str(account.get(field) or ""), validate=True)
    except (binascii.Error, ValueError):
        return None
    return seed if len(seed) == 32 else None


def _update_account(group_dir, fields, drop=()):
    """Merge `fields` into the account file (removing `drop`), keeping everything else it holds.

    Only a file that really is corrupt is started over; one that cannot be read right now raises
    (AccountReadError), because rewriting it would throw away the seed it still holds.
    """
    try:
        current = read_account(group_dir) or {}
    except AccountReadError:
        raise
    except ValueError:
        current = {}
    for key in drop:
        current.pop(key, None)
    current.update(fields)
    current["version"] = 1
    _write_json_atomic(os.path.join(group_dir, ACCOUNT_FILENAME), current)


def _now_s(now):
    return time.time() if now is None else now


def _usable_pending(account, now):
    """The seed a previous run registered but did not switch the set to, while its cert is alive."""
    seed = _account_seed(account, "pending_seed_b64")
    if seed is None:
        return None
    if _opt_int(account.get("pending_cert_expires_at"), 0) <= now + CERT_RENEW_MARGIN_S:
        return None
    return seed


def needs_renewal(account, now=None):
    """True when this install's Proton key needs a run: the backfill check (INTEGRATION §5).

    True while a registered key is waiting to be written into the set, when the set was written
    with a key other than the account's, or when the cert has CERT_RENEW_MARGIN_S or less left.
    False without an account or a key: issuing a first set is `should_issue`'s question.
    """
    if not isinstance(account, dict):
        return False
    now = _now_s(now)
    if _usable_pending(account, now) is not None:
        return True
    if _account_seed(account) is None:
        return False
    if _opt_int(account.get("cert_expires_at"), 0) <= now + CERT_RENEW_MARGIN_S:
        return True
    set_public = _text(account.get("set_wg_public"))
    wg_public = _text(account.get("wg_public"))
    return bool(set_public and wg_public and set_public != wg_public)


def _route_labels(proxies):
    """Password-free names of the routes a run would try (stored with a failure).

    The login stays in the label: the relay login carries the build version, so an updated Nova
    whose old login was refused counts as a new route and is not held back by that refusal.
    """
    labels = ["напрямую"]
    for proxy in proxies or ():
        text = str(proxy or "").strip()
        if not text:
            continue
        try:
            username = urlsplit(text).username
        except ValueError:
            username = None
        label = redact_proxy_url(text)
        labels.append(f"{label} ({_clean_api_text(unquote(username), 64)})" if username else label)
    return labels


def _failure_cooldown(account, now, routes=None):
    """(seconds since the failure, seconds left, code, error) while a normal run must wait; else None.

    A failure where nobody answered does not hold back a run that has a route the failed run did
    not have: at Nova start the API is often tried before the local Opera proxy is up, and that
    failure says nothing about the proxy.
    """
    if not isinstance(account, dict):
        return None
    failed_at = _opt_int(account.get("failed_at"), 0)
    if failed_at <= 0:
        return None
    code = _opt_int(account.get("last_code"), None) if account.get("last_code") is not None else None
    window = HUMAN_VERIFICATION_COOLDOWN_S if code == CODE_HUMAN_VERIFICATION else FAILURE_COOLDOWN_S
    elapsed = now - failed_at
    if not 0 <= elapsed < window:
        return None
    tried = account.get("last_routes")
    if routes is not None and account.get("last_transport") is True and isinstance(tried, list):
        if set(routes) - {str(label) for label in tried}:
            return None
    return elapsed, window - elapsed, code, _text(account.get("last_error"))


def _cooldown_text(cooldown):
    elapsed, left, _code, error = cooldown
    text = (f"прошлая попытка выпуска не удалась {int(elapsed // 60)} мин назад — повтор позже "
            f"(через {max(1, int(-(-left // 60)))} мин)")
    return f"{text}. Причина: {error}" if error else text


def _nodes_refresh_window(account):
    source = _text((account or {}).get("nodes_source"))
    return LIVE_NODES_REFRESH_S if source == NODES_SOURCE_LIVE else BUNDLED_NODES_REFRESH_S


def _nodes_fresh(account, now):
    checked = _opt_int((account or {}).get("nodes_checked_at"), 0)
    return checked > 0 and 0 <= now - checked < _nodes_refresh_window(account)


def should_issue(account, now, profiles_present, *, proxies=None):
    """(bool, Russian reason): whether a normal run would do anything (mirrors WARP should_reissue).

    Cheap and file-free apart from the account dict: for ProfileJobs and the connect path. A
    recent failure wins first (FAILURE_COOLDOWN_S, HUMAN_VERIFICATION_COOLDOWN_S after 9001) --
    unless nobody answered then and `proxies` (the list the run would get) adds a route; `force=True`
    runs ignore it. `issue_profiles` applies the same rules itself.
    """
    now = _now_s(now)
    cooldown = _failure_cooldown(account, now, None if proxies is None else _route_labels(proxies))
    if cooldown is not None:
        return False, _cooldown_text(cooldown)
    if not profiles_present:
        return True, "профилей Proton ещё нет"
    if not isinstance(account, dict) or (
            _account_seed(account) is None and _usable_pending(account, now) is None):
        return True, "ключ Proton ещё не выпущен"
    if _usable_pending(account, now) is not None:
        return True, "новый ключ зарегистрирован, но набор ещё не переписан на него"
    if needs_renewal(account, now):
        return True, f"сертификат ключа истекает {_format_date(_opt_int(account.get('cert_expires_at'), 0))}"
    if not _nodes_fresh(account, now):
        return True, "список узлов Proton устарел"
    return False, "набор Proton свежий — выпуск не нужен"


def _conf_private_key(path):
    """The first `PrivateKey = …` value of a profile file, or None (missing, unreadable, no key)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(_CONF_PEEK_CHARS)
    except (OSError, ValueError):
        return None
    match = _PRIVATE_KEY_LINE.search(head)
    return match.group(1) if match else None


def _foreign_conf_names(group_dir, own_keys):
    """Lower-case names of `.conf` files in the folder that this install's keys did not write."""
    names = set()
    try:
        entries = os.listdir(group_dir)
    except OSError:
        return names
    for entry in entries:
        if entry.lower().endswith(".conf") and _conf_private_key(os.path.join(group_dir, entry)) not in own_keys:
            names.add(entry.lower())
    return names


def _remove_own_drafts(group_dir, own_keys, log):
    """Drafts (`*.conf.tmp`) an interrupted run left behind carry our private key: remove them."""
    try:
        entries = os.listdir(group_dir)
    except OSError:
        return
    for entry in entries:
        if not entry.lower().endswith(".conf" + _DRAFT_SUFFIX):
            continue
        path = os.path.join(group_dir, entry)
        if _conf_private_key(path) in own_keys and not _remove_quietly(path):
            log(f"{LOG_PREFIX} черновик {entry} от прерванного выпуска не удалён")


def write_nodes_file(path, nodes, *, generated_at_ms=None):
    """Public node facts in the shipped `proton_nodes.json` shape. Returns the node count."""
    ordered = order_nodes(nodes)
    document = {
        "generated_at": int(generated_at_ms if generated_at_ms is not None else time.time() * 1000),
        "source": "vpn-api.proton.me /vpn/logicals?Tier=0",
        "note": "Only public server facts. No keys, no account: each device registers its own.",
        "nodes": [
            {
                "server_name": node["name"],
                "country": node["country"],
                "city": node["city"],
                "entry_ip": node["entry_ip"],
                "peer_public_key": node["peer_public_key"],
            }
            for node in ordered
        ],
    }
    _write_json_atomic(path, document)
    return len(ordered)


def _write_profile_set(group_dir, files, previous_names, log, own_keys):
    """Write the new set next to the old one, switch it in, then remove the old set.

    Returns (written names, removed count). Ownership is proven by the private key inside a file,
    never by its name alone: a file is replaced or removed only when it carries one of `own_keys`
    (this install's live, pending or new key). Removal covers names from the account's record and
    generated-looking names (leftovers of an interrupted run); a hand-dropped `NL-FREE-12.conf`
    with someone else's key survives, and a planned file whose name is taken by such a file is
    skipped. Nothing of the old set is touched until every new file is on disk; a failed write or
    switch removes every draft (they hold the private key) and raises OSError with a Russian text.
    """
    own = set(own_keys)
    staged = []
    written = []
    try:
        for filename, text in files:
            final = os.path.join(group_dir, filename)
            if os.path.lexists(final) and _conf_private_key(final) not in own:
                log(f"{LOG_PREFIX} {filename} уже лежит в папке и записан не этой установкой — не перезаписываю")
                continue
            tmp = final + _DRAFT_SUFFIX
            # Staged before the write: a write that fails half-way still gets its draft removed.
            staged.append((tmp, final))
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            written.append(filename)
    except OSError as exc:
        _discard_drafts(staged, log)
        name = os.path.basename(staged[-1][1]) if staged else "профиль"
        raise OSError(f"черновик {name} не записан ({_os_reason(exc)}) — прежние профили не тронуты") from exc

    switched = 0
    try:
        for tmp, final in staged:
            _replace_with_retry(tmp, final)
            switched += 1
    except OSError as exc:
        _discard_drafts(staged[switched:], log)
        name = os.path.basename(staged[switched][1])
        raise OSError(
            f"{name} не заменён — файл занят другой программой ({_os_reason(exc)}); "
            f"переключено {switched} из {len(staged)}, прежние профили не удалены"
        ) from exc

    if not written:
        return written, 0  # nothing switched in: the old set stays exactly as it was
    new_names = {name.lower() for name in written}
    previous = {str(name).lower() for name in (previous_names or ())}
    removed = 0
    for entry in os.listdir(group_dir):
        low = entry.lower()
        if low in new_names or not low.endswith(".conf"):
            continue
        if low not in previous and not is_generated_name(entry):
            continue
        path = os.path.join(group_dir, entry)
        if _conf_private_key(path) not in own:
            if low in previous:
                log(f"{LOG_PREFIX} {entry} был в прежнем наборе, но ключ в нём не этой установки — оставляю")
            continue
        try:
            os.remove(path)
            removed += 1
        except OSError as exc:
            log(f"{LOG_PREFIX} старый профиль {entry} не удалён: {_os_reason(exc)}")
    return written, removed


def _discard_drafts(staged, log):
    for tmp, _final in staged:
        if not _remove_quietly(tmp):
            log(f"{LOG_PREFIX} не удалось убрать черновик {os.path.basename(tmp)}")


# =============================================================================================
# Orchestration
# =============================================================================================

class _Cancelled(Exception):
    pass


def _format_date(epoch_s):
    try:
        return time.strftime("%d.%m.%Y", time.localtime(int(epoch_s)))
    except (OverflowError, OSError, ValueError):
        return str(epoch_s)


def _make_i1_factory(log, rng):
    """Per-profile QUIC Initial builder. Blank on any trouble -- never a stub (N6)."""
    state = {"warned": False, "module": None, "offset": rng.randrange(1 << 16)}

    def warn(message):
        if not state["warned"]:
            state["warned"] = True
            log(message)

    def build(index):
        if state["module"] is None:
            try:
                import nova_quic_initial
            except Exception as exc:  # missing or broken module: profiles still work without I1
                warn(f"{LOG_PREFIX} модуль I1 недоступен ({type(exc).__name__}) — профили без маски QUIC")
                state["module"] = False
                return ""
            state["module"] = nova_quic_initial
        if state["module"] is False:
            return ""
        try:
            sni = state["module"].pick_sni(state["offset"] + index)
            value = str(state["module"].build_i1(sni) or "").strip()
        except Exception as exc:
            warn(f"{LOG_PREFIX} I1 не собрался ({type(exc).__name__}) — такие профили без маски QUIC")
            return ""
        if value and not _I1_LITERAL.match(value):
            warn(f"{LOG_PREFIX} I1 в неожиданном формате — такие профили без маски QUIC")
            return ""
        return value

    return build


def _base_summary(group_dir):
    return {
        "ok": False,
        "count": 0,
        "profiles": [],
        "profile_ids": [],
        "dir": group_dir,
        "nodes_source": "",
        "nodes_available": 0,
        "countries": {},
        "registered": False,
        "cert_expires_at": 0,
        "route": "",
        "removed": 0,
        "error": "",
        "code": None,
        "cancelled": False,
        "relay_outdated": False,
        # Added after phase 1; consumers of the original shape can ignore them.
        "reused": False,         # the existing set was kept as it is, nothing was written
        "warning": "",           # the run succeeded, but something the user may want to know failed
        "session_code": None,    # Proton Code of a failed session step the run survived (e.g. 9001)
    }


def _record_failure(group_dir, now, message, code, emit, *, transport=False, routes=()):
    """Arms the cooldown: without it every connect attempt would repeat the whole failed run."""
    try:
        _update_account(group_dir, {
            "failed_at": int(now),
            "last_error": _clean_api_text(message, 300),
            "last_code": code,
            "last_transport": bool(transport),
            "last_routes": list(routes),
        })
    except (OSError, ValueError) as exc:
        emit(f"{LOG_PREFIX} отметка о неудачной попытке не записана: {_os_reason(exc)}")


def issue_profiles(base_dir, *, log, proxies=(), count=TARGET_COUNT, force=False, progress=None):
    """Issue the Proton profile set into `profiles/AWG Proton/`. Never raises; returns a summary.

    A normal run keeps a complete set written with the live key and does not touch the network
    while its node list is fresh (LIVE_NODES_REFRESH_S / BUNDLED_NODES_REFRESH_S): the summary
    then has `reused` True. It also stays off the network for FAILURE_COOLDOWN_S after a failed run
    (HUMAN_VERIFICATION_COOLDOWN_S after 9001). The stored seed is reused while its cert has more
    than 30 days left; a new key is registered as *pending* and becomes the account's key only
    once the set written with it is on disk, and a later run finishes such a switch without a
    second registration. `force` ignores reuse and cooldown and always makes a new key. Live
    logicals win, the bundled list is the fallback -- but a stale complete set is kept rather than
    replaced by the bundled list. Only files carrying this install's key are replaced or removed.
    `progress(text)` may raise to cancel: the run then stops before touching any profile.
    """
    proxies = tuple(str(p).strip() for p in (proxies or ()) if str(p or "").strip())
    scrub = _Scrubber(proxies)
    emit = _safe_log(log, scrub)
    group_dir = profile_group_dir(base_dir)
    summary = _base_summary(group_dir)
    if not _RUN_LOCK.acquire(blocking=False):
        summary["error"] = "выпуск профилей Proton уже идёт"
        emit(f"{LOG_PREFIX} {summary['error']} — второй не начинаю")
        return summary
    try:
        _issue(base_dir, group_dir, summary, emit, scrub, proxies, count, force, progress)
    except _Cancelled:
        summary["cancelled"] = True
        summary["ok"] = False
        summary["error"] = summary["error"] or "выпуск прерван"
        emit(f"{LOG_PREFIX} выпуск прерван — прежние профили не тронуты")
    except Exception as exc:
        summary["ok"] = False
        summary["reused"] = False
        summary["error"] = f"{type(exc).__name__}: {scrub(_clean_api_text(exc, 300))}"
        emit(f"{LOG_PREFIX} выпуск упал: {summary['error']}")
        if not isinstance(exc, AccountReadError):
            _record_failure(group_dir, time.time(), summary["error"], None, emit)
    finally:
        _RUN_LOCK.release()
    return summary


def _intact_set(group_dir, account, wg_private, count):
    """The recorded set when every file of it is on disk with `wg_private` and it is big enough; else None."""
    names = account.get("generated_files") if isinstance(account, dict) else None
    if not isinstance(names, list) or not names:
        return None
    if not all(isinstance(name, str) for name in names):
        return None
    requested = _opt_int(account.get("requested_count"), 0)
    if len(names) < count and requested < count:
        return None
    for name in names:
        if os.path.basename(name) != name or not name.lower().endswith(".conf"):
            return None
        if _conf_private_key(os.path.join(group_dir, name)) != wg_private:
            return None
    return list(names)


def _reuse_set(summary, account, names, cert_expires_at, warning):
    countries = account.get("countries")
    if not isinstance(countries, dict) or not all(isinstance(v, int) for v in countries.values()):
        countries = {}
        for name in names:
            country = name.split("-", 1)[0].upper() if is_generated_name(name) else "??"
            countries[country] = countries.get(country, 0) + 1
    summary.update({
        "ok": True,
        "count": len(names),
        "profiles": list(names),
        "profile_ids": [f"{GROUP_PROTON}/{name[:-5]}" for name in names],
        "nodes_source": _text(account.get("nodes_source")),
        "nodes_available": _opt_int(account.get("nodes_available"), len(names)),
        "countries": dict(countries),
        "registered": False,
        "cert_expires_at": int(cert_expires_at),
        "removed": 0,
        "error": "",
        "code": None,
        "reused": True,
        "warning": warning,
    })


def _source_text(source):
    return "живой список" if source == NODES_SOURCE_LIVE else "встроенный список"


def _issue(base_dir, group_dir, summary, emit, scrub, proxies, count, force, progress):
    def step(text):
        emit(f"{LOG_PREFIX} {text}")
        if progress is not None:
            try:
                progress(text)
            except Exception as exc:
                raise _Cancelled() from exc

    def fail(message, code=None, record=True, transport=False):
        summary["error"] = message
        summary["code"] = code
        emit(f"{LOG_PREFIX} выпуск не удался: {message} — прежние профили не тронуты")
        if record:
            _record_failure(group_dir, now, scrub(message), code, emit,
                            transport=transport, routes=_route_labels(proxies))

    now = int(time.time())
    os.makedirs(group_dir, exist_ok=True)
    count = max(1, int(count))
    rng = random.SystemRandom()

    try:
        account = read_account(group_dir)
    except AccountReadError as exc:
        # Probably a sync client or AV holding the file: the seed in it is fine, so neither a new
        # identity nor a rewrite -- try again later.
        fail(f"{exc} — выпуск отложен, чтобы не завести новый ключ поверх сохранённого", record=False)
        return
    except ValueError as exc:
        emit(f"{LOG_PREFIX} {exc} — выпускаю новую личность")
        account = None

    device = account.get("device") if isinstance(account, dict) else None
    if not is_valid_device_profile(device):
        if device is not None:
            emit(f"{LOG_PREFIX} сохранённый профиль устройства неполон — составляю новый")
        device = build_device_profile(rng)

    live_seed = _account_seed(account)
    live_expires = _opt_int((account or {}).get("cert_expires_at"), 0)
    stored_pending = _account_seed(account, "pending_seed_b64")
    pending_seed = None if force else _usable_pending(account, now)
    # Every key this install may have written a profile with: only files carrying one of these
    # are ever replaced or removed.
    own_keys = {derive_keys(s)["wg_private"] for s in (live_seed, stored_pending) if s is not None}
    _remove_own_drafts(group_dir, own_keys, emit)

    previous_names = []
    if isinstance(account, dict) and isinstance(account.get("generated_files"), list):
        previous_names = [str(name) for name in account["generated_files"]]

    switching = False       # the set is being moved to a key the account does not call live yet
    registered_at = None
    if pending_seed is not None:
        seed = pending_seed
        cert_expires_at = _opt_int(account.get("pending_cert_expires_at"), 0)
        registered_at = _opt_int(account.get("pending_registered_at"), now)
        cert_alive = True
        switching = True
        emit(f"{LOG_PREFIX} ключ, зарегистрированный прошлым прогоном (сертификат до "
             f"{_format_date(cert_expires_at)}), ещё не записан в профили — дописываю набор с ним, "
             "повторной регистрации не будет")
    elif not force and live_seed is not None and live_expires > now + CERT_RENEW_MARGIN_S:
        seed = live_seed
        cert_expires_at = live_expires
        cert_alive = True
    else:
        seed = None
        cert_expires_at = 0
        cert_alive = False
        if live_seed is not None and force:
            emit(f"{LOG_PREFIX} принудительный выпуск — новый ключ и новая регистрация")
        elif live_seed is not None:
            emit(f"{LOG_PREFIX} сертификат ключа истекает {_format_date(live_expires)} "
                 "(меньше 30 дней) — выпускаю новый ключ")

    existing = None
    if cert_alive and not switching:
        existing = _intact_set(group_dir, account, derive_keys(seed)["wg_private"], count)
        if existing is not None and _nodes_fresh(account, now):
            _reuse_set(summary, account, existing, cert_expires_at, "")
            checked = _opt_int(account.get("nodes_checked_at"), now)
            emit(f"{LOG_PREFIX} набор свежий: {len(existing)} профилей, ключ до {_format_date(cert_expires_at)}, "
                 f"{_source_text(summary['nodes_source'])} проверен {(now - checked) // 3600} ч назад — "
                 "в сеть не иду")
            return

    if not force:
        cooldown = _failure_cooldown(account, now, _route_labels(proxies))
        if cooldown is not None:
            text = _cooldown_text(cooldown)
            if existing is not None:
                _reuse_set(summary, account, existing, cert_expires_at, f"набор не обновлён: {text}")
                emit(f"{LOG_PREFIX} {text}; остаюсь на прежнем наборе ({len(existing)} шт.)")
                return
            summary["relay_outdated"] = RELAY_OUTDATED_MESSAGE in cooldown[3]
            fail(text, cooldown[2], record=False)
            return

    if cert_alive and not switching:
        emit(f"{LOG_PREFIX} ключ зарегистрирован до {_format_date(cert_expires_at)} — "
             "переиспользую его, повторной регистрации не будет")

    # The attempt is marked before the first network step: whatever happens below, the next run
    # sees it (Android writeNodesAttempt), and the device frame stays the same across attempts.
    _update_account(group_dir, {
        "device": device,
        "device_name": DEVICE_NAME,
        "last_attempt_at": now,
        "nodes_checked_at": now,
    })

    client = ProtonClient(device, log=emit, proxies=proxies, scrub=scrub)
    try:
        step("создаю сессию")
        auth = None
        live_problem = ""
        try:
            auth = client.create_credentialless_session()
        except ProtonApiError as exc:
            summary["relay_outdated"] = client.relay_outdated
            if not cert_alive:
                fail(exc.message, exc.code, transport=exc.transport)
                return
            # Kept apart from "code": this run can still succeed, and a consumer that shows the
            # human-verification text on code 9001 must not show it after a successful issue.
            summary["session_code"] = exc.code
            live_problem = exc.message
            emit(f"{LOG_PREFIX} сессия не получена ({exc.message}); ключ жив — живого списка узлов не будет")

        nodes = []
        if auth is not None:
            step("беру список серверов")
            try:
                nodes = client.fetch_free_servers(auth)
            except ProtonApiError as exc:
                emit(f"{LOG_PREFIX} /vpn/logicals не ответил: {exc.message}")
                live_problem = exc.message
                nodes = []
            if not nodes:
                live_problem = live_problem or "живой список серверов пуст"
                emit(f"{LOG_PREFIX} живой список серверов пуст или не пришёл")
        summary["route"] = client.last_route_label
        summary["relay_outdated"] = client.relay_outdated
        if nodes:
            summary["nodes_source"] = NODES_SOURCE_LIVE
            emit(f"{LOG_PREFIX} получено {len(nodes)} бесплатных узлов, стран: "
                 f"{len({n['country'] for n in nodes})}")
        else:
            if existing is not None:
                # A complete set on the live key only went stale: the bundled list is not better
                # than yesterday's live one, and replacing it would change every profile id.
                warning = (f"список узлов Proton не обновился ({live_problem}) — "
                           f"прежний набор, {len(existing)} шт.")
                _reuse_set(summary, account, existing, cert_expires_at, warning)
                hours = _nodes_refresh_window(account) // 3600
                emit(f"{LOG_PREFIX} {warning}; следующая попытка через {hours} ч")
                return
            nodes_path = os.path.join(group_dir, NODES_FILENAME)
            try:
                nodes = load_bundled_nodes(nodes_path)
            except FileNotFoundError:
                emit(f"{LOG_PREFIX} встроенного {NODES_FILENAME} нет")
                nodes = []
            except (OSError, ValueError) as exc:
                emit(f"{LOG_PREFIX} встроенный {NODES_FILENAME} не читается: {type(exc).__name__}")
                nodes = []
            summary["nodes_source"] = NODES_SOURCE_BUNDLED
            if not nodes:
                fail("нет ни живого списка серверов Proton, ни встроенного")
                return
            summary["warning"] = f"живой список серверов не пришёл ({live_problem}) — профили из встроенного списка"
            emit(f"{LOG_PREFIX} список серверов от API не пришёл — беру встроенный: {len(nodes)} узлов")
        summary["nodes_available"] = len(nodes)

        if cert_alive:
            keys = derive_keys(seed)
        else:
            new_seed = random_seed()
            keys = derive_keys(new_seed)
            step("регистрирую ключ")
            try:
                expires = client.register_key(auth, keys["ed25519_pem"])
            except ProtonApiError as exc:
                summary["relay_outdated"] = client.relay_outdated
                fail(exc.message, exc.code, transport=exc.transport)
                return
            # Persisted at once (the profiles are useless without this seed), but as PENDING: the
            # confs on disk still carry the old key, and until the new set is written the account
            # must keep saying so -- otherwise an interruption below leaves old confs behind a
            # "fresh" cert and the renewal check never fires again.
            _update_account(group_dir, {
                "pending_seed_b64": base64.b64encode(new_seed).decode("ascii"),
                "pending_wg_public": keys["wg_public"],
                "pending_cert_expires_at": int(expires),
                "pending_registered_at": now,
                "device": device,
                "device_name": DEVICE_NAME,
            })
            seed = new_seed
            cert_expires_at = int(expires)
            registered_at = now
            switching = True
            own_keys.add(keys["wg_private"])
            summary["registered"] = True
            emit(f"{LOG_PREFIX} ключ зарегистрирован, сертификат до {_format_date(cert_expires_at)}")
        summary["cert_expires_at"] = cert_expires_at
        summary["route"] = client.last_route_label
        summary["relay_outdated"] = client.relay_outdated

        step("собираю профили")
        taken = _foreign_conf_names(group_dir, own_keys)
        plan = plan_profiles(nodes, count, taken=taken)
        blocked = sum(1 for n in order_nodes(nodes) if conf_filename(n.get("name")).lower() in taken)
        if blocked:
            emit(f"{LOG_PREFIX} узлов пропущено: {blocked} — файл с таким именем уже лежит в папке "
                 "и записан не этой установкой")
        make_i1 = _make_i1_factory(emit, rng)
        files = []
        for index, item in enumerate(plan):
            text = build_proton_conf(
                keys["wg_private"], item["node"], item["port"], random_junk(rng), make_i1(index)
            )
            files.append((item["filename"], text))
        if not files:
            fail("из списка серверов не собралось ни одного профиля")
            return

        step(f"записываю {len(files)} профилей")
        try:
            written, removed = _write_profile_set(group_dir, files, previous_names, emit, own_keys)
        except OSError as exc:
            fail(f"профили не записаны: {exc}")
            return
        if not written:
            fail("ни один профиль не записан: все имена заняты файлами, записанными не этой установкой")
            return

        written_low = {name.lower() for name in written}
        countries = {}
        for item in plan:
            if item["filename"].lower() in written_low:
                country = item["node"]["country"]
                countries[country] = countries.get(country, 0) + 1
        commit = {
            "seed_b64": base64.b64encode(seed).decode("ascii"),
            "wg_public": keys["wg_public"],
            "set_wg_public": keys["wg_public"],
            "cert_expires_at": int(cert_expires_at),
            "device": device,
            "device_name": DEVICE_NAME,
            "generated_files": list(written),
            "requested_count": count,
            "issued_at": now,
            "nodes_source": summary["nodes_source"],
            "nodes_checked_at": now,
            "nodes_available": len(nodes),
            "countries": countries,
        }
        if switching:
            commit["registered_at"] = registered_at or now
        # One write moves the key to live, records the set and clears the failure: the account
        # never names a key the set on disk does not use.
        _update_account(group_dir, commit, drop=_PENDING_FIELDS + _FAILURE_FIELDS)

        summary.update({
            "ok": True,
            "count": len(written),
            "profiles": list(written),
            "profile_ids": [f"{GROUP_PROTON}/{name[:-5]}" for name in written],
            "countries": countries,
            "removed": removed,
            "error": "",
            "code": None,
        })
        spread = ", ".join(f"{cc} {n}" for cc, n in sorted(countries.items(), key=lambda kv: (-kv[1], kv[0])))
        emit(f"{LOG_PREFIX} готово: {len(written)} профилей ({_source_text(summary['nodes_source'])}; {spread}), "
             f"старых убрано: {removed}")
    finally:
        client.close()


def refresh_nodes_file(base_dir, *, log, proxies=(), nodes=None):
    """Rewrite `profiles/AWG Proton/proton_nodes.json` with live public node facts.

    With `nodes` given, only writes them; otherwise fetches the list through a fresh
    credential-less session using the stored device frame. Never raises.
    """
    proxies = tuple(str(p).strip() for p in (proxies or ()) if str(p or "").strip())
    scrub = _Scrubber(proxies)
    emit = _safe_log(log, scrub)
    group_dir = profile_group_dir(base_dir)
    result = {"ok": False, "count": 0, "error": ""}
    try:
        os.makedirs(group_dir, exist_ok=True)
        if nodes is None:
            try:
                account = read_account(group_dir)
            except AccountReadError:
                raise  # busy, not corrupt: writing a new device frame would clobber the seed
            except ValueError:
                account = None
            device = (account or {}).get("device")
            if not is_valid_device_profile(device):
                device = build_device_profile()
                _update_account(group_dir, {"device": device})
            with ProtonClient(device, log=emit, proxies=proxies, scrub=scrub) as client:
                auth = client.create_credentialless_session()
                nodes = client.fetch_free_servers(auth)
        if not nodes:
            result["error"] = "Proton не выдал ни одного бесплатного узла"
            emit(f"{LOG_PREFIX} {NODES_FILENAME} не обновлён: {result['error']}")
            return result
        written = write_nodes_file(os.path.join(group_dir, NODES_FILENAME), nodes)
        result.update({"ok": True, "count": written})
        emit(f"{LOG_PREFIX} {NODES_FILENAME} обновлён: {written} узлов")
    except ProtonApiError as exc:
        result["error"] = exc.message
        emit(f"{LOG_PREFIX} {NODES_FILENAME} не обновлён: {exc.message}")
    except (OSError, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {scrub(_clean_api_text(exc))}"
        emit(f"{LOG_PREFIX} {NODES_FILENAME} не обновлён: {result['error']}")
    return result
