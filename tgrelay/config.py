import logging
import os
import string
import random
import socket as _socket
import threading

from dataclasses import dataclass, field
from typing import Dict, List
from urllib.request import Request, urlopen

log = logging.getLogger('tg-mtproto-proxy')

CFPROXY_DOMAINS_URL = (
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main"
    "/.github/cfproxy-domains.txt"
)

_CFPROXY_ENC: List[str] = ['virkgj.com', 'vmmzovy.com', 'mkuosckvso.com', 'zaewayzmplad.com', 'twdmbzcm.com']
_S = ''.join(chr(c) for c in (46, 99, 111, 46, 117, 107))


def _dd(s: str) -> str:
    """Only for decoding CF proxy domains"""
    if not s[-4:] == '.com':
        return s
    p, n = s[:-4], sum(c.isalpha() for c in s[:-4])
    return ''.join(
        chr((ord(c) - (97 if c > '`' else 65) - n) % 26 + (97 if c > '`' else 65))
        if c.isalpha() else c for c in p
    ) + _S


CFPROXY_DEFAULT_DOMAINS: List[str] = [_dd(d) for d in _CFPROXY_ENC]
NOVA_CFPROXY_PRIMARY_DOMAINS: List[str] = ["nova-app.eu"]


# --- Access token for the owned Cloudflare Worker ---------------------------
#
# The Worker on the owned domains is an open Telegram WSS proxy for anyone who
# learns the hostname. Nova signs every handshake so the Worker can tell its own
# client from an unrelated program pointed at the same subdomain.
#
# The signature travels as an extra WebSocket subprotocol next to ``binary``:
#
#     Sec-WebSocket-Protocol: binary, nova1.<window>.<hmac>
#
# ``window`` is the Unix time divided by CF_WS_TOKEN_WINDOW, so a captured token
# stops working within minutes. The Worker recomputes the HMAC over
# ``"<window>|<hostname>"``, which also stops a token minted for one subdomain
# from being replayed against another.
#
# The secret is read from NOVA_TG_CF_SECRET, then from tgrelay/cf_ws.key. That
# file sits next to this module so the installer ships it with the rest of the
# package, while the publication rules keep it out of git: only ``tgrelay/*.py``
# is whitelisted there. The built-in constant below is the public fallback — a
# clone of this repository still produces well-formed tokens, they just do not
# match the secret configured on the owner's Worker.
CF_WS_TOKEN_VERSION = "nova1"
CF_WS_TOKEN_WINDOW = 120
_CF_WS_TOKEN_PUBLIC_SECRET = "nova-public-fallback"
_CF_WS_SECRET_CACHE: List[str] = []


def _read_cf_ws_secret_file() -> str:
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "cf_ws.key"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "awg", "cf_ws.key"),
    ]
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                secret = handle.read().strip()
            if secret:
                return secret
        except Exception:
            continue
    return ""


def get_cf_ws_secret() -> str:
    if _CF_WS_SECRET_CACHE:
        return _CF_WS_SECRET_CACHE[0]
    secret = str(os.environ.get("NOVA_TG_CF_SECRET", "") or "").strip()
    if not secret:
        secret = _read_cf_ws_secret_file()
    if not secret:
        secret = _CF_WS_TOKEN_PUBLIC_SECRET
    _CF_WS_SECRET_CACHE.append(secret)
    return secret


def is_owned_cf_domain(host: str) -> bool:
    """True for hostnames served by the Worker Nova itself controls."""
    host = str(host or "").strip().lower().rstrip(".")
    if not host:
        return False
    for base in NOVA_CFPROXY_PRIMARY_DOMAINS:
        base = str(base or "").strip().lower()
        if base and (host == base or host.endswith("." + base)):
            return True
    return False


def build_cf_ws_token(host: str, now: float = 0.0) -> str:
    """Signed subprotocol entry for `host`, or '' if the host is not ours."""
    import hashlib
    import hmac
    import time as _time

    host = str(host or "").strip().lower().rstrip(".")
    if not is_owned_cf_domain(host):
        return ""
    window = int((now or _time.time()) // CF_WS_TOKEN_WINDOW)
    digest = hmac.new(
        get_cf_ws_secret().encode("utf-8"),
        f"{window}|{host}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]
    return f"{CF_WS_TOKEN_VERSION}.{window}.{digest}"


def cf_ws_subprotocol_header(host: str) -> str:
    """Value for Sec-WebSocket-Protocol: always 'binary', signed when ours."""
    token = build_cf_ws_token(host)
    return f"binary, {token}" if token else "binary"


@dataclass
class ProxyConfig:
    port: int = 1443
    host: str = '127.0.0.1'
    secret: str = field(default_factory=lambda: os.urandom(16).hex())
    dc_redirects: Dict[int, str] = field(default_factory=lambda: {2: '149.154.167.220', 4: '149.154.167.220'})
    buffer_size: int = 256 * 1024
    pool_size: int = 4
    fallback_cfproxy: bool = True
    fallback_cfproxy_priority: bool = True
    cfproxy_user_domain: str = ''
    cfproxy_domains: List[str] = field(default_factory=lambda: list(CFPROXY_DEFAULT_DOMAINS))
    active_cfproxy_domain: str = field(default_factory=lambda: random.choice(CFPROXY_DEFAULT_DOMAINS))
    fake_tls_domain: str = ''
    proxy_protocol: bool = False


proxy_config = ProxyConfig()


def _split_domains(raw: str) -> List[str]:
    return [
        item.strip().strip(".").lower()
        for item in str(raw or "").replace(";", ",").split(",")
        if item.strip().strip(".")
    ]


def _dedupe_domains(*groups: List[str]) -> List[str]:
    seen = set()
    merged: List[str] = []
    for group in groups:
        for item in group or []:
            domain = str(item or "").strip().strip(".").lower()
            if not domain or domain in seen:
                continue
            seen.add(domain)
            merged.append(domain)
    return merged


def get_cfproxy_domains(*env_names: str, fallback_pool: List[str] | None = None) -> List[str]:
    configured: List[str] = []
    configured.extend(_split_domains(os.environ.get("NOVA_TG_CF_DOMAINS", "")))
    for env_name in env_names:
        configured.extend(_split_domains(os.environ.get(str(env_name), "")))
    if proxy_config.cfproxy_user_domain:
        configured.append(str(proxy_config.cfproxy_user_domain))
    configured.extend(list(NOVA_CFPROXY_PRIMARY_DOMAINS))
    pool = list(fallback_pool) if fallback_pool is not None else list(proxy_config.cfproxy_domains or CFPROXY_DEFAULT_DOMAINS)
    return _dedupe_domains(configured, pool, list(CFPROXY_DEFAULT_DOMAINS))


def get_cfproxy_primary_domains(*env_names: str) -> List[str]:
    configured: List[str] = []
    configured.extend(_split_domains(os.environ.get("NOVA_TG_CF_DOMAINS", "")))
    for env_name in env_names:
        configured.extend(_split_domains(os.environ.get(str(env_name), "")))
    if proxy_config.cfproxy_user_domain:
        configured.append(str(proxy_config.cfproxy_user_domain))
    configured.extend(list(NOVA_CFPROXY_PRIMARY_DOMAINS))
    return _dedupe_domains(configured)


def get_cfproxy_public_domains(fallback_pool: List[str] | None = None) -> List[str]:
    pool = list(fallback_pool) if fallback_pool is not None else list(proxy_config.cfproxy_domains or CFPROXY_DEFAULT_DOMAINS)
    public = [item for item in pool if str(item or "").strip().lower() not in set(get_cfproxy_primary_domains())]
    if public:
        return _dedupe_domains(public)
    return _dedupe_domains(list(CFPROXY_DEFAULT_DOMAINS))


def _fetch_cfproxy_domain_list() -> List[str]:
    try:
        req = Request(CFPROXY_DOMAINS_URL + "?" + "".join(random.choices(string.ascii_letters, k=7)),
                       headers={'User-Agent': 'tg-ws-proxy'})
        with urlopen(req, timeout=10) as resp:
            text = resp.read().decode('utf-8', errors='replace')
        encoded = [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith('#')
        ]
        return [_dd(d) for d in encoded]
    except Exception as exc:
        log.warning("Failed to fetch CF proxy domain list: %s", exc)
        return []


def refresh_cfproxy_domains() -> None:
    fetched = _fetch_cfproxy_domain_list()

    if fetched:
        pool = _dedupe_domains(fetched)
        log.info("CF proxy domain pool updated from GitHub (%d domains)", len(pool))
    else:
        pool = list(proxy_config.cfproxy_domains) or list(CFPROXY_DEFAULT_DOMAINS)

    proxy_config.cfproxy_domains = get_cfproxy_domains(fallback_pool=pool)
    proxy_config.active_cfproxy_domain = proxy_config.cfproxy_domains[0] if proxy_config.cfproxy_domains else ""


_refresh_stop: threading.Event = threading.Event()


def start_cfproxy_domain_refresh() -> None:
    global _refresh_stop
    _refresh_stop.set()
    _refresh_stop = threading.Event()
    stop = _refresh_stop

    def _loop():
        refresh_cfproxy_domains()
        while not stop.wait(timeout=3600):
            refresh_cfproxy_domains()

    threading.Thread(target=_loop, daemon=True, name='cfproxy-domains-refresh').start()


def parse_dc_ip_list(dc_ip_list: List[str]) -> Dict[int, str]:
    dc_redirects: Dict[int, str] = {}
    for entry in dc_ip_list:
        if ':' not in entry:
            raise ValueError(
                f"Invalid --dc-ip format {entry!r}, expected DC:IP")
        dc_s, ip_s = entry.split(':', 1)
        try:
            dc_n = int(dc_s)
            _socket.inet_aton(ip_s)
        except (ValueError, OSError):
            raise ValueError(f"Invalid --dc-ip {entry!r}")
        dc_redirects[dc_n] = ip_s
    return dc_redirects
