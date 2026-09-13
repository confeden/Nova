import asyncio
import base64
import contextlib
import json
import os
import ipaddress
import logging
import random
import socket
import struct
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .config import (
    CFPROXY_DEFAULT_DOMAINS,
    cf_ws_subprotocol_header,
    get_cfproxy_domains,
    get_cfproxy_primary_domains,
    is_owned_cf_domain,
    proxy_config,
    start_cfproxy_domain_refresh,
)
from . import persona, phase
from .raw_websocket import (
    RawWebSocket,
    WsHandshakeError,
    note_deflate_unusable,
    offers_deflate,
    set_sock_opts,
)
from .transport import (
    open_stream,
    open_tls_stream,
    set_upstream_provider,
    get_upstream_attempts,
    set_log_func as set_transport_logger,
)


log = logging.getLogger("nova.telegram.relay")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_ROOT = os.path.dirname(REPO_ROOT) if os.path.basename(REPO_ROOT).lower() == "resources" else REPO_ROOT

ZERO_64 = b"\x00" * 64
PROTO_ABRIDGED = 0xEFEFEFEF
PROTO_INTERMEDIATE = 0xEEEEEEEE
PROTO_PADDED_INTERMEDIATE = 0xDDDDDDDD
TG_TCP_PORTS = {80, 443, 5222, *range(7300, 7311)}
WS_POOL_MAX_AGE = 120.0


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(str(name), None)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    try:
        return max(float(minimum), float(os.environ.get(str(name), str(default)) or default))
    except Exception:
        return float(default)


# Включено по умолчанию с 1.36.3. Выключенным оно ничего не стоило и ничего не
# давало; цена ошибки в другую сторону измерена — молчащий егресс держит
# соединение до таймаута, хотя рядом есть отвечающий за полсекунды.
# NOVA_TG_RELAY_FIRST_BYTE_RETRY=0 возвращает прежнее поведение.
FIRST_BYTE_STALL_RETRY = _env_bool("NOVA_TG_RELAY_FIRST_BYTE_RETRY", True)
FIRST_DOWN_UPLOAD_IDLE_GRACE = _env_float(
    "NOVA_TG_RELAY_UPLOAD_IDLE_GRACE",
    6.0,
    minimum=2.0,
)
MEDIA_WSS_MIN_PROGRESS = max(
    1024,
    int(_env_float("NOVA_TG_RELAY_MEDIA_MIN_PROGRESS", 4096.0, minimum=1024.0)),
)
CF_MEDIA_CONNECT_BUDGET = _env_float(
    "NOVA_TG_RELAY_CF_MEDIA_CONNECT_BUDGET",
    3.0,
    minimum=1.0,
)
CF_MEDIA_BAD_TTL = _env_float(
    "NOVA_TG_RELAY_CF_MEDIA_BAD_TTL",
    6.0,
    minimum=2.0,
)
FALLBACK_LOG_INTERVAL = _env_float("NOVA_TG_RELAY_FALLBACK_LOG_INTERVAL", 8.0, minimum=1.0)
SKIP_LOG_INTERVAL = _env_float("NOVA_TG_RELAY_SKIP_LOG_INTERVAL", 300.0, minimum=1.0)
# Сколько ждать первого байта от клиента. Молчащий сокет — не поломка:
# Telegram гоняет транспорты наперегонки, открывает :443 и :80 к одному DC и
# пишет только в победивший, а при выключенном в клиенте прокси оба приезжают
# сюда через redirect. Проигравший стоит молча до этого срока.
CLIENT_FIRST_BYTE_TIMEOUT = _env_float("NOVA_TG_RELAY_CLIENT_FIRST_BYTE_TIMEOUT", 5.0, minimum=1.0)
SILENT_CLIENT_LOG_INTERVAL = _env_float("NOVA_TG_RELAY_SILENT_CLIENT_LOG_INTERVAL", 60.0, minimum=1.0)
CF_FALLBACK_ENABLED = _env_bool("NOVA_TG_RELAY_CF_FALLBACK", True)
# How long a target stays marked as "Telegram is racing its HTTP transport
# here". Cleared early whenever a route becomes usable again.
HTTP_TRANSPORT_DROP_TTL = _env_float("NOVA_TG_RELAY_HTTP_TRANSPORT_TTL", 60.0, minimum=5.0)
CF_EMPTY_DOMAIN_TTL = _env_float("NOVA_TG_RELAY_CF_EMPTY_DOMAIN_TTL", 30.0, minimum=5.0)
CF_EMPTY_RECENT_GOOD_TTL = _env_float("NOVA_TG_RELAY_CF_EMPTY_RECENT_GOOD_TTL", 45.0, minimum=10.0)
CF_EMPTY_PRIMARY_TTL = _env_float("NOVA_TG_RELAY_CF_EMPTY_PRIMARY_TTL", 60.0, minimum=10.0)
CF_CONNECT_RACE_WIDTH = max(
    1,
    min(6, int(_env_float("NOVA_TG_RELAY_CF_RACE_WIDTH", 3.0, minimum=1.0))),
)
CF_RECENT_GOOD_TTL = _env_float("NOVA_TG_RELAY_CF_RECENT_GOOD_TTL", 900.0, minimum=30.0)
CF_FIRST_DCS = {
    int(item)
    for item in str(os.environ.get("NOVA_TG_RELAY_CF_FIRST_DCS", "1,2,3,4,5,203") or "").replace(";", ",").split(",")
    if item.strip().isdigit()
}
# Telegram's own web route goes first for media, and the Worker is the reserve.
#
# The order used to be the other way round for one reason: the Worker was the
# only thing that carried media at all. That is no longer what the measurements
# say. `kwsN-1.web.telegram.org` at the DC redirect IP, over warp-socks, carries
# media here with no Cloudflare in the path — Telegram bans WARP egress for raw
# MTProto (a native req_pq stays silent for 6 s on every DC) but not for WSS to
# web.telegram.org. Meanwhile the owned zone is a **finite daily budget**, and
# spending it first means spending it on sessions the free route would have
# served.
#
# Deliberately a plain boolean and not another `..._DCS` list: G16 is exactly
# the trap of a per-DC default that flips half the DCs when written out, and
# `NOVA_TG_RELAY_CF_FIRST_DCS` / `_MEDIA_DCS` are on the settings denylist for
# that reason. An explicit list still wins over this switch, so D11's opt-in
# ordering is untouched.
MEDIA_WEB_FIRST = _env_bool("NOVA_TG_RELAY_MEDIA_WEB_FIRST", True)
# How many owned-Worker requests this process has made, and when it last said
# so. The daily budget is spent by the whole install base, and nothing in the
# logs said what one machine contributes (`open-issues.md#o6`); this counts the
# handshakes that actually reached the Worker — a reply with an HTTP status,
# which is what Cloudflare bills — split by media, because that is the axis the
# routing decisions are made on.
CF_WORKER_USAGE_LOG_INTERVAL = _env_float("NOVA_TG_RELAY_CF_USAGE_LOG_INTERVAL", 3600.0, minimum=60.0)
_cf_worker_requests = {"media": 0, "plain": 0}
_cf_worker_usage_logged = [0.0]


CF_FIRST_MEDIA_DCS = {
    int(item)
    for item in str(os.environ.get("NOVA_TG_RELAY_CF_FIRST_MEDIA_DCS", "2,4,5,203") or "").replace(";", ",").split(",")
    if item.strip().isdigit()
}

_TG_EXACT_TARGETS: Dict[str, Tuple[int, bool]] = {
    # DC1
    "149.154.175.50": (1, False),
    "149.154.175.51": (1, False),
    "149.154.175.53": (1, False),
    "149.154.175.54": (1, False),
    "149.154.175.55": (1, False),
    "149.154.175.59": (1, False),
    "149.154.175.52": (1, True),
    # DC2
    "149.154.167.35": (2, False),
    "149.154.167.36": (2, False),
    "149.154.167.41": (2, False),
    "149.154.167.50": (2, False),
    "149.154.167.51": (2, False),
    "149.154.167.220": (2, False),
    "95.161.76.100": (2, False),
    "149.154.162.123": (2, True),
    "149.154.167.151": (2, True),
    "149.154.167.222": (2, True),
    "149.154.167.223": (2, True),
    "149.154.167.99": (2, True),
    # DC3
    "149.154.175.100": (3, False),
    "149.154.175.101": (3, False),
    "149.154.175.102": (3, True),
    # DC4
    "149.154.164.250": (4, True),
    "149.154.165.111": (4, True),
    "149.154.166.120": (4, True),
    "149.154.166.121": (4, True),
    "149.154.167.91": (4, False),
    "149.154.167.92": (4, False),
    "149.154.167.118": (4, True),
    # DC5
    "91.108.56.100": (5, False),
    "91.108.56.101": (5, False),
    "91.108.56.102": (5, True),
    "91.108.56.116": (5, False),
    "91.108.56.126": (5, False),
    "91.108.56.128": (5, True),
    "91.108.56.123": (5, True),
    "91.108.56.151": (5, True),
    "149.154.171.5": (5, False),
    # DC203
    "91.105.192.100": (203, False),
}

_TG_IPV4_RANGES = [
    (int(ipaddress.IPv4Address("5.28.195.0")), int(ipaddress.IPv4Address("5.28.195.255"))),
    (int(ipaddress.IPv4Address("185.76.151.0")), int(ipaddress.IPv4Address("185.76.151.255"))),
    (int(ipaddress.IPv4Address("149.154.160.0")), int(ipaddress.IPv4Address("149.154.175.255"))),
    (int(ipaddress.IPv4Address("91.105.192.0")), int(ipaddress.IPv4Address("91.105.193.255"))),
    (int(ipaddress.IPv4Address("91.108.0.0")), int(ipaddress.IPv4Address("91.108.255.255"))),
]

_TG_IPV6_PREFIXES = [
    ipaddress.ip_network("2001:067c:04e8:f000::/52"),
    ipaddress.ip_network("2001:0b28:f23d:f000::/52"),
    ipaddress.ip_network("2001:0b28:f23f:f000::/52"),
]

_TG_WS_REDIRECT_IPS: Dict[int, str] = {
    1: "149.154.174.100",
    2: "149.154.167.220",
    3: "149.154.174.100",
    4: "149.154.167.220",
    5: "149.154.170.100",
    203: "149.154.167.220",
}

_TG_TCP_FALLBACK_IPS: Dict[int, str] = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "149.154.171.5",
    203: "91.105.192.100",
}


@dataclass
class TransparentInitInfo:
    proto: int
    dc: int = 0
    is_media: bool = False


class TransparentMsgSplitter:
    def __init__(self, init_data: bytes, proto: int):
        if len(init_data) < 56:
            raise ValueError("init packet too short")
        self._stream = _new_ctr(init_data[8:40], init_data[40:56])
        self._stream.update(ZERO_64)
        self._proto = _proto_to_type(proto)
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk: bytes) -> List[bytes]:
        if not chunk:
            return []
        if self._disabled:
            return [bytes(chunk)]
        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(self._stream.update(chunk))
        parts: List[bytes] = []
        while True:
            packet_len = self._peek_packet_size()
            if packet_len < 0:
                return parts
            if packet_len == 0:
                tail = self.flush()
                if tail:
                    parts.extend(tail)
                self._disabled = True
                return parts
            if len(self._cipher_buf) < packet_len or len(self._plain_buf) < packet_len:
                return parts
            parts.append(bytes(self._cipher_buf[:packet_len]))
            del self._cipher_buf[:packet_len]
            del self._plain_buf[:packet_len]

    def flush(self) -> List[bytes]:
        if not self._cipher_buf:
            return []
        tail = bytes(self._cipher_buf)
        self._cipher_buf.clear()
        self._plain_buf.clear()
        return [tail]

    def _peek_packet_size(self) -> int:
        if not self._plain_buf:
            return -1
        if self._proto == 0:
            return self._peek_abridged_packet_size()
        if self._proto in (1, 2):
            return self._peek_intermediate_packet_size()
        return 0

    def _peek_abridged_packet_size(self) -> int:
        length_tag = self._plain_buf[0] & 0x7F
        header_size = 1
        if length_tag == 0x7F:
            if len(self._plain_buf) < 4:
                return -1
            header_size = 4
            payload_size = ((self._plain_buf[1]) | (self._plain_buf[2] << 8) | (self._plain_buf[3] << 16)) * 4
        else:
            payload_size = int(length_tag) * 4
        if payload_size <= 0:
            return 0
        frame_size = header_size + payload_size
        if len(self._plain_buf) < frame_size:
            return -1
        return frame_size

    def _peek_intermediate_packet_size(self) -> int:
        if len(self._plain_buf) < 4:
            return -1
        payload_size = struct.unpack("<I", self._plain_buf[:4])[0] & 0x7FFFFFFF
        if payload_size <= 0:
            return 0
        frame_size = 4 + payload_size
        if len(self._plain_buf) < frame_size:
            return -1
        return frame_size


def _new_ctr(key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    return cipher.encryptor()


def _valid_proto(proto: int) -> bool:
    return proto in (PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED_INTERMEDIATE)


# Telegram Desktop races an obfuscated TCP transport against a plain HTTP one.
# The HTTP transport opens port 80 and starts with a real request line, so its
# first 64 bytes never decrypt into a protocol tag. Such a socket cannot be
# carried over ``/apiws`` and must not be rewritten to the canonical MTProto
# port either — the DC answers HTTP only on the port the client picked.
_HTTP_TRANSPORT_PREFIXES = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ")


def _looks_like_http_request(data: bytes) -> bool:
    if not data:
        return False
    head = bytes(data[:8])
    return any(head.startswith(prefix) for prefix in _HTTP_TRANSPORT_PREFIXES)


# Не всё, что приходит на телеграмовский адрес, является MTProto. Обновлятор
# Telegram Desktop ходит на updates.tdesktop.com, который резолвится в
# 149.154.167.80 — внутрь диапазона DC2, — и открывает там обычный TLS.
# Такому сокету путь через /apiws закрыт: WSS несёт MTProto, а не произвольный
# поток. Раньше он просто отбрасывался, см. ветку unparsed-init.
#
# Байты: 0x16 — record type handshake, дальше legacy-версия записи. TLS 1.3
# по-прежнему пишет туда 0x0301 или 0x0303, так что двух вариантов достаточно.
_TLS_CLIENT_HELLO_PREFIXES = (b"\x16\x03\x01", b"\x16\x03\x03")


def _looks_like_tls_client_hello(data: bytes) -> bool:
    if not data:
        return False
    head = bytes(data[:3])
    return any(head.startswith(prefix) for prefix in _TLS_CLIENT_HELLO_PREFIXES)


# Заголовки CONNECT: конец — пустая строка. Ограничены и по размеру, и по
# общему времени: клиент, который никогда не пришлёт CRLFCRLF, не должен ни
# расти в памяти, ни занимать задачу дольше срока.
_HTTP_HEAD_END = b"\r\n\r\n"
_HTTP_HEAD_MAX = 8192
_HTTP_HEAD_TIMEOUT = 5.0

# Тот же смысл, что у _HTTP_HEAD_TIMEOUT, и намеренно рядом с ним: срок общий на
# всё рукопожатие SOCKS5. Раньше здесь стояли отдельные пятисекундные таймауты на
# каждом чтении — см. _socks_handshake.
_SOCKS_HANDSHAKE_TIMEOUT = 5.0

# Обрыв со стороны клиента. 64 — ERROR_NETNAME_DELETED, 10053/10054 — обрыв и
# сброс сокета, 995 — прерванная операция ввода-вывода. Всё это конец
# соединения, а не отказ релея.
_CLIENT_GONE_WINERRORS = frozenset({64, 995, 10053, 10054, 10058})


def _burst_tail(suppressed: int, interval: float) -> str:
    """Хвост строки-ограничителя: сколько таких же было подавлено."""
    return f" Ещё {suppressed} за последние {int(interval)} с." if suppressed else ""


def _split_http_authority(target: str) -> Tuple[Optional[str], Optional[int]]:
    """`host:port` из строки запроса CONNECT.

    IPv6 приходит в скобках (`[2001:db8::1]:443`), поэтому разделить по
    последнему двоеточию можно только после того, как скобки сняты.
    """
    text = str(target or "").strip()
    if not text:
        return None, None
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return None, None
        host = text[1:end]
        tail = text[end + 1:]
        if tail and not tail.startswith(":"):
            return None, None
        port_text = tail[1:]
    else:
        host, sep, port_text = text.rpartition(":")
        if not sep:
            host, port_text = text, ""
    host = host.strip()
    if not host:
        return None, None
    if not port_text:
        # CONNECT без порта — не по RFC 9110, но встречается у самодельных
        # клиентов. Для туннеля осмыслен ровно один порт.
        return host, 443
    try:
        port = int(port_text)
    except ValueError:
        return None, None
    if not 0 < port < 65536:
        return None, None
    return host, port


def _proto_label(proto: int) -> str:
    if proto == PROTO_ABRIDGED:
        return "abridged"
    if proto == PROTO_INTERMEDIATE:
        return "intermediate"
    if proto == PROTO_PADDED_INTERMEDIATE:
        return "padded-intermediate"
    return f"0x{proto:08x}"


def _proto_to_type(proto: int) -> int:
    if proto == PROTO_INTERMEDIATE:
        return 1
    if proto == PROTO_PADDED_INTERMEDIATE:
        return 2
    return 0


def parse_transparent_init_info(data: bytes) -> Optional[TransparentInitInfo]:
    if len(data) < 64:
        return None
    try:
        stream = _new_ctr(data[8:40], data[40:56])
    except Exception:
        return None
    keystream = stream.update(ZERO_64)
    plain = bytes(data[56 + i] ^ keystream[56 + i] for i in range(8))
    proto = struct.unpack("<I", plain[:4])[0]
    if not _valid_proto(proto):
        return None
    dc_idx = struct.unpack("<h", plain[4:6])[0]
    dc_abs = abs(int(dc_idx))
    info = TransparentInitInfo(proto=proto)
    if 1 <= dc_abs <= 203:
        info.dc = dc_abs
        info.is_media = dc_idx < 0
    return info


def _ws_domains(dc: int, is_media: bool) -> List[str]:
    if int(dc or 0) == 203:
        dc = 2
    if is_media:
        return [f"kws{dc}-1.web.telegram.org", f"kws{dc}.web.telegram.org"]
    return [f"kws{dc}.web.telegram.org"]


# Two different things travel over WSS: our own Worker and Telegram Web itself.
# They fail for unrelated reasons, so the first-byte circuit keeps a counter per
# kind. Before this split the key was (dc, is_media) alone, and two empty replies
# from the weaker route tripped the breaker for the healthy one on the same DC —
# visible in the log as a web.telegram.org pair at down=0 followed immediately by
# nova-app.eu being paused.
WSS_ROUTE_KINDS = ("cf", "web")


def _wss_route_kind(route_label) -> str:
    """"web" for kwsN[-1].web.telegram.org, "cf" for our Worker zones.

    Labels look like ``domain via egress`` or ``domain@ip via egress``; an
    unparsable one counts as "cf", which is the path that carries most traffic
    and the behaviour these counters had before the split.
    """
    try:
        domain = str(route_label or "").split(" via ", 1)[0].split("@", 1)[0].strip().lower()
    except Exception:
        return "cf"
    return "web" if domain.endswith("web.telegram.org") else "cf"


def _cf_ws_domains_for_bases(dc: int, bases: List[str], is_media: bool = False) -> List[str]:
    if int(dc or 0) == 203:
        dc = 2
    domains: List[str] = []
    for base in bases:
        domain_base = str(base or "").strip().lower()
        if not domain_base:
            continue
        # Allow kwsN-1 for media on custom CF domains as well
        if is_media:
            domains.append(f"kws{int(dc)}-1.{domain_base}")
        # The Worker picks Telegram's media upstream from the ``-1`` hostname, so
        # the regular sibling sends a media session to the non-media upstream:
        # the handshake succeeds, then nothing ever arrives.
        #
        # This used to exclude the sibling for nova-app.eu only, which made the
        # other zones actively harmful. Their ``-1`` names have no DNS record, so
        # a media race offered exactly one resolvable candidate per zone — the
        # broken sibling — and it won the race by answering first, every time.
        # Measured: kws2.pclead.co.uk answers 101 in ~350 ms and then delivers
        # down=0, while kws2-1.pclead.co.uk does not resolve at all.
        #
        # Dropping it costs zone diversity for media until those zones get their
        # ``-1`` records; carrying it cost media entirely.
        if not is_media:
            domains.append(f"kws{int(dc)}.{domain_base}")
    seen = set()
    return [item for item in domains if not (item in seen or seen.add(item))]


def _cf_ws_domains(dc: int, is_media: bool = False) -> List[str]:
    bases = get_cfproxy_domains("NOVA_TG_RELAY_CF_DOMAINS")
    return _cf_ws_domains_for_bases(int(dc), list(bases or []), bool(is_media))


def _has_custom_cfproxy_domain() -> bool:
    try:
        bases = get_cfproxy_domains("NOVA_TG_RELAY_CF_DOMAINS")
    except Exception:
        bases = []
    for base in bases:
        if str(base or "").strip().lower() == "nova-app.eu":
            return True
    return False


def _cf_ws_domain_bases(primary_only: bool = False) -> List[str]:
    if primary_only:
        return get_cfproxy_primary_domains("NOVA_TG_RELAY_CF_DOMAINS")
    return get_cfproxy_domains("NOVA_TG_RELAY_CF_DOMAINS")


def _cf_domain_base(domain: str) -> str:
    domain = str(domain or "").split(" via ", 1)[0].split("@", 1)[0].strip().lower()
    if not domain:
        return ""
    try:
        bases = sorted(
            {str(item or "").strip().lower() for item in _cf_ws_domain_bases(primary_only=False) if item},
            key=len,
            reverse=True,
        )
    except Exception:
        bases = []
    for base in bases:
        if domain == base or domain.endswith("." + base):
            return base
    return ""


# --- Cloudflare's daily Worker budget ---------------------------------------
#
# `429` with `error code: 1027` is Cloudflare saying the Worker behind this zone
# has spent its daily request allowance. It is not a per-connection hiccup and
# it is not the SNI's fault: every name in the zone answers the same way, from
# every egress, until the counter resets at 00:00 UTC.
#
# It used to be read, used to decide the egress was healthy, and then dropped.
# Nothing said so in the log — on a live session `nova_console.log` carried no
# line with either number — and the domain re-entered the race six seconds later
# (`CF_MEDIA_BAD_TTL`). For media that is fatal rather than merely wasteful:
# only the owned zone has `kwsN-1` records, the public zones answer NXDOMAIN for
# them, so the client spent the rest of the UTC day reconnecting every eight
# seconds and never loaded a single photo.
CF_QUOTA_STATUS = 429
# 0 keeps the honest answer — the time left in the UTC day. The override is for
# tests, and for the day Cloudflare charges the budget on some other clock.
CF_QUOTA_TTL_OVERRIDE = _env_float("NOVA_TG_RELAY_CF_QUOTA_TTL", 0.0, minimum=0.0)
CF_QUOTA_TTL_MIN = 300.0
_cf_zone_quota_until: Dict[str, float] = {}


def _seconds_to_utc_midnight(now: Optional[float] = None) -> float:
    """How long Cloudflare's daily counter has left to run."""
    now = float(now if now is not None else time.time())
    return max(60.0, 86400.0 - (now % 86400.0))


def _cf_quota_ttl() -> float:
    if CF_QUOTA_TTL_OVERRIDE > 0.0:
        return float(CF_QUOTA_TTL_OVERRIDE)
    return max(CF_QUOTA_TTL_MIN, _seconds_to_utc_midnight())


def _cf_note_quota_exhausted(exc: BaseException, domain: str) -> bool:
    """Step a whole zone aside until its Worker budget resets.

    Ours only. A 429 from one of the public Workers is somebody else's budget on
    somebody else's schedule; the per-domain bench already covers that without
    having to guess when it clears.
    """
    if not isinstance(exc, WsHandshakeError):
        return False
    if int(getattr(exc, "status_code", 0) or 0) != CF_QUOTA_STATUS:
        return False
    if not is_owned_cf_domain(domain):
        return False
    base = _cf_domain_base(domain) or str(domain or "").strip().lower()
    if not base:
        return False
    ttl = _cf_quota_ttl()
    now = time.monotonic()
    previous = float(_cf_zone_quota_until.get(base, 0.0) or 0.0)
    _cf_zone_quota_until[base] = max(previous, now + ttl)
    if previous <= now:
        _log_wss_egress(
            f"[TgRelay] Свой Cloudflare-воркер исчерпал суточную квоту (429/1027): зона {base} "
            f"отключена на {int(ttl // 3600)} ч {int((ttl % 3600) // 60)} мин, до сброса счётчика "
            f"в 00:00 UTC. Медиа и остальной WSS идут запасным маршрутом."
        )
    return True


def _cf_domain_is_media(domain: str) -> bool:
    """`kwsN-1.<zone>` is the media sibling; `kwsN.<zone>` is not."""
    head = str(domain or "").split(".", 1)[0].strip().lower()
    return head.startswith("kws") and head.endswith("-1")


def _cf_note_worker_request(domain: str) -> None:
    """One handshake reached our own Worker — the unit Cloudflare charges for."""
    if not is_owned_cf_domain(domain):
        return
    _cf_worker_requests["media" if _cf_domain_is_media(domain) else "plain"] += 1
    now = time.monotonic()
    last = float(_cf_worker_usage_logged[0] or 0.0)
    if last <= 0.0:
        # Start the clock at the first request rather than at import, so the
        # first line covers a real interval instead of however long the process
        # sat idle before anyone opened Telegram.
        _cf_worker_usage_logged[0] = now
        return
    if (now - last) < CF_WORKER_USAGE_LOG_INTERVAL:
        return
    _cf_worker_usage_logged[0] = now
    media = int(_cf_worker_requests["media"])
    plain = int(_cf_worker_requests["plain"])
    _log_wss_egress(
        f"[TgRelay] Запросов к своему воркеру с этой машины: {media + plain} "
        f"(медиа {media}, остальное {plain}) за {int((now - last) / 60)} мин."
    )


def _cf_zone_out_of_quota(domain: str) -> bool:
    base = _cf_domain_base(domain) or str(domain or "").strip().lower()
    if not base:
        return False
    return float(_cf_zone_quota_until.get(base, 0.0) or 0.0) > time.monotonic()


def _cf_clear_zone_quota(domain: str) -> None:
    """A handshake got through, so whatever the counter said, it says no more."""
    base = _cf_domain_base(domain) or str(domain or "").strip().lower()
    if not base:
        return
    if float(_cf_zone_quota_until.pop(base, 0.0) or 0.0) > time.monotonic():
        _log_wss_egress(
            f"[TgRelay] Квота Cloudflare-воркера восстановлена: зона {base} снова в работе."
        )


def _cf_owned_zone_available() -> bool:
    """Is at least one zone we control still answering?"""
    try:
        bases = get_cfproxy_primary_domains("NOVA_TG_RELAY_CF_DOMAINS")
    except Exception:
        bases = []
    now = time.monotonic()
    for base in bases:
        base = str(base or "").strip().lower()
        if base and float(_cf_zone_quota_until.get(base, 0.0) or 0.0) <= now:
            return True
    return False


def _cf_route_worth_reconnecting(is_media: bool = False) -> bool:
    """Is there still a WSS route worth closing the client for?

    Every "close instead of falling back to raw TCP" branch below rests on one
    bet: the ISP throttles Telegram's own protocol, so a reconnect over WSS
    beats a fallback. `_has_custom_cfproxy_domain()` was standing in for that
    bet and it is a constant — config.py always puts the owned zone in the list
    — so the bet was never re-examined, not even once the Worker had stopped
    answering at all.

    Media is where that goes wrong. Only the owned zone carries the `kwsN-1`
    records a media session needs, so when its budget is gone there is nothing
    left to reconnect to and the loop runs until the quota resets. Plain TCP is
    a poor path, but "poor" beats "none": for the rest of the traffic the public
    zones are still there, which is why the answer differs by `is_media`.
    """
    if not _has_custom_cfproxy_domain():
        return False
    if not bool(is_media):
        return True
    return _cf_owned_zone_available()


def _canonical_dc_ips(dc: int) -> List[str]:
    mapping = {
        1: ["149.154.175.50"],
        2: ["149.154.167.220", "149.154.167.50", "149.154.167.41", "149.154.167.51"],
        3: ["149.154.175.100"],
        4: ["149.154.167.220", "149.154.167.91", "5.28.195.2"],
        5: ["149.154.171.5", "91.108.56.100", "91.108.56.101", "91.108.56.116", "91.108.56.126", "91.108.56.102", "91.108.56.128", "91.108.56.151", "173.239.243.185", "91.108.56.123"],
        203: ["91.105.192.100"],
    }
    return list(mapping.get(int(dc), []))


def _domain_dc(domain: str) -> int:
    domain = str(domain or "").strip().lower()
    if domain.startswith("pluto") or domain.startswith("kws1"):
        return 1
    if domain.startswith("venus") or domain.startswith("kws2"):
        return 2
    if domain.startswith("aurora") or domain.startswith("kws3"):
        return 3
    if domain.startswith("vesta") or domain.startswith("kws4"):
        return 4
    if domain.startswith("flora") or domain.startswith("kws5"):
        return 5
    if domain.startswith("kws203"):
        return 203
    return 0


def _target_dc_hint(target_ip: str, is_media: bool = False) -> int:
    target_ip = str(target_ip or "").strip().lower()
    if not target_ip:
        return 0
    if target_ip in _TG_EXACT_TARGETS:
        return _TG_EXACT_TARGETS[target_ip][0]
    if target_ip == "173.239.243.185":
        return 5
    if target_ip == "5.28.195.2":
        return 4
    if target_ip == "149.154.167.220":
        return 4 if is_media else 2
    if target_ip in {"149.154.167.92", "149.154.167.255"}:
        return 4
    if target_ip in {"149.154.167.50", "149.154.167.41"}:
        return 2
    try:
        addr = ipaddress.ip_address(target_ip)
    except ValueError:
        return 0
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in ipaddress.ip_network("91.108.56.0/22") or addr in ipaddress.ip_network("149.154.171.0/24"):
            return 5
        if addr == ipaddress.ip_address("149.154.167.50") or addr == ipaddress.ip_address("149.154.167.41"):
            return 2
        if addr == ipaddress.ip_address("149.154.167.91") or addr == ipaddress.ip_address("149.154.167.255"):
            return 4
        if addr == ipaddress.ip_address("149.154.167.51"):
            return 2
        if addr in ipaddress.ip_network("149.154.167.0/24"):
            return 2
        if addr in ipaddress.ip_network("149.154.175.48/28"):
            return 1
        if addr == ipaddress.ip_address("149.154.175.50"):
            return 1
        if addr == ipaddress.ip_address("149.154.175.100"):
            return 3
        if addr == ipaddress.ip_address("91.105.192.100"):
            return 203
    else:
        if addr in ipaddress.ip_network("2001:067c:04e8:f002::/64"):
            return 2
        if addr in ipaddress.ip_network("2001:067c:04e8:f004::/64"):
            return 4
        if addr in ipaddress.ip_network("2001:0b28:f23f:f005::/64"):
            return 5
    return 0


def _likely_media_target(target_ip: str, target_port: int, dc_hint: int) -> bool:
    info = _TG_EXACT_TARGETS.get(str(target_ip or "").strip().lower())
    if info is not None:
        return bool(info[1])
    if str(target_ip or "").strip().lower() in {"5.28.195.2", "149.154.167.91", "149.154.167.92", "149.154.167.99", "149.154.167.255"}:
        return True
    if 7300 <= int(target_port) <= 7310:
        return False
    return int(dc_hint or 0) == 4 and int(target_port or 0) in (80, 443)


def _preferred_ws_target(target_ip: str, dc_hint: int, is_media: bool) -> str:
    target_ip = str(target_ip or "").strip()
    if int(dc_hint or 0) in (2, 4):
        if dc_hint == 2:
            return "149.154.167.220"
        if dc_hint == 4 and (is_media or target_ip in {"5.28.195.2", "149.154.167.91", "149.154.167.255"}):
            return "149.154.167.220"
    return target_ip


def _is_telegram_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(host or "").strip())
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        value = int(addr)
        for lo, hi in _TG_IPV4_RANGES:
            if lo <= value <= hi:
                return True
        return False
    return any(addr in prefix for prefix in _TG_IPV6_PREFIXES)


def _is_telegram_domain(host: str) -> bool:
    host = str(host or "").strip().lower()
    return (
        host.endswith(".telegram.org")
        or host in {"telegram.org", "t.me", "telegra.ph", "telegram.me", "telesco.pe", "tdesktop.com"}
        or host.endswith(".tdesktop.com")
    )


def _wss_candidate(target_host: str, target_ip: str, target_port: int) -> bool:
    if int(target_port or 0) not in TG_TCP_PORTS:
        return False
    return _is_telegram_ip(target_ip) or _is_telegram_domain(target_host)


def _cfproxy_upstream_attempts() -> List[Dict[str, object]]:
    try:
        attempts = list(get_upstream_attempts() or [])
    except Exception:
        attempts = []
    allow_direct = bool(
        attempts
        and isinstance(attempts[0], dict)
        and str(attempts[0].get("kind") or "").strip().lower() == "direct"
    )
    selected_attempts = []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        rendered = dict(attempt)
        if str(rendered.get("kind") or "").strip().lower() == "direct":
            if not allow_direct:
                continue
            rendered.setdefault("timeout", 1.2)
        selected_attempts.append(rendered)
    if selected_attempts:
        return selected_attempts
    if allow_direct:
        return [{"kind": "direct", "label": "direct", "timeout": 1.2}]
    return []


def _telegram_upstream_attempts(base_attempts=None) -> List[Dict[str, object]]:
    try:
        attempts = list(base_attempts if base_attempts is not None else (get_upstream_attempts() or []))
    except Exception:
        attempts = []
    allow_direct = bool(
        attempts
        and isinstance(attempts[0], dict)
        and str(attempts[0].get("kind") or "").strip().lower() == "direct"
    )
    rendered: List[Dict[str, object]] = []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        if str(attempt.get("kind") or "").strip().lower() == "direct" and not allow_direct:
            continue
        rendered.append(dict(attempt))
    return rendered


async def _resolve_ip(host: str) -> str:
    host = str(host or "").strip()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    def _resolve():
        try:
            # Prefer IPv4 for Telegram cold start on the target networks: IPv6/AAAA
            # answers can exist in DNS but still be slower or degraded on the ISP path.
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            for family, _, _, _, sockaddr in infos:
                if family == socket.AF_INET:
                    return sockaddr[0]
            for _, _, _, _, sockaddr in infos:
                if sockaddr:
                    return sockaddr[0]
        except Exception:
            return host
        return host

    return await asyncio.to_thread(_resolve)


# --- Egress health for the WSS handshake -----------------------------------
#
# Reachability of an egress is not a property of the moment it is chosen. WARP
# in particular keeps answering TCP and TLS long after it has stopped carrying
# WebSocket upgrades, and there is no way to tell from the connect alone. These
# few functions remember which egress last failed a handshake so the next call
# starts somewhere else, and let it back to the front as soon as it works again
# or after the penalty expires.
WSS_EGRESS_BAD_TTL = _env_float("NOVA_TG_RELAY_WSS_EGRESS_BAD_TTL", 90.0, minimum=10.0)
WSS_MIN_ATTEMPT_TIMEOUT = _env_float("NOVA_TG_RELAY_WSS_MIN_ATTEMPT_TIMEOUT", 2.0, minimum=0.5)
_wss_egress_bad: Dict[str, float] = {}
_wss_egress_log: Dict[str, float] = {}
_wss_egress_log_func = None


def set_wss_egress_logger(log_func) -> None:
    global _wss_egress_log_func
    _wss_egress_log_func = log_func if callable(log_func) else None


def _wss_egress_label(attempt) -> str:
    if not isinstance(attempt, dict):
        return "unknown"
    return str(attempt.get("label") or attempt.get("kind") or "unknown").strip() or "unknown"


def _mark_wss_egress_bad(label: str, domain: str = "") -> None:
    label = str(label or "").strip()
    if not label:
        return
    first = label not in _wss_egress_bad or _wss_egress_bad[label] <= time.monotonic()
    _wss_egress_bad[label] = time.monotonic() + WSS_EGRESS_BAD_TTL
    if first:
        # Wording matters: the console tags any line containing "fail" as an
        # alert and pins it in the window. Switching egress is routine
        # self-healing, so it belongs in the log file, not in a red banner.
        _log_wss_egress(f"[TgRelay] WSS egress {label} stopped answering the handshake for {domain or 'CF'}; moved to the back of the queue for {int(WSS_EGRESS_BAD_TTL)}s.")


def _mark_wss_egress_good(label: str) -> None:
    label = str(label or "").strip()
    if label and _wss_egress_bad.pop(label, None) is not None:
        _log_wss_egress(f"[TgRelay] WSS egress {label} is healthy again.")


def _log_wss_egress(message: str) -> None:
    # The NovaWFP proxy imports this module without a console of its own, so
    # fall back to the module logger instead of dropping the line.
    func = _wss_egress_log_func if callable(_wss_egress_log_func) else log.info
    now = time.monotonic()
    last = float(_wss_egress_log.get(message, 0.0) or 0.0)
    if (now - last) < FALLBACK_LOG_INTERVAL:
        return
    _wss_egress_log[message] = now
    with contextlib.suppress(Exception):
        func(message)


def _log_wss_egress_switch(label: str, domain: str) -> None:
    _log_wss_egress(f"[TgRelay] WSS handshake for {domain} went through {label} instead of the preferred egress.")


def _order_wss_attempts(attempts) -> List[Dict[str, object]]:
    """Caller's order, with recently failed egresses moved to the back."""
    try:
        source = list(attempts) if attempts else list(_cfproxy_upstream_attempts())
    except Exception:
        source = []
    now = time.monotonic()
    healthy: List[Dict[str, object]] = []
    penalised: List[Dict[str, object]] = []
    for attempt in source:
        if not isinstance(attempt, dict):
            continue
        if float(_wss_egress_bad.get(_wss_egress_label(attempt), 0.0) or 0.0) > now:
            penalised.append(dict(attempt))
        else:
            healthy.append(dict(attempt))
    return healthy + penalised


# --- Health of the native MTProto path -------------------------------------
#
# WSS exists because the провайдер kills direct MTProto. That is true for a
# direct socket and for WARP, but not for every egress: an HTTP proxy can carry
# Telegram's own protocol untouched, and then the WebSocket detour through
# Cloudflare only adds two network legs. Measured on the target network, the
# same req_pq/resPQ exchange takes 0.64s natively through Opera against 1.25s
# over WSS — and since uploads acknowledge every chunk, that ratio is what the
# user feels when sending a photo.
#
# Which of the two works is a property of the network, not something to assume,
# so it is learned: a tunnel that receives bytes back from Telegram marks the
# pair (DC, egress) as good, one that stays silent marks it bad.
NATIVE_GOOD_TTL = _env_float("NOVA_TG_RELAY_NATIVE_GOOD_TTL", 600.0, minimum=30.0)
NATIVE_BAD_TTL = _env_float("NOVA_TG_RELAY_NATIVE_BAD_TTL", 120.0, minimum=15.0)
NATIVE_FIRST_ENABLED = _env_bool("NOVA_TG_RELAY_NATIVE_FIRST", True)
NATIVE_PROBE_INTERVAL = _env_float("NOVA_TG_RELAY_NATIVE_PROBE_INTERVAL", 45.0, minimum=10.0)
NATIVE_PROBE_RETRY = _env_float("NOVA_TG_RELAY_NATIVE_PROBE_RETRY", 6.0, minimum=2.0)
# Separate switch from NATIVE_FIRST_ENABLED: media is where the bytes are, so it
# is the part worth being able to roll back on its own.
NATIVE_MEDIA_ENABLED = _env_bool("NOVA_TG_RELAY_NATIVE_MEDIA", True)
_native_health: Dict[Tuple[int, str], Tuple[bool, float]] = {}


def _native_record(dc: int, label: str, ok: bool) -> None:
    label = str(label or "").strip().lower()
    if not label or int(dc or 0) <= 0:
        return
    ttl = NATIVE_GOOD_TTL if ok else NATIVE_BAD_TTL
    previous = _native_health.get((int(dc), label))
    _native_health[(int(dc), label)] = (bool(ok), time.monotonic() + ttl)
    if previous is None or previous[0] != bool(ok):
        state = "carries Telegram directly" if ok else "stays silent"
        _log_wss_egress(f"[TgRelay] Native MTProto over {label} {state} for DC{int(dc)}.")


def _native_state(dc: int, label: str):
    entry = _native_health.get((int(dc or 0), str(label or "").strip().lower()))
    if not entry or entry[1] <= time.monotonic():
        return None
    return entry[0]


def _should_retry_after_stall(bootstrap_canonical: bool, initial: bytes, route_label: str, dc_hint: int) -> bool:
    """Менять ли егресс, который принял соединение и не прислал ни байта.

    Раньше условие требовало DC строго из (1, 3, 5), и ROADMAP записал механизм
    как бесполезный: европейские DC2/DC4 в него не попадали. Измерение
    2026-08-13 показало цену — до `updates.tdesktop.com` (149.154.167.80, это
    DC2) WARP не дотягивается, рукопожатие TLS истекает за 12.1 с, а Opera
    отвечает за 0.5 с. SOCKS5 к WARP при этом проходит, поэтому отказ по
    коннекту такое не ловит: проблема живёт уровнем выше.

    Вместо номера DC — вопрос по существу: доказан ли этот егресс для этого DC.
    Доказанный не трогаем, даже медленный: отбирать у рабочего канала 0.75 с
    нельзя. Недоказанный меняем — тот же сигнал уже управляет коротким поводком
    в `_bridge_streams`, так что это не новая агрессивность, а доведение её до
    повторной попытки вместо молчаливой сдачи.

    `initial` обязателен: без него нечего переиграть на новом соединении.
    """
    if not FIRST_BYTE_STALL_RETRY or bootstrap_canonical or not initial:
        return False
    if str(route_label or "").strip().lower() != "warp-socks":
        return False
    return _native_state(dc_hint, route_label) is not True


def _native_candidate_labels() -> List[str]:
    try:
        return [_wss_egress_label(a) for a in (_telegram_upstream_attempts() or [])]
    except Exception:
        return []


def _native_preferred(dc: int) -> bool:
    """True when some egress is proven to carry native MTProto to this DC."""
    if not NATIVE_FIRST_ENABLED:
        return False
    return any(_native_state(dc, label) is True for label in _native_candidate_labels())


def _native_worth_trying(dc: int) -> bool:
    """True while at least one egress is either proven or still untested."""
    if not NATIVE_FIRST_ENABLED:
        return False
    labels = _native_candidate_labels()
    if not labels:
        return False
    return any(_native_state(dc, label) is not False for label in labels)


def _build_native_probe(dc: int) -> bytes:
    """obfuscated2 init plus req_pq_multi, framed for the abridged transport.

    Telegram answers this with resPQ before any authorisation, so it is the
    cheapest honest question one can ask an egress: not "does TCP open" but
    "does this data centre talk back through you".
    """
    while True:
        buf = bytearray(os.urandom(64))
        if buf[0] == 0xEF:
            continue
        if struct.unpack("<I", bytes(buf[:4]))[0] in _NATIVE_PROBE_BAD_FIRST:
            continue
        if struct.unpack("<I", bytes(buf[4:8]))[0] == 0:
            continue
        break
    buf[56:60] = struct.pack("<I", PROTO_ABRIDGED)
    buf[60:62] = struct.pack("<h", int(dc))
    stream = _new_ctr(bytes(buf[8:40]), bytes(buf[40:56]))
    wire = stream.update(bytes(buf))
    init = bytes(buf[:56]) + wire[56:64]

    msg_id = (int(time.time()) << 32) & 0x7FFFFFFFFFFFFFFF
    body = struct.pack("<I", 0xBE7E8EF1) + os.urandom(16)
    payload = struct.pack("<q", 0) + struct.pack("<q", msg_id) + struct.pack("<i", len(body)) + body
    framed = bytes([len(payload) // 4]) + payload
    return init + stream.update(framed)


_NATIVE_PROBE_BAD_FIRST = {0x44414548, 0x54534F50, 0x20544547, 0x4954504F, 0xDDDDDDDD, 0xEEEEEEEE, 0x02010316}


def _order_native_attempts(attempts, dc: int):
    """Proven egresses first, untested next, recently silent ones last.

    Without this the tunnel would keep picking WARP — which answers TCP but
    never delivers a byte from Telegram — and would then record the native path
    as dead for the whole DC, hiding the egress that actually works.
    """
    if not attempts or int(dc or 0) <= 0:
        return attempts
    good, unknown, bad = [], [], []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        state = _native_state(dc, _wss_egress_label(attempt))
        (good if state is True else bad if state is False else unknown).append(attempt)
    return good + unknown + bad


# --- Keeping the route name out of the clear --------------------------------
#
# The route has to be named somewhere in the request, and today it is named in
# the SNI: `kws2.nova-app.eu` travels in plaintext on every tunnel Nova opens.
# A single rule over `^kws\d+\.` retires the entire domain pool at once, and no
# amount of work on the TLS fingerprint behind it changes that — the name is
# read before the fingerprint matters.
#
# Cloudflare routes Workers on the Host header, which is inside TLS, and it
# tolerates the SNI disagreeing with it as long as both names belong to the
# same zone. Measured against the live Worker: apex, `www.` and `cdn.` in the
# SNI all reach the same handler as the literal name, while a name from another
# zone is answered with 403. So the route can keep travelling in the Host
# header and the SNI can be an unremarkable subdomain of the same zone.
#
# Nothing else moves. The domain string stays the health-cache key, the log
# label, and the value the handshake signature is bound to, so no state
# migrates and the Worker needs no change at all.
NEUTRAL_SNI_ENABLED = _env_bool("NOVA_TG_RELAY_NEUTRAL_SNI", True)
# One candidate, and it is `www.` — not a shortlist to pick from.
#
# The list used to be `[base, f"www.{base}"]` and `random.choice` took the apex
# about half the time. Re-measured against the live Worker with the route in the
# `Host` header:
#
#     SNI kws5-1.nova-app.eu -> 429     (edge matched the route)
#     SNI www.nova-app.eu    -> 429     (edge matched the route)
#     SNI nova-app.eu        -> 403     (edge refused)
#
# 429 is the Worker's exhausted daily quota, i.e. the request got as far as our
# route; 403 is the edge declining before that. So the apex does not work here,
# and every second start was retiring the zone's substituted name for fifteen
# minutes — which read in the logs like a working automatic rollback rather than
# like a defect.
#
# There is also no wildcard to fall back on: `cdn.`, `static.` and `assets.` do
# not resolve at all. `www.` has its own record and sits inside the universal
# certificate, so verification can still be switched on later without revisiting
# this. ADR 0004 said otherwise on both counts and has been corrected.
def _cf_neutral_candidates(base: str) -> List[str]:
    return [f"www.{base}"]
# One name per zone for the life of the process, rather than a fresh one per
# connection. A client that talks to a single content host looks like every
# other client; one that sprays five names per minute is its own signature.
_cf_sni_choice: Dict[str, str] = {}
_cf_sni_literal_until: Dict[str, float] = {}
CF_NEUTRAL_SNI_BAD_TTL = _env_float("NOVA_TG_RELAY_NEUTRAL_SNI_BAD_TTL", 900.0, minimum=60.0)


def _cf_neutral_sni(domain: str) -> str:
    """The name to offer in the SNI when connecting to `domain`.

    Returns `domain` unchanged whenever substituting would be a guess: for
    Telegram's own `kwsN.web.telegram.org`, whose edge really does route on the
    SNI, and for the third-party Workers in the public pool, where the same
    measurement has not been made and breaking somebody else's infrastructure
    on a hunch is worse than a legible name.
    """
    domain = str(domain or "").strip().lower()
    if not NEUTRAL_SNI_ENABLED or not domain:
        return domain
    if not is_owned_cf_domain(domain):
        return domain
    base = _cf_domain_base(domain) or ""
    if not base:
        return domain
    until = float(_cf_sni_literal_until.get(base, 0.0) or 0.0)
    if until > time.monotonic():
        return domain
    choice = _cf_sni_choice.get(base)
    if not choice:
        choice = random.choice(_cf_neutral_candidates(base))
        _cf_sni_choice[base] = choice
    return choice


def _cf_note_neutral_sni_bad(domain: str) -> None:
    """Fall back to the literal name for this zone for a while.

    Reached only when a handshake carrying a substituted SNI was ignored or
    refused. The substitution is an optimisation, not a requirement, so the
    first sign that a network dislikes it is enough to stop paying for it.
    """
    base = _cf_domain_base(str(domain or "").strip().lower()) or ""
    if not base:
        return
    if float(_cf_sni_literal_until.get(base, 0.0) or 0.0) <= time.monotonic():
        _log_wss_egress(
            f"[TgRelay] Neutral SNI was not accepted for {base}; using the literal route name "
            f"for {int(CF_NEUTRAL_SNI_BAD_TTL)}s."
        )
    _cf_sni_literal_until[base] = time.monotonic() + CF_NEUTRAL_SNI_BAD_TTL


def _note_sni_verdict(exc: BaseException, domain: str, signature: str) -> None:
    """Retire the substituted SNI if the failure could plausibly be its fault.

    Only two shapes qualify. A handshake that went unanswered is the one window
    where the name we offered is still a suspect; `421 Misdirected Request` and
    `403` are what a CDN says when it does not accept the name it was given for
    the host that was asked for. Everything else happened either before the
    name was on the wire or after it had already been accepted, and rolling
    back on those would give up a real gain over unrelated noise.
    """
    used = str(getattr(exc, "nova_sni", "") or "")
    if not used or used == str(domain or "").strip().lower():
        return
    if phase.wants_tls_profile_change(signature) or signature == phase.TLS_CERTIFICATE_MISMATCH:
        _cf_note_neutral_sni_bad(domain)
        return
    if isinstance(exc, WsHandshakeError) and int(getattr(exc, "status_code", 0) or 0) in (403, 421):
        _cf_note_neutral_sni_bad(domain)


def _attempt_signature(exc: BaseException) -> str:
    """Name the gate a failed WSS attempt died at.

    The evidence was recorded on the way up by ``transport.open_tls_stream``
    and ``_connect_websocket_once``; this only reads it back and applies the
    shared decision table. When nothing was recorded the default is the gate
    that used to be assumed for everything, so an untagged path behaves exactly
    as it did before rather than silently acquiring a new verdict.
    """
    reached = phase.reached_from_exception(exc, phase.Reached.RESOLVED)
    if isinstance(exc, WsHandshakeError) and int(getattr(exc, "status_code", 0) or 0) > 0:
        ended = phase.Ended.HTTP_STATUS
        # An HTTP status is itself proof the handshake finished — nobody sends
        # one before TLS is up. Trusting the annotation over that would let a
        # missing tag turn a definitive refusal into a blackholed route, and
        # demote an egress that had just carried a full request and reply.
        reached = max(reached, int(phase.Reached.HANDSHAKE_DONE))
    else:
        ended = phase.ended_from_exception(exc)
    return phase.classify(
        reached,
        ended,
        since_hello_ms=getattr(exc, "nova_since_hello_ms", None),
        rtt_ms=None,
    )


async def _connect_websocket_target(host: str, domain: str, timeout: float = 8.0, attempts=None):
    """Open a Telegram WSS tunnel, moving to another egress if one stops working.

    An egress can accept the TCP connection and complete TLS while silently
    dropping the WebSocket upgrade — that is exactly how a degraded WARP tunnel
    behaves. Selecting the egress inside ``open_tls_stream`` cannot notice this,
    because by then the connection already looks healthy. So the handshake is
    driven here, one egress at a time, and a failure that leaves us without an
    HTTP status is charged to the egress rather than to the domain.
    """
    ordered = _order_wss_attempts(attempts)
    if len(ordered) < 2:
        try:
            result = await _connect_websocket_once(host, domain, timeout, attempts, ordered[0] if ordered else None)
        except BaseException as exc:
            _note_sni_verdict(exc, domain, _attempt_signature(exc))
            _cf_note_quota_exhausted(exc, domain)
            raise
        _cf_clear_zone_quota(domain)
        return result

    # Split the caller's budget so probing a dead egress cannot stretch the
    # whole attempt past what the CF race is willing to wait for.
    attempt_timeout = max(WSS_MIN_ATTEMPT_TIMEOUT, float(timeout) / len(ordered))
    last_error: Optional[BaseException] = None
    for index, attempt in enumerate(ordered):
        label = str(attempt.get("label") or attempt.get("kind") or "unknown").strip() or "unknown"
        try:
            result = await _connect_websocket_once(host, domain, attempt_timeout, [attempt], attempt)
            _mark_wss_egress_good(label)
            _cf_clear_zone_quota(domain)
            if index:
                _log_wss_egress_switch(label, domain)
            return result
        except WsHandshakeError as exc:
            if int(getattr(exc, "status_code", 0) or 0) > 0:
                # The egress delivered a real HTTP status: it works, the domain
                # refused us. Retrying elsewhere would only repeat the refusal.
                _mark_wss_egress_good(label)
                signature = _attempt_signature(exc)
                exc.nova_signature = signature
                _note_sni_verdict(exc, domain, signature)
                _cf_note_quota_exhausted(exc, domain)
                raise
            last_error = exc
        except (asyncio.TimeoutError, OSError) as exc:
            last_error = exc

        # Which layer just failed decides which layer gets charged. Collapsing
        # all of these into "this egress is bad" is how a resolver hiccup or a
        # silent Worker takes down a tunnel that was carrying traffic fine.
        signature = _attempt_signature(last_error)
        with contextlib.suppress(Exception):
            last_error.nova_signature = signature
        _note_sni_verdict(last_error, domain, signature)
        if phase.is_not_our_fault(signature):
            # Nothing here is evidence about this egress, and the next one in
            # the list will fail identically, so there is also nothing to learn
            # from marking it and moving on.
            continue
        if phase.reached_from_exception(last_error, phase.Reached.RESOLVED) >= phase.Reached.HANDSHAKE_DONE:
            # TLS completed end to end through this egress and only then did
            # the far side go quiet. The egress carried a whole handshake; it
            # is the last thing that deserves the blame.
            _mark_wss_egress_good(label)
            continue
        _mark_wss_egress_bad(label, domain)
    raise last_error if last_error is not None else WsHandshakeError(0, "no upstream attempts available")


# An upgrade reply is a few hundred bytes; Cloudflare's is under one KiB. The
# cap is here for the same reason the frame-length cap is in raw_websocket: the
# size of the allocation is chosen by the far side, not by this one.
MAX_UPGRADE_HEADER_LINES = 128


async def _read_upgrade_head(reader, timeout: float):
    """Read the reply header block under **one** deadline for the whole block.

    A `wait_for` around a single `readline` bounds one read, not the exchange: a
    peer that sends one header just inside the budget holds the attempt open for
    as long as it likes. That is G22 again, after the SOCKS handshake, and it was
    reproduced on this very loop before it was changed: 4.86 s against a 0.5 s
    budget, and it stopped only because the harness ran out of lines
    (`temp/upgrade_head_dribble.py`).

    Extracted from `_connect_websocket_once` so the budget can be tested without
    a TLS stack behind it.
    """
    deadline = time.monotonic() + float(timeout)
    response_lines = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError("upgrade reply did not complete within the budget")
        line = await asyncio.wait_for(reader.readline(), timeout=remaining)
        if line in (b"\r\n", b"\n", b""):
            break
        if len(response_lines) >= MAX_UPGRADE_HEADER_LINES:
            raise WsHandshakeError(0, "upgrade reply header block too long")
        response_lines.append(line.decode("utf-8", errors="replace").strip())
    return response_lines


async def _connect_websocket_once(host: str, domain: str, timeout: float, attempts, attempt=None):
    # Timed from here so the reset-timing rule compares against a round trip
    # rather than against DNS plus TCP setup, which would swamp it.
    started = time.monotonic()
    # The route keeps travelling in the Host header below; only the name
    # offered in the clear changes.
    sni = _cf_neutral_sni(domain)
    try:
        reader, writer, upstream_label = await open_tls_stream(
            host,
            443,
            server_hostname=sni,
            timeout=timeout,
            attempts=attempts,
        )
    except BaseException as exc:
        # open_tls_stream already recorded which gate it died at; all that is
        # missing is how long it took to get there, and which name was on the
        # wire when it happened.
        if not hasattr(exc, "nova_since_hello_ms"):
            exc.nova_since_hello_ms = int((time.monotonic() - started) * 1000)
        if not hasattr(exc, "nova_sni"):
            exc.nova_sni = sni
        raise
    set_sock_opts(writer.transport, proxy_config.buffer_size)
    # RFC 6455 wants sixteen random bytes here, and browsers send exactly that.
    # This used to pack a millisecond clock and a performance counter, which is
    # both guessable and a pattern that repeats across every connection Nova
    # opens — the opposite of what the field is for.
    ws_key = base64.b64encode(os.urandom(16)).decode()
    req = persona.upgrade_request(
        "/apiws",
        domain,
        ws_key,
        cf_ws_subprotocol_header(domain),
        offer_deflate=offers_deflate(domain),
    )
    # TLS is up. Everything from here on is past the point where the shape of
    # our ClientHello could still be the suspect — the far side read it and
    # agreed to speak.
    try:
        writer.write(req)
        await writer.drain()

        response_lines = await _read_upgrade_head(reader, timeout)
        if not response_lines:
            writer.close()
            await writer.wait_closed()
            raise WsHandshakeError(0, "empty response")
        status_code, first_line = persona.status_of(response_lines)
        # Counted here and nowhere earlier: an attempt that died at TCP or TLS
        # never reached the Worker and is not billed. A reply — 101 or refusal —
        # means it ran.
        _cf_note_worker_request(domain)
        headers = persona.parse_headers(response_lines[1:])
        if status_code != 101:
            writer.close()
            await writer.wait_closed()
            raise WsHandshakeError(status_code, first_line, headers, location=headers.get("location"))
        # A 101 is not enough on its own: an endpoint that accepted the
        # compression offer sends deflated frames from here on, and nothing
        # downstream can inflate them. Withdraw the offer so the retry goes out
        # without it, and fail this attempt rather than carry bytes we cannot
        # read into the MTProto path.
        refusal = persona.rejects_us(headers)
        if refusal:
            note_deflate_unusable(domain)
            writer.close()
            await writer.wait_closed()
            raise WsHandshakeError(0, refusal, headers)
    except BaseException as exc:
        if not hasattr(exc, "nova_reached"):
            exc.nova_reached = int(phase.Reached.HANDSHAKE_DONE)
        if not hasattr(exc, "nova_since_hello_ms"):
            exc.nova_since_hello_ms = int((time.monotonic() - started) * 1000)
        if not hasattr(exc, "nova_sni"):
            exc.nova_sni = sni
        raise
    return RawWebSocket(reader, writer), upstream_label


class _TelegramWsPool:
    def __init__(self):
        self._idle: Dict[Tuple[int, bool], deque] = {}
        self._refilling = set()

    async def get(self, dc: int, is_media: bool, target_ip: str, domains: List[str]):
        key = (int(dc), bool(is_media))
        now = time.monotonic()
        bucket = self._idle.setdefault(key, deque())
        while bucket:
            ws, created, route_label = bucket.popleft()
            age = now - created
            try:
                transport_closing = bool(ws.writer.transport.is_closing())
            except Exception:
                transport_closing = True
            if age > WS_POOL_MAX_AGE or getattr(ws, "_closed", False) or transport_closing:
                with contextlib.suppress(Exception):
                    await ws.close()
                continue
            self._schedule_refill(key, target_ip, domains)
            return ws, route_label
        self._schedule_refill(key, target_ip, domains)
        return None, ""

    def _schedule_refill(self, key, target_ip: str, domains: List[str]):
        if key in self._refilling:
            return
        if int(getattr(proxy_config, "pool_size", 0) or 0) <= 0:
            return
        self._refilling.add(key)
        asyncio.create_task(self._refill(key, target_ip, domains))

    async def _refill(self, key, target_ip: str, domains: List[str]):
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = max(0, int(getattr(proxy_config, "pool_size", 4) or 4) - len(bucket))
            if needed <= 0:
                return
            ws_attempts = _telegram_upstream_attempts()
            for _ in range(needed):
                ws = None
                route_label = ""
                for domain in domains:
                    try:
                        ws, upstream_label = await _connect_websocket_target(
                            target_ip,
                            domain,
                            timeout=6.0,
                            attempts=ws_attempts,
                        )
                        route_label = f"{domain}@{target_ip} via {upstream_label}"
                        break
                    except WsHandshakeError as exc:
                        if exc.is_redirect:
                            continue
                        break
                    except Exception:
                        break
                if ws is not None:
                    bucket.append((ws, time.monotonic(), route_label))
        finally:
            self._refilling.discard(key)

    def warmup(self):
        for dc, target_ip in _TG_WS_REDIRECT_IPS.items():
            for is_media in (False, True):
                self._schedule_refill((int(dc), bool(is_media)), target_ip, _ws_domains(dc, is_media))


_WS_POOL = _TelegramWsPool()


async def _traffic_stats_loop(counters: Dict[str, int], started: float, label: str, log_func, interval: float = 8.0):
    if not label or not callable(log_func):
        return
    last_up = 0
    last_down = 0
    try:
        while True:
            await asyncio.sleep(max(2.0, float(interval or 8.0)))
            up = int(counters.get("up", 0) or 0)
            down = int(counters.get("down", 0) or 0)
            delta_up = up - last_up
            delta_down = down - last_down
            if delta_up <= 0 and delta_down <= 0:
                continue
            elapsed = max(0.001, time.monotonic() - float(started or time.monotonic()))
            log_func(
                f"[TgRelay] traffic {label} duration_s={elapsed:.1f} "
                f"up={up} down={down} rate_up={delta_up / interval:.0f}B/s rate_down={delta_down / interval:.0f}B/s"
            )
            last_up = up
            last_down = down
    except asyncio.CancelledError:
        return


async def _bridge_streams(
    reader1,
    writer1,
    reader2,
    writer2,
    stats_label: str = "",
    log_func=None,
    first_down_timeout: float = 0.0,
):
    counters = {"up": 0, "down": 0}
    started = time.monotonic()
    first_down = asyncio.Event()
    first_down_timed_out = False

    async def _pipe(src, dst):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                if src is reader1:
                    counters["up"] += len(data)
                else:
                    counters["down"] += len(data)
                    first_down.set()
                dst.write(data)
                await dst.drain()
        finally:
            with contextlib.suppress(Exception):
                dst.close()

    async def _first_down_timeout():
        nonlocal first_down_timed_out
        timeout = float(first_down_timeout or 0.0)
        if timeout <= 0.0:
            return
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(first_down.wait(), timeout=timeout)
        if counters["down"] <= 0:
            first_down_timed_out = True
            for w in (writer1, writer2):
                with contextlib.suppress(Exception):
                    transport = getattr(w, "transport", None)
                    if transport is not None and hasattr(transport, "abort"):
                        transport.abort()
                    else:
                        w.close()
            return
        await asyncio.Future()

    tasks = [asyncio.create_task(_pipe(reader1, writer2)), asyncio.create_task(_pipe(reader2, writer1))]
    if float(first_down_timeout or 0.0) > 0.0:
        tasks.append(asyncio.create_task(_first_down_timeout()))
    if stats_label and callable(log_func):
        tasks.append(asyncio.create_task(_traffic_stats_loop(counters, started, stats_label, log_func)))
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    for task in done:
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    return counters["up"], counters["down"], int((time.monotonic() - started) * 1000)


async def _bridge_ws(
    reader,
    writer,
    ws: RawWebSocket,
    splitter: Optional[TransparentMsgSplitter],
    replay_limit: int = 0,
    close_writer: bool = True,
    first_down_timeout: float = 0.0,
    stats_label: str = "",
    log_func=None,
    first_down_callback=None,
    minimum_down_bytes: int = 1,
):
    counters = {"up": 0, "down": 0}
    started = time.monotonic()
    replay_buf = bytearray()
    replay_complete = True
    replay_enabled = int(replay_limit or 0) > 0
    first_down = asyncio.Event()
    first_down_timed_out = False
    required_down = max(1, int(minimum_down_bytes or 1))

    def _abort_ws_transport() -> None:
        with contextlib.suppress(Exception):
            setattr(ws, "_closed", True)
        ws_writer = getattr(ws, "writer", None)
        if ws_writer is not None:
            with contextlib.suppress(Exception):
                transport = getattr(ws_writer, "transport", None)
                if transport is not None and hasattr(transport, "abort"):
                    transport.abort()
                else:
                    ws_writer.close()
            return
        with contextlib.suppress(Exception):
            close_fn = getattr(ws, "Close", None)
            if callable(close_fn):
                close_fn()

    async def _close_ws():
        _abort_ws_transport()
        ws_writer = getattr(ws, "writer", None)
        if ws_writer is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(ws_writer.wait_closed(), timeout=0.25)

    async def _client_to_ws():
        nonlocal replay_complete
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    if splitter:
                        tail = splitter.flush()
                        if tail:
                            if len(tail) == 1:
                                await ws.send(tail[0])
                            else:
                                await ws.send_batch(tail)
                    return
                counters["up"] += len(data)
                if replay_enabled and counters["down"] <= 0:
                    if len(replay_buf) + len(data) <= int(replay_limit or 0):
                        replay_buf.extend(data)
                    else:
                        replay_complete = False
                        replay_buf.clear()
                if splitter:
                    parts = splitter.split(data)
                    if not parts:
                        continue
                    if len(parts) == 1:
                        await ws.send(parts[0])
                    else:
                        await ws.send_batch(parts)
                else:
                    await ws.send(data)
        finally:
            await _close_ws()

    async def _ws_to_client():
        try:
            while True:
                payload = await ws.recv()
                if payload is None:
                    return
                if not payload:
                    continue
                if counters["down"] <= 0:
                    replay_buf.clear()
                counters["down"] += len(payload)
                if counters["down"] >= required_down and not first_down.is_set():
                    if callable(first_down_callback):
                        with contextlib.suppress(Exception):
                            first_down_callback(counters["down"])
                    first_down.set()
                writer.write(payload)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
            return
        finally:
            if close_writer:
                with contextlib.suppress(Exception):
                    writer.close()

    async def _first_down_timeout():
        nonlocal first_down_timed_out
        timeout = float(first_down_timeout or 0.0)
        if timeout <= 0.0:
            return
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(first_down.wait(), timeout=timeout)
        if counters["down"] >= required_down:
            await asyncio.Future()

        # A quiet downstream is normal while Telegram is accepting an upload.
        # Never tear down a stream that can no longer be replayed safely, and
        # keep extending the watchdog while client->Telegram bytes progress.
        while counters["down"] < required_down:
            if counters["down"] <= 0 and not replay_complete:
                await asyncio.Future()
            observed_up = int(counters["up"] or 0)
            if observed_up <= 0:
                break
            idle_grace = (
                min(2.0, float(FIRST_DOWN_UPLOAD_IDLE_GRACE))
                if required_down > 1
                else float(FIRST_DOWN_UPLOAD_IDLE_GRACE)
            )
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    first_down.wait(),
                    timeout=idle_grace,
                )
            if counters["down"] >= required_down:
                await asyncio.Future()
            if int(counters["up"] or 0) <= observed_up:
                break

        first_down_timed_out = True
        _abort_ws_transport()
        return

    tasks = [asyncio.create_task(_client_to_ws()), asyncio.create_task(_ws_to_client())]
    if replay_enabled and float(first_down_timeout or 0.0) > 0.0:
        tasks.append(asyncio.create_task(_first_down_timeout()))
    if stats_label and callable(log_func):
        tasks.append(asyncio.create_task(_traffic_stats_loop(counters, started, stats_label, log_func)))
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    for task in done:
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    replay = bytes(replay_buf) if replay_enabled and replay_complete and (counters["down"] <= 0 or first_down_timed_out) else b""
    # `first_down_timed_out` возвращается наружу, а не остаётся внутренним:
    # вызывающий отличает по нему «ждали первый байт и не дождались» от
    # «собеседник закрыл соединение сразу же, ничего не прислав». Это разные
    # диагнозы — первое означает медленный или чёрнодырный маршрут, второе отказ,
    # — а без флага оба сваливались в одну строку про таймаут.
    return (counters["up"], counters["down"],
            int((time.monotonic() - started) * 1000), replay, first_down_timed_out)


async def serve_until_stopped(server: asyncio.AbstractServer, stop_event: asyncio.Event) -> None:
    """Отдать сервер в работу и остановить его так, чтобы остановка кончалась.

    Отдельная функция, а не пять строк внутри `_run()`, потому что здесь важен
    порядок, и порядок этот неочевиден настолько, что первый вариант его
    нарушал и вешал релей навсегда.

    `serve_forever()` отвечает на отмену собственными `close()` и
    `wait_closed()`, а `wait_closed()` начиная с 3.12.1 ждёт ещё и отцепления
    каждого клиентского транспорта. Telegram держит свои SOCKS5-сокеты часами.
    Поэтому «отменить задачу и дождаться её» до того, как клиенты отпущены, —
    это ожидание длиной в сессию: корутина не возвращается, `stop()` уходит по
    таймауту join и обнуляет `self.server` под работающей корутиной, а та потом
    падает на `None.close()` и приходит в супервизор как «Ошибка запуска».
    Внешний `wait_for` от этого не спасает: отмену съедает `suppress` внутри.

    Отсюда правило: сначала закрыть сервер и сбросить клиентов, и только потом
    ждать отменённые задачи. Проверено воспроизведением с живым клиентом —
    прежний порядок не возвращается за 15 с, этот выходит сразу.
    """
    serve_task = asyncio.create_task(server.serve_forever())
    stop_task = asyncio.create_task(stop_event.wait())
    try:
        await asyncio.wait({serve_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        server.close()
        # Появился в 3.13; на более раннем интерпретаторе просто нечего звать.
        with contextlib.suppress(Exception):
            server.close_clients()
        for task in (serve_task, stop_task):
            task.cancel()
        for task in (serve_task, stop_task):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        # Ограничен намеренно: к этому моменту закрывать уже нечего, и повод
        # ждать здесь дольше означал бы, что сброс клиентов не сработал.
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), timeout=3.0)


class TelegramTransparentRelayServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 1372, log_func=None, upstream_provider=None, warp_bootstrap_waiter=None):
        self.host = host
        self.port = int(port)
        self.log_func = log_func or (lambda msg: log.info(msg))
        # Egress switching happens in module-level code shared with the NovaWFP
        # proxy; route it to the same console the rest of the relay writes to.
        set_wss_egress_logger(self.log_func)
        # То же и для вердикта о маскировке TLS: без этого он оставался в
        # `logging`, а у корневого логгера в оконной сборке нет потока.
        set_transport_logger(self.log_func)
        self.upstream_provider = upstream_provider
        self.warp_bootstrap_waiter = warp_bootstrap_waiter
        self.thread = None
        self.loop = None
        self.server = None
        self.stop_event = None
        self.started_event = threading.Event()
        self.running = False
        # Set by stop() so the supervisor in _thread_main can tell an ordered
        # shutdown from a crash and not fight it by restarting.
        self._stopping = False
        self._cf_started = False
        self._no_probe_until: Dict[Tuple[str, int], float] = {}
        self._http_transport_until: Dict[Tuple[str, int], float] = {}
        # DCs this client actually talks to; the native prober only asks about
        # these instead of sweeping every data centre Telegram has.
        self._seen_dcs: set = set()
        self._prefer_direct_until: Dict[Tuple[int, str], float] = {}
        self._route_preference_until: Dict[Tuple[str, int], Tuple[str, float]] = {}
        self._last_fallback_log: Dict[Tuple[str, str, int, str], float] = {}
        self._last_wss_route_log: Dict[Tuple[int, str, bool], float] = {}
        self._last_probe_diag_log: Dict[Tuple[str, int, str], float] = {}
        self._cf_bootstrap_probe_logged: Dict[int, float] = {}
        self._cf_last_good_domain: Dict[Tuple[int, bool], Tuple[str, float]] = {}
        self._cf_bad_domain_until: Dict[str, float] = {}
        self._cf_domain_score: Dict[str, Tuple[float, float]] = {}
        self._cf_health_cache_last_save = 0.0
        self._cf_prewarm_started: Dict[Tuple[int, bool], float] = {}
        self._cf_idle: Dict[Tuple[int, bool, bool], deque] = {}
        self._cf_refilling = set()
        self._last_skip_log: Dict[Tuple[str, str, int, int, bool], float] = {}
        # Метод -> (сколько подавлено с прошлой записи, когда записали).
        self._http_method_refusals: Dict[str, Tuple[int, float]] = {}
        # Адрес клиента -> (сколько подавлено, когда записали).
        self._silent_clients: Dict[str, Tuple[int, float]] = {}
        self._client_timeouts: Dict[str, Tuple[int, float]] = {}
        self._route_scoring: Dict[Tuple[int, str], float] = {}  # (dc, route_label_type): score
        # Ключ (dc, is_media, route_kind) — см. _wss_route_kind.
        self._wss_first_byte_fail: Dict[Tuple[int, bool, str], Tuple[int, float]] = {}
        self._wss_first_byte_disabled_until: Dict[Tuple[int, bool, str], float] = {}
        self._active_clients = {}
        self._last_client_mode_seen = {"socks": 0.0, "divert": 0.0, "http": 0.0}
        self._last_mode_switch_close = 0.0
        self._start_mono = 0.0
        self._last_startup_timeout_log = 0.0
        self._cf_health_cache_load()

    def _cf_health_cache_path(self) -> str:
        return os.path.join(APP_ROOT, "temp", "tgrelay_cf_health.json")

    @staticmethod
    def _cache_wall_from_mono(mono_seen: float) -> float:
        try:
            return time.time() - max(0.0, time.monotonic() - float(mono_seen or 0.0))
        except Exception:
            return time.time()

    def _cf_health_cache_load(self) -> None:
        path = self._cf_health_cache_path()
        try:
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if not isinstance(payload, dict):
                return
            now_wall = time.time()
            now_mono = time.monotonic()

            scores = payload.get("scores")
            if isinstance(scores, dict):
                for domain, item in scores.items():
                    domain = str(domain or "").strip().lower()
                    if not domain or not isinstance(item, dict):
                        continue
                    try:
                        score = max(0.0, min(100.0, float(item.get("score") or 0.0)))
                        seen_wall = float(item.get("seen") or 0.0)
                    except Exception:
                        continue
                    age = max(0.0, now_wall - seen_wall)
                    if score > 0.0 and age <= CF_RECENT_GOOD_TTL:
                        self._cf_domain_score[domain] = (score, now_mono - age)

            last_good = payload.get("last_good")
            if isinstance(last_good, dict):
                for key_text, item in last_good.items():
                    if not isinstance(item, dict):
                        continue
                    try:
                        dc_text, media_text = str(key_text).split(":", 1)
                        dc = int(dc_text)
                        is_media = media_text in ("1", "true", "True")
                        domain = str(item.get("domain") or "").strip().lower()
                        seen_wall = float(item.get("seen") or 0.0)
                    except Exception:
                        continue
                    age = max(0.0, now_wall - seen_wall)
                    if dc > 0 and domain and age <= CF_RECENT_GOOD_TTL:
                        self._cf_last_good_domain[(dc, bool(is_media))] = (
                            domain,
                            now_mono + max(30.0, CF_RECENT_GOOD_TTL - age),
                        )
        except Exception:
            return

    def _cf_health_cache_save(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - float(self._cf_health_cache_last_save or 0.0)) < 3.0:
            return
        self._cf_health_cache_last_save = now
        path = self._cf_health_cache_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            now_mono = time.monotonic()
            scores = {}
            for domain, (score, seen_mono) in list(self._cf_domain_score.items()):
                try:
                    if (now_mono - float(seen_mono or 0.0)) > CF_RECENT_GOOD_TTL:
                        continue
                    if float(score or 0.0) <= 0.0:
                        continue
                    scores[str(domain)] = {
                        "score": round(float(score or 0.0), 3),
                        "seen": self._cache_wall_from_mono(float(seen_mono or 0.0)),
                    }
                except Exception:
                    continue

            last_good = {}
            for (dc, is_media), (domain, until_mono) in list(self._cf_last_good_domain.items()):
                try:
                    if float(until_mono or 0.0) <= now_mono:
                        continue
                    key = f"{int(dc)}:{1 if bool(is_media) else 0}"
                    score_item = scores.get(str(domain))
                    last_good[key] = {
                        "domain": str(domain),
                        "seen": float(score_item.get("seen")) if isinstance(score_item, dict) else time.time(),
                    }
                except Exception:
                    continue

            payload = {
                "version": 1,
                "saved": time.time(),
                "ttl": CF_RECENT_GOOD_TTL,
                "scores": scores,
                "last_good": last_good,
            }
            tmp_path = f"{path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp_path, path)
        except Exception:
            pass

    def _divert_state_path(self) -> str:
        return str(
            os.environ.get(
                "NOVA_DIVERT_REDIRECT_MAP",
                os.path.join(APP_ROOT, "temp", "NovaDivertRedirectMap.json"),
            )
            or ""
        ).strip()

    async def _lookup_divert_context(self, peer) -> Optional[dict]:
        if not peer:
            return None
        try:
            peer_host = str(peer[0])
            peer_port = int(peer[1])
        except Exception:
            return None
        is_loopback_peer = False
        try:
            is_loopback_peer = bool(ipaddress.ip_address(peer_host).is_loopback)
        except Exception:
            if peer_host in {"localhost"}:
                is_loopback_peer = True
        path = self._divert_state_path()
        if not path or not os.path.exists(path):
            return None
        attempts = 3 if is_loopback_peer else 40
        for _attempt in range(attempts):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                entries = payload.get("tcp") if isinstance(payload, dict) else {}
                if not isinstance(entries, dict):
                    entries = {}
                now = time.time()
                exact = entries.get(f"{peer_host}:{peer_port}")
                candidates = [exact] if isinstance(exact, dict) else []
                if not candidates:
                    for value in entries.values():
                        if not isinstance(value, dict):
                            continue
                        try:
                            if int(value.get("local_port") or 0) == peer_port and int(value.get("service_port") or self.port) == int(self.port):
                                candidates.append(value)
                        except Exception:
                            continue
                if not candidates and not is_loopback_peer:
                    nearby = []
                    for value in entries.values():
                        if not isinstance(value, dict):
                            continue
                        try:
                            local_host = str(value.get("local_host") or "").strip()
                            local_port = int(value.get("local_port") or 0)
                            updated = float(value.get("updated", 0.0) or 0.0)
                            expires = float(value.get("expires", 0.0) or 0.0)
                        except Exception:
                            continue
                        if local_host != peer_host:
                            continue
                        if expires < now:
                            continue
                        if abs(local_port - peer_port) > 16:
                            continue
                        if (now - updated) > 8.0:
                            continue
                        nearby.append(value)
                    if nearby:
                        nearby.sort(
                            key=lambda item: (
                                abs(int(item.get("local_port") or 0) - peer_port),
                                -float(item.get("updated", 0.0) or 0.0),
                            )
                        )
                        candidates = [nearby[0]]
                candidates = [
                    item for item in candidates
                    if float(item.get("expires", 0.0) or 0.0) >= now
                ]
                if candidates:
                    non_closing = [item for item in candidates if not bool(item.get("closing"))]
                    if non_closing:
                        candidates = non_closing
                if not candidates:
                    await asyncio.sleep(0.05)
                    continue
                candidates.sort(key=lambda item: float(item.get("updated", 0.0) or 0.0), reverse=True)
                item = candidates[0]
                target_host = str(item.get("target_host") or "").strip()
                target_port = int(item.get("target_port") or 0)
                if target_host and target_port > 0:
                    return item
            except (json.JSONDecodeError, PermissionError):
                await asyncio.sleep(0.05)
            except OSError:
                await asyncio.sleep(0.05)
            except Exception:
                await asyncio.sleep(0.05)
        return None

    def _register_client(self, writer, mode: str):
        key = id(writer)
        try:
            self._active_clients[key] = (writer, str(mode or ""), time.monotonic())
        except Exception:
            pass
        return key

    def _unregister_client(self, key) -> None:
        try:
            self._active_clients.pop(key, None)
        except Exception:
            pass

    async def _close_clients_by_mode(self, mode: str, reason: str) -> None:
        mode = str(mode or "").strip().lower()
        if not mode:
            return
        items = []
        try:
            items = [
                (key, writer)
                for key, (writer, client_mode, _started) in list(self._active_clients.items())
                if str(client_mode or "").strip().lower() == mode
            ]
        except Exception:
            items = []
        closed = 0
        for key, writer in items:
            try:
                self._active_clients.pop(key, None)
                writer.close()
                await writer.wait_closed()
                closed += 1
            except Exception:
                pass
        if closed:
            self.log_func(f"[TgRelay] mode-switch: closed {closed} stale {mode} client(s) ({reason}).")

    async def _note_client_mode(self, mode: str) -> None:
        mode = str(mode or "").strip().lower()
        if mode not in ("socks", "divert", "http"):
            return
        self._last_client_mode_seen[mode] = time.monotonic()

    def start(self, timeout: float = 8.0) -> bool:
        if self.thread and self.thread.is_alive():
            return True
        self._stopping = False
        self.started_event.clear()
        self.thread = threading.Thread(target=self._thread_main, daemon=True, name="NovaTelegramRelay")
        self.thread.start()
        self.started_event.wait(timeout=timeout)
        return bool(self.running)

    def stop(self, timeout: float = 5.0) -> None:
        self._stopping = True
        if self.loop and self.stop_event:
            try:
                self.loop.call_soon_threadsafe(self.stop_event.set)
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=timeout)
        self.thread = None
        self.loop = None
        self.server = None
        self.stop_event = None
        self.running = False

    def notify_route_usable(self) -> None:
        try:
            if self.loop and self.running:
                self.loop.call_soon_threadsafe(self._on_route_usable)
        except Exception:
            pass

    def _on_route_usable(self) -> None:
        try:
            self._no_probe_until.clear()
        except Exception:
            pass
        try:
            self._http_transport_until.clear()
        except Exception:
            pass
        try:
            # A route just came back; give every egress its place in the queue
            # again instead of making it sit out the rest of its penalty.
            _wss_egress_bad.clear()
        except Exception:
            pass
        try:
            self._wss_first_byte_fail.clear()
            self._wss_first_byte_disabled_until.clear()
        except Exception:
            pass
        try:
            if _has_custom_cfproxy_domain():
                asyncio.create_task(self._schedule_cf_bootstrap_prewarm_wave(0.05))
        except Exception:
            pass

    # Supervision. A single unhandled exception out of _run() used to end the
    # relay for the rest of the session: the thread returned, nothing watched
    # `running`, and Telegram simply had no local SOCKS5 until Nova restarted.
    # Observed in the field as one line — «Ошибка запуска: invalid state» — and
    # then eighteen minutes of silence.
    #
    # A crash mid-session is not the same failure as a bad start, so the backoff
    # resets after a run that stayed up: a relay that served for a minute and
    # then hit a race should come back at once, while a port that is genuinely
    # taken should not spin.
    _SUPERVISOR_BACKOFF_MAX = 15.0
    _SUPERVISOR_HEALTHY_RUN = 30.0
    # Сколько раз за одну жизнь релея цикл возобновляется после
    # InvalidStateError. Живой темп — единицы за сессию, так что до потолка
    # доходит только по-настоящему сломанный цикл; см. _run_once.
    _LOOP_RESUME_LIMIT = 20

    def _thread_main(self) -> None:
        backoff = 1.0
        attempt = 0
        while not self._stopping:
            attempt += 1
            started = time.monotonic()
            crashed = self._run_once()
            uptime = time.monotonic() - started

            if self._stopping:
                break
            if not crashed:
                # Ordered exit of the event loop without an exception.
                break

            if uptime >= self._SUPERVISOR_HEALTHY_RUN:
                backoff = 1.0
                attempt = 1
            # First failure and then every fifth: enough to see it in the log
            # without burying everything else when a port stays occupied.
            if attempt == 1 or attempt % 5 == 0:
                self.log_func(
                    f"[TgRelay] Релей упал после {uptime:.0f}с (попытка {attempt}); "
                    f"перезапуск через {backoff:.0f}с."
                )
            slept = 0.0
            while slept < backoff and not self._stopping:
                step = min(0.25, backoff - slept)
                time.sleep(step)
                slept += step
            backoff = min(self._SUPERVISOR_BACKOFF_MAX, backoff * 2.0)

    def _run_once(self) -> bool:
        """One life of the relay. True when it ended on an exception."""
        crashed = False
        loop = asyncio.new_event_loop()
        self.loop = loop
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(self._loop_exception_handler)
        self.stop_event = asyncio.Event()
        set_upstream_provider(self.upstream_provider)
        with contextlib.suppress(Exception):
            import concurrent.futures
            loop.set_default_executor(
                concurrent.futures.ThreadPoolExecutor(
                    max_workers=48,
                    thread_name_prefix="NovaTgRelayIO",
                )
            )
        try:
            # InvalidStateError из IocpProactor._poll — не наша авария и не
            # повод ронять всё. Место известно точно (windows_events.py:806:
            # `f.set_exception(e)` при уже завершённом фьючерсе, хотя тремя
            # строками выше стоит `elif not f.done()`), но воспроизвести его не
            # удалось: 4152 соединения с обрывами по RST не дали ни одного
            # случая, межпоточных достроек фьючерсов не зафиксировано, с моим
            # 501-на-POST корреляции нет (14 отказов, 0 падений). Живой темп
            # рваный: 4 падения за 7 минут в одну сессию и ни одного за 25
            # минут под такой же нагрузкой в другую.
            #
            # Цена аварии сама по себе — один потерянный результат сокетной
            # операции. Цена реакции на неё была несоизмеримой: исключение
            # выходило наружу, супервизор считал это падением и поднимал релей
            # заново, обрывая ВСЕ живые туннели. Цикл при этом не закрыт —
            # проверено вкручиванием ровно этого исключения: повторный вход в
            # run_until_complete возобновляет работу, и пять живых туннелей
            # переживают аварию (485 эхо против 21 на момент сбоя).
            #
            # Поэтому: продолжаем, но громко и с потолком. Если это начнёт
            # повторяться подряд — значит цикл действительно сломан, и тогда
            # перезапуск правильнее.
            task = loop.create_task(self._run())
            resumed = 0
            while True:
                try:
                    loop.run_until_complete(task)
                    break
                except asyncio.InvalidStateError as exc:
                    resumed += 1
                    if resumed > self._LOOP_RESUME_LIMIT:
                        self.log_func(
                            f"[TgRelay] Цикл не восстанавливается: {self._LOOP_RESUME_LIMIT} "
                            "подряд InvalidStateError — перезапуск релея."
                        )
                        raise
                    if resumed == 1:
                        self.log_func(
                            "[TgRelay] Сбой asyncio (InvalidStateError в IocpProactor._poll); "
                            "цикл продолжен, туннели сохранены."
                        )
                        with contextlib.suppress(Exception):
                            for line in "".join(traceback.format_exception(exc)).rstrip().splitlines():
                                self.log_func(f"[TgRelay]   {line}")
                    else:
                        self.log_func(
                            f"[TgRelay] Сбой asyncio: цикл продолжен ({resumed}-й раз за эту жизнь)."
                        )
        except Exception as exc:
            crashed = True
            # Тип и трассировка, а не только str(exc). Разбор аварии 2026-08-09
            # встал именно на этом: в логе была одна строка «Ошибка запуска:
            # invalid state» — текст `asyncio.InvalidStateError` без единого
            # намёка, где он возник, и восстановить место по нему не удалось.
            self.log_func(f"[TgRelay] Ошибка запуска: {type(exc).__name__}: {exc}")
            with contextlib.suppress(Exception):
                for line in "".join(traceback.format_exception(exc)).rstrip().splitlines():
                    self.log_func(f"[TgRelay]   {line}")
        finally:
            self.running = False
            self.started_event.set()
            with contextlib.suppress(Exception):
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            # close() тоже под подавлением: он сам зовёт _poll, а именно оттуда
            # и прилетает InvalidStateError. Незакрытый цикл — утечка одного
            # объекта, исключение здесь — потерянные `self.loop = None` ниже,
            # то есть stop() и notify_route_usable(), зовущие в мёртвый цикл.
            with contextlib.suppress(Exception):
                loop.close()
            # The loop these belong to is gone; leaving them set would let
            # stop() and notify_route_usable() call into a closed loop.
            self.loop = None
            self.stop_event = None
        return crashed

    def _loop_exception_handler(self, loop, context):
        exc = (context or {}).get("exception")
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError)):
            return
        try:
            msg = (context or {}).get("message") or str(exc or "unknown")
            if exc is not None:
                msg = f"{type(exc).__name__}: {exc} ({msg})"
            self.log_func(f"[TgRelay] asyncio warning: {msg}")
            # Всё, что сюда попадает, уже потеряло свой стек в глазах вызывающего:
            # это не исключение, а отчёт о нём. Без трассировки такая строка
            # называет симптом и молчит о месте.
            if exc is not None:
                with contextlib.suppress(Exception):
                    for line in "".join(traceback.format_exception(exc)).rstrip().splitlines():
                        self.log_func(f"[TgRelay]   {line}")
        except Exception:
            pass

    def _log_burst(self, bucket, key: str, interval: float, render) -> None:
        """Первая строка всплеска сразу, остальные — счётчиком в следующей.

        `render(suppressed)` строит сообщение; ноль означает, что подавлять было
        нечего. Ограничитель — украшение, поэтому любая его поломка обязана
        заканчиваться записью, а не молчанием: «стало тише» и «перестало
        работать» в логе выглядят одинаково.

        Хвост всплеска, за которым ничего не последовало, так и не будет назван.
        Осознанный размен: строка «было ещё N» без нового события никому не
        нужна, а таймер ради неё пришлось бы держать.
        """
        suppressed = 0
        try:
            now = time.monotonic()
            seen, last = bucket.get(key, (0, 0.0))
            if last and (now - last) < float(interval):
                bucket[key] = (seen + 1, last)
                return
            bucket[key] = (0, now)
            suppressed = seen
        except Exception:
            pass
        self.log_func(render(suppressed))

    def _log_unsupported_http_method(self, method: str) -> None:
        """Одна строка на всплеск, а не на каждый запрос.

        Telegram Desktop гоняет свой HTTP-транспорт параллельно с TCP, и через
        прокси это выглядит как поток POST'ов: 110 одинаковых строк за 19 минут
        живой работы. Ответить 501 надо каждому, писать в лог — нет.
        """
        method = str(method or "").strip().upper() or "?"
        self._log_burst(
            self._http_method_refusals,
            method,
            FALLBACK_LOG_INTERVAL,
            lambda n: (
                f"[TgRelay] HTTP-прокси: метод {method} не поддержан, нужен CONNECT."
                + _burst_tail(n, FALLBACK_LOG_INTERVAL)
            ),
        )

    def _log_silent_client(self, label: str) -> None:
        """Клиент подключился и не прислал ни байта. Это не «Ошибка клиента».

        Разобрано по отчёту пользователя, у которого «посыпались ошибки» сразу
        после того, как он выключил прокси в клиенте Telegram: 52 строки
        «Ошибка клиента … timed out» за 5 минут — и при этом 102 туннеля, 101 из
        них с входящим трафиком, 2.86 МБ за час. Не сломалось ничего; сломано
        было слово «Ошибка» в строке про совершенно штатную гонку транспортов.
        """
        peer = str(label or "?").rsplit(":", 1)[0] or "?"
        self._log_burst(
            self._silent_clients,
            peer,
            SILENT_CLIENT_LOG_INTERVAL,
            lambda n: (
                f"[TgRelay] Клиент {label} молчал {int(CLIENT_FIRST_BYTE_TIMEOUT)} с и закрыт — "
                f"обычно это проигравший сокет в гонке транспортов Telegram, а не сбой."
                + _burst_tail(n, SILENT_CLIENT_LOG_INTERVAL)
            ),
        )


    def _log_client_timeout(self, label: str, exc: BaseException) -> None:
        """Истёк срок — но чей?

        Строка называлась «Ошибка клиента <адрес клиента>», и адрес в ней —
        единственное, что видит читатель. Между тем `socket.create_connection`
        в `transport.py` отдаёт ровно `TimeoutError('timed out')`, когда не
        достучался до **вышестоящего** узла: клиент тут ни при чём, он просто
        тот, для кого канал поднимали. Пустое сообщение (`''`) отдаёт
        `asyncio.wait_for` — по нему эти два случая и различимы.

        Отчёт, с которого разобрано: 52 такие строки за 5 минут, и в том же логе
        102 туннеля, 101 с входящим трафиком, 2.86 МБ за час. Всплеск совпал с
        `WSS empty response` и `TCP fallback ... down=0`, то есть с тем, что
        душили канал наверх.
        """
        detail = str(exc or "").strip()
        peer = str(label or "?").rsplit(":", 1)[0] or "?"
        self._log_burst(
            self._client_timeouts,
            peer,
            SILENT_CLIENT_LOG_INTERVAL,
            lambda n: (
                f"[TgRelay] Канал для клиента {label} не поднят: истёк срок"
                + (f" ({detail})" if detail else "")
                + ". Обычно это вышестоящий узел, а не клиент."
                + _burst_tail(n, SILENT_CLIENT_LOG_INTERVAL)
            ),
        )


    def _log_skipping_fallback(self, reason: str, target_ip: str, target_port: int, dc_hint: int, is_media: bool) -> None:
        try:
            key = (
                str(reason or "").strip().lower(),
                str(target_ip or "").strip().lower(),
                int(target_port or 0),
                int(dc_hint or 0),
                bool(is_media),
            )
            now = time.monotonic()
            last = float(self._last_skip_log.get(key, 0.0) or 0.0)
            if (now - last) < SKIP_LOG_INTERVAL:
                return
            self._last_skip_log[key] = now
        except Exception:
            pass
        self.log_func(
            f"[TgRelay] Skipping TCP fallback for {reason} (ISP throttled): dc={dc_hint or '?'} "
            f"media={bool(is_media)} target={target_ip}:{target_port}"
        )

    async def _run(self):
        self._start_mono = time.monotonic()
        proxy_config.buffer_size = max(64 * 1024, int(getattr(proxy_config, "buffer_size", 256 * 1024)))
        if not self._cf_started:
            proxy_config.cfproxy_domains = get_cfproxy_domains("NOVA_TG_RELAY_CF_DOMAINS")
            proxy_config.active_cfproxy_domain = proxy_config.active_cfproxy_domain or (proxy_config.cfproxy_domains[0] if proxy_config.cfproxy_domains else "")
            proxy_config.fallback_cfproxy = bool(CF_FALLBACK_ENABLED)
            self._cf_started = True
        try:
            # Custom CF/WSS is the primary path. Warming the direct Telegram
            # fallback would otherwise open up to 48 mostly-unused WSS streams
            # through WARP during the most latency-sensitive startup window.
            if _has_custom_cfproxy_domain():
                proxy_config.pool_size = 0
            else:
                if int(getattr(proxy_config, "pool_size", 0) or 0) <= 0:
                    proxy_config.pool_size = 4
                _WS_POOL.warmup()
        except Exception:
            pass
        try:
            cf_preview = ", ".join((proxy_config.cfproxy_domains or [])[:3])
            if cf_preview:
                self.log_func(f"[TgRelay] CF proxy domains: {cf_preview}")
        except Exception:
            pass
        try:
            if _has_custom_cfproxy_domain():
                # Prewarm only routes proven useful in the recent health cache.
                # Unknown DCs connect lazily on first use instead of consuming
                # Worker requests in four speculative all-DC waves.
                asyncio.create_task(self._schedule_cf_bootstrap_prewarm_wave(1.5))
        except Exception:
            pass
        try:
            asyncio.create_task(self._native_probe_loop())
        except Exception:
            pass

        server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            backlog=512,
            limit=max(256 * 1024, int(getattr(proxy_config, "buffer_size", 256 * 1024))),
        )
        # Локальная привязка нарочно: `stop()` обнуляет `self.server`, не
        # дожидаясь конца этой корутины, и чтение атрибута ниже уронило бы
        # `AttributeError: 'NoneType' object has no attribute 'close'` в
        # супервизор под видом «Ошибка запуска».
        self.server = server
        self.running = True
        self.started_event.set()
        self.log_func(
            f"[TgRelay] Локальный relay активен на {self.host}:{self.port} (SOCKS5 и HTTP CONNECT)."
        )
        await serve_until_stopped(server, self.stop_event)

    async def _schedule_cf_bootstrap_prewarm_wave(self, delay: float = 0.0) -> None:
        try:
            await asyncio.sleep(max(0.0, float(delay or 0.0)))
            recent_keys = sorted(
                {
                    (int(dc), bool(is_media))
                    for dc, is_media in self._cf_last_good_domain.keys()
                    if int(dc or 0) in _TG_TCP_FALLBACK_IPS
                }
            )
            for index, (dc, is_media) in enumerate(recent_keys):
                self._schedule_cf_bootstrap_prewarm(
                    dc,
                    is_media=is_media,
                    delay=(0.05 + (0.12 * index)),
                )
        except Exception:
            pass

    def _wss_first_byte_disabled(self, dc_hint: int, is_media: bool, route_kind=None) -> bool:
        """Is the first-byte circuit open?

        With ``route_kind`` — for that kind alone. Without it the question is
        «is WSS worth attempting at all», and the answer is yes while any kind
        still has a closed circuit: one dead route must not speak for the other.
        """
        try:
            now = time.monotonic()
            kinds = (str(route_kind),) if route_kind else WSS_ROUTE_KINDS
            for kind in kinds:
                key = (int(dc_hint or 0), bool(is_media), kind)
                until = float(self._wss_first_byte_disabled_until.get(key, 0.0) or 0.0)
                if until <= now:
                    return False
            return True
        except Exception:
            return False

    def _note_wss_first_byte_result(self, dc_hint: int, is_media: bool, down: int, route_label="") -> None:
        kind = _wss_route_kind(route_label)
        key = (int(dc_hint or 0), bool(is_media), kind)
        if key[0] <= 0:
            return
        now = time.monotonic()
        try:
            if int(down or 0) > 0:
                self._wss_first_byte_fail.pop(key, None)
                self._wss_first_byte_disabled_until.pop(key, None)
                return
            count, first_seen = self._wss_first_byte_fail.get(key, (0, now))
            if (now - float(first_seen or now)) > 45.0:
                count = 0
                first_seen = now
            count += 1
            self._wss_first_byte_fail[key] = (count, first_seen)
            has_recent_good = self._cf_has_recent_good(key[0], key[1], max_age=180.0)
            has_cf = _has_custom_cfproxy_domain()
            threshold = 2 if (bool(is_media) and has_cf) else (4 if has_recent_good else (3 if has_cf else 2))
            if count >= threshold:
                ttl = 3.0 if (has_recent_good or (bool(is_media) and has_cf)) else (8.0 if bool(is_media) else 15.0)
                self._wss_first_byte_disabled_until[key] = now + ttl
                self._wss_first_byte_fail[key] = (0, now)
                action = (
                    "pausing WSS retries without raw TCP fallback"
                    if has_cf
                    else "using TCP fallback via WARP"
                )
                self.log_func(
                    f"[TgRelay] WSS first-byte circuit: dc={key[0]} media={bool(is_media)} route={kind} "
                    f"disabled_for={int(ttl)}s; {action}."
                )
        except Exception:
            pass

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        label = f"{peer[0]}:{peer[1]}" if peer else "?"
        prefetched_ws_task = None
        client_key = None
        try:
            try:
                prefetched = await asyncio.wait_for(
                    reader.readexactly(1), timeout=CLIENT_FIRST_BYTE_TIMEOUT
                )
            except (asyncio.TimeoutError, TimeoutError):
                # Разбирается здесь, а не в общем обработчике внизу: там
                # «истёк срок» может означать что угодно — рукопожатие SOCKS,
                # ответ прокси, застрявший туннель. Здесь он означает ровно
                # одно, и это не сбой.
                self._log_silent_client(label)
                return
            divert_context = await self._lookup_divert_context(peer)
            if divert_context:
                client_mode = "divert"
                target_host = str(divert_context.get("target_host") or "").strip()
                target_port = int(divert_context.get("target_port") or 0)
                if not target_host or target_port <= 0:
                    return
            elif b"A" <= prefetched[:1] <= b"Z":
                # Метод HTTP начинается с заглавной латинской буквы, SOCKS5 —
                # с 0x05. Проверка именно на диапазон, а не «всё, что не 0x05»:
                # иначе бинарный мусор вместо мгновенного отказа висел бы в
                # ожидании заголовков. См. _http_connect_handshake — без этой
                # ветки системный прокси Windows до релея не доходит вовсе.
                client_mode = "http"
                target_host, target_port, prefetched = await self._http_connect_handshake(
                    reader, writer, prefetched=prefetched
                )
            else:
                client_mode = "socks"
                target_host, target_port = await self._socks_handshake(reader, writer, prefetched=prefetched)
                prefetched = b""
            if not target_host:
                return
            client_key = self._register_client(writer, client_mode)
            await self._note_client_mode(client_mode)
            target_ip = await _resolve_ip(target_host)
            if not _wss_candidate(target_host, target_ip, target_port):
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, prefetched, label, media_hint=None)
                return

            probe_key = (str(target_ip or target_host or "").strip(), int(target_port or 0))
            now_mono = time.monotonic()
            # A socket already known to carry Telegram's HTTP transport for a
            # WSS-capable DC gets closed without even reading the probe: the
            # payload cannot go over /apiws, and the DC itself is unreachable
            # over the proxied egress, so any tunnel here only stalls until the
            # first-byte timeout while Telegram waits on it.
            if float(self._http_transport_until.get(probe_key, 0.0) or 0.0) > now_mono:
                self._log_skipping_fallback(
                    "http-transport-cached",
                    target_ip,
                    target_port,
                    _target_dc_hint(target_ip),
                    False,
                )
                return
            no_probe_until = float(self._no_probe_until.get(probe_key, 0.0) or 0.0)
            if no_probe_until > now_mono:
                cached_dc_hint = _target_dc_hint(target_ip)
                cached_is_media = _likely_media_target(target_ip, target_port, cached_dc_hint)
                if not cached_is_media:
                    init_packet = await self._read_probe(reader, want=64, timeout=1.2, initial=prefetched)
                    if await self._try_cf_bootstrap_non_media(
                        reader,
                        writer,
                        target_ip=target_ip,
                        target_port=target_port,
                        init_packet=init_packet,
                        label=label,
                        dc_hint=cached_dc_hint,
                    ):
                        return
                    await self._handle_plain_tunnel(
                        reader,
                        writer,
                        target_host,
                        target_port,
                        init_packet,
                        label,
                        media_hint=False,
                    )
                    return
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, prefetched, label, media_hint=None)
                return

            predicted_is_media = _likely_media_target(target_ip, target_port, 0)
            predicted_dc = _target_dc_hint(target_ip, predicted_is_media)
            if predicted_is_media and int(target_port or 0) == 80 and predicted_dc in _TG_WS_REDIRECT_IPS:
                try:
                    prefetched_ws_task = asyncio.create_task(
                        self._connect_ws_route(predicted_dc, target_ip, predicted_is_media, label)
                    )
                except Exception:
                    prefetched_ws_task = None

            # Telegram startup opens many short bootstrap/control sockets. For
            # sockets that do not even look like media by IP/port heuristics,
            # almost all probe delay is wasted because we will plain-tunnel them
            # anyway. Keep a near-zero probe there; retain longer probing only
            # for likely media sockets where WSS path can still matter.
            if not predicted_is_media:
                # Обе ветки условия здесь были одинаковыми (0.25), а сам предикат
                # — константа True (G54). Ни выбора, ни разницы: остаётся число.
                probe_timeout = 0.25
            else:
                probe_timeout = 0.15 if int(target_port or 0) == 80 else 0.6
            init_packet = await self._read_probe(reader, want=64, timeout=probe_timeout, initial=prefetched)
            init_info = parse_transparent_init_info(init_packet) if len(init_packet) >= 64 else None
            if init_info is None:
                dc_hint = _target_dc_hint(target_ip)
                is_media = _likely_media_target(target_ip, target_port, dc_hint)
                if prefetched_ws_task is not None:
                    prefetched_ws_task.cancel()
                    with contextlib.suppress(Exception):
                        await prefetched_ws_task
                if int(target_port or 0) == 80:
                    cache_for = 45.0 if not init_packet else 20.0
                    self._no_probe_until[probe_key] = time.monotonic() + cache_for
                http_transport = _looks_like_http_request(init_packet)
                tls_transport = _looks_like_tls_client_hello(init_packet)
                if http_transport:
                    probe_reason = "unparsed-init-http-transport"
                elif tls_transport:
                    probe_reason = "unparsed-init-tls"
                else:
                    probe_reason = "unparsed-init-no-wss"
                self._log_probe_diag(
                    probe_reason,
                    target_ip,
                    target_port,
                    len(init_packet or b""),
                    dc_hint,
                )
                # Telegram's HTTP transport cannot be carried over ``/apiws``,
                # and on a WSS-capable DC it is redundant: the same data centre
                # is reachable through the Worker. Tunnelling it anyway only
                # parks the socket on an egress that never answers, so Telegram
                # sits on a dead transport for the whole first-byte timeout.
                # Close at once so its transport race commits to TCP, which is
                # the leg that WSS can actually serve.
                if http_transport and int(dc_hint or 0) in _TG_WS_REDIRECT_IPS:
                    self._http_transport_until[probe_key] = time.monotonic() + HTTP_TRANSPORT_DROP_TTL
                    self._log_skipping_fallback(
                        "unparsed-init-http-transport",
                        target_ip,
                        target_port,
                        dc_hint,
                        is_media,
                    )
                    return
                # «Не дошло до WSS — закрываем, пусть клиент переподключится
                # через WSS» верно только для MTProto: смысл ветки в том, что
                # сырой TCP к Telegram душит провайдер, а WSS — нет. У TLS-сессии
                # такого второго шанса нет вовсе, /apiws её не несёт, и закрытие
                # означает просто оборванное соединение. Так был сломан
                # обновлятор Telegram Desktop: его хост лежит внутри диапазона
                # DC2, поэтому попадал сюда и умирал молча.
                if _cf_route_worth_reconnecting(is_media) and not http_transport and not tls_transport:
                    self._log_skipping_fallback(
                        "unparsed-init-no-wss",
                        target_ip,
                        target_port,
                        dc_hint,
                        is_media,
                    )
                    return
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=is_media)
                return

            dc_hint = init_info.dc or _target_dc_hint(target_ip)
            is_media = bool(init_info.is_media or _likely_media_target(target_ip, target_port, dc_hint))
            if int(dc_hint or 0) > 0:
                self._seen_dcs.add(int(dc_hint))
            if not is_media:
                if self._wss_first_byte_disabled(dc_hint, False):
                    await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=False)
                    return
                # Native MTProto beats the Worker whenever it gets through: same
                # data, two fewer network legs, no WebSocket framing. Take it as
                # soon as it is proven for this DC and leave WSS as the reserve.
                if _native_preferred(dc_hint):
                    await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=False)
                    return
                if await self._try_cf_bootstrap_non_media(
                    reader,
                    writer,
                    target_ip=target_ip,
                    target_port=target_port,
                    init_packet=init_packet,
                    label=label,
                    dc_hint=dc_hint,
                    proto_label=_proto_label(init_info.proto),
                    proto=init_info.proto,
                ):
                    return
                if prefetched_ws_task is not None:
                    prefetched_ws_task.cancel()
                    with contextlib.suppress(Exception):
                        await prefetched_ws_task
                self._log_probe_diag(
                    "parsed-non-media-cf-failed",
                    target_ip,
                    target_port,
                    len(init_packet or b""),
                    dc_hint,
                )
                # WSS just failed. Dropping the socket used to be the only
                # option because the native path was assumed dead everywhere;
                # try it instead unless the last attempts proved it silent for
                # this DC. Either way the outcome is recorded, so the next
                # connection decides on evidence rather than on the assumption.
                if _cf_route_worth_reconnecting(False) and not _native_worth_trying(dc_hint):
                    self._log_skipping_fallback(
                        "parsed-non-media-cf-failed",
                        target_ip,
                        target_port,
                        dc_hint,
                        False,
                    )
                    return
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=False)
                return
            # Media is the bulk of the traffic, so it gets the same rule as the
            # control sessions: once an egress is proven to carry Telegram's own
            # protocol to this DC, use it and leave the Worker as the reserve.
            if is_media and NATIVE_MEDIA_ENABLED and _native_preferred(dc_hint):
                if prefetched_ws_task is not None:
                    prefetched_ws_task.cancel()
                    with contextlib.suppress(Exception):
                        await prefetched_ws_task
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=True)
                return
            ws_capable = int(dc_hint or 0) in _TG_WS_REDIRECT_IPS
            if not is_media and not ws_capable:
                if prefetched_ws_task is not None:
                    prefetched_ws_task.cancel()
                    with contextlib.suppress(Exception):
                        await prefetched_ws_task
                if _cf_route_worth_reconnecting(False):
                    self._log_skipping_fallback(
                        "non-ws-capable",
                        target_ip,
                        target_port,
                        dc_hint,
                        False,
                    )
                    return
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=False)
                return
            if self._wss_first_byte_disabled(dc_hint, is_media):
                if prefetched_ws_task is not None:
                    prefetched_ws_task.cancel()
                    with contextlib.suppress(Exception):
                        await prefetched_ws_task
                if _cf_route_worth_reconnecting(is_media):
                    # Raw Telegram TCP is throttled on this route. During the
                    # short WSS cooldown, close and let Telegram reconnect once
                    # the circuit opens again without spending more Worker calls.
                    self._log_skipping_fallback(
                        "wss-first-byte-cooldown",
                        target_ip,
                        target_port,
                        dc_hint,
                        is_media,
                    )
                    return
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=is_media)
                return
            ws = None
            route_label = ""
            prefetched_route_consumed = False
            if (
                prefetched_ws_task is not None
                and int(predicted_dc or 0) == int(dc_hint or 0)
                and bool(predicted_is_media) == bool(is_media)
            ):
                prefetched_route_consumed = True
                try:
                    # The task has already been running during the protocol probe.
                    # Reuse it instead of launching a duplicate Worker request when
                    # the handshake takes longer than the old 350 ms peek window.
                    ws, route_label = await prefetched_ws_task
                except Exception:
                    ws = None
                    route_label = ""
            elif prefetched_ws_task is not None:
                prefetched_ws_task.cancel()
                with contextlib.suppress(Exception):
                    await prefetched_ws_task

            if ws is None and not prefetched_route_consumed:
                ws, route_label = await self._connect_ws_route(dc_hint, target_ip, is_media, label)
            if ws is None:
                if _cf_route_worth_reconnecting(is_media):
                    return
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=True)
                return
            try:
                self._no_probe_until.pop(probe_key, None)
            except Exception:
                pass

            splitter = None
            try:
                splitter = TransparentMsgSplitter(init_packet, init_info.proto)
            except Exception:
                splitter = None

            try:
                await ws.send(init_packet)
            except Exception:
                with contextlib.suppress(Exception):
                    await ws.close()
                if _cf_route_worth_reconnecting(is_media):
                    self._cf_note_bad_route_label(route_label, is_media, ttl=CF_MEDIA_BAD_TTL)
                    self._note_wss_first_byte_result(dc_hint, is_media, 0, route_label)
                    return
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=True)
                return

            self.log_func(
                f"[TgRelay] Подключено: proto={_proto_label(init_info.proto)} dc={dc_hint or '?'} media={is_media} route={route_label} target={target_ip}:{target_port}"
            )
            stats_label = (
                f"path=wss proto={_proto_label(init_info.proto)} dc={dc_hint or '?'} "
                f"media={is_media} route={route_label} target={target_ip}:{target_port}"
            )
            up, down, duration_ms, _replay, first_byte_timed_out = await _bridge_ws(
                reader,
                writer,
                ws,
                splitter,
                replay_limit=1048576,
                close_writer=False,
                first_down_timeout=(2.0 if is_media else 1.0),
                stats_label=stats_label,
                log_func=self.log_func,
                first_down_callback=lambda down_len, rl=route_label, dc=dc_hint, media=is_media: self._cf_note_good_route_label(
                    rl,
                    dc,
                    media,
                    down_len,
                ),
                minimum_down_bytes=(MEDIA_WSS_MIN_PROGRESS if is_media else 1),
            )
            self.log_func(
                f"[TgRelay] Закрыто: proto={_proto_label(init_info.proto)} dc={dc_hint or '?'} media={is_media} "
                f"route={route_label} target={target_ip}:{target_port} duration_ms={duration_ms} up={up + len(init_packet)} down={down}"
            )
            if int(down or 0) > 0:
                # The watchdog exists to move media off a route that is
                # technically alive and practically useless. With the owned
                # Worker out of budget there is nowhere to move: the retry
                # lands on the same web route and starts from zero bytes, so
                # a slow tunnel is strictly better than a restarted one.
                media_stalled = bool(
                    is_media
                    and int(down or 0) < MEDIA_WSS_MIN_PROGRESS
                    and int(duration_ms or 0) >= 1800
                    and _cf_owned_zone_available()
                )
                if media_stalled:
                    self._cf_note_bad_route_label(route_label, True, ttl=CF_MEDIA_BAD_TTL)
                    self._note_wss_first_byte_result(dc_hint, True, 0, route_label)
                    self.log_func(
                        f"[TgRelay] WSS media progress stalled: dc={dc_hint or '?'} "
                        f"route={route_label} down={down} duration_ms={duration_ms}; reconnecting."
                    )
                    return
                self._cf_note_good_route_label(route_label, dc_hint, is_media, down)
                self._note_wss_first_byte_result(dc_hint, is_media, down, route_label)
                return
            if int(down or 0) <= 0:
                pending_replay = bytes(_replay or b"")
                replay_initial = bytes(init_packet or b"") + pending_replay
                if self._cf_note_bad_route_label(
                    route_label,
                    is_media,
                    ttl=self._cf_empty_route_ttl(route_label, dc_hint, is_media),
                ):
                    self.log_func(
                        f"[TgRelay] WSS custom first-byte timeout; retrying Telegram Web WSS: "
                        f"proto={_proto_label(init_info.proto)} dc={dc_hint or '?'} media={is_media} "
                        f"target={target_ip}:{target_port} route={route_label}"
                    )
                    retried, retry_replay = await self._retry_web_ws_after_empty(
                        reader,
                        writer,
                        dc_hint=dc_hint,
                        is_media=is_media,
                        target_ip=target_ip,
                        target_port=target_port,
                        init_packet=init_packet,
                        pending_replay=pending_replay,
                        label=label,
                        proto=init_info.proto,
                        proto_label=_proto_label(init_info.proto),
                        replay_limit=1048576,
                        first_down_timeout=(2.0 if is_media else 1.0),
                        failed_route_label=route_label,
                    )
                    if retried:
                        return
                    replay_initial = retry_replay
                self._note_wss_first_byte_result(dc_hint, is_media, 0, route_label)
                # «Не дождались первого байта» и «собеседник закрылся сразу,
                # ничего не прислав» — разные отказы, и лечатся они по-разному:
                # первый это медленный или чёрнодырный маршрут, второй — отказ на
                # той стороне. Раньше обе ветки печатали «timeout», и в логе
                # получалось «timeout ... duration_ms=0» — таймаут, уложившийся в
                # ноль миллисекунд.
                verdict = "first-byte timeout" if first_byte_timed_out else "empty close (peer sent nothing)"
                # Skip TCP fallback when CF domains are available — ISP throttles
                # raw Telegram TCP even through WARP. Let Telegram reconnect via WSS.
                if _cf_route_worth_reconnecting(is_media):
                    self.log_func(
                        f"[TgRelay] WSS {verdict}; skipping TCP fallback (ISP throttled): proto={_proto_label(init_info.proto)} "
                        f"dc={dc_hint or '?'} media={is_media} target={target_ip}:{target_port} "
                        f"route={route_label} replay={len(replay_initial)} duration_ms={duration_ms}"
                    )
                    return
                self.log_func(
                    f"[TgRelay] WSS {verdict}; TCP fallback: proto={_proto_label(init_info.proto)} "
                    f"dc={dc_hint or '?'} media={is_media} target={target_ip}:{target_port} "
                    f"route={route_label} replay={len(replay_initial)} duration_ms={duration_ms}"
                )
                await self._handle_plain_tunnel(
                    reader,
                    writer,
                    target_ip,
                    target_port,
                    replay_initial,
                    label,
                    media_hint=is_media,
                )
        except asyncio.IncompleteReadError:
            pass
        except (asyncio.TimeoutError, TimeoutError) as exc:
            # Отдельно и **до** OSError. `TimeoutError` — его подкласс с Python
            # 3.3, а `socket.timeout` и `asyncio.TimeoutError` с 3.10/3.11 — это
            # он же, поэтому ветка ниже перехватывала все таймауты первой, а
            # подавление стартового окна в `except Exception` не могло
            # исполниться ни разу. Проверено по двум собранным логам: строки
            # «Стартовое окно» нет ни в одном.
            try:
                start_age = (time.monotonic() - float(self._start_mono or 0.0)) if self._start_mono else 999.0
                if start_age < 45.0:
                    now = time.monotonic()
                    if (now - float(self._last_startup_timeout_log or 0.0)) > FALLBACK_LOG_INTERVAL:
                        self._last_startup_timeout_log = now
                        self.log_func("[TgRelay] Стартовое окно: ждём стабилизацию WARP/SOCKS, клиентские timeout временно подавлены.")
                    return
            except Exception:
                pass
            self._log_client_timeout(label, exc)
        except OSError as exc:
            # Клиент ушёл — это не авария релея, а обычный конец соединения, и
            # чаще всего мы же его и оборвали: Nova сама сбрасывает TCP-сессии
            # Telegram, чтобы клиент переподключился через релей («сброшено
            # TCP-сессий N» в логе), а следом сюда прилетает WinError 64.
            # Пользователь читал это как поломку — строка называется «Ошибка
            # клиента» и появляется пачками сразу после запуска.
            if getattr(exc, "winerror", None) in _CLIENT_GONE_WINERRORS or isinstance(
                exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)
            ):
                return
            self.log_func(f"[TgRelay] Ошибка клиента {label}: {exc}")
        except Exception as exc:
            self.log_func(f"[TgRelay] Ошибка клиента {label}: {exc}")
        finally:
            if client_key is not None:
                self._unregister_client(client_key)
            if prefetched_ws_task is not None:
                try:
                    if not prefetched_ws_task.done():
                        prefetched_ws_task.cancel()
                except Exception:
                    pass
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _try_cf_bootstrap_non_media(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        target_ip: str,
        target_port: int,
        init_packet: bytes,
        label: str,
        dc_hint: int,
        proto_label: str = "raw",
        proto: int = 0,
    ) -> bool:
        if not init_packet or len(init_packet) < 64:
            return False
        if not _valid_proto(int(proto or 0)):
            return False
        try:
            dc_hint = int(dc_hint or 0)
            target_port = int(target_port or 0)
        except Exception:
            return False
        if dc_hint <= 0 or target_port not in (80, 443, 5222, 5228):
            return False
        if not CF_FALLBACK_ENABLED or not _has_custom_cfproxy_domain():
            return False
        # Только CF: этот путь ведёт исключительно на свой Worker, и молчание
        # web.telegram.org не повод его пропускать.
        if self._wss_first_byte_disabled(dc_hint, False, route_kind="cf"):
            return False
        # Treat all Telegram connections as CF/WSS bootstrap candidates when a custom domain is configured.
        try:
            await self._maybe_wait_for_warp_bootstrap(
                target_ip,
                target_port,
                media_hint=False,
                dc_hint=dc_hint,
            )
        except Exception:
            pass
        now = time.monotonic()
        last = float(self._cf_bootstrap_probe_logged.get(dc_hint, 0.0) or 0.0)
        if (now - last) > 10.0:
            self._cf_bootstrap_probe_logged[dc_hint] = now
            try:
                candidate_bases = _cf_ws_domain_bases(primary_only=False)
            except Exception:
                candidate_bases = []
            candidate_preview = ",".join(candidate_bases[:4]) or "none"
            self.log_func(
                f"[TgRelay] Bootstrap CF/WSS probe: dc={dc_hint} target={target_ip}:{target_port} "
                f"candidates={candidate_preview}"
            )
        ws, route_label = await self._connect_cf_ws_route(dc_hint, False, primary_only=False)
        if ws is None:
            return False
        try:
            await ws.send(init_packet)
        except Exception:
            with contextlib.suppress(Exception):
                await ws.close()
            return False
        try:
            splitter = TransparentMsgSplitter(init_packet, int(proto or 0))
        except Exception:
            with contextlib.suppress(Exception):
                await ws.close()
            return False
        self.log_func(
            f"[TgRelay] Подключено: proto={proto_label} dc={dc_hint} media=False route={route_label} target={target_ip}:{target_port}"
        )
        up, down, duration_ms, replay, first_byte_timed_out = await _bridge_ws(
            reader,
            writer,
            ws,
            splitter,
            replay_limit=524288,
            close_writer=False,
            first_down_timeout=1.2,
            stats_label=f"path=wss proto={proto_label} dc={dc_hint} media=False route={route_label} target={target_ip}:{target_port}",
            log_func=self.log_func,
            first_down_callback=lambda down_len, rl=route_label, dc=dc_hint: self._cf_note_good_route_label(
                rl,
                dc,
                False,
                down_len,
            ),
        )
        self.log_func(
            f"[TgRelay] Закрыто: proto={proto_label} dc={dc_hint} media=False route={route_label} "
            f"target={target_ip}:{target_port} duration_ms={duration_ms} up={up + len(init_packet)} down={down}"
        )
        if int(down or 0) > 0:
            self._cf_note_good_route_label(route_label, dc_hint, False, down)
            self._note_wss_first_byte_result(dc_hint, False, down, route_label)
            return True
        if int(down or 0) <= 0:
            pending_replay = bytes(replay or b"")
            replay_initial = bytes(init_packet or b"") + pending_replay
            if self._cf_note_bad_route_label(
                route_label,
                False,
                ttl=self._cf_empty_route_ttl(route_label, dc_hint, False),
            ):
                self.log_func(
                    f"[TgRelay] WSS custom empty; retrying Telegram Web WSS: proto={proto_label} "
                    f"dc={dc_hint} target={target_ip}:{target_port} route={route_label}"
                )
                retried, retry_replay = await self._retry_web_ws_after_empty(
                    reader,
                    writer,
                    dc_hint=dc_hint,
                    is_media=False,
                    target_ip=target_ip,
                    target_port=target_port,
                    init_packet=init_packet,
                    pending_replay=pending_replay,
                    label=label,
                    proto=proto,
                    proto_label=proto_label,
                    replay_limit=524288,
                    first_down_timeout=1.2,
                    failed_route_label=route_label,
                )
                if retried:
                    return True
                replay_initial = retry_replay
            self._note_wss_first_byte_result(dc_hint, False, 0, route_label)
            if int(target_port or 0) == 80 and self._cf_has_recent_good(dc_hint, False, max_age=180.0):
                self.log_func(
                    f"[TgRelay] WSS recent-good dc={dc_hint}; closing empty bootstrap target={target_ip}:{target_port} "
                    f"instead of raw TCP fallback."
                )
                return True
            # Skip TCP fallback when CF domains are available — ISP throttles
            # raw Telegram TCP even through WARP. Let Telegram reconnect via WSS.
            if _cf_route_worth_reconnecting(False):
                self.log_func(
                    f"[TgRelay] WSS empty response; skipping TCP fallback (ISP throttled): proto={proto_label} dc={dc_hint} "
                    f"target={target_ip}:{target_port} replay={len(replay_initial)} duration_ms={duration_ms}"
                )
                return True
            self.log_func(
                f"[TgRelay] WSS empty response; TCP fallback: proto={proto_label} dc={dc_hint} "
                f"target={target_ip}:{target_port} replay={len(replay_initial)} duration_ms={duration_ms}"
            )
            await self._handle_plain_tunnel(
                reader,
                writer,
                target_ip,
                target_port,
                replay_initial,
                label,
                media_hint=False,
            )
        return True

    async def _socks_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, prefetched: bytes = b"") -> Tuple[Optional[str], Optional[int]]:
        # Срок общий на всё рукопожатие, а не на каждое чтение. Раньше здесь у
        # каждого readexactly были свои 5 секунд, поэтому клиент, шлющий по байту
        # раз в четыре секунды, продлевал их бесконечно и держал задачу столько,
        # сколько ему угодно, — ровно та ошибка, о которой G22, и слушатель поднят
        # на 0.0.0.0, то есть доступен из локальной сети. HTTP-ветку на общий срок
        # перевели тогда же, эту забыли.
        deadline = time.monotonic() + _SOCKS_HANDSHAKE_TIMEOUT
        buf = bytearray(prefetched or b"")

        async def take(count: int) -> bytes:
            """Ровно count байт, но не дольше общего срока рукопожатия.

            readexactly, а не read: перебор испортил бы начало туннеля — клиент
            вправе дослать полезную нагрузку сразу за запросом, а вызывающий
            обнуляет prefetched после нас. Остаток от prefetched при этом не
            теряется, он живёт в buf до следующего take.
            """
            if count <= 0:
                return b""
            while len(buf) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                buf.extend(
                    await asyncio.wait_for(
                        reader.readexactly(count - len(buf)), timeout=remaining
                    )
                )
            out = bytes(buf[:count])
            del buf[:count]
            return out

        async def refuse(reply: bytes) -> Tuple[Optional[str], Optional[int]]:
            # G22: отвечаем всегда. Молчащий прокси выглядит зависшим и
            # диагностируется часами.
            with contextlib.suppress(Exception):
                writer.write(reply)
                await writer.drain()
            return None, None

        try:
            header = await take(2)
            if header[0] != 0x05:
                return await refuse(b"\x05\xff")
            methods = await take(header[1])
            if 0x00 not in methods:
                return await refuse(b"\x05\xff")
            writer.write(b"\x05\x00")
            await writer.drain()

            ver, cmd, _, atyp = await take(4)
            if ver != 0x05 or cmd != 0x01:
                return await refuse(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")

            if atyp == 0x01:
                host = socket.inet_ntoa(await take(4))
            elif atyp == 0x03:
                ln = (await take(1))[0]
                host = (await take(ln)).decode("ascii", "ignore")
            elif atyp == 0x04:
                host = str(ipaddress.IPv6Address(await take(16)))
            else:
                return await refuse(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            port = struct.unpack("!H", await take(2))[0]
        except asyncio.TimeoutError:
            # Один ответ на оба способа исчерпать срок — не прислать первый байт
            # и капать по байту до самого дедлайна.
            return await refuse(b"\x05\xff")

        writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.port))
        await writer.drain()
        return host, int(port)

    async def _http_reply(self, writer: asyncio.StreamWriter, status: bytes) -> None:
        try:
            writer.write(
                b"HTTP/1.1 " + status + b"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
        except Exception:
            pass

    async def _http_connect_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        prefetched: bytes = b"",
    ) -> Tuple[Optional[str], Optional[int], bytes]:
        """`CONNECT host:port` — то же назначение, что у SOCKS5, но по HTTP.

        Нужен не ради полноты протоколов. Системный прокси Windows берёт из PAC
        только токены PROXY и SOCKS (SOCKS4); `SOCKS5` он не понимает и молча
        пропускает. Поэтому клиент, стоящий на «использовать системные
        настройки прокси», доходил до Opera на 1371 и до релея не добирался
        никогда. С этой веткой PAC может отдать ему `PROXY 127.0.0.1:1372`, и
        один и тот же слушатель обслуживает оба вида клиентов.

        Возвращает `(host, port, остаток)`. Остаток непуст, когда клиент не стал
        дожидаться «200» и дослал полезную нагрузку следом за заголовками; эти
        байты — уже начало туннеля, и потерять их нельзя.
        """
        head = bytearray(prefetched or b"")
        # Срок общий на всё рукопожатие, а не на отдельное чтение. С таймаутом
        # только внутри wait_for клиент, шлющий по байту раз в четыре секунды,
        # держал бы задачу столько, сколько ему угодно — а слушатель поднят на
        # 0.0.0.0 и доступен из локальной сети.
        deadline = time.monotonic() + _HTTP_HEAD_TIMEOUT
        while _HTTP_HEAD_END not in head:
            if len(head) >= _HTTP_HEAD_MAX:
                await self._http_reply(writer, b"431 Request Header Fields Too Large")
                return None, None, b""
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0:
                    raise asyncio.TimeoutError
                chunk = await asyncio.wait_for(reader.read(1024), timeout=remaining)
            except asyncio.TimeoutError:
                # Один ответ на оба способа исчерпать срок — не дождаться
                # первого байта и капать по байту до самого дедлайна.
                await self._http_reply(writer, b"408 Request Timeout")
                return None, None, b""
            if not chunk:
                return None, None, b""
            head.extend(chunk)
        raw_head, _, rest = bytes(head).partition(_HTTP_HEAD_END)
        request_line = raw_head.split(b"\r\n", 1)[0].decode("latin-1", "ignore").strip()
        parts = request_line.split()
        if len(parts) < 2:
            await self._http_reply(writer, b"400 Bad Request")
            return None, None, b""
        method = parts[0].upper()
        if method != "CONNECT":
            # Абсолютный URI вместо CONNECT — это обычный проксируемый HTTP, а
            # релей умеет только туннель. Отвечаем явно: молчащий прокси
            # выглядит как зависший и диагностируется часами.
            self._log_unsupported_http_method(method)
            await self._http_reply(writer, b"501 Not Implemented")
            return None, None, b""
        host, port = _split_http_authority(parts[1])
        if not host or not port:
            await self._http_reply(writer, b"400 Bad Request")
            return None, None, b""
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        return host, int(port), rest

    async def _read_probe(self, reader: asyncio.StreamReader, want: int = 64, timeout: float = 4.0, initial: bytes = b"") -> bytes:
        data = bytearray(initial or b"")
        deadline = time.time() + float(timeout)
        while len(data) < want:
            remaining = max(0.2, deadline - time.time())
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(want - len(data)), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    async def _probe_native_path(self, dc: int, attempt) -> bool:
        """Returns True when a verdict was recorded, False when unanswerable."""
        label = _wss_egress_label(attempt)
        host = _TG_TCP_FALLBACK_IPS.get(int(dc or 0))
        if not host:
            return False
        try:
            reader, writer, _used = await open_stream(host, 443, timeout=4.0, attempts=[attempt])
        except Exception:
            # The egress itself is not up — right after a restart Opera is still
            # registering with its API. That says nothing about whether Telegram
            # answers through it, so record nothing and ask again next sweep.
            return False
        ok = False
        try:
            writer.write(_build_native_probe(int(dc)))
            await writer.drain()
            ok = bool(await asyncio.wait_for(reader.read(64), timeout=4.0))
        except Exception:
            ok = False
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
        _native_record(int(dc), label, ok)
        return True

    async def _native_probe_loop(self):
        """Ask, rather than wait for a failure, whether native MTProto works.

        Learning only from broken WSS connections meant the better path stayed
        invisible while the worse one kept succeeding. A probe costs one short
        connection per (DC, egress) and only runs while the answer is unknown
        or has expired, so a settled setup makes no traffic at all.
        """
        if not NATIVE_FIRST_ENABLED:
            return
        # Start from the DCs the previous session used. Without this the first
        # sweep has nothing to ask about, live connections reach the decision
        # first, and each one pays the full first-byte timeout on a dead egress
        # before anything is learned — which is exactly the stall this loop
        # exists to prevent.
        with contextlib.suppress(Exception):
            self._seed_seen_dcs_from_cache()
        while not self.stop_event.is_set():
            delay = NATIVE_PROBE_INTERVAL
            with contextlib.suppress(Exception):
                pending = [
                    (dc, attempt)
                    for dc in sorted(self._seen_dcs)
                    for attempt in (_telegram_upstream_attempts() or [])
                    if _native_state(dc, _wss_egress_label(attempt)) is None
                ]
                if pending:
                    # Concurrently: a sequential sweep over several silent
                    # egresses would itself take longer than the interval.
                    results = await asyncio.gather(
                        *(self._probe_native_path(dc, attempt) for dc, attempt in pending),
                        return_exceptions=True,
                    )
                    # Nothing answerable means the egresses are still coming up
                    # after a restart; come back quickly instead of leaving the
                    # relay on WSS for a full interval.
                    delay = NATIVE_PROBE_INTERVAL if any(r is True for r in results) else NATIVE_PROBE_RETRY
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.stop_event.wait(), timeout=delay)

    def _seed_seen_dcs_from_cache(self) -> None:
        path = self._cf_health_cache_path()
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        for key in (payload.get("last_good") or {}):
            dc_text = str(key).split(":", 1)[0].strip()
            if dc_text.isdigit() and int(dc_text) > 0:
                self._seen_dcs.add(int(dc_text))

    async def _maybe_wait_for_warp_bootstrap(self, target_host: str, target_port: int, media_hint=None, dc_hint: int = 0):
        waiter = getattr(self, "warp_bootstrap_waiter", None)
        if not callable(waiter):
            return 0.0
        try:
            return float(
                await asyncio.to_thread(
                    waiter,
                    str(target_host or "").strip(),
                    int(target_port or 0),
                    bool(media_hint),
                    int(dc_hint or 0),
                )
            )
        except Exception:
            return 0.0

    async def _handle_plain_tunnel(self, reader, writer, target_host: str, target_port: int, initial: bytes, label: str, media_hint=None):
        effective_host = str(target_host)
        effective_port = int(target_port)
        route_suffix = ""
        dc_hint = 0
        bootstrap_canonical = False
        try:
            target_ip = await _resolve_ip(target_host)
            if media_hint is None:
                media_hint = _likely_media_target(target_ip, target_port, 0)
            dc_hint = _target_dc_hint(target_ip, bool(media_hint))
            if dc_hint and (bool(media_hint) or int(target_port or 0) == 80) and not _looks_like_http_request(initial):
                fallback_host = _TG_TCP_FALLBACK_IPS.get(int(dc_hint))
                if fallback_host:
                    effective_host = fallback_host
                    effective_port = 443
                    route_suffix = f" orig={target_host}:{target_port} dc={dc_hint}"
                    if int(target_port or 0) == 80:
                        bootstrap_canonical = True
                        route_suffix = f"{route_suffix} bootstrap=canonical-443"
        except Exception:
            pass

        waited_warp = await self._maybe_wait_for_warp_bootstrap(
            effective_host,
            effective_port,
            media_hint=media_hint,
            dc_hint=dc_hint,
        )
        if waited_warp > 0.01:
            route_suffix = f"{route_suffix} wait-warp={waited_warp:.2f}s".rstrip()

        attempts = None
        try:
            from .transport import get_upstream_attempts
            base_attempts = _telegram_upstream_attempts(get_upstream_attempts() or [])
            if base_attempts:
                pref_key = (str(effective_host or "").strip(), int(effective_port or 0))
                pref_route, pref_until = self._route_preference_until.get(pref_key, ("", 0.0))
                if pref_until <= time.monotonic():
                    pref_route = ""
                prefer_direct_key = (int(dc_hint or 0), str(effective_host or "").strip())
                prefer_direct_until = float(self._prefer_direct_until.get(prefer_direct_key, 0.0) or 0.0)
                direct_attempts = [a for a in base_attempts if str(a.get("kind") or "").strip().lower() == "direct"]
                warp_attempts = [a for a in base_attempts if str(a.get("label") or "").strip().lower() == "warp-socks"]
                other_attempts = [
                    a for a in base_attempts
                    if a not in direct_attempts and a not in warp_attempts
                ]
                # Direct Telegram is often provider-shaped on the target networks.
                # Never promote it to first place based on transient WARP stalls.
                if pref_route == "warp-socks":
                    proxy_attempts = warp_attempts + other_attempts
                    attempts = proxy_attempts or direct_attempts
                elif prefer_direct_until > time.monotonic():
                    proxy_attempts = other_attempts + warp_attempts
                    attempts = proxy_attempts or direct_attempts
                else:
                    attempts = base_attempts
        except Exception:
            attempts = None

        connect_timeout = 2.5 if int(dc_hint or 0) in (1, 3, 5) else 6.0
        if bootstrap_canonical:
            connect_timeout = min(connect_timeout, 1.35)

        if not bootstrap_canonical and not _looks_like_http_request(initial):
            ordered_native = _order_native_attempts(attempts or _telegram_upstream_attempts(), dc_hint)
            # Never hand open_stream an empty list: that raises instead of
            # falling back to the provider's own defaults, as attempts=None does.
            if ordered_native:
                attempts = ordered_native

        upstream_reader, upstream_writer, route_label = await open_stream(
            effective_host,
            effective_port,
            timeout=connect_timeout,
            attempts=attempts,
        )
        if initial:
            upstream_writer.write(initial)
            await upstream_writer.drain()
        prefetched_reply = b""
        try:
            pref_key = (str(effective_host or "").strip(), int(effective_port or 0))
            if str(route_label or "").strip().lower() == "warp-socks":
                self._route_preference_until[pref_key] = (str(route_label).strip().lower(), time.monotonic() + 300.0)
        except Exception:
            pass
        if _should_retry_after_stall(bootstrap_canonical, initial, route_label, dc_hint):
            try:
                prefetched_reply = await asyncio.wait_for(
                    upstream_reader.read(1),
                    timeout=(0.45 if bootstrap_canonical else 0.75),
                )
            except asyncio.TimeoutError:
                prefetched_reply = b""
            except Exception:
                prefetched_reply = b""

            if not prefetched_reply:
                with contextlib.suppress(Exception):
                    upstream_writer.close()
                    await upstream_writer.wait_closed()

                retry_attempts = None
                try:
                    from .transport import get_upstream_attempts
                    base_attempts = _telegram_upstream_attempts(get_upstream_attempts() or [])
                    direct_attempts = [a for a in base_attempts if str(a.get("kind") or "").strip().lower() == "direct"]
                    warp_attempts = [a for a in base_attempts if str(a.get("label") or "").strip().lower() == "warp-socks"]
                    other_attempts = [a for a in base_attempts if a not in direct_attempts and a not in warp_attempts]
                    if bootstrap_canonical:
                        proxy_retry_attempts = warp_attempts + other_attempts
                    else:
                        proxy_retry_attempts = other_attempts + warp_attempts
                    retry_attempts = proxy_retry_attempts or direct_attempts
                except Exception:
                    retry_attempts = None

                upstream_reader, upstream_writer, route_label = await open_stream(
                    effective_host,
                    effective_port,
                    timeout=(1.6 if bootstrap_canonical else 3.0),
                    attempts=retry_attempts,
                )
                if initial:
                    upstream_writer.write(initial)
                    await upstream_writer.drain()
                try:
                    pref_key = (str(effective_host or "").strip(), int(effective_port or 0))
                    if str(route_label or "").strip().lower() == "warp-socks":
                        self._route_preference_until[pref_key] = (str(route_label).strip().lower(), time.monotonic() + 300.0)
                except Exception:
                    pass
                route_suffix = f"{route_suffix} retry=after-warp-stall".rstrip()
        self._log_fallback(route_label, effective_host, effective_port, route_suffix)
        if prefetched_reply:
            writer.write(prefetched_reply)
            await writer.drain()
        stats_label = (
            f"path=tcp-fallback route={route_label} target={effective_host}:{effective_port}"
            f"{route_suffix} media={bool(media_hint)}"
        )
        up, down, duration_ms = await _bridge_streams(
            reader,
            writer,
            upstream_reader,
            upstream_writer,
            stats_label=stats_label,
            log_func=self.log_func,
            first_down_timeout=(
                1.15 if bootstrap_canonical
                # An egress not yet proven for this DC gets a short leash. WARP
                # answers TCP and then never delivers a byte, and waiting out
                # the default window on it is what makes a cold start feel dead.
                else 1.5 if (int(dc_hint or 0) > 0 and _native_state(dc_hint, route_label) is not True)
                else 0.0
            ),
        )
        total_down = down + len(prefetched_reply or b"")
        self.log_func(
            f"[TgRelay] TCP fallback closed route={route_label} target={effective_host}:{effective_port}"
            f"{route_suffix} duration_ms={duration_ms} up={up + len(initial or b'')} down={total_down}"
        )
        # Only a tunnel that actually carried MTProto tells us anything: the
        # HTTP transport and the canonical-443 bootstrap are rewritten paths and
        # their silence says nothing about the native route.
        if not bootstrap_canonical and not _looks_like_http_request(initial) and int(dc_hint or 0) > 0:
            _native_record(dc_hint, route_label, total_down > 0)

    def _log_fallback(self, route_label: str, effective_host: str, effective_port: int, route_suffix: str) -> None:
        try:
            suffix_text = str(route_suffix or "")
            if "retry=after-warp-stall" in suffix_text:
                # Retry mode is intentionally opt-in now; if enabled, keep it visible.
                key_suffix = "retry"
            elif "bootstrap=canonical-443" in suffix_text:
                key_suffix = "bootstrap"
            else:
                key_suffix = ""
            key = (
                str(route_label or "").strip().lower(),
                str(effective_host or "").strip().lower(),
                int(effective_port or 0),
                key_suffix,
            )
            now = time.monotonic()
            last = float(self._last_fallback_log.get(key, 0.0) or 0.0)
            if (now - last) < FALLBACK_LOG_INTERVAL:
                return
            self._last_fallback_log[key] = now
        except Exception:
            pass
        self.log_func(f"[TgRelay] TCP fallback route={route_label} target={effective_host}:{effective_port}{route_suffix}")

    def _log_wss_route_unavailable(self, dc_hint: int, target_ip: str, is_media: bool) -> None:
        try:
            key = (int(dc_hint or 0), str(target_ip or "").strip().lower(), bool(is_media))
            now = time.monotonic()
            last = float(self._last_wss_route_log.get(key, 0.0) or 0.0)
            if (now - last) < FALLBACK_LOG_INTERVAL:
                return
            self._last_wss_route_log[key] = now
        except Exception:
            pass
        action = "closing for a clean WSS reconnect" if _cf_route_worth_reconnecting(is_media) else "switching to TCP fallback"
        self.log_func(
            f"[TgRelay] WSS path unavailable for DC{dc_hint} target={target_ip} media={is_media}; {action}."
        )

    def _log_probe_diag(self, reason: str, target_ip: str, target_port: int, init_len: int = 0, dc_hint: int = 0) -> None:
        try:
            key = (str(target_ip or "").strip().lower(), int(target_port or 0), str(reason or ""))
            now = time.monotonic()
            last = float(self._last_probe_diag_log.get(key, 0.0) or 0.0)
            if (now - last) < 8.0:
                return
            self._last_probe_diag_log[key] = now
        except Exception:
            pass
        self.log_func(
            f"[TgRelay] probe diag: reason={reason} dc={dc_hint or '?'} target={target_ip}:{target_port} init_len={int(init_len or 0)}"
        )

    def _cf_note_bad_route_label(
        self,
        route_label: str,
        is_media: bool = False,
        ttl: float = 120.0,
    ) -> bool:
        domain = str(route_label or "").split(" via ", 1)[0].split("@", 1)[0].strip().lower()
        if not domain:
            return False
        try:
            bases = _cf_ws_domain_bases(primary_only=False)
        except Exception:
            bases = []
        for base in bases:
            base = str(base or "").strip().lower()
            if base and (domain == base or domain.endswith("." + base)):
                self._cf_note_bad_domain(domain, bool(is_media), ttl=ttl)
                return True
        return False

    def _cf_empty_route_ttl(self, route_label: str, dc_hint: int, is_media: bool) -> float:
        domain = str(route_label or "").split(" via ", 1)[0].split("@", 1)[0].strip().lower()
        if bool(is_media):
            return float(CF_MEDIA_BAD_TTL)
        ttl = float(CF_EMPTY_DOMAIN_TTL)
        if _cf_domain_base(domain) == "nova-app.eu":
            ttl = max(ttl, float(CF_EMPTY_PRIMARY_TTL))
        if domain:
            try:
                last_domain, last_until = self._cf_last_good_domain.get((int(dc_hint or 0), bool(is_media)), ("", 0.0))
                if domain == str(last_domain or "").strip().lower() and float(last_until or 0.0) > time.monotonic():
                    ttl = max(ttl, float(CF_EMPTY_RECENT_GOOD_TTL))
            except Exception:
                pass
        return ttl

    async def _retry_web_ws_after_empty(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        dc_hint: int,
        is_media: bool,
        target_ip: str,
        target_port: int,
        init_packet: bytes,
        pending_replay: bytes,
        label: str,
        proto: int,
        proto_label: str,
        replay_limit: int,
        first_down_timeout: float,
        failed_route_label: str = "",
    ) -> Tuple[bool, bytes]:
        ws = None
        route_label = ""
        failed_domain = str(failed_route_label or "").split(" via ", 1)[0].split("@", 1)[0].strip().lower()
        excluded_domains = {failed_domain} if failed_domain else None
        if CF_FALLBACK_ENABLED and _has_custom_cfproxy_domain():
            ws, route_label = await self._connect_cf_ws_route(
                dc_hint,
                is_media,
                primary_only=False,
                exclude_domains=excluded_domains,
            )
        if ws is None:
            ws, route_label = await self._connect_ws_route(dc_hint, target_ip, is_media, label, allow_cf=False)
        if ws is None:
            return False, bytes(init_packet or b"") + bytes(pending_replay or b"")
        try:
            splitter = TransparentMsgSplitter(init_packet, int(proto or 0))
            await ws.send(init_packet)
            if pending_replay:
                parts = splitter.split(pending_replay)
                if parts:
                    if len(parts) == 1:
                        await ws.send(parts[0])
                    else:
                        await ws.send_batch(parts)
        except Exception:
            with contextlib.suppress(Exception):
                await ws.close()
            return False, bytes(init_packet or b"") + bytes(pending_replay or b"")

        self.log_func(
            f"[TgRelay] WSS retry: proto={proto_label} dc={dc_hint or '?'} media={bool(is_media)} "
            f"route={route_label} target={target_ip}:{target_port}"
        )
        stats_label = (
            f"path=wss-retry proto={proto_label} dc={dc_hint or '?'} media={bool(is_media)} "
            f"route={route_label} target={target_ip}:{target_port}"
        )
        up, down, duration_ms, replay, first_byte_timed_out = await _bridge_ws(
            reader,
            writer,
            ws,
            splitter,
            replay_limit=int(replay_limit or 0),
            close_writer=False,
            first_down_timeout=float(first_down_timeout or 0.0),
            stats_label=stats_label,
            log_func=self.log_func,
            first_down_callback=lambda down_len, rl=route_label, dc=dc_hint, media=is_media: self._cf_note_good_route_label(
                rl,
                dc,
                media,
                down_len,
            ),
            minimum_down_bytes=(MEDIA_WSS_MIN_PROGRESS if is_media else 1),
        )
        self.log_func(
            f"[TgRelay] WSS retry closed: proto={proto_label} dc={dc_hint or '?'} media={bool(is_media)} "
            f"route={route_label} target={target_ip}:{target_port} duration_ms={duration_ms} "
            f"up={up + len(init_packet or b'') + len(pending_replay or b'')} down={down}"
        )
        media_stalled = bool(
            is_media
            and 0 < int(down or 0) < MEDIA_WSS_MIN_PROGRESS
            and int(duration_ms or 0) >= 1800
            and _cf_owned_zone_available()
        )
        self._note_wss_first_byte_result(dc_hint, is_media, 0 if media_stalled else down, route_label)
        if media_stalled:
            self._cf_note_bad_route_label(route_label, True, ttl=CF_MEDIA_BAD_TTL)
            self.log_func(
                f"[TgRelay] WSS retry media progress stalled: dc={dc_hint or '?'} "
                f"route={route_label} down={down} duration_ms={duration_ms}; reconnecting."
            )
            return True, b""
        if int(down or 0) > 0:
            self._cf_note_good_route_label(route_label, dc_hint, is_media, down)
            return True, b""
        self._cf_note_bad_route_label(
            route_label,
            is_media,
            ttl=self._cf_empty_route_ttl(route_label, dc_hint, is_media),
        )
        return False, bytes(init_packet or b"") + bytes(pending_replay or b"") + bytes(replay or b"")

    async def _connect_ws_route(self, dc_hint: int, target_ip: str, is_media: bool, label: str, allow_cf: bool = True):
        dc_hint = int(dc_hint or 0)
        if dc_hint <= 0:
            return None, ""

        try:
            await self._maybe_wait_for_warp_bootstrap(
                target_ip,
                443,
                media_hint=bool(is_media),
                dc_hint=dc_hint,
            )
        except Exception:
            pass

        # Порядок маршрутов. Ниже уже написана полная развилка: сначала один из
        # двух путей, затем второй (второй CF-заход прикрыт tried_cf_route), так
        # что web-first — это рабочий режим, а не заготовка.
        #
        # Недостижим он был из-за одной строки: `_has_custom_cfproxy_domain()`
        # константно True (config.py всегда добавляет nova-app.eu в список), а
        # значит `custom_cf_first` истинно всегда и ветка выбора по DC никогда не
        # исполнялась. Обе ветки при этом имели одинаковое тело, поэтому само по
        # себе их «оживление» ничего бы не изменило — менять надо было условие.
        #
        # Списки решают, только если оператор задал их явно. Иначе остаётся
        # сегодняшнее поведение: CF первым для всех DC. Без этой оговорки дефолт
        # CF_FIRST_MEDIA_DCS увёл бы медиа DC1 и DC3 на web-first молча.
        cf_order_configured = bool(
            str(os.environ.get("NOVA_TG_RELAY_CF_FIRST_DCS", "") or "").strip()
            or str(os.environ.get("NOVA_TG_RELAY_CF_FIRST_MEDIA_DCS", "") or "").strip()
        )
        # Media goes to Telegram's own web route first and keeps the Worker in
        # reserve — the budget is finite and the free route demonstrably carries
        # media on this network. The exception is a web route already in its
        # first-byte cooldown: trying it ahead of the Worker would only move the
        # stall earlier, and the circuit exists to say exactly that.
        web_first = bool(is_media) and MEDIA_WEB_FIRST and not cf_order_configured
        if web_first and self._wss_first_byte_disabled(dc_hint, is_media, route_kind="web"):
            web_first = False
        if cf_order_configured:
            cf_first = self._cf_first(dc_hint, is_media)
        else:
            cf_first = not web_first
        custom_cf_first = bool(
            allow_cf and CF_FALLBACK_ENABLED and _has_custom_cfproxy_domain() and cf_first
        )
        tried_cf_route = False
        if allow_cf and CF_FALLBACK_ENABLED and (custom_cf_first or cf_first):
            tried_cf_route = True
            ws, route_label = await self._connect_cf_ws_route(dc_hint, is_media, primary_only=False)
            if ws is not None:
                return ws, route_label

        redirect_target = _TG_WS_REDIRECT_IPS.get(dc_hint)
        if redirect_target:
            domains = _ws_domains(dc_hint, is_media)
            ws_attempts = _telegram_upstream_attempts()
            try:
                pooled_ws, pooled_label = await _WS_POOL.get(dc_hint, is_media, redirect_target, domains)
                if pooled_ws is not None:
                    return pooled_ws, pooled_label
            except Exception:
                pass
            for domain in domains:
                try:
                    ws, upstream_label = await asyncio.wait_for(
                        _connect_websocket_target(
                            redirect_target,
                            domain,
                            timeout=(2.5 if is_media else 6.0),
                            attempts=ws_attempts,
                        ),
                        timeout=(3.0 if is_media else 7.0),
                    )
                    _WS_POOL._schedule_refill((int(dc_hint), bool(is_media)), redirect_target, domains)
                    return ws, f"{domain}@{redirect_target} via {upstream_label}"
                except WsHandshakeError as exc:
                    if exc.is_redirect:
                        continue
                    break
                except Exception:
                    break

        if allow_cf and CF_FALLBACK_ENABLED:
            if not tried_cf_route:
                ws, route_label = await self._connect_cf_ws_route(dc_hint, is_media, primary_only=False)
                if ws is not None:
                    return ws, route_label

        self._log_wss_route_unavailable(dc_hint, target_ip, is_media)
        return None, ""

    @staticmethod
    def _cf_first(dc_hint: int, is_media: bool) -> bool:
        try:
            dc = int(dc_hint or 0)
        except Exception:
            return False

        env_val = str(os.environ.get("NOVA_TG_RELAY_CF_FIRST_DCS", "") or "").strip().upper()
        if env_val in ("*", "ALL"):
            return True

        if bool(is_media):
            return dc in CF_FIRST_MEDIA_DCS
        return dc in CF_FIRST_DCS

    @staticmethod
    def _still_pending(task_domains, pending):
        """The subset of the race that has not been dealt with yet."""
        return [(task, domain) for task, domain in task_domains if task in pending]

    async def _cleanup_cf_race_tasks(self, task_domains, is_media: bool) -> None:
        for task, domain in task_domains:
            try:
                _domain, ws, _upstream_label = await task
            except asyncio.CancelledError:
                continue
            except Exception:
                self._cf_note_bad_domain(domain, bool(is_media))
                continue
            with contextlib.suppress(Exception):
                await ws.close()

    async def _connect_cf_ws_route(
        self,
        dc_hint: int,
        is_media: bool = False,
        primary_only: bool = False,
        exclude_domains=None,
    ):
        dc_hint = int(dc_hint or 0)
        excluded = {str(item or "").strip().lower() for item in (exclude_domains or set()) if item}
        domains = _cf_ws_domains_for_bases(
            dc_hint,
            _cf_ws_domain_bases(primary_only=primary_only),
            bool(is_media),
        )
        if excluded:
            domains = [domain for domain in domains if str(domain or "").strip().lower() not in excluded]
        ordered = self._cf_order_domains(
            dc_hint,
            bool(is_media),
            domains,
        )
        if not ordered:
            return None, ""
        pool_key = (int(dc_hint or 0), bool(is_media), bool(primary_only))
        pooled_ws, pooled_label = await self._cf_pool_get(pool_key, ordered)
        if pooled_ws is not None:
            pooled_domain = str(pooled_label or "").split(" via ", 1)[0].strip().lower()
            self.log_func(
                f"[TgRelay] CF/WSS selected: dc={dc_hint} media={bool(is_media)} "
                f"domain={pooled_domain or '?'} source=pool"
            )
            return pooled_ws, pooled_label
        cf_attempts = _cfproxy_upstream_attempts()
        if not cf_attempts:
            return None, ""
        timeout = 2.5 if bool(is_media) else (3.5 if primary_only else 7.0)
        connect_deadline = (
            time.monotonic() + float(CF_MEDIA_CONNECT_BUDGET)
            if bool(is_media)
            else 0.0
        )
        # Media races one deep. The public zones have no `kwsN-1` record at
        # all, so a three-wide race there wins nothing and costs three
        # concurrent dials — each of which can park an egress for 90 s on a
        # failure that belongs to the domain, not to the egress.
        race_width = 1 if bool(is_media) else min(max(1, int(CF_CONNECT_RACE_WIDTH)), len(ordered))

        async def _open_candidate(domain: str):
            ws, upstream_label = await _connect_websocket_target(
                domain,
                domain,
                timeout=timeout,
                attempts=cf_attempts,
            )
            return domain, ws, upstream_label

        batches = []
        remaining = list(ordered)
        if bool(is_media):
            # Do not race the two owned media siblings against each other. The
            # persisted last-good score chooses the first one; its sibling is a
            # sequential fallback, which halves common Worker invocations.
            owned = [item for item in remaining if _cf_domain_base(item) == "nova-app.eu"]
            remaining = [item for item in remaining if item not in owned]
            batches.extend([[item] for item in owned])
        batches.extend(
            remaining[offset:offset + race_width]
            for offset in range(0, len(remaining), race_width)
        )

        for batch in batches:
            task_domains = [
                (asyncio.create_task(_open_candidate(domain)), domain)
                for domain in batch
            ]
            pending = {task for task, _domain in task_domains}
            while pending:
                try:
                    wait_timeout = None
                    if connect_deadline > 0.0:
                        wait_timeout = max(0.0, connect_deadline - time.monotonic())
                        if wait_timeout <= 0.0:
                            for task in pending:
                                task.cancel()
                            # Only what is still in flight. Handing over the whole
                            # list re-awaits the tasks this loop already processed, and
                            # a failed one is charged a second time: measured 1.0 -> 0.25
                            # for a single failure (temp/race_double_bench.py), where one
                            # charge leaves 0.5. The winner path below already filters.
                            asyncio.create_task(self._cleanup_cf_race_tasks(self._still_pending(task_domains, pending), bool(is_media)))
                            return None, ""
                    done, pending = await asyncio.wait(
                        pending,
                        timeout=wait_timeout,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if not done:
                        for task in pending:
                            task.cancel()
                        asyncio.create_task(self._cleanup_cf_race_tasks(self._still_pending(task_domains, pending), bool(is_media)))
                        return None, ""
                except asyncio.CancelledError:
                    asyncio.create_task(self._cleanup_cf_race_tasks(self._still_pending(task_domains, pending), bool(is_media)))
                    raise
                winner = None
                for task in done:
                    domain = next((item for item_task, item in task_domains if item_task is task), "")
                    try:
                        result = task.result()
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        self._cf_note_bad_domain(domain, bool(is_media))
                        continue
                    if winner is None:
                        winner = result
                    else:
                        with contextlib.suppress(Exception):
                            await result[1].close()
                if winner is None:
                    continue
                if pending:
                    asyncio.create_task(
                        self._cleanup_cf_race_tasks(
                            [(task, domain) for task, domain in task_domains if task in pending],
                            bool(is_media),
                        )
                    )
                domain, ws, upstream_label = winner
                self.log_func(
                    f"[TgRelay] CF/WSS selected: dc={dc_hint} media={bool(is_media)} "
                    f"domain={domain} via={upstream_label} source=race width={len(batch)}"
                )
                return ws, f"{domain} via {upstream_label}"
        return None, ""

    def _cf_order_domains(self, dc_hint: int, is_media: bool, domains: List[str]) -> List[str]:
        ordered = self._cf_filter_bad_domains(domains, dc_hint=dc_hint, is_media=is_media)
        if not ordered:
            return []
        now = time.monotonic()
        pref_key = (int(dc_hint or 0), bool(is_media))
        try:
            last_good_domain, last_good_until = self._cf_last_good_domain.get(pref_key, ("", 0.0))
        except Exception:
            last_good_domain, last_good_until = ("", 0.0)
        last_good_domain = str(last_good_domain or "").strip().lower()
        if last_good_until <= now:
            last_good_domain = ""

        def _score(domain: str) -> Tuple[int, float, int]:
            name = str(domain or "").strip().lower()
            score, seen = self._cf_domain_score.get(name, (0.0, 0.0))
            fresh_score = float(score or 0.0) if (now - float(seen or 0.0)) <= CF_RECENT_GOOD_TTL else 0.0
            return (1 if name == last_good_domain else 0, fresh_score, -ordered.index(domain))

        return sorted(ordered, key=_score, reverse=True)

    def _cf_filter_bad_domains(self, domains: List[str], dc_hint: int = 0, is_media: bool = False) -> List[str]:
        ordered = list(domains or [])
        if not ordered:
            return ordered
        now = time.monotonic()
        filtered = []
        for domain in ordered:
            normalized = str(domain or "").strip().lower()
            # A zone whose Worker has spent its daily budget answers every
            # name in it with the same 429. Racing them is a guaranteed loss
            # that still spends the media connect budget, so the zone steps
            # aside whole rather than one domain at a time.
            if _cf_zone_out_of_quota(normalized):
                continue
            if float(self._cf_bad_domain_until.get(normalized, 0.0) or 0.0) > now:
                continue
            filtered.append(domain)
        return filtered

    def _cf_note_bad_domain(self, domain: str, is_media: bool = False, ttl: Optional[float] = None) -> None:
        domain = str(domain or "").strip().lower()
        if not domain:
            return
        ttl = float(ttl if ttl is not None else (CF_MEDIA_BAD_TTL if bool(is_media) else 12.0))
        try:
            self._cf_bad_domain_until[domain] = time.monotonic() + ttl
            score, _seen = self._cf_domain_score.get(domain, (0.0, 0.0))
            self._cf_domain_score[domain] = (max(0.0, float(score or 0.0) * 0.5), time.monotonic())
        except Exception:
            pass

    def _cf_note_good_route_label(self, route_label: str, dc_hint: int, is_media: bool, down: int) -> bool:
        domain = str(route_label or "").split(" via ", 1)[0].split("@", 1)[0].strip().lower()
        if not domain or int(down or 0) <= 0:
            return False
        try:
            bases = _cf_ws_domain_bases(primary_only=False)
        except Exception:
            bases = []
        is_custom = False
        for base in bases:
            base = str(base or "").strip().lower()
            if base and (domain == base or domain.endswith("." + base)):
                is_custom = True
                break
        if not is_custom:
            return False
        now = time.monotonic()
        try:
            self._cf_bad_domain_until.pop(domain, None)
            prev_score, _seen = self._cf_domain_score.get(domain, (0.0, 0.0))
            gain = min(25.0, 2.0 + (int(down or 0).bit_length() / 2.0))
            self._cf_domain_score[domain] = (min(100.0, float(prev_score or 0.0) + gain), now)
            # A tiny media response proves reachability but is not enough to
            # promote the route above a previously sustained download. The end
            # of a useful media bridge will call this again with its full byte count.
            if not bool(is_media) or int(down or 0) >= 4096:
                self._cf_last_good_domain[(int(dc_hint or 0), bool(is_media))] = (domain, now + CF_RECENT_GOOD_TTL)
            self._cf_health_cache_save()
        except Exception:
            pass
        return True

    def _cf_has_recent_good(self, dc_hint: int, is_media: bool, max_age: float = 180.0) -> bool:
        try:
            domain, until = self._cf_last_good_domain.get((int(dc_hint or 0), bool(is_media)), ("", 0.0))
            if not domain:
                return False
            return float(until or 0.0) > (time.monotonic() + (CF_RECENT_GOOD_TTL - float(max_age)))
        except Exception:
            return False

    @staticmethod
    def _warp_preferred_now() -> bool:
        try:
            attempts = _telegram_upstream_attempts()
            if not attempts:
                return False
            first = attempts[0]
            return str(first.get("label") or "").strip().lower() == "warp-socks"
        except Exception:
            return False

    async def _cf_pool_get(self, key, ordered: List[str]):
        now = time.monotonic()
        bucket = self._cf_idle.setdefault(key, deque())
        prefer_warp = self._warp_preferred_now()
        ordered_set = {str(item or "").strip().lower() for item in ordered}
        while bucket:
            ws, created, route_label = bucket.popleft()
            age = now - created
            try:
                transport_closing = bool(ws.writer.transport.is_closing())
            except Exception:
                transport_closing = True
            try:
                pooled_domain = str(route_label or "").split(" via ", 1)[0].split("@", 1)[0].strip().lower()
            except Exception:
                pooled_domain = ""
            if age > WS_POOL_MAX_AGE or getattr(ws, "_closed", False) or transport_closing:
                with contextlib.suppress(Exception):
                    await ws.close()
                continue
            if ordered and pooled_domain and pooled_domain not in ordered_set:
                with contextlib.suppress(Exception):
                    await ws.close()
                continue
            if prefer_warp and " via opera-http" in str(route_label or "").lower():
                with contextlib.suppress(Exception):
                    await ws.close()
                continue
            self._schedule_cf_refill(key, ordered)
            return ws, route_label
        # Do not open a background WSS in parallel with the foreground cold
        # connection below. That used to double Worker invocations whenever a
        # pool was empty. Explicit prewarm and refill-after-consume still keep
        # recently active routes hot.
        return None, ""

    def _schedule_cf_refill(self, key, ordered: List[str]) -> None:
        if key in self._cf_refilling:
            return
        self._cf_refilling.add(key)
        try:
            asyncio.create_task(self._refill_cf_pool(key, list(ordered or [])))
        except Exception:
            self._cf_refilling.discard(key)

    async def _refill_cf_pool(self, key, ordered: List[str]) -> None:
        try:
            bucket = self._cf_idle.setdefault(key, deque())
            if len(bucket) >= 1:
                return
            cf_attempts = _cfproxy_upstream_attempts()
            try:
                dc_hint = int(key[0])
                is_media = bool(key[1])
            except Exception:
                dc_hint = 0
                is_media = False
            for domain in self._cf_filter_bad_domains(ordered, dc_hint=dc_hint, is_media=is_media):
                try:
                    ws, upstream_label = await _connect_websocket_target(
                        domain,
                        domain,
                        timeout=1.5,
                        attempts=cf_attempts,
                    )
                    bucket.append((ws, time.monotonic(), f"{domain} via {upstream_label}"))
                    return
                except Exception:
                    self._cf_note_bad_domain(domain, is_media)
                    continue
        finally:
            self._cf_refilling.discard(key)

    def _schedule_cf_bootstrap_prewarm(self, dc_hint: int, is_media: bool = False, delay: float = 0.5) -> None:
        key = (int(dc_hint or 0), bool(is_media))
        if key in self._cf_prewarm_started:
            return
        self._cf_prewarm_started[key] = time.monotonic()
        try:
            asyncio.create_task(self._prewarm_cf_bootstrap_route(int(dc_hint or 0), bool(is_media), float(delay)))
        except Exception:
            self._cf_prewarm_started.pop(key, None)

    async def _prewarm_cf_bootstrap_route(self, dc_hint: int, is_media: bool = False, delay: float = 0.5) -> None:
        key = (int(dc_hint or 0), bool(is_media))
        try:
            await asyncio.sleep(max(0.0, float(delay)))
            fallback_host = str(_TG_TCP_FALLBACK_IPS.get(int(dc_hint or 0)) or "").strip()
            if fallback_host:
                await self._maybe_wait_for_warp_bootstrap(
                    fallback_host,
                    443,
                    media_hint=is_media,
                    dc_hint=dc_hint,
                )
            ordered = self._cf_order_domains(
                int(dc_hint or 0),
                bool(is_media),
                _cf_ws_domains_for_bases(int(dc_hint or 0), _cf_ws_domain_bases(primary_only=True), bool(is_media)),
            )
            self._schedule_cf_refill((int(dc_hint or 0), bool(is_media), True), ordered)
            await asyncio.sleep(0.05)
        except Exception:
            pass
        finally:
            self._cf_prewarm_started.pop(key, None)
