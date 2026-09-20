"""VLESS: parse a `vless://` link (or a sing-box outbound) and render the Xray configuration.

A port of Nova Android's `VlessConfig.kt` + `VlessXrayConfig.kt`, on purpose and nearly line for
line: the two apps consume the same public subscriptions, so a link that works on the phone has to
work here, and a quirk learned on one side is a quirk fixed on both. Field names are the ones of
`tools/xray-core/infra/conf` v26.7.28, the fork both projects vendor.

The division of labour with `bin/nova-xray.exe` is the one wireproxy already has with the AWG
backend: Python decides everything about a node and hands the helper a finished configuration. So
every rule below is under pytest instead of inside a 32 MB binary.

What the real corpus forced (measured 2026-09-20 over 5916 `vless://` lines of
Epodonios/v2ray-configs, the largest Russian-reachable source):

* transports in the wild are `tcp` 41 %, `ws` 36 %, `grpc` 9 %, `xhttp` 11 %, and `security` is
  `reality` 41 %, `tls` 29 %, `none`/absent 30 %. Nothing else appears often enough to matter, but
  `kcp` and `httpupgrade` are cheap to keep;
* `urllib.parse.urlsplit` **cannot** be used: a link whose authority is a bracketed IPv4
  (`@[1.2.3.4]:443`) makes it raise `ValueError` on Python 3.14, and such lines exist. The
  authority is split by hand here;
* 108 of those 5916 lines have a port that is not a number. They are rejected one by one, never by
  failing the whole import;
* parameter names arrive in both cases (`allowInsecure` and `allowinsecure`), so the query is
  lower-cased on parse.
"""

import base64
import binascii
import json
import re
import unicodedata
from urllib.parse import quote, unquote

__all__ = [
    "SCHEME", "NETWORKS", "SECURITIES",
    "VlessNode", "parse_uri", "parse_singbox_text", "parse_many",
    "validate", "build_xray_config", "decode_subscription_body", "safe_profile_name",
]

SCHEME = "vless://"

# Xray renamed its transports and subscriptions mix the old and new names; without one spelling the
# same node changes identity whenever the generator that wrote the link changes.
_NETWORK_ALIASES = {
    "": "tcp", "tcp": "tcp", "raw": "tcp",
    "xhttp": "xhttp", "splithttp": "xhttp",
    "ws": "ws", "websocket": "ws",
    "kcp": "kcp", "mkcp": "kcp",
    "httpupgrade": "httpupgrade",
    "h2": "http", "http": "http",
    "grpc": "grpc",
}
# `http`/`h2` is deliberately absent: the transport was dropped from the core this helper is built
# on, so a link claiming it is rejected by `validate` instead of failing at load time.
NETWORKS = ("tcp", "ws", "grpc", "xhttp", "httpupgrade", "kcp")
SECURITIES = ("none", "tls", "reality")

# REALITY only supports RAW, XHTTP and gRPC (infra/conf/transport_internet.go:101). Over ws,
# httpupgrade or kcp the core refuses the WHOLE configuration, so the tunnel does not merely fail to
# connect -- it never starts, taking a working choice down with it.
REALITY_NETWORKS = ("tcp", "xhttp", "grpc")

# The only flow the core knows (infra/conf/vless.go:49-52); anything else fails the config load.
# Vision rides the TLS record layer, so it is allowed exactly where REALITY-grade transports are.
FLOWS = ("xtls-rprx-vision", "xtls-rprx-vision-udp443")

# XHTTP modes the core accepts. An unknown one fails the load the same way an unknown flow does.
XHTTP_MODES = ("auto", "packet-up", "stream-up", "stream-one")

# Every uTLS fingerprint this core knows (transport/internet/tls/tls.go: PresetFingerprints,
# ModernFingerprints, OtherFingerprints). An unknown name is not ignored by the core -- it is an
# error at config load (infra/conf/transport_security.go:184 and :355), so an unknown `fp` is
# dropped here and the core falls back to its own default instead of refusing to start.
FINGERPRINTS = frozenset((
    "360", "android", "chrome", "edge", "firefox", "ios", "qq", "random", "randomized",
    "randomizednoalpn", "safari", "unsafe",
    "hello360_11_0", "hellochrome_120", "hellochrome_131", "hellochrome_133", "helloedge_106",
    "hellofirefox_120", "hellofirefox_148", "helloios_13", "helloios_14", "helloqq_11_1",
    "hellosafari_26_3",
    "hello360_7_5", "hello360_auto", "helloandroid_11_okhttp", "hellochrome_100",
    "hellochrome_100_psk", "hellochrome_102", "hellochrome_106_shuffle",
    "hellochrome_112_psk_shuf", "hellochrome_114_padding_psk_shuf", "hellochrome_115_pq",
    "hellochrome_115_pq_psk", "hellochrome_120_pq", "hellochrome_58", "hellochrome_62",
    "hellochrome_70", "hellochrome_72", "hellochrome_83", "hellochrome_87", "hellochrome_96",
    "hellochrome_auto", "helloedge_85", "helloedge_auto", "hellofirefox_102", "hellofirefox_105",
    "hellofirefox_55", "hellofirefox_56", "hellofirefox_63", "hellofirefox_65", "hellofirefox_99",
    "hellofirefox_auto", "hellogolang", "helloios_11_1", "helloios_12_1", "helloios_auto",
    "helloqq_auto", "hellorandomized", "hellorandomizedalpn", "hellorandomizednoalpn",
    "hellosafari_16_0", "hellosafari_auto",
))
# REALITY needs a real TLS 1.3 ClientHello, so the escape hatch the TLS path allows is not one here.
_REALITY_FORBIDDEN_FINGERPRINTS = frozenset(("unsafe",))

# Parameters the model has a field for; everything else is kept in `extra` so a link survives
# import and export without losing what this version does not understand yet.
_KNOWN_PARAMS = frozenset((
    "type", "security", "encryption", "sni", "peer", "servername", "fp", "alpn",
    "allowinsecure", "insecure",
    "pbk", "sid", "spx", "path", "host", "servicename", "mode", "headertype", "flow",
    "seed", "quicsecurity", "key",
))

# REALITY needs TLS 1.3. These uTLS profiles imitate clients that only speak TLS 1.2, so the server
# refuses them — and subscriptions are full of them. The value is replaced for the handshake and
# kept verbatim in the record.
_TLS12_ONLY_FINGERPRINTS = frozenset(("android", "360"))

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHORT_ID_RE = re.compile(r"^[0-9a-fA-F]{1,16}$")
_BASE64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/")

# A subscription body is a few megabytes at most; anything past this is not a node list.
MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_NODES = 20000


def _decode(value):
    """Percent-decode one query component.

    `+` is escaped before decoding: `unquote_plus` would turn it into a space, and a `+` inside a
    path, an ALPN list or a REALITY public key is a real character.
    """
    text = str(value or "")
    try:
        return unquote(text.replace("+", "%2B"))
    except (UnicodeDecodeError, ValueError):
        return text


def _encode(value):
    return quote(str(value or ""), safe="")


def _normalize_network(value):
    key = str(value or "").strip().lower()
    return _NETWORK_ALIASES.get(key, key or "tcp")


def _split_host_port(value):
    """`host:port` / `[v6]:port` / `[v4]:port` -> (host, port), or None.

    Hand-rolled rather than `urlsplit`: a bracketed IPv4 authority is illegal by RFC and present in
    real subscriptions, and `urlsplit` raises on it instead of returning something usable.
    """
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith("["):
        close = text.find("]")
        if close < 0:
            return None
        host = text[1:close]
        rest = text[close + 1:]
        if not rest.startswith(":"):
            return None
        port_text = rest[1:]
    else:
        colon = text.rfind(":")
        if colon <= 0:
            return None
        host, port_text = text[:colon], text[colon + 1:]
    try:
        port = int(port_text)
    except (TypeError, ValueError):
        return None
    return (host.strip(), port)


def _parse_query(query):
    """`a=1&b=2` -> `{"a": "1", "b": "2"}`, keys lower-cased, values decoded, order kept."""
    result = {}
    for pair in str(query or "").split("&"):
        if not pair:
            continue
        key, sep, value = pair.partition("=")
        result[_decode(key).strip().lower()] = _decode(value) if sep else ""
    return result


def _is_acceptable_user_id(value):
    """Xray does not require a canonical UUID.

    `common/uuid/uuid.go` ParseString reads 32..36 characters as a UUID and derives a UUIDv5 from
    anything 1..30 characters long; 31, and anything over 36, is refused. Demanding a UUID here
    would silently drop working nodes — Android found two in one Russian list whose id is a
    30-character login.
    """
    text = str(value or "")
    length = len(text)
    if 32 <= length <= 36:
        return bool(_UUID_RE.match(text) or _HEX32_RE.match(text))
    return 1 <= length <= 30


def _base64url_byte_length(value):
    """Bytes a base64url string decodes to, or -1 when it is not base64 at all."""
    symbols = str(value or "").strip().rstrip("=")
    if not symbols:
        return -1
    if any(ch not in _BASE64URL_ALPHABET for ch in symbols):
        return -1
    return (len(symbols) * 6) // 8


class VlessNode(object):
    """One parsed `vless://` node. Immutable in practice; treated as a value."""

    __slots__ = (
        "uuid", "host", "port", "remark",
        "security", "sni", "alpn", "fingerprint", "allow_insecure",
        "reality_public_key", "reality_short_id", "reality_spider_x",
        "network", "path", "host_header", "service_name", "mode", "header_type",
        "flow", "encryption", "extra",
    )

    def __init__(self, uuid, host, port, remark="", security="none", sni="", alpn=(),
                 fingerprint="", allow_insecure=False, reality_public_key="",
                 reality_short_id="", reality_spider_x="", network="tcp", path="",
                 host_header="", service_name="", mode="", header_type="", flow="",
                 encryption="none", extra=None):
        self.uuid = str(uuid or "")
        self.host = str(host or "")
        self.port = int(port)
        self.remark = str(remark or "")
        self.security = str(security or "none").lower()
        self.sni = str(sni or "")
        self.alpn = tuple(str(a).strip() for a in (alpn or ()) if str(a).strip())
        self.fingerprint = str(fingerprint or "")
        self.allow_insecure = bool(allow_insecure)
        self.reality_public_key = str(reality_public_key or "")
        self.reality_short_id = str(reality_short_id or "")
        self.reality_spider_x = str(reality_spider_x or "")
        self.network = _normalize_network(network)
        self.path = str(path or "")
        self.host_header = str(host_header or "")
        self.service_name = str(service_name or "")
        self.mode = str(mode or "")
        self.header_type = str(header_type or "")
        self.flow = str(flow or "")
        self.encryption = str(encryption or "none")
        self.extra = dict(extra or {})

    @property
    def is_reality(self):
        return self.security == "reality"

    @property
    def effective_fingerprint(self):
        """The uTLS fingerprint that can actually complete a REALITY handshake (see the constant)."""
        if not self.is_reality:
            return self.fingerprint
        if self.fingerprint.strip().lower() in _TLS12_ONLY_FINGERPRINTS:
            return "chrome"
        return self.fingerprint or "chrome"

    @property
    def endpoint(self):
        """`host:port` in the form the rest of Nova stores endpoints in."""
        host = self.host
        if ":" in host and not host.startswith("["):
            host = "[" + host + "]"
        return "%s:%d" % (host, self.port)

    @property
    def identity(self):
        """The key a node is recognised by across subscription refreshes.

        The remark is deliberately **not** part of it: providers rename nodes constantly, and a key
        that included the name would make every refresh look like a full replacement. Every
        parameter is, because neighbouring lines in real subscriptions differ only by `fp` or
        `alpn` and a shortened key collapses distinct nodes into one.
        """
        params = {}

        def put(key, value):
            text = str(value or "").strip()
            if text and text != "null":
                params[key] = text

        put("security", self.security)
        put("type", self.network)
        put("sni", self.sni)
        put("fp", self.fingerprint)
        put("alpn", ",".join(self.alpn))
        put("pbk", self.reality_public_key)
        put("sid", self.reality_short_id)
        put("spx", self.reality_spider_x)
        put("path", self.path)
        put("host", self.host_header)
        put("serviceName", self.service_name)
        put("mode", self.mode)
        put("headerType", self.header_type)
        put("flow", self.flow)
        put("encryption", self.encryption)
        if self.allow_insecure:
            put("allowInsecure", "1")
        for key, value in self.extra.items():
            put(key, value)

        head = "%s|%s|%d" % (self.uuid, self.host.lower(), self.port)
        tail = "".join("|%s=%s" % (k, params[k]) for k in sorted(params))
        return head + tail

    @property
    def display_name(self):
        return self.remark.strip() or self.endpoint

    def to_uri(self):
        """Back to a `vless://` link. Round-trips through `parse_uri` for everything parsed here."""
        authority_host = "[%s]" % self.host if ":" in self.host else self.host
        params = []

        def add(key, value):
            text = str(value or "").strip()
            if text:
                params.append((key, text))

        add("type", self.network)
        add("security", self.security)
        add("encryption", self.encryption)
        add("sni", self.sni)
        add("fp", self.fingerprint)
        add("alpn", ",".join(self.alpn))
        if self.allow_insecure:
            add("allowInsecure", "1")
        add("pbk", self.reality_public_key)
        add("sid", self.reality_short_id)
        add("spx", self.reality_spider_x)
        add("path", self.path)
        add("host", self.host_header)
        add("serviceName", self.service_name)
        add("mode", self.mode)
        add("headerType", self.header_type)
        add("flow", self.flow)
        for key, value in self.extra.items():
            add(key, value)

        query = "&".join("%s=%s" % (_encode(k), _encode(v)) for k, v in params)
        base = "vless://%s@%s:%d" % (self.uuid, authority_host, self.port)
        if query:
            base += "?" + query
        if self.remark:
            base += "#" + _encode(self.remark)
        return base

    def to_dict(self):
        """The stored form of a profile file. `v` is there so a later shape can be told apart."""
        return {
            "v": 1,
            "type": "vless",
            "uri": self.to_uri(),
            "remark": self.remark,
            "host": self.host,
            "port": self.port,
            "network": self.network,
            "security": self.security,
            "identity": self.identity,
        }

    def __repr__(self):
        return "VlessNode(%s, %s/%s)" % (self.endpoint, self.network, self.security)

    def __eq__(self, other):
        return isinstance(other, VlessNode) and other.identity == self.identity

    def __hash__(self):
        return hash(self.identity)


def parse_uri(raw):
    """One `vless://` link -> `VlessNode`, or None when it cannot be one.

    None means: not a vless scheme, no `@`, an empty user id, no host, or a port outside 1..65535.
    A link that parses may still be unusable — `validate` says why.
    """
    text = str(raw or "").strip()
    if not text:
        return None
    # Spaces and '|' appear inside remarks in live subscriptions and make the link formally
    # invalid. They are escaped rather than thrown away.
    text = text.replace(" ", "%20").replace("|", "%7C")
    if not text[:len(SCHEME)].lower() == SCHEME:
        return None
    body = text[len(SCHEME):]

    body, sep, fragment = body.partition("#")
    remark = _decode(fragment) if sep else ""

    authority, sep, query = body.partition("?")
    if not sep:
        query = ""

    at = authority.rfind("@")
    if at <= 0:
        return None
    uuid = _decode(authority[:at]).strip()
    if not uuid:
        return None

    # A path may follow host:port (`@host:80/?type=ws`); it carries nothing for VLESS, the real
    # path arrives as the `path` parameter.
    host_port = authority[at + 1:].strip().partition("/")[0]
    split = _split_host_port(host_port)
    if split is None:
        return None
    host, port = split
    if not host or not (1 <= port <= 65535):
        return None

    params = _parse_query(query)

    def param(*names):
        for name in names:
            value = params.get(name)
            if value:
                return value
        return ""

    # `insecure` is the commoner spelling in the wild by a factor of six (69 links against 12 in the
    # corpus this was measured on) and was being read as neither.
    allow_insecure_raw = param("allowinsecure", "insecure")
    return VlessNode(
        uuid=uuid,
        host=host,
        port=port,
        remark=remark,
        security=(param("security") or "none").lower(),
        # "peer" is the retired name of SNI and still turns up in older subscriptions;
        # "servername" is what a sing-box-shaped generator writes.
        sni=param("sni", "peer", "servername"),
        alpn=[a.strip() for a in param("alpn").split(",") if a.strip()],
        fingerprint=param("fp"),
        allow_insecure=allow_insecure_raw == "1" or allow_insecure_raw.lower() == "true",
        reality_public_key=param("pbk"),
        reality_short_id=param("sid"),
        reality_spider_x=param("spx"),
        network=_normalize_network(param("type")),
        path=param("path"),
        host_header=param("host"),
        service_name=param("servicename"),
        mode=param("mode"),
        header_type=param("headertype"),
        flow=param("flow"),
        encryption=param("encryption") or "none",
        extra={k: v for k, v in params.items() if k not in _KNOWN_PARAMS},
    )


def _singbox_outbound(obj):
    """One sing-box outbound object -> `VlessNode`, or None when it is not a VLESS one."""
    if not isinstance(obj, dict):
        return None
    if str(obj.get("type") or "").strip().lower() != "vless":
        return None
    uuid = str(obj.get("uuid") or "").strip()
    host = str(obj.get("server") or "").strip()
    try:
        port = int(obj.get("server_port") or -1)
    except (TypeError, ValueError):
        return None
    if not uuid or not host or not (1 <= port <= 65535):
        return None

    tls = obj.get("tls") if isinstance(obj.get("tls"), dict) else {}
    reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
    utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
    if reality.get("enabled"):
        security = "reality"
    elif tls.get("enabled"):
        security = "tls"
    else:
        security = "none"

    alpn = tls.get("alpn")
    alpn = [str(a).strip() for a in alpn if str(a).strip()] if isinstance(alpn, list) else []

    transport = obj.get("transport") if isinstance(obj.get("transport"), dict) else {}
    headers = transport.get("headers") if isinstance(transport.get("headers"), dict) else {}
    # `Host` is a string in some generators and a one-element array in others. The list has to be
    # unwrapped *before* str(): str(["a"]) is "['a']", which is non-empty, so a later "if it came
    # out empty, try the list" check never runs and the header travels as the repr of a list.
    raw_host = headers.get("Host")
    if raw_host is None:
        raw_host = headers.get("host")
    if isinstance(raw_host, (list, tuple)):
        raw_host = raw_host[0] if raw_host else ""
    host_header = str(raw_host or "").strip()

    return VlessNode(
        uuid=uuid,
        host=host,
        port=port,
        remark=str(obj.get("tag") or "").strip(),
        security=security,
        sni=str(tls.get("server_name") or "").strip(),
        alpn=alpn,
        fingerprint=str(utls.get("fingerprint") or "").strip() if utls.get("enabled") else "",
        allow_insecure=bool(tls.get("insecure")),
        reality_public_key=str(reality.get("public_key") or "").strip(),
        reality_short_id=str(reality.get("short_id") or "").strip(),
        network=_normalize_network(str(transport.get("type") or "")),
        path=str(transport.get("path") or "").strip(),
        host_header=host_header,
        service_name=str(transport.get("service_name") or "").strip(),
        flow=str(obj.get("flow") or "").strip(),
    )


def parse_singbox_text(raw):
    """Every VLESS outbound inside pasted sing-box JSON.

    Accepts a lone object, an array, and a whole config with `"outbounds": [...]` — all three are
    handed out in the wild. An empty list means "there was no sing-box VLESS here", which the
    caller relies on to fall through to link parsing.
    """
    text = str(raw or "").strip()
    if not text:
        return []
    start = -1
    for index, ch in enumerate(text):
        if ch in "{[":
            start = index
            break
    if start < 0:
        return []
    try:
        payload = json.loads(text[start:])
    except (ValueError, RecursionError):
        return []
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        items = payload.get("outbounds") if isinstance(payload.get("outbounds"), list) else [payload]
    else:
        return []
    nodes = []
    for item in items:
        node = _singbox_outbound(item)
        if node is not None:
            nodes.append(node)
    return nodes


def _without_metadata_comments(text):
    """The body with the `#profile-title:`-style header lines removed.

    Providers put them in front of a base64 body, and several of them (`#support-url`,
    `#profile-web-page-url`) carry a URL. A plain "does the body contain ://" test therefore reads
    the whole subscription as a link list and never decodes it — which imports nothing at all.
    """
    kept = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("#") and ":" in stripped:
            continue
        kept.append(line)
    return "\n".join(kept)


def decode_subscription_body(data):
    """A fetched subscription body -> its text, base64 unwrapped when that is what it is.

    Three shapes are handed out today and all three appear among the sources Nova ships with:
    a plain list of links, the same list base64-encoded whole, and sing-box/clash JSON. The
    base64 test is "it decodes and the result contains a scheme", not "it looks like base64" — a
    plain link list is itself almost-valid base64 and would be mangled by a looser test.

    Both alphabets are tried. A panel that hands out the URL-safe one (`-` and `_` where the
    standard has `+` and `/`) is not exotic: decoded with the standard table its bytes come out as
    mojibake with no `://` in them, so the body read as "not base64" and the whole subscription
    imported as zero nodes.
    """
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", "replace")
    else:
        text = str(data or "")
    text = text.lstrip("﻿")
    body = _without_metadata_comments(text)
    stripped = "".join(body.split())
    if not stripped:
        return "" if not "".join(text.split()) else text
    if "://" in body[:4096] or stripped[:1] in "{[":
        return text
    padded = stripped + "=" * (-len(stripped) % 4)
    for table in (None, str.maketrans("-_", "+/")):
        source = padded if table is None else padded.translate(table)
        try:
            decoded = base64.b64decode(source, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            candidate = decoded.decode("utf-8")
        except UnicodeDecodeError:
            candidate = decoded.decode("utf-8", "replace")
        if "://" in candidate:
            return candidate
    return text


def parse_many(raw, limit=MAX_NODES):
    """A whole subscription body -> (`nodes`, `stats`).

    `stats` counts what was skipped and why, because "imported 0 of 4000" with no reason is the
    report that wastes an evening: `total` lines seen, `vless` links found, `other_scheme`
    (vmess/ss/trojan/hysteria2 — not supported here), `bad` (a vless link that would not parse),
    `duplicate`, and `truncated` when `limit` cut the list.

    Metadata comment lines are skipped: barry-far's list opens with `#profile-title:`,
    `#profile-update-interval:`, `#subscription-userinfo:`, `#support-url:` and
    `#profile-web-page-url:`, and a naive parser reports five failures on every refresh.
    """
    text = decode_subscription_body(raw)
    stats = {"total": 0, "vless": 0, "other_scheme": 0, "bad": 0, "duplicate": 0, "truncated": 0}

    nodes = []
    seen = set()

    def take(node):
        if node is None:
            return False
        if len(nodes) >= int(limit):
            stats["truncated"] += 1
            return False
        key = node.identity
        if key in seen:
            stats["duplicate"] += 1
            return False
        seen.add(key)
        nodes.append(node)
        return True

    for node in parse_singbox_text(text):
        stats["vless"] += 1
        take(node)
    if nodes:
        stats["total"] = stats["vless"]
        return nodes, stats

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        stats["total"] += 1
        if line[:len(SCHEME)].lower() != SCHEME:
            if "://" in line:
                stats["other_scheme"] += 1
            else:
                stats["bad"] += 1
            continue
        stats["vless"] += 1
        node = parse_uri(line)
        if node is None:
            stats["bad"] += 1
            continue
        take(node)
    return nodes, stats


def validate(node):
    """A human-readable reason the node will not work, or "" when it looks usable."""
    if node is None:
        return "Профиль не разобран"
    if not _is_acceptable_user_id(node.uuid):
        return "Идентификатор пользователя не подходит: %s" % node.uuid
    if node.network not in NETWORKS:
        return "Неизвестный транспорт type=%s" % node.network
    if node.security not in SECURITIES:
        return "Неизвестное значение security=%s" % node.security
    if node.is_reality:
        if node.network not in REALITY_NETWORKS:
            # Not "will not connect" but "the core refuses the whole configuration" — the tunnel
            # never starts, so a node like this must never be offered.
            return "REALITY работает только с %s, а указан %s" % (
                "/".join(REALITY_NETWORKS), node.network)
        if not node.reality_public_key:
            return "REALITY без публичного ключа (pbk) — подключение невозможно"
        if not node.sni:
            return "REALITY без SNI — сервер не сможет подобрать сертификат"
        short_id = node.reality_short_id
        if short_id and (not _SHORT_ID_RE.match(short_id) or len(short_id) % 2 != 0):
            # sid is the hex of up to 8 bytes, so its length is even.
            return "shortId (sid) должен быть hex чётной длины до 16 символов"
        if _base64url_byte_length(node.reality_public_key) != 32:
            return "публичный ключ (pbk) должен быть 32-байтным X25519 в base64url"
    if node.flow:
        if node.flow.strip().lower() not in FLOWS:
            return "ядро не знает flow=%s" % node.flow
        # Vision works on the TLS record layer: it needs a security layer, and it needs a transport
        # that carries one whole. REALITY + XHTTP + Vision is a legal modern combination and used to
        # be rejected here by a rule that allowed type=tcp only.
        if node.security == "none":
            return "flow=%s требует security=tls или reality" % node.flow
        if node.network not in REALITY_NETWORKS:
            return "flow=%s не работает с type=%s" % (node.flow, node.network)
    encryption = node.encryption
    if encryption and encryption.lower() != "none" and not encryption.lower().startswith("mlkem768"):
        return "неизвестное значение encryption=%s" % encryption
    return ""


def _known_fingerprint(name, for_reality=False):
    """The `fp` value the core will accept, or "" when it would refuse the configuration.

    An unknown fingerprint is not ignored by the core: `infra/conf/transport_security.go` errors out
    at load, taking the whole tunnel with it. Dropping it instead lets the core use its own default,
    which is a working connection rather than none.
    """
    text = str(name or "").strip().lower()
    if not text or text not in FINGERPRINTS:
        return ""
    if for_reality and text in _REALITY_FORBIDDEN_FINGERPRINTS:
        return ""
    return text


def _header_request(node):
    """The HTTP camouflage header for RAW, carrying the link's own host and path.

    Without these the core falls back to its built-in sample values (`www.bing.com` and `/`), so the
    camouflage announces a different site than the one the node was configured for.
    """
    request = {"version": "1.1", "method": "GET", "path": [node.path or "/"]}
    if node.host_header:
        request["headers"] = {"Host": [node.host_header]}
    return request


def _stream_settings(node):
    stream = {}
    # Xray takes the old name `tcp` and the new `raw`; the new one is written.
    network = "raw" if node.network == "tcp" else node.network
    stream["network"] = network

    if node.security == "reality":
        stream["security"] = "reality"
        reality = {
            "serverName": node.sni,
            "publicKey": node.reality_public_key,
        }
        fingerprint = _known_fingerprint(node.effective_fingerprint, for_reality=True)
        if fingerprint:
            reality["fingerprint"] = fingerprint
        if node.reality_short_id:
            reality["shortId"] = node.reality_short_id
        if node.reality_spider_x:
            spider = node.reality_spider_x
            # The core parses spiderX as a URL path and rejects the configuration without the slash.
            reality["spiderX"] = spider if spider.startswith("/") else "/" + spider
        # Post-quantum verification of the REALITY certificate (ML-DSA-65), when the server
        # announced it. Links spell it `pqv`; the core's field is `mldsa65Verify`.
        verify = node.extra.get("pqv") or node.extra.get("mldsa65verify")
        if verify:
            reality["mldsa65Verify"] = verify
        stream["realitySettings"] = reality
    elif node.security == "tls":
        # Without this key the core reads the stream as plain TCP and `tlsSettings` is dead weight:
        # the VLESS handshake then goes out unencrypted and the node refuses it.
        stream["security"] = "tls"
        tls = {"serverName": node.sni or node.host_header or node.host}
        fingerprint = _known_fingerprint(node.fingerprint)
        if fingerprint:
            tls["fingerprint"] = fingerprint
        if node.alpn:
            tls["alpn"] = list(node.alpn)
        # `allowInsecure` is a removed feature: a configuration carrying it fails to load
        # (infra/conf/transport_security.go:362). Its replacements are what the core reads now, and
        # a link that only says "do not verify" gets a verified connection instead of no connection.
        pinned = node.extra.get("pcs")
        if pinned:
            tls["pinnedPeerCertSha256"] = pinned
        by_name = node.extra.get("vcn")
        if by_name:
            tls["verifyPeerCertByName"] = by_name
        stream["tlsSettings"] = tls
    else:
        stream["security"] = "none"

    if network == "raw":
        if node.header_type and node.header_type != "none":
            header = {"type": node.header_type}
            if node.header_type.lower() == "http":
                header["request"] = _header_request(node)
            stream["rawSettings"] = {"header": header}
    elif network == "ws":
        ws = {"path": node.path or "/"}
        if node.host_header:
            ws["host"] = node.host_header
        # WebSocket early data: the core reads the length out of the path's own query.
        early = node.extra.get("ed")
        if early and "ed=" not in ws["path"]:
            joiner = "&" if "?" in ws["path"] else "?"
            ws["path"] = "%s%sed=%s" % (ws["path"], joiner, early)
        header = node.extra.get("eh")
        if header:
            ws["heartbeatPeriod"] = header if isinstance(header, int) else ws.get("heartbeatPeriod", 0)
            if not ws["heartbeatPeriod"]:
                ws.pop("heartbeatPeriod", None)
        stream["wsSettings"] = ws
    elif network == "httpupgrade":
        upgrade = {"path": node.path or "/"}
        if node.host_header:
            upgrade["host"] = node.host_header
        stream["httpupgradeSettings"] = upgrade
    elif network == "grpc":
        grpc = {"serviceName": node.service_name}
        # For gRPC `mode` takes gun and multi — these are not the XHTTP modes.
        if node.mode.lower() == "multi":
            grpc["multiMode"] = True
        # `authority` is the link's own key for it; `host` is the fallback the older generators use.
        authority = node.extra.get("authority") or node.host_header
        if authority:
            grpc["authority"] = authority
        stream["grpcSettings"] = grpc
    elif network == "xhttp":
        # `extra` carries the fine XHTTP settings (xmux, padding, chunk sizes) as JSON. It goes in
        # FIRST: what the link states outright — path, mode, host — is the node's own answer and
        # must win over whatever the blob happens to repeat, which is the opposite of what a plain
        # `update()` does.
        xhttp = {}
        raw_extra = node.extra.get("extra")
        if raw_extra and raw_extra != "null":
            parsed = None
            for attempt in (raw_extra, raw_extra.replace("+", " ")):
                try:
                    parsed = json.loads(attempt)
                except (ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, dict):
                    break
            if isinstance(parsed, dict):
                xhttp.update(parsed)
        xhttp["path"] = node.path or xhttp.get("path") or "/"
        mode = (node.mode or xhttp.get("mode") or "auto").strip().lower()
        # An unknown mode fails the config load; "auto" is what the core would have picked anyway.
        xhttp["mode"] = mode if mode in XHTTP_MODES else "auto"
        if node.host_header:
            xhttp["host"] = node.host_header
        stream["xhttpSettings"] = xhttp
    elif network == "kcp":
        kcp = {}
        if node.header_type:
            kcp["header"] = {"type": node.header_type}
        if node.extra.get("seed"):
            kcp["seed"] = node.extra["seed"]
        stream["kcpSettings"] = kcp
    return stream


def build_xray_config(node, socks_port, socks_host="127.0.0.1", log_level="warning",
                      udp=True, sniffing=True, http_port=0):
    """The Xray configuration `bin/nova-xray.exe run --config` takes: SOCKS5 in, VLESS out.

    A SOCKS5 inbound rather than a TUN: it is what the rest of Nova already speaks — the PAC hands
    browsers `SOCKS5 127.0.0.1:1370` and the helpers dial the same port — so a VLESS node slots in
    beside wireproxy and MASQUE with no change to routing.

    `http_port` adds a second inbound speaking HTTP CONNECT on the same outbound. The primary slot
    does not need it; the reserve slot does, because every consumer of the reserve (tcp_proxy.py,
    the Telegram relay, the app transport plans) dials one HTTP CONNECT port under the frozen label
    `opera-http`. It requires `proxy/http` in the helper's registry — a config the shipped binary
    cannot serve is accepted and then fails at start, so the two must be changed together.

    Sniffing is on so REALITY and TLS see the connection's real SNI instead of only the address the
    SOCKS client asked for; `routeOnly` stays False because there is no routing table here to
    consult, only the one outbound.
    """
    def _sniffing():
        return {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}

    inbound = {
        "tag": "socks-in",
        "listen": str(socks_host or "127.0.0.1"),
        "port": int(socks_port),
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": bool(udp)},
    }
    if sniffing:
        inbound["sniffing"] = _sniffing()
    inbounds = [inbound]
    try:
        http_port = int(http_port or 0)
    except (TypeError, ValueError):
        http_port = 0
    if 0 < http_port < 65536 and http_port != int(socks_port):
        http_inbound = {
            "tag": "http-in",
            "listen": str(socks_host or "127.0.0.1"),
            "port": http_port,
            "protocol": "http",
            "settings": {"allowTransparent": False},
        }
        if sniffing:
            http_inbound["sniffing"] = _sniffing()
        inbounds.append(http_inbound)

    user = {"id": node.uuid, "encryption": node.encryption or "none", "level": 0}
    if node.flow:
        user["flow"] = node.flow

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": node.host, "port": int(node.port), "users": [user]}]},
        "streamSettings": _stream_settings(node),
    }

    return {
        "log": {"loglevel": str(log_level or "warning")},
        "inbounds": inbounds,
        "outbounds": [outbound],
    }


def safe_profile_name(node, fallback="VLESS"):
    """A file-system-safe profile name from the node's remark.

    Remarks carry flags, emoji and path separators; the name becomes a file name in
    `profiles/VLESS/`, so everything Windows refuses is dropped rather than escaped — an escaped
    name is unreadable in the window, and the link itself is kept inside the file.
    """
    text = unicodedata.normalize("NFKC", str(getattr(node, "remark", "") or "")).strip()
    cleaned = []
    for ch in text:
        if ch in '\\/:*?"<>|' or ord(ch) < 32:
            continue
        category = unicodedata.category(ch)
        # Symbols and private-use characters are the emoji and flags every list prefixes names with.
        if category in ("So", "Cn", "Co", "Cs"):
            continue
        cleaned.append(ch)
    name = " ".join("".join(cleaned).split()).strip(" .")
    if not name:
        name = getattr(node, "endpoint", "") or fallback
        name = name.replace(":", "_").replace("[", "").replace("]", "")
    return name[:64] or fallback
