"""One place that decides what Nova looks like on the wire.

Two things have to agree about which client Nova is pretending to be: the shape
of the TLS ClientHello, and the HTTP request carried inside it. Today they do
not. The handshake announces `Chrome/131` while the TLS layer underneath is
CPython's OpenSSL, which resembles no browser at all — and the two copies of the
upgrade request in this package had already drifted apart from each other, one
sending `Origin` and the other not.

Neither half of that is visible to a DPI box, which sees only the ClientHello.
The reason to fix it anyway is that the profile work has to land somewhere, and
a single profile name driving both layers is the difference between changing
one constant and hunting for every place a browser is impersonated. When the
shaped-TLS crate arrives it selects a name here, and the headers follow.

The header sets below are ordinary and self-consistent, not byte-exact copies of
any particular build. Claiming more than that would be claiming a measurement
nobody has made.
"""

import os
from typing import Dict, List, Optional, Tuple

# Advertising compression we cannot perform would be a silent data corruption
# bug, not a cosmetic one: a `permessage-deflate` frame arrives with RSV1 set
# and a deflated payload, and the frame reader would hand the compressed bytes
# on as though they were MTProto. So the offer is made — every browser makes it,
# and its absence is the kind of detail an endpoint can notice — but the reply
# is checked, and a server that takes us up on it is refused rather than
# misread. See `rejects_us` below and the RSV1 guard in `raw_websocket`.
DEFLATE_OFFER = "permessage-deflate; client_max_window_bits"

_CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

PROFILES: Dict[str, Dict[str, str]] = {
    # Measured, not composed. These are the headers Yandex Browser 26.6
    # (Chromium 148) sent to a local listener on this machine — the same build
    # whose ClientHello became `nova-rs/crates/nova-tls/profiles/yandex-windows.json`.
    # Both halves therefore name one browser, which is the entire point of this
    # module. Refresh them together, with `capture-hello`: point the browser at
    # `http://127.0.0.1:8443/` for these and `https://` for the handshake.
    "yandex-windows": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/148.0.0.0 YaBrowser/26.6.0.0 Safari/537.36"
        ),
        "accept_language": "ru,en;q=0.9",
        # `zstd` is in the real list. Dropping it to match an older guess would
        # be a difference from the browser for no reason.
        "accept_encoding": "gzip, deflate, br, zstd",
    },
    # Deliberately the string that was already in the code. Bumping it to a
    # plausible-looking newer release would be inventing a measurement: a user
    # agent naming a build that never shipped is a worse tell than a stale one.
    # This moves when the TLS profile it belongs to is real and measured.
    "chrome-windows": {
        "user_agent": _CHROME_WINDOWS,
        "accept_language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "accept_encoding": "gzip, deflate, br",
    },
}

# The shaped handshake emits `yandex-windows`, and the two layers must name the
# same browser or the pairing is a tell in itself.
DEFAULT_PROFILE = "yandex-windows"
_active: List[str] = []


def active_profile() -> str:
    """The persona every layer should currently be presenting."""
    if _active:
        return _active[0]
    name = str(os.environ.get("NOVA_TG_PERSONA", "") or "").strip().lower()
    return name if name in PROFILES else DEFAULT_PROFILE


def set_active_profile(name: str) -> str:
    """Point every layer at another persona. Unknown names are ignored.

    Ignoring rather than raising is deliberate: this will be driven by learned
    state read off disk, and a stale name in a config file should degrade to the
    default rather than stop Telegram from connecting.
    """
    name = str(name or "").strip().lower()
    if name in PROFILES:
        _active.clear()
        _active.append(name)
    return active_profile()


def _fields(profile: Optional[str] = None) -> Dict[str, str]:
    return PROFILES.get(profile or active_profile(), PROFILES[DEFAULT_PROFILE])


def upgrade_request(
    path: str,
    host: str,
    ws_key: str,
    subprotocol: str,
    origin: str = "https://web.telegram.org",
    offer_deflate: bool = True,
    profile: Optional[str] = None,
) -> bytes:
    """The WebSocket upgrade request, built once for every caller.

    `host` is what names the route and must stay the real endpoint name — on
    the Cloudflare path it is the Host header, not the SNI, that decides which
    Worker answers.
    """
    fields = _fields(profile)
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Connection: Upgrade",
        "Pragma: no-cache",
        "Cache-Control: no-cache",
        f"User-Agent: {fields['user_agent']}",
        "Upgrade: websocket",
        f"Origin: {origin}",
        "Sec-WebSocket-Version: 13",
        f"Accept-Encoding: {fields['accept_encoding']}",
        f"Accept-Language: {fields['accept_language']}",
        f"Sec-WebSocket-Key: {ws_key}",
    ]
    if offer_deflate:
        lines.append(f"Sec-WebSocket-Extensions: {DEFLATE_OFFER}")
    lines.append(f"Sec-WebSocket-Protocol: {subprotocol}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", "ignore")


def rejects_us(headers: Dict[str, str]) -> str:
    """Why a `101` still cannot be used, or an empty string when it can.

    Only one reason so far, and it is the one that would otherwise corrupt
    silently: a server that accepted the compression offer. Every frame after
    that point arrives deflated, and nothing downstream knows how to inflate it.
    """
    negotiated = str(headers.get("sec-websocket-extensions", "") or "").lower()
    if "permessage-deflate" in negotiated:
        return "server negotiated permessage-deflate, which this client cannot decode"
    return ""


def parse_headers(response_lines: List[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in response_lines:
        if ":" in item:
            key, value = item.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return headers


def status_of(response_lines: List[str]) -> Tuple[int, str]:
    """The status code and the raw status line, tolerant of junk."""
    if not response_lines:
        return 0, ""
    first_line = response_lines[0]
    parts = first_line.split(" ", 2)
    try:
        return (int(parts[1]) if len(parts) >= 2 else 0), first_line
    except ValueError:
        return 0, first_line
