"""Tor for Nova PC: a tor.exe child process, a Nova-managed lyrebird, bridge collection.

Port of Nova Android's Tor transport (`TorTransport.kt`, `TorBridges.kt`) to the
Windows child-process model. Spec: `and-tor.md` §8 and DESIGN §9/§9a.

Process model (option A of the spec)
------------------------------------
* ``nova-lyrebird.exe`` is started by Nova itself with the managed-PT environment
  (``TOR_PT_*``). Its stdin pipe is held open for its whole life: with
  ``TOR_PT_EXIT_ON_STDIN_CLOSE=1`` that pipe is the only parent-death signal lyrebird
  has on Windows. The ``CMETHOD`` it prints becomes
  ``ClientTransportPlugin <t> socks5 127.0.0.1:<port>`` -- no executable path ever
  lands in torrc, so the torrc quoting rules for spaced paths never apply to it.
* ``nova-tor.exe`` gets every path-valued option (DataDirectory, ControlPortWriteToFile,
  CookieAuthFile, Log) on argv. Measured here: tor 0.4.9.12 takes argv through the
  ANSI code page, so a Cyrillic directory arrives as ``????`` and tor cannot open
  anything; the 8.3 short name of the same directory works. `tor_safe_path` does that.
* Both processes sit in a Job Object with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``: if
  Nova crashes or is killed, Windows closes the job handle and takes them down.
  ``tor.pid`` (pid + image path) covers the window before the job assignment; a
  process is only ever killed by pid after its image path was checked -- never by
  image name (that would hit a user's own Tor Browser).

The module is free of Tk and of nova.pyw globals; the network parts take injectable
callables so `tests/test_nova_tor.py` runs without network.
"""

import ctypes
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from urllib.parse import urlsplit

try:
    from nova_temp_log import CappedLog
except ImportError:  # resources/ not on sys.path: fall back to an uncapped writer
    CappedLog = None

__all__ = [
    "TorManager", "BridgeCollector", "ManagedPt", "TorControl", "KillOnCloseJob",
    "ControlError", "ControlReply", "PtError", "TorPathError", "FetchResponse",
    "SOCKS_PORT", "HTTP_PORT", "ENTRY_MODES", "AUTO_ATTEMPTS",
    "normalize_entry", "attempts_for_entry",
    "parse_bridge_line", "explain_bridge_line", "parse_bridge_text", "parse_moat_response",
    "bridge_dial_target", "bridge_is_usable", "is_placeholder_host", "has_control_chars",
    "select_bridges_for_entry", "trim_keeping_every_kind", "count_bridges", "bridges_summary_text",
    "load_builtin_bridges", "load_bridge_store", "save_bridge_store", "bridge_store_is_fresh",
    "read_auto_progress", "note_auto_failure", "clear_auto_progress",
    "render_torrc", "torrc_path_value", "tor_safe_path",
    "parse_control_reply", "parse_control_replies", "read_control_reply",
    "parse_bootstrap_phase", "describe_bootstrap_phase", "parse_control_port_file", "parse_listener_port",
    "parse_pt_line", "socks5_connect_probe", "tcp_connect_probe", "webtunnel_upgrade_probe",
    "requests_fetch", "scrub_proxy_credentials", "redact_proxy_url",
    "terminate_pid_if_image", "query_process_image", "read_pid_file", "write_pid_file",
    "port_is_free",
]

# --------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------

LOG_PREFIX = "[Tor] "

# Fixed ports: the PAC chain for browser=tor is `SOCKS5 127.0.0.1:1375; PROXY 127.0.0.1:1378`
# and a PAC cannot follow a port that moves.
SOCKS_PORT = 1375
HTTP_PORT = 1378

TOR_EXE_NAME = "nova-tor.exe"
LYREBIRD_EXE_NAME = "nova-lyrebird.exe"
PT_CONFIG_NAME = "pt_config.json"
GEOIP_NAME = "geoip"
GEOIP6_NAME = "geoip6"

RUNTIME_DIRNAME = "tor"                      # temp/tor/
TORRC_NAME = "torrc"
TORRC_DEFAULTS_NAME = "torrc-defaults"       # empty on purpose: no foreign defaults apply
DATA_DIRNAME = "data"
PT_STATE_DIRNAME = "pt_state"
TOR_LOG_NAME = "tor.log"
TOR_STDOUT_LOG_NAME = "tor.stdout.log"       # what tor prints before its own Log opens
LYREBIRD_LOG_NAME = "lyrebird.log"
CONTROL_PORT_FILE_NAME = "control_port"
COOKIE_NAME = "cookie"
PID_FILE_NAME = "tor.pid"
BRIDGES_FILE_NAME = "bridges.json"
AUTO_ENTRY_FILE_NAME = "auto_entry.txt"

ENTRY_AUTO = "auto"
ENTRY_WEBTUNNEL = "webtunnel"
ENTRY_OBFS4 = "obfs4"
ENTRY_SNOWFLAKE = "snowflake"
ENTRY_VANILLA = "vanilla"
ENTRY_DIRECT = "direct"
ENTRY_MODES = (ENTRY_AUTO, ENTRY_WEBTUNNEL, ENTRY_OBFS4, ENTRY_SNOWFLAKE, ENTRY_VANILLA, ENTRY_DIRECT)
# Direct is never part of auto: from RU it sticks at `Bootstrapped 10% (conn_done)` (G186).
AUTO_ATTEMPTS = (ENTRY_WEBTUNNEL, ENTRY_OBFS4, ENTRY_SNOWFLAKE, ENTRY_VANILLA)

PT_TRANSPORTS = ("obfs4", "webtunnel", "snowflake")
SUPPORTED_TRANSPORTS = ("obfs4", "webtunnel", "snowflake", "vanilla")
# An enumeration, not a guess from the shape of the line: a vanilla bridge starts
# straight with `[2001:...]:443` and any heuristic eventually eats the address.
KNOWN_TRANSPORTS = frozenset({
    "obfs4", "obfs3", "obfs2", "webtunnel", "snowflake", "meek", "meek_lite",
    "meek-azure", "conjure", "scramblesuit", "dnstt", "vanilla",
})
# The address in these lines is a bridge identifier for tor, not something to dial:
# webtunnel writes 2001:db8::/32 there (G177), snowflake 192.0.2.0/24.
DECORATION_TRANSPORTS = frozenset({"webtunnel", "snowflake"})
PLACEHOLDER_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "0.0.0.0", "2001:db8:", "2001:0db8:")

# tor hands bridge args to an external PT in the SOCKS5 username and password,
# 255 bytes each (RFC 1929). Whatever does not fit is silently lost.
MAX_SOCKS5_ARG_BYTES = 510
# Stock lyrebird passes `max=` straight into `make(chan, max)`: out of range is a
# `makechan: size out of range` crash of the whole PT process (G201).
SNOWFLAKE_MAX_PEERS = 8

# Bootstrap is judged by movement, not by wall time: an attempt fails after
# BOOTSTRAP_TIMEOUT_S without the progress percentage going up, or at the hard cap even
# while it still moves. Measured: cold snowflake sat at 50% (loading_descriptors) for
# 150 s, the same entry with a warm data dir was done in 51 s.
BOOTSTRAP_TIMEOUT_S = 150.0
BOOTSTRAP_HARD_CAP_S = 180.0
BOOTSTRAP_HARD_CAP_SNOWFLAKE_S = 300.0
POLL_INTERVAL_S = 1.0
BOOTSTRAP_REPEAT_S = 30.0
SILENT_POLLS_LIMIT = 10
# Measured inside a running Nova (2026-09-13): tor opened its control listener at once but
# answered nothing for >5 s while it parsed the 26 MB of GeoIP files on a CPU shared with
# winws and the strategy checker. A 5 s budget failed all four entries in a row, so the
# file wait and the first authentication get a minute, retried while tor is alive.
CONTROL_FILE_WAIT_S = 60.0
CONTROL_TIMEOUT_S = 15.0
CONTROL_READY_WAIT_S = 60.0
PT_START_TIMEOUT_S = 10.0
SHUTDOWN_WAIT_S = 3.0
PORT_FREE_WAIT_S = 3.0

# Liveness is SOCKS5 CONNECT success through tor, not an HTTP 200: Cloudflare answers
# Tor exits with challenges (G165), and tor replies success only once the exit opened TCP.
LIVENESS_TARGET = ("1.1.1.1", 443)
LIVENESS_TIMEOUT_S = 12.0
LIVENESS_TRIES_AFTER_BOOTSTRAP = 3
HOLD_POLL_S = 2.0
HOLD_PROBE_EVERY_S = 60.0
HOLD_PROBE_RETRY_S = 15.0
DEAD_CHAIN_FAILURES = 4
DEAD_CHAIN_MIN_S = 30.0
RESTART_LIMIT = 3
RESTART_WINDOW_S = 30 * 60.0

AUTO_MEMORY_FRESH_S = 30 * 60
BRIDGES_FRESH_S = 24 * 3600
# How long a failed collection is left alone. One hour, not one day: the usual reason is that the
# network is down or the sources are blocked right now, and both change.
BRIDGES_FAIL_BACKOFF_S = 3600
KEEP_LIMIT = 40

LYREBIRD_LOG_CAP = 512 * 1024
LYREBIRD_LOG_KEEP = 256 * 1024

MIRROR_BASES = (
    "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/",
    "https://center2055.github.io/OnionHop-Bridges-Collector/bridge/",
    "https://cdn.jsdelivr.net/gh/center2055/OnionHop-Bridges-Collector@main/bridge/",
    "https://cdn.statically.io/gh/center2055/OnionHop-Bridges-Collector@main/bridge/",
)
FALLBACK_BASES = (
    "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/",
    "https://cdn.jsdelivr.net/gh/Delta-Kronecker/Tor-Bridges-Collector@main/bridge/",
)
LIST_FILES = ("obfs4_tested.txt", "webtunnel_tested.txt", "vanilla_tested.txt")
FALLBACK_FILE = "obfs4_tested.txt"
MOAT_SETTINGS_URL = "https://bridges.torproject.org/moat/circumvention/settings"
MOAT_COUNTRY = "ru"
MOAT_TRANSPORTS = ("webtunnel", "obfs4", "snowflake")
HTTP_USER_AGENT = "Nova"
HTTP_TIMEOUT = (10.0, 20.0)
MAX_HTTP_BODY_BYTES = 4 * 1024 * 1024
MIRROR_RACE_TIMEOUT_S = 25.0
SOURCES_PHASE_CAP_S = 180.0
PROBE_LIMIT_PER_TRANSPORT = 16
PROBE_LIMIT_WEBTUNNEL = 8
PROBE_TIMEOUT_S = 6.0
PROBE_WORKERS = 8
PROBE_BUDGET_S = 60.0
RENDEZVOUS_PROBE_TIMEOUT_S = 4.0
RENDEZVOUS_PROBE_LIMIT = 3
WEBTUNNEL_PROBE_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
# A collection is bounded by its own phases (sources cap + probe budget); waiting for one
# that is already running uses that bound plus a margin, and stops early on a stop.
BRIDGE_WAIT_S = SOURCES_PHASE_CAP_S + PROBE_BUDGET_S + 60.0
# An entry without stored bridges does not start another forced collection when one
# finished this recently: it would ask the same sources again (TOR-6).
RECOLLECT_PAUSE_S = 300.0

# Fallback only when bin/tor/pt_config.json is missing or unparseable (DESIGN §9a):
# snowflake v2.14.1 `client/torrc`, identical to Nova Android's SNOWFLAKE_CDN77.
_SNOWFLAKE_ICE_ANDROID = (
    "ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,"
    "stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,"
    "stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443"
)
SNOWFLAKE_CDN77_FALLBACK = (
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ "
    "fronts=www.cdn77.com,www.phpmyadmin.net " + _SNOWFLAKE_ICE_ANDROID + " utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA "
    "fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ "
    "fronts=www.cdn77.com,www.phpmyadmin.net " + _SNOWFLAKE_ICE_ANDROID + " utls-imitate=hellorandomizedalpn",
)
# The rendezvous fallback set: Google's AMP cache fronted at www.google.com. Same two
# fingerprints as the primary set, so only one set ever goes into torrc.
SNOWFLAKE_AMP = (
    "snowflake 192.0.2.5:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net/ "
    "ampcache=https://cdn.ampproject.org/ front=www.google.com " + _SNOWFLAKE_ICE_ANDROID
    + " utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.6:80 8838024498816A039FCBBAB14E6F40A0843051FA "
    "fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net/ "
    "ampcache=https://cdn.ampproject.org/ front=www.google.com " + _SNOWFLAKE_ICE_ANDROID
    + " utls-imitate=hellorandomizedalpn",
)

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_IS_WINDOWS = sys.platform == "win32"


class TorPathError(Exception):
    """A runtime path tor.exe cannot open (non-ASCII without an 8.3 short name)."""


class ControlError(Exception):
    """Control-port failure: connection, protocol or a non-2xx reply."""


class PtError(Exception):
    """The managed pluggable transport did not come up."""


class _Stopped(Exception):
    """The worker was asked to stop; unwinds to the worker loop."""


class _AttemptFailed(Exception):
    """An attempt step failed; the message is the Russian detail for the log."""


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------

_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/@]+@")


def scrub_proxy_credentials(text):
    """Remove `user:password@` from every URL inside a text (logs are published, I19)."""
    return _USERINFO_RE.sub(r"\1", str(text))


def redact_proxy_url(url):
    """Proxy URL without userinfo -- same rule as nova.pyw `_redact_proxy_url`."""
    text = str(url or "")
    scheme, sep, rest = text.partition("://")
    if not sep:
        return text
    return "{}://{}".format(scheme, rest.rpartition("@")[2] or rest)


def _short_error(exc, limit=200):
    text = scrub_proxy_credentials("{}: {}".format(type(exc).__name__, exc))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _now_ms(now=None):
    return int((time.time() if now is None else float(now)) * 1000)


def _atomic_write_text(path, text):
    """UTF-8 without BOM, `\\n` line ends, tmp + os.replace."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    os.replace(tmp, path)


def _remove_file(path):
    """Delete a file; returns an error text or "" (missing counts as removed)."""
    try:
        os.remove(path)
    except FileNotFoundError:
        return ""
    except OSError as exc:
        return _short_error(exc)
    return ""


def normalize_entry(value):
    text = str(value or "").strip().lower()
    return text if text in ENTRY_MODES else ENTRY_AUTO


def attempts_for_entry(entry):
    mode = normalize_entry(entry)
    return list(AUTO_ATTEMPTS) if mode == ENTRY_AUTO else [mode]


def port_is_free(port, host="127.0.0.1"):
    """True when nobody listens on host:port (exclusive bind test)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            sock.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        sock.bind((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()


# --------------------------------------------------------------------------------------
# Bridges: parsing and filtering
# --------------------------------------------------------------------------------------

def has_control_chars(text):
    """ISO control characters (Java `isISOControl`): C0, DEL and C1.

    A newline inside a network-sourced bridge line would turn one `Bridge` record into
    "a bridge plus any directive", e.g. `SocksPort 0.0.0.0:9050` (G174).
    """
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in str(text))


_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
# In torrc a trailing backslash continues the line into the next `Bridge` record, `#`
# starts a comment and a value that opens with `"` is read as a C string. No real bridge
# line contains any of them.
_TORRC_UNSAFE_CHARS = frozenset('\\#"')


def parse_bridge_endpoint(text):
    """`1.2.3.4:443` or `[2001:db8::1]:443` -> (host, port), else None.

    Mirrors tor's `tor_addr_port_parse` for a Bridge line: an IP literal (a hostname is a
    configuration error), IPv6 only in brackets (unbracketed, tor reads the port as part
    of the address), port 1..65535. A scope id (`%eth0`) is refused as tor refuses it.
    """
    host, sep, port_text = str(text or "").rpartition(":")
    # The length check comes before int(): Python refuses to convert over 4300 digits.
    if not sep or not port_text.isdigit() or len(port_text) > 5 or not 1 <= int(port_text) <= 65535:
        return None
    if "%" in host:
        return None
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return None
        return host[1:-1], int(port_text)
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return None
    return host, int(port_text)


def _is_key_value(token):
    """tor's `string_is_key_value`: at least `k=`, an `=` present, not in first position."""
    return len(token) >= 2 and "=" in token and not token.startswith("=")


def explain_bridge_line(raw):
    """Parse one bridge line -> (bridge dict or None, rejection reason or "").

    Formats: `<transport> <addr:port> [FPR] <k=v>...` and vanilla `<addr:port> [FPR]`.
    Whatever passes here also passes tor's own `parse_bridge_line`: one line tor refuses
    makes the whole torrc invalid and costs every bridge of the entry.
    Reasons: empty, control, non_ascii, syntax, unsupported, sqs, endpoint, fingerprint,
    args_too_long, max. Never raises.
    """
    line = str(raw if raw is not None else "").strip(" \t\r\n")
    if not line or line.startswith("#"):
        return None, "empty"
    if has_control_chars(line):
        return None, "control"
    if not line.isascii():
        # Real bridge lines are ASCII; anything else would reach tor as ANSI garbage.
        return None, "non_ascii"
    if any(ch in _TORRC_UNSAFE_CHARS for ch in line):
        return None, "syntax"
    body = line
    if len(line) > 7 and line[:7].lower() == "bridge ":
        body = line[7:].strip(" ")
    parts = body.split()
    if not parts:
        return None, "empty"
    first = parts[0].lower()
    has_transport = first in KNOWN_TRANSPORTS
    transport = first if has_transport else "vanilla"
    if transport not in SUPPORTED_TRANSPORTS:
        return None, "unsupported"
    lowered = [part.lower() for part in parts]
    # G199: snowflake's SQS rendezvous next to a broker URL ends in log.Fatalln inside
    # lyrebird -- one line from the network would kill every transport it serves.
    if any(part.startswith("sqsqueue=") or part.startswith("sqscreds=") for part in lowered):
        return None, "sqs"
    rest = parts[1:] if has_transport else parts
    if not rest or parse_bridge_endpoint(rest[0]) is None:
        return None, "endpoint"
    endpoint = rest[0]
    tail = rest[1:]
    fingerprint = ""
    if transport in PT_TRANSPORTS:
        # tor: the token after the address is socks args when it is k=v, else the
        # fingerprint; everything after that must be k=v.
        args_tokens = tail
        if tail and not _is_key_value(tail[0]):
            if not _FINGERPRINT_RE.match(tail[0]):
                return None, "fingerprint"
            fingerprint = tail[0].upper()
            args_tokens = tail[1:]
        if not all(_is_key_value(token) for token in args_tokens):
            return None, "syntax"
        # Before any per-argument parsing: bounds every value that is converted below.
        if len(";".join(args_tokens).encode("utf-8")) > MAX_SOCKS5_ARG_BYTES:
            return None, "args_too_long"
        if transport == "snowflake":
            for token in args_tokens:
                if token.lower().startswith("max="):
                    value = token[4:]
                    if not (value.isdigit() and len(value) <= 2 and 1 <= int(value) <= SNOWFLAKE_MAX_PEERS):
                        return None, "max"
    else:
        # tor joins every token after a vanilla address into the fingerprint, so a spaced
        # `4C17 FB53 ...` is valid and anything else there is a configuration error.
        joined = "".join(tail)
        if joined:
            if not _FINGERPRINT_RE.match(joined):
                return None, "fingerprint"
            fingerprint = joined.upper()
    url = next((part[4:] for part in tail if part.startswith("url=")), "")
    if first == "vanilla":
        # `vanilla` is our kind name, not a tor transport: tor would want a plugin for it.
        body = " ".join(rest)
    bridge_id = "{}|{}".format(transport, fingerprint or endpoint)
    return {
        "transport": transport,
        "line": body,
        "endpoint": endpoint,
        "fingerprint": fingerprint,
        "url": url,
        "id": bridge_id,
    }, ""


def parse_bridge_line(raw):
    return explain_bridge_line(raw)[0]


_REJECT_TEXT = {
    "control": "управляющие символы",
    "non_ascii": "символы вне ASCII",
    "syntax": "строка не по формату tor",
    "unsupported": "транспорт не поддерживается",
    "sqs": "рандеву snowflake через SQS",
    "endpoint": "нет адреса IP:порт",
    "fingerprint": "отпечаток не из 40 hex-цифр",
    "max": "max= вне 1..{}".format(SNOWFLAKE_MAX_PEERS),
    "args_too_long": "аргументы длиннее {} Б".format(MAX_SOCKS5_ARG_BYTES),
}


def _explain_listed_line(raw):
    """explain_bridge_line for a line inside a batch: one bad line never drops the batch."""
    try:
        return explain_bridge_line(raw)
    except ValueError:
        return None, "syntax"


def _describe_rejections(rejected):
    parts = ["{} — {}".format(_REJECT_TEXT.get(reason, reason), count)
             for reason, count in sorted(rejected.items()) if reason != "empty" and count]
    return ", ".join(parts)


def parse_bridge_text(text):
    """Bridge lines out of a list body -> (bridges, {reason: count}).

    Split on `\\n` only: `str.splitlines` would also cut at \\x85 or \\x1c and let the
    halves of a poisoned line pass the control-character rule separately.
    """
    bridges, rejected = [], {}
    for raw in str(text or "").split("\n"):
        bridge, reason = _explain_listed_line(raw)
        if bridge is None:
            rejected[reason] = rejected.get(reason, 0) + 1
        else:
            bridges.append(bridge)
    return bridges, rejected


def parse_moat_response(obj):
    """`settings[i].bridges.bridge_strings[j]` of a Moat answer -> (bridges, rejected)."""
    bridges, rejected = [], {}
    settings = obj.get("settings") if isinstance(obj, dict) else None
    if not isinstance(settings, list):
        return bridges, rejected
    for setting in settings:
        block = setting.get("bridges") if isinstance(setting, dict) else None
        strings = block.get("bridge_strings") if isinstance(block, dict) else None
        if not isinstance(strings, list):
            continue
        for raw in strings:
            bridge, reason = _explain_listed_line(raw if isinstance(raw, str) else "")
            if bridge is None:
                rejected[reason] = rejected.get(reason, 0) + 1
            else:
                bridges.append(bridge)
    return bridges, rejected


def is_placeholder_host(host):
    clean = str(host or "").strip()
    if not clean:
        return False
    if clean in ("::", "::1"):
        return True
    lowered = clean.lower()
    return any(lowered.startswith(prefix) for prefix in PLACEHOLDER_PREFIXES)


def bridge_dial_target(bridge):
    """(host, port) a TCP probe may dial, or None (decoration or placeholder address)."""
    if bridge.get("transport") in DECORATION_TRANSPORTS:
        return None
    host, sep, port_text = str(bridge.get("endpoint") or "").rpartition(":")
    if not sep:
        return None
    host = host.strip("[]")
    if not host or not port_text.isdigit() or len(port_text) > 5:
        return None
    port = int(port_text)
    if not 1 <= port <= 65535 or is_placeholder_host(host):
        return None
    return host, port


def bridge_is_usable(bridge):
    return bridge.get("transport") in DECORATION_TRANSPORTS or bridge_dial_target(bridge) is not None


def bridge_arg(bridge, name):
    prefix = name + "="
    for part in str(bridge.get("line") or "").split():
        if part.lower().startswith(prefix):
            return part[len(prefix):]
    return ""


def select_bridges_for_entry(bridges, mode):
    """Bridges that may go into torrc for an entry mode (G174 re-checked here)."""
    return [
        bridge for bridge in bridges
        if bridge.get("transport") == mode
        and not has_control_chars(bridge.get("line", ""))
        and bridge_is_usable(bridge)
    ]


def trim_keeping_every_kind(bridges, limit=KEEP_LIMIT):
    """Keep `limit` bridges round-robin across kinds so a rare kind (snowflake) survives."""
    items = list(bridges)
    if len(items) <= limit:
        return items
    queues = {}
    for bridge in items:
        queues.setdefault(bridge.get("transport", ""), deque()).append(bridge)
    result = []
    while len(result) < limit and any(queues.values()):
        for pending in queues.values():
            if len(result) >= limit:
                break
            if pending:
                result.append(pending.popleft())
    return result


def count_bridges(bridges):
    counts = {}
    for bridge in bridges:
        kind = bridge.get("transport", "")
        counts[kind] = counts.get(kind, 0) + 1
    return {kind: counts[kind] for kind in SUPPORTED_TRANSPORTS if counts.get(kind)}


def bridges_summary_text(bridges):
    counts = count_bridges(bridges)
    detail = ", ".join("{} {}".format(kind, n) for kind, n in counts.items())
    total = sum(counts.values())
    return "живых мостов {} ({})".format(total, detail) if total else "живых мостов нет"


def load_builtin_bridges(tor_dir):
    """Builtin bridges from Tor Browser's `pt_config.json` next to the binaries.

    Returns {"obfs4": [...], "snowflake": [...], "source": str, "error": str}. The
    Android snowflake lines are used only when the file gives no snowflake line.
    """
    path = os.path.join(str(tor_dir), PT_CONFIG_NAME)
    result = {"obfs4": [], "snowflake": [], "source": PT_CONFIG_NAME, "error": ""}
    data = None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        result["error"] = "нет файла {}".format(PT_CONFIG_NAME)
    except (OSError, ValueError) as exc:
        result["error"] = "{} не читается: {}".format(PT_CONFIG_NAME, _short_error(exc))
    section = data.get("bridges") if isinstance(data, dict) else None
    if data is not None and not isinstance(section, dict):
        result["error"] = "в {} нет раздела bridges".format(PT_CONFIG_NAME)
    if isinstance(section, dict):
        for kind in ("obfs4", "snowflake"):
            lines = section.get(kind)
            if not isinstance(lines, list):
                continue
            for raw in lines:
                bridge = parse_bridge_line(raw) if isinstance(raw, str) else None
                if bridge is not None and bridge["transport"] == kind:
                    result[kind].append(bridge)
    if not result["snowflake"]:
        result["snowflake"] = [b for b in map(parse_bridge_line, SNOWFLAKE_CDN77_FALLBACK) if b]
        result["source"] = "{} + встроенные строки snowflake Nova".format(PT_CONFIG_NAME)
    return result


# --------------------------------------------------------------------------------------
# Bridge store (temp/tor/bridges.json -- public lines only) and auto-entry memory
# --------------------------------------------------------------------------------------

def load_bridge_store(path):
    """-> {"bridges", "updated_at" (ms), "source", "last_error", "readable"}; empty when missing.

    Every stored line is parsed again: the file is outside our control once written,
    and G174 must hold for whatever is in it.

    `readable` is False only when the file exists and could not be **opened** -- a lock, an
    antivirus scan, a sharing violation. That is not the same as "there are no bridges", and the
    difference costs the whole list: the failed-collection branch of `_refresh_store` writes the
    snapshot it was given straight back, so an empty snapshot from a momentary OSError erased a
    good file and left the install with no bridges at all. A file that opens and parses to
    nonsense is a different thing -- it really is corrupt, and replacing it is right.
    """
    snapshot = {"bridges": [], "updated_at": 0, "attempted_at": 0, "source": "", "last_error": "",
                "readable": True}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return snapshot
    except OSError as exc:
        # The reason is named: "не открылся" alone leaves whoever reads the report guessing
        # between a lock, an antivirus and a permission problem.
        snapshot["last_error"] = "файл мостов не открылся: {}".format(type(exc).__name__)
        snapshot["readable"] = False
        return snapshot
    except ValueError:
        snapshot["last_error"] = "файл мостов повреждён"
        return snapshot
    if not isinstance(data, dict):
        return snapshot
    seen = set()
    for item in data.get("bridges") or []:
        if not isinstance(item, dict) or not isinstance(item.get("line"), str):
            continue
        bridge = parse_bridge_line(item["line"])
        if bridge is None or bridge["id"] in seen:
            continue
        seen.add(bridge["id"])
        snapshot["bridges"].append(bridge)
    for key in ("updated_at", "attempted_at"):
        try:
            snapshot[key] = int(data.get(key) or 0)
        except (TypeError, ValueError):
            snapshot[key] = 0
    snapshot["source"] = str(data.get("source") or "")
    snapshot["last_error"] = str(data.get("last_error") or "")
    return snapshot


def save_bridge_store(path, snapshot):
    if snapshot.get("readable") is False:
        # The caller is about to write back what it could not read. Refusing here rather than in
        # every caller keeps the rule in one place: a snapshot that never held the file's contents
        # may not replace them.
        raise OSError("список мостов не читался — перезаписывать его нечем")
    payload = {
        "version": 1,
        "updated_at": int(snapshot.get("updated_at") or 0),
        # When the last collection was attempted, whether or not it produced anything. Kept apart
        # from `updated_at`, which answers "how old is this list".
        "attempted_at": int(snapshot.get("attempted_at") or 0),
        "source": str(snapshot.get("source") or ""),
        "last_error": str(snapshot.get("last_error") or ""),
        "bridges": [
            {key: bridge.get(key, "") for key in ("transport", "line", "endpoint", "fingerprint", "url")}
            for bridge in snapshot.get("bridges") or []
        ],
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=1))


def bridge_store_is_fresh(snapshot, now=None):
    if not snapshot.get("bridges"):
        return False
    age_ms = _now_ms(now) - int(snapshot.get("updated_at") or 0)
    return 0 <= age_ms < BRIDGES_FRESH_S * 1000


def bridge_collection_backing_off(snapshot, now=None):
    """True while a failed collection should be left alone.

    A failed run deliberately keeps the previous `updated_at`, so the list stays due and the next
    trigger collects again. That is right for one retry and wrong as a policy: the background
    issuance pipeline pokes every 30 minutes for as long as Nova runs, and a full collection is
    minutes of fetching and probing. On a network where the bridge sources are simply unreachable
    -- which is the network Tor is wanted on -- that became a permanent background load with
    nothing to show for it. A separate stamp is kept for the attempt, so a failure backs off
    without making the list look fresh.
    """
    attempted = int((snapshot or {}).get("attempted_at") or 0)
    if attempted <= 0 or not (snapshot or {}).get("last_error"):
        return False
    age_ms = _now_ms(now) - attempted
    return 0 <= age_ms < BRIDGES_FAIL_BACKOFF_S * 1000


def read_auto_progress(path, now=None):
    """Entry modes auto already failed with, within the last 30 minutes.

    Line 1 is an epoch-ms stamp, then one failed mode per line. A stale or future
    stamp deletes the file and reads as empty (G197: without memory a restart re-runs
    webtunnel forever).
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    lines = [line.strip() for line in raw.split("\n") if line.strip()]
    if not lines or not lines[0].isdigit() or len(lines[0]) > 19:
        return []
    age_ms = _now_ms(now) - int(lines[0])
    if not 0 <= age_ms < AUTO_MEMORY_FRESH_S * 1000:
        _remove_file(path)
        return []
    result = []
    for mode in lines[1:]:
        if mode in AUTO_ATTEMPTS and mode not in result:
            result.append(mode)
    return result


def note_auto_failure(path, mode, now=None):
    """Remember that auto failed with `mode` (raises OSError on a write failure)."""
    modes = read_auto_progress(path, now=now)
    if mode not in modes:
        modes.append(mode)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _atomic_write_text(path, "\n".join([str(_now_ms(now))] + modes) + "\n")


def clear_auto_progress(path):
    return _remove_file(path)


# --------------------------------------------------------------------------------------
# torrc
# --------------------------------------------------------------------------------------

TORRC_HEADER = "# Written by Nova PC. Regenerated on every Tor connect; manual edits do not survive."


def torrc_path_value(path):
    """A path as a torrc value: always quoted, backslashes escaped.

    Not forward slashes, measured: tor 0.4.9.12 on Windows calls `D:/x/geoip`
    "relative" and writes a [warn] on every start (it still resolves it). A value
    starting with `"` is a C-escaped string, so `\\` is doubled; quoting always also
    covers spaces (`Nova PC`) and `#`, which would start a comment unquoted.
    """
    text = str(path).replace("/", "\\")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


_LOOPBACK_ADDR_RE = re.compile(r"^127\.0\.0\.1:(\d{1,5})$")


def render_torrc(mode, *, socks_port=SOCKS_PORT, http_port=HTTP_PORT, bridges=(), transport_addr="",
                 geoip_file="", geoip6_file=""):
    """torrc text for one concrete entry mode (auto is expanded by the caller).

    Paths that tor must open are passed on argv (see module docstring); the only paths
    here are the GeoIP files, already converted with `tor_safe_path` by the caller.
    Raises ValueError for anything that must never reach tor.
    """
    if mode not in ENTRY_MODES or mode == ENTRY_AUTO:
        raise ValueError("неизвестный вход Tor: {!r}".format(mode))
    lines = [
        TORRC_HEADER,
        "ClientOnly 1",
        "SocksPort 127.0.0.1:{}".format(int(socks_port)),
    ]
    if http_port:
        lines.append("HTTPTunnelPort 127.0.0.1:{}".format(int(http_port)))
    lines += [
        "SocksPolicy accept 127.0.0.0/8",
        "SocksPolicy reject *",
        "ControlPort 127.0.0.1:auto",
        "CookieAuthentication 1",
        "DormantCanceledByStartup 1",
    ]
    if geoip_file:
        lines.append("GeoIPFile " + torrc_path_value(geoip_file))
    if geoip6_file:
        lines.append("GeoIPv6File " + torrc_path_value(geoip6_file))
    if mode == ENTRY_DIRECT:
        lines.append("UseBridges 0")
        return "\n".join(lines) + "\n"
    bridge_lines = []
    for bridge in bridges:
        line = str(bridge.get("line") or "")
        # G174, second check: at write time, whatever the list went through before.
        if not line or has_control_chars(line) or not line.isascii():
            raise ValueError("строка моста с управляющими символами не пишется в torrc")
        if bridge.get("transport") != mode:
            raise ValueError("мост {} попал во вход {}".format(bridge.get("transport"), mode))
        bridge_lines.append("Bridge " + line)
    if not bridge_lines:
        raise ValueError("для входа {} нет ни одного моста".format(mode))
    if mode in PT_TRANSPORTS:
        match = _LOOPBACK_ADDR_RE.match(str(transport_addr or ""))
        if not match or not 1 <= int(match.group(1)) <= 65535:
            raise ValueError("адрес транспорта {} не на 127.0.0.1: {!r}".format(mode, transport_addr))
        lines.append("ClientTransportPlugin {} socks5 {}".format(mode, transport_addr))
    lines.append("UseBridges 1")
    lines += bridge_lines
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------
# Windows process plumbing (ctypes)
# --------------------------------------------------------------------------------------

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
_PROCESS_TERMINATE = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_STILL_ACTIVE = 259
_WAIT_OBJECT_0 = 0
_ERROR_INVALID_PARAMETER = 87

_kernel32_lock = threading.Lock()
_kernel32_cache = []


def _kernel32():
    """A private kernel32 instance with declared prototypes (does not touch ctypes.windll)."""
    if not _IS_WINDOWS:
        raise OSError("только для Windows")
    with _kernel32_lock:
        if _kernel32_cache:
            return _kernel32_cache[0]
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
        k32.SetInformationJobObject.restype = wintypes.BOOL
        k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        k32.AssignProcessToJobObject.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = (wintypes.HANDLE,)
        k32.CloseHandle.restype = wintypes.BOOL
        k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
        k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        k32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        k32.TerminateProcess.restype = wintypes.BOOL
        k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        k32.WaitForSingleObject.restype = wintypes.DWORD
        k32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        k32.GetExitCodeProcess.restype = wintypes.BOOL
        k32.GetShortPathNameW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
        k32.GetShortPathNameW.restype = wintypes.DWORD
        _kernel32_cache.append(k32)
        return k32


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class KillOnCloseJob:
    """A Job Object whose processes die when its last handle closes.

    Nova keeps the handle for its lifetime; a crash or a taskkill of Nova closes it
    and Windows terminates tor and lyrebird with it.
    """

    def __init__(self):
        self._handle = None
        self._lock = threading.Lock()

    def _ensure_locked(self):
        if self._handle:
            return self._handle
        k32 = _kernel32()
        handle = k32.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = k32.SetInformationJobObject(handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                                         ctypes.byref(info), ctypes.sizeof(info))
        if not ok:
            error = ctypes.get_last_error()
            k32.CloseHandle(handle)
            raise ctypes.WinError(error)
        self._handle = handle
        return handle

    def assign(self, proc):
        """Put a `subprocess.Popen` child into the job. Raises OSError on failure."""
        process_handle = getattr(proc, "_handle", None)
        if not process_handle:
            raise OSError("у процесса нет дескриптора")
        with self._lock:
            job = self._ensure_locked()
            if not _kernel32().AssignProcessToJobObject(job, int(process_handle)):
                raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        """Close the job handle -- every process still inside is terminated."""
        with self._lock:
            handle, self._handle = self._handle, None
        if handle:
            _kernel32().CloseHandle(handle)


def query_process_image(pid):
    """Full image path of a live process, or None when it is gone or not accessible."""
    if not _IS_WINDOWS:
        return None
    from ctypes import wintypes
    k32 = _kernel32()
    handle = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if not k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return None
        return buf.value
    finally:
        k32.CloseHandle(handle)


def _same_path(a, b):
    return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))


def terminate_pid_if_image(pid, allowed_images, wait_s=SHUTDOWN_WAIT_S):
    """Kill a pid only when its image is one of `allowed_images`.

    Returns "gone" | "mismatch" | "killed" | "failed: <reason>". Never kills by name.
    """
    if not _IS_WINDOWS:
        return "failed: только для Windows"
    from ctypes import wintypes
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return "failed: неверный pid"
    if pid <= 0:
        return "failed: неверный pid"
    k32 = _kernel32()
    access = _PROCESS_QUERY_LIMITED_INFORMATION | _PROCESS_TERMINATE | _SYNCHRONIZE
    handle = k32.OpenProcess(access, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == _ERROR_INVALID_PARAMETER:
            return "gone"
        return "failed: OpenProcess {}".format(error)
    try:
        code = wintypes.DWORD(0)
        if k32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != _STILL_ACTIVE:
            return "gone"
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if not k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return "failed: QueryFullProcessImageNameW {}".format(ctypes.get_last_error())
        if not any(_same_path(buf.value, image) for image in allowed_images):
            return "mismatch"
        if not k32.TerminateProcess(handle, 1):
            return "failed: TerminateProcess {}".format(ctypes.get_last_error())
        k32.WaitForSingleObject(handle, int(max(0.0, wait_s) * 1000))
        return "killed"
    finally:
        k32.CloseHandle(handle)


def write_pid_file(path, records):
    """records: [{"role", "pid", "image"}]."""
    payload = {"version": 1, "processes": [
        {"role": str(r.get("role", "")), "pid": int(r.get("pid", 0)), "image": str(r.get("image", ""))}
        for r in records
    ]}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _atomic_write_text(path, json.dumps(payload, ensure_ascii=False))


def read_pid_file(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    result = []
    for item in (data.get("processes") if isinstance(data, dict) else None) or []:
        if not isinstance(item, dict):
            continue
        try:
            pid = int(item.get("pid"))
        except (TypeError, ValueError):
            continue
        result.append({"role": str(item.get("role", "")), "pid": pid, "image": str(item.get("image", ""))})
    return result


def _short_path_name(path):
    if not _IS_WINDOWS:
        return None
    k32 = _kernel32()
    size = 1024
    while True:
        buf = ctypes.create_unicode_buffer(size)
        needed = k32.GetShortPathNameW(str(path), buf, size)
        if needed == 0:
            return None
        if needed < size:
            return buf.value
        size = needed + 1


def tor_safe_path(path, created_by_tor=False):
    """A spelling of `path` tor.exe can open.

    tor reads argv and opens files through the ANSI code page (measured: a Cyrillic
    directory reaches it as `????`). ASCII paths pass unchanged; others become the
    8.3 short name of the path (or of its existing parent plus an ASCII file name).
    `created_by_tor`: always spell it as short(parent) + name -- the short name of a
    file that is deleted and re-created (`CONTRO~1` for `control_port`) would make
    tor write a file under that literal name.
    Raises TorPathError when no ASCII spelling exists (8.3 names disabled on the volume).
    """
    full = os.path.abspath(str(path))
    if full.isascii():
        return full
    candidate = None
    if os.path.exists(full) and not created_by_tor:
        candidate = _short_path_name(full)
    else:
        parent, name = os.path.split(full)
        if name.isascii():
            short_parent = _short_path_name(parent)
            if short_parent:
                candidate = os.path.join(short_parent, name)
    if candidate and candidate.isascii():
        return candidate
    raise TorPathError(
        "путь «{}» содержит символы вне ASCII, а короткого имени 8.3 у него нет — "
        "nova-tor.exe не сможет открыть свои файлы".format(full)
    )


# --------------------------------------------------------------------------------------
# Control port
# --------------------------------------------------------------------------------------

class ControlReply:
    """One control-port reply: final status and every line of it."""

    __slots__ = ("status", "entries")

    def __init__(self, status, entries):
        self.status = int(status)
        # (code, separator, text, data): data is the dot-terminated block of a `+` line.
        self.entries = list(entries)

    @property
    def ok(self):
        return 200 <= self.status < 300

    def message(self):
        return " | ".join(text for _code, _sep, text, _data in self.entries if text)

    def values(self):
        """GETINFO-style `key=value` pairs (`+` blocks give the block as the value)."""
        result = {}
        for code, _sep, text, data in self.entries:
            if code != 250 or "=" not in text:
                continue
            key, _, value = text.partition("=")
            result[key] = data if data is not None else value
        return result


_MAX_CONTROL_LINE = 1 << 20


def read_control_reply(readline, skip_async=True):
    """Read one reply through `readline()` (str without CRLF, or None at EOF).

    Mid lines `NNN-`, data lines `NNN+` followed by a block ending in `.` (leading dots
    doubled on the wire), end line `NNN `. Asynchronous 6xx replies are skipped.
    """
    while True:
        entries = []
        while True:
            line = readline()
            if line is None:
                raise ControlError("управляющее соединение закрылось посреди ответа")
            if len(line) < 4 or not line[:3].isdigit() or line[3] not in " -+":
                raise ControlError("непонятная строка ответа tor: {!r}".format(line[:80]))
            code, sep, text = int(line[:3]), line[3], line[4:]
            data = None
            if sep == "+":
                chunks = []
                while True:
                    chunk = readline()
                    if chunk is None:
                        raise ControlError("управляющее соединение закрылось посреди блока данных")
                    if chunk == ".":
                        break
                    chunks.append(chunk[1:] if chunk.startswith(".") else chunk)
                data = "\n".join(chunks)
            entries.append((code, sep, text, data))
            if sep == " ":
                break
        status = entries[-1][0]
        if skip_async and 600 <= status < 700:
            continue
        return ControlReply(status, entries)


def parse_control_replies(text, skip_async=True):
    """Every complete reply in a captured control-port transcript."""
    lines = str(text).replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    position = [0]

    def readline():
        if position[0] >= len(lines):
            return None
        line = lines[position[0]]
        position[0] += 1
        return line

    replies = []
    while position[0] < len(lines):
        try:
            replies.append(read_control_reply(readline, skip_async=skip_async))
        except ControlError:
            if position[0] >= len(lines):
                break
            raise
    return replies


def parse_control_reply(text):
    replies = parse_control_replies(text)
    if not replies:
        raise ControlError("в тексте нет ни одного ответа")
    return replies[0]


class TorControl:
    """Plain-socket control connection with cookie authentication."""

    def __init__(self, port, host="127.0.0.1", timeout=CONTROL_TIMEOUT_S):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self._lock = threading.RLock()
        self._sock = None
        self._file = None

    @property
    def connected(self):
        return self._sock is not None

    def connect(self):
        with self._lock:
            self._close_locked()
            try:
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            except OSError as exc:
                raise ControlError("порт управления {} не принимает соединение: {}".format(
                    self.port, _short_error(exc))) from exc
            sock.settimeout(self.timeout)
            self._sock = sock
            self._file = sock.makefile("rb")

    def _readline(self):
        raw = self._file.readline(_MAX_CONTROL_LINE)
        if not raw:
            return None
        if not raw.endswith(b"\n"):
            raise ControlError("строка ответа tor длиннее {} байт или оборвана".format(_MAX_CONTROL_LINE))
        return raw.rstrip(b"\r\n").decode("utf-8", "replace")

    def command(self, line):
        text = str(line)
        if "\r" in text or "\n" in text:
            raise ValueError("перевод строки внутри команды управления")
        with self._lock:
            if self._sock is None:
                raise ControlError("нет соединения с портом управления")
            try:
                self._sock.sendall(text.encode("ascii") + b"\r\n")
                return read_control_reply(self._readline)
            except OSError as exc:
                # A timeout leaves the buffered reader in an undefined state: drop it.
                self._close_locked()
                raise ControlError("порт управления: {}".format(_short_error(exc))) from exc
            except ControlError:
                self._close_locked()
                raise

    def authenticate_cookie(self, cookie):
        cookie = bytes(cookie)
        if len(cookie) != 32:
            raise ControlError("cookie управления не 32 байта ({})".format(len(cookie)))
        reply = self.command("AUTHENTICATE " + cookie.hex().upper())
        if not reply.ok:
            raise ControlError("tor не принял cookie: {} {}".format(reply.status, reply.message()))

    def getinfo(self, *keys):
        reply = self.command("GETINFO " + " ".join(keys))
        if not reply.ok:
            raise ControlError("GETINFO {}: {} {}".format(" ".join(keys), reply.status, reply.message()))
        return reply.values()

    def signal(self, name):
        reply = self.command("SIGNAL " + str(name))
        if not reply.ok:
            raise ControlError("SIGNAL {}: {} {}".format(name, reply.status, reply.message()))

    def _close_locked(self):
        sock, handle = self._sock, self._file
        self._sock = None
        self._file = None
        for closable in (handle, sock):
            if closable is None:
                continue
            try:
                closable.close()
            except OSError:
                pass  # closing an already-broken connection: nothing left to release

    def close(self):
        with self._lock:
            self._close_locked()


_KV_RE = re.compile(r'([A-Za-z_]+)=("(?:[^"\\]|\\.)*"|\S*)')


def parse_bootstrap_phase(value):
    """`GETINFO status/bootstrap-phase` -> dict.

    Example: `NOTICE BOOTSTRAP PROGRESS=25 TAG=enough_dirinfo SUMMARY="Loading ..."`;
    a WARN phase adds WARNING/REASON/RECOMMENDATION. Done on PROGRESS=100 or TAG=done.
    """
    text = str(value or "").strip()
    result = {"severity": "", "progress": -1, "tag": "", "summary": "", "warning": "",
              "reason": "", "recommendation": "", "done": False, "raw": text}
    if not text:
        return result
    head = text.split(" ", 1)[0]
    if head in ("NOTICE", "WARN", "ERR"):
        result["severity"] = head
    for key, raw in _KV_RE.findall(text):
        val = raw
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            val = re.sub(r"\\(.)", r"\1", raw[1:-1])
        key = key.upper()
        if key == "PROGRESS":
            result["progress"] = int(val) if val.isdigit() and len(val) <= 3 else -1
        elif key in ("TAG", "SUMMARY", "WARNING", "REASON", "RECOMMENDATION"):
            result[key.lower()] = val
    result["done"] = result["progress"] == 100 or result["tag"] == "done"
    return result


def describe_bootstrap_phase(phase):
    progress = phase.get("progress", -1)
    text = "загрузка {}%".format(progress if progress >= 0 else "?")
    if phase.get("tag"):
        text += " ({})".format(phase["tag"])
    if phase.get("summary"):
        text += " — " + phase["summary"]
    if phase.get("warning"):
        text += "; предупреждение: {}".format(phase["warning"])
        if phase.get("reason"):
            text += " [{}]".format(phase["reason"])
    return text


def parse_control_port_file(text):
    """`PORT=127.0.0.1:NNNN` (ControlPortWriteToFile, measured) -> port or None."""
    match = re.search(r"PORT=127\.0\.0\.1:(\d{1,5})\b", str(text or ""))
    if not match:
        return None
    port = int(match.group(1))
    return port if 1 <= port <= 65535 else None


def parse_listener_port(value):
    """`GETINFO net/listeners/socks` value (`"127.0.0.1:1375"`) -> last port or None."""
    matches = re.findall(r":(\d{1,5})", str(value or ""))
    if not matches:
        return None
    port = int(matches[-1])
    return port if 1 <= port <= 65535 else None


# --------------------------------------------------------------------------------------
# Managed pluggable transport
# --------------------------------------------------------------------------------------

def parse_pt_line(line):
    """One stdout line of a managed PT -> (kind, fields)."""
    text = str(line or "").strip()
    word, _, rest = text.partition(" ")
    if word == "CMETHOD":
        parts = rest.split()
        if len(parts) >= 3:
            return "cmethod", {"name": parts[0], "proto": parts[1], "addr": parts[2]}
        return "other", {"text": text}
    if word == "CMETHOD-ERROR":
        name, _, message = rest.partition(" ")
        return "cmethod-error", {"name": name, "message": message.strip()}
    if word == "CMETHODS" and rest.strip() == "DONE":
        return "done", {}
    if word in ("ENV-ERROR", "VERSION-ERROR", "PROXY-ERROR"):
        return "fatal", {"message": text}
    if word == "VERSION":
        return "version", {"version": rest.strip()}
    if word in ("LOG", "STATUS"):
        return word.lower(), {"text": rest}
    return "other", {"text": text}


class _PlainLog:
    """Fallback when nova_temp_log is not importable: truncate once, append lines."""

    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._handle = open(path, "w", encoding="utf-8", newline="")
        self._lock = threading.Lock()

    def write(self, message):
        with self._lock:
            if self._handle is None:
                return
            self._handle.write(str(message).rstrip("\n") + "\n")
            self._handle.flush()

    def close(self):
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None


class ManagedPt:
    """`nova-lyrebird.exe` run as a managed client transport (pt-spec, option A)."""

    def __init__(self, exe_path, transports, state_dir, log_path, *, log=None, spawn=None, cwd=None):
        self.exe_path = str(exe_path)
        self.transports = [str(t) for t in transports]
        self.state_dir = str(state_dir)
        self.log_path = str(log_path)
        self.cwd = cwd
        self.methods = {}
        self.proc = None
        self._log = log or (lambda _msg: None)
        self._spawn = spawn or (lambda argv, **kwargs: subprocess.Popen(argv, **kwargs))
        self._lines = queue.Queue()
        self._handshake_done = threading.Event()
        self._reader = None
        self._file_log = None
        # stop() may come from the owner's teardown while start() is still in the handshake
        # on the worker thread (which calls stop() itself on failure): one at a time.
        self._stop_lock = threading.Lock()

    def start(self, timeout=PT_START_TIMEOUT_S):
        """Spawn and wait for `CMETHODS DONE`. Returns {transport: "127.0.0.1:port"}."""
        if not os.path.isfile(self.exe_path):
            raise PtError("не найден {}".format(os.path.basename(self.exe_path)))
        try:
            os.makedirs(self.state_dir, exist_ok=True)
        except OSError as exc:
            raise PtError("папка состояния транспорта не создаётся: {}".format(_short_error(exc))) from exc
        try:
            if CappedLog is not None:
                self._file_log = CappedLog(self.log_path, LYREBIRD_LOG_CAP, LYREBIRD_LOG_KEEP, truncate=True)
            else:
                self._file_log = _PlainLog(self.log_path)
        except OSError as exc:
            self._file_log = None
            self._log("лог {} не открывается ({}) — вывод транспорта не сохраняется".format(
                LYREBIRD_LOG_NAME, _short_error(exc)))
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("TOR_PT_")}
        env.update({
            "TOR_PT_MANAGED_TRANSPORT_VER": "1",
            "TOR_PT_CLIENT_TRANSPORTS": ",".join(self.transports),
            "TOR_PT_STATE_LOCATION": self.state_dir,
            # Without this lyrebird has no parent-death detection on Windows at all.
            "TOR_PT_EXIT_ON_STDIN_CLOSE": "1",
        })
        try:
            self.proc = self._spawn(
                [self.exe_path],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=env, cwd=self.cwd, creationflags=_NO_WINDOW,
            )
        except OSError as exc:
            self._close_file_log()
            raise PtError("{} не запустился: {}".format(os.path.basename(self.exe_path), _short_error(exc))) from exc
        except BaseException:
            # e.g. the owner refused the spawn because a stop arrived: release the log, re-raise.
            self._close_file_log()
            raise
        self._reader = threading.Thread(target=self._drain, name="NovaTorPtReader", daemon=True)
        self._reader.start()

        deadline = time.monotonic() + float(timeout)
        methods, errors = {}, {}
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                self.stop()
                raise PtError("не выдал CMETHODS DONE за {:.0f} с".format(float(timeout)))
            try:
                item = self._lines.get(timeout=left)
            except queue.Empty:
                continue
            if item is None:
                code = self._wait_exit(1.0)
                self.stop()
                raise PtError("завершился до CMETHODS DONE (код {})".format(code))
            kind, fields = parse_pt_line(item)
            if kind == "cmethod":
                match = _LOOPBACK_ADDR_RE.match(fields["addr"])
                if fields["proto"] != "socks5":
                    errors[fields["name"]] = "протокол {} вместо socks5".format(fields["proto"])
                elif not match or not 1 <= int(match.group(1)) <= 65535:
                    errors[fields["name"]] = "адрес не на 127.0.0.1: {}".format(fields["addr"])
                else:
                    methods[fields["name"]] = fields["addr"]
            elif kind == "cmethod-error":
                errors[fields["name"]] = fields["message"] or "CMETHOD-ERROR"
            elif kind == "fatal":
                self.stop()
                raise PtError(fields["message"])
            elif kind == "done":
                break
        missing = [t for t in self.transports if t not in methods]
        if missing:
            self.stop()
            raise PtError("; ".join("{}: {}".format(t, errors.get(t, "нет CMETHOD")) for t in missing))
        self._handshake_done.set()
        self.methods = methods
        return dict(methods)

    def _wait_exit(self, seconds):
        try:
            return self.proc.wait(seconds)
        except subprocess.TimeoutExpired:
            return None

    def _drain(self):
        stream = self.proc.stdout
        try:
            while True:
                raw = stream.readline(8192)
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if not self._handshake_done.is_set():
                    self._lines.put(line)
                self._write_file_log(line)
        except (OSError, ValueError) as exc:
            self._write_file_log("чтение вывода транспорта прервано: {}".format(_short_error(exc)))
        finally:
            self._lines.put(None)
            try:
                stream.close()
            except OSError:
                pass  # the pipe is already gone; nothing else depends on this close

    def _write_file_log(self, line):
        target = self._file_log
        if target is not None:
            target.write(time.strftime("%H:%M:%S ") + line)

    def _close_file_log(self):
        target, self._file_log = self._file_log, None
        if target is not None:
            target.close()

    def poll(self):
        return None if self.proc is None else self.proc.poll()

    def stop(self, wait_s=2.0):
        """Close stdin (the PT's exit signal), then kill by handle if it lingers. Idempotent."""
        with self._stop_lock:
            proc = self.proc
            if proc is None:
                self._close_file_log()
                return None
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass  # a broken or already closed stdin pipe already is the exit signal we meant to send
            if proc.poll() is None:
                try:
                    proc.wait(wait_s)
                except subprocess.TimeoutExpired:
                    self._log("{} не вышел после закрытия stdin за {:.0f} с — завершаем принудительно".format(
                        os.path.basename(self.exe_path), wait_s))
                    proc.kill()
                    try:
                        proc.wait(wait_s)
                    except subprocess.TimeoutExpired:
                        self._log("{} не завершился даже после TerminateProcess".format(
                            os.path.basename(self.exe_path)))
            reader = self._reader
            if reader is not None and reader is not threading.current_thread():
                reader.join(1.0)
            self._close_file_log()
            return proc.returncode


# --------------------------------------------------------------------------------------
# Network probes and fetch
# --------------------------------------------------------------------------------------

class FetchResponse:
    __slots__ = ("status", "headers", "text")

    def __init__(self, status, headers, text):
        self.status = int(status)
        self.headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        self.text = str(text or "")


def requests_fetch(method, url, *, headers=None, data=None, proxy=None, timeout=HTTP_TIMEOUT,
                   max_bytes=MAX_HTTP_BODY_BYTES):
    """HTTP through `requests` with no environment proxies (trust_env=False).

    "Direct" must really be direct: on Windows `requests` would otherwise pick up a
    system ProxyServer. Raises OSError subclasses (requests.RequestException) on failure.
    """
    import requests  # bundled in the frozen app; imported lazily for the tests
    session = requests.Session()
    session.trust_env = False
    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        response = session.request(method, url, headers=headers, data=data, proxies=proxies,
                                   timeout=timeout, stream=True, allow_redirects=True)
        try:
            chunks, total = [], 0
            if max_bytes > 0:
                for chunk in response.iter_content(65536):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= max_bytes:
                        break
            body = b"".join(chunks)[: max(0, max_bytes)]
            try:
                text = body.decode(response.encoding or "utf-8", "replace")
            except LookupError:
                text = body.decode("utf-8", "replace")
            return FetchResponse(response.status_code, dict(response.headers), text)
        finally:
            response.close()
    finally:
        session.close()


# Bridge lines come from public lists, and a list may name any address. Without this rule a
# poisoned list would make every Nova probe loopback or the LAN: a port scan of the user's own
# network run from the user's machine. Probes therefore dial only addresses that are public
# (`is_global`) -- all of a name's addresses, not the first -- and dial the checked address itself,
# so a second DNS answer cannot swap in a private one between the check and the connect.
# Tests talk to local servers and switch the rule off; nothing else may.
_PROBE_PRIVATE_TARGETS_ALLOWED = False


def _public_probe_targets(host, port):
    """[(family, sockaddr), ...] for `host`, or [] when it resolves to anything that is not public."""
    host = str(host or "").strip().strip("[]")
    if not host:
        return []
    try:
        infos = socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError):
        return []
    targets = []
    for family, _socktype, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        try:
            address = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        except ValueError:
            return []
        if not (address.is_global or _PROBE_PRIVATE_TARGETS_ALLOWED):
            return []
        if (family, sockaddr) not in targets:
            targets.append((family, sockaddr))
    return targets


def _connect_public(host, port, timeout):
    """A connected socket to a public address of host:port; raises OSError when there is none."""
    targets = _public_probe_targets(host, port)
    if not targets:
        raise OSError("адрес не публичный или не разрешился")
    last_error = None
    for family, sockaddr in targets[:2]:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            try:
                sock.close()
            except OSError:
                pass
    raise last_error or OSError("соединение не установилось")


def tcp_connect_probe(host, port, timeout=PROBE_TIMEOUT_S):
    try:
        sock = _connect_public(host, int(port), timeout)
    except (OSError, ValueError):
        return False
    try:
        sock.close()
    except OSError:
        pass
    return True


def webtunnel_upgrade_probe(url, timeout=PROBE_TIMEOUT_S):
    """A webtunnel bridge is alive iff a WebSocket upgrade GET answers 101.

    HTTP/1.1 only: HTTP/2 forbids Connection/Upgrade (Android measured 0/8 with an h2
    client), and a plain GET returns 502 even on live bridges.
    """
    try:
        parts = urlsplit(str(url))
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return False
    if parts.scheme not in ("https", "http") or not host:
        return False
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    host_header = "[{}]".format(host) if ":" in host else host
    if parts.port:
        host_header += ":{}".format(parts.port)
    request = (
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\nUser-Agent: {}\r\n\r\n"
    ).format(path, host_header, WEBTUNNEL_PROBE_KEY, HTTP_USER_AGENT)
    deadline = time.monotonic() + 2 * timeout
    sock = None
    try:
        sock = _connect_public(host, port, timeout)
        if parts.scheme == "https":
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(request.encode("ascii"))
        head = b""
        while b"\r\n" not in head and len(head) < 1024:
            if time.monotonic() > deadline:
                return False
            chunk = sock.recv(1024)
            if not chunk:
                break
            head += chunk
        status = head.split(b"\r\n", 1)[0].split()
        return len(status) >= 2 and status[0].startswith(b"HTTP/1.") and status[1] == b"101"
    except (OSError, UnicodeError, ValueError):
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass  # probe socket: the verdict is already decided


def rendezvous_reachable_probe(url, timeout=RENDEZVOUS_PROBE_TIMEOUT_S):
    """Snowflake rendezvous reachability: any HTTP status counts (broker root is 404).

    A raw HTTP/1.1 request over TLS to the checked public address, not `requests`: no redirect is
    ever followed (a 30x is already "reachable"), and no second resolution can reach a private host.
    """
    try:
        parts = urlsplit(str(url))
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return False
    if parts.scheme not in ("https", "http") or not host:
        return False
    deadline = time.monotonic() + 2 * float(timeout)
    sock = None
    try:
        sock = _connect_public(host, port, timeout)
        if parts.scheme == "https":
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        host_header = "[{}]".format(host) if ":" in host else host
        sock.sendall("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n".format(
            parts.path or "/", host_header, HTTP_USER_AGENT).encode("ascii"))
        head = b""
        while b"\r\n" not in head and len(head) < 1024:
            if time.monotonic() > deadline:
                return False
            chunk = sock.recv(1024)
            if not chunk:
                break
            head += chunk
        return head.startswith(b"HTTP/")
    except (OSError, UnicodeError, ValueError):
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


_SOCKS_REPLY_TEXT = {
    1: "общий отказ", 2: "запрещено правилами", 3: "сеть недоступна", 4: "узел недоступен",
    5: "соединение отвергнуто", 6: "истёк TTL", 7: "команда не поддерживается", 8: "тип адреса не поддерживается",
}


def socks5_connect_probe(port, target_host=LIVENESS_TARGET[0], target_port=LIVENESS_TARGET[1],
                         timeout=LIVENESS_TIMEOUT_S, host="127.0.0.1"):
    """SOCKS5 CONNECT through a local proxy -> (ok, detail). Never raises."""
    deadline = time.monotonic() + float(timeout)

    def left():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("бюджет пробы исчерпан")
        return max(0.05, remaining)

    def recv_exact(sock, count):
        data = b""
        while len(data) < count:
            sock.settimeout(left())
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise ConnectionError("прокси закрыл соединение")
            data += chunk
        return data

    try:
        with socket.create_connection((host, int(port)), timeout=min(3.0, left())) as sock:
            sock.settimeout(left())
            sock.sendall(b"\x05\x01\x00")
            if recv_exact(sock, 2) != b"\x05\x00":
                return False, "прокси не принял приветствие SOCKS5"
            try:
                address = b"\x01" + socket.inet_aton(str(target_host))
            except OSError:
                encoded = str(target_host).encode("idna")
                address = b"\x03" + bytes([len(encoded)]) + encoded
            sock.sendall(b"\x05\x01\x00" + address + struct.pack("!H", int(target_port)))
            head = recv_exact(sock, 4)
            if head[0] != 5:
                return False, "ответ не SOCKS5"
            if head[1] != 0:
                return False, "tor ответил кодом {} ({})".format(head[1], _SOCKS_REPLY_TEXT.get(head[1], "?"))
            if head[3] == 1:
                recv_exact(sock, 6)
            elif head[3] == 4:
                recv_exact(sock, 18)
            elif head[3] == 3:
                recv_exact(sock, recv_exact(sock, 1)[0] + 2)
            return True, ""
    except TimeoutError:
        return False, "нет ответа за {:.0f} с".format(float(timeout))
    except (OSError, ValueError) as exc:
        return False, _short_error(exc)


# --------------------------------------------------------------------------------------
# Bridge collection (port of TorBridgeManager.runRefresh)
# --------------------------------------------------------------------------------------

def _short_host(url):
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url


def _list_label(url):
    """`cdn.jsdelivr.net, OnionHop` -- the same CDN serves both collectors."""
    collector = "Delta-Kronecker" if "Delta-Kronecker" in url else "OnionHop" if "OnionHop" in url else ""
    return "{}, {}".format(_short_host(url), collector) if collector else _short_host(url)


class BridgeCollector:
    """One collection run: sources, liveness probes, 40 kept round-robin.

    Every network touch is an injectable callable so tests run offline:
    `fetch(method, url, *, headers, data, proxy, timeout) -> FetchResponse`,
    `tcp_probe(host, port, timeout)`, `webtunnel_probe(url, timeout)`,
    `rendezvous_probe(url, timeout)` -> bool.
    """

    def __init__(self, *, log, builtin, proxies=(), fetch=None, tcp_probe=None, webtunnel_probe=None,
                 rendezvous_probe=None, should_stop=None, race_timeout=MIRROR_RACE_TIMEOUT_S,
                 probe_budget=PROBE_BUDGET_S):
        self._log = log
        self._builtin = builtin or {"obfs4": [], "snowflake": []}
        self._proxies = [str(p) for p in proxies if p]
        self._fetch = fetch or requests_fetch
        self._tcp_probe = tcp_probe or tcp_connect_probe
        self._webtunnel_probe = webtunnel_probe or webtunnel_upgrade_probe
        self._rendezvous_probe = rendezvous_probe or rendezvous_reachable_probe
        self._should_stop = should_stop or (lambda: False)
        self._race_timeout = float(race_timeout)
        self._probe_budget = float(probe_budget)
        self._verdicts = {}
        self._forced_verdicts = set()
        self._verdict_lock = threading.Lock()

    # -- sources ------------------------------------------------------------------------

    def _fetch_bridge_list(self, url, proxy):
        response = self._fetch("GET", url, headers={"User-Agent": HTTP_USER_AGENT}, data=None,
                               proxy=proxy, timeout=HTTP_TIMEOUT)
        if not 200 <= response.status < 300:
            raise OSError("HTTP {}".format(response.status))
        if not response.text.strip():
            raise OSError("пустой ответ")
        bridges, rejected = parse_bridge_text(response.text)
        if not bridges:
            # A captive portal's 200 page must not win the race over a real list.
            raise OSError("в ответе нет ни одной строки моста")
        return url, bridges, rejected

    def _race(self, jobs, timeout):
        """First successful job wins -> (result or None, [error texts]). Daemon threads only."""
        results = queue.Queue()

        def run(label, job):
            try:
                results.put((label, job(), None))
            except Exception as exc:  # each job's failure is data for the race, reported below
                results.put((label, None, _short_error(exc)))

        for label, job in jobs:
            threading.Thread(target=run, args=(label, job), name="NovaTorRace", daemon=True).start()
        deadline = time.monotonic() + timeout
        errors, pending = [], len(jobs)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                errors.append("истёк срок {:.0f} с".format(timeout))
                break
            try:
                label, result, error = results.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                if self._should_stop():
                    break
                continue
            pending -= 1
            if result is not None:
                return result, errors
            errors.append("{} — {}".format(label, error))
        return None, errors

    def _fetch_list(self, name, bases):
        for proxy in [None] + self._proxies:
            if self._should_stop():
                return None
            route = "напрямую" if proxy is None else "через {}".format(redact_proxy_url(proxy))
            jobs = [(_short_host(base), (lambda u=base + name, p=proxy: self._fetch_bridge_list(u, p)))
                    for base in bases]
            won, errors = self._race(jobs, self._race_timeout)
            if won is not None:
                url, bridges, rejected = won
                return url, bridges, rejected, route
            self._log("список {} {} не получен: {}".format(name, route, "; ".join(errors) or "нет ответа"))
        return None

    def _fetch_moat(self):
        payload = json.dumps({"country": MOAT_COUNTRY, "transports": list(MOAT_TRANSPORTS)}).encode("utf-8")
        headers = {"Content-Type": "application/vnd.api+json", "User-Agent": HTTP_USER_AGENT}
        for proxy in [None] + self._proxies:
            if self._should_stop():
                return []
            route = "напрямую" if proxy is None else "через {}".format(redact_proxy_url(proxy))
            try:
                response = self._fetch("POST", MOAT_SETTINGS_URL, headers=headers, data=payload,
                                       proxy=proxy, timeout=HTTP_TIMEOUT)
            except (OSError, ValueError) as exc:
                text = _short_error(exc)
                if " 407" in text or "407 " in text:
                    text += " — релей отклонил ключ; если это повторяется, ключ релея устарел: обновите Nova"
                self._log("Moat {} не ответил — {}".format(route, text))
                continue
            if response.status == 407:
                reason = response.headers.get("x-nova-relay-reason", "")
                if reason == "outdated-client":
                    self._log("Moat {}: ключ релея устарел — обновите Nova".format(route))
                else:
                    self._log("Moat {}: прокси требует авторизацию (407)".format(route))
                continue
            if not 200 <= response.status < 300:
                self._log("Moat {} ответил HTTP {}".format(route, response.status))
                continue
            try:
                bridges, rejected = parse_moat_response(json.loads(response.text))
            except ValueError as exc:
                self._log("Moat {} прислал не JSON — {}".format(route, _short_error(exc)))
                continue
            if bridges:
                note = _describe_rejections(rejected)
                self._log("Moat ответил {}, мостов {}{}.".format(
                    route, len(bridges), "; отброшено: " + note if note else ""))
                return bridges
            self._log("Moat ответил {}, но ни одного пригодного моста в ответе нет".format(route))
        return []

    # -- snowflake rendezvous -----------------------------------------------------------

    @staticmethod
    def rendezvous_targets(bridge):
        targets = []
        for candidate in [bridge_arg(bridge, "ampcache"), bridge.get("url", "")]:
            if candidate and candidate not in targets:
                targets.append(candidate)
        fronts = bridge_arg(bridge, "fronts").split(",") + [bridge_arg(bridge, "front")]
        for front in fronts:
            front = front.strip()
            if front and "https://{}/".format(front) not in targets:
                targets.append("https://{}/".format(front))
        return targets

    def _rendezvous_ok(self, bridge):
        targets = self.rendezvous_targets(bridge)
        if not targets:
            return False
        key = "|".join(targets)
        with self._verdict_lock:
            if key in self._verdicts:
                return self._verdicts[key]
        reachable = False
        for target in targets[:RENDEZVOUS_PROBE_LIMIT]:
            if self._rendezvous_probe(target, RENDEZVOUS_PROBE_TIMEOUT_S):
                reachable = True
                break
        with self._verdict_lock:
            # G202: one verdict per run, however many callers ask.
            self._verdicts.setdefault(key, reachable)
            return self._verdicts[key]

    def _choose_snowflake_set(self):
        primary = list(self._builtin.get("snowflake") or [])
        amp = [b for b in map(parse_bridge_line, SNOWFLAKE_AMP) if b]
        if primary and any(self._rendezvous_ok(b) for b in primary):
            self._log("встроенный snowflake — рандеву основного набора отвечает, берём его ({} моста).".format(
                len(primary)))
            return primary
        self._log("встроенный snowflake — основной набор молчит, пробуем запасной путь через AMP-кэш.")
        if any(self._rendezvous_ok(b) for b in amp):
            self._log("встроенный snowflake — рандеву через AMP-кэш отвечает, берём его ({} моста).".format(len(amp)))
            return amp
        with self._verdict_lock:
            for bridge in primary:
                key = "|".join(self.rendezvous_targets(bridge))
                self._verdicts[key] = True
                self._forced_verdicts.add(key)
        self._log("встроенный snowflake — ни основной набор, ни AMP-кэш не ответили обычным запросом. "
                  "Оставляем основной непроверенным: рандеву в транспорте идёт с uTLS и фронтингом "
                  "и может пройти там, где не прошла проверка.")
        return primary

    def _verified(self, bridge):
        """False for a snowflake line kept alive only by the forced verdict above."""
        if bridge.get("transport") != "snowflake":
            return True
        with self._verdict_lock:
            return "|".join(self.rendezvous_targets(bridge)) not in self._forced_verdicts

    # -- liveness -----------------------------------------------------------------------

    def _probe_alive(self, bridges):
        tcp_groups = {}
        for bridge in bridges:
            if bridge["transport"] in DECORATION_TRANSPORTS:
                continue
            group = tcp_groups.setdefault(bridge["transport"], [])
            if len(group) < PROBE_LIMIT_PER_TRANSPORT:
                group.append(bridge)
        tasks = []
        for group in tcp_groups.values():
            for bridge in group:
                target = bridge_dial_target(bridge)
                if target is not None:
                    tasks.append((bridge, lambda t=target: self._tcp_probe(t[0], t[1], PROBE_TIMEOUT_S)))
        webtunnel = [b for b in bridges if b["transport"] == "webtunnel" and b["url"]][:PROBE_LIMIT_WEBTUNNEL]
        for bridge in webtunnel:
            tasks.append((bridge, lambda u=bridge["url"]: self._webtunnel_probe(u, PROBE_TIMEOUT_S)))
        for bridge in bridges:
            if bridge["transport"] == "snowflake":
                tasks.append((bridge, lambda b=bridge: self._rendezvous_ok(b)))
        if not tasks:
            return []

        verdicts = [None] * len(tasks)
        work = queue.Queue()
        for index in range(len(tasks)):
            work.put(index)
        done = queue.Queue()
        deadline = time.monotonic() + self._probe_budget

        def worker():
            while time.monotonic() < deadline and not self._should_stop():
                try:
                    index = work.get_nowait()
                except queue.Empty:
                    return
                try:
                    ok = bool(tasks[index][1]())
                except Exception as exc:  # a probe that blows up is a dead bridge, said once in the log
                    self._log("проверка моста упала: {}".format(_short_error(exc)))
                    ok = False
                done.put((index, ok))

        for _ in range(min(PROBE_WORKERS, len(tasks))):
            threading.Thread(target=worker, name="NovaTorProbe", daemon=True).start()
        received = 0
        while received < len(tasks):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self._should_stop():
                self._log("проверка живости остановлена по бюджету {:.0f} с: проверено {} из {}.".format(
                    self._probe_budget, received, len(tasks)))
                break
            try:
                index, ok = done.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            verdicts[index] = ok
            received += 1
        return [tasks[i][0] for i in range(len(tasks)) if verdicts[i]]

    # -- the run ------------------------------------------------------------------------

    def collect(self):
        """-> {"bridges", "source", "error", "collected", "alive", "cancelled", "builtin_alive"}.

        A run succeeds only when at least one live, really checked bridge came from a list
        or Moat. Builtins (and the snowflake set kept by the forced verdict) are there on
        every run, reachable network or not: alone they must never replace a stored list
        (TOR-1). Such a run returns `error` with empty `bridges`; the builtins that passed a
        real check are in `builtin_alive` for the caller to use where it has nothing better.
        """
        result = {"bridges": [], "source": "", "error": "", "collected": 0, "alive": 0, "cancelled": False,
                  "builtin_alive": []}
        list_jobs = [(name, MIRROR_BASES) for name in LIST_FILES] + [(FALLBACK_FILE, FALLBACK_BASES)]
        holders = [dict() for _ in list_jobs]
        moat_holder, snowflake_holder = {}, {}

        def keep(holder, func, *args):
            try:
                holder["value"] = func(*args)
            except Exception as exc:  # the source is reported as failed; others go on
                holder["error"] = _short_error(exc)

        threads = [threading.Thread(target=keep, args=(holders[i], self._fetch_list, name, bases),
                                    name="NovaTorList", daemon=True)
                   for i, (name, bases) in enumerate(list_jobs)]
        threads.append(threading.Thread(target=keep, args=(moat_holder, self._fetch_moat),
                                        name="NovaTorMoat", daemon=True))
        threads.append(threading.Thread(target=keep, args=(snowflake_holder, self._choose_snowflake_set),
                                        name="NovaTorSnowflake", daemon=True))
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + SOURCES_PHASE_CAP_S
        for thread in threads:
            while thread.is_alive() and time.monotonic() < deadline:
                if self._should_stop():
                    result["cancelled"] = True
                    return result
                thread.join(0.25)

        collected, sources, last_error = {}, [], ""
        network_ids = set()
        for (name, _bases), holder in zip(list_jobs, holders):
            won = holder.get("value")
            if not won:
                last_error = "список {} недоступен ни с одного зеркала".format(name)
                if holder.get("error"):
                    self._log("список {}: {}".format(name, holder["error"]))
                continue
            url, bridges, rejected, route = won
            added = 0
            for bridge in bridges:
                if bridge["id"] not in collected:
                    added += 1
                collected[bridge["id"]] = bridge
                network_ids.add(bridge["id"])
            note = _describe_rejections(rejected)
            suffix = "; отброшено: " + note if note else ""
            if added:
                sources.append(_list_label(url))
                self._log("из списка {} ({}, {}) взято {} мостов{}.".format(name, _list_label(url), route, added, suffix))
            else:
                self._log("список {} ({}) не добавил новых мостов — все {} уже были{}.".format(
                    name, _list_label(url), len(bridges), suffix))

        for bridge in moat_holder.get("value") or []:
            collected.setdefault(bridge["id"], bridge)
            network_ids.add(bridge["id"])
        if moat_holder.get("value"):
            sources.append("moat")
        elif moat_holder.get("error"):
            self._log("Moat: {}".format(moat_holder["error"]))

        builtin_added = 0
        for bridge in list(self._builtin.get("obfs4") or []) + list(snowflake_holder.get("value") or []):
            if bridge["id"] not in collected:
                collected[bridge["id"]] = bridge
                builtin_added += 1
        if snowflake_holder.get("error"):
            self._log("выбор встроенного snowflake: {}".format(snowflake_holder["error"]))
        if builtin_added:
            sources.append("встроенные")

        if self._should_stop():
            result["cancelled"] = True
            return result
        result["collected"] = len(collected)
        if not collected:
            result["error"] = last_error or "ни один источник не ответил"
            return result
        alive = self._probe_alive(list(collected.values()))
        if self._should_stop():
            result["cancelled"] = True
            return result
        result["alive"] = len(alive)
        if not any(bridge["id"] in network_ids and self._verified(bridge) for bridge in alive):
            result["builtin_alive"] = [bridge for bridge in alive
                                       if bridge["id"] not in network_ids and self._verified(bridge)]
            if not network_ids:
                result["error"] = "ни один источник мостов не ответил (списки и Moat)"
            elif not alive:
                result["error"] = "ни один мост не ответил на проверку"
            else:
                result["error"] = "ни один мост из списков и Moat не ответил на проверку"
            return result
        result["bridges"] = trim_keeping_every_kind(alive)
        result["source"] = ", ".join(dict.fromkeys(sources))
        return result


# --------------------------------------------------------------------------------------
# TorManager
# --------------------------------------------------------------------------------------

class _Session:
    __slots__ = ("mode", "generation", "tor", "pt", "control", "started", "children")

    def __init__(self, mode, generation):
        self.mode = mode
        # The start() generation that owns it: a stop may only tear down sessions of
        # generations before it, never the one a later start() already brought up.
        self.generation = generation
        self.tor = None
        self.pt = None
        self.control = None
        self.started = time.monotonic()
        # role -> Popen, filled under the process lock at spawn time. A teardown that
        # lands before the worker has taken a child in (lyrebird inside its handshake,
        # tor right after Popen returned) still finds it here (TOR-3).
        self.children = {}


class TorManager:
    """Owns one tor.exe (+ lyrebird) session; every slow step runs on its worker thread.

    `start()` returns at once; `status()` is a lock-protected snapshot and does no I/O.
    Ports and the runtime dir are overridable so tests and live checks never touch
    1375/1378 of a running Nova.
    """

    def __init__(self, base_dir, bin_dir, log_func, proxies_provider=None, *, socks_port=SOCKS_PORT,
                 http_port=HTTP_PORT, runtime_dir=None, fetch=None, bootstrap_timeout=BOOTSTRAP_TIMEOUT_S,
                 autoload=True):
        self.base_dir = os.path.abspath(str(base_dir))
        bin_dir = os.path.abspath(str(bin_dir))
        # Accept both `bin` and `bin/tor`.
        self.tor_dir = bin_dir if os.path.isfile(os.path.join(bin_dir, TOR_EXE_NAME)) else os.path.join(bin_dir, "tor")
        self.tor_exe = os.path.join(self.tor_dir, TOR_EXE_NAME)
        self.lyrebird_exe = os.path.join(self.tor_dir, LYREBIRD_EXE_NAME)
        self.runtime_dir = (os.path.abspath(str(runtime_dir)) if runtime_dir
                            else os.path.join(self.base_dir, "temp", RUNTIME_DIRNAME))
        self.socks_port = int(socks_port)
        self.http_port = int(http_port)
        # Seconds without bootstrap progress before an attempt fails; the hard caps bound
        # an attempt that keeps moving (see BOOTSTRAP_TIMEOUT_S).
        self.bootstrap_timeout = float(bootstrap_timeout)
        self.bootstrap_hard_cap = BOOTSTRAP_HARD_CAP_S
        self.bootstrap_hard_cap_snowflake = BOOTSTRAP_HARD_CAP_SNOWFLAKE_S
        self.torrc_path = os.path.join(self.runtime_dir, TORRC_NAME)
        self.torrc_defaults_path = os.path.join(self.runtime_dir, TORRC_DEFAULTS_NAME)
        self.data_dir = os.path.join(self.runtime_dir, DATA_DIRNAME)
        self.pt_state_dir = os.path.join(self.runtime_dir, PT_STATE_DIRNAME)
        self.tor_log_path = os.path.join(self.runtime_dir, TOR_LOG_NAME)
        self.tor_stdout_path = os.path.join(self.runtime_dir, TOR_STDOUT_LOG_NAME)
        self.lyrebird_log_path = os.path.join(self.runtime_dir, LYREBIRD_LOG_NAME)
        self.control_port_path = os.path.join(self.runtime_dir, CONTROL_PORT_FILE_NAME)
        self.cookie_path = os.path.join(self.runtime_dir, COOKIE_NAME)
        self.pid_path = os.path.join(self.runtime_dir, PID_FILE_NAME)
        self.bridges_path = os.path.join(self.runtime_dir, BRIDGES_FILE_NAME)
        self.auto_entry_path = os.path.join(self.runtime_dir, AUTO_ENTRY_FILE_NAME)

        self._log_func = log_func
        self._proxies_provider = proxies_provider
        self._fetch = fetch
        # Process factory; tests swap it to run a fake tor. Always called with the
        # real argv and CREATE_NO_WINDOW in kwargs.
        self._popen = subprocess.Popen

        self._state_lock = threading.Lock()
        self._op_lock = threading.Lock()
        self._proc_lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._generation = 0
        self._worker = None
        self._stop_event = threading.Event()
        self._session = None
        self._pid_records = {}
        self._job = None
        self._job_failed = False
        self._last_collection_at = None      # time.monotonic() when the last collection finished
        self._state = {
            "state": "stopped", "entry": ENTRY_AUTO, "attempt": "", "progress": 0,
            "summary": "Tor выключен", "error": "", "bridges": {}, "refreshing_bridges": False,
            "bridges_updated_at": 0, "bootstrap_seconds": None, "attempts": [], "updated_at": time.time(),
        }
        if autoload:
            threading.Thread(target=self._load_counts, name="NovaTorCounts", daemon=True).start()

    # -- plumbing -----------------------------------------------------------------------

    def _log(self, message):
        try:
            self._log_func(LOG_PREFIX + scrub_proxy_credentials(message))
        except Exception:
            pass  # the log sink failing must not take the Tor worker down with it

    def _set_state(self, generation, **changes):
        with self._state_lock:
            if generation is not None and generation != self._generation:
                return False
            self._state.update(changes)
            self._state["updated_at"] = time.time()
            return True

    def status(self):
        with self._state_lock:
            snapshot = dict(self._state)
        snapshot["bridges"] = dict(snapshot["bridges"])
        snapshot["attempts"] = [dict(item) for item in snapshot["attempts"]]
        snapshot["socks_port"] = self.socks_port
        snapshot["http_port"] = self.http_port
        return snapshot

    def is_ready(self):
        with self._state_lock:
            return self._state["state"] == "ready"

    def _load_counts(self):
        snapshot = load_bridge_store(self.bridges_path)
        with self._state_lock:
            self._state["bridges"] = count_bridges(snapshot["bridges"])
            self._state["bridges_updated_at"] = snapshot["updated_at"]

    def _proxies(self):
        if self._proxies_provider is None:
            return []
        try:
            provided = self._proxies_provider()
        except Exception as exc:  # a broken provider costs the proxy routes, not the collection
            self._log("список прокси для сбора мостов не получен: {}".format(_short_error(exc)))
            return []
        return [str(p) for p in (provided or []) if isinstance(p, str) and p.strip()]

    def _get_job(self):
        if not _IS_WINDOWS or self._job_failed:
            return None
        if self._job is None:
            self._job = KillOnCloseJob()
        return self._job

    # -- public API ---------------------------------------------------------------------

    def start(self, entry=ENTRY_AUTO, bridge_lines=None):
        """Connect in the background. `bridge_lines` overrides the store for this session."""
        mode = normalize_entry(entry)
        lines = [str(line) for line in bridge_lines] if bridge_lines is not None else None
        with self._op_lock:
            previous_worker = self._worker
            self._stop_event.set()
            stop_event = threading.Event()
            self._stop_event = stop_event
            with self._state_lock:
                self._generation += 1
                generation = self._generation
                self._state.update({"state": "starting", "entry": mode, "attempt": "", "progress": 0,
                                    "summary": "Tor: запуск (вход {})".format(mode), "error": "",
                                    "bootstrap_seconds": None, "attempts": [], "updated_at": time.time()})
            worker = threading.Thread(target=self._worker_main,
                                      args=(generation, mode, lines, stop_event, previous_worker),
                                      name="NovaTor", daemon=True)
            self._worker = worker
            worker.start()
        return True

    def stop(self, wait=True):
        """Stop Tor. Blocks up to ~8 s when `wait` (SHUTDOWN, 3 s grace, kill)."""
        with self._op_lock:
            worker = self._worker
            self._worker = None
            self._stop_event.set()
            with self._state_lock:
                self._generation += 1
                stop_generation = self._generation
                was = self._state["state"]
                self._state.update({"state": "stopped", "attempt": "", "progress": 0,
                                    "summary": "Tor выключен", "updated_at": time.time()})
        if was in ("starting", "ready"):
            self._log("отключение по запросу.")
        if wait:
            self._shutdown(worker, stop_generation)
        else:
            threading.Thread(target=self._shutdown, args=(worker, stop_generation),
                             name="NovaTorStop", daemon=True).start()

    def _shutdown(self, worker, stop_generation):
        self._teardown_session("остановка по запросу", up_to=stop_generation)
        if worker is not None and worker is not threading.current_thread():
            worker.join(10.0)
            if worker.is_alive():
                self._log("поток Tor не завершился за 10 с после остановки.")
        # A worker that was between steps may have registered a session after the teardown.
        self._teardown_session("остановка по запросу", up_to=stop_generation)

    def close(self):
        """Stop and release the Job Object (Nova shutdown)."""
        self.stop(wait=True)
        job, self._job = self._job, None
        if job is not None:
            job.close()

    def new_identity(self):
        """SIGNAL NEWNYM: new streams get new circuits; open ones keep theirs."""
        with self._proc_lock:
            session = self._session
        control = session.control if session is not None else None
        if not self.is_ready() or control is None:
            self._log("новая цепочка: Tor не подключён.")
            return False
        try:
            control.signal("NEWNYM")
        except ControlError as exc:
            self._log("новая цепочка не запрошена: {}".format(exc))
            return False
        self._log("запрошена новая цепочка (NEWNYM): новые соединения пойдут через другой выход, "
                  "уже открытые остаются на прежнем; страна выхода может не смениться.")
        return True

    def reset_auto_progress(self):
        """Forget auto's failed entries (manual entry change in the UI)."""
        error = clear_auto_progress(self.auto_entry_path)
        if error:
            self._log("память авто-входа не стёрлась: {}".format(error))

    def refresh_bridges(self, force=True, wait=False):
        """Collect bridges. Non-blocking by default: returns True when a run was started."""
        if wait:
            snapshot = self._refresh_store(force=force, reason="по запросу", wait_existing=True)
            return bool(snapshot["bridges"])
        if self._refresh_lock.locked():
            self._log("сбор мостов уже идёт — второй не заводим.")
            return False
        threading.Thread(target=self._refresh_store, kwargs={"force": force, "reason": "по запросу"},
                         name="NovaTorBridges", daemon=True).start()
        return True

    # -- bridges ------------------------------------------------------------------------

    def _refresh_store(self, force, reason, wait_existing=False, stop_event=None):
        should_stop = (stop_event.is_set if stop_event is not None else (lambda: False))
        if not self._refresh_lock.acquire(blocking=False):
            if not wait_existing:
                return load_bridge_store(self.bridges_path)
            self._log("сбор мостов уже идёт — ждём его результата ({}).".format(reason))
            # Until that run ends: its phases are capped, BRIDGE_WAIT_S only guards a hang.
            deadline = time.monotonic() + BRIDGE_WAIT_S
            while not self._refresh_lock.acquire(timeout=1.0):
                if should_stop():
                    return load_bridge_store(self.bridges_path)
                if time.monotonic() > deadline:
                    self._log("сбор мостов не закончился за {:.0f} с — берём то, что уже сохранено ({}).".format(
                        BRIDGE_WAIT_S, reason))
                    return load_bridge_store(self.bridges_path)
            self._refresh_lock.release()
            return load_bridge_store(self.bridges_path)
        try:
            snapshot = load_bridge_store(self.bridges_path)
            if snapshot.get("readable") is False:
                # Collecting now would end in the failure branch writing an empty list over a file
                # that is very likely fine and merely busy.
                self._log("список мостов сейчас не читается — сбор отложен ({}).".format(reason))
                return snapshot
            if not force and bridge_store_is_fresh(snapshot):
                age_min = (_now_ms() - snapshot["updated_at"]) // 60000
                self._log("список мостов свежий ({} шт., {} мин) — повторный сбор не нужен ({}).".format(
                    len(snapshot["bridges"]), age_min, reason))
                return snapshot
            if not force and bridge_collection_backing_off(snapshot):
                left_min = (BRIDGES_FAIL_BACKOFF_S * 1000 - (_now_ms() - snapshot["attempted_at"])) // 60000
                self._log("прошлый сбор мостов не удался ({}) — следующая попытка через {} мин ({}).".format(
                    snapshot["last_error"] or "без причины", max(1, left_min), reason))
                return snapshot
            snapshot["attempted_at"] = _now_ms()
            with self._state_lock:
                self._state["refreshing_bridges"] = True
            self._log("собираем мосты ({}).".format(reason))
            builtin = load_builtin_bridges(self.tor_dir)
            if builtin["error"]:
                self._log("встроенные мосты: {} — snowflake берём из строк Nova.".format(builtin["error"]))
            collector = BridgeCollector(log=self._log, builtin=builtin, proxies=self._proxies(),
                                        fetch=self._fetch, should_stop=should_stop)
            started = time.monotonic()
            result = collector.collect()
            if result["cancelled"]:
                self._log("сбор мостов прерван остановкой.")
                return snapshot
            self._last_collection_at = time.monotonic()
            if result["bridges"]:
                # `attempted_at` travels with the success too: it is the stamp that says when the
                # collector last went out, and a fresh list must not leave a stale attempt behind.
                snapshot = {"bridges": result["bridges"], "updated_at": _now_ms(),
                            "attempted_at": _now_ms(), "source": result["source"], "last_error": ""}
                try:
                    save_bridge_store(self.bridges_path, snapshot)
                    stored = "сохранили {}".format(len(result["bridges"]))
                except OSError as exc:
                    stored = "но записать список не удалось ({})".format(_short_error(exc))
                self._log("из {} собранных мостов живыми оказались {}, {} (источники: {}; {:.0f} с). {}.".format(
                    result["collected"], result["alive"], stored, result["source"],
                    time.monotonic() - started, bridges_summary_text(result["bridges"])))
            else:
                # A failed run keeps the previous list and its updated_at (so it stays due for
                # the next collection); only last_error changes. Builtins that passed a real
                # check fill in kinds the list has none of -- never replace what it has.
                previous = snapshot["bridges"]
                have_kinds, have_ids = count_bridges(previous), {b["id"] for b in previous}
                extra = []
                for bridge in result.get("builtin_alive") or []:
                    if bridge["transport"] not in have_kinds and bridge["id"] not in have_ids:
                        extra.append(bridge)
                        have_ids.add(bridge["id"])
                if extra:
                    snapshot["bridges"] = trim_keeping_every_kind(previous + extra)
                snapshot["last_error"] = result["error"]
                try:
                    save_bridge_store(self.bridges_path, snapshot)
                except OSError as exc:
                    self._log("ошибку сбора записать не удалось: {}".format(_short_error(exc)))
                added = "; добавили проверенные встроенные — {}".format(
                    ", ".join("{} {}".format(k, n) for k, n in count_bridges(extra).items())) if extra else ""
                if previous:
                    self._log("{}. Оставляем прошлый список — {} шт.{}".format(result["error"], len(previous), added))
                elif extra:
                    self._log("{}. Сохранённых мостов не было{}; список остаётся несвежим.".format(
                        result["error"], added))
                else:
                    self._log("{}. Сохранённых мостов нет.".format(result["error"]))
            with self._state_lock:
                self._state["bridges"] = count_bridges(snapshot["bridges"])
                self._state["bridges_updated_at"] = snapshot["updated_at"]
            return snapshot
        finally:
            with self._state_lock:
                self._state["refreshing_bridges"] = False
            self._refresh_lock.release()

    def _seconds_since_collection(self):
        finished = self._last_collection_at
        return None if finished is None else max(0.0, time.monotonic() - finished)

    def _bridges_for_attempt(self, mode, lines, stop_event):
        if lines is not None:
            bridges, rejected = parse_bridge_text("\n".join(lines))
            usable = select_bridges_for_entry(bridges, mode)
            note = _describe_rejections(rejected)
            self._log("вход {}: заданные строки мостов — пригодных {} из {}{}.".format(
                mode, len(usable), len(lines), "; отброшено: " + note if note else ""))
            return usable
        snapshot = load_bridge_store(self.bridges_path)
        with self._state_lock:
            self._state["bridges"] = count_bridges(snapshot["bridges"])
            self._state["bridges_updated_at"] = snapshot["updated_at"]
        usable = select_bridges_for_entry(snapshot["bridges"], mode)
        since = self._seconds_since_collection()
        recent = since is not None and since < RECOLLECT_PAUSE_S
        if usable:
            if not bridge_store_is_fresh(snapshot) and not self._refresh_lock.locked() and not recent:
                self._log("список мостов не свежий (старше суток или прошлый сбор не удался) — "
                          "подключаемся по нему и обновляем в фоне.")
                threading.Thread(target=self._refresh_store, kwargs={"force": True, "reason": "устарел"},
                                 name="NovaTorBridges", daemon=True).start()
            return usable
        builtin = load_builtin_bridges(self.tor_dir)
        if mode == ENTRY_SNOWFLAKE and builtin["snowflake"]:
            # Snowflake's bridges are not collected, only its rendezvous is chosen: no
            # reason to make the user wait for a full collection run.
            self._log("вход snowflake: сохранённых строк нет — берём встроенные ({}).".format(builtin["source"]))
            return select_bridges_for_entry(builtin["snowflake"], mode)
        if recent and not self._refresh_lock.locked():
            # The sources were asked moments ago and gave nothing of this kind: asking
            # them again would only cost minutes in "starting" (TOR-6).
            self._log("вход {}: сохранённых мостов этого вида нет, а сбор {:.0f} с назад их не дал — "
                      "повторно не собираем.".format(mode, since))
        else:
            self._log("вход {}: сохранённых мостов этого вида нет — собираем.".format(mode))
            snapshot = self._refresh_store(force=True, reason="вход {}".format(mode), wait_existing=True,
                                           stop_event=stop_event)
        usable = select_bridges_for_entry(snapshot["bridges"], mode)
        if not usable and mode == ENTRY_OBFS4 and builtin["obfs4"]:
            self._log("вход obfs4: сбор не дал мостов — берём встроенные из {} ({} шт., без проверки).".format(
                PT_CONFIG_NAME, len(builtin["obfs4"])))
            usable = select_bridges_for_entry(builtin["obfs4"], mode)
        return usable

    # -- processes ----------------------------------------------------------------------

    def _spawn_guarded(self, session, stop_event, role, argv, **kwargs):
        """Popen under the process lock, so a stop can never race a fresh child.

        The child is registered on the session before the lock is released: a teardown
        either finds it there or finds the session gone and refuses the spawn.
        """
        with self._proc_lock:
            if stop_event.is_set() or self._session is not session:
                raise _Stopped()
            proc = self._popen(argv, **kwargs)
            session.children[role] = proc
            if role == "tor":
                session.tor = proc
            job = self._get_job()
            if job is not None:
                try:
                    job.assign(proc)
                except OSError as exc:
                    self._job_failed = True
                    self._log("процесс {} не привязан к Job Object ({}) — при аварийном выходе Nova "
                              "его завершит очистка по {}.".format(os.path.basename(argv[0]), _short_error(exc),
                                                                   PID_FILE_NAME))
            self._pid_records[role] = {"role": role, "pid": proc.pid, "image": argv[0]}
            try:
                write_pid_file(self.pid_path, list(self._pid_records.values()))
            except OSError as exc:
                self._log("{} не записался: {}".format(PID_FILE_NAME, _short_error(exc)))
            return proc

    def _cleanup_stale(self):
        records = read_pid_file(self.pid_path)
        allowed = [self.tor_exe, self.lyrebird_exe]
        for record in records:
            if not any(_same_path(record["image"], image) for image in allowed):
                self._log("в {} чужой образ ({}) — не трогаем.".format(PID_FILE_NAME, os.path.basename(record["image"])))
                continue
            verdict = terminate_pid_if_image(record["pid"], allowed)
            name = os.path.basename(record["image"])
            if verdict == "killed":
                self._log("остался {} (pid {}) от прошлого запуска — завершён.".format(name, record["pid"]))
            elif verdict.startswith("failed"):
                self._log("старый {} (pid {}) завершить не удалось: {}".format(name, record["pid"], verdict))
        if records:
            error = _remove_file(self.pid_path)
            if error:
                self._log("{} не удаляется: {}".format(PID_FILE_NAME, error))

    def _teardown_session(self, reason, generation=None, up_to=None):
        """Tear down the current session if it belongs to `generation` / to one `<= up_to`."""
        with self._proc_lock:
            current = self._session
            if current is None:
                return
            if generation is not None and current.generation != generation:
                return
            if up_to is not None and current.generation > up_to:
                return
            self._session = None
        self._shutdown_session(current, reason)

    def _shutdown_session(self, session, reason):
        tor, control = session.tor, session.control
        if tor is not None and tor.poll() is None:
            signalled = False
            if control is not None and control.connected:
                try:
                    control.signal("SHUTDOWN")
                    signalled = True
                except ControlError as exc:
                    self._log("SIGNAL SHUTDOWN не прошёл ({}) — завершаем nova-tor.exe принудительно.".format(exc))
            if signalled:
                try:
                    tor.wait(SHUTDOWN_WAIT_S)
                except subprocess.TimeoutExpired:
                    self._log("nova-tor.exe не вышел за {:.0f} с после SHUTDOWN — завершаем принудительно.".format(
                        SHUTDOWN_WAIT_S))
            if tor.poll() is None:
                tor.kill()
                try:
                    tor.wait(SHUTDOWN_WAIT_S)
                except subprocess.TimeoutExpired:
                    self._log("nova-tor.exe (pid {}) не завершился даже после TerminateProcess.".format(tor.pid))
        if control is not None:
            control.close()
        if session.pt is not None:
            session.pt.stop()
        for role, proc in list(session.children.items()):
            if role == "tor" or proc.poll() is not None:
                continue
            # A lyrebird its ManagedPt did not hold yet (stop inside the handshake): the
            # same exit signal -- stdin closed -- then kill by handle.
            name = os.path.basename(self.lyrebird_exe)
            try:
                if proc.stdin is not None:
                    proc.stdin.close()
            except (OSError, ValueError):
                pass  # an unusable stdin pipe: the kill below still ends the process
            try:
                proc.wait(2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(SHUTDOWN_WAIT_S)
                except subprocess.TimeoutExpired:
                    self._log("{} (pid {}) не завершился даже после TerminateProcess.".format(name, proc.pid))
            self._log("{} остановлен посреди запуска ({}).".format(name, reason))
        with self._proc_lock:
            if self._session is None:
                self._pid_records.clear()
                for path in (self.pid_path, self.cookie_path, self.control_port_path):
                    error = _remove_file(path)
                    if error:
                        self._log("{} не удаляется: {}".format(os.path.basename(path), error))
        if tor is not None:
            self._log("tor остановлен ({}), код выхода {}.".format(reason, tor.returncode))

    def _log_tail(self, limit=3):
        """Last warn/err lines of tor's own logs, for a failure summary."""
        found = []
        for path in (self.tor_stdout_path, self.tor_log_path):
            try:
                with open(path, "rb") as handle:
                    handle.seek(0, os.SEEK_END)
                    size = handle.tell()
                    handle.seek(max(0, size - 65536))
                    text = handle.read().decode("utf-8", "replace")
            except OSError:
                continue
            for line in text.split("\n"):
                if "[warn]" in line or "[err]" in line:
                    clean = re.sub(r"^\w{3} \d{2} [\d:.]+ ", "", line.strip())
                    if clean not in found:
                        found.append(clean[:220])
        return found[-limit:]

    def _tail_note(self):
        tail = self._log_tail()
        return (" Последнее от tor: " + " / ".join(tail)) if tail else ""

    # -- worker -------------------------------------------------------------------------

    def _worker_main(self, generation, entry, lines, stop_event, previous_worker):
        try:
            self._teardown_session("перезапуск", up_to=generation - 1)
            if previous_worker is not None and previous_worker.is_alive():
                previous_worker.join(15.0)
                self._teardown_session("перезапуск", up_to=generation - 1)
            self._run(generation, entry, lines, stop_event)
        except _Stopped:
            pass
        except Exception as exc:  # last line of defence: the failure is reported, never swallowed
            self._log("поток Tor упал: {}".format(_short_error(exc, 400)))
            self._set_state(generation, state="failed", error=_short_error(exc),
                            summary="Tor: внутренняя ошибка — {}".format(_short_error(exc)))
        finally:
            # `_run` only returns once its session is over (stopped or failed); whatever
            # this generation still has registered must not outlive the worker.
            self._teardown_session("поток Tor завершён", generation=generation)

    def _run(self, generation, entry, lines, stop_event):
        restarts = []
        working = None
        while not stop_event.is_set():
            if working is None:
                outcome, mode = self._walk_attempts(generation, entry, lines, stop_event)
            else:
                # A watchdog restart retries the entry that was working first (TOR-2): after
                # sleep or a Wi-Fi change it comes back in seconds, while auto's full order
                # would put minutes of dead entries in front of it.
                outcome, mode = self._walk_attempts(generation, entry, lines, stop_event, only=working)
                if outcome == "failed" and entry == ENTRY_AUTO and not stop_event.is_set():
                    self._log("вход {} после перезапуска не поднялся — перебираем остальные входы авто-режима.".format(
                        working))
                    self._set_state(generation, state="starting", progress=0,
                                    summary="Tor: перезапуск — вход {} не поднялся, перебор входов".format(working))
                    outcome, mode = self._walk_attempts(generation, entry, lines, stop_event)
            if outcome != "ready":
                return
            verdict = self._hold(generation, stop_event)
            if verdict is None:
                return
            self._teardown_session(verdict, generation=generation)
            now = time.monotonic()
            restarts = [t for t in restarts if now - t < RESTART_WINDOW_S]
            if len(restarts) >= RESTART_LIMIT:
                message = "{} — перезапусков уже {} за 30 мин, больше не пробуем".format(verdict, len(restarts))
                self._log(message + ".")
                self._set_state(generation, state="failed", error=message, progress=0,
                                summary="Tor не держит соединение: " + verdict)
                return
            restarts.append(now)
            working = mode
            self._log("{} — перезапускаем Tor (вход {}{}).".format(
                verdict, mode, ", выбранный авто-входом" if entry == ENTRY_AUTO else ""))
            self._set_state(generation, state="starting", progress=0,
                            summary="Tor: перезапуск — {}".format(verdict))

    def _preflight(self):
        if not os.path.isfile(self.tor_exe):
            return "не найден {} в {}".format(TOR_EXE_NAME, self.tor_dir)
        try:
            for path in (self.runtime_dir, self.data_dir, self.pt_state_dir):
                os.makedirs(path, exist_ok=True)
            _atomic_write_text(self.torrc_defaults_path, "")
        except OSError as exc:
            return "папка {} не пишется: {}".format(self.runtime_dir, _short_error(exc))
        self._cleanup_stale()
        for port in (self.socks_port, self.http_port):
            deadline = time.monotonic() + PORT_FREE_WAIT_S
            while not port_is_free(port):
                if time.monotonic() > deadline:
                    return "порт 127.0.0.1:{} занят другой программой — Tor не может его открыть".format(port)
                time.sleep(0.2)
        return ""

    def _walk_attempts(self, generation, entry, lines, stop_event, only=None):
        """-> (outcome, mode): ("ready", mode) | ("failed", None) | ("fatal", None) | ("stopped", None).

        "failed" and "fatal" set state=failed, except that with `only` (retry just that
        concrete entry, a watchdog restart) under entry=auto a plain failure leaves the
        state to the caller, which goes on with the full auto order.
        """
        final = only is None or entry != ENTRY_AUTO
        error = self._preflight()
        if error:
            self._log(error + ".")
            self._set_state(generation, state="failed", error=error, summary="Tor не подключился: " + error)
            return "fatal", None
        planned = attempts_for_entry(entry) if only is None else [only]
        remaining = list(planned)
        if only is not None:
            self._log("перезапуск: снова вход {}, который работал.".format(only))
        elif entry == ENTRY_AUTO:
            tried = read_auto_progress(self.auto_entry_path)
            remaining = [mode for mode in planned if mode not in tried]
            if not remaining:
                error = clear_auto_progress(self.auto_entry_path)
                self._log("перебор входов исчерпан — не сработал ни один из {} ({}). Начинаем заново{}.".format(
                    len(planned), ", ".join(planned), "; память не стёрлась: " + error if error else ""))
                remaining = list(planned)
            elif tried:
                self._log("авто-вход продолжается — уже не сработали {}, осталось попробовать {}.".format(
                    ", ".join(tried), ", ".join(remaining)))
        else:
            error = clear_auto_progress(self.auto_entry_path)
            if error:
                self._log("память авто-входа не стёрлась: {}".format(error))

        failures = []
        for index, mode in enumerate(remaining):
            if stop_event.is_set():
                return "stopped", None
            if only is not None:
                pass  # announced above
            elif entry == ENTRY_AUTO:
                self._log("авто-вход, попытка {} из {} — {}.".format(planned.index(mode) + 1, len(planned), mode))
            else:
                self._log("вход {}.".format(mode))
            started = time.monotonic()
            try:
                outcome, detail, info = self._run_attempt(generation, mode, lines, stop_event)
            except _Stopped:
                outcome, detail, info = "stopped", "", {}
            record = {"entry": mode, "ok": outcome == "ready", "seconds": round(time.monotonic() - started, 1),
                      "bootstrap_seconds": info.get("bootstrap_seconds"), "detail": detail}
            with self._state_lock:
                if self._generation == generation:
                    self._state["attempts"] = self._state["attempts"] + [record]
            if outcome == "ready":
                error = clear_auto_progress(self.auto_entry_path)
                if error:
                    self._log("память авто-входа не стёрлась: {}".format(error))
                boot = info.get("bootstrap_seconds") or 0.0
                self._set_state(generation, state="ready", attempt=mode, progress=100, error="",
                                bootstrap_seconds=round(boot, 1),
                                summary="Tor готов: вход {}, загрузка {:.0f} с".format(mode, boot))
                return "ready", mode
            self._teardown_session("вход {} не сработал".format(mode), generation=generation)
            if outcome == "stopped" or stop_event.is_set():
                return "stopped", None
            self._log("вход {} не сработал: {}".format(mode, detail))
            failures.append("{}: {}".format(mode, detail))
            if outcome == "fatal":
                self._set_state(generation, state="failed", error=detail, progress=0,
                                summary="Tor не подключился: " + detail)
                return "fatal", None
            if entry == ENTRY_AUTO:
                try:
                    if only is None and index == len(remaining) - 1:
                        error = clear_auto_progress(self.auto_entry_path)
                        if error:
                            raise OSError(error)
                    else:
                        # With `only`: the full walk that follows skips the entry that just failed.
                        note_auto_failure(self.auto_entry_path, mode)
                except OSError as exc:
                    self._log("память авто-входа не записалась: {}".format(_short_error(exc)))
        if not final:
            return "failed", None
        if entry == ENTRY_AUTO:
            message = "ни один способ входа не сработал ({})".format("; ".join(failures))
        else:
            message = failures[0] if failures else "вход {} не сработал".format(entry)
        self._set_state(generation, state="failed", error=message, progress=0,
                        summary="Tor не подключился: " + message)
        return "failed", None

    def _run_attempt(self, generation, mode, lines, stop_event):
        """-> (outcome, detail, info); outcome in ready | next | fatal | stopped."""
        self._set_state(generation, attempt=mode, progress=0, summary="Tor: вход {} — подготовка".format(mode))
        bridges = []
        if mode != ENTRY_DIRECT:
            bridges = self._bridges_for_attempt(mode, lines, stop_event)
            if stop_event.is_set():
                return "stopped", "", {}
            if not bridges:
                return "next", "нет пригодных мостов {}".format(mode), {}
        try:
            geoip_path = os.path.join(self.tor_dir, GEOIP_NAME)
            geoip6_path = os.path.join(self.tor_dir, GEOIP6_NAME)
            geoip = tor_safe_path(geoip_path) if os.path.isfile(geoip_path) else ""
            geoip6 = tor_safe_path(geoip6_path) if os.path.isfile(geoip6_path) else ""
            argv_paths = {
                "torrc": tor_safe_path(self.torrc_path, created_by_tor=True),
                "defaults": tor_safe_path(self.torrc_defaults_path),
                "data": tor_safe_path(self.data_dir),
                "control_port": tor_safe_path(self.control_port_path, created_by_tor=True),
                "cookie": tor_safe_path(self.cookie_path, created_by_tor=True),
                "log": tor_safe_path(self.tor_log_path, created_by_tor=True),
            }
        except TorPathError as exc:
            return "fatal", str(exc), {}

        session = _Session(mode, generation)
        self._teardown_session("перезапуск", up_to=generation - 1)
        with self._proc_lock:
            if stop_event.is_set():
                return "stopped", "", {}
            if self._session is not None:
                return "next", "предыдущая сессия Tor ещё не остановлена", {}
            self._session = session

        transport_addr = ""
        if mode in PT_TRANSPORTS:
            pt = ManagedPt(self.lyrebird_exe, [mode], self.pt_state_dir, self.lyrebird_log_path, log=self._log,
                           spawn=lambda argv, **kw: self._spawn_guarded(session, stop_event, "lyrebird", argv, **kw),
                           cwd=self.tor_dir)
            # On the session before it spawns anything: a stop inside the handshake must
            # find it (ManagedPt.stop closes stdin, which ends start() with PtError) (TOR-3).
            session.pt = pt
            pt_started = time.monotonic()
            try:
                methods = pt.start(PT_START_TIMEOUT_S)
            except PtError as exc:
                if stop_event.is_set():
                    return "stopped", "", {}
                return "next", "{} не поднял {}: {}".format(LYREBIRD_EXE_NAME, mode, exc), {}
            if stop_event.is_set():
                return "stopped", "", {}
            transport_addr = methods[mode]
            self._log("вход {}: {} слушает {} ({} мс), мостов в torrc {}.".format(
                mode, LYREBIRD_EXE_NAME, transport_addr, int((time.monotonic() - pt_started) * 1000), len(bridges)))

        try:
            text = render_torrc(mode, socks_port=self.socks_port, http_port=self.http_port, bridges=bridges,
                                transport_addr=transport_addr, geoip_file=geoip, geoip6_file=geoip6)
        except ValueError as exc:
            return "next", "torrc не собран: {}".format(exc), {}
        try:
            _atomic_write_text(self.torrc_path, text)
            for path in (self.control_port_path, self.cookie_path):
                error = _remove_file(path)
                if error:
                    raise OSError("{} от прошлого запуска не удаляется: {}".format(os.path.basename(path), error))
            with open(self.tor_log_path, "w", encoding="utf-8"):
                pass
            stdout_handle = open(self.tor_stdout_path, "wb")
        except OSError as exc:
            return "fatal", "файлы Tor в {} не пишутся: {}".format(self.runtime_dir, _short_error(exc)), {}

        argv = [
            self.tor_exe,
            "-f", argv_paths["torrc"],
            "--defaults-torrc", argv_paths["defaults"],
            "--DataDirectory", argv_paths["data"],
            "--ControlPortWriteToFile", argv_paths["control_port"],
            "--CookieAuthFile", argv_paths["cookie"],
            "--Log", "notice file " + argv_paths["log"],
            "__OwningControllerProcess", str(os.getpid()),
        ]
        try:
            proc = self._spawn_guarded(session, stop_event, "tor", argv, cwd=self.tor_dir,
                                       stdin=subprocess.DEVNULL, stdout=stdout_handle,
                                       stderr=subprocess.STDOUT, creationflags=_NO_WINDOW)
        except OSError as exc:
            return "fatal", "{} не запустился: {}".format(TOR_EXE_NAME, _short_error(exc)), {}
        finally:
            stdout_handle.close()
        spawned = time.monotonic()           # session.tor was set by _spawn_guarded under the lock

        try:
            port, cookie = self._wait_control_files(proc, stop_event)
        except _AttemptFailed as exc:
            return "next", str(exc), {}
        try:
            control = self._connect_control(proc, port, cookie, stop_event)
        except _AttemptFailed as exc:
            return "next", str(exc), {}
        session.control = control

        outcome = self._await_bootstrap(generation, mode, session, stop_event, spawned)
        if outcome is not None:
            return outcome
        boot_seconds = time.monotonic() - spawned
        try:
            listeners = control.getinfo("net/listeners/socks").get("net/listeners/socks", "")
            listen_port = parse_listener_port(listeners)
            if listen_port is not None and listen_port != self.socks_port:
                return "next", "tor слушает SOCKS на {} вместо {}".format(listen_port, self.socks_port), {}
        except ControlError as exc:
            self._log("вход {}: адрес SOCKS не прочитан ({}) — решит проба.".format(mode, exc))
        self._log("вход {}: загрузка завершена за {:.0f} с, SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}.".format(
            mode, boot_seconds, self.socks_port, self.http_port))
        self._set_state(generation, progress=100, summary="Tor: вход {} — проверка цепочки".format(mode))

        detail = ""
        for attempt in range(LIVENESS_TRIES_AFTER_BOOTSTRAP):
            ok, detail = socks5_connect_probe(self.socks_port, timeout=LIVENESS_TIMEOUT_S)
            if ok:
                self._log("вход {}: проба CONNECT {}:{} через Tor прошла.".format(mode, *LIVENESS_TARGET))
                return "ready", "", {"bootstrap_seconds": boot_seconds}
            self._log("вход {}: проба через Tor {} из {} не прошла — {}.".format(
                mode, attempt + 1, LIVENESS_TRIES_AFTER_BOOTSTRAP, detail))
            if stop_event.wait(2.0):
                return "stopped", "", {}
        return "next", "цепочка через вход {} не провезла ни одной пробы ({})".format(mode, detail), {
            "bootstrap_seconds": boot_seconds}

    def _connect_control(self, proc, port, cookie, stop_event):
        """Authenticated control connection, retried while tor is alive and still starting up.

        A busy tor accepts the TCP connection but answers AUTHENTICATE late; that is not a
        failed entry. Only a refused cookie, an exited tor or the deadline end the attempt.
        """
        deadline = time.monotonic() + CONTROL_READY_WAIT_S
        last_error = ""
        tries = 0
        while True:
            code = proc.poll()
            if code is not None:
                raise _AttemptFailed("nova-tor.exe завершился при запуске (код {}).{}".format(code, self._tail_note()))
            tries += 1
            control = TorControl(port)
            try:
                control.connect()
                control.authenticate_cookie(cookie)
                if tries > 1:
                    self._log("порт управления ответил с {}-й попытки.".format(tries))
                return control
            except ControlError as exc:
                control.close()
                last_error = str(exc)
                if last_error.startswith("tor не принял cookie"):
                    raise _AttemptFailed("порт управления: {}.{}".format(last_error, self._tail_note()))
            if time.monotonic() > deadline:
                raise _AttemptFailed("порт управления не ответил за {:.0f} с ({} попыток): {}.{}".format(
                    CONTROL_READY_WAIT_S, tries, last_error, self._tail_note()))
            if stop_event.wait(1.0):
                raise _Stopped()

    def _wait_control_files(self, proc, stop_event):
        deadline = time.monotonic() + CONTROL_FILE_WAIT_S
        last_error = ""
        while True:
            code = proc.poll()
            if code is not None:
                raise _AttemptFailed("nova-tor.exe завершился при запуске (код {}).{}".format(code, self._tail_note()))
            try:
                with open(self.control_port_path, "r", encoding="ascii", errors="replace") as handle:
                    port = parse_control_port_file(handle.read())
                with open(self.cookie_path, "rb") as handle:
                    cookie = handle.read()
                if port and len(cookie) == 32:
                    return port, cookie
            except FileNotFoundError:
                pass  # tor has not written the files yet; the deadline below decides
            except OSError as exc:
                last_error = _short_error(exc)
            if time.monotonic() > deadline:
                raise _AttemptFailed("tor не записал порт управления за {:.0f} с{}.{}".format(
                    CONTROL_FILE_WAIT_S, " ({})".format(last_error) if last_error else "", self._tail_note()))
            if stop_event.wait(0.2):
                raise _Stopped()

    def _await_bootstrap(self, generation, mode, session, stop_event, spawned):
        """None when bootstrapped, else the (outcome, detail, info) of the failure."""
        control, proc = session.control, session.tor
        stall_limit, hard_cap = self._bootstrap_limits(mode)
        # Progress only goes up in tor (status/bootstrap-phase reports a new maximum), so
        # "moved" means a higher percentage than any seen before.
        best_progress, last_advance = -1, spawned
        silent = 0
        last_key, last_progress, last_logged = None, -100, 0.0
        phase = parse_bootstrap_phase("")
        while True:
            code = proc.poll()
            if code is not None:
                return "next", "nova-tor.exe завершился во время загрузки (код {}).{}".format(
                    code, self._tail_note()), {}
            if session.pt is not None and session.pt.poll() is not None:
                return "next", "{} завершился во время загрузки (код {}); его вывод — в {}".format(
                    LYREBIRD_EXE_NAME, session.pt.poll(), LYREBIRD_LOG_NAME), {}
            value = ""
            try:
                if not control.connected:
                    control.connect()
                    with open(self.cookie_path, "rb") as handle:
                        control.authenticate_cookie(handle.read())
                value = control.getinfo("status/bootstrap-phase").get("status/bootstrap-phase", "")
            except (ControlError, OSError) as exc:
                if stop_event.is_set():
                    return "stopped", "", {}
                if silent == 0:
                    self._log("вход {}: опрос загрузки не прошёл — {}".format(mode, _short_error(exc)))
            if value:
                silent = 0
                phase = parse_bootstrap_phase(value)
                text = describe_bootstrap_phase(phase)
                progress = max(0, phase["progress"])
                self._set_state(generation, progress=progress, summary="Tor: вход {} — {}".format(mode, text))
                now = time.monotonic()
                if phase["progress"] > best_progress:
                    best_progress, last_advance = phase["progress"], now
                # One line per stage (tag or warning change) or per 10 points: loading
                # descriptors alone moves through ~40 single percents (G183: no spam).
                key = (phase["tag"], phase["warning"], phase["done"])
                if key != last_key or progress - last_progress >= 10:
                    self._log("вход {}: {}".format(mode, text))
                    last_key, last_progress, last_logged = key, progress, now
                elif now - last_logged >= BOOTSTRAP_REPEAT_S:
                    stalled = now - last_advance
                    self._log("вход {}: всё ещё {}{}".format(
                        mode, text, " (без продвижения {:.0f} с из {:.0f})".format(stalled, stall_limit)
                        if stalled >= BOOTSTRAP_REPEAT_S else ""))
                    last_progress, last_logged = progress, now
                if phase["done"]:
                    return None
            else:
                silent += 1
                if silent >= SILENT_POLLS_LIMIT:
                    return "next", "управляющее соединение молчит {} опросов подряд.{}".format(
                        SILENT_POLLS_LIMIT, self._tail_note()), {}
            now = time.monotonic()
            if now - last_advance >= stall_limit:
                return "next", "загрузка не продвигалась {:.0f} с — застряла: {}.{}".format(
                    stall_limit, describe_bootstrap_phase(phase), self._tail_note()), {}
            if now - spawned >= hard_cap:
                return "next", ("не загрузился за предельные {:.0f} с для входа {} — загрузка шла, "
                                "но не дошла до конца; остановились на: {}.{}").format(
                    hard_cap, mode, describe_bootstrap_phase(phase), self._tail_note()), {}
            if stop_event.wait(POLL_INTERVAL_S):
                return "stopped", "", {}

    def _bootstrap_limits(self, mode):
        """-> (seconds without progress, hard cap in seconds) for one entry mode."""
        stall = float(self.bootstrap_timeout)
        cap = self.bootstrap_hard_cap_snowflake if mode == ENTRY_SNOWFLAKE else self.bootstrap_hard_cap
        # A caller that asked for a longer stall timeout than the cap gets it in full.
        return stall, max(float(cap), stall)

    def _hold(self, generation, stop_event):
        """Watch a ready session. None when stopped, else the reason it died."""
        with self._proc_lock:
            session = self._session
        if session is None or session.generation != generation:
            return None if stop_event.is_set() else "сессия Tor пропала"
        last_healthy = time.monotonic()
        failures = 0
        next_probe = time.monotonic() + HOLD_PROBE_EVERY_S
        while not stop_event.wait(HOLD_POLL_S):
            code = session.tor.poll()
            if code is not None:
                return "nova-tor.exe завершился (код {}).{}".format(code, self._tail_note())
            if session.pt is not None and session.pt.poll() is not None:
                return "{} завершился (код {}); вывод — в {}".format(
                    LYREBIRD_EXE_NAME, session.pt.poll(), LYREBIRD_LOG_NAME)
            now = time.monotonic()
            if now < next_probe:
                continue
            ok, detail = socks5_connect_probe(self.socks_port, timeout=LIVENESS_TIMEOUT_S)
            if stop_event.is_set():
                return None
            now = time.monotonic()
            if ok:
                if failures:
                    self._log("цепочка снова пропускает трафик после {} неудачных проб.".format(failures))
                    self._set_state(generation, summary="Tor готов: вход {}".format(session.mode))
                failures, last_healthy = 0, now
                next_probe = now + HOLD_PROBE_EVERY_S
                continue
            failures += 1
            next_probe = now + HOLD_PROBE_RETRY_S
            self._log("проба через Tor не прошла ({} подряд) — {}.".format(failures, detail))
            if failures == 2 and session.control is not None:
                try:
                    session.control.signal("ACTIVE")
                    session.control.signal("NEWNYM")
                    self._log("две пробы подряд не прошли — SIGNAL ACTIVE + NEWNYM.")
                except ControlError as exc:
                    self._log("SIGNAL ACTIVE/NEWNYM не прошёл: {}".format(exc))
                self._set_state(generation, summary="Tor: цепочка не отвечает, пересобираем")
            if failures >= DEAD_CHAIN_FAILURES and now - last_healthy >= DEAD_CHAIN_MIN_S:
                return "цепочка перестала пропускать трафик ({} проб подряд)".format(failures)
        return None


