"""Profile storage: the `profiles/` layout, the selection model, attempt plans, import and migration.

Until 1.38 every AWG profile lived flat in `awg/`, was keyed by its bare file stem and
was picked by one hard-coded order (identity round-robin, last success first). There was
no way to say "use this one" and nothing distinguished a shipped seed from a hand-dropped
file. This module is the single source of truth for the new layout:

    profiles/AWG Cloudflare/  shipped WARPv* seeds, generated WARPgen_NN, hand-dropped confs
    profiles/AWG Proton/      per-device Proton confs
    profiles/MASQUE/          MASQUE identities (Android `masque_config.json` key set)
    profiles/Custom/          everything the user imports
    profiles/.runtime/        rendered wireproxy configs (private keys, never listed)

A profile is addressed everywhere by `"<group>/<file stem>"` (selection, stats, logs,
runtime config path). The selection model enforces I1: an explicit choice (`profile` or
`group`) is never silently replaced by another group, WARP or MASQUE.

Stdlib only (plus `cryptography` for optional MASQUE key checks): the module is imported
by pytest without `nova.pyw`. Nothing here touches Tk; every function may run on a worker.
Records carry the raw WireGuard PrivateKey as `identity` (the round-robin key nova.pyw has
always used) — never log a record or a candidate as a whole.
"""

import base64
import binascii
import codecs
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import threading
import time
import zlib

__all__ = [
    # layout constants
    "PROFILES_DIRNAME", "GROUP_CLOUDFLARE", "GROUP_PROTON", "GROUP_MASQUE", "GROUP_CUSTOM", "GROUPS",
    "RUNTIME_DIRNAME", "RELAY_KEY_FILENAME", "LEGACY_AWG_DIRNAME", "SELECTION_FILENAME", "STATS_FILENAME",
    "GENERATED_WARP_PREFIX", "BUNDLED_WARP_PREFIX",
    "TEMP_DIRNAME", "CF_WS_KEY_FILENAME", "LEGACY_AWG_STATE_FILENAME", "PRIVATE_FILENAMES",
    "MODE_AUTO", "MODE_GROUP", "MODE_PROFILE", "BACKEND_AWG", "BACKEND_MASQUE", "BACKEND_WARP_CLI",
    "ORIGIN_BUNDLED", "ORIGIN_GENERATED", "ORIGIN_IMPORTED", "KIND_AWG", "KIND_MASQUE",
    "AUTO_GENERATED_LEAD_LIMIT", "AUTO_PROTON_LIMIT", "MASQUE_DEFAULT_PORTS",
    "WARNING_AWG3", "is_fatal_issue",
    "ISSUE_NO_INTERFACE", "ISSUE_NO_PEER", "ISSUE_NO_PRIVATE_KEY", "ISSUE_BAD_PRIVATE_KEY",
    "ISSUE_NO_PEER_PUBLIC_KEY", "ISSUE_BAD_PEER_PUBLIC_KEY", "ISSUE_NO_ENDPOINT", "ISSUE_ENDPOINT_NO_PORT",
    "ISSUE_NO_ADDRESS", "ISSUE_MASQUE_NOT_JSON", "ISSUE_MASQUE_NOT_IDENTITY", "ISSUE_MASQUE_NO_PRIVATE_KEY",
    "ISSUE_MASQUE_BAD_PRIVATE_KEY", "ISSUE_MASQUE_NO_PUB_KEY", "ISSUE_MASQUE_BAD_PUB_KEY",
    "ISSUE_MASQUE_NO_ENDPOINT", "ISSUE_MASQUE_NO_TUNNEL_ADDRESS", "ISSUE_AMNEZIA_UNREADABLE",
    "ISSUE_TEXT_TOO_LARGE", "ISSUE_UNKNOWN_KIND",
    "ISSUE_FILE_BOM", "ISSUE_FILE_UTF16", "ISSUE_MASQUE_BAD_IPV4", "ISSUE_MASQUE_BAD_IPV6",
    "ISSUE_MASQUE_BAD_FIELD_TYPE",
    "REASON_PROFILE_DELETED", "REASON_GROUP_EMPTY", "REASON_UNKNOWN_GROUP", "REASON_PROFILE_INVALID",
    "REASON_UNKNOWN_MODE", "DEFAULT_RECOVERY_BUDGET",
    # paths
    "profiles_dir", "group_dir", "runtime_dir", "selection_path", "stats_path", "legacy_awg_dir",
    "make_profile_id", "split_profile_id", "relay_key_candidates", "runtime_config_path", "ensure_layout",
    # listing
    "list_profiles", "natural_key",
    # selection / plans
    "load_selection", "save_selection", "normalize_selection", "resolve_effective_selection",
    "group_empty_message", "build_attempt_plan", "build_recovery_plan", "record_country", "proton_countries",
    # stats
    "load_stats", "record_outcome", "record_rtts",
    # parsing / import
    "parse_awg_conf", "awg_identity_key", "validate_awg_conf", "awg_fingerprint",
    "looks_like_masque_identity", "normalize_masque_identity", "masque_fingerprint",
    "parse_import_text", "safe_profile_name", "import_candidates", "delete_profile", "rename_profile",
    # migration
    "migrate_legacy_layout",
]

# --------------------------------------------------------------------------------------------
# Layout constants (names fixed by the design contract)

PROFILES_DIRNAME = "profiles"
GROUP_CLOUDFLARE = "AWG Cloudflare"
GROUP_PROTON = "AWG Proton"
GROUP_MASQUE = "MASQUE"
GROUP_CUSTOM = "Custom"
GROUPS = (GROUP_CLOUDFLARE, GROUP_PROTON, GROUP_MASQUE, GROUP_CUSTOM)
RUNTIME_DIRNAME = ".runtime"
RELAY_KEY_FILENAME = "opera_relay.key"
LEGACY_AWG_DIRNAME = "awg"
SELECTION_FILENAME = "profile-selection.json"
STATS_FILENAME = "profile-stats.json"
GENERATED_WARP_PREFIX = "WARPgen_"
BUNDLED_WARP_PREFIX = "WARPv"

TEMP_DIRNAME = "temp"
CF_WS_KEY_FILENAME = "cf_ws.key"
LEGACY_AWG_STATE_FILENAME = "awg-profile-state.json"
# Private material that sits next to profiles but is not a profile itself. warp_native_profile.json
# is nova.pyw's personal overlay identity (moved out of temp/); it has private_key and would
# otherwise pass for a MASQUE identity.
PRIVATE_FILENAMES = ("warp_identity.json", "proton_account.json", "proton_nodes.json", "warp_native_profile.json")
# Folders where Nova keeps its own non-profile JSON: an unrelated JSON there is not listed. In
# MASQUE and Custom every JSON is a profile, broken or not, so it stays visible and deletable.
_NON_PROFILE_JSON_GROUPS = (GROUP_CLOUDFLARE, GROUP_PROTON)
_IGNORED_SUFFIXES = (".tmp", ".pending", ".lock", ".bak")

MODE_AUTO = "auto"
MODE_GROUP = "group"
MODE_PROFILE = "profile"
_MODES = (MODE_AUTO, MODE_GROUP, MODE_PROFILE)

BACKEND_AWG = "awg"
BACKEND_MASQUE = "masque"
BACKEND_WARP_CLI = "warp-cli"

ORIGIN_BUNDLED = "bundled"
ORIGIN_GENERATED = "generated"
ORIGIN_IMPORTED = "imported"

KIND_AWG = "awg"
KIND_MASQUE = "masque"

AUTO_GENERATED_LEAD_LIMIT = 12
AUTO_PROTON_LIMIT = 10
DEFAULT_RECOVERY_BUDGET = 4
# Proton connect queue (Nova Android G207): a failure older than this no longer sinks a node.
# Nodes die and come back between sessions; a queue that remembers every failure forever ends up
# looping over the same few survivors.
PROTON_FAILURE_MEMORY_SEC = 6 * 3600
# «Авто» stops trying MASQUE after this many failures in a row, until the last failure is this old
# (Nova Android MasqueStartPolicy.AUTO_FIRST_FAILURE_LIMIT). A MASQUE attempt costs tens of seconds
# on a network that cuts it, and in «Авто» it is a guess, not the user's request -- a guess that must
# be able to expire, so the lockout is timed, not permanent.
AUTO_MASQUE_FAILURE_LIMIT = 2
AUTO_MASQUE_LOCKOUT_SEC = 20 * 60
# PC order recommended by and-masque.md §4.1: 443 first (the only port with the TCP fallback),
# 8095 last because of the rx=0 measurement.
MASQUE_DEFAULT_PORTS = (443, 8443, 4443, 500, 1701, 4500, 8095)
_MASQUE_SIBLINGS_V4 = ("162.159.198.1", "162.159.198.2")
_MASQUE_SIBLINGS_V6 = ("2606:4700:103::1", "2606:4700:103::2")

_MAX_PROFILE_FILE_BYTES = 1024 * 1024
_MAX_IMPORT_TEXT_CHARS = 4 * 1024 * 1024
_MAX_AMNEZIA_JSON_BYTES = 4 * 1024 * 1024
_MAX_NAME_CHARS = 80
_MAX_STATS_ENTRIES = 1000

_BUNDLED_NAME_RE = re.compile(r"(?i)WARPv[0-9A-Za-z_-]*")
_GENERATED_WARP_NAME_RE = re.compile(r"(?i)WARPgen_[0-9]+")
_GENERATED_PROTON_NAME_RE = re.compile(r"(?i)[A-Z]{2,3}-FREE-[0-9]+")
_RUNTIME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")

# --------------------------------------------------------------------------------------------
# Issue texts (user-visible, Russian)

ISSUE_NO_INTERFACE = "Нет секции [Interface]"
ISSUE_NO_PEER = "Нет секции [Peer]"
ISSUE_NO_PRIVATE_KEY = "Нет PrivateKey"
ISSUE_BAD_PRIVATE_KEY = "PrivateKey не 32 байта"
ISSUE_NO_PEER_PUBLIC_KEY = "Нет PublicKey пира"
ISSUE_BAD_PEER_PUBLIC_KEY = "PublicKey пира не 32 байта"
ISSUE_NO_ENDPOINT = "Нет Endpoint"
ISSUE_ENDPOINT_NO_PORT = "Endpoint без порта"
ISSUE_NO_ADDRESS = "Нет Address"
WARNING_AWG3 = "параметры AWG 3.x не поддерживаются ядром — сервер может не принять рукопожатие"

ISSUE_MASQUE_NOT_JSON = "Файл не разбирается как JSON"
ISSUE_MASQUE_NOT_IDENTITY = "JSON не похож на профиль MASQUE"
ISSUE_MASQUE_NO_PRIVATE_KEY = "Нет private_key"
ISSUE_MASQUE_BAD_PRIVATE_KEY = "private_key не разбирается как ключ P-256 (SEC1)"
ISSUE_MASQUE_NO_PUB_KEY = "Нет endpoint_pub_key"
ISSUE_MASQUE_BAD_PUB_KEY = "endpoint_pub_key не разбирается как открытый ключ P-256"
ISSUE_MASQUE_NO_ENDPOINT = "Нет адреса сервера (endpoint_v4 / endpoint_v6)"
ISSUE_MASQUE_NO_TUNNEL_ADDRESS = "Нет внутреннего адреса (ipv4 / ipv6)"
ISSUE_MASQUE_BAD_IPV4 = "ipv4 не IPv4-адрес"
ISSUE_MASQUE_BAD_IPV6 = "ipv6 не IPv6-адрес"
# Followed by ": <key>" — nova-go's json.Unmarshal rejects the whole file for one mistyped field.
ISSUE_MASQUE_BAD_FIELD_TYPE = "Поле неверного типа"

# The readers that consume a profile (nova.pyw's wg-quick reader, nova-go's JSON decoder) take the
# bytes as UTF-8 and do not skip a BOM, so these files fail there however they look in an editor.
ISSUE_FILE_BOM = "Файл сохранён в UTF-8 с BOM — пересохраните его как UTF-8 без BOM"
ISSUE_FILE_UTF16 = "Файл сохранён в UTF-16 («Юникод») — пересохраните его как UTF-8"

ISSUE_AMNEZIA_UNREADABLE = (
    "Не удалось разобрать ключ Amnezia vpn://. Попробуйте экспортировать из Amnezia обычный "
    "AmneziaWG/WireGuard .conf и импортировать его."
)
ISSUE_TEXT_TOO_LARGE = "Текст слишком большой для импорта"
ISSUE_UNKNOWN_KIND = "Неизвестный вид профиля"

_WARNING_ISSUES = frozenset({WARNING_AWG3})


def is_fatal_issue(issue):
    """True when an issue makes a profile unusable; AWG 3.x keys are only a warning."""
    return issue not in _WARNING_ISSUES


# Selection reasons
REASON_PROFILE_DELETED = "профиль удалён"
REASON_GROUP_EMPTY = "в группе нет профилей"
REASON_UNKNOWN_GROUP = "неизвестная группа"
REASON_PROFILE_INVALID = "профиль с ошибками"
REASON_UNKNOWN_MODE = "неизвестный режим"
REASON_COUNTRY_EMPTY = "нет профилей этой страны"

# --------------------------------------------------------------------------------------------
# Paths


def profiles_dir(base_dir):
    return os.path.join(base_dir, PROFILES_DIRNAME)


def group_dir(base_dir, group):
    if group not in GROUPS:
        raise ValueError(f"Неизвестная группа профилей: {group}")
    return os.path.join(profiles_dir(base_dir), group)


def runtime_dir(base_dir):
    return os.path.join(profiles_dir(base_dir), RUNTIME_DIRNAME)


def selection_path(base_dir):
    return os.path.join(base_dir, TEMP_DIRNAME, SELECTION_FILENAME)


def stats_path(base_dir):
    return os.path.join(base_dir, TEMP_DIRNAME, STATS_FILENAME)


def legacy_awg_dir(base_dir):
    return os.path.join(base_dir, LEGACY_AWG_DIRNAME)


def make_profile_id(group, name):
    return f"{group}/{name}"


def split_profile_id(profile_id):
    """`"AWG Cloudflare/WARPv1_11"` -> `("AWG Cloudflare", "WARPv1_11")`; no known group -> `("", id)`."""
    value = str(profile_id or "").strip()
    group, sep, name = value.partition("/")
    if sep and group in GROUPS and name:
        return group, name
    return "", value


def relay_key_candidates(base_dir):
    """Where the Opera relay password is read from, in order (the legacy path is a read fallback)."""
    return [
        os.path.join(profiles_dir(base_dir), RELAY_KEY_FILENAME),
        os.path.join(legacy_awg_dir(base_dir), RELAY_KEY_FILENAME),
    ]


def runtime_config_path(base_dir, profile_id):
    """Rendered wireproxy config for a profile: `profiles/.runtime/<sanitised id>.conf`.

    The contract regex maps "AWG Cloudflare/WARPv1_11" to "AWG_Cloudflare_WARPv1_11". It is
    lossy for stems with spaces or Cyrillic ("Custom/Германия" and "Custom/Франция" would both
    become "Custom_"), and two profiles sharing one runtime file can start with each other's
    key. Such stems get a short hash of the id appended; ASCII-safe stems keep the exact
    contract name.
    """
    value = str(profile_id or "awg")
    safe = _RUNTIME_SAFE_RE.sub("_", value)
    _group, stem = split_profile_id(value)
    if _RUNTIME_SAFE_RE.search(stem):
        safe = f"{safe}-{hashlib.sha1(value.encode('utf-8')).hexdigest()[:8]}"
    return os.path.join(runtime_dir(base_dir), f"{safe}.conf")


def _set_hidden_attribute(path):
    """Best-effort FILE_ATTRIBUTE_HIDDEN on Windows; returns whether the attribute is set."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_attrs = kernel32.GetFileAttributesW
        get_attrs.argtypes = [wintypes.LPCWSTR]
        get_attrs.restype = wintypes.DWORD
        set_attrs = kernel32.SetFileAttributesW
        set_attrs.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
        set_attrs.restype = wintypes.BOOL
        attrs = get_attrs(path)
        if attrs == 0xFFFFFFFF:
            return False
        if attrs & 0x2:
            return True
        return bool(set_attrs(path, attrs | 0x2))
    except (OSError, AttributeError, ValueError):
        return False


def ensure_layout(base_dir):
    """Create `profiles/`, the four group folders and `.runtime`; returns the folders created.

    Raises OSError when a folder cannot be created (e.g. a file named `profiles` is in the way).
    """
    created = []
    targets = [profiles_dir(base_dir)] + [os.path.join(profiles_dir(base_dir), g) for g in GROUPS]
    targets.append(runtime_dir(base_dir))
    for path in targets:
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
            created.append(path)
    _set_hidden_attribute(runtime_dir(base_dir))
    return created


# --------------------------------------------------------------------------------------------
# Small helpers


def _decode_bytes(data):
    # utf-8 with errors ignored, as nova.pyw read profiles; Notepad's "Unicode" (UTF-16 with a
    # BOM) is decoded properly instead of turning into NUL-separated garbage.
    data = bytes(data)
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="ignore")
    return data.decode("utf-8", errors="ignore")


def _coerce_text(value):
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return _decode_bytes(value)
    return str(value)


def _read_profile_bytes(path):
    """Raw profile bytes. Raises OSError, or ValueError for a file over the size cap."""
    with open(path, "rb") as handle:
        data = handle.read(_MAX_PROFILE_FILE_BYTES + 1)
    if len(data) > _MAX_PROFILE_FILE_BYTES:
        raise ValueError("файл больше 1 МБ")
    return data


def _strip_bom(text):
    return text[1:] if text.startswith("\ufeff") else text


def _meant_text(data):
    """What the file says to a person: UTF-16 decoded, a leading BOM dropped."""
    return _strip_bom(_decode_bytes(data))


def _read_profile_text(path):
    """Read a profile file the way nova.pyw did (utf-8, errors ignored), minus a leading BOM.

    Raises OSError, or ValueError for a file over the size cap.
    """
    return _meant_text(_read_profile_bytes(path))


def _file_encoding_issue(data):
    """The encoding a consumer reading plain UTF-8 would trip over, or ""."""
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return ISSUE_FILE_UTF16
    if data.startswith(codecs.BOM_UTF8):
        return ISSUE_FILE_BOM
    return ""


def _reject_json_constant(constant):
    raise ValueError(f"non-standard JSON constant {constant}")


def _loads_strict_json(text):
    """json.loads without NaN/Infinity: Go's encoding/json (nova-go) refuses them."""
    return json.loads(text, parse_constant=_reject_json_constant)


def _replace_with_retry(src, dst, attempts=10, pause=0.05):
    # Windows refuses os.replace while an indexer or antivirus holds the target for a moment.
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(pause)


def _atomic_write_bytes(path, data):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _replace_with_retry(tmp, path)
    except BaseException:
        _remove_quietly(tmp)
        raise


def _atomic_write_json(path, payload):
    data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    _atomic_write_bytes(path, data)


def _remove_quietly(path):
    """Remove a leftover temp/derived file; a failure here never matters for correctness."""
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def _as_int(value, default=0):
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):  # OverflowError: int(float("inf"))
        return default


def _as_float(value, default):
    if isinstance(value, bool) or value is None:
        return default
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(result):  # NaN/Infinity from a hand-edited file would poison later math
        return default
    return result


def natural_key(name):
    """Sort key with numbers compared as numbers: WARPv1_2 before WARPv1_11."""
    text = str(name or "")
    parts = re.split(r"([0-9]+)", text.lower())
    key = tuple(int(part) if index % 2 else part for index, part in enumerate(parts))
    return (key, text.lower(), text)


def _strip_inline_comment(value):
    # go-ini (wireproxy) drops "value # comment"; keys and endpoints never contain '#' or ';'.
    match = re.search(r"\s[#;]", value)
    return value[: match.start()].strip() if match else value.strip()


def _split_endpoint(value):
    """`host:port` or `[v6]:port` -> (host, port); anything else (no port, bad port) -> None."""
    text = _strip_inline_comment(str(value or ""))
    match = re.fullmatch(r"\[([^\]\s]+)\]:([0-9]{1,5})", text)
    if match:
        host, port = match.group(1), int(match.group(2))
    elif text.count(":") == 1:
        host, _, port_text = text.partition(":")
        if not re.fullmatch(r"[0-9]{1,5}", port_text):
            return None
        host, port = host.strip(), int(port_text)
    else:
        return None
    if not host or re.search(r"\s", host) or not 1 <= port <= 65535:
        return None
    return host, port


def _is_wg_key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def _sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------------
# AWG / wg-quick parsing

_AWG_KEY_RE = re.compile(r"(?i)^(jc|jmin|jmax|s[1-4]|h[1-4]|i[1-5])$")
_AWG3_KEY_RE = re.compile(
    r"(?im)^[ \t]*(HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|"
    r"RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies)[ \t]*="
)


def _text_mode_lines(text):
    # Same line splitting as iterating a file opened in text mode (universal newlines).
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def parse_awg_conf(text):
    """Parse wg-quick/AWG text exactly like nova.pyw `WarpManager._parse_awg_source_profile`.

    `#`/`;` comment lines are skipped, keys are lowercased into `interface`/`peer` (last one
    wins), AWG keys Jc/Jmin/Jmax/S1-4/H1-4/I1-5 of `[Interface]` are also kept verbatim in
    `awg_lines` with their original case. `Reserved` and every other key stay out of
    `awg_lines`. A leading BOM is NOT stripped here: nova.pyw's reader keeps it, which is why
    `list_profiles` flags a file whose BOM hides a line (`ISSUE_FILE_BOM`).
    """
    parsed = {"interface": {}, "peer": {}, "awg_lines": []}
    current_section = ""
    for line in _text_mode_lines(_coerce_text(text)):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1].strip().lower()
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        key_low = key.lower()
        if current_section == "interface":
            parsed["interface"][key_low] = value
            if _AWG_KEY_RE.match(key):
                parsed["awg_lines"].append(f"{key} = {value}")
        elif current_section == "peer":
            parsed["peer"][key_low] = value
    return parsed


def awg_identity_key(parsed, path_or_name=""):
    """The WireGuard identity a profile connects as (nova.pyw `_awg_profile_identity_key`)."""
    interface = (parsed or {}).get("interface", {}) or {}
    key = str(interface.get("privatekey", "")).strip()
    if key:
        return key
    address = str(interface.get("address", "")).strip()
    if address:
        return address
    return os.path.basename(str(path_or_name or ""))


def _sections(text):
    found = set()
    for line in _text_mode_lines(text):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            found.add(stripped[1:-1].strip().lower())
    return found


def validate_awg_conf(text):
    """Russian issues for a wg-quick/AWG text; empty list means usable.

    Only `WARNING_AWG3` is non-fatal (see `is_fatal_issue`).
    """
    text = _coerce_text(text)
    parsed = parse_awg_conf(text)
    sections = _sections(text)
    interface, peer = parsed["interface"], parsed["peer"]
    issues = []
    if "interface" not in sections:
        issues.append(ISSUE_NO_INTERFACE)
    if "peer" not in sections:
        issues.append(ISSUE_NO_PEER)
    private_key = _strip_inline_comment(interface.get("privatekey", ""))
    if not private_key:
        issues.append(ISSUE_NO_PRIVATE_KEY)
    elif not _is_wg_key(private_key):
        issues.append(ISSUE_BAD_PRIVATE_KEY)
    public_key = _strip_inline_comment(peer.get("publickey", ""))
    if not public_key:
        issues.append(ISSUE_NO_PEER_PUBLIC_KEY)
    elif not _is_wg_key(public_key):
        issues.append(ISSUE_BAD_PEER_PUBLIC_KEY)
    endpoint = _strip_inline_comment(peer.get("endpoint", ""))
    if not endpoint:
        issues.append(ISSUE_NO_ENDPOINT)
    elif _split_endpoint(endpoint) is None:
        issues.append(ISSUE_ENDPOINT_NO_PORT)
    if not _strip_inline_comment(interface.get("address", "")):
        issues.append(ISSUE_NO_ADDRESS)
    if _AWG3_KEY_RE.search(text):
        issues.append(WARNING_AWG3)
    return issues


def _fingerprint_value(key, value):
    value = _strip_inline_comment(value)
    value = re.sub(r"\s*,\s*", ", ", re.sub(r"\s+", " ", value))
    if key == "endpoint":
        value = value.lower()
    return value


def awg_fingerprint(text):
    """sha256 over sorted `section.key=value` pairs of Interface+Peer; comments, DNS and MTU ignored.

    Two exports of one server that differ only in comments, spacing, DNS or MTU are duplicates.
    """
    parsed = parse_awg_conf(text)
    pairs = []
    for section in ("interface", "peer"):
        for key, value in parsed[section].items():
            if key in ("dns", "mtu"):
                continue
            pairs.append(f"{section}.{key}={_fingerprint_value(key, value)}")
    pairs.sort()
    return _sha256_hex("awg\n" + "\n".join(pairs))


# --------------------------------------------------------------------------------------------
# MASQUE identities (port of Nova Android nova-core/engine/masque.go parseMasqueIdentity)

_MASQUE_DETECT_KEYS = (
    "endpoint_pub_key", "endpoint_v4", "endpoint_v6", "endpoint_v4_candidates", "endpoint_v6_candidates",
)


def looks_like_masque_identity(obj):
    """Android `masque_config.json` or usque `config.json` shape (private_key + endpoint keys)."""
    return isinstance(obj, dict) and "private_key" in obj and any(key in obj for key in _MASQUE_DETECT_KEYS)


def _json_str(value):
    return value.strip() if isinstance(value, str) else ""


def _parse_ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _canonical_ip(value, want_v4):
    """nova-go normalizeEndpointCandidates: netip.ParseAddr, Unmap, family filter -> text, or ""."""
    ip = _parse_ip(value)
    if ip is None:
        return ""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (ip.version == 4) != want_v4:
        return ""
    return str(ip)


def _normalize_tunnel_address(raw):
    """nova-go normalizeTunnelAddress: "172.16.0.2/32" -> "172.16.0.2"; anything unparsable is kept."""
    value = str(raw or "").strip()
    address, sep, bits = value.partition("/")
    if sep:
        ip = _parse_ip(address)
        if ip is not None and "%" not in address and re.fullmatch(r"[0-9]{1,3}", bits) \
                and int(bits) <= (32 if ip.version == 4 else 128):
            return str(ip)
        return value
    ip = _parse_ip(value)
    return str(ip) if ip is not None else value


def _normalize_endpoint_host(raw):
    value = str(raw or "").strip()
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")].strip()
    if value.count(":") == 1:
        host = value.split(":", 1)[0]
        return host.strip().strip("[]")
    if _parse_ip(value) is not None:
        return value
    return value.strip("[]")


def _normalize_masque_candidates(primary, candidates, want_v4):
    ordered = []

    def add(value):
        normalized = _canonical_ip(_normalize_endpoint_host(value), want_v4)
        if normalized and normalized not in ordered:
            ordered.append(normalized)

    add(primary)
    for candidate in candidates if isinstance(candidates, list) else []:
        if isinstance(candidate, str):
            add(candidate)
    siblings = _MASQUE_SIBLINGS_V4 if want_v4 else _MASQUE_SIBLINGS_V6
    if any(candidate in siblings for candidate in ordered):
        for sibling in siblings:
            add(sibling)
    return ordered


def _normalize_masque_ports(ports):
    ordered = []
    for port in ports if isinstance(ports, list) else []:
        if isinstance(port, bool):
            continue
        if isinstance(port, float):
            value = int(port) if port.is_integer() else 0
        elif isinstance(port, int):
            value = port
        elif isinstance(port, str) and port.strip().isdigit():
            value = int(port.strip())
        else:
            value = 0
        if 0 < value <= 65535 and value not in ordered:
            ordered.append(value)
    for port in MASQUE_DEFAULT_PORTS:
        if port not in ordered:
            ordered.append(port)
    return ordered


def _is_sec1_der(der):
    # SEC1 ECPrivateKey: SEQUENCE { INTEGER 1, ... }; PKCS#8 starts with INTEGER 0 and Go's
    # x509.ParseECPrivateKey (the helper) rejects it.
    if len(der) < 5 or der[0] != 0x30:
        return False
    first = der[1]
    if first < 0x80:
        offset = 2
    elif first == 0x81:
        offset = 3
    elif first == 0x82:
        offset = 4
    else:
        return False
    return der[offset:offset + 3] == b"\x02\x01\x01"


def _masque_key_issues(private_key, public_pem):
    issues = []
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        return issues
    try:
        # Go's base64.StdEncoding skips CR/LF only; any other whitespace inside the key is an error.
        der = base64.b64decode(re.sub(r"[\r\n]+", "", private_key), validate=True)
        key = serialization.load_der_private_key(der, password=None)
        private_ok = (
            _is_sec1_der(der)
            and isinstance(key, ec.EllipticCurvePrivateKey)
            and isinstance(key.curve, ec.SECP256R1)
        )
    except (binascii.Error, ValueError, TypeError, UnsupportedAlgorithm):
        private_ok = False
    if not private_ok:
        issues.append(ISSUE_MASQUE_BAD_PRIVATE_KEY)
    try:
        public = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        public_ok = isinstance(public, ec.EllipticCurvePublicKey) and isinstance(public.curve, ec.SECP256R1)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        public_ok = False
    if not public_ok:
        issues.append(ISSUE_MASQUE_BAD_PUB_KEY)
    return issues


def normalize_masque_identity(obj):
    """Normalise an Android/usque MASQUE JSON object -> (identity dict in Android key order, issues).

    usque's `id` maps to `device_id`. Mirrors nova-go `Identity.normalize` + `Validate`: an endpoint
    is the first IP of its family (a host name or the other family is dropped, never dialled),
    candidates get the known Cloudflare siblings, tunnel addresses lose a `/32`/`/128` and must be
    real addresses, ports get the defaults appended. A `nova` metadata object is preserved.
    """
    if not isinstance(obj, dict):
        return {}, [ISSUE_MASQUE_NOT_IDENTITY]
    private_key = _json_str(obj.get("private_key"))
    public_pem = _json_str(obj.get("endpoint_pub_key"))
    candidates_v4 = _normalize_masque_candidates(
        _normalize_endpoint_host(_json_str(obj.get("endpoint_v4"))), obj.get("endpoint_v4_candidates"), True)
    candidates_v6 = _normalize_masque_candidates(
        _normalize_endpoint_host(_json_str(obj.get("endpoint_v6"))), obj.get("endpoint_v6_candidates"), False)
    endpoint_v4 = candidates_v4[0] if candidates_v4 else ""
    endpoint_v6 = candidates_v6[0] if candidates_v6 else ""
    device_id = _json_str(obj.get("device_id")) or _json_str(obj.get("id"))

    identity = {"private_key": private_key}
    if endpoint_v4:
        identity["endpoint_v4"] = endpoint_v4
    if endpoint_v6:
        identity["endpoint_v6"] = endpoint_v6
    if candidates_v4:
        identity["endpoint_v4_candidates"] = candidates_v4
    if candidates_v6:
        identity["endpoint_v6_candidates"] = candidates_v6
    identity["endpoint_pub_key"] = public_pem
    endpoint_host = _json_str(obj.get("endpoint_host"))
    if endpoint_host:
        identity["endpoint_host"] = endpoint_host
    identity["ipv4"] = _normalize_tunnel_address(_json_str(obj.get("ipv4")))
    identity["ipv6"] = _normalize_tunnel_address(_json_str(obj.get("ipv6")))
    identity["ports"] = _normalize_masque_ports(obj.get("ports"))
    for key in ("access_token",):
        if _json_str(obj.get(key)):
            identity[key] = _json_str(obj.get(key))
    if device_id:
        identity["device_id"] = device_id
    if _json_str(obj.get("license")):
        identity["license"] = _json_str(obj.get("license"))
    issued_at = _as_int(obj.get("issued_at"), 0)
    if issued_at > 0:
        identity["issued_at"] = issued_at
    if _json_str(obj.get("last_endpoint")):
        identity["last_endpoint"] = _json_str(obj.get("last_endpoint"))
    last_port = _as_int(obj.get("last_port"), 0)
    if 0 < last_port <= 65535:
        identity["last_port"] = last_port
    if isinstance(obj.get("nova"), dict):
        identity["nova"] = dict(obj["nova"])

    issues = []
    if not private_key:
        issues.append(ISSUE_MASQUE_NO_PRIVATE_KEY)
    if not public_pem:
        issues.append(ISSUE_MASQUE_NO_PUB_KEY)
    if not endpoint_v4 and not endpoint_v6:
        issues.append(ISSUE_MASQUE_NO_ENDPOINT)
    if not identity["ipv4"] and not identity["ipv6"]:
        issues.append(ISSUE_MASQUE_NO_TUNNEL_ADDRESS)
    if identity["ipv4"]:
        ip = _parse_ip(identity["ipv4"])
        if ip is None or ip.version != 4:
            issues.append(ISSUE_MASQUE_BAD_IPV4)
    if identity["ipv6"]:
        ip = _parse_ip(identity["ipv6"])
        if ip is None or ip.version != 6 or ip.ipv4_mapped is not None:  # Go: !Is6() || Is4In6()
            issues.append(ISSUE_MASQUE_BAD_IPV6)
    if private_key and public_pem:
        issues.extend(_masque_key_issues(private_key, public_pem))
    return identity, issues


# Go types of nova-go `Identity` (+ usque `id`). encoding/json matches keys case-insensitively and
# fails the whole ParseIdentity on one mistyped value; JSON null is fine for every field.
_MASQUE_GO_FIELD_KINDS = {
    "private_key": "string", "endpoint_v4": "string", "endpoint_v6": "string",
    "endpoint_v4_candidates": "strings", "endpoint_v6_candidates": "strings", "endpoint_pub_key": "string",
    "endpoint_host": "string", "ipv4": "string", "ipv6": "string", "ports": "ints", "access_token": "string",
    "device_id": "string", "license": "string", "issued_at": "int", "last_endpoint": "string",
    "last_port": "int", "id": "string",
}


def _is_go_int(value):
    # A JSON number with a fraction or an exponent (443.0, 1e3) is a Python float and a Go error.
    return isinstance(value, int) and not isinstance(value, bool) and -(2 ** 63) <= value < 2 ** 63


def _masque_go_type_issues(obj):
    issues = []
    for key, value in obj.items():
        kind = _MASQUE_GO_FIELD_KINDS.get(str(key).lower())
        if kind is None or value is None:
            continue
        if kind == "string":
            ok = isinstance(value, str)
        elif kind == "int":
            ok = _is_go_int(value)
        elif kind == "strings":
            ok = isinstance(value, list) and all(item is None or isinstance(item, str) for item in value)
        else:
            ok = isinstance(value, list) and all(item is None or _is_go_int(item) for item in value)
        if not ok:
            issues.append(f"{ISSUE_MASQUE_BAD_FIELD_TYPE}: {str(key)[:40]}")
    return issues


def masque_fingerprint(identity):
    """A MASQUE identity is its private key: re-exports with other endpoints are duplicates."""
    private_key = re.sub(r"\s+", "", _json_str((identity or {}).get("private_key")))
    return _sha256_hex("masque\n" + private_key)


def _masque_endpoint(identity):
    host = identity.get("endpoint_v4") or ""
    if not host and identity.get("endpoint_v6"):
        host = f"[{identity['endpoint_v6']}]"
    if not host:
        return ""
    ports = identity.get("ports") or list(MASQUE_DEFAULT_PORTS)
    return f"{host}:{ports[0]}"


# --------------------------------------------------------------------------------------------
# Listing

_FILE_CACHE = {}
_FILE_CACHE_LOCK = threading.Lock()


def _is_ignored_filename(name):
    low = name.lower()
    return name.startswith(".") or low.endswith(_IGNORED_SUFFIXES) or low in PRIVATE_FILENAMES


def _origin_for(group, name, masque_source=""):
    if group == GROUP_CLOUDFLARE:
        if _BUNDLED_NAME_RE.fullmatch(name):
            return ORIGIN_BUNDLED
        if _GENERATED_WARP_NAME_RE.fullmatch(name):
            return ORIGIN_GENERATED
        return ORIGIN_IMPORTED
    if group == GROUP_PROTON:
        return ORIGIN_GENERATED if _GENERATED_PROTON_NAME_RE.fullmatch(name) else ORIGIN_IMPORTED
    if group == GROUP_MASQUE:
        return ORIGIN_IMPORTED if str(masque_source or "").lower().startswith("import") else ORIGIN_GENERATED
    return ORIGIN_IMPORTED


def _conf_file_info(path):
    data = _read_profile_bytes(path)
    # Everything is judged on the text WarpManager._parse_awg_source_profile sees (utf-8, errors
    # ignored, BOM kept): that reader renders the runtime config, so a file it misreads is unusable
    # however it looks in an editor. A BOM glued to a comment line hides nothing and stays valid.
    renderer_text = data.decode("utf-8", errors="ignore")
    parsed = parse_awg_conf(renderer_text)
    issues = validate_awg_conf(renderer_text)
    encoding_issue = _file_encoding_issue(data)
    if encoding_issue:
        meant_text = _meant_text(data)
        meant_issues = validate_awg_conf(meant_text)
        if meant_issues != issues or parse_awg_conf(meant_text) != parsed:
            # Name the cause, then what would still be wrong after re-saving as plain UTF-8.
            issues = [encoding_issue] + meant_issues
    return {
        "kind": KIND_AWG,
        "identity": awg_identity_key(parsed, path),
        "endpoint": _strip_inline_comment(parsed["peer"].get("endpoint", "")),
        "valid": not any(is_fatal_issue(issue) for issue in issues),
        "issues": issues,
        "fingerprint": awg_fingerprint(renderer_text),
        "masque_source": "",
    }


def _json_file_info(path, group):
    data = _read_profile_bytes(path)
    try:
        obj = _loads_strict_json(_meant_text(data))
    except ValueError:
        obj = None
    encoding_issue = _file_encoding_issue(data)
    if not looks_like_masque_identity(obj):
        if group in _NON_PROFILE_JSON_GROUPS:
            return None  # Nova's own non-profile JSON can sit in the AWG folders
        # In MASQUE and Custom a broken file stays listed: an explicit choice of it must fail
        # visibly (I1) instead of the profile vanishing and its group taking over.
        return {
            "kind": KIND_MASQUE,
            "identity": path,
            "endpoint": "",
            "valid": False,
            "issues": ([encoding_issue] if encoding_issue else [])
            + [ISSUE_MASQUE_NOT_JSON if obj is None else ISSUE_MASQUE_NOT_IDENTITY],
            "fingerprint": "",
            "masque_source": "",
        }
    identity, issues = normalize_masque_identity(obj)
    # nova-go strips a UTF-8 BOM and decodes UTF-16 before encoding/json (masque/identity.go
    # profileText), so the encoding is no issue for a file it parses; the exact Go types still are.
    issues = _masque_go_type_issues(obj) + issues
    nova = identity.get("nova") if isinstance(identity.get("nova"), dict) else {}
    return {
        "kind": KIND_MASQUE,
        "identity": identity.get("device_id") or path,
        "endpoint": _masque_endpoint(identity),
        "valid": not any(is_fatal_issue(issue) for issue in issues),
        "issues": issues,
        "fingerprint": masque_fingerprint(identity),
        "masque_source": _json_str(nova.get("source")),
    }


def _file_info(path, st, ext, group):
    signature = (st.st_mtime_ns, st.st_size, group)
    with _FILE_CACHE_LOCK:
        cached = _FILE_CACHE.get(path)
    if cached is not None and cached[0] == signature:
        info = cached[1]
    else:
        try:
            info = _conf_file_info(path) if ext == ".conf" else _json_file_info(path, group)
        except (OSError, ValueError) as exc:
            reason = getattr(exc, "strerror", None) or str(exc)
            # Not cached: a file that is being written right now is re-read next time.
            return {
                "kind": KIND_MASQUE if ext == ".json" else KIND_AWG,
                "identity": path,
                "endpoint": "",
                "valid": False,
                "issues": [f"Не удалось прочитать файл: {reason}"],
                "fingerprint": "",
                "masque_source": "",
            }
        with _FILE_CACHE_LOCK:
            if len(_FILE_CACHE) > 4096:
                _FILE_CACHE.clear()
            _FILE_CACHE[path] = (signature, info)
    if info is None:
        return None
    result = dict(info)
    result["issues"] = list(info["issues"])
    return result


def list_profiles(base_dir):
    """Every profile under `profiles/<group>/`, groups in `GROUPS` order, natural name order inside.

    Pure read: never creates folders, never raises for a missing or unreadable folder.
    Record: id, group, name, path, kind, origin, identity, endpoint, valid, issues, fingerprint.
    `valid` means the consumer will read the file as written: a .conf is judged on the text
    nova.pyw's reader sees (a BOM or UTF-16 that hides lines -> ISSUE_FILE_BOM/UTF16), a .json on
    nova-go's ParseIdentity rules. Every .json in MASQUE and Custom is listed, broken ones as
    invalid; in the two AWG folders only MASQUE identities are.
    """
    root = os.path.abspath(profiles_dir(base_dir))
    records = []
    for group in GROUPS:
        folder = os.path.join(root, group)
        try:
            entries = os.listdir(folder)
        except OSError:
            continue
        group_records = []
        seen_ids = set()
        # .conf before .json so a stem clash keeps the AWG file on the plain id.
        entries.sort(key=lambda e: (os.path.splitext(e)[1].lower() != ".conf", e.lower()))
        for entry in entries:
            if _is_ignored_filename(entry):
                continue
            stem, ext = os.path.splitext(entry)
            ext = ext.lower()
            if ext not in (".conf", ".json") or not stem:
                continue
            path = os.path.join(folder, entry)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            info = _file_info(path, st, ext, group)
            if info is None:
                continue
            profile_id = make_profile_id(group, stem)
            issues = info["issues"]
            valid = info["valid"]
            if profile_id.lower() in seen_ids:
                # "x.conf" and "x.json" in one folder: the second keeps a distinct id and is unusable.
                profile_id = make_profile_id(group, entry)
                issues = issues + [f"Имя «{stem}» уже занято другим файлом этой группы"]
                valid = False
            seen_ids.add(profile_id.lower())
            group_records.append({
                "id": profile_id,
                "group": group,
                "name": stem,
                "path": path,
                "kind": info["kind"],
                "origin": _origin_for(group, stem, info["masque_source"]),
                "identity": info["identity"],
                "endpoint": info["endpoint"],
                "valid": valid,
                "issues": issues,
                "fingerprint": info["fingerprint"],
            })
        group_records.sort(key=lambda r: natural_key(r["name"]))
        records.extend(group_records)
    return records


def _find_record(base_dir, profile_id):
    wanted = str(profile_id or "").strip()
    records = list_profiles(base_dir)
    for record in records:
        if record["id"] == wanted:
            return record
    for record in records:
        if record["id"].lower() == wanted.lower():
            return record
    return None


# --------------------------------------------------------------------------------------------
# Selection model


_COUNTRY_CODE_RE = re.compile(r"[A-Z]{2}")
_PROTON_COUNTRY_NAME_RE = re.compile(r"(?i)([A-Z]{2})-FREE-[0-9]+")


def normalize_selection(sel):
    """Coerce any selection-like value to `{"version":1,"mode",["group"],["profile"],["country"]}`.

    `country` exists only for the Proton group: it narrows the group to one exit country. An empty
    country means "any country, nearest first".
    """
    if not isinstance(sel, dict):
        return {"version": 1, "mode": MODE_AUTO}
    mode = str(sel.get("mode") or "").strip().lower()
    if mode not in _MODES:
        mode = MODE_AUTO
    out = {"version": 1, "mode": mode}
    group = sel.get("group")
    if isinstance(group, str) and group.strip():
        out["group"] = group.strip()
    profile = sel.get("profile")
    if not (isinstance(profile, str) and profile.strip()):
        profile = sel.get("profile_id")
    if isinstance(profile, str) and profile.strip():
        out["profile"] = profile.strip()
    country = str(sel.get("country") or "").strip().upper()
    if out.get("group", "").lower() == GROUP_PROTON.lower() and _COUNTRY_CODE_RE.fullmatch(country):
        out["country"] = country
    return out


def record_country(record):
    """Exit country of a profile when its name states one (`AWG Proton/NL-FREE-128` -> NL), else ""."""
    if not isinstance(record, dict) or record.get("group") != GROUP_PROTON:
        return ""
    match = _PROTON_COUNTRY_NAME_RE.fullmatch(str(record.get("name") or ""))
    return match.group(1).upper() if match else ""


def proton_countries(profiles):
    """Countries that valid Proton profiles actually exist for (unordered set)."""
    return {
        country
        for country in (record_country(r) for r in (profiles or []) if isinstance(r, dict) and r.get("valid"))
        if country
    }


def load_selection(base_dir):
    """The persisted choice; a missing or corrupt file means `{"version":1,"mode":"auto"}`."""
    try:
        with open(selection_path(base_dir), "rb") as handle:
            data = handle.read(65536)
        obj = json.loads(data.decode("utf-8-sig"))
    except (OSError, ValueError):
        return {"version": 1, "mode": MODE_AUTO}
    return normalize_selection(obj)


def save_selection(base_dir, sel):
    """Persist a selection atomically (tmp + fsync + os.replace). Returns what was written; raises OSError.

    Blocking I/O: the fsync, plus up to ~0.5 s of retries while an indexer, antivirus or a
    concurrent reader holds the target. Never call it on the Tk thread — save from the worker
    that applies the selection.
    """
    payload = normalize_selection(sel)
    _atomic_write_json(selection_path(base_dir), payload)
    return payload


def _match_group(value):
    text = str(value or "").strip()
    for group in GROUPS:
        if group == text:
            return group
    for group in GROUPS:
        if group.lower() == text.lower():
            return group
    return ""


def group_empty_message(group):
    return f"В группе «{group}» нет профилей"


def resolve_effective_selection(sel, profiles):
    """What the connect path should honour right now -> {"mode","group","profile_id","reason"}.

    A deleted profile behaves as its group and an empty group stays a group (I1); neither is
    persisted. Only a selection that cannot name a real group falls back to auto.
    """
    raw_mode = str((sel or {}).get("mode") or "").strip().lower() if isinstance(sel, dict) else ""
    normalized = normalize_selection(sel)
    mode = normalized["mode"]
    records = list(profiles or [])

    if mode == MODE_PROFILE:
        wanted = normalized.get("profile", "")
        record = next((r for r in records if r.get("id") == wanted), None)
        if record is None and wanted:
            record = next((r for r in records if str(r.get("id", "")).lower() == wanted.lower()), None)
        if record is not None:
            return {
                "mode": MODE_PROFILE,
                "group": record.get("group", ""),
                "profile_id": record["id"],
                "reason": "" if record.get("valid") else REASON_PROFILE_INVALID,
            }
        group = _match_group(wanted.partition("/")[0]) if "/" in wanted else ""
        if group:
            return {"mode": MODE_GROUP, "group": group, "profile_id": "", "reason": REASON_PROFILE_DELETED}
        return {"mode": MODE_AUTO, "group": "", "profile_id": "", "reason": REASON_PROFILE_DELETED}

    if mode == MODE_GROUP:
        group = _match_group(normalized.get("group", ""))
        if not group:
            return {"mode": MODE_AUTO, "group": "", "profile_id": "", "reason": REASON_UNKNOWN_GROUP}
        members = [r for r in records if r.get("group") == group and r.get("valid") and not _is_legacy_seed_copy(r)]
        effective = {
            "mode": MODE_GROUP,
            "group": group,
            "profile_id": "",
            "reason": "" if members else REASON_GROUP_EMPTY,
        }
        country = normalized.get("country", "") if group == GROUP_PROTON else ""
        if country:
            # A country is part of the explicit choice (I1): no profiles there means no profiles,
            # not "some other country".
            effective["country"] = country
            if members and not any(record_country(r) == country for r in members):
                effective["reason"] = REASON_COUNTRY_EMPTY
        return effective

    reason = REASON_UNKNOWN_MODE if raw_mode and raw_mode not in _MODES else ""
    return {"mode": MODE_AUTO, "group": "", "profile_id": "", "reason": reason}


# --------------------------------------------------------------------------------------------
# Attempt plans


def _attempt(record):
    backend = BACKEND_MASQUE if record.get("kind") == KIND_MASQUE else BACKEND_AWG
    return {"backend": backend, "profile": record}


_LEGACY_COPY_RE = re.compile(r"(?i)(.+) \(legacy(?: [0-9]+)?\)")


def _is_legacy_seed_copy(record):
    """`WARPv1_2 (legacy).conf`: an old install's shipped seed kept by migration because it differed.

    It stays listed and can be chosen as a profile, but automatic plans (auto, group) skip it:
    otherwise every upgrade could double the Cloudflare round-robin with stale seeds.
    """
    if record.get("group") != GROUP_CLOUDFLARE:
        return False
    match = _LEGACY_COPY_RE.fullmatch(str(record.get("name", "")))
    return bool(match and _BUNDLED_NAME_RE.fullmatch(match.group(1)))


def _generated_metrics(generated_state, record):
    profiles = generated_state.get("profiles") if isinstance(generated_state, dict) else None
    entry = {}
    if isinstance(profiles, dict):
        entry = profiles.get(record["name"]) or profiles.get(record["id"]) or {}
    if not isinstance(entry, dict):
        entry = {}
    return _as_int(entry.get("failures"), 0), _as_float(entry.get("rtt_ms"), float("inf"))


def _stats_failures(stats, record):
    entry = stats.get(record["id"]) if isinstance(stats, dict) else None
    return _as_int(entry.get("fail"), 0) if isinstance(entry, dict) else 0


def _identity_round_robin(records, preferred_id=""):
    """nova.pyw `_get_ordered_awg_profiles`: one profile per identity per pass, preferred first.

    The pre-sort is by lowercased name, as nova.pyw did (not natural order): it decides both
    the bucket order and the draw order inside a bucket, so it must not change.
    """
    ordered_input = sorted(records, key=lambda r: str(r.get("name", "")).lower())
    buckets = {}
    for record in ordered_input:
        buckets.setdefault(record.get("identity"), []).append(record)
    ordered = []
    remaining = True
    while remaining:
        remaining = False
        for bucket in buckets.values():
            if bucket:
                ordered.append(bucket.pop(0))
                if bucket:
                    remaining = True
    _move_to_front(ordered, preferred_id)
    return ordered


def _record_matches_preferred(record, preferred_id):
    if not preferred_id:
        return False
    if "/" in preferred_id:
        return str(record.get("id", "")).lower() == preferred_id.lower()
    # A bare stem is the pre-1.39 `preferred_profile`; it always meant the Cloudflare pool.
    return record.get("group") == GROUP_CLOUDFLARE and str(record.get("name", "")).lower() == preferred_id.lower()


def _move_to_front(records, preferred_id):
    for index, record in enumerate(records):
        if _record_matches_preferred(record, preferred_id):
            records.insert(0, records.pop(index))
            return True
    return False


def _cloudflare_segments(records, preferred_id, generated_state):
    """(lead, pool, rest): healthy own profiles by rtt, the shared/bundled pool, own profiles that failed."""
    generated = [r for r in records if r["origin"] == ORIGIN_GENERATED]
    pool = [r for r in records if r["origin"] != ORIGIN_GENERATED]  # bundled seeds + hand-dropped confs

    def generated_key(record):
        failures, rtt = _generated_metrics(generated_state, record)
        return (failures, rtt, natural_key(record["name"]))

    healthy = sorted((r for r in generated if _generated_metrics(generated_state, r)[0] == 0), key=generated_key)
    lead = healthy[:AUTO_GENERATED_LEAD_LIMIT]
    lead_ids = {r["id"] for r in lead}
    rest = sorted((r for r in generated if r["id"] not in lead_ids), key=generated_key)
    return lead, _identity_round_robin(pool, preferred_id), rest


def _cloudflare_order(records, preferred_id, generated_state):
    lead, pool, rest = _cloudflare_segments(records, preferred_id, generated_state)
    return lead + pool + rest


def _stats_order(records, stats):
    return sorted(records, key=lambda r: (_stats_failures(stats, r), natural_key(r["name"])))


def _stats_entry(stats, record):
    entry = stats.get(record["id"]) if isinstance(stats, dict) else None
    return entry if isinstance(entry, dict) else {}


def _proton_order(records, stats, now=None):
    """Proton connect queue by attempt outcomes, then distance (Nova Android G207 + ProtonLatency).

    0. nodes whose latest success is newer than their latest failure;
    1. untried nodes, and nodes whose failure is older than PROTON_FAILURE_MEMORY_SEC;
    2. recently failed nodes, the oldest failure first.
    Inside a bucket the nearest node (TCP 443 rtt, `rtt_ms`) goes first; unmeasured ones after, and
    lifetime failures break the remaining ties.
    """
    now = time.time() if now is None else float(now)

    def key(record):
        entry = _stats_entry(stats, record)
        last_ok = _as_float(entry.get("last_ok_at"), 0.0)
        last_fail = _as_float(entry.get("last_fail_at"), 0.0)
        rtt = _as_float(entry.get("rtt_ms"), float("inf"))
        if last_ok and last_ok >= last_fail:
            bucket, tiebreak = 0, 0.0
        elif last_fail and last_fail > last_ok and 0 <= now - last_fail < PROTON_FAILURE_MEMORY_SEC:
            bucket, tiebreak = 2, last_fail
        else:
            bucket, tiebreak = 1, 0.0
        return (bucket, tiebreak, rtt, _stats_failures(stats, record), natural_key(record["name"]))

    return sorted(records, key=key)


def _masque_locked_out(record, stats, now):
    """True while «Авто» should not guess this MASQUE profile (see AUTO_MASQUE_FAILURE_LIMIT)."""
    entry = _stats_entry(stats, record)
    streak = _as_int(entry.get("fail_streak"), 0)
    last_fail = _as_float(entry.get("last_fail_at"), 0.0)
    return streak >= AUTO_MASQUE_FAILURE_LIMIT and 0 <= now - last_fail < AUTO_MASQUE_LOCKOUT_SEC


def _front(records, preferred_id):
    ordered = list(records)
    _move_to_front(ordered, preferred_id)
    return ordered


def _contains_preferred(records, preferred_id):
    return any(_record_matches_preferred(r, preferred_id) for r in records)


def build_attempt_plan(profiles, sel, *, preferred_id="", generated_state=None, stats=None, now=None):
    """Ordered attempts for a connect: `[{"backend": "awg"|"masque"|"warp-cli", "profile": record|None}]`.

    Own profiles -- issued for this install (generated WARP, Proton, MASQUE) -- always go before the
    shared seeds everyone got with the installer (owner's rule: switch to personal profiles whenever
    a switch happens at all). A .conf dropped into the Cloudflare folder by hand stays in the seeds'
    round-robin, as it always did: its identity may well be a seed's. `preferred_id` is the last profile that carried traffic: it goes first
    in its own segment, and when it is an own profile its segment goes first, so a restart comes
    back to the same kind of connection.

    auto:    own Cloudflare (healthy, by rtt, <=12) -> MASQUE (skipped after repeated failures)
             -> Proton (<=10, connect queue) -> shared Cloudflare seeds (identity round-robin)
             -> own Cloudflare that failed -> warp-cli. The segment holding an own `preferred_id`
             moves to the front. Custom is never part of auto.
    group:   that group only, never warp-cli; own profiles before seeds; Proton by the connect
             queue, narrowed to `country` when the selection names one.
    profile: exactly that profile.
    Invalid records are never attempted. Migration's "WARPv… (legacy)" copies are attempted only
    when chosen as the profile.
    """
    records = [r for r in (profiles or []) if isinstance(r, dict) and r.get("id")]
    effective = resolve_effective_selection(sel, records)
    preferred = str(preferred_id or "").strip()
    stats = stats if isinstance(stats, dict) else {}
    now = time.time() if now is None else float(now)
    valid = [r for r in records if r.get("valid") and not _is_legacy_seed_copy(r)]

    def members(group):
        return [r for r in valid if r.get("group") == group]

    if effective["mode"] == MODE_PROFILE:
        record = next((r for r in records if r["id"] == effective["profile_id"]), None)
        return [_attempt(record)] if record is not None and record.get("valid") else []

    if effective["mode"] == MODE_GROUP:
        group = effective["group"]
        if group == GROUP_CLOUDFLARE:
            # The preferred profile leads its own segment only: a seed never jumps over own profiles,
            # and an own profile that has failed since stays behind the seeds, where failures go.
            lead, pool, rest = _cloudflare_segments(members(group), preferred, generated_state)
            ordered = _front(lead, preferred) + pool + _front(rest, preferred)
        elif group == GROUP_PROTON:
            country = effective.get("country", "")
            group_members = [r for r in members(group) if not country or record_country(r) == country]
            ordered = _front(_proton_order(group_members, stats, now), preferred)
        else:
            ordered = _front(_stats_order(members(group), stats), preferred)
        return [_attempt(r) for r in ordered]

    lead, pool, rest = _cloudflare_segments(members(GROUP_CLOUDFLARE), preferred, generated_state)
    masque = [r for r in _stats_order(members(GROUP_MASQUE), stats) if not _masque_locked_out(r, stats, now)]
    proton = _proton_order(members(GROUP_PROTON), stats, now)
    proton_head = proton[:AUTO_PROTON_LIMIT]
    if not _contains_preferred(proton_head, preferred) and _contains_preferred(proton, preferred):
        proton_head = _front(proton, preferred)[:AUTO_PROTON_LIMIT]
    personal = [_front(lead, preferred), _front(masque, preferred), _front(proton_head, preferred)]
    for index, segment in enumerate(personal):
        if _contains_preferred(segment, preferred):
            personal.insert(0, personal.pop(index))
            break
    ordered = [r for segment in personal for r in segment]
    ordered += pool  # the round-robin already put a preferred seed first among the seeds
    ordered += _front(rest, preferred)
    plan = [_attempt(r) for r in ordered]
    plan.append({"backend": BACKEND_WARP_CLI, "profile": None})
    return plan


def build_recovery_plan(plan, failed_id, budget=DEFAULT_RECOVERY_BUDGET):
    """Next attempts after `failed_id` died: its identity-mates last, itself dropped, warp-cli excluded."""
    entries = [a for a in (plan or []) if isinstance(a, dict) and isinstance(a.get("profile"), dict)
               and a.get("backend") != BACKEND_WARP_CLI]
    failed_id = str(failed_id or "")
    failed = next((a["profile"] for a in entries if a["profile"].get("id") == failed_id), None)
    identity = failed.get("identity") if failed else None
    others, mates = [], []
    for attempt in entries:
        if attempt["profile"].get("id") == failed_id:
            continue
        if identity and attempt["profile"].get("identity") == identity:
            mates.append(attempt)
        else:
            others.append(attempt)
    return (others + mates)[:max(0, _as_int(budget, DEFAULT_RECOVERY_BUDGET))]


# --------------------------------------------------------------------------------------------
# Stats (public-safe: ids and counters only)

_STATS_LOCK = threading.Lock()


def _clean_stats_entry(entry):
    if not isinstance(entry, dict):
        return None
    last_ms = entry.get("last_ms")
    rtt_ms = entry.get("rtt_ms")
    return {
        "ok": max(0, _as_int(entry.get("ok"), 0)),
        "fail": max(0, _as_int(entry.get("fail"), 0)),
        "last_ok_at": _as_float(entry.get("last_ok_at"), None),
        "last_fail_at": _as_float(entry.get("last_fail_at"), None),
        "last_ms": _as_int(last_ms, None) if last_ms is not None else None,
        # Failures since the last success: the counters above are lifetime totals and cannot say
        # "failing right now", which is what the MASQUE lockout of «Авто» needs.
        "fail_streak": max(0, _as_int(entry.get("fail_streak"), 0)),
        # Distance to the node's entry (TCP connect, ms); None = not measured or did not answer.
        "rtt_ms": _as_int(rtt_ms, None) if rtt_ms is not None else None,
        "rtt_at": _as_float(entry.get("rtt_at"), None),
    }


def load_stats(base_dir):
    """`{profile_id: {"ok","fail","last_ok_at","last_fail_at","last_ms","fail_streak","rtt_ms","rtt_at"}}`.

    Missing or corrupt file -> {}.
    """
    try:
        with open(stats_path(base_dir), "rb") as handle:
            obj = json.loads(handle.read().decode("utf-8-sig"))
    except (OSError, ValueError):
        return {}
    if not isinstance(obj, dict):
        return {}
    stats = {}
    for key, value in obj.items():
        entry = _clean_stats_entry(value)
        if isinstance(key, str) and key and entry is not None:
            stats[key] = entry
    return stats


def _save_stats_locked(base_dir, stats):
    if len(stats) > _MAX_STATS_ENTRIES:
        def last_seen(item):
            entry = item[1]
            return max(entry.get("last_ok_at") or 0, entry.get("last_fail_at") or 0)
        stats = dict(sorted(stats.items(), key=last_seen, reverse=True)[:_MAX_STATS_ENTRIES])
    _atomic_write_json(stats_path(base_dir), stats)


def record_outcome(base_dir, profile_id, ok, ms=None):
    """Count one attempt outcome. Returns the updated entry, or None when the file could not be written.

    Stats are advisory (ordering only), so a write failure is reported by the return value and
    never raised into the connect path.
    """
    profile_id = str(profile_id or "").strip()
    if not profile_id:
        return None
    now = round(time.time(), 3)
    with _STATS_LOCK:
        stats = load_stats(base_dir)
        entry = stats.get(profile_id) or _clean_stats_entry({})
        if ok:
            entry["ok"] += 1
            entry["last_ok_at"] = now
            entry["fail_streak"] = 0
            elapsed = _as_float(ms, None)  # None for a missing or non-finite measurement
            if elapsed is not None:
                entry["last_ms"] = max(0, int(round(elapsed)))
        else:
            entry["fail"] += 1
            entry["last_fail_at"] = now
            entry["fail_streak"] = entry.get("fail_streak", 0) + 1
        stats[profile_id] = entry
        try:
            _save_stats_locked(base_dir, stats)
        except OSError:
            return None
    return dict(entry)


def record_rtts(base_dir, measurements, now=None):
    """Store distances `{profile_id: ms or None}` in one write. Returns how many were stored, or None.

    None means "did not answer" and clears an older number: a node that stopped answering must not
    keep the rank it earned when it did.
    """
    items = [(str(pid or "").strip(), value) for pid, value in dict(measurements or {}).items()]
    items = [(pid, value) for pid, value in items if pid]
    if not items:
        return 0
    stamp = round(float(time.time() if now is None else now), 3)
    with _STATS_LOCK:
        stats = load_stats(base_dir)
        for profile_id, value in items:
            entry = stats.get(profile_id) or _clean_stats_entry({})
            ms = _as_float(value, None)
            entry["rtt_ms"] = max(1, int(round(ms))) if ms is not None and ms >= 0 else None
            entry["rtt_at"] = stamp
            stats[profile_id] = entry
        try:
            _save_stats_locked(base_dir, stats)
        except OSError:
            return None
    return len(items)


def _move_stats_entry(base_dir, old_id, new_id=None):
    with _STATS_LOCK:
        stats = load_stats(base_dir)
        if old_id not in stats:
            return False
        entry = stats.pop(old_id)
        if new_id:
            stats[new_id] = entry
        try:
            _save_stats_locked(base_dir, stats)
        except OSError:
            return False
    return True


# --------------------------------------------------------------------------------------------
# Import


def safe_profile_name(name):
    """File-system-safe display name (Cyrillic kept); "" when nothing usable is left."""
    value = re.sub(r'[\\/:*?"<>|\x00-\x1f\x7f]', "_", str(name or ""))
    value = re.sub(r" {2,}", " ", value).strip()
    # Windows drops trailing dots/spaces; a leading dot would make the listing skip the file.
    value = value.strip(" .")
    value = value[:_MAX_NAME_CHARS].rstrip(" .")
    if not value:
        return ""
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
    if value.split(".")[0].upper() in reserved:
        value += "_"
    return value


def _source_stem(source_name):
    base = os.path.basename(str(source_name or "").replace("\\", "/").rstrip("/"))
    stem = os.path.splitext(base)[0] if base else ""
    return stem.strip()


def _conf_name(block_text, parsed):
    match = re.search(r"(?im)^[ \t]*[#;][ \t]*name[ \t]*[=:][ \t]*(.+?)[ \t]*$", block_text)
    if match and match.group(1).strip():
        return match.group(1).strip()
    first_line = block_text.lstrip("\n").split("\n", 1)[0].strip()
    if first_line.startswith(("#", ";")):
        comment = first_line.lstrip("#; \t").strip()
        if comment and re.search(r"\w", comment):
            return comment
    endpoint = _split_endpoint(parsed["peer"].get("endpoint", ""))
    if endpoint:
        host, port = endpoint
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return "Профиль"


def _conf_candidate(text, name=""):
    text = text.strip("\n")
    text = "\n".join(line.rstrip() for line in _text_mode_lines(text)).strip("\n") + "\n"
    parsed = parse_awg_conf(text)
    issues = validate_awg_conf(text)
    return {
        "kind": KIND_AWG,
        "name": name or _conf_name(text, parsed),
        "text": text,
        "endpoint": _strip_inline_comment(parsed["peer"].get("endpoint", "")),
        "issues": issues,
        "ok": not any(is_fatal_issue(issue) for issue in issues),
        "fingerprint": awg_fingerprint(text),
    }


def _invalid_candidate(name, issues, kind=KIND_AWG):
    return {"kind": kind, "name": name, "text": "", "endpoint": "", "issues": list(issues),
            "ok": False, "fingerprint": ""}


def _masque_candidate(obj, name=""):
    identity, issues = normalize_masque_identity(obj)
    source = "import-usque" if "id" in obj and "device_id" not in obj else "import-android"
    nova = dict(identity.get("nova") or {})
    nova.setdefault("schema", 1)
    nova["source"] = source
    identity["nova"] = nova
    endpoint = _masque_endpoint(identity)
    display = name or _json_str(nova.get("name")) or endpoint or "MASQUE"
    return {
        "kind": KIND_MASQUE,
        "name": display,
        "text": json.dumps(identity, ensure_ascii=False, indent=2) + "\n",
        "endpoint": endpoint,
        "issues": issues,
        "ok": not any(is_fatal_issue(issue) for issue in issues),
        "fingerprint": masque_fingerprint(identity),
    }


def _inflate_limited(data, limit):
    inflater = zlib.decompressobj()
    out = inflater.decompress(data, limit + 1)
    if len(out) > limit:
        raise ValueError("payload too large")
    if not inflater.eof:
        raise ValueError("truncated zlib stream")
    return out


def _decode_amnezia_payload(key):
    """`vpn://` -> JSON object: base64url, 4-byte big-endian qCompress length, zlib, UTF-8 JSON."""
    encoded = key.strip()[len("vpn://"):].strip()
    if not encoded:
        raise ValueError("empty key")
    normalized = encoded.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        packed = base64.b64decode(normalized)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("bad base64") from exc
    if len(packed) <= 5:
        raise ValueError("payload too short")
    try:
        raw = _inflate_limited(packed[4:], _MAX_AMNEZIA_JSON_BYTES)
    except zlib.error as exc:
        # Some exporters skip qCompress; accept a bare JSON body.
        if packed.lstrip()[:1] != b"{":
            raise ValueError("not zlib") from exc
        raw = packed
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("not json") from exc
    if not isinstance(payload, dict):
        raise ValueError("not an object")
    return payload


def _finalize_amnezia_config(config, dns1, dns2):
    dns_csv = ", ".join(v for v in (dns1, dns2) if v)
    text = config.replace("$PRIMARY_DNS", dns1).replace("$SECONDARY_DNS", dns2)
    lines = []
    for line in _text_mode_lines(text):
        match = re.match(r"(?i)^[ \t]*DNS[ \t]*=(.*)$", line)
        if match:
            if dns_csv:
                line = f"DNS = {dns_csv}"
            else:
                values = [v.strip() for v in match.group(1).split(",") if v.strip()]
                if not values:
                    continue  # an unresolved placeholder: let the renderer use its default DNS
                line = "DNS = " + ", ".join(values)
        lines.append(line)
    return "\n".join(lines).strip() + "\n"


def _amnezia_candidate(key, stem):
    try:
        payload = _decode_amnezia_payload(key)
    except ValueError:
        return _invalid_candidate(stem or "Amnezia vpn://", [ISSUE_AMNEZIA_UNREADABLE])
    host = _json_str(payload.get("hostName"))
    default_container = _json_str(payload.get("defaultContainer"))
    dns1, dns2 = _json_str(payload.get("dns1")), _json_str(payload.get("dns2"))
    containers = [c for c in payload.get("containers") or [] if isinstance(c, dict)] \
        if isinstance(payload.get("containers"), list) else []
    # The default container first (Android's rule), then any other AWG/WireGuard container.
    containers.sort(key=lambda c: 0 if default_container and _json_str(c.get("container")) == default_container else 1)
    for container in containers:
        for proto_key in ("awg", "wireguard"):
            proto = container.get(proto_key)
            if not isinstance(proto, dict):
                continue
            last_config = proto.get("last_config")
            if isinstance(last_config, str):
                try:
                    last_config = json.loads(last_config)
                except ValueError:
                    continue
            if not isinstance(last_config, dict):
                continue
            config = _json_str(last_config.get("config"))
            if config:
                return _conf_candidate(_finalize_amnezia_config(config, dns1, dns2), name=stem or host)
    message = (
        f"Не удалось извлечь AWG/WireGuard-конфигурацию из ключа Amnezia vpn:// для "
        f"{host or 'сервер'} ({default_container or 'amnezia-awg2'}). Попробуйте импорт через обычный .conf."
    )
    return _invalid_candidate(stem or host or "Amnezia vpn://", [message])


def _conf_blocks(masked):
    """Split text on `[Interface]` lines; each block keeps the comment lines directly above it."""
    lines = masked.split("\n")
    headers = [i for i, line in enumerate(lines) if line.strip().lower() == "[interface]"]
    blocks = []
    if not headers:
        if re.search(r"(?im)^[ \t]*\[peer\][ \t]*$", masked) or re.search(r"(?im)^[ \t]*privatekey[ \t]*=", masked):
            blocks.append((0, masked))
        return blocks
    starts = []
    previous_header = -1
    for header in headers:
        start = header
        cursor = header - 1
        while cursor > previous_header and not lines[cursor].strip():
            cursor -= 1
        comment_top = cursor
        while comment_top > previous_header and lines[comment_top].strip().startswith(("#", ";")):
            comment_top -= 1
        if comment_top < cursor:
            start = comment_top + 1
        starts.append(start)
        previous_header = header
    offsets = []
    position = 0
    for line in lines:
        offsets.append(position)
        position += len(line) + 1
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(lines)
        blocks.append((offsets[start], "\n".join(lines[start:end])))
    return blocks


def parse_import_text(text, source_name=""):
    """Every importable profile found in one text (a file body or the clipboard).

    Accepts any mix of wg-quick/AWG blocks, Amnezia `vpn://` keys and MASQUE JSON (Android
    `masque_config.json` or usque `config.json`). Candidates come back in text order:
    `{"kind","name","text","endpoint","issues","ok","fingerprint"}`; `text` is what would be
    written to `profiles/Custom/`. Nothing is written here.
    """
    text = _coerce_text(text)
    if text.startswith("\ufeff"):
        text = text[1:]
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return []
    stem = _source_stem(source_name)
    if len(text) > _MAX_IMPORT_TEXT_CHARS:
        return [_invalid_candidate(stem or "Импорт", [ISSUE_TEXT_TOO_LARGE])]

    found = []
    consumed = []
    for match in re.finditer(r"(?i)vpn://[A-Za-z0-9_\-+/=]*", text):
        found.append((match.start(), _amnezia_candidate(match.group(0), stem)))
        consumed.append((match.start(), match.end()))

    decoder = json.JSONDecoder(parse_constant=_reject_json_constant)  # nova-go refuses NaN/Infinity
    cursor = 0
    while True:
        start = text.find("{", cursor)
        if start < 0:
            break
        if any(s <= start < e for s, e in consumed):
            cursor = start + 1
            continue
        try:
            obj, end = decoder.raw_decode(text, start)
        except ValueError:
            cursor = start + 1
            continue
        if looks_like_masque_identity(obj):
            found.append((start, _masque_candidate(obj, stem)))
            consumed.append((start, end))
        cursor = end

    masked_chars = list(text)
    for start, end in consumed:
        for index in range(start, end):
            if masked_chars[index] != "\n":
                masked_chars[index] = " "
    masked = "".join(masked_chars)
    for offset, block in _conf_blocks(masked):
        if block.strip():
            found.append((offset, _conf_candidate(block, stem)))

    found.sort(key=lambda item: item[0])
    return [candidate for _offset, candidate in found]


# nova-go keeps `<profile>.pending` (a key enrolled but not yet written into the profile) next to
# the profile; it names a profile that may appear any moment and must not be inherited by a new one.
_PENDING_SIDECAR_RE = re.compile(r"(?i)(.+\.(?:conf|json))\.pending")


def _entry_profile_filename(entry):
    """The profile file a directory entry stands for: itself, or the owner of a `.pending` sidecar."""
    match = _PENDING_SIDECAR_RE.fullmatch(entry)
    return match.group(1) if match else entry


def _existing_stems(folder):
    try:
        entries = os.listdir(folder)
    except FileNotFoundError:
        return set()
    stems = set()
    for entry in entries:
        stems.add(os.path.splitext(entry)[0].lower())
        stems.add(os.path.splitext(_entry_profile_filename(entry))[0].lower())
    return stems


def _write_new_file(folder, base_name, ext, data):
    """Create `<folder>/<name><ext>` without ever overwriting; collisions get " (2)", " (3)"…"""
    stems = _existing_stems(folder)
    for number in range(1, 1000):
        stem = base_name if number == 1 else f"{base_name} ({number})"
        if stem.lower() in stems or f"{stem}{ext}".lower() in PRIVATE_FILENAMES:
            continue
        target = os.path.join(folder, f"{stem}{ext}")
        tmp = os.path.join(folder, f".{os.getpid()}.{threading.get_ident()}.import.tmp")
        try:
            # Inside the try: a full disk or an antivirus block must not leave the hidden tmp
            # (it holds the private key) behind, where the listing never shows it.
            with open(tmp, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "nt":
                os.rename(tmp, target)  # refuses an existing target on Windows
            else:
                os.link(tmp, target)  # refuses an existing target on POSIX
                os.remove(tmp)
        except FileExistsError:
            _remove_quietly(tmp)
            stems.add(stem.lower())
            continue
        except BaseException:
            _remove_quietly(tmp)
            raise
        return target, stem
    raise OSError(f"слишком много профилей с именем «{base_name}»")


def import_candidates(base_dir, candidates):
    """Write accepted candidates to `profiles/Custom/`; never touches the selection.

    Each candidate is re-validated from its `text` (the preview may have edited the name).
    Returns `[{"name","status":"imported"|"duplicate"|"invalid","id","issues"}]`; a duplicate is
    the same fingerprint as any existing profile in any group, or an earlier candidate.
    """
    results = []
    folder = os.path.join(profiles_dir(base_dir), GROUP_CUSTOM)
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as exc:
        issue = f"Не удалось создать папку {GROUP_CUSTOM}: {exc.strerror or exc}"
        return [{"name": str((c or {}).get("name") or ""), "status": "invalid", "id": "", "issues": [issue]}
                for c in candidates or []]
    known = {}
    for record in list_profiles(base_dir):
        if record.get("fingerprint"):
            known.setdefault(record["fingerprint"], record["id"])

    for candidate in candidates or []:
        candidate = candidate if isinstance(candidate, dict) else {}
        kind = candidate.get("kind")
        name = str(candidate.get("name") or "")
        text = _coerce_text(candidate.get("text"))
        if kind == KIND_AWG and text.strip():
            fresh = _conf_candidate(text, name=name)
            ext = ".conf"
        elif kind == KIND_MASQUE and text.strip():
            try:
                obj = _loads_strict_json(text)
            except ValueError:
                obj = None
            if not looks_like_masque_identity(obj):
                results.append({"name": name, "status": "invalid", "id": "", "issues": [ISSUE_MASQUE_NOT_IDENTITY]})
                continue
            fresh = _masque_candidate(obj, name=name)
            ext = ".json"
        else:
            issues = list(candidate.get("issues") or []) or [ISSUE_UNKNOWN_KIND]
            results.append({"name": name, "status": "invalid", "id": "", "issues": issues})
            continue

        if not fresh["ok"]:
            results.append({"name": fresh["name"], "status": "invalid", "id": "", "issues": fresh["issues"]})
            continue
        if fresh["fingerprint"] in known:
            results.append({"name": fresh["name"], "status": "duplicate", "id": known[fresh["fingerprint"]],
                            "issues": fresh["issues"]})
            continue
        safe = safe_profile_name(fresh["name"]) or safe_profile_name(fresh["endpoint"]) or "Профиль"
        try:
            _path, stem = _write_new_file(folder, safe, ext, fresh["text"].encode("utf-8"))
        except OSError as exc:
            issue = f"Не удалось записать файл: {exc.strerror or exc}"
            results.append({"name": fresh["name"], "status": "invalid", "id": "", "issues": [issue]})
            continue
        profile_id = make_profile_id(GROUP_CUSTOM, stem)
        known[fresh["fingerprint"]] = profile_id
        results.append({"name": stem, "status": "imported", "id": profile_id, "issues": fresh["issues"]})
    return results


def _acquire_masque_lock(profile_path):
    """Take nova-go's `<profile>.lock` without waiting; returns a descriptor, or None while nova-go holds it.

    nova-go locks byte 0 with LockFileEx(EXCLUSIVE|FAIL_IMMEDIATELY) on Windows and flock(LOCK_EX)
    elsewhere, for the whole of `register`/`enroll`. The CRT's LockFile (msvcrt.locking) and flock
    conflict with those, so holding it here also keeps a new enroll off the files we move.
    Raises OSError when the lock file cannot be opened at all.
    """
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    fd = os.open(profile_path + ".lock", flags, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _release_masque_lock(fd, profile_path):
    """Unlock and drop the lock file of a name that no longer holds a profile.

    POSIX: unlinked while still locked, so no nova-go can be holding the old inode. Windows: our
    own handle blocks deletion, so it is removed after closing; a nova-go that opened it in the
    meantime keeps it in place (Go opens without FILE_SHARE_DELETE), which is just as safe.
    """
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            _remove_quietly(profile_path + ".lock")
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    finally:
        os.close(fd)
    if os.name == "nt":
        _remove_quietly(profile_path + ".lock")


def _masque_busy_message(record):
    return (f"Профиль «{record['name']}» сейчас занят nova-go (регистрация или смена ключа) — "
            f"повторите через минуту")


def _masque_pending_backups(profile_path):
    """nova-go's set-aside keys `<profile>.pending.<unix>.bak` (private keys, never listed)."""
    folder, filename = os.path.split(profile_path)
    pattern = re.compile(re.escape(filename) + r"\.pending\.[0-9]+\.bak", re.IGNORECASE)
    try:
        return sorted(os.path.join(folder, entry) for entry in os.listdir(folder) if pattern.fullmatch(entry))
    except OSError:
        return []


def delete_profile(base_dir, profile_id):
    """Delete a profile file (and its stats entry and rendered runtime config).

    A MASQUE profile also loses nova-go's `.pending`, `.pending.<unix>.bak` and `.lock` sidecars
    (the first two hold private keys); while nova-go holds the profile lock nothing is deleted.
    Raises ValueError (Russian message) for an unknown, bundled or nova-go-locked profile, OSError
    when the file cannot be removed. The selection is not rewritten: a deleted explicit profile
    resolves to its group at read time.
    """
    record = _find_record(base_dir, profile_id)
    if record is None:
        raise ValueError(f"Профиль «{profile_id}» не найден")
    if record["origin"] == ORIGIN_BUNDLED:
        raise ValueError(f"Встроенный профиль «{record['name']}» удалить нельзя: он приходит с установкой Nova")
    if record["kind"] == KIND_MASQUE:
        lock = _acquire_masque_lock(record["path"])
        if lock is None:
            raise ValueError(_masque_busy_message(record))
        try:
            os.remove(record["path"])
            for sidecar in [record["path"] + ".pending"] + _masque_pending_backups(record["path"]):
                _remove_quietly(sidecar)
        finally:
            _release_masque_lock(lock, record["path"])
    else:
        os.remove(record["path"])
    _move_stats_entry(base_dir, record["id"])
    _remove_quietly(runtime_config_path(base_dir, record["id"]))
    return record["path"]


def _rename_masque_files(record, target):
    source = record["path"]
    lock = _acquire_masque_lock(source)
    if lock is None:
        raise ValueError(_masque_busy_message(record))
    try:
        pending = source + ".pending"
        moved_pending = False
        if os.path.exists(pending):
            os.rename(pending, target + ".pending")
            moved_pending = True
        try:
            os.rename(source, target)
        except BaseException:
            if moved_pending:
                try:
                    os.rename(target + ".pending", pending)
                except OSError:
                    pass
            raise
        prefix_length = len(os.path.basename(source))
        for backup in _masque_pending_backups(source):
            suffix = os.path.basename(backup)[prefix_length:]
            try:
                os.rename(backup, target + suffix)
            except OSError:
                pass  # best effort: a set-aside key nova-go never reads again
    finally:
        _release_masque_lock(lock, source)


def rename_profile(base_dir, profile_id, new_name):
    """Rename a Custom profile; returns the new id. Raises ValueError (Russian) or OSError.

    A MASQUE profile takes nova-go's `.pending` / `.pending.<unix>.bak` along (an interrupted
    enroll resumes under the new name) and is refused while nova-go holds its lock.
    """
    record = _find_record(base_dir, profile_id)
    if record is None:
        raise ValueError(f"Профиль «{profile_id}» не найден")
    if record["group"] != GROUP_CUSTOM:
        raise ValueError(f"Переименовать можно только профили группы «{GROUP_CUSTOM}»")
    safe = safe_profile_name(new_name)
    if not safe:
        raise ValueError("Пустое имя профиля")
    if safe == record["name"]:
        return record["id"]
    folder = os.path.dirname(record["path"])
    ext = os.path.splitext(record["path"])[1]
    own_file = os.path.basename(record["path"]).lower()
    for entry in os.listdir(folder):
        owner = _entry_profile_filename(entry)
        if owner.lower() != own_file and os.path.splitext(owner)[0].lower() == safe.lower():
            raise ValueError(f"Профиль «{safe}» уже есть")
    if f"{safe}{ext}".lower() in PRIVATE_FILENAMES:
        raise ValueError(f"Имя «{safe}» зарезервировано")
    target = os.path.join(folder, f"{safe}{ext}")
    if os.name != "nt" and os.path.exists(target) and safe.lower() != record["name"].lower():
        raise ValueError(f"Профиль «{safe}» уже есть")
    if record["kind"] == KIND_MASQUE:
        _rename_masque_files(record, target)
    else:
        os.rename(record["path"], target)
    new_id = make_profile_id(GROUP_CUSTOM, safe)
    _move_stats_entry(base_dir, record["id"], new_id)
    _remove_quietly(runtime_config_path(base_dir, record["id"]))
    selection = load_selection(base_dir)
    if selection.get("mode") == MODE_PROFILE and selection.get("profile") == record["id"]:
        # Renaming is not a new choice: keep the explicit selection pointing at the same file.
        selection["profile"] = new_id
        save_selection(base_dir, selection)
    return new_id


# --------------------------------------------------------------------------------------------
# Migration awg/ -> profiles/


def _same_bytes(path_a, path_b):
    if os.path.getsize(path_a) != os.path.getsize(path_b):
        return False
    with open(path_a, "rb") as a, open(path_b, "rb") as b:
        while True:
            chunk_a, chunk_b = a.read(65536), b.read(65536)
            if chunk_a != chunk_b:
                return False
            if not chunk_a:
                return True


def _migrate_conf(src, target_dir, stem, ext, summary):
    target = os.path.join(target_dir, f"{stem}{ext}")
    if not os.path.exists(target):
        os.replace(src, target)
        summary["moved"].append(target)
        return
    if _same_bytes(src, target):
        os.remove(src)
        summary["deduplicated"].append(target)
        return
    for number in range(1, 100):
        suffix = " (legacy)" if number == 1 else f" (legacy {number})"
        legacy_target = os.path.join(target_dir, f"{stem}{suffix}{ext}")
        if not os.path.exists(legacy_target):
            os.replace(src, legacy_target)
            summary["kept_as_legacy"].append(legacy_target)
            return
        if _same_bytes(src, legacy_target):
            os.remove(src)
            summary["deduplicated"].append(legacy_target)
            return
    raise OSError(f"нет свободного имени для {stem}{ext}")


def _migrate_key_file(src, dst):
    """'moved' | 'legacy-deleted' | '' — a non-empty profiles/ key is newer (the installer put it there).

    An empty or unreadable profiles/ copy (interrupted copy, placeholder) is not a key: the legacy
    one replaces it instead of being deleted, or the relay would lose its only password.
    """
    if not os.path.isfile(src):
        return ""
    try:
        dst_is_key = os.path.isfile(dst) and os.path.getsize(dst) > 0
    except OSError:
        dst_is_key = False
    if dst_is_key:
        os.remove(src)
        return "legacy-deleted"
    os.replace(src, dst)
    return "moved"


def _rewrite_preferred_profile(base_dir):
    path = os.path.join(base_dir, TEMP_DIRNAME, LEGACY_AWG_STATE_FILENAME)
    try:
        with open(path, "rb") as handle:
            payload = json.loads(handle.read().decode("utf-8-sig"))
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return False  # nova.pyw treats an unreadable state file as empty; nothing to rewrite
    if not isinstance(payload, dict):
        return False
    preferred = payload.get("preferred_profile")
    if not isinstance(preferred, str) or not preferred.strip() or "/" in preferred:
        return False
    stem = preferred.strip()
    group = GROUP_CLOUDFLARE
    cloudflare_conf = os.path.join(profiles_dir(base_dir), GROUP_CLOUDFLARE, f"{stem}.conf")
    custom_conf = os.path.join(profiles_dir(base_dir), GROUP_CUSTOM, f"{stem}.conf")
    if not os.path.exists(cloudflare_conf) and os.path.exists(custom_conf):
        group = GROUP_CUSTOM
    payload["preferred_profile"] = make_profile_id(group, stem)
    _atomic_write_json(path, payload)
    return True


def migrate_legacy_layout(base_dir, log=None):
    """Move the pre-1.39 `awg/` folder into `profiles/`. Idempotent, runs every start, never raises.

    1. create the layout; 2. `awg/WARPv*.conf` -> AWG Cloudflare, other valid confs -> Custom
    (identical target: legacy deleted; different: legacy kept as "<stem> (legacy).conf");
    3. `opera_relay.key` / `cf_ws.key`: an existing `profiles/` copy wins, else moved;
    4. empty `awg/` removed; 5. `temp/awg-profile-state.json` preferred stem gets its group prefix.
    Returns a summary dict; `summary["changed"]` tells whether anything was moved or rewritten.
    """
    summary = {
        "created_dirs": [], "moved": [], "deduplicated": [], "kept_as_legacy": [], "left_in_awg": [],
        "relay_key": "", "cf_ws_key": "", "legacy_dir_removed": False, "state_rewritten": False,
        "errors": [], "changed": False,
    }

    def emit(message):
        if log is None:
            return
        try:
            log(message)
        except Exception:  # a broken logger must not break startup
            return

    try:
        return _migrate_legacy_layout_steps(base_dir, summary, emit)
    except Exception as exc:  # startup must survive a bug here; the reason goes to the log
        summary["errors"].append(f"unexpected: {exc!r}")
        emit(f"[Profiles] Перенос awg → profiles прерван: {exc!r}")
        return summary


def _migrate_legacy_layout_steps(base_dir, summary, emit):
    try:
        summary["created_dirs"] = ensure_layout(base_dir)
    except OSError as exc:
        summary["errors"].append(f"profiles: {exc}")
        emit(f"[Profiles] Не удалось создать папку profiles: {exc}")
        return summary

    legacy = legacy_awg_dir(base_dir)
    try:
        if os.path.isdir(legacy):
            for entry in sorted(os.listdir(legacy), key=str.lower):
                src = os.path.join(legacy, entry)
                stem, ext = os.path.splitext(entry)
                if not os.path.isfile(src) or ext.lower() != ".conf" or not stem:
                    continue
                try:
                    if stem.lower().startswith(BUNDLED_WARP_PREFIX.lower()):
                        target_dir = os.path.join(profiles_dir(base_dir), GROUP_CLOUDFLARE)
                    else:
                        issues = validate_awg_conf(_read_profile_text(src))
                        if any(is_fatal_issue(issue) for issue in issues):
                            summary["left_in_awg"].append(entry)
                            continue
                        target_dir = os.path.join(profiles_dir(base_dir), GROUP_CUSTOM)
                    _migrate_conf(src, target_dir, stem, ext, summary)
                except (OSError, ValueError) as exc:
                    summary["errors"].append(f"{entry}: {exc}")
                    emit(f"[Profiles] Не удалось перенести awg/{entry}: {exc}")

            for filename, field in ((RELAY_KEY_FILENAME, "relay_key"), (CF_WS_KEY_FILENAME, "cf_ws_key")):
                try:
                    summary[field] = _migrate_key_file(
                        os.path.join(legacy, filename), os.path.join(profiles_dir(base_dir), filename)
                    )
                except OSError as exc:
                    summary["errors"].append(f"{filename}: {exc}")
                    emit(f"[Profiles] Не удалось перенести awg/{filename}: {exc}")

            try:
                if not os.listdir(legacy):
                    os.rmdir(legacy)
                    summary["legacy_dir_removed"] = True
            except OSError as exc:
                summary["errors"].append(f"awg: {exc}")
                emit(f"[Profiles] Не удалось удалить пустую папку awg: {exc}")
    except OSError as exc:
        summary["errors"].append(f"awg: {exc}")
        emit(f"[Profiles] Не удалось прочитать папку awg: {exc}")

    try:
        summary["state_rewritten"] = _rewrite_preferred_profile(base_dir)
    except OSError as exc:
        summary["errors"].append(f"{LEGACY_AWG_STATE_FILENAME}: {exc}")
        emit(f"[Profiles] Не удалось обновить {LEGACY_AWG_STATE_FILENAME}: {exc}")

    summary["changed"] = bool(
        summary["moved"] or summary["deduplicated"] or summary["kept_as_legacy"] or summary["relay_key"]
        or summary["cf_ws_key"] or summary["legacy_dir_removed"] or summary["state_rewritten"]
    )
    if summary["moved"] or summary["deduplicated"] or summary["kept_as_legacy"] or summary["relay_key"] \
            or summary["cf_ws_key"] or summary["legacy_dir_removed"]:
        parts = [f"перенесено {len(summary['moved'])}"]
        if summary["deduplicated"]:
            parts.append(f"совпадали и удалены {len(summary['deduplicated'])}")
        if summary["kept_as_legacy"]:
            parts.append(f"отличались и сохранены как (legacy) {len(summary['kept_as_legacy'])}")
        key_words = {"moved": "перенесён", "legacy-deleted": "старая копия удалена"}
        if summary["relay_key"]:
            parts.append(f"ключ релея {key_words[summary['relay_key']]}")
        if summary["cf_ws_key"]:
            parts.append(f"cf_ws.key {key_words[summary['cf_ws_key']]}")
        if summary["left_in_awg"]:
            parts.append(f"оставлено в awg (не профили) {len(summary['left_in_awg'])}")
        if summary["legacy_dir_removed"]:
            parts.append("папка awg удалена")
        emit("[Profiles] Перенос awg → profiles: " + ", ".join(parts) + ".")
    return summary
