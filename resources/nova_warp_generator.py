"""Генератор собственных WARP-профилей: своя личность, свои точки входа.

Порт генератора Nova Android (`WarpProfileGenerator` + `WarpGeneratedStore`,
`register.go`). Устройство регистрирует **свой** ключ X25519 в Cloudflare, сканер
находит **свои** точки входа настоящим рукопожатием WireGuard, и на выходе —
до пятидесяти профилей AmneziaWG, которые грузит существующий бэкенд
`wireproxy-awg.exe`, ровно как встроенные семена.

Тяжёлую сеть делает Go-помощник `nova-go warp …`: он регистрирует ключ через
обфусцированный uTLS и сканирует префиксы WARP реальным хендшейком. Всё общение с
ним — через одну частную функцию `_run_nova_go`, чтобы тесты подменяли её фейком и
проверяли логику без сети и без бинаря.

Python отвечает за: генерацию и проверку ключа (`cryptography`), разбор ответа
регистрации, сборку конфигов (джанк на профиль, свой `I1` на профиль — RFC 9001, N5),
поэтапную запись профилей, политику перевыпуска (14 дней / все отказали, час
остывания после неудачного прогона), счётчики отказов по точкам входа и
публично-безопасное состояние в `temp/` без ключей, токена и абсолютных путей (I19).

Каталоги захардкожены по DESIGN §1 намеренно — `nova_profiles` этот модуль не
импортирует. Логи по-русски с префиксом «[WARP-ген]».
"""

from __future__ import annotations

__all__ = [
    "GROUP_CLOUDFLARE",
    "PROFILES_DIRNAME",
    "GENERATED_WARP_PREFIX",
    "IDENTITY_FILENAME",
    "STATE_FILENAME",
    "TARGET_COUNT",
    "ENOUGH_VERIFIED",
    "MAX_PER_SUBNET",
    "REISSUE_AFTER_SEC",
    "COOLDOWN_SEC",
    "generate_keypair",
    "parse_registration",
    "parse_scan_output",
    "diversify",
    "random_junk",
    "build_warp_conf",
    "should_reissue",
    "note_outcome",
    "load_state",
    "generate",
]

import base64
import json
import os
import random
import re
import subprocess
import tempfile
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

import nova_quic_initial

# --- layout (hard-coded from DESIGN §1, deliberately not imported) -----------
PROFILES_DIRNAME = "profiles"
GROUP_CLOUDFLARE = "AWG Cloudflare"
GENERATED_WARP_PREFIX = "WARPgen_"
BUNDLED_WARP_PREFIX = "WARPv"
IDENTITY_FILENAME = "warp_identity.json"
STATE_FILENAME = "warp-generated-state.json"
TEMP_DIRNAME = "temp"

LOG_PREFIX = "[WARP-ген]"

# --- generation constants (and-warpgen §11) ----------------------------------
TARGET_COUNT = 50
SCAN_TIMEOUT_SEC = 45
ENOUGH_VERIFIED = 24
MAX_PER_SUBNET = 3
MAX_DESIRABLE_RTT_MS = 1500
REGISTER_TIMEOUT_SEC = 60
# Extra wall-clock budget over the tool's own timeout before we give up on the process.
_SUBPROCESS_MARGIN_SEC = 20

REISSUE_AFTER_SEC = 14 * 24 * 60 * 60  # 14 days (NovaVpnService GENERATED_WARP_REISSUE_AFTER_MS)
COOLDOWN_SEC = 60 * 60  # 1 hour after a fruitless run (GENERATED_WARP_BACKFILL_RETRY_MS)

# Junk bounds — only Jc/Jmin/Jmax vary; S/H are stock WireGuard literals (and-warpgen §2.2, N5).
JUNK_COUNT_MIN = 3
JUNK_COUNT_MAX = 8
JUNK_SIZE_FLOOR = 30
JUNK_SIZE_CEILING = 150

_STATE_VERSION = 1
_IDENTITY_VERSION = 1

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# nova-go reads the registration proxy from this variable when --api-proxy is absent, so a relay
# URL with credentials never has to sit on a command line (readable by every local process).
_API_PROXY_ENV = "NOVA_API_PROXY"
# nova-go exit code for rejected arguments (bad flag, malformed key) — see cmd/nova-go/warp.go.
_EXIT_USAGE = 2

# Every read-modify-write of the state file runs under this lock: the connect thread's
# note_outcome, a profile test and a 1-3 minute generate() all touch the same file.
_STATE_LOCK = threading.RLock()
# Windows refuses os.replace onto a file another handle holds open without FILE_SHARE_DELETE
# (a Profiles-window refresh, an AV scan). Such holds last milliseconds, so retry briefly.
_REPLACE_RETRIES = 5
_REPLACE_RETRY_SLEEP_SEC = 0.1

_REASON_MAX_CHARS = 240
_GO_LOG_PREFIX_RE = re.compile(r"^\S+\s+(?:DBG|INF|WRN|ERR)\s+[\w-]+:\s*")
_URL_CREDENTIALS_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]+@")


# --- key generation -----------------------------------------------------------
def generate_keypair() -> tuple[str, str]:
    """A fresh WireGuard X25519 keypair as (private_b64, public_b64), standard base64.

    Matches Android's `Base64.NO_WRAP` (standard alphabet, padded, no newlines). `cryptography`
    clamps on DH internally; the stored raw private bytes are what Cloudflare's server never
    sees anyway — it only needs the derived public key.
    """
    private = x25519.X25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_private).decode("ascii"), base64.b64encode(raw_public).decode("ascii")


def _key_bytes(value) -> bytes | None:
    """32 raw bytes of a standard-base64 WireGuard key, else None (same rule as nova-go DecodeKey)."""
    try:
        raw = base64.b64decode(str(value or "").strip(), validate=True)
    except (ValueError, TypeError):
        return None
    return raw if len(raw) == 32 else None


# --- registration parsing (and-warpgen §1.3-1.4) -----------------------------
def _reserved_from_client_id(client_id) -> str:
    """`config.client_id` base64 → decimal CSV "a,b,c" of its first three bytes, else ""."""
    if not client_id:
        return ""
    try:
        raw = base64.b64decode(str(client_id))
    except (ValueError, TypeError):
        return ""
    if len(raw) < 3:
        return ""
    return f"{raw[0]},{raw[1]},{raw[2]}"


def parse_registration(obj: dict) -> dict:
    """Cloudflare registration JSON → identity fields (no private key — the caller adds that).

    Tolerant of the `result` wrapper (`resultObj = obj.result ?? obj`) and of the two endpoint
    spellings (`v4` / `host` / `v6`, in that order). Raises ValueError when the mandatory tunnel
    fields are missing, so a truncated or error body never yields a half-built identity.
    """
    if not isinstance(obj, dict):
        raise ValueError("ответ регистрации не является объектом JSON")
    result = obj.get("result") if isinstance(obj.get("result"), dict) else obj
    config = result.get("config")
    if not isinstance(config, dict):
        raise ValueError("в ответе регистрации нет объекта config")

    peers = config.get("peers")
    if not isinstance(peers, list) or not peers or not isinstance(peers[0], dict):
        raise ValueError("в ответе регистрации нет узла config.peers[0]")
    peer0 = peers[0]
    peer_public_key = str(peer0.get("public_key") or "").strip()
    if not peer_public_key:
        raise ValueError("в ответе регистрации нет открытого ключа пира")

    endpoint = peer0.get("endpoint") if isinstance(peer0.get("endpoint"), dict) else {}
    peer_endpoint = ""
    for field in ("v4", "host", "v6"):
        value = str(endpoint.get(field) or "").strip()
        if value:
            peer_endpoint = value
            break

    interface = config.get("interface")
    if not isinstance(interface, dict):
        raise ValueError("в ответе регистрации нет объекта config.interface")
    addresses = interface.get("addresses") if isinstance(interface.get("addresses"), dict) else {}
    ipv4 = str(addresses.get("v4") or "").strip()
    ipv6 = str(addresses.get("v6") or "").strip()
    if not ipv4 and not ipv6:
        raise ValueError("в ответе регистрации нет внутренних адресов туннеля")

    return {
        "peer_public_key": peer_public_key,
        "peer_endpoint": peer_endpoint,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "reserved": _reserved_from_client_id(config.get("client_id")),
        "device_id": str(result.get("id") or obj.get("id") or "").strip(),
        "token": str(result.get("token") or obj.get("token") or "").strip(),
    }


# --- scan output parsing ------------------------------------------------------
def parse_scan_output(text: str) -> list[dict]:
    """`addr:port|rtt_ms` lines → [{host, port, rtt_ms}], IPv6 arriving as `[addr]:port`.

    Splits on the **last** colon so both forms parse; drops blanks, malformed lines and any
    non-positive rtt (the Go side already omits `-1` padding, this is belt-and-braces). The host
    is returned unbracketed; `build_warp_conf` adds the brackets back for the Endpoint line.
    """
    endpoints: list[dict] = []
    for line in (text or "").splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        address, sep, rtt_part = trimmed.partition("|")
        if not sep:
            continue
        try:
            rtt_ms = int(rtt_part.strip())
        except ValueError:
            continue
        if rtt_ms <= 0:
            continue
        address = address.strip()
        host, _, port_text = address.rpartition(":")
        if not host:
            continue
        host = host.strip().strip("[]")
        try:
            port = int(port_text.strip())
        except ValueError:
            continue
        if not host or not (1 <= port <= 65535):
            continue
        endpoints.append({"host": host, "port": port, "rtt_ms": rtt_ms})
    return endpoints


def _subnet(host: str) -> str:
    if ":" in host:
        return ":".join(host.split(":")[:3])
    return ".".join(host.split(".")[:3])


def diversify(endpoints: list[dict], max_per_subnet: int = MAX_PER_SUBNET) -> list[dict]:
    """Reorder so the head has at most `max_per_subnet` endpoints per subnet (/24 v4, /48-ish v6).

    Reorders, never drops: the tail keeps everything that overflowed, in original order. A block
    that goes dark takes two same-/24 hits with it, so spreading the head across subnets is what
    makes the lead of the queue survive a network change.
    """
    per_subnet: dict[str, int] = {}
    head: list[dict] = []
    tail: list[dict] = []
    for endpoint in endpoints:
        key = _subnet(endpoint["host"])
        seen = per_subnet.get(key, 0)
        if seen < max_per_subnet:
            per_subnet[key] = seen + 1
            head.append(endpoint)
        else:
            tail.append(endpoint)
    return head + tail


# --- junk & config assembly (and-warpgen §2) ----------------------------------
def random_junk(rng: random.Random) -> tuple[int, int, int]:
    """(Jc, Jmin, Jmax) for one profile. Different per profile on purpose (N5).

    Jc in [3,8], Jmin in [30,70], Jmax in [Jmin+20, min(Jmin+80, 150)]. Bounds from and-warpgen
    §2.2: floor from the seeds that work everywhere, ceiling from N25 (heavy junk gained nothing,
    cost ~60 KB), zero excluded by N2.
    """
    count = rng.randint(JUNK_COUNT_MIN, JUNK_COUNT_MAX)
    minimum = rng.randint(JUNK_SIZE_FLOOR, JUNK_SIZE_FLOOR + 40)
    maximum = rng.randint(minimum + 20, min(minimum + 80, JUNK_SIZE_CEILING))
    return count, minimum, maximum


def _endpoint_text(host, port) -> str:
    """`host:port`, IPv6 as `[addr]:port` — an unbracketed v6 literal is not a valid Endpoint."""
    host = str(host).strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}"


def build_warp_conf(identity: dict, host: str, port: int, junk, i1: str = "") -> str:
    """One AmneziaWG config, byte-for-byte like Android's `WarpGeneratedStore.buildRawConfig`.

    `junk` is the `(Jc, Jmin, Jmax)` triple from `random_junk`. `i1` is an AmneziaWG `<b 0x…>`
    literal or "": when blank the `I1` line is omitted entirely — an empty `I1 = ` is an unknown
    key and `uapi.go` kills the tunnel on it (N6). `S1-S4=0` and `H1-H4=1,2,3,4` are stock
    WireGuard values, not parameters: a WARP node speaks stock WireGuard and understands nothing
    else (§2.1). An IPv6 `host` is bracketed in the Endpoint line (wireproxy-awg and
    nova_profiles reject `2606:…:2408`).
    """
    count, minimum, maximum = junk
    addresses = ", ".join(a for a in (identity.get("ipv4", ""), identity.get("ipv6", "")) if a)
    lines = [
        "[Interface]",
        f"PrivateKey = {identity['private_key']}",
        f"Address = {addresses}",
        "DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001",
        "MTU = 1280",
        "S1 = 0",
        "S2 = 0",
        "S3 = 0",
        "S4 = 0",
        f"Jc = {count}",
        f"Jmin = {minimum}",
        f"Jmax = {maximum}",
        "H1 = 1",
        "H2 = 2",
        "H3 = 3",
        "H4 = 4",
    ]
    if i1:
        lines.append(f"I1 = {i1}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {identity['peer_public_key']}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {_endpoint_text(host, port)}",
    ]
    return "\n".join(lines) + "\n"


# --- re-issue policy & failure counters (and-warpgen §5) ----------------------
def should_reissue(state: dict, now: float, profiles_present: bool) -> tuple[bool, str]:
    """Decide whether the whole set should be re-issued now. Returns (reissue, russian reason).

    Order matters. The 1-hour cooldown after a fruitless run wins first (a run costs a
    registration plus up to 45 s of scanning; retrying every minute is pointless). Then: no
    profiles on disk → issue; a set older than 14 days → issue; every recorded endpoint has
    failed → issue immediately (the user moved networks). Otherwise the set is fresh, keep it.
    """
    state = state or {}
    failed_at = state.get("failed_at") or 0
    if failed_at and 0 <= now - failed_at < COOLDOWN_SEC:
        return False, "недавняя неудачная попытка — ждём час до следующей"
    if not profiles_present:
        return True, "своих профилей ещё нет"
    created_at = state.get("created_at") or 0
    if not created_at:
        return True, "нет отметки о времени выпуска набора"
    if now - created_at > REISSUE_AFTER_SEC:
        return True, "профилям больше 14 дней"
    profiles = state.get("profiles") or {}
    if profiles and all((entry or {}).get("failures", 0) > 0 for entry in profiles.values()):
        return True, "все точки входа набора отказали"
    return False, "набор свежий, перевыпуск не нужен"


def _state_path(base_dir: str) -> str:
    return os.path.join(base_dir, TEMP_DIRNAME, STATE_FILENAME)


def _identity_path(base_dir: str) -> str:
    return os.path.join(base_dir, PROFILES_DIRNAME, GROUP_CLOUDFLARE, IDENTITY_FILENAME)


def _cloudflare_dir(base_dir: str) -> str:
    return os.path.join(base_dir, PROFILES_DIRNAME, GROUP_CLOUDFLARE)


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _os_error_text(exc: OSError) -> str:
    """Path-free description of an OSError: `str(exc)` embeds absolute paths (with the Windows
    user name), and reasons land in temp/, which ships with problem reports (I19)."""
    text = str(getattr(exc, "strerror", "") or "").strip() or type(exc).__name__
    winerror = getattr(exc, "winerror", None)
    errno_value = getattr(exc, "errno", None)
    if winerror:
        return f"{text} (WinError {winerror})"
    if errno_value:
        return f"{text} (errno {errno_value})"
    return text


def _scrub_reason(text: str) -> str:
    """One line, credentials stripped from any URL, bounded length — safe for logs and temp/."""
    line = " ".join(str(text or "").split())
    line = _URL_CREDENTIALS_RE.sub(r"\1***@", line)
    if len(line) > _REASON_MAX_CHARS:
        line = line[: _REASON_MAX_CHARS - 1] + "…"
    return line


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _replace_with_retry(src: str, dst: str) -> None:
    """`os.replace` that outlasts a brief Windows sharing violation (see _REPLACE_RETRIES)."""
    attempts = max(1, int(_REPLACE_RETRIES))
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt + 1 >= attempts:
                raise
            time.sleep(_REPLACE_RETRY_SLEEP_SEC)


def _remove_quietly(paths) -> None:
    for path in paths:
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass


def _write_json_atomic(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        _replace_with_retry(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def load_state(base_dir: str) -> dict:
    """The keyless generator state (`temp/warp-generated-state.json`), {} when absent or corrupt."""
    with _STATE_LOCK:
        return _read_json(_state_path(base_dir))


def _update_state(base_dir: str, mutate) -> dict:
    """Reload the state from disk, apply `mutate(state)` and write it back, all under the lock.

    Never write back a snapshot taken earlier: a long generate() would erase the failure counters
    note_outcome recorded meanwhile. Raises OSError when the write fails.
    """
    with _STATE_LOCK:
        state = _read_json(_state_path(base_dir))
        state.setdefault("version", _STATE_VERSION)
        mutate(state)
        _write_json_atomic(_state_path(base_dir), state)
        return state


def _profile_stem(name) -> str:
    """`AWG Cloudflare/WARPgen_03`, `…\\WARPgen_03.conf` or `WARPgen_03` → `WARPgen_03`."""
    stem = str(name or "").strip().replace("\\", "/").rsplit("/", 1)[-1].strip()
    if stem.lower().endswith(".conf"):
        stem = stem[: -len(".conf")]
    return stem


def note_outcome(base_dir: str, name: str, ok: bool) -> dict:
    """Record one connection outcome for a generated profile. Success zeroes its failure count.

    `name` is a profile stem such as `WARPgen_03`; a record id (`AWG Cloudflare/WARPgen_03`) or a
    file name is normalised to the stem. Names outside the current generated set (a seed, a
    replaced or unknown name) are ignored: a blank entry would never be read by the planner and
    would keep should_reissue's all-failed rule from firing. One success clears the counter and
    one failure raises the lead threshold (and-warpgen §5.3), so the queue converges in a single
    pass. Best-effort like `nova_profiles.record_outcome`: never raises, returns the state as it
    now stands in memory. The state file carries no keys or tokens (I19).
    """
    stem = _profile_stem(name)
    with _STATE_LOCK:
        state = _read_json(_state_path(base_dir))
        profiles = state.get("profiles")
        entry = None
        if stem.startswith(GENERATED_WARP_PREFIX) and isinstance(profiles, dict):
            entry = profiles.get(stem)
        if not isinstance(entry, dict):
            return state
        previous = _as_int(entry.get("failures"), 0)
        if ok:
            if previous == 0 and entry.get("failures") == 0:
                return state
            entry["failures"] = 0
        else:
            entry["failures"] = max(0, previous) + 1
        try:
            _write_json_atomic(_state_path(base_dir), state)
        except OSError:
            pass  # a counter is advisory; the connect loop must not die on a sharing violation
        return state


# --- nova-go bridge (the single seam tests replace) ---------------------------
def _run_nova_go(args: list[str], stdin_text: str = "", timeout: float = REGISTER_TIMEOUT_SEC,
                 env_extra: dict | None = None):
    """Run `nova-go <args>`; return (returncode, stdout, stderr). The one place tests fake.

    `args[0]` is the nova-go executable path. Never places a secret on argv — the scan private
    key rides in on stdin, a proxy URL in `env_extra`. `env_extra` overlays the inherited
    environment (a None value removes the variable); without it the environment is inherited
    unchanged. Windowless like every Nova helper. A timeout or a spawn failure is turned into a
    non-zero return and a russian, path-free stderr line rather than an exception, so the caller
    has one failure path.
    """
    env = None
    if env_extra:
        env = dict(os.environ)
        for key, value in env_extra.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = str(value)
    try:
        completed = subprocess.run(
            list(args),
            input=stdin_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
            env=env,
        )
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"nova-go не ответил за {timeout:g} с"
    except OSError as exc:
        return 127, "", f"не удалось запустить nova-go: {_os_error_text(exc)}"


def _register_args(nova_go_path: str, public_key_b64: str, api_mode: str = "auto") -> list[str]:
    return [
        nova_go_path, "warp", "register",
        "--public-key", public_key_b64,
        "--model", "PC",
        "--locale", "en-US",
        "--api-mode", api_mode,
        "--timeout", f"{REGISTER_TIMEOUT_SEC}s",
    ]


def _proxy_routes(api_proxy) -> list:
    """One URL, a list of URLs or None -> the ordered, de-duplicated list of proxy routes."""
    if api_proxy is None:
        return []
    raw = [api_proxy] if isinstance(api_proxy, str) else list(api_proxy)
    routes = []
    for value in raw:
        text = str(value or "").strip()
        if text and text not in routes:
            routes.append(text)
    return routes


def _scan_args(nova_go_path: str, peer_public_key_b64: str) -> list[str]:
    return [
        nova_go_path, "warp", "scan",
        "--peer-public-key", peer_public_key_b64,
        "--v4", "--v6",
        "--timeout", f"{SCAN_TIMEOUT_SEC}s",
        "--limit", str(TARGET_COUNT),
        "--rtt-max", f"{MAX_DESIRABLE_RTT_MS}ms",
    ]


def _stderr_detail(stderr: str) -> str:
    """The last non-blank stderr line without nova-go's `<time> INF warp:` prefix, scrubbed."""
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    if not lines:
        return ""
    return _scrub_reason(_GO_LOG_PREFIX_RE.sub("", lines[-1]))


def _register(nova_go_path: str, public_key_b64: str, api_proxy, log) -> dict:
    """Register the public key via nova-go. Raises RuntimeError with a russian reason on failure.

    `api_proxy` is one URL or a list of them (local Opera first, then the Nova relays, which carry
    api.cloudflareclient.com on their allow-list). The first run is nova-go's own `auto`: direct
    uTLS first, then the first proxy. Each further proxy gets a run of its own in `proxy` mode --
    nova-go takes one proxy per run, and a refusal on one route (blocked SNI, 429 from a shared
    address) says nothing about the next.
    """
    routes = _proxy_routes(api_proxy)
    attempts = [("auto", routes[0] if routes else None)] + [("proxy", route) for route in routes[1:]]
    last_error = None
    for index, (mode, route) in enumerate(attempts):
        try:
            return _register_once(nova_go_path, public_key_b64, route, mode, log)
        except RuntimeError as exc:
            last_error = exc
            if getattr(exc, "usage_error", False) or index == len(attempts) - 1:
                break
            log(f"{LOG_PREFIX} регистрация не прошла ({exc}) — пробую следующий маршрут.")
    raise last_error


def _register_once(nova_go_path: str, public_key_b64: str, api_proxy, api_mode, log) -> dict:
    # The proxy never goes on argv (a relay URL carries its password). None removes an
    # inherited NOVA_API_PROXY so a stray value cannot silently reroute the registration.
    env_extra = {_API_PROXY_ENV: str(api_proxy) if api_proxy else None}
    code, stdout, stderr = _run_nova_go(
        _register_args(nova_go_path, public_key_b64, api_mode),
        timeout=REGISTER_TIMEOUT_SEC + _SUBPROCESS_MARGIN_SEC,
        env_extra=env_extra,
    )
    line = next((ln for ln in stdout.splitlines() if ln.strip()), "").strip()
    payload = {}
    if line:
        try:
            payload = json.loads(line)
        except ValueError:
            payload = {}
    if code == 0 and isinstance(payload, dict) and payload.get("ok"):
        response = payload.get("response")
        if not isinstance(response, dict):
            raise RuntimeError("nova-go вернул регистрацию без поля response")
        via = str(payload.get("via") or "").strip()
        if via:
            log(f"{LOG_PREFIX} регистрация прошла через {_scrub_reason(via)}.")
        try:
            return parse_registration(response)
        except ValueError as exc:
            raise RuntimeError(f"ответ регистрации непригоден: {exc}") from None
    # Prefer the tool's own structured reason; fall back to exit-code meaning.
    reason = ""
    if isinstance(payload, dict):
        reason = _scrub_reason(payload.get("error") or "")
    if not reason:
        reason = {
            20: "API Cloudflare недоступен",
            21: "API Cloudflare ответил ошибкой",
            2: "неверные аргументы вызова nova-go",
            124: "nova-go не ответил вовремя",
            127: "не удалось запустить nova-go",
        }.get(code, f"nova-go завершился с кодом {code}")
    error = RuntimeError(reason)
    # Wrong arguments are wrong on every route; a missing binary is missing on every route too.
    error.usage_error = code in (2, 127)
    raise error


def _scan(nova_go_path: str, private_key_b64: str, peer_public_key_b64: str, log):
    """One scan pass via nova-go → (verified endpoints, error).

    `error` is None when nova-go exited 0 (zero hits included — exit 0 is Go's success), else
    `{"code": N, "detail": "<last stderr line>"}`: a killed, missing or argument-rejecting
    scanner is a failure, not an empty network.
    """
    code, stdout, stderr = _run_nova_go(
        _scan_args(nova_go_path, peer_public_key_b64),
        stdin_text=private_key_b64 + "\n",
        timeout=SCAN_TIMEOUT_SEC + _SUBPROCESS_MARGIN_SEC,
    )
    if code != 0:
        detail = _stderr_detail(stderr)
        log(f"{LOG_PREFIX} сканер завершился с кодом {code}" + (f": {detail}" if detail else "."))
        return [], {"code": code, "detail": detail}
    return parse_scan_output(stdout), None


def _scan_error_reason(error: dict) -> str:
    detail = error.get("detail") or ""
    return f"сканер завершился с ошибкой (код {error.get('code')})" + (f": {detail}" if detail else "")


def _collect_verified(nova_go_path: str, identity: dict, log, progress=None, target: int = TARGET_COUNT):
    """Two-pass verified-endpoint collection → (endpoints, error of the last pass or None).

    The second pass runs only if the first exited cleanly with fewer than 24 hits. Union (not
    intersection) of the two passes, taking the min rtt per (host,port) — the scanner walks the
    prefixes at random, so two passes find largely different addresses and an intersection would
    be near-empty (and-warpgen §3.5). The progress callback fires before the second pass, so a
    cancel (or Nova shutting down) does not spawn another nova-go.
    """
    private_key, peer_key = identity["private_key"], identity["peer_public_key"]
    first, error = _scan(nova_go_path, private_key, peer_key, log)
    if error is not None:
        # A scanner that failed (killed at Nova exit, missing, rejecting its arguments) fails
        # again; a second pass would only start another nova-go that may outlive Nova.
        return first, error
    if len(first) >= ENOUGH_VERIFIED:
        return first, None
    log(f"{LOG_PREFIX} проверенных точек {len(first)} — меньше {ENOUGH_VERIFIED}, идём вторым проходом.")
    _progress(progress, "WARP: ищу точки входа, второй проход", 0, target)
    second, error = _scan(nova_go_path, private_key, peer_key, log)
    best: dict[tuple, dict] = {}
    for endpoint in first + second:
        key = (endpoint["host"], endpoint["port"])
        current = best.get(key)
        if current is None or endpoint["rtt_ms"] < current["rtt_ms"]:
            best[key] = endpoint
    return list(best.values()), error


def _identity_problem(identity: dict) -> str:
    """Why a saved identity cannot produce working profiles, or "" when it can."""
    if not identity:
        return "файл личности пуст или не читается"
    raw_private = _key_bytes(identity.get("private_key"))
    if raw_private is None:
        return "закрытый ключ не является ключом WireGuard"
    raw_public = _key_bytes(identity.get("public_key"))
    if raw_public is None:
        return "открытый ключ не является ключом WireGuard"
    if _key_bytes(identity.get("peer_public_key")) is None:
        return "ключ пира не является ключом WireGuard"
    derived = x25519.X25519PrivateKey.from_private_bytes(raw_private).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if derived != raw_public:
        # Cloudflare knows only the registered public key: handshakes would fail silently.
        return "закрытый ключ не соответствует зарегистрированному открытому"
    if not str(identity.get("ipv4") or "").strip() and not str(identity.get("ipv6") or "").strip():
        return "нет внутренних адресов туннеля"
    return ""


def _load_identity(base_dir: str) -> tuple[dict, str]:
    """(identity, "") when usable; ({}, "") when absent; ({}, problem) when present but unusable."""
    path = _identity_path(base_dir)
    if not os.path.exists(path):
        return {}, ""
    identity = _read_json(path)
    problem = _identity_problem(identity)
    return ({}, problem) if problem else (identity, "")


def _issue_identity(base_dir: str, nova_go_path: str, api_proxy, log, now: float) -> tuple[dict, str]:
    """Generate a key, register it and save the identity → (identity, "") or ({}, russian reason)."""
    private_b64, public_b64 = generate_keypair()
    try:
        parsed = _register(nova_go_path, public_b64, api_proxy, log)
    except RuntimeError as exc:
        reason = str(exc)
        log(f"{LOG_PREFIX} регистрация не прошла — {reason}. Остаются встроенные семена.")
        return {}, f"регистрация не прошла: {reason}"
    identity = {
        "private_key": private_b64,
        "public_key": public_b64,
        "peer_public_key": parsed["peer_public_key"],
        "ipv4": parsed["ipv4"],
        "ipv6": parsed["ipv6"],
        "reserved": parsed["reserved"],
        "device_id": parsed["device_id"],
        "token": parsed["token"],
        "created_at": now,
        "version": _IDENTITY_VERSION,
    }
    try:
        _write_json_atomic(_identity_path(base_dir), identity)
    except OSError as exc:
        reason = f"не удалось сохранить личность: {_os_error_text(exc)}"
        log(f"{LOG_PREFIX} {reason}. Остаются встроенные семена.")
        return {}, reason
    log(f"{LOG_PREFIX} личность зарегистрирована, адрес {identity['ipv4'] or identity['ipv6']}.")
    return identity, ""


def _existing_generated(cloudflare_dir: str) -> list[str]:
    try:
        names = os.listdir(cloudflare_dir)
    except OSError:
        return []
    return sorted(
        n for n in names
        if n.startswith(GENERATED_WARP_PREFIX) and n.lower().endswith(".conf")
    )


def _progress(progress, message: str, done: int, total: int) -> None:
    """Report progress. The callback may raise to abort — that propagates out of `generate`."""
    if progress is not None:
        progress(message, done, total)


def _profile_entry(endpoint: dict, prior) -> dict:
    """Keyless per-profile state; the failure count survives only for the very same endpoint."""
    prior = prior if isinstance(prior, dict) else {}
    same = prior.get("host") == endpoint["host"] and _as_int(prior.get("port"), -1) == endpoint["port"]
    return {
        "host": endpoint["host"],
        "port": endpoint["port"],
        "rtt_ms": endpoint["rtt_ms"],
        "failures": max(0, _as_int(prior.get("failures"), 0)) if same else 0,
    }


def generate(base_dir, nova_go_path, *, log, force=False, api_proxy=None, progress=None, target=50) -> dict:
    """Issue up to `target` own-WARP profiles into `profiles/AWG Cloudflare/`.

    Reuses `warp_identity.json` unless `force` or it is unusable (malformed keys, a private key
    that does not match the registered public key); if the scanner rejects a reused identity
    (exit 2) it is re-registered once. Registers via nova-go only when needed (`api_proxy` is one
    URL or an ordered list of them, tried route by route; it goes through the environment, never
    argv), scans for endpoints (a second pass if the first exited
    cleanly with fewer than 24 verified, unioned by min rtt), diversifies, then writes
    `WARPgen_01..NN.conf`: all texts built first, every one staged as `*.tmp`, then each
    `os.replace`d (retrying brief sharing violations), then stale `WARPgen_*` beyond the new count
    removed. A scan with zero hits or a failed scanner keeps the previous set and records the
    real reason (with the 1-hour cooldown). If a replace still fails midway, the state records
    exactly what is on disk. `WARPv*` seeds are never touched. The `progress(message, done,
    total)` callback may raise to abort. Returns a summary dict; the keyless, path-free state
    goes to `temp/warp-generated-state.json` (I19), merged into the file as it is at write time.
    """
    now = time.time()
    cloudflare_dir = _cloudflare_dir(base_dir)
    os.makedirs(cloudflare_dir, exist_ok=True)
    previous_state = load_state(base_dir)  # read-only: decisions only, never written back
    summary = {"ok": False, "reason": "", "count": 0, "reused_identity": False, "best_rtt_ms": None}

    def save_state(mutate) -> None:
        try:
            _update_state(base_dir, mutate)
        except OSError as exc:
            log(f"{LOG_PREFIX} не удалось сохранить состояние генератора: {_os_error_text(exc)}")

    def record_failure(reason: str, *, scan_code=None, swapped=()) -> dict:
        def mutate(state: dict) -> None:
            state["last_run_at"] = now
            state["last_error"] = reason
            state["failed_at"] = now
            if scan_code is not None:
                state["last_scan_code"] = scan_code
            if swapped:
                profiles = state.get("profiles") if isinstance(state.get("profiles"), dict) else {}
                for name, endpoint in swapped:
                    profiles[name] = _profile_entry(endpoint, profiles.get(name))
                state["profiles"] = profiles

        save_state(mutate)
        summary["ok"] = False
        summary["reason"] = reason
        return summary

    # Any exception below propagates to the caller on purpose: a progress-callback abort
    # (a user-initiated cancel) is not a fault and must NOT arm the 1-hour cooldown, and an
    # unexpected bug should surface. Operational failures — registration, failed or empty scan,
    # write fault — are each handled inline with record_failure() and an early return.
    _progress(progress, "WARP: готовлю личность", 0, target)
    identity = {}
    if not force:
        identity, problem = _load_identity(base_dir)
        if problem:
            log(f"{LOG_PREFIX} сохранённая личность непригодна ({problem}) — регистрирую устройство заново.")
    if identity:
        log(f"{LOG_PREFIX} личность уже есть, регистрацию пропускаем.")
        summary["reused_identity"] = True
    else:
        _progress(progress, "WARP: регистрирую устройство", 0, target)
        identity, reason = _issue_identity(base_dir, nova_go_path, api_proxy, log, now)
        if not identity:
            return record_failure(reason)

    _progress(progress, "WARP: ищу точки входа", 0, target)
    verified, scan_error = _collect_verified(nova_go_path, identity, log, progress, target)
    if (not verified and scan_error is not None and scan_error["code"] == _EXIT_USAGE
            and summary["reused_identity"]
            and _as_int(previous_state.get("last_scan_code"), 0) != _EXIT_USAGE):
        # nova-go rejected the arguments built from the saved identity. Re-register once; if the
        # fresh identity is rejected too, last_scan_code=2 stops this from repeating every hour.
        log(f"{LOG_PREFIX} сканер отверг сохранённую личность (код {_EXIT_USAGE}) — "
            f"регистрирую устройство заново.")
        _progress(progress, "WARP: регистрирую устройство", 0, target)
        identity, reason = _issue_identity(base_dir, nova_go_path, api_proxy, log, now)
        if not identity:
            return record_failure(reason)
        summary["reused_identity"] = False
        _progress(progress, "WARP: ищу точки входа", 0, target)
        verified, scan_error = _collect_verified(nova_go_path, identity, log, progress, target)

    verified.sort(key=lambda e: e["rtt_ms"])
    endpoints = diversify(verified)[:target]
    if not endpoints:
        if scan_error is not None:
            reason = _scan_error_reason(scan_error)
            log(f"{LOG_PREFIX} {reason}. Личность сохранена, прошлый набор профилей не тронут.")
            return record_failure(reason, scan_code=scan_error["code"])
        log(f"{LOG_PREFIX} сканер не нашёл ни одной точки входа. "
            f"Личность сохранена, прошлый набор профилей не тронут.")
        return record_failure("сканер не нашёл точек входа", scan_code=0)

    # Build every config text first (this is where per-profile I1 is forged and where the
    # abort-raising progress callback fires); nothing is written until they all exist.
    rng = random.Random()
    sni_offset = rng.randrange(len(nova_quic_initial.WHITE_SNI))
    planned: list[tuple[str, str]] = []  # (WARPgen_NN, config text)
    with_own_i1 = 0
    for index, endpoint in enumerate(endpoints):
        name = f"{GENERATED_WARP_PREFIX}{index + 1:02d}"
        junk = random_junk(rng)
        sni = nova_quic_initial.pick_sni(sni_offset + index)
        i1 = nova_quic_initial.build_i1(sni) if sni else ""
        if i1:
            with_own_i1 += 1
        planned.append((name, build_warp_conf(identity, endpoint["host"], endpoint["port"], junk, i1)))
        _progress(progress, f"WARP: собираю профиль {index + 1}", index + 1, len(endpoints))
    # I19/I4: silence here is indistinguishable from success — say when no SNI made it in.
    if with_own_i1 == 0:
        log(f"{LOG_PREFIX} предупреждение: ни для одного профиля не собрано прикрытие I1.")
    else:
        log(f"{LOG_PREFIX} своё прикрытие I1 собрано для {with_own_i1} из {len(planned)} профилей.")

    # Stage 1: every text to its *.tmp. A fault here has swapped nothing — the old set is intact.
    tmp_paths = [os.path.join(cloudflare_dir, f"{name}.conf.tmp") for name, _ in planned]
    try:
        for (_name, text), tmp in zip(planned, tmp_paths):
            with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
    except OSError as exc:
        _remove_quietly(tmp_paths)
        reason = f"не удалось записать профили: {_os_error_text(exc)}"
        log(f"{LOG_PREFIX} {reason}. Прошлый набор профилей не тронут.")
        return record_failure(reason, scan_code=0)

    # Stage 2: swap each staged file in. A fault that outlasts the retry leaves a mixed set, so
    # the state must then describe exactly the files that now hold new content.
    swapped: list[tuple[str, dict]] = []
    try:
        for (name, _text), tmp, endpoint in zip(planned, tmp_paths, endpoints):
            _replace_with_retry(tmp, os.path.join(cloudflare_dir, f"{name}.conf"))
            swapped.append((name, endpoint))
    except OSError as exc:
        _remove_quietly(tmp_paths)
        detail = _os_error_text(exc)
        if not swapped:
            reason = f"не удалось записать профили: {detail}"
            log(f"{LOG_PREFIX} {reason}. Прошлый набор профилей не тронут.")
            return record_failure(reason, scan_code=0)
        reason = f"набор профилей записан частично ({len(swapped)} из {len(planned)}): {detail}"
        log(f"{LOG_PREFIX} {reason}.")
        return record_failure(reason, scan_code=0, swapped=swapped)

    # Remove stale generated confs beyond the new count (never WARPv* seeds).
    keep = {f"{name}.conf" for name, _ in planned}
    for name in _existing_generated(cloudflare_dir):
        if name not in keep:
            try:
                os.remove(os.path.join(cloudflare_dir, name))
            except OSError as exc:
                log(f"{LOG_PREFIX} не удалось удалить устаревший {name}: {_os_error_text(exc)}")

    best_rtt = min((e["rtt_ms"] for e in endpoints), default=None)

    def mutate_success(state: dict) -> None:
        # Built from the state as it is now, so failures recorded during the run carry forward
        # for endpoints that stayed behind the same name.
        old_profiles = state.get("profiles") if isinstance(state.get("profiles"), dict) else {}
        state.update({
            "created_at": now,
            "last_run_at": now,
            "last_error": "",
            "failed_at": 0,
            "last_scan_code": 0,
            "profiles": {name: _profile_entry(endpoint, old_profiles.get(name)) for name, endpoint in swapped},
        })

    save_state(mutate_success)

    log(f"{LOG_PREFIX} выпущено {len(planned)} профилей, лучший {best_rtt} мс.")
    summary.update({
        "ok": True,
        "reason": "",
        "count": len(planned),
        "best_rtt_ms": best_rtt,
    })
    _progress(progress, f"WARP: {len(planned)} профилей, лучший {best_rtt} мс", len(planned), len(planned))
    return summary
