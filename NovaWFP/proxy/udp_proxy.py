import argparse
import ctypes
import ipaddress
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Dict, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
# В установленной программе REPO_ROOT уже указывает на каталог resources; при
# запуске из исходников модули Nova лежат в resources/ рядом с nova.pyw.
for _root in (REPO_ROOT / "resources", REPO_ROOT):
    if _root.is_dir() and str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

APP_ROOT = REPO_ROOT.parent if REPO_ROOT.name.lower() == "resources" else REPO_ROOT

# `temp/` надо считать опубликованным: его прикладывают к отчётам о проблеме.
# Имя пользователя Windows внутри пути программы опознаёт человека, а для
# классификации приложения нужен хвост пути, а не начало.
try:
    from nova_privacy import redact_user_path, redact_user_paths_in_text
except Exception:  # модуль не найден — лучше писать полный путь, чем упасть
    def redact_user_path(value):
        return value

    def redact_user_paths_in_text(value):
        return value



def _data_path(*parts):
    r"""Данные верхнего уровня (`ip/`, `list/`, `temp/`) лежат НЕ рядом с модулем.

    Копия правила из `tcp_proxy.py` — оба помощника обязаны считать одинаково;
    там же расписано, чем обошлась прежняя эвристика с
    `candidate.parent.is_dir()`. Здесь она не выстрелила только потому, что все
    вызовы двухсоставные (`temp/...`), но расхождение между двумя копиями
    одного резолвера — это следующий такой же тихий отказ.

    Корень определяется тем же правилом, что и `APP_ROOT` в
    `tgrelay/transparent_relay.py`: перешагнуть каталог по имени `resources`.
    Существующий путь побеждает — файл он или каталог; иначе побеждает `{app}`.
    """
    for root in (APP_ROOT, REPO_ROOT):
        candidate = root.joinpath(*parts)
        if candidate.exists():
            return candidate
    return APP_ROOT.joinpath(*parts)


from tgrelay.udp_transport import UdpEndpoint, get_udp_upstream_attempts, open_udp_endpoint  # noqa: E402

# ИИ-приложения на «Авто» читают тот же temp/vpn-egress.json, что и tcp_proxy (страна выхода слотов и
# признак DNS-AI). Без модуля остаётся прежнее поведение.
try:
    import nova_vpn_slots as _vpn_slots  # noqa: E402
except Exception:  # pragma: no cover
    _vpn_slots = None

_EGRESS_STATE_CACHE = (
    _vpn_slots.EgressStateCache(str(_data_path("temp", _vpn_slots.EGRESS_STATE_FILENAME)))
    if _vpn_slots is not None else None
)


def _egress_state():
    if _EGRESS_STATE_CACHE is None:
        return None
    try:
        return _EGRESS_STATE_CACHE.get()
    except Exception:
        return None


def _ai_apps_udp_labels():
    """UDP of an AI app on «Авто»: SOCKS5 of the main slot when its exit is outside RU/BY; with no
    suitable slot, direct only while DNS-AI carries the DNS. The second slot is HTTP CONNECT and has
    no UDP, so when it is the only suitable one the app falls back to TCP (nothing leaks)."""
    state = _egress_state()
    slots = _vpn_slots.ai_apps_auto_slots_from_state(state)
    if "primary" in slots:
        return ["warp-socks"]
    if slots:
        return []
    return ["direct"] if _vpn_slots.ai_apps_direct_allowed(state) else []
from nova_routing_profiles import dns_ai_route_state, dns_ai_route_labels, is_dns_ai_endpoint


LOG = logging.getLogger("nova.wfp.udp_proxy")
DIVERT_REDIRECT_MAP = str(os.environ.get("NOVA_DIVERT_REDIRECT_MAP", "") or "").strip()

ENVELOPE_MAGIC = b"NUP1"
ENVELOPE_FAMILY_V4 = 4
ENVELOPE_FAMILY_V6 = 6
SESSION_IDLE_TIMEOUT = float(os.environ.get("NOVA_WFP_UDP_IDLE_TIMEOUT", "30.0") or 30.0)
# Discord «Авто»: голос идёт сначала напрямую (winws уже десинхронизирует его UDP), и только
# если за это время от сервера не пришло ни одного пакета — через VPN. Без этой проверки UDP
# не умеет «не открылось»: сокет всегда открывается, а молчание выглядит как тишина в звонке.
DISCORD_DIRECT_MIN_TX = int(os.environ.get("NOVA_WFP_DISCORD_DIRECT_MIN_TX", "6") or 6)
DISCORD_DIRECT_SILENT_SEC = float(os.environ.get("NOVA_WFP_DISCORD_DIRECT_SILENT_SEC", "3.0") or 3.0)
DISCORD_DIRECT_BAD_TTL = float(os.environ.get("NOVA_WFP_DISCORD_DIRECT_BAD_TTL", "300.0") or 300.0)
# Второй случай «прямой молчит»: провайдер пропускает первые ответы сервера (IP discovery) и затем
# режет поток (pktmon на сетевой карте: клиент шлёт ~20 пакетов/с, ответов 2 за минуту, а через VPN
# тот же сервер отвечает ровно). Нулевых ответов тут нет, поэтому первая проверка его не ловит.
DISCORD_DIRECT_STALL_SEC = float(os.environ.get("NOVA_WFP_DISCORD_DIRECT_STALL_SEC", "8.0") or 8.0)
DISCORD_DIRECT_STALL_MIN_TX = int(os.environ.get("NOVA_WFP_DISCORD_DIRECT_STALL_MIN_TX", "3") or 3)
DISCORD_DIRECT_STALL_BAD_TTL = float(os.environ.get("NOVA_WFP_DISCORD_DIRECT_STALL_BAD_TTL", "1800.0") or 1800.0)
DISCORD_STATS_EVERY_SEC = float(os.environ.get("NOVA_WFP_DISCORD_STATS_EVERY_SEC", "15.0") or 15.0)
NOVA_WFP_PROTOCOL_VERSION = 16
NOVA_WFP_DEVICE_PATH = r"\\.\NovaWFP"
NOVA_WFP_DEVICE_TYPE = 0xA501
NOVA_WFP_IOCTL_INDEX = 0x900
IPPROTO_UDP = 17
FWP_IP_VERSION_V4 = 0
FWP_IP_VERSION_V6 = 1
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
ERROR_NOT_FOUND = 1168
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ROUTING_SETTINGS_PATH = _data_path("temp", "routing_settings.json")
_ROUTING_SETTINGS_CACHE: dict = {}
_ROUTING_SETTINGS_MTIME: float = -1.0
ROUTING_GROUP_ALIASES = {
    "browser": "browser",
    "telegram": "telegram",
    "whatsapp": "whatsapp",
    "discord": "discord",
    "ai_apps": "ai_apps",
}


def _load_routing_settings() -> dict:
    global _ROUTING_SETTINGS_CACHE, _ROUTING_SETTINGS_MTIME
    try:
        stat = ROUTING_SETTINGS_PATH.stat()
        mtime = float(stat.st_mtime)
    except Exception:
        _ROUTING_SETTINGS_CACHE = {}
        _ROUTING_SETTINGS_MTIME = -1.0
        return {}
    if mtime == _ROUTING_SETTINGS_MTIME and isinstance(_ROUTING_SETTINGS_CACHE, dict):
        return _ROUTING_SETTINGS_CACHE
    try:
        with ROUTING_SETTINGS_PATH.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}
    _ROUTING_SETTINGS_CACHE = payload
    _ROUTING_SETTINGS_MTIME = mtime
    return payload


def _get_app_route_mode(app_key: str) -> str:
    payload = _load_routing_settings()
    key = ROUTING_GROUP_ALIASES.get(str(app_key or "").strip().lower(), "browser")
    routes = payload.get("routes") if isinstance(payload, dict) else {}
    if isinstance(routes, dict) and routes:
        mode = str(routes.get(key) or "auto").strip().lower()
        if mode not in {"auto", "warp", "opera", "direct"}:
            mode = "auto"
        if key != "browser" and mode == "auto":
            mode = str(routes.get("browser") or "auto").strip().lower()
            if mode not in {"auto", "warp", "opera", "direct"}:
                mode = "auto"
        return mode
    apps = payload.get("apps") if isinstance(payload, dict) else {}
    if not isinstance(apps, dict):
        return "auto"
    mode = str(apps.get(key) or "auto").strip().lower()
    if mode not in {"auto", "warp", "opera", "direct"}:
        mode = "auto"
    return mode


# Жёсткая привязка к слоту обещана пока только для Telegram: «Осн.»/«Доп.» в
# его строке настроек означает «этим маршрутом и никаким другим». Discord,
# WhatsApp и OBS остались на прежнем поведении, где режим — предпочтение.
PINNED_EGRESS_APPS = {"telegram"}
PINNED_EGRESS_BY_MODE = {"warp": "warp-socks", "opera": "opera-http"}


def _pinned_egress_label(app_family: str) -> str:
    app = str(app_family or "").strip().lower()
    if app not in PINNED_EGRESS_APPS:
        return ""
    return PINNED_EGRESS_BY_MODE.get(_get_app_route_mode(app), "")


def _ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    return ((int(device_type) << 16) | (int(access) << 14) | (int(function) << 2) | int(method))


IOCTL_NOVA_WFP_RESOLVE_UDP_FLOW = _ctl_code(NOVA_WFP_DEVICE_TYPE, NOVA_WFP_IOCTL_INDEX + 5, 0, 1)
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_KERNEL32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
_KERNEL32.CreateFileW.restype = wintypes.HANDLE
_KERNEL32.DeviceIoControl.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
_KERNEL32.DeviceIoControl.restype = wintypes.BOOL
_KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
_KERNEL32.CloseHandle.restype = wintypes.BOOL

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


_KERNEL32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_KERNEL32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_KERNEL32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_KERNEL32.Process32FirstW.restype = wintypes.BOOL
_KERNEL32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_KERNEL32.Process32NextW.restype = wintypes.BOOL


class NOVA_WFP_SOCKET_ADDRESS_V1(ctypes.Structure):
    _fields_ = [
        ("ScopeId", wintypes.ULONG),
        ("Port", wintypes.USHORT),
        ("Address", ctypes.c_ubyte * 16),
    ]


class NOVA_WFP_UDP_FLOW_KEY_V1(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("IpVersion", wintypes.ULONG),
        ("Protocol", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
        ("LocalAddress", NOVA_WFP_SOCKET_ADDRESS_V1),
    ]


class NOVA_WFP_UDP_FLOW_INFO_V1(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("IpVersion", wintypes.ULONG),
        ("Protocol", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("PreferredEgress", wintypes.ULONG),
        ("TargetFlags", wintypes.ULONG),
        ("LastSeenTick", ctypes.c_ulonglong),
        ("LocalAddress", NOVA_WFP_SOCKET_ADDRESS_V1),
        ("RemoteAddress", NOVA_WFP_SOCKET_ADDRESS_V1),
        ("AppId", wintypes.WCHAR * 520),
    ]


def _mask_ip_for_log(host: str) -> str:
    try:
        addr = ipaddress.ip_address(str(host or "").strip())
    except ValueError:
        return str(host or "").strip()
    if addr.version == 4:
        parts = str(addr).split(".")
        return f"{parts[0]}.{parts[1]}.***.***"
    text = str(addr)
    chunks = text.split(":")
    return ":".join(chunks[:2] + ["****", "****"])


def _snapshot_process_parents() -> Dict[int, Tuple[int, str]]:
    snapshot: Dict[int, Tuple[int, str]] = {}
    handle = _KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if int(handle) == int(INVALID_HANDLE_VALUE):
        return snapshot
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not _KERNEL32.Process32FirstW(handle, ctypes.byref(entry)):
            return snapshot
        while True:
            snapshot[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), str(entry.szExeFile or ""))
            if not _KERNEL32.Process32NextW(handle, ctypes.byref(entry)):
                break
    finally:
        try:
            _KERNEL32.CloseHandle(handle)
        except Exception:
            pass
    return snapshot


def encode_envelope(host: str, port: int, payload: bytes) -> bytes:
    addr = ipaddress.ip_address(str(host or "").strip())
    if addr.version == 4:
        family = ENVELOPE_FAMILY_V4
        packed = addr.packed
    else:
        family = ENVELOPE_FAMILY_V6
        packed = addr.packed
    header = ENVELOPE_MAGIC + bytes([family, 0]) + int(port).to_bytes(2, "big")
    return header + packed + bytes(payload or b"")


def decode_envelope(packet: bytes) -> Tuple[str, int, bytes]:
    if len(packet) < 8 or packet[:4] != ENVELOPE_MAGIC:
        raise OSError("invalid NovaWFP UDP envelope")
    family = int(packet[4])
    port = int.from_bytes(packet[6:8], "big")
    offset = 8
    if family == ENVELOPE_FAMILY_V4:
        end = offset + 4
    elif family == ENVELOPE_FAMILY_V6:
        end = offset + 16
    else:
        raise OSError(f"unsupported NovaWFP UDP family {family}")
    if len(packet) < end:
        raise OSError("truncated NovaWFP UDP envelope")
    host = str(ipaddress.ip_address(packet[offset:end]))
    return host, port, packet[end:]


def _driver_socket_address_for_host(host: str, port: int) -> Tuple[NOVA_WFP_SOCKET_ADDRESS_V1, int]:
    addr = ipaddress.ip_address(str(host or "").strip())
    out = NOVA_WFP_SOCKET_ADDRESS_V1()
    out.Port = int(port)
    packed = addr.packed
    for index, value in enumerate(packed):
        out.Address[index] = value
    if addr.version == 4:
        return out, FWP_IP_VERSION_V4
    return out, FWP_IP_VERSION_V6


def _format_driver_socket_address(address: NOVA_WFP_SOCKET_ADDRESS_V1, ip_version: int) -> Tuple[str, int]:
    port = int(address.Port)
    if int(ip_version) == FWP_IP_VERSION_V4:
        raw = int.from_bytes(bytes(address.Address[:4]), byteorder="little", signed=False)
        return socket.inet_ntoa(struct.pack("!I", raw)), port
    return str(ipaddress.ip_address(bytes(address.Address[:16]))), port


def _resolve_udp_flow_exact(local_host: str, local_port: int) -> Optional[dict]:
    handle = _KERNEL32.CreateFileW(
        NOVA_WFP_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        key = NOVA_WFP_UDP_FLOW_KEY_V1()
        info = NOVA_WFP_UDP_FLOW_INFO_V1()
        bytes_returned = wintypes.DWORD(0)
        key.Version = NOVA_WFP_PROTOCOL_VERSION
        key.Protocol = IPPROTO_UDP
        key.LocalAddress, key.IpVersion = _driver_socket_address_for_host(local_host, local_port)
        ok = _KERNEL32.DeviceIoControl(
            handle,
            IOCTL_NOVA_WFP_RESOLVE_UDP_FLOW,
            ctypes.byref(key),
            ctypes.sizeof(key),
            ctypes.byref(info),
            ctypes.sizeof(info),
            ctypes.byref(bytes_returned),
            None,
        )
        if not ok:
            error = ctypes.get_last_error()
            if int(error) == ERROR_NOT_FOUND:
                return None
            raise ctypes.WinError(error)
        target_host, target_port = _format_driver_socket_address(info.RemoteAddress, int(info.IpVersion))
        resolved_local_host, resolved_local_port = _format_driver_socket_address(info.LocalAddress, int(info.IpVersion))
        return {
            "target_host": target_host,
            "target_port": target_port,
            "local_host": resolved_local_host,
            "local_port": resolved_local_port,
            "process_id": int(info.ProcessId),
            "preferred_egress": int(info.PreferredEgress),
            "target_flags": int(info.TargetFlags),
            "app_id": str(info.AppId).rstrip("\x00"),
        }
    finally:
        _KERNEL32.CloseHandle(handle)


def resolve_udp_flow(local_host: str, local_port: int) -> Optional[dict]:
    candidates = [str(local_host or "").strip()]
    try:
        addr = ipaddress.ip_address(candidates[0])
        if addr.version == 4:
            for extra in ("0.0.0.0", "127.0.0.1"):
                if extra not in candidates:
                    candidates.append(extra)
        else:
            for extra in ("::", "::1"):
                if extra not in candidates:
                    candidates.append(extra)
    except ValueError:
        pass
    for candidate in candidates:
        try:
            resolved = _resolve_udp_flow_exact(candidate, int(local_port))
        except Exception as exc:
            LOG.info(
                f"[NovaWFP][UDP] resolve-error local={candidate}:{int(local_port)} error={exc}"
            )
            return None
        if resolved:
            return resolved
    return None


def _resolve_divert_udp_flow(local_host: str, local_port: int) -> Optional[dict]:
    path = str(DIVERT_REDIRECT_MAP or "").strip()
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            payload = json.load(f) or {}
    except Exception:
        return None
    entries = payload.get("udp") or {}
    if not isinstance(entries, dict) or not entries:
        return None
    key = f"{str(local_host or '').strip()}:{int(local_port)}"
    item = entries.get(key)
    if isinstance(item, dict):
        return dict(item)
    best = None
    now = time.time()
    for value in entries.values():
        if not isinstance(value, dict):
            continue
        try:
            if int(value.get("local_port") or 0) != int(local_port):
                continue
        except Exception:
            continue
        if float(value.get("expires") or 0.0) < now:
            continue
        if best is None:
            best = value
            continue
        current_closing = bool(best.get("closing"))
        candidate_closing = bool(value.get("closing"))
        if current_closing and not candidate_closing:
            best = value
            continue
        if candidate_closing == current_closing and float(value.get("updated") or 0.0) > float(best.get("updated") or 0.0):
            best = value
    return dict(best or {}) if best else None


class PinnedRouteUnavailable(OSError):
    """Егресс, к которому привязано приложение, не умеет UDP (или не поднят).

    Отдельный класс, а не просто `OSError`: это не сбой, а исполнение выбора
    пользователя, и в лог оно должно попадать по разу в полминуты, а не на
    каждый пакет — во время звонка их десятки в секунду.
    """


class UdpSession:
    # Значения по умолчанию на уровне класса: тесты собирают сессию через object.__new__.
    last_rx_at = None
    tx_since_rx = 0
    ka_sent_at = 0.0
    ka_n = 0
    ka_sum_ms = 0.0
    ka_max_ms = 0.0
    stats_logged_at = 0.0
    failover_reason = ""

    def __init__(
        self,
        owner,
        client_addr: Tuple[str, int],
        target_host: str,
        target_port: int,
        encapsulated: bool = True,
        app_family: str = "",
        preferred_egress: int = 0,
    ):
        self.owner = owner
        self.client_addr = (str(client_addr[0]), int(client_addr[1]))
        self.target_host = str(target_host)
        self.target_port = int(target_port)
        self.encapsulated = bool(encapsulated)
        self.app_family = str(app_family or "").strip().lower()
        self.preferred_egress = int(preferred_egress or 0)
        self.created_at = time.monotonic()
        self.last_activity = self.created_at
        self.closed = False
        self.lock = threading.Lock()
        self.upstream: Optional[UdpEndpoint] = None
        self.upstream_generation = 0
        self.route_label = "unknown"
        self.recv_thread = None
        self.tx_packets = 0
        self.rx_packets = 0
        self.vpn_failover_done = False

        self._open_upstream()
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.recv_thread.start()

    def _attempt_specs(self):
        return self.owner.build_attempts_for_target(
            self.target_host,
            self.target_port,
            app_family=self.app_family,
            preferred_egress=self.preferred_egress,
        )

    def _open_upstream(self):
        attempts = self._attempt_specs()
        if not attempts:
            # Пустой список нельзя отдавать в open_udp_endpoint: там
            # `attempts or get_udp_upstream_attempts()`, то есть пустой список
            # означает «бери всё подряд» — мимо выбранного слота.
            raise PinnedRouteUnavailable(
                f"{self.app_family or 'flow'}: у выбранного слота нет UDP-маршрута"
            )
        self.upstream, self.route_label = open_udp_endpoint(timeout=2.0, attempts=attempts)
        self.upstream_generation += 1
        self.owner.log(
            f"[NovaWFP][UDP] session-open mode={'redirect' if not self.encapsulated else 'envelope'} "
            f"client={self.client_addr[0]}:{self.client_addr[1]} "
            f"target={self.target_host}:{self.target_port} route={self.route_label}"
        )

    def _reopen_direct(self):
        with self.lock:
            if self.closed:
                return False
            try:
                if self.upstream:
                    self.upstream.close()
            except Exception:
                pass
            self.upstream = None
            self.owner.mark_route_bad(self.target_host, self.target_port, self.route_label, ttl=45.0)
            if _pinned_egress_label(self.app_family):
                # Этот запасной путь ходит напрямую мимо любого слота. Для
                # привязанного приложения он и есть та самая утечка, которую
                # просили убрать: «Доп.» не должен на первой ошибке стать
                # «напрямую».
                return False
            attempts = [
                attempt
                for attempt in get_udp_upstream_attempts()
                if str(attempt.get("kind") or "").strip().lower() == "direct"
            ]
            if not attempts:
                return False
            try:
                self.upstream, self.route_label = open_udp_endpoint(timeout=2.0, attempts=attempts)
                self.upstream_generation += 1
            except Exception:
                return False
            self.owner.log(
                f"[NovaWFP][UDP] route-fallback client={self.client_addr[0]}:{self.client_addr[1]} "
                f"target={self.target_host}:{self.target_port} route={self.route_label}"
            )
            return True

    def _direct_is_silent(self) -> bool:
        """Discord «Авто»: прямой путь не отвечает (совсем или после первых пакетов)."""
        if self.vpn_failover_done or self.route_label != "direct":
            return False
        if self.app_family != "discord" or _get_app_route_mode("discord") != "auto":
            return False
        now = time.monotonic()
        if self.rx_packets == 0:
            if self.tx_packets < DISCORD_DIRECT_MIN_TX:
                return False
            if (now - self.created_at) >= DISCORD_DIRECT_SILENT_SEC:
                self.failover_reason = "no-reply"
                return True
            return False
        last_rx = self.last_rx_at if self.last_rx_at is not None else self.created_at
        if self.tx_since_rx >= DISCORD_DIRECT_STALL_MIN_TX and (now - last_rx) >= DISCORD_DIRECT_STALL_SEC:
            self.failover_reason = "stalled"
            return True
        return False

    def _failover_from_silent_direct(self) -> bool:
        with self.lock:
            if self.closed or self.vpn_failover_done:
                return False
            self.vpn_failover_done = True
            try:
                if self.upstream:
                    self.upstream.close()
            except Exception:
                pass
            self.upstream = None
            bad_ttl = DISCORD_DIRECT_STALL_BAD_TTL if self.failover_reason == "stalled" else DISCORD_DIRECT_BAD_TTL
            self.owner.mark_route_bad(self.target_host, self.target_port, "direct", ttl=bad_ttl)
            attempts = [a for a in self._attempt_specs() if str((a or {}).get("kind") or "").strip().lower() != "direct"]
            if not attempts:
                # Нечем заменить: возвращаем прямой путь, чтобы звонок не остался без сокета.
                attempts = [a for a in get_udp_upstream_attempts() if str(a.get("kind") or "").strip().lower() == "direct"]
            try:
                self.upstream, self.route_label = open_udp_endpoint(timeout=2.0, attempts=attempts)
                self.upstream_generation += 1
            except Exception as exc:
                self.owner.log(
                    f"[NovaWFP][UDP] vpn-failover-failed client={self.client_addr[0]}:{self.client_addr[1]} "
                    f"target={self.target_host}:{self.target_port} error={exc}"
                )
                return False
        self.owner.log(
            f"[NovaWFP][UDP] direct-silent client={self.client_addr[0]}:{self.client_addr[1]} "
            f"target={self.target_host}:{self.target_port} reason={self.failover_reason or 'no-reply'} "
            f"tx={self.tx_packets} rx={self.rx_packets} "
            f"-> route={self.route_label}"
        )
        return True

    def send(self, payload: bytes):
        payload = bytes(payload or b"")
        with self.lock:
            if self.closed or self.upstream is None:
                raise OSError("session is closed")
            try:
                self.upstream.sendto(payload, self.target_host, self.target_port)
                self.last_activity = time.monotonic()
                self.tx_packets += 1
                self.tx_since_rx += 1
                if len(payload) == 8:
                    self.ka_sent_at = self.last_activity
                silent = self._direct_is_silent()
            except Exception as exc:
                silent = False
                self.owner.log(
                    f"[NovaWFP][UDP] send-failed client={self.client_addr[0]}:{self.client_addr[1]} "
                    f"target={self.target_host}:{self.target_port} route={self.route_label} error={exc}"
                )
            else:
                if not silent:
                    return
        if silent:
            # Пакет, по которому принято решение, уже ушёл напрямую и пропал; повторим его по новому пути.
            if self._failover_from_silent_direct():
                with self.lock:
                    if self.closed or self.upstream is None:
                        raise OSError("session closed during failover")
                    self.upstream.sendto(payload, self.target_host, self.target_port)
                    self.last_activity = time.monotonic()
                return
            raise OSError("UDP upstream failover failed")
        if self.route_label != "direct" and self._reopen_direct():
            with self.lock:
                if self.closed or self.upstream is None:
                    raise OSError("session closed during fallback")
                self.upstream.sendto(payload, self.target_host, self.target_port)
                self.last_activity = time.monotonic()
                return
        raise OSError("UDP upstream send failed")

    def _recv_loop(self):
        while True:
            with self.lock:
                if self.closed or self.upstream is None:
                    return
                upstream = self.upstream
                generation = self.upstream_generation
            try:
                payload, source = upstream.recvfrom(65535, timeout=1.0)
            except (socket.timeout, TimeoutError):
                if self.owner.should_close_idle(self):
                    self.close(reason="idle-timeout")
                    return
                self._maybe_log_stats()
                continue
            except Exception as exc:
                with self.lock:
                    replaced = self.closed or self.upstream is not upstream or self.upstream_generation != generation
                if replaced:
                    if self.closed:
                        return
                    continue
                self.owner.log(
                    f"[NovaWFP][UDP] recv-failed client={self.client_addr[0]}:{self.client_addr[1]} "
                    f"target={self.target_host}:{self.target_port} route={self.route_label} error={exc}"
                )
                self.close(reason="recv-error")
                return

            self.last_activity = time.monotonic()
            self.last_rx_at = self.last_activity
            self.tx_since_rx = 0
            self.rx_packets += 1
            if len(payload) == 8 and self.ka_sent_at:
                rtt_ms = (self.last_activity - self.ka_sent_at) * 1000.0
                self.ka_sent_at = 0.0
                self.ka_n += 1
                self.ka_sum_ms += rtt_ms
                self.ka_max_ms = max(self.ka_max_ms, rtt_ms)
            self._maybe_log_stats()
            if self.rx_packets == 1 and self.app_family == "discord":
                self.owner.log(
                    f"[NovaWFP][UDP] first-reply client={self.client_addr[0]}:{self.client_addr[1]} "
                    f"target={self.target_host}:{self.target_port} route={self.route_label} "
                    f"after_ms={int((time.monotonic() - self.created_at) * 1000)} tx={self.tx_packets}"
                )
            try:
                if self.encapsulated:
                    packet = encode_envelope(source[0], int(source[1]), payload)
                else:
                    packet = payload
                self.owner.sock.sendto(packet, self.client_addr)
            except Exception as exc:
                self.owner.log(
                    f"[NovaWFP][UDP] deliver-failed client={self.client_addr[0]}:{self.client_addr[1]} "
                    f"source={source[0]}:{source[1]} route={self.route_label} error={exc}"
                )
                self.close(reason="deliver-error")
                return

    def _stats_text(self) -> str:
        now = time.monotonic()
        last_rx = self.last_rx_at if self.last_rx_at is not None else self.created_at
        ka = f"{self.ka_sum_ms / self.ka_n:.0f}/{self.ka_max_ms:.0f}" if self.ka_n else "-"
        return (
            f"route={self.route_label} age_s={now - self.created_at:.0f} tx={self.tx_packets} "
            f"rx={self.rx_packets} rx_age_s={now - last_rx:.1f} echo8_n={self.ka_n} echo8_avg/max_ms={ka}"
        )

    def _maybe_log_stats(self):
        """Discord: раз в несколько секунд — сколько реально отвечает выбранный путь (по нему видно «пилу» пинга)."""
        if self.app_family != "discord" or DISCORD_STATS_EVERY_SEC <= 0:
            return
        now = time.monotonic()
        if (now - self.stats_logged_at) < DISCORD_STATS_EVERY_SEC:
            return
        self.stats_logged_at = now
        self.owner.log(
            f"[NovaWFP][UDP] voice-stats client={self.client_addr[0]}:{self.client_addr[1]} "
            f"target={self.target_host}:{self.target_port} {self._stats_text()}"
        )

    def close(self, reason: str = "closed"):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            upstream = self.upstream
            self.upstream = None
        try:
            if upstream:
                upstream.close()
        except Exception:
            pass
        self.owner.drop_session(self.client_addr, self.target_host, self.target_port, self.encapsulated)
        lifetime_ms = int((time.monotonic() - self.created_at) * 1000)
        self.owner.log(
            f"[NovaWFP][UDP] session-close mode={'redirect' if not self.encapsulated else 'envelope'} "
            f"client={self.client_addr[0]}:{self.client_addr[1]} "
            f"target={self.target_host}:{self.target_port} route={self.route_label} "
            f"reason={reason} duration_ms={lifetime_ms} tx={self.tx_packets} rx={self.rx_packets}"
            + (f" echo8_n={self.ka_n}" if self.app_family == "discord" else "")
        )


class NovaWfpUdpProxy:
    def __init__(self, host: str = "127.0.0.1", port: int = 17871):
        self.host = str(host or "127.0.0.1")
        self.port = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(1.0)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._sessions: Dict[Tuple[str, int, str, int, int], UdpSession] = {}
        self._redirect_sessions: Dict[Tuple[str, int], UdpSession] = {}
        self._bad_routes: Dict[Tuple[str, int, str], float] = {}
        self._webview_host_family_cache: Dict[int, Tuple[str, float]] = {}

    def log(self, line: str):
        LOG.info(line)

    @staticmethod
    def _app_family_from_app_id(app_id: str) -> str:
        lower = str(app_id or "").replace("/", "\\").lower()
        process_name = lower.rsplit("\\", 1)[-1]
        if process_name.startswith("dns-ai") and process_name.endswith(".exe"):
            return "dns_ai"
        if any(token in lower for token in ("telegram.exe", "ayugram.exe", "novagram.exe", "telegram desktop")):
            return "telegram"
        if any(token in lower for token in ("discord.exe", "discordcanary.exe", "discordptb.exe", "discord\\update.exe", "discordcanary\\update.exe", "discordptb\\update.exe")):
            return "discord"
        if "whatsapp.exe" in lower or "whatsapp.root.exe" in lower or "whatsapp\\app.exe" in lower:
            return "whatsapp"
        if any(token in lower for token in ("obs64.exe", "obs32.exe", "obs-studio")):
            return "obs"
        if "pathofexile" in lower or "path of exile" in lower or " poe" in lower or lower.endswith("\\poe") or "client.exe" in lower:
            return "games"
        return ""

    def _resolve_webview_host_family(self, process_id: int) -> str:
        try:
            pid = int(process_id or 0)
        except Exception:
            pid = 0
        if pid <= 0:
            return ""
        now = time.monotonic()
        cached = self._webview_host_family_cache.get(pid)
        if cached and (now - float(cached[1] or 0.0) <= 15.0):
            return str(cached[0] or "")
        family = ""
        try:
            snapshot = _snapshot_process_parents()
            current_pid = pid
            visited = set()
            for _ in range(8):
                if current_pid <= 0 or current_pid in visited:
                    break
                visited.add(current_pid)
                parent_pid, exe_name = snapshot.get(current_pid, (0, ""))
                lower_name = str(exe_name or "").strip().lower()
                if lower_name in {"whatsapp.exe", "whatsapp.root.exe"}:
                    family = "whatsapp"
                    break
                current_pid = int(parent_pid or 0)
        except Exception:
            family = ""
        self._webview_host_family_cache[pid] = (family, now)
        return family

    def _classify_redirect_flow(self, resolved: dict) -> Tuple[str, int]:
        app_id = str(resolved.get("app_id") or "")
        process_id = int(resolved.get("process_id") or 0)
        preferred_egress = int(resolved.get("preferred_egress") or 0)
        app_family = self._app_family_from_app_id(app_id)
        if (not app_family) and ("msedgewebview2.exe" in app_id.replace("/", "\\").lower()):
            app_family = self._resolve_webview_host_family(process_id)
            if app_family == "whatsapp":
                preferred_egress = 1
            else:
                app_family = "webview2"
                preferred_egress = 3
        return app_family, preferred_egress

    def build_attempts_for_target(self, host: str, port: int, app_family: str = "", preferred_egress: int = 0):
        now = time.monotonic()
        upstream_attempts = [dict(attempt) for attempt in get_udp_upstream_attempts() if isinstance(attempt, dict)]
        dns_state = dns_ai_route_state()
        if (str(app_family).lower() == "dns_ai" and dns_state) or is_dns_ai_endpoint(host, port):
            labels = dns_ai_route_labels(True, True, dns_state)
            # Same order as TCP (direct first, D48). The secondary's HTTP CONNECT cannot carry
            # UDP, so it simply has no attempt here; when it is the only fallback the client
            # retries encrypted DNS over TCP, which can reach it.
            by_label = {a.get("label"): a for a in upstream_attempts}
            return [by_label[label] for label in labels if label in by_label]
        if not upstream_attempts:
            upstream_attempts = []
        direct_attempts = [
            attempt for attempt in upstream_attempts
            if str(attempt.get("kind") or "").strip().lower() == "direct"
        ]
        proxy_attempts = [attempt for attempt in upstream_attempts if attempt not in direct_attempts]
        app_family = str(app_family or "").strip().lower()

        if app_family == "webview2" or int(preferred_egress or 0) == 3:
            ordered_attempts = direct_attempts + proxy_attempts
        elif app_family == "discord" and _get_app_route_mode("discord") == "auto":
            # Голос Discord: напрямую (winws), VPN — только если прямой молчит (UdpSession).
            ordered_attempts = direct_attempts + proxy_attempts
        else:
            ordered_attempts = proxy_attempts + direct_attempts

        if app_family == "ai_apps" and _vpn_slots is not None and _get_app_route_mode("ai_apps") == "auto":
            ai_labels = _ai_apps_udp_labels()
            return [
                dict(attempt) for attempt in ordered_attempts
                if str((attempt or {}).get("label") or (attempt or {}).get("kind") or "").strip().lower() in ai_labels
            ]

        pin = _pinned_egress_label(app_family)
        if pin:
            # Привязка, а не предпочтение: соседний егресс не берётся вовсе.
            # UDP умеет только SOCKS5 и direct, а «Доп.» — это HTTP CONNECT
            # (Opera/Tor/свой профиль), через который UDP не ходит. Пустой
            # список здесь и означает «маршрута нет»; звонок уйдёт на
            # TCP-рефлекторы Telegram, но не мимо выбранного слота.
            return [
                dict(attempt) for attempt in ordered_attempts
                if str((attempt or {}).get("label") or (attempt or {}).get("kind") or "").strip().lower() == pin
            ]

        route_mode = _get_app_route_mode(app_family) if app_family in {"discord", "telegram", "whatsapp", "obs"} else "auto"
        if route_mode != "auto":
            priority_map = {
                "warp": {"warp-socks": 0, "opera-http": 1, "direct": 2},
                "opera": {"opera-http": 0, "warp-socks": 1, "direct": 2},
                "direct": {"direct": 0, "warp-socks": 1, "opera-http": 2},
            }.get(route_mode, {})
            ordered_attempts = sorted(
                ordered_attempts,
                key=lambda attempt: priority_map.get(
                    str((attempt or {}).get("label") or (attempt or {}).get("kind") or "").strip().lower(),
                    99,
                ),
            )

        attempts = []
        for attempt in ordered_attempts:
            if not isinstance(attempt, dict):
                continue
            label = str(attempt.get("label") or attempt.get("kind") or "unknown").strip() or "unknown"
            expiry = self._bad_routes.get((str(host), int(port), label), 0.0)
            if expiry > now:
                continue
            attempts.append(dict(attempt))
        if attempts:
            return attempts
        return ordered_attempts or upstream_attempts

    def mark_route_bad(self, host: str, port: int, label: str, ttl: float = 45.0):
        if not label:
            return
        self._bad_routes[(str(host), int(port), str(label))] = time.monotonic() + max(5.0, float(ttl))

    def should_close_idle(self, session: UdpSession) -> bool:
        return (time.monotonic() - float(session.last_activity)) >= SESSION_IDLE_TIMEOUT

    def _session_key(self, client_addr: Tuple[str, int], host: str, port: int, encapsulated: bool = True):
        return (str(client_addr[0]), int(client_addr[1]), str(host), int(port), 1 if encapsulated else 0)

    def get_session(
        self,
        client_addr: Tuple[str, int],
        host: str,
        port: int,
        encapsulated: bool = True,
        app_family: str = "",
        preferred_egress: int = 0,
    ) -> UdpSession:
        key = self._session_key(client_addr, host, port, encapsulated)
        with self._lock:
            session = self._sessions.get(key)
            if session and not session.closed:
                return session
            session = UdpSession(
                self,
                client_addr,
                host,
                port,
                encapsulated=encapsulated,
                app_family=app_family,
                preferred_egress=preferred_egress,
            )
            self._sessions[key] = session
            if not encapsulated:
                self._redirect_sessions[(str(client_addr[0]), int(client_addr[1]))] = session
            return session

    def drop_session(self, client_addr: Tuple[str, int], host: str, port: int, encapsulated: bool = True):
        key = self._session_key(client_addr, host, port, encapsulated)
        with self._lock:
            existing = self._sessions.get(key)
            if existing and existing.closed:
                self._sessions.pop(key, None)
            if not encapsulated:
                self._redirect_sessions.pop((str(client_addr[0]), int(client_addr[1])), None)

    def resolve_redirect_target(self, client_addr: Tuple[str, int]) -> Optional[dict]:
        if DIVERT_REDIRECT_MAP:
            resolved = _resolve_divert_udp_flow(str(client_addr[0]), int(client_addr[1]))
        else:
            resolved = resolve_udp_flow(str(client_addr[0]), int(client_addr[1]))
        if not resolved:
            return None
        if DIVERT_REDIRECT_MAP:
            self.log(
                f"[NovaWFP][UDP] redirect-resolve-map client={client_addr[0]}:{client_addr[1]} "
                f"local={resolved.get('local_host')}:{resolved.get('local_port')} "
                f"target={_mask_ip_for_log(resolved.get('target_host'))}:{resolved.get('target_port')} "
                f"egress={resolved.get('preferred_egress')} app={redact_user_path(resolved.get('app_id') or resolved.get('app_family') or '-')}"
            )
        else:
            self.log(
                f"[NovaWFP][UDP] redirect-resolve client={client_addr[0]}:{client_addr[1]} "
                f"local={resolved['local_host']}:{resolved['local_port']} "
                f"target={_mask_ip_for_log(resolved['target_host'])}:{resolved['target_port']} "
                f"egress={resolved['preferred_egress']} app={redact_user_path(resolved['app_id'])}"
            )
        return resolved

    def get_redirect_session(self, client_addr: Tuple[str, int]) -> UdpSession:
        redirect_key = (str(client_addr[0]), int(client_addr[1]))
        with self._lock:
            session = self._redirect_sessions.get(redirect_key)
            if session and not session.closed:
                return session
        resolved = self.resolve_redirect_target(client_addr)
        if not resolved:
            raise OSError("NovaWFP did not resolve redirected UDP target")
        app_family, preferred_egress = self._classify_redirect_flow(resolved)
        return self.get_session(
            client_addr,
            str(resolved["target_host"]),
            int(resolved["target_port"]),
            encapsulated=False,
            app_family=app_family,
            preferred_egress=preferred_egress,
        )

    def _log_pin_block(self, client_addr: Tuple[str, int], exc: BaseException) -> None:
        now = time.monotonic()
        if now < float(getattr(self, "_pin_block_log_until", 0.0) or 0.0):
            return
        self._pin_block_log_until = now + 30.0
        self.log(
            f"[NovaWFP][UDP] pin-block client={client_addr[0]}:{client_addr[1]} error={exc} "
            f"— трафик привязан к слоту VPN, обходной маршрут не берём"
        )

    def _cleanup_bad_routes(self):
        now = time.monotonic()
        expired = [key for key, expiry in self._bad_routes.items() if expiry <= now]
        for key in expired:
            self._bad_routes.pop(key, None)

    def _cleanup_idle_sessions(self):
        with self._lock:
            sessions = list(self._sessions.values())
        for session in sessions:
            if session.closed:
                continue
            if self.should_close_idle(session):
                session.close(reason="idle-timeout")

    def run(self):
        self.log(f"[NovaWFP][UDP] listening on {self.host}:{self.port}")
        while not self._stop.is_set():
            try:
                packet, client_addr = self.sock.recvfrom(65535)
            except socket.timeout:
                self._cleanup_bad_routes()
                self._cleanup_idle_sessions()
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                self.log(f"[NovaWFP][UDP] server-recv-failed error={exc}")
                continue

            try:
                if len(packet) >= 4 and packet[:4] == ENVELOPE_MAGIC:
                    target_host, target_port, payload = decode_envelope(packet)
                    session = self.get_session(client_addr, target_host, target_port, encapsulated=True)
                    session.send(payload)
                    self.log(
                        f"[NovaWFP][UDP] tx client={client_addr[0]}:{client_addr[1]} "
                        f"target={_mask_ip_for_log(target_host)}:{target_port} route={session.route_label} size={len(payload)}"
                    )
                else:
                    session = self.get_redirect_session(client_addr)
                    session.send(packet)
                    self.log(
                        f"[NovaWFP][UDP] redirect-tx client={client_addr[0]}:{client_addr[1]} "
                        f"target={_mask_ip_for_log(session.target_host)}:{session.target_port} "
                        f"route={session.route_label} size={len(packet)}"
                    )
            except PinnedRouteUnavailable as exc:
                self._log_pin_block(client_addr, exc)
            except Exception as exc:
                self.log(
                    f"[NovaWFP][UDP] tx-failed client={client_addr[0]}:{client_addr[1]} "
                    f"error={exc}"
                )

        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close(reason="shutdown")

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass


def _default_log_file() -> Path:
    return _data_path("temp", "NovaWfpUdpProxy.log")


def _configure_file_logging(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.FileHandler(path, mode="w", encoding="utf-8")],
    )
    return path


def _parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--host", default=os.environ.get("NOVA_WFP_UDP_PROXY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("NOVA_WFP_UDP_PROXY_PORT", "17871")))
    parser.add_argument("--log", default=os.environ.get("NOVA_WFP_UDP_PROXY_LOG") or str(_default_log_file()))
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    log_path = _configure_file_logging(Path(args.log))
    LOG.info("[NovaWFP][UDP] starting")
    LOG.info(f"[NovaWFP][UDP] log={log_path}")
    LOG.info(f"[NovaWFP][UDP] bind={args.host}:{args.port}")
    proxy = NovaWfpUdpProxy(host=str(args.host), port=int(args.port))
    try:
        proxy.run()
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        proxy.stop()


if __name__ == "__main__":
    raise SystemExit(main())
