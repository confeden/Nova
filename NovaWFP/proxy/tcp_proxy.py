import asyncio
import argparse
import contextlib
import ctypes
import ipaddress
import json
import logging
import os
import socket
import sys
import time
from collections import deque
from ctypes import wintypes
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tgrelay.transport import open_stream  # noqa: E402
try:
    from tgrelay.config import CFPROXY_DEFAULT_DOMAINS, get_cfproxy_domains, get_cfproxy_primary_domains  # noqa: E402
    from tgrelay.transparent_relay import (  # noqa: E402
        TransparentMsgSplitter,
        _connect_websocket_target,
        _likely_media_target,
        _proto_label,
        _resolve_ip,
        _target_dc_hint,
        _ws_domains,
        parse_transparent_init_info,
    )
    from tgrelay.raw_websocket import WsHandshakeError  # noqa: E402
except Exception:  # pragma: no cover - keeps TCP fallback alive if relay deps are absent.
    CFPROXY_DEFAULT_DOMAINS = []
    get_cfproxy_domains = None
    get_cfproxy_primary_domains = None
    TransparentMsgSplitter = None
    WsHandshakeError = Exception
    _connect_websocket_target = None
    _likely_media_target = None
    _proto_label = None
    _resolve_ip = None
    _target_dc_hint = None
    _ws_domains = None
    parse_transparent_init_info = None


LOG = logging.getLogger("nova.wfp.tcp_proxy")

SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS = 0x980000DC
SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT = 0x980000DD
SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS = 0x980000DE

AF_INET = 2
AF_INET6 = 23
IPPROTO_TCP = 6
FWP_IP_VERSION_V4 = 0
FWP_IP_VERSION_V6 = 1

NOVA_WFP_REDIRECT_CONTEXT_MAGIC = 0x4650574E
NOVA_WFP_MAX_IMAGE_PATH = 520

TELEGRAM_TCP_PORTS = {80, 443, 5222, *range(7300, 7311)}


def _env_int(name: str, default: int, minimum: int = 0, maximum: int = 16) -> int:
    try:
        value = int(str(os.environ.get(name, str(default))).strip())
    except Exception:
        value = int(default)
    return max(int(minimum), min(int(maximum), value))


def _env_float(name: str, default: float, minimum: float = 0.05, maximum: float = 30.0) -> float:
    try:
        value = float(str(os.environ.get(name, str(default))).strip())
    except Exception:
        value = float(default)
    return max(float(minimum), min(float(maximum), value))


TG_WS_BRIDGE_MEDIA_ONLY = os.environ.get("NOVA_TG_WS_MEDIA_ONLY", "1").strip().lower() not in {"0", "false", "no"}
TG_WS_BRIDGE_ENABLED = os.environ.get("NOVA_TG_WS_BRIDGE", "1").strip().lower() not in {"0", "false", "no"}
TG_WS_CF_FALLBACK_ENABLED = os.environ.get("NOVA_TG_WS_CF_FALLBACK", "1").strip().lower() not in {"0", "false", "no"}
TG_WS_VERBOSE_FAILURES = os.environ.get("NOVA_TG_WS_VERBOSE_FAILURES", "0").strip().lower() not in {"0", "false", "no"}
TG_WS_STARTUP_PREWARM = os.environ.get("NOVA_TG_WS_STARTUP_PREWARM", "1").strip().lower() not in {"0", "false", "no"}
TG_WS_POOL_SIZE = _env_int("NOVA_TG_WS_POOL_SIZE", 2, minimum=0, maximum=6)
TG_WS_POOL_MAX_AGE = _env_float("NOVA_TG_WS_POOL_MAX_AGE", 45.0, minimum=5.0, maximum=180.0)
TG_INITIAL_PROBE_TIMEOUT = _env_float("NOVA_TG_INITIAL_PROBE_TIMEOUT", 0.35, minimum=0.1, maximum=2.0)
TG_WS_MEDIA_FAST_CLOSE_MS = _env_int("NOVA_TG_WS_MEDIA_FAST_CLOSE_MS", 1500, minimum=250, maximum=10000)
TG_WS_MEDIA_FAST_CLOSE_BYTES = _env_int("NOVA_TG_WS_MEDIA_FAST_CLOSE_BYTES", 4096, minimum=512, maximum=65536)
TG_WS_MEDIA_PASSTHROUGH_TTL = _env_float("NOVA_TG_WS_MEDIA_PASSTHROUGH_TTL", 90.0, minimum=10.0, maximum=600.0)
TG_WS_REDIRECT_IPS = {
    1: "149.154.175.50",
    2: "149.154.167.220",
    3: "149.154.175.100",
    4: "149.154.167.220",
    5: "149.154.171.5",
    203: "91.105.192.100",
}
TG_TCP_FALLBACK_IPS = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "149.154.171.5",
    203: "91.105.192.100",
}
TG_WS_CF_FIRST_DCS = {1, 5}
TG_WS_CF_FIRST_MEDIA_DCS = {
    int(item)
    for item in str(os.environ.get("NOVA_TG_WS_CF_FIRST_MEDIA_DCS", "5") or "")
    .replace(";", ",")
    .split(",")
    if item.strip().isdigit()
}
TG_WS_CALL_SAFE_MEDIA_DCS = {
    int(item)
    for item in str(os.environ.get("NOVA_TG_WS_CALL_SAFE_MEDIA_DCS", "2,4,5") or "")
    .replace(";", ",")
    .split(",")
    if item.strip().isdigit()
}
TG_WS_STARTUP_PREWARM_PLAN = (
    (5, False),
    (1, False),
    (2, False),
    (4, False),
    (5, True),
    (2, True),
    (4, True),
)


class NOVA_WFP_SOCKET_ADDRESS_V1(ctypes.Structure):
    _fields_ = [
        ("ScopeId", wintypes.ULONG),
        ("Port", wintypes.USHORT),
        ("Address", ctypes.c_ubyte * 16),
    ]


class NOVA_WFP_REDIRECT_CONTEXT_V1(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.ULONG),
        ("Version", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("IpVersion", wintypes.ULONG),
        ("Protocol", wintypes.ULONG),
        ("PreferredEgress", wintypes.ULONG),
        ("TargetFlags", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
        ("OriginalDestination", NOVA_WFP_SOCKET_ADDRESS_V1),
        ("AppId", wintypes.WCHAR * NOVA_WFP_MAX_IMAGE_PATH),
    ]


class WinsockError(OSError):
    pass


_WSA_IO_PENDING = 997
_WSA = ctypes.windll.Ws2_32
_WSA.WSAGetLastError.restype = ctypes.c_int
_KERNEL32 = ctypes.windll.kernel32

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
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
_KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
_KERNEL32.CloseHandle.restype = wintypes.BOOL


def _wsa_last_error() -> int:
    return int(_WSA.WSAGetLastError())


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
        with contextlib.suppress(Exception):
            _KERNEL32.CloseHandle(handle)
    return snapshot


def _socket_handle(sock: socket.socket) -> wintypes.HANDLE:
    return wintypes.HANDLE(sock.fileno())


def _wsa_ioctl_out(sock: socket.socket, control_code: int, max_size: int = 8192) -> bytes:
    out_buffer = ctypes.create_string_buffer(max_size)
    bytes_returned = wintypes.DWORD(0)
    result = _WSA.WSAIoctl(
        _socket_handle(sock),
        wintypes.DWORD(control_code),
        None,
        0,
        out_buffer,
        max_size,
        ctypes.byref(bytes_returned),
        None,
        None,
    )
    if result != 0:
        raise WinsockError(_wsa_last_error(), f"WSAIoctl({control_code:#x}) failed")
    return out_buffer.raw[: bytes_returned.value]


def _wsa_ioctl_set(sock: socket.socket, control_code: int, payload: bytes) -> None:
    in_buffer = ctypes.create_string_buffer(payload)
    bytes_returned = wintypes.DWORD(0)
    result = _WSA.WSAIoctl(
        _socket_handle(sock),
        wintypes.DWORD(control_code),
        in_buffer,
        len(payload),
        None,
        0,
        ctypes.byref(bytes_returned),
        None,
        None,
    )
    if result != 0:
        raise WinsockError(_wsa_last_error(), f"WSAIoctl({control_code:#x}) failed")


def query_redirect_records(sock: socket.socket) -> bytes:
    return _wsa_ioctl_out(sock, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, 8192)


def query_redirect_context(sock: socket.socket) -> bytes:
    return _wsa_ioctl_out(sock, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, 4096)


def set_redirect_records(sock: socket.socket, redirect_records: bytes) -> None:
    if redirect_records:
        _wsa_ioctl_set(sock, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, redirect_records)


def _format_socket_address(address: NOVA_WFP_SOCKET_ADDRESS_V1, ip_version: int) -> Tuple[str, int]:
    port = int(address.Port)
    if ip_version in {FWP_IP_VERSION_V4, 4, AF_INET}:
        packed = bytes(address.Address[:4])
        return socket.inet_ntop(AF_INET, packed), port
    if ip_version in {FWP_IP_VERSION_V6, 6, AF_INET6}:
        packed = bytes(address.Address[:16])
        return socket.inet_ntop(AF_INET6, packed), port
    raise ValueError(f"unsupported ip version: {ip_version}")


def parse_redirect_context(payload: bytes) -> Optional[NOVA_WFP_REDIRECT_CONTEXT_V1]:
    if not payload or len(payload) < ctypes.sizeof(NOVA_WFP_REDIRECT_CONTEXT_V1):
        return None
    ctx = NOVA_WFP_REDIRECT_CONTEXT_V1.from_buffer_copy(payload[: ctypes.sizeof(NOVA_WFP_REDIRECT_CONTEXT_V1)])
    if int(ctx.Magic) != NOVA_WFP_REDIRECT_CONTEXT_MAGIC:
        return None
    return ctx


async def _bridge_streams(reader1, writer1, reader2, writer2, initial_up: int = 0, initial_down: int = 0):
    counters = {"client_to_upstream": int(initial_up), "upstream_to_client": int(initial_down)}
    started = time.monotonic()

    async def _pipe(src, dst, counter_key: str):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                counters[counter_key] += len(data)
                dst.write(data)
                await dst.drain()
        finally:
            with contextlib.suppress(Exception):
                dst.close()

    tasks = [
        asyncio.create_task(_pipe(reader1, writer2, "client_to_upstream")),
        asyncio.create_task(_pipe(reader2, writer1, "upstream_to_client")),
    ]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
        with contextlib.suppress(Exception):
            await task
    for task in done:
        with contextlib.suppress(Exception):
            await task
    elapsed_ms = int((time.monotonic() - started) * 1000)
    return counters["client_to_upstream"], counters["upstream_to_client"], elapsed_ms


class NovaWfpTcpProxy:
    def __init__(self, host: str = "0.0.0.0", port: int = 17870, log_func=None):
        self.host = host
        self.port = int(port)
        self.server = None
        self.stop_event = asyncio.Event()
        self.log_func = log_func or (lambda message: LOG.info(message))
        self._route_cache = {}
        self._route_cache_ttl = 300.0
        self._bad_route_cache = {}
        self._bad_route_cache_ttl = 90.0
        self._webview_host_family_cache = {}
        self._tg_ws_bad_until = {}
        self._tg_ws_media_passthrough_until = {}
        self._tg_ws_media_fail_streak = {}
        self._tg_ws_pool: Dict[Tuple[int, bool], Deque[Tuple[object, float, str]]] = {}
        self._tg_ws_refilling = set()
        self._warp_socks_probe_until = 0.0
        self._warp_socks_probe_ok = False
        self._discord_networks = self._load_networks("discord*.txt")
        self._telegram_networks = self._load_networks("telegram*.txt")
        self._whatsapp_networks = self._load_networks("whatsapp*.txt")
        self.log_func(
            f"[NovaWFP][Proxy] discord-networks={len(self._discord_networks)} "
            f"telegram-networks={len(self._telegram_networks)} whatsapp-networks={len(self._whatsapp_networks)}"
        )
        if TG_WS_BRIDGE_ENABLED and TG_WS_POOL_SIZE > 0:
            self.log_func(
                f"[NovaWFP][TGWS] warm-pool enabled size={TG_WS_POOL_SIZE} max_age={int(TG_WS_POOL_MAX_AGE)}s"
            )

    @staticmethod
    def _app_family_from_app_id(app_id: str) -> str:
        lower = str(app_id or "").replace("/", "\\").lower()
        if any(token in lower for token in ("telegram.exe", "ayugram.exe", "telegram desktop")):
            return "telegram"
        if any(token in lower for token in ("discord.exe", "discordcanary.exe", "discordptb.exe", "discord\\update.exe", "discordcanary\\update.exe", "discordptb\\update.exe")):
            return "discord"
        if (
            "whatsapp.exe" in lower
            or "whatsapp.root.exe" in lower
            or "whatsapp\\app.exe" in lower
        ):
            return "whatsapp"
        if any(token in lower for token in ("opencode.exe", "opencode-cli.exe", "\\opencode\\")):
            return "opencode"
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
                if lower_name in {"opencode.exe", "opencode-cli.exe"}:
                    family = "opencode"
                    break
                if lower_name in {"whatsapp.exe", "whatsapp.root.exe"}:
                    family = "whatsapp"
                    break
                current_pid = int(parent_pid or 0)
        except Exception:
            family = ""
        self._webview_host_family_cache[pid] = (family, now)
        return family

    def _load_networks(self, pattern: str):
        nets = []
        try:
            ip_dir = REPO_ROOT / "ip"
            for path in sorted(ip_dir.glob(str(pattern))):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for raw_line in f:
                        line = raw_line.split("#", 1)[0].strip()
                        if not line:
                            continue
                        try:
                            nets.append(ipaddress.ip_network(line, strict=False))
                        except Exception:
                            continue
        except Exception:
            return []
        return nets

    def _is_telegram_target(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(str(host).strip())
        except Exception:
            return False
        for net in self._telegram_networks:
            try:
                if addr in net:
                    return True
            except Exception:
                continue
        return False

    def _is_discord_target(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(str(host).strip())
        except Exception:
            return False
        for net in self._discord_networks:
            try:
                if addr in net:
                    return True
            except Exception:
                continue
        return False

    def _is_whatsapp_target(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(str(host).strip())
        except Exception:
            return False
        for net in self._whatsapp_networks:
            try:
                if addr in net:
                    return True
            except Exception:
                continue
        return False

    @staticmethod
    def _route_scope_value(route_scope: str) -> str:
        value = str(route_scope or "").strip().lower()
        return value or "-"

    @staticmethod
    def _route_scope_family(route_scope: str) -> str:
        value = str(route_scope or "").strip().lower()
        if not value:
            return ""
        return value.split("|", 1)[0]

    def _route_label_cache_get(self, target_host: str, target_port: int, route_scope: str = "") -> Optional[str]:
        key = f"{self._route_scope_value(route_scope)}|{str(target_host).strip()}:{int(target_port)}"
        now = time.monotonic()
        entry = self._route_cache.get(key)
        if not entry:
            return None
        label, expires_at = entry
        if now >= float(expires_at):
            self._route_cache.pop(key, None)
            return None
        label = str(label or "").strip()
        if self._route_label_is_bad(target_host, target_port, label, route_scope=route_scope):
            self._route_cache.pop(key, None)
            return None
        return label or None

    def _route_label_cache_put(self, target_host: str, target_port: int, label: str, route_scope: str = "") -> None:
        try:
            key = f"{self._route_scope_value(route_scope)}|{str(target_host).strip()}:{int(target_port)}"
            self._route_cache[key] = (str(label or "").strip(), time.monotonic() + self._route_cache_ttl)
        except Exception:
            return

    def _route_label_cache_pop(self, target_host: str, target_port: int, route_scope: str = "") -> None:
        try:
            key = f"{self._route_scope_value(route_scope)}|{str(target_host).strip()}:{int(target_port)}"
            self._route_cache.pop(key, None)
        except Exception:
            return

    def _bad_route_key(self, target_host: str, target_port: int, label: str, route_scope: str = "") -> str:
        return (
            f"{self._route_scope_value(route_scope)}|{str(target_host).strip()}:{int(target_port)}|"
            f"{str(label or '').strip()}"
        )

    def _route_label_is_bad(self, target_host: str, target_port: int, label: str, route_scope: str = "") -> bool:
        label = str(label or "").strip()
        if not label:
            return False
        keys = [
            self._bad_route_key(target_host, target_port, label, route_scope=route_scope),
            self._bad_route_key(target_host, 0, label, route_scope=route_scope),
        ]
        expires_at = None
        active_key = None
        for key in keys:
            expires_at = self._bad_route_cache.get(key)
            if expires_at:
                active_key = key
                break
        if not expires_at:
            return False
        if time.monotonic() >= float(expires_at):
            if active_key:
                self._bad_route_cache.pop(active_key, None)
            return False
        return True

    def _bad_route_cache_put(
        self,
        target_host: str,
        target_port: int,
        label: str,
        route_scope: str = "",
        ttl: Optional[float] = None,
        all_ports: bool = False,
    ) -> None:
        label = str(label or "").strip()
        if not label:
            return
        try:
            cache_port = 0 if all_ports else int(target_port)
            self._bad_route_cache[self._bad_route_key(target_host, cache_port, label, route_scope=route_scope)] = (
                time.monotonic() + float(ttl or self._bad_route_cache_ttl)
            )
            self._route_label_cache_pop(target_host, target_port, route_scope=route_scope)
        except Exception:
            return

    @staticmethod
    def _attempt_by_label(label: str) -> Optional[dict]:
        mapping = {
            "warp-socks": {
                "kind": "socks5",
                "host": "127.0.0.1",
                "port": 1370,
                "label": "warp-socks",
                "timeout": 2.5,
                "first_byte_timeout": 1.4,
            },
            "opera-http": {
                "kind": "http",
                "host": "127.0.0.1",
                "port": 1371,
                "label": "opera-http",
                "timeout": 3.0,
                "first_byte_timeout": 2.4,
            },
            "direct": {"kind": "direct", "label": "direct", "timeout": 1.2, "first_byte_timeout": 1.4},
        }
        return dict(mapping[label]) if label in mapping else None

    @staticmethod
    def _effective_first_byte_timeout(attempt: dict, telegram_media: bool = False) -> float:
        try:
            base_timeout = max(0.2, float(attempt.get("first_byte_timeout") or 1.5))
        except Exception:
            base_timeout = 1.5
        if not telegram_media:
            return base_timeout
        label = str(attempt.get("label") or attempt.get("kind") or "").strip().lower()
        if label == "warp-socks":
            return max(base_timeout, 4.2)
        if label == "opera-http":
            return max(base_timeout, 3.4)
        if label == "direct":
            return max(base_timeout, 3.0)
        return max(base_timeout, 3.0)

    @staticmethod
    def _route_transport_label(route_label: str) -> str:
        route_label = str(route_label or "").strip().lower()
        if "via warp-socks" in route_label:
            return "warp-socks"
        if "via opera-http" in route_label:
            return "opera-http"
        if "via direct" in route_label:
            return "direct"
        return ""

    def _warp_socks_available(self) -> bool:
        now = time.monotonic()
        if now < float(self._warp_socks_probe_until or 0.0):
            return bool(self._warp_socks_probe_ok)
        ok = False
        sock = None
        try:
            sock = socket.socket(AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.18)
            ok = int(sock.connect_ex(("127.0.0.1", 1370))) == 0
        except Exception:
            ok = False
        finally:
            with contextlib.suppress(Exception):
                if sock is not None:
                    sock.close()
        self._warp_socks_probe_ok = bool(ok)
        self._warp_socks_probe_until = now + (2.0 if ok else 0.7)
        return bool(ok)

    def _tg_ws_should_keep_pooled(self, route_label: str) -> bool:
        transport = self._route_transport_label(route_label)
        if not transport or transport == "warp-socks":
            return True
        return not self._warp_socks_available()

    def _build_attempts_for_target(
        self,
        target_host: str,
        target_port: int,
        preferred_egress: int,
        telegram_media: bool = False,
        app_family: str = "",
        route_scope: str = "",
    ) -> List[dict]:
        app_family = str(app_family or "").strip().lower()
        is_discord_target = self._is_discord_target(target_host) or app_family == "discord"
        is_telegram_target = self._is_telegram_target(target_host)
        is_telegram_app = app_family == "telegram"
        is_whatsapp_target = self._is_whatsapp_target(target_host) or app_family == "whatsapp"
        if is_discord_target:
            if preferred_egress == 2:
                attempts = ["opera-http", "warp-socks", "direct"]
            elif preferred_egress == 3:
                attempts = ["direct", "warp-socks", "opera-http"]
            else:
                attempts = ["warp-socks", "opera-http", "direct"]
        elif is_telegram_target:
            # Keep Telegram on WARP by default and avoid early direct fallback:
            # direct path is frequently shaped and can break MTProto key exchange.
            attempts = ["warp-socks", "opera-http", "direct"]
            if self._warp_socks_available():
                attempts = ["warp-socks", "opera-http"]
        elif is_telegram_app:
            # Telegram app also talks to non-Telegram endpoints during calls/bootstrap.
            # Do not force strict MTProto DC routing rules onto those hosts.
            # Media/helpers on non-standard ports behave differently from small
            # bootstrap helpers on 443: they often stall badly via Opera/direct
            # and then work immediately via WARP. Keep those on WARP-first.
            if int(target_port or 0) not in (80, 443, 5222, 5228):
                attempts = ["warp-socks", "direct", "opera-http"]
            else:
                attempts = ["opera-http", "direct", "warp-socks"]
        elif is_whatsapp_target:
            if preferred_egress == 2:
                attempts = ["opera-http", "warp-socks", "direct"]
            elif preferred_egress == 3:
                attempts = ["direct", "warp-socks", "opera-http"]
            else:
                # WhatsApp direct frequently stalls on shaped networks. Keep it
                # as the final emergency path, not the first fallback after WARP.
                attempts = ["warp-socks", "opera-http", "direct"]
        else:
            if preferred_egress == 2:
                attempts = ["opera-http", "direct", "warp-socks"]
            else:
                attempts = ["direct", "warp-socks", "opera-http"]

        cached_label = self._route_label_cache_get(target_host, target_port, route_scope=route_scope)
        if cached_label in attempts:
            attempts = [cached_label] + [item for item in attempts if item != cached_label]

        filtered_attempts = [
            label for label in attempts
            if not self._route_label_is_bad(target_host, target_port, label, route_scope=route_scope)
        ]
        if filtered_attempts:
            attempts = filtered_attempts

        rendered = []
        for label in attempts:
            attempt = self._attempt_by_label(label)
            if attempt:
                if is_discord_target:
                    if label == "warp-socks":
                        attempt["timeout"] = min(float(attempt.get("timeout") or 2.5), 0.75)
                        attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 1.4), 0.9)
                    elif label == "opera-http":
                        attempt["timeout"] = min(float(attempt.get("timeout") or 3.0), 1.8)
                        attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 2.4), 1.8)
                elif is_telegram_target and telegram_media:
                    if label == "warp-socks":
                        attempt["timeout"] = max(float(attempt.get("timeout") or 2.5), 3.2)
                        attempt["first_byte_timeout"] = max(float(attempt.get("first_byte_timeout") or 1.4), 5.8)
                    elif label == "direct":
                        attempt["timeout"] = max(float(attempt.get("timeout") or 1.2), 2.2)
                        attempt["first_byte_timeout"] = max(float(attempt.get("first_byte_timeout") or 1.4), 3.2)
                    elif label == "opera-http":
                        attempt["timeout"] = max(float(attempt.get("timeout") or 3.0), 2.8)
                        attempt["first_byte_timeout"] = max(float(attempt.get("first_byte_timeout") or 2.4), 3.8)
                elif is_telegram_target:
                    if label == "warp-socks":
                        attempt["timeout"] = max(float(attempt.get("timeout") or 2.5), 2.8)
                        attempt["first_byte_timeout"] = max(float(attempt.get("first_byte_timeout") or 1.4), 2.6)
                    elif label == "opera-http":
                        attempt["timeout"] = min(float(attempt.get("timeout") or 3.0), 2.0)
                        attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 2.4), 2.0)
                    elif label == "direct":
                        attempt["timeout"] = min(float(attempt.get("timeout") or 1.2), 1.0)
                        attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 1.4), 1.2)
                elif is_telegram_app:
                    if int(target_port or 0) not in (80, 443, 5222, 5228):
                        if label == "warp-socks":
                            attempt["timeout"] = min(float(attempt.get("timeout") or 2.5), 1.2)
                            attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 1.4), 1.2)
                        elif label == "direct":
                            attempt["timeout"] = min(float(attempt.get("timeout") or 1.2), 0.4)
                            attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 1.4), 0.4)
                        elif label == "opera-http":
                            attempt["timeout"] = min(float(attempt.get("timeout") or 3.0), 0.8)
                            attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 2.4), 0.8)
                    else:
                        if label == "warp-socks":
                            attempt["timeout"] = min(float(attempt.get("timeout") or 2.5), 1.0)
                            attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 1.4), 1.0)
                        elif label == "direct":
                            attempt["timeout"] = min(float(attempt.get("timeout") or 1.2), 0.35)
                            attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 1.4), 0.35)
                        elif label == "opera-http":
                            attempt["timeout"] = min(float(attempt.get("timeout") or 3.0), 1.1)
                            attempt["first_byte_timeout"] = min(float(attempt.get("first_byte_timeout") or 2.4), 1.1)
                rendered.append(attempt)
        return rendered

    def _fallback_target(self) -> Optional[Tuple[str, int]]:
        raw = str(os.environ.get("NOVA_WFP_PROXY_TARGET", "")).strip()
        if not raw or ":" not in raw:
            return None
        host, port = raw.rsplit(":", 1)
        try:
            return host.strip(), int(port)
        except Exception:
            return None

    def _divert_state_path(self) -> str:
        return str(
            os.environ.get(
                "NOVA_DIVERT_REDIRECT_MAP",
                str(REPO_ROOT / "temp" / "NovaDivertRedirectMap.json"),
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
        path = self._divert_state_path()
        if not path or not os.path.exists(path):
            return None
        # Give WinDivert map writer enough time during startup bursts and
        # during flow-close races where the redirected socket reaches the
        # proxy slightly after the original flow is already being torn down.
        for _attempt in range(40):
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
                            if int(value.get("local_port") or 0) == peer_port:
                                candidates.append(value)
                        except Exception:
                            continue
                if not candidates:
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

    async def _open_upstream_with_attempts(
        self,
        target_host: str,
        target_port: int,
        route_attempts: List[dict],
        route_scope: str = "",
    ):
        last_error = None
        route_family = self._route_scope_family(route_scope)
        for attempt in route_attempts:
            label = str(attempt.get("label") or attempt.get("kind") or "unknown").strip() or "unknown"
            started = time.monotonic()
            try:
                upstream_reader, upstream_writer, route_label = await open_stream(
                    target_host,
                    int(target_port),
                    timeout=8.0,
                    attempts=[attempt],
                )
                elapsed_ms = int((time.monotonic() - started) * 1000)
                return upstream_reader, upstream_writer, route_label, elapsed_ms
            except Exception as exc:
                last_error = exc
                elapsed_ms = int((time.monotonic() - started) * 1000)
                bad_ttl = 45.0
                if route_family == "telegram":
                    if label == "warp-socks":
                        bad_ttl = 5.0
                    elif label == "opera-http":
                        bad_ttl = 15.0
                    elif label == "direct":
                        bad_ttl = 30.0
                self._bad_route_cache_put(
                    target_host,
                    int(target_port),
                    label,
                    route_scope=route_scope,
                    ttl=bad_ttl,
                )
                self.log_func(
                    f"[NovaWFP][Proxy] attempt-failed target={target_host}:{target_port} "
                    f"route={label} ms={elapsed_ms} error={exc}"
                )
        if last_error is None:
            last_error = OSError("no upstream attempts available")
        raise last_error

    async def _open_verified_upstream_with_attempts(
        self,
        target_host: str,
        target_port: int,
        route_attempts: List[dict],
        initial_data: bytes,
        route_scope: str = "",
        bad_route_all_ports: bool = True,
        telegram_media: bool = False,
    ):
        last_error = None
        for attempt in route_attempts:
            label = str(attempt.get("label") or attempt.get("kind") or "unknown").strip() or "unknown"
            started = time.monotonic()
            upstream_writer = None
            try:
                upstream_reader, upstream_writer, route_label, route_open_ms = await self._open_upstream_with_attempts(
                    target_host,
                    int(target_port),
                    [attempt],
                    route_scope=route_scope,
                )
                upstream_writer.write(initial_data)
                await upstream_writer.drain()
                first_timeout = self._effective_first_byte_timeout(attempt, telegram_media=telegram_media)
                try:
                    first_down = await asyncio.wait_for(upstream_reader.read(65536), timeout=first_timeout)
                except asyncio.TimeoutError as exc:
                    if telegram_media and label == "warp-socks":
                        verify_ms = int((time.monotonic() - started) * 1000)
                        self.log_func(
                            f"[NovaWFP][Proxy] verify-soft-timeout target={target_host}:{target_port} "
                            f"route={route_label} ms={verify_ms} wait={first_timeout:.1f}s; continue-bridge"
                        )
                        return upstream_reader, upstream_writer, route_label, route_open_ms, b""
                    raise TimeoutError(f"no first byte in {first_timeout:.1f}s") from exc
                if not first_down:
                    raise OSError("upstream closed before first byte")
                verify_ms = int((time.monotonic() - started) * 1000)
                self.log_func(
                    f"[NovaWFP][Proxy] verified target={target_host}:{target_port} route={route_label} "
                    f"open_ms={route_open_ms} verify_ms={verify_ms} first_down={len(first_down)}"
                )
                return upstream_reader, upstream_writer, route_label, route_open_ms, first_down
            except Exception as exc:
                last_error = exc
                elapsed_ms = int((time.monotonic() - started) * 1000)
                self._bad_route_cache_put(
                    target_host,
                    int(target_port),
                    label,
                    route_scope=route_scope,
                    ttl=(12.0 if telegram_media else None),
                    all_ports=bool(bad_route_all_ports),
                )
                self.log_func(
                    f"[NovaWFP][Proxy] verify-failed target={target_host}:{target_port} "
                    f"route={label} ms={elapsed_ms} error={exc}"
                )
                with contextlib.suppress(Exception):
                    if upstream_writer is not None:
                        upstream_writer.close()
                        await upstream_writer.wait_closed()
                continue
        if last_error is None:
            last_error = OSError("no upstream attempts available")
        raise last_error

    async def _read_initial_probe(self, reader: asyncio.StreamReader, want: int = 64, timeout: float = TG_INITIAL_PROBE_TIMEOUT) -> bytes:
        data = bytearray()
        deadline = time.monotonic() + max(0.05, float(timeout))
        while len(data) < want:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(want - len(data)), timeout=max(0.05, remaining))
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def _tg_ws_deps_ready(self) -> bool:
        return bool(
            TG_WS_BRIDGE_ENABLED
            and TransparentMsgSplitter is not None
            and callable(parse_transparent_init_info)
            and callable(_connect_websocket_target)
            and callable(_target_dc_hint)
            and callable(_likely_media_target)
            and callable(_ws_domains)
        )

    def _tg_ws_bad(self, dc: int, is_media: bool, domain: str, target_ip: str) -> bool:
        key = (int(dc or 0), bool(is_media), str(domain or ""), str(target_ip or ""))
        until = float(self._tg_ws_bad_until.get(key, 0.0) or 0.0)
        if until <= 0:
            return False
        if until <= time.monotonic():
            self._tg_ws_bad_until.pop(key, None)
            return False
        return True

    def _tg_ws_mark_bad(self, dc: int, is_media: bool, domain: str, target_ip: str, ttl: float = 45.0) -> None:
        key = (int(dc or 0), bool(is_media), str(domain or ""), str(target_ip or ""))
        self._tg_ws_bad_until[key] = time.monotonic() + max(5.0, float(ttl))

    def _tg_ws_pool_key(self, dc: int, is_media: bool) -> Tuple[int, bool]:
        return int(dc or 0), bool(is_media)

    async def _tg_ws_close_quietly(self, ws) -> None:
        with contextlib.suppress(Exception):
            await ws.close()

    def _tg_ws_is_alive(self, ws, created_at: float) -> bool:
        if not ws:
            return False
        if (time.monotonic() - float(created_at or 0.0)) > TG_WS_POOL_MAX_AGE:
            return False
        if bool(getattr(ws, "_closed", False)):
            return False
        try:
            transport = getattr(getattr(ws, "writer", None), "transport", None)
            if transport is not None and transport.is_closing():
                return False
        except Exception:
            return False
        return True

    async def _tg_ws_pool_take(self, dc: int, is_media: bool, original_target_ip: str):
        if TG_WS_POOL_SIZE <= 0:
            return None, ""
        key = self._tg_ws_pool_key(dc, is_media)
        bucket = self._tg_ws_pool.setdefault(key, deque())
        now = time.monotonic()
        while bucket:
            ws, created_at, route_label = bucket.popleft()
            if self._tg_ws_is_alive(ws, created_at):
                if not self._tg_ws_should_keep_pooled(route_label):
                    self.log_func(
                        f"[NovaWFP][TGWS] discard-pooled dc={dc} media={bool(is_media)} "
                        f"route={route_label} reason=warp-ready"
                    )
                    await self._tg_ws_close_quietly(ws)
                    continue
                age_ms = int((now - float(created_at or now)) * 1000)
                self._tg_ws_schedule_refill(dc, is_media, original_target_ip)
                return ws, f"{route_label} pooled=1 age_ms={age_ms}"
            await self._tg_ws_close_quietly(ws)
        self._tg_ws_schedule_refill(dc, is_media, original_target_ip)
        return None, ""

    def _tg_ws_schedule_refill(self, dc: int, is_media: bool, original_target_ip: str, delay: float = 0.05) -> None:
        if TG_WS_POOL_SIZE <= 0 or not self._tg_ws_deps_ready():
            return
        dc = int(dc or 0)
        if dc <= 0:
            return
        key = self._tg_ws_pool_key(dc, is_media)
        if key in self._tg_ws_refilling:
            return
        self._tg_ws_refilling.add(key)
        try:
            asyncio.create_task(self._tg_ws_refill(dc, bool(is_media), str(original_target_ip or ""), delay=delay))
        except RuntimeError:
            self._tg_ws_refilling.discard(key)

    async def _tg_ws_refill(self, dc: int, is_media: bool, original_target_ip: str, delay: float = 0.05) -> None:
        key = self._tg_ws_pool_key(dc, is_media)
        try:
            if delay > 0:
                await asyncio.sleep(float(delay))
            bucket = self._tg_ws_pool.setdefault(key, deque())
            kept = deque()
            while bucket:
                ws, created_at, route_label = bucket.popleft()
                if self._tg_ws_is_alive(ws, created_at) and self._tg_ws_should_keep_pooled(route_label):
                    kept.append((ws, created_at, route_label))
                else:
                    await self._tg_ws_close_quietly(ws)
            self._tg_ws_pool[key] = kept
            bucket = self._tg_ws_pool[key]
            needed = max(0, TG_WS_POOL_SIZE - len(bucket))
            for _ in range(needed):
                ws, route_label = await self._open_tg_ws_route_fresh(dc, is_media, original_target_ip)
                if ws is None:
                    break
                bucket.append((ws, time.monotonic(), route_label))
            if bucket:
                self.log_func(f"[NovaWFP][TGWS] pool-ready dc={dc} media={bool(is_media)} size={len(bucket)}")
        finally:
            self._tg_ws_refilling.discard(key)

    async def _open_tg_ws_route_fresh(self, dc: int, is_media: bool, original_target_ip: str):
        dc = int(dc or 0)
        if dc <= 0:
            return None, ""
        redirect_target = TG_WS_REDIRECT_IPS.get(dc)
        if not redirect_target:
            return None, ""
        if self._tg_ws_prefers_cf_first(dc, is_media):
            ws, route_label = await self._open_tg_ws_cf_route(dc, is_media, primary_only=True)
            if ws is not None:
                return ws, route_label
        domains = list(_ws_domains(dc, bool(is_media)) or [])
        for domain in domains:
            if self._tg_ws_bad(dc, is_media, domain, redirect_target):
                continue
            started = time.monotonic()
            try:
                ws, upstream_label = await _connect_websocket_target(
                    redirect_target,
                    domain,
                    timeout=self._tg_ws_handshake_timeout(is_media),
                )
                elapsed_ms = int((time.monotonic() - started) * 1000)
                return ws, f"{domain}@{redirect_target} via {upstream_label} ws_ms={elapsed_ms}"
            except WsHandshakeError as exc:
                ttl = 300.0 if getattr(exc, "is_redirect", False) else 60.0
                self._tg_ws_mark_bad(dc, is_media, domain, redirect_target, ttl=ttl)
                if TG_WS_VERBOSE_FAILURES:
                    self.log_func(
                        f"[NovaWFP][TGWS] ws-failed dc={dc} media={bool(is_media)} "
                        f"domain={domain} target={redirect_target} error={exc}"
                    )
                continue
            except Exception as exc:
                self._tg_ws_mark_bad(dc, is_media, domain, redirect_target, ttl=45.0)
                if TG_WS_VERBOSE_FAILURES:
                    self.log_func(
                        f"[NovaWFP][TGWS] ws-failed dc={dc} media={bool(is_media)} "
                        f"domain={domain} target={redirect_target} error={exc}"
                    )
                continue
        ws, route_label = await self._open_tg_ws_cf_route(dc, is_media)
        if ws is not None:
            return ws, route_label
        return None, ""

    async def _open_tg_ws_route(self, dc: int, is_media: bool, original_target_ip: str):
        ws, route_label = await self._tg_ws_pool_take(dc, is_media, original_target_ip)
        if ws is not None:
            return ws, route_label
        ws, route_label = await self._open_tg_ws_route_fresh(dc, is_media, original_target_ip)
        if ws is not None:
            self._tg_ws_schedule_refill(dc, is_media, original_target_ip)
        return ws, route_label

    async def _normalize_telegram_bootstrap_target(
        self,
        target_host: str,
        target_port: int,
        mtproto_init=None,
    ) -> Tuple[str, int, str, int]:
        host = str(target_host or "").strip()
        port = int(target_port or 0)
        if not host or port != 80 or not self._is_telegram_target(host):
            return host, port, "", 0

        try:
            target_ip = await _resolve_ip(host) if callable(_resolve_ip) else host
        except Exception:
            target_ip = host

        dc_hint = 0
        try:
            dc_hint = int(getattr(mtproto_init, "dc", 0) or 0)
        except Exception:
            dc_hint = 0
        if dc_hint <= 0:
            try:
                dc_hint = int(_target_dc_hint(target_ip, False) or 0)
            except Exception:
                dc_hint = 0

        upgraded_host = str(TG_TCP_FALLBACK_IPS.get(dc_hint) or target_ip or host).strip() or host
        note = f" orig={host}:{port}"
        if dc_hint > 0:
            note = f"{note} dc={dc_hint}"
        if upgraded_host == host:
            note = f"{note} bootstrap=same-host-443"
        else:
            note = f"{note} bootstrap=canonical-443"
        return upgraded_host, 443, note, int(dc_hint or 0)

    def _tg_ws_cf_domains(self, primary_only: bool = False) -> List[str]:
        if primary_only and callable(get_cfproxy_primary_domains):
            return [str(item).strip() for item in get_cfproxy_primary_domains("NOVA_TG_WS_CF_DOMAINS") if str(item).strip()]
        if callable(get_cfproxy_domains):
            return [str(item).strip() for item in get_cfproxy_domains("NOVA_TG_WS_CF_DOMAINS") if str(item).strip()]
        return [str(item).strip() for item in (CFPROXY_DEFAULT_DOMAINS or []) if str(item).strip()]

    def _tg_ws_prefers_cf_first(self, dc: int, is_media: bool) -> bool:
        dc = int(dc or 0)
        if bool(is_media):
            return dc in TG_WS_CF_FIRST_MEDIA_DCS
        return dc in TG_WS_CF_FIRST_DCS

    def _tg_ws_call_safe_disabled(self, dc: int, is_media: bool) -> bool:
        if not bool(is_media):
            return False
        dc = int(dc or 0)
        return dc in TG_WS_CALL_SAFE_MEDIA_DCS

    def _tg_ws_media_passthrough_active(self, dc: int, is_media: bool) -> bool:
        if not bool(is_media):
            return False
        dc = int(dc or 0)
        if dc <= 0:
            return False
        until = float(self._tg_ws_media_passthrough_until.get(dc, 0.0) or 0.0)
        return time.monotonic() < until

    def _tg_ws_note_media_close(self, dc: int, is_media: bool, up: int, down: int, duration_ms: int) -> None:
        if not bool(is_media):
            return
        dc = int(dc or 0)
        if dc <= 0:
            return
        now = time.monotonic()
        suspicious = int(duration_ms or 0) <= TG_WS_MEDIA_FAST_CLOSE_MS and int(down or 0) <= TG_WS_MEDIA_FAST_CLOSE_BYTES
        if suspicious:
            streak = self._tg_ws_media_fail_streak.get(dc)
            if not isinstance(streak, deque):
                streak = deque(maxlen=8)
            streak.append(now)
            while streak and (now - float(streak[0])) > 20.0:
                streak.popleft()
            self._tg_ws_media_fail_streak[dc] = streak
            if len(streak) >= 2:
                self._tg_ws_media_passthrough_until[dc] = now + float(TG_WS_MEDIA_PASSTHROUGH_TTL)
                self._tg_ws_media_fail_streak[dc] = deque(maxlen=8)
                self.log_func(
                    f"[NovaWFP][TGWS] media-call-safe dc={dc} enabled for {int(TG_WS_MEDIA_PASSTHROUGH_TTL)}s "
                    f"(rapid-close down={int(down or 0)} duration_ms={int(duration_ms or 0)}); tcp-path"
                )
            return
        with contextlib.suppress(Exception):
            self._tg_ws_media_fail_streak.pop(dc, None)
        if int(down or 0) > max(4096, TG_WS_MEDIA_FAST_CLOSE_BYTES * 4):
            with contextlib.suppress(Exception):
                self._tg_ws_media_passthrough_until.pop(dc, None)

    @staticmethod
    def _tg_ws_handshake_timeout(is_media: bool) -> float:
        return 6.5 if bool(is_media) else 4.0

    async def _open_tg_ws_cf_route(self, dc: int, is_media: bool, primary_only: bool = False):
        if not TG_WS_CF_FALLBACK_ENABLED:
            return None, ""
        for base_domain in self._tg_ws_cf_domains(primary_only=primary_only):
            candidates = [f"kws{dc}-1.{base_domain}", f"kws{dc}.{base_domain}"] if bool(is_media) else [f"kws{dc}.{base_domain}"]
            for domain in candidates:
                if self._tg_ws_bad(dc, is_media, domain, domain):
                    continue
                started = time.monotonic()
                try:
                    ws, upstream_label = await _connect_websocket_target(
                        domain,
                        domain,
                        timeout=max(5.0, self._tg_ws_handshake_timeout(is_media) + 0.5),
                    )
                    elapsed_ms = int((time.monotonic() - started) * 1000)
                    return ws, f"{domain} via {upstream_label} cf_ws_ms={elapsed_ms}"
                except Exception as exc:
                    self._tg_ws_mark_bad(dc, is_media, domain, domain, ttl=120.0)
                    if TG_WS_VERBOSE_FAILURES:
                        self.log_func(
                            f"[NovaWFP][TGWS] cf-failed dc={dc} media={bool(is_media)} "
                            f"domain={domain} error={exc}"
                        )
                    continue
        return None, ""

    def _schedule_startup_prewarm(self) -> None:
        if not (TG_WS_STARTUP_PREWARM and TG_WS_POOL_SIZE > 0 and self._tg_ws_deps_ready()):
            return
        scheduled = 0
        for index, (dc, is_media) in enumerate(TG_WS_STARTUP_PREWARM_PLAN):
            if self._tg_ws_call_safe_disabled(dc, is_media):
                continue
            target_ip = str(TG_TCP_FALLBACK_IPS.get(int(dc), "") or "")
            if not target_ip:
                continue
            self._tg_ws_schedule_refill(int(dc), bool(is_media), target_ip, delay=0.05 + (0.08 * index))
            scheduled += 1
        if scheduled:
            self.log_func(f"[NovaWFP][TGWS] startup-prewarm scheduled={scheduled}")

    async def _bridge_tg_ws_streams(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        ws,
        splitter,
    ):
        counters = {"up": 0, "down": 0}
        started = time.monotonic()

        async def _client_to_ws():
            try:
                while True:
                    data = await client_reader.read(65536)
                    if not data:
                        if splitter:
                            tail = splitter.flush()
                            for part in tail:
                                await ws.send(part)
                        break
                    counters["up"] += len(data)
                    if splitter:
                        parts = splitter.split(data)
                        for part in parts:
                            await ws.send(part)
                    else:
                        await ws.send(data)
            except (asyncio.CancelledError, asyncio.IncompleteReadError, ConnectionError, OSError):
                return
            finally:
                with contextlib.suppress(Exception):
                    await ws.close()

        async def _ws_to_client():
            try:
                while True:
                    payload = await ws.recv()
                    if payload is None:
                        break
                    if not payload:
                        continue
                    counters["down"] += len(payload)
                    client_writer.write(payload)
                    await client_writer.drain()
            except (asyncio.CancelledError, asyncio.IncompleteReadError, ConnectionError, OSError):
                return
            finally:
                with contextlib.suppress(Exception):
                    client_writer.close()

        tasks = [asyncio.create_task(_client_to_ws()), asyncio.create_task(_ws_to_client())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
            with contextlib.suppress(BaseException):
                await task
        for task in done:
            with contextlib.suppress(BaseException):
                await task
        return counters["up"], counters["down"], int((time.monotonic() - started) * 1000)

    async def _try_tg_ws_bridge(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
        initial_data: bytes,
        peer_label: str,
    ) -> bool:
        if not self._tg_ws_deps_ready() or len(initial_data) < 64 or int(target_port or 0) not in TELEGRAM_TCP_PORTS:
            return False
        init_info = parse_transparent_init_info(initial_data[:64])
        if init_info is None:
            return False
        try:
            target_ip = await _resolve_ip(target_host) if callable(_resolve_ip) else str(target_host)
        except Exception:
            target_ip = str(target_host)
        try:
            dc_hint = int(getattr(init_info, "dc", 0) or 0) or int(_target_dc_hint(target_ip, bool(getattr(init_info, "is_media", False))) or 0)
        except Exception:
            dc_hint = int(getattr(init_info, "dc", 0) or 0)
        try:
            is_media = bool(getattr(init_info, "is_media", False) or _likely_media_target(target_ip, int(target_port), dc_hint))
        except Exception:
            is_media = bool(getattr(init_info, "is_media", False))
        if self._tg_ws_call_safe_disabled(dc_hint, is_media):
            self.log_func(
                f"[NovaWFP][TGWS] call-safe dc={dc_hint or '?'} media=True "
                f"target={target_ip}:{target_port}; tcp-path"
            )
            return False
        if self._tg_ws_media_passthrough_active(dc_hint, is_media):
            self.log_func(
                f"[NovaWFP][TGWS] media-call-safe-active dc={dc_hint or '?'} "
                f"target={target_ip}:{target_port}; tcp-path"
            )
            return False
        if TG_WS_BRIDGE_MEDIA_ONLY and not is_media:
            self.log_func(
                f"[NovaWFP][TGWS] observed proto={_proto_label(init_info.proto) if callable(_proto_label) else init_info.proto} "
                f"dc={dc_hint or '?'} media=False target={target_ip}:{target_port}; tcp-path"
            )
            return False
        ws, route_label = await self._open_tg_ws_route(dc_hint, is_media, target_ip)
        if ws is None:
            self.log_func(
                f"[NovaWFP][TGWS] no-ws dc={dc_hint or '?'} media={is_media} target={target_ip}:{target_port}; tcp-path"
            )
            return False
        splitter = None
        try:
            splitter = TransparentMsgSplitter(initial_data[:64], init_info.proto)
        except Exception:
            splitter = None
        try:
            await ws.send(initial_data)
        except Exception as exc:
            self._tg_ws_schedule_refill(dc_hint, is_media, target_ip)
            self.log_func(
                f"[NovaWFP][TGWS] init-send-failed dc={dc_hint or '?'} media={is_media} "
                f"route={route_label} error={exc}; tcp-path"
            )
            with contextlib.suppress(Exception):
                await ws.close()
            return False
        proto = _proto_label(init_info.proto) if callable(_proto_label) else str(init_info.proto)
        self.log_func(
            f"[NovaWFP][TGWS] connected={peer_label} proto={proto} dc={dc_hint or '?'} "
            f"media={is_media} route={route_label} target={target_ip}:{target_port}"
        )
        up, down, duration_ms = await self._bridge_tg_ws_streams(reader, writer, ws, splitter)
        self.log_func(
            f"[NovaWFP][TGWS] closed={peer_label} dc={dc_hint or '?'} media={is_media} "
            f"duration_ms={duration_ms} up={up + len(initial_data)} down={down}"
        )
        self._tg_ws_note_media_close(dc_hint, is_media, up + len(initial_data), down, duration_ms)
        return True

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        peer_label = f"{peer[0]}:{peer[1]}" if peer else "?"
        accepted_socket = writer.get_extra_info("socket")
        target_host = None
        target_port = None
        target_note = ""
        context = None
        divert_context = None
        redirect_records = b""
        app_id = ""
        app_family = ""

        try:
            if accepted_socket is not None:
                try:
                    redirect_records = query_redirect_records(accepted_socket)
                except Exception:
                    redirect_records = b""
                try:
                    context = parse_redirect_context(query_redirect_context(accepted_socket))
                except Exception:
                    context = None

            if context is not None:
                target_host, target_port = _format_socket_address(context.OriginalDestination, int(context.IpVersion))
            else:
                divert_context = await self._lookup_divert_context(peer)
                if divert_context:
                    target_host = str(divert_context.get("target_host") or "").strip()
                    target_port = int(divert_context.get("target_port") or 0)
            if not target_host or not target_port:
                fallback = self._fallback_target()
                if fallback:
                    target_host, target_port = fallback

            if not target_host or not target_port:
                self.log_func(f"[NovaWFP][Proxy] {peer_label} no redirect context; closing")
                return

            preferred_egress = 0
            route_scope = ""
            if context is not None:
                preferred_egress = int(context.PreferredEgress)
                app_id = str(context.AppId).split("\x00", 1)[0]
                app_family = self._app_family_from_app_id(app_id)
                if (not app_family) and ("msedgewebview2.exe" in str(app_id or "").replace("/", "\\").lower()):
                    app_family = self._resolve_webview_host_family(int(context.ProcessId))
                    if app_family == "opencode":
                        preferred_egress = 2
                    elif app_family == "whatsapp":
                        preferred_egress = 1
                    else:
                        app_family = "webview2"
                        preferred_egress = 3
                route_scope = f"{str(app_family or 'generic').strip().lower()}|egress:{int(preferred_egress)}"
            elif divert_context is not None:
                preferred_egress = int(divert_context.get("preferred_egress") or 0)
                app_id = str(divert_context.get("app_id") or "")
                app_family = str(divert_context.get("app_family") or self._app_family_from_app_id(app_id) or "").strip().lower()
                route_scope = f"{str(app_family or 'generic').strip().lower()}|egress:{int(preferred_egress)}"
            initial_data = b""
            first_down = b""
            mtproto_init = None
            bootstrap_dc_hint = 0
            telegram_media_tcp = False
            if self._is_telegram_target(target_host):
                initial_data = await self._read_initial_probe(reader, want=64)
                if self._tg_ws_deps_ready() and len(initial_data) >= 64:
                    try:
                        mtproto_init = parse_transparent_init_info(initial_data[:64])
                    except Exception:
                        mtproto_init = None
                if mtproto_init is not None:
                    try:
                        media_target_ip = await _resolve_ip(target_host) if callable(_resolve_ip) else str(target_host)
                    except Exception:
                        media_target_ip = str(target_host)
                    try:
                        media_dc_hint = int(getattr(mtproto_init, "dc", 0) or 0)
                    except Exception:
                        media_dc_hint = 0
                    if media_dc_hint <= 0:
                        try:
                            media_dc_hint = int(
                                _target_dc_hint(
                                    media_target_ip,
                                    bool(getattr(mtproto_init, "is_media", False)),
                                ) or 0
                            )
                        except Exception:
                            media_dc_hint = 0
                    try:
                        telegram_media_tcp = bool(
                            getattr(mtproto_init, "is_media", False)
                            or _likely_media_target(media_target_ip, int(target_port), media_dc_hint)
                        )
                    except Exception:
                        telegram_media_tcp = bool(getattr(mtproto_init, "is_media", False))
                if initial_data and await self._try_tg_ws_bridge(
                    reader,
                    writer,
                    target_host,
                    int(target_port),
                        initial_data,
                        peer_label,
                ):
                    return
                target_host, target_port, target_note, bootstrap_dc_hint = await self._normalize_telegram_bootstrap_target(
                    target_host,
                    int(target_port),
                    mtproto_init,
                )
                if (
                    "bootstrap=canonical-443" in str(target_note)
                    and int(bootstrap_dc_hint or 0) in TG_WS_CF_FIRST_DCS
                    and not telegram_media_tcp
                ):
                    preferred_egress = 3
            route_attempts = self._build_attempts_for_target(
                target_host,
                int(target_port),
                preferred_egress,
                telegram_media=telegram_media_tcp,
                app_family=app_family,
                route_scope=route_scope,
            )
            if initial_data and telegram_media_tcp:
                upstream_reader, upstream_writer, route_label, route_open_ms, first_down = await self._open_verified_upstream_with_attempts(
                    target_host,
                    int(target_port),
                    route_attempts,
                    initial_data,
                    route_scope=route_scope,
                    bad_route_all_ports=False,
                    telegram_media=True,
                )
            elif initial_data:
                upstream_reader, upstream_writer, route_label, route_open_ms = await self._open_upstream_with_attempts(
                    target_host,
                    int(target_port),
                    route_attempts,
                    route_scope=route_scope,
                )
                upstream_writer.write(initial_data)
                await upstream_writer.drain()
            else:
                upstream_reader, upstream_writer, route_label, route_open_ms = await self._open_upstream_with_attempts(
                    target_host,
                    int(target_port),
                    route_attempts,
                    route_scope=route_scope,
                )
            self._route_label_cache_put(target_host, int(target_port), route_label, route_scope=route_scope)
            self.log_func(
                f"[NovaWFP][Proxy] accepted={peer_label} target={target_host}:{target_port}{target_note} "
                f"route={route_label} open_ms={route_open_ms}"
            )
            if context is not None:
                self.log_func(
                    f"[NovaWFP][Proxy] context pid={int(context.ProcessId)} ipver={int(context.IpVersion)} "
                    f"proto={int(context.Protocol)} egress={int(context.PreferredEgress)} "
                    f"family={app_family or '-'} app={app_id}"
                )
            elif divert_context is not None:
                self.log_func(
                    f"[NovaWFP][Proxy] divert-context pid={int(divert_context.get('process_id') or 0)} "
                    f"egress={int(preferred_egress)} family={app_family or '-'} app={app_id}"
                )

            # Redirect records are useful for a direct proxy socket. The current first
            # implementation still routes through warp/opera/direct transport helpers,
            # so the records are only logged and preserved for the next integration step.
            if redirect_records:
                self.log_func(f"[NovaWFP][Proxy] redirect-records={len(redirect_records)} bytes")

            if first_down:
                writer.write(first_down)
                await writer.drain()

            sent_bytes, received_bytes, duration_ms = await _bridge_streams(
                reader,
                writer,
                upstream_reader,
                upstream_writer,
                initial_up=len(initial_data),
                initial_down=len(first_down),
            )
            self.log_func(
                f"[NovaWFP][Proxy] closed={peer_label} target={target_host}:{target_port}{target_note} route={route_label} "
                f"duration_ms={duration_ms} up={sent_bytes} down={received_bytes}"
            )
            if (
                self._is_telegram_target(target_host)
                and str(route_label) in {"warp-socks", "opera-http"}
                and sent_bytes > 0
                and received_bytes == 0
            ):
                stall_ms = 7000 if telegram_media_tcp else 2800
                if duration_ms >= stall_ms:
                    if str(route_label) == "warp-socks":
                        self.log_func(
                            f"[NovaWFP][Proxy] route-stalled-observed target={target_host}:{target_port} "
                            f"route={route_label}; kept-primary for Telegram"
                        )
                    else:
                        self._bad_route_cache_put(
                            target_host,
                            int(target_port),
                            route_label,
                            route_scope=route_scope,
                            ttl=(12.0 if telegram_media_tcp else None),
                            all_ports=(not telegram_media_tcp),
                        )
                        scope = "target" if telegram_media_tcp else "host"
                        self.log_func(
                            f"[NovaWFP][Proxy] route-stalled target={target_host}:{target_port} "
                            f"route={route_label}; temporarily deprioritized for {scope}"
                        )
        except Exception as exc:
            self.log_func(f"[NovaWFP][Proxy] {peer_label} failed: {exc}")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def run(self):
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.log_func(f"[NovaWFP][Proxy] listening on {self.host}:{self.port}")
        self._schedule_startup_prewarm()
        async with self.server:
            serve_task = asyncio.create_task(self.server.serve_forever())
            stop_task = asyncio.create_task(self.stop_event.wait())
            done, pending = await asyncio.wait({serve_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
                with contextlib.suppress(Exception):
                    await task
            if stop_task in done:
                self.server.close()
                await self.server.wait_closed()
            if serve_task in done:
                with contextlib.suppress(Exception):
                    await serve_task
def _default_log_file() -> Path:
    return REPO_ROOT / "temp" / "NovaWfpTcpProxy.log"


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
    parser.add_argument("--host", default=os.environ.get("NOVA_WFP_PROXY_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("NOVA_WFP_PROXY_PORT", "17870")))
    parser.add_argument("--log", default=os.environ.get("NOVA_WFP_PROXY_LOG") or str(_default_log_file()))
    return parser.parse_args()


async def _main_async(host: str, port: int):
    proxy = NovaWfpTcpProxy(host=host, port=port)
    await proxy.run()


def main() -> int:
    args = _parse_args()
    log_path = _configure_file_logging(Path(args.log))
    LOG.info("[NovaWFP][Proxy] starting")
    LOG.info(f"[NovaWFP][Proxy] log={log_path}")
    LOG.info(f"[NovaWFP][Proxy] bind={args.host}:{args.port}")
    try:
        asyncio.run(_main_async(str(args.host), int(args.port)))
        return 0
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
