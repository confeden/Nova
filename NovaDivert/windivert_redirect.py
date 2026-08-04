import argparse
import collections
import contextlib
import ctypes
from ctypes import wintypes
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import traceback

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.dirname(BASE_DIR)
# resources/ - каталог собственных модулей Nova. В установленной программе
# BASE_DIR сам и есть этот каталог, поэтому лишний кандидат просто не
# существует и пропускается; при запуске из исходников именно он их и находит.
for _path in (os.path.join(BASE_DIR, "resources"), BASE_DIR, APP_DIR):
    if _path and _path not in sys.path:
        sys.path.insert(0, _path)

from nova_routing_profiles import match_app_by_process_path
from nova_transport_plans import _get_app_route_mode


WINDIVERT_LAYER_NETWORK = 0
WINDIVERT_LAYER_FLOW = 2
WINDIVERT_LAYER_SOCKET = 3

WINDIVERT_EVENT_FLOW_ESTABLISHED = 1
WINDIVERT_EVENT_FLOW_DELETED = 2
WINDIVERT_EVENT_SOCKET_CONNECT = 4

WINDIVERT_FLAG_SNIFF = 1
WINDIVERT_FLAG_RECV_ONLY = 4

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_COMMAND_LINE_INFORMATION = 60
MAX_PATH = 32768
INET6_ADDRSTRLEN = 64
ERROR_OPERATION_ABORTED = 995
ERROR_INVALID_HANDLE = 6
ERROR_NO_DATA = 232
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_NAME = 123
NO_ERROR = 0

IPPROTO_TCP = 6
IPPROTO_UDP = 17
NETWORK_CAPTURE_SIZE = 0xFFFF
MAP_TTL_SECONDS = 300.0
MAP_REMOVE_GRACE_SECONDS = 20.0
WINDIVERT_REDIRECT_NETWORK_PRIORITY = -1190
WINDIVERT_REDIRECT_EVENT_PRIORITY = 1191
WINDIVERT_FLAG_OUTBOUND_BIT = 1 << 17
WINDIVERT_FLAG_LOOPBACK_BIT = 1 << 18

APP_FAMILY = {
    "Discord": "discord",
    "Telegram": "telegram",
    "WhatsApp": "whatsapp",
    "IDE": "ide",
    "CLI": "cli",
    "Games": "games",
    "GamesDirect": "games-steam-direct",
    "OBS": "obs",
}


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]

_ROUTE_MODE_CACHE = {"ts": 0.0, "modes": {}}

PREFERRED_EGRESS = {
    "discord": 1,   # WARP
    "telegram": 1,  # WARP
    "whatsapp": 1,  # WARP
    "ide": 2,       # Opera/EU
    "cli": 0,       # Browser-like auto routing
    "games": 1,     # WARP
    "games-steam-direct": 3,
}

_TELEGRAM_IPV6_NETWORKS = [
    ipaddress.ip_network("2001:067c:04e8:f000::/52"),
    ipaddress.ip_network("2001:0b28:f23d:f000::/52"),
    ipaddress.ip_network("2001:0b28:f23f:f000::/52"),
]


def _load_ip_networks(path):
    nets = []
    try:
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


def _env_bool(name, default=False):
    raw = os.environ.get(str(name), None)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _current_route_mode_for_app(app):
    now = time.time()
    try:
        cached_ts = float(_ROUTE_MODE_CACHE.get("ts") or 0.0)
        cached_modes = _ROUTE_MODE_CACHE.get("modes") or {}
        app_key = str(APP_FAMILY.get(str(app or "").strip(), "") or "").strip().lower()
        if not app_key:
            return "auto"
        if cached_modes and (now - cached_ts) <= 1.0:
            return str(cached_modes.get(app_key) or "auto").strip().lower()
        refreshed = {}
        for family_key in set(APP_FAMILY.values()):
            try:
                refreshed[family_key] = str(_get_app_route_mode(family_key) or "auto").strip().lower()
            except Exception:
                refreshed[family_key] = "auto"
        _ROUTE_MODE_CACHE["ts"] = now
        _ROUTE_MODE_CACHE["modes"] = refreshed
        return str(refreshed.get(app_key) or "auto").strip().lower()
    except Exception:
        return "auto"


def _app_redirect_enabled(app):
    route_mode = _current_route_mode_for_app(app)
    if route_mode == "direct":
        return False
    if app == "Telegram":
        # Release-safe default: Telegram/AyuGram TCP must be handled by the
        # signed WinDivert backend because sing-box is no longer used as the
        # default fallback. Set NOVA_WINDIVERT_TELEGRAM=0 only for diagnostics.
        return _env_bool("NOVA_WINDIVERT_TELEGRAM", True)
    if app == "WhatsApp":
        return _env_bool("NOVA_WINDIVERT_WHATSAPP", True)
    if app == "Discord":
        return _env_bool("NOVA_WINDIVERT_DISCORD", True)
    return True


def _app_udp_redirect_enabled(app):
    route_mode = _current_route_mode_for_app(app)
    if route_mode == "direct":
        return False
    if app == "Telegram":
        return _env_bool("NOVA_WINDIVERT_TELEGRAM_UDP", True)
    if app == "WhatsApp":
        return _env_bool("NOVA_WINDIVERT_WHATSAPP_UDP", True)
    if app == "Discord":
        return _env_bool("NOVA_WINDIVERT_DISCORD_UDP", True)
    return False


EVENT_LABELS = {
    WINDIVERT_EVENT_FLOW_ESTABLISHED: "flow-established",
    WINDIVERT_EVENT_FLOW_DELETED: "flow-deleted",
    WINDIVERT_EVENT_SOCKET_CONNECT: "socket-connect",
}


class WINDIVERT_DATA_FLOW(ctypes.Structure):
    _fields_ = [
        ("Endpoint", ctypes.c_uint64),
        ("ParentEndpoint", ctypes.c_uint64),
        ("ProcessId", ctypes.c_uint32),
        ("LocalAddr", ctypes.c_uint32 * 4),
        ("RemoteAddr", ctypes.c_uint32 * 4),
        ("LocalPort", ctypes.c_uint16),
        ("RemotePort", ctypes.c_uint16),
        ("Protocol", ctypes.c_uint8),
    ]


class WINDIVERT_DATA_SOCKET(ctypes.Structure):
    _fields_ = [
        ("Endpoint", ctypes.c_uint64),
        ("ParentEndpoint", ctypes.c_uint64),
        ("ProcessId", ctypes.c_uint32),
        ("LocalAddr", ctypes.c_uint32 * 4),
        ("RemoteAddr", ctypes.c_uint32 * 4),
        ("LocalPort", ctypes.c_uint16),
        ("RemotePort", ctypes.c_uint16),
        ("Protocol", ctypes.c_uint8),
    ]


class WINDIVERT_DATA_NETWORK(ctypes.Structure):
    _fields_ = [
        ("IfIdx", ctypes.c_uint32),
        ("SubIfIdx", ctypes.c_uint32),
    ]


class WINDIVERT_ADDRESS_UNION(ctypes.Union):
    _fields_ = [
        ("Network", WINDIVERT_DATA_NETWORK),
        ("Flow", WINDIVERT_DATA_FLOW),
        ("Socket", WINDIVERT_DATA_SOCKET),
    ]


class WINDIVERT_ADDRESS(ctypes.Structure):
    _anonymous_ = ("Data",)
    _fields_ = [
        ("Timestamp", ctypes.c_int64),
        ("Flags", ctypes.c_uint64),
        ("Data", WINDIVERT_ADDRESS_UNION),
    ]

    @property
    def event(self):
        return int((self.Flags >> 8) & 0xFF)

    @property
    def outbound(self):
        return bool((self.Flags >> 17) & 0x1)

    def set_outbound(self, value):
        if value:
            self.Flags = int(self.Flags) | WINDIVERT_FLAG_OUTBOUND_BIT
        else:
            self.Flags = int(self.Flags) & ~WINDIVERT_FLAG_OUTBOUND_BIT

    def set_loopback(self, value):
        if value:
            self.Flags = int(self.Flags) | WINDIVERT_FLAG_LOOPBACK_BIT
        else:
            self.Flags = int(self.Flags) & ~WINDIVERT_FLAG_LOOPBACK_BIT


def _clone_address(addr):
    cloned = WINDIVERT_ADDRESS()
    ctypes.memmove(ctypes.byref(cloned), ctypes.byref(addr), ctypes.sizeof(WINDIVERT_ADDRESS))
    return cloned


def _as_inbound_address(addr):
    # WinDivert inject direction is controlled by WINDIVERT_ADDRESS.Outbound,
    # not by packet IPs. Local transparent proxy traffic must be injected into
    # the inbound path so Windows delivers it to the listening socket/client.
    cloned = _clone_address(addr)
    cloned.set_outbound(False)
    return cloned


_BEST_INTERFACE_CACHE = {}
_BEST_INTERFACE_LOCK = threading.Lock()


def _best_interface_index(ipv4):
    ip_text = str(ipv4 or "").strip()
    if not ip_text:
        return 0
    with _BEST_INTERFACE_LOCK:
        cached = _BEST_INTERFACE_CACHE.get(ip_text)
        if cached is not None:
            return int(cached)
    try:
        dest = int.from_bytes(socket.inet_aton(ip_text), "little")
        index = ctypes.c_uint32(0)
        rc = ctypes.windll.iphlpapi.GetBestInterface(ctypes.c_uint32(dest), ctypes.byref(index))
        value = int(index.value) if int(rc) == NO_ERROR else 0
    except Exception:
        value = 0
    with _BEST_INTERFACE_LOCK:
        _BEST_INTERFACE_CACHE[ip_text] = value
    return value


def _as_inbound_for_remote(addr, remote_ip):
    cloned = _as_inbound_address(addr)
    if_idx = _best_interface_index(remote_ip)
    if if_idx > 0:
        with contextlib.suppress(Exception):
            cloned.Network.IfIdx = int(if_idx)
            cloned.Network.SubIfIdx = 0
    return cloned

def _as_outbound_for_remote(addr, remote_ip):
    """
    Minimal patch: reinject as outbound (toward remote) for remote-directed traffic.
    This complements _as_inbound_for_remote by flipping the direction bit and
    preserving interface selection for the path back to the remote.
    """
    cloned = _clone_address(addr)
    # Mark as outbound so WinDivert reinjects toward the remote endpoint
    cloned.set_outbound(True)
    if_idx = _best_interface_index(remote_ip)
    if if_idx > 0:
        with contextlib.suppress(Exception):
            cloned.Network.IfIdx = int(if_idx)
            cloned.Network.SubIfIdx = 0
    return cloned


def _as_local_proxy_inbound(addr):
    # The destination was rewritten to this host's listening address, so the
    # packet must enter the inbound stack. Reinjecting it as outbound sends the
    # SYN back toward the physical gateway and the local proxy never accepts it.
    cloned = _as_inbound_address(addr)
    # Destination remains this host's LAN address, not 127.0.0.1.
    cloned.set_loopback(False)
    return cloned


class WinDivertApi:
    def __init__(self, bin_dir):
        dll_path = os.path.join(bin_dir, "WinDivert.dll")
        if not os.path.exists(dll_path):
            raise FileNotFoundError(dll_path)
        if hasattr(os, "add_dll_directory"):
            with contextlib.suppress(Exception):
                os.add_dll_directory(bin_dir)
        self.dll = ctypes.WinDLL(dll_path, use_last_error=True)
        self._configure()

    def _configure(self):
        self.dll.WinDivertOpen.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_int16, ctypes.c_uint64]
        self.dll.WinDivertOpen.restype = wintypes.HANDLE
        self.dll.WinDivertRecv.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(WINDIVERT_ADDRESS),
        ]
        self.dll.WinDivertRecv.restype = wintypes.BOOL
        self.dll.WinDivertSend.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(WINDIVERT_ADDRESS),
        ]
        self.dll.WinDivertSend.restype = wintypes.BOOL
        self.dll.WinDivertShutdown.argtypes = [wintypes.HANDLE, ctypes.c_uint]
        self.dll.WinDivertShutdown.restype = wintypes.BOOL
        self.dll.WinDivertClose.argtypes = [wintypes.HANDLE]
        self.dll.WinDivertClose.restype = wintypes.BOOL
        self.dll.WinDivertHelperCalcChecksums.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.POINTER(WINDIVERT_ADDRESS),
            ctypes.c_uint64,
        ]
        self.dll.WinDivertHelperCalcChecksums.restype = wintypes.BOOL
        self.dll.WinDivertHelperFormatIPv6Address.argtypes = [
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        self.dll.WinDivertHelperFormatIPv6Address.restype = wintypes.BOOL

    def open(self, filter_text, layer, priority, flags):
        ctypes.set_last_error(0)
        handle = self.dll.WinDivertOpen(filter_text.encode("ascii"), layer, priority, flags)
        if handle in (None, 0, ctypes.c_void_p(-1).value):
            err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
            raise ctypes.WinError(err)
        return handle

    def recv(self, handle, packet_size=0):
        addr = WINDIVERT_ADDRESS()
        recv_len = ctypes.c_uint(0)
        packet = None
        packet_ptr = None
        if int(packet_size or 0) > 0:
            packet = ctypes.create_string_buffer(int(packet_size))
            packet_ptr = ctypes.cast(packet, ctypes.c_void_p)
        ctypes.set_last_error(0)
        ok = self.dll.WinDivertRecv(
            handle,
            packet_ptr,
            int(packet_size or 0),
            ctypes.byref(recv_len),
            ctypes.byref(addr),
        )
        if not ok:
            err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
            raise ctypes.WinError(err)
        if packet is None:
            return addr, b""
        return addr, packet.raw[: recv_len.value]

    def send(self, handle, packet, addr, recalc=True):
        data = bytes(packet or b"")
        if not data:
            return 0
        buf = ctypes.create_string_buffer(data, len(data))
        if recalc:
            with contextlib.suppress(Exception):
                self.dll.WinDivertHelperCalcChecksums(buf, len(data), ctypes.byref(addr), 0)
        send_len = ctypes.c_uint(0)
        ctypes.set_last_error(0)
        ok = self.dll.WinDivertSend(handle, ctypes.cast(buf, ctypes.c_void_p), len(data), ctypes.byref(send_len), ctypes.byref(addr))
        if not ok:
            err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
            raise ctypes.WinError(err)
        return int(send_len.value)

    def shutdown(self, handle):
        with contextlib.suppress(Exception):
            self.dll.WinDivertShutdown(handle, 1)

    def close(self, handle):
        with contextlib.suppress(Exception):
            self.dll.WinDivertClose(handle)

    def format_ipv6(self, words):
        buf = ctypes.create_string_buffer(INET6_ADDRSTRLEN)
        self.dll.WinDivertHelperFormatIPv6Address(ctypes.cast(words, ctypes.POINTER(ctypes.c_uint32)), buf, len(buf))
        text = buf.value.decode("ascii", errors="ignore").strip() or "::"
        with contextlib.suppress(Exception):
            parsed = ipaddress.IPv6Address(text)
            if parsed.ipv4_mapped:
                return str(parsed.ipv4_mapped)
        return text


class ProcessResolver:
    def __init__(self, ttl=30.0):
        self.ttl = max(5.0, float(ttl or 30.0))
        self._cache = {}
        self._lock = threading.Lock()
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self._kernel32.OpenProcess.restype = wintypes.HANDLE
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self._ntdll = ctypes.WinDLL("ntdll")
        self._ntdll.NtQueryInformationProcess.argtypes = [
            wintypes.HANDLE,
            wintypes.ULONG,
            wintypes.LPVOID,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        ]
        self._ntdll.NtQueryInformationProcess.restype = wintypes.LONG

    def resolve(self, pid):
        pid = int(pid or 0)
        if pid <= 0:
            return "", None
        now = time.time()
        with self._lock:
            cached = self._cache.get(pid)
            if cached and now - cached["ts"] <= self.ttl:
                return cached["path"], cached["app"]
        path = self._query_image_path(pid)
        app = match_app_by_process_path(path) if path else None
        if not app and self._is_gemini_cli_node(path, pid):
            app = "CLI"
        if app not in {"Discord", "Telegram", "WhatsApp", "IDE", "CLI", "Games", "GamesDirect", "OBS"}:
            app = None
        with self._lock:
            self._cache[pid] = {"ts": now, "path": path, "app": app}
        return path, app

    def _query_image_path(self, pid):
        handle = self._kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return ""
        try:
            size = wintypes.DWORD(MAX_PATH)
            buffer = ctypes.create_unicode_buffer(MAX_PATH)
            ok = self._kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
            if ok:
                return buffer.value[: size.value]
            return ""
        finally:
            self._kernel32.CloseHandle(handle)

    def _is_gemini_cli_node(self, process_path, pid):
        normalized_path = str(process_path or "").replace("/", "\\").lower()
        if not normalized_path.endswith("\\node.exe"):
            return False
        command_line = str(self._query_command_line(pid) or "").replace("/", "\\").lower()
        return bool(
            "\\@google\\gemini-cli\\" in command_line
            and "\\bundle\\gemini.js" in command_line
        )

    def _query_command_line(self, pid):
        handle = self._kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return ""
        try:
            needed = wintypes.ULONG(0)
            self._ntdll.NtQueryInformationProcess(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                None,
                0,
                ctypes.byref(needed),
            )
            size = int(needed.value or 0)
            if size <= ctypes.sizeof(UNICODE_STRING) or size > (1024 * 1024):
                return ""
            buffer = ctypes.create_string_buffer(size)
            status = int(self._ntdll.NtQueryInformationProcess(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                buffer,
                size,
                ctypes.byref(needed),
            ))
            if status != 0:
                return ""
            info = ctypes.cast(buffer, ctypes.POINTER(UNICODE_STRING)).contents
            if not info.Buffer or int(info.Length or 0) <= 0:
                return ""
            return ctypes.wstring_at(info.Buffer, int(info.Length) // ctypes.sizeof(ctypes.c_wchar))
        except Exception:
            return ""
        finally:
            self._kernel32.CloseHandle(handle)


class RedirectState:
    def __init__(self):
        self._lock = threading.Lock()
        self.ready = False
        self.handles = {"network": "starting", "flow": "starting", "socket": "starting"}
        self.meta = {"elevated": False, "requires_admin": False, "last_error": ""}
        self.stats = {"redirected_tcp": 0, "restored_tcp": 0, "bypassed_tcp": 0}
        self.recent = collections.deque(maxlen=120)

    def set_handle(self, name, status):
        with self._lock:
            self.handles[str(name)] = str(status)
            self.ready = self.handles.get("network") == "open" and (
                self.handles.get("flow") == "open" or self.handles.get("socket") == "open"
            )

    def set_meta(self, key, value):
        with self._lock:
            self.meta[str(key)] = value

    def count(self, key, event=None):
        with self._lock:
            self.stats[str(key)] = int(self.stats.get(str(key), 0)) + 1
            if event:
                self.recent.appendleft(dict(event))

    def snapshot(self):
        with self._lock:
            return {
                "ts": time.time(),
                "ready": bool(self.ready),
                "handles": dict(self.handles),
                "meta": dict(self.meta),
                "stats": dict(self.stats),
                "recent_events": list(self.recent),
            }


class RedirectMap:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._entries = {"tcp": {}, "udp": {}}
        self._last_write = 0.0

    def _cleanup_locked(self):
        now = time.time()
        for bucket in list(self._entries.keys()):
            entries = self._entries.get(bucket) or {}
            expired = [key for key, value in entries.items() if float(value.get("expires", 0.0)) < now]
            for key in expired:
                entries.pop(key, None)

    def put(self, local_ip, local_port, payload, protocol="tcp"):
        proto = str(protocol or "tcp").strip().lower()
        if proto not in {"tcp", "udp"}:
            proto = "tcp"
        key = f"{local_ip}:{int(local_port)}"
        with self._lock:
            item = dict(payload or {})
            item["local_host"] = str(local_ip)
            item["local_port"] = int(local_port)
            item["protocol"] = proto
            item["updated"] = time.time()
            item["expires"] = time.time() + MAP_TTL_SECONDS
            self._entries.setdefault(proto, {})[key] = item
            self._cleanup_locked()
            # TCP bootstrap is latency-sensitive: if the redirected socket
            # reaches TgRelay/proxy before the map hits disk, Telegram stalls
            # waiting for context. Force immediate writes for TCP; keep UDP
            # coalescing to avoid unnecessary churn during media/call bursts.
            self._write_locked(force=(proto == "tcp"))

    def remove(self, local_ip, local_port, protocol="tcp"):
        proto = str(protocol or "tcp").strip().lower()
        if proto not in {"tcp", "udp"}:
            proto = "tcp"
        key = f"{local_ip}:{int(local_port)}"
        with self._lock:
            entries = self._entries.setdefault(proto, {})
            existing = entries.get(key)
            if isinstance(existing, dict):
                item = dict(existing)
                now = time.time()
                item["updated"] = now
                item["expires"] = now + MAP_REMOVE_GRACE_SECONDS
                item["closing"] = True
                entries[key] = item
            else:
                entries.pop(key, None)
            self._write_locked(force=(proto == "tcp"))

    def _write_locked(self, force=False):
        now = time.time()
        if not force and (now - self._last_write < 0.04):
            return
        self._last_write = now
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        payload = {
            "version": 2,
            "updated": now,
            "tcp": dict(self._entries.get("tcp") or {}),
            "udp": dict(self._entries.get("udp") or {}),
        }
        temp_path = f"{self.path}.tmp"
        try:
            with open(temp_path, "w", encoding="utf-8", newline="") as f:
                json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
            for _ in range(5):
                try:
                    os.replace(temp_path, self.path)
                    return
                except PermissionError:
                    time.sleep(0.03)
                except OSError as exc:
                    if getattr(exc, "winerror", None) == ERROR_ACCESS_DENIED:
                        time.sleep(0.03)
                        continue
                    raise
            # Some Windows readers keep the destination open without delete-share.
            # Do a best-effort in-place rewrite instead of killing the redirect worker.
            with open(self.path, "w", encoding="utf-8", newline="") as f:
                json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
        finally:
            with contextlib.suppress(Exception):
                if os.path.exists(temp_path):
                    os.remove(temp_path)


def _tuple_key(proto, src_ip, src_port, dst_ip, dst_port):
    return (
        str(proto or "").lower(),
        str(src_ip or "").lower(),
        int(src_port or 0),
        str(dst_ip or "").lower(),
        int(dst_port or 0),
    )


def _is_global_target(host):
    try:
        addr = ipaddress.ip_address(str(host or ""))
        return not (addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_private)
    except ValueError:
        return False


def _parse_ipv4_tcp(packet):
    data = bytes(packet or b"")
    if len(data) < 40:
        return None
    if data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl + 20:
        return None
    if int(data[9]) != IPPROTO_TCP:
        return None
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    src_port = int.from_bytes(data[ihl:ihl + 2], "big")
    dst_port = int.from_bytes(data[ihl + 2:ihl + 4], "big")
    flags = int(data[ihl + 13])
    return {
        "ihl": ihl,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
    }


def _parse_ipv4_udp(packet):
    data = bytes(packet or b"")
    if len(data) < 28:
        return None
    if data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl + 8:
        return None
    if int(data[9]) != IPPROTO_UDP:
        return None
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    src_port = int.from_bytes(data[ihl:ihl + 2], "big")
    dst_port = int.from_bytes(data[ihl + 2:ihl + 4], "big")
    return {
        "protocol": "udp",
        "ihl": ihl,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def _rewrite_ipv4_tcp(packet, *, src_ip=None, src_port=None, dst_ip=None, dst_port=None):
    data = bytearray(packet)
    ihl = (data[0] & 0x0F) * 4
    if src_ip is not None:
        data[12:16] = socket.inet_aton(str(src_ip))
    if dst_ip is not None:
        data[16:20] = socket.inet_aton(str(dst_ip))
    if src_port is not None:
        data[ihl:ihl + 2] = int(src_port).to_bytes(2, "big")
    if dst_port is not None:
        data[ihl + 2:ihl + 4] = int(dst_port).to_bytes(2, "big")
    # Let WinDivert recalculate IP/TCP checksums.
    data[10:12] = b"\x00\x00"
    tcp_header_len = ((data[ihl + 12] >> 4) & 0x0F) * 4
    if len(data) >= ihl + max(20, tcp_header_len):
        data[ihl + 16:ihl + 18] = b"\x00\x00"
    return bytes(data)


def _rewrite_ipv4_udp(packet, *, src_ip=None, src_port=None, dst_ip=None, dst_port=None):
    data = bytearray(packet)
    ihl = (data[0] & 0x0F) * 4
    if src_ip is not None:
        data[12:16] = socket.inet_aton(str(src_ip))
    if dst_ip is not None:
        data[16:20] = socket.inet_aton(str(dst_ip))
    if src_port is not None:
        data[ihl:ihl + 2] = int(src_port).to_bytes(2, "big")
    if dst_port is not None:
        data[ihl + 2:ihl + 4] = int(dst_port).to_bytes(2, "big")
    data[10:12] = b"\x00\x00"
    if len(data) >= ihl + 8:
        data[ihl + 6:ihl + 8] = b"\x00\x00"
    return bytes(data)


class RedirectService:
    def __init__(self, log_path, state_path, map_path, tcp_proxy_port=17870, udp_proxy_port=17871, telegram_relay_port=1372, filter_text="outbound and (tcp or udp) and not impostor"):
        self.base_dir = BASE_DIR
        self.bin_dir = os.path.join(self.base_dir, "bin")
        self.log_path = log_path
        self.state_path = state_path
        self.map = RedirectMap(map_path)
        self.tcp_proxy_port = int(tcp_proxy_port)
        self.udp_proxy_port = int(udp_proxy_port)
        self.telegram_relay_port = int(telegram_relay_port)
        self.filter_text = str(filter_text or "outbound and (tcp or udp) and not impostor")
        self.api = WinDivertApi(self.bin_dir)
        self.resolver = ProcessResolver()
        self.state = RedirectState()
        self._stop_event = threading.Event()
        self._threads = []
        self._handles = []
        self._write_lock = threading.Lock()
        self._flow_lock = threading.Lock()
        self._tuple_to_flow = {}
        self._flow_to_tuples = {}
        self._sessions = {}
        self._log_limiter = {}
        self._telegram_networks = _load_ip_networks(os.path.join(self.base_dir, "ip", "telegram.txt"))
        self._games_networks = _load_ip_networks(os.path.join(self.base_dir, "ip", "games.txt"))

    def _is_games_target(self, host):
        try:
            addr = ipaddress.ip_address(str(host or "").strip())
        except Exception:
            return False
        for net in self._games_networks:
            try:
                if addr in net:
                    return True
            except Exception:
                continue
        return False

    def _open_with_fallbacks(self, source, filter_candidates, layer, priority, flags):
        candidates = []
        seen = set()
        for raw in filter_candidates:
            text = str(raw or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            candidates.append(text)
        last_exc = None
        for idx, candidate in enumerate(candidates):
            try:
                if idx > 0:
                    self.log(f"[NovaDivert][Redirect] {source} filter fallback -> \"{candidate}\".")
                return self.api.open(candidate, layer, priority, flags), candidate
            except OSError as exc:
                last_exc = exc
                if getattr(exc, "winerror", None) != ERROR_INVALID_NAME or idx >= len(candidates) - 1:
                    raise
                self.log(
                    f"[NovaDivert][Redirect] {source} filter rejected (WinError 123): \"{candidate}\". "
                    "Пробуем совместимый вариант."
                )
        if last_exc:
            raise last_exc
        raise RuntimeError(f"{source} filter candidates are empty")

    def _is_telegram_target(self, host):
        try:
            addr = ipaddress.ip_address(str(host or "").strip())
        except Exception:
            return False
        for net in self._telegram_networks:
            try:
                if addr in net:
                    return True
            except Exception:
                continue
        return False

    def _service_port_for_app_family(self, app_family, target_host=None):
        family = str(app_family or "").strip().lower()
        if family == "telegram":
            if self._is_telegram_target(target_host):
                return int(self.telegram_relay_port)
            return int(self.tcp_proxy_port)
        return int(self.tcp_proxy_port)

    def _service_port_for_meta(self, meta):
        if str((meta or {}).get("protocol") or "").strip().lower() == "udp":
            return int(self.udp_proxy_port)
        return self._service_port_for_app_family(
            (meta or {}).get("app_family"),
            (meta or {}).get("remote_ip"),
        )

    def log(self, message):
        line = f"{time.strftime('%H:%M:%S')} {message}\n"
        with self._write_lock:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8", newline="") as f:
                f.write(line)

    def write_state(self):
        payload = self.state.snapshot()
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        temp_path = f"{self.state_path}.tmp"
        with open(temp_path, "w", encoding="utf-8", newline="") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(temp_path, self.state_path)

    def _format_addr(self, words):
        return self.api.format_ipv6(words)

    def _event_payload(self, source, addr):
        data = addr.Flow if source == "flow" else addr.Socket
        proto_num = int(data.Protocol)
        if proto_num not in {IPPROTO_TCP, IPPROTO_UDP}:
            return None
        pid = int(data.ProcessId)
        process_path, app = self.resolver.resolve(pid)
        if app not in APP_FAMILY:
            return None
        direct_bypass = app == "GamesDirect"
        if not direct_bypass and not _app_redirect_enabled(app):
            return None
        if proto_num == IPPROTO_UDP and (direct_bypass or not _app_udp_redirect_enabled(app)):
            return None
        local_ip = self._format_addr(data.LocalAddr)
        remote_ip = self._format_addr(data.RemoteAddr)
        if ":" in local_ip or ":" in remote_ip:
            return None
        local_port = int(data.LocalPort)
        remote_port = int(data.RemotePort)
        if not _is_global_target(remote_ip):
            return None
        protocol = "udp" if proto_num == IPPROTO_UDP else "tcp"
        flow_key = f"{protocol}|{local_ip}|{local_port}|{remote_ip}|{remote_port}|{pid}"
        return {
            "protocol": protocol,
            "source": source,
            "event": EVENT_LABELS.get(addr.event, f"event-{addr.event}"),
            "app": app,
            "app_family": APP_FAMILY.get(app, ""),
            "pid": pid,
            "exe": process_path,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "flow_key": flow_key,
            "timestamp": time.time(),
        }

    def _index_flow_payload(self, payload):
        flow_key = str(payload.get("flow_key") or "")
        if not flow_key:
            return
        protocol = str(payload.get("protocol") or "tcp").strip().lower()
        local_ip = payload["local_ip"]
        remote_ip = payload["remote_ip"]
        local_port = int(payload["local_port"])
        remote_port = int(payload["remote_port"])
        tuples = [
            _tuple_key(protocol, local_ip, local_port, remote_ip, remote_port),
            _tuple_key(protocol, remote_ip, remote_port, local_ip, local_port),
        ]
        meta = {
            "protocol": protocol,
            "app": payload.get("app"),
            "app_family": payload.get("app_family"),
            "pid": int(payload.get("pid") or 0),
            "exe": payload.get("exe") or "",
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "preferred_egress": PREFERRED_EGRESS.get(str(payload.get("app_family") or ""), 1),
            "service_port": self._service_port_for_app_family(payload.get("app_family"), remote_ip),
        }
        with self._flow_lock:
            old = self._flow_to_tuples.pop(flow_key, set())
            for item in old:
                self._tuple_to_flow.pop(item, None)
            self._flow_to_tuples[flow_key] = set(tuples)
            for item in tuples:
                self._tuple_to_flow[item] = dict(meta)
            if meta["app_family"] != "games-steam-direct":
                self._sessions[(protocol, local_ip.lower(), local_port)] = dict(meta)
        if meta["app_family"] == "games-steam-direct":
            return
        self.map.put(local_ip, local_port, {
            "target_host": remote_ip,
            "target_port": remote_port,
            "app_id": meta["exe"],
            "app_family": meta["app_family"],
            "process_id": meta["pid"],
            "preferred_egress": meta["preferred_egress"],
            "source": "windivert",
        }, protocol=protocol)

    def _remove_flow_payload(self, payload):
        flow_key = str(payload.get("flow_key") or "")
        protocol = str(payload.get("protocol") or "tcp").strip().lower()
        local_ip = str(payload.get("local_ip") or "")
        local_port = int(payload.get("local_port") or 0)
        with self._flow_lock:
            tuples = self._flow_to_tuples.pop(flow_key, set())
            for item in tuples:
                self._tuple_to_flow.pop(item, None)
            self._sessions.pop((protocol, local_ip.lower(), local_port), None)
        if local_ip and local_port:
            self.map.remove(local_ip, local_port, protocol=protocol)

    def _flow_worker(self, source, layer, priority):
        handle = None
        try:
            handle, filter_used = self._open_with_fallbacks(
                source,
                ("tcp or udp", "true"),
                layer,
                priority,
                WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY,
            )
            self._handles.append(handle)
            self.state.set_handle(source, "open")
            self.log(f"[NovaDivert][Redirect] {source} handle open filter=\"{filter_used}\".")
            while not self._stop_event.is_set():
                try:
                    addr, _packet = self.api.recv(handle, packet_size=0)
                except OSError as exc:
                    if exc.winerror in {ERROR_OPERATION_ABORTED, ERROR_INVALID_HANDLE, ERROR_NO_DATA}:
                        break
                    self.log(f"[NovaDivert][Redirect] {source} recv-error {exc}.")
                    time.sleep(0.15)
                    continue
                payload = self._event_payload(source, addr)
                if not payload:
                    continue
                if payload["event"] in {"flow-established", "socket-connect"}:
                    self._index_flow_payload(payload)
                elif payload["event"] == "flow-deleted":
                    self._remove_flow_payload(payload)
        except Exception as exc:
            if isinstance(exc, OSError) and getattr(exc, "winerror", None) == ERROR_ACCESS_DENIED:
                self.state.set_handle(source, f"access-denied: {exc}")
                self.state.set_meta("requires_admin", True)
                self.state.set_meta("last_error", "access denied")
            else:
                self.state.set_handle(source, f"error: {exc}")
                self.state.set_meta("last_error", str(exc))
            self.log(f"[NovaDivert][Redirect] {source} worker-error: {exc}")
        finally:
            if handle:
                self.api.shutdown(handle)
                self.api.close(handle)
                with contextlib.suppress(ValueError):
                    self._handles.remove(handle)
            status = str(self.state.snapshot().get("handles", {}).get(source, ""))
            if not (status.startswith("error:") or status.startswith("access-denied:")):
                self.state.set_handle(source, "closed")

    def _lookup_flow(self, parsed):
        key = _tuple_key(parsed.get("protocol") or "tcp", parsed["src_ip"], parsed["src_port"], parsed["dst_ip"], parsed["dst_port"])
        with self._flow_lock:
            return dict(self._tuple_to_flow.get(key) or {})

    def _lookup_session(self, protocol, local_ip, local_port):
        local_port = int(local_port)
        local_ip_key = str(local_ip).lower()
        protocol = str(protocol or "tcp").strip().lower()
        with self._flow_lock:
            exact = self._sessions.get((protocol, local_ip_key, local_port))
            if exact:
                return dict(exact)
            for (session_proto, _session_ip, session_port), meta in self._sessions.items():
                try:
                    if str(session_proto or "").strip().lower() != protocol:
                        continue
                    if int(session_port) == local_port:
                        return dict(meta)
                except Exception:
                    continue
        return {}

    def _should_log(self, key):
        now = time.time()
        last = float(self._log_limiter.get(key) or 0.0)
        if now - last < 5.0:
            return False
        self._log_limiter[key] = now
        return True

    def _network_worker(self):
        handle = None
        try:
            handle, filter_used = self._open_with_fallbacks(
                "network",
                (
                    self.filter_text,
                    "outbound and (tcp or udp)",
                    "outbound",
                ),
                WINDIVERT_LAYER_NETWORK,
                WINDIVERT_REDIRECT_NETWORK_PRIORITY,
                0,
            )
            self._handles.append(handle)
            self.state.set_handle("network", "open")
            self.log(
                f"[NovaDivert][Redirect] network handle open filter=\"{filter_used}\" "
                f"tcp_proxy_port={self.tcp_proxy_port} udp_proxy_port={self.udp_proxy_port} telegram_port={self.telegram_relay_port}."
            )
            while not self._stop_event.is_set():
                try:
                    addr, packet = self.api.recv(handle, packet_size=NETWORK_CAPTURE_SIZE)
                except OSError as exc:
                    if exc.winerror in {ERROR_OPERATION_ABORTED, ERROR_INVALID_HANDLE, ERROR_NO_DATA}:
                        break
                    self.log(f"[NovaDivert][Redirect] network recv-error {exc}.")
                    time.sleep(0.15)
                    continue
                if len(packet) >= 40 and (packet[0] >> 4) == 6:
                    try:
                        dst_ip = ipaddress.ip_address(packet[24:40])
                        if any(dst_ip in net for net in _TELEGRAM_IPV6_NETWORKS):
                            # Drop Telegram IPv6 packets to force fast fallback to IPv4
                            log_key = f"drop_ipv6|{dst_ip}"
                            if self._should_log(log_key):
                                self.log(f"[NovaDivert][Redirect] Dropped Telegram IPv6 packet to {dst_ip} to force fast IPv4 fallback.")
                            continue
                    except Exception:
                        pass
                modified = packet
                recalc = False
                send_addr = addr
                parsed = _parse_ipv4_tcp(packet)
                if parsed:
                    parsed["protocol"] = "tcp"
                    # Proxy -> app: restore original source so the client sees the real remote endpoint.
                    if int(parsed["src_port"]) in {self.tcp_proxy_port, self.telegram_relay_port}:
                        meta = self._lookup_session("tcp", parsed["dst_ip"], parsed["dst_port"])
                        if meta:
                            modified = _rewrite_ipv4_tcp(
                                packet,
                                src_ip=meta["remote_ip"],
                                src_port=meta["remote_port"],
                                dst_ip=meta["local_ip"],
                                dst_port=meta["local_port"],
                            )
                            recalc = True
                            send_addr = _as_inbound_for_remote(addr, meta["remote_ip"])
                            self.state.count("restored_tcp", {
                                "event": "restore",
                                "app": meta.get("app"),
                                "target": f"{meta['remote_ip']}:{meta['remote_port']}",
                            })

                    # App -> remote: redirect to the local transparent TCP proxy.
                    elif int(parsed["dst_port"]) not in {self.tcp_proxy_port, self.telegram_relay_port} and _is_global_target(parsed["dst_ip"]):
                        meta = self._lookup_flow(parsed)
                        direct_app_flow = bool(
                            meta and meta.get("app_family") == "games-steam-direct"
                        )
                        if direct_app_flow:
                            meta = {}
                        if (
                            not meta
                            and not direct_app_flow
                            and _current_route_mode_for_app("Games") != "direct"
                            and int(parsed["dst_port"]) in (80, 443)
                            and self._is_games_target(parsed["dst_ip"])
                        ):
                            # Observer may have missed the socket-connect event for the PoE
                            # patch/update server (it opens very early / from the launcher stub).
                            # Fall back to the static Games IP list so the patch connection is
                            # always intercepted and routed via WARP by the TCP proxy. Other
                            # game TCP ports use the normal process-aware Games flow metadata.
                            meta = {
                                "app": "Games",
                                "app_family": "games",
                                "exe": "",
                                "pid": 0,
                                "preferred_egress": 1,
                            }
                        if meta:
                            if meta.get("app_family") == "telegram" and not self._is_telegram_target(parsed["dst_ip"]):
                                self.state.count("bypassed_tcp")
                                continue
                            service_port = self._service_port_for_meta(meta)
                            # Redirect to the packet's local interface where
                            # the transparent proxy listens on 0.0.0.0.
                            # WinDivert loopback injection to 127.0.0.1 is
                            # unreliable on some Windows stacks and leaves
                            # clients stuck in SYN-SENT.
                            proxy_host = str(parsed.get("src_ip") or "").strip() or "127.0.0.1"
                            modified = _rewrite_ipv4_tcp(
                                packet,
                                dst_ip=proxy_host,
                                dst_port=service_port,
                            )
                            recalc = True
                            send_addr = _as_local_proxy_inbound(addr)
                            self.state.count("redirected_tcp", {
                                "event": "redirect",
                                "app": meta.get("app"),
                                "target": f"{parsed['dst_ip']}:{parsed['dst_port']}",
                            })
                            self.map.put(parsed["src_ip"], parsed["src_port"], {
                                "target_host": parsed["dst_ip"],
                                "target_port": parsed["dst_port"],
                                "app_id": meta.get("exe") or "",
                                "app_family": meta.get("app_family") or "",
                                "process_id": int(meta.get("pid") or 0),
                                "preferred_egress": int(meta.get("preferred_egress") or 1),
                                "service_port": int(service_port),
                                "source": "windivert",
                            }, protocol="tcp")
                            log_key = f"{meta.get('app')}|{parsed['dst_ip']}:{parsed['dst_port']}"
                            if self._should_log(log_key):
                                self.log(
                                    f"[NovaDivert][Redirect] tcp app={meta.get('app')} "
                                    f"{parsed['src_ip']}:{parsed['src_port']} -> {parsed['dst_ip']}:{parsed['dst_port']} "
                                    f"via {proxy_host}:{service_port}"
                                )
                        else:
                            self.state.count("bypassed_tcp")
                else:
                    parsed = _parse_ipv4_udp(packet)
                    if parsed:
                        if self.udp_proxy_port > 0 and int(parsed["src_port"]) == self.udp_proxy_port:
                            meta = self._lookup_session("udp", parsed["dst_ip"], parsed["dst_port"])
                            if meta:
                                modified = _rewrite_ipv4_udp(
                                    packet,
                                    src_ip=meta["remote_ip"],
                                    src_port=meta["remote_port"],
                                    dst_ip=meta["local_ip"],
                                    dst_port=meta["local_port"],
                                )
                                recalc = True
                                send_addr = _as_inbound_for_remote(addr, meta["remote_ip"])
                                self.state.count("restored_udp", {
                                    "event": "restore",
                                    "app": meta.get("app"),
                                    "target": f"{meta['remote_ip']}:{meta['remote_port']}",
                                })
                        elif self.udp_proxy_port > 0 and int(parsed["dst_port"]) != self.udp_proxy_port and _is_global_target(parsed["dst_ip"]):
                            meta = self._lookup_flow(parsed)
                            if meta:
                                if meta.get("app_family") == "telegram" and not self._is_telegram_target(parsed["dst_ip"]):
                                    self.state.count("bypassed_udp")
                                    continue
                                # Same rule as the TCP branch above: rewrite to
                                # the packet's own local interface, never to
                                # 127.0.0.1. A datagram with src=<LAN ip> and
                                # dst=127.0.0.1 reinjected on a non-loopback
                                # interface is dropped by the Windows stack as a
                                # martian, so the proxy never sees it and voice
                                # traffic dies silently.
                                proxy_host = str(parsed.get("src_ip") or "").strip() or "127.0.0.1"
                                modified = _rewrite_ipv4_udp(
                                    packet,
                                    dst_ip=proxy_host,
                                    dst_port=self.udp_proxy_port,
                                )
                                recalc = True
                                send_addr = _as_local_proxy_inbound(addr)
                                self.state.count("redirected_udp", {
                                    "event": "redirect",
                                    "app": meta.get("app"),
                                    "target": f"{parsed['dst_ip']}:{parsed['dst_port']}",
                                })
                                self.map.put(parsed["src_ip"], parsed["src_port"], {
                                    "target_host": parsed["dst_ip"],
                                    "target_port": parsed["dst_port"],
                                    "app_id": meta.get("exe") or "",
                                    "app_family": meta.get("app_family") or "",
                                    "process_id": int(meta.get("pid") or 0),
                                    "preferred_egress": int(meta.get("preferred_egress") or 1),
                                    "service_port": int(self.udp_proxy_port),
                                    "source": "windivert",
                                }, protocol="udp")
                                log_key = f"udp|{meta.get('app')}|{parsed['dst_ip']}:{parsed['dst_port']}"
                                if self._should_log(log_key):
                                    self.log(
                                        f"[NovaDivert][Redirect] udp app={meta.get('app')} "
                                        f"{parsed['src_ip']}:{parsed['src_port']} -> {parsed['dst_ip']}:{parsed['dst_port']} "
                                        f"via {proxy_host}:{self.udp_proxy_port}"
                                    )
                            else:
                                self.state.count("bypassed_udp")
                self.api.send(handle, modified, send_addr, recalc=recalc)
        except Exception as exc:
            if isinstance(exc, OSError) and getattr(exc, "winerror", None) == ERROR_ACCESS_DENIED:
                self.state.set_handle("network", f"access-denied: {exc}")
                self.state.set_meta("requires_admin", True)
                self.state.set_meta("last_error", "access denied")
            else:
                self.state.set_handle("network", f"error: {exc}")
                self.state.set_meta("last_error", str(exc))
            self.log(f"[NovaDivert][Redirect] network worker-error: {exc}")
        finally:
            if handle:
                self.api.shutdown(handle)
                self.api.close(handle)
                with contextlib.suppress(ValueError):
                    self._handles.remove(handle)
            status = str(self.state.snapshot().get("handles", {}).get("network", ""))
            if not (status.startswith("error:") or status.startswith("access-denied:")):
                self.state.set_handle("network", "closed")

    def _state_worker(self):
        while not self._stop_event.wait(1.0):
            with contextlib.suppress(Exception):
                self.write_state()

    def run(self):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.log_path, "w", encoding="utf-8", newline="") as f:
            f.write("")
        self.log("[NovaDivert][Redirect] starting.")
        with contextlib.suppress(Exception):
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
            self.state.set_meta("elevated", elevated)
            self.log(f"[NovaDivert][Redirect] elevated={int(elevated)}.")
        self._threads = [
            threading.Thread(target=self._network_worker, daemon=True, name="NovaDivertRedirectNetwork"),
            threading.Thread(target=self._flow_worker, args=("flow", WINDIVERT_LAYER_FLOW, WINDIVERT_REDIRECT_EVENT_PRIORITY), daemon=True, name="NovaDivertRedirectFlow"),
            threading.Thread(target=self._flow_worker, args=("socket", WINDIVERT_LAYER_SOCKET, WINDIVERT_REDIRECT_EVENT_PRIORITY + 1), daemon=True, name="NovaDivertRedirectSocket"),
            threading.Thread(target=self._state_worker, daemon=True, name="NovaDivertRedirectState"),
        ]
        for thread in self._threads:
            thread.start()
        deadline = time.time() + 2.5
        while time.time() < deadline and not self._stop_event.is_set():
            snapshot = self.state.snapshot()
            if snapshot.get("ready"):
                break
            statuses = list((snapshot.get("handles") or {}).values())
            if statuses and all(str(x).startswith("error:") or str(x).startswith("access-denied:") for x in statuses):
                break
            time.sleep(0.1)
        with contextlib.suppress(Exception):
            self.write_state()
        if not self.state.snapshot().get("ready"):
            self.log("[NovaDivert][Redirect] not ready; stopping.")
            self.stop()
            return
        try:
            while not self._stop_event.wait(0.5):
                pass
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self._stop_event.set()
        for handle in list(self._handles):
            self.api.shutdown(handle)
            self.api.close(handle)
        deadline = time.time() + 3.0
        for thread in self._threads:
            remaining = max(0.0, deadline - time.time())
            if remaining <= 0:
                break
            with contextlib.suppress(Exception):
                thread.join(timeout=remaining)
        with contextlib.suppress(Exception):
            self.write_state()
        self.log("[NovaDivert][Redirect] stopped.")


def _write_bootstrap_log(log_path, message):
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a", encoding="utf-8", newline="") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {message}\n")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Nova WinDivert TCP/UDP redirect worker")
    parser.add_argument("--log", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--map", required=True)
    parser.add_argument("--tcp-proxy-port", type=int, default=17870)
    parser.add_argument("--udp-proxy-port", type=int, default=17871)
    parser.add_argument("--telegram-relay-port", type=int, default=1372)
    parser.add_argument("--filter", default="outbound and (tcp or udp) and not impostor")
    args = parser.parse_args()
    try:
        _write_bootstrap_log(args.log, "[NovaDivert][Redirect] bootstrap.")
        RedirectService(
            log_path=args.log,
            state_path=args.state,
            map_path=args.map,
            tcp_proxy_port=args.tcp_proxy_port,
            udp_proxy_port=args.udp_proxy_port,
            telegram_relay_port=args.telegram_relay_port,
            filter_text=args.filter,
        ).run()
        return 0
    except Exception:
        _write_bootstrap_log(args.log, "[NovaDivert][Redirect] fatal:")
        for line in traceback.format_exc().splitlines():
            _write_bootstrap_log(args.log, line)
        return 1


if __name__ == "__main__":
    sys.exit(main())
