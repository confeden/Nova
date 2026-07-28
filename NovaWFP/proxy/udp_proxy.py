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
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tgrelay.udp_transport import UdpEndpoint, get_udp_upstream_attempts, open_udp_endpoint  # noqa: E402


LOG = logging.getLogger("nova.wfp.udp_proxy")
DIVERT_REDIRECT_MAP = str(os.environ.get("NOVA_DIVERT_REDIRECT_MAP", "") or "").strip()

ENVELOPE_MAGIC = b"NUP1"
ENVELOPE_FAMILY_V4 = 4
ENVELOPE_FAMILY_V6 = 6
SESSION_IDLE_TIMEOUT = float(os.environ.get("NOVA_WFP_UDP_IDLE_TIMEOUT", "30.0") or 30.0)
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
ROUTING_SETTINGS_PATH = REPO_ROOT / "temp" / "routing_settings.json"
_ROUTING_SETTINGS_CACHE: dict = {}
_ROUTING_SETTINGS_MTIME: float = -1.0
ROUTING_GROUP_ALIASES = {
    "browser": "browser",
    "telegram": "telegram",
    "whatsapp": "whatsapp",
    "discord": "discord",
    "ide": "ide",
    "cli": "cli",
    "opencode": "ide",
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
    legacy_key = "opencode" if key == "ide" else key
    mode = str(apps.get(legacy_key) or "auto").strip().lower()
    if mode not in {"auto", "warp", "opera", "direct"}:
        mode = "auto"
    return mode


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


class UdpFlowSuppressed(OSError):
    pass


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


class UdpSession:
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

    def send(self, payload: bytes):
        payload = bytes(payload or b"")
        with self.lock:
            if self.closed or self.upstream is None:
                raise OSError("session is closed")
            try:
                self.upstream.sendto(payload, self.target_host, self.target_port)
                self.last_activity = time.monotonic()
                return
            except Exception as exc:
                self.owner.log(
                    f"[NovaWFP][UDP] send-failed client={self.client_addr[0]}:{self.client_addr[1]} "
                    f"target={self.target_host}:{self.target_port} route={self.route_label} error={exc}"
                )
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
            except socket.timeout:
                if self.owner.should_close_idle(self):
                    self.close(reason="idle-timeout")
                    return
                continue
            except TimeoutError:
                if self.owner.should_close_idle(self):
                    self.close(reason="idle-timeout")
                    return
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
            f"reason={reason} duration_ms={lifetime_ms}"
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
        self._suppressed_flows: Dict[Tuple[str, int, str], float] = {}

    def log(self, line: str):
        LOG.info(line)

    @staticmethod
    def _app_family_from_app_id(app_id: str) -> str:
        lower = str(app_id or "").replace("/", "\\").lower()
        if any(token in lower for token in ("telegram.exe", "ayugram.exe", "telegram desktop")):
            return "telegram"
        if any(token in lower for token in ("discord.exe", "discordcanary.exe", "discordptb.exe", "discord\\update.exe", "discordcanary\\update.exe", "discordptb\\update.exe")):
            return "discord"
        if "whatsapp.exe" in lower or "whatsapp.root.exe" in lower or "whatsapp\\app.exe" in lower:
            return "whatsapp"
        if any(token in lower for token in ("opencode.exe", "\\opencode\\", "code.exe", "\\vscode\\", "cursor.exe", "\\cursor\\", "windsurf.exe", "\\windsurf\\", "antigravity.exe", "\\antigravity\\", "codex.exe", "\\codex\\")):
            return "ide"
        if any(token in lower for token in ("opencode-cli.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "gemini.exe", "gemini-cli.exe", "codex-cli.exe")):
            return "cli"
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
                if lower_name in {"opencode.exe", "code.exe", "cursor.exe", "windsurf.exe", "antigravity.exe", "codex.exe"}:
                    family = "ide"
                    break
                if lower_name in {"opencode-cli.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "gemini.exe", "gemini-cli.exe", "codex-cli.exe"}:
                    family = "cli"
                    break
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
            if app_family == "ide":
                preferred_egress = 2
            elif app_family == "whatsapp":
                preferred_egress = 1
            else:
                app_family = "webview2"
                preferred_egress = 3
        return app_family, preferred_egress

    def _log_udp_suppressed_once(self, app_family: str, target_host: str, target_port: int):
        key = (str(app_family or "").strip().lower(), int(target_port), str(target_host or "").strip())
        now = time.monotonic()
        expiry = float(self._suppressed_flows.get(key, 0.0) or 0.0)
        if expiry > now:
            return
        self._suppressed_flows[key] = now + 15.0
        self.log(
            f"[NovaWFP][UDP] suppress family={app_family or '-'} "
            f"target={_mask_ip_for_log(target_host)}:{int(target_port)} reason=tcp-only-eu"
        )

    def build_attempts_for_target(self, host: str, port: int, app_family: str = "", preferred_egress: int = 0):
        now = time.monotonic()
        upstream_attempts = [dict(attempt) for attempt in get_udp_upstream_attempts() if isinstance(attempt, dict)]
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
        else:
            ordered_attempts = proxy_attempts + direct_attempts

        route_mode = _get_app_route_mode(app_family) if app_family in {"discord", "telegram", "whatsapp", "ide", "cli", "obs"} else "auto"
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
                f"egress={resolved.get('preferred_egress')} app={resolved.get('app_id') or resolved.get('app_family') or '-'}"
            )
        else:
            self.log(
                f"[NovaWFP][UDP] redirect-resolve client={client_addr[0]}:{client_addr[1]} "
                f"local={resolved['local_host']}:{resolved['local_port']} "
                f"target={_mask_ip_for_log(resolved['target_host'])}:{resolved['target_port']} "
                f"egress={resolved['preferred_egress']} app={resolved['app_id']}"
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
        if app_family == "ide":
            self._log_udp_suppressed_once(app_family, str(resolved["target_host"]), int(resolved["target_port"]))
            raise UdpFlowSuppressed("OpenCode UDP suppressed to force TCP EU fallback")
        return self.get_session(
            client_addr,
            str(resolved["target_host"]),
            int(resolved["target_port"]),
            encapsulated=False,
            app_family=app_family,
            preferred_egress=preferred_egress,
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
            except UdpFlowSuppressed:
                continue
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
    return REPO_ROOT / "temp" / "NovaWfpUdpProxy.log"


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
