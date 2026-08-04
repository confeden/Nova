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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.dirname(BASE_DIR)
# resources/ - каталог собственных модулей Nova. В установленной программе
# BASE_DIR сам и есть этот каталог, поэтому лишний кандидат просто не
# существует и пропускается; при запуске из исходников именно он их и находит.
for _path in (os.path.join(BASE_DIR, "resources"), BASE_DIR, APP_DIR):
    if _path and _path not in sys.path:
        sys.path.insert(0, _path)

from nova_routing_profiles import match_app_by_process_path


WINDIVERT_LAYER_NETWORK = 0
WINDIVERT_LAYER_FLOW = 2
WINDIVERT_LAYER_SOCKET = 3

WINDIVERT_EVENT_FLOW_ESTABLISHED = 1
WINDIVERT_EVENT_FLOW_DELETED = 2
WINDIVERT_EVENT_SOCKET_BIND = 3
WINDIVERT_EVENT_SOCKET_CONNECT = 4
WINDIVERT_EVENT_SOCKET_LISTEN = 5
WINDIVERT_EVENT_SOCKET_ACCEPT = 6
WINDIVERT_EVENT_SOCKET_CLOSE = 7

WINDIVERT_FLAG_SNIFF = 1
WINDIVERT_FLAG_RECV_ONLY = 4

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MAX_PATH = 32768
INET6_ADDRSTRLEN = 64
ERROR_OPERATION_ABORTED = 995
ERROR_INVALID_HANDLE = 6
ERROR_NO_DATA = 232
ERROR_ACCESS_DENIED = 5

EVENT_LABELS = {
    WINDIVERT_EVENT_FLOW_ESTABLISHED: "flow-established",
    WINDIVERT_EVENT_FLOW_DELETED: "flow-deleted",
    WINDIVERT_EVENT_SOCKET_BIND: "socket-bind",
    WINDIVERT_EVENT_SOCKET_CONNECT: "socket-connect",
    WINDIVERT_EVENT_SOCKET_LISTEN: "socket-listen",
    WINDIVERT_EVENT_SOCKET_ACCEPT: "socket-accept",
    WINDIVERT_EVENT_SOCKET_CLOSE: "socket-close",
}

PROTO_LABELS = {
    6: "tcp",
    17: "udp",
}

NETWORK_CAPTURE_SIZE = 0xFFFF


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


class WINDIVERT_ADDRESS_UNION(ctypes.Union):
    _fields_ = [
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
    def layer(self):
        return int(self.Flags & 0xFF)

    @property
    def event(self):
        return int((self.Flags >> 8) & 0xFF)

    @property
    def outbound(self):
        return bool((self.Flags >> 17) & 0x1)

    @property
    def loopback(self):
        return bool((self.Flags >> 18) & 0x1)

    @property
    def ipv6(self):
        return bool((self.Flags >> 20) & 0x1)


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

        self.dll.WinDivertShutdown.argtypes = [wintypes.HANDLE, ctypes.c_uint]
        self.dll.WinDivertShutdown.restype = wintypes.BOOL

        self.dll.WinDivertClose.argtypes = [wintypes.HANDLE]
        self.dll.WinDivertClose.restype = wintypes.BOOL

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
        packet_len = 0
        if int(packet_size or 0) > 0:
            packet_len = int(packet_size)
            packet = ctypes.create_string_buffer(packet_len)
            packet_ptr = ctypes.cast(packet, ctypes.c_void_p)
        ctypes.set_last_error(0)
        ok = self.dll.WinDivertRecv(
            handle,
            packet_ptr,
            packet_len,
            ctypes.byref(recv_len),
            ctypes.byref(addr),
        )
        if not ok:
            err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
            raise ctypes.WinError(err)
        if packet is None:
            return addr, b""
        return addr, packet.raw[: recv_len.value]

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
        with self._lock:
            self._cache[pid] = {"ts": now, "path": path, "app": app}
        return path, app

    def _query_image_path(self, pid):
        handle = self._kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
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


class StateStore:
    def __init__(self):
        self._lock = threading.Lock()
        self.apps = {
            "Discord": {"events": 0, "flows": 0, "packets": 0, "bytes": 0},
            "Telegram": {"events": 0, "flows": 0, "packets": 0, "bytes": 0},
            "WhatsApp": {"events": 0, "flows": 0, "packets": 0, "bytes": 0},
        }
        self.recent = collections.deque(maxlen=120)
        self.active_flows = {}
        self.handles = {}
        self.meta = {
            "elevated": False,
            "requires_admin": False,
            "last_error": "",
        }

    def update(self, event):
        app = str(event.get("app") or "")
        key = str(event.get("flow_key") or "")
        kind = str(event.get("event") or "")
        with self._lock:
            bucket = self.apps.setdefault(app, {"events": 0, "flows": 0, "packets": 0, "bytes": 0})
            bucket["events"] += 1
            if kind == "flow-established" and key:
                self.active_flows[key] = dict(event)
            elif kind == "flow-deleted" and key:
                self.active_flows.pop(key, None)
            bucket["flows"] = sum(1 for item in self.active_flows.values() if item.get("app") == app)
            self.recent.appendleft(dict(event))

    def update_packet(self, event):
        app = str(event.get("app") or "")
        packet_len = int(event.get("packet_len") or 0)
        with self._lock:
            bucket = self.apps.setdefault(app, {"events": 0, "flows": 0, "packets": 0, "bytes": 0})
            bucket["packets"] += 1
            bucket["bytes"] += max(0, packet_len)
            self.recent.appendleft(dict(event))

    def snapshot(self):
        with self._lock:
            handles = dict(self.handles)
            handle_values = list(handles.values())
            network_open = handles.get("network") == "open"
            flow_visible = handles.get("flow") == "open" or handles.get("socket") == "open"
            return {
                "ts": time.time(),
                "apps": dict(self.apps),
                "active_flow_count": len(self.active_flows),
                "ready": bool(network_open and flow_visible),
                "handles": handles,
                "meta": dict(self.meta),
                "recent_events": list(self.recent),
            }

    def set_handle_status(self, source, status):
        with self._lock:
            self.handles[str(source)] = str(status)

    def set_meta(self, key, value):
        with self._lock:
            self.meta[str(key)] = value


class ObserverService:
    def __init__(self, log_path, state_path, filter_text="tcp or udp"):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.bin_dir = os.path.join(self.base_dir, "bin")
        self.log_path = log_path
        self.state_path = state_path
        self.filter_text = str(filter_text or "tcp or udp")
        self.api = WinDivertApi(self.bin_dir)
        self.resolver = ProcessResolver()
        self.state = StateStore()
        self._stop_event = threading.Event()
        self._threads = []
        self._handles = []
        self._write_lock = threading.Lock()
        self._flow_lock = threading.Lock()
        self._packet_log_counts = {}
        self._tuple_to_flow = {}
        self._flow_to_tuples = {}
        self.state.set_handle_status("network", "starting")
        self.state.set_handle_status("flow", "starting")
        self.state.set_handle_status("socket", "starting")

    def log(self, message):
        line = f"{time.strftime('%H:%M:%S')} {message}\n"
        with self._write_lock:
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
        if source == "flow":
            data = addr.Flow
        else:
            data = addr.Socket
        pid = int(data.ProcessId)
        process_path, app = self.resolver.resolve(pid)
        if app not in {"Discord", "Telegram", "WhatsApp", "IDE", "CLI", "Games", "OBS"}:
            return None
        local_ip = self._format_addr(data.LocalAddr)
        remote_ip = self._format_addr(data.RemoteAddr)
        proto = PROTO_LABELS.get(int(data.Protocol), str(int(data.Protocol)))
        event_name = EVENT_LABELS.get(addr.event, f"event-{addr.event}")
        flow_key = f"{proto}|{local_ip}|{int(data.LocalPort)}|{remote_ip}|{int(data.RemotePort)}|{pid}|{int(addr.outbound)}"
        return {
            "source": source,
            "event": event_name,
            "app": app,
            "pid": pid,
            "exe": process_path,
            "proto": proto,
            "local": f"{local_ip}:{int(data.LocalPort)}",
            "remote": f"{remote_ip}:{int(data.RemotePort)}",
            "outbound": bool(addr.outbound),
            "loopback": bool(addr.loopback),
            "flow_key": flow_key,
            "endpoint": int(data.Endpoint),
            "parent_endpoint": int(data.ParentEndpoint),
            "timestamp": time.time(),
        }

    def _packet_tuple_key(self, proto, src_ip, src_port, dst_ip, dst_port):
        return (
            str(proto or "").strip().lower(),
            str(src_ip or "").strip().lower(),
            int(src_port or 0),
            str(dst_ip or "").strip().lower(),
            int(dst_port or 0),
        )

    def _index_flow_payload(self, payload):
        try:
            flow_key = str(payload.get("flow_key") or "")
            if not flow_key:
                return
            proto = str(payload.get("proto") or "").strip().lower()
            local = str(payload.get("local") or "")
            remote = str(payload.get("remote") or "")
            local_ip, local_port = local.rsplit(":", 1)
            remote_ip, remote_port = remote.rsplit(":", 1)
            tuples = [
                self._packet_tuple_key(proto, local_ip, int(local_port), remote_ip, int(remote_port)),
                self._packet_tuple_key(proto, remote_ip, int(remote_port), local_ip, int(local_port)),
            ]
            with self._flow_lock:
                old = self._flow_to_tuples.pop(flow_key, set())
                for item in old:
                    self._tuple_to_flow.pop(item, None)
                self._flow_to_tuples[flow_key] = set(tuples)
                for item in tuples:
                    self._tuple_to_flow[item] = {
                        "app": payload.get("app"),
                        "pid": int(payload.get("pid") or 0),
                        "exe": payload.get("exe") or "",
                        "flow_key": flow_key,
                    }
        except:
            pass

    def _remove_flow_payload(self, payload):
        flow_key = str(payload.get("flow_key") or "")
        if not flow_key:
            return
        with self._flow_lock:
            tuples = self._flow_to_tuples.pop(flow_key, set())
            for item in tuples:
                self._tuple_to_flow.pop(item, None)

    def _parse_network_packet(self, packet):
        try:
            data = bytes(packet or b"")
            if len(data) < 20:
                return None
            version = data[0] >> 4
            if version == 4:
                header_len = (data[0] & 0x0F) * 4
                if header_len < 20 or len(data) < header_len + 4:
                    return None
                proto_num = int(data[9])
                if proto_num not in PROTO_LABELS:
                    return None
                src_ip = socket.inet_ntop(socket.AF_INET, data[12:16])
                dst_ip = socket.inet_ntop(socket.AF_INET, data[16:20])
                src_port = int.from_bytes(data[header_len:header_len + 2], "big")
                dst_port = int.from_bytes(data[header_len + 2:header_len + 4], "big")
                return {
                    "ip_version": 4,
                    "proto": PROTO_LABELS.get(proto_num, str(proto_num)),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "packet_len": len(data),
                }
            if version == 6:
                if len(data) < 44:
                    return None
                proto_num = int(data[6])
                if proto_num not in PROTO_LABELS:
                    return None
                src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
                dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
                src_port = int.from_bytes(data[40:42], "big")
                dst_port = int.from_bytes(data[42:44], "big")
                return {
                    "ip_version": 6,
                    "proto": PROTO_LABELS.get(proto_num, str(proto_num)),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "packet_len": len(data),
                }
        except:
            return None
        return None

    def _network_payload(self, addr, packet):
        parsed = self._parse_network_packet(packet)
        if not parsed:
            return None
        tuple_key = self._packet_tuple_key(
            parsed["proto"],
            parsed["src_ip"],
            parsed["src_port"],
            parsed["dst_ip"],
            parsed["dst_port"],
        )
        with self._flow_lock:
            flow_meta = dict(self._tuple_to_flow.get(tuple_key) or {})
        app = str(flow_meta.get("app") or "")
        if app not in {"Discord", "Telegram", "WhatsApp"}:
            return None
        return {
            "source": "network",
            "event": "packet",
            "app": app,
            "pid": int(flow_meta.get("pid") or 0),
            "exe": flow_meta.get("exe") or "",
            "proto": parsed["proto"],
            "local": f"{parsed['src_ip']}:{parsed['src_port']}",
            "remote": f"{parsed['dst_ip']}:{parsed['dst_port']}",
            "outbound": bool(addr.outbound),
            "loopback": bool(addr.loopback),
            "flow_key": str(flow_meta.get("flow_key") or ""),
            "packet_len": int(parsed["packet_len"]),
            "ip_version": int(parsed["ip_version"]),
            "timestamp": time.time(),
        }

    def _worker(self, source, layer, priority, flags):
        handle = None
        try:
            handle = self.api.open(self.filter_text, layer, priority, flags)
            self._handles.append(handle)
            self.state.set_handle_status(source, "open")
            self.log(f"[NovaDivert] {source} handle open layer={layer} filter=\"{self.filter_text}\".")
            while not self._stop_event.is_set():
                try:
                    packet_size = NETWORK_CAPTURE_SIZE if source == "network" else 0
                    addr, packet = self.api.recv(handle, packet_size=packet_size)
                except OSError as exc:
                    if exc.winerror in {ERROR_OPERATION_ABORTED, ERROR_INVALID_HANDLE, ERROR_NO_DATA}:
                        break
                    self.log(f"[NovaDivert] {source} recv-error winerror={exc.winerror} message={exc}.")
                    time.sleep(0.25)
                    continue
                if source == "network":
                    payload = self._network_payload(addr, packet)
                    if not payload:
                        continue
                    self.state.update_packet(payload)
                    flow_key = str(payload.get("flow_key") or "") or f"{payload['app']}|{payload['proto']}|{payload['local']}|{payload['remote']}"
                    log_count = int(self._packet_log_counts.get(flow_key) or 0) + 1
                    self._packet_log_counts[flow_key] = log_count
                    if log_count <= 2 or log_count in {8, 32, 128}:
                        self.log(
                            f"[NovaDivert] network packet app={payload['app']} pid={payload['pid']} "
                            f"proto={payload['proto']} len={payload['packet_len']} "
                            f"{payload['local']} -> {payload['remote']} outbound={int(payload['outbound'])}"
                        )
                else:
                    payload = self._event_payload(source, addr)
                    if not payload:
                        continue
                    self.state.update(payload)
                    if payload["event"] == "flow-established":
                        self._index_flow_payload(payload)
                    elif payload["event"] == "flow-deleted":
                        self._remove_flow_payload(payload)
                    self.log(
                        f"[NovaDivert] {payload['source']} {payload['event']} app={payload['app']} "
                        f"pid={payload['pid']} proto={payload['proto']} {payload['local']} -> {payload['remote']} "
                        f"outbound={int(payload['outbound'])}"
                    )
        except Exception as exc:
            if isinstance(exc, OSError) and getattr(exc, "winerror", None) == ERROR_ACCESS_DENIED:
                self.state.set_handle_status(source, f"access-denied: {exc}")
                self.state.set_meta("requires_admin", True)
                self.state.set_meta("last_error", "access denied")
            else:
                self.state.set_handle_status(source, f"error: {exc}")
                self.state.set_meta("last_error", str(exc))
            self.log(f"[NovaDivert] {source} worker-error: {exc}")
        finally:
            if handle:
                self.api.shutdown(handle)
                self.api.close(handle)
                with contextlib.suppress(ValueError):
                    self._handles.remove(handle)
            handle_status = str(self.state.snapshot().get("handles", {}).get(source, ""))
            if not (handle_status.startswith("error:") or handle_status.startswith("access-denied:")):
                self.state.set_handle_status(source, "closed")

    def _state_worker(self):
        while not self._stop_event.wait(2.0):
            with contextlib.suppress(Exception):
                self.write_state()

    def run(self):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.log_path, "w", encoding="utf-8", newline="") as f:
            f.write("")
        self.log("[NovaDivert] observer starting.")
        with contextlib.suppress(Exception):
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
            self.state.set_meta("elevated", elevated)
            self.log(f"[NovaDivert] elevated={int(elevated)}.")
        self._threads = [
            threading.Thread(
                target=self._worker,
                args=("network", WINDIVERT_LAYER_NETWORK, 1249, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY),
                daemon=True,
                name="NovaDivertNetwork",
            ),
            threading.Thread(
                target=self._worker,
                args=("flow", WINDIVERT_LAYER_FLOW, 1250, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY),
                daemon=True,
                name="NovaDivertFlow",
            ),
            threading.Thread(
                target=self._worker,
                args=("socket", WINDIVERT_LAYER_SOCKET, 1251, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY),
                daemon=True,
                name="NovaDivertSocket",
            ),
            threading.Thread(target=self._state_worker, daemon=True, name="NovaDivertState"),
        ]
        for thread in self._threads:
            thread.start()
        deadline = time.time() + 2.0
        while time.time() < deadline and not self._stop_event.is_set():
            snapshot = self.state.snapshot()
            statuses = list((snapshot.get("handles") or {}).values())
            if bool(snapshot.get("ready")):
                break
            if statuses and all(str(status).startswith("error:") or str(status).startswith("access-denied:") for status in statuses):
                break
            time.sleep(0.1)
        snapshot = self.state.snapshot()
        statuses = list((snapshot.get("handles") or {}).values())
        if not bool(snapshot.get("ready")):
            if statuses and all(str(status).startswith("access-denied:") for status in statuses):
                self.state.set_meta("requires_admin", True)
                self.state.set_meta("last_error", "access denied")
                self.log("[NovaDivert] handles blocked by access denied; run Nova elevated.")
            elif any(status == "open" for status in statuses):
                self.log("[NovaDivert] partial handle set is not enough for signed-backend; observer stopping.")
            self.log("[NovaDivert] no handles opened; observer stopping.")
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
        self.log("[NovaDivert] observer stopped.")


def main():
    parser = argparse.ArgumentParser(description="Nova WinDivert observer (FLOW/SOCKET proof-of-concept)")
    parser.add_argument("--log", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--filter", default="tcp or udp")
    args = parser.parse_args()
    ObserverService(log_path=args.log, state_path=args.state, filter_text=args.filter).run()


if __name__ == "__main__":
    main()
