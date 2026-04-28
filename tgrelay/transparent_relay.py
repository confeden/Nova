import asyncio
import contextlib
import json
import os
import ipaddress
import logging
import socket
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .config import (
    CFPROXY_DEFAULT_DOMAINS,
    get_cfproxy_domains,
    get_cfproxy_primary_domains,
    proxy_config,
    start_cfproxy_domain_refresh,
)
from .raw_websocket import RawWebSocket, WsHandshakeError, set_sock_opts
from .transport import open_stream, open_tls_stream, set_upstream_provider


log = logging.getLogger("nova.telegram.relay")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ZERO_64 = b"\x00" * 64
PROTO_ABRIDGED = 0xEFEFEFEF
PROTO_INTERMEDIATE = 0xEEEEEEEE
PROTO_PADDED_INTERMEDIATE = 0xDDDDDDDD
TG_TCP_PORTS = {80, 443, 5222, *range(7300, 7311)}
WS_POOL_MAX_AGE = 120.0


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(str(name), None)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    try:
        return max(float(minimum), float(os.environ.get(str(name), str(default)) or default))
    except Exception:
        return float(default)


FIRST_BYTE_STALL_RETRY = _env_bool("NOVA_TG_RELAY_FIRST_BYTE_RETRY", False)
FALLBACK_LOG_INTERVAL = _env_float("NOVA_TG_RELAY_FALLBACK_LOG_INTERVAL", 8.0, minimum=1.0)
CF_FALLBACK_ENABLED = _env_bool("NOVA_TG_RELAY_CF_FALLBACK", True)
CF_FIRST_DCS = {
    int(item)
    for item in str(os.environ.get("NOVA_TG_RELAY_CF_FIRST_DCS", "1,5") or "").replace(";", ",").split(",")
    if item.strip().isdigit()
}
CF_FIRST_MEDIA_DCS = {
    int(item)
    for item in str(os.environ.get("NOVA_TG_RELAY_CF_FIRST_MEDIA_DCS", "5") or "").replace(";", ",").split(",")
    if item.strip().isdigit()
}

_TG_EXACT_TARGETS: Dict[str, Tuple[int, bool]] = {
    # DC1
    "149.154.175.50": (1, False),
    "149.154.175.51": (1, False),
    "149.154.175.53": (1, False),
    "149.154.175.54": (1, False),
    "149.154.175.52": (1, True),
    # DC2
    "149.154.167.35": (2, False),
    "149.154.167.36": (2, False),
    "149.154.167.41": (2, False),
    "149.154.167.50": (2, False),
    "149.154.167.51": (2, False),
    "149.154.167.220": (2, False),
    "95.161.76.100": (2, False),
    "149.154.162.123": (2, True),
    "149.154.167.151": (2, True),
    "149.154.167.222": (2, True),
    "149.154.167.223": (2, True),
    "149.154.167.99": (2, True),
    # DC3
    "149.154.175.100": (3, False),
    "149.154.175.101": (3, False),
    "149.154.175.102": (3, True),
    # DC4
    "149.154.164.250": (4, True),
    "149.154.165.111": (4, True),
    "149.154.166.120": (4, True),
    "149.154.166.121": (4, True),
    "149.154.167.91": (4, False),
    "149.154.167.92": (4, False),
    "149.154.167.118": (4, True),
    # DC5
    "91.108.56.100": (5, False),
    "91.108.56.101": (5, False),
    "91.108.56.102": (5, True),
    "91.108.56.116": (5, False),
    "91.108.56.126": (5, False),
    "91.108.56.128": (5, True),
    "91.108.56.123": (5, True),
    "91.108.56.151": (5, True),
    "149.154.171.5": (5, False),
    # DC203
    "91.105.192.100": (203, False),
}

_TG_IPV4_RANGES = [
    (int(ipaddress.IPv4Address("5.28.195.0")), int(ipaddress.IPv4Address("5.28.195.255"))),
    (int(ipaddress.IPv4Address("185.76.151.0")), int(ipaddress.IPv4Address("185.76.151.255"))),
    (int(ipaddress.IPv4Address("149.154.160.0")), int(ipaddress.IPv4Address("149.154.175.255"))),
    (int(ipaddress.IPv4Address("91.105.192.0")), int(ipaddress.IPv4Address("91.105.193.255"))),
    (int(ipaddress.IPv4Address("91.108.0.0")), int(ipaddress.IPv4Address("91.108.255.255"))),
]

_TG_IPV6_PREFIXES = [
    ipaddress.ip_network("2001:067c:04e8:f000::/52"),
    ipaddress.ip_network("2001:0b28:f23d:f000::/52"),
    ipaddress.ip_network("2001:0b28:f23f:f000::/52"),
]

_TG_WS_REDIRECT_IPS: Dict[int, str] = {
    2: "149.154.167.220",
    4: "149.154.167.220",
    203: "149.154.167.220",
}

_TG_TCP_FALLBACK_IPS: Dict[int, str] = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "149.154.171.5",
    203: "91.105.192.100",
}


@dataclass
class TransparentInitInfo:
    proto: int
    dc: int = 0
    is_media: bool = False


class TransparentMsgSplitter:
    def __init__(self, init_data: bytes, proto: int):
        if len(init_data) < 56:
            raise ValueError("init packet too short")
        self._stream = _new_ctr(init_data[8:40], init_data[40:56])
        self._stream.update(ZERO_64)
        self._proto = _proto_to_type(proto)
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk: bytes) -> List[bytes]:
        if not chunk:
            return []
        if self._disabled:
            return [bytes(chunk)]
        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(self._stream.update(chunk))
        parts: List[bytes] = []
        while True:
            packet_len = self._peek_packet_size()
            if packet_len < 0:
                return parts
            if packet_len == 0:
                tail = self.flush()
                if tail:
                    parts.extend(tail)
                self._disabled = True
                return parts
            if len(self._cipher_buf) < packet_len or len(self._plain_buf) < packet_len:
                return parts
            parts.append(bytes(self._cipher_buf[:packet_len]))
            del self._cipher_buf[:packet_len]
            del self._plain_buf[:packet_len]

    def flush(self) -> List[bytes]:
        if not self._cipher_buf:
            return []
        tail = bytes(self._cipher_buf)
        self._cipher_buf.clear()
        self._plain_buf.clear()
        return [tail]

    def _peek_packet_size(self) -> int:
        if not self._plain_buf:
            return -1
        if self._proto == 0:
            return self._peek_abridged_packet_size()
        if self._proto in (1, 2):
            return self._peek_intermediate_packet_size()
        return 0

    def _peek_abridged_packet_size(self) -> int:
        length_tag = self._plain_buf[0] & 0x7F
        header_size = 1
        if length_tag == 0x7F:
            if len(self._plain_buf) < 4:
                return -1
            header_size = 4
            payload_size = ((self._plain_buf[1]) | (self._plain_buf[2] << 8) | (self._plain_buf[3] << 16)) * 4
        else:
            payload_size = int(length_tag) * 4
        if payload_size <= 0:
            return 0
        frame_size = header_size + payload_size
        if len(self._plain_buf) < frame_size:
            return -1
        return frame_size

    def _peek_intermediate_packet_size(self) -> int:
        if len(self._plain_buf) < 4:
            return -1
        payload_size = struct.unpack("<I", self._plain_buf[:4])[0] & 0x7FFFFFFF
        if payload_size <= 0:
            return 0
        frame_size = 4 + payload_size
        if len(self._plain_buf) < frame_size:
            return -1
        return frame_size


def _new_ctr(key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    return cipher.encryptor()


def _valid_proto(proto: int) -> bool:
    return proto in (PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED_INTERMEDIATE)


def _proto_label(proto: int) -> str:
    if proto == PROTO_ABRIDGED:
        return "abridged"
    if proto == PROTO_INTERMEDIATE:
        return "intermediate"
    if proto == PROTO_PADDED_INTERMEDIATE:
        return "padded-intermediate"
    return f"0x{proto:08x}"


def _proto_to_type(proto: int) -> int:
    if proto == PROTO_INTERMEDIATE:
        return 1
    if proto == PROTO_PADDED_INTERMEDIATE:
        return 2
    return 0


def parse_transparent_init_info(data: bytes) -> Optional[TransparentInitInfo]:
    if len(data) < 64:
        return None
    try:
        stream = _new_ctr(data[8:40], data[40:56])
    except Exception:
        return None
    keystream = stream.update(ZERO_64)
    plain = bytes(data[56 + i] ^ keystream[56 + i] for i in range(8))
    proto = struct.unpack("<I", plain[:4])[0]
    if not _valid_proto(proto):
        return None
    dc_idx = struct.unpack("<h", plain[4:6])[0]
    dc_abs = abs(int(dc_idx))
    info = TransparentInitInfo(proto=proto)
    if 1 <= dc_abs <= 203:
        info.dc = dc_abs
        info.is_media = dc_idx < 0
    return info


def _ws_domains(dc: int, is_media: bool) -> List[str]:
    if int(dc or 0) == 203:
        dc = 2
    if is_media:
        return [f"kws{dc}-1.web.telegram.org", f"kws{dc}.web.telegram.org"]
    return [f"kws{dc}.web.telegram.org"]


def _cf_ws_domains_for_bases(dc: int, bases: List[str], is_media: bool = False) -> List[str]:
    domains: List[str] = []
    for base in bases:
        domain_base = str(base or "").strip().lower()
        if not domain_base:
            continue
        # For custom/user CF domains Flowseal's own guide uses only kwsN
        # records. Keep kwsN-1 for Telegram-owned web.telegram.org domains,
        # but do not require separate kwsN-1 records on user domains.
        if is_media and domain_base.endswith(".web.telegram.org"):
            domains.append(f"kws{int(dc)}-1.{domain_base}")
        domains.append(f"kws{int(dc)}.{domain_base}")
    seen = set()
    return [item for item in domains if not (item in seen or seen.add(item))]


def _cf_ws_domains(dc: int, is_media: bool = False) -> List[str]:
    bases = get_cfproxy_domains("NOVA_TG_RELAY_CF_DOMAINS")
    return _cf_ws_domains_for_bases(int(dc), list(bases or []), bool(is_media))


def _has_custom_cfproxy_domain() -> bool:
    try:
        bases = get_cfproxy_domains("NOVA_TG_RELAY_CF_DOMAINS")
    except Exception:
        bases = []
    for base in bases:
        if str(base or "").strip().lower() == "nova-app.eu":
            return True
    return False


def _cf_ws_domain_bases(primary_only: bool = False) -> List[str]:
    if primary_only:
        return get_cfproxy_primary_domains("NOVA_TG_RELAY_CF_DOMAINS")
    return get_cfproxy_domains("NOVA_TG_RELAY_CF_DOMAINS")


def _canonical_dc_ips(dc: int) -> List[str]:
    mapping = {
        1: ["149.154.175.50"],
        2: ["149.154.167.220", "149.154.167.50", "149.154.167.41", "149.154.167.51"],
        3: ["149.154.175.100"],
        4: ["149.154.167.220", "149.154.167.91", "5.28.195.2"],
        5: ["149.154.171.5", "91.108.56.100", "91.108.56.101", "91.108.56.116", "91.108.56.126", "91.108.56.102", "91.108.56.128", "91.108.56.151", "173.239.243.185", "91.108.56.123"],
        203: ["91.105.192.100"],
    }
    return list(mapping.get(int(dc), []))


def _domain_dc(domain: str) -> int:
    domain = str(domain or "").strip().lower()
    if domain.startswith("pluto") or domain.startswith("kws1"):
        return 1
    if domain.startswith("venus") or domain.startswith("kws2"):
        return 2
    if domain.startswith("aurora") or domain.startswith("kws3"):
        return 3
    if domain.startswith("vesta") or domain.startswith("kws4"):
        return 4
    if domain.startswith("flora") or domain.startswith("kws5"):
        return 5
    if domain.startswith("kws203"):
        return 203
    return 0


def _target_dc_hint(target_ip: str, is_media: bool = False) -> int:
    target_ip = str(target_ip or "").strip().lower()
    if not target_ip:
        return 0
    if target_ip in _TG_EXACT_TARGETS:
        return _TG_EXACT_TARGETS[target_ip][0]
    if target_ip == "173.239.243.185":
        return 5
    if target_ip == "5.28.195.2":
        return 4
    if target_ip == "149.154.167.220":
        return 4 if is_media else 2
    if target_ip in {"149.154.167.92", "149.154.167.255"}:
        return 4
    if target_ip in {"149.154.167.50", "149.154.167.41"}:
        return 2
    try:
        addr = ipaddress.ip_address(target_ip)
    except ValueError:
        return 0
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in ipaddress.ip_network("91.108.56.0/22") or addr in ipaddress.ip_network("149.154.171.0/24"):
            return 5
        if addr == ipaddress.ip_address("149.154.167.50") or addr == ipaddress.ip_address("149.154.167.41"):
            return 2
        if addr == ipaddress.ip_address("149.154.167.91") or addr == ipaddress.ip_address("149.154.167.255"):
            return 4
        if addr == ipaddress.ip_address("149.154.167.51"):
            return 2
        if addr in ipaddress.ip_network("149.154.167.0/24"):
            return 2
        if addr == ipaddress.ip_address("149.154.175.50"):
            return 1
        if addr == ipaddress.ip_address("149.154.175.100"):
            return 3
        if addr == ipaddress.ip_address("91.105.192.100"):
            return 203
    else:
        if addr in ipaddress.ip_network("2001:067c:04e8:f002::/64"):
            return 2
        if addr in ipaddress.ip_network("2001:067c:04e8:f004::/64"):
            return 4
        if addr in ipaddress.ip_network("2001:0b28:f23f:f005::/64"):
            return 5
    return 0


def _likely_media_target(target_ip: str, target_port: int, dc_hint: int) -> bool:
    info = _TG_EXACT_TARGETS.get(str(target_ip or "").strip().lower())
    if info is not None:
        return bool(info[1])
    if str(target_ip or "").strip().lower() in {"5.28.195.2", "149.154.167.91", "149.154.167.92", "149.154.167.99", "149.154.167.255"}:
        return True
    if 7300 <= int(target_port) <= 7310:
        return False
    return int(dc_hint or 0) == 4 and int(target_port or 0) in (80, 443)


def _preferred_ws_target(target_ip: str, dc_hint: int, is_media: bool) -> str:
    target_ip = str(target_ip or "").strip()
    if int(dc_hint or 0) in (2, 4):
        if dc_hint == 2:
            return "149.154.167.220"
        if dc_hint == 4 and (is_media or target_ip in {"5.28.195.2", "149.154.167.91", "149.154.167.255"}):
            return "149.154.167.220"
    return target_ip


def _is_telegram_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(host or "").strip())
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        value = int(addr)
        for lo, hi in _TG_IPV4_RANGES:
            if lo <= value <= hi:
                return True
        return False
    return any(addr in prefix for prefix in _TG_IPV6_PREFIXES)


def _is_telegram_domain(host: str) -> bool:
    host = str(host or "").strip().lower()
    return (
        host.endswith(".telegram.org")
        or host in {"telegram.org", "t.me", "telegra.ph", "telegram.me", "telesco.pe", "tdesktop.com"}
        or host.endswith(".tdesktop.com")
    )


def _wss_candidate(target_host: str, target_ip: str, target_port: int) -> bool:
    if int(target_port or 0) not in TG_TCP_PORTS:
        return False
    return _is_telegram_ip(target_ip) or _is_telegram_domain(target_host)


async def _resolve_ip(host: str) -> str:
    host = str(host or "").strip()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    def _resolve():
        try:
            # Prefer IPv4 for Telegram cold start on the target networks: IPv6/AAAA
            # answers can exist in DNS but still be slower or degraded on the ISP path.
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            for family, _, _, _, sockaddr in infos:
                if family == socket.AF_INET:
                    return sockaddr[0]
            for _, _, _, _, sockaddr in infos:
                if sockaddr:
                    return sockaddr[0]
        except Exception:
            return host
        return host

    return await asyncio.to_thread(_resolve)


async def _connect_websocket_target(host: str, domain: str, timeout: float = 8.0):
    reader, writer, upstream_label = await open_tls_stream(host, 443, server_hostname=domain, timeout=timeout)
    set_sock_opts(writer.transport, proxy_config.buffer_size)
    ws_key = struct.pack("!QQ", int(time.time() * 1000), int(time.perf_counter_ns() & 0xFFFFFFFFFFFFFFFF))
    import base64
    req = (
        "GET /apiws HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {base64.b64encode(ws_key).decode()}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: binary\r\n"
        "Origin: https://web.telegram.org\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
        "\r\n"
    ).encode("ascii", "ignore")
    writer.write(req)
    await writer.drain()

    response_lines = []
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if line in (b"\r\n", b"\n", b""):
            break
        response_lines.append(line.decode("utf-8", errors="replace").strip())
    if not response_lines:
        writer.close()
        await writer.wait_closed()
        raise WsHandshakeError(0, "empty response")
    first_line = response_lines[0]
    parts = first_line.split(" ", 2)
    status_code = 0
    try:
        if len(parts) >= 2:
            status_code = int(parts[1])
    except Exception:
        status_code = 0
    if status_code != 101:
        headers = {}
        for item in response_lines[1:]:
            if ":" in item:
                k, v = item.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        writer.close()
        await writer.wait_closed()
        raise WsHandshakeError(status_code, first_line, headers, location=headers.get("location"))
    return RawWebSocket(reader, writer), upstream_label


class _TelegramWsPool:
    def __init__(self):
        self._idle: Dict[Tuple[int, bool], deque] = {}
        self._refilling = set()

    async def get(self, dc: int, is_media: bool, target_ip: str, domains: List[str]):
        key = (int(dc), bool(is_media))
        now = time.monotonic()
        bucket = self._idle.setdefault(key, deque())
        while bucket:
            ws, created, route_label = bucket.popleft()
            age = now - created
            try:
                transport_closing = bool(ws.writer.transport.is_closing())
            except Exception:
                transport_closing = True
            if age > WS_POOL_MAX_AGE or getattr(ws, "_closed", False) or transport_closing:
                with contextlib.suppress(Exception):
                    await ws.close()
                continue
            self._schedule_refill(key, target_ip, domains)
            return ws, route_label
        self._schedule_refill(key, target_ip, domains)
        return None, ""

    def _schedule_refill(self, key, target_ip: str, domains: List[str]):
        if key in self._refilling:
            return
        if int(getattr(proxy_config, "pool_size", 0) or 0) <= 0:
            return
        self._refilling.add(key)
        asyncio.create_task(self._refill(key, target_ip, domains))

    async def _refill(self, key, target_ip: str, domains: List[str]):
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = max(0, int(getattr(proxy_config, "pool_size", 4) or 4) - len(bucket))
            if needed <= 0:
                return
            for _ in range(needed):
                ws = None
                route_label = ""
                for domain in domains:
                    try:
                        ws, upstream_label = await _connect_websocket_target(target_ip, domain, timeout=6.0)
                        route_label = f"{domain}@{target_ip} via {upstream_label}"
                        break
                    except WsHandshakeError as exc:
                        if exc.is_redirect:
                            continue
                        break
                    except Exception:
                        break
                if ws is not None:
                    bucket.append((ws, time.monotonic(), route_label))
        finally:
            self._refilling.discard(key)

    def warmup(self):
        for dc, target_ip in _TG_WS_REDIRECT_IPS.items():
            for is_media in (False, True):
                self._schedule_refill((int(dc), bool(is_media)), target_ip, _ws_domains(dc, is_media))


_WS_POOL = _TelegramWsPool()


async def _bridge_streams(reader1, writer1, reader2, writer2):
    async def _pipe(src, dst):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        finally:
            with contextlib.suppress(Exception):
                dst.close()

    tasks = [asyncio.create_task(_pipe(reader1, writer2)), asyncio.create_task(_pipe(reader2, writer1))]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
        with contextlib.suppress(Exception):
            await task
    for task in done:
        with contextlib.suppress(Exception):
            await task


async def _bridge_ws(reader, writer, ws: RawWebSocket, splitter: Optional[TransparentMsgSplitter]):
    async def _close_ws():
        with contextlib.suppress(Exception):
            close_fn = getattr(ws, "close", None)
            if callable(close_fn):
                result = close_fn()
                if asyncio.iscoroutine(result):
                    await result
                return
            close_fn = getattr(ws, "Close", None)
            if callable(close_fn):
                close_fn()

    async def _client_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    if splitter:
                        tail = splitter.flush()
                        if tail:
                            if len(tail) == 1:
                                await ws.send(tail[0])
                            else:
                                await ws.send_batch(tail)
                    return
                if splitter:
                    parts = splitter.split(data)
                    if not parts:
                        continue
                    if len(parts) == 1:
                        await ws.send(parts[0])
                    else:
                        await ws.send_batch(parts)
                else:
                    await ws.send(data)
        finally:
            await _close_ws()

    async def _ws_to_client():
        try:
            while True:
                payload = await ws.recv()
                if payload is None:
                    return
                if not payload:
                    continue
                writer.write(payload)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
            return
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    tasks = [asyncio.create_task(_client_to_ws()), asyncio.create_task(_ws_to_client())]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
        with contextlib.suppress(Exception):
            await task
    for task in done:
        with contextlib.suppress(Exception):
            await task


class TelegramTransparentRelayServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 1376, log_func=None, upstream_provider=None, warp_bootstrap_waiter=None):
        self.host = host
        self.port = int(port)
        self.log_func = log_func or (lambda msg: log.info(msg))
        self.upstream_provider = upstream_provider
        self.warp_bootstrap_waiter = warp_bootstrap_waiter
        self.thread = None
        self.loop = None
        self.server = None
        self.stop_event = None
        self.started_event = threading.Event()
        self.running = False
        self._cf_started = False
        self._no_probe_until: Dict[Tuple[str, int], float] = {}
        self._prefer_direct_until: Dict[Tuple[int, str], float] = {}
        self._route_preference_until: Dict[Tuple[str, int], Tuple[str, float]] = {}
        self._last_fallback_log: Dict[Tuple[str, str, int, str], float] = {}
        self._cf_bootstrap_probe_logged: Dict[int, float] = {}
        self._cf_last_good_domain: Dict[Tuple[int, bool], Tuple[str, float]] = {}
        self._cf_prewarm_started: Dict[Tuple[int, bool], float] = {}
        self._cf_idle: Dict[Tuple[int, bool, bool], deque] = {}
        self._cf_refilling = set()

    def _divert_state_path(self) -> str:
        return str(
            os.environ.get(
                "NOVA_DIVERT_REDIRECT_MAP",
                os.path.join(REPO_ROOT, "temp", "NovaDivertRedirectMap.json"),
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

    def start(self, timeout: float = 8.0) -> bool:
        if self.thread and self.thread.is_alive():
            return True
        self.started_event.clear()
        self.thread = threading.Thread(target=self._thread_main, daemon=True, name="NovaTelegramRelay")
        self.thread.start()
        self.started_event.wait(timeout=timeout)
        return bool(self.running)

    def stop(self, timeout: float = 5.0) -> None:
        if self.loop and self.stop_event:
            try:
                self.loop.call_soon_threadsafe(self.stop_event.set)
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=timeout)
        self.thread = None
        self.loop = None
        self.server = None
        self.stop_event = None
        self.running = False

    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        self.loop = loop
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(self._loop_exception_handler)
        self.stop_event = asyncio.Event()
        set_upstream_provider(self.upstream_provider)
        with contextlib.suppress(Exception):
            import concurrent.futures
            loop.set_default_executor(
                concurrent.futures.ThreadPoolExecutor(
                    max_workers=48,
                    thread_name_prefix="NovaTgRelayIO",
                )
            )
        try:
            loop.run_until_complete(self._run())
        except Exception as exc:
            self.log_func(f"[TgRelay] Ошибка запуска: {exc}")
        finally:
            self.running = False
            self.started_event.set()
            with contextlib.suppress(Exception):
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    def _loop_exception_handler(self, loop, context):
        exc = (context or {}).get("exception")
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError)):
            return
        try:
            msg = (context or {}).get("message") or str(exc or "unknown")
            self.log_func(f"[TgRelay] asyncio warning: {msg}")
        except Exception:
            pass

    async def _run(self):
        proxy_config.buffer_size = max(64 * 1024, int(getattr(proxy_config, "buffer_size", 256 * 1024)))
        if not self._cf_started:
            proxy_config.cfproxy_domains = get_cfproxy_domains("NOVA_TG_RELAY_CF_DOMAINS")
            proxy_config.active_cfproxy_domain = proxy_config.active_cfproxy_domain or (proxy_config.cfproxy_domains[0] if proxy_config.cfproxy_domains else "")
            proxy_config.fallback_cfproxy = bool(CF_FALLBACK_ENABLED)
            self._cf_started = True
        try:
            if int(getattr(proxy_config, "pool_size", 0) or 0) <= 0:
                proxy_config.pool_size = 4
            _WS_POOL.warmup()
        except Exception:
            pass
        try:
            cf_preview = ", ".join((proxy_config.cfproxy_domains or [])[:3])
            if cf_preview:
                self.log_func(f"[TgRelay] CF proxy domains: {cf_preview}")
        except Exception:
            pass
        try:
            if _has_custom_cfproxy_domain():
                warmup_dcs = sorted({1, 2, 5, *CF_FIRST_DCS})
                for index, dc in enumerate(warmup_dcs):
                    self._schedule_cf_bootstrap_prewarm(int(dc), is_media=False, delay=(0.35 + (0.18 * index)))
                media_warmup_dcs = sorted(set(CF_FIRST_MEDIA_DCS))
                for index, dc in enumerate(media_warmup_dcs):
                    self._schedule_cf_bootstrap_prewarm(int(dc), is_media=True, delay=(0.55 + (0.22 * index)))
        except Exception:
            pass

        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            backlog=512,
            limit=max(256 * 1024, int(getattr(proxy_config, "buffer_size", 256 * 1024))),
        )
        self.running = True
        self.started_event.set()
        self.log_func(f"[TgRelay] Локальный SOCKS5 relay активен на {self.host}:{self.port}.")
        async with self.server:
            serve_task = asyncio.create_task(self.server.serve_forever())
            stop_task = asyncio.create_task(self.stop_event.wait())
            done, pending = await asyncio.wait({serve_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            if stop_task in done:
                self.server.close()
                await self.server.wait_closed()
            if serve_task in done:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await serve_task

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        label = f"{peer[0]}:{peer[1]}" if peer else "?"
        prefetched_ws_task = None
        try:
            prefetched = await asyncio.wait_for(reader.readexactly(1), timeout=5.0)
            divert_context = await self._lookup_divert_context(peer)
            if divert_context:
                target_host = str(divert_context.get("target_host") or "").strip()
                target_port = int(divert_context.get("target_port") or 0)
                if not target_host or target_port <= 0:
                    return
            else:
                target_host, target_port = await self._socks_handshake(reader, writer, prefetched=prefetched)
                prefetched = b""
            if not target_host:
                return
            target_ip = await _resolve_ip(target_host)
            if not _wss_candidate(target_host, target_ip, target_port):
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, prefetched, label, media_hint=None)
                return

            probe_key = (str(target_ip or target_host or "").strip(), int(target_port or 0))
            now_mono = time.monotonic()
            no_probe_until = float(self._no_probe_until.get(probe_key, 0.0) or 0.0)
            if no_probe_until > now_mono:
                cached_dc_hint = _target_dc_hint(target_ip)
                cached_is_media = _likely_media_target(target_ip, target_port, cached_dc_hint)
                if not cached_is_media:
                    init_packet = await self._read_probe(reader, want=64, timeout=0.05, initial=prefetched)
                    if await self._try_cf_bootstrap_non_media(
                        reader,
                        writer,
                        target_ip=target_ip,
                        target_port=target_port,
                        init_packet=init_packet,
                        label=label,
                        dc_hint=cached_dc_hint,
                    ):
                        return
                    await self._handle_plain_tunnel(
                        reader,
                        writer,
                        target_host,
                        target_port,
                        init_packet,
                        label,
                        media_hint=False,
                    )
                    return
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, prefetched, label, media_hint=None)
                return

            predicted_is_media = _likely_media_target(target_ip, target_port, 0)
            predicted_dc = _target_dc_hint(target_ip, predicted_is_media)
            if predicted_is_media and int(target_port or 0) == 80 and predicted_dc in _TG_WS_REDIRECT_IPS:
                try:
                    prefetched_ws_task = asyncio.create_task(
                        self._connect_ws_route(predicted_dc, target_ip, predicted_is_media, label)
                    )
                except Exception:
                    prefetched_ws_task = None

            # Telegram startup opens many short bootstrap/control sockets. For
            # sockets that do not even look like media by IP/port heuristics,
            # almost all probe delay is wasted because we will plain-tunnel them
            # anyway. Keep a near-zero probe there; retain longer probing only
            # for likely media sockets where WSS path can still matter.
            if not predicted_is_media:
                probe_timeout = 0.02
            else:
                probe_timeout = 0.15 if int(target_port or 0) == 80 else 0.6
            init_packet = await self._read_probe(reader, want=64, timeout=probe_timeout, initial=prefetched)
            init_info = parse_transparent_init_info(init_packet) if len(init_packet) >= 64 else None
            if init_info is None:
                dc_hint = _target_dc_hint(target_ip)
                is_media = _likely_media_target(target_ip, target_port, dc_hint)
                if not is_media:
                    if await self._try_cf_bootstrap_non_media(
                        reader,
                        writer,
                        target_ip=target_ip,
                        target_port=target_port,
                        init_packet=init_packet,
                        label=label,
                        dc_hint=dc_hint,
                    ):
                        return
                    if prefetched_ws_task is not None:
                        prefetched_ws_task.cancel()
                        with contextlib.suppress(Exception):
                            await prefetched_ws_task
                    await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=False)
                    return
                ws_capable = int(dc_hint or 0) in _TG_WS_REDIRECT_IPS or (
                    CF_FALLBACK_ENABLED and bool(_cf_ws_domains(int(dc_hint or 0), bool(predicted_is_media)))
                )
                if ws_capable:
                    ws = None
                    route_label = ""
                    if (
                        prefetched_ws_task is not None
                        and int(predicted_dc or 0) == int(dc_hint or 0)
                        and bool(predicted_is_media) == bool(is_media)
                    ):
                        try:
                            ws, route_label = await asyncio.wait_for(asyncio.shield(prefetched_ws_task), timeout=0.35)
                        except Exception:
                            ws = None
                            route_label = ""
                    elif prefetched_ws_task is not None:
                        prefetched_ws_task.cancel()
                        with contextlib.suppress(Exception):
                            await prefetched_ws_task
                    if ws is None:
                        ws, route_label = await self._connect_ws_route(dc_hint, target_ip, is_media, label)
                    if ws is not None:
                        try:
                            self._no_probe_until.pop(probe_key, None)
                        except Exception:
                            pass
                        try:
                            if init_packet:
                                await ws.send(init_packet)
                        except Exception:
                            with contextlib.suppress(Exception):
                                await ws.close()
                            await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=is_media)
                            return
                        self.log_func(
                            f"[TgRelay] Подключено: proto=raw dc={dc_hint or '?'} media={is_media} route={route_label} target={target_ip}:{target_port}"
                        )
                        await _bridge_ws(reader, writer, ws, None)
                        return
                if prefetched_ws_task is not None:
                    prefetched_ws_task.cancel()
                    with contextlib.suppress(Exception):
                        await prefetched_ws_task
                if int(target_port or 0) == 80:
                    # Repeated :80 connects to the same Telegram host rarely benefit
                    # from waiting for a full MTProto init. Cache that knowledge and
                    # send the next connections straight to fallback.
                    cache_for = 45.0 if not init_packet else 20.0
                    self._no_probe_until[probe_key] = time.monotonic() + cache_for
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=None)
                return

            dc_hint = init_info.dc or _target_dc_hint(target_ip)
            is_media = bool(init_info.is_media or _likely_media_target(target_ip, target_port, dc_hint))
            if not is_media:
                if await self._try_cf_bootstrap_non_media(
                    reader,
                    writer,
                    target_ip=target_ip,
                    target_port=target_port,
                    init_packet=init_packet,
                    label=label,
                    dc_hint=dc_hint,
                    proto_label=_proto_label(init_info.proto),
                ):
                    return
                if prefetched_ws_task is not None:
                    prefetched_ws_task.cancel()
                    with contextlib.suppress(Exception):
                        await prefetched_ws_task
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=False)
                return
            ws_capable = int(dc_hint or 0) in _TG_WS_REDIRECT_IPS
            if not is_media and not ws_capable:
                if prefetched_ws_task is not None:
                    prefetched_ws_task.cancel()
                    with contextlib.suppress(Exception):
                        await prefetched_ws_task
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=False)
                return
            ws = None
            route_label = ""
            if (
                prefetched_ws_task is not None
                and int(predicted_dc or 0) == int(dc_hint or 0)
                and bool(predicted_is_media) == bool(is_media)
            ):
                try:
                    ws, route_label = await asyncio.wait_for(asyncio.shield(prefetched_ws_task), timeout=0.35)
                except Exception:
                    ws = None
                    route_label = ""
            elif prefetched_ws_task is not None:
                prefetched_ws_task.cancel()
                with contextlib.suppress(Exception):
                    await prefetched_ws_task

            if ws is None:
                ws, route_label = await self._connect_ws_route(dc_hint, target_ip, is_media, label)
            if ws is None:
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=True)
                return
            try:
                self._no_probe_until.pop(probe_key, None)
            except Exception:
                pass

            splitter = None
            try:
                splitter = TransparentMsgSplitter(init_packet, init_info.proto)
            except Exception:
                splitter = None

            try:
                await ws.send(init_packet)
            except Exception:
                with contextlib.suppress(Exception):
                    await ws.close()
                await self._handle_plain_tunnel(reader, writer, target_host, target_port, init_packet, label, media_hint=True)
                return

            self.log_func(
                f"[TgRelay] Подключено: proto={_proto_label(init_info.proto)} dc={dc_hint or '?'} media={is_media} route={route_label} target={target_ip}:{target_port}"
            )
            await _bridge_ws(reader, writer, ws, splitter)
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            self.log_func(f"[TgRelay] Ошибка клиента {label}: {exc}")
        finally:
            if prefetched_ws_task is not None:
                try:
                    if not prefetched_ws_task.done():
                        prefetched_ws_task.cancel()
                except Exception:
                    pass
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _try_cf_bootstrap_non_media(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        target_ip: str,
        target_port: int,
        init_packet: bytes,
        label: str,
        dc_hint: int,
        proto_label: str = "raw",
    ) -> bool:
        try:
            dc_hint = int(dc_hint or 0)
            target_port = int(target_port or 0)
        except Exception:
            return False
        if dc_hint <= 0 or target_port not in (80, 443, 5222, 5228):
            return False
        if not CF_FALLBACK_ENABLED or not _has_custom_cfproxy_domain():
            return False
        if not _cf_ws_domains(dc_hint, False):
            return False
        if target_port == 80:
            # First cold-start :80 control sockets are often disposable probes.
            # Once a DC already has a proven CF/WSS route, however, reusing that
            # last-good domain is faster than repeating plain canonical-443
            # bootstrap for every next chat/control open.
            try:
                last_good_domain, last_good_until = self._cf_last_good_domain.get((dc_hint, False), ("", 0.0))
            except Exception:
                last_good_domain, last_good_until = ("", 0.0)
            if last_good_until <= time.monotonic() or not last_good_domain:
                return False
        try:
            await self._maybe_wait_for_warp_bootstrap(
                target_ip,
                target_port,
                media_hint=False,
                dc_hint=dc_hint,
            )
        except Exception:
            pass
        now = time.monotonic()
        last = float(self._cf_bootstrap_probe_logged.get(dc_hint, 0.0) or 0.0)
        if (now - last) > 10.0:
            self._cf_bootstrap_probe_logged[dc_hint] = now
            self.log_func(
                f"[TgRelay] Bootstrap CF/WSS probe: dc={dc_hint} target={target_ip}:{target_port} domain=nova-app.eu"
            )
        ws, route_label = await self._connect_cf_ws_route(dc_hint, False, primary_only=True)
        if ws is None:
            return False
        try:
            if init_packet:
                await ws.send(init_packet)
        except Exception:
            with contextlib.suppress(Exception):
                await ws.close()
            return False
        self.log_func(
            f"[TgRelay] Подключено: proto={proto_label} dc={dc_hint} media=False route={route_label} target={target_ip}:{target_port}"
        )
        await _bridge_ws(reader, writer, ws, None)
        return True

    async def _socks_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, prefetched: bytes = b"") -> Tuple[Optional[str], Optional[int]]:
        header_bytes = bytearray(prefetched or b"")
        while len(header_bytes) < 2:
            header_bytes.extend(await asyncio.wait_for(reader.readexactly(2 - len(header_bytes)), timeout=5.0))
        header = bytes(header_bytes[:2])
        if header[0] != 0x05:
            writer.write(b"\x05\xff")
            await writer.drain()
            return None, None
        methods = await asyncio.wait_for(reader.readexactly(header[1]), timeout=5.0)
        if 0x00 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return None, None
        writer.write(b"\x05\x00")
        await writer.drain()

        req = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
        ver, cmd, _, atyp = req
        if ver != 0x05 or cmd != 0x01:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return None, None

        if atyp == 0x01:
            addr_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
            host = socket.inet_ntoa(addr_bytes)
        elif atyp == 0x03:
            ln = (await asyncio.wait_for(reader.readexactly(1), timeout=5.0))[0]
            host_bytes = await asyncio.wait_for(reader.readexactly(ln), timeout=5.0)
            host = host_bytes.decode("ascii", "ignore")
        elif atyp == 0x04:
            addr_bytes = await asyncio.wait_for(reader.readexactly(16), timeout=5.0)
            host = str(ipaddress.IPv6Address(addr_bytes))
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return None, None
        port = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), timeout=5.0))[0]
        writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.port))
        await writer.drain()
        return host, int(port)

    async def _read_probe(self, reader: asyncio.StreamReader, want: int = 64, timeout: float = 4.0, initial: bytes = b"") -> bytes:
        data = bytearray(initial or b"")
        deadline = time.time() + float(timeout)
        while len(data) < want:
            remaining = max(0.2, deadline - time.time())
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(want - len(data)), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    async def _maybe_wait_for_warp_bootstrap(self, target_host: str, target_port: int, media_hint=None, dc_hint: int = 0):
        waiter = getattr(self, "warp_bootstrap_waiter", None)
        if not callable(waiter):
            return 0.0
        try:
            return float(
                await asyncio.to_thread(
                    waiter,
                    str(target_host or "").strip(),
                    int(target_port or 0),
                    bool(media_hint),
                    int(dc_hint or 0),
                )
            )
        except Exception:
            return 0.0

    async def _handle_plain_tunnel(self, reader, writer, target_host: str, target_port: int, initial: bytes, label: str, media_hint=None):
        effective_host = str(target_host)
        effective_port = int(target_port)
        route_suffix = ""
        dc_hint = 0
        bootstrap_canonical = False
        try:
            target_ip = await _resolve_ip(target_host)
            if media_hint is None:
                media_hint = _likely_media_target(target_ip, target_port, 0)
            dc_hint = _target_dc_hint(target_ip, bool(media_hint))
            if dc_hint and (bool(media_hint) or int(target_port or 0) == 80):
                fallback_host = _TG_TCP_FALLBACK_IPS.get(int(dc_hint))
                if fallback_host:
                    effective_host = fallback_host
                    effective_port = 443
                    route_suffix = f" orig={target_host}:{target_port} dc={dc_hint}"
                    if int(target_port or 0) == 80:
                        bootstrap_canonical = True
                        route_suffix = f"{route_suffix} bootstrap=canonical-443"
        except Exception:
            pass

        waited_warp = await self._maybe_wait_for_warp_bootstrap(
            effective_host,
            effective_port,
            media_hint=media_hint,
            dc_hint=dc_hint,
        )
        if waited_warp > 0.01:
            route_suffix = f"{route_suffix} wait-warp={waited_warp:.2f}s".rstrip()

        attempts = None
        try:
            from .transport import get_upstream_attempts
            base_attempts = list(get_upstream_attempts() or [])
            if base_attempts:
                pref_key = (str(effective_host or "").strip(), int(effective_port or 0))
                pref_route, pref_until = self._route_preference_until.get(pref_key, ("", 0.0))
                if pref_until <= time.monotonic():
                    pref_route = ""
                prefer_direct_key = (int(dc_hint or 0), str(effective_host or "").strip())
                prefer_direct_until = float(self._prefer_direct_until.get(prefer_direct_key, 0.0) or 0.0)
                direct_attempts = [a for a in base_attempts if str(a.get("kind") or "").strip().lower() == "direct"]
                warp_attempts = [a for a in base_attempts if str(a.get("label") or "").strip().lower() == "warp-socks"]
                other_attempts = [
                    a for a in base_attempts
                    if a not in direct_attempts and a not in warp_attempts
                ]
                # Direct Telegram is often provider-shaped on the target networks.
                # Never promote it to first place based on transient WARP stalls.
                if pref_route == "warp-socks":
                    proxy_attempts = warp_attempts + other_attempts
                    attempts = proxy_attempts or direct_attempts
                elif prefer_direct_until > time.monotonic():
                    proxy_attempts = other_attempts + warp_attempts
                    attempts = proxy_attempts or direct_attempts
                else:
                    attempts = base_attempts
        except Exception:
            attempts = None

        connect_timeout = 2.5 if int(dc_hint or 0) in (1, 3, 5) else 6.0
        if bootstrap_canonical:
            connect_timeout = min(connect_timeout, 1.35)

        upstream_reader, upstream_writer, route_label = await open_stream(
            effective_host,
            effective_port,
            timeout=connect_timeout,
            attempts=attempts,
        )
        if initial:
            upstream_writer.write(initial)
            await upstream_writer.drain()
        prefetched_reply = b""
        try:
            pref_key = (str(effective_host or "").strip(), int(effective_port or 0))
            if str(route_label or "").strip().lower() == "warp-socks":
                self._route_preference_until[pref_key] = (str(route_label).strip().lower(), time.monotonic() + 300.0)
        except Exception:
            pass
        if (
            FIRST_BYTE_STALL_RETRY
            and (not bootstrap_canonical)
            and initial
            and str(route_label or "").strip().lower() == "warp-socks"
            and int(dc_hint or 0) in (1, 3, 5)
        ):
            try:
                prefetched_reply = await asyncio.wait_for(
                    upstream_reader.read(1),
                    timeout=(0.45 if bootstrap_canonical else 0.75),
                )
            except asyncio.TimeoutError:
                prefetched_reply = b""
            except Exception:
                prefetched_reply = b""

            if not prefetched_reply:
                with contextlib.suppress(Exception):
                    upstream_writer.close()
                    await upstream_writer.wait_closed()

                retry_attempts = None
                try:
                    from .transport import get_upstream_attempts
                    base_attempts = list(get_upstream_attempts() or [])
                    direct_attempts = [a for a in base_attempts if str(a.get("kind") or "").strip().lower() == "direct"]
                    warp_attempts = [a for a in base_attempts if str(a.get("label") or "").strip().lower() == "warp-socks"]
                    other_attempts = [a for a in base_attempts if a not in direct_attempts and a not in warp_attempts]
                    if bootstrap_canonical:
                        proxy_retry_attempts = warp_attempts + other_attempts
                    else:
                        proxy_retry_attempts = other_attempts + warp_attempts
                    retry_attempts = proxy_retry_attempts or direct_attempts
                except Exception:
                    retry_attempts = None

                upstream_reader, upstream_writer, route_label = await open_stream(
                    effective_host,
                    effective_port,
                    timeout=(1.6 if bootstrap_canonical else 3.0),
                    attempts=retry_attempts,
                )
                if initial:
                    upstream_writer.write(initial)
                    await upstream_writer.drain()
                try:
                    pref_key = (str(effective_host or "").strip(), int(effective_port or 0))
                    if str(route_label or "").strip().lower() == "warp-socks":
                        self._route_preference_until[pref_key] = (str(route_label).strip().lower(), time.monotonic() + 300.0)
                except Exception:
                    pass
                route_suffix = f"{route_suffix} retry=after-warp-stall".rstrip()
        self._log_fallback(route_label, effective_host, effective_port, route_suffix)
        if prefetched_reply:
            writer.write(prefetched_reply)
            await writer.drain()
        await _bridge_streams(reader, writer, upstream_reader, upstream_writer)

    def _log_fallback(self, route_label: str, effective_host: str, effective_port: int, route_suffix: str) -> None:
        try:
            suffix_text = str(route_suffix or "")
            if "retry=after-warp-stall" in suffix_text:
                # Retry mode is intentionally opt-in now; if enabled, keep it visible.
                key_suffix = "retry"
            elif "bootstrap=canonical-443" in suffix_text:
                key_suffix = "bootstrap"
            else:
                key_suffix = ""
            key = (
                str(route_label or "").strip().lower(),
                str(effective_host or "").strip().lower(),
                int(effective_port or 0),
                key_suffix,
            )
            now = time.monotonic()
            last = float(self._last_fallback_log.get(key, 0.0) or 0.0)
            if (now - last) < FALLBACK_LOG_INTERVAL:
                return
            self._last_fallback_log[key] = now
        except Exception:
            pass
        self.log_func(f"[TgRelay] TCP fallback route={route_label} target={effective_host}:{effective_port}{route_suffix}")

    async def _connect_ws_route(self, dc_hint: int, target_ip: str, is_media: bool, label: str):
        dc_hint = int(dc_hint or 0)
        if dc_hint <= 0:
            return None, ""

        if CF_FALLBACK_ENABLED and self._cf_first(dc_hint, is_media):
            ws, route_label = await self._connect_cf_ws_route(dc_hint, is_media)
            if ws is not None:
                return ws, route_label

        redirect_target = _TG_WS_REDIRECT_IPS.get(dc_hint)
        if redirect_target:
            domains = _ws_domains(dc_hint, is_media)
            try:
                pooled_ws, pooled_label = await _WS_POOL.get(dc_hint, is_media, redirect_target, domains)
                if pooled_ws is not None:
                    return pooled_ws, pooled_label
            except Exception:
                pass
            for domain in domains:
                try:
                    ws, upstream_label = await _connect_websocket_target(redirect_target, domain, timeout=6.0)
                    _WS_POOL._schedule_refill((int(dc_hint), bool(is_media)), redirect_target, domains)
                    return ws, f"{domain}@{redirect_target} via {upstream_label}"
                except WsHandshakeError as exc:
                    if exc.is_redirect:
                        continue
                    break
                except Exception:
                    break

        if CF_FALLBACK_ENABLED:
            ws, route_label = await self._connect_cf_ws_route(dc_hint, is_media)
            if ws is not None:
                return ws, route_label

        self.log_func(f"[TgRelay] WSS route failed for DC{dc_hint} target={target_ip} media={is_media}.")
        return None, ""

    @staticmethod
    def _cf_first(dc_hint: int, is_media: bool) -> bool:
        try:
            dc = int(dc_hint or 0)
        except Exception:
            return False
        if bool(is_media):
            return dc in CF_FIRST_MEDIA_DCS
        return dc in CF_FIRST_DCS

    async def _connect_cf_ws_route(self, dc_hint: int, is_media: bool = False, primary_only: bool = False):
        dc_hint = int(dc_hint or 0)
        ordered = _cf_ws_domains_for_bases(dc_hint, _cf_ws_domain_bases(primary_only=primary_only), bool(is_media))
        pref_key = (int(dc_hint or 0), bool(is_media))
        try:
            last_good_domain, last_good_until = self._cf_last_good_domain.get(pref_key, ("", 0.0))
        except Exception:
            last_good_domain, last_good_until = ("", 0.0)
        if last_good_until <= time.monotonic():
            last_good_domain = ""
        if last_good_domain and last_good_domain in ordered:
            ordered = [last_good_domain] + [item for item in ordered if item != last_good_domain]
        pool_key = (int(dc_hint or 0), bool(is_media), bool(primary_only))
        pooled_ws, pooled_label = await self._cf_pool_get(pool_key, ordered)
        if pooled_ws is not None:
            return pooled_ws, pooled_label
        for domain in ordered:
            try:
                timeout = 1.25 if (primary_only and not bool(is_media)) else 7.0
                ws, upstream_label = await _connect_websocket_target(domain, domain, timeout=timeout)
                if str(upstream_label or "").strip().lower() != "warp-socks":
                    with contextlib.suppress(Exception):
                        await ws.close()
                    continue
                try:
                    self._cf_last_good_domain[pref_key] = (str(domain), time.monotonic() + 600.0)
                except Exception:
                    pass
                return ws, f"{domain} via {upstream_label}"
            except Exception:
                continue
        return None, ""

    async def _cf_pool_get(self, key, ordered: List[str]):
        now = time.monotonic()
        bucket = self._cf_idle.setdefault(key, deque())
        while bucket:
            ws, created, route_label = bucket.popleft()
            age = now - created
            try:
                transport_closing = bool(ws.writer.transport.is_closing())
            except Exception:
                transport_closing = True
            if age > WS_POOL_MAX_AGE or getattr(ws, "_closed", False) or transport_closing:
                with contextlib.suppress(Exception):
                    await ws.close()
                continue
            self._schedule_cf_refill(key, ordered)
            return ws, route_label
        self._schedule_cf_refill(key, ordered)
        return None, ""

    def _schedule_cf_refill(self, key, ordered: List[str]) -> None:
        if key in self._cf_refilling:
            return
        self._cf_refilling.add(key)
        try:
            asyncio.create_task(self._refill_cf_pool(key, list(ordered or [])))
        except Exception:
            self._cf_refilling.discard(key)

    async def _refill_cf_pool(self, key, ordered: List[str]) -> None:
        try:
            bucket = self._cf_idle.setdefault(key, deque())
            if len(bucket) >= 1:
                return
            for domain in ordered:
                try:
                    ws, upstream_label = await _connect_websocket_target(domain, domain, timeout=1.5)
                    if str(upstream_label or "").strip().lower() != "warp-socks":
                        with contextlib.suppress(Exception):
                            await ws.close()
                        continue
                    bucket.append((ws, time.monotonic(), f"{domain} via {upstream_label}"))
                    return
                except Exception:
                    continue
        finally:
            self._cf_refilling.discard(key)

    def _schedule_cf_bootstrap_prewarm(self, dc_hint: int, is_media: bool = False, delay: float = 0.5) -> None:
        key = (int(dc_hint or 0), bool(is_media))
        if key in self._cf_prewarm_started:
            return
        self._cf_prewarm_started[key] = time.monotonic()
        try:
            asyncio.create_task(self._prewarm_cf_bootstrap_route(int(dc_hint or 0), bool(is_media), float(delay)))
        except Exception:
            self._cf_prewarm_started.pop(key, None)

    async def _prewarm_cf_bootstrap_route(self, dc_hint: int, is_media: bool = False, delay: float = 0.5) -> None:
        key = (int(dc_hint or 0), bool(is_media))
        try:
            await asyncio.sleep(max(0.0, float(delay)))
            fallback_host = str(_TG_TCP_FALLBACK_IPS.get(int(dc_hint or 0)) or "").strip()
            if fallback_host:
                await self._maybe_wait_for_warp_bootstrap(
                    fallback_host,
                    443,
                    media_hint=is_media,
                    dc_hint=dc_hint,
                )
            ordered = _cf_ws_domains_for_bases(int(dc_hint or 0), _cf_ws_domain_bases(primary_only=True), bool(is_media))
            pref_key = (int(dc_hint or 0), bool(is_media))
            try:
                last_good_domain, last_good_until = self._cf_last_good_domain.get(pref_key, ("", 0.0))
            except Exception:
                last_good_domain, last_good_until = ("", 0.0)
            if last_good_until > time.monotonic() and last_good_domain and last_good_domain in ordered:
                ordered = [last_good_domain] + [item for item in ordered if item != last_good_domain]
            self._schedule_cf_refill((int(dc_hint or 0), bool(is_media), True), ordered)
            await asyncio.sleep(0.05)
        except Exception:
            pass
        finally:
            self._cf_prewarm_started.pop(key, None)
