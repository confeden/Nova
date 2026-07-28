import ipaddress
import socket
import struct
from typing import Dict, List, Optional, Tuple

from .transport import get_upstream_attempts


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("unexpected EOF from upstream proxy")
        data.extend(chunk)
    return bytes(data)


def _encode_socks_target(host: str) -> Tuple[bytes, bytes]:
    host = str(host or "").strip()
    try:
        addr = ipaddress.ip_address(host)
        if addr.version == 4:
            return b"\x01", addr.packed
        return b"\x04", addr.packed
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise OSError("target hostname too long for SOCKS5")
        return b"\x03", bytes([len(encoded)]) + encoded


def _decode_socks_target(atyp: int, payload: bytes, offset: int = 0) -> Tuple[str, int]:
    if atyp == 0x01:
        end = offset + 4
        if len(payload) < end:
            raise OSError("short SOCKS5 IPv4 payload")
        return str(ipaddress.IPv4Address(payload[offset:end])), end
    if atyp == 0x04:
        end = offset + 16
        if len(payload) < end:
            raise OSError("short SOCKS5 IPv6 payload")
        return str(ipaddress.IPv6Address(payload[offset:end])), end
    if atyp == 0x03:
        if len(payload) < offset + 1:
            raise OSError("short SOCKS5 domain payload")
        ln = payload[offset]
        start = offset + 1
        end = start + ln
        if len(payload) < end:
            raise OSError("short SOCKS5 domain payload")
        return payload[start:end].decode("idna", "ignore"), end
    raise OSError(f"unsupported SOCKS5 ATYP {atyp}")


def _is_unspecified_address(host: str) -> bool:
    try:
        return ipaddress.ip_address(str(host or "").strip()).is_unspecified
    except ValueError:
        return False


class UdpEndpoint:
    def __init__(self, label: str):
        self.label = str(label or "").strip() or "unknown"

    def sendto(self, data: bytes, target_host: str, target_port: int) -> None:
        raise NotImplementedError

    def recvfrom(self, bufsize: int = 65535, timeout: Optional[float] = None) -> Tuple[bytes, Tuple[str, int]]:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class DirectUdpEndpoint(UdpEndpoint):
    def __init__(self, label: str = "direct"):
        super().__init__(label)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))

    def sendto(self, data: bytes, target_host: str, target_port: int) -> None:
        self.sock.sendto(data, (str(target_host), int(target_port)))

    def recvfrom(self, bufsize: int = 65535, timeout: Optional[float] = None) -> Tuple[bytes, Tuple[str, int]]:
        prev_timeout = self.sock.gettimeout()
        try:
            self.sock.settimeout(timeout)
            payload, addr = self.sock.recvfrom(int(bufsize))
            return payload, (str(addr[0]), int(addr[1]))
        finally:
            self.sock.settimeout(prev_timeout)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


class Socks5UdpEndpoint(UdpEndpoint):
    def __init__(self, proxy_host: str, proxy_port: int, timeout: float = 3.0, label: str = "warp-socks"):
        super().__init__(label)
        self.proxy_host = str(proxy_host or "127.0.0.1").strip()
        self.proxy_port = int(proxy_port)
        self.timeout = max(0.2, float(timeout))
        self.control_sock = socket.create_connection((self.proxy_host, self.proxy_port), timeout=self.timeout)
        self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.data_sock.bind(("0.0.0.0", 0))
        self.relay_addr = self._associate()

    def _associate(self) -> Tuple[str, int]:
        self.control_sock.sendall(b"\x05\x01\x00")
        greeting = _recv_exact(self.control_sock, 2)
        if greeting != b"\x05\x00":
            raise OSError(f"SOCKS5 no-auth negotiation failed: {greeting!r}")

        req = b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
        self.control_sock.sendall(req)
        header = _recv_exact(self.control_sock, 4)
        if header[0] != 0x05:
            raise OSError(f"invalid SOCKS5 version in UDP ASSOCIATE reply: {header!r}")
        if header[1] != 0x00:
            raise OSError(f"SOCKS5 UDP ASSOCIATE failed with code {header[1]}")

        atyp = header[3]
        if atyp == 0x01:
            payload = _recv_exact(self.control_sock, 4 + 2)
        elif atyp == 0x03:
            ln = _recv_exact(self.control_sock, 1)[0]
            payload = bytes([ln]) + _recv_exact(self.control_sock, ln + 2)
        elif atyp == 0x04:
            payload = _recv_exact(self.control_sock, 16 + 2)
        else:
            raise OSError(f"unknown SOCKS5 UDP ASSOCIATE ATYP {atyp}")

        relay_host, offset = _decode_socks_target(atyp, payload, 0)
        relay_port = int.from_bytes(payload[offset:offset + 2], "big")
        if relay_port <= 0:
            raise OSError("SOCKS5 UDP ASSOCIATE returned empty relay port")
        if _is_unspecified_address(relay_host):
            relay_host = self.proxy_host
        return relay_host, relay_port

    def sendto(self, data: bytes, target_host: str, target_port: int) -> None:
        atyp, addr = _encode_socks_target(target_host)
        packet = b"\x00\x00\x00" + atyp + addr + int(target_port).to_bytes(2, "big") + bytes(data or b"")
        self.data_sock.sendto(packet, self.relay_addr)

    def recvfrom(self, bufsize: int = 65535, timeout: Optional[float] = None) -> Tuple[bytes, Tuple[str, int]]:
        prev_timeout = self.data_sock.gettimeout()
        try:
            self.data_sock.settimeout(timeout)
            packet, _ = self.data_sock.recvfrom(int(bufsize))
        finally:
            self.data_sock.settimeout(prev_timeout)

        if len(packet) < 4:
            raise OSError("short SOCKS5 UDP packet")
        if packet[2] != 0x00:
            raise OSError("fragmented SOCKS5 UDP packets are not supported")
        atyp = packet[3]
        host, offset = _decode_socks_target(atyp, packet, 4)
        if len(packet) < offset + 2:
            raise OSError("short SOCKS5 UDP packet")
        port = int.from_bytes(packet[offset:offset + 2], "big")
        return packet[offset + 2:], (host, port)

    def close(self) -> None:
        for sock in (self.data_sock, self.control_sock):
            try:
                sock.close()
            except Exception:
                pass


def get_udp_upstream_attempts() -> List[Dict[str, object]]:
    attempts = []
    for attempt in get_upstream_attempts():
        if not isinstance(attempt, dict):
            continue
        kind = str(attempt.get("kind") or "").strip().lower()
        if kind not in {"socks5", "direct"}:
            continue
        attempts.append(dict(attempt))
    if attempts:
        return attempts
    return [
        {"kind": "socks5", "host": "127.0.0.1", "port": 1370, "label": "warp-socks"},
        {"kind": "direct", "label": "direct"},
    ]


def open_udp_endpoint(
    timeout: float = 3.0,
    attempts: Optional[List[Dict[str, object]]] = None,
) -> Tuple[UdpEndpoint, str]:
    last_error = None
    for attempt in attempts or get_udp_upstream_attempts():
        kind = str(attempt.get("kind") or "").strip().lower()
        label = str(attempt.get("label") or kind or "unknown").strip() or "unknown"
        try:
            attempt_timeout = max(0.2, float(attempt.get("timeout") or timeout))
        except Exception:
            attempt_timeout = float(timeout)
        try:
            if kind == "direct":
                return DirectUdpEndpoint(label=label), label
            if kind == "socks5":
                endpoint = Socks5UdpEndpoint(
                    proxy_host=str(attempt.get("host") or "127.0.0.1").strip(),
                    proxy_port=int(attempt.get("port") or 0),
                    timeout=attempt_timeout,
                    label=label,
                )
                return endpoint, label
            last_error = OSError(f"unsupported UDP attempt kind: {kind}")
        except Exception as exc:
            last_error = exc
            continue
    if last_error is None:
        last_error = OSError("no UDP upstream attempts available")
    raise last_error
