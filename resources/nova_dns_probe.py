"""nova_dns_probe - DNS unblocking proxy probe and rule generator.

Decides, per DNS name, which unblocking DNS providers answer with their own
proxy address rather than the service's original address.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import json
import os
import socket
import struct
import time


def build_query(name: str, qtype: int, qid: int) -> bytes:
    """Build standard DNS query with RD=1, QCLASS=IN."""
    qname = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.strip(".").split(".") if p) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)


def _skip_name(data: bytes, offset: int) -> int:
    """Skip a DNS domain name in wire format, handling compression pointers."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            if offset + 2 > len(data):
                raise ValueError("Truncated pointer")
            return offset + 2
        if (length & 0xC0) != 0:
            raise ValueError("Invalid label type")
        offset += 1 + length
    raise ValueError("Truncated name")


def parse_response(data: bytes, qid: int) -> list[str] | None:
    """Parse DNS response: None on malformed/mismatch, [] on NXDOMAIN/empty, else A/AAAA IPs."""
    if len(data) < 12:
        return None
    try:
        resp_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        if resp_id != qid or (flags & 0x0F) not in (0, 3):
            return None
        if (flags & 0x0F) == 3:
            return []
        offset = 12
        for _ in range(qdcount):
            offset = _skip_name(data, offset) + 4
            if offset > len(data):
                return None
        answers: list[str] = []
        for _ in range(ancount):
            offset = _skip_name(data, offset)
            if offset + 10 > len(data):
                return None
            rtype, rclass, _, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            if offset + rdlen > len(data):
                return None
            rdata = data[offset : offset + rdlen]
            offset += rdlen
            if rclass == 1:
                if rtype == 1 and rdlen == 4:
                    answers.append(str(ipaddress.IPv4Address(rdata)))
                elif rtype == 28 and rdlen == 16:
                    answers.append(str(ipaddress.IPv6Address(rdata)))
        return answers
    except Exception:
        return None


def query(server: str, name: str, qtype: int, timeout: float = 2.0) -> list[str] | None:
    """One UDP DNS query (AF_INET/AF_INET6), random qid, None on error."""
    try:
        addr = ipaddress.ip_address(server)
        family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    except ValueError:
        return None
    qid = int.from_bytes(os.urandom(2), "big")
    packet = build_query(name, qtype, qid)
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        return parse_response(data, qid)
    except (OSError, ValueError):
        return None
    finally:
        if sock:
            sock.close()


def resolve(server: str, name: str, timeout: float = 2.0, query_fn=None) -> list[str] | None:
    """Resolve A and AAAA; None only if both None; else sorted union."""
    fn = query_fn or query
    a, aaaa = fn(server, name, 1, timeout), fn(server, name, 28, timeout)
    if a is None and aaaa is None:
        return None
    return sorted(set((a or []) + (aaaa or [])))


def first_alive(addresses, probe_name: str = "example.com", timeout: float = 2.0, query_fn=None) -> str | None:
    """First address whose A query is not None."""
    fn = query_fn or query
    for addr in addresses:
        if fn(addr, probe_name, 1, timeout) is not None:
            return addr
    return None


def measure(
    providers,
    names,
    reference: tuple[str, ...] = ("8.8.8.8", "1.1.1.1", "77.88.8.8"),
    timeout: float = 2.0,
    workers: int = 16,
    query_fn=None,
) -> dict:
    """Measure providers against names and reference servers."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        alive_futs = {p: executor.submit(first_alive, addrs, "example.com", timeout, query_fn) for p, addrs in providers}
        alive = {p: fut.result() for p, fut in alive_futs.items()}
        prov_futs = {(p, n): executor.submit(resolve, s, n, timeout, query_fn) for p, s in alive.items() if s for n in names}
        ref_futs = {(s, n): executor.submit(resolve, s, n, timeout, query_fn) for s in reference for n in names}
        answers = {p: ({n: prov_futs[(p, n)].result() for n in names} if s else {}) for p, s in alive.items()}
        reference_ans = {n: sorted(set().union(*(ref_futs[(s, n)].result() or [] for s in reference))) for n in names}
    return {"alive": alive, "answers": answers, "reference": reference_ans}


def _prefix(ip: str) -> str:
    """'/24' network string for IPv4, '/64' for IPv6."""
    addr = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 64}", strict=False))


def _reg_domain(name: str) -> str:
    """Last two labels of domain name."""
    parts = name.strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name.strip(".").lower()


def classify(measurement: dict) -> dict[str, list[str]]:
    """Decide which providers proxy each name."""
    alive, answers, ref = measurement.get("alive", {}), measurement.get("answers", {}), measurement.get("reference", {})
    prov_order = list(alive.keys())
    clusters: dict[str, set[str]] = {}
    for p in prov_order:
        prefix_doms: dict[str, set[str]] = {}
        for n, ips in answers.get(p, {}).items():
            if not ips:
                continue
            dom = _reg_domain(n)
            for ip in ips:
                prefix_doms.setdefault(_prefix(ip), set()).add(dom)
        clusters[p] = {pref for pref, doms in prefix_doms.items() if len(doms) >= 2}

    names = list(ref.keys())
    if not names:
        names = list(dict.fromkeys(n for p in prov_order for n in answers.get(p, {})))

    result: dict[str, list[str]] = {}
    for n in names:
        ref_ips = set(ref.get(n) or [])
        result[n] = [
            p
            for p in prov_order
            if (ans := answers.get(p, {}).get(n))
            and set(ans).isdisjoint(ref_ips)
            and all(_prefix(ip) in clusters[p] for ip in ans)
        ]
    return result


def rules(support: dict[str, list[str]], providers) -> list[tuple[str, list[str]]]:
    """Build rules: (name, servers) for names with >=1 provider, sorted by name."""
    result = []
    for name in sorted(n for n, ps in support.items() if len(ps) >= 1):
        supp_set = set(support[name])
        servers: list[str] = []
        seen: set[str] = set()
        for p, addrs in providers:
            if p in supp_set:
                for addr in ([addrs] if isinstance(addrs, str) else addrs):
                    if addr not in seen:
                        seen.add(addr)
                        servers.append(addr)
        result.append((name, servers))
    return result


def signature(providers, names) -> str:
    """Canonical JSON sha256 hex signature of providers and names."""
    canonical = json.dumps({"names": list(names), "providers": providers}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def save_cache(path: str, support: dict, sig: str) -> None:
    """Save cache file atomically."""
    path = os.path.abspath(path)
    if parent := os.path.dirname(path):
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.{os.getpid()}.{time.time_ns()}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump({"sig": sig, "at": int(time.time()), "support": support}, f, indent=2)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def load_cache(path: str, sig: str, max_age: float = 86400) -> dict | None:
    """Load cached support dict if sig matches and not older than max_age."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("sig") != sig:
            return None
        if not isinstance(at := data.get("at"), (int, float)) or (time.time() - at) > max_age:
            return None
        return data.get("support") if isinstance(data.get("support"), dict) else None
    except Exception:
        return None
