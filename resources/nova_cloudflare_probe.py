"""Evidence gathering for the Cloudflare-fronted-site classifier.

Two-tier probe, deliberately not trusting the system's own DNS path for the
part that decides "was this blocked": the reported bug is that a
Cloudflare-fronted site fails completely until manually added to a route
list, and the leading theory (.claude/kb/routing.md) is that ordinary DNS
resolution for that domain is itself interfered with -- so confirming "is
this really Cloudflare and really reachable" has to use a path that does not
depend on the same resolution the baseline probe just failed at.

Talks to nova-engine's `cloudflare-classify` subcommand, not to
nova_cloudflare directly -- that crate deliberately carries no networking
code, this module is the evidence half of the adapter it expects.
"""

import socket
import ssl

BASELINE_TIMEOUT_SEC = 4.0
FALLBACK_TIMEOUT_SEC = 5.0
FALLBACK_PORT = 443
HEAD_RESPONSE_CAP = 8192


def _empty_evidence():
    return {
        "addresses": [],
        "cname_chain": [],
        "server_header": None,
        "cf_ray": False,
        "cf_mitigated": False,
        "status": None,
        "failure": None,
    }


def first_cloudflare_ipv4(cloudflare_cidr_path):
    """First host address in the first IPv4 CIDR of ip/cloudflare.txt.

    Cloudflare's edge is anycast: any address in the published ranges reaches
    the same reverse proxy and answers for any hostname sent as SNI/Host, so
    which one is used does not matter -- only whether it is really theirs.
    """
    try:
        with open(cloudflare_cidr_path, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.split("#", 1)[0].strip()
                if not line or ":" in line:
                    continue
                network = line.split("/", 1)[0]
                parts = network.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    return ".".join(parts[:3] + [str(int(parts[3]) + 1)])
    except OSError:
        pass
    return "104.16.0.1"  # Cloudflare-owned fallback if the list is unreadable.


def classify_socket_failure(exc):
    """Map a Python network exception to a BlockSignature name the Rust
    classifier understands.

    Best-effort: precision beyond "did this look like interference" is not
    needed for the v1 decision -- nova-cloudflare's policy::decide only
    branches on BlockSignature::is_not_our_fault(), and every signature this
    returns is deliberately NOT in that "not our fault" set (ConnectionRefused/
    CloudflareOriginDown/DnsFailure), because a signal only reaches this
    function after the DNS-independent edge probe already confirmed the site
    is real, Cloudflare-fronted and reachable -- so a baseline failure at this
    point is evidence of interference, not of a broken destination.
    """
    if isinstance(exc, socket.gaierror):
        return "dns_poisoned"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "blackholed"
    if isinstance(exc, ConnectionResetError):
        return "rst_immediate"
    if isinstance(exc, ssl.SSLError):
        return "sni_timeout"
    return "blackholed"


def _send_head_and_read(tls_sock, host, evidence):
    """Issue a HEAD request over an already-established TLS socket and fill
    in the header-derived evidence fields. Returns True if any response
    bytes came back at all."""
    request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    tls_sock.sendall(request.encode("ascii", errors="ignore"))
    tls_sock.settimeout(4.0)
    raw = b""
    try:
        while len(raw) < HEAD_RESPONSE_CAP:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw:
                break
    except (socket.timeout, TimeoutError):
        pass
    if not raw:
        return False

    text = raw.decode("latin-1", errors="ignore")
    header_block = text.split("\r\n\r\n", 1)[0]
    lines = header_block.split("\r\n")
    try:
        evidence["status"] = int(lines[0].split()[1])
    except (IndexError, ValueError):
        pass
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        name = name.strip().lower()
        value = value.strip()
        if name == "server":
            evidence["server_header"] = value.lower()
        elif name == "cf-ray":
            evidence["cf_ray"] = True
        elif name == "cf-mitigated":
            evidence["cf_mitigated"] = True
    return True


def probe_baseline(host, timeout=BASELINE_TIMEOUT_SEC):
    """What a browser itself would see: normal DNS, then a normal HTTPS
    request with full certificate verification.

    Returns (ok, evidence). `evidence["failure"]` is set to a BlockSignature
    name whenever ok is False.
    """
    evidence = _empty_evidence()
    try:
        infos = socket.getaddrinfo(host, FALLBACK_PORT, proto=socket.IPPROTO_TCP)
        evidence["addresses"] = sorted({info[4][0] for info in infos})
    except OSError as e:
        evidence["failure"] = classify_socket_failure(e)
        return False, evidence

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((evidence["addresses"][0], FALLBACK_PORT), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                if not _send_head_and_read(tls, host, evidence):
                    evidence["failure"] = "sni_timeout"
                    return False, evidence
        return True, evidence
    except Exception as e:
        evidence["failure"] = classify_socket_failure(e)
        return False, evidence


def probe_via_cloudflare_edge(host, cloudflare_cidr_path, timeout=FALLBACK_TIMEOUT_SEC):
    """Dial a known-Cloudflare IP directly, bypassing DNS resolution of
    `host` entirely, and ask for `host` by SNI/Host. A response carrying a
    cf-ray header is strong, DNS-independent proof the domain really is
    Cloudflare-fronted and reachable at the edge.

    Certificate verification stays ON: `server_hostname=host` makes SNI (and
    therefore the certificate Cloudflare's edge presents, and therefore what
    ssl verifies against) follow `host`, not the literal `edge_ip` socket
    address being dialed -- that is the whole mechanism that lets one IP
    terminate TLS for many domains. A verified response is a *stronger*
    signal than an unverified one: it proves the edge holds a real
    certificate for `host`, which a naive interception box faking a
    `cf-ray` header would not.
    """
    edge_ip = first_cloudflare_ipv4(cloudflare_cidr_path)
    evidence = _empty_evidence()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((edge_ip, FALLBACK_PORT), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                got_response = _send_head_and_read(tls, host, evidence)
        return (got_response and evidence["cf_ray"]), evidence
    except Exception as e:
        evidence["failure"] = classify_socket_failure(e)
        return False, evidence


def gather_evidence(host, cloudflare_cidr_path):
    """Two-tier probe entry point.

    Returns (should_classify, evidence). should_classify is False when the
    baseline path already works (nothing to fix) or when even the
    DNS-independent edge probe could not confirm Cloudflare + reachability
    (no independent evidence worth acting on).
    """
    baseline_ok, baseline_evidence = probe_baseline(host)
    if baseline_ok:
        return False, baseline_evidence

    edge_ok, edge_evidence = probe_via_cloudflare_edge(host, cloudflare_cidr_path)
    if not edge_ok:
        return False, edge_evidence

    # Identity/reachability proof comes from the edge probe; the failure
    # signature comes from the path that could not reach the host directly.
    combined = dict(edge_evidence)
    combined["failure"] = baseline_evidence["failure"]
    if not combined["addresses"]:
        combined["addresses"] = baseline_evidence["addresses"]
    return True, combined
