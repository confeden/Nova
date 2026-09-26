"""Детектор блокировки AI-сервисов по региону на выходе second и DNS-разблокировщиков.

Домены AI, лежащие в second.txt, идут через дополнительный VPN. Если его выход сервис
отвергает по региону (API без ключа отвечает «unsupported country» вместо 401), а имя
сервиса разворачивает DNS-разблокировщик (dns-ai.ru, xbox-dns.ru, comss.one, geohide.ru —
системный DNS адаптера, клиент DNS-AI или правило NRPT), этим доменам лучше напрямую
по winws: разблокировщик отдаёт адрес своего зарубежного прокси.

Главные страницы (chatgpt.com, claude.ai) для детекта непригодны: замерено 2026-09-26 —
Cloudflare-челлендж 403 и из разрешённого региона. Поэтому пробуются API-адреса.
"""
import sys
from typing import NamedTuple

class Service(NamedTuple):
    id: str
    suffixes: tuple[str, ...]
    url: str

class Unblockers(NamedTuple):
    system: tuple[str, ...]
    nrpt: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]

SERVICES = (
    Service(
        "openai",
        ("openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com"),
        "https://api.openai.com/v1/models"
    ),
    Service(
        "anthropic",
        ("anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com", "claudemcpcontent.com"),
        "https://api.anthropic.com/v1/models"
    ),
    Service(
        "google_ai",
        ("gemini.google.com", "aistudio.google.com", "notebooklm.google.com", "notebooklm.google",
         "generativelanguage.googleapis.com", "alkalimakersuite-pa.clients6.google.com"),
        "https://generativelanguage.googleapis.com/v1beta/models?key=nova-region-probe"
    ),
    Service(
        "xai",
        ("x.ai", "grok.com"),
        "https://api.x.ai/v1/models"
    )
)

def service_for(host: str) -> Service | None:
    host = host.lower().rstrip(".")
    best = None
    best_len = -1
    for s in SERVICES:
        for suffix in s.suffixes:
            if host == suffix or host.endswith("." + suffix):
                if len(suffix) > best_len:
                    best = s
                    best_len = len(suffix)
    return best

def classify(service_id: str, status: int, body: str) -> str:
    body_lower = body.lower()
    blocked_phrases = (
        "unsupported_country",
        "country, region, or territory",
        "user location is not supported",
        "not available in your region",
        "not available in your country",
        "request not allowed"
    )
    if status == 451 or any(p in body_lower for p in blocked_phrases):
        return "blocked"
    if status in (200, 401) or (status == 400 and ("api key not valid" in body_lower or "api_key_invalid" in body_lower)):
        return "ok"
    return "unknown"

def probe(service: Service, proxy_url: str, timeout=(6, 10), session_factory=None) -> str:
    if session_factory:
        session = session_factory()
    else:
        import requests
        session = requests.Session()
        session.trust_env = False
        session.proxies = {"http": proxy_url, "https": proxy_url}

    try:
        resp = session.get(service.url, headers={"User-Agent": "Mozilla/5.0"}, stream=True, timeout=timeout)
        chunks = []
        read_bytes = 0
        for chunk in resp.iter_content(chunk_size=4096):
            if chunk:
                chunks.append(chunk)
                read_bytes += len(chunk)
                if read_bytes >= 65536:
                    break
        body = b"".join(chunks).decode("utf-8", errors="replace")
        resp.close()
        return classify(service.id, resp.status_code, body)
    except Exception:
        return "unknown"
    finally:
        session.close()

def probe_all(proxy_url: str, services=SERVICES, **kw) -> dict[str, str]:
    return {s.id: probe(s, proxy_url, **kw) for s in services}

def read_nrpt_rules() -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    if sys.platform != "win32":
        return []
    import winreg
    from nova_dns_ai import normalize_address

    rules = []
    keys = (
        r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig",
        r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"
    )
    for key_path in keys:
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        except OSError:
            continue
        try:
            idx = 0
            while True:
                try:
                    subkey = winreg.EnumKey(root, idx)
                except OSError:
                    break
                idx += 1
                try:
                    with winreg.OpenKey(root, subkey) as sk:
                        names, _ = winreg.QueryValueEx(sk, "Name")
                        servers_raw, _ = winreg.QueryValueEx(sk, "GenericDNSServers")

                        if isinstance(names, str):
                            names = [names]
                        if not isinstance(names, list):
                            continue

                        namespaces = tuple(n.lower().lstrip(".") for n in names if n)

                        servers = []
                        if isinstance(servers_raw, str):
                            for s in servers_raw.split(";"):
                                norm = normalize_address(s)
                                if norm:
                                    servers.append(norm)

                        if namespaces and servers:
                            rules.append((namespaces, tuple(servers)))
                except OSError:
                    pass
        finally:
            root.Close()
    return rules

def detect_unblockers(providers: tuple, adapter_servers=None, nrpt_rules=None, dns_ai_mode="") -> Unblockers:
    from nova_dns_ai import system_dns_servers, normalize_address, normalize_addresses

    if adapter_servers is None:
        adapter_servers = system_dns_servers()
    adapter_servers = set(normalize_addresses(adapter_servers or ()))
    if nrpt_rules is None:
        nrpt_rules = read_nrpt_rules()

    addr_to_prov = {}
    for prov_name, addrs in providers:
        for a in addrs:
            norm = normalize_address(a)
            if norm:
                addr_to_prov[norm] = prov_name

    active_sys = set()
    for prov_name, addrs in providers:
        for a in addrs:
            norm = normalize_address(a)
            if norm and norm in adapter_servers:
                active_sys.add(prov_name)
    if dns_ai_mode:
        active_sys.add("dns-ai.ru")

    system = []
    for prov_name, _ in providers:
        if prov_name in active_sys and prov_name not in system:
            system.append(prov_name)
    if "dns-ai.ru" in active_sys and "dns-ai.ru" not in system:
        system.append("dns-ai.ru")

    nrpt = []
    for namespaces, servers in nrpt_rules:
        provs = []
        for s in servers:
            p = addr_to_prov.get(s)
            if p and p not in provs:
                provs.append(p)
        if provs:
            nrpt.append((namespaces, tuple(provs)))

    return Unblockers(tuple(system), tuple(nrpt))

def unblocker_for(host: str, unblockers: Unblockers) -> str | None:
    if unblockers.system:
        return unblockers.system[0]
    
    host_lower = host.lower()
    for namespaces, provs in unblockers.nrpt:
        for ns in namespaces:
            if host_lower == ns or host_lower.endswith("." + ns):
                return provs[0]
    return None

def describe(unblockers: Unblockers) -> str:
    if not unblockers.system and not unblockers.nrpt:
        return "нет"
    parts = []
    if unblockers.system:
        parts.append(f"системный DNS: {', '.join(unblockers.system)}")
    if unblockers.nrpt:
        nrpt_provs = []
        for _, provs in unblockers.nrpt:
            for p in provs:
                if p not in nrpt_provs:
                    nrpt_provs.append(p)
        parts.append(f"NRPT: {', '.join(nrpt_provs)} ({len(unblockers.nrpt)} правил)")
    return "; ".join(parts)

def direct_domains(domains: set[str] | list[str], verdicts: dict[str, str], unblockers: Unblockers) -> set[str]:
    result = set()
    for d in domains:
        s = service_for(d)
        if s and verdicts.get(s.id) == "blocked" and unblocker_for(d, unblockers) is not None:
            result.add(d)
    return result

def summary(verdicts: dict[str, str]) -> str:
    parts = []
    for s in SERVICES:
        if s.id in verdicts:
            v = verdicts[s.id]
            if v == "ok":
                ru = "доступен"
            elif v == "blocked":
                ru = "блок региона"
            else:
                ru = "не ясно"
            parts.append(f"{s.id}: {ru}")
    return ", ".join(parts)
