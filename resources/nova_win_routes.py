"""Физический маршрут наружу — через Windows API, без единого процесса.

Раньше это спрашивал PowerShell: `Get-NetIPConfiguration` с фильтром по имени
адаптера. Один такой спавн стоит на этой машине около 1400 мс, а вызов сидит в
цикле ожидания с шагом 0.5 с — то есть цикл, рассчитанный на шестнадцать
попыток за восемь секунд, получал четыре. Здесь тот же ответ собирается из
`GetAdaptersAddresses` и `GetIpForwardTable` за доли миллисекунды.

Отвечать нужно ровно на тот же вопрос, что и прежний PowerShell, потому что от
формы ответа зависит доверие к измерению: непустой `gateway` означает «это
настоящий адаптер», а пустой — что сработал UDP-фолбэк, который при поднятом
TUN возвращает адрес ВНУТРИ туннеля. Ошибка здесь не косметическая: вызывающий
на её основании чистит суточный кэш проверок доменов.

Поэтому логика повторена буквально:
  1. адаптеры со статусом Up, с адресом IPv4 и со шлюзом по умолчанию;
  2. из них выкидываются те, чьё имя или описание похоже на VPN;
  3. берётся первый; если после фильтра не осталось никого — первый из всех;
  4. отдаются alias, IPv4 и NextHop шлюза.
"""

import ctypes
import ctypes.wintypes
import os
import re
import socket
import struct

# Те же имена, что в прежнем PowerShell-фильтре, слово в слово. Список описывает
# «это туннель, а не физический выход» и должен меняться только вместе с ним.
VPN_NAME_PATTERN = re.compile(
    r"Cloudflare|WARP|NovaVoice|WireGuard|Amnezia|TAP|TUN|Wintun|Proton|OpenVPN|"
    r"ZeroTier|Tailscale|WG|Sing-Box|Remote NDIS|Bluetooth|VMware|WireSock|SSTAP",
    re.IGNORECASE,
)

AF_INET = 2
AF_UNSPEC = 0
IF_OPER_STATUS_UP = 1
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
ERROR_BUFFER_OVERFLOW = 111


class _SOCKADDR(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 26)]


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.POINTER(_SOCKADDR)), ("iSockaddrLength", ctypes.c_int)]


class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


_IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", ctypes.c_ulong),
    ("PreferredLifetime", ctypes.c_ulong),
    ("LeaseLifetime", ctypes.c_ulong),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class _IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
    pass


_IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
    ("Length", ctypes.c_ulong),
    ("Reserved", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
]


class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", ctypes.c_ulong),
    ("IfIndex", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Mtu", ctypes.c_ulong),
    ("IfType", ctypes.c_ulong),
    ("OperStatus", ctypes.c_int),
    ("Ipv6IfIndex", ctypes.c_ulong),
    ("ZoneIndices", ctypes.c_ulong * 16),
    ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_ulonglong),
    ("ReceiveLinkSpeed", ctypes.c_ulonglong),
    ("FirstWinsServerAddress", ctypes.c_void_p),
    ("FirstGatewayAddress", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Ipv4Metric", ctypes.c_ulong),
    ("Ipv6Metric", ctypes.c_ulong),
    ("Luid", ctypes.c_ulonglong),
    ("Dhcpv4Server", _SOCKET_ADDRESS),
    ("CompartmentId", ctypes.c_uint32),
    ("NetworkGuid", ctypes.c_ubyte * 16),
    ("ConnectionType", ctypes.c_int),
    ("TunnelType", ctypes.c_int),
    ("Dhcpv6Server", _SOCKET_ADDRESS),
    ("Dhcpv6ClientDuid", ctypes.c_ubyte * 130),
    ("Dhcpv6ClientDuidLength", ctypes.c_ulong),
    ("Dhcpv6Iaid", ctypes.c_ulong),
    ("FirstDnsSuffix", ctypes.c_void_p),
]


def _ipv4_of(sockaddr_ptr):
    """IPv4 из SOCKET_ADDRESS, или '' если это не IPv4."""
    try:
        if not sockaddr_ptr:
            return ""
        sa = sockaddr_ptr.contents
        if sa.sa_family != AF_INET:
            return ""
        # sockaddr_in: 2 байта family, 2 байта порт, дальше 4 байта адреса
        return socket.inet_ntoa(bytes(sa.sa_data[2:6]))
    except Exception:
        return ""


def list_adapters():
    """Адаптеры Up с IPv4, в порядке, который отдаёт система."""
    if os.name != "nt":
        return []
    size = ctypes.c_ulong(0)
    flags = (GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
             | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS)
    rc = ctypes.windll.iphlpapi.GetAdaptersAddresses(AF_UNSPEC, flags, None, None, ctypes.byref(size))
    if rc != ERROR_BUFFER_OVERFLOW and rc != 0:
        return []
    buf = ctypes.create_string_buffer(size.value)
    rc = ctypes.windll.iphlpapi.GetAdaptersAddresses(
        AF_UNSPEC, flags, None,
        ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES)), ctypes.byref(size))
    if rc != 0:
        return []

    out = []
    node = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
    while node:
        a = node.contents
        if a.OperStatus == IF_OPER_STATUS_UP:
            ip = ""
            uni = a.FirstUnicastAddress
            while uni and not ip:
                ip = _ipv4_of(uni.contents.Address.lpSockaddr)
                uni = uni.contents.Next
            gw = ""
            g = a.FirstGatewayAddress
            while g and not gw:
                gw = _ipv4_of(g.contents.Address.lpSockaddr)
                g = g.contents.Next
            if ip:
                out.append({
                    "alias": a.FriendlyName or "",
                    "description": a.Description or "",
                    "ip": ip,
                    "gateway": gw,
                    "index": int(a.IfIndex),
                    "metric": int(a.Ipv4Metric),
                })
        node = a.Next
    return out


def default_route_gateways():
    """Шлюзы маршрутов 0.0.0.0/0, по возрастанию метрики: [(metric, gw, ifindex)]."""
    if os.name != "nt":
        return []

    class _ROW(ctypes.Structure):
        _fields_ = [("dwForwardDest", ctypes.c_ulong), ("dwForwardMask", ctypes.c_ulong),
                    ("dwForwardPolicy", ctypes.c_ulong), ("dwForwardNextHop", ctypes.c_ulong),
                    ("dwForwardIfIndex", ctypes.c_ulong), ("dwForwardType", ctypes.c_ulong),
                    ("dwForwardProto", ctypes.c_ulong), ("dwForwardAge", ctypes.c_ulong),
                    ("dwForwardNextHopAS", ctypes.c_ulong), ("dwForwardMetric1", ctypes.c_ulong),
                    ("dwForwardMetric2", ctypes.c_ulong), ("dwForwardMetric3", ctypes.c_ulong),
                    ("dwForwardMetric4", ctypes.c_ulong), ("dwForwardMetric5", ctypes.c_ulong)]
    try:
        size = ctypes.c_ulong(0)
        ctypes.windll.iphlpapi.GetIpForwardTable(None, ctypes.byref(size), 0)
        buf = ctypes.create_string_buffer(size.value)
        if ctypes.windll.iphlpapi.GetIpForwardTable(buf, ctypes.byref(size), 0) != 0:
            return []
        count = struct.unpack("I", buf.raw[:4])[0]
        step = ctypes.sizeof(_ROW)
        rows = []
        for i in range(count):
            off = 4 + i * step
            r = _ROW.from_buffer_copy(buf.raw[off:off + step])
            if r.dwForwardDest == 0 and r.dwForwardMask == 0:
                gw = socket.inet_ntoa(struct.pack("I", r.dwForwardNextHop))
                rows.append((int(r.dwForwardMetric1), gw, int(r.dwForwardIfIndex)))
        rows.sort()
        return rows
    except Exception:
        return []


def looks_like_tunnel(adapter):
    name = "%s %s" % (adapter.get("alias") or "", adapter.get("description") or "")
    return bool(VPN_NAME_PATTERN.search(name))


def direct_route_info():
    """{'alias','ip','gateway'} физического выхода, или None.

    Тот же отбор, что делал PowerShell. Шлюз берётся из адаптера, а при его
    отсутствии — из таблицы маршрутов по индексу интерфейса: `GetAdaptersAddresses`
    не всегда заполняет FirstGatewayAddress, а пустой шлюз здесь означает
    «доверять нельзя», так что вторая попытка тут не роскошь.
    """
    adapters = [a for a in list_adapters() if a.get("gateway")]
    if not adapters:
        by_index = {}
        for metric, gw, idx in default_route_gateways():
            by_index.setdefault(idx, gw)
        for a in list_adapters():
            gw = by_index.get(a.get("index"))
            if gw:
                a = dict(a)
                a["gateway"] = gw
                adapters.append(a)

    if not adapters:
        return None
    physical = [a for a in adapters if not looks_like_tunnel(a)]
    pick = (physical or adapters)[0]
    ip = str(pick.get("ip") or "")
    if not ip or "." not in ip or ip.startswith("127."):
        return None
    return {
        "alias": str(pick.get("alias") or "direct"),
        "ip": ip,
        "gateway": str(pick.get("gateway") or ""),
    }
