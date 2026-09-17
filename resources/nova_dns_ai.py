# -*- coding: utf-8 -*-
"""Пользуется ли машина резолвером DNS-AI прямо сейчас.

У программы DNS-AI два несовместимых режима, и адреса в адаптере видны только
в одном из них:

* «Native DNS support» — в адаптеры прописаны собственные адреса резолвера
  (192.144.59.14 / 186.246.49.127 и их IPv6), а шифрует сама Windows по
  зарегистрированному DoH-шаблону;
* «Legacy DNS перехват» — в адаптеры прописан 127.0.0.1 (и ::1), шифрует сама
  программа: на этом адресе слушает её собственный резолвер. Это режим по
  умолчанию везде, где нет встроенного DoH-клиента (Windows 10), и именно он
  стоит на машине владельца.

Прежняя проверка искала в адаптерах адреса dns-ai.ru и поэтому видела только
первый режим. Во втором адаптер показывает 127.0.0.1, а по самому адресу
нельзя сказать, чей это резолвер: на той же машине рядом живёт 127.0.0.53 от
AG Unlocker. Поэтому Legacy определяется по владельцу сокета — какой процесс
держит :53 на том самом loopback-адресе, который прописан в адаптере. Это факт
о системе, а не догадка, и он отличает DNS-AI от любого другого локального
резолвера.

Замерено 2026-09-16 на машине владельца (Legacy-режим, портативная установка
без службы): 127.0.0.1:53 и ::1:53 держит `dns-ai.exe`, 127.0.0.53:53 —
`ag_dns.exe`; снимок процессов 4.5 мс, обе таблицы UDP 0.6 мс. Именованного
канала службы там нет вовсе, поэтому опрос канала годится только как запасной
признак, а не как основной.

Кому это нужно в Nova: правила NRPT уводят имена ИИ на явно указанный каскад
резолверов по обычному UDP. Пока DNS всей машины идёт через DNS-AI, такие
правила делают хуже в обоих режимах — они снимают эти имена с шифрованного
канала (и первыми в каскаде стоят адреса dns-ai.ru, которые открытый :53 не
обслуживают вовсе, то есть каждый запрос начинается с таймаута). Индикатор
«DNS-AI» на главном экране показывает тот же факт.

Отдельный модуль, а не функция в `nova.pyw`: только так это покрывается
тестами (I15). Ctypes-часть подменяется аргументами `detect_mode`.
"""

import contextlib
import ipaddress
import re

# Что вернул `detect_mode`. Пустая строка - DNS-AI машину не обслуживает.
MODE_NATIVE = "native"
MODE_STUB = "stub"

# Имя процесса резолвера. Оно одно и то же и для службы `DnsAiClient` (она
# запускает тот же файл с аргументом `service`), и для портативного запуска;
# `dns-ai-svc.exe` - имя прежней, отдельной службы, которое ещё может
# встретиться на машине, обновлявшейся с ранней версии.
PROCESS_PREFIX = "dns-ai"

# Запасные признаки: именованный канал службы и её запись в реестре. Оба
# означают лишь «клиент DNS-AI на машине есть», поэтому применяются только
# когда владельца сокета выяснить не удалось.
PIPE_NAME = r"\\.\pipe\dns-ai-svc"
SERVICE_KEY = r"SYSTEM\CurrentControlSet\Services\DnsAiClient"

DNS_PORT = 53


# ============================ разбор адресов ============================

def normalize_address(text):
    """Адрес в каноничной форме: `2A0D:8480:0000:067C::0014` и
    `2a0d:8480:0:67c::14` - это один адрес, а сравнение строк этого не знает.

    Неразбираемое значение возвращается как есть (в нижнем регистре): пусть
    вызывающий сравнит хотя бы текстом, а не потеряет его молча.
    """
    raw = str(text or "").strip().strip("[]")
    if not raw:
        return ""
    # Зона IPv6 (`fe80::1%12`) - свойство интерфейса, а не адреса.
    raw = raw.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(raw))
    except Exception:
        return raw.lower()


def normalize_addresses(values):
    return {a for a in (normalize_address(v) for v in (values or ())) if a}


def is_loopback(text):
    """127.0.0.0/8 или ::1 - адрес, за которым может сидеть локальный резолвер."""
    raw = str(text or "").strip().strip("[]").split("%", 1)[0]
    try:
        return bool(ipaddress.ip_address(raw).is_loopback)
    except Exception:
        return False


def loopback_addresses(values):
    return {a for a in normalize_addresses(values) if is_loopback(a)}


def is_dns_ai_process(name):
    """Имя процесса принадлежит DNS-AI.

    По префиксу, а не по точному списку: программа портативная, рядом с
    `dns-ai.exe` встречается `dns-ai-svc.exe`, а файл с версией в имени
    пользователь может сделать сам. `ag_dns.exe` от другой программы владельца
    под префикс не попадает - это и есть цель проверки.
    """
    text = str(name or "").strip().lower()
    if text.endswith(".exe"):
        text = text[:-4]
    return text.startswith(PROCESS_PREFIX)


# ======================= чтение состояния системы =======================

def system_dns_servers():
    """Адреса DNS, настроенные в системе. Читается из реестра, без процессов.

    PowerShell стоил бы 0.5-2 с на вызов (та же цена, что сделала фазу NRPT
    самой долгой на старте), а состояние опрашивает ещё и индикатор. Правило
    Windows: статический NameServer старше DhcpNameServer, и когда он задан,
    используется именно он - поэтому здесь тот же приоритет.
    """
    try:
        import winreg as _winreg
    except Exception:
        return set()
    servers = set()
    for branch in ("Tcpip", "Tcpip6"):
        key_path = "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters\\Interfaces" % branch
        try:
            root_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, key_path)
        except Exception:
            continue
        try:
            index = 0
            while True:
                try:
                    interface_name = _winreg.EnumKey(root_key, index)
                except OSError:
                    break
                except Exception:
                    break
                index += 1
                static_value = ""
                dhcp_value = ""
                try:
                    interface_key = _winreg.OpenKey(root_key, interface_name)
                except Exception:
                    continue
                try:
                    try:
                        static_value = _winreg.QueryValueEx(interface_key, "NameServer")[0]
                    except Exception:
                        static_value = ""
                    try:
                        dhcp_value = _winreg.QueryValueEx(interface_key, "DhcpNameServer")[0]
                    except Exception:
                        dhcp_value = ""
                finally:
                    with contextlib.suppress(Exception):
                        interface_key.Close()
                raw = str(static_value or "").strip() or str(dhcp_value or "").strip()
                for token in re.split(r"[,;\s]+", raw):
                    token = normalize_address(token)
                    if token:
                        servers.add(token)
        finally:
            with contextlib.suppress(Exception):
                root_key.Close()
    return servers


def _process_names():
    """{pid: имя.exe} снимком Toolhelp. Пустой словарь - снимок не получился."""
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

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
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.windll.kernel32
    names = {}
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if int(snapshot) == int(INVALID_HANDLE_VALUE):
        return names
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                with contextlib.suppress(Exception):
                    names[int(entry.th32ProcessID)] = str(entry.szExeFile or "").strip().lower()
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        with contextlib.suppress(Exception):
            kernel32.CloseHandle(snapshot)
    return names


def _socket_owners(port=DNS_PORT):
    """[(адрес, pid)] - кто слушает этот порт. None - таблицы прочитать не вышло.

    UDP и слушающий TCP вместе: резолвер DNS-AI открывает оба (`stub.rs`), но
    порядок появления сокетов не гарантирован ничем, а лишняя таблица стоит
    доли миллисекунды.
    """
    import ctypes
    import socket as _socket
    from ctypes import wintypes

    AF_INET = 2
    AF_INET6 = 23
    UDP_TABLE_OWNER_PID = 1
    TCP_TABLE_OWNER_PID_LISTENER = 3
    NO_ERROR = 0

    class MIB_UDPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("ucLocalAddr", ctypes.c_ubyte * 16),
            ("dwLocalScopeId", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("ucLocalAddr", ctypes.c_ubyte * 16),
            ("dwLocalScopeId", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("ucRemoteAddr", ctypes.c_ubyte * 16),
            ("dwRemoteScopeId", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwState", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    iphlpapi = ctypes.windll.iphlpapi
    rows = []
    read_any = False

    def _walk(getter, family, row_class, table_kind):
        nonlocal read_any
        size = wintypes.DWORD(0)
        getter(None, ctypes.byref(size), True, family, table_kind, 0)
        if int(size.value or 0) <= 0:
            return
        buffer = ctypes.create_string_buffer(size.value)
        if int(getter(ctypes.byref(buffer), ctypes.byref(size), True, family, table_kind, 0)) != NO_ERROR:
            return
        read_any = True
        count = int.from_bytes(buffer.raw[:4], "little")
        row_size = ctypes.sizeof(row_class)
        offset = 4
        for _ in range(count):
            chunk = buffer[offset:offset + row_size]
            offset += row_size
            if len(chunk) < row_size:
                break
            row = row_class.from_buffer_copy(chunk)
            if int(_socket.ntohs(int(row.dwLocalPort) & 0xFFFF)) != int(port):
                continue
            if family == AF_INET:
                address = _socket.inet_ntoa(int(row.dwLocalAddr).to_bytes(4, "little"))
            else:
                address = _socket.inet_ntop(_socket.AF_INET6, bytes(row.ucLocalAddr))
            rows.append((normalize_address(address), int(row.dwOwningPid)))

    for family, row_class in ((AF_INET, MIB_UDPROW_OWNER_PID), (AF_INET6, MIB_UDP6ROW_OWNER_PID)):
        with contextlib.suppress(Exception):
            _walk(iphlpapi.GetExtendedUdpTable, family, row_class, UDP_TABLE_OWNER_PID)
    for family, row_class in ((AF_INET, MIB_TCPROW_OWNER_PID), (AF_INET6, MIB_TCP6ROW_OWNER_PID)):
        with contextlib.suppress(Exception):
            _walk(iphlpapi.GetExtendedTcpTable, family, row_class, TCP_TABLE_OWNER_PID_LISTENER)
    return rows if read_any else None


def resolver_owner_names(addresses, port=DNS_PORT):
    """Имена процессов, слушающих `port` на этих адресах. None - выяснить не вышло.

    Пустое множество - это ответ, а не отказ: в адаптере стоит loopback, но на
    нём никто не отвечает. Слушающий на 0.0.0.0/:: попадает в ответ для любого
    loopback-адреса - такой сокет обслуживает и его тоже.
    """
    wanted = normalize_addresses(addresses)
    if not wanted:
        return set()
    owners = _socket_owners(port=port)
    if owners is None:
        return None
    wildcard = {"0.0.0.0", "::"}
    pids = {pid for address, pid in owners if address in wanted or address in wildcard}
    if not pids:
        return set()
    names = _process_names()
    return {names.get(pid, "") for pid in pids} - {""}


def client_present():
    """Запасной признак: клиент DNS-AI на машине есть и, похоже, работает.

    Именованный канал открывает служба; портативный запуск (машина владельца)
    его не создаёт вовсе, поэтому вторым идёт снимок процессов, а третьей -
    запись службы в реестре.
    """
    with contextlib.suppress(Exception):
        import ctypes
        from ctypes import wintypes

        ERROR_FILE_NOT_FOUND = 2
        ERROR_PATH_NOT_FOUND = 3
        kernel32 = ctypes.windll.kernel32
        kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
        kernel32.WaitNamedPipeW.restype = wintypes.BOOL
        if kernel32.WaitNamedPipeW(PIPE_NAME, 0):
            return True
        # Канал есть, но все его экземпляры заняты - это тоже «служба жива».
        if int(kernel32.GetLastError()) not in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
            return True
    with contextlib.suppress(Exception):
        if any(is_dns_ai_process(name) for name in _process_names().values()):
            return True
    with contextlib.suppress(Exception):
        import winreg as _winreg

        with _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY):
            return True
    return False


# ============================== сам ответ ==============================

def detect_mode(dns_ai_servers, servers=None, owners=None, present=None):
    """`MODE_NATIVE`, `MODE_STUB` или `""` - как машина сейчас ходит в DNS.

    `dns_ai_servers` - собственные адреса резолвера; единственный источник
    правды для них в Nova - каскад NRPT, поэтому они приходят аргументом, а не
    заводятся здесь второй копией.

    `servers`, `owners`, `present` подменяются в тестах; по умолчанию читается
    настоящая система.
    """
    values = servers if servers is not None else system_dns_servers()
    configured = normalize_addresses(values)
    if configured & normalize_addresses(dns_ai_servers):
        return MODE_NATIVE

    loopback = {a for a in configured if is_loopback(a)}
    if not loopback:
        return ""

    owners_func = owners if owners is not None else resolver_owner_names
    try:
        names = owners_func(loopback)
    except Exception:
        names = None
    if names is not None:
        return MODE_STUB if any(is_dns_ai_process(name) for name in names) else ""

    # Владельца сокета выяснить не удалось. Тогда решает наличие самого
    # клиента: в адаптере уже стоит loopback, и если DNS-AI на машине живёт,
    # почти наверняка этот loopback его.
    present_func = present if present is not None else client_present
    try:
        return MODE_STUB if present_func() else ""
    except Exception:
        return ""


def is_active(dns_ai_servers, **kwargs):
    """DNS машины идёт через DNS-AI - в любом из двух режимов."""
    return bool(detect_mode(dns_ai_servers, **kwargs))
