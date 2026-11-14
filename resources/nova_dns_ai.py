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
import os
import ipaddress
import base64
import json
import re
import socket
import subprocess
import time
import sys
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import nova_exit_probe

# Что вернул `detect_mode`. Пустая строка - DNS-AI машину не обслуживает.
MODE_NATIVE = "native"
MODE_STUB = "stub"

# Шаблон DoH, который DNS-AI ставит в систему. Адреса в адаптере без него -
# это открытый UDP/53, а сервис на нём не отвечает (G74 / D18): такая машина
# DNS-AI не обслуживает, и разблокировку ставит Nova.
DOH_TEMPLATE = "https://dns.dns-ai.ru/dns-query"
INSTALL_SERVERS = ("194.87.196.13", "45.151.102.219", "2a00:b700:5::3:62", "2a12:5940:d4ef::219")
DOH_CACHE_SECONDS = 60.0
_doh_cache = {"ts": 0.0, "value": False}


# Три входа в DNS-AI, все с DoH. Порядок - предпочтение: пока первый отвечает, остальные не
# трогаются; если он не проходит (например, его не пускает стратегия winws), работает следующий.
#
#   dns.dns-ai.ru - наш прямой адрес, все транспорты, GET и POST;
#   cf.dns-ai.ru  - за Cloudflare (бесплатный тариф): только DoH, GET и POST; клиент ходит на адреса
#                   Cloudflare, они плавают, поэтому разрешаются во время работы, а не вшиваются;
#   ru.dns-ai.ru  - через CDN, ТОЛЬКО личная ссылка: весь путь - токен устройства,
#                   https://ru.dns-ai.ru/<token>. Без токена ответ 404 - это "ссылка не задана", а не "умер".
#                   CDN для этого ресурса отдаёт POST с 413: вход только на GET (?dns=<base64url>).
#                   Поэтому ru - ОПЦИОНАЛЬНЫЙ: без сохранённой ссылки его не пробуют и не считают сбоем.
# Замерено 2026-11-13 с домашней линии: dns/cf отвечали 200 на GET, cf и на POST; ru 404 без токена,
# 200 по GET с токеном, 413 по POST.
DNS_AI_DOMAIN = "dns-ai.ru"
DOH_HOSTS = ("dns.dns-ai.ru", "cf.dns-ai.ru", "ru.dns-ai.ru")
HOST_DIRECT, HOST_CF, HOST_RU = DOH_HOSTS
DOH_PATH = "/dns-query"
PERSONAL_HOSTS = (HOST_RU,)        # нужен токен; без него вход пропускается
GET_ONLY_HOSTS = (HOST_RU,)        # POST отвергается (413)
PROBE_METHOD = "GET"               # чем пробует Nova; GET_ONLY_HOSTS всегда GET
# Системный DoH-клиент Windows с ru НЕ РАБОТАЕТ (замер 2026-11-13 на этом ПК): Windows помечает адрес ru как
# «Unencrypted», новые имена с ru первым в списке резолвятся 8-27 с (к ru идут повторы, потом Windows
# переходит на следующий сервер). Скорее всего он шлёт POST, а CDN за ru на POST отвечает 413; документация
# Microsoft о методе молчит. True - ru в списке Windows в порядке выбора; None (не измерено) - ru последним;
# False - ru в Windows не ставится (Nova ходит к нему сама, по GET).
WINDOWS_DOH_SENDS_GET = False
RU_EDGE_NAME = "b3280326fa528d82.topology.gslb.yccdn.ru"   # имя края CDN, запасной вход для разрешения ru
PERSONAL_TOKEN_RE = re.compile(r"^[a-z2-7]{13}$")
PERSONAL_LINK_FILE = "dns-ai-ru-link.txt"                  # в profiles/.runtime: не в git, не в temp (I19)
ENTRANCE_CACHE_FILE = "dns-ai-entrances.json"              # последние отвечавшие адреса CDN
LINK_STATUS_FILE = "dns-ai-ru-status.json"                 # принята ли сохранённая ссылка (без токена)
LINK_ACCEPTED, LINK_REJECTED, LINK_UNVERIFIED = "accepted", "rejected", "unverified"
LINK_RECHECK_SECONDS = 600.0                               # непроверенную ссылку перепроверяем чаще
# Выбор входа в меню индикатора: "auto" - каскад dns -> cf -> ru; иначе выбранный идёт первым.
ENTRANCE_HOSTS = {"dns": HOST_DIRECT, "cf": HOST_CF, "ru": HOST_RU}
ENTRANCE_AUTO = "auto"
_preferred_entrance = [ENTRANCE_AUTO]
MAX_ADDRESSES_PER_FAMILY = 2
ENTRANCE_REFRESH_SECONDS = 6 * 3600.0
_chosen_host = {}   # (kind, port) -> host that answered last time through that route
_runtime_dir = [None]


def is_dns_ai_name(host):
    """dns-ai.ru and any subdomain: dns./cf./ru. today, whatever the owner adds next."""
    name = str(host or "").strip().lower().rstrip(".")
    return name == DNS_AI_DOMAIN or name.endswith("." + DNS_AI_DOMAIN)


def chosen_host(kind, port):
    return _chosen_host.get((kind, port))


# ---------------------------------------------------------------- personal ru link (a secret)

def set_runtime_dir(path):
    """Where the personal link and the entrance cache live (`profiles/.runtime`, hidden from git)."""
    _runtime_dir[0] = str(path) if path else None


def _runtime_file(name):
    return os.path.join(_runtime_dir[0], name) if _runtime_dir[0] else None


def normalize_personal_token(text):
    """The 13-char token out of what the user pasted: the bare token, `https://ru.dns-ai.ru/<token>`
    or the browser template `https://ru.dns-ai.ru/<token>{?dns}`. Empty string - not a valid link."""
    value = str(text or "").strip()
    if "://" in value:
        parts = urlsplit(value)
        if (parts.hostname or "").lower() != HOST_RU:
            return ""
        value = parts.path
    elif value.lower().startswith(HOST_RU + "/"):
        value = value[len(HOST_RU):]
    segment = value.strip("/").split("/")[0]
    token = re.split(r"[{?#]", segment, maxsplit=1)[0].strip().lower()
    return token if PERSONAL_TOKEN_RE.match(token) else ""


def load_personal_token():
    path = _runtime_file(PERSONAL_LINK_FILE)
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return normalize_personal_token(handle.read())
    except OSError:
        return ""


def personal_link_error(text):
    """Why `text` is not a personal ru link, in Russian and without quoting it. Empty string - it is one."""
    if normalize_personal_token(text):
        return ""
    value = str(text or "").strip()
    if "://" in value and (urlsplit(value).hostname or "").lower() != HOST_RU:
        return "Ссылка ведёт не на ru.dns-ai.ru. Нужна личная ссылка из Витрины."
    return ("Неверная форма ссылки. Ожидается https://ru.dns-ai.ru/<токен из 13 символов a-z и 2-7> "
            "(можно с {?dns} на конце) или сам токен.")


def save_personal_token(text):
    """Store the link (token only). Raises ValueError for text that is not a ru.dns-ai.ru link;
    the message never contains the text. A new link starts unverified."""
    token = normalize_personal_token(text)
    if not token:
        raise ValueError(personal_link_error(text))
    path = _runtime_file(PERSONAL_LINK_FILE)
    if not path:
        raise RuntimeError("Каталог для личной ссылки DNS-AI не задан.")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    os.replace(temp, path)
    _clear_link_status()
    return token


def clear_personal_token():
    path = _runtime_file(PERSONAL_LINK_FILE)
    if path:
        with contextlib.suppress(OSError):
            os.remove(path)
    _clear_link_status()


def _clear_link_status():
    path = _runtime_file(LINK_STATUS_FILE)
    if path:
        with contextlib.suppress(OSError):
            os.remove(path)


def _set_link_status(state):
    path = _runtime_file(LINK_STATUS_FILE)
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"state": state, "ts": time.time()}, handle)
    except OSError as error:
        logging.getLogger(__name__).warning("DNS-AI: состояние личной ссылки не сохранено (%s)", error)


def link_status():
    """"" (no link), "accepted", "rejected" or "unverified" for the stored personal link."""
    if not load_personal_token():
        return ""
    path = _runtime_file(LINK_STATUS_FILE)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            state = (json.load(handle) or {}).get("state")
    except (OSError, TypeError, ValueError, AttributeError):
        return LINK_UNVERIFIED
    return state if state in (LINK_ACCEPTED, LINK_REJECTED) else LINK_UNVERIFIED


def link_status_age():
    """Seconds since the link was last checked; a very large number when never."""
    try:
        return max(0.0, time.time() - os.path.getmtime(_runtime_file(LINK_STATUS_FILE)))
    except (OSError, TypeError):
        return 1e12


def check_personal_link(budget=6.0, probe=None):
    """Live check of the stored link: one GET on /<token>?dns=. 200 -> accepted, 404 -> rejected (wrong
    or revoked), anything else (network, TLS, 5xx) -> unverified. The result is remembered. Returns the
    state, "" when no link is stored."""
    token = load_personal_token()
    if not token:
        _clear_link_status()
        return ""
    try:
        (probe or (lambda: _probe_one_host("direct", 0, HOST_RU, budget, token)))()
        state = LINK_ACCEPTED
    except nova_exit_probe.ProbeError as error:
        state = LINK_REJECTED if "HTTP 404" in str(error) else LINK_UNVERIFIED
    _set_link_status(state)
    return state


# ---------------------------------------------------------------- which entrance is preferred

def normalize_entrance(value):
    return value if value in ENTRANCE_HOSTS else ENTRANCE_AUTO


def ordered_hosts(choice=None):
    """The cascade with the chosen entrance first; "auto" is dns, cf, ru."""
    choice = normalize_entrance(_preferred_entrance[0] if choice is None else choice)
    if choice == ENTRANCE_AUTO:
        return DOH_HOSTS
    first = ENTRANCE_HOSTS[choice]
    return (first,) + tuple(host for host in DOH_HOSTS if host != first)


def set_preferred_entrance(choice):
    _preferred_entrance[0] = normalize_entrance(choice)


def ru_blocker():
    """Why ru cannot be chosen right now (Russian, for the menu); "" when it can."""
    status = link_status()
    if not status:
        return "нужна личная ссылка из Витрины"
    if status == LINK_REJECTED:
        return "ссылка не принята (проверьте в Витрине, не отозвана ли)"
    if status == LINK_UNVERIFIED:
        return "ссылка ещё не проверена"
    return ""


def windows_ru_blocker():
    """Why ru is not (fully) a Windows DoH server. the CDN behind it serves it by GET only (POST -> 413). "" only when
    Windows' own DoH client is known to send GET; unmeasured, ru is kept as the LAST server of the list."""
    if WINDOWS_DOH_SENDS_GET is True:
        return ""
    if WINDOWS_DOH_SENDS_GET is False:
        return ("системный DoH Windows с ru не работает (адрес остаётся незашифрованным, ответы запаздывают; "
                "CDN за ru принимает только GET, на POST отвечает 413), поэтому в список Windows ru не ставится")
    return ("метод системного DoH Windows не подтверждён (CDN за ru принимает только GET, на POST отвечает 413); "
            "поэтому ru стоит в списке Windows последним, запасным входом")


def entrance_reset_reason(choice):
    """Non-empty when a saved choice cannot stand: the link is gone, revoked or not accepted."""
    if normalize_entrance(choice) == "ru":
        return ru_blocker()
    return ""


def entrance_path(host, token=""):
    return "/" + token if host in PERSONAL_HOSTS else DOH_PATH


def entrance_template(host, token=""):
    """The DoH template for a browser or Windows; the personal one carries the token and `{?dns}`."""
    return "https://" + host + entrance_path(host, token) + ("{?dns}" if host in PERSONAL_HOSTS else "")


def active_hosts(hosts=DOH_HOSTS, token=None):
    """The entrances worth trying now: a personal one only when a link is stored (skipped, not failed)."""
    token = load_personal_token() if token is None else token
    return tuple(host for host in hosts if host not in PERSONAL_HOSTS or token)


# ---------------------------------------------------------------- probing

def _dns_query():
    return (b'\x4e\x56\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x07example\x03com\x00\x00\x01\x00\x01')


def _probe_one_host(kind, port, host, budget, token="", method=None, connect_host=None):
    query = _dns_query()
    method = "GET" if host in GET_ONLY_HOSTS else str(method or PROBE_METHOD).upper()
    path = entrance_path(host, token)
    extra = {}
    if method == "GET":
        path += '?dns=' + base64.urlsafe_b64encode(query).decode('ascii').rstrip('=')
    else:
        extra.update(method="POST", body=query)
    if connect_host:
        extra["connect_host"] = connect_host
    started = time.monotonic()
    try:
        body = nova_exit_probe.fetch_via_proxy(kind, port, host, path, budget=budget, binary=True,
                                              http2=True, **extra)
    except nova_exit_probe.ProbeError as error:
        # 404 on the personal path is a wrong or revoked link; say so without echoing the path.
        if host in PERSONAL_HOSTS and 'HTTP 404' in str(error):
            raise nova_exit_probe.ProbeError(f'{host}: личная ссылка не принята (HTTP 404)') from None
        raise
    if (len(body) < 12 or body[:2] != query[:2] or not body[2] & 0x80 or body[3] & 0x0f):
        raise nova_exit_probe.ProbeError('DNS-AI did not return a valid successful DNS response')
    return round((time.monotonic() - started) * 1000, 2)


def measure_route_latency(kind, port, budget=4.0, hosts=None, token=None, method=None):
    """Time an authenticated DoH query through this route, including the server response.

    The hosts are tried in order and the first one that really answers wins; the route counts as
    failed only when every host failed (so a host blocked on this route does not make DIRECT look dead
    while another one works). The winner is remembered in `chosen_host`. A personal entrance (ru) is
    tried only when a link is stored; without one it is skipped and is not an error.
    """
    token = load_personal_token() if token is None else token
    errors = []
    for host in active_hosts(ordered_hosts() if hosts is None else hosts, token):
        try:
            latency = _probe_one_host(kind, port, host, budget, token, method)
        except nova_exit_probe.ProbeError as error:
            errors.append(f'{host}: {error}')
            if host in PERSONAL_HOSTS and 'HTTP 404' in str(error):
                _set_link_status(LINK_REJECTED)          # revoked: the menu and the choice notice it
            continue
        if host in PERSONAL_HOSTS:
            _set_link_status(LINK_ACCEPTED)
        _chosen_host[(kind, port)] = host
        return latency
    _chosen_host.pop((kind, port), None)
    raise nova_exit_probe.ProbeError('; '.join(errors) or 'DNS-AI: нет ни одного хоста для проверки')


# ---------------------------------------------------------------- CDN addresses (they move)

def resolve_host_addresses(host, getaddrinfo=None):
    """Public IPv4/IPv6 addresses `host` resolves to right now: {"v4": [...], "v6": [...]}."""
    getaddrinfo = getaddrinfo or socket.getaddrinfo
    found = {"v4": [], "v6": []}
    try:
        infos = getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return found
    for info in infos:
        try:
            ip = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        except (ValueError, IndexError):
            continue
        key = "v6" if ip.version == 6 else "v4"
        if ip.is_global and str(ip) not in found[key]:
            found[key].append(str(ip))
    return found


def _load_entrance_cache():
    path = _runtime_file(ENTRANCE_CACHE_FILE)
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, TypeError, ValueError):
        return {}


def _save_entrance_cache(data):
    path = _runtime_file(ENTRANCE_CACHE_FILE)
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=True)
        os.replace(path + ".tmp", path)
    except OSError as error:
        logging.getLogger(__name__).warning("DNS-AI: адреса входов не сохранены (%s)", error)


def probe_address(address, host, token="", budget=4.0, method=None):
    """A real DoH query sent straight to one CDN address, with `host` as the TLS name."""
    return _probe_one_host("direct", 0, host, budget, token, method, connect_host=address)


def refresh_entrance_addresses(hosts=(HOST_CF, HOST_RU), token=None, resolve=resolve_host_addresses,
                               probe=probe_address, now=time.time):
    """Re-resolve each CDN entrance and keep only the addresses that answer a real DoH query now.

    Candidates are the freshly resolved addresses plus the last ones that answered (the resolver may be
    DNS-AI itself and be down). Result: {host: {"v4": [...], "v6": [...]}}, at most
    MAX_ADDRESSES_PER_FAMILY each; a host with no answering address is absent, so the caller falls
    through to the next entrance. A personal host without a stored link is skipped. The answering set
    is saved for the next run."""
    token = load_personal_token() if token is None else token
    cache = _load_entrance_cache()
    result = {}
    for host in active_hosts(hosts, token):
        fresh = resolve(host)
        if host == HOST_RU and not (fresh["v4"] or fresh["v6"]):
            fresh = resolve(RU_EDGE_NAME)
        old = cache.get(host) if isinstance(cache.get(host), dict) else {}
        candidates = []
        for family in ("v4", "v6"):
            for address in list(fresh.get(family, [])) + [a for a in old.get(family, []) if isinstance(a, str)]:
                if address not in [c[1] for c in candidates]:
                    candidates.append((family, address))

        def answers(item, host=host):
            try:
                probe(item[1], host, token)
                return True
            except nova_exit_probe.ProbeError:
                return False
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(candidates)))) as pool:
            ok = list(pool.map(answers, candidates))
        alive = {"v4": [], "v6": []}
        for (family, address), good in zip(candidates, ok):
            if good and len(alive[family]) < MAX_ADDRESSES_PER_FAMILY:
                alive[family].append(address)
        if alive["v4"] or alive["v6"]:
            result[host] = alive
            cache[host] = dict(alive, ts=now())
    _save_entrance_cache(cache)
    return result


def build_install_plan(addresses=None, token="", ru_in_windows=None, preferred=None):
    """Ordered Windows DoH servers per family, cascade order: our direct addresses, then the CDN ones
    (the chosen entrance first when the user picked one).

    Windows takes an IP plus a template, and walks the adapter's server list in order when one does not
    answer - so the cascade dns -> cf -> ru is the list order. ru enters only with a stored link, in its
    chosen place when Windows' DoH client is known to send GET, otherwise (`WINDOWS_DOH_SENDS_GET` unmeasured)
    last; never when it is known to send POST."""
    explicit = ru_in_windows is not None
    if ru_in_windows is None:
        ru_in_windows = WINDOWS_DOH_SENDS_GET is not False
    # Unmeasured method: ru is the tail of the list, unless the owner picked ru as the entrance by hand (that is
    # how the method gets measured: Windows falls through to dns/cf when ru answers 413).
    chosen = normalize_entrance(_preferred_entrance[0] if preferred is None else preferred)
    ru_last = (not explicit) and WINDOWS_DOH_SENDS_GET is not True and chosen != "ru"
    plan = {"v4": [], "v6": []}
    seen = set()

    def add(address, template):
        ip = ipaddress.ip_address(address)
        if address not in seen and "'" not in template:
            seen.add(address)
            plan["v6" if ip.version == 6 else "v4"].append({"server": address, "template": template})

    for host in ordered_hosts(preferred):
        if host == HOST_DIRECT:
            for address in INSTALL_SERVERS:
                add(address, DOH_TEMPLATE)
            continue
        if host in PERSONAL_HOSTS and not (token and ru_in_windows):
            continue
        if host in PERSONAL_HOSTS and ru_last:
            continue                                  # appended after the loop, see below
        for family in ("v4", "v6"):
            for address in ((addresses or {}).get(host) or {}).get(family, []):
                add(address, entrance_template(host, token))
    if token and ru_in_windows and ru_last:
        for family in ("v4", "v6"):
            for address in ((addresses or {}).get(HOST_RU) or {}).get(family, []):
                add(address, entrance_template(HOST_RU, token))
    return plan


def current_install_plan(token=None, refresh=None):
    """The plan for right now: CDN addresses re-resolved and probed. If that fails altogether, only
    our own direct addresses remain (what Nova installed before the CDN entrances existed)."""
    token = load_personal_token() if token is None else token
    try:
        addresses = (refresh or refresh_entrance_addresses)(token=token)
    except Exception as error:
        logging.getLogger(__name__).warning("DNS-AI: адреса входов не обновлены (%s)", error)
        addresses = {}
    return build_install_plan(addresses, token)


class RouteLatencyMonitor:
    """Bounded background samples tied to the exact live helper, with no system DNS changes."""

    def __init__(self, probe=measure_route_latency, clock=time.monotonic):
        self._probe, self._clock = probe, clock
        self._lock = threading.Lock()
        self._routes, self._samples = {}, {}
        self._due = 0.0
        self._running = False

    def refresh(self, routes):
        routes = dict(routes)
        now = self._clock()
        with self._lock:
            if routes != self._routes:
                self._samples = {label: sample for label, sample in self._samples.items()
                                 if self._routes.get(label) == routes.get(label)}
                self._routes = routes
                self._due = 0.0
            if not routes or self._running or now < self._due:
                return
            self._running = True
        threading.Thread(target=self._sample, args=(routes,), daemon=True, name='NovaDnsAiLatency').start()

    def _sample(self, routes):
        def measure(item):
            label, (_key, kind, port) = item
            try:
                return label, (self._probe(kind, port), '')
            except nova_exit_probe.ProbeError as error:
                return label, (None, str(error))
        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                results = dict(pool.map(measure, routes.items()))
            now = self._clock()
            with self._lock:
                for label, (ms, error) in results.items():
                    if self._routes.get(label) == routes[label]:
                        old = self._samples.get(label)
                        if error and (old is None or old[2] != error):
                            logging.getLogger(__name__).warning('DNS-AI: замер через %s не прошёл: %s', label, error)
                        self._samples[label] = (ms, now, error)
                self._due = now + 30.0 if self._routes == routes else 0.0
        finally:
            with self._lock:
                self._running = False

    def snapshot(self, routes):
        now = self._clock()
        with self._lock:
            samples = {label: sample for label, sample in self._samples.items()
                       if self._routes.get(label) == routes.get(label) and label in routes
                       and 0 <= now - sample[1] <= 90.0}
        state = {'vpn_up': {label: label in routes for label in ('warp-socks', 'opera-http')},
                 'latency_ms': {label: sample[0] for label, sample in samples.items() if sample[0] is not None},
                 'latency_errors': {label: sample[2] for label, sample in samples.items() if sample[2]}}
        hosts = {label: chosen_host(routes[label][1], routes[label][2]) for label in state['latency_ms']}
        hosts = {label: host for label, host in hosts.items() if host}
        if hosts:
            state['doh_host'] = hosts
        return state


def is_windows_11():
    if sys.platform != "win32":
        return False
    version = sys.getwindowsversion()
    return version.build >= 22000 and version.product_type == 1


def _run_dns_setup(script, timeout=45):
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
    if result.returncode:
        # The script emits only its own error message, never account/adapter metadata.
        message = result.stdout.decode("utf-8-sig", "replace").strip()
        raise RuntimeError(message or "Windows не смогла применить настройки DNS over HTTPS.")
    return result.stdout.decode("utf-8-sig", "strict").strip()


_DNS_SETUP_HEADER = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
"""

_DNS_SNAPSHOT = r"""
foreach ($cmd in @('Get-DnsClientDohServerAddress','Add-DnsClientDohServerAddress',
    'Set-DnsClientDohServerAddress','Remove-DnsClientDohServerAddress','Set-DnsClientServerAddress')) {
    $null = Get-Command $cmd -ErrorAction Stop
}
$routes = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
    Select-Object -ExpandProperty InterfaceIndex -Unique)
$interfaces = @()
foreach ($adapter in @(Get-NetAdapter -Physical | Where-Object {
    $_.Status -eq 'Up' -and $_.InterfaceIndex -in $routes })) {
    $families = @()
    foreach ($dns in @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex)) {
        $v6 = [int]$dns.AddressFamily -eq 23
        $component = if ($v6) { 'ms_tcpip6' } else { 'ms_tcpip' }
        if (-not (Get-NetAdapterBinding -InterfaceDescription $adapter.InterfaceDescription -ComponentID $component).Enabled) { continue }
        $branch = if ($v6) { 'Tcpip6' } else { 'Tcpip' }
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $branch + '\Parameters\Interfaces\' + $adapter.InterfaceGuid
        $property = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        $families += @{ family=[int]$dns.AddressFamily; servers=@($dns.ServerAddresses);
            static=([bool]([string]$property.NameServer).Trim()) }
    }
    if ($families.Count) { $interfaces += @{ index=[int]$adapter.InterfaceIndex; families=$families } }
}
if (-not $interfaces.Count) { throw 'Нет активного физического адаптера с маршрутом в Интернет.' }
$known = @(Get-DnsClientDohServerAddress)
$doh = @()
foreach ($server in $servers) {
    $previous = $known | Where-Object { $_.ServerAddress -eq $server } | Select-Object -First 1
    $doh += @{ server=$server; exists=($null -ne $previous); template=[string]$previous.DohTemplate;
        auto=[bool]$previous.AutoUpgrade; fallback=[bool]$previous.AllowFallbackToUdp }
}
@{ interfaces=$interfaces; doh=$doh } | ConvertTo-Json -Depth 8 -Compress
"""

_DNS_APPLY = r"""
foreach ($entry in $state.doh) {
    if (-not $map.ContainsKey($entry.server)) { continue }
    $params = @{ ServerAddress=$entry.server; DohTemplate=$map[$entry.server]; AutoUpgrade=$true; AllowFallbackToUdp=$false }
    if ($entry.exists) { $null = Set-DnsClientDohServerAddress @params }
    else { $null = Add-DnsClientDohServerAddress @params }
}
foreach ($adapter in $state.interfaces) {
    foreach ($family in $adapter.families) {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.index |
            Where-Object { [int]$_.AddressFamily -eq [int]$family.family }
        if ($null -eq $dns) { throw 'Сетевой адаптер изменился во время настройки DNS.' }
        $addresses = if ([int]$family.family -eq 23) { @($order6) } else { @($order4) }
        $dns | Set-DnsClientServerAddress -ServerAddresses $addresses
        $actual = Get-DnsClientServerAddress -InterfaceIndex $adapter.index |
            Where-Object { [int]$_.AddressFamily -eq [int]$family.family }
        if ((@($actual.ServerAddresses) -join ',') -ne ($addresses -join ',')) {
            throw 'Windows не подтвердила новые адреса DNS.'
        }
    }
}
$known = @(Get-DnsClientDohServerAddress)
foreach ($server in $servers) {
    $entry = $known | Where-Object { $_.ServerAddress -eq $server } | Select-Object -First 1
    if ($null -eq $entry -or $entry.DohTemplate -ne $map[$server] -or -not $entry.AutoUpgrade -or $entry.AllowFallbackToUdp) {
        throw 'Windows не подтвердила обязательное шифрование DNS.'
    }
}
Clear-DnsClientCache
Write-Output 'OK'
"""

_DNS_ROLLBACK = r"""
$errors = @()
foreach ($adapter in $state.interfaces) {
    foreach ($family in $adapter.families) {
        try {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.index |
                Where-Object { [int]$_.AddressFamily -eq [int]$family.family }
            if ($null -eq $dns) { throw 'Адаптер отсутствует при восстановлении DNS.' }
            if ($family.static) { $dns | Set-DnsClientServerAddress -ServerAddresses @($family.servers) }
            else { $dns | Set-DnsClientServerAddress -ResetServerAddresses }
        } catch { $errors += $_.Exception.Message }
    }
}
$known = @(Get-DnsClientDohServerAddress)
foreach ($entry in $state.doh) {
    try {
        if ($entry.exists) {
            Set-DnsClientDohServerAddress -ServerAddress $entry.server -DohTemplate $entry.template `
                -AutoUpgrade ([bool]$entry.auto) -AllowFallbackToUdp ([bool]$entry.fallback)
        } elseif ($known.ServerAddress -contains $entry.server) {
            Remove-DnsClientDohServerAddress -ServerAddress $entry.server -Confirm:$false
        }
    } catch { $errors += $_.Exception.Message }
}
if ($errors.Count) { throw ($errors -join '; ') }
Clear-DnsClientCache
"""


CHOICE_AUTO, CHOICE_DNS_AI, CHOICE_SYSTEM = "auto", "dns_ai", "system"


def normalize_choice(value):
    """The saved indicator choice; anything unknown means "follow the system"."""
    return value if value in (CHOICE_DNS_AI, CHOICE_SYSTEM) else CHOICE_AUTO


def effective_choice(value, installed):
    """What the UI and Nova do: the user's explicit pick wins; otherwise DNS-AI if the system already
    uses it, else the system DNS (Nova never switches the machine to DNS-AI on its own)."""
    choice = normalize_choice(value)
    if choice != CHOICE_AUTO:
        return choice
    return CHOICE_DNS_AI if installed else CHOICE_SYSTEM


def has_restore_snapshot(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return isinstance(data, dict) and bool(data.get("interfaces"))
    except (OSError, ValueError):
        return False


def restore_system_dns(snapshot_path):
    """Put back the DNS settings Nova saved before it installed DNS-AI. Deletes the snapshot on success."""
    try:
        with open(snapshot_path, "r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
    except (OSError, ValueError):
        snapshot = None
    if not isinstance(snapshot, dict) or not snapshot.get("interfaces") or not snapshot.get("doh"):
        raise RuntimeError("Нет сохранённых прежних настроек DNS: Nova не настраивала DNS-AI в этой системе.")
    state = json.dumps(snapshot, ensure_ascii=True).replace("'", "''")
    script = (_DNS_SETUP_HEADER + "$state = ConvertFrom-Json '" + state + "'\n"
              "try {\n" + _DNS_ROLLBACK + "\n} catch { Write-Output $_.Exception.Message; exit 1 }")
    _run_dns_setup(script)
    with contextlib.suppress(OSError):
        os.remove(snapshot_path)
    _doh_cache.update(ts=0.0, value=False)
    return {"interfaces": len(snapshot["interfaces"])}


def _plan_header(plan):
    """PowerShell variables for a plan: every server, the per-family order and the address->template map."""
    entries = list(plan["v4"]) + list(plan["v6"])
    for entry in entries:
        ipaddress.ip_address(entry["server"])            # never put anything but an address into the script
        if "'" in entry["template"] or "\n" in entry["template"]:
            raise RuntimeError("Недопустимый шаблон DoH.")

    def array(items):
        return "@(" + ",".join("'%s'" % item for item in items) + ")"
    mapping = "; ".join("'%s'='%s'" % (entry["server"], entry["template"]) for entry in entries)
    return ("$servers = " + array([entry["server"] for entry in entries]) + "\n"
            "$order4 = " + array([entry["server"] for entry in plan["v4"]]) + "\n"
            "$order6 = " + array([entry["server"] for entry in plan["v6"]]) + "\n"
            "$map = @{" + mapping + "}\n")


def _direct_plan():
    return build_install_plan(None, "")


def install_system_dns(snapshot_path=None, plan=None):
    """Configure active physical adapters. Roll back exact static/DHCP settings on any failure.

    `plan` (see `current_install_plan`) lists the DoH servers in cascade order; without it only the
    direct dns.dns-ai.ru addresses are installed. With `snapshot_path` the previous settings are kept
    on disk after success, so the user can go back to the system DNS later (`restore_system_dns`).
    The applied plan is stored beside them so `refresh_system_dns` can tell when addresses moved."""
    if not is_windows_11():
        raise RuntimeError("Системный DNS-AI с DoH доступен только в Windows 11.")
    plan = plan or _direct_plan()
    header = _DNS_SETUP_HEADER + _plan_header(plan)
    # Capture before any mutation, in Python memory so an apply-process timeout can also roll back.
    snapshot = json.loads(_run_dns_setup(header + _DNS_SNAPSHOT, timeout=20))
    if not isinstance(snapshot, dict) or not snapshot.get("interfaces") or not snapshot.get("doh"):
        raise RuntimeError("Не удалось сохранить прежние настройки DNS.")
    state = json.dumps(snapshot, ensure_ascii=True).replace("'", "''")
    setup = header + "$state = ConvertFrom-Json '" + state + "'\n"
    # Convert PowerShell errors to UTF-8 stdout; stderr is CLIXML on some Windows versions.
    def wrapped(script):
        return setup + "try {\n" + script + "\n} catch { Write-Output $_.Exception.Message; exit 1 }"
    try:
        _run_dns_setup(wrapped(_DNS_APPLY))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        try:
            _run_dns_setup(wrapped(_DNS_ROLLBACK))
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as rollback_error:
            raise RuntimeError(f"Не удалось применить DNS-AI: {error}. Восстановление DNS не завершено: {rollback_error}") from error
        raise RuntimeError(f"Не удалось применить DNS-AI; прежние настройки восстановлены: {error}") from error
    if snapshot_path:
        try:
            os.makedirs(os.path.dirname(snapshot_path), exist_ok=True)
            with open(snapshot_path, "w", encoding="utf-8") as handle:
                json.dump(dict(snapshot, plan=plan), handle, ensure_ascii=True)
        except OSError as error:
            logging.getLogger(__name__).warning("DNS-AI: прежние настройки DNS не сохранены (%s)", error)
    _doh_cache.update(ts=0.0, value=False)
    return {"interfaces": len(snapshot["interfaces"]), "encrypted": True}


# Серверы DNS активных физических адаптеров с маршрутом в Интернет: только чтение.
_DNS_ADAPTERS_NOW = r"""
$routes = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
    Select-Object -ExpandProperty InterfaceIndex -Unique)
$items = @()
foreach ($adapter in @(Get-NetAdapter -Physical | Where-Object {
    $_.Status -eq 'Up' -and $_.InterfaceIndex -in $routes })) {
    foreach ($dns in @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex)) {
        $items += @{ index=[int]$adapter.InterfaceIndex; family=[int]$dns.AddressFamily; servers=@($dns.ServerAddresses) }
    }
}
@{ items=$items } | ConvertTo-Json -Depth 6 -Compress
"""

# Вернуть адаптерам автоматические (DHCP) серверы DNS. Только те семейства адресов, что уже заданы вручную.
_DNS_RESET_AUTO = r"""
$routes = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
    Select-Object -ExpandProperty InterfaceIndex -Unique)
foreach ($adapter in @(Get-NetAdapter -Physical | Where-Object {
    $_.Status -eq 'Up' -and $_.InterfaceIndex -in $routes })) {
    foreach ($dns in @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex)) {
        if (@($dns.ServerAddresses).Count) { $dns | Set-DnsClientServerAddress -ResetServerAddresses }
    }
}
Clear-DnsClientCache
Write-Output 'OK'
"""


def external_dns_ai_in_use(snapshot_path):
    """True when Windows already uses OUR direct addresses but Nova holds no snapshot of the settings before them:
    DNS-AI was set up by hand or by an older Nova. Nova cannot restore such a machine and does not know its cascade."""
    if not is_windows_11() or has_restore_snapshot(snapshot_path):
        return False
    try:
        found = json.loads(_run_dns_setup(_DNS_SETUP_HEADER + _DNS_ADAPTERS_NOW, timeout=20)).get("items") or []
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        return False
    used = [address for item in found for address in (item.get("servers") or [])]
    return bool(used) and all(address in INSTALL_SERVERS for address in used)


def takeover_system_dns(snapshot_path, plan=None):
    """Nova takes over a DNS-AI that it did not install: the adapters go back to automatic DNS (so the snapshot
    Nova keeps is the honest "before", and «Системный DNS» returns there), then the normal install runs with
    the full cascade. If the install fails the previous direct addresses are put back: the machine never stays
    on plain DNS because of an attempt."""
    if not is_windows_11():
        raise RuntimeError("Системный DNS-AI с DoH доступен только в Windows 11.")
    plan = plan or current_install_plan()
    _run_dns_setup(_DNS_SETUP_HEADER + _DNS_RESET_AUTO, timeout=30)
    try:
        return install_system_dns(snapshot_path=snapshot_path, plan=plan)
    except Exception as error:
        try:
            install_system_dns(snapshot_path=None, plan=_direct_plan())
        except Exception as restore_error:
            raise RuntimeError(f"{error} Прежний DNS-AI не восстановлен: {restore_error}") from error
        raise


def refresh_system_dns(snapshot_path, plan=None):
    """Follow moved CDN addresses on a machine where Nova installed DNS-AI.

    Re-resolves the entrances, and when the answering set differs from the plan applied last time,
    re-applies the server list. The stored pre-Nova snapshot is kept (extended with the new servers so
    "system DNS" still removes them). Nothing happens when there is no snapshot (DNS-AI was not set up by
    Nova) or nothing moved. A failed re-apply is NOT rolled back to the pre-Nova DNS: the previous
    cascade keeps working and the next refresh retries."""
    if not is_windows_11():
        return {"changed": False}
    try:
        with open(snapshot_path, "r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
    except (OSError, ValueError):
        return {"changed": False}
    if not isinstance(snapshot, dict) or not snapshot.get("interfaces") or not snapshot.get("doh"):
        return {"changed": False}
    if "plan" not in snapshot:
        # Installed by an older Nova (direct addresses only): the CDN entrances are added on the next
        # explicit "DNS-AI" pick, never silently in the background.
        return {"changed": False}
    plan = plan or current_install_plan()
    if snapshot.get("plan") == plan:
        return {"changed": False}
    header = _DNS_SETUP_HEADER + _plan_header(plan)
    # What Windows holds NOW for every server of the plan: the apply script must Set what already exists
    # and Add only what does not. (The stored snapshot says what existed BEFORE Nova - not the same thing.)
    current = json.loads(_run_dns_setup(header + _DNS_SNAPSHOT, timeout=20))
    known = {entry.get("server") for entry in snapshot["doh"]}
    new_servers = [entry for entry in (current.get("doh") or []) if entry.get("server") not in known]
    snapshot["doh"] = list(snapshot["doh"]) + new_servers      # so "system DNS" removes them too
    state = json.dumps({"interfaces": snapshot["interfaces"], "doh": current.get("doh") or []},
                       ensure_ascii=True).replace("'", "''")
    script = (header + "$state = ConvertFrom-Json '" + state + "'\n"
              "try {\n" + _DNS_APPLY + "\n} catch { Write-Output $_.Exception.Message; exit 1 }")
    _run_dns_setup(script)
    # ru left the Windows list (the system DoH client cannot use it): drop its DoH registration too, so an address
    # with a template that never works does not linger. Only entries whose template is a ru one, only when the
    # previous plan carried ru and the new one does not.
    def _has_ru(candidate):
        return any(str(entry.get("template") or "").startswith("https://" + HOST_RU + "/")
                   for entry in list((candidate or {}).get("v4", [])) + list((candidate or {}).get("v6", [])))
    if _has_ru(snapshot.get("plan")) and not _has_ru(plan):
        keep = ",".join("'%s'" % entry["server"] for entry in list(plan["v4"]) + list(plan["v6"]))
        cleanup = (_DNS_SETUP_HEADER + "$keep = @(" + keep + ")" + chr(10)
                   + "Get-DnsClientDohServerAddress | Where-Object { $_.DohTemplate -like 'https://" + HOST_RU
                   + "/*' -and $keep -notcontains $_.ServerAddress } | ForEach-Object { try { "
                   + "Remove-DnsClientDohServerAddress -ServerAddress $_.ServerAddress -Confirm:$false } catch { } }"
                   + chr(10) + "Write-Output 'OK'")
        with contextlib.suppress(Exception):
            _run_dns_setup(cleanup, timeout=30)
    snapshot["plan"] = plan
    with open(snapshot_path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, ensure_ascii=True)
    _doh_cache.update(ts=0.0, value=False)
    return {"changed": True, "servers": len(new_servers)}

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

def doh_encrypted(dns_ai_servers, lines=None):
    """Включено ли в системе шифрование DNS-AI: его адрес с шаблоном DoH.

    Читается `Get-DnsClientDohServerAddress`. Процесс порождается не чаще раза в
    `DOH_CACHE_SECONDS`: опрос индикатора идёт каждые 10 с, а в native-режиме
    он попадает сюда только когда адреса DNS-AI уже стоят в адаптере.
    `lines` подменяется в тестах (строки `адрес<TAB>шаблон`).
    """
    now = time.time()
    if lines is None:
        if now - _doh_cache["ts"] < DOH_CACHE_SECONDS:
            return bool(_doh_cache["value"])
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-DnsClientDohServerAddress | ForEach-Object { "
                 "$_.ServerAddress + [char]9 + $_.DohTemplate }"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            )
            lines = result.stdout.splitlines() if result.returncode == 0 else []
        except Exception:
            lines = []
        value = _doh_matches(dns_ai_servers, lines)
        _doh_cache["ts"] = now
        _doh_cache["value"] = value
        return value
    return _doh_matches(dns_ai_servers, lines)


def _doh_matches(dns_ai_servers, lines):
    addresses = normalize_addresses(dns_ai_servers)
    template = DOH_TEMPLATE.rstrip("/").lower()
    for line in lines:
        address, _, doh = str(line).partition("\t")
        if normalize_addresses([address.strip()]) & addresses and doh.strip().rstrip("/").lower() == template:
            return True
    return False


def detect_mode(dns_ai_servers, servers=None, owners=None, present=None, doh=None):
    """`MODE_NATIVE`, `MODE_STUB` или `""` - как машина сейчас ходит в DNS.

    `dns_ai_servers` - собственные адреса резолвера; единственный источник
    правды для них в Nova - каскад NRPT, поэтому они приходят аргументом, а не
    заводятся здесь второй копией.

    Native считается только при включённом DoH-шифровании DNS-AI (`doh_encrypted`):
    адреса без шифрования сервис не обслуживают, и Nova должна поставить разблокировку.

    `servers`, `owners`, `present`, `doh` подменяются в тестах; по умолчанию читается
    настоящая система.
    """
    values = servers if servers is not None else system_dns_servers()
    configured = normalize_addresses(values)
    if configured & normalize_addresses(dns_ai_servers):
        encrypted = doh() if doh is not None else doh_encrypted(dns_ai_servers)
        return MODE_NATIVE if encrypted else ""

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


# ---------------------------------------------------------------------------------------------
# winws: DNS-AI has a profile of its own, first in the list, instead of falling into `general`.

def winws_tcp_strategy(strategies):
    """Strategy args for DNS-AI over TCP: `strategies['dns_ai']` when the owner defines it, else the
    TCP half of `ai` (what already unblocks the AI services). Only the first block, up to `--new`."""
    for key in ("dns_ai", "ai"):
        args = (strategies or {}).get(key)
        if isinstance(args, dict):
            args = args.get("args")
        if not isinstance(args, list):
            continue
        block = []
        for arg in args:
            if arg == "--new":
                break
            if isinstance(arg, str) and arg.strip():
                block.append(arg.strip())
        if any(arg.startswith(("--filter-tcp", "--wf-tcp")) for arg in block):
            return block
    return []


def write_runtime_hostlist(path):
    """temp/dns_ai_runtime.txt: one domain, and winws matches its subdomains too (dns., cf., ru.)."""
    wanted = DNS_AI_DOMAIN + "\n"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            if handle.read() == wanted:
                return path
    except OSError:
        pass
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(wanted)
    return path


def winws_profile_args(strategies, hostlist_path, fix_arg=None):
    """One winws profile (no leading `--new`) for every *.dns-ai.ru name; [] when no strategy fits."""
    block = winws_tcp_strategy(strategies)
    if not block:
        return []
    args = ["--hostlist=" + hostlist_path]
    for arg in block:
        if fix_arg is not None:
            arg = fix_arg(arg)
        args.append(arg.replace("--wf-tcp", "--filter-tcp", 1) if arg.startswith("--wf-tcp") else arg)
    return args


def winws_guard_command(exe_path, strategies, hostlist_path, fix_arg=None):
    """A winws that serves only DNS-AI: what keeps running after «Отключить» while Nova is open."""
    profile = winws_profile_args(strategies, hostlist_path, fix_arg)
    if not profile:
        return []
    return [exe_path, "--wf-tcp=443"] + profile
