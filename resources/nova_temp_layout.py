"""Опись папки `temp/`: что там лежит и кто это использует.

Папку читает не человек, а тот, кто разбирает отчёт о проблеме, — и получает
сорок с лишним файлов без единого слова о том, что есть что. Половина времени
разбора уходила на выяснение, какой файл кэш, какой состояние, а какой вообще
никем не читается.

Таблица ниже — источник правды, а `_README.txt` в папке — её отпечаток,
записываемый раз за запуск. Держать текст в коде, а не в файле, важно: файл
пользователь может стереть, а таблица ещё и проверяется тестом на то, что все
перечисленные имена в коде действительно встречаются.

Вид файла говорит, что с ним можно делать:

* `log`     — только дозапись, читается человеком/агентом; терять не жалко.
* `state`   — переживает перезапуск и **влияет на поведение**; терять жалко.
* `cache`   — ускоряет, но восстановимо; стереть безопасно.
* `runtime` — порождается на запуске для другого процесса; стирать бессмысленно.
* `report`  — снимок для разбора; программой не читается.

Отдельно от вида — пометка `private`: папку прикладывают к отчёту о проблеме
(I19), и строка с этой пометкой говорит упаковщику, что именно прикладывать
нельзя.
"""

__all__ = ["ENTRIES", "Entry", "render_readme", "write_readme"]

import os


class Entry:
    """Одна строка описи.

    `needle` — строка, по которой тест находит имя в исходниках, когда само имя
    слишком короткое и встречается где угодно («tor» есть в «monitor»).
    `private` — содержимое личное: в отчёт о проблеме не прикладывать.
    """

    __slots__ = ("name", "kind", "written_by", "read_by", "note", "needle", "private")

    def __init__(self, name, kind, written_by, read_by, note, needle=None, private=False):
        self.name = name
        self.kind = kind
        self.written_by = written_by
        self.read_by = read_by
        self.note = note
        self.needle = needle
        self.private = bool(private)


E = Entry

ENTRIES = (
    # --- то, ради чего папку и открывают ---------------------------------
    E("nova_console.log", "log", "nova.pyw", "человек/агент",
      "главный лог. Всё, что видно в окне журнала"),
    E("boot_timeline.jsonl", "report", "nova.pyw", "никто",
      "фазы запуска с длительностями; печатается в лог одной сводкой"),
    E("NovaDivertRedirect.log", "log", "windivert_redirect.py", "человек/агент",
      "какое соединение куда перенаправлено. Усекается на каждом запуске"),
    E("NovaDivertRedirect.log.startup.log", "log", "windivert_redirect.py (stdout)", "человек/агент",
      "stdout/stderr помощника. Обрезается до хвоста в 256 КБ"),
    E("NovaDivertTcpProxy.log", "log", "NovaWFP/proxy/tcp_proxy.py", "человек/агент",
      "прокси перенаправленных TCP-потоков"),
    E("NovaDivertUdpProxy.log", "log", "NovaWFP/proxy/udp_proxy.py", "человек/агент",
      "то же для UDP"),
    E("opera.log", "log", "opera-proxy.exe", "человек/агент",
      "лог стороннего клиента Opera VPN"),
    E("wireproxy-awg.log", "log", "wireproxy-awg.exe", "человек/агент",
      "лог AWG/WARP. Строки handshake здесь — единственный признак O5"),
    E("tls_terminator.log", "log", "nova-tls-terminator.exe", "человек/агент",
      "лог помощника, выполняющего рукопожатия TLS"),
    E("nova-go-masque.log", "log", "nova-go.exe (masque socks)", "человек/агент",
      "лог MASQUE-помощника: события NOVA_MASQUE и ошибки. Усекается на каждом запуске"),
    E("nova-xray.log", "log", "nova-xray.exe", "человек/агент",
      "лог помощника VLESS: что ядро Xray сделало с соединением. Имя узла в строках есть, "
      "ключа пользователя нет — он только в profiles/.runtime", needle='"nova-xray.log"'),
    E("nova-xray-secondary.log", "log", "nova-xray.exe (резервный слот)", "человек/агент",
      "то же для профиля VLESS, занявшего слот дополнительного VPN (порты 1379/1380). "
      "Отдельный файл, потому что два экземпляра пишут одновременно",
      needle='"nova-xray-secondary.log"'),
    E("wireproxy-secondary.log", "log", "wireproxy-awg.exe (резервный слот)", "человек/агент",
      "то же для своего профиля AWG в слоте дополнительного VPN",
      needle='"wireproxy-secondary.log"'),

    # --- состояние: влияет на поведение ----------------------------------
    E("nrpt_dns_support.json", "cache", "nova.pyw", "nova.pyw",
      "какие DNS-разблокировщики проксируют какие AI-имена (замер, сутки); по нему ставятся правила NRPT"),
    E("list_sync_state.json", "state", "nova_list_sync.py", "nova_list_sync.py",
      "метка времени последнего применённого манифеста списков из nova_updates; "
      "манифест старше неё (устаревшее зеркало) не применяется"),
    E("checker_state.json", "state", "nova.pyw", "nova.pyw",
      "докуда дошла проверка стратегий; переживает перезапуск"),
    E("strategy_scores.json", "state", "nova.pyw", "nova.pyw",
      "накопленные оценки стратегий. Самый ценный файл в папке"),
    E("learning_data.json", "state", "nova.pyw", "nova.pyw",
      "что выучено про домены и стратегии"),
    E("NovaDivertRedirectState.json", "state", "windivert_redirect.py", "nova.pyw",
      "живые перенаправления; читается при подхвате помощника"),
    E("NovaDivertRedirectMap.json", "state", "windivert_redirect.py", "NovaWFP/proxy",
      "соответствие «локальный порт -> куда и чьё это приложение»"),
    E("awg-profile-state.json", "state", "nova.pyw", "nova.pyw",
      "на каком профиле AWG остановились; не даёт ходить по кругу"),
    E("nova-routing-backend-state.json", "state", "nova.pyw", "nova.pyw",
      "какой backend маршрутизации выбран"),
    E("ip_history.json", "state", "nova.pyw", "nova.pyw",
      "смены прямого маршрута; по ним сбрасывается суточный кэш проверок"),
    E("ip_last.txt", "state", "nova.pyw", "nova.pyw",
      "идентичность прямого маршрута: адаптер|адрес|шлюз"),
    E("window_state.json", "state", "nova.pyw", "nova.pyw",
      "положение и размер окна"),
    E("routing_settings.json", "state", "nova.pyw", "nova.pyw",
      "режимы маршрутизации по группам приложений"),
    E("profile-selection.json", "state", "nova_profiles.py", "nova.pyw",
      "выбор в окне «Профили»: авто, группа или один профиль. Явный выбор не подменяется"),
    E("profile-stats.json", "state", "nova_profiles.py", "nova.pyw",
      "удачи и неудачи по профилям: порядок попыток и строки окна «Профили». Без ключей"),
    E("warp-generated-state.json", "state", "nova_warp_generator.py", "nova_warp_generator.py",
      "когда выпущены свои профили WARP, чем кончился выпуск, RTT точек. Без ключей"),
    E("vpn-last.json", "state", "nova_vpn_slots.py", "nova.pyw",
      "последнее подключение основного и дополнительного VPN: вид, имя профиля, страна, "
      "регион Opera или вход Tor. С него начинается «Авто» после перезапуска. Без ключей и адресов"),
    E("tor/data/", "state", "nova-tor.exe", "nova-tor.exe",
      "состояние Tor: выбранные guard-узлы, по ним сеансы одного человека связываются "
      "между собой. Стирать можно (Tor выберет новые), прикладывать к отчёту — нет",
      needle='DATA_DIRNAME = "data"', private=True),

    # --- кэши: стереть безопасно -----------------------------------------
    E("test_ip_cache.json", "cache", "nova.pyw", "nova.pyw",
      "результаты проверок адресов, TTL 8 часов"),
    E("direct_check_cache.json", "cache", "nova.pyw", "nova.pyw",
      "что уже проверено на прямом маршруте"),
    E("opera_endpoint_cache.json", "cache", "nova.pyw", "nova.pyw",
      "последняя удачная точка выхода Opera; ускоряет запуск"),
    E("tgrelay_cf_health.json", "cache", "tgrelay/", "tgrelay/",
      "здоровье доменов Worker'ов между запусками"),
    E("provider_public_ip.txt", "cache", "nova.pyw", "nova.pyw",
      "внешний адрес прямого маршрута, **маскированный** (I19)"),
    E("dns_warmup.txt", "report", "nova.pyw", "никто",
      "домен -> адреса на момент прогрева DNS; для разбора подмены DNS"),

    # --- порождается на запуске ------------------------------------------
    E("nova.pac", "runtime", "nova.pyw", "система/браузеры",
      "сам скрипт PAC. Отдаётся локальным сервером на 1369"),
    E("*_runtime.txt", "runtime", "nova.pyw", "winws.exe",
      "списки доменов для ядра: telegram, discord, youtube"),
    E("winws_last_command.txt", "report", "nova.pyw", "никто",
      "командная строка ядра целиком. Первое, что стоит посмотреть"),
    E("awg_last_command.txt", "report", "nova.pyw", "никто",
      "то же для wireproxy-awg"),
    E("masque_last_command.txt", "report", "nova.pyw", "никто",
      "то же для nova-go masque socks; пути пользователя замаскированы"),
    # Отрендеренные конфиги wireproxy (awg-runtime/) сюда больше не пишутся: у
    # своих профилей WARP/Proton ключи личные, а temp/ уходит с отчётом о
    # проблеме (I19). Они живут в profiles/.runtime.
    E("masque-ready.json", "runtime", "nova-go.exe (masque socks)", "nova.pyw",
      "сигнал готовности MASQUE: транспорт, точка входа, SNI. Без ключей"),
    E("vless-ready.json", "runtime", "nova-xray.exe", "nova.pyw",
      "сигнал готовности VLESS: pid помощника и версия Xray. Без ключей и без адреса узла"),
    E("vless-ready-secondary.json", "runtime", "nova-xray.exe (резервный слот)", "nova.pyw",
      "то же для экземпляра, обслуживающего дополнительный VPN. Своё имя нужно затем, "
      "что помощник удаляет файл готовности и на старте, и на остановке",
      needle='"vless-ready-secondary.json"'),
    E("vpn-egress.json", "runtime", "nova.pyw (nova_vpn_slots.py)", "tcp_proxy.py, tgrelay/transport.py",
      "что сейчас основной и дополнительный VPN: вид, подпись, поднят ли, страна выхода основного "
      "и порты дополнительного (Opera 1371, Tor 1375/1378 или свой профиль 1379/1380). По стране "
      "решается, пускать ли список EU через основной. Без адресов"),
    E("tor/", "runtime", "nova_tor.py", "nova-tor.exe, nova-lyrebird.exe",
      "Tor: torrc, pt_state/, tor.log, tor.stdout.log, lyrebird.log, tor.pid, control_port, "
      "bridges.json (только публичные строки мостов), auto_entry.txt. "
      "data/ и cookie — отдельными строками: их в отчёт не прикладывать",
      needle='RUNTIME_DIRNAME = "tor"'),
    E("tor/cookie", "runtime", "nova-tor.exe", "nova_tor.py",
      "cookie порта управления Tor; пересоздаётся на каждом запуске. "
      "Кто его прочтёт, пока Tor жив, управляет Tor",
      needle='COOKIE_NAME = "cookie"', private=True),
    E("*.pid", "runtime", "nova.pyw", "nova.pyw",
      "pid помощников: по ним подхватывают уже запущенное",
      needle='.pid"'),
    E(".nova_infra_version", "state", "nova.pyw", "nova.pyw",
      "версия разложенной инфраструктуры; по ней решают, надо ли обновлять"),
)

_KIND_ORDER = ("log", "state", "cache", "runtime", "report")
_KIND_TITLE = {
    "log": "ЛОГИ — дозапись, читаются глазами, терять не жалко",
    "state": "СОСТОЯНИЕ — переживает перезапуск и влияет на поведение",
    "cache": "КЭШИ — только ускоряют, стереть безопасно",
    "runtime": "ПОРОЖДАЕМОЕ — создаётся на запуске для другого процесса",
    "report": "СНИМКИ — для разбора; программа их не читает",
}

README_NAME = "_README.txt"
PRIVATE_MARK = "НЕ ПРИКЛАДЫВАТЬ"


def render_readme():
    """Текст описи. Одинаковый на любой машине — личных данных здесь нет."""
    private = sorted(e.name for e in ENTRIES if e.private)
    out = [
        "Опись папки temp. Пишется Nova на запуске; править бессмысленно.",
        "Источник правды — resources/nova_temp_layout.py.",
        "",
        "Логи обрезаются по хвосту и не растут без предела; состояние пишется",
        "атомарно (запись во временный файл, затем переименование), поэтому",
        "внезапное выключение не оставляет обрывков.",
        "",
    ]
    if private:
        out += [
            f"{PRIVATE_MARK} к отчёту о проблеме: " + ", ".join(private),
            "",
        ]
    for kind in _KIND_ORDER:
        rows = [e for e in ENTRIES if e.kind == kind]
        if not rows:
            continue
        out.append(_KIND_TITLE[kind])
        width = max(len(e.name) for e in rows)
        for e in sorted(rows, key=lambda x: x.name):
            out.append(f"  {e.name:<{width}}  {e.note}")
            out.append(f"  {'':<{width}}  пишет: {e.written_by}; читает: {e.read_by}")
            if e.private:
                out.append(f"  {'':<{width}}  {PRIVATE_MARK}: личное")
        out.append("")
    return "\n".join(out)


def write_readme(temp_dir):
    """Положить опись рядом с файлами, которые она описывает.

    Одна запись за запуск. Ошибка здесь не должна ничего ронять: опись — это
    удобство, а не работа программы.
    """
    try:
        path = os.path.join(str(temp_dir), README_NAME)
        text = render_readme()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.replace(tmp, path)
        return path
    except Exception:
        return ""
