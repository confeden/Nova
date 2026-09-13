"""Какие настройки релея Telegram можно отдать наружу, и во что они превращаются.

Чистая функция без побочных эффектов: на входе блок `relay` из
`routing_settings.json`, на выходе словарь переменных окружения. Применяет их
`nova.pyw`; здесь только решение, что именно применять.

Вынесено из `nova.pyw` по той же причине, что и классификатор ниш: тот файл
pytest импортировать не может — при импорте он поднимает права и рисует окно.
А проверять здесь есть что, и в первую очередь не преобразование значений, а
сам список: пустить в него лишнее имя дешевле всего именно на этом шаге.

Релей читает 35 переменных. Разрешены пять выключателей и список доменов;
почему остальные запрещены — в `FORBIDDEN_ENV` ниже, каждая со своей причиной.
Молчание тоже часть контракта: если в настройках ничего нет, не
экспортируется ничего, и релей остаётся на своих дефолтах. Продублировать их
здесь значило бы завести второе место, где они живут.
"""

# Выключатели отката. Каждый уже описан как рычаг: NEUTRAL_SNI — в ADR 0004,
# NATIVE_MEDIA — отдельным комментарием в relay (там сказано, что это
# сознательно отдельный от NATIVE_FIRST переключатель), MEDIA_WEB_FIRST —
# порядок маршрутов для медиа.
#
# MEDIA_WEB_FIRST пущен сюда, а `..._CF_FIRST_DCS` и `..._CF_FIRST_MEDIA_DCS`
# запрещены ниже, и это не противоречие: там ловушка в самом дефолте — список
# по DC, выписанный явно, молча переводит часть датацентров. Здесь булев
# выключатель без списка, его дефолт живёт в одном месте (relay), и выставить
# его «как в документации» нельзя — можно только включить или выключить.
RELAY_ENV_BOOL_KEYS = {
    "cf_fallback": "NOVA_TG_RELAY_CF_FALLBACK",
    "media_web_first": "NOVA_TG_RELAY_MEDIA_WEB_FIRST",
    "native_first": "NOVA_TG_RELAY_NATIVE_FIRST",
    "native_media": "NOVA_TG_RELAY_NATIVE_MEDIA",
    "neutral_sni": "NOVA_TG_RELAY_NEUTRAL_SNI",
}

RELAY_ENV_DOMAINS = "NOVA_TG_RELAY_CF_DOMAINS"

# Имена, которых в выдаче не должно быть никогда, и почему. Список существует не
# для документации: тест сверяет с ним результат, поэтому «случайно разрешить»
# одно из них нельзя — это будет падение, а не тихое расширение поверхности.
FORBIDDEN_ENV = {
    "NOVA_TG_CF_SECRET":
        "подписывает handshake к Worker'у владельца, а settings-файл лежит в двух "
        "общедоступных местах; его surface — tgrelay/cf_ws.key, который не публикуется",
    "NOVA_TLS_TERMINATOR_PORT":
        "выпускается заново каждый запуск и перебивает runtime-файл; устаревшее "
        "значение увело бы релей на мёртвый порт и выключило маскировку на сессию",
    "NOVA_TLS_TERMINATOR_TOKEN":
        "секрет текущего запуска, выпускаемый вместе с портом; в файле настроек он "
        "пережил бы свой процесс и открыл бы локальный TLS-прокси кому угодно",
    "NOVA_DIVERT_REDIRECT_MAP":
        "уже пишет NovaDivertTcpProxyManager; второй писатель рассинхронизирует "
        "родительский процесс и дочерний",
    "NOVA_TELEGRAM_RELAY":
        "решает, существует ли релей вообще; для этого уже есть строка Telegram "
        "в окне маршрутов, а второй скрытый выключатель даёт состояние "
        "«telegram=warp, но на 1372 никто не слушает», неотличимое от падения",
    "NOVA_TG_RELAY_FIRST_BYTE_RETRY":
        "срабатывает только для DC из (1,3,5), а рабочие — 2 и 4: на этих машинах "
        "переключатель не делает ничего",
    "NOVA_TG_RELAY_CF_FIRST_DCS":
        "опасен своим же документированным дефолтом: выставить его явно значит "
        "молча перевести медиа DC1 и DC3 на web-first",
    "NOVA_TG_RELAY_CF_FIRST_MEDIA_DCS":
        "та же ловушка для медийных маршрутов: у всех шести DC есть web-цель, так "
        "что явно выставленный дефолт '2,4,5,203' переключает DC1 и DC3 без единой "
        "строки в логе",
}


def _domains_to_value(raw):
    """Список или строка -> строка через запятую. Пустое -> ''."""
    if isinstance(raw, (list, tuple)):
        parts = [str(item).strip() for item in raw]
    else:
        parts = str(raw or "").split(",")
    return ",".join(part for part in (p.strip() for p in parts) if part)


def relay_env_from_settings(relay):
    """Блок `relay` -> переменные окружения. Пусто на входе — пусто на выходе."""
    if not isinstance(relay, dict) or not relay:
        return {}

    exported = {}

    domains = _domains_to_value(relay.get("cf_domains"))
    if domains:
        # Единственная настройка, которую можно поменять и после старта:
        # get_cfproxy_domains() перечитывает переменную на каждом вызове.
        exported[RELAY_ENV_DOMAINS] = domains

    for key, env_name in RELAY_ENV_BOOL_KEYS.items():
        if key not in relay:
            continue
        # Релей понимает 1/true/yes/on, всё прочее для него ложь. Приводим сами,
        # чтобы «false» строкой из JSON не превратилось в истину.
        exported[env_name] = "1" if _as_bool(relay.get(key)) else "0"

    return exported


def _as_bool(value):
    """JSON даёт bool, но человек, правящий файл руками, напишет и 'no', и '0'."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "yes", "on")
