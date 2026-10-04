"""Охват стратегии general: всё, что не попало ни в один другой список.

До 1.42 general была привязана к list/general.txt (67 тысяч строк) и к
ip/general.txt — а в последнем лежали только диапазоны Cloudflare. ipset в
winws — жёсткий фильтр профиля, поэтому general на деле срабатывала лишь для
доменов из списка, которые хостятся на Cloudflare. Теперь профиль general
стоит последним и без --hostlist/--ipset: он ловит любой сайт на 80/443,
кроме перечисленных в исключениях и в списках, у которых свой маршрут или своя
стратегия (main/second уходят в VPN, youtube/discord/... — в свои профили).
"""
import os

# Списки, домены которых general не трогает. Порядок — только для читаемости
# командной строки: winws проверяет все --hostlist-exclude профиля.
GENERAL_EXCLUDED_LISTS = (
    "exclude.txt",
    "main.txt",
    "second.txt",
    "u_main.txt",
    "u_second.txt",
    "ai.txt",
    "youtube.txt",
    "discord.txt",
    "telegram.txt",
    "whatsapp.txt",
    "cloudflare.txt",
    "games.txt",
)

# Адресные списки сервисов со своими профилями.
GENERAL_EXCLUDED_IPSETS = (
    "exclude.txt",
    "warp.txt",
    "discord.txt",
    "telegram.txt",
    "whatsapp.txt",
)

LEGACY_GENERAL_LIST = "general.txt"


def _has_entries(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for line in f:
                s = line.split("#", 1)[0].strip()
                if s:
                    return True
    except OSError:
        return False
    return False


def general_scope_args(base_dir, runtime_lists=None, extra_hostlists=(), extra_ipsets=(), has_entries=None):
    """Аргументы --hostlist-exclude/--ipset-exclude для профиля general.

    runtime_lists: {имя_файла: путь} — сгенерированные на лету копии
    (youtube/discord/telegram), они подменяют файл из list/.
    Пустые и отсутствующие файлы пропускаются: пустой список winws не любит.
    """
    has_entries = has_entries or _has_entries
    runtime_lists = runtime_lists or {}
    out, seen = [], set()

    def add(flag, path):
        if not path:
            return
        key = os.path.normcase(os.path.abspath(path))
        if key in seen or not has_entries(path):
            return
        seen.add(key)
        out.append(f"{flag}={path}")

    for name in GENERAL_EXCLUDED_LISTS:
        add("--hostlist-exclude", runtime_lists.get(name) or os.path.join(base_dir, "list", name))
    for path in extra_hostlists:
        add("--hostlist-exclude", path)
    for name in GENERAL_EXCLUDED_IPSETS:
        add("--ipset-exclude", os.path.join(base_dir, "ip", name))
    for path in extra_ipsets:
        add("--ipset-exclude", path)
    return out


def remove_legacy_general_list(base_dir, log=None):
    """Убирает list/general.txt, оставшийся от версий до 1.42. True — удалён."""
    path = os.path.join(base_dir, "list", LEGACY_GENERAL_LIST)
    if not os.path.isfile(path):
        return False
    try:
        os.remove(path)
    except OSError as e:
        if log:
            log(f"[Init] Не удалось удалить устаревший list/general.txt: {e}")
        return False
    if log:
        log("[Init] Удалён устаревший list/general.txt: general теперь применяется ко всем сайтам вне списков.")
    return True


# Метод оценки general. С 1.42 панель general включает контрольные сайты
# (nova_strategy_panel), и прежние оценки — «сколько заблокированного открылось»
# — с новыми несопоставимы. Хуже того: чекер продвигает лучшую стратегию по
# сохранённым оценкам, не перепроверяя её, и на первом же проходе вернул
# старый split2 вместо выпущенной hostfakesplit (замер 2026-10-04): у новых
# стратегий оценок не было вовсе. Смена метода сбрасывает оценки general,
# и пул измеряется заново.
# controls-v2: тестовый winws чекера фильтровал пакеты по IP из своего кэша, а
# проба шла на свежий адрес CDN — обход к ней не применялся, и стратегия,
# ломающая сайт, всё равно получала за него очко. Оценки v1 этим испорчены.
GENERAL_SCORING_METHOD = "controls-v2"


def reset_stale_general_scores(scores, state, recorded_method):
    """Сбрасывает оценки general, если они получены другим методом.

    Меняет scores и state на месте. True — сброс сделан.
    """
    if recorded_method == GENERAL_SCORING_METHOD:
        return False
    if isinstance(scores, dict):
        # Пустой словарь, а не удаление ключа: save_json_safe не пишет пустой
        # объект поверх непустого файла, и сброс молча не сохранился бы.
        scores["general"] = {}
    if isinstance(state, dict):
        for key in ("general_score", "general_total", "general_checked"):
            state.pop(key, None)
        state["checks_completed"] = False
    return True
