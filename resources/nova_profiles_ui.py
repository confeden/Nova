"""The «Профили» window: profile groups, the explicit selection, import, generators and Tor.

The window is built only from a duck-typed `ctx` that nova.pyw creates next to the routing
settings popup (DESIGN.md §10); this module never imports nova.pyw. Fields it reads:

    root, theme (SETTINGS_THEME), pill_button_cls (PopupPillButton), apply_window_icon(win),
    place_window(win), base_dir, log(msg), get_runtime_status(), apply_selection(sel),
    generate_warp(force), issue_proton(force), register_masque([replace]), test_profile(id, done_cb),
    open_folder(path), job_status(), tor_status(), tor_connect(entry), tor_disconnect(),
    tor_new_identity(), tor_refresh_bridges()

A missing optional field degrades to a notice in the window, never to an exception.

tor_status() may carry two optional keys on top of TorManager.status():
    "route_active": bool   the browser route is "tor" (get_routing_group_mode("browser") == "tor").
                           The Tor toggle follows it: a failed or stopped Tor whose route is still "tor"
                           offers «Отключить Tor», so the browsers can be put back to «Авто».
    "entry_setting": str   the persisted entry (get_tor_entry_mode()). TorManager reports "auto" until
                           its first start, so without this key «Подключить Tor» cannot know the stored
                           choice and sends whatever the status shows.

Threading. Every ctx callback returns immediately by contract, so action callbacks are called
on the Tk thread. The window's own file work (listing, stats, reading import files, import,
delete, rename, creating a folder) and the status getters run on daemon threads. Their results
travel back through a `queue.Queue` that the Tk thread drains with `root.after`. Worker threads
never call into Tcl: a foreign thread calling `root.after` makes tkinter raise "main thread is
not in main loop" whenever the Tk thread is not inside `mainloop` (startup, tests pumping
`update()`), so the queue is the one hand-off that works in every state.

Import never changes the selection (I1 is about explicit choices; an import is not one).
Candidates carry private keys in `text`: nothing here logs a candidate or a record whole.
"""

import inspect
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

__all__ = [
    "open_profiles_window", "toggle_profiles_window", "close_profiles_window", "get_profiles_window",
    "ProfilesWindow", "ImportPreview", "FallbackPillButton", "ThemedScrollbar",
    "TABS", "TAB_TOR", "TAB_SUBS", "ACTION_LABELS", "TAB_ACTION_ROWS", "TOR_ENTRIES",
    "IMPORT_FILETYPES", "DEFAULT_THEME", "merge_theme", "is_dark_theme", "set_pill_text",
    "format_outcome", "format_row_text", "format_selection_text", "format_runtime_text",
    "format_job_line", "format_tor_status", "format_list_header", "classify_import_candidates",
    "format_subscription_row", "format_subs_header", "SUBS_INTERVAL_CHOICES",
]

# Group names are fixed by the design contract (nova_profiles.GROUP_*); repeated here so the
# window can be built before nova_profiles has been imported by a worker.
GROUP_CLOUDFLARE = "AWG Cloudflare"
GROUP_PROTON = "AWG Proton"
GROUP_MASQUE = "MASQUE"
GROUP_VLESS = "VLESS"
GROUP_CUSTOM = "Custom"
PROFILE_GROUPS = (GROUP_CLOUDFLARE, GROUP_PROTON, GROUP_MASQUE, GROUP_VLESS, GROUP_CUSTOM)
# Profile kinds, likewise repeated (nova_profiles.KIND_*): the file's own type, not its folder,
# decides which helper starts it and therefore which group an import lands in.
KIND_AWG = "awg"
KIND_MASQUE = "masque"
KIND_VLESS = "vless"
# Groups whose profiles the user brought in, so renaming them is theirs to do.
IMPORTED_GROUPS = (GROUP_CUSTOM, GROUP_VLESS)
TAB_TOR = "tor"
# The subscriptions tab: URLs that hand out profiles, and how often each is re-downloaded. It has
# no profile list of its own -- what it brings lands in VLESS and «Custom AWG» -- so it reuses the
# list panel with rows of its own.
TAB_SUBS = "subscriptions"
TABS = (
    (GROUP_CLOUDFLARE, "AWG Cloudflare"),
    (GROUP_PROTON, "AWG Proton"),
    (GROUP_MASQUE, "MASQUE"),
    (GROUP_VLESS, "VLESS"),
    # The group's folder, its id prefix and everything stored under it stay "Custom"; only the
    # caption says what is in it, because «Custom» alone told the owner nothing.
    (GROUP_CUSTOM, "Custom AWG"),
    (TAB_SUBS, "Подписки"),
    (TAB_TOR, "Tor"),
)

ACTION_LABELS = {
    "connect": "Подключить",
    "connect_group": "Подключить группу",
    "test": "Проверить",
    "test_list": "Проверить список",
    "refresh_profiles": "Обновить профили",
    "folder": "Папка",
    "sub_add": "Добавить…",
    "sub_interval": "Период…",
    "sub_toggle": "Вкл/выкл",
    "sub_refresh": "Обновить сейчас",
    "sub_delete": "Удалить",
    "generate_warp": "Сгенерировать свои",
    "issue_proton": "Выпустить профили",
    "register_masque": "Зарегистрировать",
    "reissue_warp": "Перевыпустить",
    "reissue_proton": "Перевыпустить",
    "reissue_masque": "Перевыпустить",
    "delete": "Удалить",
    "rename": "Переименовать",
    "import_file": "Импорт файла…",
    "import_clipboard": "Вставить из буфера",
    "tor_toggle": "Подключить Tor",
    "tor_new_identity": "Новая цепочка",
    "tor_refresh_bridges": "Обновить мосты",
}
TOR_CONNECT_LABEL = "Подключить Tor"
TOR_DISCONNECT_LABEL = "Отключить Tor"

# The first row is the same five actions on every profile tab (owner's request 2026-09-20):
# Подключить / Проверить / Проверить список / Обновить профили / Папка. What each of them means is
# the tab's business — «Обновить профили» issues on Cloudflare, Proton and MASQUE, and downloads
# the subscriptions on VLESS and Custom — but where the owner clicks does not move between tabs.
# The second row holds what only some tabs have: the imports, rename and delete.
#
# «Подключить группу» and «В резерв» were removed on the owner's word 2026-09-20 ("unclear
# buttons"), not because the two things went away: the group connect is what «Подключить» does when
# no row is selected, and the reserve slot is chosen from its own pill menu on the main window,
# which lists the same groups and nodes.
_MAIN_ROW = ("connect", "test", "test_list", "refresh_profiles", "folder")
TAB_ACTION_ROWS = {
    GROUP_CLOUDFLARE: (_MAIN_ROW,),
    GROUP_PROTON: (_MAIN_ROW,),
    GROUP_MASQUE: (_MAIN_ROW, ("delete",)),
    GROUP_VLESS: (_MAIN_ROW, ("import_file", "import_clipboard", "rename", "delete")),
    GROUP_CUSTOM: (_MAIN_ROW, ("import_file", "import_clipboard", "rename", "delete")),
    TAB_SUBS: (("sub_add", "sub_interval", "sub_toggle", "sub_refresh", "sub_delete"),),
    TAB_TOR: (("tor_toggle", "tor_new_identity", "tor_refresh_bridges"),),
}


TOR_ENTRIES = (
    ("auto", "Auto"),
    ("webtunnel", "WebTunnel"),
    ("obfs4", "obfs4"),
    ("snowflake", "Snowflake"),
    ("vanilla", "Vanilla"),
    ("direct", "Без мостов"),
)
_TOR_ENTRY_LABELS = dict(TOR_ENTRIES)
_TOR_STATE_WORDS = {
    "stopped": "остановлен",
    "starting": "запускается",
    "ready": "готов",
    "failed": "не подключился",
}
_TOR_BRIDGE_ORDER = ("webtunnel", "obfs4", "snowflake", "meek_lite", "vanilla")
TOR_DEFAULT_SOCKS_PORT = 1375
TOR_DEFAULT_HTTP_PORT = 1378

# The group whose «Обновить профили» runs an issue job. VLESS and Custom are not here: their
# profiles come from subscriptions, and `_on_refresh_profiles` sends them there instead.
JOB_KIND_BY_GROUP = {GROUP_CLOUDFLARE: "warp", GROUP_PROTON: "proton", GROUP_MASQUE: "masque"}
# Which job line a tab shows. Subscriptions feed both import groups, so both watch «subs».
JOB_LINE_BY_GROUP = dict(JOB_KIND_BY_GROUP,
                         **{GROUP_VLESS: "subs", GROUP_CUSTOM: "subs", TAB_SUBS: "subs"})
_JOB_NOUNS = {"warp": "Генерация WARP", "proton": "Выпуск Proton", "masque": "Регистрация MASQUE",
              "subs": "Обновление подписок"}

IMPORT_FILETYPES = [("Профили", "*.conf *.json *.txt"), ("Все файлы", "*.*")]
IMPORT_MAX_FILES = 64
IMPORT_MAX_FILE_BYTES = 4 * 1024 * 1024

REFRESH_INTERVAL_MS = 1500
DRAIN_INTERVAL_MS = 50
TOGGLE_DEBOUNCE_S = 0.18
TEST_RESULT_TIMEOUT_S = 180.0
JOB_START_GRACE_S = 10.0
NOTICE_TTL_S = 20.0
# One ctx status getter gets this long per refresh; after that the refresh uses its last value.
STATUS_GETTER_TIMEOUT_S = 3.0
# A refresh worker (profile files included) running longer than this is reported once.
REFRESH_STALL_S = 10.0
_STATUS_GETTERS = (("get_runtime_status", "runtime", {}), ("job_status", "jobs", {}), ("tor_status", "tor", None))

_REASON_PROFILE_DELETED = "профиль удалён"
_WARNING_AWG3_MARK = "AWG 3.x"

# nova.pyw SETTINGS_THEME (dark) — used only when ctx.theme lacks a key.
DEFAULT_THEME = {
    "bg": "#0B1410",
    "panel": "#111B15",
    "border": "#22402B",
    "text": "#E5F7E8",
    "muted": "#93AD98",
    "pill_on_bg": "#12381D",
    "pill_on_fg": "#D9FFE1",
    "pill_off_bg": "#1A241D",
    "pill_off_fg": "#8DA38F",
}
# Row/notice tones. Dark values are nova.pyw LOG_COLOR_TEXT_*; light ones are darker variants
# that stay readable on SETTINGS_THEME light panels.
_TONES_DARK = {"ok": "#47E05F", "fail": "#FF6B6B", "warn": "#E4C05B"}
_TONES_LIGHT = {"ok": "#13A10E", "fail": "#C62828", "warn": "#9A6700"}
_OUTLINE_ACCENT = "#13A10E"  # nova.pyw OUTLINE_ACCENT_COLOR = MAIN_COLOR_TEXT_NORMAL
_SCROLL_THUMB_DARK = ("#2D5A37", "#418050")  # nova.pyw ModernScrollbar (thumb, hover)
_SCROLL_THUMB_LIGHT = ("#9CC8A5", "#79B487")

_REGISTRY_ATTR = "_nova_profiles_window_ref"


# --------------------------------------------------------------------------------------------
# Theme helpers


def merge_theme(theme):
    merged = dict(DEFAULT_THEME)
    if isinstance(theme, dict):
        for key, value in theme.items():
            if isinstance(value, str) and value:
                merged[key] = value
    return merged


def _hex_rgb(color):
    text = str(color or "").strip()
    if len(text) == 7 and text.startswith("#"):
        try:
            return int(text[1:3], 16), int(text[3:5], 16), int(text[5:7], 16)
        except ValueError:
            return None
    return None


def is_dark_theme(theme):
    rgb = _hex_rgb((theme or {}).get("bg"))
    if rgb is None:
        return True
    r, g, b = rgb
    return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255.0 < 0.5


def _lighter_hex(color, factor):
    rgb = _hex_rgb(color)
    if rgb is None:
        return color
    r, g, b = (min(255, int(c + (255 - c) * factor)) for c in rgb)
    return f"#{r:02X}{g:02X}{b:02X}"


def apply_title_bar_theme(win, dark):
    """Dark/light DWM title bar like nova.pyw does for its popups (Windows 10 1809+)."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        value = ctypes.c_int(1 if dark else 0)
        result = ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
        return result == 0
    except (OSError, AttributeError, tk.TclError):
        # Cosmetic only: an old Windows build keeps the default title bar.
        return False


def drop_maximize_box(win):
    """Take the maximize button off a window resizable in width only (Windows).

    Tk adds the button as soon as one dimension is resizable. Measured: a maximized «Профили» spans
    the whole screen (2560 px) at its fixed height, and nova.pyw's placement then keeps that width
    after a restore. Without WS_MAXIMIZEBOX a double click on the title bar does not maximize either.
    """
    if os.name != "nt":
        return False
    gwl_style, ws_maximizebox = -16, 0x00010000
    # SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED: redraw the caption only.
    swp_frame_only = 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020
    try:
        import ctypes

        win.update_idletasks()
        user32 = ctypes.windll.user32
        hwnd = user32.GetParent(win.winfo_id())
        if not hwnd:
            return False
        style = user32.GetWindowLongW(hwnd, gwl_style)
        if style & ws_maximizebox:
            user32.SetWindowLongW(hwnd, gwl_style, style & ~ws_maximizebox)
            user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, swp_frame_only)
        return True
    except (OSError, AttributeError, tk.TclError):
        # Cosmetic only: the button stays and does what Windows does with it.
        return False


def set_pill_text(pill, text):
    """Change a pill's caption. PopupPillButton has no setter, but it is a Canvas with one text item."""
    setter = getattr(pill, "set_text", None)
    if callable(setter):
        setter(text)
        return True
    try:
        items = [item for item in pill.find_all() if pill.type(item) == "text"]
        for item in items:
            pill.itemconfigure(item, text=text)
    except (AttributeError, tk.TclError):
        return False
    return bool(items)


# --------------------------------------------------------------------------------------------
# Pure formatting (no Tk; unit-tested directly)


# How long a latency figure is worth showing and worth not re-measuring. Short enough that the
# number in front of the owner is about the network they have now, long enough that flipping between
# tabs does not re-measure anything.
LATENCY_FRESH_S = 180.0
# The pause between the starts of two probes in a background sweep. At 0.12 s a group of fifty is a
# trickle spread over six seconds instead of a burst — the window must not be felt while it is open.
LATENCY_PACE_S = 0.12
# How many rows one sweep measures. A VLESS group filled from four public subscriptions can hold
# several hundred, and measuring them all would take a minute of trickle for a list the owner is
# looking at right now. The rows are already in connect order (nova_profiles._vless_order), so the
# first N are the ones that matter — and what was left out is said in the log rather than implied.
LATENCY_SWEEP_LIMIT = 80
# «Проверить список» is an explicit request, so it covers a whole imported group (a subscription
# brings a couple of hundred nodes) instead of the cap that keeps the automatic on-open sweep
# cheap. At the pace below that is a trickle of about half a minute, not a burst.
LATENCY_LIST_LIMIT = 400
# Repeated from nova_subscriptions (the window is built before a worker has imported it).
DEFAULT_SUB_INTERVAL_HOURS = 12
SUB_MAX_INTERVAL_HOURS = 24 * 7
# A subscription the owner adds by hand is the one they want whole, so its own quota is the size of
# a real list rather than the conservative share the four shipped sources divide between them.
SUB_DEFAULT_KEEP = 300
# How often the window takes the sweep's progress and redraws the rows. Six probes land per pace
# interval and each redraw rebuilds the whole listbox, so the events are coalesced into ~7 frames
# a second rather than drawn one by one.
LATENCY_POLL_MS = 150
# Ports a TCP connect falls back to when ICMP is filtered, per profile kind. A VLESS node is probed
# on its own port, which is the port its traffic uses; a WireGuard endpoint is UDP, so 443 is a
# stand-in for "is this host reachable at all" (Proton keeps OpenVPN TCP there).
LATENCY_FALLBACK_PORTS = (443,)


def _plural(count, one, few, many):
    n = abs(int(count)) % 100
    if 11 <= n <= 19:
        return many
    n %= 10
    if n == 1:
        return one
    if 2 <= n <= 4:
        return few
    return many


def _num(value):
    if isinstance(value, bool) or value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _normalize_test_result(result):
    if not isinstance(result, dict):
        return {"ok": False, "ms": None, "message": "проверка вернула пустой ответ", "skipped": False}
    ms = result.get("ms")
    try:
        ms = None if ms is None or isinstance(ms, bool) else max(0, int(round(float(ms))))
    except (TypeError, ValueError):
        ms = None
    # "skipped": the check did not run (it would cut the live tunnel or could not pass beside it),
    # so it says nothing about the profile.
    return {"ok": bool(result.get("ok")), "ms": ms, "message": str(result.get("message") or "").strip(),
            "skipped": bool(result.get("skipped")) and not result.get("ok")}


def format_latency(measurement):
    """A background measurement -> the short text beside a row, or "" when there is none.

    The number is deliberately not called «ок»: it says the host answered a ping or a TCP connect,
    which is not the same as "a tunnel through it carries traffic" — of sixty reachable public VLESS
    nodes measured on 2026-09-20, four carried anything. «—» is the honest word for a host that did
    not answer at all: that one really is out.
    """
    if not isinstance(measurement, (tuple, list)) or not measurement:
        return "", "normal"
    ms = measurement[0]
    if ms is None:
        return "не отвечает", "muted"
    try:
        return f"{int(ms)} мс", "normal"
    except (TypeError, ValueError):
        return "", "normal"


def format_outcome(stats_entry, test_result=None, testing=False, latency=None, probing=False):
    """Last outcome of a profile -> (text, tone): «ок 12 мс» / «сбой» / «не проверялся».

    A background latency figure never replaces a verdict — a check that ran is what the owner asked
    for — but it does replace «не проверялся», which tells them nothing at all.

    `testing` is a real «Проверить» (a tunnel is being started through this profile); `probing` is
    the cheap sweep of «Проверить список» passing over this row right now. Both say so in the row,
    because a list of two hundred that changes nothing for eight seconds looks broken — the owner
    asked to see which rows are being measured at this moment.
    """
    if testing:
        return "проверка…", "muted"
    if probing:
        return "замеряем…", "warn"
    entry = stats_entry if isinstance(stats_entry, dict) else {}
    ok_at = _num(entry.get("last_ok_at"))
    fail_at = _num(entry.get("last_fail_at"))
    if test_result is not None:
        result, at = test_result
        if _num(at) >= max(ok_at, fail_at):
            result = _normalize_test_result(result)
            if result["ok"]:
                return (f"ок {result['ms']} мс" if result["ms"] is not None else "ок"), "ok"
            return "сбой", "muted"
    if ok_at <= 0 and fail_at <= 0:
        text, tone = format_latency(latency)
        return (text or "не проверялся"), tone
    if ok_at >= fail_at:
        last_ms = entry.get("last_ms")
        if last_ms is not None and not isinstance(last_ms, bool):
            try:
                return f"ок {int(last_ms)} мс", "ok"
            except (TypeError, ValueError):
                pass
        return "ок", "ok"
    # It failed last time. The ping still matters: «сбой» on a host that does not answer at all is a
    # different problem from «сбой» on one that pings in 40 ms.
    text, _tone = format_latency(latency)
    return (f"сбой · {text}" if text else "сбой"), "muted"


def _issue_split(record, is_fatal=None):
    issues = [str(i) for i in (record.get("issues") or []) if str(i).strip()]
    if is_fatal is None:
        def is_fatal(issue):
            return _WARNING_AWG3_MARK not in issue
    fatal = [i for i in issues if is_fatal(i)]
    warnings = [i for i in issues if not is_fatal(i)]
    return fatal, warnings


def format_row_text(record, *, live=False, outcome="не проверялся", pad="   ", is_fatal=None,
                    reserve=False):
    """One listbox row: «● name  ·  endpoint  ·  outcome» (no monospace alignment).

    `●` is the profile carrying the primary tunnel, `◆` the one serving the reserve slot. One
    profile is never both: the two slots are separate helpers on separate ports.
    """
    marker = "● " if live else ("◆ " if reserve else pad)
    parts = [str(record.get("name") or record.get("id") or "")]
    endpoint = str(record.get("endpoint") or "").strip()
    if endpoint and endpoint != parts[0]:
        parts.append(endpoint)
    fatal, warnings = _issue_split(record, is_fatal)
    if not record.get("valid", True):
        parts.append("ошибка: " + (fatal[0] if fatal else (warnings[0] if warnings else "профиль не читается")))
    else:
        parts.append(outcome)
        if warnings:
            parts.append("⚠ " + (_WARNING_AWG3_MARK if _WARNING_AWG3_MARK in warnings[0] else warnings[0]))
    return marker + "  ·  ".join(parts)


def format_list_header(group, records, loaded=True):
    if not loaded:
        return "Загрузка списка…"
    total = len(records)
    if total == 0:
        hints = {
            GROUP_CLOUDFLARE: "нажмите «Сгенерировать свои»",
            GROUP_PROTON: "нажмите «Выпустить профили»",
            GROUP_MASQUE: "нажмите «Зарегистрировать»",
            GROUP_VLESS: "нажмите «Обновить профили» или вставьте ссылку vless:// из буфера",
            GROUP_CUSTOM: "импортируйте файл или вставьте конфиг из буфера",
        }
        return f"В группе «{group}» пока нет профилей — {hints.get(group, 'добавьте профиль')}"
    text = f"{group}: {total} {_plural(total, 'профиль', 'профиля', 'профилей')}"
    if group == GROUP_CLOUDFLARE:
        generated = sum(1 for r in records if r.get("origin") == "generated")
        bundled = sum(1 for r in records if r.get("origin") == "bundled")
        extra = []
        if generated:
            extra.append(f"свои {generated}")
        if bundled:
            extra.append(f"встроенные {bundled}")
        if extra:
            text += " (" + ", ".join(extra) + ")"
    broken = sum(1 for r in records if not r.get("valid", True))
    if broken:
        text += f" · с ошибками {broken}"
    return text


# What «Период…» offers, in hours. Twelve is the default and the owner's request: lists change
# slowly and a conditional GET that finds nothing costs 0 bytes (measured: 304 on every source), so
# the interval is chosen for freshness, not for traffic.
SUBS_INTERVAL_CHOICES = (1, 3, 6, 12, 24, 48, 168)


def _age_text(stamp, now=None):
    """«5 мин назад» / «3 ч назад» / «вчера»; "" when there is no stamp."""
    stamp = _num(stamp)
    if stamp <= 0:
        return ""
    delta = max(0.0, (time.time() if now is None else float(now)) - stamp)
    if delta < 90:
        return "только что"
    minutes = int(delta // 60)
    if minutes < 60:
        return f"{minutes} мин назад"
    hours = int(delta // 3600)
    if hours < 24:
        return f"{hours} ч назад"
    days = int(delta // 86400)
    return "вчера" if days == 1 else f"{days} {_plural(days, 'день', 'дня', 'дней')} назад"


def _subs_kind_word(kind):
    return {"vless": "VLESS", "awg": "AWG"}.get(str(kind or "").lower(), "авто")


def format_subscription_row(record, now=None, pad="   ", refreshing=False):
    """One row of the «Подписки» tab -> (text, tone).

    The URL is deliberately not in the row. A subscription link is a credential often enough
    (`.../link/<secret>`, `?token=<secret>`) that the folder «Папка» opens must never carry one in
    a file name (G89); a window the owner screenshots is the same exposure. The row says where it
    goes — host and file — and the whole link is one «Период…» away for anyone who needs it.
    """
    entry = record if isinstance(record, dict) else {}
    name = str(entry.get("name") or "").strip()
    url = str(entry.get("url") or "")
    host, _sep, tail = url.partition("://")[2].partition("/")
    title = name or host or str(entry.get("id") or "подписка")
    enabled = bool(entry.get("enabled", True))
    interval = _as_hours(entry.get("interval_hours"))
    count = max(0, int(_num(entry.get("node_count"))))
    parts = [title, host or "?"]
    if not enabled:
        parts.append("выключена")
    else:
        parts.append(f"каждые {interval} ч")
    parts.append(f"{count} {_plural(count, 'профиль', 'профиля', 'профилей')}")
    parts.append(_subs_kind_word(entry.get("kind")))
    if refreshing:
        parts.append("обновляется…")
        tone = "warn"
    else:
        status = str(entry.get("last_status") or "").strip()
        when = _age_text(entry.get("last_checked_at"), now)
        if status:
            parts.append(status + (f" · {when}" if when else ""))
        elif when:
            parts.append(when)
        else:
            parts.append("ещё не загружалась")
        streak = int(_num(entry.get("fail_streak")))
        tone = "fail" if streak else ("muted" if not enabled else "normal")
    return pad + "  ·  ".join(str(p) for p in parts if str(p)), tone


def _as_hours(value):
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 12


def format_subs_header(records, loaded=True):
    if not loaded:
        return "Загрузка подписок…"
    total = len(records or [])
    if not total:
        return "Подписок нет — «Добавить…» и вставьте ссылку на список VLESS или AWG"
    on = sum(1 for r in records if r.get("enabled", True))
    nodes = sum(max(0, int(_num(r.get("node_count")))) for r in records)
    text = f"Подписки: {total}, включено {on}"
    if nodes:
        text += f" · профилей {nodes}"
    return text


def format_selection_text(effective, selection=None):
    eff = effective if isinstance(effective, dict) else {}
    sel = selection if isinstance(selection, dict) else {}
    mode = str(eff.get("mode") or "auto")
    group = str(eff.get("group") or "")
    reason = str(eff.get("reason") or "")
    if mode == "profile":
        profile_id = str(eff.get("profile_id") or "")
        name = profile_id.partition("/")[2] or profile_id
        text = f"Профиль «{name}» из группы «{group}»"
    elif mode == "group":
        if reason == _REASON_PROFILE_DELETED:
            wanted = str(sel.get("profile") or sel.get("profile_id") or "")
            name = wanted.partition("/")[2] or wanted or "?"
            return f"Профиль «{name}» удалён — используется группа «{group}»"
        text = f"Группа «{group}»: Nova перебирает только её профили"
    else:
        # Both imported groups are out of «Авто» (D25), and the line used to name only one of them.
        text = "Авто: Nova сама выбирает профиль из своих групп; VLESS и Custom AWG — только вручную"
    if reason:
        text += f" — {reason}"
    return text


_BACKEND_NAMES = {"awg": "AWG", "masque": "MASQUE", "vless": "VLESS",
                  "cloudflare": "WARP", "warp-cli": "WARP"}


def format_runtime_text(runtime):
    """-> (text, tone) for «Сейчас: …»."""
    status = runtime if isinstance(runtime, dict) else {}
    backend = str(status.get("backend") or "")
    profile_id = str(status.get("profile_id") or "")
    label = str(status.get("label") or "").strip()
    connected = bool(status.get("connected"))
    what = profile_id or label or _BACKEND_NAMES.get(backend, backend)
    if not what:
        return ("Сейчас: подключено" if connected else "Сейчас: не подключено"), ("ok" if connected else "muted")
    if connected:
        return f"Сейчас: ● {what} · подключено", "ok"
    return f"Сейчас: {what} · подключение…", "muted"


def format_job_line(job, kind, *, started_at=0.0, snapshot_started_at=0.0, now=None):
    """-> (text, tone) for the generator line of a tab."""
    noun = _JOB_NOUNS.get(kind, kind)
    now = time.time() if now is None else now
    info = job if isinstance(job, dict) else {}
    running = bool(info.get("running"))
    message = str(info.get("message") or "").strip()
    if not running and started_at and snapshot_started_at < started_at and now - started_at < JOB_START_GRACE_S:
        return f"{noun}: запускается…", "muted"
    if running:
        return f"{noun}: {message or 'идёт…'}", "ok"
    if not message:
        return "", "muted"
    at = _num(info.get("at"))
    stamp = f" · {time.strftime('%H:%M', time.localtime(at))}" if at > 0 else ""
    tone = "warn" if info.get("ok") is False else "muted"
    return f"{noun}: {message}{stamp}", tone


def format_tor_status(status):
    """tor_status() -> texts for the Tor tab.

    `running` is the Tor process state (starting/ready). `engaged` is what the toggle follows: the
    browsers are routed to Tor, so the next click must disconnect. With `route_active` in the status
    that is the route itself (or a running Tor); without it a failed Tor still counts as engaged,
    because nothing reverts the browser route when Tor fails.
    """
    if not isinstance(status, dict):
        return {"state_key": "unavailable", "running": False, "engaged": False,
                "state": "Tor недоступен в этой сборке", "progress": "", "bridges": "", "ports": "", "error": "",
                "entry": "", "entry_setting": ""}
    state = str(status.get("state") or "stopped")
    entry = str(status.get("entry") or "")
    attempt = str(status.get("attempt") or "")
    running = state in ("starting", "ready")
    route_active = status.get("route_active")
    if route_active is None:
        engaged = running or state == "failed"
    else:
        engaged = running or bool(route_active)
    state_text = _TOR_STATE_WORDS.get(state, state)
    if state in ("starting", "ready", "failed") and entry:
        state_text += f" · вход {_TOR_ENTRY_LABELS.get(entry, entry)}"
        if entry == "auto" and attempt and attempt != "auto":
            state_text += f" → {_TOR_ENTRY_LABELS.get(attempt, attempt)}"
    try:
        progress = max(0, min(100, int(status.get("progress") or 0)))
    except (TypeError, ValueError):
        progress = 0
    summary = str(status.get("summary") or "").strip()
    # nova_tor summaries look like "Tor: вход obfs4 — Loading relay descriptors"; the tail is the
    # bootstrap phase itself.
    tail = summary.rsplit(" — ", 1)[-1].strip() if " — " in summary else summary
    if state == "starting":
        progress_text = f"Загрузка {progress}%" + (f" — {tail}" if tail else "")
    elif state in ("ready", "failed"):
        progress_text = summary
    elif engaged:
        progress_text = "Браузеры направлены в Tor, но он не запущен"
    else:
        progress_text = ""
    bridges = status.get("bridges") if isinstance(status.get("bridges"), dict) else {}
    counts = []
    for kind in sorted(bridges, key=lambda k: (_TOR_BRIDGE_ORDER.index(k) if k in _TOR_BRIDGE_ORDER else 99, k)):
        try:
            number = int(bridges[kind])
        except (TypeError, ValueError):
            continue
        if number > 0:
            counts.append(f"{kind} {number}")
    bridges_text = " · ".join(counts) if counts else "сохранённых мостов нет"
    if status.get("refreshing_bridges"):
        bridges_text += " · обновляются…"
    socks = status.get("socks_port") or TOR_DEFAULT_SOCKS_PORT
    http = status.get("http_port") or TOR_DEFAULT_HTTP_PORT
    entry_setting = str(status.get("entry_setting") or "")
    return {
        "state_key": state,
        "running": running,
        "engaged": engaged,
        "state": state_text,
        "progress": progress_text,
        "bridges": bridges_text,
        "ports": f"SOCKS 127.0.0.1:{socks} · HTTP 127.0.0.1:{http}",
        "error": str(status.get("error") or "").strip(),
        "entry": entry,
        "entry_setting": entry_setting if entry_setting in _TOR_ENTRY_LABELS else "",
    }


def _selection_key(selection):
    """(mode, group, profile) of a selection dict, with only the fields its mode uses."""
    sel = selection if isinstance(selection, dict) else {}
    mode = str(sel.get("mode") or "auto").strip().lower()
    profile = str(sel.get("profile") or sel.get("profile_id") or "").strip()
    group = str(sel.get("group") or "").strip()
    if mode == "profile":
        return mode, group or profile.partition("/")[0], profile
    if mode == "group":
        return mode, group, ""
    return "auto", "", ""


def _error_candidate(name, issue):
    return {"kind": "awg", "name": name, "text": "", "endpoint": "", "issues": [issue], "ok": False,
            "fingerprint": ""}


def classify_import_candidates(candidates, existing_profiles, is_fatal=None):
    """Preview rows: status "new" | "duplicate" | "invalid" with the Russian status text."""
    known = {}
    for record in existing_profiles or []:
        fingerprint = record.get("fingerprint") if isinstance(record, dict) else None
        if fingerprint:
            known.setdefault(fingerprint, str(record.get("id") or ""))
    seen = set()
    rows = []
    for candidate in candidates or []:
        if not isinstance(candidate, dict):
            continue
        fingerprint = candidate.get("fingerprint") or ""
        fatal, warnings = _issue_split(candidate, is_fatal)
        if not candidate.get("ok"):
            first = fatal[0] if fatal else (warnings[0] if warnings else "профиль не разобран")
            status, text = "invalid", f"ошибка: {first}"
        elif fingerprint and fingerprint in known:
            status, text = "duplicate", f"уже есть ({known[fingerprint]})" if known[fingerprint] else "уже есть"
        elif fingerprint and fingerprint in seen:
            status, text = "duplicate", "уже есть (повтор в списке)"
        else:
            status, text = "new", "новый"
            if warnings:
                text += " · ⚠ " + (_WARNING_AWG3_MARK if _WARNING_AWG3_MARK in warnings[0] else warnings[0])
        if fingerprint:
            seen.add(fingerprint)
        rows.append({"candidate": candidate, "status": status, "status_text": text})
    return rows


def _error_text(exc):
    if isinstance(exc, OSError):
        return str(exc.strerror or exc)
    if isinstance(exc, (ValueError, RuntimeError)):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


def _load_profiles_module():
    try:
        import nova_profiles
    except ImportError as exc:
        return None, f"Модуль профилей недоступен: {exc}"
    return nova_profiles, ""


def _load_subs_module():
    try:
        import nova_subscriptions
    except ImportError as exc:
        return None, f"Модуль подписок недоступен: {exc}"
    return nova_subscriptions, ""


def _require_subs_module():
    module, error = _load_subs_module()
    if module is None:
        raise RuntimeError(error)
    return module


def _require_profiles_module():
    module, error = _load_profiles_module()
    if module is None:
        raise RuntimeError(error)
    return module


def _decode_import_bytes(data):
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        # A conf saved by an old Russian-locale editor.
        return data.decode("cp1251", errors="replace")


# --------------------------------------------------------------------------------------------
# Widgets


def _round_rect_points(x1, y1, x2, y2, r):
    return [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
            x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]


class FallbackPillButton(tk.Canvas):
    """Plain-canvas stand-in for nova.pyw PopupPillButton when ctx does not provide one."""

    def __init__(self, master, text, command, width=68, height=28, theme=None):
        self._theme = merge_theme(theme)
        super().__init__(master, width=width, height=height, bg=self._theme["bg"], highlightthickness=0,
                         bd=0, relief="flat")
        self._command = command
        self._selected = False
        self._hover = False
        self._width = int(width)
        self._height = int(height)
        self._shape = self.create_polygon(
            _round_rect_points(1, 1, self._width - 2, self._height - 2, 10), smooth=True, width=2)
        self._text_id = self.create_text(self._width // 2, self._height // 2, text=text, font=("Segoe UI", 8))
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", lambda _e: self.invoke())
        self._render()

    def set_selected(self, selected):
        self._selected = bool(selected)
        self._render()

    def set_text(self, text):
        self.itemconfigure(self._text_id, text=text)

    def invoke(self):
        if callable(self._command):
            self._command()

    def _on_enter(self, _event=None):
        self._hover = True
        self.configure(cursor="hand2")
        self._render()

    def _on_leave(self, _event=None):
        self._hover = False
        self.configure(cursor="")
        self._render()

    def _render(self):
        t = self._theme
        fill = t["pill_on_bg"] if self._selected else t["pill_off_bg"]
        fg = t["pill_on_fg"] if self._selected else t["pill_off_fg"]
        if self._hover:
            outline = _OUTLINE_ACCENT
        elif self._selected:
            outline = t["border"]
        else:
            outline = fill
        self.itemconfigure(self._shape, fill=fill, outline=outline)
        self.itemconfigure(self._text_id, fill=_lighter_hex(fg, 0.18) if self._hover else fg,
                           font=("Segoe UI Semibold", 8) if self._hover else ("Segoe UI", 8))


class ThemedScrollbar(tk.Canvas):
    """nova.pyw ModernScrollbar with SETTINGS_THEME colours; the thumb hides when all rows fit."""

    def __init__(self, master, command, theme, dark, width=14):
        self.bg_color = merge_theme(theme)["panel"]
        self.thumb_color, self.hover_color = _SCROLL_THUMB_DARK if dark else _SCROLL_THUMB_LIGHT
        # height=1: a Canvas otherwise requests ~7 cm and would stretch the list next to it.
        super().__init__(master, bg=self.bg_color, width=width, height=1, highlightthickness=0, bd=0,
                         cursor="sb_v_double_arrow")
        self.command = command
        self.y_lo = 0.0
        self.y_hi = 1.0
        self.is_hover = False
        self._dragging = False
        self._drag_offset_y = 0.0
        self._thumb_y1 = 0.0
        self._thumb_y2 = 0.0
        self.bind("<Button-1>", self._on_click)
        self.bind("<B1-Motion>", self._on_drag)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Configure>", self._draw)
        self.bind("<MouseWheel>", self._on_wheel)

    def set(self, lo, hi):
        self.y_lo = float(lo)
        self.y_hi = float(hi)
        self._draw()

    def _draw(self, _event=None):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        view_span = min(1.0, max(0.0, self.y_hi - self.y_lo))
        if h <= 0 or w <= 0 or view_span >= 0.999:
            self._thumb_y1 = self._thumb_y2 = 0.0
            return
        thumb_h = min(float(h), max(24.0, h * view_span))
        travel = max(0.0, h - thumb_h)
        max_lo = max(0.0, 1.0 - view_span)
        thumb_y = travel * (min(max(self.y_lo, 0.0), max_lo) / max_lo) if max_lo else 0.0
        pad = 3
        x1, x2 = pad, w - pad
        y1, y2 = thumb_y + 2, thumb_y + thumb_h - 2
        self._thumb_y1, self._thumb_y2 = y1, y2
        color = self.hover_color if self.is_hover else self.thumb_color
        r = min((x2 - x1) / 2, (y2 - y1) / 2)
        self.create_oval(x1, y1, x2, y1 + 2 * r, fill=color, outline=color)
        self.create_oval(x1, y2 - 2 * r, x2, y2, fill=color, outline=color)
        self.create_rectangle(x1, y1 + r, x2, y2 - r, fill=color, outline=color)

    def _on_click(self, event):
        if not self.command:
            return
        if self._thumb_y1 <= event.y <= self._thumb_y2:
            self._dragging = True
            self._drag_offset_y = event.y - self._thumb_y1
        else:
            self._dragging = False
            self.command("scroll", -1 if event.y < self._thumb_y1 else 1, "pages")

    def _on_drag(self, event):
        if not self._dragging or not self.command:
            return
        h = float(self.winfo_height())
        thumb_h = max(0.0, self._thumb_y2 - self._thumb_y1)
        travel = max(0.0, h - thumb_h)
        view_span = min(1.0, max(0.0, self.y_hi - self.y_lo))
        max_lo = max(0.0, 1.0 - view_span)
        if travel <= 0.0 or max_lo <= 0.0:
            return
        thumb_y = min(travel, max(0.0, event.y - self._drag_offset_y))
        self.command("moveto", (thumb_y / travel) * max_lo)

    def _on_release(self, _event):
        self._dragging = False

    def _on_wheel(self, event):
        if self.command and event.delta:
            self.command("scroll", -1 if event.delta > 0 else 1, "units")

    def _on_enter(self, _event):
        self.is_hover = True
        self._draw()

    def _on_leave(self, _event):
        self.is_hover = False
        self._draw()


class _TestToken:
    """One pending «Проверить»: the result is accepted exactly once (done_cb or the timeout)."""

    __slots__ = ("profile_id", "started", "_lock", "_claimed")

    def __init__(self, profile_id):
        self.profile_id = profile_id
        self.started = time.monotonic()
        self._lock = threading.Lock()
        self._claimed = False

    def claim(self):
        with self._lock:
            if self._claimed:
                return False
            self._claimed = True
            return True


class _StatusCall:
    """Single-flight runner for one ctx status getter.

    Each call runs on its own daemon thread, so a getter that blocks cannot hold back the other
    getters or the profile list. While a call is still running, later refreshes join that same call
    instead of starting another thread: a stuck getter costs one thread, not one per refresh.
    """

    __slots__ = ("name", "_lock", "_pending", "_last")

    def __init__(self, name):
        self.name = name
        self._lock = threading.Lock()
        self._pending = None  # (done Event, outcome dict, started monotonic)
        self._last = None  # (value,) from the last call that returned

    def start(self, fn):
        """Start a call unless one is still running; returns that call's (done, outcome, started)."""
        with self._lock:
            if self._pending is not None:
                return self._pending
            pending = (threading.Event(), {}, time.monotonic())
            self._pending = pending
        done, outcome, _started = pending

        def run():
            try:
                outcome["value"] = fn()
            except Exception as exc:  # handed to the refresh that collects this call
                outcome["error"] = exc
            with self._lock:
                if "value" in outcome:
                    self._last = (outcome["value"],)
                self._pending = None
            done.set()

        try:
            threading.Thread(target=run, name=f"NovaProfilesStatus-{self.name}", daemon=True).start()
        except RuntimeError as exc:
            outcome["error"] = exc
            with self._lock:
                self._pending = None
            done.set()
        return pending

    def last(self):
        with self._lock:
            return self._last


# --------------------------------------------------------------------------------------------
# The window


def _registry(root):
    ref = getattr(root, _REGISTRY_ATTR, None)
    if not isinstance(ref, dict):
        ref = {"view": None, "last_toggle_ts": 0.0, "configure_bound": False, "align_pending": False,
               "last_tab": GROUP_CLOUDFLARE}
        setattr(root, _REGISTRY_ATTR, ref)
    return ref


class ProfilesWindow:
    """One «Профили» window per Tk root. Create through `open_profiles_window(ctx)`."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.root = ctx.root
        self.theme = merge_theme(getattr(ctx, "theme", None))
        self.dark = is_dark_theme(self.theme)
        self.tones = dict(_TONES_DARK if self.dark else _TONES_LIGHT)
        self.base_dir = os.fspath(getattr(ctx, "base_dir", "") or "")
        self.current_tab = _registry(self.root).get("last_tab") or GROUP_CLOUDFLARE

        self._results = queue.Queue()
        self._inflight = 0
        self._drain_after_id = None
        self._tick_after_id = None
        self._closed = False
        self._refresh_running = False
        self._refresh_again = False
        self._refresh_started = 0.0  # monotonic start of the running refresh
        self._refresh_stall_reported = False
        self._status_calls = {name: _StatusCall(name) for name, _key, _default in _STATUS_GETTERS}
        self._snapshot = {"started_at": 0.0, "loaded": False, "profiles": [], "stats": {},
                          "selection": {"version": 1, "mode": "auto"},
                          "effective": {"mode": "auto", "group": "", "profile_id": "", "reason": ""},
                          "runtime": {}, "jobs": {}, "tor": None, "errors": [],
                          "subs": [], "subs_loaded": False}
        self._optimistic_selection = None  # (selection, set_at)
        self._selected_ids = {}
        self._reveal_ids = {}
        self._row_ids = []
        self._row_signature = None
        self._tests = {}
        self._test_results = {}
        # {profile_id: (ms or None, method, measured_at)} from the background latency sweep.
        self._latency = {}
        self._latency_running = False
        self._latency_at = 0.0
        # The rows the sweep has in flight right now, the queue their events arrive on, and the
        # poll that draws them. A queue of their own, not the window's result queue: `_drain`
        # counts one in-flight worker per item it takes, so a few hundred progress events would
        # spend the counter that keeps a «Проверить» result moving, and the drain loop would stop
        # rescheduling itself. The poll runs only while a sweep is in flight and coalesces the
        # events — a redraw per event rebuilds the whole listbox ~16 times a second.
        self._latency_active = set()
        self._latency_events = queue.Queue()
        self._latency_poll_after_id = None
        self._job_started = {}
        self._tor_entry = None  # an entry pill the user clicked in this window
        self._tor_optimistic = None  # (expected state_key, set_at wall clock, set_at monotonic)
        self._busy = set()
        self._preview = None
        self._logged_once = set()
        self._notice_at = 0.0
        self._notice_tone = "muted"
        self._notice_text = ""  # full text: a wider window shows more of it
        self._fit_cache = {}
        self._last_snapshot_errors = ()
        self._title_bar_done = False
        self._maximize_box_dropped = False
        self._min_content_px = 0
        self._outer_pad_px = 0
        self.win = None
        try:
            self._build()
        except BaseException:
            # A half-built window must not linger as an invisible Toplevel.
            self._closed = True
            if self.win is not None:
                try:
                    self.win.destroy()
                except tk.TclError:
                    pass  # already gone together with the interpreter
            raise

    # -- building ------------------------------------------------------------------------

    def _label(self, parent, tone="normal", font=None):
        # width=1: a text never widens the window. Every label is packed to fill the row and its text is
        # fitted to the row width (_fit), so the width comes from the pill rows, the list and the user.
        return tk.Label(parent, text="", anchor="w", justify="left", bg=self.theme["bg"],
                        fg=self._tone_color(tone), font=font or self.font_text, bd=0, padx=0, width=1)

    def _measure(self, font, text):
        return int(self.root.tk.call("font", "measure", font, text))

    def _pill_width(self, text, min_width=62):
        return max(int(min_width), self._measure(self.font_pill, text) + 22)

    def _make_pill(self, master, text, command, width=None, height=26, min_width=62):
        if width is None:
            width = self._pill_width(text, min_width)
        cls = getattr(self.ctx, "pill_button_cls", None)
        if cls is None:
            return FallbackPillButton(master, text, command, width=width, height=height, theme=self.theme)
        return cls(master, text, command, width=width, height=height)

    def _divider(self, parent, pady):
        tk.Frame(parent, bg=self.theme["border"], height=1).pack(fill="x", pady=pady)

    def _build(self):
        t = self.theme
        root = self.root
        # Font descriptions, not tkinter.font.Font objects: a Font has __del__ that calls into Tcl, and
        # the cyclic GC may run it on a refresh worker (measured: the worker blocked in `font delete`).
        self.font_title = ("Segoe UI", 10)
        self.font_text = ("Segoe UI", 9)
        self.font_pill = ("Segoe UI Semibold", 8)

        win = tk.Toplevel(root)
        win.withdraw()
        self.win = win
        self._win_path = str(win)
        win.title("Профили")
        # Wider only: rows and notices are long (endpoint, outcome, warnings), the height is set by the list.
        win.resizable(True, False)
        win.configure(bg=t["bg"], bd=1, highlightthickness=1, highlightbackground=t["border"])
        self._call_ctx_quiet("apply_window_icon", win)
        win.protocol("WM_DELETE_WINDOW", self.hide)
        win._nova_raise_above_owner = self._raise
        win._refresh_state = self.refresh_now
        win.bind("<Destroy>", self._on_destroy, add="+")
        # A restore from the taskbar maps the window without going through show().
        win.bind("<Map>", self._on_map, add="+")
        win.bind("<Escape>", lambda _e: self.hide())
        win.bind("<Control-KeyPress>", self._on_control_key)

        outer = tk.Frame(win, bg=t["bg"], padx=10, pady=10)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text="Профили", font=self.font_title, bg=t["bg"], fg=t["text"], anchor="w").pack(
            fill="x", pady=(0, 6))

        tabs_row = tk.Frame(outer, bg=t["bg"])
        tabs_row.pack(fill="x")
        self.tab_pills = {}
        for index, (key, caption) in enumerate(TABS):
            pill = self._make_pill(tabs_row, caption, lambda k=key: self.select_tab(k), min_width=52)
            pill.pack(side="left", padx=(0 if index == 0 else 4, 0))
            self.tab_pills[key] = pill

        # The «Режим: Авто / Группа / Профиль» row was removed on the owner's word 2026-09-20
        # ("superfluous information"): it named the same thing three times — the pills, the line
        # under them and the main window's own VPN pill — and two of its three buttons duplicated
        # «Подключить». What remains is the one line that says what is actually in use.
        self.selection_label = self._label(outer, tone="muted")
        self.selection_label.pack(fill="x", pady=(8, 0))
        self.runtime_label = self._label(outer)
        self.runtime_label.pack(fill="x", pady=(1, 0))

        self._divider(outer, (8, 8))

        body = tk.Frame(outer, bg=t["bg"])
        body.pack(fill="x")
        body.grid_columnconfigure(0, weight=1)
        self.list_panel = tk.Frame(body, bg=t["bg"])
        self.list_panel.grid(row=0, column=0, sticky="nsew")
        self.tor_panel = tk.Frame(body, bg=t["bg"])
        self.tor_panel.grid(row=0, column=0, sticky="nsew")
        self._build_list_panel(self.list_panel)
        self._build_tor_panel(self.tor_panel)

        self._divider(outer, (8, 8))

        actions = tk.Frame(outer, bg=t["bg"])
        actions.pack(fill="x")
        actions.grid_columnconfigure(0, weight=1)
        self.action_frames = {}
        self.action_pills = {}
        for key, _caption in TABS:
            frame = tk.Frame(actions, bg=t["bg"])
            frame.grid(row=0, column=0, sticky="nsew")
            self.action_frames[key] = frame
            self.action_pills[key] = {}
            for row_index, row in enumerate(TAB_ACTION_ROWS[key]):
                row_frame = tk.Frame(frame, bg=t["bg"])
                row_frame.pack(fill="x", pady=(0 if row_index == 0 else 4, 0))
                for index, action in enumerate(row):
                    caption = ACTION_LABELS[action]
                    width = None
                    if action == "tor_toggle":
                        width = max(self._pill_width(TOR_CONNECT_LABEL), self._pill_width(TOR_DISCONNECT_LABEL))
                    pill = self._make_pill(row_frame, caption, lambda a=action: self._dispatch_action(a), width=width)
                    pill.pack(side="left", padx=(0 if index == 0 else 4, 0))
                    self.action_pills[key][action] = pill

        bottom = tk.Frame(outer, bg=t["bg"])
        bottom.pack(fill="x", pady=(10, 0))
        self.close_pill = self._make_pill(bottom, "Закрыть", self.hide, width=74)
        self.close_pill.pack(side="right")
        self.notice_label = self._label(bottom, tone="muted")
        self.notice_label.pack(side="left", fill="x", expand=True)

        win.update_idletasks()
        content_px = max(tabs_row.winfo_reqwidth(), actions.winfo_reqwidth(), body.winfo_reqwidth(),
                         360)
        self.tor_hint.configure(text="Tor включается только для группы «Браузеры»: остальные приложения идут "
                                     "прежним путём.")
        self._apply_content_width(content_px)
        # The built width is the narrowest one: pills and the list never get cut off.
        self._min_content_px = content_px
        self._outer_pad_px = 2 * int(outer.cget("padx"))
        frame_px = win.winfo_reqwidth() - (outer.winfo_reqwidth() - self._outer_pad_px)
        win.minsize(content_px + frame_px, 1)
        outer.bind("<Configure>", self._on_outer_configure, add="+")
        space = max(1, self._measure(self.font_text, " "))
        self._marker_pad = " " * max(1, round(self._measure(self.font_text, "● ") / space))
        self.select_tab(self.current_tab if self.current_tab in dict(TABS) else GROUP_CLOUDFLARE)

    def _build_list_panel(self, panel):
        t = self.theme
        self.list_header = self._label(panel)
        self.list_header.pack(fill="x", pady=(0, 5))
        box = tk.Frame(panel, bg=t["panel"], highlightthickness=1, highlightbackground=t["border"],
                       highlightcolor=t["border"], bd=0)
        box.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(
            box, height=12, width=62, activestyle="none", exportselection=False, selectmode="browse",
            bg=t["panel"], fg=t["text"], selectbackground=t["pill_on_bg"], selectforeground=t["pill_on_fg"],
            highlightthickness=0, relief="flat", bd=0, font=self.font_text,
        )
        self.scrollbar = ThemedScrollbar(box, self.listbox.yview, t, self.dark)
        self.listbox.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y", pady=2)
        self.listbox.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=4)
        self.listbox.bind("<<ListboxSelect>>", self._on_list_select)
        self.listbox.bind("<Delete>", lambda _e: self._dispatch_action("delete")
                          if "delete" in self.action_pills.get(self.current_tab, {}) else None)
        self.job_label = self._label(panel, tone="muted")
        self.job_label.pack(fill="x", pady=(5, 0))

    def _build_tor_panel(self, panel):
        t = self.theme
        entry_row = tk.Frame(panel, bg=t["bg"])
        entry_row.pack(fill="x", pady=(0, 6))
        caption = tk.Label(entry_row, text="Вход", width=10, anchor="w", bg=t["bg"], fg=t["text"],
                           font=self.font_text)
        caption.pack(side="left")
        self.tor_entry_pills = {}
        for index, (entry, label) in enumerate(TOR_ENTRIES):
            pill = self._make_pill(entry_row, label, lambda e=entry: self._on_tor_entry(e), min_width=46)
            pill.pack(side="left", padx=(0 if index == 0 else 4, 0))
            self.tor_entry_pills[entry] = pill
        self.tor_labels = {}
        for key, text in (("state", "Состояние"), ("progress", ""), ("bridges", "Мосты"), ("ports", "Порты"),
                          ("error", "")):
            row = tk.Frame(panel, bg=t["bg"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=text, width=10, anchor="w", bg=t["bg"], fg=t["text"], font=self.font_text).pack(
                side="left")
            value = self._label(row)
            value.pack(side="left", fill="x", expand=True)
            self.tor_labels[key] = value
        self.tor_hint = self._label(panel, tone="muted")
        self.tor_hint.pack(fill="x", pady=(8, 0))
        panel.update_idletasks()
        self._tor_caption_width = caption.winfo_reqwidth()

    def _apply_content_width(self, content_px):
        self._content_px = content_px
        self._tor_value_px = max(120, content_px - self._tor_caption_width)
        self._notice_px = max(120, content_px - self.close_pill.winfo_reqwidth() - 10)
        self.tor_hint.configure(wraplength=content_px)

    def _on_outer_configure(self, event):
        # `outer` fills the window, so its width follows a drag of the window's edge: refit every text.
        content_px = max(self._min_content_px, int(event.width) - self._outer_pad_px)
        if content_px == self._content_px or not self.alive():
            return
        self._apply_content_width(content_px)
        self._set_label(self.notice_label, self._notice_text, self._notice_tone, max_px=self._notice_px)
        self._render_all()

    # -- small helpers -------------------------------------------------------------------

    def _tone_color(self, tone):
        if tone == "muted":
            return self.theme["muted"]
        if tone in self.tones:
            return self.tones[tone]
        return self.theme["text"]

    def _fit(self, text, max_px):
        text = str(text or "")
        key = (text, int(max_px))
        cached = self._fit_cache.get(key)
        if cached is not None:
            return cached
        result = text
        if max_px > 0 and self._measure(self.font_text, text) > max_px:
            lo, hi = 0, len(text)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if self._measure(self.font_text, text[:mid].rstrip() + "…") <= max_px:
                    lo = mid
                else:
                    hi = mid - 1
            result = text[:lo].rstrip() + "…"
        if len(self._fit_cache) > 512:
            self._fit_cache.clear()
        self._fit_cache[key] = result
        return result

    def _set_label(self, label, text, tone="normal", max_px=None):
        fitted = self._fit(text, self._content_px if max_px is None else max_px)
        color = self._tone_color(tone)
        if label.cget("text") != fitted:
            label.configure(text=fitted)
        if label.cget("fg") != color:
            label.configure(fg=color)

    def _log(self, message):
        fn = getattr(self.ctx, "log", None)
        if not callable(fn):
            return
        try:
            fn(message)
        except Exception:  # a broken log sink must not break the window; nothing to report it to
            return

    def _log_once(self, message):
        if message in self._logged_once:
            return
        if len(self._logged_once) > 256:
            self._logged_once.clear()
        self._logged_once.add(message)
        self._log(f"[Profiles] {message}")

    def _notice(self, text, tone="muted"):
        self._notice_at = time.monotonic()
        self._notice_tone = tone
        self._notice_text = str(text or "")
        if self.alive():
            self._set_label(self.notice_label, text, tone, max_px=self._notice_px)

    def _report_error(self, prefix, exc):
        detail = _error_text(exc)
        self._notice(f"{prefix}: {detail}", "fail")
        self._log(f"[Profiles] {prefix}: {detail}")

    def _call_ctx_quiet(self, name, *args):
        fn = getattr(self.ctx, name, None)
        if not callable(fn):
            return False
        try:
            fn(*args)
            return True
        except Exception as exc:
            self._log_once(f"{name} не выполнен: {_error_text(exc)}")
            return False

    def _call_ctx(self, name, *args, error_prefix):
        fn = getattr(self.ctx, name, None)
        if not callable(fn):
            self._notice("Действие недоступно в этой сборке Nova", "warn")
            return False
        try:
            fn(*args)
        except Exception as exc:
            self._report_error(error_prefix, exc)
            return False
        return True

    def alive(self):
        if self._closed:
            return False
        try:
            return bool(self.win.winfo_exists())
        except tk.TclError:
            return False

    def is_visible(self):
        if not self.alive():
            return False
        try:
            return str(self.win.state()) == "normal"
        except tk.TclError:
            return False

    # -- async plumbing ------------------------------------------------------------------

    def _run_async(self, name, fn, on_done):
        """Run `fn` on a daemon thread; `on_done(result, error)` runs later on the Tk thread."""
        results = self._results

        def worker():
            try:
                outcome = (fn(), None)
            except Exception as exc:  # handed to on_done, which reports it
                outcome = (None, exc)
            results.put((on_done, outcome[0], outcome[1]))

        self._inflight += 1
        try:
            threading.Thread(target=worker, name=name, daemon=True).start()
        except RuntimeError as exc:
            self._inflight -= 1
            on_done(None, exc)
            return
        self._ensure_drain()

    def _ensure_drain(self):
        if self._drain_after_id is not None or self._closed:
            return
        try:
            self._drain_after_id = self.root.after(DRAIN_INTERVAL_MS, self._drain)
        except tk.TclError as exc:
            self._drain_after_id = None
            self._log_once(f"очередь окна профилей остановлена: {exc}")

    def _drain(self):
        self._drain_after_id = None
        if self._closed:
            return
        while True:
            try:
                on_done, result, error = self._results.get_nowait()
            except queue.Empty:
                break
            self._inflight = max(0, self._inflight - 1)
            try:
                on_done(result, error)
            except Exception as exc:
                self._report_error("Ошибка окна профилей", exc)
        if self._tests:
            self._expire_tests()
        if self._inflight > 0:
            self._ensure_drain()

    def _cancel_after(self, after_id):
        if after_id is None:
            return
        try:
            self.root.after_cancel(after_id)
        except tk.TclError:
            return  # the interpreter is already gone; nothing is left to cancel

    # -- show / hide ---------------------------------------------------------------------

    def show(self):
        if not self.alive():
            return
        self._render_all()
        self.refresh_now()
        try:
            self.win.update_idletasks()
        except tk.TclError:
            return
        self.place()
        try:
            self.win.deiconify()
        except tk.TclError:
            return
        if not self._title_bar_done:
            # The DWM frame exists only once the toplevel has been mapped (same as nova.pyw's log window).
            self._title_bar_done = apply_title_bar_theme(self.win, self.dark)
        if not self._maximize_box_dropped:
            self._maximize_box_dropped = drop_maximize_box(self.win)
        self._raise()
        self._schedule_tick()
        # Opening the window is the moment the owner wants to know which profile is worth choosing,
        # so the figures are measured then rather than on a timer nobody is watching. `force=False`
        # keeps a figure measured in the last few minutes, so re-opening costs nothing.
        self._sweep_current_tab()

    def hide(self):
        if self._preview is not None:
            self._preview.close()
        self._cancel_after(self._tick_after_id)
        self._tick_after_id = None
        if self.alive():
            try:
                self.win.withdraw()
            except tk.TclError:
                return

    def place(self):
        fn = getattr(self.ctx, "place_window", None)
        if callable(fn):
            try:
                fn(self.win)
                return
            except Exception as exc:
                self._log_once(f"place_window не выполнен: {_error_text(exc)}")
        try:
            x = self.root.winfo_rootx() + self.root.winfo_width() + 8
            y = self.root.winfo_rooty()
            self.win.geometry(f"+{max(0, x)}+{max(0, y)}")
        except tk.TclError as exc:
            self._log_once(f"окно профилей не удалось разместить: {exc}")

    def _raise(self):
        if not self.alive():
            return
        try:
            self.win.lift()
            self.win.attributes("-topmost", True)
            self.win.after(80, self._drop_topmost)
        except tk.TclError:
            return

    def _drop_topmost(self):
        if self.alive():
            try:
                self.win.attributes("-topmost", False)
            except tk.TclError:
                return

    def _on_destroy(self, event):
        if str(getattr(event, "widget", "")) != self._win_path:
            return
        self._closed = True
        self._cancel_after(self._tick_after_id)
        self._cancel_after(self._drain_after_id)
        self._cancel_after(self._latency_poll_after_id)
        self._tick_after_id = None
        self._drain_after_id = None
        self._latency_poll_after_id = None
        ref = getattr(self.root, _REGISTRY_ATTR, None)
        if isinstance(ref, dict) and ref.get("view") is self:
            ref["view"] = None

    def _on_map(self, event):
        if str(getattr(event, "widget", "")) != self._win_path or not self.alive():
            return
        self._schedule_tick()
        if not self._refresh_running:
            self.refresh_now()

    def _on_control_key(self, event):
        # keycode 86 is VK_V whatever the keyboard layout (a Russian layout sends Cyrillic_em).
        if getattr(event, "keycode", None) == 86 or str(getattr(event, "keysym", "")).lower() == "v":
            self._dispatch_action("import_clipboard")
            return "break"
        return None

    # -- refresh -------------------------------------------------------------------------

    def _schedule_tick(self):
        if self._tick_after_id is not None or self._closed:
            return
        try:
            self._tick_after_id = self.root.after(REFRESH_INTERVAL_MS, self._tick)
        except tk.TclError:
            self._tick_after_id = None

    def _tick(self):
        self._tick_after_id = None
        if not self.alive():
            return
        try:
            state = str(self.win.state())
        except tk.TclError:
            return
        if state == "withdrawn":
            return  # hide() owns this state; show() starts the loop again
        if state == "iconic":
            # Minimized: nothing to render, but keep the loop so a restore that skips <Map> still refreshes.
            self._schedule_tick()
            return
        self.refresh_now()
        self._check_refresh_stall()
        self._expire_tests()
        if self._notice_tone != "fail" and self._notice_at and time.monotonic() - self._notice_at > NOTICE_TTL_S:
            self._notice_at = 0.0
            self._notice_text = ""
            self._set_label(self.notice_label, "", "muted", max_px=self._notice_px)
        self._schedule_tick()

    def _check_refresh_stall(self):
        if not self._refresh_running or self._refresh_stall_reported:
            return
        if time.monotonic() - self._refresh_started <= REFRESH_STALL_S:
            return
        self._refresh_stall_reported = True
        self._notice("Nova не отвечает на запрос состояния — окно показывает прежние данные", "warn")
        self._log(f"[Profiles] Обновление окна профилей идёт дольше {int(REFRESH_STALL_S)} с "
                  "(чтение профилей или статусов Nova).")

    def refresh_now(self):
        """Re-read profiles, stats, selection and statuses on a worker; render on the Tk thread."""
        if not self.alive():
            return
        if self._refresh_running:
            self._refresh_again = True
            return
        self._refresh_running = True
        self._refresh_started = time.monotonic()
        started = time.time()
        self._run_async("NovaProfilesRefresh", lambda: self._collect_snapshot(started), self._on_snapshot)

    def _collect_snapshot(self, started):
        # Worker thread: no Tk calls here.
        snap = {"started_at": started, "loaded": True, "profiles": [], "stats": {},
                "selection": {"version": 1, "mode": "auto"},
                "effective": {"mode": "auto", "group": "", "profile_id": "", "reason": ""},
                "runtime": {}, "jobs": {}, "tor": None, "errors": [],
                "subs": [], "subs_loaded": False}
        # The getters run next to the file work, each on its own thread (see _StatusCall).
        calls = []
        for name, key, default in _STATUS_GETTERS:
            fn = getattr(self.ctx, name, None)
            if callable(fn):
                calls.append((self._status_calls[name], key, default, self._status_calls[name].start(fn)))
        module, error = _load_profiles_module()
        if module is None:
            snap["errors"].append(error)
        else:
            try:
                snap["profiles"] = module.list_profiles(self.base_dir)
                snap["stats"] = module.load_stats(self.base_dir)
                snap["selection"] = module.load_selection(self.base_dir)
                snap["effective"] = module.resolve_effective_selection(snap["selection"], snap["profiles"])
            except Exception as exc:
                snap["errors"].append(f"Не удалось прочитать профили: {_error_text(exc)}")
        subs_module, subs_error = _load_subs_module()
        if subs_module is None:
            # Not an error line in the window: a build without the module simply has no such tab,
            # and the tab itself says so when it is opened.
            self._log_once(subs_error)
        else:
            try:
                snap["subs"] = subs_module.load(self.base_dir)
                snap["subs_loaded"] = True
            except Exception as exc:
                snap["errors"].append(f"Не удалось прочитать подписки: {_error_text(exc)}")
        for call, key, default, (done, outcome, call_started) in calls:
            remaining = call_started + STATUS_GETTER_TIMEOUT_S - time.monotonic()
            if done.wait(max(0.0, remaining)):
                if "error" in outcome:
                    snap["errors"].append(f"{call.name} не ответил: {_error_text(outcome['error'])}")
                    continue
                value = outcome.get("value")
            else:
                last = call.last()
                snap["errors"].append(f"{call.name} не отвечает — показано последнее известное состояние")
                if last is None:
                    continue
                value = last[0]
            snap[key] = value if isinstance(value, dict) else default
        return snap

    def _on_snapshot(self, snap, error):
        self._refresh_running = False
        self._refresh_stall_reported = False
        if error is not None:
            self._report_error("Не удалось обновить окно профилей", error)
        elif self.alive():
            self._snapshot = snap
            errors = tuple(snap.get("errors") or ())
            for message in errors:
                self._log_once(message)
            # Only a new error takes over the notice line; a persistent one must not hide action results.
            if errors and errors != self._last_snapshot_errors:
                self._notice(errors[0], "fail")
            self._last_snapshot_errors = errors
            self._render_all()
        if self._refresh_again and self.alive():
            self._refresh_again = False
            self.refresh_now()

    # -- rendering -----------------------------------------------------------------------

    def _selection_pair(self):
        snap = self._snapshot
        selection = snap.get("selection") or {"version": 1, "mode": "auto"}
        effective = snap.get("effective") or {"mode": "auto", "group": "", "profile_id": "", "reason": ""}
        if self._optimistic_selection is not None:
            chosen, set_at = self._optimistic_selection
            if set_at >= _num(snap.get("started_at")):
                selection = chosen
                module = sys.modules.get("nova_profiles")
                if module is not None and snap.get("loaded"):
                    try:
                        effective = module.resolve_effective_selection(chosen, snap.get("profiles") or [])
                    except Exception as exc:
                        self._log_once(f"resolve_effective_selection: {_error_text(exc)}")
                        effective = self._naive_effective(chosen)
                else:
                    effective = self._naive_effective(chosen)
            else:
                self._optimistic_selection = None
        return selection, effective

    @staticmethod
    def _naive_effective(selection):
        mode = str(selection.get("mode") or "auto")
        profile = str(selection.get("profile") or "")
        group = str(selection.get("group") or profile.partition("/")[0])
        return {"mode": mode, "group": group if mode != "auto" else "", "profile_id": profile, "reason": ""}

    def _render_all(self):
        if not self.alive():
            return
        selection, effective = self._selection_pair()
        self._set_label(self.selection_label, format_selection_text(effective, selection), "muted")
        text, tone = format_runtime_text(self._snapshot.get("runtime"))
        self._set_label(self.runtime_label, text, "ok" if tone == "ok" else "normal")
        if self.current_tab == TAB_TOR:
            self._render_tor()
        elif self.current_tab == TAB_SUBS:
            self._render_subs()
            self._render_job_line()
        else:
            self._render_list()
            self._render_job_line()

    def _records_for(self, group):
        return [r for r in self._snapshot.get("profiles") or [] if isinstance(r, dict) and r.get("group") == group]

    def _is_fatal_fn(self):
        module = sys.modules.get("nova_profiles")
        fn = getattr(module, "is_fatal_issue", None) if module is not None else None
        return fn if callable(fn) else None

    def _live_profile_id(self):
        runtime = self._snapshot.get("runtime") or {}
        return str(runtime.get("profile_id") or ""), bool(runtime.get("connected"))

    def _reserve_profile_id(self):
        """The profile serving the reserve slot right now, "" when the reserve is Opera or Tor."""
        runtime = self._snapshot.get("runtime") or {}
        return str(runtime.get("secondary_profile") or "")

    def _render_list(self):
        group = self.current_tab
        records = self._records_for(group)
        self._set_label(self.list_header, format_list_header(group, records, self._snapshot.get("loaded")))
        live_id, connected = self._live_profile_id()
        reserve_id = self._reserve_profile_id()
        stats = self._snapshot.get("stats") or {}
        is_fatal = self._is_fatal_fn()
        rows = []
        for record in records:
            pid = record.get("id")
            probing = pid in self._latency_active
            outcome, outcome_tone = format_outcome(stats.get(pid), self._test_results.get(pid),
                                                   pid in self._tests, self._latency_of(pid, stats),
                                                   probing=probing)
            live = bool(live_id) and pid == live_id
            reserve = bool(reserve_id) and pid == reserve_id
            text = format_row_text(record, live=live, outcome=outcome, pad=self._marker_pad,
                                   is_fatal=is_fatal, reserve=reserve)
            if not record.get("valid", True):
                tone = "fail"
            elif probing:
                # The row being measured right now: the owner asked to see which ones those are,
                # and the sweep passes over a few hundred rows one screenful at a time.
                tone = "warn"
            elif live and connected:
                tone = "ok"
            elif reserve:
                tone = "ok" if self._snapshot.get("runtime", {}).get("secondary_up") else "muted"
            elif outcome_tone == "muted" or live:
                tone = "muted"
            else:
                tone = "normal"
            rows.append((pid, text, tone))
        self._fill_listbox(group, rows)

    def _latency_of(self, profile_id, stats):
        """This window's own measurement of a profile, or the one Nova recorded while connecting.

        Nova measures a VLESS group before it walks it (the «Auto» choice) and sweeps the rest once
        the tunnel is up, writing `rtt_ms` into profile-stats.json. Without this the window would
        show «не проверялся» for rows Nova had just measured, and the owner would have no way to
        see the latency the connect order was built from.
        """
        known = self._latency.get(profile_id)
        if known is not None:
            return known
        entry = stats.get(profile_id) if isinstance(stats, dict) else None
        if not isinstance(entry, dict):
            return None
        ms = entry.get("rtt_ms")
        at = _num(entry.get("rtt_at"))
        if at <= 0:
            return None  # never measured; `rtt_ms` None *with* a stamp means "did not answer"
        try:
            ms = None if ms is None else int(ms)
        except (TypeError, ValueError):
            return None
        return (ms, "", at)

    def _render_subs(self):
        """The «Подписки» tab, in the same listbox the profile tabs use."""
        records = list(self._snapshot.get("subs") or [])
        loaded = bool(self._snapshot.get("subs_loaded"))
        self._set_label(self.list_header, format_subs_header(records, loaded))
        running = bool((self._snapshot.get("jobs") or {}).get("subs", {}).get("running"))
        now = time.time()
        rows = []
        for record in records:
            sub_id = str(record.get("id") or "")
            text, tone = format_subscription_row(record, now=now, pad=self._marker_pad,
                                                 refreshing=running and record.get("enabled", True))
            rows.append((sub_id, text, tone))
        self._fill_listbox(TAB_SUBS, rows)

    def _fill_listbox(self, key, rows):
        """Draw `[(row_id, text, tone)]`, keeping the scroll position and the selection."""
        signature = (key, tuple(rows))
        lb = self.listbox
        wanted = self._selected_ids.get(key)
        if signature != self._row_signature:
            same = bool(self._row_signature) and self._row_signature[0] == key
            top = lb.yview()[0] if rows and same else 0.0
            lb.delete(0, "end")
            for index, (_row_id, text, tone) in enumerate(rows):
                lb.insert("end", text)
                lb.itemconfigure(index, fg=self._tone_color(tone))
            self._row_ids = [row_id for row_id, _text, _tone in rows]
            self._row_signature = signature
            if rows:
                lb.yview_moveto(top)
        if wanted in self._row_ids:
            index = self._row_ids.index(wanted)
            if tuple(lb.curselection()) != (index,):
                lb.selection_clear(0, "end")
                lb.selection_set(index)
            if self._reveal_ids.pop(key, None) == wanted:
                lb.see(index)

    def _selected_sub(self):
        """The subscription record the row selection points at, or None."""
        if self.current_tab != TAB_SUBS:
            return None
        selection = self.listbox.curselection()
        if not selection or selection[0] >= len(self._row_ids):
            return None
        wanted = self._row_ids[selection[0]]
        for record in self._snapshot.get("subs") or []:
            if str(record.get("id") or "") == wanted:
                return record
        return None

    def _render_job_line(self):
        kind = JOB_LINE_BY_GROUP.get(self.current_tab)
        if not kind:
            self._set_label(self.job_label, "", "muted")
            return
        jobs = self._snapshot.get("jobs") or {}
        text, tone = format_job_line(jobs.get(kind), kind, started_at=self._job_started.get(kind, 0.0),
                                     snapshot_started_at=_num(self._snapshot.get("started_at")))
        self._set_label(self.job_label, text, tone)

    def _tor_view(self):
        view = format_tor_status(self._snapshot.get("tor"))
        if self._tor_optimistic is not None:
            expected, set_at, set_mono = self._tor_optimistic
            connecting = expected == "starting"
            # nova.pyw applies the route in a worker, so the first snapshots after the click can still
            # show the old state. Keep the click's state until a later snapshot reflects it, or the grace ends.
            if connecting:
                reflected = view["engaged"] and view["state_key"] != "stopped"
            else:
                reflected = not view["engaged"]
            fresh = _num(self._snapshot.get("started_at")) > set_at
            if (fresh and reflected) or time.monotonic() - set_mono > JOB_START_GRACE_S:
                self._tor_optimistic = None
            else:
                view["pending"] = expected
                view["running"] = connecting
                view["engaged"] = connecting
                if connecting:
                    view["state"] = "запускается…"
                else:
                    view["state"] = "останавливается…"
                    view["progress"] = ""
        return view

    def _tor_entry_choice(self, view):
        """The entry the next «Подключить Tor» sends: a pill clicked here, else the stored setting."""
        if self._tor_entry in _TOR_ENTRY_LABELS:
            return self._tor_entry
        if view.get("entry_setting") in _TOR_ENTRY_LABELS:
            return view["entry_setting"]
        entry = view.get("entry")
        return entry if entry in _TOR_ENTRY_LABELS else "auto"

    def _render_tor(self):
        view = self._tor_view()
        entry = self._tor_entry_choice(view)
        for key, pill in self.tor_entry_pills.items():
            pill.set_selected(key == entry)
        state_tone = {"ready": "ok", "failed": "fail"}.get(view.get("state_key"), "normal")
        self._set_label(self.tor_labels["state"], view["state"], state_tone, max_px=self._tor_value_px)
        self._set_label(self.tor_labels["progress"], view["progress"],
                        "fail" if view.get("state_key") == "failed" else "normal", max_px=self._tor_value_px)
        self._set_label(self.tor_labels["bridges"], view["bridges"], "normal", max_px=self._tor_value_px)
        self._set_label(self.tor_labels["ports"], view["ports"], "muted", max_px=self._tor_value_px)
        self._set_label(self.tor_labels["error"], view["error"], "fail", max_px=self._tor_value_px)
        toggle = self.action_pills[TAB_TOR]["tor_toggle"]
        caption = TOR_DISCONNECT_LABEL if view["engaged"] else TOR_CONNECT_LABEL
        if getattr(toggle, "_nova_caption", None) != caption:
            set_pill_text(toggle, caption)
            toggle._nova_caption = caption

    # -- tabs and list selection ---------------------------------------------------------

    def select_tab(self, tab):
        if tab not in dict(TABS) or not self.alive():
            return
        self.current_tab = tab
        _registry(self.root)["last_tab"] = tab
        for key, pill in self.tab_pills.items():
            pill.set_selected(key == tab)
        if tab == TAB_TOR:
            self.tor_panel.tkraise()
        else:
            # The subscriptions tab borrows the list panel: its rows are subscriptions, not
            # profiles, and `_row_ids` then holds subscription ids — every reader of it goes
            # through `_selected_sub`/`_selected_record`, which check the tab first.
            self.list_panel.tkraise()
            self._row_signature = None
            self._reveal_ids[tab] = self._selected_ids.get(tab)
        self.action_frames[tab].tkraise()
        self._render_all()
        self._sweep_current_tab()

    def _sweep_current_tab(self):
        """Measure the visible group in the background, unless its figures are still fresh."""
        if self.current_tab not in PROFILE_GROUPS:
            return
        records = self._records_for(self.current_tab)
        if records:
            self._start_latency_sweep(records)

    def _on_list_select(self, _event=None):
        selection = self.listbox.curselection()
        if selection and selection[0] < len(self._row_ids):
            self._selected_ids[self.current_tab] = self._row_ids[selection[0]]

    def select_profile(self, profile_id):
        """Select a row by id (switches to its group tab)."""
        group = str(profile_id or "").partition("/")[0]
        if group not in PROFILE_GROUPS:
            return False
        self._selected_ids[group] = profile_id
        self._reveal_ids[group] = profile_id
        if self.current_tab != group:
            self.select_tab(group)
        else:
            self._render_list()
        return profile_id in self._row_ids

    def _selected_record(self):
        if self.current_tab not in PROFILE_GROUPS:
            return None
        selection = self.listbox.curselection()
        wanted = None
        if selection and selection[0] < len(self._row_ids):
            wanted = self._row_ids[selection[0]]
        if wanted is None:
            return None
        for record in self._records_for(self.current_tab):
            if record.get("id") == wanted:
                return record
        return None

    def _first_issue(self, record):
        fatal, warnings = _issue_split(record, self._is_fatal_fn())
        return fatal[0] if fatal else (warnings[0] if warnings else "профиль не читается")

    # -- actions -------------------------------------------------------------------------

    def _dispatch_action(self, action):
        handlers = {
            "connect": self._on_connect,
            "connect_group": self._on_connect_group,
            "test": self._on_test,
            "test_list": self._on_test_list,
            "refresh_profiles": self._on_refresh_profiles,
            "folder": self._on_folder,
            "generate_warp": lambda: self._on_job("warp"),
            "issue_proton": lambda: self._on_job("proton"),
            "register_masque": lambda: self._on_job("masque"),
            "reissue_warp": lambda: self._on_job("warp", force=True),
            "reissue_proton": lambda: self._on_job("proton", force=True),
            "reissue_masque": lambda: self._on_job("masque", force=True),
            "delete": self._on_delete,
            "rename": self._on_rename,
            "sub_add": self._on_sub_add,
            "sub_interval": self._on_sub_interval,
            "sub_toggle": self._on_sub_toggle,
            "sub_refresh": self._on_sub_refresh,
            "sub_delete": self._on_sub_delete,
            "import_file": self._on_import_file,
            "import_clipboard": self._on_import_clipboard,
            "tor_toggle": self._on_tor_toggle,
            "tor_new_identity": self._on_tor_new_identity,
            "tor_refresh_bridges": self._on_tor_refresh_bridges,
        }
        handler = handlers.get(action)
        if handler is None or not self.alive():
            return
        try:
            handler()
        except Exception as exc:
            self._report_error(f"«{ACTION_LABELS.get(action, action)}» не выполнено", exc)

    def _selection_already_live(self, selection):
        """True when `selection` is the current choice and Nova is connected through it."""
        wanted = _selection_key(selection)
        current, _effective = self._selection_pair()
        if wanted != _selection_key(current):
            return False
        live_id, connected = self._live_profile_id()
        if not connected:
            return False  # not connected: the click is a retry and goes through
        mode, group, profile = wanted
        if mode == "profile":
            return live_id == profile
        if mode == "group":
            return bool(live_id) and live_id.partition("/")[0] == group
        return True

    def _apply_selection(self, selection, notice):
        # nova.pyw tears the connection down and walks the attempt plan again on every apply_selection.
        if self._selection_already_live(selection):
            self._notice("Этот выбор уже действует — подключение не трогаем", "muted")
            self.refresh_now()
            return False
        if not self._call_ctx("apply_selection", dict(selection), error_prefix="Не удалось применить выбор"):
            return False
        self._optimistic_selection = (dict(selection), time.time())
        self._notice(notice, "ok")
        self._render_all()
        self.refresh_now()
        return True

    def _on_connect_group(self):
        group = self.current_tab
        if group not in PROFILE_GROUPS:
            self._notice("Откройте вкладку группы профилей, чтобы выбрать группу", "warn")
            return
        valid = [r for r in self._records_for(group) if r.get("valid", True)]
        if group in IMPORTED_GROUPS and not valid and self._snapshot.get("loaded"):
            # The issued groups fill themselves when they are chosen empty; an imported one cannot —
            # nothing will arrive unless the user imports it or a subscription brings it.
            self._notice(f"В группе «{group}» нет профилей — сначала импортируйте их", "warn")
            return
        note = (f"Группа «{group}» (Auto): Nova промерит первые узлы и начнёт с самого быстрого"
                if group in IMPORTED_GROUPS
                else f"Подключение к группе «{group}»: другие группы не используются")
        self._apply_selection({"version": 1, "mode": "group", "group": group}, note)

    def _on_connect(self):
        """«Подключить»: the selected node, or the whole group when no row is selected.

        The group connect used to be a button of its own («Подключить группу»), removed on the
        owner's word as unclear. It is not lost: clicking «Подключить» with nothing selected means
        "use this group", which is what the group pill menu on the main window calls «Auto» — Nova
        measures the head of the queue and starts with the node that answered fastest.
        """
        record = self._selected_record()
        if record is None:
            if self.current_tab in PROFILE_GROUPS:
                self._on_connect_group()
            else:
                self._notice("Выберите профиль в списке", "warn")
            return
        if not record.get("valid", True):
            self._notice(f"Профиль «{record.get('name')}» с ошибками: {self._first_issue(record)}", "fail")
            return
        self._apply_selection(
            {"version": 1, "mode": "profile", "group": record.get("group"), "profile": record.get("id")},
            f"Подключение к профилю «{record.get('name')}»")

    def _on_test(self):
        record = self._selected_record()
        if record is None:
            self._notice("Выберите профиль в списке", "warn")
            return
        pid = str(record.get("id"))
        if not record.get("valid", True):
            self._notice(f"Профиль «{record.get('name')}» с ошибками: {self._first_issue(record)}", "fail")
            return
        if pid in self._tests:
            self._notice(f"Проверка «{record.get('name')}» уже идёт", "muted")
            return
        fn = getattr(self.ctx, "test_profile", None)
        if not callable(fn):
            self._notice("Проверка недоступна в этой сборке Nova", "warn")
            return
        token = _TestToken(pid)
        results = self._results
        view = self

        def done_cb(result=None):
            # May run on any thread, possibly synchronously inside test_profile.
            if token.claim():
                results.put((lambda value, _err, tok=token: view._on_test_done(tok, value), result, None))

        self._tests[pid] = token
        self._inflight += 1
        try:
            fn(pid, done_cb)
        except Exception as exc:
            if token.claim():
                self._tests.pop(pid, None)
                self._inflight = max(0, self._inflight - 1)
                self._report_error(f"Проверка «{record.get('name')}» не запустилась", exc)
                self._render_list()
                return
            # done_cb already delivered a result before test_profile raised: keep the result,
            # still surface the exception.
            self._ensure_drain()
            self._report_error(f"Проверка «{record.get('name')}» завершилась с ошибкой", exc)
            return
        self._ensure_drain()
        self._notice(f"Проверка «{record.get('name')}»…", "muted")
        self._render_list()

    def _on_test_done(self, token, result):
        if self._tests.get(token.profile_id) is not token:
            return
        self._tests.pop(token.profile_id, None)
        normalized = _normalize_test_result(result)
        name = token.profile_id.partition("/")[2] or token.profile_id
        if normalized["skipped"]:
            # Not a verdict: the row keeps the profile's last real outcome.
            reason = f" — {normalized['message']}" if normalized["message"] else ""
            self._notice(f"«{name}»: не проверен{reason}", "warn")
            self._render_all()
            self.refresh_now()
            return
        self._test_results[token.profile_id] = (normalized, time.time())
        if normalized["ok"]:
            ms = f" {normalized['ms']} мс" if normalized["ms"] is not None else ""
            self._notice(f"«{name}»: ок{ms}", "ok")
        else:
            reason = f" — {normalized['message']}" if normalized["message"] else ""
            self._notice(f"«{name}»: сбой{reason}", "fail")
        self._render_all()
        self.refresh_now()

    def _expire_tests(self):
        now = time.monotonic()
        expired = False
        for pid, token in list(self._tests.items()):
            if now - token.started <= TEST_RESULT_TIMEOUT_S or not token.claim():
                continue
            expired = True
            self._tests.pop(pid, None)
            self._inflight = max(0, self._inflight - 1)
            self._test_results[pid] = ({"ok": False, "ms": None, "message": "нет ответа"}, time.time())
            self._notice(f"«{pid.partition('/')[2] or pid}»: проверка не ответила за "
                         f"{int(TEST_RESULT_TIMEOUT_S // 60)} мин", "fail")
            self._log(f"[Profiles] Проверка профиля «{pid}» не вернула результат за {int(TEST_RESULT_TIMEOUT_S)} с.")
        if expired and self.alive() and self.current_tab in PROFILE_GROUPS:
            self._render_list()

    def _on_folder(self):
        group = self.current_tab
        if group not in PROFILE_GROUPS:
            return
        if not callable(getattr(self.ctx, "open_folder", None)):
            self._notice("Открытие папки недоступно в этой сборке Nova", "warn")
            return
        path = os.path.join(self.base_dir, "profiles", group)

        def work():
            os.makedirs(path, exist_ok=True)
            return path

        def done(result, error):
            if error is not None:
                self._report_error(f"Не удалось создать папку «{group}»", error)
                return
            self._call_ctx("open_folder", result, error_prefix=f"Не удалось открыть папку «{group}»")

        self._run_async("NovaProfilesFolder", work, done)

    # -- subscriptions -------------------------------------------------------------------

    def _subs_write(self, what, work, notice):
        """Run a registry edit on a worker, then re-read the window. `work(module)` -> anything."""
        def run():
            return work(_require_subs_module())

        def done(_result, error):
            if error is not None:
                self._report_error(what, error)
                return
            self._notice(notice, "ok")
            self.refresh_now()

        self._run_async("NovaProfilesSubsEdit", run, done)

    def _on_sub_add(self):
        """«Добавить…»: a URL, then how often to re-download it.

        The kind (VLESS or AWG) is not asked: the body decides it, which is the whole point — the
        same link shape hands out `vless://` lines, wg-quick blocks and Amnezia `vpn://` keys, and
        making the owner classify their own link is making them guess.
        """
        url = self._ask_string("Новая подписка",
                               "Ссылка на подписку (http/https).\n\nПодойдёт список vless://, "
                               "конфиги WireGuard/AmneziaWG или ссылка панели — Nova сама "
                               "разберёт содержимое.")
        if not url:
            return
        url = url.strip()
        if not url.lower().startswith(("http://", "https://")):
            self._notice("Ссылка должна начинаться с http:// или https://", "warn")
            return
        name = (self._ask_string("Новая подписка",
                                 "Название (необязательно) — как показывать её в списке:") or "").strip()
        hours = self._ask_interval(DEFAULT_SUB_INTERVAL_HOURS)
        if hours is None:
            return
        base = self.base_dir

        def run():
            module = _require_subs_module()
            record, _records = module.add(base, url, name=name, interval_hours=hours,
                                          keep=SUB_DEFAULT_KEEP)
            if record is None:
                raise ValueError("ссылка не похожа на адрес подписки")
            return record

        def done(record, error):
            if error is not None:
                self._report_error("Подписка не добавлена", error)
                return
            record = record if isinstance(record, dict) else {}
            title = str(record.get("name") or record.get("id") or "подписка")
            self._selected_ids[TAB_SUBS] = str(record.get("id") or "")
            self._reveal_ids[TAB_SUBS] = self._selected_ids[TAB_SUBS]
            self._notice(f"Подписка «{title}» добавлена — загружаем профили…", "ok")
            self.refresh_now()
            # Downloading it at once is the point of adding it: a list that arrives in twelve hours
            # is not an answer to "I have just added this".
            self._call_ctx_quiet("refresh_subscriptions")

        self._run_async("NovaProfilesSubsAdd", run, done)

    def _on_sub_interval(self):
        record = self._selected_sub()
        if record is None:
            self._notice("Выберите подписку в списке", "warn")
            return
        hours = self._ask_interval(_num(record.get("interval_hours")) or DEFAULT_SUB_INTERVAL_HOURS,
                                   url=str(record.get("url") or ""))
        if hours is None:
            return
        sub_id = str(record.get("id") or "")
        title = str(record.get("name") or sub_id)
        base = self.base_dir
        self._subs_write("Период не изменён", lambda m: m.set_interval(base, sub_id, hours),
                         f"«{title}»: обновление каждые {hours} ч")

    def _on_sub_toggle(self):
        record = self._selected_sub()
        if record is None:
            self._notice("Выберите подписку в списке", "warn")
            return
        sub_id = str(record.get("id") or "")
        title = str(record.get("name") or sub_id)
        wanted = not bool(record.get("enabled", True))
        base = self.base_dir
        word = "включена" if wanted else "выключена"
        self._subs_write("Подписка не изменена", lambda m: m.set_enabled(base, sub_id, wanted),
                         f"«{title}»: {word}")

    def _on_sub_delete(self):
        record = self._selected_sub()
        if record is None:
            self._notice("Выберите подписку в списке", "warn")
            return
        sub_id = str(record.get("id") or "")
        title = str(record.get("name") or sub_id)
        count = int(_num(record.get("node_count")))
        question = (f"Удалить подписку «{title}»?\n\n"
                    "Уже скачанные из неё профили останутся на месте — их можно удалить "
                    "на вкладке группы.")
        if count:
            question += (f"\n\nСейчас она даёт {count} "
                         f"{_plural(count, 'профиль', 'профиля', 'профилей')}.")
        try:
            if not messagebox.askyesno("Подписки", question, parent=self.win):
                return
        except Exception:
            return
        base = self.base_dir
        self._subs_write("Подписка не удалена", lambda m: m.remove(base, sub_id),
                         f"Подписка «{title}» удалена")

    def _on_sub_refresh(self):
        if not callable(getattr(self.ctx, "refresh_subscriptions", None)):
            self._notice("Обновление подписок недоступно в этой сборке Nova", "warn")
            return
        jobs = self._snapshot.get("jobs") or {}
        if (jobs.get("subs") or {}).get("running"):
            self._notice("Обновление подписок уже идёт", "muted")
            return
        if self._call_ctx("refresh_subscriptions", error_prefix="Не удалось обновить подписки"):
            self._job_started["subs"] = time.time()
            self._notice("Обновляем подписки…", "muted")
            self._render_job_line()

    def _ask_string(self, title, prompt, initial=""):
        try:
            return simpledialog.askstring(title, prompt, parent=self.win, initialvalue=initial)
        except Exception as exc:
            self._report_error("Не удалось открыть диалог", exc)
            return None

    def _ask_interval(self, current, url=""):
        """Hours between refreshes; None when the owner cancelled or typed something else."""
        try:
            current = max(1, int(current or DEFAULT_SUB_INTERVAL_HOURS))
        except (TypeError, ValueError):
            current = DEFAULT_SUB_INTERVAL_HOURS
        choices = ", ".join(str(h) for h in SUBS_INTERVAL_CHOICES)
        prompt = ("Как часто обновлять подписку, в часах?\n\n"
                  f"Обычные значения: {choices}. По умолчанию 12: списки меняются медленно, "
                  "а запрос, который не нашёл изменений, не скачивает ничего.")
        if url:
            prompt += f"\n\nСсылка: {url}"
        answer = self._ask_string("Период обновления", prompt, initial=str(current))
        if answer is None:
            return None
        try:
            hours = int(str(answer).strip())
        except (TypeError, ValueError):
            self._notice("Период — это число часов", "warn")
            return None
        if hours < 1:
            self._notice("Период не может быть меньше часа", "warn")
            return None
        return min(hours, SUB_MAX_INTERVAL_HOURS)

    def _latency_targets(self, records, force=False):
        """`{profile_id: (host, ports)}` for the records worth measuring right now."""
        now = time.time()
        targets = {}
        for record in records or []:
            pid = str(record.get("id") or "")
            endpoint = str(record.get("endpoint") or "").strip()
            if not pid or not endpoint:
                continue
            if not force:
                known = self._latency.get(pid)
                if known is not None and (now - known[2]) < LATENCY_FRESH_S:
                    continue
            host, _sep, port = endpoint.rpartition(":")
            if endpoint.startswith("["):
                host, _sep, port = endpoint[1:].partition("]")
                port = port.lstrip(":")
            if not host:
                host, port = endpoint, ""
            ports = LATENCY_FALLBACK_PORTS
            if record.get("kind") == "vless" and port.isdigit():
                # The node's own port is the one its traffic uses, so it is also the honest probe.
                ports = (int(port),)
            targets[pid] = (host, ports)
        return targets

    def _start_latency_sweep(self, records, reason="", force=False, limit=LATENCY_SWEEP_LIMIT):
        """Measure the given records in the background. Returns how many were sent to be measured."""
        fn = getattr(self.ctx, "measure_latency", None)
        if not callable(fn) or self._latency_running:
            return 0
        targets = self._latency_targets(records, force=force)
        if not targets:
            return 0
        skipped = 0
        if len(targets) > limit:
            keep = [str(r.get("id") or "") for r in records][:len(records)]
            order = {pid: index for index, pid in enumerate(keep)}
            chosen = sorted(targets, key=lambda pid: order.get(pid, len(order)))[:limit]
            skipped = len(targets) - len(chosen)
            targets = {pid: targets[pid] for pid in chosen}
        view = self
        results = self._results

        def done_cb(measured=None):
            # May run on any thread: the result travels through the same queue as a «Проверить».
            results.put((lambda value, _err: view._on_latency_done(value), measured, None))

        events = self._latency_events

        def progress_cb(event, keys, result=None):
            # Also any thread, several times a second. Nothing here may touch Tk — a queue the Tk
            # thread polls is the only hand-off that works from here (the same rule as the results
            # queue: a worker calling root.after raises «main thread is not in main loop»).
            events.put((str(event or ""), tuple(str(k) for k in keys or ()),
                        getattr(result, "ms", None), str(getattr(result, "method", "") or "")))

        self._latency_running = True
        self._inflight += 1
        try:
            self._call_measure_latency(fn, dict(targets), done_cb, progress_cb)
        except Exception as exc:
            self._latency_running = False
            self._inflight = max(0, self._inflight - 1)
            self._report_error("Замер задержки не запустился", exc)
            return 0
        self._ensure_drain()
        self._schedule_latency_poll()
        if reason or skipped:
            tail = f"; остальные {skipped} не мерились — предел одного прохода" if skipped else ""
            self._log(f"[Profiles] Замер задержки ({reason or 'окно'}): {len(targets)} "
                      f"{_plural(len(targets), 'профиль', 'профиля', 'профилей')}{tail}.")
        return len(targets)

    @staticmethod
    def _call_measure_latency(fn, targets, done_cb, progress_cb):
        """Call the ctx getter, with the progress callback only when it takes one.

        An older nova.pyw (or a test double) has the two-argument signature, and the window has to
        keep working there — without the row highlight, which is the only thing that is lost. The
        signature is asked for rather than a TypeError caught: a TypeError raised *inside* a
        three-argument implementation would otherwise start the whole sweep a second time.
        """
        takes_progress = True
        try:
            takes_progress = len(inspect.signature(fn).parameters) >= 3
        except (TypeError, ValueError):
            pass  # a callable whose signature cannot be read: assume the current contract
        if takes_progress:
            return fn(targets, done_cb, progress_cb)
        return fn(targets, done_cb)

    def _schedule_latency_poll(self):
        if self._latency_poll_after_id is not None or self._closed:
            return
        try:
            self._latency_poll_after_id = self.root.after(LATENCY_POLL_MS, self._poll_latency_events)
        except tk.TclError:
            self._latency_poll_after_id = None

    def _poll_latency_events(self):
        """Tk thread: take everything the sweep has reported since the last turn and draw it once."""
        self._latency_poll_after_id = None
        if not self.alive():
            return
        changed = False
        while True:
            try:
                event, keys, ms, method = self._latency_events.get_nowait()
            except queue.Empty:
                break
            except ValueError:  # a payload of another shape: drop it rather than stop the poll
                continue
            changed = True
            if event == "start":
                self._latency_active.update(keys)
                continue
            self._latency_active.difference_update(keys)
            if ms is None and not method:
                continue  # abandoned: nothing was measured, so nothing is recorded
            try:
                value = int(ms) if ms is not None else None
            except (TypeError, ValueError):
                value = None
            now = time.time()
            for key in keys:
                self._latency[key] = (value, method, now)
        if self._latency_running:
            self._schedule_latency_poll()
        elif self._latency_active:
            # The sweep is over and something never reported its end: the rows must not stay marked.
            self._latency_active.clear()
            changed = True
        if changed and self.current_tab in PROFILE_GROUPS:
            self._render_list()

    def _on_latency_done(self, measured):
        self._latency_running = False
        self._latency_active.clear()
        self._latency_at = time.time()
        if not isinstance(measured, dict):
            self._render_all()
            return
        now = time.time()
        reachable = 0
        for pid, value in measured.items():
            ms, method = (None, "")
            if isinstance(value, (tuple, list)) and value:
                ms = value[0]
                method = str(value[1]) if len(value) > 1 else ""
            elif isinstance(value, (int, float)):
                ms = value
            try:
                ms = int(ms) if ms is not None else None
            except (TypeError, ValueError):
                ms = None
            self._latency[str(pid)] = (ms, method, now)
            if ms is not None:
                reachable += 1
        if measured:
            self._notice(f"Отвечают {reachable} из {len(measured)}", "ok" if reachable else "warn")
        self._render_all()

    def _on_test_list(self):
        """«Проверить список»: measure every profile of the tab, cheaply.

        Deliberately not «run «Проверить» on each row». A real check starts a tunnel and holds the
        profile's WireGuard key for up to ~25 s; fifty of them in a row would take twenty minutes
        and, worse, hammer one key — the nodes probed hardest stop answering it for 25 minutes and
        a finished handshake takes a live Proton tunnel over (G71, G72, N26). What this does is the
        latency sweep: one ICMP echo, a TCP connect if that is filtered, no keys and no handshakes.
        It says which nodes are reachable and how far they are, which is what ordering a list of a
        few hundred needs; «Проверить» stays the way to prove one of them carries traffic.
        """
        group = self.current_tab
        if group not in PROFILE_GROUPS:
            return
        records = self._records_for(group)
        if not records:
            self._notice(f"В группе «{group}» нет профилей", "warn")
            return
        if not callable(getattr(self.ctx, "measure_latency", None)):
            self._notice("Проверка списка недоступна в этой сборке Nova", "warn")
            return
        started = self._start_latency_sweep(records, reason="список", force=True,
                                            limit=LATENCY_LIST_LIMIT)
        if started:
            self._notice(f"Проверяем {started} {_plural(started, 'профиль', 'профиля', 'профилей')}… "
                         "— строка, которую меряем сейчас, подсвечена", "muted")
        elif self._latency_running:
            self._notice("Проверка списка уже идёт", "muted")
        else:
            self._notice("Свежие замеры уже есть — проверять нечего", "muted")

    def _on_refresh_profiles(self):
        """«Обновить профили»: whatever brings fresh profiles into this tab.

        On the issuing groups it is the issue job when the group is empty and a **re-issue** when it
        is not — which is the point of the button. Proton hands out a different subset of its free
        nodes every time it is asked, and a set issued weeks ago is largely dead by now: the owner
        reported connections failing on stale nodes, and re-issuing is the cure, not a last resort.
        A re-issue still asks its question first (`_confirm_reissue`), and it does not cut the live
        tunnel.

        On VLESS and Custom the fresh profiles come from the subscriptions, so it downloads those.
        """
        group = self.current_tab
        kind = JOB_KIND_BY_GROUP.get(group)
        if kind:
            self._on_job(kind, force=bool(self._records_for(group)))
            return
        if group in (GROUP_VLESS, GROUP_CUSTOM):
            if not callable(getattr(self.ctx, "refresh_subscriptions", None)):
                self._notice("Обновление подписок недоступно в этой сборке Nova", "warn")
                return
            if self._call_ctx("refresh_subscriptions", error_prefix="Не удалось обновить подписки"):
                self._notice("Обновляем подписки…", "muted")
            return
        self._notice("Для этой вкладки обновление не предусмотрено", "muted")

    _REISSUE_QUESTIONS = {
        "warp": "Перевыпустить свои профили WARP?\n\nБудет зарегистрировано новое устройство Cloudflare "
                "и найдены новые точки входа; прежние свои профили WARP заменятся.",
        "proton": "Перевыпустить профили Proton?\n\nБудет выпущен новый ключ и новый набор узлов; "
                  "прежние свои профили Proton заменятся.",
        "masque": "Перевыпустить профиль MASQUE?\n\nБудет зарегистрировано новое устройство; прежние свои "
                  "профили MASQUE удалятся (кроме того, через который идёт трафик прямо сейчас).",
    }

    def _confirm_reissue(self, kind):
        question = self._REISSUE_QUESTIONS.get(kind, "Перевыпустить профили?")
        question += "\n\nТекущее подключение не прервётся: новые профили применятся при следующем переключении."
        try:
            return bool(messagebox.askyesno("Перевыпуск профилей", question, parent=self.win))
        except Exception:
            return False

    def _on_job(self, kind, force=False):
        jobs = self._snapshot.get("jobs") or {}
        job = jobs.get(kind) if isinstance(jobs.get(kind), dict) else {}
        noun = _JOB_NOUNS.get(kind, kind)
        if job.get("running"):
            message = str(job.get("message") or "").strip()
            self._notice(f"{noun} уже идёт" + (f": {message}" if message else ""), "muted")
            return
        if force and not self._confirm_reissue(kind):
            return
        if kind == "warp":
            ok = self._call_ctx("generate_warp", bool(force), error_prefix="Генерация WARP не запустилась")
            notice = ("Перевыпуск своих профилей WARP запущен — новая регистрация и поиск точек входа"
                      if force else "Генерация своих профилей WARP запущена — это займёт пару минут")
        elif kind == "proton":
            ok = self._call_ctx("issue_proton", bool(force), error_prefix="Выпуск Proton не запустился")
            notice = "Перевыпуск профилей Proton запущен" if force else "Выпуск профилей Proton запущен"
        elif force:
            ok = self._call_ctx("register_masque", True, error_prefix="Регистрация MASQUE не запустилась")
            notice = "Перевыпуск профиля MASQUE запущен"
        else:
            ok = self._call_ctx("register_masque", error_prefix="Регистрация MASQUE не запустилась")
            notice = "Регистрация MASQUE запущена"
        if ok:
            self._job_started[kind] = time.time()
            self._notice(notice, "ok")
            self._render_job_line()
            self.refresh_now()

    def _on_delete(self):
        record = self._selected_record()
        if record is None:
            self._notice("Выберите профиль в списке", "warn")
            return
        if record.get("origin") == "bundled":
            self._notice("Встроенный профиль удалить нельзя: он приходит с установкой Nova", "fail")
            return
        pid = str(record.get("id"))
        if ("delete", pid) in self._busy:
            return
        name = record.get("name")
        text = f"Удалить профиль «{name}» из группы «{record.get('group')}»?\n\nФайл будет удалён без возможности восстановления."
        live_id, _connected = self._live_profile_id()
        if pid == live_id:
            text += "\nПрофиль сейчас используется: подключение останется до следующего переключения."
        _selection, effective = self._selection_pair()
        if effective.get("mode") == "profile" and effective.get("profile_id") == pid:
            text += f"\nОн выбран явно: после удаления Nova будет подключаться к группе «{record.get('group')}»."
        if not messagebox.askyesno("Удалить профиль", text, parent=self.win):
            return
        self._busy.add(("delete", pid))
        base = self.base_dir

        def work():
            return _require_profiles_module().delete_profile(base, pid)

        def done(_result, error):
            self._busy.discard(("delete", pid))
            if error is not None:
                if isinstance(error, ValueError):
                    self._notice(str(error), "fail")
                else:
                    self._report_error(f"Не удалось удалить «{name}»", error)
                return
            if self._selected_ids.get(record.get("group")) == pid:
                self._selected_ids.pop(record.get("group"), None)
            self._test_results.pop(pid, None)
            self._notice(f"Профиль «{name}» удалён", "ok")
            self._log(f"[Profiles] Профиль «{pid}» удалён из окна «Профили».")
            self.refresh_now()

        self._run_async("NovaProfilesDelete", work, done)

    def _on_rename(self):
        record = self._selected_record()
        if record is None:
            self._notice("Выберите профиль в списке", "warn")
            return
        if record.get("group") not in IMPORTED_GROUPS:
            groups = " и ".join(f"«{g}»" for g in IMPORTED_GROUPS)
            self._notice(f"Переименовать можно только профили групп {groups}", "warn")
            return
        pid = str(record.get("id"))
        old_name = str(record.get("name") or "")
        new_name = simpledialog.askstring("Переименовать профиль", "Новое имя профиля:", initialvalue=old_name,
                                          parent=self.win)
        if new_name is None:
            return
        new_name = new_name.strip()
        if not new_name or new_name == old_name:
            return
        if ("rename", pid) in self._busy:
            return
        self._busy.add(("rename", pid))
        base = self.base_dir

        def work():
            return _require_profiles_module().rename_profile(base, pid, new_name)

        def done(new_id, error):
            self._busy.discard(("rename", pid))
            if error is not None:
                if isinstance(error, ValueError):
                    self._notice(str(error), "fail")
                else:
                    self._report_error(f"Не удалось переименовать «{old_name}»", error)
                return
            new_id = str(new_id or "")
            if new_id:
                # The renamed profile's own group, not «Custom»: renaming a VLESS node used to move
                # the cursor on the Custom tab, where the node is not.
                target = str(record.get("group") or "") or new_id.partition("/")[0] or GROUP_CUSTOM
                self._selected_ids[target] = new_id
                self._reveal_ids[target] = new_id
            final = new_id.partition("/")[2] or new_name
            self._test_results.pop(pid, None)
            self._notice(f"Профиль переименован: «{old_name}» → «{final}»", "ok")
            self._log(f"[Profiles] Профиль «{pid}» переименован в «{new_id or final}».")
            self.refresh_now()

        self._run_async("NovaProfilesRename", work, done)

    # -- import --------------------------------------------------------------------------

    def _on_import_clipboard(self):
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            self._notice("В буфере обмена нет текста", "warn")
            return
        if not str(text or "").strip():
            self._notice("В буфере обмена нет текста", "warn")
            return
        self._start_import([("text", str(text))])

    def _on_import_file(self):
        paths = filedialog.askopenfilenames(parent=self.win, title="Импорт профилей", filetypes=IMPORT_FILETYPES)
        if isinstance(paths, str):
            paths = list(self.root.tk.splitlist(paths)) if paths else []
        paths = [str(p) for p in (paths or []) if str(p).strip()]
        if not paths:
            return
        if len(paths) > IMPORT_MAX_FILES:
            self._notice(f"Слишком много файлов: {len(paths)} (не больше {IMPORT_MAX_FILES} за раз)", "warn")
            return
        self._start_import([("file", p) for p in paths])

    def _start_import(self, sources):
        if "parse" in self._busy:
            self._notice("Разбор предыдущего импорта ещё идёт", "muted")
            return
        self._busy.add("parse")
        self._notice("Разбираем профили…", "muted")
        base = self.base_dir

        def work():
            return self._parse_import_sources(base, sources)

        def done(rows, error):
            self._busy.discard("parse")
            if error is not None:
                self._report_error("Импорт не разобран", error)
                return
            if not rows:
                self._notice("Профилей для импорта не найдено", "warn")
                return
            self._notice("", "muted")
            self.open_import_preview(rows)

        self._run_async("NovaProfilesImportParse", work, done)

    @staticmethod
    def _parse_import_sources(base_dir, sources):
        # Worker thread.
        module = _require_profiles_module()
        candidates = []
        for kind, value in sources:
            if kind == "file":
                name = os.path.basename(value) or value
                try:
                    with open(value, "rb") as handle:
                        data = handle.read(IMPORT_MAX_FILE_BYTES + 1)
                except OSError as exc:
                    candidates.append(_error_candidate(name, f"Не удалось прочитать файл: {_error_text(exc)}"))
                    continue
                if len(data) > IMPORT_MAX_FILE_BYTES:
                    candidates.append(_error_candidate(name, "Файл больше 4 МБ — это не профиль"))
                    continue
                found = module.parse_import_text(_decode_import_bytes(data), source_name=value)
                if not found:
                    candidates.append(_error_candidate(name, "В файле нет профилей AWG/WireGuard, vpn:// или MASQUE"))
                candidates.extend(found)
            else:
                found = module.parse_import_text(value, source_name="")
                if not found:
                    candidates.append(_error_candidate(
                        "Буфер обмена", "В тексте нет профилей AWG/WireGuard, ключа vpn:// или MASQUE JSON"))
                candidates.extend(found)
        existing = module.list_profiles(base_dir)
        return classify_import_candidates(candidates, existing, getattr(module, "is_fatal_issue", None))

    def open_import_preview(self, rows):
        if self._preview is not None:
            self._preview.close()
        self._preview = ImportPreview(self, rows)
        return self._preview

    def _import_chosen(self, preview, candidates):
        if "import" in self._busy:
            return
        self._busy.add("import")
        preview.set_busy(True)
        base = self.base_dir

        def work():
            return _require_profiles_module().import_candidates(base, candidates)

        def done(results, error):
            self._busy.discard("import")
            if error is not None:
                preview.set_busy(False)
                preview.set_status(f"Импорт не выполнен: {_error_text(error)}", "fail")
                self._log(f"[Profiles] Импорт не выполнен: {_error_text(error)}")
                return
            results = [r for r in (results or []) if isinstance(r, dict)]
            imported = [r for r in results if r.get("status") == "imported"]
            duplicates = [r for r in results if r.get("status") == "duplicate"]
            invalid = [r for r in results if r.get("status") == "invalid"]
            preview.close()
            parts = [f"импортировано {len(imported)}"]
            if duplicates:
                parts.append(f"уже были {len(duplicates)}")
            if invalid:
                first = (invalid[0].get("issues") or ["ошибка"])[0]
                parts.append(f"с ошибками {len(invalid)} ({first})")
            self._notice("Импорт: " + ", ".join(parts), "fail" if invalid and not imported else "ok")
            # The group is read from the id: a vless:// link lands in «VLESS» and a wg-quick block in
            # «Custom», and one import can do both. Saying «Импорт в Custom» would then be a lie and
            # the window would switch to the tab the profiles are not in.
            groups = []
            for row in imported:
                group = str(row.get("id") or "").partition("/")[0]
                if group and group not in groups:
                    groups.append(group)
            where = ", ".join("«%s»" % g for g in groups) or f"«{GROUP_CUSTOM}»"
            self._log(f"[Profiles] Импорт в {where}: новых {len(imported)}, уже были {len(duplicates)}, "
                      f"с ошибками {len(invalid)}.")
            if imported:
                first_id = str(imported[0].get("id") or "")
                target = first_id.partition("/")[0] or GROUP_CUSTOM
                if first_id:
                    self._selected_ids[target] = first_id
                    self._reveal_ids[target] = first_id
                if self.current_tab != target:
                    self.select_tab(target)
            self.refresh_now()

        self._run_async("NovaProfilesImport", work, done)

    # -- Tor -----------------------------------------------------------------------------

    def _on_tor_entry(self, entry):
        if entry not in _TOR_ENTRY_LABELS:
            return
        self._tor_entry = entry
        for key, pill in self.tor_entry_pills.items():
            pill.set_selected(key == entry)
        view = self._tor_view()
        if view["running"] and view.get("entry") and view["entry"] != entry:
            self._notice("Новый вход применится при следующем подключении Tor", "muted")

    def _on_tor_toggle(self):
        view = self._tor_view()
        if view.get("state_key") == "unavailable" and not callable(getattr(self.ctx, "tor_connect", None)):
            self._notice("Tor недоступен в этой сборке Nova", "warn")
            return
        pending = view.get("pending")
        if pending:
            # The previous click has not reached the status yet; a second call would restart the bootstrap.
            self._notice("Tor уже запускается — дождитесь состояния" if pending == "starting"
                         else "Tor уже отключается — дождитесь состояния", "muted")
            return
        if view["engaged"]:
            if self._call_ctx("tor_disconnect", error_prefix="Tor не отключился"):
                self._tor_optimistic = ("stopped", time.time(), time.monotonic())
                self._notice("Tor отключается, браузеры возвращаются в «Авто»", "muted")
        else:
            entry = self._tor_entry_choice(view)
            if self._call_ctx("tor_connect", entry, error_prefix="Tor не запустился"):
                self._tor_optimistic = ("starting", time.time(), time.monotonic())
                self._notice(f"Tor запускается (вход {_TOR_ENTRY_LABELS.get(entry, entry)}) — загрузка до пары минут",
                             "ok")
        self._render_tor()
        self.refresh_now()

    def _on_tor_new_identity(self):
        view = self._tor_view()
        if view.get("state_key") != "ready":
            self._notice("Новая цепочка доступна, когда Tor готов", "warn")
            return
        if self._call_ctx("tor_new_identity", error_prefix="Новая цепочка не запрошена"):
            self._notice("Запрошена новая цепочка Tor", "ok")
            self.refresh_now()

    def _on_tor_refresh_bridges(self):
        if self._call_ctx("tor_refresh_bridges", error_prefix="Мосты не обновлены"):
            self._notice("Обновляем мосты Tor…", "muted")
            self.refresh_now()


class ImportPreview:
    """Toplevel listing parsed candidates; checked rows (Listbox multi-selection) get imported."""

    def __init__(self, view, rows):
        self.view = view
        self.rows = list(rows)
        self.busy = False
        t = view.theme
        top = tk.Toplevel(view.win)
        top.withdraw()
        self.top = top
        top.title("Импорт профилей")
        top.resizable(False, False)
        top.configure(bg=t["bg"], bd=1, highlightthickness=1, highlightbackground=t["border"])
        view._call_ctx_quiet("apply_window_icon", top)
        try:
            top.transient(view.win)
        except tk.TclError as exc:
            view._log_once(f"окно импорта без владельца: {exc}")
        top.protocol("WM_DELETE_WINDOW", self.close)
        top.bind("<Escape>", lambda _e: self.close())

        outer = tk.Frame(top, bg=t["bg"], padx=10, pady=10)
        outer.pack(fill="both", expand=True)
        total = len(self.rows)
        new = sum(1 for r in self.rows if r["status"] == "new")
        tk.Label(outer, text=f"Найдено профилей: {total} · новых: {new}", font=view.font_title, bg=t["bg"],
                 fg=t["text"], anchor="w").pack(fill="x")
        # The group follows the kind, not the button: a vless:// link goes to «VLESS» and a
        # wg-quick block to «Custom», and one paste can carry both.
        groups = []
        for row in self.rows:
            candidate = row.get("candidate") if isinstance(row, dict) else None
            group = GROUP_VLESS if (candidate or {}).get("kind") == KIND_VLESS else GROUP_CUSTOM
            if group not in groups:
                groups.append(group)
        where = " и ".join(f"«{g}»" for g in groups) or f"«{GROUP_CUSTOM}»"
        tk.Label(outer, text=f"Отмеченные попадут в {'группы' if len(groups) > 1 else 'группу'} {where}. "
                             "Режим подключения не меняется.",
                 font=view.font_text, bg=t["bg"], fg=t["muted"], anchor="w").pack(fill="x", pady=(2, 6))

        box = tk.Frame(outer, bg=t["panel"], highlightthickness=1, highlightbackground=t["border"], bd=0)
        box.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(
            box, height=min(12, max(4, total)), width=72, activestyle="none", exportselection=False,
            selectmode="multiple", bg=t["panel"], fg=t["text"], selectbackground=t["pill_on_bg"],
            selectforeground=t["pill_on_fg"], highlightthickness=0, relief="flat", bd=0, font=view.font_text,
        )
        scrollbar = ThemedScrollbar(box, self.listbox.yview, t, view.dark)
        self.listbox.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y", pady=2)
        self.listbox.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=4)

        self._checked = {i for i, row in enumerate(self.rows) if row["status"] == "new"}
        for index in range(total):
            self.listbox.insert("end", self._row_text(index))
            self.listbox.itemconfigure(index, fg=self._row_color(index))
            if index in self._checked:
                self.listbox.selection_set(index)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)

        self.status_label = tk.Label(outer, text="", anchor="w", bg=t["bg"], fg=t["muted"], font=view.font_text)
        self.status_label.pack(fill="x", pady=(6, 0))

        buttons = tk.Frame(outer, bg=t["bg"])
        buttons.pack(fill="x", pady=(8, 0))
        self.cancel_pill = view._make_pill(buttons, "Отмена", self.close, width=74)
        self.cancel_pill.pack(side="right")
        width = max(view._pill_width("Импортировать 999"), 110)
        self.import_pill = view._make_pill(buttons, self._button_text(), self._on_import, width=width)
        self.import_pill.set_selected(True)
        self.import_pill.pack(side="right", padx=(0, 6))

        top.update_idletasks()
        self._place()
        top.deiconify()
        apply_title_bar_theme(top, view.dark)
        try:
            top.lift()
            self.listbox.focus_set()
        except tk.TclError:
            return

    def alive(self):
        try:
            return bool(self.top.winfo_exists())
        except tk.TclError:
            return False

    def _place(self):
        try:
            owner = self.view.win
            width = self.top.winfo_reqwidth()
            x = owner.winfo_rootx() + max(0, (owner.winfo_width() - width) // 2)
            y = owner.winfo_rooty() + 60
            self.top.geometry(f"+{max(0, x)}+{max(0, y)}")
        except tk.TclError as exc:
            self.view._log_once(f"окно импорта не удалось разместить: {exc}")

    def importable(self, index):
        return 0 <= index < len(self.rows) and self.rows[index]["status"] == "new"

    def checked_indices(self):
        return sorted(self._checked)

    def _row_text(self, index):
        row = self.rows[index]
        candidate = row["candidate"]
        box = "☑" if index in self._checked else "☐"
        parts = [str(candidate.get("name") or "Профиль")]
        endpoint = str(candidate.get("endpoint") or "").strip()
        if endpoint and endpoint != parts[0]:
            parts.append(endpoint)
        parts.append(row["status_text"])
        return f"{box}  " + "  ·  ".join(parts)

    def _row_color(self, index):
        status = self.rows[index]["status"]
        if status == "invalid":
            return self.view._tone_color("fail")
        if status == "duplicate":
            return self.view._tone_color("muted")
        return self.view.theme["text"]

    def _button_text(self):
        return f"Импортировать {len(self._checked)}"

    def _rewrite_row(self, index):
        top = self.listbox.yview()[0]
        self.listbox.delete(index)
        self.listbox.insert(index, self._row_text(index))
        self.listbox.itemconfigure(index, fg=self._row_color(index))
        if index in self._checked:
            self.listbox.selection_set(index)
        self.listbox.yview_moveto(top)

    def set_checked(self, indices):
        """Replace the checked set (non-importable rows are ignored)."""
        wanted = {i for i in indices if self.importable(i)}
        changed = wanted ^ self._checked
        self._checked = wanted
        for index in range(len(self.rows)):
            if index in wanted:
                self.listbox.selection_set(index)
            else:
                self.listbox.selection_clear(index)
        for index in sorted(changed):
            self._rewrite_row(index)
        set_pill_text(self.import_pill, self._button_text())

    def _on_select(self, _event=None):
        current = {int(i) for i in self.listbox.curselection()}
        if self.busy:
            current = set(self._checked)
        self.set_checked(current)

    def _on_import(self):
        if self.busy or not self.alive():
            return
        if not self._checked:
            self.set_status("Отметьте хотя бы один новый профиль", "warn")
            return
        chosen = [self.rows[i]["candidate"] for i in sorted(self._checked)]
        self.view._import_chosen(self, chosen)

    def set_busy(self, busy):
        self.busy = bool(busy)
        if busy:
            self.set_status("Импорт…", "muted")

    def set_status(self, text, tone="muted"):
        if not self.alive():
            return
        self.status_label.configure(text=self.view._fit(text, max(200, self.listbox.winfo_reqwidth())),
                                    fg=self.view._tone_color(tone))

    def close(self):
        if self.view._preview is self:
            self.view._preview = None
        if self.alive():
            try:
                self.top.destroy()
            except tk.TclError:
                return


# --------------------------------------------------------------------------------------------
# Entry points


def _bind_root_alignment(root, ref):
    if ref.get("configure_bound"):
        return

    def on_configure(event):
        if getattr(event, "widget", None) is not root:
            return
        view = ref.get("view")
        if view is None or ref.get("align_pending") or not view.is_visible():
            return
        ref["align_pending"] = True

        def align():
            ref["align_pending"] = False
            if view.is_visible():
                view.place()

        try:
            root.after_idle(align)
        except tk.TclError:
            ref["align_pending"] = False

    root.bind("<Configure>", on_configure, add="+")
    ref["configure_bound"] = True


def get_profiles_window(ctx):
    """The live window for ctx.root, or None."""
    ref = _registry(ctx.root)
    view = ref.get("view")
    return view if view is not None and view.alive() else None


def open_profiles_window(ctx):
    """Show the «Профили» window (built once per ctx.root, re-shown afterwards). Tk thread only."""
    root = getattr(ctx, "root", None)
    if root is None:
        raise ValueError("ctx.root is required")
    ref = _registry(root)
    view = ref.get("view")
    if view is not None and view.alive():
        view.ctx = ctx
        view.base_dir = os.fspath(getattr(ctx, "base_dir", "") or view.base_dir)
        view.show()
        return view
    view = ProfilesWindow(ctx)
    ref["view"] = view
    _bind_root_alignment(root, ref)
    view.show()
    return view


def toggle_profiles_window(ctx):
    """Hide the window when it is visible, show it otherwise; repeated clicks within 0.18 s are ignored."""
    root = getattr(ctx, "root", None)
    if root is None:
        raise ValueError("ctx.root is required")
    ref = _registry(root)
    now = time.monotonic()
    if now - float(ref.get("last_toggle_ts") or 0.0) < TOGGLE_DEBOUNCE_S:
        return ref.get("view")
    ref["last_toggle_ts"] = now
    view = ref.get("view")
    if view is not None and view.alive() and view.is_visible():
        view.hide()
        return view
    return open_profiles_window(ctx)


def close_profiles_window(ctx):
    """Withdraw the window if it exists (e.g. from nova.pyw on_closing)."""
    root = getattr(ctx, "root", None)
    if root is None:
        return False
    view = _registry(root).get("view")
    if view is None or not view.alive():
        return False
    view.hide()
    return True
