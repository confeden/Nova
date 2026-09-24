import json
import os


# IDE и CLI сняты с перехвата: они существовали только ради доступа к нейросетям
# внутри редакторов и терминалов, а эту задачу решает разблокировка AI через
# NRPT — подмена DNS, которой перехват трафика не нужен.
ROUTING_GROUP_ALIASES = {
    "browser": "browser",
    "telegram": "telegram",
    "whatsapp": "whatsapp",
    "discord": "discord",
    "games": "games",
    "poe": "games",
    # Без этих двух `_get_app_route_mode` не находил ключ и откатывался на
    # "browser": строка OBS в настройках управляла чужим режимом, а поток
    # GamesDirect — тоже. Заметно стало только после того, как файл настроек
    # вообще начал находиться.
    "obs": "obs",
    "games-steam-direct": "games",
}
ROUTING_MODE_VALUES = {"auto", "warp", "opera", "direct"}


def _safe_bool(value):
    try:
        return bool(value)
    except:
        return False


def _routing_settings_path():
    """Найти файл настроек там, где его действительно пишет nova.pyw.

    Здесь стояло `dirname(__file__)/temp/routing_settings.json`, то есть
    `resources/temp/...` — каталога с таким именем нет ни в исходниках, ни в
    установленной программе. Файл не находился НИКОГДА: настройки читались как
    {}, режим любого приложения выходил "auto", и `_app_redirect_enabled` в
    NovaDivert не возвращал False ни разу. Симптом был виден годами и выглядел
    как «настройка не работает»: в routing_settings.json стоит "ide": "direct",
    а трафик всё равно перехватывается на 17870.

    Канон — `<base>/temp/routing_settings.json`, рядом лежит устаревшая копия
    `<base>/routing_settings.json` (nova.pyw пишет обе). Каталог `<base>`
    считается от этого модуля: из исходников он в `<repo>/resources/`, в
    установленной программе — в `{app}\\resources\\`, и в обоих случаях
    родительский каталог и есть нужный. Кандидаты перебираются, потому что
    помощники запускаются из разных мест, и молчаливый промах здесь стоит
    ровно того, что уже случилось.
    """
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        roots = (os.path.dirname(here), here, os.path.dirname(os.path.dirname(here)))
        for root in roots:
            if not root:
                continue
            for candidate in (
                os.path.join(root, "temp", "routing_settings.json"),
                os.path.join(root, "routing_settings.json"),
            ):
                if os.path.exists(candidate):
                    return candidate
        return ""
    except:
        return ""


def _load_routing_settings():
    path = _routing_settings_path()
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return payload if isinstance(payload, dict) else {}
    except:
        return {}


def _normalize_mode(value, default="auto"):
    mode = str(value or "").strip().lower()
    if mode not in ROUTING_MODE_VALUES:
        mode = str(default or "auto").strip().lower()
    if mode not in ROUTING_MODE_VALUES:
        mode = "auto"
    return mode


def _browser_mode_from_legacy_pac(payload):
    pac = payload.get("pac") if isinstance(payload, dict) else {}
    if not isinstance(pac, dict):
        return "auto"
    mode = str(pac.get("mode") or "").strip().lower()
    full_target = str(pac.get("full_target") or "").strip().lower()
    if mode == "off":
        return "direct"
    if mode == "full":
        return _normalize_mode(full_target or "warp", "warp")
    return "auto"


# Привязка к слоту VPN. «Осн.»/«Доп.» в строке Telegram — обещание, а не
# предпочтение: выбранный слот и есть весь маршрут, соседний егресс не берётся
# даже когда выбранный лежит, и WSS через чужой Worker не берётся тем более.
# Остальные группы (Discord, WhatsApp, OBS, Games) остались на прежнем
# поведении, где режим лишь переставляет порядок попыток.
PINNED_EGRESS_BY_MODE = {"warp": "warp-socks", "opera": "opera-http"}
PINNED_EGRESS_APPS = {"telegram"}


def pinned_egress_label(app_key):
    """Метка единственного разрешённого егресса, или пустая строка."""
    app = ROUTING_GROUP_ALIASES.get(str(app_key or "").strip().lower(), "browser")
    if app not in PINNED_EGRESS_APPS:
        return ""
    return PINNED_EGRESS_BY_MODE.get(_get_app_route_mode(app), "")


def _get_app_route_mode(app_key):
    payload = _load_routing_settings()
    key = ROUTING_GROUP_ALIASES.get(str(app_key or "").strip().lower(), "browser")
    routes = payload.get("routes") if isinstance(payload, dict) else {}
    if not isinstance(routes, dict):
        routes = {}
    if routes:
        mode = _normalize_mode(routes.get(key), "auto")
        if key != "browser" and mode == "auto":
            mode = _normalize_mode(routes.get("browser"), "auto")
        return mode
    legacy_apps = payload.get("apps") if isinstance(payload, dict) else {}
    if isinstance(legacy_apps, dict):
        mode = _normalize_mode(legacy_apps.get(key), "auto")
        if key != "browser" and mode == "auto":
            return _browser_mode_from_legacy_pac(payload)
        return mode
    if key == "browser":
        return _browser_mode_from_legacy_pac(payload)
    return _browser_mode_from_legacy_pac(payload) if key != "browser" else "auto"


def _reorder_labels(mode, default_labels):
    labels = [str(item or "").strip().lower() for item in list(default_labels or []) if str(item or "").strip()]
    if mode == "warp":
        preferred = ["warp-socks", "opera-http", "direct"]
    elif mode == "opera":
        preferred = ["opera-http", "warp-socks", "direct"]
    elif mode == "direct":
        preferred = ["direct", "warp-socks", "opera-http"]
    else:
        preferred = list(labels)
    rendered = []
    seen = set()
    for label in preferred + labels:
        if label in labels and label not in seen:
            seen.add(label)
            rendered.append(label)
    return rendered


def build_public_tcp_upstream_attempts(
    *,
    warp_manager=None,
    opera_proxy_manager=None,
    include_direct=True,
    warp_timeout=1.2,
    opera_timeout=1.0,
    secondary=None,
):
    """`secondary` = {"kind", "ready", "http_port"} names the reserve slot.

    `kind` is `opera`, `tor` or `profile` (an imported profile Nova runs itself). Opera is the one
    this function probes; the other two are managed elsewhere and arrive with their own `ready` and
    their own port. The label stays `opera-http` for all three, because every ordering rule knows
    the secondary slot by it — `egress` is what says which tenant it really is.
    """
    attempts = []
    secondary = secondary if isinstance(secondary, dict) else None
    secondary_kind = str((secondary or {}).get("kind") or "").strip().lower()
    secondary_is_tor = secondary_kind == "tor"
    # Anything that is not Opera is a tenant with its own port and its own liveness: its attempt is
    # built from what the caller passed, never probed here.
    secondary_is_managed = bool(secondary) and secondary_kind in ("tor", "profile")

    try:
        if warp_manager is not None:
            warp_port = int(getattr(warp_manager, "port", 1370) or 1370)
            warp_connected = bool(getattr(warp_manager, "is_connected", False))
            tester = getattr(warp_manager, "_test_socks5_internet", None)
            warp_ok = False
            if warp_connected and callable(tester):
                try:
                    warp_ok = bool(tester(warp_port, timeout=float(warp_timeout)))
                except:
                    warp_ok = False
            if warp_ok:
                attempts.append(
                    {
                        "kind": "socks5",
                        "host": "127.0.0.1",
                        "port": warp_port,
                        "label": "warp-socks",
                        "timeout": float(warp_timeout),
                    }
                )
    except:
        pass

    if secondary_is_managed:
        if secondary.get("ready"):
            # Tor builds a circuit before CONNECT answers (seconds); an own profile dials its node
            # abroad per flow, which is slower than Opera's local hop and faster than Tor.
            default_port = 1378 if secondary_is_tor else 1380
            floor = 10.0 if secondary_is_tor else 6.0
            attempts.append(
                {
                    "kind": "http",
                    "host": "127.0.0.1",
                    "port": int(secondary.get("http_port") or default_port),
                    "label": "opera-http",
                    "egress": secondary_kind,
                    "timeout": max(float(opera_timeout), floor),
                }
            )
    try:
        if opera_proxy_manager is not None and not secondary_is_managed:
            port_open = False
            proxy_ok = False
            try:
                port_open = _safe_bool(getattr(opera_proxy_manager, "_is_port_open_local", lambda: False)())
            except:
                port_open = False
            if port_open:
                try:
                    proxy_ok = _safe_bool(
                        getattr(opera_proxy_manager, "_is_http_proxy_alive", lambda timeout=1.0: False)(
                            timeout=float(opera_timeout)
                        )
                    )
                except:
                    proxy_ok = False
            if port_open and proxy_ok:
                attempts.append(
                    {
                        "kind": "http",
                        "host": "127.0.0.1",
                        "port": int(getattr(opera_proxy_manager, "port", 1371) or 1371),
                        "label": "opera-http",
                        "timeout": float(opera_timeout),
                    }
                )
    except:
        pass

    if include_direct:
        attempts.append({"kind": "direct", "label": "direct"})

    return attempts


def build_public_app_transport_plan(
    app_key,
    *,
    warp_manager=None,
    opera_proxy_manager=None,
    secondary=None,
):
    route_mode = _get_app_route_mode(app_key)
    normalized_app = ROUTING_GROUP_ALIASES.get(str(app_key or "").strip().lower(), "browser")
    include_direct = True
    if normalized_app == "telegram" and route_mode != "direct":
        include_direct = False
    attempts = build_public_tcp_upstream_attempts(
        warp_manager=warp_manager,
        opera_proxy_manager=opera_proxy_manager,
        include_direct=include_direct,
        secondary=secondary,
    )
    by_label = {
        str((attempt or {}).get("label") or (attempt or {}).get("kind") or "").strip().lower(): attempt
        for attempt in attempts
        if isinstance(attempt, dict)
    }
    ordered_labels = _reorder_labels(
        route_mode,
        [str((attempt or {}).get("label") or (attempt or {}).get("kind") or "").strip().lower() for attempt in attempts],
    )
    ordered_attempts = [dict(by_label[label]) for label in ordered_labels if label in by_label]
    if ordered_attempts:
        attempts = ordered_attempts
    pin = pinned_egress_label(normalized_app)
    if pin:
        # План — это то, что Nova показывает о себе в панели состояния. Если он
        # перечисляет три егресса, а помощники ходят в один, расходится не план
        # с кодом, а картинка с реальностью — и разбирать жалобу придётся по ней.
        attempts = [dict(by_label[pin])] if pin in by_label else []
    return {
        "app": normalized_app,
        "tcp_attempts": attempts,
        "tcp_chain": [str(item.get("label") or item.get("kind") or "unknown") for item in attempts],
    }
