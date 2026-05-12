import json
import os


ROUTING_GROUP_ALIASES = {
    "browser": "browser",
    "telegram": "telegram",
    "whatsapp": "whatsapp",
    "discord": "discord",
    "ide": "ide",
    "cli": "cli",
    "opencode": "ide",
}
ROUTING_MODE_VALUES = {"auto", "warp", "opera", "direct"}


def _safe_bool(value):
    try:
        return bool(value)
    except:
        return False


def _routing_settings_path():
    try:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp", "routing_settings.json")
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
        legacy_key = "opencode" if key == "ide" else key
        mode = _normalize_mode(legacy_apps.get(legacy_key), "auto")
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
):
    attempts = []

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

    try:
        if opera_proxy_manager is not None:
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
):
    attempts = build_public_tcp_upstream_attempts(
        warp_manager=warp_manager,
        opera_proxy_manager=opera_proxy_manager,
        include_direct=True,
    )
    by_label = {
        str((attempt or {}).get("label") or (attempt or {}).get("kind") or "").strip().lower(): attempt
        for attempt in attempts
        if isinstance(attempt, dict)
    }
    route_mode = _get_app_route_mode(app_key)
    ordered_labels = _reorder_labels(
        route_mode,
        [str((attempt or {}).get("label") or (attempt or {}).get("kind") or "").strip().lower() for attempt in attempts],
    )
    ordered_attempts = [dict(by_label[label]) for label in ordered_labels if label in by_label]
    if ordered_attempts:
        attempts = ordered_attempts
    return {
        "app": ROUTING_GROUP_ALIASES.get(str(app_key or "").strip().lower(), "browser"),
        "tcp_attempts": attempts,
        "tcp_chain": [str(item.get("label") or item.get("kind") or "unknown") for item in attempts],
    }
