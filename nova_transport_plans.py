def _safe_bool(value):
    try:
        return bool(value)
    except:
        return False


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
    return {
        "app": str(app_key or "").strip().lower(),
        "tcp_attempts": attempts,
        "tcp_chain": [str(item.get("label") or item.get("kind") or "unknown") for item in attempts],
    }
