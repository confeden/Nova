import json
import os
import sys
from dataclasses import asdict, dataclass


BACKEND_AUTO = "auto"
BACKEND_CURRENT = "current"
BACKEND_PUBLIC_HYBRID = "public-hybrid"
BACKEND_WINDIVERT_HYBRID = "windivert-hybrid"


@dataclass(frozen=True)
class AppTransportDecision:
    key: str
    tcp_backend: str
    tcp_outbound: str
    udp_backend: str
    udp_outbound: str
    include_routing_tcp_rules: bool
    include_routing_udp_rules: bool
    keep_tun_tcp_catchall: bool


def _backend_aliases():
    return {
        "auto": BACKEND_AUTO,
        "current": BACKEND_CURRENT,
        "classic": BACKEND_CURRENT,
        "singbox": BACKEND_CURRENT,
        "public": BACKEND_PUBLIC_HYBRID,
        "public-hybrid": BACKEND_PUBLIC_HYBRID,
        "hybrid": BACKEND_PUBLIC_HYBRID,
        "relay": BACKEND_PUBLIC_HYBRID,
        "windivert": BACKEND_WINDIVERT_HYBRID,
        "windivert-hybrid": BACKEND_WINDIVERT_HYBRID,
        "signed-hybrid": BACKEND_WINDIVERT_HYBRID,
        "divert": BACKEND_WINDIVERT_HYBRID,
    }


def _argv_backend_override(argv=None):
    argv = list(argv or sys.argv or [])
    for index, arg in enumerate(argv):
        text = str(arg or "").strip()
        if not text:
            continue
        lower = text.lower()
        if lower.startswith("--routing-backend="):
            return text.split("=", 1)[1].strip()
        if lower.startswith("--backend="):
            return text.split("=", 1)[1].strip()
        if lower in {"--routing-backend", "--backend"}:
            if index + 1 < len(argv):
                return str(argv[index + 1] or "").strip()
    return ""


def get_selected_routing_backend_info():
    aliases = _backend_aliases()
    cli_raw = str(_argv_backend_override() or "").strip().lower()
    if cli_raw:
        return {
            "mode": aliases.get(cli_raw, BACKEND_AUTO),
            "source": "cli",
            "raw": cli_raw,
        }
    env_raw = str(os.environ.get("NOVA_ROUTING_BACKEND", BACKEND_AUTO) or "").strip().lower()
    return {
        "mode": aliases.get(env_raw, BACKEND_AUTO),
        "source": "env",
        "raw": env_raw,
    }


def get_selected_routing_backend_mode():
    return str((get_selected_routing_backend_info() or {}).get("mode") or BACKEND_AUTO)


def is_auto_routing_backend(mode):
    return str(mode or "").strip().lower() == BACKEND_AUTO


def is_public_hybrid_backend(mode):
    return str(mode or "").strip().lower() == BACKEND_PUBLIC_HYBRID


def is_windivert_hybrid_backend(mode):
    return str(mode or "").strip().lower() == BACKEND_WINDIVERT_HYBRID


def _env_bool(name, default=False):
    raw = os.environ.get(str(name), None)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def wants_windivert_hybrid_backend(mode):
    normalized = str(mode or "").strip().lower()
    return normalized in {BACKEND_AUTO, BACKEND_WINDIVERT_HYBRID}


def resolve_runtime_routing_backend_mode(mode, *, novadivert_ready=False):
    normalized = str(mode or "").strip().lower()
    if normalized == BACKEND_AUTO:
        return BACKEND_WINDIVERT_HYBRID if bool(novadivert_ready) else BACKEND_CURRENT
    if normalized in {BACKEND_CURRENT, BACKEND_PUBLIC_HYBRID, BACKEND_WINDIVERT_HYBRID}:
        return normalized
    return BACKEND_CURRENT


def build_app_transport_decisions(
    *,
    backend_mode,
    telegram_relay_ready,
    public_relay_states=None,
    singbox_allowed=True,
    novawfp_telegram_redirect_ready,
    novawfp_whatsapp_redirect_ready,
    novawfp_whatsapp_udp_ready=False,
    novawfp_discord_redirect_ready=False,
    novadivert_tcp_redirect_ready=False,
    novadivert_udp_redirect_ready=False,
    discord_tcp_outbound,
    discord_udp_outbound,
    telegram_tcp_outbound,
    telegram_udp_outbound,
    whatsapp_tcp_outbound,
    whatsapp_driver_fallback_outbound,
    whatsapp_udp_outbound,
):
    backend_mode = backend_mode or get_selected_routing_backend_mode()
    public_relay_states = public_relay_states or {}

    def _relay_ready(relay_key, legacy_ready=False):
        try:
            state = public_relay_states.get(relay_key) or {}
            if bool(state.get("ready")):
                return True
        except:
            pass
        return bool(legacy_ready)

    telegram_public_relay_ready = _relay_ready("telegram", telegram_relay_ready)
    whatsapp_public_relay_ready = _relay_ready("whatsapp", False)
    singbox_allowed = bool(singbox_allowed)

    telegram_tcp_backend = BACKEND_CURRENT
    telegram_tcp_tag = telegram_tcp_outbound
    telegram_udp_backend = BACKEND_CURRENT
    telegram_include_udp_rules = True
    telegram_keep_tcp_catchall = True
    telegram_include_tcp_rules = True
    if novawfp_telegram_redirect_ready:
        telegram_tcp_backend = "novawfp"
        telegram_keep_tcp_catchall = False
        telegram_include_tcp_rules = False
    elif telegram_public_relay_ready:
        telegram_tcp_backend = "telegram-relay"
        telegram_tcp_tag = "telegram-relay"
        # In relay mode Telegram TCP stays out of legacy TUN/runtime rules.
        telegram_keep_tcp_catchall = False
        telegram_include_tcp_rules = False

    whatsapp_tcp_backend = BACKEND_CURRENT
    whatsapp_tcp_tag = whatsapp_tcp_outbound
    whatsapp_udp_backend = BACKEND_CURRENT
    whatsapp_include_udp_rules = True
    whatsapp_keep_tcp_catchall = True
    whatsapp_include_tcp_rules = True
    if novawfp_whatsapp_redirect_ready:
        whatsapp_tcp_backend = "novawfp"
        whatsapp_tcp_tag = whatsapp_driver_fallback_outbound
        whatsapp_keep_tcp_catchall = False
        whatsapp_include_tcp_rules = False
    if novawfp_whatsapp_udp_ready:
        whatsapp_udp_backend = "novawfp"
        whatsapp_include_udp_rules = False
    elif is_public_hybrid_backend(backend_mode) and whatsapp_public_relay_ready:
        whatsapp_tcp_backend = "whatsapp-relay"
        whatsapp_tcp_tag = "whatsapp-relay"

    discord_tcp_backend = BACKEND_CURRENT
    discord_udp_backend = BACKEND_CURRENT
    discord_include_tcp_rules = True
    discord_include_udp_rules = True
    discord_keep_tcp_catchall = True
    if novawfp_discord_redirect_ready:
        discord_tcp_backend = "novawfp"
        discord_udp_backend = "novawfp"
        discord_include_tcp_rules = False
        discord_include_udp_rules = False
        discord_keep_tcp_catchall = False

    if is_windivert_hybrid_backend(backend_mode) and bool(novadivert_tcp_redirect_ready):
        if _env_bool("NOVA_WINDIVERT_TELEGRAM", True):
            telegram_tcp_backend = "windivert"
            telegram_tcp_tag = "windivert-tcp"
            telegram_include_tcp_rules = False
            telegram_keep_tcp_catchall = False
            if bool(novadivert_udp_redirect_ready):
                telegram_udp_backend = "windivert"
                telegram_include_udp_rules = False

        if _env_bool("NOVA_WINDIVERT_WHATSAPP", True):
            whatsapp_tcp_backend = "windivert"
            whatsapp_tcp_tag = "windivert-tcp"
            whatsapp_include_tcp_rules = False
            whatsapp_keep_tcp_catchall = False

        if _env_bool("NOVA_WINDIVERT_DISCORD", True):
            discord_tcp_backend = "windivert"
            discord_include_tcp_rules = False
            discord_keep_tcp_catchall = False

    if not singbox_allowed:
        telegram_include_tcp_rules = False
        telegram_keep_tcp_catchall = False
        whatsapp_include_tcp_rules = False
        whatsapp_keep_tcp_catchall = False
        discord_include_tcp_rules = False
        discord_keep_tcp_catchall = False
        if telegram_tcp_backend == BACKEND_CURRENT:
            telegram_tcp_backend = "disabled"
            telegram_tcp_tag = "disabled"
        if telegram_udp_backend == BACKEND_CURRENT:
            telegram_udp_backend = "disabled"
            telegram_include_udp_rules = False
        if whatsapp_tcp_backend == BACKEND_CURRENT:
            whatsapp_tcp_backend = "disabled"
            whatsapp_tcp_tag = "disabled"
        if whatsapp_udp_backend == BACKEND_CURRENT:
            whatsapp_udp_backend = "disabled"
            whatsapp_include_udp_rules = False
        if discord_tcp_backend == BACKEND_CURRENT:
            discord_tcp_backend = "disabled"
        if discord_udp_backend == BACKEND_CURRENT:
            discord_udp_backend = "disabled"
            discord_include_udp_rules = False

    decisions = {
        "discord": AppTransportDecision(
            key="discord",
            tcp_backend=discord_tcp_backend,
            tcp_outbound=discord_tcp_outbound,
            udp_backend=discord_udp_backend,
            udp_outbound=discord_udp_outbound,
            include_routing_tcp_rules=discord_include_tcp_rules,
            include_routing_udp_rules=discord_include_udp_rules,
            keep_tun_tcp_catchall=discord_keep_tcp_catchall,
        ),
        "telegram": AppTransportDecision(
            key="telegram",
            tcp_backend=telegram_tcp_backend,
            tcp_outbound=telegram_tcp_tag,
            udp_backend=telegram_udp_backend,
            udp_outbound=telegram_udp_outbound,
            include_routing_tcp_rules=telegram_include_tcp_rules,
            include_routing_udp_rules=telegram_include_udp_rules,
            keep_tun_tcp_catchall=telegram_keep_tcp_catchall,
        ),
        "whatsapp": AppTransportDecision(
            key="whatsapp",
            tcp_backend=whatsapp_tcp_backend,
            tcp_outbound=whatsapp_tcp_tag,
            udp_backend=whatsapp_udp_backend,
            udp_outbound=whatsapp_udp_outbound,
            include_routing_tcp_rules=whatsapp_include_tcp_rules,
            include_routing_udp_rules=whatsapp_include_udp_rules,
            keep_tun_tcp_catchall=whatsapp_keep_tcp_catchall,
        ),
    }
    return decisions


def write_routing_state_snapshot(path, *, backend_mode, decisions):
    if not path:
        return False
    payload = {
        "backend_mode": backend_mode or get_selected_routing_backend_mode(),
        "apps": {key: asdict(value) for key, value in (decisions or {}).items()},
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return True
