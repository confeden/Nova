"""Two VPN slots: the primary egress (SOCKS on 1370) and the secondary one (the reserve).

Nova keeps two tunnels up at once. The **primary** is one of Nova's own userspace backends on
127.0.0.1:1370 -- Cloudflare AWG, Cloudflare MASQUE, Proton AWG, or a profile the user imported
(a VLESS node or an own .conf). The **secondary** is the reserve: Opera's HTTP proxy on
127.0.0.1:1371 (region EU or US), Tor (SOCKS 1375, HTTP CONNECT 1378), or an imported profile Nova
runs itself (SOCKS 1379, HTTP CONNECT 1380). The reserve always offers an HTTP CONNECT port,
because that is the one thing every consumer of the slot dials.

Everything the rest of Nova needs to agree on lives here, and nothing else does: the choices and
their labels, how a choice maps onto the persisted profile selection, the order «Авто» walks, the
route rule for the EU list, the runtime state file the helper processes read, and the memory of the
last connection. The module is stdlib-only and free of Nova globals, Tk and logging, so the
out-of-process helpers (NovaWFP\\proxy\\tcp_proxy.py) import it as they import nova_routing_profiles,
and every decision is pinned by a unit test instead of an observation.

## The route rule

Traffic on the EU list exists to leave Russia. It used to go to Opera only, because the primary
was WARP and WARP exits in the client's own country: Cloudflare geolocates the egress to the
client, so a Russian address leaves as RU whatever colo carries it (measured on Nova Android: node
HEL, exit RU; `ExitColoPolicy.kt`). Proton always exits abroad, and a Cloudflare tunnel can too
when the client is not in Russia. So the rule is by the **measured exit country**, not by the
backend name: when the primary exits outside HOME_COUNTRY, EU traffic takes the primary first and
the secondary becomes its fallback. Unknown is not foreign -- until the measurement lands, EU stays
on the secondary, exactly as before.

## Explicit choices are never substituted (Nova Android I1)

«Авто» is the only mode where Nova may walk from one transport to another. A named choice is
retried as itself or reported as failing; it is never replaced by something else silently.
"""

import json
import os
import re
import threading
import time

__all__ = [
    "HOME_COUNTRY", "is_foreign_country", "normalize_country", "order_countries",
    "PRIMARY_AUTO", "PRIMARY_CF_AWG", "PRIMARY_CF_MASQUE", "PRIMARY_PROTON", "PRIMARY_CUSTOM",
    "PRIMARY_VLESS", "PRIMARY_CF_WARP",
    "PRIMARY_CHOICES", "PRIMARY_IMPORTED_CHOICES", "PRIMARY_MENU_LABELS", "PRIMARY_PILL_LABELS",
    "GROUP_BY_PRIMARY", "primary_kind_of_group", "proton_country_of", "normalize_primary_country",
    "primary_choice_from_selection", "selection_for_primary", "primary_indicator_label",
    "SECONDARY_AUTO", "SECONDARY_OPERA", "SECONDARY_TOR", "SECONDARY_PROFILE", "SECONDARY_MODES",
    "SECONDARY_MENU_LABELS", "SECONDARY_PROFILE_KEY",
    "SECONDARY_PILL_CHOICES", "OPERA_REGIONS", "TOR_ENTRY_AUTO", "TOR_ENTRIES", "TOR_AUTO_ATTEMPTS",
    "normalize_tor_entry", "normalize_opera_region", "normalize_secondary_mode", "normalize_secondary_block",
    "normalize_secondary_kind", "normalize_secondary_profile_block",
    "secondary_choice", "secondary_pill_key", "secondary_choice_for_pill", "secondary_attempts",
    "secondary_indicator_label", "secondary_ports",
    "OPERA_HTTP_PORT", "TOR_SOCKS_PORT", "TOR_HTTP_PORT", "PRIMARY_SOCKS_PORT",
    "SECONDARY_PROFILE_SOCKS_PORT", "SECONDARY_PROFILE_HTTP_PORT",
    "EGRESS_STATE_FILENAME", "egress_state_path", "make_egress_state", "normalize_egress_state",
    "write_egress_state", "read_egress_state", "EgressStateCache",
    "eu_route_slots", "ru_route_slots", "secondary_pac_tokens", "secondary_http_attempt",
    "YOUTUBE_ROUTE_FOLLOWERS", "youtube_route_slots", "route_chain",
    "LAST_FILENAME", "last_path", "load_last", "remember_primary", "remember_secondary",
]

# --------------------------------------------------------------------------------------------
# Countries

# The country whose exit counts as "not abroad". Nova's lists are built for Russia (main.txt,
# second.txt), so the rule is written for Russia too; a user elsewhere gets the same lists anyway.
HOME_COUNTRY = "RU"

_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")

# Nova Android CountryDisplayOrder.kt: preferred exits first, then Europe, America, Asia, other.
_PREFERRED_COUNTRIES = ("NL", "NO", "PL", "RO", "CH", "US", "CA", "MX", "JP", "SG")
_EUROPE = frozenset((
    "AL", "AD", "AT", "BA", "BE", "BG", "BY", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR",
    "GB", "GR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MC", "MD", "ME", "MK", "MT",
    "NL", "NO", "PL", "PT", "RO", "RS", "RU", "SE", "SI", "SK", "SM", "UA", "VA",
))
_AMERICA = frozenset((
    "AR", "BO", "BR", "CA", "CL", "CO", "CR", "CU", "DO", "EC", "GT", "HN", "JM", "MX", "NI", "PA",
    "PE", "PR", "PY", "SV", "US", "UY", "VE",
))
_ASIA = frozenset((
    "AE", "AM", "AZ", "BD", "BH", "BN", "CN", "GE", "HK", "ID", "IL", "IN", "IQ", "IR", "JO", "JP",
    "KG", "KH", "KP", "KR", "KW", "KZ", "LA", "LB", "LK", "MM", "MN", "MO", "MY", "NP", "OM", "PH",
    "PK", "QA", "SA", "SG", "SY", "TH", "TJ", "TM", "TR", "TW", "UZ", "VN", "YE",
))


# Two-letter codes that are not a country: an Opera region, and the geolocation databases' own
# "unknown" / "Europe" / "Asia-Pacific" markers (Cloudflare says XX for unknown and T1 for Tor).
_NOT_COUNTRIES = frozenset(("EU", "XX", "ZZ", "AP"))


def normalize_country(value):
    """Two uppercase letters, or "" for anything else (an unmeasured exit, garbage, a region)."""
    text = str(value or "").strip().upper()
    return text if _COUNTRY_RE.match(text) and text not in _NOT_COUNTRIES else ""


def is_foreign_country(value):
    """True only for a known country other than HOME_COUNTRY: unknown is never foreign."""
    country = normalize_country(value)
    return bool(country) and country != HOME_COUNTRY


def order_countries(codes):
    """Display order for exit countries (Nova Android CountryDisplayOrder), duplicates dropped."""
    seen = []
    for raw in codes or ():
        code = normalize_country(raw)
        if code and code not in seen:
            seen.append(code)
    preferred = [c for c in _PREFERRED_COUNTRIES if c in seen]
    rest = [c for c in seen if c not in _PREFERRED_COUNTRIES]
    europe = sorted(c for c in rest if c in _EUROPE)
    america = sorted(c for c in rest if c in _AMERICA)
    asia = sorted(c for c in rest if c in _ASIA)
    other = sorted(c for c in rest if c not in _EUROPE and c not in _AMERICA and c not in _ASIA)
    return preferred + europe + america + asia + other


# --------------------------------------------------------------------------------------------
# Primary slot

PRIMARY_AUTO = "auto"
PRIMARY_CF_AWG = "cf_awg"
PRIMARY_CF_MASQUE = "cf_masque"
PRIMARY_PROTON = "proton"
# Imported profiles: the owner's own .conf files (Custom) and public nodes from a vless:// link or a
# subscription (VLESS). Offered as a slot choice since 2026-09-20, but still never part of «Авто»
# (D25) -- a dead stranger node in the automatic ladder would cost every connect its timeout.
PRIMARY_CUSTOM = "custom"
PRIMARY_VLESS = "vless"
# warp-cli is the last step of «Авто» and never a choice; it exists so the indicator can name it.
PRIMARY_CF_WARP = "cf_warp"

# What the settings row and the slot menu offer, in order.
PRIMARY_CHOICES = (PRIMARY_AUTO, PRIMARY_CF_AWG, PRIMARY_CF_MASQUE, PRIMARY_PROTON,
                   PRIMARY_VLESS, PRIMARY_CUSTOM)
# Kinds whose group holds profiles Nova cannot vouch for: reachable by naming them, never by «Авто».
PRIMARY_IMPORTED_CHOICES = (PRIMARY_VLESS, PRIMARY_CUSTOM)
PRIMARY_MENU_LABELS = {
    PRIMARY_AUTO: "Авто",
    PRIMARY_CF_AWG: "Cloudflare AWG",
    PRIMARY_CF_MASQUE: "Cloudflare MASQUE",
    PRIMARY_PROTON: "Proton",
    PRIMARY_VLESS: "VLESS",
    # The same words as the tab in «Профили» (owner's request 2026-09-20): one group, one name.
    # The folder on disk and every stored id stay "Custom" — only what is shown changed.
    PRIMARY_CUSTOM: "Custom AWG",
}
PRIMARY_PILL_LABELS = {
    PRIMARY_AUTO: "Авто",
    PRIMARY_CF_AWG: "CF AWG",
    PRIMARY_CF_MASQUE: "MASQUE",
    PRIMARY_PROTON: "Proton",
    PRIMARY_VLESS: "VLESS",
    PRIMARY_CUSTOM: "Свои",
}
_PRIMARY_INDICATOR = {
    PRIMARY_AUTO: "АВТО",
    PRIMARY_CF_AWG: "CF AWG",
    PRIMARY_CF_MASQUE: "CF MASQUE",
    PRIMARY_PROTON: "PROTON",
    PRIMARY_CUSTOM: "AWG",
    PRIMARY_VLESS: "VLESS",
    PRIMARY_CF_WARP: "CF WARP",
}

# Group names are nova_profiles.GROUP_*; repeated so helpers need not import nova_profiles.
_GROUP_CLOUDFLARE = "AWG Cloudflare"
_GROUP_PROTON = "AWG Proton"
_GROUP_MASQUE = "MASQUE"
_GROUP_VLESS = "VLESS"
_GROUP_CUSTOM = "Custom"
GROUP_BY_PRIMARY = {
    PRIMARY_CF_AWG: _GROUP_CLOUDFLARE,
    PRIMARY_CF_MASQUE: _GROUP_MASQUE,
    PRIMARY_PROTON: _GROUP_PROTON,
    PRIMARY_VLESS: _GROUP_VLESS,
    PRIMARY_CUSTOM: _GROUP_CUSTOM,
}
_PRIMARY_BY_GROUP = {group.lower(): kind for kind, group in GROUP_BY_PRIMARY.items()}

# `NL-FREE-128`, `US-FREE-34`: what nova_proton.conf_filename makes of Proton's `NL-FREE#128`.
_PROTON_NAME_RE = re.compile(r"^([A-Za-z]{2})-FREE-[0-9]+$")


def primary_kind_of_group(group):
    """Slot kind for a profile group name; "" for an unknown group."""
    return _PRIMARY_BY_GROUP.get(str(group or "").strip().lower(), "")


def proton_country_of(name):
    """Country of an issued Proton profile from its name (`NL-FREE-128` -> NL); "" when unknown.

    A Proton .conf dropped in by hand has no such name and no country: it is still a Proton
    profile, only a country filter cannot select it.
    """
    text = str(name or "").strip()
    if "/" in text:
        text = text.rpartition("/")[2]
    match = _PROTON_NAME_RE.match(text)
    return normalize_country(match.group(1)) if match else ""


def normalize_primary_country(value):
    return normalize_country(value)


def primary_choice_from_selection(selection):
    """nova_profiles selection -> {"kind", "country", "profile"}.

    auto -> auto; a group -> its slot kind (a Proton group may carry a country); a pinned
    profile -> the kind of its group plus the profile id. Unknown groups read as auto.
    """
    sel = selection if isinstance(selection, dict) else {}
    mode = str(sel.get("mode") or "").strip().lower()
    if mode == "group":
        kind = primary_kind_of_group(sel.get("group"))
        if not kind:
            return {"kind": PRIMARY_AUTO, "country": "", "profile": ""}
        country = normalize_country(sel.get("country")) if kind == PRIMARY_PROTON else ""
        return {"kind": kind, "country": country, "profile": ""}
    if mode == "profile":
        profile = str(sel.get("profile") or sel.get("profile_id") or "").strip()
        group, sep, name = profile.partition("/")
        kind = primary_kind_of_group(group) if sep else ""
        if not kind:
            return {"kind": PRIMARY_AUTO, "country": "", "profile": ""}
        country = proton_country_of(name) if kind == PRIMARY_PROTON else ""
        return {"kind": kind, "country": country, "profile": profile}
    return {"kind": PRIMARY_AUTO, "country": "", "profile": ""}


def selection_for_primary(kind, country="", profile=""):
    """Slot choice -> the selection nova_profiles persists. Unknown kinds mean auto.

    `profile` pins one profile of that kind's group (`mode` becomes "profile"), which is how an
    imported node is chosen by name rather than by group. A profile id whose group prefix does not
    belong to `kind` is ignored rather than trusted: the kind is what the caller asked for.
    """
    kind = str(kind or "").strip().lower()
    group = GROUP_BY_PRIMARY.get(kind)
    if kind not in PRIMARY_CHOICES or not group:
        return {"version": 1, "mode": "auto"}
    profile_id = str(profile or "").strip()
    if profile_id:
        prefix, sep, _name = profile_id.partition("/")
        if sep and prefix.strip().lower() == group.lower():
            return {"version": 1, "mode": "profile", "group": group, "profile": profile_id}
    selection = {"version": 1, "mode": "group", "group": group}
    code = normalize_country(country)
    if kind == PRIMARY_PROTON and code:
        selection["country"] = code
    return selection


def primary_indicator_label(backend, profile_id, connected, choice_kind=PRIMARY_AUTO):
    """What the main-window pill names: the backend that carries traffic, else the pending choice.

    `backend` is WarpManager.active_backend ("awg", "masque", "vless", "cloudflare"); `profile_id`
    the full `group/name`. A Proton exit names its country when the profile name carries one.
    """
    backend = str(backend or "").strip().lower()
    if connected:
        if backend == "masque":
            return _PRIMARY_INDICATOR[PRIMARY_CF_MASQUE]
        if backend == "vless":
            return _PRIMARY_INDICATOR[PRIMARY_VLESS]
        if backend == "awg":
            group, sep, name = str(profile_id or "").partition("/")
            kind = primary_kind_of_group(group) if sep else PRIMARY_CF_AWG
            if kind == PRIMARY_PROTON:
                country = proton_country_of(name)
                return f"PROTON {country}" if country else "PROTON"
            return _PRIMARY_INDICATOR.get(kind or PRIMARY_CF_AWG, "CF AWG")
        if backend in ("cloudflare", "warp-cli"):
            return _PRIMARY_INDICATOR[PRIMARY_CF_WARP]
    kind = str(choice_kind or PRIMARY_AUTO).strip().lower()
    return _PRIMARY_INDICATOR.get(kind, _PRIMARY_INDICATOR[PRIMARY_AUTO])


# --------------------------------------------------------------------------------------------
# Secondary slot

SECONDARY_AUTO = "auto"
SECONDARY_OPERA = "opera"
SECONDARY_TOR = "tor"
# An imported profile (a VLESS node or an own .conf) run as the reserve, on its own ports beside the
# primary. Never part of the «Авто» walk, for D25's reason: Nova cannot vouch for those nodes, and a
# dead one in an automatic ladder costs every fallback its timeout. A named choice only.
SECONDARY_PROFILE = "profile"
SECONDARY_MODES = (SECONDARY_AUTO, SECONDARY_OPERA, SECONDARY_TOR, SECONDARY_PROFILE)
SECONDARY_MENU_LABELS = {
    SECONDARY_AUTO: "Авто",
    SECONDARY_OPERA: "Opera",
    SECONDARY_TOR: "Tor",
    SECONDARY_PROFILE: "Свой профиль",
}
OPERA_REGIONS = ("EU", "US")

# The settings row offers five pills: the Opera region is part of the choice there.
SECONDARY_PILL_CHOICES = (
    ("auto", "Авто"),
    ("opera:EU", "Opera EU"),
    ("opera:US", "Opera US"),
    ("tor", "Tor"),
    ("profile", "Свой"),
)

TOR_ENTRY_AUTO = "auto"
# Order and labels as on Nova Android (ConnectionSelectorPolicy.TOR_ENTRY_MODES): by the odds of
# passing from Russia. Values are nova_tor.ENTRY_MODES; a test keeps the two lists equal.
TOR_ENTRIES = (
    ("auto", "Авто"),
    ("webtunnel", "WebTunnel"),
    ("obfs4", "obfs4"),
    ("snowflake", "Snowflake"),
    ("vanilla", "Vanilla"),
    ("direct", "Без мостов"),
)
# What «Авто» walks. `direct` is not in it: from Russia it stalls at conn_done (Android P-measure).
TOR_AUTO_ATTEMPTS = ("webtunnel", "obfs4", "snowflake", "vanilla")

OPERA_HTTP_PORT = 1371
TOR_SOCKS_PORT = 1375
TOR_HTTP_PORT = 1378
PRIMARY_SOCKS_PORT = 1370
# The reserve profile's own listeners. 1369-1396 is Nova's reserved local band (nova-go's
# masque/cli_test.go says so); inside it 1379 and 1380 were the first pair nothing in the repository
# referenced. SOCKS is what wireproxy and Xray speak natively; the HTTP CONNECT port beside it is
# what every consumer of the secondary slot already dials, so nothing downstream has to learn a new
# attempt kind. wireproxy serves both from one `[http]` section (measured 2026-09-20); nova-xray
# needs proxy/http in its registry and a second inbound.
SECONDARY_PROFILE_SOCKS_PORT = 1379
SECONDARY_PROFILE_HTTP_PORT = 1380


def normalize_secondary_kind(value):
    """A secondary kind string -> one of opera|tor|profile. Anything unknown reads as Opera.

    Every reader and writer of the runtime state goes through this, so a kind an older Nova does not
    know degrades to the pre-slots behaviour (Opera on 1371) instead of to a port nothing listens on.
    """
    text = str(value or "").strip().lower()
    return text if text in (SECONDARY_TOR, SECONDARY_PROFILE) else SECONDARY_OPERA


def normalize_tor_entry(value):
    text = str(value or "").strip().lower()
    return text if text in dict(TOR_ENTRIES) else TOR_ENTRY_AUTO


def normalize_opera_region(value, default="EU"):
    text = str(value or "").strip().upper()
    if text == "AM":
        text = "US"
    if text in OPERA_REGIONS:
        return text
    fallback = str(default or "EU").strip().upper()
    return fallback if fallback in OPERA_REGIONS else "EU"


def normalize_secondary_mode(value):
    text = str(value or "").strip().lower()
    return text if text in SECONDARY_MODES else SECONDARY_AUTO


def normalize_secondary_block(block):
    """The `secondary` block of routing_settings.json: `{"mode": auto|opera|tor|profile}`.

    The Opera region stays in the top-level `opera_region`, the Tor entry in `tor.entry` and the
    reserve profile in `secondary_profile`, the way earlier versions already keep the first two;
    this block only says which of them runs.
    """
    mode = block.get("mode") if isinstance(block, dict) else block
    return {"mode": normalize_secondary_mode(mode)}


SECONDARY_PROFILE_KEY = "secondary_profile"


def normalize_secondary_profile_block(block):
    """`secondary_profile` of routing_settings.json -> {"group", "profile"}.

    A group alone means "any profile of that group, in the group's own order"; a profile id pins one
    node. Both are plain names, never a key or an address -- the same rule the primary selection
    follows, and the reason this file may be read by the out-of-process helpers.
    """
    payload = block if isinstance(block, dict) else {}
    profile = str(payload.get("profile") or "").strip()
    group = str(payload.get("group") or "").strip()
    if profile and not group:
        prefix, sep, _name = profile.partition("/")
        group = prefix.strip() if sep else ""
    if profile:
        prefix, sep, _name = profile.partition("/")
        if not sep or prefix.strip().lower() != group.lower():
            # A profile id that does not live in the named group is not this group's choice.
            profile = ""
    return {"group": group, "profile": profile}


def secondary_choice(settings):
    """routing settings -> {"mode", "opera_region", "tor_entry", "profile_group", "profile"}."""
    payload = settings if isinstance(settings, dict) else {}
    tor_block = payload.get("tor") if isinstance(payload.get("tor"), dict) else {}
    profile_block = normalize_secondary_profile_block(payload.get(SECONDARY_PROFILE_KEY))
    return {
        "mode": normalize_secondary_block(payload.get("secondary"))["mode"],
        "opera_region": normalize_opera_region(payload.get("opera_region")),
        "tor_entry": normalize_tor_entry(tor_block.get("entry")),
        "profile_group": profile_block["group"],
        "profile": profile_block["profile"],
    }


def secondary_pill_key(choice):
    """Which of SECONDARY_PILL_CHOICES is selected for a secondary choice."""
    choice = choice if isinstance(choice, dict) else {}
    mode = normalize_secondary_mode(choice.get("mode"))
    if mode == SECONDARY_OPERA:
        return "opera:" + normalize_opera_region(choice.get("opera_region"))
    return mode


def secondary_choice_for_pill(pill_key, current=None):
    """A pill press -> (mode, opera_region); the region is kept unless the pill names one."""
    current = current if isinstance(current, dict) else {}
    region = normalize_opera_region(current.get("opera_region"))
    key = str(pill_key or "").strip()
    if key.lower().startswith("opera:"):
        return SECONDARY_OPERA, normalize_opera_region(key.partition(":")[2], region)
    return normalize_secondary_mode(key), region


def secondary_attempts(choice, last=None):
    """The order the secondary slot walks: [(kind, region_or_entry_or_profile), ...].

    Named choices are a list of one (I1). «Авто» starts with the last secondary that carried
    traffic, then Opera in the configured region -- Opera's own controller may fall back EU -> US
    inside that attempt, which is allowed in auto only -- then Tor: the remembered entry when there
    is one, otherwise Tor's own «Авто» walk. An imported profile is a named choice only and never
    joins the «Авто» ring (D25); its own walk over the group's nodes happens one level down, inside
    the runner, exactly the way a named Opera may still fall back EU -> US inside its attempt.
    """
    choice = choice if isinstance(choice, dict) else {}
    mode = normalize_secondary_mode(choice.get("mode"))
    region = normalize_opera_region(choice.get("opera_region"))
    entry = normalize_tor_entry(choice.get("tor_entry"))
    if mode == SECONDARY_PROFILE:
        return [(SECONDARY_PROFILE, str(choice.get("profile") or choice.get("profile_group") or ""))]
    if mode == SECONDARY_OPERA:
        return [(SECONDARY_OPERA, region)]
    if mode == SECONDARY_TOR:
        return [(SECONDARY_TOR, entry)]
    last = last if isinstance(last, dict) else {}
    last_kind = str(last.get("kind") or "").strip().lower()
    opera_region = normalize_opera_region(last.get("region"), region) if last_kind == SECONDARY_OPERA else region
    tor_entry = normalize_tor_entry(last.get("entry")) if last_kind == SECONDARY_TOR else TOR_ENTRY_AUTO
    opera = (SECONDARY_OPERA, opera_region)
    tor = (SECONDARY_TOR, tor_entry)
    return [tor, opera] if last_kind == SECONDARY_TOR else [opera, tor]


def secondary_indicator_label(kind, region=""):
    """EU / US for Opera (Opera's runtime label may add `/WARP`), TOR for Tor, the short group or
    node name for an imported profile (the runner passes it; "СВОЙ" when it has none yet)."""
    kind = normalize_secondary_kind(kind)
    if kind == SECONDARY_TOR:
        return "TOR"
    if kind == SECONDARY_PROFILE:
        return str(region or "").strip().upper() or "СВОЙ"
    label = str(region or "").strip().upper()
    if label.startswith("AM"):
        label = "US" + label[2:]
    return label or "EU"


def secondary_ports(kind):
    """Local ports of a secondary kind: the HTTP CONNECT port every consumer can use, and SOCKS."""
    kind = normalize_secondary_kind(kind)
    if kind == SECONDARY_TOR:
        return {"http_port": TOR_HTTP_PORT, "socks_port": TOR_SOCKS_PORT}
    if kind == SECONDARY_PROFILE:
        return {"http_port": SECONDARY_PROFILE_HTTP_PORT, "socks_port": SECONDARY_PROFILE_SOCKS_PORT}
    return {"http_port": OPERA_HTTP_PORT, "socks_port": 0}


# --------------------------------------------------------------------------------------------
# Runtime egress state (temp/vpn-egress.json)

EGRESS_STATE_FILENAME = "vpn-egress.json"
_STATE_VERSION = 1
# The foreign flag decides where EU traffic goes. A flag nobody refreshed for this long is not
# trusted: the writer heartbeats every few minutes while Nova runs.
EGRESS_FOREIGN_TRUST_SEC = 15 * 60


def egress_state_path(base_dir):
    return os.path.join(str(base_dir), "temp", EGRESS_STATE_FILENAME)


def make_egress_state(*, primary_up, primary_kind="", primary_label="", primary_country="",
                      secondary_up, secondary_kind=SECONDARY_OPERA, secondary_label="",
                      secondary_country="", now=None):
    """The whole state as one dict. No address, no key, no path -- only kinds, labels and a country.

    `secondary_country` is measured only for a reserve Nova itself runs (an imported profile): Opera
    and Tor are known to exit abroad, a stranger's node is not. Nothing routes on it yet -- it is
    published so the log and the UI can say where the reserve comes out.
    """
    country = normalize_country(primary_country)
    secondary_kind = normalize_secondary_kind(secondary_kind)
    secondary_code = normalize_country(secondary_country)
    return {
        "version": _STATE_VERSION,
        "updated_at": round(float(time.time() if now is None else now), 3),
        "primary": {
            "up": bool(primary_up),
            "kind": str(primary_kind or ""),
            "label": str(primary_label or ""),
            "country": country,
            "foreign": is_foreign_country(country),
            "socks_port": PRIMARY_SOCKS_PORT,
        },
        "secondary": {
            "up": bool(secondary_up),
            "kind": secondary_kind,
            "label": str(secondary_label or ""),
            "country": secondary_code,
            **secondary_ports(secondary_kind),
        },
    }


_DEFAULT_STATE = {
    "version": _STATE_VERSION,
    "updated_at": 0.0,
    "primary": {"up": False, "kind": "", "label": "", "country": "", "foreign": False,
                "socks_port": PRIMARY_SOCKS_PORT},
    "secondary": {"up": False, "kind": SECONDARY_OPERA, "label": "", "country": "",
                  "http_port": OPERA_HTTP_PORT, "socks_port": 0},
}


def normalize_egress_state(payload, now=None):
    """Validate a read state; missing or broken pieces fall back to the pre-slots behaviour.

    The fallback is what Nova did before this file existed: Opera on 1371 is the secondary and
    the primary is not foreign. A stale foreign flag is dropped (EGRESS_FOREIGN_TRUST_SEC).
    """
    now = time.time() if now is None else float(now)
    state = json.loads(json.dumps(_DEFAULT_STATE))
    if not isinstance(payload, dict):
        return state
    try:
        updated = float(payload.get("updated_at") or 0.0)
    except (TypeError, ValueError):
        updated = 0.0
    state["updated_at"] = updated
    primary = payload.get("primary") if isinstance(payload.get("primary"), dict) else {}
    secondary = payload.get("secondary") if isinstance(payload.get("secondary"), dict) else {}
    country = normalize_country(primary.get("country"))
    fresh = updated > 0 and 0 <= now - updated <= EGRESS_FOREIGN_TRUST_SEC
    state["primary"].update({
        "up": bool(primary.get("up")),
        "kind": str(primary.get("kind") or ""),
        "label": str(primary.get("label") or ""),
        "country": country,
        "foreign": bool(fresh and is_foreign_country(country) and primary.get("foreign") is not False),
    })
    kind = normalize_secondary_kind(secondary.get("kind"))
    state["secondary"].update({
        "up": bool(secondary.get("up")),
        "kind": kind,
        "label": str(secondary.get("label") or ""),
        "country": normalize_country(secondary.get("country")),
        **secondary_ports(kind),
    })
    return state


def write_egress_state(path, state):
    """Atomic write (tmp + os.replace). Raises OSError; the caller decides whether that matters."""
    path = str(path)
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    data = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True)
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(data)
    last_error = None
    for _ in range(10):
        try:
            os.replace(tmp, path)
            return
        except PermissionError as exc:  # a reader holds the target for a moment
            last_error = exc
            time.sleep(0.05)
    try:
        os.remove(tmp)
    except OSError:
        pass
    raise last_error


def read_egress_state(path, now=None):
    try:
        with open(str(path), "rb") as handle:
            payload = json.loads(handle.read(65536).decode("utf-8-sig"))
    except (OSError, ValueError):
        payload = None
    return normalize_egress_state(payload, now=now)


class EgressStateCache:
    """mtime-cached reader for the helpers, which ask once per connection."""

    def __init__(self, path, min_interval=1.0):
        self.path = str(path)
        self.min_interval = float(min_interval)
        self._lock = threading.Lock()
        self._checked_at = -1e9
        self._mtime = None
        self._raw = None

    def get(self, now=None):
        mono = time.monotonic()
        with self._lock:
            if mono - self._checked_at >= self.min_interval:
                self._checked_at = mono
                try:
                    mtime = os.stat(self.path).st_mtime
                except OSError:
                    mtime = None
                if mtime != self._mtime:
                    self._mtime = mtime
                    self._raw = None
                    if mtime is not None:
                        try:
                            with open(self.path, "rb") as handle:
                                self._raw = json.loads(handle.read(65536).decode("utf-8-sig"))
                        except (OSError, ValueError):
                            self._raw = None
            raw = self._raw
        # Normalised on every call: the foreign flag ages even when the file does not change.
        return normalize_egress_state(raw, now=now)


def eu_route_slots(primary_foreign):
    """Where EU-list traffic goes, in order: the primary only when it exits abroad."""
    return ["primary", "secondary"] if primary_foreign else ["secondary"]


def ru_route_slots():
    """RU-list traffic (blocked by DPI, not by geography): the primary first, the secondary behind it."""
    return ["primary", "secondary"]


# Names that must leave by googlevideo.com's exit even though they are not YouTube: Google binds a
# media URL to the exit that asked for it, and NotebookLM's audio issuer is bet to be lh3 (D22).
YOUTUBE_ROUTE_FOLLOWERS = ("lh3.googleusercontent.com",)


def youtube_route_slots(primary_foreign, secondary_kind=SECONDARY_OPERA):
    """Where YouTube goes, in order, for browsers on «Auto» (the hybrid PAC).

    A primary whose exit is Russian (or not measured yet) reaches Google from inside the Russian DPI:
    through Cloudflare's Moscow colo 35-50 % of new YouTube connections sat silent for 10 s, filtered
    by SNI (G81). The secondary exits abroad, so it goes first; the primary stays behind it, because a
    YouTube that half works beats the direct leg. With a foreign exit YouTube is RU-list traffic again,
    and so it is with Tor as the secondary: video over Tor is too slow to be worth it (owner, D23).
    """
    if primary_foreign or str(secondary_kind or "").strip().lower() == SECONDARY_TOR:
        return ["primary", "secondary"]
    return ["secondary", "primary"]


def route_chain(slots, *, primary_up, secondary_up, primary_tokens, secondary_tokens, last_resort):
    """PAC chain for an ordered slot list: only the slots that are up, `last_resort` always last."""
    parts = []
    for slot in slots:
        if slot == "primary" and primary_up:
            parts.append(primary_tokens)
        elif slot == "secondary" and secondary_up:
            parts.append(secondary_tokens)
    parts.append(last_resort)
    return "; ".join(parts)


def secondary_pac_tokens(kind, http_port=None, socks_port=None):
    """PAC tokens for the secondary. Tor and an own profile get SOCKS5 first (browsers) and PROXY
    for WinINET/WinHTTP, which ignore SOCKS5 tokens; Opera speaks HTTP CONNECT only."""
    kind = normalize_secondary_kind(kind)
    if kind == SECONDARY_TOR:
        socks = int(socks_port or TOR_SOCKS_PORT)
        http = int(http_port or TOR_HTTP_PORT)
        return [f"SOCKS5 127.0.0.1:{socks}", f"PROXY 127.0.0.1:{http}"]
    if kind == SECONDARY_PROFILE:
        socks = int(socks_port or SECONDARY_PROFILE_SOCKS_PORT)
        http = int(http_port or SECONDARY_PROFILE_HTTP_PORT)
        return [f"SOCKS5 127.0.0.1:{socks}", f"PROXY 127.0.0.1:{http}"]
    return [f"PROXY 127.0.0.1:{int(http_port or OPERA_HTTP_PORT)}"]


# Tor builds a circuit before HTTPTunnelPort answers CONNECT: seconds, not the ~1 s of Opera.
_TOR_ATTEMPT_TIMEOUT = 10.0
_TOR_FIRST_BYTE_TIMEOUT = 8.0
# An own profile dials its node per flow -- a REALITY or a WireGuard-over-userspace handshake, not
# the local hop Opera is. Measured on public VLESS nodes: the first byte of a fresh flow lands in
# 0.3-4 s. Shorter than Tor, longer than Opera.
_PROFILE_ATTEMPT_TIMEOUT = 6.0
_PROFILE_FIRST_BYTE_TIMEOUT = 5.0


def secondary_http_attempt(state, timeout=3.0, first_byte_timeout=2.4):
    """The `opera-http` attempt of the helpers, pointed at whatever the secondary is right now.

    The label stays `opera-http` on purpose: it is the secondary slot's label in dozens of
    ordering rules in tcp_proxy.py, and renaming it there would be a rewrite, not a routing change.
    `egress` says what it really is, for the log. The kind stays `http` for every tenant, which is
    why an own profile is given an HTTP CONNECT listener beside its SOCKS one: no consumer of the
    secondary slot has to learn a new attempt kind.
    """
    secondary = (state or {}).get("secondary") if isinstance(state, dict) else None
    secondary = secondary if isinstance(secondary, dict) else {}
    kind = normalize_secondary_kind(secondary.get("kind"))
    ports = secondary_ports(kind)
    attempt = {
        "kind": "http",
        "host": "127.0.0.1",
        "port": ports["http_port"],
        "label": "opera-http",
        "egress": kind,
        "timeout": float(timeout),
        "first_byte_timeout": float(first_byte_timeout),
    }
    if kind == SECONDARY_TOR:
        attempt["timeout"] = max(attempt["timeout"], _TOR_ATTEMPT_TIMEOUT)
        attempt["first_byte_timeout"] = max(attempt["first_byte_timeout"], _TOR_FIRST_BYTE_TIMEOUT)
    elif kind == SECONDARY_PROFILE:
        attempt["timeout"] = max(attempt["timeout"], _PROFILE_ATTEMPT_TIMEOUT)
        attempt["first_byte_timeout"] = max(attempt["first_byte_timeout"], _PROFILE_FIRST_BYTE_TIMEOUT)
    return attempt


# --------------------------------------------------------------------------------------------
# Memory of the last connection (temp/vpn-last.json)

LAST_FILENAME = "vpn-last.json"
_LAST_LOCK = threading.Lock()


def last_path(base_dir):
    return os.path.join(str(base_dir), "temp", LAST_FILENAME)


def load_last(base_dir):
    """{"primary": {...}, "secondary": {...}}; missing or broken halves are empty dicts."""
    try:
        with open(last_path(base_dir), "rb") as handle:
            payload = json.loads(handle.read(65536).decode("utf-8-sig"))
    except (OSError, ValueError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    primary = payload.get("primary") if isinstance(payload.get("primary"), dict) else {}
    secondary = payload.get("secondary") if isinstance(payload.get("secondary"), dict) else {}
    return {"primary": dict(primary), "secondary": dict(secondary)}


def _save_last(base_dir, mutate):
    with _LAST_LOCK:
        current = load_last(base_dir)
        mutate(current)
        payload = {"version": 1, "primary": current["primary"], "secondary": current["secondary"]}
        write_egress_state(last_path(base_dir), payload)
        return payload


def remember_primary(base_dir, kind, profile_id="", country="", now=None):
    """Record the primary that just carried traffic. Profile ids are names, never keys."""
    entry = {
        "kind": str(kind or ""),
        "profile": str(profile_id or ""),
        "country": normalize_country(country),
        "at": round(float(time.time() if now is None else now), 3),
    }

    def mutate(current):
        current["primary"] = entry

    return _save_last(base_dir, mutate)


def remember_secondary(base_dir, kind, region="", entry="", profile="", now=None):
    """Record the secondary that just carried traffic. Profile ids are names, never keys."""
    kind = normalize_secondary_kind(kind)
    record = {
        "kind": kind,
        "region": normalize_opera_region(region) if kind == SECONDARY_OPERA else "",
        "entry": normalize_tor_entry(entry) if kind == SECONDARY_TOR else "",
        "profile": str(profile or "").strip() if kind == SECONDARY_PROFILE else "",
        "at": round(float(time.time() if now is None else now), 3),
    }

    def mutate(current):
        current["secondary"] = record

    return _save_last(base_dir, mutate)
