"""Published Opera endpoint list (opera_endpoints.json), read the way Nova Android reads it.

Why it exists: SurfEasy `discover` answers differently by the caller's address, and the set
handed out to Russian clients often dies on dial (opera.log: `dial tcp ...: operation was
canceled`). A list discovered from outside Russia is published next to the update manifest;
an endpoint from it is tried before the live discover, the same as a cached one.

Pure parsing lives here so tests can import it; the fetch is the only network part.
"""

import json
import ipaddress
import logging
import re
import urllib.request
from urllib.parse import urlsplit

FEED_URLS = (
    "https://raw.githubusercontent.com/confeden/nova_updates/main/nova_pc/opera_endpoints.json",
    "https://confeden.github.io/nova_updates/nova_pc/opera_endpoints.json",
    "https://raw.githubusercontent.com/confeden/nova_updates/main/opera_endpoints.json",
    "https://confeden.github.io/nova_updates/opera_endpoints.json",
)
# Same regions opera-proxy takes via -country; US is the same exit as AM.
KNOWN_REGIONS = ("EU", "AM", "AS")
_ALIASES = {"US": "AM"}


def valid_endpoint(value):
    try:
        endpoint = urlsplit("//" + value)
        if endpoint.username or endpoint.password or endpoint.path or endpoint.query or endpoint.fragment:
            return False
        if not endpoint.hostname or not endpoint.port or not 1 <= endpoint.port <= 65535:
            return False
        try:
            return ipaddress.ip_address(endpoint.hostname).is_global
        except ValueError:
            return bool(len(endpoint.hostname) <= 253 and "." in endpoint.hostname and re.fullmatch(
                r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+", endpoint.hostname))
    except (ValueError, TypeError):
        return False


def parse_endpoint_feed(body):
    """Return {region: [host:port, ...]} for the regions opera-proxy understands; {} on junk."""
    try:
        root = json.loads(body) if isinstance(body, str) else {}
    except (ValueError, TypeError):
        return {}
    regions = root.get("regions") if isinstance(root, dict) else None
    if not isinstance(regions, dict):
        return {}
    parsed = {}
    for raw_region, raw_endpoints in regions.items():
        region = str(raw_region or "").strip().upper()
        region = _ALIASES.get(region, region)
        if region not in KNOWN_REGIONS or not isinstance(raw_endpoints, list):
            continue
        endpoints = []
        for item in raw_endpoints[:64]:
            endpoint = str(item or "").strip()
            if valid_endpoint(endpoint) and endpoint not in endpoints:
                endpoints.append(endpoint)
        if endpoints:
            parsed[region] = endpoints
    return parsed


def endpoints_for_country(feed, country):
    """Published endpoints for one region, in the feed's own order."""
    region = str(country or "").strip().upper()
    region = _ALIASES.get(region, region)
    return list((feed or {}).get(region, []))


def fetch_endpoint_feed(timeout=2.5):
    """Try both mirrors of the feed; return the parsed regions or {} when neither answers."""
    for url in FEED_URLS:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "NovaPC"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                parsed = parse_endpoint_feed(response.read(256 * 1024).decode("utf-8", "replace"))
            if parsed:
                return parsed
        except (OSError, ValueError) as error:
            logging.getLogger(__name__).debug("Opera feed unavailable at %s: %s", url, type(error).__name__)
    logging.getLogger(__name__).warning("Opera endpoint feed unavailable; using direct discovery and API relay")
    return {}
