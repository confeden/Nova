"""What to issue after a connection is up: the order and the reasons, decided without doing it.

Owner's rule for 1.39: once the first tunnel carries traffic, issue this install's own profiles --
Cloudflare first, then Proton -- and collect Tor bridges in the background, cached across restarts.
Nothing issued here is switched to at once: a working connection on a shared profile is not torn
down. Own profiles take over at the next switch that happens anyway -- a failing tunnel, a manual
choice, a restart (nova_profiles.build_attempt_plan puts them first).

Nova Android does the same (its D22: own Cloudflare profiles have no toggle, issued 30 s after
connect, re-issued after 14 days).

This module only decides. ProfileJobs in nova.pyw runs the steps one after another on a worker,
so a registration never competes with the next one for the same narrow uplink.
"""

import time

import nova_profiles
import nova_proton
import nova_warp_generator

__all__ = [
    "STEP_WARP", "STEP_MASQUE", "STEP_PROTON", "STEP_PROTON_RTT", "STEP_TOR_BRIDGES", "STEPS",
    "MASQUE_REGISTER_COOLDOWN_SEC", "PROTON_RTT_MAX_AGE_SEC", "plan_backfill", "plan_reissue",
    "proton_rtt_targets",
]

STEP_WARP = "warp"
STEP_MASQUE = "masque"
STEP_PROTON = "proton"
STEP_PROTON_RTT = "proton_rtt"
STEP_TOR_BRIDGES = "tor_bridges"
STEPS = (STEP_WARP, STEP_MASQUE, STEP_PROTON, STEP_PROTON_RTT, STEP_TOR_BRIDGES)

# A failed MASQUE registration is not retried for this long within one run of Nova: every attempt
# is a device registration on Cloudflare's side.
MASQUE_REGISTER_COOLDOWN_SEC = 3600
# Distances to Proton nodes are re-measured when older than this; networks change (Wi-Fi, LTE).
PROTON_RTT_MAX_AGE_SEC = 6 * 3600


def _valid(records, group, origins=None):
    return [
        r for r in (records or [])
        if isinstance(r, dict) and r.get("group") == group and r.get("valid")
        and (origins is None or r.get("origin") in origins)
    ]


def proton_rtt_targets(records, stats, now=None, max_age=PROTON_RTT_MAX_AGE_SEC):
    """`{profile_id: host}` for the valid Proton profiles whose distance is unknown or stale."""
    from nova_latency import endpoint_host

    now = time.time() if now is None else float(now)
    stats = stats if isinstance(stats, dict) else {}
    targets = {}
    for record in _valid(records, nova_profiles.GROUP_PROTON):
        host = endpoint_host(record.get("endpoint"))
        if not host:
            continue
        entry = stats.get(record["id"]) if isinstance(stats.get(record["id"]), dict) else {}
        measured_at = entry.get("rtt_at")
        try:
            fresh = measured_at is not None and 0 <= now - float(measured_at) < max_age
        except (TypeError, ValueError):
            fresh = False
        if not fresh:
            targets[record["id"]] = host
    return targets


def plan_backfill(*, records, warp_state, proton_account, stats=None, tor_bridges_fresh=True,
                  masque_failed_at=0.0, now=None, proxies=None):
    """[(step, Russian reason), ...] in the order they should run; empty when all is fresh.

    `records` is nova_profiles.list_profiles(); `warp_state` nova_warp_generator.load_state();
    `proton_account` nova_proton.read_account() (None when absent); `proxies` the API routes a
    Proton run would get (nova_proton.should_issue uses them to lift a cooldown when a route was
    added); `masque_failed_at` the time of this run's last failed MASQUE registration.
    """
    now = time.time() if now is None else float(now)
    steps = []

    generated_present = bool(_valid(records, nova_profiles.GROUP_CLOUDFLARE, {nova_profiles.ORIGIN_GENERATED}))
    reissue, why = nova_warp_generator.should_reissue(warp_state, now, generated_present)
    if reissue:
        steps.append((STEP_WARP, why))

    if not _valid(records, nova_profiles.GROUP_MASQUE):
        failed_at = float(masque_failed_at or 0.0)
        if not failed_at or not 0 <= now - failed_at < MASQUE_REGISTER_COOLDOWN_SEC:
            steps.append((STEP_MASQUE, "профиля MASQUE ещё нет"))

    proton_present = bool(_valid(records, nova_profiles.GROUP_PROTON))
    issue, why = nova_proton.should_issue(proton_account, now, proton_present, proxies=proxies)
    if issue:
        steps.append((STEP_PROTON, why))
    # Measured after an issue as well: the step list is re-read from disk before it runs.
    if issue or proton_rtt_targets(records, stats, now):
        steps.append((STEP_PROTON_RTT, "расстояние до узлов Proton не измерено или устарело"))

    if not tor_bridges_fresh:
        steps.append((STEP_TOR_BRIDGES, "список мостов Tor старше суток или пуст"))
    return steps


def plan_reissue():
    """A manual «Перевыпустить личные профили»: every kind, forced, in the same order."""
    return [
        (STEP_WARP, "перевыпуск по запросу"),
        (STEP_MASQUE, "перевыпуск по запросу"),
        (STEP_PROTON, "перевыпуск по запросу"),
        (STEP_PROTON_RTT, "замер после перевыпуска"),
        (STEP_TOR_BRIDGES, "обновление по запросу"),
    ]
