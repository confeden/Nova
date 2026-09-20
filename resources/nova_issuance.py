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
    "STEP_WARP", "STEP_MASQUE", "STEP_PROTON", "STEP_PROTON_FRESH", "STEP_PROTON_RTT",
    "STEP_TOR_BRIDGES", "STEP_SUBSCRIPTIONS", "STEPS",
    "PROTON_DEAD_SET_MIN_AGE_SEC", "PROTON_DEAD_SET_EVIDENCE_SEC", "PROTON_DEAD_SET_MIN_TRIED",
    "proton_set_is_dead",
    "MASQUE_REGISTER_COOLDOWN_SEC", "PROTON_RTT_MAX_AGE_SEC", "plan_backfill", "plan_reissue",
    "proton_rtt_targets",
]

STEP_WARP = "warp"
STEP_MASQUE = "masque"
STEP_PROTON = "proton"
# A set that is present, fresh by the clock, and dead in practice. Separate from STEP_PROTON
# because it is the one issue that has to be forced: every ordinary guard says there is nothing
# to do, and the guards are right about the clock and wrong about the nodes.
STEP_PROTON_FRESH = "proton_fresh"
STEP_PROTON_RTT = "proton_rtt"
STEP_TOR_BRIDGES = "tor_bridges"
STEP_SUBSCRIPTIONS = "subscriptions"
STEPS = (STEP_WARP, STEP_MASQUE, STEP_PROTON, STEP_PROTON_FRESH, STEP_PROTON_RTT,
         STEP_TOR_BRIDGES, STEP_SUBSCRIPTIONS)

# A failed MASQUE registration is not retried for this long within one run of Nova: every attempt
# is a device registration on Cloudflare's side.
MASQUE_REGISTER_COOLDOWN_SEC = 3600
# Distances to Proton nodes are re-measured when older than this; networks change (Wi-Fi, LTE).
PROTON_RTT_MAX_AGE_SEC = 6 * 3600

# A set has to have been alive long enough for "it stopped working" to mean anything, and a forced
# re-issue stamps `issued_at`, so this age is also what stops the rule firing twice over.
PROTON_DEAD_SET_MIN_AGE_SEC = 2 * 3600
# The failures have to be current: a set that failed yesterday and has not been tried since says
# nothing about today's network.
PROTON_DEAD_SET_EVIDENCE_SEC = 3600
# One or two failures are a node or a flow (G69); a whole set failing is the set.
PROTON_DEAD_SET_MIN_TRIED = 3


def proton_set_is_dead(records, stats, account, now=None):
    """True when the issued Proton set is present and every node of it has recently stopped working.

    The gap this closes: `nova_proton.should_issue` decides by the clock -- the key, the cert and
    the age of the node list -- and by that measure a set issued yesterday is perfectly fresh. It
    has no way to know that not one of its fifty nodes answers any more, although the very stats
    that prove it are already in this module's hands. That is why a Proton group could sit on a
    dead set for a day: nothing ever asked the question.

    The answer is deliberately hard to get to. Every condition below has to hold:

    * at least `PROTON_DEAD_SET_MIN_TRIED` nodes were actually tried -- one or two failures are a
      node or an unlucky local port (G69), not a verdict about the set;
    * every tried node failed later than it last succeeded;
    * the newest of those failures is younger than `PROTON_DEAD_SET_EVIDENCE_SEC`;
    * the set is older than `PROTON_DEAD_SET_MIN_AGE_SEC`, which also bounds the rule: a forced
      re-issue writes `issued_at = now`, so it cannot fire again for two hours.
    """
    now = time.time() if now is None else float(now)
    members = _valid(records, nova_profiles.GROUP_PROTON)
    if len(members) < PROTON_DEAD_SET_MIN_TRIED:
        return False
    issued_at = 0.0
    if isinstance(account, dict):
        try:
            issued_at = float(account.get("issued_at") or 0.0)
        except (TypeError, ValueError):
            issued_at = 0.0
    if issued_at <= 0 or (now - issued_at) < PROTON_DEAD_SET_MIN_AGE_SEC:
        return False

    stats = stats if isinstance(stats, dict) else {}
    tried = 0
    newest_failure = 0.0
    for record in members:
        entry = stats.get(record["id"])
        if not isinstance(entry, dict):
            continue
        try:
            ok_at = float(entry.get("last_ok_at") or 0.0)
            fail_at = float(entry.get("last_fail_at") or 0.0)
        except (TypeError, ValueError):
            continue
        if fail_at <= 0:
            continue
        if ok_at >= fail_at:
            return False  # one node still works: the set is not dead
        tried += 1
        newest_failure = max(newest_failure, fail_at)
    if tried < PROTON_DEAD_SET_MIN_TRIED:
        return False
    return 0 <= (now - newest_failure) < PROTON_DEAD_SET_EVIDENCE_SEC


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
                  masque_failed_at=0.0, now=None, proxies=None, subscriptions_due=0):
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
    elif proton_set_is_dead(records, stats, proton_account, now):
        steps.append((STEP_PROTON_FRESH, "ни один узел выпущенного набора Proton больше не отвечает"))
    # Measured after an issue as well: the step list is re-read from disk before it runs.
    if issue or proton_rtt_targets(records, stats, now):
        steps.append((STEP_PROTON_RTT, "расстояние до узлов Proton не измерено или устарело"))

    if not tor_bridges_fresh:
        steps.append((STEP_TOR_BRIDGES, "список мостов Tor старше суток или пуст"))

    # Subscriptions are the VLESS group's supply, and public nodes rot fast: of sixty reachable
    # ones measured 2026-09-20, four carried traffic. A refresh that finds nothing new is a
    # conditional GET answered with 304 and zero bytes, so asking often costs nothing.
    if int(subscriptions_due or 0) > 0:
        steps.append((STEP_SUBSCRIPTIONS, f"подписок к обновлению: {int(subscriptions_due)}"))
    return steps


def plan_reissue():
    """A manual «Перевыпустить личные профили»: every kind, forced, in the same order."""
    return [
        (STEP_WARP, "перевыпуск по запросу"),
        (STEP_MASQUE, "перевыпуск по запросу"),
        (STEP_PROTON, "перевыпуск по запросу"),
        (STEP_PROTON_FRESH, "перевыпуск по запросу"),
        (STEP_PROTON_RTT, "замер после перевыпуска"),
        (STEP_TOR_BRIDGES, "обновление по запросу"),
        (STEP_SUBSCRIPTIONS, "обновление по запросу"),
    ]
