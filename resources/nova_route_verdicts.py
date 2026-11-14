"""Direct-reachability verdicts for the browsers' «Auto» routing (owner, 2026-11-12).

The question this answers, per host: *does the site open DIRECTLY, through the winws strategy?* If it
does, a browser on «Auto» goes straight there even when the host is on `main.txt` (the list says
«blocked by DPI», the strategy may already beat it); if it does not, the host takes the VPN chain.
A PAC cannot observe anything, so Nova measures: one small TLS probe per host (nova_direct_probe),
a bounded rotation over the hosts the lists name, and the verdicts are written into the PAC as a
plain set. Nothing here touches the network or the clock by itself, so every rule is unit-tested.

Rules, chosen to be cheap and not to flap:
- **Unknown is not direct.** A host with no verdict, an expired verdict or a failed one keeps the
  VPN chain: the safe answer for a host the list calls blocked.
- **Promotion needs two clean probes** at least `CONFIRM_GAP_SEC` apart. One lucky handshake must not
  send a blocked site direct; the second probe costs ~6 KB.
- **Demotion needs two failures in a row**, the second `RETRY_BAD_GAP_SEC` after the first, so a
  single dropped packet does not move a working site onto the VPN. A host already `bad` stays bad on
  one more failure and backs off (20 min -> 2 h) so a dead site is not hammered.
- **Verdicts expire** (`OK_TTL_SEC` 6 h, `BAD_TTL_SEC` 2 h): the strategy and the ISP change.
- A probe that could not judge (no DNS, a local error) records no verdict, but the host is DEFERRED
  (`defer`): a never-probed host stays at the head of `due`, so one name that never resolves used to be
  probed every 5 s forever and starved every other host, the stale verdicts of YouTube included.
- Bounded: `MAX_ENTRIES` hosts in the file, `MAX_PAC_HOSTS` in the PAC.
Stdlib only, free of Nova globals (I15).
"""

import json
import os
import time

__all__ = [
    "OK_TTL_SEC", "BAD_TTL_SEC", "CONFIRM_GAP_SEC", "RETRY_BAD_GAP_SEC", "MAX_ENTRIES", "MAX_PAC_HOSTS",
    "DEFER_SEC", "DIRECT_OK", "DIRECT_BAD", "UNKNOWN", "VerdictStore", "candidate_hosts", "host_key",
]

OK_TTL_SEC = 6 * 3600.0
BAD_TTL_SEC = 2 * 3600.0
CONFIRM_GAP_SEC = 30.0
RETRY_BAD_GAP_SEC = 60.0
BAD_BACKOFF_SEC = (1200.0, 2400.0, 4800.0, 7200.0)
DEFER_SEC = 1800.0
MAX_ENTRIES = 1200
MAX_PAC_HOSTS = 600

DIRECT_OK = "direct_ok"
DIRECT_BAD = "direct_bad"
UNKNOWN = "unknown"


def host_key(host):
    """Lower-case host without a leading `www.`/dot; "" for anything that is not a plain DNS name."""
    text = str(host or "").strip().lower().strip(".")
    if text.startswith("www."):
        text = text[4:]
    if not text or "/" in text or ":" in text or " " in text or "*" in text:
        return ""
    if text.replace(".", "").isdigit():  # an IPv4 literal is not a name
        return ""
    return text if "." in text else ""


# Discord names the app reaches through the system PAC. Probed like main-class names so that in
# Discord «Авто» they go DIRECT (winws) and fall to the VPN only on a failed verdict. `discord.media`
# is left out: the apex has no site to handshake with (its voice hosts are c-<dc>-<id>.discord.media).
DISCORD_PROBE_HOSTS = (
    "discord.com",
    "gateway.discord.gg",
    "cdn.discordapp.com",
    "media.discordapp.net",
    "updates.discord.com",
    "dl.discordapp.net",
    "discord-attachments-uploads-prd.storage.googleapis.com",
)


def unsafe_direct_domains(domains, bad_hosts):
    """Domains a bad verdict reaches: PAC matches by suffix, so `discordapp.com` is as bad as its failing `cdn.`."""
    bad = [host_key(item) for item in (bad_hosts or ())]
    out = set()
    for domain in domains or ():
        key = host_key(domain)
        if key and any(b == key or b.endswith("." + key) for b in bad if b):
            out.add(key)
    return out


def candidate_hosts(*lists):
    """Hosts worth probing, in priority order and without duplicates: every list in the order given."""
    seen = set()
    out = []
    for items in lists:
        for item in items or ():
            key = host_key(item)
            if key and key not in seen:
                seen.add(key)
                out.append(key)
    return out


class VerdictStore(object):
    """host -> verdict with streaks and probe schedule; JSON on disk, clock injectable."""

    def __init__(self, path="", clock=time.time):
        self.path = str(path or "")
        self._clock = clock
        self.entries = {}
        self.dirty = False

    # -- persistence ------------------------------------------------------------------------

    def load(self):
        self.entries = {}
        if not self.path:
            return self
        try:
            with open(self.path, "rb") as handle:
                data = json.loads(handle.read(4 * 1024 * 1024).decode("utf-8-sig"))
        except (OSError, ValueError):
            return self
        rows = data.get("hosts") if isinstance(data, dict) else None
        if not isinstance(rows, dict):
            return self
        for host, row in rows.items():
            key = host_key(host)
            if key and isinstance(row, dict):
                self.entries[key] = _clean(row)
        return self

    def save(self):
        """Atomic write; False when it could not be written (verdicts are advisory)."""
        if not self.path:
            return False
        payload = json.dumps({"version": 1, "hosts": self.entries}, separators=(",", ":"), sort_keys=True)
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(tmp, self.path)
        except OSError:
            return False
        self.dirty = False
        return True

    # -- queries ----------------------------------------------------------------------------

    def state(self, host, now=None):
        """DIRECT_OK, DIRECT_BAD or UNKNOWN (no verdict, or one that has expired)."""
        entry = self.entries.get(host_key(host))
        if not entry or not entry["state"]:
            return UNKNOWN
        now = self._clock() if now is None else now
        ttl = OK_TTL_SEC if entry["state"] == DIRECT_OK else BAD_TTL_SEC
        if now - entry["at"] > ttl:
            return UNKNOWN
        return entry["state"]

    def bad_hosts(self, now=None):
        """The hosts with a fresh DIRECT_BAD verdict (an expired one is UNKNOWN, not bad)."""
        now = self._clock() if now is None else now
        return sorted(h for h in self.entries if self.state(h, now) == DIRECT_BAD)

    def direct_ok_hosts(self, now=None, limit=MAX_PAC_HOSTS):
        """The hosts that currently open directly, most recently confirmed first, capped for the PAC."""
        now = self._clock() if now is None else now
        rows = [(e["at"], h) for h, e in self.entries.items() if self.state(h, now) == DIRECT_OK]
        rows.sort(reverse=True)
        return sorted(h for _at, h in rows[:max(0, int(limit))])

    def due(self, hosts, now=None, limit=10):
        """Up to `limit` of `hosts` whose probe is due, in the order `hosts` lists them (it is the priority).

        Never-probed and overdue hosts compete on position alone. «Never probed first» used to put the
        whole of main.txt ahead of the YouTube verdicts that had been overdue for hours, so after a
        restart the names that matter most waited longest (~30 min at one probe per 5 s)."""
        now = self._clock() if now is None else now
        ordered, seen = [], set()
        for raw in hosts or ():
            host = host_key(raw)
            if not host or host in seen:
                continue
            seen.add(host)
            entry = self.entries.get(host)
            if entry is None or entry["next"] <= now:
                ordered.append(host)
        return ordered[:max(0, int(limit))]

    # -- updates ----------------------------------------------------------------------------

    def record(self, host, ok, why="", now=None):
        """Book one probe (`ok` True/False). Returns True when the host's EFFECTIVE verdict changed."""
        key = host_key(host)
        if not key or ok is None:
            return False
        now = self._clock() if now is None else now
        before = self.state(key, now)
        entry = self.entries.get(key) or _clean({})
        entry["why"] = str(why or "")[:24]
        if ok:
            entry["streak_bad"] = 0
            entry["streak_ok"] += 1
            if entry["state"] == DIRECT_OK:
                entry["at"] = now
                entry["next"] = now + OK_TTL_SEC * 0.8
            elif entry["streak_ok"] >= 2:
                entry["state"] = DIRECT_OK
                entry["at"] = now
                entry["next"] = now + OK_TTL_SEC * 0.8
            else:
                entry["next"] = now + CONFIRM_GAP_SEC  # one clean probe is not enough: look again soon
        else:
            entry["streak_ok"] = 0
            entry["streak_bad"] += 1
            if entry["state"] == DIRECT_BAD:
                entry["at"] = now
                step = min(entry["streak_bad"] - 1, len(BAD_BACKOFF_SEC) - 1)
                entry["next"] = now + BAD_BACKOFF_SEC[step]
            elif entry["streak_bad"] >= 2 or entry["state"] != DIRECT_OK:
                entry["state"] = DIRECT_BAD
                entry["at"] = now
                entry["next"] = now + BAD_BACKOFF_SEC[0]
            else:
                entry["next"] = now + RETRY_BAD_GAP_SEC  # a working host failed once: confirm before demoting
        self.entries[key] = entry
        self.dirty = True
        self._trim()
        return before != self.state(key, now)

    def defer(self, host, seconds=DEFER_SEC, why="", now=None):
        """A probe could not judge `host`: no verdict changes, but it is not due again for `seconds`."""
        key = host_key(host)
        if not key:
            return False
        now = self._clock() if now is None else now
        entry = self.entries.get(key) or _clean({})
        entry["next"] = now + float(seconds)
        entry["why"] = str(why or "")[:24]
        self.entries[key] = entry
        self.dirty = True
        self._trim()
        return True

    def forget_except(self, hosts):
        """Drop verdicts of hosts that left every list (the file follows the lists, not the other way)."""
        keep = {host_key(h) for h in hosts or ()}
        gone = [h for h in self.entries if h not in keep]
        for host in gone:
            del self.entries[host]
        if gone:
            self.dirty = True
        return len(gone)

    def _trim(self):
        extra = len(self.entries) - MAX_ENTRIES
        if extra > 0:
            for _at, host in sorted((e["at"], h) for h, e in self.entries.items())[:extra]:
                del self.entries[host]


def _clean(row):
    def num(name):
        try:
            return float(row.get(name) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    def count(name):
        try:
            return max(0, int(row.get(name) or 0))
        except (TypeError, ValueError):
            return 0

    state = row.get("state") if row.get("state") in (DIRECT_OK, DIRECT_BAD) else ""
    return {"state": state, "at": num("at"), "next": num("next"), "streak_ok": count("streak_ok"),
            "streak_bad": count("streak_bad"), "why": str(row.get("why") or "")[:24]}
