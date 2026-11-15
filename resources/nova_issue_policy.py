"""When and how gently Nova replaces its built-in profiles with its own.

Parity with Nova Android D45 (owner 2026-11-14), written for a PC:

* **Once per app version.** An install that has no own set issues one; a set stamped with this
  version or a newer one is never touched automatically; a set from an older version, or one with
  no stamp at all (built before this module existed), is renewed exactly once after the update.
  The stamp is written only when a run really produced a set (`record_attempt(..., ok=True)`).
  Manual «Перевыпустить» ignores all of this and stamps on success.
* **Back-off, not hammering.** After a failed automatic attempt: 1 h, 3 h, 12 h, then daily. A
  renewal of an existing set gives up after `RENEW_ATTEMPT_CAP` automatic attempts per version
  (the button remains); a missing set never stops asking, but never faster than daily.
* **A gate for background work.** Nothing is issued while the PC is busy: the network is carrying
  traffic, the CPU is loaded, or a laptop is on a low battery / battery saver. A closed gate is a
  deferral, not a failure -- the 5-minute heartbeat of `VpnSlotsRuntime` asks again. Steps that
  do issue are spaced `STEP_SPACING_SEC` apart so two registrations never hit the uplink together.

Pure decisions live here and are unit-tested; the readers at the bottom talk to Windows through
ctypes and return None where a number is unavailable (an unreadable sensor never blocks forever).
"""

import ctypes
import json
import os
import re
import threading
import time

__all__ = [
    "LEDGER_FILENAME", "KIND_WARP", "KIND_PROTON", "KINDS",
    "BACKOFF_SEC", "RENEW_ATTEMPT_CAP", "STEP_SPACING_SEC", "MIN_USEFUL_WARP_PROFILES",
    "GATE_SAMPLE_SEC", "GATE_MAX_BYTES_PER_SEC", "GATE_MAX_CPU_BUSY", "GATE_MIN_BATTERY_PCT",
    "version_key", "decide", "apply_attempt", "load", "record_attempt",
    "evaluate_gate", "check_gate",
]

LEDGER_FILENAME = "profile-issue-ledger.json"
TEMP_DIRNAME = "temp"
_LEDGER_VERSION = 1

KIND_WARP = "warp"
KIND_PROTON = "proton"
KINDS = (KIND_WARP, KIND_PROTON)

# After the Nth failed automatic attempt within one version wait BACKOFF_SEC[N-1] (the last
# value repeats): 1 h, 3 h, 12 h, then daily.
BACKOFF_SEC = (3600.0, 3 * 3600.0, 12 * 3600.0, 24 * 3600.0)
RENEW_ATTEMPT_CAP = 4
# Two background issuers never start together (Android G268 found them waking in the same second).
STEP_SPACING_SEC = 30.0
# A WARP set thinner than this is written but not stamped: it must not count as "replaced".
MIN_USEFUL_WARP_PROFILES = 8

GATE_SAMPLE_SEC = 3.0
# ~0.8 Mbit/s over the physical adapters in both of two consecutive samples: somebody is using the
# channel. Counted on real adapters only, so Nova's own tunnel does not double it.
GATE_MAX_BYTES_PER_SEC = 100 * 1024
GATE_MAX_CPU_BUSY = 0.70
GATE_MIN_BATTERY_PCT = 20

_LOCK = threading.Lock()


# --- version rule --------------------------------------------------------------------------------
def version_key(text):
    """`"1.46.2"` -> (1, 46, 2); anything without digits -> (0,). Compared as tuples."""
    numbers = re.findall(r"\d+", str(text or ""))
    return tuple(int(n) for n in numbers[:4]) or (0,)


def _entry(ledger, kind):
    kinds = ledger.get("kinds") if isinstance(ledger, dict) else None
    entry = kinds.get(kind) if isinstance(kinds, dict) else None
    return entry if isinstance(entry, dict) else {}


def _attempts_this_version(entry, version):
    if str(entry.get("attempt_version") or "") != str(version):
        return 0
    try:
        return max(0, int(entry.get("attempts") or 0))
    except (TypeError, ValueError):
        return 0


def _minutes(seconds):
    return max(1, int(-(-float(seconds) // 60)))


def decide(ledger, kind, *, set_present, current_version, now=None):
    """(issue?, Russian reason): may an automatic run issue / renew this kind of set now.

    Only the ledger's own rule (version + back-off); a kind's other guards (a cooldown after
    Proton's CAPTCHA, a key already registered but not written) stay with its module.
    """
    now = time.time() if now is None else float(now)
    entry = _entry(ledger, kind)
    stamp = str(entry.get("issued") or "")
    if set_present and stamp and version_key(stamp) >= version_key(current_version):
        return False, f"набор выпущен версией {stamp} — дальше только вручную"

    attempts = _attempts_this_version(entry, current_version)
    if set_present and attempts >= RENEW_ATTEMPT_CAP:
        return False, f"замена набора не удалась {attempts} раза за версию — только вручную"
    try:
        last = float(entry.get("last_attempt") or 0.0)
    except (TypeError, ValueError):
        last = 0.0
    if attempts > 0 and last > 0:
        wait = BACKOFF_SEC[min(attempts, len(BACKOFF_SEC)) - 1]
        if 0 <= now - last < wait:
            return False, f"прошлая попытка не удалась — ждём ещё {_minutes(wait - (now - last))} мин"

    if not set_present:
        return True, "своих профилей ещё нет"
    if stamp:
        return True, f"набор выпущен версией {stamp}, текущая {current_version} — обновляем один раз"
    return True, f"набор без отметки версии, текущая {current_version} — обновляем один раз"


def apply_attempt(ledger, kind, version, ok, now=None):
    """The ledger after one attempt: success stamps the version, failure counts toward the back-off."""
    now = time.time() if now is None else float(now)
    ledger = dict(ledger) if isinstance(ledger, dict) else {}
    kinds = dict(ledger.get("kinds")) if isinstance(ledger.get("kinds"), dict) else {}
    entry = dict(_entry(ledger, kind))
    if ok:
        entry.update({"issued": str(version), "attempt_version": str(version), "attempts": 0,
                      "last_attempt": now})
    else:
        entry.update({"attempt_version": str(version),
                      "attempts": _attempts_this_version(entry, version) + 1,
                      "last_attempt": now})
    kinds[kind] = entry
    ledger["version"] = _LEDGER_VERSION
    ledger["kinds"] = kinds
    return ledger


# --- persistence (temp/profile-issue-ledger.json: keyless, declared in nova_temp_layout) -----------
def _path(base_dir):
    return os.path.join(base_dir, TEMP_DIRNAME, LEDGER_FILENAME)


def load(base_dir):
    """The ledger, {} when absent or unreadable (an unreadable ledger means "unstamped")."""
    try:
        with open(_path(base_dir), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def record_attempt(base_dir, kind, version, ok, now=None):
    """Read-modify-write under a lock; returns the new ledger. A write fault is swallowed:
    losing a stamp costs one more gentle renewal, not a crash of the issuing pipeline."""
    with _LOCK:
        ledger = apply_attempt(load(base_dir), kind, version, ok, now)
        path = _path(base_dir)
        tmp = path + ".tmp"
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(ledger, handle, ensure_ascii=False, indent=1)
            os.replace(tmp, path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return ledger


# --- gate ----------------------------------------------------------------------------------------
def evaluate_gate(*, net_rates=(), cpu_busy=(), ac_online=None, battery_pct=None, battery_saver=False):
    """(open?, Russian reason). `net_rates` bytes/s and `cpu_busy` 0..1 are one value per sample
    interval; the gate opens only when EVERY interval was calm. None/empty = not measured = calm."""
    if ac_online is False:
        if battery_saver:
            return False, "включена экономия заряда"
        if battery_pct is not None and battery_pct < GATE_MIN_BATTERY_PCT:
            return False, f"заряд батареи {battery_pct}%"
    rates = [r for r in net_rates if r is not None]
    if rates and min(rates) > GATE_MAX_BYTES_PER_SEC:
        # `min`: a single burst between two quiet samples (a page loading) must not hold the
        # gate shut; sustained load shows in both.
        return False, f"канал занят: {int(min(rates) // 1024)} КБ/с"
    busy = [c for c in cpu_busy if c is not None]
    if busy and min(busy) > GATE_MAX_CPU_BUSY:
        return False, f"процессор занят на {int(min(busy) * 100)}%"
    return True, "канал и процессор свободны"


def check_gate(*, should_stop=None, sleep=time.sleep, read_net=None, read_cpu=None, read_power=None,
               clock=time.monotonic):
    """Sample the PC for two intervals and decide. Blocks ~2 * GATE_SAMPLE_SEC on a worker thread.

    The readers are injectable for tests; the defaults are the Windows ones below.
    """
    read_net = read_net or read_net_bytes
    read_cpu = read_cpu or read_cpu_times
    read_power = read_power or read_power_status
    stop = should_stop or (lambda: False)

    ac, pct, saver = read_power()
    samples = []
    for index in range(3):
        if index:
            sleep(GATE_SAMPLE_SEC)
            if stop():
                return False, "Nova закрывается"
        samples.append((clock(), read_net(), read_cpu()))
    net_rates, cpu_busy = [], []
    for (t0, n0, c0), (t1, n1, c1) in zip(samples, samples[1:]):
        elapsed = max(t1 - t0, 0.001)
        net_rates.append(None if n0 is None or n1 is None else max(0, n1 - n0) / elapsed)
        cpu_busy.append(_cpu_busy_fraction(c0, c1))
    return evaluate_gate(net_rates=net_rates, cpu_busy=cpu_busy, ac_online=ac, battery_pct=pct,
                         battery_saver=saver)


def _cpu_busy_fraction(before, after):
    if before is None or after is None:
        return None
    idle = after[0] - before[0]
    total = (after[1] - before[1]) + (after[2] - before[2])  # kernel time includes idle
    if total <= 0:
        return None
    return min(1.0, max(0.0, 1.0 - idle / total))


# --- Windows readers (ctypes; None when unavailable) ----------------------------------------------
_REAL_ADAPTER_TYPES = {6, 23, 71, 243, 244}  # ethernet, ppp, wi-fi, wwan
_VIRTUAL_MARKERS = ("tap", "wintun", "wireguard", "tunnel", "loopback", "virtual", "vethernet",
                    "vmware", "amnezia", "nova", "warp", "vpn", "hyper-v", "bluetooth")


class _IfRow(ctypes.Structure):
    _fields_ = [
        ("wszName", ctypes.c_wchar * 256), ("dwIndex", ctypes.c_uint32), ("dwType", ctypes.c_uint32),
        ("dwMtu", ctypes.c_uint32), ("dwSpeed", ctypes.c_uint32), ("dwPhysAddrLen", ctypes.c_uint32),
        ("bPhysAddr", ctypes.c_ubyte * 8), ("dwAdminStatus", ctypes.c_uint32),
        ("dwOperStatus", ctypes.c_uint32), ("dwLastChange", ctypes.c_uint32),
        ("dwInOctets", ctypes.c_uint32), ("dwInUcastPkts", ctypes.c_uint32),
        ("dwInNUcastPkts", ctypes.c_uint32), ("dwInDiscards", ctypes.c_uint32),
        ("dwInErrors", ctypes.c_uint32), ("dwInUnknownProtos", ctypes.c_uint32),
        ("dwOutOctets", ctypes.c_uint32), ("dwOutUcastPkts", ctypes.c_uint32),
        ("dwOutNUcastPkts", ctypes.c_uint32), ("dwOutDiscards", ctypes.c_uint32),
        ("dwOutErrors", ctypes.c_uint32), ("dwOutQLen", ctypes.c_uint32),
        ("dwDescrLen", ctypes.c_uint32), ("bDescr", ctypes.c_ubyte * 256),
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]


class _PowerStatus(ctypes.Structure):
    _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte),
                ("BatteryLifePercent", ctypes.c_ubyte), ("SystemStatusFlag", ctypes.c_ubyte),
                ("BatteryLifeTime", ctypes.c_uint32), ("BatteryFullLifeTime", ctypes.c_uint32)]


_NET_WRAP = 1 << 32
_net_last = {}  # (index, in/out) -> last raw counter, to unwrap the 32-bit values


def read_net_bytes():
    """Cumulative in+out octets of the real adapters (unwrapped 32-bit counters), or None."""
    try:
        iphlpapi = ctypes.windll.iphlpapi
        size = ctypes.c_ulong(0)
        iphlpapi.GetIfTable(None, ctypes.byref(size), False)
        if not size.value:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        if iphlpapi.GetIfTable(buffer, ctypes.byref(size), False) != 0:
            return None
        count = ctypes.c_uint32.from_buffer(buffer).value
        row_size = ctypes.sizeof(_IfRow)
        total = 0
        for index in range(count):
            offset = 4 + index * row_size
            if offset + row_size > size.value:
                break
            row = _IfRow.from_buffer_copy(buffer, offset)
            if row.dwType not in _REAL_ADAPTER_TYPES or row.dwOperStatus not in (4, 5):
                continue
            descr = bytes(row.bDescr[:min(row.dwDescrLen, 256)]).decode("latin-1", "replace").lower()
            if any(marker in descr for marker in _VIRTUAL_MARKERS):
                continue
            for direction, raw in (("in", row.dwInOctets), ("out", row.dwOutOctets)):
                key = (row.dwIndex, direction)
                last = _net_last.get(key)
                _net_last[key] = raw
                base = _net_totals.get(key, 0)
                if last is not None and raw < last:
                    base += _NET_WRAP
                _net_totals[key] = base
                total += base + raw
        return total
    except (OSError, AttributeError, ValueError):
        return None


_net_totals = {}


def read_cpu_times():
    """(idle, kernel, user) in 100 ns units, or None."""
    try:
        idle, kernel, user = _FileTime(), _FileTime(), _FileTime()
        if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel),
                                                     ctypes.byref(user)):
            return None
        return tuple((t.hi << 32) | t.lo for t in (idle, kernel, user))
    except (OSError, AttributeError):
        return None


def read_power_status():
    """(on_ac: bool|None, battery_percent: int|None, battery_saver: bool); (None, None, False) if unknown."""
    try:
        status = _PowerStatus()
        if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
            return None, None, False
        ac = {0: False, 1: True}.get(status.ACLineStatus)
        pct = None if status.BatteryLifePercent == 255 else int(status.BatteryLifePercent)
        return ac, pct, bool(status.SystemStatusFlag & 1)
    except (OSError, AttributeError):
        return None, None, False
