"""Who holds a loopback port: tells a profile fault from a port the machine has already given away.

The reserve slot serves an imported profile on 127.0.0.1:1379 (SOCKS) and :1373 (HTTP CONNECT).
When another program owns one of them, nova-proxy exits at once with «loopback port is already
occupied» (exit code 2) -- for every profile it is given. Reading that as «the node is dead» walks
four healthy nodes per pass, writes four false failures into profile-stats.json and pauses the slot
for five minutes (2026-11-12: delegator-core.exe on 1380 made 9 of 50 live Nova nodes «fail»).
Stdlib only and free of Nova globals, so it is pinned by unit tests (I15).
"""

import csv
import io
import re
import subprocess

__all__ = ["parse_listeners", "holder_of", "port_holder", "describe_holder"]

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def parse_listeners(netstat_text):
    """`netstat -ano -p tcp` text -> {port: pid} of loopback/any-address LISTENING sockets."""
    out = {}
    for line in str(netstat_text or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP" or parts[3].upper() != "LISTENING":
            continue
        match = re.match(r"^(?:127\.0\.0\.1|0\.0\.0\.0|\[::1?\]|\[::\]):(\d+)$", parts[1])
        if not match:
            continue
        try:
            out.setdefault(int(match.group(1)), int(parts[4]))
        except ValueError:
            continue
    return out


def _image_name(pid, run):
    try:
        done = run(["tasklist", "/FI", f"PID eq {int(pid)}", "/FO", "CSV", "/NH"],
                   capture_output=True, text=True, timeout=5, creationflags=_NO_WINDOW)
    except Exception:
        return ""
    for row in csv.reader(io.StringIO(str(getattr(done, "stdout", "") or ""))):
        if len(row) >= 2 and row[1].strip() == str(int(pid)):
            return row[0].strip()
    return ""


def holder_of(port, netstat_text, image_of=None):
    """(pid, image name) of the listener on `port` in `netstat_text`; None when nobody listens."""
    pid = parse_listeners(netstat_text).get(int(port))
    if pid is None:
        return None
    name = image_of(pid) if callable(image_of) else ""
    return pid, str(name or "")


def port_holder(port, run=subprocess.run):
    """Live lookup: `(pid, image)` of what listens on `port`, None when free or unknown."""
    try:
        done = run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=8,
                   creationflags=_NO_WINDOW)
    except Exception:
        return None
    return holder_of(port, getattr(done, "stdout", ""), image_of=lambda pid: _image_name(pid, run))


def describe_holder(holder):
    """Human text for a log line: `delegator-core.exe (PID 19988)`."""
    if not holder:
        return "неизвестный процесс"
    pid, name = holder
    return f"{name or 'процесс'} (PID {pid})"
