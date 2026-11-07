"""Bounded, observable exit work. No Tk calls or process-name-wide termination."""

import queue
import threading
import time
import os
import subprocess


def run_cleanup(tasks, timeout, log, required=(), required_timeout=None, failures=None):
    """Run independent cleanup once, sharing one deadline; return unfinished task names."""
    completed = queue.Queue()
    pending = set(tasks)

    def run(name, action):
        try:
            action()
        except Exception as error:
            if failures is not None:
                failures[name] = error
            log(f"[Выход] {name}: {error}")
        finally:
            completed.put(name)

    deadline = time.monotonic() + timeout
    required_deadline = deadline if required_timeout is None else deadline + max(0, required_timeout - timeout)
    required = set(required)
    for name, action in tasks.items():
        threading.Thread(target=run, args=(name, action), name="NovaExit-" + name, daemon=True).start()
    while pending:
        now = time.monotonic()
        if now >= deadline and not pending.intersection(required):
            break
        remaining = (required_deadline if now >= deadline else deadline) - now
        if remaining <= 0:
            break
        try:
            pending.discard(completed.get(timeout=remaining))
        except queue.Empty:
            if time.monotonic() >= required_deadline or not pending.intersection(required):
                break
    if pending:
        log("[Выход] Истёк срок очистки: " + ", ".join(sorted(pending)))
    return pending


def restart_command(argv, executable, *, compiled=False, debug=False, show_log=False):
    """Preserve launch mode and explicit flags without requiring an elevating nova.pyw import."""
    flags = ['--restart', '--force-instance']
    if show_log:
        flags.insert(0, '--show-log')
    if debug:
        flags.append('--debug')
    if '--dev-log' in argv:
        flags.append('--dev-log')
    script = os.path.abspath(argv[0])
    if compiled or script.lower().endswith('.exe'):
        return [script, *flags]
    return [os.path.abspath(executable), script, *flags]


def launch_restart(command, cwd):
    """Launch only after the final ownership sweep; no registration sleeps or shell fallback."""
    return subprocess.Popen(command, cwd=cwd, close_fds=True, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                            | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
