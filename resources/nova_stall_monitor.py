"""Tells WHO blocked the Tk main thread, when it was blocked.

The connecting animation froze during a VPN connect and nothing recorded why: the boot timeline
measures worker phases, not the UI thread. A heartbeat on the Tk thread (`root.after`) stamps a clock;
a watcher thread notices a stamp that is older than the threshold and logs the main thread's own stack
at that moment, which names the call that holds it. Two numbers per report: the stall and the GIL lag
(how late a plain `time.sleep(0.005)` woke), because a stall with a busy interpreter is contention and
one without is a blocking call. Cost: one `after` every 50 ms and a thread that sleeps 100 ms; used
only in debug runs (`--debug`). No Nova globals (I15).
"""

import sys
import threading
import time
import traceback

__all__ = ["StallMonitor"]


class StallMonitor(object):
    def __init__(self, schedule, log, main_thread_id=None, threshold_sec=0.15, beat_ms=50,
                 clock=time.perf_counter, frames=None, depth=6):
        self._schedule = schedule            # schedule(ms, fn) on the Tk thread, e.g. root.after
        self._log = log
        self._main = main_thread_id or threading.main_thread().ident
        self._threshold = float(threshold_sec)
        self._beat_ms = int(beat_ms)
        self._clock = clock
        self._frames = frames or sys._current_frames
        self._depth = int(depth)
        self._last = clock()
        self._reported = None
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._last = self._clock()
        self._beat()
        self._thread = threading.Thread(target=self._watch, daemon=True, name="NovaStallMonitor")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _beat(self):
        if self._stop.is_set():
            return
        self._last = self._clock()
        try:
            self._schedule(self._beat_ms, self._beat)
        except Exception:
            self._stop.set()

    def check(self, now=None, gil_lag=0.0):
        """The report text when the Tk thread has been silent past the threshold, else None. Once per stall."""
        now = self._clock() if now is None else now
        stalled = now - self._last
        if stalled < self._threshold + self._beat_ms / 1000.0 or self._reported == self._last:
            return None
        self._reported = self._last
        frame = self._frames().get(self._main)
        stack = "".join(traceback.format_stack(frame)[-self._depth:]) if frame is not None else "(no frame)"
        return (f"[Stall] Tk-поток не отвечал {stalled * 1000:.0f} мс (опоздание GIL {gil_lag * 1000:.0f} мс). "
                f"Стек:\n{stack.rstrip()}")

    def _watch(self):
        while not self._stop.is_set():
            t0 = self._clock()
            time.sleep(0.1)
            gil_lag = max(0.0, self._clock() - t0 - 0.1)
            report = self.check(gil_lag=gil_lag)
            if report:
                try:
                    self._log(report)
                except Exception:
                    pass
