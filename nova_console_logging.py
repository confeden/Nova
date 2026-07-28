import os
import threading
import time


class SessionConsoleLogWriter:
    def __init__(self, path, flush_interval=1.5, max_buffer_bytes=16384):
        self.path = path
        self.flush_interval = flush_interval
        self.max_buffer_bytes = max_buffer_bytes
        self._lock = threading.Lock()
        self._buffer = []
        self._buffer_bytes = 0
        self._stop_event = threading.Event()
        self._enabled = False
        self._thread = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write("")
            self._enabled = True
            self._thread = threading.Thread(target=self._flush_worker, daemon=True)
            self._thread.start()
        except Exception:
            self._enabled = False

    def write(self, text):
        if not self._enabled or not text:
            return
        if not isinstance(text, str):
            try:
                text = str(text)
            except Exception:
                return
        try:
            size = len(text.encode("utf-8", errors="ignore"))
        except Exception:
            size = len(text)
        should_flush = False
        with self._lock:
            self._buffer.append(text)
            self._buffer_bytes += size
            if self._buffer_bytes >= self.max_buffer_bytes:
                should_flush = True
        if should_flush:
            self.flush()

    def flush(self):
        if not self._enabled:
            return
        with self._lock:
            if not self._buffer:
                return
            data = "".join(self._buffer)
            self._buffer.clear()
            self._buffer_bytes = 0
        try:
            with open(self.path, "a", encoding="utf-8", buffering=65536, newline="") as f:
                f.write(data)
        except Exception:
            pass

    def close(self):
        try:
            self._stop_event.set()
        except Exception:
            pass
        self.flush()

    def _flush_worker(self):
        while not self._stop_event.wait(self.flush_interval):
            self.flush()


def get_default_session_console_log_path():
    return os.path.join(
        os.environ.get("TEMP", os.path.join(os.getcwd(), "temp")),
        "nova_console.log",
    )


def format_session_console_log_lines(text):
    if text is None:
        return ""
    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return ""
    parts = text.splitlines(True)
    if not parts:
        parts = [text]
    out = []
    for part in parts:
        if part == "":
            continue
        line = part.rstrip("\r\n")
        nl = part[len(line):]
        if line:
            out.append(f"{time.strftime('%H:%M:%S')} {line}{nl or os.linesep}")
        else:
            out.append(nl or os.linesep)
    return "".join(out)
