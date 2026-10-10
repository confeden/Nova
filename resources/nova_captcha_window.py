"""Proton human verification (Code 9001): a window where the owner solves the CAPTCHA.

Nova does not solve or dodge the challenge: it shows Proton's own CAPTCHA page to the person at the
keyboard and hands the answer back to the API, the way Proton's Windows client does
(ProtonVPN/win-app HumanVerificationOverlayView: WebView2 on `<api host>/core/v4/captcha?Token=`).

The page is `frame-ancestors https://vpn.proton.me` and talks only to its parent or an embedding
WebView, so a plain browser tab cannot give the answer back. With `ForceWebMessaging=1` it posts
`{"type": "pm_captcha", "token": "<HumanVerificationToken>:<answer>"}` to `window.parent`, which in a
top-level WebView2 window is the window itself; a listener injected after load catches it. That
whole string goes into `x-pm-human-verification-token` with `x-pm-human-verification-token-type:
captcha` on a repeat of the request that got 9001.

The window is pywebview (Edge WebView2) in a child process: pywebview needs the main thread, and
Nova's main thread is Tk. Frozen, the child is Nova.exe itself with CAPTCHA_FLAG (nova.pyw
dispatches it before anything else starts); from source, it is this file run by the same Python.
The child writes its answer into a JSON file named by the parent and exits.

The window must leave the machine by the same address as the API call that got 9001: Proton checks
the answer against the request, and the same CAPTCHA solved from another address ends in Code 12087
("CAPTCHA validation failed"). pywebview hard-codes WebView2's browser arguments and ignores the
WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS variable, so `--proxy-server` is put in by patching
EdgeChrome.__init__ (measured 2026-10-10: without it the page left through Nova's primary route,
104.28.x WARP, while the API call through Opera 1371 left as 77.111.x).
The window opens on the monitor of Nova's own window (`--anchor-pid`), not on the primary one.
"""

import argparse
import ctypes
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from urllib.parse import quote, urlsplit

CAPTCHA_FLAG = "--proton-captcha"
WINDOW_TITLE = "Nova — проверка Proton"
DEFAULT_TIMEOUT_S = 15 * 60

_LISTENER_JS = r"""
(function () {
  if (window.__novaHv) { return; }
  window.__novaHv = true;
  window.addEventListener('message', function (event) {
    var data = event.data;
    if (typeof data === 'string') {
      try { data = JSON.parse(data); } catch (e) { return; }
    }
    if (!data || data.type !== 'pm_captcha' || !data.token) { return; }
    var send = function () {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.done) {
        window.pywebview.api.done(String(data.token));
      } else {
        setTimeout(send, 100);
      }
    };
    send();
  });
})();
"""


def captcha_url(api_host, hv_token, dark=True):
    url = f"{str(api_host).rstrip('/')}/core/v4/captcha?Token={quote(str(hv_token), safe='')}&ForceWebMessaging=1"
    return url + ("&Dark=1" if dark else "")


def window_available():
    """True when the pywebview package is importable (frozen builds bundle it)."""
    try:
        return importlib.util.find_spec("webview") is not None
    except (ImportError, ValueError):
        return False


def browser_proxy(proxy_url):
    """A proxy WebView2 can use as `--proxy-server`, or None. Chromium takes no credentials on the
    command line, so a proxy with a login (the TLS relay) is not usable here."""
    if not proxy_url:
        return None
    try:
        parts = urlsplit(str(proxy_url))
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        if parts.username or parts.password:
            return None
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def _child_command(url, out_path, proxy):
    args = [CAPTCHA_FLAG, "--url", url, "--out", out_path, "--anchor-pid", str(os.getpid())]
    if proxy:
        args += ["--proxy", proxy]
    if getattr(sys, "frozen", False):
        return [sys.executable] + args
    return [sys.executable, os.path.abspath(__file__)] + args


def solve(api_host, hv_token, *, proxy=None, timeout_s=DEFAULT_TIMEOUT_S, log=None):
    """Show the CAPTCHA window and wait. Returns (token, reason): the token for the
    `x-pm-human-verification-token` header, or None and a Russian reason for the log."""
    if not window_available():
        return None, "окно капчи недоступно: в этой сборке нет pywebview"
    url = captcha_url(api_host, hv_token)
    fd, out_path = tempfile.mkstemp(prefix="nova_hv_", suffix=".json")
    os.close(fd)
    try:
        os.remove(out_path)
    except OSError:
        pass
    command = _child_command(url, out_path, browser_proxy(proxy))
    try:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        return None, f"окно капчи не открылось: {type(exc).__name__}"
    try:
        try:
            child.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)
            return None, f"капча не решена за {int(timeout_s // 60)} мин — окно закрыто"
        try:
            with open(out_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return None, "окно капчи закрыто без ответа"
        except (OSError, ValueError) as exc:
            return None, f"ответ окна капчи не прочитан: {type(exc).__name__}"
        token = str((data or {}).get("token") or "").strip()
        if token:
            return token, ""
        error = str((data or {}).get("error") or "").strip()
        return None, f"окно капчи не сработало: {error}" if error else "окно капчи закрыто без ответа"
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass


# --- child process -------------------------------------------------------------------------------

def _write_result(out_path, payload):
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    os.replace(tmp, out_path)


def _apply_browser_args(extra):
    """Appends Chromium switches to the ones pywebview's EdgeChrome sets itself (it overrides the
    environment variable). The source of __init__ is rewritten and re-executed in the module."""
    from webview.platforms import edgechromium
    marker = "'--disable-features=ElasticOverscroll'"
    source = textwrap.dedent(inspect.getsource(edgechromium.EdgeChrome.__init__))
    if marker not in source:
        raise RuntimeError("EdgeChrome.__init__ changed")
    namespace = dict(vars(edgechromium))
    exec(source.replace(marker, repr("--disable-features=ElasticOverscroll " + extra)), namespace)
    edgechromium.EdgeChrome.__init__ = namespace["__init__"]


def _anchor_position(pid, width, height):
    """(x, y) that centres a width x height window (device-independent px) on the monitor of
    Nova's window `pid` (its foreground window if it has the focus, else the first visible one),
    or None. Everything in physical pixels: the child is made per-monitor DPI aware first."""
    try:
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass
        found = []

        def _owned(hwnd):
            owner = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            return owner.value == pid

        fore = user32.GetForegroundWindow()
        if fore and _owned(fore):
            found.append(fore)
        else:
            proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

            def _enum(hwnd, _lparam):
                if user32.IsWindowVisible(hwnd) and not user32.IsIconic(hwnd) and _owned(hwnd)                         and user32.GetWindowTextLengthW(hwnd) > 0:
                    found.append(hwnd)
                return True

            user32.EnumWindows(proc(_enum), 0)
        if not found:
            return None
        hwnd = found[0]
        rect = wintypes.RECT()
        if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            return None
        scale = 1.0
        try:
            scale = max(1.0, user32.GetDpiForWindow(hwnd) / 96.0)
        except Exception:
            pass
        cx, cy = (rect.left + rect.right) // 2, (rect.top + rect.bottom) // 2
        x = int(cx - width * scale / 2)
        y = int(cy - height * scale / 2)

        class _MonitorInfo(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT),
                        ("rcWork", wintypes.RECT), ("dwFlags", wintypes.DWORD)]

        monitor = user32.MonitorFromWindow(hwnd, 2)  # MONITOR_DEFAULTTONEAREST
        info = _MonitorInfo()
        info.cbSize = ctypes.sizeof(info)
        if monitor and user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
            work = info.rcWork
            x = max(work.left, min(x, work.right - int(width * scale)))
            y = max(work.top, min(y, work.bottom - int(height * scale)))
        return x, y
    except Exception:
        return None


def run_window(url, out_path, proxy=None, anchor_pid=None):
    try:
        import webview
    except Exception as exc:  # the parent checks first; this is the frozen-build safety net
        _write_result(out_path, {"error": f"pywebview: {type(exc).__name__}"})
        return 2
    if proxy:
        try:
            _apply_browser_args(f"--proxy-server={proxy}")
        except Exception as exc:
            # Without the proxy the answer would come from another address than the request.
            _write_result(out_path, {"error": f"прокси для окна не применился: {type(exc).__name__}"})
            return 4

    state = {"window": None, "done": False}

    class _Api:
        def done(self, token):
            if state["done"]:
                return
            state["done"] = True
            _write_result(out_path, {"token": str(token)})
            window = state["window"]
            if window is not None:
                window.destroy()

    width, height = 520, 720
    position = _anchor_position(anchor_pid, width, height) if anchor_pid else None
    options = {"x": position[0], "y": position[1]} if position else {}
    window = webview.create_window(WINDOW_TITLE, url, js_api=_Api(), width=width, height=height,
                                   on_top=True, text_select=True, **options)
    state["window"] = window

    def _on_loaded():
        try:
            window.evaluate_js(_LISTENER_JS)
        except Exception:
            pass

    window.events.loaded += _on_loaded
    # One folder per run: WebView2 shares a browser process (and its switches) per user data folder.
    storage = os.path.join(tempfile.gettempdir(), f"nova_hv_webview_{os.getpid()}")
    try:
        webview.start(gui="edgechromium", private_mode=True, storage_path=storage)
    except Exception as exc:
        if not state["done"]:
            _write_result(out_path, {"error": f"{type(exc).__name__}: {str(exc)[:200]}"})
        return 3
    finally:
        shutil.rmtree(storage, ignore_errors=True)
    return 0


def main(argv):
    parser = argparse.ArgumentParser(prog="nova-captcha")
    parser.add_argument(CAPTCHA_FLAG, action="store_true")
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--anchor-pid", type=int, default=None)
    args, _unknown = parser.parse_known_args(argv)
    return run_window(args.url, args.out, args.proxy, args.anchor_pid)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
