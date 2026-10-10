"""Services and processes Nova shares a name with, and how to leave them as Nova found them.

Two Windows service names are not Nova's alone:

* ``CloudflareWARP`` is the official Cloudflare One / WARP client's service. Up to 1.42 Nova
  registered its bundled warp-svc.exe under that very name and ``sc config``-ed an existing one
  onto its own binary, so the official client could not start even with Nova closed (owner report,
  2026-10-06; on the owner's PC the official service pointed at ``Nova PC\\bin\\warp-svc.exe``).
  Nova's own service is ``NovaWARP`` now; a ``CloudflareWARP`` that points into Nova's ``bin`` is
  given back to the official binary when one is installed, deleted otherwise.
* ``WinDivert`` is the driver service every WinDivert 2.x program shares. The WinDivert DLL marks it
  for deletion right after loading, so it vanishes once the last handle closes; Nova's repair
  re-creates it pointing at Nova's own WinDivert64.sys and clears DeleteFlag, so the registration
  outlived Nova and other programs then started Nova's driver -- or a file an update or uninstall
  had removed. On exit Nova deletes it when, and only when, it points into Nova's ``bin``.

Processes are matched by full image path for the same reason: ``taskkill /IM warp-svc.exe`` also
killed the official client's daemon.
"""

import os
import subprocess
import time

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

NOVA_WARP_SERVICE = "NovaWARP"
NOVA_WARP_DISPLAY_NAME = "Nova WARP"
OFFICIAL_WARP_SERVICE = "CloudflareWARP"
OFFICIAL_WARP_DISPLAY_NAME = "Cloudflare WARP"
WINDIVERT_SERVICE = "WinDivert"


def _log(log_func, text):
    if log_func:
        try:
            log_func(text)
        except Exception:
            pass


def run_sc(*args, timeout=8):
    try:
        result = subprocess.run(["sc", *args], capture_output=True, timeout=timeout,
                                creationflags=CREATE_NO_WINDOW)
        out = (result.stdout or b"").decode("cp866", "ignore") + (result.stderr or b"").decode("cp866", "ignore")
        return result.returncode, out
    except Exception as e:
        return -1, str(e)


def service_image_path(name):
    """The service's ImagePath as stored, or None when the service is not registered."""
    try:
        import winreg
        flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            rf"SYSTEM\CurrentControlSet\Services\{name}", 0, flags) as key:
            value = winreg.QueryValueEx(key, "ImagePath")[0]
        return str(value or "")
    except OSError:
        return None


def image_file_from_command(image_path):
    """The executable/driver file of an ImagePath: quotes, arguments and NT prefixes removed."""
    text = os.path.expandvars(str(image_path or "").strip())
    if text.startswith('"'):
        end = text.find('"', 1)
        text = text[1:end] if end > 0 else text[1:]
    else:
        lower = text.lower()
        for ext in (".exe", ".sys"):
            pos = lower.find(ext)
            if pos >= 0:
                text = text[:pos + len(ext)]
                break
    for prefix in ("\\??\\", "\\\\?\\"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    if text.lower().startswith("\\systemroot\\"):
        text = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), text[len("\\systemroot\\"):])
    return text


def path_in_dir(path, directory):
    if not path or not directory:
        return False
    try:
        p = os.path.normcase(os.path.abspath(path))
        d = os.path.normcase(os.path.abspath(directory)).rstrip("\\/")
        return p.startswith(d + os.sep)
    except Exception:
        return False


def service_points_into(name, directory):
    image = service_image_path(name)
    return image is not None and path_in_dir(image_file_from_command(image), directory)


def official_warp_svc_path():
    """warp-svc.exe of an installed official Cloudflare One / WARP client, or ""."""
    for base in (os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles"), r"C:\Program Files"):
        if base:
            candidate = os.path.join(base, "Cloudflare", "Cloudflare WARP", "warp-svc.exe")
            if os.path.isfile(candidate):
                return candidate
    return ""


def official_warp_service_running(nova_bin_dir):
    """True when a CloudflareWARP service that is not Nova's runs: its daemon owns the WARP pipe
    and ProgramData\\Cloudflare, so Nova's own warp-svc must not start beside it."""
    image = service_image_path(OFFICIAL_WARP_SERVICE)
    if image is None or path_in_dir(image_file_from_command(image), nova_bin_dir):
        return False
    rc, out = run_sc("query", OFFICIAL_WARP_SERVICE, timeout=5)
    return rc == 0 and "RUNNING" in out.upper()


def _wait_stopped(name, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, out = run_sc("query", name, timeout=4)
        up = out.upper()
        if rc != 0 or "STOPPED" in up:
            return True
        time.sleep(0.3)
    return False


def release_legacy_warp_service(nova_bin_dir, log_func=None):
    """Hand a CloudflareWARP registration that points into Nova's bin back to its owner.

    Returns "restored" (pointed at the official binary again), "deleted" (no official client
    installed), "failed", or "" (nothing of Nova's there -- the usual case, one registry read).
    """
    if not service_points_into(OFFICIAL_WARP_SERVICE, nova_bin_dir):
        return ""
    run_sc("stop", OFFICIAL_WARP_SERVICE, timeout=10)
    _wait_stopped(OFFICIAL_WARP_SERVICE, 8.0)
    official = official_warp_svc_path()
    if official:
        rc, out = run_sc("config", OFFICIAL_WARP_SERVICE, "binPath=", f'"{official}"', "start=", "auto",
                         "DisplayName=", OFFICIAL_WARP_DISPLAY_NAME, timeout=8)
        if rc == 0:
            # The official client normally runs its service from boot; start it now so the
            # client opens without a reboot. A failure here is the client's own business.
            run_sc("start", OFFICIAL_WARP_SERVICE, timeout=8)
            _log(log_func, "[WARP] Служба CloudflareWARP возвращена официальному клиенту Cloudflare (Nova использует свою NovaWARP).")
            return "restored"
        _log(log_func, f"[WARP] Не удалось вернуть службу CloudflareWARP официальному клиенту: {out.strip()}")
        return "failed"
    rc, out = run_sc("delete", OFFICIAL_WARP_SERVICE, timeout=8)
    if rc == 0 or "1072" in out:
        _log(log_func, "[WARP] Удалена старая служба CloudflareWARP от Nova (теперь служба Nova называется NovaWARP).")
        return "deleted"
    _log(log_func, f"[WARP] Не удалось удалить старую службу CloudflareWARP: {out.strip()}")
    return "failed"


def delete_windivert_if_nova(nova_bin_dir, log_func=None):
    """Delete the WinDivert service when it points at Nova's driver. Call after every Nova process
    holding a WinDivert handle is gone. If something else still holds one, the delete only marks
    the service, which is exactly what the WinDivert DLL itself does after loading the driver."""
    if not service_points_into(WINDIVERT_SERVICE, nova_bin_dir):
        return False
    run_sc("stop", WINDIVERT_SERVICE, timeout=6)
    _wait_stopped(WINDIVERT_SERVICE, 4.0)
    rc, out = run_sc("delete", WINDIVERT_SERVICE, timeout=6)
    ok = rc == 0 or "1072" in out
    if ok:
        _log(log_func, "[WinDivert] Регистрация драйвера Nova снята: другие программы с WinDivert установят свою.")
    else:
        _log(log_func, f"[WinDivert] Не удалось снять регистрацию драйвера: {out.strip()}")
    return ok


def kill_images_in_dir(image_names, directory):
    """Terminate processes whose image name is in image_names AND whose file lies in directory.
    Returns how many were terminated."""
    wanted = {str(n).lower() for n in image_names if n}
    if not wanted or not directory:
        return 0
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return 0

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.OpenProcess.restype = wintypes.HANDLE
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    INVALID = wintypes.HANDLE(-1).value

    pids = []
    snap = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if not snap or snap == INVALID:
        return 0
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() in wanted:
                pids.append(int(entry.th32ProcessID))
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)

    killed = 0
    for pid in pids:
        handle = kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            continue
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buf))
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                continue
            if path_in_dir(buf.value, directory) and kernel32.TerminateProcess(handle, 1):
                killed += 1
        finally:
            kernel32.CloseHandle(handle)
    return killed
