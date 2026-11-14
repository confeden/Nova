"""Client of `nova-engine gpu-serve`: the GPU background renderer (D51/D52).

The engine is a persistent child process. Commands go to its stdin as newline JSON; frames come back
through a named shared-memory mapping and one stdout line per frame. This module is pure logic with no
Tk import (I15), so pytest drives it against a fake engine. Nothing here touches a widget: the reader
thread only updates plain attributes (`pending_seq`, `state`) which the Tk polling loop reads.

Fallback contract: `start()` returns False with a logged reason when the engine is missing, has no GL
3.3, speaks an older protocol or does not answer within the timeout; a later crash flips `state` to
"failed" once. The caller then keeps (or returns to) the CPU renderer.
"""

import colorsys
import ctypes
import json
import logging
import mmap
import os
import queue
import struct
import subprocess
import tempfile
import threading
import time

import nova_native_render

PROTOCOL = 2
HEADER_SIZE = 32
MAX_SCENE_SIDE = 1440
START_TIMEOUT = 8.0
OVERLAY_PREFIX = "gpu_overlay_"
OVERLAY_SUFFIX = ".rgba"

TEXTURE_IDS = ("basalt", "marble", "wood", "sand", "grass", "cracks", "water", "ether", "aurora", "smoke",
               "starfield", "constellation", "slime", "rain", "lightning", "snow", "fractal", "fractal2", "maze", "matrix", "warp")

# nova_appearance.TEXTURES key -> engine texture id. 'none' and unknown names are absent on purpose:
# they stay on the CPU path. Crystals/shards were dropped by the owner (saved names map to cracks);
# splatter was renamed to rain (D51).
TEXTURE_MAP = {
    "basalt": "basalt", "marble": "marble", "wood": "wood", "sand": "sand", "grass": "grass",
    "cracks": "cracks", "water": "water", "ether": "ether", "smoke": "smoke", "starfield": "starfield",
    "constellation": "constellation",
    "slime": "slime", "rain": "rain", "lightning": "lightning", "snow": "snow", "fractal": "fractal",
    "fractal2": "fractal2", "warp": "warp", "aurora": "aurora", "maze": "maze",
    "matrix": "matrix", "crystals": "cracks", "shards": "cracks", "splatter": "rain",
}

DEFAULT_ACCENT = 31
_log = logging.getLogger(__name__)


# --- pure helpers -------------------------------------------------------------------------------

def gpu_texture(name):
    """Engine texture id for a Nova texture name, or None when it must stay on the CPU path."""
    return TEXTURE_MAP.get(name) if isinstance(name, str) else None


def scene_size(width, height):
    """Mirror of nova_gpu::scene_size: the longest side is capped at 1440, floor 64x48."""
    width, height = max(1, int(width)), max(1, int(height))
    k = min(1.0, MAX_SCENE_SIDE / max(width, height))
    return max(64, round(width * k)), max(48, round(height * k))


def frame_fits(width, height):
    """GPU frames must cover the canvas 1:1, so a surface beyond the cap stays on the CPU path."""
    return scene_size(width, height) == (int(width), int(height))


def pointer_to_lab(px, py, width, height):
    """Canvas pixels -> lab coordinates: height = 1, centred, y up."""
    width, height = max(1, width), max(1, height)
    return ((px / width) - 0.5) * (width / height), 0.5 - py / height


def accent_rgb(index):
    """Lab accent colour of hue index 0..63: HSL(i/64, .68, .56)."""
    red, green, blue = colorsys.hls_to_rgb((int(index) % 64) / 64.0, 0.56, 0.68)
    return round(red * 255), round(green * 255), round(blue * 255)


def nearest_accent_index(color):
    """Hue index (hue = i/64*360 degrees) nearest to a '#RRGGBB' theme accent; grey falls to teal."""
    try:
        text = color.strip().lstrip("#")
        red, green, blue = (int(text[i:i + 2], 16) / 255.0 for i in (0, 2, 4))
    except (AttributeError, ValueError, IndexError):
        return DEFAULT_ACCENT
    hue, light, saturation = colorsys.rgb_to_hls(red, green, blue)
    if saturation < 0.12 or light < 0.04 or light > 0.96:
        return DEFAULT_ACCENT
    return round(hue * 64) % 64


def intensity_from_pref(value):
    """texture_intensity 0..0.6 (default 0.30) -> lab 0..100: the old default lands on the lab's 90."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 90.0
    if value != value:
        return 90.0
    value = min(0.6, max(0.0, value))
    if value <= 0.30:
        return value / 0.30 * 90.0
    return 90.0 + (value - 0.30) / 0.30 * 10.0


def seed_from_variant(variant):
    """Different variant -> different seed; kept small because the shaders take an f32."""
    try:
        return float(int(variant) % 100003)
    except (TypeError, ValueError):
        return 0.0


class _DevMode(ctypes.Structure):
    _fields_ = [("dmDeviceName", ctypes.c_wchar * 32), ("dmSpecVersion", ctypes.c_ushort),
                ("dmDriverVersion", ctypes.c_ushort), ("dmSize", ctypes.c_ushort),
                ("dmDriverExtra", ctypes.c_ushort), ("dmFields", ctypes.c_ulong),
                ("dmUnion", ctypes.c_short * 8), ("dmColor", ctypes.c_short),
                ("dmDuplex", ctypes.c_short), ("dmYResolution", ctypes.c_short),
                ("dmTTOption", ctypes.c_short), ("dmCollate", ctypes.c_short),
                ("dmFormName", ctypes.c_wchar * 32), ("dmLogPixels", ctypes.c_ushort),
                ("dmBitsPerPel", ctypes.c_ulong), ("dmPelsWidth", ctypes.c_ulong),
                ("dmPelsHeight", ctypes.c_ulong), ("dmDisplayFlags", ctypes.c_ulong),
                ("dmDisplayFrequency", ctypes.c_ulong), ("dmICMMethod", ctypes.c_ulong),
                ("dmICMIntent", ctypes.c_ulong), ("dmMediaType", ctypes.c_ulong),
                ("dmDitherType", ctypes.c_ulong), ("dmReserved1", ctypes.c_ulong),
                ("dmReserved2", ctypes.c_ulong), ("dmPanningWidth", ctypes.c_ulong),
                ("dmPanningHeight", ctypes.c_ulong)]


def monitor_refresh_hz():
    """Primary monitor refresh rate in Hz (EnumDisplaySettingsW); 60 when it cannot be read."""
    try:
        mode = _DevMode()
        mode.dmSize = ctypes.sizeof(_DevMode)
        if ctypes.windll.user32.EnumDisplaySettingsW(None, -1, ctypes.byref(mode)):
            hz = int(mode.dmDisplayFrequency)
            if 24 <= hz <= 500:
                return hz
    except (AttributeError, OSError, ValueError):
        pass
    return 60


_hires_users = 0


def hires_timer(enable):
    """Ask Windows for a 1 ms timer tick while animating (ref-counted). Tk's `after` otherwise fires on the
    15.6 ms system tick, so 60 fps frames are shown at 14/24 ms alternately and the motion judders."""
    global _hires_users
    try:
        winmm = ctypes.windll.winmm
    except (AttributeError, OSError):
        return
    if enable:
        _hires_users += 1
        if _hires_users == 1:
            winmm.timeBeginPeriod(1)
    elif _hires_users > 0:
        _hires_users -= 1
        if _hires_users == 0:
            winmm.timeEndPeriod(1)


def target_fps(prefs=None, hz=None):
    """Frame rate for the Tk upload path: monitor rate capped at 60, 30 when the user asks for it.

    Appearance prefs have no frame-rate switches yet; the D51 defaults apply (limit off, sync on).
    """
    prefs = prefs or {}
    hz = monitor_refresh_hz() if hz is None else hz
    fps = min(60, max(24, int(hz))) if prefs.get("sync_monitor", True) is not False else 60
    if prefs.get("limit_30fps") is True:
        fps = min(fps, 30)
    return fps


def _pref_number(prefs, key, default, low, high):
    try:
        value = float(prefs.get(key, default))
    except (TypeError, ValueError):
        return default
    return default if value != value else min(high, max(low, value))


def config_from_prefs(prefs, accent_hex, fps):
    """The engine `config` fields for appearance prefs, or None when the texture is not a GPU one."""
    texture = gpu_texture(prefs.get("texture"))
    if texture is None:
        return None
    hue = prefs.get("accent_hue")
    accent = (int(hue) % 64 if isinstance(hue, (int, float)) and not isinstance(hue, bool)
              else nearest_accent_index(accent_hex))
    if "brightness" in prefs:
        intensity = _pref_number(prefs, "brightness", 90, 0, 100)
    else:
        intensity = intensity_from_pref(prefs.get("texture_intensity", 0.30))
    return {"texture": texture, "seed": seed_from_variant(prefs.get("variant", 0)),
            "accent": accent, "intensity": intensity, "glow": 100,
            "warp": _pref_number(prefs, "warp", 50, 0, 100),
            "speed": _pref_number(prefs, "speed", 100, 0, 300),
            "sat": _pref_number(prefs, "saturation", 100, 0, 200),
            "fps": int(fps), "anim": prefs.get("immersion") is True, "drift": True}


def parse_ready(line):
    """Validate the handshake line -> (info dict, None) or (None, reason)."""
    try:
        info = json.loads(line)
    except (TypeError, ValueError):
        return None, "непонятный ответ движка"
    if not isinstance(info, dict):
        return None, "непонятный ответ движка"
    if info.get("ready") is not True:
        return None, "движок отказался: %s" % (info.get("error") or "нет GL 3.3")
    if int(info.get("protocol") or 0) < PROTOCOL:
        return None, "старый протокол движка (%s)" % info.get("protocol")
    if not info.get("map") or int(info.get("size") or 0) <= HEADER_SIZE:
        return None, "движок не вернул область кадров"
    return info, None


def read_frame(buf, retries=3, _after_copy=None):
    """Copy the newest frame out of the mapping -> (seq, w, h, rgb bytes) or None.

    Layout: [u64 seq][u32 w][u32 h][u32 stride][3 x u32] then RGB8 top-down; the writer bumps seq last.
    The copy is accepted only when seq reads the same before and after it; a changed seq means the
    writer published meanwhile, so the copy is repeated. `_after_copy` is a test hook.
    """
    for _ in range(max(1, retries)):
        seq, width, height, stride = struct.unpack_from("<QIII", buf, 0)
        if seq == 0 or width == 0 or height == 0:
            return None
        if stride != width * 3 or HEADER_SIZE + stride * height > len(buf):
            return None
        data = bytes(buf[HEADER_SIZE:HEADER_SIZE + stride * height])
        if _after_copy is not None:
            _after_copy()
            _after_copy = None
        if struct.unpack_from("<Q", buf, 0)[0] == seq:
            return seq, width, height, data
    return None


# --- the engine process -----------------------------------------------------------------------

class GpuEngine:
    """One `nova-engine gpu-serve` child. Thread-safe command methods; never blocks the caller."""

    def __init__(self, exe=None, temp_dir=None, argv=None, on_frame=None, start_timeout=START_TIMEOUT):
        self._exe = exe
        self._argv = list(argv) if argv else None
        self.temp_dir = str(temp_dir) if temp_dir else tempfile.gettempdir()
        self.on_frame = on_frame
        self.start_timeout = start_timeout
        self.state = "new"            # new | starting | ready | failed | stopped
        self.reason = ""
        self.info = {}
        self.pending_seq = 0          # newest frame number announced on stdout
        self.frames = 0
        self.last_gpu_ms = None
        self.last_error = ""
        self._proc = None
        self._map = None
        self._commands = queue.SimpleQueue()
        self._hello = threading.Event()
        self._hello_line = None
        self._lock = threading.Lock()
        self._stopping = False
        self._overlays = []           # [(path, seq at send, time at send)]
        self._overlay_counter = 0
        self._starter = None

    # -- lifecycle --

    @property
    def ready(self):
        return self.state == "ready"

    @property
    def failed(self):
        return self.state == "failed"

    def _resolve_argv(self):
        if self._argv:
            return self._argv
        exe = self._exe or os.environ.get("NOVA_GPU_ENGINE") or nova_native_render.engine_path()
        if not exe or not os.path.isfile(str(exe)):
            return None
        return [str(exe), "gpu-serve"]

    def _fail(self, reason):
        with self._lock:
            first = self.state not in ("failed", "stopped")
            if self.state != "stopped":
                self.state = "failed"
            self.reason = self.reason or reason
        if first and not self._stopping:
            _log.warning("[GPU] Фон на видеокарте недоступен (%s); используется прежний расчёт.", reason)
        self._hello.set()

    def fail(self, reason):
        """The client gave up on the engine (any thread): log once, end the child, report `failed`."""
        self._fail(reason)
        self._kill()

    def start(self):
        """Spawn and handshake; blocks up to `start_timeout`, so never call it on the Tk thread."""
        with self._lock:
            if self.state != "new":
                return self.state == "ready"
            self.state = "starting"
        argv = self._resolve_argv()
        if argv is None:
            self._fail("nova-engine.exe не найден")
            return False
        try:
            self._proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
        except OSError as error:
            self._fail("не запустился: %s" % type(error).__name__)
            return False
        threading.Thread(target=self._read_loop, name="NovaGpuRead", daemon=True).start()
        threading.Thread(target=self._write_loop, name="NovaGpuWrite", daemon=True).start()
        if not self._hello.wait(self.start_timeout):
            self._fail("нет ответа за %.0f с" % self.start_timeout)
            self._kill()
            return False
        if self.state != "starting":
            self._kill()
            return False
        info, reason = parse_ready(self._hello_line)
        if info is None:
            self._fail(reason)
            self._kill()
            return False
        try:
            self._map = mmap.mmap(-1, int(info["size"]), tagname=str(info["map"]), access=mmap.ACCESS_READ)
        except (OSError, ValueError) as error:
            self._fail("нет доступа к области кадров: %s" % type(error).__name__)
            self._kill()
            return False
        self.info = info
        self._sweep_stale_overlays()
        with self._lock:
            if self.state == "starting":
                self.state = "ready"
        return self.state == "ready"

    def start_async(self):
        """Start on a helper thread; poll `state` from the UI."""
        if self._starter is None:
            self._starter = threading.Thread(target=self.start, name="NovaGpuStart", daemon=True)
            self._starter.start()

    def _kill(self):
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass

    def stop(self, wait=1.0):
        """Ask the engine to quit, close its stdin, then kill it after `wait` seconds.

        wait=0 returns at once (Tk thread): a daemon thread does the killing, and the engine ends on
        its own when stdin closes even if this process dies first.
        """
        with self._lock:
            already = self.state == "stopped"
            self.state = "stopped"
        self._stopping = True
        if not already:
            self._commands.put(json.dumps({"cmd": "quit"}) + chr(10))
            self._commands.put(None)
        proc = self._proc

        def finish():
            if proc is not None:
                try:
                    proc.wait(max(wait, 1.0))
                except subprocess.TimeoutExpired:
                    self._kill()
                except OSError:
                    pass
            self._drop_overlays(force=True)
            mapping, self._map = self._map, None
            if mapping is not None:
                try:
                    mapping.close()
                except (BufferError, ValueError):
                    pass

        if wait > 0:
            finish()
        else:
            threading.Thread(target=finish, name="NovaGpuStop", daemon=True).start()

    # -- threads --

    def _write_loop(self):
        proc = self._proc
        while True:
            line = self._commands.get()
            try:
                if line is None:
                    proc.stdin.close()
                    return
                proc.stdin.write(line.encode("utf-8"))
                proc.stdin.flush()
            except (OSError, ValueError):
                try:
                    proc.stdin.close()  # a broken pipe leaves unflushed bytes that would warn at GC
                except (OSError, ValueError):
                    pass
                return

    def _read_loop(self):
        proc = self._proc
        first = True
        try:
            for raw in proc.stdout:
                text = raw.decode("utf-8", "replace").strip()
                if not text:
                    continue
                if first:
                    first = False
                    self._hello_line = text
                    self._hello.set()
                    continue
                try:
                    message = json.loads(text)
                except ValueError:
                    continue
                if not isinstance(message, dict):
                    continue
                if "frame" in message:
                    self.last_gpu_ms = message.get("ms")
                    self.frames += 1
                    self.pending_seq = int(message["frame"])
                    self._drop_overlays()
                    callback = self.on_frame
                    if callback is not None:
                        callback(self.pending_seq)
                elif message.get("error"):
                    self.last_error = str(message["error"])[:200]
                    _log.warning("[GPU] Движок сообщил об ошибке: %s", self.last_error)
        except (OSError, ValueError):
            pass
        code = None
        try:
            code = proc.wait(2)
        except (subprocess.TimeoutExpired, OSError):
            pass
        if first:
            self._fail("движок завершился до готовности (код %s)" % code)
        elif not self._stopping:
            self._fail("движок завершился (код %s)" % code)

    # -- commands (all non-blocking: they only enqueue) --

    def _send(self, message):
        if self.state in ("failed", "stopped"):
            return False
        self._commands.put(json.dumps(message, separators=(",", ":"), allow_nan=False) + chr(10))
        return True

    def configure(self, **fields):
        """texture, seed, accent, intensity, glow, warp, fps, anim; only the given fields change."""
        return self._send(dict(fields, cmd="config"))

    def resize(self, width, height):
        return self._send({"cmd": "size", "w": int(width), "h": int(height)})

    def set_pointer(self, x, y, inside=True):
        return self._send({"cmd": "pointer", "x": round(float(x), 5), "y": round(float(y), 5), "in": bool(inside)})

    def set_paused(self, paused):
        return self._send({"cmd": "pause", "on": bool(paused)})

    @property
    def features(self):
        """Capabilities the running engine announced in `ready` (empty for an older engine)."""
        value = self.info.get("features") if isinstance(self.info, dict) else None
        return frozenset(value) if isinstance(value, (list, tuple)) else frozenset()

    def set_overlay(self, rgba, width, height, mask=None):
        """RGBA8 straight alpha, top-down, exactly the frame size. Goes through a temp file the engine
        reads once; the file is deleted after a later frame confirms it (or on stop).
        `mask` (w*h bytes, 255 = frosted glass) rides behind the RGBA plane when the engine can frost."""
        if len(rgba) != width * height * 4:
            raise ValueError("overlay has %d bytes, want %d" % (len(rgba), width * height * 4))
        if mask is not None and (len(mask) != width * height or "glass" not in self.features):
            mask = None
        if self.state in ("failed", "stopped"):
            return False
        with self._lock:
            self._overlay_counter += 1
            name = "%s%d_%d%s" % (OVERLAY_PREFIX, os.getpid(), self._overlay_counter, OVERLAY_SUFFIX)
        os.makedirs(self.temp_dir, exist_ok=True)
        path = os.path.join(self.temp_dir, name)
        with open(path, "wb") as stream:
            stream.write(rgba)
            if mask is not None:
                stream.write(mask)
        with self._lock:
            self._overlays.append((path, self.pending_seq, time.monotonic()))
        command = {"cmd": "overlay", "path": path, "w": int(width), "h": int(height)}
        if mask is not None:
            command["glass"] = True
        if not self._send(command):
            self._drop_overlays(force=True)
            return False
        return True

    def set_hot(self, rect, radius=0, reach=None):
        """Hover glow + shimmer on a plate (frame pixels, top-down); rect=None fades it out.
        False when this engine cannot do it, so the caller keeps its own hover look."""
        if "hot" not in self.features or self.state != "ready":
            return False
        if rect is None:
            return self._send({"cmd": "hot", "on": False})
        left, top, right, bottom = (round(float(v), 1) for v in rect)
        command = {"cmd": "hot", "on": True, "rect": [left, top, right, bottom], "radius": round(float(radius), 1)}
        if reach:
            command["reach"] = round(float(reach), 1)
        return self._send(command)

    def clear_overlay(self):
        return self._send({"cmd": "overlay", "clear": True})

    # -- frames --

    def latest_frame(self):
        mapping = self._map
        if mapping is None or self.state != "ready":
            return None
        try:
            return read_frame(mapping)
        except (ValueError, struct.error, BufferError):
            return None

    # -- overlay files --

    def _drop_overlays(self, force=False):
        """Delete overlay files the engine has certainly read: a frame arrived after they were sent and
        they are older than a second (a frame line already in the pipe may predate the command)."""
        now = time.monotonic()
        with self._lock:
            keep, doomed = [], []
            for entry in self._overlays:
                path, seq, sent = entry
                if force or (self.pending_seq > seq and now - sent > 1.0):
                    doomed.append(path)
                else:
                    keep.append(entry)
            if len(keep) > 16:
                doomed.extend(entry[0] for entry in keep[:-16])
                keep = keep[-16:]
            self._overlays = keep
        for path in doomed:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            except OSError:
                with self._lock:
                    self._overlays.append((path, self.pending_seq - 1, now - 2.0))

    def _sweep_stale_overlays(self):
        """Files left by a crashed run (older than a minute and not ours)."""
        try:
            names = os.listdir(self.temp_dir)
        except OSError:
            return
        mine = "%s%d_" % (OVERLAY_PREFIX, os.getpid())
        for name in names:
            if name.startswith(OVERLAY_PREFIX) and name.endswith(OVERLAY_SUFFIX) and not name.startswith(mine):
                path = os.path.join(self.temp_dir, name)
                try:
                    if time.time() - os.path.getmtime(path) > 60:
                        os.remove(path)
                except OSError:
                    pass
