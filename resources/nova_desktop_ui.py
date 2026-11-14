"""Desktop presentation of Nova Android's appearance system. No transport logic."""

import logging
import math
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageFilter, ImageFont, ImageTk

import nova_appearance
import nova_appearance_ui
import nova_glass
import nova_gpu


MIN_WIDTH = 560
MIN_HEIGHT = 420

CONNECTED_TEXT = "АКТИВНО : РАБОТАЕТ"
# Every label the connect sequence passes through before «АКТИВНО». The rings belong to all of them.
CONNECTING_TEXTS = frozenset({
    "ПОДКЛЮЧЕНИЕ", "ПЕРЕЗАПУСК", "ПЕРЕЗАПУСК ЯДРА...", "ЗАПУСК . . .", "Запуск...",
})
# A label that is not part of the sequence (ОСТАНОВЛЕНО while a profile switch stops and restarts the
# core, ГОТОВ К ЗАПУСКУ between two steps) ends the rings only when it outlasts this. The rings used
# to vanish for good on the first such flicker, and the connect then looked interrupted (2026-11-12).
STOP_GRACE_SEC = 2.5


class ConnectionStateTracker(object):
    """The scene's connection state from the status label, without flicker.

    `update(text)` is called with every label the status pill shows; `current()` is what the scene
    should draw now and can be asked again later: a non-connect label that follows «connecting»
    keeps the rings for `STOP_GRACE_SEC`, so a switch that stops and restarts the core in between
    does not cut the animation. «АКТИВНО : РАБОТАЕТ» is immediate, in both directions.
    """

    def __init__(self, clock=time.monotonic, held=None):
        self._clock = clock
        # `held()` is true while «Автоподключение» is off and the user has not pressed ПОДКЛЮЧИТЬ: the VPN
        # connects in the background, but that is not a connect the user asked for, so no rings.
        self._held = held or (lambda: False)
        self._text = ""
        self._state = "stopped"
        self._connecting_until = 0.0

    def update(self, text):
        text = str(text or "")
        now = self._clock()
        if self._held():
            self._state = "stopped"
            self._text = text
            return self._state
        if text == CONNECTED_TEXT:
            self._state = "connected"
        elif text in CONNECTING_TEXTS:
            self._state = "connecting"
            self._connecting_until = now + STOP_GRACE_SEC
        elif self._state == "connecting" and now < self._connecting_until:
            pass  # flicker: keep the rings until the grace is over (current() decides)
        else:
            self._state = "stopped"
        self._text = text
        return self.current()

    def current(self):
        if self._held():
            self._state = "stopped"
            return self._state
        if self._state == "connecting" and self._text not in CONNECTING_TEXTS \
                and self._clock() >= self._connecting_until:
            self._state = "stopped"
        return self._state


def connection_waves(size, origin, elapsed, accent, scale=1.0):
    """Nova Android TronRingsView: 8.2 s sweep, 48 dp radial trail, quadratic fade."""
    waves = Image.new("RGBA", size)
    cx, cy = origin
    reach = math.hypot(max(cx, size[0] - cx), max(cy, size[1] - cy))
    tail = 48 * scale
    for offset in (0, .34, .67):
        progress = (elapsed / 8.2 - offset) % 1
        radius = reach * progress
        peak = int((1 - progress) ** 2 * 190)
        if progress <= .001 or radius <= 1 or peak <= 2:
            continue
        outer = radius + tail * .22
        stops = (max(0, radius - tail), max(0, radius - tail * .45), radius, outer)
        levels = (0, int(peak * .18), peak, 0)
        lut = []
        for value in range(256):
            # Pillow reaches 255 at the square's corners, not at the circle's edge.
            distance = value / 255 * outer * math.sqrt(2)
            alpha = 0
            for start, end, low, high in zip(stops, stops[1:], levels, levels[1:]):
                if start <= distance <= end and end > start:
                    alpha = round(low + (high - low) * (distance - start) / (end - start))
                    break
            lut.append(alpha)
        extent = max(1, round(outer * 2))
        mask = Image.radial_gradient("L").point(lut).resize((extent, extent), Image.Resampling.BILINEAR)
        ring = Image.new("RGBA", mask.size, accent + (0,))
        ring.putalpha(mask)
        waves.alpha_composite(ring, (round(cx - outer), round(cy - outer)))
    return waves

def display_scale(widget):
    return max(1.0, round(float(widget.tk.call("tk", "scaling")) * 0.75, 2))


def _slot_geometry(width, scale):
    """Centres of: primary button, its «>», secondary button, its «>» -- mirrored about the middle."""
    button, nxt, inner, gap = round(112 * scale), round(34 * scale), round(6 * scale), round(16 * scale)
    unit = button + inner + nxt
    left = width / 2 - gap / 2 - unit
    right = width / 2 + gap / 2
    return (left + button / 2, left + button + inner + nxt / 2,
            right + button / 2, right + button + inner + nxt / 2)


def main_layout(width, height, scale=1.0):
    """One geometry source for the background, captions and live controls."""
    extra = max(0, height - MIN_HEIGHT * scale)
    hero_bottom = round(224 * scale + extra * 0.4)
    routes_top = hero_bottom + round(12 * scale)
    return {
        "hero": (round(20 * scale), round(72 * scale), width - round(20 * scale), hero_bottom),
        "routes": (round(20 * scale), routes_top, width - round(20 * scale), height - round(70 * scale)),
        "status": (width / 2, round(109 * scale + extra * 0.2)),
        "action": (width / 2, round(169 * scale + extra * 0.2)),
        "update": (width / 2, hero_bottom - round(17 * scale)),
        "header_y": round(31 * scale), "route_heading_y": routes_top + round(20 * scale),
        "slot_label_y": routes_top + round(50 * scale),
        "slot_y": routes_top + round(75 * scale),
        "slot_x": round(40 * scale), "slot_width": width - round(80 * scale),
        # Two equal slot buttons about the centre line, as wide as the word «Дополнительный».
        "slot_button_w": round(112 * scale), "slot_next_w": round(34 * scale),
        "slot_button_centers": (_slot_geometry(width, scale)[0], _slot_geometry(width, scale)[2]),
        "slot_next_centers": (_slot_geometry(width, scale)[1], _slot_geometry(width, scale)[3]),
        "footer_y": height - round(50 * scale),
        "links_y": height - round(18 * scale),
    }


def status_text(value):
    return {
        "АКТИВНО : РАБОТАЕТ": "Подключено", "ГОТОВ К ЗАПУСКУ": "Готово к подключению",
        "ОСТАНОВЛЕНО": "Отключено", "ПОДКЛЮЧЕНИЕ": "Подключение…",
        "ПЕРЕЗАПУСК": "Перезапуск…", "ПАУЗА (VPN)": "Приостановлено: другой VPN",
        "АКТИВНО : ТОЛЬКО EU": "Работает дополнительный VPN",
        "ОСТАНОВЛЕНО (СБОЙ)": "Остановлено из-за ошибки",
        "ЗАПУСК . . .": "Запуск…", "ПЕРЕЗАПУСК ЯДРА...": "Перезапуск подключения…",
        "Запуск...": "Запуск…",
    }.get(value, value)


def action_text(value):
    return {"ПОДКЛЮЧИТЬ": "Подключить", "ОТКЛЮЧИТЬ": "Отключить"}.get(value, value)


def status_glow(text, pixel_size, color):
    """Soft static halo; the sharp, native Tk caption stays above it."""
    font = ImageFont.truetype("seguisb.ttf", max(1, round(pixel_size)))
    bounds = font.getbbox(text)
    pad = max(6, round(pixel_size * .5))
    mask = Image.new("L", (bounds[2] - bounds[0] + pad * 2, bounds[3] - bounds[1] + pad * 2))
    ImageDraw.Draw(mask).text((pad - bounds[0], pad - bounds[1]), text, font=font, fill=180)
    mask = mask.filter(ImageFilter.GaussianBlur(max(1.5, pixel_size * .12)))
    glow = Image.new("RGBA", mask.size, color)
    glow.putalpha(mask)
    return glow


def soft_glow(mask, color, radius, strength):
    """A faint halo of `color` shaped like an L mask (padded so the blur is not clipped); strength 0..1."""
    pad = max(4, round(radius * 2.5))
    padded = Image.new("L", (mask.width + 2 * pad, mask.height + 2 * pad), 0)
    padded.paste(mask, (pad, pad))
    padded = padded.filter(ImageFilter.GaussianBlur(max(1.0, radius))).point(lambda value: int(value * strength))
    glow = Image.new("RGBA", padded.size, tuple(color))
    glow.putalpha(padded)
    return glow


def text_mask(text, pixel_size):
    font = ImageFont.truetype("seguisb.ttf", max(1, round(pixel_size)))
    bounds = font.getbbox(text)
    mask = Image.new("L", (bounds[2] - bounds[0], bounds[3] - bounds[1]), 0)
    ImageDraw.Draw(mask).text((-bounds[0], -bounds[1]), text, font=font, fill=255)
    return mask


def fit_caption(text, width, measure):
    """Fit untrusted profile names with a bounded number of native font measurements."""
    if measure(text) <= width:
        return text
    if measure("…") > width:
        return ""
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if measure(text[:middle] + "…") <= width:
            low = middle
        else:
            high = middle - 1
    return text[:low] + "…"


def action_foreground(theme_id):
    accent = nova_appearance.THEMES[theme_id]["accent"].lstrip("#")
    r, g, b = (int(accent[index:index + 2], 16) for index in (0, 2, 4))
    return "#090817" if (r * 299 + g * 587 + b * 114) / 1000 >= 150 else "#FFFFFF"


_HEAVY_FAMILY = {}


def bold_font(font):
    """The hovered caption: heavier than the Semibold the UI uses. Windows has no bold cut of 'Segoe UI Semibold',
    so asking for bold changes nothing; 'Segoe UI Black' is the next weight up."""
    family, size = font[0], font[1]
    if "heavy" not in _HEAVY_FAMILY:
        try:
            _HEAVY_FAMILY["heavy"] = "Segoe UI Black" in set(tkfont.families())
        except (tk.TclError, RuntimeError):
            # No Tk root yet: every supported Windows ships the face.
            _HEAVY_FAMILY["heavy"] = sys.platform == "win32"
    if family.startswith("Segoe UI") and _HEAVY_FAMILY["heavy"]:
        return ("Segoe UI Black", size)
    return (family, size, "bold")


def set_link_hover(label, hovered, color, underline=True):
    """Style existing canvas items: recreating an item under the pointer loops Enter/Leave."""
    base = tuple(label.font_spec)
    font = (bold_font(base) if hovered else base) + (("underline",) if hovered and underline else ())
    for item in label.text_items:
        label.canvas.itemconfigure(item, fill=color if hovered else label.fg, font=font)


def supernova_icon(size=64, accent="#50C878"):
    """A vector starburst, rasterized at the target DPI for windows and the tray."""
    scale = 4
    image = Image.new("RGBA", (size * scale, size * scale))
    color = tuple(int(accent[index:index + 2], 16) for index in (1, 3, 5))
    center = size * scale / 2
    unit = size * scale
    glow = Image.new("RGBA", image.size)
    pen = ImageDraw.Draw(glow)
    pen.ellipse((center - unit * .16, center - unit * .16,
                 center + unit * .16, center + unit * .16), fill=color + (95,))
    radius = unit * .325
    pen.ellipse((center - radius, center - radius, center + radius, center + radius),
                outline=color + (180,), width=max(1, round(unit * .025)))
    image = Image.alpha_composite(image, glow.filter(ImageFilter.GaussianBlur(unit * .11)))
    pen = ImageDraw.Draw(image)
    for radius, opacity, width in ((.36, 50, .006), (.325, 220, .009), (.304, 70, .005)):
        distance = unit * radius
        pen.ellipse((center - distance, center - distance, center + distance, center + distance),
                    outline=color + (opacity,), width=max(1, round(unit * width)))
    for index in range(12):
        angle = index * math.tau / 12 - math.pi / 2
        length = unit * (.46 if index % 3 == 0 else .30 if index % 2 == 0 else .21)
        half_width = unit * (.045 if index % 3 == 0 else .018)
        dx, dy = math.cos(angle), math.sin(angle)
        px, py = -dy * half_width, dx * half_width
        pen.polygon(((center + px, center + py), (center + dx * length, center + dy * length),
                     (center - px, center - py)), fill=color + (255,))
    radius = unit * .115
    pen.ellipse((center - radius, center - radius, center + radius, center + radius), fill=color + (255,))
    radius = unit * .048
    pen.ellipse((center - radius, center - radius, center + radius, center + radius), fill="#F5FFF8")
    for x, y, radius in ((.74, .23, .019), (.22, .70, .014), (.73, .72, .013)):
        pen.ellipse(((x - radius) * unit, (y - radius) * unit,
                     (x + radius) * unit, (y + radius) * unit), fill=color + (180,))
    return image.resize((size, size), Image.Resampling.LANCZOS)


def app_icon(size=64, accent="#50C878"):
    """Window / taskbar / tray icon: the starburst on its own dark rounded badge with a light rim, so it stays
    visible on any taskbar colour (a bare transparent star vanishes on light green or white bars)."""
    scale = 4
    unit = size * scale
    color = tuple(int(accent[index:index + 2], 16) for index in (1, 3, 5))
    badge = Image.new("RGBA", (unit, unit), (0, 0, 0, 0))
    pen = ImageDraw.Draw(badge)
    margin = unit * .03
    box = (margin, margin, unit - margin, unit - margin)
    ground = tuple(round(value * .16 + 6) for value in color)
    pen.rounded_rectangle(box, radius=unit * .24, fill=ground + (255,))
    glow = Image.new("RGBA", badge.size, (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse((unit * .2, unit * .2, unit * .8, unit * .8), fill=color + (90,))
    glow = glow.filter(ImageFilter.GaussianBlur(unit * .12))
    mask = Image.new("L", badge.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle(box, radius=unit * .24, fill=255)
    glow.putalpha(ImageChops.multiply(glow.getchannel("A"), mask))
    badge = Image.alpha_composite(badge, glow)
    pen = ImageDraw.Draw(badge)
    pen.rounded_rectangle(box, radius=unit * .24, outline=(255, 255, 255, 120), width=max(2, round(unit * .035)))
    star = supernova_icon(round(size * .94), "#%02X%02X%02X" % tuple(round(v + (255 - v) * .35) for v in color))
    star = star.resize((round(unit * .94), round(unit * .94)), Image.Resampling.LANCZOS)
    offset = round((unit - star.width) / 2)
    badge.alpha_composite(star, (offset, offset))
    return badge.resize((size, size), Image.Resampling.LANCZOS)


class DesktopScene:
    """Render one continuous textured surface, including translucent cards, off-thread."""

    def __init__(self, canvas, appearance, version, preferences_path=None, on_error=None, gpu=None):
        self.canvas = canvas
        self.appearance = dict(appearance)
        self.version = version
        self.preferences_path = preferences_path
        self.on_error = on_error
        self.scale = display_scale(canvas)
        self._requests = queue.Queue()
        self._results = queue.Queue()
        self._generation = 0
        self._size = (MIN_WIDTH, MIN_HEIGHT)
        self._closed = False
        self._preferences_lock = threading.Lock()
        self._saved_generation = -1
        self._photo = None
        self._connection = "stopped"
        self.state_resolver = None  # optional callable -> state; polled on every animation tick
        self._animation_start = time.monotonic()
        self._animation_id = None
        self._render_pending = False
        self._layers = {}
        self._pattern_size = None
        self._overlay_key = None
        self._overlay = None
        self._overlay_mask = None
        # Glass plates registered by the buttons/pills of the main window (D51): key -> shape tuple.
        self._plates = {}
        self._plate_shapes = ()
        self._plate_job = None
        # NOVA caption toggle: the cards fold into pills around the text (glass_compact), animated by _compact_e.
        self._compact = bool(appearance.get("glass_compact"))
        self._compact_e = 1.0 if self._compact else 0.0
        self._compact_anim = None
        self._compact_job = None
        self._zone_job = None
        self._plates_cache = (None,)
        self._brand_rect = None
        self._brand_text = None
        self._brand_font = None
        self._brand_hit = None
        self._caption_shadows = []      # (image item, text item, caption, pixel size): soft shadow of a text that has no glass when folded
        self._shadow_cache = {}
        self._background = canvas.create_image(0, 0, anchor="nw", tags="desktop_background")
        # GPU path (D52): nova-engine gpu-serve draws the background; None/False = CPU path only.
        self._gpu = None
        self._gpu_mode = False
        self._gpu_photo = None
        self._gpu_seq = 0
        self._gpu_poll_id = None
        self._gpu_poll_due = 0.
        self._gpu_fast_until = 0.
        self._gpu_paused = None
        self._gpu_sent = None
        self._gpu_surface = None
        self._gpu_pointer_at = 0.
        self._gpu_pointer_job = None
        self._gpu_pointer_last = None
        self._gpu_hires = False
        self._gpu_frame_ms = 1000 / 60
        threading.Thread(target=self._render_worker, name="NovaAppearance", daemon=True).start()
        self._poll_id = canvas.after(40, self._poll)
        canvas.bind("<Destroy>", self._on_destroy, add="+")
        self._gpu_setup(gpu)
        self._schedule_animation()

    def _persist_preferences(self, generation, prefs):
        if not self.preferences_path:
            return
        prefs = {key: value for key, value in prefs.items() if not key.startswith("_")}   # render-only extras
        with self._preferences_lock:
            if generation < self._saved_generation:
                return
            nova_appearance.save_preferences(self.preferences_path, prefs)
            self._saved_generation = generation

    def flush_preferences(self, prefs):
        """Worker-safe final save; an older queued render must not overwrite it."""
        self._persist_preferences(self._generation, prefs)

    def _on_destroy(self, event):
        if event.widget == self.canvas:
            self._closed = True
            self._requests.put(None)
            self.canvas.after_cancel(self._poll_id)
            if self._animation_id is not None:
                self.canvas.after_cancel(self._animation_id)
            for job in (self._gpu_poll_id, self._gpu_pointer_job):
                if job is not None:
                    self.canvas.after_cancel(job)
            self._gpu_poll_id = self._gpu_pointer_job = None
            if self._gpu is not None:
                # No waiting on the Tk thread: stdin closes, so the engine ends even if Nova dies first.
                self._gpu.stop(wait=0)
                self._gpu_mode = False
            self._gpu_photo = None
            self._gpu_hires_timer(False)
            # Release Tcl-backed images on their owner thread, before cyclic GC can run on a worker.
            self._photo = None
            self._logo_photo = None
            self._brand_hit = None
            self._logo_glow = None
            self._brand_glow = None

    def set_appearance(self, appearance):
        if appearance["variant"] != self.appearance["variant"]:
            self._animation_start = time.monotonic()
        self.appearance = dict(appearance, glass_compact=self._compact)    # the caption toggle is the scene's own
        if self._gpu is not None:
            self._gpu_refresh()
            if self._gpu_mode:
                self._gpu_configure()
        self.draw(*self._size, save=True)
        self._schedule_animation()

    def set_connection_state(self, state):
        if state == self._connection:
            return
        self._connection = state
        self._schedule_animation()
        self.draw(*self._size)

    def _schedule_animation(self):
        if self._animation_id is not None:
            self.canvas.after_cancel(self._animation_id)
            self._animation_id = None
        if self._gpu_mode:
            # The GPU animates by itself; only the connection waves (an overlay) cost CPU, at <= 20 Hz.
            if self._connection == "connecting":
                self._animation_id = self.canvas.after(50 if self.canvas.winfo_viewable() else 1000, self._animate)
            return
        if self._connection == "connecting" or (
                self.appearance.get("immersion") and self.appearance["texture"] not in ("none", "custom")):
            self._animation_id = self.canvas.after(16 if self.canvas.winfo_viewable() else 1000, self._animate)

    def _animate(self):
        self._animation_id = None
        if self._closed:
            return
        resolver = self.state_resolver
        if resolver is not None:
            # A grace that ran out while nothing changed the label: the tracker answers, the scene follows.
            try:
                state = resolver()
            except Exception:
                state = self._connection
            if state != self._connection:
                self.set_connection_state(state)
                return
        if self.canvas.winfo_viewable() and not self._render_pending:
            self.draw(*self._size, frame=(self._connection, time.monotonic() - self._animation_start))
        self._schedule_animation()

    def draw(self, width, height, save=False, frame=None):
        redraw_labels = frame is None
        if frame is None:
            frame = (self._connection, time.monotonic() - self._animation_start)
        self._size = (max(round(MIN_WIDTH * self.scale), width), max(round(MIN_HEIGHT * self.scale), height))
        self._generation += 1
        self._render_pending = True
        prefs = dict(self.appearance, glass_compact=self._compact)
        prefs["_cards"] = self._card_groups(*self._size)      # None while the cards are whole
        prefs["_fast"] = self._compact_anim is not None
        self._requests.put((self._generation, self._size, prefs, save, frame))
        self.canvas.after_cancel(self._poll_id)
        self._poll_id = self.canvas.after(4, self._poll)
        if self._gpu is not None:
            self._gpu_kick()
        if redraw_labels:
            self._draw_labels()
        self._update_caption_shadows()

    def _update_caption_shadows(self):
        """Texts left without glass once the cards are folded get a soft dark shadow (faint, only to keep them readable);
        it fades in and out with the fold in a few steps."""
        level = round(self._compact_e * 6) / 6
        for image_id, text_id, caption, pixels in self._caption_shadows:
            try:
                if level <= 0:
                    self.canvas.itemconfigure(image_id, state="hidden")
                    continue
                key = (caption, pixels, level)
                image = self._shadow_cache.get(key)
                if image is None:
                    mask = text_mask(caption, pixels)
                    blur = max(1.5, 2.2 * self.scale)
                    image = ImageTk.PhotoImage(soft_glow(mask, (0, 0, 0), blur, .62 * level), master=self.canvas)
                    if len(self._shadow_cache) > 24:
                        self._shadow_cache.clear()
                    self._shadow_cache[key] = image
                box = self.canvas.bbox(text_id)
                if box is None:
                    continue
                self.canvas.coords(image_id, (box[0] + box[2]) / 2, (box[1] + box[3]) / 2 + round(1 * self.scale))
                self.canvas.itemconfigure(image_id, image=image, state="normal")
            except (tk.TclError, OSError):
                continue

    def _dive_layer(self, size, prefs):
        # Keep the seeded surface across frames and resizes; only explicit appearance edits rebuild it.
        if self._pattern_size is None:
            self._pattern_size = size
        key = tuple((name, prefs[name]) for name in
                    ("theme", "texture", "texture_intensity", "variant", "temperature"))
        if key not in self._layers:
            width, height = self._pattern_size
            # Two device pixels per display pixel leave room for inward motion without a coarse raster.
            ratio = min(2.0, 1440 / max(self._pattern_size))
            self._layers[key] = nova_appearance.render_background(
                max(8, round(width * ratio)), max(8, round(height * ratio)), prefs["theme"],
                prefs["texture"], prefs["texture_intensity"],
                prefs["variant"], prefs["temperature"])
            while len(self._layers) > 4:
                del self._layers[next(iter(self._layers))]
        return self._layers[key]

    def _custom_frame(self, size, prefs):
        """«Своё изображение»: the owner's picture, cover-fitted, still. Rendered once per size/setting."""
        path = prefs.get("custom_image") or ""
        key = (path, size, prefs.get("brightness", 100), prefs.get("saturation", 100))
        cached = getattr(self, "_custom_cache", None)
        if cached is not None and cached[0] == key:
            return cached[1]
        frame = nova_appearance.render_background(*size, prefs["theme"], "none", 0)
        try:
            with Image.open(path) as source:
                picture = source.convert("RGB")
        except (OSError, ValueError):
            picture = None
        if picture is not None:
            fit = max(size[0] / picture.width, size[1] / picture.height)
            scaled = picture.resize((max(1, round(picture.width * fit)), max(1, round(picture.height * fit))),
                                    Image.Resampling.LANCZOS)
            left, top = (scaled.width - size[0]) // 2, (scaled.height - size[1]) // 2
            frame = scaled.crop((left, top, left + size[0], top + size[1]))
            frame = ImageEnhance.Brightness(frame).enhance(max(0.0, prefs.get("brightness", 100) / 100))
            frame = ImageEnhance.Color(frame).enhance(max(0.0, prefs.get("saturation", 100) / 100))
        self._custom_cache = (key, frame)
        return frame

    def _dive_frame(self, size, prefs, elapsed):
        if prefs["texture"] == "custom":
            return self._custom_frame(size, prefs)
        if nova_appearance.live_enabled(prefs["texture"]):
            # D43: the native renderer owns the forward camera; time alone drives the motion.
            return nova_appearance.render_live_background(
                *size, prefs["theme"], prefs["texture"], prefs["texture_intensity"], prefs["variant"],
                prefs["temperature"], elapsed if prefs.get("immersion") else 0.)
        # Always move inward; logarithmic easing retains detail without reversing or resetting the pattern.
        zoom = 1 + .5 * math.log1p(max(0, elapsed) / 60) if prefs.get("immersion") else 1
        if self._pattern_size is None:
            self._pattern_size = size
        w, h = self._pattern_size
        aspect = size[0] / size[1]
        crop_w, crop_h = min(w, h * aspect) / zoom, min(h, w / aspect) / zoom
        left, top = (w - crop_w) * .5, (h - crop_h) * .43
        if prefs["texture"] == "fractal":
            return nova_appearance.render_fractal_background(
                *size, prefs["theme"], prefs["texture_intensity"], prefs["variant"], prefs["temperature"],
                self._pattern_size, (left / w, top / h, (left + crop_w) / w, (top + crop_h) / h))
        if prefs["texture"] == "matrix" and os.environ.get("NOVA_ANDROID_TEXTURES") != "0":
            return nova_appearance.render_matrix_background(
                *size, prefs["theme"], prefs["texture_intensity"], prefs["variant"], prefs["temperature"],
                self._pattern_size, (left / w, top / h, (left + crop_w) / w, (top + crop_h) / h), elapsed if prefs.get("immersion") else 0.)
        layer = self._dive_layer(size, prefs)
        # Cached surfaces may be capped at 1440 px; convert the camera into their pixel coordinates.
        left, top, crop_w, crop_h = left / w * layer.width, top / h * layer.height, crop_w / w * layer.width, crop_h / h * layer.height
        return layer.resize(size, Image.Resampling.BILINEAR, box=(left, top, left + crop_w, top + crop_h))

    def set_plate(self, key, rect, radius, tint=None):
        """Register (or move) a glass plate under a button/indicator: rect in canvas pixels."""
        left, top, right, bottom = (round(value) for value in rect)
        shape = (left, top, right, bottom, max(1, round(radius)), tuple(tint) if tint else None)
        if self._plates.get(key) == shape:
            return
        self._plates[key] = shape
        self._plates_changed()

    def remove_plate(self, key):
        if self._plates.pop(key, None) is not None:
            self._plates_changed()

    def _plates_changed(self):
        self._plate_shapes = tuple(self._plates[key] for key in sorted(self._plates, key=str))
        if self._plate_job is None and not self._closed:
            self._plate_job = self.canvas.after_idle(self._plates_redraw)

    def _plates_redraw(self):
        self._plate_job = None
        if not self._closed:
            self.draw(*self._size)

    def set_hot(self, rect, radius=0):
        """Hover glow on a plate. True when the GPU background draws it (callers then skip their own glow)."""
        engine = self._gpu
        if not self._gpu_mode or engine is None or "hot" not in engine.features:
            return False
        engine.set_hot(rect, radius, reach=26 * self.scale)
        self._gpu_kick()
        return True

    # --- the NOVA toggle: cards <-> pills around the text ---

    COMPACT_SECONDS = .6
    ZONES = (("hero", ("status", "update")), ("routes", ("heading",)))

    @property
    def compact(self):
        return self._compact

    def zone_rects(self):
        """Pill rectangles hugging the text items tagged zone_<key> (hidden items have no bounding box)."""
        zones = {}
        pad_x, pad_y = 17 * self.scale, 8 * self.scale
        for _group, keys in self.ZONES:
            for key in keys:
                box = self.canvas.bbox("zone_" + key)
                if not box:
                    continue
                left, top, right, bottom = box
                top, bottom = top - pad_y, bottom + pad_y
                left, right = left - pad_x, right + pad_x
                if right - left < bottom - top:
                    centre = (left + right) / 2
                    left, right = centre - (bottom - top) / 2, centre + (bottom - top) / 2
                zones[key] = (left, top, right, bottom)
        return zones

    def _card_groups(self, width, height):
        """Per card, the rectangles that make its glass at the current fold: the card itself at 0, one pill per text
        zone at 1, in between every pill is the card pulled towards its pill (None while nothing is folded)."""
        fold = self._compact_e
        if fold <= 0.0:
            return None
        layout = main_layout(width, height, self.scale)
        radius = round(nova_appearance.THEMES[self.appearance["theme"]]["radius"] * self.scale)
        zones = self.zone_rects()
        groups = []
        for name, keys in self.ZONES:
            left, top, right, bottom = layout[name]
            pills = [zones[key] for key in keys if key in zones]
            if not pills:
                centre_x, centre_y = (left + right) / 2, (top + bottom) / 2
                pills = [(centre_x - 2, centre_y - 2, centre_x + 2, centre_y + 2)]
            rects = []
            for pill in pills:
                rect = [left + (pill[0] - left) * fold, top + (pill[1] - top) * fold,
                        right + (pill[2] - right) * fold, bottom + (pill[3] - bottom) * fold,
                        radius + ((pill[3] - pill[1]) / 2 - radius) * fold]
                rects.append(tuple(round(value, 1) for value in rect))
            groups.append(tuple(rects))
        return tuple(groups)

    def zone_changed(self):
        """A text of a zone changed size or visibility: while folded the pills follow it."""
        if self._compact_e > 0.0 and self._zone_job is None and not self._closed:
            self._zone_job = self.canvas.after_idle(self._zone_redraw)

    def _zone_redraw(self):
        self._zone_job = None
        if not self._closed and self._compact_anim is None:
            self.draw(*self._size, frame=(self._connection, time.monotonic() - self._animation_start))

    def toggle_compact(self):
        self.set_compact(not self._compact)

    def set_compact(self, flag, animate=True):
        flag = bool(flag)
        if flag == self._compact:
            return
        self._compact = flag
        self.appearance["glass_compact"] = flag
        target = 1.0 if flag else 0.0
        try:
            visible = self.canvas.winfo_viewable()
        except tk.TclError:
            visible = False
        if self._compact_job is not None:
            self.canvas.after_cancel(self._compact_job)
            self._compact_job = None
        if not animate or not visible:
            self._compact_anim = None
            self._compact_e = target
            self.draw(*self._size, save=True)
            return
        span = abs(target - self._compact_e)
        self._compact_anim = (time.monotonic(), self._compact_e, target, self.COMPACT_SECONDS * span)
        self._compact_step(save=True)

    def _compact_step(self, save=False):
        self._compact_job = None
        if self._closed or self._compact_anim is None:
            return
        start, source, target, seconds = self._compact_anim
        now = time.monotonic()
        x = min(1.0, (now - start) / max(seconds, 1e-3))
        eased = x * x * x * (x * (6 * x - 15) + 10)                     # smootherstep: soft start and landing
        self._compact_e = source + (target - source) * eased
        if x >= 1.0:
            self._compact_e = target
            self._compact_anim = None
        self.draw(*self._size, save=save or x >= 1.0, frame=(self._connection, now - self._animation_start))
        if self._compact_anim is not None:
            self._compact_job = self.canvas.after(8, self._compact_step)

    def _brand_hover(self, on):
        self.canvas.configure(cursor="hand2" if on else "")
        lit = False
        if self._brand_rect is not None:
            left, top, right, bottom = self._brand_rect
            lit = self.set_hot((left, top, right, bottom) if on else None, (bottom - top) / 2)
        return lit

    def _panel_overlay(self, width, height, prefs, colors, layout):
        """Cards and plates as one RGBA layer plus a frost mask; rebuilt only when they change."""
        plates = self._plate_shapes
        cards = prefs.get("_cards")
        overlay_key = (width, height, prefs["theme"], plates, cards)
        if self._overlay_key != overlay_key:
            radius = round(nova_appearance.THEMES[prefs["theme"]]["radius"] * self.scale)
            if cards is not None:
                overlay, mask = nova_glass.compose_cards((width, height), cards, self.scale, bool(prefs.get("_fast")))
                plates_key = (width, height, plates)
                if self._plates_cache[0] != plates_key:
                    self._plates_cache = (plates_key, *nova_glass.compose((width, height), plates, self.scale))
                _, plate_layer, plate_mask = self._plates_cache
                overlay = Image.alpha_composite(overlay, plate_layer)
                mask = ImageChops.lighter(mask, plate_mask)
                self._overlay, self._overlay_mask, self._overlay_key = overlay, mask, overlay_key
                return self._overlay
            shapes = [(*layout[name], radius, None) for name in ("hero", "routes")] + list(plates)
            overlay, mask = nova_glass.compose((width, height), shapes, self.scale)
            self._overlay, self._overlay_mask, self._overlay_key = overlay, mask, overlay_key
        return self._overlay

    def _render_worker(self):
        while True:
            request = self._requests.get()
            if request is None:
                return
            save = request[3]
            while not self._requests.empty():
                latest = self._requests.get()
                if latest is None:
                    return
                save = save or latest[3]
                request = latest
            generation, (width, height), prefs, _, frame = request
            try:
                if save and self.preferences_path:
                    try:
                        self._persist_preferences(generation, prefs)
                    except OSError as error:
                        self._results.put((generation, None, error))
                if self._gpu_mode and nova_gpu.gpu_texture(prefs["texture"]) is not None:
                    self._gpu_worker_step(width, height, prefs, frame)
                    self._results.put((generation, None, None))
                    continue
                image = self._dive_frame((width, height), prefs, frame[1] if frame else 0).convert("RGBA")
                colors = nova_appearance.settings_theme(prefs["theme"])
                layout = main_layout(width, height, self.scale)
                overlay = self._panel_overlay(width, height, prefs, colors, layout)
                image = Image.alpha_composite(nova_glass.frost(image, self._overlay_mask), overlay)
                if frame is not None and frame[0] == "connecting":
                    color = tuple(int(colors["accent"][i:i + 2], 16) for i in (1, 3, 5))
                    image = Image.alpha_composite(image, connection_waves(
                        image.size, layout["action"], frame[1], color, self.scale))
                image = image.convert("RGB")
                self._results.put((generation, image, None))
            except Exception as error:
                logging.exception("Appearance rendering failed")
                self._results.put((generation, None, error))

    def _poll(self):
        if self._closed:
            return
        try:
            while not self._results.empty():
                generation, rendered, error = self._results.get()
                # A failed upload must release backpressure just like a completed frame.
                if generation == self._generation:
                    self._render_pending = False
                if error is not None:
                    logging.error("Cannot apply Nova appearance: %s", error)
                    if self.on_error is not None:
                        try:
                            self.on_error(f"[UI] Не удалось применить оформление: {error}")
                        except Exception:
                            logging.exception("Appearance error callback failed")
                if generation == self._generation and rendered is not None and not self._gpu_mode:
                    try:
                        photo = ImageTk.PhotoImage(rendered, master=self.canvas)
                        self.canvas.itemconfigure(self._background, image=photo)
                        self._photo = photo
                        self.canvas.tag_lower(self._background)
                    except tk.TclError:
                        logging.exception("Appearance frame upload failed")
        finally:
            if not self._closed:
                self._poll_id = self.canvas.after(4 if self._render_pending else 200, self._poll)

    # --- GPU background (nova_gpu.GpuEngine); every method below runs on the Tk thread unless noted ---

    def _gpu_setup(self, gpu):
        """gpu: None = decide by NOVA_GPU, False = never, or an engine object (tests)."""
        if gpu is False or os.environ.get("NOVA_GPU") == "0":
            return
        if gpu is None or gpu is True:
            temp = None
            if self.preferences_path:
                temp = os.path.join(os.path.dirname(os.path.abspath(os.fspath(self.preferences_path))), "temp")
            gpu = nova_gpu.GpuEngine(temp_dir=temp)
        self._gpu = gpu
        if gpu.state == "new":
            gpu.start_async()
        canvas = self.canvas
        canvas.bind("<Motion>", self._gpu_on_motion, add="+")
        canvas.bind("<Leave>", self._gpu_on_leave, add="+")
        canvas.bind("<Map>", lambda _event: self._gpu_kick(), add="+")
        canvas.bind("<Unmap>", lambda _event: self._gpu_kick(), add="+")
        self._gpu_schedule(100)

    def _gpu_schedule(self, delay):
        if self._closed:
            return
        due = time.monotonic() + delay / 1000
        if self._gpu_poll_id is not None:
            if self._gpu_poll_due <= due:
                return
            self.canvas.after_cancel(self._gpu_poll_id)
        self._gpu_poll_due = due
        self._gpu_poll_id = self.canvas.after(delay, self._gpu_poll)

    def _gpu_kick(self):
        """Something was sent that will produce a frame: poll fast for a while."""
        if self._gpu is None or self._closed:
            return
        self._gpu_fast_until = time.monotonic() + 0.5
        self._gpu_schedule(2)

    def _gpu_hires_timer(self, enable):
        """1 ms system timer while frames are flowing, so Tk's after() stops quantising to 15.6 ms."""
        if enable != self._gpu_hires:
            self._gpu_hires = enable
            nova_gpu.hires_timer(enable)

    def _gpu_wanted(self):
        engine = self._gpu
        return (engine is not None and engine.ready
                and nova_gpu.gpu_texture(self.appearance.get("texture")) is not None
                and nova_gpu.frame_fits(*self._size))

    def _gpu_refresh(self):
        """Move between the CPU and GPU paths: engine ready/failed, texture and size changes."""
        if self._gpu is None:
            return
        if self._gpu.failed:
            self._gpu_abandon()
            return
        wanted = self._gpu_wanted()
        if wanted and not self._gpu_mode:
            self._gpu_enter()
        elif not wanted and self._gpu_mode:
            self._gpu_leave()

    def _gpu_enter(self):
        self._gpu_mode = True
        self._gpu_photo = None
        self._gpu_seq = 0
        self._gpu_paused = None
        self._gpu_sent = None
        self._gpu_surface = None
        if self._animation_id is not None:
            self.canvas.after_cancel(self._animation_id)
            self._animation_id = None
        self._gpu_configure()
        self._gpu_sync_visibility()
        self._schedule_animation()
        self.draw(*self._size)

    def _gpu_leave(self):
        self._gpu_mode = False
        self._gpu_hires_timer(False)
        self._gpu_photo = None
        self._gpu_paused = None
        if self._gpu is not None:
            self._gpu.set_paused(True)
        self._schedule_animation()
        self.draw(*self._size)

    def _gpu_abandon(self, reason=None):
        """The engine died or the pump broke: back to the CPU path for good, without a user-visible error."""
        engine, self._gpu = self._gpu, None
        if engine is None:
            return
        if reason and not engine.failed:
            engine.fail(reason)
        engine.stop(wait=0)
        self._gpu_hires_timer(False)
        if self._gpu_mode:
            self._gpu_mode = False
            self._gpu_photo = None
            self._schedule_animation()
            self.draw(*self._size)

    def _gpu_configure(self):
        config = nova_gpu.config_from_prefs(self.appearance, nova_appearance.THEMES[self.appearance["theme"]]["accent"],
                                            nova_gpu.target_fps(self.appearance))
        if config is not None and self._gpu is not None:
            self._gpu_frame_ms = 1000 / max(1, config["fps"])
            if "drift" not in getattr(self._gpu, "features", ()):
                config.pop("drift", None)   # an older engine has no slowly drifting second hue
            self._gpu.configure(**config)
            self._gpu_kick()

    def _gpu_sync_visibility(self):
        """Pause the engine whenever the canvas cannot be seen (minimised or withdrawn)."""
        try:
            paused = not self.canvas.winfo_viewable()
        except tk.TclError:
            return
        if paused != self._gpu_paused:
            self._gpu_paused = paused
            self._gpu_hires_timer(not paused and self._gpu_mode)
            self._gpu.set_paused(paused)
            if not paused:
                self._gpu_kick()

    def _gpu_poll(self):
        self._gpu_poll_id = None
        if self._closed or self._gpu is None:
            return
        delay = 250
        try:
            self._gpu_refresh()
            if self._gpu is None:
                return
            if self._gpu_mode:
                self._gpu_sync_visibility()
                if self._gpu_show_frame():
                    # The next frame is due in about one frame time: sleep most of it, then poll finely.
                    delay = max(2, int(self._gpu_frame_ms * 0.7))
                elif time.monotonic() < self._gpu_fast_until:
                    delay = 2
            elif self._gpu.state in ("new", "starting"):
                delay = 100
        except Exception:
            logging.exception("GPU frame pump failed")
            self._gpu_abandon("сбой показа кадра")
            return
        self._gpu_schedule(delay)

    def _gpu_show_frame(self):
        """Upload the newest engine frame into the background item; True when one was shown."""
        engine = self._gpu
        if engine.pending_seq == self._gpu_seq:
            return False
        frame = engine.latest_frame()
        if frame is None or frame[0] == self._gpu_seq:
            return False
        seq, width, height, data = frame
        image = Image.frombuffer("RGB", (width, height), data, "raw", "RGB", 0, 1)
        photo = self._gpu_photo
        if photo is not None and (photo.width(), photo.height()) == (width, height):
            photo.paste(image)
        else:
            # One PhotoImage is reused for every frame of a size: paste() is 2x cheaper than a new image.
            photo = self._gpu_photo = ImageTk.PhotoImage(image, master=self.canvas)
            self.canvas.itemconfigure(self._background, image=photo)
            self.canvas.tag_lower(self._background)
        self._gpu_seq = seq
        self._gpu_fast_until = time.monotonic() + 0.3
        return True

    def _gpu_on_motion(self, event):
        if not self._gpu_mode:
            return
        self._gpu_pointer_last = (event.x, event.y, True)
        if time.monotonic() - self._gpu_pointer_at >= 1 / 60:
            self._gpu_flush_pointer()
        elif self._gpu_pointer_job is None:
            self._gpu_pointer_job = self.canvas.after(17, self._gpu_pointer_tick)

    def _gpu_on_leave(self, event):
        if self._gpu_mode:
            self._gpu_pointer_last = (event.x, event.y, False)
            self._gpu_flush_pointer()

    def _gpu_pointer_tick(self):
        self._gpu_pointer_job = None
        if self._gpu_mode:
            self._gpu_flush_pointer()

    def _gpu_flush_pointer(self):
        last = self._gpu_pointer_last
        if last is None or self._gpu is None:
            return
        x, y = nova_gpu.pointer_to_lab(last[0], last[1], *self._size)
        self._gpu.set_pointer(x, y, last[2])
        self._gpu_pointer_at = time.monotonic()
        self._gpu_kick()

    def _gpu_worker_step(self, width, height, prefs, frame):
        """Worker thread: size, then the cards/divider/waves overlay; never any widget access."""
        engine = self._gpu
        if engine is None or not engine.ready:
            return
        try:
            if self._gpu_surface != (width, height):
                engine.resize(width, height)  # the engine drops its overlay on a size change
                self._gpu_surface = (width, height)
                self._gpu_sent = None
            connecting = frame is not None and frame[0] == "connecting"
            key = (width, height, prefs["theme"], self._plate_shapes, prefs.get("_cards"), "waves" if connecting else "plain")
            if not connecting and self._gpu_sent == key:
                return
            colors = nova_appearance.settings_theme(prefs["theme"])
            layout = main_layout(width, height, self.scale)
            layer = self._panel_overlay(width, height, prefs, colors, layout)
            if connecting:
                color = tuple(int(colors["accent"][i:i + 2], 16) for i in (1, 3, 5))
                layer = Image.alpha_composite(layer, connection_waves(layer.size, layout["action"], frame[1],
                                                                       color, self.scale))
            engine.set_overlay(layer.tobytes(), width, height, mask=self._overlay_mask.tobytes())
            self._gpu_sent = key
        except OSError as error:
            engine.fail("не записан слой панелей: %s" % type(error).__name__)

    def _draw_labels(self):
        canvas = self.canvas
        canvas.delete("desktop_chrome")
        width, height = self._size
        theme = nova_appearance.THEMES[self.appearance["theme"]]
        colors = nova_appearance.settings_theme(self.appearance["theme"])
        fonts = nova_appearance.font_roles(self.appearance["theme"])
        scale = self.scale
        layout = main_layout(width, height, scale)

        def text(x, y, value, role, color, anchor="w", zone=None):
            return canvas.create_text(x, y, text=value, font=fonts[role], fill=color, anchor=anchor,
                                      tags=("desktop_chrome", "zone_" + zone) if zone else "desktop_chrome")

        brand_x, brand_lift = round(57 * scale), 0
        # The logo and the NOVA caption glow faintly in the theme hue (weaker than a hovered button).
        accent = tuple(int(theme["accent"][i:i + 2], 16) for i in (1, 3, 5))
        icon = supernova_icon(round(34 * scale), theme["accent"])
        self._logo_glow = ImageTk.PhotoImage(soft_glow(icon.getchannel("A"), accent, 7 * scale, .55), master=canvas)
        canvas.create_image(round(36 * scale), layout["header_y"], image=self._logo_glow, tags="desktop_chrome")
        self._logo_photo = ImageTk.PhotoImage(icon, master=canvas)
        canvas.create_image(round(36 * scale), layout["header_y"], image=self._logo_photo, tags="desktop_chrome")
        try:
            brand_px = fonts["brand"][1] * 96 / 72 * scale
            brand_mask = text_mask("NOVA", brand_px)
            self._brand_glow = ImageTk.PhotoImage(soft_glow(brand_mask, accent, 6 * scale, .5), master=canvas)
            canvas.create_image(brand_x + brand_mask.width / 2, layout["header_y"], image=self._brand_glow,
                                tags="desktop_chrome")
            # Tk centres the whole line box on y, but the capitals sit lower in it: lift the caption so the
            # centre of the letters (not of the line) lands on the centre of the logo.
            font = ImageFont.truetype("seguisb.ttf", max(1, round(brand_px)))
            ascent, descent = font.getmetrics()
            _, glyph_top, _, glyph_bottom = font.getbbox("NOVA")
            brand_lift = round((glyph_top + glyph_bottom) / 2 - (ascent + descent) / 2)
        except OSError:
            self._brand_glow = None
        # A glass chip under the logo and caption keeps them legible over any texture.
        brand_width = self._brand_glow.width() - round(30 * scale) if self._brand_glow is not None else 80 * scale
        self.set_plate("brand", (round(14 * scale), layout["header_y"] - round(23 * scale),
                                 round(brand_x + brand_width + 12 * scale), layout["header_y"] + round(23 * scale)),
                       round(23 * scale))
        self._brand_text = text(brand_x, layout["header_y"] - brand_lift, "NOVA", "brand", colors["text"])
        self._brand_font = fonts["brand"]
        text(layout["slot_x"], layout["route_heading_y"], "Маршруты VPN", "section", colors["text"], zone="heading")
        self._caption_shadows = []
        caption_px = fonts["caption"][1] * 96 / 72 * scale
        for centre, caption in zip(layout["slot_button_centers"], ("Основной", "Дополнительный")):
            shadow = canvas.create_image(centre, layout["slot_label_y"], anchor="center", state="hidden",
                                         tags="desktop_chrome")
            item = text(centre, layout["slot_label_y"], caption, "caption", colors["value"], "center")
            canvas.tag_lower(shadow, item)
            self._caption_shadows.append((shadow, item, caption, caption_px))
        # The caption is a switch: an almost transparent image over the chip takes the pointer (an empty rectangle
        # would only react on its outline).
        chip = (round(14 * scale), layout["header_y"] - round(23 * scale),
                round(brand_x + brand_width + 12 * scale), layout["header_y"] + round(23 * scale))
        self._brand_rect = chip
        self._brand_hit = ImageTk.PhotoImage(Image.new("RGBA", (chip[2] - chip[0], chip[3] - chip[1]), (0, 0, 0, 1)),
                                             master=canvas)
        hit = canvas.create_image(chip[0], chip[1], image=self._brand_hit, anchor="nw", tags="desktop_chrome")
        canvas.tag_bind(hit, "<Enter>", lambda _event: self._brand_hover(True))
        canvas.tag_bind(hit, "<Leave>", lambda _event: self._brand_hover(False))
        canvas.tag_bind(hit, "<Button-1>", lambda _event: self.toggle_compact())
        self.zone_changed()      # the labels exist now: while folded, the pills follow them


class UiLogPump:
    """Workers enqueue rows; one bounded Tk batch leaves time for input and frames."""

    def __init__(self):
        self.rows = queue.Queue()
        self.root = None
        self.after_id = None

    def put(self, row):
        self.rows.put(row)

    def start(self, root, deliver):
        self.root = root
        self.deliver = deliver
        root.bind("<Destroy>", self._destroy, add="+")
        self.after_id = root.after(16, self._drain)

    def _drain(self):
        batch = []
        for _ in range(128):
            try:
                batch.append(self.rows.get_nowait())
            except queue.Empty:
                break
        if batch:
            self.deliver(batch)
        self.after_id = self.root.after(16, self._drain)

    def _destroy(self, event):
        if event.widget is self.root:
            self.root.after_cancel(self.after_id)
            self.root = None
            self.after_id = None


class UiJobs:
    """Queue worker results to Tk without calling even after() from a worker."""

    def __init__(self, root):
        self.root = root
        self.results = queue.Queue()
        self.pending = 0
        self.closed = False
        self.after_id = None
        root.bind("<Destroy>", self._destroy, add="+")

    def _destroy(self, event):
        if event.widget is self.root:
            self.closed = True
            if self.after_id is not None:
                self.root.after_cancel(self.after_id)

    def submit(self, work, done, name="NovaUiData"):
        if self.closed:
            return
        self.pending += 1

        def run():
            try:
                value, error = work(), None
            except Exception as exc:
                value, error = None, exc
            self.results.put((done, value, error))

        threading.Thread(target=run, name=name, daemon=True).start()
        if self.after_id is None:
            self.after_id = self.root.after(25, self._drain)

    def _drain(self):
        self.after_id = None
        if self.closed:
            return
        while True:
            try:
                done, value, error = self.results.get_nowait()
            except queue.Empty:
                break
            self.pending -= 1
            try:
                done(value, error)
            except Exception:
                self.root.report_callback_exception(*sys.exc_info())
        if self.pending:
            self.after_id = self.root.after(25, self._drain)


class ImageCache(dict):
    """Bound image retention during resize/theme changes; callers stay on the Tk thread."""

    def __init__(self, limit=64):
        super().__init__()
        self.limit = limit

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        while len(self) > self.limit:
            del self[next(iter(self))]


class ThemedMenu:
    """Small cached Tk popup with explicit text and arrow colors on Windows."""

    def __init__(self, master, **options):
        self.parent = master if isinstance(master, ThemedMenu) else None
        self.root = master.root if self.parent else master
        self.options = options
        self.work_area = options.get("work_area") or (self.parent.work_area if self.parent else None)
        self.entries = []
        self.children = []
        self.top = None
        self.active = -1
        self._rows = []

    def add_command(self, **entry):
        self.entries.append(dict(entry, kind="command"))

    def add_radiobutton(self, **entry):
        self.entries.append(dict(entry, kind="radio"))

    def add_cascade(self, **entry):
        self.entries.append(dict(entry, kind="cascade"))
        self.children.append(entry["menu"])

    def add_separator(self):
        self.entries.append({"kind": "separator"})

    def _owner(self):
        return self.parent._owner() if self.parent else self

    def _build(self):
        if self.top is not None:
            return
        colors = self.options
        scale = display_scale(self.root)
        self.top = tk.Toplevel(self.root)
        self.top.withdraw()
        self.top.overrideredirect(True)
        self.top.attributes("-topmost", True)
        self.top.configure(bg=colors["selectcolor"])
        self.canvas = tk.Canvas(self.top, highlightthickness=0, bg=colors["bg"], bd=0)
        self.canvas.pack(padx=1, pady=1)
        font = colors["font"]
        width = max(round(220 * scale), max((int(self.root.tk.call(
            "font", "measure", font, entry.get("label", ""))) for entry in self.entries), default=0) + round(64 * scale))
        width = min(width, self.root.winfo_screenwidth() - round(24 * scale))
        y = round(4 * scale)
        for index, entry in enumerate(self.entries):
            height = round((9 if entry["kind"] == "separator" else 30) * scale)
            rectangle = self.canvas.create_rectangle(0, y, width, y + height, fill=colors["bg"], outline="")
            items = []
            if entry["kind"] == "separator":
                self.canvas.create_line(12 * scale, y + height / 2, width - 12 * scale, y + height / 2,
                                        fill=colors["disabledforeground"])
            else:
                enabled = entry.get("state") != "disabled"
                foreground = colors["fg"] if enabled else colors["disabledforeground"]
                caption = fit_caption(entry.get("label", ""), width - 64 * scale,
                                      lambda value: int(self.root.tk.call("font", "measure", font, value)))
                items.append(self.canvas.create_text(30 * scale, y + height / 2, anchor="w",
                             text=caption, fill=foreground, font=font))
                if entry["kind"] == "cascade":
                    cx, cy = width - 15 * scale, y + height / 2
                    items.append(self.canvas.create_polygon(cx - 3 * scale, cy - 4 * scale,
                                 cx + 2 * scale, cy, cx - 3 * scale, cy + 4 * scale, fill=foreground))
                if entry["kind"] == "radio":
                    variable = entry.get("variable")
                    if variable is not None and str(variable.get()) == str(entry.get("value")):
                        items.append(self.canvas.create_oval(12 * scale, y + height / 2 - 3 * scale,
                                     18 * scale, y + height / 2 + 3 * scale, fill=foreground, outline=""))
            self._rows.append((y, y + height, rectangle, items))
            y += height
        self.width, self.height = width, y + round(4 * scale)
        self.canvas.configure(width=self.width, height=self.height)
        self.canvas.configure(scrollregion=(0, 0, self.width, self.height))
        self.top.bind("<MouseWheel>", lambda event: self.canvas.yview_scroll(-int(event.delta / 120) * 2, "units"))
        self.top.bind("<Motion>", self._motion)
        self.top.bind("<ButtonRelease-1>", self._click)
        self.top.bind("<Escape>", lambda event: self._owner().unpost())
        self.top.bind("<Up>", lambda event: self._step(-1))
        self.top.bind("<Down>", lambda event: self._step(1))
        self.top.bind("<Right>", lambda event: self._invoke(self.active))
        self.top.bind("<Left>", lambda event: self._back())
        self.top.bind("<Return>", lambda event: self._invoke(self.active))
        self.top.bind("<FocusOut>", lambda event: self.top.after_idle(self._check_focus))
        self.top.bind("<Destroy>", self._on_destroy, add="+")

    def _on_destroy(self, event):
        if event.widget is self.top:
            # A cached menu owns StringVar objects; release them before background GC can reach Tcl.
            for entry in self.entries:
                entry.pop("variable", None)
            self._nova_var = None
            self.top = None

    def _check_focus(self):
        if self.top is not None and self.top.winfo_exists():
            focused = self.root.focus_get()
            owner = self._owner()
            menus = [owner]
            for menu in menus:
                menus.extend(menu.children)
            if not any(menu.top is not None and focused is not None and
                       focused.winfo_toplevel() is menu.top for menu in menus):
                owner.unpost()

    def _select(self, index):
        if index == self.active:
            return
        for child in self.children:
            child.unpost()
        self.active = index
        for i, (_top, _bottom, rectangle, items) in enumerate(self._rows):
            selected = i == index and self._enabled(i)
            entry = self.entries[i]
            self.canvas.itemconfigure(rectangle, fill=self.options["activebackground"] if selected else self.options["bg"])
            foreground = self.options["disabledforeground"] if entry.get("state") == "disabled" else (
                self.options["activeforeground"] if selected else self.options["fg"])
            for item in items:
                self.canvas.itemconfigure(item, fill=foreground)
        if self._enabled(index) and self.entries[index]["kind"] == "cascade":
            child = self.entries[index]["menu"]
            child.tk_popup(self.top.winfo_rootx() + self.width,
                           self.top.winfo_rooty() + self._rows[index][0] - self.canvas.canvasy(0))

    def _enabled(self, index):
        return 0 <= index < len(self.entries) and self.entries[index]["kind"] != "separator" and self.entries[index].get("state") != "disabled"

    def _motion(self, event):
        menus = [self._owner()]
        for menu in menus:
            menus.extend(menu.children)
        for menu in reversed(menus):
            if menu.top is None or not menu.top.winfo_viewable():
                continue
            x, y = event.x_root - menu.top.winfo_rootx(), event.y_root - menu.top.winfo_rooty()
            if 0 <= x < menu.width and 0 <= y < menu.viewport_height:
                y = menu.canvas.canvasy(y)
                index = next((i for i, (top, bottom, *_rest) in enumerate(menu._rows) if top <= y < bottom), -1)
                menu._select(index)
                return

    def _step(self, direction):
        for offset in range(1, len(self.entries) + 1):
            index = (self.active + offset * direction) % len(self.entries)
            if self._enabled(index):
                self._select(index)
                top, bottom = self._rows[index][:2]
                visible_top = self.canvas.canvasy(0)
                if top < visible_top or bottom > visible_top + self.viewport_height:
                    self.canvas.yview_moveto(max(0, top - self.viewport_height / 2) / self.height)
                break

    def _back(self):
        if self.parent:
            self.unpost()
            self.parent.top.grab_set()
            self.parent.top.focus_set()

    def _click(self, event):
        menus = [self._owner()]
        for menu in menus:
            menus.extend(menu.children)
        for menu in reversed(menus):
            if menu.top is None or not menu.top.winfo_viewable():
                continue
            x, y = event.x_root - menu.top.winfo_rootx(), event.y_root - menu.top.winfo_rooty()
            if 0 <= x < menu.width and 0 <= y < menu.viewport_height:
                y = menu.canvas.canvasy(y)
                index = next((i for i, (top, bottom, *_rest) in enumerate(menu._rows) if top <= y < bottom), -1)
                menu._invoke(index)
                return
        self._owner().unpost()

    def _invoke(self, index):
        if not self._enabled(index):
            return
        entry = self.entries[index]
        if entry["kind"] == "cascade":
            child = entry["menu"]
            if child.top is not None and child.top.state() == "withdrawn":
                self.active = -1
            self._select(index)
            child.top.focus_set()
            return
        if entry["kind"] == "radio" and entry.get("variable") is not None:
            entry["variable"].set(entry.get("value", ""))
        self._owner().unpost()
        command = entry.get("command")
        if command:
            command()

    def tk_popup(self, x, y):
        self._build()
        # Virtual desktop coordinates may be negative on a secondary monitor.
        left, top = self.root.winfo_vrootx(), self.root.winfo_vrooty()
        right, bottom = left + self.root.winfo_vrootwidth(), top + self.root.winfo_vrootheight()
        if self.work_area:
            left, top, right, bottom = self.work_area(int(x), int(y))
        self.viewport_height = min(self.height, bottom - top - 16)
        self.canvas.configure(height=self.viewport_height)
        x = max(left, min(int(x), right - self.width - 2))
        y = max(top, min(int(y), bottom - self.viewport_height - 2))
        if self.parent and x < self.parent.top.winfo_rootx() + self.parent.width:
            x = max(left, self.parent.top.winfo_rootx() - self.width)
        self.top.geometry(f"+{x}+{y}")
        self.top.deiconify()
        self.top.lift()
        self.top.grab_set()
        if self.parent is None:
            self.top.focus_set()

    def grab_release(self):
        # Kept for the tk.Menu call contract; the grab lives until unpost().
        return

    def unpost(self):
        for child in self.children:
            child.unpost()
        if self.top is not None:
            if self.top.grab_current() is self.top:
                self.top.grab_release()
            self.top.withdraw()
        if self.active != -1:
            self._select(-1)

    def destroy(self):
        self.unpost()
        for child in self.children:
            child.destroy()
        if self.top is not None:
            self.top.destroy()
            self.top = None
        for entry in self.entries:
            entry.pop("variable", None)
        self._nova_var = None


AppearanceWindow = nova_appearance_ui.AppearanceWindow
reveal_window = nova_appearance_ui.reveal_window
