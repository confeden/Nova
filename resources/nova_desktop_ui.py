"""Desktop presentation of Nova Android's appearance system. No transport logic."""

import logging
import math
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageTk

import nova_appearance


MIN_WIDTH = 560
MIN_HEIGHT = 420


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

THEME_TITLES = {
    "aurora": "Aurora", "dnsai": "DNS-AI", "proton": "Proton", "charcoal": "Charcoal",
    "graphene": "Graphene", "neon": "Neon", "poe1": "Path of Exile", "poe2": "Path of Exile II",
    "gta6sunset": "Vice Sunset", "gta6night": "Vice Night", "matrix": "Matrix", "diablo2": "Diablo II",
}


def display_scale(widget):
    return max(1.0, round(float(widget.tk.call("tk", "scaling")) * 0.75, 2))


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


def set_link_hover(label, hovered, color, underline=True):
    """Style existing canvas items: recreating an item under the pointer loops Enter/Leave."""
    font = tuple(label.font_spec) + (("underline",) if hovered and underline else ())
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


class DesktopScene:
    """Render one continuous textured surface, including translucent cards, off-thread."""

    def __init__(self, canvas, appearance, version, preferences_path=None, on_error=None):
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
        self._animation_start = time.monotonic()
        self._animation_id = None
        self._render_pending = False
        self._layers = {}
        self._pattern_size = None
        self._overlay_key = None
        self._overlay = None
        self._background = canvas.create_image(0, 0, anchor="nw", tags="desktop_background")
        threading.Thread(target=self._render_worker, name="NovaAppearance", daemon=True).start()
        self._poll_id = canvas.after(40, self._poll)
        canvas.bind("<Destroy>", self._on_destroy, add="+")
        self._schedule_animation()

    def _persist_preferences(self, generation, prefs):
        if not self.preferences_path:
            return
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
            # Release Tcl-backed images on their owner thread, before cyclic GC can run on a worker.
            self._photo = None
            self._logo_photo = None

    def set_appearance(self, appearance):
        if appearance["variant"] != self.appearance["variant"]:
            self._animation_start = time.monotonic()
        self.appearance = dict(appearance)
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
        if self._connection == "connecting" or (
                self.appearance.get("immersion") and self.appearance["texture"] != "none"):
            self._animation_id = self.canvas.after(16 if self.canvas.winfo_viewable() else 1000, self._animate)

    def _animate(self):
        self._animation_id = None
        if self._closed:
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
        self._requests.put((self._generation, self._size, dict(self.appearance), save, frame))
        self.canvas.after_cancel(self._poll_id)
        self._poll_id = self.canvas.after(4, self._poll)
        if redraw_labels:
            self._draw_labels()

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

    def _dive_frame(self, size, prefs, elapsed):
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
                image = self._dive_frame((width, height), prefs, frame[1] if frame else 0).convert("RGBA")
                colors = nova_appearance.settings_theme(prefs["theme"])
                layout = main_layout(width, height, self.scale)
                overlay_key = (width, height, prefs["theme"])
                if self._overlay_key != overlay_key:
                    overlay = Image.new("RGBA", image.size)
                    for bounds in (layout["hero"], layout["routes"]):
                        left, top, right, bottom = bounds
                        radius = round(nova_appearance.THEMES[prefs["theme"]]["radius"] * self.scale)
                        panel = nova_appearance.render_surface(right - left, bottom - top, prefs["theme"], radius=radius)
                        overlay.alpha_composite(panel, (left, top))
                    draw = ImageDraw.Draw(overlay)
                    draw.line((width // 2, layout["slot_label_y"] - round(6 * self.scale),
                               width // 2, layout["slot_y"] + round(8 * self.scale)), fill=colors["border"], width=1)
                    self._overlay, self._overlay_key = overlay, overlay_key
                image = Image.alpha_composite(image, self._overlay)
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
        while not self._results.empty():
            generation, rendered, error = self._results.get()
            if error is not None:
                logging.error("Cannot apply Nova appearance: %s", error)
                if self.on_error is not None:
                    self.on_error(f"[UI] Не удалось применить оформление: {error}")
            if generation == self._generation and rendered is not None:
                self._photo = ImageTk.PhotoImage(rendered, master=self.canvas)
                self.canvas.itemconfigure(self._background, image=self._photo)
                self.canvas.tag_lower(self._background)
            if generation == self._generation:
                self._render_pending = False
        self._poll_id = self.canvas.after(4 if self._render_pending else 200, self._poll)

    def _draw_labels(self):
        canvas = self.canvas
        canvas.delete("desktop_chrome")
        width, height = self._size
        theme = nova_appearance.THEMES[self.appearance["theme"]]
        colors = nova_appearance.settings_theme(self.appearance["theme"])
        fonts = nova_appearance.font_roles(self.appearance["theme"])
        scale = self.scale
        layout = main_layout(width, height, scale)

        def text(x, y, value, role, color, anchor="w"):
            canvas.create_text(x, y, text=value, font=fonts[role],
                               fill=color, anchor=anchor, tags="desktop_chrome")

        self._logo_photo = ImageTk.PhotoImage(supernova_icon(round(34 * scale), theme["accent"]), master=canvas)
        canvas.create_image(round(36 * scale), layout["header_y"], image=self._logo_photo, tags="desktop_chrome")
        text(62 * scale, layout["header_y"], "NOVA", "brand", colors["text"])
        text(layout["slot_x"], layout["route_heading_y"], "Маршруты VPN", "section", colors["text"])
        text(layout["slot_x"] + layout["slot_width"] / 4, layout["slot_label_y"],
             "Основной", "caption", colors["value"], "center")
        text(width - layout["slot_x"] - layout["slot_width"] / 4, layout["slot_label_y"],
             "Дополнительный", "caption", colors["value"], "center")


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


class AppearanceWindow:
    """Live appearance controls, independent of connection and routing settings."""

    def __init__(self, root, preferences, on_apply, place_window=None, show=True):
        self.preferences = dict(preferences)
        self.on_apply = on_apply
        self.top = tk.Toplevel(root)
        self.top.withdraw()
        self.top.title("Оформление Nova")
        self.top.transient(root)
        self.top.resizable(False, False)
        self.top.protocol("WM_DELETE_WINDOW", self.top.withdraw)
        self._build()
        self.top.update_idletasks()
        if place_window is not None:
            place_window(self.top)
        else:
            x = min(root.winfo_rootx() + root.winfo_width() + 12,
                    root.winfo_screenwidth() - self.top.winfo_reqwidth() - 24)
            y = max(24, min(root.winfo_rooty(), root.winfo_screenheight() - self.top.winfo_reqheight() - 64))
            self.top.geometry(f"+{max(0, x)}+{y}")
        self.top.bind("<Escape>", lambda event: self.top.withdraw())
        self.top.bind("<Destroy>", self._on_destroy, add="+")
        if show:
            self.top.deiconify()

    def _on_destroy(self, event):
        if event.widget is self.top:
            self.immersion = None
            self.random_texture = None

    def _build(self):
        colors = nova_appearance.settings_theme(self.preferences["theme"])
        theme = nova_appearance.THEMES[self.preferences["theme"]]
        fonts = nova_appearance.font_roles(self.preferences["theme"])
        scale = display_scale(self.top)
        px = lambda value: round(value * scale)
        self.top.configure(bg=colors["bg"])
        outer = tk.Frame(self.top, bg=colors["bg"], padx=px(18), pady=px(16))
        outer.pack(fill="both", expand=True)
        tk.Label(outer, text="Оформление", bg=colors["bg"], fg=colors["text"],
                 font=fonts["title"], anchor="w").pack(fill="x", pady=(0, px(12)))
        theme_grid = tk.Frame(outer, bg=colors["bg"])
        theme_grid.pack(fill="x")
        self.theme_buttons = {}
        tile_width = max(px(108), max(int(self.top.tk.call("font", "measure", fonts["control"], name))
                                     for name in THEME_TITLES.values()) + px(24))
        for index, (key, candidate) in enumerate(nova_appearance.THEMES.items()):
            selected = key == self.preferences["theme"]
            candidate_colors = nova_appearance.settings_theme(key)
            swatch = tk.Canvas(theme_grid, width=tile_width, height=px(42), highlightthickness=0,
                               bg=colors["bg"], cursor="hand2", takefocus=True)
            swatch.grid(row=index // 4, column=index % 4, padx=px(2), pady=px(2))
            swatch.create_rectangle(px(1), px(1), tile_width - px(1), px(41),
                                    fill=candidate_colors["panel"],
                                    outline=candidate["accent"] if selected else colors["border"],
                                    width=px(2) if selected else 1)
            swatch.create_line(px(10), px(10), px(24), px(10), fill=candidate["accent"], width=px(2))
            swatch.create_text(px(10), px(28), anchor="w", text=THEME_TITLES[key],
                               fill=candidate_colors["text"], font=fonts["control"])
            swatch.bind("<Button-1>", lambda event, k=key: self._change(theme=k))
            swatch.bind("<Return>", lambda event, k=key: self._change(theme=k))
            swatch.bind("<space>", lambda event, k=key: self._change(theme=k))
            swatch._nova_theme_key = key
            self.theme_buttons[key] = swatch

        self._caption(outer, "Фактура", colors, fonts, px)
        style = ttk.Style(self.top)
        style.theme_use("clam")
        style.configure("Nova.TCombobox", fieldbackground=colors["panel"], background=colors["panel"],
                        foreground=colors["text"], arrowcolor=theme["accent"],
                        bordercolor=colors["border"], padding=px(4))
        style.map("Nova.TCombobox", fieldbackground=[("readonly", colors["panel"])],
                  foreground=[("readonly", colors["text"])], selectbackground=[("readonly", colors["panel"])])
        self.top.option_add("*TCombobox*Listbox.background", colors["panel"])
        self.top.option_add("*TCombobox*Listbox.foreground", colors["text"])
        self.top.option_add("*TCombobox*Listbox.font", fonts["control"])
        self.texture = ttk.Combobox(outer, values=list(nova_appearance.TEXTURES.values()),
                                    state="readonly", style="Nova.TCombobox", font=fonts["control"])
        self.texture.current(list(nova_appearance.TEXTURES).index(self.preferences["texture"]))
        self.texture.pack(fill="x")
        self.texture.bind("<<ComboboxSelected>>", lambda event: self._change(
            texture=list(nova_appearance.TEXTURES)[self.texture.current()]))
        self.intensity_value = self._caption(outer, "Интенсивность", colors, fonts, px,
                                             str(round(self.preferences["texture_intensity"] * 100)) + " %")
        self.intensity = self._slider(outer, 0, 60, self.preferences["texture_intensity"] * 100,
                                     self._set_intensity, colors, px)
        temperature = self.preferences["temperature"]
        self.temperature_value = self._caption(outer, "Температура", colors, fonts, px,
                                               self._temperature_text(temperature))
        self.temperature = self._slider(outer, -100, 100, temperature, self._set_temperature, colors, px)
        self.immersion = tk.BooleanVar(self.top, value=self.preferences.get("immersion", True))
        tk.Checkbutton(outer, text="Анимация фоновой фактуры", variable=self.immersion,
                       command=lambda: self._change(immersion=self.immersion.get()),
                       bg=colors["bg"], fg=colors["text"], activebackground=colors["bg"],
                       activeforeground=colors["text"], selectcolor=colors["panel"],
                       font=fonts["control"], anchor="w").pack(fill="x", pady=(px(12), 0))
        self.random_texture = tk.BooleanVar(self.top, value=self.preferences.get('random_texture_on_start', False))
        tk.Checkbutton(outer, text="Случайная фактура при запуске", variable=self.random_texture,
                       command=lambda: self._change(random_texture_on_start=self.random_texture.get()),
                       bg=colors['bg'], fg=colors['text'], activebackground=colors['bg'],
                       activeforeground=colors['text'], selectcolor=colors['panel'],
                       font=fonts['control'], anchor='w').pack(fill='x', pady=(px(6), 0))
        actions = tk.Frame(outer, bg=colors["bg"])
        actions.pack(fill="x", pady=(px(16), 0))
        self.pattern_button = tk.Button(
            actions, text="Новый рисунок", command=self._new_pattern, relief="flat", bd=0,
            bg=colors["panel"], fg=colors["text"], activebackground=colors["pill_on_bg"],
            activeforeground=colors["pill_on_fg"], disabledforeground=colors["muted"],
            font=fonts["control"], cursor="hand2", padx=px(12), pady=px(7))
        self.pattern_button.pack(side="left")
        tk.Button(actions, text="Готово", command=self.top.withdraw, relief="flat", bd=0,
                  bg=colors["pill_on_bg"], fg=colors["text"], activebackground=colors["panel"],
                  activeforeground=colors["pill_on_fg"], font=fonts["control"], cursor="hand2",
                  padx=px(18), pady=px(7)).pack(side="right")
        self._refresh_texture_controls()

    @staticmethod
    def _caption(parent, text, colors, fonts, px, value=None):
        row = tk.Frame(parent, bg=colors["bg"])
        row.pack(fill="x", pady=(px(12), px(5)))
        tk.Label(row, text=text, bg=colors["bg"], fg=colors["value"],
                 font=fonts["caption"], anchor="w").pack(side="left")
        if value is not None:
            label = tk.Label(row, text=value, bg=colors["bg"], fg=colors["value"], font=fonts["caption"])
            label.pack(side="right")
            return label

    @staticmethod
    def _slider(parent, start, end, value, command, colors, px):
        style = ttk.Style(parent)
        style.configure("Nova.Horizontal.TScale", background=colors["accent"], borderwidth=0,
                        troughcolor=colors["panel"], bordercolor=colors["panel"],
                        lightcolor=colors["panel"], darkcolor=colors["panel"], sliderlength=px(16))
        style.map("Nova.Horizontal.TScale", background=[("active", colors["pill_on_fg"]),
                                                       ("disabled", colors["muted"])])
        scale = ttk.Scale(parent, from_=start, to=end, orient="horizontal", style="Nova.Horizontal.TScale")
        scale.set(value)
        scale.pack(fill="x", pady=(px(2), 0))
        scale.configure(command=command)
        return scale

    @staticmethod
    def _temperature_text(value):
        return "Нейтральная" if value == 0 else "Холоднее " + str(abs(value)) if value < 0 else "Теплее " + str(value)

    def _set_intensity(self, value):
        value = round(float(value))
        self.intensity_value.configure(text=str(value) + " %")
        self._change(texture_intensity=value / 100)

    def _set_temperature(self, value):
        value = round(float(value))
        self.temperature_value.configure(text=self._temperature_text(value))
        self._change(temperature=value)

    def _refresh_texture_controls(self):
        disabled = self.preferences["texture"] == "none"
        self.pattern_button.configure(state="disabled" if disabled else "normal")
        self.intensity.state(["disabled"] if disabled else ["!disabled"])

    def _change(self, **values):
        focused = self.top.focus_get()
        restore_theme_focus = getattr(focused, "_nova_theme_key", None) is not None
        old_theme = self.preferences["theme"]
        self.preferences.update(values)
        self.on_apply(dict(self.preferences))
        if self.preferences["theme"] != old_theme:
            for child in self.top.winfo_children():
                child.destroy()
            self._build()
            if restore_theme_focus:
                self.theme_buttons[self.preferences["theme"]].focus_set()
        else:
            self._refresh_texture_controls()

    def _new_pattern(self):
        if self.preferences["texture"] != "none":
            self._change(variant=self.preferences["variant"] + 1)
