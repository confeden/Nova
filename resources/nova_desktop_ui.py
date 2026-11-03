"""Desktop presentation of Nova Android's appearance system. No transport logic."""

import logging
import math
import queue
import threading
import tkinter as tk
from tkinter import ttk

from PIL import Image, ImageDraw, ImageFilter, ImageTk

import nova_appearance


MIN_WIDTH = 560
MIN_HEIGHT = 420

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
        "footer_y": height - round(36 * scale),
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
    image = Image.alpha_composite(image, glow.filter(ImageFilter.GaussianBlur(unit * .11)))
    pen = ImageDraw.Draw(image)
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
        self._photo = None
        self._background = canvas.create_image(0, 0, anchor="nw", tags="desktop_background")
        threading.Thread(target=self._render_worker, name="NovaAppearance", daemon=True).start()
        self._poll_id = canvas.after(40, self._poll)
        canvas.bind("<Destroy>", self._on_destroy, add="+")

    def _on_destroy(self, event):
        if event.widget == self.canvas:
            self._closed = True
            self._requests.put(None)
            self.canvas.after_cancel(self._poll_id)

    def set_appearance(self, appearance):
        self.appearance = dict(appearance)
        self.draw(*self._size, save=True)

    def draw(self, width, height, save=False):
        self._size = (max(round(MIN_WIDTH * self.scale), width), max(round(MIN_HEIGHT * self.scale), height))
        self._generation += 1
        self._requests.put((self._generation, self._size, dict(self.appearance), save))
        self._draw_labels()

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
            generation, (width, height), prefs, _ = request
            try:
                if save and self.preferences_path:
                    try:
                        nova_appearance.save_preferences(self.preferences_path, prefs)
                    except OSError as error:
                        self._results.put((generation, None, error))
                image = nova_appearance.render_background(
                    width, height, prefs["theme"], prefs["texture"],
                    prefs["texture_intensity"], prefs["variant"], prefs["temperature"],
                ).convert("RGBA")
                colors = nova_appearance.settings_theme(prefs["theme"])
                overlay = Image.new("RGBA", image.size)
                layout = main_layout(width, height, self.scale)
                for bounds in (layout["hero"], layout["routes"]):
                    left, top, right, bottom = bounds
                    radius = round(nova_appearance.THEMES[prefs["theme"]]["radius"] * self.scale)
                    panel = nova_appearance.render_surface(right - left, bottom - top, prefs["theme"], radius=radius)
                    overlay.alpha_composite(panel, (left, top))
                draw = ImageDraw.Draw(overlay)
                draw.line((width // 2, layout["slot_label_y"] - round(6 * self.scale),
                           width // 2, layout["slot_y"] + round(8 * self.scale)), fill=colors["border"], width=1)
                image = Image.alpha_composite(image, overlay).convert("RGB")
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
        self._poll_id = self.canvas.after(40, self._poll)

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
        brand_width = int(canvas.tk.call("font", "measure", fonts["brand"], "NOVA"))
        text(62 * scale + brand_width + 12 * scale, layout["header_y"] + 3 * scale,
             "v" + self.version, "caption", colors["muted"])
        text(layout["slot_x"], layout["route_heading_y"], "Маршруты VPN", "section", colors["text"])
        text(layout["slot_x"] + layout["slot_width"] / 4, layout["slot_label_y"],
             "Основной", "caption", colors["value"], "center")
        text(width - layout["slot_x"] - layout["slot_width"] / 4, layout["slot_label_y"],
             "Дополнительный", "caption", colors["value"], "center")


class AppearanceWindow:
    """Live appearance controls, independent of connection and routing settings."""

    def __init__(self, root, preferences, on_apply, place_window=None):
        self.preferences = dict(preferences)
        self.on_apply = on_apply
        self.top = tk.Toplevel(root)
        self.top.title("Оформление Nova")
        self.top.transient(root)
        self.top.resizable(False, False)
        self.top.protocol("WM_DELETE_WINDOW", self.top.destroy)
        self._build()
        self.top.update_idletasks()
        if place_window is not None:
            place_window(self.top)
        else:
            x = min(root.winfo_rootx() + root.winfo_width() + 12,
                    root.winfo_screenwidth() - self.top.winfo_reqwidth() - 24)
            y = max(24, min(root.winfo_rooty(), root.winfo_screenheight() - self.top.winfo_reqheight() - 64))
            self.top.geometry(f"+{max(0, x)}+{y}")
        self.top.bind("<Escape>", lambda event: self.top.destroy())

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
        actions = tk.Frame(outer, bg=colors["bg"])
        actions.pack(fill="x", pady=(px(16), 0))
        self.pattern_button = tk.Button(
            actions, text="Новый рисунок", command=self._new_pattern, relief="flat", bd=0,
            bg=colors["panel"], fg=colors["text"], activebackground=colors["pill_on_bg"],
            activeforeground=colors["pill_on_fg"], disabledforeground=colors["muted"],
            font=fonts["control"], cursor="hand2", padx=px(12), pady=px(7))
        self.pattern_button.pack(side="left")
        tk.Button(actions, text="Готово", command=self.top.destroy, relief="flat", bd=0,
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
