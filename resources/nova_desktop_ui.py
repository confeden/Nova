"""Desktop presentation of Nova Android's appearance system. No transport logic."""

import logging
import math
import queue
import threading
import tkinter as tk
from tkinter import ttk

from PIL import Image, ImageDraw, ImageFilter, ImageTk

import nova_appearance


MIN_WIDTH = 640
MIN_HEIGHT = 600


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
        self._size = (max(MIN_WIDTH, width), max(MIN_HEIGHT, height))
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
                theme = nova_appearance.THEMES[prefs["theme"]]
                colors = nova_appearance.settings_theme(prefs["theme"])
                overlay = Image.new("RGBA", image.size)
                for bounds in ((24, 104, width - 24, 338),
                               (24, 356, width - 24, height - 112),
                               (24, height - 94, width - 24, height - 24)):
                    left, top, right, bottom = bounds
                    panel = nova_appearance.render_surface(right - left, bottom - top, prefs["theme"])
                    overlay.alpha_composite(panel, (left, top))
                draw = ImageDraw.Draw(overlay)
                cx = width // 2
                accent = theme["accent"]
                # The quiet orbital geometry leaves status and action unobstructed.
                draw.arc((cx - 156, 128, cx + 156, 322), 195, 345, fill=colors["border"], width=1)
                draw.arc((cx - 148, 136, cx + 148, 314), 199, 341, fill=accent, width=1)
                draw.line((width // 2, 402, width // 2, height - 134), fill=colors["border"], width=1)
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
        family = theme["font_family"]

        def text(x, y, value, size, color, anchor="w", weight="normal"):
            canvas.create_text(x, y, text=value, font=(family, size, weight),
                               fill=color, anchor=anchor, tags="desktop_chrome")

        self._logo_photo = ImageTk.PhotoImage(supernova_icon(42, theme["accent"]), master=canvas)
        canvas.create_image(45, 43, image=self._logo_photo, tags="desktop_chrome")
        text(70, 42, "NOVA", 22, colors["text"], weight="bold")
        text(32, 79, "Свободный интернет", 10, colors["muted"])
        text(width / 2, 127, "ПОДКЛЮЧЕНИЕ", 9, colors["muted"], "center")
        text(width / 2, 301, "DPI-обход  ·  два VPN-маршрута", 10, colors["muted"], "center")
        text(44, 380, "VPN-МАРШРУТЫ", 9, colors["muted"])
        text(44 + (width - 88) / 4, 418, "ОСНОВНОЙ", 8, colors["muted"], "center")
        text(width - 44 - (width - 88) / 4, 418, "ДОПОЛНИТЕЛЬНЫЙ", 8, colors["muted"], "center")
        text(32, height - 10, "Nova PC", 8, colors["muted"])
        text(width - 32, height - 10, "v" + self.version, 8, colors["muted"], "e")


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
        family = theme["font_family"]
        self.top.configure(bg=colors["bg"])
        outer = tk.Frame(self.top, bg=colors["bg"], padx=24, pady=22)
        outer.pack(fill="both", expand=True)
        tk.Label(outer, text="Оформление", bg=colors["bg"], fg=colors["text"],
                 font=(family, 18, "bold"), anchor="w").pack(fill="x")
        tk.Label(outer, text="Темы и фактуры Nova Android", bg=colors["bg"],
                 fg=colors["muted"], font=(family, 10), anchor="w").pack(fill="x", pady=(4, 20))
        theme_grid = tk.Frame(outer, bg=colors["bg"])
        theme_grid.pack(fill="x")
        for index, (key, candidate) in enumerate(nova_appearance.THEMES.items()):
            selected = key == self.preferences["theme"]
            swatch = tk.Canvas(theme_grid, width=132, height=53, highlightthickness=0,
                               bg=colors["bg"], cursor="hand2", takefocus=True)
            swatch.grid(row=index // 3, column=index % 3, padx=3, pady=3)
            swatch.create_rectangle(1, 1, 131, 52, fill=nova_appearance.settings_theme(key)["panel"],
                                    outline=candidate["accent"] if selected else colors["border"],
                                    width=2 if selected else 1)
            swatch.create_oval(12, 12, 21, 21, fill=candidate["accent"], outline="")
            swatch.create_text(12, 35, anchor="w", text=candidate["name"],
                               fill=nova_appearance.settings_theme(key)["text"], font=(family, 9))
            swatch.bind("<Button-1>", lambda event, k=key: self._change(theme=k))
            swatch.bind("<Return>", lambda event, k=key: self._change(theme=k))
            swatch.bind("<space>", lambda event, k=key: self._change(theme=k))

        self._caption(outer, "Фактура", colors, family)
        style = ttk.Style(self.top)
        style.theme_use("clam")
        style.configure("Nova.TCombobox", fieldbackground=colors["panel"], background=colors["panel"],
                        foreground=colors["text"], arrowcolor=theme["accent"],
                        bordercolor=colors["border"], padding=6)
        style.map("Nova.TCombobox", fieldbackground=[("readonly", colors["panel"])],
                  foreground=[("readonly", colors["text"])], selectbackground=[("readonly", colors["panel"])])
        self.top.option_add("*TCombobox*Listbox.background", colors["panel"])
        self.top.option_add("*TCombobox*Listbox.foreground", colors["text"])
        self.texture = ttk.Combobox(outer, values=list(nova_appearance.TEXTURES.values()),
                                    state="readonly", style="Nova.TCombobox", font=(family, 10))
        self.texture.current(list(nova_appearance.TEXTURES).index(self.preferences["texture"]))
        self.texture.pack(fill="x")
        self.texture.bind("<<ComboboxSelected>>", lambda event: self._change(
            texture=list(nova_appearance.TEXTURES)[self.texture.current()]))
        self._caption(outer, "Интенсивность фактуры", colors, family)
        self._slider(outer, 0, 60, self.preferences["texture_intensity"] * 100,
                     lambda value: self._change(texture_intensity=float(value) / 100), colors)
        self._caption(outer, "Температура  ·  холоднее — теплее", colors, family)
        self._slider(outer, -100, 100, self.preferences["temperature"],
                     lambda value: self._change(temperature=int(float(value))), colors)
        actions = tk.Frame(outer, bg=colors["bg"])
        actions.pack(fill="x", pady=(18, 0))
        for caption, command in (("Новый рисунок", self._new_pattern), ("Готово", self.top.destroy)):
            tk.Button(actions, text=caption, command=command, relief="flat", bd=0,
                      bg=colors["panel"], fg=colors["text"], activebackground=colors["pill_on_bg"],
                      activeforeground=colors["pill_on_fg"], font=(family, 10), cursor="hand2",
                      padx=18, pady=9).pack(side="left" if caption == "Новый рисунок" else "right")

    @staticmethod
    def _caption(parent, text, colors, family):
        tk.Label(parent, text=text, bg=colors["bg"], fg=colors["muted"],
                 font=(family, 9), anchor="w").pack(fill="x", pady=(16, 7))

    @staticmethod
    def _slider(parent, start, end, value, command, colors):
        style = ttk.Style(parent)
        style.configure("Nova.Horizontal.TScale", background=colors["accent"],
                        troughcolor=colors["panel"], bordercolor=colors["bg"],
                        lightcolor=colors["accent"], darkcolor=colors["accent"])
        style.map("Nova.Horizontal.TScale", background=[("active", colors["pill_on_fg"])])
        scale = ttk.Scale(parent, from_=start, to=end, orient="horizontal",
                          style="Nova.Horizontal.TScale")
        scale.set(value)
        scale.pack(fill="x")
        scale.configure(command=command)

    def _change(self, **values):
        old_theme = self.preferences["theme"]
        self.preferences.update(values)
        self.on_apply(dict(self.preferences))
        if self.preferences["theme"] != old_theme:
            for child in self.top.winfo_children():
                child.destroy()
            self._build()

    def _new_pattern(self):
        self._change(variant=self.preferences["variant"] + 1)
