"""Appearance window (D51): texture tiles, accent hue, texture sliders. Tk only, no transport logic.

The browser light-lab was the reference: a tile per texture with a still preview, one accent-hue slider
instead of themes, thin sliders with a round thumb. Previews are still pictures cut from a baked atlas
(resources/nova_texture_thumbs.png, made by gpu/make_thumbs.py at the default hue) and rotated to the
current hue, so nothing animates here and the CPU stays idle.
"""

import colorsys
import os
import tkinter as tk
import tkinter.font as tkfont

from PIL import Image, ImageDraw, ImageTk

import nova_appearance
import nova_gpu

SS = 4  # supersampling of the drawn controls: Tk canvas ovals and lines are not antialiased
IMAGE_TYPES = [('Изображения', '*.png *.jpg *.jpeg *.bmp *.webp *.gif'), ('Все файлы', '*.*')]

ATLAS_NAME = "nova_texture_thumbs.png"
ATLAS_COLUMNS = 4
THUMB_W, THUMB_H = 192, 144
TILE_GAP = 6          # horizontal gap between tiles at 96 dpi
TILE_MIN_WIDTH = 74   # narrowest tile worth drawing at 96 dpi


def tile_columns(count, available, gap=TILE_GAP, minimum=TILE_MIN_WIDTH):
    """Columns for `count` tiles in `available` px: the widest fit, or up to two fewer when that leaves the last row fuller."""
    widest = max(1, (available + gap) // (minimum + gap))
    best = None
    for columns in range(max(1, widest - 2), widest + 1):
        empty = -(-count // columns) * columns - count
        if best is None or (empty, -columns) < best[0]:
            best = ((empty, -columns), columns)
    return best[1]
HUE_STEPS = nova_appearance.HUE_COUNT
SLIDERS = (
    # key, caption, low, high, unit shown after the number
    ("accent_hue", "Оттенок", 0, HUE_STEPS - 1, "hue"),
    ("brightness", "Яркость", 0, 100, "%"),
    ("saturation", "Насыщенность цвета", 0, 200, "%"),
    ("speed", "Скорость погружения", 0, 200, "%"),
    ("warp", "Искривление от курсора", 0, 100, "%"),
)


def load_atlas(directories):
    """The baked preview atlas (RGB) or None; the first directory holding it wins."""
    for directory in directories:
        path = os.path.join(str(directory), ATLAS_NAME)
        try:
            with Image.open(path) as image:
                return image.convert("RGB")
        except (OSError, ValueError):
            continue
    return None


def atlas_cell(atlas, texture):
    """The preview of a Nova texture key (None when it has no baked cell)."""
    engine = nova_gpu.gpu_texture(texture)
    if atlas is None or engine is None:
        return None
    index = nova_gpu.TEXTURE_IDS.index(engine)
    column, row = index % ATLAS_COLUMNS, index // ATLAS_COLUMNS
    left, top = column * THUMB_W, row * THUMB_H
    if left + THUMB_W > atlas.width or top + THUMB_H > atlas.height:
        return None
    return atlas.crop((left, top, left + THUMB_W, top + THUMB_H))


def rotate_hue(image, hue):
    """Move a preview baked at the default hue to another one (accent, second and ground all follow H)."""
    shift = round((int(hue) - nova_appearance.DEFAULT_HUE) * 256 / HUE_STEPS) % 256
    if shift == 0:
        return image
    hsv = image.convert("HSV")
    hue_band, sat_band, val_band = hsv.split()
    hue_band = hue_band.point(lambda value: (value + shift) % 256)
    return Image.merge("HSV", (hue_band, sat_band, val_band)).convert("RGB")


def hue_color(index, lightness=.56, saturation=.68):
    red, green, blue = colorsys.hls_to_rgb((int(index) % HUE_STEPS) / HUE_STEPS, lightness, saturation)
    return "#%02X%02X%02X" % (round(red * 255), round(green * 255), round(blue * 255))


def reveal_window(win, delay=45):
    """Show a withdrawn Toplevel without the visible element-by-element repaint: map it fully transparent,
    let Tk lay out and paint every child, then make it opaque in one step."""
    try:
        win.attributes("-alpha", 0.0)
    except tk.TclError:
        pass
    try:
        win.deiconify()
        win.update_idletasks()
        win.lift()
    except tk.TclError:
        return

    def opaque():
        try:
            if win.winfo_exists():
                win.attributes("-alpha", 1.0)
        except tk.TclError:
            pass
    win.after(delay, opaque)


def value_text(unit, value):
    if unit == "hue":
        return "%d°" % round(value * 360 / HUE_STEPS)
    return "%d %%" % value


def _rgb(color):
    return tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))


def aa_photo(master, width, height, paint):
    """A smooth (supersampled) picture of a control: paint(draw, k) draws in 4x pixels, then it is filtered down."""
    image = Image.new("RGBA", (width * SS, height * SS), (0, 0, 0, 0))
    paint(ImageDraw.Draw(image), SS, image)
    return ImageTk.PhotoImage(image.resize((width, height), Image.Resampling.LANCZOS), master=master)


def pill(draw, k, left, top, right, bottom, fill):
    """A capsule from (left, top) to (right, bottom) in output pixels."""
    draw.rounded_rectangle((left * k, top * k, right * k - 1, bottom * k - 1),
                           radius=(bottom - top) * k / 2, fill=fill)


class _Slider(tk.Canvas):
    """Thin track, filled part in the accent, round thumb. command(value, final): final=False while dragging."""

    def __init__(self, master, low, high, value, colors, px, command, rainbow=False):
        self.px = px
        self.colors = colors
        self.low, self.high = low, high
        self.value = max(low, min(high, int(value)))
        self.command = command
        self.rainbow = rainbow
        self._dragging = False
        self._hover = False
        super().__init__(master, height=px(26), bg=colors["bg"], highlightthickness=0, bd=0,
                         cursor="hand2", takefocus=True)
        self.bind("<Configure>", lambda event: self._draw())
        self.bind("<ButtonPress-1>", self._press)
        self.bind("<B1-Motion>", self._drag)
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<MouseWheel>", self._wheel)
        self.bind("<Enter>", lambda event: self._set_hover(True))
        self.bind("<Leave>", lambda event: self._set_hover(False))
        self.bind("<FocusIn>", lambda event: self._draw())
        self.bind("<FocusOut>", lambda event: self._draw())
        for key, step in (("<Left>", -1), ("<Right>", 1), ("<Down>", -1), ("<Up>", 1)):
            self.bind(key, lambda event, s=step: self._nudge(s))
        self.bind("<Home>", lambda event: self._commit(self.low, True))
        self.bind("<End>", lambda event: self._commit(self.high, True))

    def _span(self):
        pad = self.px(10)
        return pad, max(pad + 1, self.winfo_width() - pad)

    def _x_of(self, value):
        left, right = self._span()
        return left + (value - self.low) / max(1, self.high - self.low) * (right - left)

    def _value_at(self, x):
        left, right = self._span()
        fraction = min(1.0, max(0.0, (x - left) / max(1, right - left)))
        return round(self.low + fraction * (self.high - self.low))

    def _set_hover(self, hover):
        self._hover = hover
        self._draw()

    def recolor(self, colors):
        self.colors = colors
        self.configure(bg=colors["bg"])
        self._draw()

    def _draw(self):
        width, height = self.winfo_width(), self.winfo_height()
        if width < 8 or height < 8:
            return
        px = self.px
        left, right = self._span()
        middle = height / 2
        accent = _rgb(self.colors["accent"])
        thumb_x = self._x_of(self.value)
        radius = px(8)
        lit = self._dragging or self._hover or self.focus_get() is self
        track = px(6) if self.rainbow else px(4)

        def paint(draw, k, image):
            if self.rainbow:
                gradient = Image.new("RGB", (max(1, round((right - left) * k)), 1))
                gradient.putdata([tuple(round(v * 255) for v in colorsys.hls_to_rgb(i / max(1, gradient.width), .56, .68))
                                  for i in range(gradient.width)])
                gradient = gradient.resize((gradient.width, round(track * k)))
                mask = Image.new("L", gradient.size, 0)
                ImageDraw.Draw(mask).rounded_rectangle((0, 0, gradient.width - 1, gradient.height - 1),
                                                       radius=gradient.height / 2, fill=255)
                image.paste(gradient, (round(left * k), round((middle - track / 2) * k)), mask)
            else:
                pill(draw, k, left - track / 2, middle - track / 2, right + track / 2, middle + track / 2,
                     _rgb(self.colors["border"]) + (255,))
                if thumb_x > left:
                    pill(draw, k, left - track / 2, middle - track / 2, thumb_x + track / 2, middle + track / 2,
                         accent + (255,))
            if lit:
                halo = px(13)
                draw.ellipse(((thumb_x - halo) * k, (middle - halo) * k, (thumb_x + halo) * k, (middle + halo) * k),
                             fill=accent + (80,))
            draw.ellipse(((thumb_x - radius) * k, (middle - radius) * k, (thumb_x + radius) * k,
                          (middle + radius) * k), fill=_rgb(self.colors["bg"]) + (255,))
            inner = radius - px(2)
            draw.ellipse(((thumb_x - inner) * k, (middle - inner) * k, (thumb_x + inner) * k,
                          (middle + inner) * k), fill=(238, 242, 248, 255))

        self._photo = aa_photo(self, width, height, paint)
        self.delete("all")
        self.create_image(0, 0, anchor="nw", image=self._photo)

    def set(self, value):
        self.value = max(self.low, min(self.high, int(value)))
        self._draw()

    def _commit(self, value, final):
        value = max(self.low, min(self.high, int(value)))
        changed = value != self.value
        self.value = value
        self._draw()
        if changed or final:
            self.command(value, final)

    def _press(self, event):
        self.focus_set()
        self._dragging = True
        self._commit(self._value_at(event.x), False)

    def _drag(self, event):
        if self._dragging:
            self._commit(self._value_at(event.x), False)

    def _release(self, event):
        if self._dragging:
            self._dragging = False
            self._commit(self._value_at(event.x), True)

    def _wheel(self, event):
        step = max(1, (self.high - self.low) // 50)
        self._commit(self.value + (step if event.delta > 0 else -step), True)

    def _nudge(self, step):
        self._commit(self.value + step * max(1, (self.high - self.low) // 100), True)


class _Switch(tk.Canvas):
    """A small pill switch with its label; one click anywhere toggles it."""

    def __init__(self, master, text, value, colors, fonts, px, command):
        self.px = px
        self.colors = colors
        self.value = bool(value)
        self.command = command
        self.text = text
        self.font = fonts["control"]
        super().__init__(master, height=px(26), bg=colors["bg"], highlightthickness=0, bd=0,
                         cursor="hand2", takefocus=True)
        self.bind("<Configure>", lambda event: self._draw())
        self.bind("<ButtonRelease-1>", lambda event: self.toggle())
        self.bind("<space>", lambda event: self.toggle())
        self.bind("<Return>", lambda event: self.toggle())
        self.bind("<FocusIn>", lambda event: self._draw())
        self.bind("<FocusOut>", lambda event: self._draw())

    def recolor(self, colors):
        self.colors = colors
        self.configure(bg=colors["bg"])
        self._draw()

    def _draw(self):
        height = self.winfo_height()
        if height < 6:
            return
        track_w, track_h = self.px(32), self.px(16)
        top = (height - track_h) / 2
        fill = _rgb(self.colors["accent"] if self.value else self.colors["border"]) + (255,)
        knob = track_h - self.px(6)
        x = track_w - track_h + self.px(3) if self.value else self.px(3)

        def paint(draw, k, image):
            pill(draw, k, 0, top, track_w, top + track_h, fill)
            draw.ellipse((x * k, (top + self.px(3)) * k, (x + knob) * k, (top + self.px(3) + knob) * k),
                         fill=(244, 246, 251, 255))

        self._photo = aa_photo(self, track_w, height, paint)
        self.delete("all")
        self.create_image(0, 0, anchor="nw", image=self._photo)
        color = self.colors["text"] if self.focus_get() is not self else self.colors["accent"]
        self.create_text(track_w + self.px(10), height / 2, anchor="w", text=self.text, fill=color, font=self.font)

    def toggle(self):
        self.value = not self.value
        self._draw()
        self.command(self.value)


class _Tile(tk.Canvas):
    """A texture tile: still preview, caption, accent outline when chosen."""

    def __init__(self, master, key, title, colors, fonts, px, command, size):
        self.key, self.title, self.colors, self.px = key, title, colors, px
        self.fonts = fonts
        self.command = command
        self.tile_w, self.thumb_h = size
        self.caption_h = px(17)
        self.caption_font = fonts["tile"]
        try:        # a long caption stays on ONE line, at the common height: the font shrinks only as far as it must
            family, size = fonts["tile"][0], fonts["tile"][1]
            for step in range(4):
                trial = (family, size + step if size < 0 else size - step) + tuple(fonts["tile"][2:])
                self.caption_font = trial
                if tkfont.Font(font=trial).measure(title) <= self.tile_w - px(4):
                    break
        except tk.TclError:
            pass
        self.selected = False
        self._hover = False
        self._photo = None
        super().__init__(master, width=self.tile_w, height=self.thumb_h + self.caption_h, bg=colors["bg"],
                         highlightthickness=0, bd=0, cursor="hand2", takefocus=True)
        self.bind("<ButtonRelease-1>", lambda event: self.command(self.key))
        self.bind("<Return>", lambda event: self.command(self.key))
        self.bind("<space>", lambda event: self.command(self.key))
        self.bind("<Enter>", lambda event: self._set_hover(True))
        self.bind("<Leave>", lambda event: self._set_hover(False))
        self.bind("<FocusIn>", lambda event: self._draw())
        self.bind("<FocusOut>", lambda event: self._draw())
        self.image = None

    def _set_hover(self, hover):
        self._hover = hover
        self._draw()

    def recolor(self, colors):
        self.colors = colors
        self.configure(bg=colors["bg"])
        self._draw()

    def set_image(self, image):
        """A PIL RGB image already at tile size, or None for the flat 'no texture' tile."""
        self.image = image
        self._photo = ImageTk.PhotoImage(image, master=self) if image is not None else None
        self._draw()

    def set_selected(self, selected):
        self.selected = selected
        self._draw()

    def _draw(self):
        self.delete("all")
        px = self.px
        accent = self.colors["accent"]
        if self._photo is not None:
            self.create_image(0, 0, anchor="nw", image=self._photo)
        else:
            self.create_rectangle(0, 0, self.tile_w, self.thumb_h, fill=self.colors["field"], outline="")
            if self.key == "custom":
                centre_x, centre_y, arm = self.tile_w / 2, self.thumb_h / 2, px(9)
                self.create_line(centre_x - arm, centre_y, centre_x + arm, centre_y, fill=self.colors["muted"], width=px(2))
                self.create_line(centre_x, centre_y - arm, centre_x, centre_y + arm, fill=self.colors["muted"], width=px(2))
            else:
                self.create_line(px(10), self.thumb_h - px(10), self.tile_w - px(10), px(10),
                                 fill=self.colors["muted"], width=px(2))
        if self.selected:
            self.create_rectangle(px(1), px(1), self.tile_w - px(1), self.thumb_h - px(1), outline=accent,
                                  width=px(2))
        elif self._hover or self.focus_get() is self:
            self.create_rectangle(px(1), px(1), self.tile_w - px(1), self.thumb_h - px(1),
                                  outline=self.colors["value"], width=1)
        color = self.colors["text"] if (self.selected or self._hover) else self.colors["muted"]
        self.create_text(self.tile_w / 2, self.thumb_h + self.caption_h / 2, text=self.title, fill=color,
                         font=self.caption_font, justify="center")


class AppearanceWindow:
    """Live appearance controls, independent of connection and routing settings."""

    def __init__(self, root, preferences, on_apply, place_window=None, show=True, asset_dirs=None):
        self.preferences = nova_appearance.normalize_preferences(preferences)
        self.on_apply = on_apply
        here = os.path.dirname(os.path.abspath(__file__))
        self.asset_dirs = list(asset_dirs or []) + [here, os.path.join(here, "resources")]
        self._atlas = load_atlas(self.asset_dirs)
        self._apply_job = None
        self._tile_job = None
        self._pending = None
        self.root = root
        self.top = tk.Toplevel(root)
        self.top.withdraw()
        self.top.title("Оформление Nova")
        self.top.transient(root)
        self.top.resizable(False, False)
        self.top.protocol("WM_DELETE_WINDOW", self.top.withdraw)
        self._build()
        self._place_window = place_window
        self.top.update_idletasks()
        self.place()
        self.top.bind("<Escape>", lambda event: self.top.withdraw())
        self.top.bind("<Destroy>", self._on_destroy, add="+")
        if show:
            self.show()

    def place(self):
        """Beside the main window, on its monitor. Runs on every open, never reuses the last position."""
        self.top.update_idletasks()
        if self._place_window is not None:
            self._place_window(self.top)
            return
        root = self.root
        x = min(root.winfo_rootx() + root.winfo_width() + 12,
                root.winfo_screenwidth() - self.top.winfo_reqwidth() - 24)
        y = max(24, min(root.winfo_rooty(), root.winfo_screenheight() - self.top.winfo_reqheight() - 64))
        self.top.geometry(f"+{max(0, x)}+{y}")

    def show(self):
        self.place()
        reveal_window(self.top)
        try:
            self.top.focus_set()
        except tk.TclError:
            pass

    def _on_destroy(self, event):
        if event.widget is self.top:
            for job in (self._apply_job, self._tile_job):
                if job is not None:
                    try:
                        self.top.after_cancel(job)
                    except tk.TclError:
                        pass
            self._apply_job = self._tile_job = None
            self.immersion = None
            self.random_texture = None

    # ----- building ---------------------------------------------------------------------------------

    def _scale(self):
        try:
            return max(1.0, float(self.top.winfo_fpixels("1i")) / 96.0)
        except tk.TclError:
            return 1.0

    def _t(self, widget, **roles):
        """Remember which colour role each option of a plain Tk widget uses, so a new hue recolours in place."""
        self._themed.append((widget, roles))
        return widget

    def _build(self):
        prefs = self.preferences
        colors = nova_appearance.settings_theme(prefs["theme"])
        fonts = dict(nova_appearance.font_roles(prefs["theme"]))
        fonts["tile"] = (fonts["caption"][0], 8)
        self.colors, self.fonts = colors, fonts
        self._themed = []
        scale = self._scale()
        px = self.px = lambda value: round(value * scale)
        self.top.configure(bg=colors["bg"])
        outer = self._t(tk.Frame(self.top, bg=colors["bg"], padx=px(18), pady=px(14)), bg="bg")
        outer.pack(fill="both", expand=True)
        self._t(tk.Label(outer, text="Оформление", bg=colors["bg"], fg=colors["text"], font=fonts["title"],
                         anchor="w"), bg="bg", fg="text").pack(fill="x", pady=(0, px(8)))

        self._section(outer, "Фактура")
        grid = self._t(tk.Frame(outer, bg=colors["bg"]), bg="bg")
        grid.pack(fill="x")
        self.tiles = {}

        self._section(outer, "Цвет")
        self.sliders, self.value_labels = {}, {}
        for key, caption, low, high, unit in SLIDERS[:3]:
            self._slider_row(outer, key, caption, low, high, unit)
        self._section(outer, "Движение")
        for key, caption, low, high, unit in SLIDERS[3:]:
            self._slider_row(outer, key, caption, low, high, unit)

        self._section(outer, "Анимация")
        switches = self._t(tk.Frame(outer, bg=colors["bg"]), bg="bg")
        switches.pack(fill="x")
        switches.grid_columnconfigure(0, weight=1, uniform="sw")
        switches.grid_columnconfigure(1, weight=1, uniform="sw")
        self.immersion = tk.BooleanVar(self.top, value=prefs["immersion"])
        self.random_texture = tk.BooleanVar(self.top, value=prefs["random_texture_on_start"])
        self.switches = {}
        for index, (key, text) in enumerate((
                ("immersion", "Анимация фона"), ("random_texture_on_start", "Случайная фактура при запуске"),
                ("limit_30fps", "Не больше 30 кадров/с"), ("sync_monitor", "По частоте монитора"))):
            switch = _Switch(switches, text, prefs[key], colors, fonts, px,
                             lambda value, k=key: self._set_flag(k, value))
            switch.grid(row=index // 2, column=index % 2, sticky="we", padx=(0, px(6)))
            self.switches[key] = switch

        actions = self._t(tk.Frame(outer, bg=colors["bg"]), bg="bg")
        actions.pack(fill="x", pady=(px(14), 0))
        self._build_tiles(grid, outer)
        self._button(actions, "Сбросить", self._reset, False).pack(side="left")
        self._button(actions, "Готово", self.top.withdraw, True).pack(side="right")

    def _recolor(self):
        """A new hue repaints the window where it stands: nothing is rebuilt, so nothing moves or blinks."""
        colors = nova_appearance.settings_theme(self.preferences["theme"])
        self.colors = colors
        self.top.configure(bg=colors["bg"])
        for widget, roles in self._themed:
            try:
                widget.configure(**{option: colors[role] for option, role in roles.items()})
            except tk.TclError:
                pass
        for group in (self.tiles, self.sliders, self.switches):
            for widget in group.values():
                widget.recolor(colors)
        self._paint_tiles(self.preferences["accent_hue"])

    def _build_tiles(self, grid, outer):
        """Tiles span the width the other rows already ask for: as many columns as fit, the last row nearly full."""
        px, prefs = self.px, self.preferences
        outer.update_idletasks()
        available = max([child.winfo_reqwidth() for child in outer.winfo_children() if child is not grid] or [0])
        order = self._tile_order()
        gap = px(TILE_GAP)
        columns = tile_columns(len(order), max(available, px(520)), gap, px(TILE_MIN_WIDTH))
        tile_w = max(px(TILE_MIN_WIDTH), max(available, px(520)) // columns - gap)
        thumb_h = round(tile_w * THUMB_H / THUMB_W)
        self.tile_size = (tile_w, thumb_h)
        for index, (key, title) in enumerate(order):
            tile = _Tile(grid, key, title, self.colors, self.fonts, px, self._choose_texture, self.tile_size)
            tile.grid(row=index // columns, column=index % columns, padx=gap // 2, pady=(0, px(5)), sticky="n")
            self.tiles[key] = tile
        self._paint_tiles(prefs["accent_hue"])
        for key, tile in self.tiles.items():
            tile.set_selected(key == prefs["texture"])

    def _tile_order(self):
        keys = [key for key in nova_appearance.TEXTURES if key != "none"]
        keys = [key for key in keys if key != "custom"]
        tail = [("custom", "Своё фото")]  # the full name does not fit a tile caption
        return [(key, nova_appearance.TEXTURES[key]) for key in keys] + tail + [("none", nova_appearance.TEXTURES["none"])]

    def _section(self, parent, text):
        self._t(tk.Label(parent, text=text, bg=self.colors["bg"], fg=self.colors["muted"],
                         font=self.fonts["caption"], anchor="w"), bg="bg", fg="muted").pack(
            fill="x", pady=(self.px(12), self.px(4)))

    def _slider_row(self, parent, key, caption, low, high, unit):
        colors, px = self.colors, self.px
        row = self._t(tk.Frame(parent, bg=colors["bg"]), bg="bg")
        row.pack(fill="x")
        row.grid_columnconfigure(1, weight=1)
        self._t(tk.Label(row, text=caption, bg=colors["bg"], fg=colors["value"], font=self.fonts["control"],
                         anchor="w", width=24), bg="bg", fg="value").grid(row=0, column=0, sticky="w")
        slider = _Slider(row, low, high, self.preferences[key], colors, px,
                         lambda value, final, k=key, u=unit: self._slide(k, u, value, final),
                         rainbow=(key == "accent_hue"))
        slider.grid(row=0, column=1, sticky="we", padx=(px(6), px(6)))
        label = self._t(tk.Label(row, text=value_text(unit, self.preferences[key]), bg=colors["bg"],
                                 fg=colors["text"], font=self.fonts["control"], width=6, anchor="e"),
                        bg="bg", fg="text")
        label.grid(row=0, column=2)
        self.sliders[key] = slider
        self.value_labels[key] = label

    def _button(self, parent, text, command, primary):
        colors = self.colors
        fill = "pill_on_bg" if primary else "panel"
        return self._t(tk.Button(parent, text=text, command=command, relief="flat", bd=0, bg=colors[fill],
                                 fg=colors["text"], activebackground=colors["panel"],
                                 activeforeground=colors["accent"], disabledforeground=colors["muted"],
                                 font=self.fonts["control"], cursor="hand2", padx=self.px(14), pady=self.px(6)),
                       bg=fill, fg="text", activebackground="panel", activeforeground="accent",
                       disabledforeground="muted")

    # ----- previews ---------------------------------------------------------------------------------

    def _custom_cell(self):
        """The chosen picture cut to the tile (cover fit), or None."""
        path = self.preferences.get("custom_image") or ""
        try:
            with Image.open(path) as picture:
                picture = picture.convert("RGB")
        except (OSError, ValueError):
            return None
        scale = max(self.tile_size[0] / picture.width, self.tile_size[1] / picture.height)
        size = (max(1, round(picture.width * scale)), max(1, round(picture.height * scale)))
        picture = picture.resize(size, Image.Resampling.BILINEAR)
        left, top = (size[0] - self.tile_size[0]) // 2, (size[1] - self.tile_size[1]) // 2
        return picture.crop((left, top, left + self.tile_size[0], top + self.tile_size[1]))

    def _paint_tiles(self, hue):
        for key, tile in self.tiles.items():
            if key == "custom":
                tile.set_image(self._custom_cell())
                continue
            cell = atlas_cell(self._atlas, key)
            if cell is None:
                tile.set_image(None)
                continue
            cell = cell.resize(self.tile_size, Image.Resampling.BILINEAR)
            tile.set_image(rotate_hue(cell, hue))

    def _schedule_tiles(self, hue):
        if self._tile_job is not None:
            self.top.after_cancel(self._tile_job)

        def paint():
            self._tile_job = None
            if self.top.winfo_exists():
                self._paint_tiles(hue)
                for key, tile in self.tiles.items():
                    tile.set_selected(key == self.preferences["texture"])
        self._tile_job = self.top.after(70, paint)

    # ----- changes ----------------------------------------------------------------------------------

    def _slide(self, key, unit, value, final):
        self.value_labels[key].configure(text=value_text(unit, value))
        if key == "accent_hue":
            self._schedule_tiles(value)
        self._change(final=final, **{key: value})

    def _set_flag(self, key, value):
        if key == "immersion":
            self.immersion.set(value)
        elif key == "random_texture_on_start":
            self.random_texture.set(value)
        self._change(final=True, **{key: value})

    def _pick_image(self):
        """Ask for a picture; it becomes the (still) background and the texture is switched to it."""
        from tkinter import filedialog
        start = os.path.dirname(self.preferences.get("custom_image") or "") or None
        path = filedialog.askopenfilename(parent=self.top, title="Своё изображение", filetypes=IMAGE_TYPES,
                                          initialdir=start)
        if not path:
            return
        self._change(final=True, custom_image=path, texture="custom")
        self._paint_tiles(self.preferences["accent_hue"])
        for name, tile in self.tiles.items():
            tile.set_selected(name == "custom")

    def _choose_texture(self, key):
        if key == "custom" and not (self.preferences.get("custom_image") or ""):
            self._pick_image()
            return
        if key == self.preferences["texture"] and key not in ("none", "custom"):
            # a second click on the chosen texture draws a new picture of it (there is no separate button)
            self._change(final=True, variant=self.preferences["variant"] + 1)
            return
        for name, tile in self.tiles.items():
            tile.set_selected(name == key)
        self._change(final=True, texture=key)

    def _reset(self):
        defaults = nova_appearance.DEFAULT_PREFERENCES
        values = {key: defaults[key] for key in ("accent_hue", "brightness", "saturation", "speed", "warp")}
        self._change(final=True, **values)
        for key, slider in self.sliders.items():
            slider.set(self.preferences[key])
            unit = next(item[4] for item in SLIDERS if item[0] == key)
            self.value_labels[key].configure(text=value_text(unit, self.preferences[key]))
        self._schedule_tiles(self.preferences["accent_hue"])

    def _change(self, final=True, **values):
        """Apply values. While a slider is dragged the theme (UI colours) stays put and only the picture
        follows; the colour rebuild of every window happens once, when the thumb is released."""
        old_theme = self.preferences["theme"]
        merged = dict(self.preferences, **values)
        if "brightness" in values:
            merged.pop("texture_intensity", None)
        prefs = nova_appearance.normalize_preferences(merged)
        if not final:
            prefs["theme"] = old_theme
        self.preferences = prefs
        self._pending = dict(prefs)
        if final:
            self._flush()
            if prefs["theme"] != old_theme:
                self._recolor()
        elif self._apply_job is None:
            self._apply_job = self.top.after(33, self._flush)

    def _flush(self):
        if self._apply_job is not None:
            try:
                self.top.after_cancel(self._apply_job)
            except tk.TclError:
                pass
            self._apply_job = None
        pending, self._pending = self._pending, None
        if pending is not None:
            self.on_apply(pending)
