"""Nova desktop appearance, aligned with Nova Android.

Palette source: Nova Android/tools/gen_nova_themes.py (THEMES).
Texture reference: Nova Android/app/src/main/java/com/example/nova/
NovaTexturePatterns.kt. Pillow is the only rendering dependency.
Render on a worker; PhotoImage creation and widget updates stay on the Tk thread.
"""

import colorsys
import json
import logging
import math
import os
from pathlib import Path
import random
import tempfile
from functools import lru_cache
import nova_fractal
import nova_android_fractal
import nova_android_textures
import nova_native_render

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont, ImageOps


HUE_COUNT = 64
DEFAULT_HUE = 31

# Themes are gone (D51): one accent hue of 64 drives every colour. These ids exist only so that an old
# appearance.json (and callers that still pass a legacy name) land on the nearest hue.
_LEGACY_ACCENTS = {
    'aurora': '#50C878', 'dnsai': '#5B8CFF', 'proton': '#6D4AFF', 'charcoal': '#4FD8C4',
    'graphene': '#F0B429', 'neon': '#39E6D6', 'poe1': '#C8AA6E', 'poe2': '#C86A32',
    'gta6sunset': '#E9639B', 'gta6night': '#E9639B', 'matrix': '#00FF41', 'diablo2': '#B79A5B',
}


def _hsl(hue, saturation, lightness):
    red, green, blue = colorsys.hls_to_rgb(hue % 1.0, lightness, saturation)
    return '#%02X%02X%02X' % (round(red * 255), round(green * 255), round(blue * 255))


def hue_theme_id(index):
    return 'hue%d' % (int(index) % HUE_COUNT)


def hue_of_color(color):
    """Nearest hue index of a '#RRGGBB' colour; greys fall to the default teal."""
    try:
        text = color.strip().lstrip('#')
        red, green, blue = (int(text[i:i + 2], 16) / 255.0 for i in (0, 2, 4))
    except (AttributeError, ValueError, IndexError):
        return DEFAULT_HUE
    hue, light, saturation = colorsys.rgb_to_hls(red, green, blue)
    if saturation < 0.12 or light < 0.04 or light > 0.96:
        return DEFAULT_HUE
    return round(hue * HUE_COUNT) % HUE_COUNT


def hue_from_theme_id(theme_id):
    """hue index for 'hue12' or a legacy theme name; None for anything else."""
    if isinstance(theme_id, str):
        if theme_id.startswith('hue') and theme_id[3:].isdigit():
            return int(theme_id[3:]) % HUE_COUNT
        if theme_id in _LEGACY_ACCENTS:
            return hue_of_color(_LEGACY_ACCENTS[theme_id])
    return None


def _hue_theme(index):
    """The lab's derivation (D51): accent HSL(H,.68,.56), second HSL(H-.07,.55,.78), dark ground of that hue."""
    hue = index / HUE_COUNT
    accent = _hsl(hue, .68, .56)
    second = _hsl(hue - .07, .55, .78)
    ground = (_hsl(hue, .30, .045), _hsl(hue, .30, .06), _hsl(hue, .30, .085))
    title = 'Hue %d' % index
    return {'name': title, 'title': title, 'font_family': 'Segoe UI', 'radius': 14,
            'bg': ground, 'accent': accent, 'accent_on': ground[0],
            'card_fill': '#14FFFFFF', 'card_stroke': '#2EFFFFFF',
            'group_from': accent, 'group_to': second,
            't_title': '#EEF2F8', 't_value': _mix(second, '#FFFFFF', .35), 't_hint': '#A3ABBE',
            'switch_on': accent, 'field_fill': '#14FFFFFF', 'field_stroke': '#26FFFFFF'}


class _ThemeTable(dict):
    """64 generated hue themes; legacy names resolve to the nearest hue and are not iterated."""

    def __init__(self):
        super().__init__()
        for index in range(HUE_COUNT):
            self[hue_theme_id(index)] = _hue_theme(index)

    def __missing__(self, key):
        index = hue_from_theme_id(key)
        if index is None:
            raise KeyError(key)
        return dict.__getitem__(self, hue_theme_id(index))

    def __contains__(self, key):
        return hue_from_theme_id(key) is not None

    def get(self, key, default=None):
        return self[key] if key in self else default


TEXTURES = {
    'none': 'Без фактуры', 'basalt': 'Базальт', 'marble': 'Мрамор', 'wood': 'Дерево',
    'sand': 'Песок', 'grass': 'Луг', 'cracks': 'Трещины', 'water': 'Вода', 'ether': 'Эфир', 'aurora': 'Полярное сияние',
    'smoke': 'Дым', 'starfield': 'Космос', 'constellation': 'Созвездия', 'slime': 'Плазма',
    'rain': 'Дождь', 'lightning': 'Молния',
    'snow': 'Снег', 'fractal': 'Фрактал 1', 'fractal2': 'Фрактал 2', 'warp': 'WARP', 'maze': 'Лабиринт', 'matrix': 'Matrix', 'custom': 'Своё изображение',
}

# D43: owner-designed live immersion; each frame is rendered natively as a function of time.
LIVE_TEXTURES = frozenset(('sand', 'grass', 'cracks', 'starfield', 'splatter',
                           'lightning', 'snow', 'fractal'))
# Live frames are computed below display size and filtered up; motion hides the softness.
LIVE_MAX_SIDE = 960
# Saved names from older versions. The owner deleted Crystals; its slot goes to Cracks.
_RENAMED_TEXTURES = {'shards': 'cracks', 'crystals': 'cracks', 'splatter': 'rain'}
# New GPU-only textures keep a CPU stand-in for machines without GL 3.3 (the old look of the name).
_CPU_TEXTURES = {'rain': 'splatter', 'ether': 'water', 'constellation': 'starfield',
                 'fractal2': 'fractal', 'warp': 'starfield', 'aurora': 'smoke', 'maze': 'basalt', 'custom': 'none'}

# The owner's own settings after the first real use of the new window (2026-11-12): everyone starts from them, a random
# texture on every start included (the switch in the window turns it off). The texture itself stays undecided.
# DEFAULT_HUE (31) is only the hue the preview atlas was baked at.
DEFAULT_PREFERENCES = {
    'accent_hue': 27, 'theme': hue_theme_id(27), 'texture': 'marble',
    'brightness': 80, 'texture_intensity': 0.2667, 'saturation': 100, 'speed': 25, 'warp': 30,
    'variant': 0, 'temperature': 0, 'immersion': True, 'random_texture_on_start': True,
    'sync_monitor': True, 'limit_30fps': False, 'custom_image': '',
    # NOVA caption on the main window: the glass folds into pills around the text (true) or covers the cards (false).
    'glass_compact': False,
}


def brightness_from_intensity(value):
    """Old texture_intensity 0..0.6 (default .30) -> brightness 0..100 (default 90, the lab's value)."""
    return value / 0.30 * 90.0 if value <= 0.30 else 90.0 + (value - 0.30) / 0.30 * 10.0


def intensity_from_brightness(value):
    """Inverse of brightness_from_intensity: what the CPU renderer mixes in (0..0.6)."""
    return value / 90.0 * 0.30 if value <= 90 else 0.30 + (value - 90) / 10.0 * 0.30


def cpu_texture(texture_id):
    """The texture the CPU renderer draws for a name (GPU-only names borrow an older look)."""
    return _CPU_TEXTURES.get(texture_id, texture_id)


def _number(value, default, low, high):
    try:
        value = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(value):
        return default
    return min(high, max(low, value))


def _flag(values, key, default):
    value = values.get(key, default)
    return value if isinstance(value, bool) else default


def _preferences(values):
    if not isinstance(values, dict):
        return dict(DEFAULT_PREFERENCES)
    texture = values.get('texture')
    texture = _RENAMED_TEXTURES.get(texture, texture) if isinstance(texture, str) else texture
    # accent_hue wins; a file from before D51 only has `theme`, which becomes its nearest hue.
    custom = values.get('custom_image', '')
    hue = values.get('accent_hue')
    if isinstance(hue, bool) or not isinstance(hue, (int, float)):
        legacy = hue_from_theme_id(values.get('theme'))
        hue = DEFAULT_PREFERENCES['accent_hue'] if legacy is None else legacy
    hue = int(_number(hue, DEFAULT_PREFERENCES['accent_hue'], 0, HUE_COUNT - 1))
    if 'brightness' in values:
        brightness = _number(values.get('brightness'), DEFAULT_PREFERENCES['brightness'], 0, 100)
    else:
        brightness = brightness_from_intensity(_number(
            values.get('texture_intensity'), DEFAULT_PREFERENCES['texture_intensity'], 0, 0.6))
    return {
        'accent_hue': hue,
        'theme': hue_theme_id(hue),
        'texture': texture if isinstance(texture, str) and texture in TEXTURES else DEFAULT_PREFERENCES['texture'],
        'brightness': int(round(brightness)),
        'texture_intensity': round(intensity_from_brightness(brightness), 4),
        'saturation': int(_number(values.get('saturation'), DEFAULT_PREFERENCES['saturation'], 0, 200)),
        'speed': int(_number(values.get('speed'), DEFAULT_PREFERENCES['speed'], 0, 300)),
        'warp': int(_number(values.get('warp'), DEFAULT_PREFERENCES['warp'], 0, 100)),
        'variant': int(_number(values.get('variant'), 0, 0, 2 ** 31 - 1)),
        'temperature': 0,
        'immersion': values.get('immersion', DEFAULT_PREFERENCES['immersion']) is True,
        'random_texture_on_start': values.get(
            'random_texture_on_start', DEFAULT_PREFERENCES['random_texture_on_start']) is True,
        'sync_monitor': _flag(values, 'sync_monitor', True),
        'limit_30fps': _flag(values, 'limit_30fps', False),
        'custom_image': custom if isinstance(custom, str) and len(custom) <= 1024 else '',
        'glass_compact': _flag(values, 'glass_compact', False),
    }


normalize_preferences = _preferences


def load_preferences(path):
    """Read a separate appearance file; a damaged file is reported, then defaults apply."""
    try:
        with open(path, 'r', encoding='utf-8-sig') as stream:
            return _preferences(json.load(stream))
    except FileNotFoundError:
        return dict(DEFAULT_PREFERENCES)
    except (OSError, ValueError) as exc:
        logging.getLogger(__name__).warning('Cannot read appearance preferences: %s', exc)
        return dict(DEFAULT_PREFERENCES)


def startup_preferences(path, choose=None):
    """Choose once per process startup; persist the last texture before rendering."""
    prefs = load_preferences(path)
    if not prefs['random_texture_on_start']:
        return prefs
    candidates = [key for key in TEXTURES if key not in ('none', 'custom', prefs['texture'])]
    if not candidates:
        return prefs
    next_prefs = dict(prefs, texture=(choose or random.SystemRandom().choice)(candidates))
    try:
        save_preferences(path, next_prefs)
    except OSError as error:
        logging.getLogger(__name__).error('Cannot persist startup texture; keeping saved texture: %s', error)
        return prefs
    return next_prefs


def save_preferences(path, prefs):
    """Save atomically. Write errors propagate so callers can show a useful error."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open('r', encoding='utf-8-sig') as stream:
            previous = json.load(stream)
    except FileNotFoundError:
        previous = {}
    if not isinstance(previous, dict) or not isinstance(prefs, dict):
        raise ValueError('Appearance preferences must be an object')
    merged = dict(previous, **prefs)
    merged.update(_preferences(merged))
    descriptor, temporary = tempfile.mkstemp(prefix=destination.name + '.', suffix='.tmp',
                                              dir=str(destination.parent))
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(merged, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _rgb(color):
    value = color.lstrip('#')[-6:]
    return tuple(int(value[index:index + 2], 16) for index in (0, 2, 4))


def _mix(first, second, amount):
    a, b = _rgb(first), _rgb(second)
    return '#%02X%02X%02X' % tuple(round(x + (y - x) * amount) for x, y in zip(a, b))


def _over(color, base):
    if len(color) == 9:
        return _mix(base, '#' + color[3:], int(color[1:3], 16) / 255.0)
    return color


def _veil(target, base):
    """Android's veil(): keep the panel colour while revealing the shared texture."""
    if len(target) == 9:
        return target
    colors, background = _rgb(target), _rgb(base)
    need = 0.0
    for color, behind in zip(colors, background):
        if color > behind:
            need = max(need, (color - behind) / (255 - behind))
        elif color < behind:
            need = max(need, (behind - color) / behind)
    alpha = max(0x0B, math.ceil(min(1.0, need * 1.3) * 255))
    amount = alpha / 255.0
    channels = [round(min(255, max(0, (color - (1 - amount) * behind) / amount)))
                for color, behind in zip(colors, background)]
    return '#%02X%02X%02X%02X' % (alpha, *channels)


THEMES = _ThemeTable()


def font_roles(theme_id='aurora'):
    """Use the native Semibold face consistently; logs keep a monospace face."""
    display = 'Segoe UI Semibold'
    body = 'Segoe UI Semibold'
    return {
        'brand': (display, 20),
        'title': (display, 16),
        'body': (body, 10),
        'control': (body, 9),
        'action': ('Segoe UI Semibold', 11),
        'status': (display, 12),
        'section': (body, 9),
        'caption': (body, 9),
        'mono': ('Consolas', 9),
    }


def settings_theme(theme_id='aurora'):
    """Compatible with nova.pyw SETTINGS_THEME and nova_profiles_ui contexts."""
    theme = THEMES.get(theme_id, THEMES['aurora'])
    fonts = font_roles(theme_id)
    base = theme['bg'][1]
    fill = theme['card_fill']
    if isinstance(fill, tuple):
        fill = fill[0]
    panel = _over(fill, base)
    return {
        'bg': base, 'panel': panel, 'border': _over(theme['card_stroke'], base),
        'text': theme['t_title'], 'muted': theme['t_hint'], 'value': theme['t_value'],
        'accent': theme['accent'], 'font_family': fonts['body'][0],
        'heading_family': fonts['title'][0], 'status_family': fonts['status'][0],
        'control_family': fonts['control'][0], 'mono_family': fonts['mono'][0],
        'theme_id': theme_id if theme_id in THEMES else 'aurora',
        'radius': theme['radius'], 'field': _over(theme['field_fill'], base),
        'pill_on_bg': _mix(panel, theme['accent'], 0.20),
        'pill_on_fg': theme['t_title'],
        'pill_off_bg': _mix(panel, theme['t_title'], 0.035),
        'pill_off_fg': theme['t_value'],
    }


def log_theme(theme_id='aurora'):
    theme = settings_theme(theme_id)
    return {
        'bg': THEMES.get(theme_id, THEMES['aurora'])['bg'][0],
        'panel': theme['bg'], 'text': theme['text'], 'button': theme['panel'],
        'button_hover': theme['pill_on_bg'], 'button_fg': theme['value'],
        'button_hover_fg': theme['text'], 'grip': theme['border'],
    }


def _noise(width, height, rng, octaves=5, base=3):
    """Deterministic multiscale field. Smooth resampling avoids visible tile seams."""
    result = Image.new('L', (width, height), 0)
    weight = 0.0
    for octave in range(octaves):
        frequency = base * (2.03 ** octave)
        short = max(1, min(width, height))
        nx = max(2, round(frequency * width / short))
        ny = max(2, round(frequency * height / short))
        coarse = Image.frombytes('L', (nx, ny), bytes(rng.randrange(256) for _ in range(nx * ny)))
        field = coarse.resize((width, height), Image.Resampling.BICUBIC)
        amplitude = 0.52 ** octave
        result = Image.blend(result, field, amplitude / (weight + amplitude))
        weight += amplitude
    return result


def _voronoi(width, height, rng, cell=70, generations=1):
    pixels = [0] * (width * height)
    for generation in range(generations):
        step = max(10, cell / (2.03 ** generation))
        cols = math.ceil(width / step) + 2
        rows = math.ceil(height / step) + 2
        points = {(x, y): ((x - 0.5 + rng.random()) * step,
                           (y - 0.5 + rng.random()) * step)
                  for y in range(-1, rows) for x in range(-1, cols)}
        line = max(0.6, 1.3 / (generation + 1))
        for y in range(height):
            cy = int(y // step)
            for x in range(width):
                cx = int(x // step)
                nearest, second = float('inf'), float('inf')
                for gy in range(cy - 1, cy + 2):
                    for gx in range(cx - 1, cx + 2):
                        px, py = points[gx, gy]
                        distance = (x - px) ** 2 + (y - py) ** 2
                        if distance < nearest:
                            second, nearest = nearest, distance
                        elif distance < second:
                            second = distance
                gap = math.sqrt(second) - math.sqrt(nearest)
                seam = max(0, 1 - gap / line)
                index = y * width + x
                pixels[index] = max(pixels[index], round(seam * (220 - generation * 30)))
    image = Image.new('L', (width, height))
    image.putdata(pixels)
    return image


def _mandelbrot(width, height, rng):
    return Image.frombytes('L', (width, height), nova_fractal.render_mask(width, height, rng))


def _draw_branch(draw, rng, start, end, depth, width, tone=220, branches=True):
    if depth <= 0:
        draw.line((start, end), fill=tone, width=max(1, width))
        return
    x0, y0 = start
    x1, y1 = end
    dx, dy = x1 - x0, y1 - y0
    shift = rng.uniform(-0.18, 0.18)
    mid = ((x0 + x1) / 2 - dy * shift, (y0 + y1) / 2 + dx * shift)
    _draw_branch(draw, rng, start, mid, depth - 1, width, tone, branches)
    _draw_branch(draw, rng, mid, end, depth - 1, width, tone, branches)
    if branches and depth > 2 and rng.random() < 0.42:
        turn = rng.choice((-1, 1)) * rng.uniform(0.4, 0.8)
        bx = dx * math.cos(turn) - dy * math.sin(turn)
        by = dx * math.sin(turn) + dy * math.cos(turn)
        end_branch = mid[0] + bx * 0.55, mid[1] + by * 0.55
        _draw_branch(draw, rng, mid, end_branch, depth - 2, 1, max(40, tone - 55), False)


@lru_cache(maxsize=4)
def _texture_mask(texture, width, height, variant):
    if texture != 'fractal' and os.environ.get('NOVA_ANDROID_TEXTURES') != '0':
        return Image.frombytes('L', (width, height), nova_android_textures.render_mask(texture, width, height, variant))
    seed = 0x4E4F5641 + list(TEXTURES).index(texture) * 7919 + variant * 6700417
    rng = random.Random(seed)
    if texture == 'fractal':
        return Image.frombytes('L', (width, height), nova_android_fractal.render_mask(width, height, variant))
    field = _noise(width, height, rng)
    noise = list(field.getdata())
    if texture in ('basalt', 'cracks'):
        seams = _voronoi(width, height, rng, max(22, min(width, height) // 5),
                         3 if texture == 'cracks' else 1)
        if texture == 'basalt':
            return ImageChops.add(ImageOps.invert(seams).point(lambda v: v // 4), field.point(lambda v: v // 6))
        return ImageChops.lighter(seams, field.point(lambda v: v // 10))

    image = field.point(lambda v: v // 10)
    draw = ImageDraw.Draw(image)
    short = min(width, height)
    if texture in ('marble', 'wood', 'sand', 'water', 'smoke', 'slime'):
        pixels = bytearray(width * height)
        blobs = [(rng.random() * width, rng.random() * height, rng.uniform(0.12, 0.25) * short)
                 for _ in range(12)] if texture == 'slime' else []
        for y in range(height):
            for x in range(width):
                u, v = x / short, y / short
                n = noise[y * width + x] / 255
                warp = n * 2 - 1
                if texture == 'marble':
                    vein = abs(math.sin((u * 3.5 + v * 1.2 + warp * 2.8) * math.pi))
                    tone = 0.08 + 0.60 * ((1 - vein) ** 5) + 0.14 * n
                elif texture == 'wood':
                    ring = math.hypot(u + 0.8 + warp * 0.14, (v - 0.45) * 0.44)
                    tone = 0.12 + 0.42 * (0.5 + 0.5 * math.sin(ring * 82 + warp * 4)) ** 4
                elif texture == 'sand':
                    dune = u * 20 + v * 7 + warp * 6
                    tone = 0.12 + 0.48 * (0.5 + 0.5 * math.cos(dune)) + 0.08 * n
                elif texture == 'water':
                    a = 1 - abs(math.sin(u * 22 + v * 9 + warp * 5))
                    b = 1 - abs(math.sin(u * 9 - v * 24 - warp * 4))
                    tone = 0.05 + (a * b) ** 2 * 0.80
                elif texture == 'smoke':
                    cloud = max(0, (n - 0.30) / 0.7)
                    tone = 0.02 + cloud ** 2 * 0.9 * (0.45 + 0.55 * v / (height / short))
                else:
                    total = sum(max(0, 1 - ((x - bx) ** 2 + (y - by) ** 2) / (radius * radius)) ** 2
                                for bx, by, radius in blobs)
                    edge = max(0, 1 - abs(total - 0.48) * 7)
                    tone = 0.04 + min(0.65, total * 0.32) + edge * 0.35
                pixels[y * width + x] = max(0, min(255, round(tone * 255)))
        return Image.frombytes('L', (width, height), bytes(pixels))

    if texture == 'grass':
        for tier, count in enumerate((220, 130, 70)):
            for _ in range(count):
                x, y = rng.uniform(-5, width + 5), rng.uniform(0, height + 20)
                length = rng.uniform(0.025, 0.11) * short * (1 + tier * 0.25)
                bend = rng.uniform(-0.5, 0.5) * length
                tone = (55, 105, 180)[tier]
                points = [(x, y), (x + bend * 0.25, y - length * 0.5), (x + bend, y - length)]
                draw.line(points, fill=tone, width=1 if tier < 2 else 2)
                if tier == 2 and rng.random() < 0.35:
                    draw.line((points[1], (x + bend - length * 0.35, y - length * 0.7)), fill=tone, width=1)
    elif texture == 'starfield':
        image = ImageChops.add(image, field.point(lambda v: max(0, v - 115) * 2))
        draw = ImageDraw.Draw(image)
        for _ in range(round(width * height / 95)):
            x, y = rng.randrange(width), rng.randrange(height)
            tone = rng.randrange(45, 175)
            draw.point((x, y), fill=tone)
        for _ in range(12):
            x, y = rng.randrange(width), rng.randrange(height)
            radius = rng.randrange(1, 4)
            draw.line((x - radius, y, x + radius, y), fill=170)
            draw.line((x, y - radius, x, y + radius), fill=170)
            draw.point((x, y), fill=255)
    elif texture == 'shards':
        impact = rng.uniform(0.2, 0.8) * width, rng.uniform(0.2, 0.8) * height

        def split(poly, depth):
            if depth <= 0:
                draw.polygon(poly, fill=rng.randrange(15, 75), outline=120)
                return
            a, b, c = poly
            middle = ((a[0] + b[0] + c[0]) / 3 + rng.uniform(-5, 5),
                      (a[1] + b[1] + c[1]) / 3 + rng.uniform(-5, 5))
            for first, second in ((a, b), (b, c), (c, a)):
                split((first, second, middle), depth - 1)
        corners = ((0, 0), (width, 0), (width, height), (0, height))
        for index in range(4):
            split((impact, corners[index], corners[(index + 1) % 4]), 3)
    elif texture == 'splatter':
        for _ in range(7):
            cx, cy = rng.randrange(width), rng.randrange(height)
            radius = rng.uniform(0.025, 0.07) * short
            draw.ellipse((cx - radius, cy - radius, cx + radius, cy + radius), fill=180)
            for _ in range(rng.randrange(14, 24)):
                angle, reach = rng.random() * math.tau, rng.uniform(1.1, 3.5) * radius
                x, y = cx + math.cos(angle) * reach, cy + math.sin(angle) * reach
                draw.line((cx, cy, x, y), fill=150, width=max(1, round(radius * 0.13)))
                drop = rng.uniform(0.5, 2)
                draw.ellipse((x - drop, y - drop, x + drop, y + drop), fill=180)
    elif texture == 'lightning':
        for _ in range(3):
            start = rng.uniform(0.1, 0.9) * width, -5
            end = rng.uniform(0, 1) * width, height * rng.uniform(0.75, 1.2)
            _draw_branch(draw, rng, start, end, 7, 1)
        image = ImageChops.add(image, image.filter(ImageFilter.GaussianBlur(3)))
    elif texture == 'snow':
        def limb(cx, cy, angle, length, depth, tone):
            ex, ey = cx + math.cos(angle) * length, cy + math.sin(angle) * length
            draw.line((cx, cy, ex, ey), fill=tone, width=1)
            if depth:
                for station in (0.28, 0.53, 0.73):
                    x, y = cx + (ex - cx) * station, cy + (ey - cy) * station
                    for side in (-1, 1):
                        limb(x, y, angle + side * math.pi / 3,
                             length * (1 - station) * 0.42, depth - 1, tone)
        for _ in range(32):
            cx, cy = rng.uniform(0, width), rng.uniform(0, height)
            radius, angle, tone = rng.uniform(0.025, 0.085) * short, rng.random() * math.tau, rng.randrange(60, 220)
            for ray in range(6):
                limb(cx, cy, angle + ray * math.pi / 3, radius, 2, tone)
    elif texture == 'matrix':
        font = ImageFont.load_default()
        cell = 9
        for x in range(0, width, cell):
            head = rng.randrange(height)
            length = rng.randrange(6, 22)
            for index in range(length):
                y = (head - index * 11) % height
                tone = max(15, round(230 * (1 - index / length)))
                draw.text((x, y), rng.choice('012345789ABCDEFGHIJKLMNOPQRSTUVWXYZ'), font=font, fill=tone)
    return image


def _gradient(width, height, colors):
    stops = [_rgb(color) for color in colors]
    data = bytearray(height * 3)
    for y in range(height):
        position = y / max(1, height - 1) * (len(stops) - 1)
        index = min(len(stops) - 2, int(position))
        fraction = position - index
        for channel in range(3):
            data[y * 3 + channel] = round(stops[index][channel] * (1 - fraction) + stops[index + 1][channel] * fraction)
    return Image.frombytes('RGB', (1, height), bytes(data)).resize((width, height))


@lru_cache(maxsize=4)
def _render_background(width, height, theme_id, texture_id, intensity, variant, temperature):
    if texture_id == 'fractal':
        return render_fractal_background(width, height, theme_id, intensity, variant, temperature,
                                         (max(8, width), max(8, height)), (0., 0., 1., 1.))
    theme = THEMES[theme_id]
    image = _gradient(width, height, theme['bg'])
    # A quiet side light gives the desktop composition depth without busy text areas.
    ambient = Image.new('L', (128, 128), 0)
    light = ImageDraw.Draw(ambient)
    light.ellipse((-65, -35, 110, 100), fill=20)
    ambient = ambient.filter(ImageFilter.GaussianBlur(35)).resize((width, height), Image.Resampling.BILINEAR)
    image = Image.composite(Image.new('RGB', image.size, theme['accent']), image, ambient)
    if texture_id != 'none' and intensity > 0:
        longest = 1440
        scale = min(1, longest / max(width, height))
        mask = _texture_mask(texture_id, max(8, round(width * scale)), max(8, round(height * scale)), variant)
        mask = mask.resize((width, height), Image.Resampling.BILINEAR).point(lambda value: round(value * intensity))
        image = Image.composite(Image.new('RGB', image.size, theme['accent']), image, mask)
    return _temperature(image, temperature)


def _temperature(image, temperature):
    width, height = image.size
    if temperature:
        tint = '#FFA84A' if temperature > 0 else '#60AAFF'
        strength = abs(temperature) / 100 * 36
        mask = Image.new('L', (1, height))
        mask.putdata([round(strength * (1 - 0.65 * y / max(1, height - 1))) for y in range(height)])
        image = Image.composite(Image.new('RGB', image.size, tint), image, mask.resize(image.size))
    return image


def render_fractal_background(width, height, theme_id, intensity, variant, temperature, source, crop):
    """Stable seeded Mandelbrot geometry with a filtered escape-time color gradient."""
    image = render_background(width, height, theme_id, 'none', 0, 0, 0)
    if intensity <= 0:
        return _temperature(image, temperature)
    ratio = min(1.0, 1440 / max(width, height))
    mw, mh = max(8, round(width * ratio)), max(8, round(height * ratio))
    pixels = nova_android_fractal.render_color(mw, mh, variant, source=source, crop=crop)
    color = Image.frombytes('RGB', (mw, mh), pixels)
    if color.size != image.size:
        color = color.resize(image.size, Image.Resampling.BILINEAR)
    color = color.filter(ImageFilter.GaussianBlur(.55))
    color = Image.blend(color, Image.new('RGB', image.size, THEMES[theme_id]['accent']), .12)
    image = Image.blend(image, color, intensity)
    return _temperature(image, temperature)


def live_enabled(texture_id):
    return cpu_texture(texture_id) in LIVE_TEXTURES and os.environ.get('NOVA_ANDROID_TEXTURES') != '0'


def render_live_background(width, height, theme_id, texture_id, intensity, variant, temperature, elapsed):
    """One live immersion frame (D43); elapsed=0 is the still picture when immersion is off."""
    texture_id = cpu_texture(texture_id)
    image = render_background(width, height, theme_id, 'none', 0, 0, 0)
    if intensity <= 0:
        return _temperature(image, temperature)
    ratio = min(1.0, LIVE_MAX_SIDE / max(width, height))
    mw, mh = max(8, round(width * ratio)), max(8, round(height * ratio))
    result = nova_native_render.live_texture(texture_id, mw, mh, variant, max(0., float(elapsed)))
    if result is None:
        reason = nova_native_render._disabled_reason or 'нативный расчёт выключен'
        raise RuntimeError(f'Генератор живых фактур недоступен: {reason}. Обновите nova-engine.exe.')
    pixels, channels = result
    accent = THEMES[theme_id]['accent']
    if channels == 3:
        color = Image.frombytes('RGB', (mw, mh), pixels)
        if color.size != image.size:
            color = color.resize(image.size, Image.Resampling.BILINEAR)
        color = color.filter(ImageFilter.GaussianBlur(.55))
        color = Image.blend(color, Image.new('RGB', image.size, accent), .12)
        image = Image.blend(image, color, intensity)
    else:
        mask = Image.frombytes('L', (mw, mh), pixels)
        if mask.size != image.size:
            mask = mask.resize(image.size, Image.Resampling.BILINEAR)
        mask = mask.point(lambda value: round(value * intensity))
        image = Image.composite(Image.new('RGB', image.size, accent), image, mask)
    return _temperature(image, temperature)


def render_matrix_background(width, height, theme_id, intensity, variant, temperature, source, crop, elapsed):
    image = render_background(width, height, theme_id, 'none', 0, 0, 0)
    if intensity <= 0:
        return _temperature(image, temperature)
    ratio = min(1.0, 1440 / max(width, height))
    mw, mh = max(8, round(width * ratio)), max(8, round(height * ratio))
    pixels = nova_android_textures.render_matrix(mw, mh, variant, elapsed, source, crop, intensity)
    mask = Image.frombytes('L', (mw, mh), pixels)
    if mask.size != image.size:
        mask = mask.resize(image.size, Image.Resampling.LANCZOS)
    image = Image.composite(Image.new('RGB', image.size, THEMES[theme_id]['accent']), image, mask)
    return _temperature(image, temperature)


def render_background(width, height, theme_id='aurora', texture_id='none', intensity=0.18,
                      variant=0, temperature=0):
    """Return an independent RGB image. Cache holds at most four desktop surfaces."""
    width, height = int(width), int(height)
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise ValueError('Appearance dimensions must be within 1..4096')
    theme_id = theme_id if theme_id in THEMES else 'aurora'
    texture_id = cpu_texture(texture_id) if texture_id in TEXTURES else 'none'
    intensity = round(_number(intensity, 0.18, 0, 0.6), 3)
    variant = int(_number(variant, 0, 0, 2 ** 31 - 1))
    temperature = int(_number(temperature, 0, -100, 100))
    if live_enabled(texture_id):
        return render_live_background(width, height, theme_id, texture_id, intensity, variant, temperature, 0.)
    if texture_id == 'matrix' and os.environ.get('NOVA_ANDROID_TEXTURES') != '0':
        return render_matrix_background(width, height, theme_id, intensity, variant, temperature,
                                        (width, height), (0., 0., 1., 1.), 0.)
    return _render_background(width, height, theme_id, texture_id, intensity, variant, temperature).copy()


def render_surface(width, height, theme_id='aurora', radius=None, selected=False):
    """Draw a transparent, antialiased card for Canvas image items."""
    theme = THEMES.get(theme_id, THEMES['aurora'])
    colors = theme['card_fill']
    if not isinstance(colors, tuple):
        colors = (colors, colors)
    stops = [_veil(value, theme['bg'][1]) for value in colors]
    rgba = [(*_rgb(value), int(value[1:3], 16)) for value in stops]
    rows = []
    for y in range(height * 2):
        position = y / max(1, height * 2 - 1) * (len(rgba) - 1)
        index = min(len(rgba) - 2, int(position))
        fraction = position - index
        rows.append(tuple(round(a * (1 - fraction) + b * fraction)
                          for a, b in zip(rgba[index], rgba[index + 1])))
    fill = Image.new('RGBA', (1, height * 2))
    fill.putdata(rows)
    fill = fill.resize((width * 2, height * 2))
    alpha = Image.new('L', fill.size, 0)
    draw = ImageDraw.Draw(alpha)
    corner = theme['radius'] if radius is None else radius
    box = (1, 1, width * 2 - 2, height * 2 - 2)
    draw.rounded_rectangle(box, radius=max(0, corner * 2), fill=255)
    fill.putalpha(ImageChops.multiply(fill.getchannel('A'), alpha))
    stroke = theme['accent'] if selected else theme['card_stroke']
    border = (*_rgb(stroke), int(stroke[1:3], 16) if len(stroke) == 9 else 255)
    ImageDraw.Draw(fill).rounded_rectangle(box, radius=max(0, corner * 2), outline=border, width=2)
    if theme_id == 'diablo2':
        draw = ImageDraw.Draw(fill)
        draw.line((8, 5, width * 2 - 8, 5), fill='#B79A5B', width=2)
        draw.line((8, height * 2 - 5, width * 2 - 8, height * 2 - 5), fill='#40351F', width=2)
    return fill.resize((width, height), Image.Resampling.LANCZOS)
