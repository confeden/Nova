"""Nova desktop appearance, aligned with Nova Android.

Palette source: Nova Android/tools/gen_nova_themes.py (THEMES).
Texture reference: Nova Android/app/src/main/java/com/example/nova/
NovaTexturePatterns.kt. Pillow is the only rendering dependency.
Render on a worker; PhotoImage creation and widget updates stay on the Tk thread.
"""

import json
import logging
import math
import os
from pathlib import Path
import random
import tempfile
from functools import lru_cache

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont, ImageOps


THEMES = {'aurora': {'name': 'Aurora mint',
            'title': 'Aurora mint',
            'font_family': 'Segoe UI',
            'radius': 14,
            'bg': ('#090817', '#120D27', '#1B1238'),
            'accent': '#50C878',
            'accent_on': '#090817',
            'card_fill': '#0BFFFFFF',
            'card_stroke': '#1FA88DFF',
            'group_from': '#50C878',
            'group_to': '#9FD9BC',
            't_title': '#EEF0F8',
            't_value': '#A8ADD4',
            't_hint': '#7A7FA8',
            'switch_on': '#50C878',
            'field_fill': '#0BFFFFFF',
            'field_stroke': '#18A88DFF'},
 'dnsai': {'name': 'DNS-AI',
           'title': 'DNS-AI',
           'font_family': 'Segoe UI',
           'radius': 14,
           'bg': ('#0D1117', '#0F141C', '#111823'),
           'accent': '#5B8CFF',
           'accent_on': '#0D1117',
           'card_fill': '#161B22',
           'card_stroke': '#12FFFFFF',
           'group_from': '#EEF4FF',
           'group_to': '#7FE0BD',
           't_title': '#E8ECF3',
           't_value': '#A8B0BF',
           't_hint': '#7B8494',
           'switch_on': '#5B8CFF',
           'field_fill': '#0BFFFFFF',
           'field_stroke': '#21FFFFFF'},
 'proton': {'name': 'Proton',
            'title': 'Proton',
            'font_family': 'Segoe UI',
            'radius': 14,
            'bg': ('#16141C', '#1A1824', '#1C1B24'),
            'accent': '#6D4AFF',
            'accent_on': '#FFFFFF',
            'card_fill': '#242230',
            'card_stroke': '#2E2B3C',
            'group_from': '#8A6EFF',
            'group_to': '#EDEAF8',
            't_title': '#EDEAF8',
            't_value': '#B0ABCC',
            't_hint': '#706B8A',
            'switch_on': '#6D4AFF',
            'field_fill': '#1C1A26',
            'field_stroke': '#2E2B3C'},
 'charcoal': {'name': 'Charcoal birch',
              'title': 'Charcoal birch',
              'font_family': 'Segoe UI',
              'radius': 16,
              'bg': ('#08090C', '#0B0C10', '#0E1014'),
              'accent': '#4FD8C4',
              'accent_on': '#08090C',
              'card_fill': '#0BFFFFFF',
              'card_stroke': '#13FFFFFF',
              'group_from': '#4FD8C4',
              'group_to': '#C9D2D8',
              't_title': '#F2F4F7',
              't_value': '#9AA3AE',
              't_hint': '#7A8290',
              'switch_on': '#4FD8C4',
              'field_fill': '#0BFFFFFF',
              'field_stroke': '#13FFFFFF'},
 'graphene': {'name': 'Graphene golden',
              'title': 'Graphene golden',
              'font_family': 'Segoe UI',
              'radius': 12,
              'bg': ('#101215', '#13161A', '#16191E'),
              'accent': '#F0B429',
              'accent_on': '#101215',
              'card_fill': '#1B1F25',
              'card_stroke': '#12FFFFFF',
              'group_from': '#F0B429',
              'group_to': '#F0E6D0',
              't_title': '#E8EAF0',
              't_value': '#9098A8',
              't_hint': '#636B78',
              'switch_on': '#F0B429',
              'field_fill': '#22262D',
              'field_stroke': '#14FFFFFF'},
 'neon': {'name': 'Cyber neon',
          'title': 'Cyber neon',
          'font_family': 'Segoe UI',
          'radius': 12,
          'bg': ('#0A0A12', '#0C0A16', '#0E0B1A'),
          'accent': '#39E6D6',
          'accent_on': '#0A0A12',
          'card_fill': '#08FFFFFF',
          'card_stroke': '#3839E6D6',
          'group_from': '#39E6D6',
          'group_to': '#FF5FBF',
          't_title': '#D6D9E6',
          't_value': '#8C93A8',
          't_hint': '#5F6678',
          'switch_on': '#39E6D6',
          'field_fill': '#0DFFFFFF',
          'field_stroke': '#2839E6D6'},
 'poe1': {'name': 'Path of Exile 1',
          'title': 'Path of Exile 1',
          'font_family': 'Georgia',
          'radius': 4,
          'bg': ('#0A0705', '#14100B', '#1A150E'),
          'accent': '#C8AA6E',
          'accent_on': '#0A0705',
          'card_fill': '#1E1810',
          'card_stroke': '#8B7343',
          'group_from': '#E8DCC0',
          'group_to': '#C8AA6E',
          't_title': '#C9BFA8',
          't_value': '#8A8073',
          't_hint': '#6B6254',
          'switch_on': '#9B2C2C',
          'field_fill': '#17110A',
          'field_stroke': '#6E5A33'},
 'poe2': {'name': 'Path of Exile 2',
          'title': 'Path of Exile 2',
          'font_family': 'Georgia',
          'radius': 2,
          'bg': ('#0E1012', '#121517', '#16191C'),
          'accent': '#C86A32',
          'accent_on': '#FFF3EA',
          'card_fill': ('#0EFFFFFF', '#05FFFFFF'),
          'card_stroke': '#21BEC8D0',
          'group_from': '#E68A4E',
          'group_to': '#AEB8C0',
          't_title': '#CBD2D8',
          't_value': '#8E979F',
          't_hint': '#666E75',
          'switch_on': '#C86A32',
          'field_fill': '#0DFFFFFF',
          'field_stroke': '#21BEC8D0'},
 'gta6sunset': {'name': 'GTA VI Vice Sunset',
                'title': 'GTA VI Vice Sunset',
                'font_family': 'Segoe UI',
                'radius': 12,
                'bg': ('#1F1F38', '#18182D', '#0C0D1B'),
                'accent': '#E9639B',
                'accent_on': '#2A0F1C',
                'card_fill': ('#38365D', '#2A2947'),
                'card_stroke': '#1FCCC2F5',
                'group_from': '#FEC497',
                'group_to': '#E9639B',
                't_title': '#E5DDFF',
                't_value': '#B0A6DE',
                't_hint': '#8B84B8',
                'switch_on': '#E9639B',
                'field_fill': '#14CCC2F5',
                'field_stroke': '#1FCCC2F5'},
 'gta6night': {'name': 'GTA VI Vice Night',
               'title': 'GTA VI Vice Night',
               'font_family': 'Segoe UI',
               'radius': 10,
               'bg': ('#07080F', '#0A0B15', '#0C0D1B'),
               'accent': '#E9639B',
               'accent_on': '#2A0F1C',
               'card_fill': '#0AD9F3FE',
               'card_stroke': '#29E9639B',
               'group_from': '#E9639B',
               'group_to': '#D9F3FE',
               't_title': '#E8EAF4',
               't_value': '#9FB4C4',
               't_hint': '#5F6A80',
               'switch_on': '#E9639B',
               'field_fill': '#0FD9F3FE',
               'field_stroke': '#1FD9F3FE'},
 'matrix': {'name': 'Matrix',
            'title': 'Matrix',
            'font_family': 'Consolas',
            'radius': 0,
            'bg': ('#000000', '#010703', '#031008'),
            'accent': '#00FF41',
            'accent_on': '#001204',
            'card_fill': '#0A1A0E',
            'card_stroke': '#2600FF41',
            'group_from': '#00FF41',
            'group_to': '#9DFFB8',
            't_title': '#8FFFA8',
            't_value': '#41C267',
            't_hint': '#2E8A49',
            'switch_on': '#00FF41',
            'field_fill': '#07120A',
            'field_stroke': '#2200FF41'},
 'diablo2': {'name': 'Diablo II',
             'title': 'Diablo II',
             'font_family': 'Georgia',
             'radius': 2,
             'bg': ('#0B0907', '#100D0A', '#15110C'),
             'accent': '#B79A5B',
             'accent_on': '#EDE4CC',
             'card_fill': ('#302C26', '#1E1B17'),
             'card_stroke': '#8B7343',
             'group_from': '#E4D3A0',
             'group_to': '#8B7343',
             't_title': '#D8D2C0',
             't_value': '#9A9384',
             't_hint': '#6E6A5E',
             'switch_on': '#8E1B1B',
             'field_fill': '#1A1712',
             'field_stroke': '#6E5A33'}}

TEXTURES = {
    'none': 'Без фактуры', 'basalt': 'Базальт', 'marble': 'Мрамор', 'wood': 'Дерево',
    'sand': 'Песок', 'grass': 'Луг', 'cracks': 'Трещины', 'water': 'Вода',
    'smoke': 'Дым', 'starfield': 'Звёздное поле', 'slime': 'Плазма',
    'shards': 'Осколки', 'splatter': 'Брызги', 'lightning': 'Молния',
    'snow': 'Снег', 'fractal': 'Фрактал', 'matrix': 'Матрица',
}

DEFAULT_PREFERENCES = {
    'theme': 'aurora', 'texture': 'none', 'texture_intensity': 0.18,
    'variant': 0, 'temperature': 0,
}


def _number(value, default, low, high):
    try:
        value = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(value):
        return default
    return min(high, max(low, value))


def _preferences(values):
    if not isinstance(values, dict):
        return dict(DEFAULT_PREFERENCES)
    theme = values.get('theme')
    texture = values.get('texture')
    return {
        'theme': theme if isinstance(theme, str) and theme in THEMES else 'aurora',
        'texture': texture if isinstance(texture, str) and texture in TEXTURES else 'none',
        'texture_intensity': _number(values.get('texture_intensity'), 0.18, 0, 0.6),
        'variant': int(_number(values.get('variant'), 0, 0, 2 ** 31 - 1)),
        'temperature': int(_number(values.get('temperature'), 0, -100, 100)),
    }


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


def save_preferences(path, prefs):
    """Save atomically. Write errors propagate so callers can show a useful error."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=destination.name + '.', suffix='.tmp',
                                              dir=str(destination.parent))
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(_preferences(prefs), stream, ensure_ascii=False, indent=2)
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


def font_roles(theme_id='aurora'):
    """Keep compact UI text readable; reserve each theme's face for display roles."""
    display = THEMES.get(theme_id, THEMES['aurora'])['font_family']
    body = 'Segoe UI Semibold'
    return {
        'brand': (display, 20, 'bold'),
        'title': (display, 16, 'bold'),
        'body': (body, 10),
        'control': (body, 9),
        'action': ('Segoe UI Semibold', 11),
        'status': (display, 12, 'bold'),
        'section': (body, 9, 'bold'),
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
    centres = [(-0.743643887037151, 0.131825904205330, 7),
               (-1.401155189092, 0, 6.5), (0.25, 0, 6),
               (-0.77568377, 0.13646737, 4.5), (-1.25066, 0.02012, 4),
               (-0.1011, 0.9563, 3.8), (-0.16070135, 1.0375665, 4.5)]

    def orbit(cr, ci, limit):
        q = (cr - 0.25) ** 2 + ci * ci
        if q * (q + cr - 0.25) <= 0.25 * ci * ci or (cr + 1) ** 2 + ci * ci <= 0.0625:
            return -1.5
        zr, zi = 0.0, 0.0
        for count in range(limit):
            rr, ii = zr * zr, zi * zi
            if rr + ii > 1e4:
                return count + 1 - math.log2(math.log(math.sqrt(rr + ii)))
            zi = 2 * zr * zi + ci
            zr = rr - ii + cr
        return -1.0 - (math.atan2(zi, zr) / math.tau + 0.5)

    aspect_x, aspect_y = width / min(width, height), height / min(width, height)
    for attempt in range(8):
        re, im, max_depth = rng.choice(centres)
        depth = rng.uniform(3, max_depth)
        scale = 10 ** -depth
        re += rng.uniform(-0.4, 0.4) * scale
        im += rng.uniform(-0.4, 0.4) * scale
        angle = rng.random() * math.tau
        cosine, sine = math.cos(angle), math.sin(angle)
        limit = min(420, round(180 + 50 * depth))
        inside = rich = 0
        for _ in range(80):
            x, y = rng.uniform(-0.5, 0.5) * scale * aspect_x, rng.uniform(-0.5, 0.5) * scale * aspect_y
            value = orbit(re + x * cosine - y * sine, im + x * sine + y * cosine, limit)
            inside += value < 0
            rich += value > 12
        if inside < 44 and rich >= 18:
            break
    pixels = bytearray(width * height)
    for y in range(height):
        py = (y / max(1, height - 1) - 0.5) * scale * aspect_y
        for x in range(width):
            px = (x / max(1, width - 1) - 0.5) * scale * aspect_x
            nu = orbit(re + px * cosine - py * sine, im + px * sine + py * cosine, limit)
            if nu < 0:
                tone = 0.025 + 0.07 * (0.5 + 0.5 * math.sin(math.tau * -(nu + 1) * 3))
            else:
                prox = min(1, max(0, (nu - 1.5) / 88.5))
                prox = prox * prox * (3 - 2 * prox)
                wide = 0.5 + 0.5 * math.sin(math.tau * nu * 0.055)
                fine = (nu * 0.22) % 1
                line = max(0, 1 - abs(fine - 0.2) / 0.2)
                tone = 0.05 + (0.12 + 0.55 * prox) * (0.25 + 0.75 * wide) + 0.12 * line * prox
            distance = math.hypot(x / width - 0.5, y / height - 0.5)
            pixels[y * width + x] = max(0, min(255, round(tone * 255 * (1 - 0.28 * distance))))
    return Image.frombytes('L', (width, height), bytes(pixels))


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
    seed = 0x4E4F5641 + list(TEXTURES).index(texture) * 7919 + variant * 6700417
    rng = random.Random(seed)
    if texture == 'fractal':
        return _mandelbrot(width, height, rng)
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
    theme = THEMES[theme_id]
    image = _gradient(width, height, theme['bg'])
    # A quiet side light gives the desktop composition depth without busy text areas.
    ambient = Image.new('L', (128, 128), 0)
    light = ImageDraw.Draw(ambient)
    light.ellipse((-65, -35, 110, 100), fill=20)
    ambient = ambient.filter(ImageFilter.GaussianBlur(35)).resize((width, height), Image.Resampling.BILINEAR)
    image = Image.composite(Image.new('RGB', image.size, theme['accent']), image, ambient)
    if texture_id != 'none' and intensity > 0:
        longest = 220 if texture_id == 'fractal' else 420
        scale = min(1, longest / max(width, height))
        mask = _texture_mask(texture_id, max(8, round(width * scale)), max(8, round(height * scale)), variant)
        mask = mask.resize((width, height), Image.Resampling.BILINEAR).point(lambda value: round(value * intensity))
        image = Image.composite(Image.new('RGB', image.size, theme['accent']), image, mask)
    if temperature:
        tint = '#FFA84A' if temperature > 0 else '#60AAFF'
        strength = abs(temperature) / 100 * 36
        mask = Image.new('L', (1, height))
        mask.putdata([round(strength * (1 - 0.65 * y / max(1, height - 1))) for y in range(height)])
        image = Image.composite(Image.new('RGB', image.size, tint), image, mask.resize(image.size))
    return image


def render_background(width, height, theme_id='aurora', texture_id='none', intensity=0.18,
                      variant=0, temperature=0):
    """Return an independent RGB image. Cache holds at most four desktop surfaces."""
    width, height = int(width), int(height)
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise ValueError('Appearance dimensions must be within 1..4096')
    theme_id = theme_id if theme_id in THEMES else 'aurora'
    texture_id = texture_id if texture_id in TEXTURES else 'none'
    intensity = round(_number(intensity, 0.18, 0, 0.6), 3)
    variant = int(_number(variant, 0, 0, 2 ** 31 - 1))
    temperature = int(_number(temperature, 0, -100, 100))
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
