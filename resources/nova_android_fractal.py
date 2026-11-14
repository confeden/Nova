"""Nova Android's fractal mask, with an independent scalar fallback for native v3."""

from ctypes import c_float
from functools import lru_cache
import math

from PIL import Image

import nova_native_render
from nova_fractal import CENTRES


def f(value):
    return c_float(value).value


class KotlinRandom:
    """Kotlin Random(Long)'s XorWow state; do not replace with Python's MT19937."""

    def __init__(self, seed):
        lo, hi = seed & 0xffffffff, (seed >> 32) & 0xffffffff
        self.state = [lo, hi, 0, 0, lo ^ 0xffffffff]
        self.add = ((lo << 10) ^ (hi >> 4)) & 0xffffffff
        for _ in range(64):
            self.word()

    def word(self):
        x, y, z, w, v = self.state
        t = x ^ (x >> 2)
        t = (t ^ (t << 1) ^ v ^ (v << 4)) & 0xffffffff
        self.state = [y, z, w, v, t]
        self.add = (self.add + 362437) & 0xffffffff
        return (t + self.add) & 0xffffffff

    def index(self, bound):
        while True:
            bits = self.word() >> 1
            value = bits % bound
            if bits - value + bound - 1 <= 0x7fffffff:
                return value

    def double(self):
        return (((self.word() >> 6) << 27) + (self.word() >> 5)) / 9007199254740992


def orbit(cr, ci, limit):
    q = (cr - .25) * (cr - .25) + ci * ci
    if q * (q + (cr - .25)) <= .25 * ci * ci or (cr + 1) * (cr + 1) + ci * ci <= .0625:
        return -1.5
    zr = zi = 0.
    for n in range(limit):
        rr, ii = zr * zr, zi * zi
        if rr + ii > 1e4:
            return f(n + 1 - math.log(math.log(math.sqrt(rr + ii))) / math.log(2))
        zi = 2 * zr * zi + ci
        zr = rr - ii + cr
    return -f(1 + f(math.atan2(zi, zr) / math.tau + .5))


@lru_cache(maxsize=4)
def select_view(width, height, variant):
    rng = KotlinRandom(0x4e4f5641 + 15 * 7919 + variant * 6700417)
    span = min(width, height)
    ax, ay = f(width / span), f(height / span)
    for _ in range(8):
        re, im, maximum = CENTRES[rng.index(7)]
        depth = 3 + rng.double() * max(0, maximum - 3)
        scale = 10 ** -depth
        real = re + (rng.double() - .5) * scale * .8
        imaginary = im + (rng.double() - .5) * scale * .8
        angle = rng.double() * math.tau
        cosine, sine = math.cos(angle), math.sin(angle)
        limit = min(420, int(180 + 50 * depth))
        inside = rich = 0
        for _ in range(300):
            px = (rng.double() - .5) * scale * ax
            py = (rng.double() - .5) * scale * ay
            nu = orbit(real + px * cosine - py * sine, imaginary + px * sine + py * cosine, limit)
            inside += nu < 0
            rich += nu >= 0 and nu > 12
        if inside < 300 * .55 and rich >= 300 * .22:
            break
    return real, imaginary, scale, cosine, sine, limit


def smooth(a, b, x):
    a, b, x = f(a), f(b), f(x)
    t = min(1, max(0, f(f(x - a) / f(b - a))))
    return f(f(t * t) * f(3 - f(2 * t)))


def render_python(width, height, variant, source, crop):
    real, imaginary, scale, cosine, sine, limit = select_view(*source, variant)
    source_span = min(source)
    ax, ay = f(source[0] / source_span), f(source[1] / source_span)
    gw, gh = (max(2, int(f(380 * width / height))), 380) if height >= width else (380, max(2, int(f(380 * height / width))))
    grid = []
    for gy in range(gh):
        py = (crop[1] + gy / (gh - 1) * (crop[3] - crop[1]) - .5) * (scale * ay)
        for gx in range(gw):
            px = (crop[0] + gx / (gw - 1) * (crop[2] - crop[0]) - .5) * (scale * ax)
            grid.append(orbit(real + px * cosine - py * sine, imaginary + px * sine + py * cosine, limit))
    span = min(width, height)
    inv, kx, ky = f(1 / span), f((gw - 1) / (width - 1)), f((gh - 1) / (height - 1))
    tau, pixels = f(6.2831855), bytearray(width * height)
    for y in range(height):
        v = f(y * inv)
        gy = min(f(gh - f(1.001)), f(f(v * span) * ky))
        iy, fy = int(gy), f(gy - int(gy))
        for x in range(width):
            u = f(x * inv)
            gx = min(f(gw - f(1.001)), f(f(u * span) * kx))
            ix, fx = int(gx), f(gx - int(gx))
            a, b, c, d = grid[iy * gw + ix], grid[iy * gw + ix + 1], grid[(iy + 1) * gw + ix], grid[(iy + 1) * gw + ix + 1]
            nearest = (a if fx < .5 else b) if fy < .5 else (c if fx < .5 else d)
            if nearest < 0:
                angle = f(f(tau * -f(nearest + 1)) * 3)
                tone = f(f(.025) + f(f(.07) * f(f(.5) + f(f(.5) * f(math.sin(angle))))))
            else:
                weights = (f(f(1 - fx) * f(1 - fy)), f(fx * f(1 - fy)), f(f(1 - fx) * fy), f(fx * fy))
                total = weight = 0.
                for nu, w in zip((a, b, c, d), weights):
                    if nu >= 0:
                        total, weight = f(total + f(nu * w)), f(weight + w)
                nu = f(total / weight) if weight > f(1e-4) else nearest
                prox = smooth(1.5, 90, nu)
                wide = f(f(.5) + f(f(.5) * f(math.sin(f(f(tau * nu) * f(.055))))))
                fine = f(f(nu * f(.22)) - math.floor(f(nu * f(.22))))
                line = f(smooth(0, .18, fine) * smooth(.5, .18, fine))
                if tuple(crop) == (0, 0, 1, 1):
                    pu, pv = u, v
                else:
                    pu, pv = f((crop[0] + x / width * (crop[2] - crop[0])) * ax), f((crop[1] + y / height * (crop[3] - crop[1])) * ay)
                distance = f(math.hypot(f(pu - f(ax * .5)), f(pv - f(ay * .5))))
                vignette = f(1 - f(f(.3) * smooth(.2, .8, distance)))
                body = f(f(.12) + f(f(.55) * prox))
                bands = f(f(.25) + f(f(.75) * wide))
                edge = f(f(f(.12) * line) * prox)
                tone = f(f(f(f(.05) + f(body * bands)) + edge) * vignette)
            pixels[y * width + x] = max(0, min(255, int(f(tone * 255))))
    return bytes(pixels)


def _validate(width, height, variant, source, crop):
    if (not 8 <= width <= 1440 or not 8 <= height <= 1440 or not 0 <= variant <= 2147483647
            or len(source) != 2 or any(not 8 <= n <= 4096 for n in source)
            or len(crop) != 4 or any(not math.isfinite(n) or not 0 <= n <= 1 for n in crop)
            or crop[2] <= crop[0] or crop[3] <= crop[1]):
        raise ValueError("Invalid Android fractal viewport")


def render_mask(width, height, variant, source=None, crop=(0., 0., 1., 1.)):
    source = (width, height) if source is None else source
    _validate(width, height, variant, source, crop)
    pixels = nova_native_render.android_fractal(width, height, variant, source, crop)
    return pixels if pixels is not None else render_python(width, height, variant, source, crop)


def _palette(nu):
    if nu < 0:
        return (.035, .05, .09)
    stops = ((.18, .22, .58), (.12, .56, .78), (.18, .72, .57),
             (.88, .64, .30), (.56, .28, .66), (.18, .22, .58))
    phase = (nu * .018 % 1) * 5
    index = min(4, int(phase))
    fraction = phase - index
    blend = fraction * fraction * (3 - 2 * fraction)
    brightness = .45 + .55 * smooth(1.5, 90, nu)
    return tuple((a * (1 - blend) + b * blend) * brightness for a, b in zip(stops[index], stops[index + 1]))


def _filtered_color(cr, ci, limit, footprint):
    inside = _palette(-1.5)
    q = (cr - .25) ** 2 + ci * ci
    if q * (q + cr - .25) <= .25 * ci * ci or (cr + 1) ** 2 + ci * ci <= .0625:
        return inside
    zr = zi = dr = di = 0.
    for n in range(limit):
        rr, ii = zr * zr, zi * zi
        if rr + ii > 1e4:
            radius = math.sqrt(rr + ii)
            nu = f(n + 1 - math.log(math.log(radius)) / math.log(2))
            derivative = math.hypot(dr, di)
            distance = .5 * math.log(radius) * radius / derivative if derivative else math.inf
            coverage = smooth(0, 1.5, distance / footprint)
            return tuple(a + (b - a) * coverage for a, b in zip(inside, _palette(nu)))
        next_dr = 2 * (zr * dr - zi * di) + 1
        di = 2 * (zr * di + zi * dr)
        dr = next_dr
        zi = 2 * zr * zi + ci
        zr = rr - ii + cr
    return inside


def render_color_python(width, height, variant, source, crop):
    real, imaginary, scale, cosine, sine, limit = select_view(*source, variant)
    span = min(source)
    ax, ay = source[0] / span, source[1] / span
    longest = min(380, max(width, height))
    gw, gh = max(2, longest * width // max(width, height)), max(2, longest * height // max(width, height))
    footprint = max(scale * ax * (crop[2] - crop[0]) / (gw - 1),
                    scale * ay * (crop[3] - crop[1]) / (gh - 1))
    # Filter colors, including interior coverage, rather than signed escape counts.
    channels = [[], [], []]
    for gy in range(gh):
        py = (crop[1] + gy / (gh - 1) * (crop[3] - crop[1]) - .5) * scale * ay
        for gx in range(gw):
            px = (crop[0] + gx / (gw - 1) * (crop[2] - crop[0]) - .5) * scale * ax
            color = _filtered_color(real + px * cosine - py * sine, imaginary + px * sine + py * cosine, limit, footprint)
            for channel, value in zip(channels, color):
                channel.append(value * 255)
    bands = []
    for channel in channels:
        band = Image.new('F', (gw, gh))
        band.putdata(channel)
        # PIL samples pixel centres; extend the endpoints to match the native grid.
        sx, sy = (gw - 1) / (width - 1), (gh - 1) / (height - 1)
        band = band.transform((width, height), Image.Transform.AFFINE,
                              (sx, 0, .5 * (1 - sx), 0, sy, .5 * (1 - sy)), Image.Resampling.BILINEAR)
        bands.append(band.point(lambda value: value + .5).convert('L'))
    return Image.merge('RGB', bands).tobytes()


def render_color(width, height, variant, source=None, crop=(0., 0., 1., 1.)):
    source = (width, height) if source is None else source
    _validate(width, height, variant, source, crop)
    pixels = nova_native_render.smooth_fractal(width, height, variant, source, crop)
    return pixels if pixels is not None else render_color_python(width, height, variant, source, crop)
