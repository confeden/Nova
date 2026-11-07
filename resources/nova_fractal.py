"""Fractal computation and its deterministic Python reference, independent of Tk/Pillow."""

import math
import random
from typing import NamedTuple

import nova_native_render

CENTRES = ((-0.743643887037151, 0.131825904205330, 7),
           (-1.401155189092, 0, 6.5), (0.25, 0, 6),
           (-0.77568377, 0.13646737, 4.5), (-1.25066, 0.02012, 4),
           (-0.1011, 0.9563, 3.8), (-0.16070135, 1.0375665, 4.5))


class FractalView(NamedTuple):
    width: int
    height: int
    real: float
    imaginary: float
    scale: float
    cosine: float
    sine: float
    iterations: int


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



def select_view(width, height, rng):
    aspect_x, aspect_y = width / min(width, height), height / min(width, height)
    for attempt in range(8):
        re, im, max_depth = rng.choice(CENTRES)
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
    return FractalView(width, height, re, im, scale, cosine, sine, limit)


def render_view_python(view):
    width, height, re, im, scale, cosine, sine, limit = view
    aspect_x, aspect_y = width / min(width, height), height / min(width, height)
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
    return bytes(pixels)



def render_mask_python(width, height, rng):
    return render_view_python(select_view(width, height, rng))


def render_mask(width, height, rng):
    # Subclasses may override random()/choice(); their MT state is not their full contract.
    if type(rng) is random.Random:
        state = rng.getstate()
        if state[0] == 3:
            frame = nova_native_render.fractal(width, height, state[1])
            if frame is not None:
                pixels, words = frame
                # The native word receipt was validated before advancing the original generator.
                for _ in range(words):
                    rng.getrandbits(32)
                return pixels
    return render_mask_python(width, height, rng)
