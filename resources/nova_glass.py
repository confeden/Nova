"""Matte-glass plates for the main window (D51): the shapes, their RGBA look and the frost mask.

A plate is a rounded rectangle (left, top, right, bottom, radius) plus an optional tint. compose() draws
all of them, and the big cards behind them, into one RGBA layer and one L mask. The GPU engine frosts the
background under the mask (blur) and lays the RGBA on top; frost() does the same job on the CPU path.
Shapes are drawn at 3x and filtered down so the edges are smooth on any scale.
"""

import math

from PIL import Image, ImageChops, ImageDraw, ImageFilter

SUPERSAMPLE = 3
# Smoky glass: a dark veil keeps light text readable over any texture, the white sheen reads as frosting.
VEIL = (8, 12, 22, 58)
SHEEN_TOP, SHEEN_BOTTOM = 30, 4
RIM = 56
FROST_RADIUS = 5


def _shape(width, height, radius, inset=0):
    """L mask of a rounded rectangle, smooth edges. Exact area coverage (box reduction, no ringing) at 8x for small
    plates and 4x for big cards: 3x with a Lanczos filter left only 9 edge levels and a stair-stepped, dotted rim."""
    k = 8 if width * height <= 90000 else SUPERSAMPLE + 1
    mask = Image.new("L", (width * k, height * k), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (inset * k, inset * k, width * k - 1 - inset * k, height * k - 1 - inset * k),
        radius=max(0, (radius - inset) * k), fill=255)
    return mask.reduce(k)


def plate_image(width, height, radius, tint=None, scale=1.0):
    """(RGBA, L) of one glass plate. tint is an (r, g, b, alpha) colour poured over the veil (accent buttons)."""
    width, height = max(2, int(width)), max(2, int(height))
    radius = max(1, min(int(radius), width // 2, height // 2))
    shape = _shape(width, height, radius)
    base = VEIL if tint is None else tuple(tint)
    layer = Image.new("RGBA", (width, height), base[:3] + (0,))
    layer.putalpha(shape.point(lambda value: value * base[3] // 255))
    sheen = Image.new("L", (1, height))
    sheen.putdata([round(SHEEN_TOP + (SHEEN_BOTTOM - SHEEN_TOP) * y / max(1, height - 1)) for y in range(height)])
    sheen = ImageChops.multiply(sheen.resize((width, height)), shape)
    white = Image.new("RGBA", (width, height), (255, 255, 255, 0))
    white.putalpha(sheen)
    layer = Image.alpha_composite(layer, white)
    rim_width = max(1, round(scale))
    inner = _shape(width, height, radius, inset=rim_width)
    rim = ImageChops.subtract(shape, inner).point(lambda value: value * RIM // 255)
    edge = Image.new("RGBA", (width, height), (255, 255, 255, 0))
    edge.putalpha(rim)
    return Image.alpha_composite(layer, edge), shape


def compose(size, shapes, scale=1.0):
    """shapes: iterable of (left, top, right, bottom, radius, tint-or-None). -> (RGBA layer, L mask) of `size`."""
    width, height = size
    layer = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    mask = Image.new("L", (width, height), 0)
    for left, top, right, bottom, radius, tint in shapes:
        left, top, right, bottom = round(left), round(top), round(right), round(bottom)
        if right - left < 2 or bottom - top < 2:
            continue
        plate, shape = plate_image(right - left, bottom - top, radius, tint, scale)
        clip = (max(0, left), max(0, top), min(width, right), min(height, bottom))
        if clip[2] <= clip[0] or clip[3] <= clip[1]:
            continue
        source = (clip[0] - left, clip[1] - top, clip[2] - left, clip[3] - top)
        layer.alpha_composite(plate.crop(source), (clip[0], clip[1]))
        mask.paste(ImageChops.lighter(mask.crop(clip), shape.crop(source)), (clip[0], clip[1]))
    return layer, mask


def compose_cards(size, groups, scale=1.0, fast=False):
    """The big cards as groups of rounded rectangles drawn as ONE glass each (no stacking where they overlap).
    groups: iterable of lists of (left, top, right, bottom, radius), float coordinates. -> (RGBA layer, L mask).
    Used while a card folds into pills around its text and back: the rectangles move by sub-pixel amounts, so each
    frame is drawn from scratch (3x when `fast`, otherwise 4x, or 6x for small groups)."""
    width, height = size
    layer = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    mask = Image.new("L", (width, height), 0)
    rim = max(1, round(scale))
    for rects in groups:
        rects = [rect for rect in rects if rect[2] - rect[0] >= 2 and rect[3] - rect[1] >= 2]
        if not rects:
            continue
        x0 = max(0, math.floor(min(rect[0] for rect in rects)) - 1)
        y0 = max(0, math.floor(min(rect[1] for rect in rects)) - 1)
        x1 = min(width, math.ceil(max(rect[2] for rect in rects)) + 1)
        y1 = min(height, math.ceil(max(rect[3] for rect in rects)) + 1)
        if x1 <= x0 or y1 <= y0:
            continue
        bw, bh = x1 - x0, y1 - y0
        k = 3 if fast else (6 if bw * bh <= 200000 else 4)
        outer = Image.new("L", (bw * k, bh * k), 0)
        inner = Image.new("L", (bw * k, bh * k), 0)
        draw_outer, draw_inner = ImageDraw.Draw(outer), ImageDraw.Draw(inner)
        for left, top, right, bottom, radius in rects:
            radius = max(0.0, min(radius, (right - left) / 2, (bottom - top) / 2))
            draw_outer.rounded_rectangle(((left - x0) * k, (top - y0) * k, (right - x0) * k - 1, (bottom - y0) * k - 1),
                                         radius=radius * k, fill=255)
            if right - left > 2 * rim + 2 and bottom - top > 2 * rim + 2:
                draw_inner.rounded_rectangle(((left + rim - x0) * k, (top + rim - y0) * k,
                                              (right - rim - x0) * k - 1, (bottom - rim - y0) * k - 1),
                                             radius=max(0.0, radius - rim) * k, fill=255)
        shape, core = outer.reduce(k), inner.reduce(k)
        group = Image.new("RGBA", (bw, bh), VEIL[:3] + (0,))
        group.putalpha(shape.point(lambda value: value * VEIL[3] // 255))
        sheen = Image.new("L", (1, bh))
        sheen.putdata([round(SHEEN_TOP + (SHEEN_BOTTOM - SHEEN_TOP) * y / max(1, bh - 1)) for y in range(bh)])
        white = Image.new("RGBA", (bw, bh), (255, 255, 255, 0))
        white.putalpha(ImageChops.multiply(sheen.resize((bw, bh)), shape))
        group = Image.alpha_composite(group, white)
        edge = Image.new("RGBA", (bw, bh), (255, 255, 255, 0))
        edge.putalpha(ImageChops.subtract(shape, core).point(lambda value: value * RIM // 255))
        group = Image.alpha_composite(group, edge)
        layer.alpha_composite(group, (x0, y0))
        mask.paste(ImageChops.lighter(mask.crop((x0, y0, x1, y1)), shape), (x0, y0))
    return layer, mask


def frost(image, mask, radius=FROST_RADIUS):
    """CPU path: blur the picture where the mask is set. Works on a quarter-size copy: the blur is wide, so
    the loss is invisible and the cost stays small even on a large window."""
    if mask.getbbox() is None:
        return image
    quarter = (max(1, image.width // 4), max(1, image.height // 4))
    soft = image.resize(quarter, Image.Resampling.BILINEAR).filter(
        ImageFilter.GaussianBlur(max(1, radius / 2)))
    soft = soft.resize(image.size, Image.Resampling.BILINEAR)
    return Image.composite(soft, image, mask)
