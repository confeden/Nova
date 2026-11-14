"""Bounded worker-side adapter to nova-engine's CPU render kernels."""

import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import threading

_lock = threading.Lock()
_disabled_reason = None


def engine_path():
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
        candidates = (base / "resources" / "bin" / "nova-engine.exe", base / "bin" / "nova-engine.exe")
    else:
        base = Path(__file__).resolve().parent
        if base.name.lower() == "resources":
            base = base.parent
        candidates = (base / "bin" / "nova-engine.exe", base / "resources" / "bin" / "nova-engine.exe")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _disable(reason):
    global _disabled_reason
    with _lock:
        if _disabled_reason is None:
            _disabled_reason = reason
            logging.getLogger(__name__).warning(
                "[UI] Нативный расчёт оформления недоступен (%s); для фрактала используется Python. "
                "Обновите nova-engine.exe и перезапустите Nova.", reason)


def _request(request, timeout=5):
    """One worker-side request; NOVA_NATIVE_RENDER=0 explicitly selects Python."""
    if os.environ.get("NOVA_NATIVE_RENDER") == "0" or _disabled_reason is not None:
        return None
    binary = engine_path()
    if binary is None:
        _disable("nova-engine.exe не найден")
        return None
    try:
        result = subprocess.run(
            [str(binary), "render-fractal"], input=json.dumps(request, allow_nan=False).encode("utf-8"),
            capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
        if result.returncode:
            detail = result.stderr.decode('utf-8', errors='replace').strip()[:300]
            _disable(f"код завершения {result.returncode}: {detail}")
            return None
        return result.stdout
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        _disable(type(error).__name__)
        return None


def _pixels(body, width, height):
    header = f"P5\n{width} {height}\n255\n".encode("ascii")
    if not body.startswith(header) or len(body) != len(header) + width * height:
        _disable("некорректный ответ движка")
        return None
    return body[len(header):]


def mandelbrot(width, height, real, imaginary, scale, cosine, sine, iterations):
    """Version 1: render an explicit viewport; kept compatible with earlier engines."""
    body = _request(dict(version=1, width=width, height=height, real=real, imaginary=imaginary,
                         scale=scale, cosine=cosine, sine=sine, iterations=iterations))
    return None if body is None else _pixels(body, width, height)


def android_fractal(width, height, variant, source, crop):
    body = _request(dict(version=3, width=width, height=height, variant=variant,
                         source=list(source), crop=list(crop)))
    return None if body is None else _pixels(body, width, height)


def smooth_fractal(width, height, variant, source, crop):
    body = _request(dict(version=6, width=width, height=height, variant=variant,
                         source=list(source), crop=list(crop)))
    if body is None:
        return None
    header = f"P6\n{width} {height}\n255\n".encode("ascii")
    if not body.startswith(header) or len(body) != len(header) + width * height * 3:
        _disable("некорректный цветной ответ движка")
        return None
    return body[len(header):]


def live_texture(texture, width, height, variant, time):
    """Version 7: one live immersive frame. Returns (bytes, channels) or None."""
    body = _request(dict(version=7, texture=texture, width=width, height=height, variant=variant,
                         time=float(time)))
    if body is None:
        return None
    for magic, channels in ((b"P5", 1), (b"P6", 3)):
        header = magic + f"\n{width} {height}\n255\n".encode("ascii")
        if body.startswith(header) and len(body) == len(header) + width * height * channels:
            return body[len(header):], channels
    _disable("некорректный ответ живой фактуры")
    return None


def texture_mask(texture, width, height, variant):
    # Static full-resolution multi-octave fields are cached by the appearance layer.
    body = _request(dict(version=4, texture=texture, width=width, height=height, variant=variant), timeout=20)
    return None if body is None else _pixels(body, width, height)


def matrix_rain(width, height, variant, time, source, crop, alpha_scale=1):
    body = _request(dict(version=5, width=width, height=height, variant=variant, time=time,
                         source=list(source), crop=list(crop), alpha_scale=alpha_scale))
    return None if body is None else _pixels(body, width, height)


def fractal(width, height, random_state):
    """Version 2: select and render; validate the RNG receipt before a caller changes its state."""
    body = _request(dict(version=2, width=width, height=height, random_state=list(random_state)))
    if body is None:
        return None
    receipt, separator, image = body.partition(b"\n")
    prefix = b"NOVA-FRACTAL/2 "
    words = receipt[len(prefix):] if receipt.startswith(prefix) else b""
    if not separator or not words.isdigit() or len(words) > 4 or not 1 <= int(words) <= 8192:
        _disable("некорректное состояние генератора в ответе движка")
        return None
    pixels = _pixels(image, width, height)
    return None if pixels is None else (pixels, int(words))
