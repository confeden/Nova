import hashlib
import json
import math
from pathlib import Path

import pytest

import nova_android_fractal as android
import nova_appearance as appearance
import nova_native_render as native


FIXTURE = json.loads((Path(__file__).parent / 'fixtures/android_fractal.json').read_text())


@pytest.mark.parametrize('case', FIXTURE['cases'])
def test_native_matches_independent_original_kotlin_pixels(case, monkeypatch):
    if native.engine_path() is None:
        pytest.skip('Build nova-engine for native parity')
    monkeypatch.setattr(native, '_disabled_reason', None)
    pixels = native.android_fractal(case['width'], case['height'], case['variant'],
                                    (case['width'], case['height']), (0., 0., 1., 1.))
    assert pixels is not None, native._disabled_reason
    assert hashlib.sha256(pixels).hexdigest() == case['pixels_sha256']


@pytest.mark.parametrize('case', FIXTURE['cases'][:2])
def test_scalar_fallback_matches_original_kotlin_pixels(case, monkeypatch):
    monkeypatch.setattr(native, 'android_fractal', lambda *_a: None)
    pixels = android.render_mask(case['width'], case['height'], case['variant'])
    assert pixels == bytes.fromhex(case['pixels_hex'])


@pytest.mark.parametrize('theme,temperature', [('aurora', 0), ('proton', 50), ('matrix', -50)])
def test_first_static_and_live_frame_use_identical_surface(theme, temperature):
    static = appearance.render_background(128, 96, theme, 'fractal', .4, 197, temperature)
    live = appearance.render_live_background(128, 96, theme, 'fractal', .4, 197, temperature, 0.)
    assert static.tobytes() == live.tobytes()


@pytest.mark.parametrize('crop', [(0, 0, 0, 1), (0, 0, 1.01, 1), (0, float('nan'), 1, 1)])
def test_invalid_camera_crops_fail_before_native_or_allocation(crop, monkeypatch):
    monkeypatch.setattr(native, 'android_fractal', lambda *_a: pytest.fail('Invalid camera reached renderer'))
    with pytest.raises(ValueError):
        android.render_mask(16, 12, 0, crop=crop)


def test_zoom_reevaluates_detail_without_reseeding(monkeypatch):
    if native.engine_path() is None:
        pytest.skip('Build nova-engine for native parity')
    monkeypatch.setattr(native, '_disabled_reason', None)
    first = android.render_mask(128, 96, 42)
    zoomed = android.render_mask(128, 96, 42, source=(128, 96), crop=(.25, .215, .75, .715))
    assert first != zoomed
    assert len(zoomed) == 128 * 96
    assert max(zoomed) - min(zoomed) > 20


@pytest.mark.parametrize('size,variant,crop', [((48, 36), 0, (0, 0, 1, 1)),
                                            ((48, 36), 197, (.2, .17, .8, .77)),
                                            ((760, 64), 42, (.2, .17, .8, .77))])
def test_color_fallback_matches_native_escape_gradient(size, variant, crop, monkeypatch):
    monkeypatch.setattr(native, '_disabled_reason', None)
    pixels = native.smooth_fractal(*size, variant, (700, 500), crop)
    assert pixels is not None, native._disabled_reason
    fallback = android.render_color_python(*size, variant, (700, 500), crop)
    assert max(abs(a - b) for a, b in zip(pixels, fallback)) <= 1
    monkeypatch.setattr(native, 'smooth_fractal', lambda *_a: None)
    assert android.render_color(*size, variant, (700, 500), crop) == fallback


def test_interior_coverage_is_filtered_without_a_nearest_pixel_cutoff(monkeypatch):
    monkeypatch.setattr(android, 'select_view', lambda *_a: (0, 0, 1, 1, 0, 100))
    monkeypatch.setattr(android, '_filtered_color', lambda real, *_a: android._palette(-1.5 if real < 0 else 80.))
    pixels = android.render_color_python(1280, 8, 0, (1280, 8), (0, 0, 1, 1))
    row = pixels[:1280 * 3]
    for channel in range(3):
        values = row[channel::3]
        assert max(abs(a - b) for a, b in zip(values, values[1:])) <= abs(values[-1] - values[0]) * .5 + 1
    assert len({tuple(row[i:i + 3]) for i in range(0, len(row), 3)}) >= 4


@pytest.mark.parametrize('crop', [(0, 0, 0, 1), (0, 0, 1.01, 1), (0, float('nan'), 1, 1)])
def test_color_validation_precedes_native_and_fallback(crop, monkeypatch):
    monkeypatch.setattr(native, 'smooth_fractal', lambda *_a: pytest.fail('Invalid camera reached renderer'))
    with pytest.raises(ValueError):
        android.render_color(16, 12, 0, crop=crop)


def test_pixel_footprint_suppresses_unresolved_escape_colors():
    inside = android._palette(-1.5)
    fine = android._filtered_color(-.1011, .9563, 420, 1e-9)
    coarse = android._filtered_color(-.1011, .9563, 420, 1e-4)
    fine_contrast = max(abs(a - b) for a, b in zip(fine, inside))
    coarse_contrast = max(abs(a - b) for a, b in zip(coarse, inside))
    assert fine_contrast > .2
    assert coarse_contrast < fine_contrast * .01


def test_dense_fractal_small_zoom_does_not_flash_unresolved_pixels(monkeypatch):
    monkeypatch.setattr(native, '_disabled_reason', None)
    source = (560, 420)
    first = android.render_color(*source, 6, source, (0, 0, 1, 1))
    side = 1 / (1 + .5 * math.log1p(.1 / 60))
    left, top = (1 - side) * .5, (1 - side) * .43
    second = android.render_color(*source, 6, source, (left, top, left + side, top + side))
    delta = [abs(a - b) for a, b in zip(first, second)]
    assert sum(delta) / len(delta) < 2.5
    assert max(delta) < 80
    assert max(first) - min(first) > 70
