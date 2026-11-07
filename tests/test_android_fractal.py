import hashlib
import json
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
def test_first_static_and_animated_frame_use_identical_android_surface(theme, temperature):
    static = appearance.render_background(128, 96, theme, 'fractal', .4, 197, temperature)
    animated = appearance.render_fractal_background(128, 96, theme, .4, 197, temperature,
                                                    (128, 96), (0., 0., 1., 1.))
    assert static.tobytes() == animated.tobytes()


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
