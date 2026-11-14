"""Independent Android source oracle: compare fields and exact Float32 drawing commands."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess

from PIL import Image
import pytest

import nova_android_textures as android
import nova_appearance as appearance
import nova_native_render as native


FIXTURE = json.loads((Path(__file__).parent / 'fixtures/android_textures.json').read_text())


def canonical(value):
    if isinstance(value, float):
        return struct.pack('<f', 0.0 if value == 0 else value).hex()
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in value.items()}
    return value


def trace(request):
    binary = native.engine_path()
    if binary is None:
        pytest.skip('Build nova-engine for Android parity')
    result = subprocess.run([str(binary), 'render-fractal'], input=json.dumps(request).encode(),
                            capture_output=True, timeout=15,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    return json.loads(result.stdout)


def assert_events(actual, case):
    assert len(actual) == case['event_count']
    encoded = json.dumps(canonical(actual), sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    assert hashlib.sha256(encoded).hexdigest() == case['events_sha256']


@pytest.mark.parametrize('case', FIXTURE['cases'], ids=lambda c: f"{c['texture']}-{c['variant']}")
def test_all_texture_fields_and_geometry_match_original_kotlin(case):
    request = {key: case[key] for key in ('texture', 'width', 'height', 'variant')}
    frame = trace(dict(request, version=4, trace=True))
    assert len(frame['base']) == case['width'] * case['height']
    assert hashlib.sha256(bytes(frame['base'])).hexdigest() == case['base_sha256']
    assert_events(frame['events'], case)


@pytest.mark.parametrize('case', FIXTURE['rain_cases'])
def test_actual_live_matrix_streams_match_original_kotlin(case):
    request = {key: case[key] for key in ('width', 'height', 'variant', 'time', 'alpha_scale')}
    frame = trace(dict(request, version=5, source=[case['width'], case['height']], crop=[0, 0, 1, 1], trace=True))
    assert len(frame['base']) == case['width'] * case['height']
    assert not any(frame['base'])
    assert_events(frame['events'], case)


def test_texture_list_is_the_light_lab_set():
    # D51 supersedes D39: Crystals is gone, Splatter became Rain, Ether joined; the order is the lab's tile order.
    assert tuple(appearance.TEXTURES) == (
        'none', 'basalt', 'marble', 'wood', 'sand', 'grass', 'cracks', 'water', 'ether', 'aurora', 'smoke', 'starfield',
        'constellation', 'slime', 'rain', 'lightning', 'snow', 'fractal', 'fractal2', 'warp', 'maze', 'matrix', 'custom')


def test_saved_removed_textures_move_to_their_successors():
    for saved, expected in (('shards', 'cracks'), ('crystals', 'cracks'), ('splatter', 'rain')):
        assert appearance._preferences({'texture': saved})['texture'] == expected


def test_missing_native_generator_is_reported_instead_of_substituting_a_pattern(monkeypatch):
    monkeypatch.setattr(native, 'texture_mask', lambda *_: None)
    monkeypatch.setattr(native, '_disabled_reason', 'missing test engine')
    with pytest.raises(RuntimeError, match='missing test engine'):
        android.render_mask('lightning', 80, 60, 0)


@pytest.mark.parametrize('texture', [name for name in appearance.TEXTURES if name not in ('none', 'fractal', 'custom')])
def test_every_android_texture_reaches_the_visible_background(texture, monkeypatch):
    monkeypatch.setattr(native, '_disabled_reason', None)
    appearance._render_background.cache_clear()
    image = appearance.render_background(128, 96, 'aurora', texture, .6, 197)
    plain = appearance.render_background(128, 96, 'aurora', 'none', .6)
    assert image.mode == 'RGB' and image.size == (128, 96)
    assert image.tobytes() != plain.tobytes()
    assert image.tobytes() == appearance.render_background(128, 96, 'aurora', texture, .6, 197).tobytes()
    assert image.tobytes() != appearance.render_background(128, 96, 'aurora', texture, .6, 198).tobytes()


def test_static_texture_retains_device_resolution_up_to_android_limit(monkeypatch):
    calls = []
    def mask(texture, width, height, variant):
        calls.append((width, height))
        return Image.new('L', (width, height), 70)
    appearance._render_background.cache_clear()
    monkeypatch.setattr(appearance, '_texture_mask', mask)
    appearance.render_background(1120, 840, 'aurora', 'marble', .4)
    appearance.render_background(1920, 1440, 'aurora', 'marble', .4)
    assert calls == [(1120, 840), (1440, 1080)]


def test_matrix_is_live_and_camera_keeps_same_variant(monkeypatch):
    monkeypatch.setattr(native, '_disabled_reason', None)
    args = (128, 96, 'matrix', .6, 197, 0, (128, 96), (0, 0, 1, 1))
    first = appearance.render_matrix_background(*args, 0)
    later = appearance.render_matrix_background(*args, 10)
    assert first.tobytes() != later.tobytes()
    assert first.tobytes() == appearance.render_matrix_background(*args, 0).tobytes()
    assert first.tobytes() == appearance.render_background(128, 96, 'matrix', 'matrix', .6, 197).tobytes()
