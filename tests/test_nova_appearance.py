"""Appearance persistence must survive failed writes; procedural assets stay reproducible."""

import json
import math
import random
import subprocess
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from PIL import Image, ImageChops, ImageColor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources"))

import nova_appearance as appearance  # noqa: E402


def test_owner_defaults_do_not_override_explicit_preferences(tmp_path):
    path = tmp_path / "appearance.json"
    defaults = appearance.load_preferences(path)
    assert defaults["texture"] == "marble"
    assert (defaults["theme"], defaults["accent_hue"]) == ("hue27", 27)
    assert (defaults["brightness"], defaults["saturation"], defaults["speed"], defaults["warp"]) == (80, 100, 25, 30)
    assert defaults["random_texture_on_start"] is True
    assert defaults["texture_intensity"] == .2667
    assert defaults['random_texture_on_start'] is True
    assert defaults["immersion"] is True
    path.write_text(json.dumps({"texture": "none", "immersion": False}), encoding="utf-8")
    saved = appearance.load_preferences(path)
    assert saved["texture"] == "none"
    assert saved["immersion"] is False
import nova_native_render as native  # noqa: E402
import nova_fractal as fractal  # noqa: E402
from nova_desktop_ui import supernova_icon  # noqa: E402


class PreferenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "appearance.json"

    def test_roundtrip_keeps_texture_reseed_and_sliders(self):
        selected = appearance.normalize_preferences({
            "accent_hue": 12, "texture": "fractal", "brightness": 93, "saturation": 140, "speed": 60,
            "warp": 20, "variant": 197, "immersion": True, "random_texture_on_start": False,
            "limit_30fps": True, "sync_monitor": False,
        })
        appearance.save_preferences(self.path, selected)
        self.assertEqual(appearance.load_preferences(self.path), selected)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_partial_save_and_changed_defaults_preserve_user_choices_and_unknown_fields(self):
        chosen = {'accent_hue': 40, 'texture': 'fractal', 'immersion': False,
                  'random_texture_on_start': False, 'future_setting': {'enabled': False}}
        self.path.write_text(json.dumps(chosen), encoding='utf-8')
        with mock.patch.dict(appearance.DEFAULT_PREFERENCES, texture='marble', immersion=True):
            appearance.save_preferences(self.path, {'speed': 150})
            loaded = appearance.startup_preferences(self.path)
        self.assertEqual((loaded['accent_hue'], loaded['texture'], loaded['immersion']),
                         (40, 'fractal', False))
        self.assertEqual(loaded['speed'], 150)
        self.assertEqual(json.loads(self.path.read_text(encoding='utf-8'))['future_setting'], {'enabled': False})

    def test_failed_replace_preserves_previous_file_and_removes_temporary(self):
        original = b'{"theme":"charcoal","variant":42}\n'
        self.path.write_bytes(original)
        with mock.patch.object(appearance.os, "replace", side_effect=PermissionError("file in use")):
            with self.assertRaisesRegex(PermissionError, "file in use"):
                appearance.save_preferences(self.path, {"theme": "proton"})
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_damaged_json_is_reported_and_produces_usable_defaults(self):
        self.path.write_text('{"theme":', encoding="utf-8")
        with self.assertLogs("nova_appearance", level="WARNING") as records:
            selected = appearance.load_preferences(self.path)
        self.assertTrue(any("Cannot read appearance preferences" in line for line in records.output))
        self.assertIn(selected["theme"], appearance.THEMES)
        self.assertIn(selected["texture"], appearance.TEXTURES)
        self.assertTrue(math.isfinite(selected["texture_intensity"]))

    def test_nonfinite_and_invalid_fields_cannot_reach_rendering(self):
        for intensity in (float("nan"), float("inf"), float("-inf"), "invalid", [], {}):
            with self.subTest(intensity=intensity):
                self.path.write_text(json.dumps({
                    "theme": [], "texture": {}, "texture_intensity": intensity,
                    "variant": float("inf"), "temperature": float("nan"),
                }), encoding="utf-8")
                selected = appearance.load_preferences(self.path)
                self.assertIn(selected["theme"], appearance.THEMES)
                self.assertIn(selected["texture"], appearance.TEXTURES)
                self.assertTrue(math.isfinite(selected["texture_intensity"]))
                self.assertGreaterEqual(selected["texture_intensity"], 0)
                self.assertLessEqual(selected["texture_intensity"], 0.6)
                self.assertIsInstance(selected["variant"], int)
                self.assertGreaterEqual(selected["variant"], 0)
                self.assertGreaterEqual(selected["temperature"], -100)
                self.assertLessEqual(selected["temperature"], 100)

    def test_saved_sliders_are_clamped(self):
        for values, expected in (
            (dict(brightness=-5, saturation=-300, speed=-1, warp=-9, accent_hue=-4),
             dict(brightness=0, saturation=0, speed=0, warp=0, accent_hue=0)),
            (dict(brightness=700, saturation=300, speed=999, warp=500, accent_hue=500),
             dict(brightness=100, saturation=200, speed=300, warp=100, accent_hue=63)),
        ):
            with self.subTest(values=values):
                appearance.save_preferences(self.path, dict(values, variant=57))
                selected = appearance.load_preferences(self.path)
                for key, value in expected.items():
                    self.assertEqual(selected[key], value, key)
                self.assertEqual(selected["variant"], 57)

    def test_old_files_migrate_theme_to_hue_and_crystals_to_cracks(self):
        self.path.write_text(json.dumps({"theme": "aurora", "texture": "crystals", "texture_intensity": 0.45,
                                         "temperature": 40}), encoding="utf-8")
        selected = appearance.load_preferences(self.path)
        self.assertEqual(selected["texture"], "cracks")
        self.assertEqual(selected["accent_hue"], appearance.hue_of_color("#50C878"))
        self.assertEqual(selected["theme"], appearance.hue_theme_id(selected["accent_hue"]))
        self.assertEqual((selected["brightness"], selected["temperature"]), (95, 0))
        self.assertEqual(appearance.normalize_preferences({"texture": "splatter"})["texture"], "rain")


class NativeRenderTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(native, "_disabled_reason", None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_source_and_installed_engine_paths_follow_the_resources_root_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "bin/nova-engine.exe"
            installed = base / "resources/bin/nova-engine.exe"
            for binary in (source, installed):
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.touch()
            with mock.patch.object(native, "__file__", str(base / "resources/nova_native_render.py")), \
                    mock.patch.object(sys, "frozen", False, create=True):
                self.assertEqual(native.engine_path(), source)
            with mock.patch.object(sys, "executable", str(base / "Nova.exe")), \
                    mock.patch.object(sys, "frozen", True, create=True):
                self.assertEqual(native.engine_path(), installed)

    def test_legacy_engine_is_attempted_once_and_failure_is_reported(self):
        with mock.patch.object(native, "engine_path", return_value=Path("nova-engine.exe")), \
                mock.patch.object(native.subprocess, "run", return_value=subprocess.CompletedProcess([], 2, b"", b"old engine")) as run, \
                self.assertLogs("nova_native_render", level="WARNING") as logs:
            for _ in range(2):
                self.assertIsNone(native.mandelbrot(8, 8, -.75, .1, .2, 1, 0, 100))
            self.assertEqual(run.call_count, 1)
            self.assertEqual(len(logs.output), 1)

    def test_partial_pgm_is_rejected_and_explicit_python_mode_never_spawns(self):
        with mock.patch.object(native, "engine_path", return_value=Path("nova-engine.exe")), \
                mock.patch.object(native.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"P5\n8 8\n255\n", b"")), \
                self.assertLogs("nova_native_render", level="WARNING"):
            self.assertIsNone(native.mandelbrot(8, 8, -.75, .1, .2, 1, 0, 100))
        with mock.patch.dict(os.environ, NOVA_NATIVE_RENDER="0"), mock.patch.object(native.subprocess, "run") as run:
            self.assertIsNone(native.mandelbrot(8, 8, -.75, .1, .2, 1, 0, 100))
            run.assert_not_called()

    def _binary(self):
        binary = Path(os.environ.get("NOVA_RENDER_TEST_ENGINE") or
                      str(Path(__file__).resolve().parents[1] / "nova-rs/target/debug/nova-engine.exe"))
        if not binary.is_file():
            self.skipTest("build nova-cli or set NOVA_RENDER_TEST_ENGINE for live Rust parity")
        return binary

    def test_v1_viewport_protocol_remains_pixel_compatible(self):
        with mock.patch.object(native, "engine_path", return_value=self._binary()), \
                mock.patch.dict(os.environ, NOVA_NATIVE_RENDER="1"):
            for width, height, seed in ((32, 24, 8), (24, 32, 9), (47, 35, 197), (80, 60, 42)):
                with self.subTest(size=(width, height), seed=seed):
                    view = fractal.select_view(width, height, random.Random(seed))
                    expected = fractal.render_view_python(view)
                    actual = native.mandelbrot(*view)
                    self.assertIsNone(native._disabled_reason, "Parity must exercise Rust, not the fallback")
                    self.assertIsNotNone(actual)
                    self.assertLessEqual(max(abs(a - b) for a, b in zip(expected, actual)), 1)

    def test_seeded_rust_preserves_pixels_and_exact_random_state_across_twists(self):
        with mock.patch.object(native, "engine_path", return_value=self._binary()), \
                mock.patch.dict(os.environ, NOVA_NATIVE_RENDER="1"):
            for seed, width, height, warmup in ((8, 32, 24, 0), (42, 24, 32, 1),
                                               (197, 47, 35, 623), (9, 32, 24, 624), (91, 32, 24, 625)):
                with self.subTest(seed=seed, warmup=warmup):
                    actual_rng = random.Random(seed)
                    for _ in range(warmup):
                        actual_rng.getrandbits(32)
                    version, state, _gaussian = actual_rng.getstate()
                    actual_rng.setstate((version, state, .125))
                    expected_rng = random.Random()
                    expected_rng.setstate(actual_rng.getstate())
                    expected = fractal.render_mask_python(width, height, expected_rng)
                    actual = fractal.render_mask(width, height, actual_rng)
                    self.assertIsNone(native._disabled_reason, "Must use native seeded selection")
                    self.assertEqual(actual_rng.getstate(), expected_rng.getstate())
                    self.assertLessEqual(max(abs(a - b) for a, b in zip(expected, actual)), 1)

    def test_bad_native_receipt_rolls_back_without_consuming_random_words(self):
        actual_rng = random.Random(8)
        expected_rng = random.Random(8)
        expected = fractal.render_mask_python(24, 18, expected_rng)
        with mock.patch.object(native, "_request", return_value=b"NOVA-FRACTAL/2 8193\n"), \
                self.assertLogs("nova_native_render", level="WARNING"):
            actual = fractal.render_mask(24, 18, actual_rng)
        self.assertEqual(actual, expected)
        self.assertEqual(actual_rng.getstate(), expected_rng.getstate())

    def test_custom_random_subclasses_keep_their_python_contract(self):
        class CustomRandom(random.Random):
            pass
        with mock.patch.object(native, "fractal") as run:
            fractal.render_mask(8, 8, CustomRandom(8))
            run.assert_not_called()


class RenderingTests(unittest.TestCase):
    def test_fractal_is_reproducible_non_solid_and_reseeds(self):
        first = appearance.render_background(96, 72, "aurora", "fractal", 0.5, variant=8)
        again = appearance.render_background(96, 72, "aurora", "fractal", 0.5, variant=8)
        changed = appearance.render_background(96, 72, "aurora", "fractal", 0.5, variant=9)
        plain = appearance.render_background(96, 72, "aurora", "none", 0.5)
        self.assertEqual(first.tobytes(), again.tobytes())
        self.assertNotEqual(first.tobytes(), changed.tobytes())
        difference = ImageChops.difference(first, plain).convert("L")
        low, high = difference.getextrema()
        self.assertGreater(high - low, 10, "Fractal must add detailed geometry beyond the base gradient")

    def test_temperature_slider_runs_from_cold_to_warm(self):
        cold = appearance.render_background(32, 32, temperature=-100).getpixel((16, 0))
        warm = appearance.render_background(32, 32, temperature=100).getpixel((16, 0))
        self.assertGreater(warm[0], cold[0])
        self.assertGreater(cold[2], warm[2])

    def test_callers_cannot_mutate_cached_backgrounds(self):
        image = appearance.render_background(80, 60, "neon", "snow", 0.4)
        original = image.tobytes()
        image.paste("#FFFFFF", (0, 0, 80, 60))
        self.assertEqual(appearance.render_background(80, 60, "neon", "snow", 0.4).tobytes(), original)

    def test_every_theme_supplies_valid_colors_to_existing_windows(self):
        required_settings = {"bg", "panel", "border", "text", "muted", "pill_on_bg",
                             "pill_on_fg", "pill_off_bg", "pill_off_fg"}
        required_log = {"bg", "panel", "text", "button", "button_hover", "button_fg",
                        "button_hover_fg", "grip"}
        for theme in appearance.THEMES:
            with self.subTest(theme=theme):
                for mapping, required in ((appearance.settings_theme(theme), required_settings),
                                          (appearance.log_theme(theme), required_log)):
                    self.assertTrue(required.issubset(mapping))
                    for key in required:
                        ImageColor.getrgb(mapping[key])
                    self.assertNotEqual(mapping["text"], mapping["bg"])
                image = appearance.render_background(64, 40, theme)
                self.assertEqual((image.mode, image.size), ("RGB", (64, 40)))

    def test_surface_preserves_android_veil_instead_of_hiding_texture(self):
        surface = appearance.render_surface(100, 60, "aurora")
        self.assertEqual(surface.mode, "RGBA")
        center = surface.getpixel((50, 30))
        self.assertEqual(center[3], 20, "the card is a faint white veil, alpha 0x14")
        base = Image.new("RGBA", surface.size, "#120D27")
        composited = Image.alpha_composite(base, surface)
        self.assertNotEqual(composited.getpixel((50, 30)), base.getpixel((50, 30)))
        self.assertLess(surface.getpixel((0, 0))[3], center[3])

    def test_background_rejects_unbounded_allocations(self):
        for size in ((0, 60), (60, -1), (4097, 60), (60, 4097)):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    appearance.render_background(*size)


class DesktopIconTests(unittest.TestCase):
    def test_supernova_remains_usable_at_native_windows_icon_sizes(self):
        sizes = (16, 20, 24, 32, 48, 64, 128, 256)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nova.ico"
            image = supernova_icon(256)
            image.save(path, format="ICO", sizes=[(size, size) for size in sizes])
            with Image.open(path) as icon:
                self.assertEqual(icon.ico.sizes(), {(size, size) for size in sizes})
                for size in sizes:
                    frame = icon.ico.getimage((size, size)).convert("RGBA")
                    self.assertGreater(frame.getpixel((size // 2, size // 2))[3], 200)
                    self.assertLess(frame.getpixel((0, 0))[3], 30)


if __name__ == "__main__":
    unittest.main()
