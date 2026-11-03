"""Appearance persistence must survive failed writes; procedural assets stay reproducible."""

import json
import math
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from PIL import Image, ImageChops, ImageColor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources"))

import nova_appearance as appearance  # noqa: E402
from nova_desktop_ui import supernova_icon  # noqa: E402


class PreferenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "appearance.json"

    def test_roundtrip_keeps_texture_reseed_and_temperature(self):
        selected = {
            "theme": "matrix", "texture": "fractal", "texture_intensity": 0.31,
            "variant": 197, "temperature": -35,
        }
        appearance.save_preferences(self.path, selected)
        self.assertEqual(appearance.load_preferences(self.path), selected)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

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

    def test_saved_intensity_and_temperature_are_clamped(self):
        for intensity, temperature, expected_intensity, expected_temperature in (
            (-5, -300, 0, -100), (7, 300, 0.6, 100),
        ):
            with self.subTest(intensity=intensity):
                appearance.save_preferences(self.path, {
                    "texture_intensity": intensity, "temperature": temperature, "variant": 57,
                })
                selected = appearance.load_preferences(self.path)
                self.assertEqual(selected["texture_intensity"], expected_intensity)
                self.assertEqual(selected["temperature"], expected_temperature)
                self.assertEqual(selected["variant"], 57)


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
        self.assertEqual(center[3], 11, "Aurora's Android card is white alpha 0x0B")
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
