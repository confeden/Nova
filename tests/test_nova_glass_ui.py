"""Matte-glass plates, the appearance window (tiles, hue slider, sliders) and the scene's plate registry."""

import json
import os
import re
import sys
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "resources"))
os.environ["NOVA_GPU"] = "0"

import nova_appearance  # noqa: E402
import nova_appearance_ui as appearance_ui  # noqa: E402
import nova_desktop_ui as desktop  # noqa: E402
import nova_glass  # noqa: E402


class GlassTests(unittest.TestCase):
    def test_compose_draws_plates_and_masks_exactly_their_shape(self):
        layer, mask = nova_glass.compose((300, 200), [(20, 20, 140, 56, 14, None),
                                                      (-10, 100, 90, 150, 12, (80, 200, 160, 205))])
        self.assertEqual((layer.size, mask.size), ((300, 200), (300, 200)))
        self.assertEqual(mask.getpixel((60, 38)), 255)
        self.assertEqual(mask.getpixel((200, 120)), 0)
        self.assertEqual(layer.getpixel((200, 120))[3], 0)
        # a plate hanging off the edge is clipped, not an error
        self.assertEqual(mask.getpixel((5, 125)), 255)
        # the tinted plate is nearly the tint colour, the plain one is a dark veil
        tinted, plain = layer.getpixel((40, 125)), layer.getpixel((60, 38))
        self.assertGreater(tinted[3], plain[3])
        self.assertGreater(tinted[1], tinted[0])

    def test_degenerate_and_outside_shapes_are_ignored(self):
        layer, mask = nova_glass.compose((50, 50), [(10, 10, 11, 11, 4, None), (200, 200, 300, 300, 4, None)])
        self.assertIsNone(mask.getbbox())
        self.assertIsNone(layer.getbbox())

    def test_frost_blurs_only_under_the_mask(self):
        noise = Image.effect_noise((120, 80), 60).convert("RGB")
        _, mask = nova_glass.compose((120, 80), [(30, 20, 90, 60, 10, None)])
        frosted = nova_glass.frost(noise, mask)
        self.assertEqual(frosted.getpixel((5, 5)), noise.getpixel((5, 5)))
        self.assertNotEqual(frosted.getpixel((60, 40)), noise.getpixel((60, 40)))
        empty = Image.new("L", (120, 80), 0)
        self.assertIs(nova_glass.frost(noise, empty), noise)


class AtlasTests(unittest.TestCase):
    def test_hue_rotation_keeps_the_default_and_moves_the_rest(self):
        image = Image.new("RGB", (8, 8), (40, 200, 160))
        self.assertIs(appearance_ui.rotate_hue(image, nova_appearance.DEFAULT_HUE), image)
        moved = appearance_ui.rotate_hue(image, 52).getpixel((0, 0))
        self.assertNotEqual(moved, (40, 200, 160))
        self.assertGreater(moved[0], moved[1])

    def test_every_gpu_texture_has_a_baked_preview(self):
        atlas = appearance_ui.load_atlas([ROOT / "resources"])
        self.assertIsNotNone(atlas, "resources/nova_texture_thumbs.png is missing")
        for key in nova_appearance.TEXTURES:
            cell = appearance_ui.atlas_cell(atlas, key)
            if key in ("none", "custom"):
                self.assertIsNone(cell)
            else:
                self.assertEqual(cell.size, (appearance_ui.THUMB_W, appearance_ui.THUMB_H), key)
                self.assertIsNotNone(cell.getbbox(), key)

    def test_missing_atlas_is_not_fatal(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertIsNone(appearance_ui.load_atlas([empty]))
        self.assertIsNone(appearance_ui.atlas_cell(None, "marble"))


class TkCase(unittest.TestCase):
    """One Tk root per class: re-initialising Tcl many times a second trips over file scanners on this PC."""

    @classmethod
    def setUpClass(cls):
        for attempt in range(6):
            try:
                cls.root = tk.Tk()
                break
            except tk.TclError:
                # Tcl sometimes cannot read its own library right after another interpreter went away.
                if attempt == 5:
                    raise
                time.sleep(0.3)
        cls.root.geometry("10x10+0+0")

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()


class WindowTests(TkCase):
    def setUp(self):
        self.seen = []
        prefs = nova_appearance.normalize_preferences({})
        self.window = appearance_ui.AppearanceWindow(
            self.root, prefs, self.seen.append, place_window=lambda win: win.geometry("+0+0"), show=False,
            asset_dirs=[ROOT / "resources"])
        self.addCleanup(self.window.top.destroy)

    def test_all_textures_are_tiles_and_the_current_one_is_marked(self):
        self.assertEqual(set(self.window.tiles), set(nova_appearance.TEXTURES))
        self.assertNotIn("crystals", self.window.tiles)
        self.assertTrue(self.window.tiles["marble"].selected)
        self.assertFalse(self.window.tiles["basalt"].selected)

    def test_choosing_a_tile_applies_the_texture(self):
        self.window._choose_texture("water")
        self.assertEqual(self.seen[-1]["texture"], "water")
        self.assertTrue(self.window.tiles["water"].selected)
        self.assertFalse(self.window.tiles["marble"].selected)

    def test_dragging_the_hue_keeps_the_ui_theme_until_release(self):
        slider = self.window.sliders["accent_hue"]
        old_theme = self.window.preferences["theme"]
        slider._commit(50, False)
        self.window._flush()
        self.assertEqual(self.seen[-1]["accent_hue"], 50)
        self.assertEqual(self.seen[-1]["theme"], old_theme, "colours of every window must not churn while dragging")
        slider = self.window.sliders["accent_hue"]
        slider._commit(50, True)
        self.assertEqual(self.seen[-1]["theme"], nova_appearance.hue_theme_id(50))
        self.assertEqual(self.window.sliders["accent_hue"].value, 50, "the window is rebuilt in the new colours")

    def test_texture_sliders_reach_the_prefs_within_bounds(self):
        for key, value in (("speed", 150), ("saturation", 20), ("warp", 80), ("brightness", 40)):
            self.window.sliders[key]._commit(value, True)
            self.assertEqual(self.seen[-1][key], value)
        self.window.sliders["speed"]._commit(10 ** 6, True)
        self.assertEqual(self.seen[-1]["speed"], 200)

    def test_a_new_hue_recolours_in_place_without_rebuilding_anything(self):
        before = {key: id(widget) for key, widget in self.window.sliders.items()}
        tiles = {key: id(widget) for key, widget in self.window.tiles.items()}
        self.window.sliders["accent_hue"]._commit(50, True)
        self.assertEqual({key: id(widget) for key, widget in self.window.sliders.items()}, before)
        self.assertEqual({key: id(widget) for key, widget in self.window.tiles.items()}, tiles)
        self.assertEqual(self.window.colors["accent"], nova_appearance.settings_theme("hue50")["accent"])
        self.assertEqual(self.window.sliders["accent_hue"].colors["accent"], self.window.colors["accent"])

    def test_own_picture_tile_asks_for_a_file_first_and_then_selects_it(self):
        asked = []
        self.window._pick_image = lambda: asked.append(True)
        self.window._choose_texture("custom")
        self.assertEqual(asked, [True])
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "pic.png"
            Image.new("RGB", (40, 20), (200, 30, 30)).save(path)
            self.window._change(final=True, custom_image=str(path))
            self.window._choose_texture("custom")
            self.assertEqual(self.seen[-1]["texture"], "custom")
            self.assertEqual(self.seen[-1]["custom_image"], str(path))
            self.assertIsNotNone(self.window._custom_cell())

    def test_switches_and_reset(self):
        self.window.switches["limit_30fps"].toggle()
        self.assertTrue(self.seen[-1]["limit_30fps"])
        self.window.sliders["warp"]._commit(90, True)
        self.window._reset()
        self.assertEqual(self.seen[-1]["warp"], nova_appearance.DEFAULT_PREFERENCES["warp"])
        self.assertEqual(self.seen[-1]["accent_hue"], nova_appearance.DEFAULT_PREFERENCES["accent_hue"])
        self.assertTrue(self.seen[-1]["limit_30fps"], "reset touches the look, not the switches")


class ScenePlateTests(TkCase):
    def setUp(self):
        self.canvas = tk.Canvas(self.root, width=560, height=420)
        self.canvas.pack()
        self.scene = desktop.DesktopScene(self.canvas, nova_appearance.normalize_preferences({}), "t", gpu=False)
        self.addCleanup(self.canvas.destroy)

    def test_plates_are_registered_deduplicated_and_removed(self):
        self.scene.set_plate("a", (10, 10, 110, 40), 10)
        first = self.scene._plate_shapes
        self.assertEqual(len(first), 1)
        self.scene.set_plate("a", (10, 10, 110, 40), 10)
        self.assertIs(self.scene._plate_shapes, first)
        self.scene.set_plate("b", (200, 10, 300, 40), 10, (1, 2, 3, 200))
        self.assertEqual(len(self.scene._plate_shapes), 2)
        self.scene.remove_plate("a")
        self.assertEqual([shape[0] for shape in self.scene._plate_shapes], [200])
        self.scene.remove_plate("missing")

    def test_own_picture_is_a_still_cover_fitted_background(self):
        prefs = nova_appearance.normalize_preferences({"texture": "custom"})
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "pic.png"
            Image.new("RGB", (100, 50), (200, 30, 30)).save(path)
            frame = self.scene._custom_frame((80, 60), dict(prefs, custom_image=str(path)))
            self.assertEqual(frame.size, (80, 60))
            self.assertGreater(frame.getpixel((40, 30))[0], 150)
            again = self.scene._custom_frame((80, 60), dict(prefs, custom_image=str(path)))
            self.assertIs(again, frame, "rendered once, not per frame")
            dim = self.scene._custom_frame((80, 60), dict(prefs, custom_image=str(path), brightness=40))
            self.assertLess(dim.getpixel((40, 30))[0], frame.getpixel((40, 30))[0])
        missing = self.scene._custom_frame((80, 60), dict(prefs, custom_image=str(Path("nope") / "x.png")))
        self.assertEqual(missing.size, (80, 60))

    def test_hot_is_not_handled_without_the_gpu_engine(self):
        self.assertFalse(self.scene.set_hot((10, 10, 100, 40), 10))

    def test_overlay_mask_follows_the_registered_plates(self):
        colors = nova_appearance.settings_theme("hue31")
        layout = desktop.main_layout(560, 420, self.scene.scale)
        prefs = nova_appearance.normalize_preferences({})
        self.scene.set_plate("p", (5, 5, 65, 25), 8)
        self.scene._panel_overlay(560, 420, prefs, colors, layout)
        self.assertEqual(self.scene._overlay_mask.getpixel((30, 15)), 255)
        self.scene.remove_plate("p")
        self.scene._panel_overlay(560, 420, prefs, colors, layout)
        self.assertEqual(self.scene._overlay_mask.getpixel((30, 15)), 0)

    def test_compose_cards_draws_overlapping_rectangles_as_one_glass(self):
        from nova_glass import compose_cards
        layer, mask = compose_cards((200, 120), [[(10, 10, 110, 60, 12), (60, 10, 180, 60, 12)]], 1.0)
        self.assertEqual(mask.getpixel((90, 30)), 255)
        self.assertEqual(layer.getpixel((90, 30)), layer.getpixel((30, 30)), "no darker band where they overlap")
        self.assertEqual(mask.getpixel((100, 100)), 0)
        _, folded = compose_cards((200, 120), [[(10.5, 10, 10.5, 10, 4)]], 1.0, fast=True)
        self.assertIsNone(folded.getbbox(), "a degenerate rectangle draws nothing")

    def test_glass_compact_is_a_saved_flag_that_defaults_off(self):
        self.assertIs(nova_appearance.normalize_preferences({})["glass_compact"], False)
        self.assertIs(nova_appearance.normalize_preferences({"glass_compact": True})["glass_compact"], True)
        self.assertIs(nova_appearance.normalize_preferences({"glass_compact": "yes"})["glass_compact"], False)

    def test_nova_toggle_folds_the_cards_into_pills_around_their_text(self):
        scene = self.scene
        scene._size = (560, 420)
        layout = desktop.main_layout(560, 420, scene.scale)
        self.canvas.create_text(*layout["status"], text="Готово к подключению", tags=("zone_status",))
        scene.draw(560, 420)
        self.assertIsNone(scene._card_groups(560, 420), "whole cards by default")
        scene.set_compact(True, animate=False)
        self.assertTrue(scene.compact and scene.appearance["glass_compact"])
        hero, routes = scene._card_groups(560, 420)
        self.assertEqual(len(hero), 1, "one pill for the status text")
        left, top, right, bottom, radius = hero[0]
        self.assertLess(right - left, layout["hero"][2] - layout["hero"][0])
        self.assertAlmostEqual(radius, (bottom - top) / 2, delta=.5)
        self.assertTrue(left <= layout["status"][0] <= right and top <= layout["status"][1] <= bottom)
        self.assertEqual(len(routes), 1, "the route heading only: the slot captions have no glass of their own")
        colors = nova_appearance.settings_theme("hue31")
        prefs = dict(nova_appearance.normalize_preferences({}), _cards=scene._card_groups(560, 420))
        scene._panel_overlay(560, 420, prefs, colors, layout)
        self.assertEqual(scene._overlay_mask.getpixel((20, layout["hero"][1] + 5)), 0, "the card is gone")
        self.assertEqual(scene._overlay_mask.getpixel((round((left + right) / 2), round((top + bottom) / 2))), 255)
        scene.set_compact(False, animate=False)
        self.assertIsNone(scene._card_groups(560, 420))
        self.assertFalse(scene.appearance["glass_compact"])

    def test_the_fold_is_kept_when_the_appearance_window_sends_older_settings(self):
        self.scene.set_compact(True, animate=False)
        self.scene.set_appearance(nova_appearance.normalize_preferences({"glass_compact": False}))
        self.assertTrue(self.scene.appearance["glass_compact"])

    def test_the_fold_never_reaches_the_saved_preferences_as_render_extras(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "appearance.json"
            scene = desktop.DesktopScene(self.canvas, nova_appearance.normalize_preferences({}), "t",
                                         preferences_path=path, gpu=False)
            scene._persist_preferences(1, dict(nova_appearance.normalize_preferences({"glass_compact": True}),
                                               _cards=((1, 2, 3, 4, 5),), _fast=True))
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(saved["glass_compact"])
            self.assertFalse([key for key in saved if key.startswith("_")])


class PopupPlacementTests(unittest.TestCase):
    """nova.pyw calc_log_window_pos: Settings/Profiles/Log/Appearance sit beside the main window, on the monitor."""

    @classmethod
    def setUpClass(cls):
        import ast
        source = (ROOT / "nova.pyw").read_text(encoding="utf-8-sig")
        node = next(item for item in ast.walk(ast.parse(source))
                    if isinstance(item, ast.FunctionDef) and item.name == "calc_log_window_pos")
        namespace = {}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "nova.pyw", "exec"), namespace)
        cls.place = staticmethod(namespace["calc_log_window_pos"])

    def test_prefers_the_right_then_the_left_side(self):
        self.assertEqual(self.place(100, 50, 600, 500, 400, 300, 0, 1920)[:3:2], (700, "right"))
        x, _, side = self.place(1400, 50, 500, 500, 400, 300, 0, 1920)
        self.assertEqual((x, side), (1000, "left"))

    def test_when_neither_side_has_room_the_window_stays_on_the_monitor(self):
        for current in (None, "left", "right"):
            x, _, side = self.place(100, 50, 800, 500, 600, 300, 0, 1000, current)
            self.assertTrue(0 <= x <= 1000 - 600, (current, x))

    def test_window_is_lifted_when_it_would_leave_the_bottom_edge(self):
        self.assertEqual(self.place(100, 900, 600, 100, 400, 300, 0, 1920, None, 0, 1000)[1], 700)
        self.assertEqual(self.place(100, -50, 600, 100, 400, 300, 0, 1920, None, 0, 1000)[1], 0)


class MainWindowWidgetTests(TkCase):
    """The nova.pyw canvas widgets (cut out by AST, as the journal-icon test does) register glass plates and
    light them on hover instead of drawing the old green outline."""

    NAMES = {"CanvasButton", "RoundedButton", "CanvasRegionPill", "create_round_rect_img",
             "create_round_outline_img", "create_glow_img", "create_chevron_img", "glass_plate", "glass_unplate", "glass_hover",
             "hover_text_color", "bold_variant", "get_lighter_hex", "get_rgb"}

    def setUp(self):
        import ast
        import contextlib
        import tkinter.font as tkfont
        source = (ROOT / "nova.pyw").read_text(encoding="utf-8-sig")
        nodes = [node for node in ast.walk(ast.parse(source))
                 if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in self.NAMES]
        self.assertEqual({node.name for node in nodes}, self.NAMES)
        self.canvas = tk.Canvas(self.root, width=560, height=420)
        self.canvas.pack()
        prefs = nova_appearance.normalize_preferences({})
        self.scene = desktop.DesktopScene(self.canvas, prefs, "t", gpu=False)
        theme = nova_appearance.settings_theme(prefs["theme"])
        self.lit = []
        self.scene.set_hot = lambda rect, radius=0: (self.lit.append(rect), self.gpu_lit)[1]
        self.gpu_lit = False
        self.ns = dict(re=re, root=self.root, tk=tk, tkfont=tkfont, time=time, contextlib=contextlib, UI_SCALE=1,
                       SETTINGS_THEME=theme, OUTLINE_ACCENT_COLOR=theme["accent"], APPEARANCE=prefs,
                       nova_appearance=nova_appearance, nova_desktop_ui=desktop, main_scene=self.scene,
                       COLOR_TEXT_ERROR="#f00", _ROUND_RECT_IMG_CACHE=desktop.ImageCache(),
                       _ROUND_OUTLINE_IMG_CACHE=desktop.ImageCache())
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "nova.pyw", "exec"), self.ns)
        self.addCleanup(self.canvas.destroy)

    def test_footer_button_is_a_plate_and_hover_uses_the_halo_unless_the_gpu_lights_it(self):
        button = self.ns["CanvasButton"](self.canvas, 100, 40, "Журнал", ("Segoe UI Semibold", 9),
                                          lambda: None, anchor="center")
        self.assertEqual(len(self.scene._plate_shapes), 1)
        button._set_hover(True)
        self.assertEqual(self.canvas.itemcget(button.outline_id, "state"), "normal", "CPU path: Tk halo")
        self.gpu_lit = True
        button._set_hover(True)
        self.assertEqual(self.canvas.itemcget(button.outline_id, "state"), "hidden", "GPU path lights the texture")
        button._set_hover(False)
        self.assertIsNone(self.lit[-1])
        button.set_visible(False)
        self.assertEqual(self.scene._plate_shapes, ())

    def test_main_action_button_is_a_plain_glass_pill_with_accent_lettering(self):
        toggle = self.ns["RoundedButton"](self.canvas, 280, 200, 232, 48, 24, "#50C878", "Включить", lambda: None,
                                          fg="#50C878")
        self.assertIsNone(self.scene._plate_shapes[0][5], "no accent fill: the same veil as the other buttons")
        self.assertEqual(self.canvas.itemcget(toggle.text_id, "fill"), "#50C878")
        toggle.config(state="disabled")
        self.assertIsNone(self.scene._plate_shapes[0][5])
        toggle.config(state="normal")
        self.assertEqual(len(self.scene._plate_shapes), 1)
        toggle.move_to(300, 220)
        self.assertEqual(len(self.scene._plate_shapes), 1)
        toggle.set_notice("чужой VPN")
        self.assertEqual(self.scene._plate_shapes, ())
        toggle.set_notice(None)
        self.assertEqual(len(self.scene._plate_shapes), 1)

    def test_slot_pill_registers_one_plate_per_button_and_drops_them_when_hidden(self):
        theme = self.ns["SETTINGS_THEME"]
        pill = self.ns["CanvasRegionPill"](self.canvas, 100, 300, ("Segoe UI", 9), anchor="center",
                                           bg_color=theme["panel"])
        pill.slot_width, pill.button_width = 520, 110
        pill.button_centers, pill.next_centers, pill.next_width = (110, 330), (190, 410), 30
        pill.segments = [("EU", "#ffffff"), ("Нет", "#aaaaaa")]
        pill.segment_keys = ["primary", "secondary"]
        pill.set_next_handler(lambda key: None)
        self.assertEqual(len(self.scene._plate_shapes), 4, "two slot buttons and two next arrows")
        pill._set_hover(0)
        self.assertEqual(self.canvas.itemcget(pill._hover_outline_id, "state"), "normal")
        self.gpu_lit = True
        pill._hover_index = None
        pill._set_hover(0)
        self.assertEqual(self.canvas.itemcget(pill._hover_outline_id, "state"), "hidden")
        pill.set_visible(False)
        self.assertEqual(self.scene._plate_shapes, ())
        pill.set_visible(True)
        self.assertEqual(len(self.scene._plate_shapes), 4)


if __name__ == "__main__":
    unittest.main()


def test_tile_columns_fill_the_row_and_leave_the_last_row_nearly_full():
    # 23 tiles in the 768 px the window already needs: 9 columns would fit, 8 leave one hole instead of four
    assert appearance_ui.tile_columns(23, 768) == 8
    assert appearance_ui.tile_columns(21, 768) == 7          # 3 full rows
    assert appearance_ui.tile_columns(23, 300) >= 1
    assert appearance_ui.tile_columns(1, 768) >= 1


def test_second_click_on_the_chosen_texture_draws_a_new_picture():
    root = tk.Tk()
    root.withdraw()
    try:
        seen = []
        win = appearance_ui.AppearanceWindow(root, dict(nova_appearance.DEFAULT_PREFERENCES, texture="sand", variant=4),
                                             seen.append, show=False)
        assert not hasattr(win, "pattern_button")
        win._choose_texture("sand")
        assert win.preferences["variant"] == 5 and win.preferences["texture"] == "sand"
        win._choose_texture("snow")
        assert win.preferences["texture"] == "snow" and win.preferences["variant"] == 5
        win.top.destroy()
    finally:
        root.destroy()
