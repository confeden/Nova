"""Concurrency and lifecycle coverage for the desktop appearance renderer."""

import threading
import ast
import tempfile
import time
import tkinter as tk
import unittest
from unittest import mock
from pathlib import Path

from PIL import Image

import nova_appearance
import nova_desktop_ui as ui


class _GuardedCanvas(tk.Canvas):
    def __init__(self, root, owner, violations):
        self._owner = owner
        self._violations = violations
        super().__init__(root)

    def _guard(self):
        if threading.get_ident() != self._owner:
            self._violations.append(threading.get_ident())
            raise AssertionError("A render worker touched Tk")

    def after(self, *args):
        self._guard()
        return super().after(*args)

    def after_cancel(self, *args):
        self._guard()
        return super().after_cancel(*args)

    def create_image(self, *args, **kwargs):
        self._guard()
        return super().create_image(*args, **kwargs)

    def itemconfigure(self, *args, **kwargs):
        self._guard()
        return super().itemconfigure(*args, **kwargs)

    def tag_lower(self, *args):
        self._guard()
        return super().tag_lower(*args)


class CaptionTests(unittest.TestCase):
    def test_link_hover_styles_in_place_and_restores_the_base_style(self):
        canvas = mock.Mock()
        label = type("Link", (), dict(canvas=canvas, text_items=[17], font_spec=("Segoe UI Semibold", 9),
                                     fg="#b0b0b0"))()
        ui.set_link_hover(label, True, "#50c878")
        self.assertEqual(canvas.itemconfigure.call_args.kwargs, dict(fill="#50c878", font=("Segoe UI Semibold", 9, "underline")))
        ui.set_link_hover(label, False, "#50c878")
        self.assertEqual(canvas.itemconfigure.call_args.kwargs, dict(fill=label.fg, font=label.font_spec))
        canvas.create_text.assert_not_called()
        canvas.delete.assert_not_called()

    def test_long_profile_name_fits_without_measuring_every_character(self):
        measurements = []

        def measure(text):
            measurements.append(text)
            return len(text) * 7

        result = ui.fit_caption("Long imported profile " * 500, 140, measure)
        self.assertTrue(result.endswith("…"))
        self.assertLessEqual(len(result) * 7, 140)
        self.assertLess(len(measurements), 20)

    def test_insufficient_space_cannot_draw_an_ellipsis_outside_the_slot(self):
        self.assertEqual(ui.fit_caption("Long name", 4, lambda text: len(text) * 7), "")


class DesktopSceneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
        except tk.TclError as error:
            raise unittest.SkipTest(f"Tk cannot create a window: {error}")
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.owner = threading.get_ident()
        self.violations = []
        self.callback_errors = []
        self.root.report_callback_exception = lambda _kind, error, _trace: self.callback_errors.append(error)
        self.scenes = []
        self.workers = []
        self.release_events = []
        self.photos = []
        self.temporary = tempfile.TemporaryDirectory(prefix="nova-desktop-ui-")
        self.addCleanup(self.temporary.cleanup)
        actual_thread = threading.Thread
        actual_photo = ui.ImageTk.PhotoImage

        def worker(*args, **kwargs):
            thread = actual_thread(*args, **kwargs)
            self.workers.append(thread)
            return thread

        def photo(rendered, **kwargs):
            self.photos.append((threading.get_ident(), rendered.getpixel((0, 0))))
            return actual_photo(rendered, **kwargs)

        for patcher in (mock.patch.object(ui.threading, "Thread", side_effect=worker),
                        mock.patch.object(ui.ImageTk, "PhotoImage", side_effect=photo),
                        mock.patch.object(ui.DesktopScene, "_draw_labels", autospec=True,
                                          side_effect=lambda scene: scene.canvas._guard())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        for scene in self.scenes:
            if scene.canvas.winfo_exists():
                scene.canvas.destroy()
        for event in self.release_events:
            event.set()
        for worker in self.workers:
            worker.join(2)
            self.assertFalse(worker.is_alive(), "Appearance worker survived canvas destruction")
        self.root.update()
        self.scenes.clear()
        self.assertEqual(self.violations, [])
        self.assertEqual(self.callback_errors, [])

    def pump_until(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.root.update()
            if predicate():
                return True
            time.sleep(0.005)
        return False

    def scene(self, on_error=None, preferences=None):
        canvas = _GuardedCanvas(self.root, self.owner, self.violations)
        scene = ui.DesktopScene(canvas, preferences or dict(nova_appearance.DEFAULT_PREFERENCES, texture="lightning"), "test",
                                preferences_path=Path(self.temporary.name) / "appearance.json", on_error=on_error)
        self.scenes.append(scene)
        return scene

    def test_slow_old_render_cannot_replace_rapid_latest_preferences(self):
        started, release = threading.Event(), threading.Event()
        self.release_events.append(release)
        rendered = []

        def render(width, height, _theme, _texture, _intensity, variant, _temperature):
            rendered.append((variant, threading.get_ident()))
            if variant == 0:
                started.set()
                if not release.wait(2):
                    raise AssertionError("Old render was never released")
            return Image.new("RGB", (width, height), (20 + variant, 40, 60))

        with mock.patch.object(ui.nova_appearance, "render_background", side_effect=render), \
                mock.patch.object(ui.nova_appearance, "save_preferences") as save:
            scene = self.scene()
            scene.draw(ui.MIN_WIDTH, ui.MIN_HEIGHT)
            self.assertTrue(self.pump_until(started.is_set))
            scene.set_appearance(dict(scene.appearance, variant=1))
            scene.set_appearance(dict(scene.appearance, variant=2))
            release.set()
            self.assertTrue(self.pump_until(lambda: scene._photo is not None))
            self.assertEqual([variant for variant, _thread in rendered], [0, 2])
            self.assertTrue(all(thread != self.owner for _variant, thread in rendered))
            self.assertEqual(self.photos, [(self.owner, (22, 40, 60))])
            self.assertEqual(save.call_count, 1)
            self.assertEqual(save.call_args.args[1]["variant"], 2)

    def test_save_failure_reports_on_tk_thread_and_still_applies_render(self):
        errors = []
        with mock.patch.object(ui.nova_appearance, "save_preferences", side_effect=PermissionError("read only")), \
                mock.patch.object(ui.nova_appearance, "render_background",
                                  side_effect=lambda width, height, *_args: Image.new("RGB", (width, height), "#203040")), \
                self.assertLogs(level="ERROR") as logs:
            scene = self.scene(lambda message: errors.append((threading.get_ident(), message)))
            scene.set_appearance(dict(scene.appearance, variant=1))
            self.assertTrue(self.pump_until(lambda: scene._photo is not None and errors))
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0][0], self.owner)
            self.assertIn("read only", errors[0][1])
            self.assertTrue(any("read only" in line for line in logs.output))
            self.assertEqual(self.photos, [(self.owner, (32, 48, 64))])

    def test_destroy_during_render_cancels_poll_and_stops_worker(self):
        started, release = threading.Event(), threading.Event()
        self.release_events.append(release)

        def render(width, height, *_args):
            started.set()
            if not release.wait(2):
                raise AssertionError("Closing render was never released")
            return Image.new("RGB", (width, height))

        with mock.patch.object(ui.nova_appearance, "render_background", side_effect=render):
            scene = self.scene()
            scene.draw(ui.MIN_WIDTH, ui.MIN_HEIGHT)
            self.assertTrue(self.pump_until(started.is_set))
            pending = scene._poll_id
            scene.canvas.destroy()
            self.assertNotIn(pending, self.root.tk.call("after", "info"))
            release.set()
            self.assertTrue(self.pump_until(lambda: not self.workers[0].is_alive()))
            deadline = time.monotonic() + 0.1
            self.assertTrue(self.pump_until(lambda: time.monotonic() >= deadline))
            self.assertEqual(self.photos, [])
            self.assertTrue(scene._closed)

    def test_hidden_scene_does_not_render_animation_frames(self):
        with mock.patch.object(ui.nova_appearance, "render_background",
                               side_effect=lambda w, h, *_args: Image.new("RGB", (w, h))) as render:
            scene = self.scene()
            scene.set_connection_state("connecting")
            self.assertTrue(self.pump_until(lambda: scene._photo is not None))
            calls = render.call_count
            scene._animate()
            self.root.update()
            self.assertEqual(render.call_count, calls)
            scene.set_connection_state("stopped")
            self.assertIsNotNone(scene._animation_id)
            scene.set_appearance(dict(scene.appearance, immersion=False))
            self.assertIsNone(scene._animation_id)

    def test_stopped_visible_scene_animates_fractal(self):
        with mock.patch.object(ui.nova_appearance, "render_background",
                               side_effect=lambda w, h, *_args: Image.new("RGB", (w, h))), \
                mock.patch.object(ui.DesktopScene, "_dive_frame",
                                  side_effect=lambda size, *_args: Image.new("RGB", size, "#203040")) as dive:
            self.root.deiconify()
            scene = self.scene(preferences=nova_appearance.DEFAULT_PREFERENCES)
            scene.canvas.pack()
            self.root.update()
            scene._animate()
            self.assertTrue(self.pump_until(lambda: dive.called))
            self.assertEqual(scene._connection, "stopped")
            self.assertIsNotNone(scene._animation_id)

    def test_connecting_frames_do_not_wait_for_the_old_80ms_tick(self):
        shown = []
        self.root.deiconify()
        with mock.patch.object(ui.DesktopScene, "_dive_frame",
                               side_effect=lambda size, *_args: Image.new("RGB", size, "#203040")):
            scene = self.scene()
            scene.canvas.pack()
            self.root.update()
            scene.set_connection_state("connecting")
            original = ui.ImageTk.PhotoImage

            def photo(*args, **kwargs):
                shown.append(time.monotonic())
                return original(*args, **kwargs)

            with mock.patch.object(ui.ImageTk, "PhotoImage", side_effect=photo):
                self.assertTrue(self.pump_until(lambda: len(shown) >= 12))
            # End-to-end worker -> Tk cadence, including the real Pillow ring renderer.
            self.assertLess((shown[-1] - shown[0]) / (len(shown) - 1), .045)

    def test_log_burst_uses_bounded_batches_and_yields_to_tk(self):
        pump = ui.UiLogPump()
        delivered, owners, heartbeat = [], [], []

        def deliver(rows):
            delivered.append(rows)
            owners.append(threading.get_ident())
            self.root.after(0, lambda: heartbeat.append(len(delivered)))

        # No Tk method, including after(), may run on the producer thread.
        producer = threading.Thread(target=lambda: [pump.put((i, "line", "info")) for i in range(1024)])
        producer.start()
        producer.join(1)
        pump.start(self.root, deliver)
        try:
            self.assertTrue(self.pump_until(lambda: sum(map(len, delivered)) == 1024))
            self.assertEqual([row[0] for batch in delivered for row in batch], list(range(1024)))
            self.assertTrue(all(len(batch) <= 128 for batch in delivered))
            self.assertEqual(set(owners), {self.owner})
            self.assertGreaterEqual(len(heartbeat), len(delivered) - 1)
        finally:
            pending = pump.after_id
            pump._destroy(type("Event", (), {"widget": self.root})())
            self.assertNotIn(pending, self.root.tk.call("after", "info"))

    def test_production_log_producers_enqueue_without_tk_calls(self):
        import types
        source = (Path(__file__).resolve().parents[1] / "nova.pyw").read_text(encoding="utf-8")
        names = {"log_print", "_safe_log_insert", "RedirectText"}
        nodes = [node for node in ast.walk(ast.parse(source))
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
        pump, console = ui.UiLogPump(), []

        class NoWorkerTk:
            def after(self, *_args):
                raise AssertionError("A log producer called Tk")

        scope = dict(root=NoWorkerTk(), ui_log_pump=pump, time=time,
                     should_suppress_strategy_noise=lambda text: text == "filtered",
                     should_ignore=lambda text: not text.strip(),
                     _build_log_entry=lambda text: (text, "info"),
                     _session_console_log_lines=lambda text: text,
                     _session_console_log_write=console.append,
                     sys=types.SimpleNamespace(__stdout__=types.SimpleNamespace(write=lambda text: None)))
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "nova.pyw", "exec"), scope)
        scope["root"] = None
        # Before Tk exists, the module has not defined its log filters yet.
        prepare = scope.pop("_build_log_entry")
        ignore = scope.pop("should_ignore")
        scope["log_print"]("bootstrap")
        scope["RedirectText"]().write("bootstrap print")
        self.assertTrue(pump.rows.empty())
        scope.update(root=NoWorkerTk(), _build_log_entry=prepare, should_ignore=ignore)
        errors = []

        def produce():
            try:
                scope["log_print"]("normal")
                scope["log_print"]("filtered")
                redirect = scope["RedirectText"]()
                redirect.write("printed")
                redirect.write("\n")
                redirect.write("could not read config")
            except Exception as error:
                errors.append(error)

        producer = threading.Thread(target=produce)
        producer.start()
        producer.join(1)
        self.assertFalse(producer.is_alive())
        self.assertEqual(errors, [])
        rows = [pump.rows.get_nowait() for _ in range(pump.rows.qsize())]
        self.assertEqual([(text, tag) for _stamp, text, tag in rows],
                         [("normal", "info"), ("printed", "info"), ("could not read config", "error")])
        self.assertIn("normal\n", console)

    def test_real_status_halo_tracks_caption_color_size_position_and_visibility(self):
        import ast
        from tkinter import font as tkfont
        source = (Path(__file__).resolve().parents[1] / "nova.pyw").read_text(encoding="utf-8")
        tree = ast.parse(source)
        label = next(node for node in ast.walk(tree)
                     if isinstance(node, ast.ClassDef) and node.name == "CanvasLabel")
        imports = [node for node in tree.body if isinstance(node, ast.ImportFrom) and node.module == "PIL"]
        scope = {"tkfont": tkfont, "UI_SCALE": 1, "nova_desktop_ui": ui}
        exec(compile(ast.Module(body=imports + [label], type_ignores=[]), "nova.pyw", "exec"), scope)
        canvas = tk.Canvas(self.root, width=560, height=160)
        caption = scope["CanvasLabel"](canvas, 280, 80, "ПОДКЛЮЧЕНИЕ", ("Segoe UI Semibold", 12),
                                       fg="#50c878", formatter=ui.status_text)
        original = caption.glow_image
        self.assertEqual(canvas.itemcget(caption.glow_id, "state"), "normal")
        self.assertGreater(caption.glow_image.width(), 20)
        caption.config(text="АКТИВНО : РАБОТАЕТ", fg="#b191ff")
        self.assertIsNot(caption.glow_image, original)
        caption.move_to(290, 95)
        bounds = canvas.bbox(caption.text_items[0])
        self.assertEqual(canvas.coords(caption.glow_id)[1], (bounds[1] + bounds[3]) / 2)
        caption.set_visible(False)
        self.assertEqual(canvas.itemcget(caption.glow_id, "state"), "hidden")
        caption.set_visible(True)
        self.assertEqual(canvas.itemcget(caption.glow_id, "state"), "normal")
        canvas.destroy()

    def test_real_link_hover_keeps_native_items_and_restores_font(self):
        canvas = tk.Canvas(self.root)
        try:
            font = ("Segoe UI Semibold", 9)
            item = canvas.create_text(100, 40, text="Благодарности", font=font, fill="#b0b0b0")
            label = type("Link", (), dict(canvas=canvas, text_items=[item], font_spec=font, fg="#b0b0b0"))()
            original = canvas.coords(item)
            ui.set_link_hover(label, True, "#50c878")
            self.assertEqual(canvas.itemcget(item, "fill"), "#50c878")
            self.assertEqual(int(self.root.tk.call("font", "actual", canvas.itemcget(item, "font"), "-underline")), 1)
            ui.set_link_hover(label, False, "#50c878")
            self.assertEqual(canvas.itemcget(item, "fill"), label.fg)
            self.assertEqual(int(self.root.tk.call("font", "actual", canvas.itemcget(item, "font"), "-underline")), 0)
            self.assertEqual(canvas.find_all(), (item,))
            self.assertEqual(canvas.coords(item), original)
        finally:
            canvas.destroy()

    def test_dive_keeps_one_pattern_across_startup_cycles_and_resizes(self):
        def render(w, h, _theme, _texture, _intensity, variant, _temperature):
            image = Image.new("RGB", (w, h))
            image.putdata([((int(x / w * 200) + variant * 47) % 256, int(y / h * 160), 60)
                           for y in range(h) for x in range(w)])
            return image

        scene = self.scene()
        with mock.patch.object(ui.nova_appearance, "render_background", side_effect=render) as renderer:
            first = scene._dive_frame((100, 80), scene.appearance, 0)
            next_frame = scene._dive_frame((100, 80), scene.appearance, .08)
            from PIL import ImageChops
            self.assertLessEqual(max(high for _, high in ImageChops.difference(first, next_frame).getextrema()), 1)
            moving = scene._dive_frame((100, 80), scene.appearance, 60)
            self.assertNotEqual(first.tobytes(), moving.tobytes())
            for elapsed in (120, 180, 240, 600, 3600):
                scene._dive_frame((100, 80), scene.appearance, elapsed)
            repeated = scene._dive_frame((100, 80), scene.appearance, 120)
            self.assertNotEqual(first.tobytes(), repeated.tobytes())
            scene._dive_frame((180, 100), scene.appearance, 30)
            static = dict(scene.appearance, immersion=False)
            self.assertEqual(first.tobytes(), scene._dive_frame((100, 80), static, 30).tobytes())
            self.assertEqual(renderer.call_count, 1)
            changed = dict(scene.appearance, variant=scene.appearance["variant"] + 1)
            replacement = scene._dive_frame((100, 80), changed, 0)
            self.assertEqual(renderer.call_count, 2)
            self.assertNotEqual(first.tobytes(), replacement.tobytes())

    def test_dive_never_reverses_or_wraps_back_at_former_cycle_boundaries(self):
        scene = self.scene()
        layer = Image.new("RGB", (100, 80), "#203040")
        with mock.patch.object(scene, "_dive_layer", return_value=layer), \
                mock.patch.object(layer, "resize", wraps=layer.resize) as resize:
            for elapsed in (0, 30, 59.999, 60.001, 90, 119.999, 120.001, 180, 240, 3600, 86400):
                scene._dive_frame((100, 80), scene.appearance, elapsed)
            boxes = [call.kwargs["box"] for call in resize.call_args_list]
            for before, after in zip(boxes, boxes[1:]):
                self.assertGreater(before[2] - before[0], after[2] - after[0])
                self.assertGreater(before[3] - before[1], after[3] - after[1])
                self.assertLess(before[0], after[0])
                self.assertLess(before[1], after[1])

    def test_fractal_recalculates_full_resolution_on_the_same_plane_during_zoom_and_resize(self):
        scene = self.scene(preferences=dict(nova_appearance.DEFAULT_PREFERENCES, texture='fractal'))
        with mock.patch.object(ui.nova_appearance.nova_android_fractal, "render_mask",
                               side_effect=lambda w, h, *_a, **_k: bytes([70]) * (w * h)) as renderer, \
                mock.patch.object(scene, "_dive_layer", side_effect=AssertionError("Fractal must not magnify a thumbnail")):
            for size, elapsed in (((700, 500), 0), ((700, 500), 3600), ((900, 600), 3601)):
                self.assertEqual(scene._dive_frame(size, scene.appearance, elapsed).size, size)
            self.assertEqual([call.args[:2] for call in renderer.call_args_list], [(700, 500), (700, 500), (900, 600)])
            self.assertTrue(all(call.kwargs["source"] == (700, 500) for call in renderer.call_args_list))
            self.assertTrue(all(call.args[2] == scene.appearance["variant"] for call in renderer.call_args_list))
            first, later = (call.kwargs["crop"] for call in renderer.call_args_list[:2])
            self.assertEqual(first, (0, 0, 1, 1))
            self.assertLess(later[2] - later[0], first[2] - first[0])

    def test_initial_resize_and_connection_draws_use_the_animation_path(self):
        with mock.patch.object(ui.nova_appearance, "render_background",
                               side_effect=lambda w, h, *_args: Image.new("RGB", (w, h), "#203040")) as renderer:
            scene = self.scene()
            with mock.patch.object(scene, "_dive_frame", wraps=scene._dive_frame) as frames:
                scene.draw(ui.MIN_WIDTH, ui.MIN_HEIGHT)
                self.assertTrue(self.pump_until(lambda: scene._photo is not None))
                self.assertEqual(frames.call_count, 1)
                scene.set_connection_state("connected")
                self.assertTrue(self.pump_until(lambda: frames.call_count >= 2 and not scene._render_pending))
                scene.draw(ui.MIN_WIDTH + 100, ui.MIN_HEIGHT + 20)
                self.assertTrue(self.pump_until(lambda: frames.call_count >= 3 and not scene._render_pending))
                self.assertEqual(renderer.call_count, 1)

    def test_matrix_uses_live_android_renderer_and_freezes_when_animation_is_disabled(self):
        scene = self.scene(preferences=dict(nova_appearance.DEFAULT_PREFERENCES, texture="matrix"))
        with mock.patch.object(ui.nova_appearance, "render_matrix_background",
                               side_effect=lambda w, h, *_a: Image.new("RGB", (w, h))) as renderer, \
                mock.patch.object(scene, "_dive_layer", side_effect=AssertionError("Matrix must stay live")):
            scene._dive_frame((700, 500), scene.appearance, 0)
            scene._dive_frame((900, 600), scene.appearance, 65)
            scene._dive_frame((700, 500), dict(scene.appearance, immersion=False), 66)
        self.assertEqual([call.args[-1] for call in renderer.call_args_list], [0, 65, 0])
        self.assertTrue(all(call.args[-3] == (700, 500) for call in renderer.call_args_list))
        self.assertTrue(all(call.args[4] == scene.appearance["variant"] for call in renderer.call_args_list))
        with mock.patch.dict(ui.os.environ, NOVA_ANDROID_TEXTURES="0"), \
                mock.patch.object(scene, "_dive_layer", return_value=Image.new("RGB", (700, 500))) as legacy, \
                mock.patch.object(ui.nova_appearance, "render_matrix_background") as native:
            scene._dive_frame((700, 500), scene.appearance, 0)
            legacy.assert_called_once()
            native.assert_not_called()

    def test_submenu_arrows_text_and_cached_window_remain_readable(self):
        root = self.root
        options = dict(bg="#151024", fg="#ffffff", activebackground="#78d2a0",
                       activeforeground="#090817", selectcolor="#a9a0cf",
                       disabledforeground="#b8b0d0", font=("Segoe UI Semibold", 9))
        menu = ui.ThemedMenu(root, **options)
        self.addCleanup(menu.destroy)
        menu.add_command(label="Дополнительный VPN", state="disabled")
        sub = ui.ThemedMenu(menu, **options)
        called = []
        sub.add_command(label="Авто", command=lambda: called.append(True))
        menu.add_cascade(label="Proton", menu=sub)
        menu.tk_popup(100, 100)
        root.update()
        original = menu.top
        menu._select(1)
        root.update()
        self.assertEqual(menu.canvas.itemcget(menu._rows[1][3][-1], "fill"), options["activeforeground"])
        self.assertEqual(menu.canvas.itemcget(menu._rows[0][3][0], "fill"), options["disabledforeground"])
        sub._back()
        self.assertEqual(sub.top.state(), "withdrawn")
        menu._invoke(1)
        self.assertEqual(sub.top.state(), "normal")
        sub._invoke(0)
        self.assertEqual(called, [True])
        self.assertEqual(menu.top.state(), "withdrawn")
        menu.tk_popup(100, 100)
        self.assertIs(menu.top, original)

    def test_journal_icon_is_legible_separate_and_moves_with_its_button(self):
        source = Path(__file__).resolve().parents[1] / "nova.pyw"
        names = {"CanvasButton", "create_round_rect_img", "create_round_outline_img", "get_lighter_hex", "get_rgb"}
        nodes = [node for node in ast.walk(ast.parse(source.read_text(encoding="utf-8-sig")))
                 if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names]
        theme = nova_appearance.settings_theme("aurora")
        namespace = dict(root=self.root, tk=tk, time=time, UI_SCALE=1, SETTINGS_THEME=theme,
                         OUTLINE_ACCENT_COLOR=theme["accent"], _ROUND_RECT_IMG_CACHE=ui.ImageCache(),
                         _ROUND_OUTLINE_IMG_CACHE=ui.ImageCache())
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
        canvas = tk.Canvas(self.root)
        button = namespace["CanvasButton"](canvas, 100, 40, "Журнал", ("Segoe UI Semibold", 9),
                                            lambda: None, anchor="center", icon="✍")
        try:
            # show_log_window()/hide_log_window() reset this caption every time.
            button.config(text="Журнал")
            icon_box = canvas.bbox(button.icon_id)
            text_box = canvas.bbox(button.text_id)
            self.assertGreaterEqual(text_box[0] - icon_box[2], 5, "Writing icon overlaps the caption")
            self.assertIn("Segoe UI Emoji", canvas.itemcget(button.icon_id, "font"))
            previous = canvas.coords(button.icon_id)
            button.move_to(200, 70, "center")
            moved = canvas.coords(button.icon_id)
            self.assertEqual((moved[0] - previous[0], moved[1] - previous[1]), (100, 30))
            button.set_visible(False)
            self.assertEqual(canvas.itemcget(button.icon_id, "state"), "hidden")
        finally:
            canvas.destroy()
            namespace["_ROUND_RECT_IMG_CACHE"].clear()
            namespace["_ROUND_OUTLINE_IMG_CACHE"].clear()
