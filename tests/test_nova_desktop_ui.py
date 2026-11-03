"""Concurrency and lifecycle coverage for the desktop appearance renderer."""

import threading
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

    def scene(self, on_error=None):
        canvas = _GuardedCanvas(self.root, self.owner, self.violations)
        scene = ui.DesktopScene(canvas, nova_appearance.DEFAULT_PREFERENCES, "test",
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
