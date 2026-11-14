"""nova_gpu: pure helpers, the engine protocol against a fake child process, and the Tk wiring.

The fake engine is a tiny Python script that speaks the gpu-serve protocol (ready line, one stdout
line per frame, a named mapping with the 32-byte header), so the suite needs no GPU. One test runs the
real nova-engine.exe and skips when it or GL 3.3 is unavailable.
"""

import colorsys
import json
import os
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "resources"))

import nova_appearance
import nova_desktop_ui as ui
import nova_gpu

FAKE_ENGINE = '''
import json, mmap, os, struct, sys, time
mode = sys.argv[1] if len(sys.argv) > 1 else "ok"
log_path = os.environ.get("FAKE_LOG")

def say(obj):
    sys.stdout.write(json.dumps(obj) + chr(10))
    sys.stdout.flush()

if mode == "old":
    sys.exit(2)
if mode == "slow":
    time.sleep(30)
if mode == "notready":
    say({"ready": False, "error": "no GL 3.3"})
    sys.exit(3)
name = "NovaGpuFake-%d" % os.getpid()
size = 1440 * 1440 * 3 + 32
mm = mmap.mmap(-1, size, tagname=name)
say({"ready": True, "map": name, "size": size, "gl": "fake", "version": "3.3",
     "protocol": 1 if mode == "oldproto" else 2, "has_overlay": True})
w = h = seq = 0

def frame():
    global seq
    seq += 1
    px = bytes([seq % 250 + 1]) * (w * h * 3)
    mm[32:32 + len(px)] = px
    mm[8:20] = struct.pack("<III", w, h, w * 3)
    mm[0:8] = struct.pack("<Q", seq)
    say({"frame": seq, "ms": 0.5})

for line in sys.stdin:
    cmd = json.loads(line)
    record = dict(cmd)
    if cmd.get("cmd") == "overlay" and not cmd.get("clear"):
        with open(cmd["path"], "rb") as stream:
            record["bytes"] = len(stream.read())
    if log_path:
        with open(log_path, "a") as stream:
            stream.write(json.dumps(record) + chr(10))
    kind = cmd.get("cmd")
    if kind == "quit":
        if mode == "deaf":
            continue
        break
    if kind == "size":
        w, h = cmd["w"], cmd["h"]
        frame()
        if mode == "crash":
            os._exit(7)
    elif kind in ("config", "pointer", "pause", "overlay"):
        if w:
            frame()
'''


def fake_script(directory):
    path = Path(directory) / "fake_gpu_engine.py"
    path.write_text(FAKE_ENGINE, encoding="utf-8")
    return str(path)


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class HelperTests(unittest.TestCase):
    def test_scene_size_caps_the_long_side_and_keeps_a_floor(self):
        self.assertEqual(nova_gpu.scene_size(560, 420), (560, 420))
        self.assertEqual(nova_gpu.scene_size(2880, 1440), (1440, 720))
        self.assertEqual(nova_gpu.scene_size(10, 10), (64, 48))
        self.assertTrue(nova_gpu.frame_fits(1440, 900))
        self.assertFalse(nova_gpu.frame_fits(1920, 1080))

    def test_pointer_maps_to_lab_coordinates(self):
        self.assertEqual(nova_gpu.pointer_to_lab(280, 210, 560, 420), (0.0, 0.0))
        x, y = nova_gpu.pointer_to_lab(0, 0, 560, 420)
        self.assertAlmostEqual(x, -0.5 * 560 / 420)
        self.assertAlmostEqual(y, 0.5)
        x, y = nova_gpu.pointer_to_lab(560, 420, 560, 420)
        self.assertAlmostEqual(x, 0.5 * 560 / 420)
        self.assertAlmostEqual(y, -0.5)

    def test_accent_hue_index_round_trips_and_default_is_teal(self):
        for index in range(64):
            self.assertEqual(nova_gpu.nearest_accent_index("#%02X%02X%02X" % nova_gpu.accent_rgb(index)), index)
        red, green, blue = (c / 255 for c in nova_gpu.accent_rgb(31))
        hue = colorsys.rgb_to_hls(red, green, blue)[0] * 360
        self.assertAlmostEqual(hue, 31 / 64 * 360, delta=1.5)

    def test_accent_of_grey_or_garbage_falls_back_to_teal(self):
        for value in ("#808080", "#000000", "#FFFFFF", "oops", None, "#12"):
            self.assertEqual(nova_gpu.nearest_accent_index(value), nova_gpu.DEFAULT_ACCENT)

    def test_every_theme_accent_maps_to_a_valid_index(self):
        for theme in nova_appearance.THEMES.values():
            self.assertIn(nova_gpu.nearest_accent_index(theme["accent"]), range(64))

    def test_intensity_keeps_the_old_default_on_the_lab_default(self):
        self.assertAlmostEqual(nova_gpu.intensity_from_pref(0.30), 90)
        self.assertEqual(nova_gpu.intensity_from_pref(0), 0)
        self.assertEqual(nova_gpu.intensity_from_pref(0.6), 100)
        self.assertEqual(nova_gpu.intensity_from_pref(9), 100)
        self.assertEqual(nova_gpu.intensity_from_pref(float("nan")), 90)
        self.assertEqual(nova_gpu.intensity_from_pref("x"), 90)

    def test_fps_follows_the_monitor_capped_at_60_and_honours_the_30_limit(self):
        self.assertEqual(nova_gpu.target_fps({}, 144), 60)
        self.assertEqual(nova_gpu.target_fps({}, 50), 50)
        self.assertEqual(nova_gpu.target_fps({"limit_30fps": True}, 144), 30)
        self.assertEqual(nova_gpu.target_fps({"sync_monitor": False}, 50), 60)
        self.assertEqual(nova_gpu.target_fps(None, 75), 60)
        self.assertIn(nova_gpu.monitor_refresh_hz(), range(24, 501))

    def test_texture_table_covers_every_nova_texture(self):
        self.assertIsNone(nova_gpu.gpu_texture("none"))
        self.assertIsNone(nova_gpu.gpu_texture("no-such"))
        self.assertIsNone(nova_gpu.gpu_texture(None))
        self.assertEqual(nova_gpu.gpu_texture("crystals"), "cracks")
        self.assertEqual(nova_gpu.gpu_texture("splatter"), "rain")
        for key in nova_appearance.TEXTURES:
            if key == "custom":
                self.assertIsNone(nova_gpu.gpu_texture(key), "the owner's picture is a still CPU background")
            elif key != "none":
                self.assertIn(nova_gpu.gpu_texture(key), nova_gpu.TEXTURE_IDS, key)
        self.assertEqual(len(set(nova_gpu.TEXTURE_IDS)), 21)

    def test_a_new_picture_changes_the_seed(self):
        self.assertNotEqual(nova_gpu.seed_from_variant(1), nova_gpu.seed_from_variant(2))
        self.assertEqual(nova_gpu.seed_from_variant("bad"), 0.0)

    def test_config_from_prefs(self):
        prefs = dict(nova_appearance.DEFAULT_PREFERENCES, texture="fractal", variant=7)
        config = nova_gpu.config_from_prefs(prefs, "#50C878", 60)
        self.assertEqual(config["texture"], "fractal")
        self.assertEqual(config["seed"], 7.0)
        self.assertEqual((config["warp"], config["glow"], config["fps"], config["anim"]), (30, 100, 60, True))
        self.assertEqual(config["accent"], 27)
        self.assertEqual(nova_gpu.config_from_prefs(dict(prefs, accent_hue=7), "#50C878", 60)["accent"], 7)
        self.assertEqual((config["intensity"], config["speed"], config["sat"]), (80, 25, 100))
        legacy = {key: value for key, value in prefs.items() if key not in ("accent_hue", "brightness")}
        self.assertEqual(nova_gpu.config_from_prefs(legacy, "#50C878", 60)["accent"],
                         nova_gpu.nearest_accent_index("#50C878"))
        self.assertFalse(nova_gpu.config_from_prefs(dict(prefs, immersion=False), "#50C878", 60)["anim"])
        self.assertIsNone(nova_gpu.config_from_prefs(dict(prefs, texture="none"), "#50C878", 60))

    def test_ready_line_validation(self):
        good = json.dumps({"ready": True, "protocol": 2, "map": "NovaGpu-1", "size": 4096})
        self.assertEqual(nova_gpu.parse_ready(good)[0]["map"], "NovaGpu-1")
        for bad in ("garbage", "[]", json.dumps({"ready": False, "error": "no GL"}),
                    json.dumps({"ready": True, "protocol": 1, "map": "x", "size": 4096}),
                    json.dumps({"ready": True, "protocol": 2, "size": 4096}),
                    json.dumps({"ready": True, "protocol": 2, "map": "x", "size": 8})):
            info, reason = nova_gpu.parse_ready(bad)
            self.assertIsNone(info, bad)
            self.assertTrue(reason)


def make_buffer(seq, width, height, value, capacity=4096):
    import struct
    buf = bytearray(capacity)
    struct.pack_into("<QIII", buf, 0, seq, width, height, width * 3)
    buf[32:32 + width * height * 3] = bytes([value]) * (width * height * 3)
    return buf


class ShaderSeedTests(unittest.TestCase):
    def test_the_seed_offset_stays_small_because_float_precision_ruins_big_ones(self):
        """Variant 428 gave an offset of 7400: water turned into fine moire, ether into broken dark blobs."""
        import re
        head = (ROOT / "gpu" / "shaders" / "head.glsl").read_text(encoding="utf-8")
        line = next(row for row in head.splitlines() if row.startswith("#define S "))
        self.assertIn("mod(", line)
        limits = [float(value) for value in re.findall(r"mod\(uSeed\*[\d.]+,([\d.]+)\)", line)]
        self.assertEqual(len(limits), 2)
        self.assertTrue(all(limit <= 128 for limit in limits), line)


class ReadFrameTests(unittest.TestCase):
    def test_reads_a_published_frame(self):
        seq, width, height, data = nova_gpu.read_frame(make_buffer(5, 4, 3, 9))
        self.assertEqual((seq, width, height, len(data)), (5, 4, 3, 36))
        self.assertEqual(set(data), {9})

    def test_nothing_published_or_a_broken_header_gives_none(self):
        self.assertIsNone(nova_gpu.read_frame(make_buffer(0, 4, 3, 9)))
        self.assertIsNone(nova_gpu.read_frame(make_buffer(1, 0, 3, 9)))
        broken = make_buffer(1, 4, 3, 9)
        broken[16:20] = (7).to_bytes(4, "little")
        self.assertIsNone(nova_gpu.read_frame(broken))
        self.assertIsNone(nova_gpu.read_frame(make_buffer(1, 40, 30, 9, capacity=5000)[:64]))

    def test_a_frame_published_during_the_copy_is_read_again(self):
        import struct
        buf = make_buffer(1, 4, 3, 1)

        def writer_publishes():
            buf[32:32 + 36] = bytes([2]) * 36
            struct.pack_into("<Q", buf, 0, 2)

        seq, _w, _h, data = nova_gpu.read_frame(buf, _after_copy=writer_publishes)
        self.assertEqual(seq, 2)
        self.assertEqual(set(data), {2}, "a copy mixing two frames was accepted")

    def test_gives_up_instead_of_returning_a_torn_copy(self):
        import struct
        buf = make_buffer(1, 4, 3, 1)

        def writer_publishes():
            struct.pack_into("<Q", buf, 0, 2)

        self.assertIsNone(nova_gpu.read_frame(buf, retries=1, _after_copy=writer_publishes))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nova-gpu-test-")
        self.addCleanup(self.temporary.cleanup)
        self.script = fake_script(self.temporary.name)
        self.log = os.path.join(self.temporary.name, "commands.jsonl")
        patcher = mock.patch.dict(os.environ, FAKE_LOG=self.log)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.engines = []
        self.addCleanup(lambda: [engine.stop(wait=1.0) for engine in self.engines])

    def engine(self, mode="ok", **kwargs):
        kwargs.setdefault("temp_dir", os.path.join(self.temporary.name, "temp"))
        engine = nova_gpu.GpuEngine(argv=[sys.executable, self.script, mode], **kwargs)
        self.engines.append(engine)
        return engine

    def commands(self):
        try:
            with open(self.log, encoding="utf-8") as stream:
                return [json.loads(line) for line in stream if line.strip()]
        except FileNotFoundError:
            return []

    def test_handshake_frames_and_commands(self):
        engine = self.engine()
        self.assertTrue(engine.start())
        self.assertTrue(engine.ready)
        engine.configure(texture="fractal", seed=3, accent=31, intensity=90, glow=100, warp=50, fps=60, anim=True)
        engine.resize(560, 420)
        self.assertTrue(wait_for(lambda: engine.pending_seq >= 1))
        engine.set_pointer(0.1, -0.2, True)
        engine.set_paused(True)
        self.assertTrue(wait_for(lambda: len(self.commands()) >= 4))
        kinds = [c["cmd"] for c in self.commands()]
        self.assertEqual(kinds[:4], ["config", "size", "pointer", "pause"])
        self.assertEqual(self.commands()[0]["texture"], "fractal")
        self.assertEqual(self.commands()[2]["in"], True)
        self.assertTrue(wait_for(lambda: engine.latest_frame() is not None))
        seq, width, height, data = engine.latest_frame()
        self.assertEqual((width, height, len(data)), (560, 420, 560 * 420 * 3))
        self.assertEqual(len(set(data)), 1, "frame pixels are torn")
        self.assertGreaterEqual(engine.frames, 1)
        self.assertEqual(engine.last_gpu_ms, 0.5)

    def test_frame_callback_runs_on_the_reader_thread_only_with_a_seq(self):
        seen = []
        engine = self.engine(on_frame=lambda seq: seen.append((seq, threading.current_thread().name)))
        self.assertTrue(engine.start())
        engine.resize(100, 80)
        self.assertTrue(wait_for(lambda: seen))
        self.assertEqual(seen[0][0], 1)
        self.assertEqual(seen[0][1], "NovaGpuRead")

    def test_overlay_goes_through_a_temp_file_that_is_removed_after_a_later_frame(self):
        engine = self.engine()
        self.assertTrue(engine.start())
        engine.resize(8, 6)
        self.assertTrue(wait_for(lambda: engine.pending_seq >= 1))
        self.assertTrue(engine.set_overlay(bytes([7]) * (8 * 6 * 4), 8, 6))
        files = [n for n in os.listdir(engine.temp_dir) if n.startswith(nova_gpu.OVERLAY_PREFIX)]
        self.assertEqual(len(files), 1)
        self.assertTrue(wait_for(lambda: any(c.get("bytes") == 192 for c in self.commands())))
        time.sleep(1.1)
        engine.set_pointer(0, 0, True)  # one more frame, after the file is old enough
        self.assertTrue(wait_for(lambda: not os.listdir(engine.temp_dir)))
        with self.assertRaises(ValueError):
            engine.set_overlay(b"short", 8, 6)

    def test_stop_removes_pending_overlay_files_and_ends_the_child(self):
        engine = self.engine()
        self.assertTrue(engine.start())
        engine.set_paused(True)
        engine.set_overlay(bytes(16), 2, 2)
        engine.stop(wait=1.0)
        self.assertEqual(os.listdir(engine.temp_dir), [])
        self.assertIsNotNone(engine._proc.poll())
        self.assertEqual(engine.state, "stopped")
        self.assertFalse(engine.resize(1, 1))

    def test_a_deaf_engine_still_ends_when_stdin_closes(self):
        engine = self.engine("deaf")
        self.assertTrue(engine.start())
        engine.stop(wait=3.0)
        self.assertIsNotNone(engine._proc.poll())

    def test_stale_overlay_files_of_a_dead_run_are_swept_on_start(self):
        temp = os.path.join(self.temporary.name, "temp")
        os.makedirs(temp)
        old = os.path.join(temp, nova_gpu.OVERLAY_PREFIX + "999_1" + nova_gpu.OVERLAY_SUFFIX)
        fresh = os.path.join(temp, nova_gpu.OVERLAY_PREFIX + "998_1" + nova_gpu.OVERLAY_SUFFIX)
        for path in (old, fresh):
            Path(path).write_bytes(b"x")
        os.utime(old, (time.time() - 3600, time.time() - 3600))
        self.assertTrue(self.engine().start())
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(fresh), "a recent file may belong to another running Nova")

    def test_missing_exe_falls_back_with_a_reason(self):
        engine = nova_gpu.GpuEngine(exe=os.path.join(self.temporary.name, "absent.exe"))
        with self.assertLogs(nova_gpu._log, "WARNING") as logs:
            self.assertFalse(engine.start())
        self.assertTrue(engine.failed)
        self.assertIn("не найден", engine.reason)
        self.assertIn("GPU", logs.output[0])
        self.assertFalse(engine.configure(texture="fractal"))
        self.assertIsNone(engine.latest_frame())

    def test_refusal_old_protocol_early_exit_and_silence_all_fail_cleanly(self):
        for mode, fragment in (("notready", "no GL"), ("oldproto", "протокол"), ("old", "до готовности")):
            engine = self.engine(mode)
            with self.assertLogs(nova_gpu._log, "WARNING"):
                self.assertFalse(engine.start(), mode)
            self.assertTrue(engine.failed, mode)
            self.assertIn(fragment, engine.reason, mode)
        engine = self.engine("slow", start_timeout=0.4)
        with self.assertLogs(nova_gpu._log, "WARNING"):
            self.assertFalse(engine.start())
        self.assertTrue(wait_for(lambda: engine._proc.poll() is not None), "a silent engine must be killed")

    def test_a_crash_after_ready_fails_once(self):
        engine = self.engine("crash")
        self.assertTrue(engine.start())
        with self.assertLogs(nova_gpu._log, "WARNING") as logs:
            engine.resize(32, 32)
            self.assertTrue(wait_for(lambda: engine.failed))
            engine.set_paused(False)
            time.sleep(0.1)
        self.assertEqual(len([line for line in logs.output if "завершился" in line]), 1)
        self.assertFalse(engine.set_paused(True))

    def test_start_async_does_not_block(self):
        engine = self.engine("slow", start_timeout=0.4)
        began = time.monotonic()
        with self.assertLogs(nova_gpu._log, "WARNING"):
            engine.start_async()
            self.assertLess(time.monotonic() - began, 0.2)
            self.assertTrue(wait_for(lambda: engine.failed, 3))


class RealEngineTests(unittest.TestCase):
    def test_real_engine_renders_a_frame(self):
        candidates = [os.environ.get("NOVA_GPU_ENGINE"), str(ROOT / "nova-rs" / "target" / "release" / "nova-engine.exe"),
                      str(ROOT / "bin" / "nova-engine.exe")]
        engine = None
        for exe in candidates:
            if exe and os.path.isfile(exe):
                with tempfile.TemporaryDirectory() as temp:
                    candidate = nova_gpu.GpuEngine(exe=exe, temp_dir=temp)
                    with mock.patch.object(nova_gpu._log, "warning"):
                        started = candidate.start()
                    if started:
                        engine = candidate
                        break
                    candidate.stop(wait=0.5)
        if engine is None:
            self.skipTest("no nova-engine.exe with gpu-serve and GL 3.3 here")
        self.addCleanup(engine.stop)
        engine.configure(texture="fractal", seed=1, accent=31, intensity=90, glow=100, warp=50, fps=60, anim=True)
        engine.resize(320, 240)
        self.assertTrue(wait_for(lambda: engine.latest_frame() is not None, 8))
        self.assertTrue(wait_for(lambda: engine.frames >= 5, 5))
        seq, width, height, data = engine.latest_frame()
        self.assertEqual((width, height, len(data)), (320, 240, 320 * 240 * 3))
        self.assertGreater(len(set(data[::97])), 8, "the frame looks blank")
        self.assertTrue(engine.set_overlay(bytes([0, 0, 0, 255]) * (320 * 240), 320, 240))
        self.assertTrue(wait_for(lambda: engine.latest_frame() is not None and engine.latest_frame()[0] > seq))
        self.assertEqual(engine.last_error, "")


class SceneWiringTests(unittest.TestCase):
    """DesktopScene on a real Tk canvas with the fake engine."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
        except tk.TclError as error:
            raise unittest.SkipTest("Tk cannot create a window: %s" % error)
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nova-gpu-scene-")
        self.addCleanup(self.temporary.cleanup)
        self.script = fake_script(self.temporary.name)
        self.log = os.path.join(self.temporary.name, "commands.jsonl")
        env = mock.patch.dict(os.environ, FAKE_LOG=self.log)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("NOVA_GPU", None)
        labels = mock.patch.object(ui.DesktopScene, "_draw_labels", autospec=True)
        labels.start()
        self.addCleanup(labels.stop)
        self.scenes = []
        self.root.deiconify()

    def tearDown(self):
        for scene in self.scenes:
            if scene.canvas.winfo_exists():
                scene.canvas.destroy()
        self.root.update()
        self.root.withdraw()

    def scene(self, mode="ok", **prefs):
        engine = nova_gpu.GpuEngine(argv=[sys.executable, self.script, mode],
                                    temp_dir=os.path.join(self.temporary.name, "temp"))
        canvas = tk.Canvas(self.root, width=560, height=420)
        canvas.pack()
        self.root.update()
        values = dict(nova_appearance.DEFAULT_PREFERENCES, texture="fractal")
        values.update(prefs)
        scene = ui.DesktopScene(canvas, values, "test", preferences_path=Path(self.temporary.name) / "appearance.json",
                                gpu=engine)
        self.scenes.append(scene)
        scene.draw(560, 420)
        return scene, engine

    def pump(self, predicate, timeout=6):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.root.update()
            if predicate():
                return True
            time.sleep(0.005)
        return False

    def commands(self):
        try:
            with open(self.log, encoding="utf-8") as stream:
                return [json.loads(line) for line in stream if line.strip()]
        except FileNotFoundError:
            return []

    def test_gpu_frames_reach_the_canvas_with_overlay_size_and_config(self):
        scene, engine = self.scene()
        self.assertTrue(self.pump(lambda: scene._gpu_mode and scene._gpu_photo is not None))
        self.assertEqual((scene._gpu_photo.width(), scene._gpu_photo.height()), (560, 420))
        self.assertEqual(scene.canvas.itemcget(scene._background, "image"), str(scene._gpu_photo))
        self.assertTrue(self.pump(lambda: any(c["cmd"] == "overlay" for c in self.commands())))
        by_kind = {}
        for command in self.commands():
            by_kind.setdefault(command["cmd"], command)
        self.assertEqual((by_kind["size"]["w"], by_kind["size"]["h"]), (560, 420))
        self.assertEqual(by_kind["overlay"]["bytes"], 560 * 420 * 4)
        self.assertEqual(by_kind["config"]["texture"], "fractal")
        self.assertEqual(by_kind["config"]["warp"], 30)
        # the CPU worker produces no picture while the GPU owns the background
        self.assertTrue(self.pump(lambda: not scene._render_pending))

    def test_panel_overlay_is_sent_once_per_size_and_theme_not_per_frame(self):
        scene, engine = self.scene()
        self.assertTrue(self.pump(lambda: sum(c["cmd"] == "overlay" for c in self.commands()) >= 1))
        self.pump(lambda: False, 0.4)
        before = sum(c["cmd"] == "overlay" for c in self.commands())
        scene.draw(560, 420)
        self.pump(lambda: False, 0.4)
        self.assertEqual(sum(c["cmd"] == "overlay" for c in self.commands()), before)
        scene.draw(600, 440)
        self.assertTrue(self.pump(lambda: sum(c["cmd"] == "overlay" for c in self.commands()) == before + 1))
        sizes = [(c["w"], c["h"]) for c in self.commands() if c["cmd"] == "size"]
        self.assertEqual(sizes[-1], (600, 440))

    def test_connecting_rebuilds_waves_then_restores_the_plain_overlay(self):
        scene, engine = self.scene()
        self.assertTrue(self.pump(lambda: scene._gpu_mode and scene._gpu_sent is not None))
        count = lambda: sum(c["cmd"] == "overlay" for c in self.commands())
        base = count()
        scene.set_connection_state("connecting")
        self.assertTrue(self.pump(lambda: count() >= base + 4, 4), "waves are not streamed to the engine")
        began, seen = time.monotonic(), count()
        self.pump(lambda: False, 1.0)
        rate = (count() - seen) / (time.monotonic() - began)
        self.assertLessEqual(rate, 21, "waves must not exceed 20 Hz")
        scene.set_connection_state("connected")
        self.pump(lambda: False, 0.5)
        settled = count()
        self.pump(lambda: False, 0.5)
        self.assertEqual(count(), settled, "overlay keeps streaming after connecting ended")
        self.assertEqual(scene._gpu_sent[-1], "plain")

    def test_pointer_is_sent_in_lab_coordinates_and_throttled(self):
        scene, engine = self.scene()
        self.assertTrue(self.pump(lambda: scene._gpu_mode))
        scene.canvas.event_generate("<Motion>", x=280, y=210)
        self.assertTrue(self.pump(lambda: any(c["cmd"] == "pointer" for c in self.commands())))
        first = [c for c in self.commands() if c["cmd"] == "pointer"][0]
        self.assertAlmostEqual(first["x"], 0, places=3)
        self.assertAlmostEqual(first["y"], 0, places=3)
        for index in range(60):
            scene.canvas.event_generate("<Motion>", x=index, y=10)
        self.pump(lambda: False, 0.5)
        pointers = [c for c in self.commands() if c["cmd"] == "pointer"]
        self.assertLess(len(pointers), 30, "pointer events are not throttled")
        self.assertAlmostEqual(pointers[-1]["x"], nova_gpu.pointer_to_lab(59, 10, 560, 420)[0], places=3)
        scene.canvas.event_generate("<Leave>", x=5, y=5)
        self.assertTrue(self.pump(lambda: [c for c in self.commands() if c["cmd"] == "pointer"][-1]["in"] is False))

    def test_engine_is_paused_when_the_window_is_hidden_and_resumed(self):
        scene, engine = self.scene()
        self.assertTrue(self.pump(lambda: scene._gpu_mode and scene._gpu_paused is False))
        self.root.withdraw()
        self.root.update()
        self.assertTrue(self.pump(lambda: any(c["cmd"] == "pause" and c["on"] for c in self.commands())))
        self.root.deiconify()
        self.root.update()
        self.assertTrue(self.pump(lambda: [c for c in self.commands() if c["cmd"] == "pause"][-1]["on"] is False))

    def test_texture_none_returns_to_the_cpu_path_and_back(self):
        scene, engine = self.scene()
        self.assertTrue(self.pump(lambda: scene._gpu_mode))
        scene.set_appearance(dict(scene.appearance, texture="none"))
        self.assertFalse(scene._gpu_mode)
        self.assertTrue(self.pump(lambda: scene._photo is not None), "the CPU path painted nothing")
        scene.set_appearance(dict(scene.appearance, texture="marble"))
        self.assertTrue(self.pump(lambda: scene._gpu_mode))
        self.assertTrue(self.pump(lambda: [c for c in self.commands() if c["cmd"] == "config"][-1]["texture"] == "marble"))

    def test_new_picture_changes_the_seed_sent_to_the_engine(self):
        scene, engine = self.scene()
        self.assertTrue(self.pump(lambda: scene._gpu_mode))
        scene.set_appearance(dict(scene.appearance, variant=scene.appearance["variant"] + 1))
        self.assertTrue(self.pump(lambda: len([c for c in self.commands() if c["cmd"] == "config"]) >= 2))
        seeds = [c["seed"] for c in self.commands() if c["cmd"] == "config"]
        self.assertNotEqual(seeds[0], seeds[-1])

    def test_engine_crash_falls_back_silently_to_the_cpu_path(self):
        scene, engine = self.scene("crash")
        with self.assertLogs(nova_gpu._log, "WARNING"):
            self.assertTrue(self.pump(lambda: scene._gpu is None and not scene._gpu_mode))
        self.assertTrue(self.pump(lambda: scene._photo is not None), "CPU frames did not resume after the crash")

    def test_unusable_engine_keeps_the_old_path(self):
        scene, engine = self.scene("old")
        with self.assertLogs(nova_gpu._log, "WARNING"):
            self.assertTrue(self.pump(lambda: scene._gpu is None))
        self.assertTrue(self.pump(lambda: scene._photo is not None))
        self.assertFalse(scene._gpu_mode)

    def test_destroy_stops_the_engine_and_cancels_the_pump(self):
        scene, engine = self.scene()
        self.assertTrue(self.pump(lambda: scene._gpu_mode))
        pending = scene._gpu_poll_id
        scene.canvas.destroy()
        if pending is not None:
            self.assertNotIn(pending, self.root.tk.call("after", "info"))
        self.assertTrue(wait_for(lambda: engine._proc.poll() is not None, 4), "the engine outlived its canvas")
        self.root.update()

    def test_surface_beyond_the_scene_cap_stays_on_the_cpu_path(self):
        scene, engine = self.scene()
        self.assertTrue(self.pump(lambda: scene._gpu_mode))
        scene.draw(1800, 900)
        self.assertTrue(self.pump(lambda: not scene._gpu_mode))

    def test_env_switch_disables_the_gpu_path(self):
        with mock.patch.dict(os.environ, NOVA_GPU="0"):
            scene, engine = self.scene()
            self.assertIsNone(scene._gpu)
            self.assertEqual(engine.state, "new")


if __name__ == "__main__":
    unittest.main()
