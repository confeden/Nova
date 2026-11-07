import os
import subprocess
import sys
import threading
import time

import pytest

from nova_foreign_services import kill_images_in_dir
from nova_shutdown import run_cleanup
import nova_shutdown
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


def _restart_harness(monkeypatch, restore_error=False, launch_error=False):
    owner = threading.get_ident()
    events, scheduled, logs = [], [], []
    def ui(name):
        def action(*args, **kw):
            assert threading.get_ident() == owner, name
            events.append(name)
        return action
    root = SimpleNamespace(geometry=lambda: '700x450+20+30', withdraw=ui('hide'), destroy=ui('destroy'),
                           deiconify=ui('show'), after=lambda delay, action: scheduled.append(action))
    def cleanup(name):
        time.sleep(.12)
        events.append(name)
        if name == 'proxy' and restore_error:
            raise OSError('fixture restore failure')
    def sweep(*args, **kw):
        events.append('sweep')
    def launch(command, cwd):
        assert events[-1] == 'sweep'
        if launch_error:
            raise OSError('fixture launch failure')
        events.append('launch')
    monkeypatch.setattr(nova_shutdown, 'launch_restart', launch)
    namespace = dict(root=root, log_window=None, is_closing=False, process=None, is_service_active=True,
                     SERVICES_RUNNING=True, SERVICE_RUN_ID=7, nova_service_status='Running',
                     restart_nova=SimpleNamespace(), save_window_state=Mock(), dns_manager=None,
                     save_visited_domains=Mock(), save_ip_history=Mock(), save_exclude_auto_checked=Mock(),
                     APPEARANCE={'random_texture_on_start': True},
                     main_scene=SimpleNamespace(flush_preferences=lambda prefs: events.append('appearance')),
                     flush_learning_data=Mock(), check_queue=__import__('queue').Queue(),
                     NOVA_WARP_SERVICE='NovaWARP', get_bin_dir=lambda: 'fixture-bin',
                     get_base_dir=lambda: 'fixture-root', service_points_into=lambda *a: False,
                     kill_images_in_dir=sweep, cleanup_tray=lambda: cleanup('tray'),
                     remove_nrpt_dns_unblock_on_exit=lambda **kw: cleanup('dns'),
                     pac_manager=SimpleNamespace(restore_system_proxy=lambda: cleanup('proxy')),
                     delete_windivert_if_nova=lambda *a: events.append('driver-delete'),
                     log_print=logs.append, nova_shutdown=nova_shutdown, threading=threading, time=time,
                     sys=SimpleNamespace(argv=['nova.pyw', '--dev-log'], executable=sys.executable),
                     os=SimpleNamespace(getpid=os.getpid, _exit=lambda code: events.append('exit')),
                     _has_debug_cli_flag=lambda: True, SESSION_CONSOLE_LOG=SimpleNamespace(close=Mock()),
                     btn_toggle=SimpleNamespace(config=ui('stopped-button')),
                     status_label=SimpleNamespace(config=ui('stopped-status')), COLOR_TEXT_FAIL='red',
                     tk=SimpleNamespace(NORMAL='normal'), messagebox=SimpleNamespace(showerror=ui('error')),
                     app_mutex=1,
                     ctypes=SimpleNamespace(windll=SimpleNamespace(kernel32=SimpleNamespace(
                         CreateMutexW=lambda *a: 1, CloseHandle=lambda handle: True))))
    tree = ast.parse((Path(__file__).resolve().parents[1] / 'nova.pyw').read_text(encoding='utf-8-sig'))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'on_closing')
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<nova shutdown>', 'exec'), namespace)
    started = time.monotonic()
    namespace['on_closing'](restart=True)
    while 'exit' not in events and 'error' not in events and time.monotonic() - started < 2:
        if scheduled:
            scheduled.pop(0)()
        else:
            time.sleep(.005)
    return namespace, events, logs, time.monotonic() - started


def test_restart_parallelizes_cleanup_and_sweeps_before_launch(monkeypatch):
    namespace, events, logs, elapsed = _restart_harness(monkeypatch)
    assert elapsed < .8
    assert events.count('sweep') == 2 and events.index('launch') > events.index('proxy')
    assert events.index('appearance') < events.index('launch')
    assert events[-1] == 'exit' and 'driver-delete' not in events
    assert namespace['is_closing'] and not namespace['SERVICES_RUNNING']
    assert namespace['SERVICE_RUN_ID'] == 8
    assert any('[Restart]' in message for message in logs)
    print(f'bounded restart fixture: {elapsed:.3f}s')


def test_restart_does_not_launch_after_required_restore_failure(monkeypatch):
    namespace, events, logs, _ = _restart_harness(monkeypatch, restore_error=True)
    assert 'launch' not in events and 'exit' not in events
    assert events[-1] == 'error' and not namespace['is_closing']
    assert any('fixture restore failure' in message for message in logs)


def test_failed_spawn_restores_mutex_and_visible_stopped_ui(monkeypatch):
    namespace, events, logs, _ = _restart_harness(monkeypatch, launch_error=True)
    assert 'exit' not in events and 'show' in events and events[-1] == 'error'
    assert namespace['app_mutex'] == 1 and not namespace['is_closing']
    assert any('fixture launch failure' in message for message in logs)


def test_restart_command_preserves_script_exe_and_log_modes():
    args = ['nova.pyw', '--dev-log']
    command = nova_shutdown.restart_command(args, sys.executable, debug=True, show_log=True)
    assert command[:2] == [os.path.abspath(sys.executable), os.path.abspath(args[0])]
    assert command[2:] == ['--show-log', '--restart', '--force-instance', '--debug', '--dev-log']
    assert nova_shutdown.restart_command(['Nova.exe'], 'unpacked/python.exe', compiled=True)[0] == os.path.abspath('Nova.exe')


@pytest.mark.skipif(os.name != 'nt', reason='Windows process handoff')
def test_replacement_survives_immediate_parent_exit(tmp_path):
    witness = tmp_path / 'replacement.txt'
    child = 'import time,pathlib;time.sleep(.15);pathlib.Path(' + repr(str(witness)) + ').write_text("ready")'
    parent = ('import nova_shutdown,sys; nova_shutdown.launch_restart([sys.executable,"-c",' + repr(child)
              + '], ' + repr(str(tmp_path)) + ')')
    process = subprocess.Popen([sys.executable, '-c', parent], creationflags=subprocess.CREATE_NO_WINDOW,
                               env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'resources')))
    assert process.wait(timeout=3) == 0
    deadline = time.monotonic() + 3
    while not witness.exists() and time.monotonic() < deadline:
        time.sleep(.02)
    assert witness.read_text() == 'ready'


def test_cleanup_shares_one_deadline_and_reports_failures():
    release = threading.Event()
    arrived = []
    logs = []

    def hanging():
        arrived.append(True)
        release.wait(3)

    def failed():
        raise OSError("test failure")

    try:
        started = time.monotonic()
        pending = run_cleanup({"a": hanging, "b": hanging, "error": failed}, .15, logs.append)
        assert time.monotonic() - started < .8
        assert pending == {"a", "b"}
        assert len(arrived) == 2
        assert any("test failure" in log for log in logs)
        assert any("a, b" in log for log in logs)
    finally:
        release.set()


def test_system_restore_can_finish_after_optional_cleanup_deadline():
    release = threading.Event()
    restored = threading.Event()
    logs = []

    def restore():
        time.sleep(.12)
        restored.set()

    try:
        pending = run_cleanup({"cache": lambda: release.wait(3), "proxy": restore},
                              .03, logs.append, required={"proxy"}, required_timeout=.6)
        assert restored.is_set()
        assert pending == {"cache"}
    finally:
        release.set()


@pytest.mark.skipif(os.name != "nt", reason="Windows native process ownership")
def test_native_cleanup_kills_descendants_but_leaves_root_and_same_image_sibling():
    child_code = "import time; time.sleep(60)"
    parent_code = ("import subprocess,sys,time; "
                   f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}],creationflags=subprocess.CREATE_NO_WINDOW); "
                   "print(p.pid,flush=True); print(p.wait(),flush=True); time.sleep(60)")
    flags = subprocess.CREATE_NO_WINDOW
    sibling = subprocess.Popen([sys.executable, "-c", child_code], creationflags=flags)
    parent = subprocess.Popen([sys.executable, "-c", parent_code], stdout=subprocess.PIPE,
                              text=True, creationflags=flags)
    try:
        assert int(parent.stdout.readline()) > 0
        started = time.monotonic()
        # Windows may also create headless conhost.exe descendants for either interpreter.
        assert kill_images_in_dir((), "", root_pid=parent.pid) >= 1
        assert parent.stdout.readline().strip() == "1"
        assert time.monotonic() - started < 1
        assert sibling.poll() is None
        assert parent.poll() is None
    finally:
        kill_images_in_dir((), "", root_pid=parent.pid)
        for proc in (parent, sibling):
            proc.kill()
            proc.wait(timeout=3)
