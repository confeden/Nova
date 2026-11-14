import ast
import contextlib
import os
import re
import sys
import types
import subprocess
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


NOVA_PATH = Path(__file__).resolve().parents[1] / "nova.pyw"


def _load_functions(*names):
    tree = ast.parse(NOVA_PATH.read_text(encoding="utf-8"), filename=str(NOVA_PATH))
    selected = [
        child for node in tree.body
        if isinstance(node, ast.Try)
        for child in node.body
        if isinstance(child, ast.FunctionDef) and child.name in names
    ]
    namespace = {
        "contextlib": contextlib,
        "os": os,
        "subprocess": subprocess,
        "threading": threading,
        "time": time,
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(NOVA_PATH), "exec"), namespace)
    return namespace


class WinDivertRecoveryTests(unittest.TestCase):
    def test_a_live_shared_device_is_healthy_despite_normal_delete_service_lifetime(self):
        ns = _load_functions("_query_windivert_service_state")
        ns.update(re=re, _run_hidden_sc=lambda *args: (1072, "1072 marked for deletion", ""),
                  _is_windivert_pending_delete_text=lambda text: "1072" in text,
                  _is_sc_service_missing_text=lambda text: "1060" in text,
                  _is_windivert_disabled_text=lambda text: False,
                  _probe_windivert_minimal_open_error=lambda: 0)
        registry = types.SimpleNamespace(HKEY_LOCAL_MACHINE=0, KEY_READ=0,
                                         OpenKey=mock.Mock(side_effect=FileNotFoundError))
        with mock.patch.dict(sys.modules, winreg=registry):
            state = ns["_query_windivert_service_state"]()
            self.assertTrue(state["registration_pending_delete"])
            self.assertTrue(state["running"])
            self.assertFalse(state["pending_delete"])
            ns["_probe_windivert_minimal_open_error"] = lambda: 2
            state = ns["_query_windivert_service_state"]()
            self.assertTrue(state["pending_delete"])
            self.assertFalse(state["running"])

    def test_live_device_marked_for_delete_is_not_reported_disabled(self):
        # Field report 1.45.1: RUNNING, Start=4, DeleteFlag=1 blocked NovaDivert Redirect.
        ns = _load_functions("_query_windivert_service_state")
        ns.update(re=re, _run_hidden_sc=lambda *args: (0, "STATE : 4 RUNNING", ""),
                  _is_windivert_pending_delete_text=lambda text: False,
                  _is_sc_service_missing_text=lambda text: False,
                  _is_windivert_disabled_text=lambda text: False,
                  _probe_windivert_service_access=lambda: {
                      "pending_delete": False, "missing": False, "access_denied": False},
                  _probe_windivert_minimal_open_error=lambda: 0)
        values = {"Start": 4, "DeleteFlag": 1}
        registry = types.SimpleNamespace(
            HKEY_LOCAL_MACHINE=0, KEY_READ=0,
            OpenKey=mock.Mock(return_value=object()), CloseKey=mock.Mock(),
            QueryValueEx=lambda key, name: (values[name], 4))
        with mock.patch.dict(sys.modules, winreg=registry):
            state = ns["_query_windivert_service_state"]()
            self.assertFalse(state["disabled"])
            self.assertFalse(state["pending_delete"])
            self.assertTrue(state["running"])
            self.assertTrue(state["registration_disabled"])
            ns["_probe_windivert_minimal_open_error"] = lambda: 2
            state = ns["_query_windivert_service_state"]()
            self.assertTrue(state["disabled"])
            self.assertTrue(state["pending_delete"])

    def test_running_driver_with_disabled_start_but_no_delete_flag_is_usable(self):
        # Field report 1.46: RUNNING + Start=4 without DeleteFlag made Auto skip observer and redirect.
        ns = _load_functions("_query_windivert_service_state")
        ns.update(re=re, _run_hidden_sc=lambda *args: (0, "STATE : 4 RUNNING", ""),
                  _is_windivert_pending_delete_text=lambda text: False,
                  _is_sc_service_missing_text=lambda text: False,
                  _is_windivert_disabled_text=lambda text: False,
                  _probe_windivert_service_access=lambda: {
                      "pending_delete": False, "missing": False, "access_denied": False},
                  _probe_windivert_minimal_open_error=lambda: 0)
        values = {"Start": 4}

        def query(key, name):
            if name not in values:
                raise OSError(name)
            return values[name], 4

        registry = types.SimpleNamespace(
            HKEY_LOCAL_MACHINE=0, KEY_READ=0,
            OpenKey=mock.Mock(return_value=object()), CloseKey=mock.Mock(), QueryValueEx=query)
        with mock.patch.dict(sys.modules, winreg=registry):
            state = ns["_query_windivert_service_state"]()
            self.assertFalse(state["disabled"])
            self.assertTrue(state["registration_disabled"])
            self.assertTrue(state["running"])
            ns["_probe_windivert_minimal_open_error"] = lambda: 2
            state = ns["_query_windivert_service_state"]()
            self.assertTrue(state["disabled"])
            ns["_probe_windivert_minimal_open_error"] = lambda: 0
            ns["_run_hidden_sc"] = lambda *args: (0, "STATE : 1 STOPPED", "")
            state = ns["_query_windivert_service_state"]()
            self.assertTrue(state["disabled"])

    def test_invalid_name_detector_is_narrow(self):
        ns = _load_functions("_is_windivert_invalid_name_open_failure")
        detect = ns["_is_windivert_invalid_name_open_failure"]

        self.assertTrue(detect(123, "windivert: error opening filter: invalid name"))
        self.assertTrue(detect("123", "ERROR OPENING FILTER: invalid name"))
        self.assertFalse(detect(123, "invalid hostlist path"))
        self.assertFalse(detect(34, "error opening filter"))
        self.assertFalse(detect(None, "error opening filter"))

    def test_registration_reset_is_bounded_to_one_attempt(self):
        ns = _load_functions("_reset_windivert_registration_once")
        calls = []
        states = iter([
            {"stopped": True},
            {"missing": False, "exists": True, "registry_exists": True, "pending_delete": True},
            {"missing": False, "exists": True, "registry_exists": True, "pending_delete": True},
            {"missing": True, "exists": False, "registry_exists": False},
            {"missing": False, "exists": True, "pending_delete": False, "disabled": False},
        ])

        ns.update({
            "_repair_lock": threading.Lock(),
            "_repair_in_progress": False,
            "_windivert_broken": False,
            "_windivert_unrecoverable_reason": "",
            "_windivert_unrecoverable_detail": "",
            "_windivert_last_repair_success_ts": 0.0,
            "_windivert_registration_reset_attempted": False,
            "get_bin_dir": lambda: r"C:\Nova\bin",
            "windivert_repair_allowed": lambda *args: True,
            "kill_images_in_dir": lambda *args: 0,
            "get_base_dir": lambda: r"C:\Nova",
            "_terminate_helper_pid": lambda path: calls.append(("pid", path)),
            "_query_windivert_service_state": lambda: next(states),
            "_is_sc_service_missing_text": lambda text: "1060" in text,
            "_is_windivert_pending_delete_text": lambda text: "1072" in text,
            "_write_windivert_registry": lambda path: calls.append(("registry", path)),
            "_run_hidden_sc": lambda *args, **kwargs: calls.append(("sc", args)) or (0, "", ""),
        })
        reset = ns["_reset_windivert_registration_once"]

        with (
            mock.patch("os.path.isfile", return_value=True),
            mock.patch("subprocess.run"),
            mock.patch("time.sleep"),
        ):
            self.assertTrue(reset())
            first_call_count = len(calls)
            self.assertFalse(reset())

        self.assertEqual(first_call_count, len(calls))
        self.assertEqual(
            [("stop", "windivert"), ("delete", "windivert"),
             ("create", "windivert", "type=", "kernel", "start=", "demand",
              "binPath=", r"\??\C:\Nova\bin\WinDivert64.sys")],
            [entry[1] for entry in calls if entry[0] == "sc"],
        )


if __name__ == "__main__":
    unittest.main()
