import sys
import os
from unittest.mock import MagicMock
import importlib.util
from importlib.machinery import SourceFileLoader

# 1. Mock all Windows-specific and GUI modules BEFORE importing nova
mock_ctypes = MagicMock()
sys.modules['ctypes'] = mock_ctypes
sys.modules['ctypes.windll'] = MagicMock()

mock_tk = MagicMock()
sys.modules['tkinter'] = mock_tk
sys.modules['tkinter.ttk'] = MagicMock()
sys.modules['tkinter.messagebox'] = MagicMock()
sys.modules['tkinter.scrolledtext'] = MagicMock()
sys.modules['tkinter.font'] = MagicMock()
sys.modules['winreg'] = MagicMock()

# Mock sys.exit to prevent the script from exiting the test runner
sys.exit = MagicMock()

# 2. Load the nova module from nova.pyw
nova_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "nova.pyw"))
loader = SourceFileLoader("nova", nova_path)
spec = importlib.util.spec_from_loader("nova", loader)
nova = importlib.util.module_from_spec(spec)
sys.modules["nova"] = nova

# Execute the module. Since we've mocked the side-effect-heavy modules and
# the main execution is protected by if __name__ == "__main__", this should be safe.
try:
    loader.exec_module(nova)
except Exception as e:
    # If it still fails, we might need more mocks, but let's see.
    # We ignore errors during module execution if get_line_tag is already defined.
    pass

from nova import get_line_tag

def test_auto_tag():
    assert get_line_tag("!!! [AUTO] some message") == "normal"

def test_info_tags():
    assert get_line_tag("[StrategyBuilder] working") == "info"
    assert get_line_tag("[Check] testing") == "info"
    assert get_line_tag("[ExcludeCheck] skipping") == "info"
    # Russian info keywords
    assert get_line_tag("пропуск операции") == "info"
    assert get_line_tag("удаление файла") == "info"
    assert get_line_tag("отмена действия") == "info"
    assert get_line_tag("инфо сообщение") == "info"
    assert get_line_tag("успешно завершено") == "info"
    assert get_line_tag("ядро активно") == "info"
    # Case insensitivity for Russian info
    assert get_line_tag("УСПЕШНО") == "info"

def test_error_tags():
    error_keywords = ["err:", "error", "dead", "crash", "could not read", "fatal", "panic", "must specify", "unknown option", "не удается", "не найдено"]
    for kw in error_keywords:
        assert get_line_tag(f"Something happened: {kw}") == "error"
        assert get_line_tag(f"{kw.upper()}: message") == "error"

def test_fail_tag():
    assert get_line_tag("The process failed") == "fail"
    assert get_line_tag("FAIL") == "fail"

def test_ok_normal():
    assert get_line_tag("Status: ok (verified)") == "normal"
    assert get_line_tag("OK (") == "normal"

def test_precedence():
    # Priority 1: !!! [AUTO]
    assert get_line_tag("!!! [AUTO] error") == "normal"

    # Priority 2: info markers
    assert get_line_tag("[Check] an error occurred") == "info"
    assert get_line_tag("[StrategyBuilder] failed") == "info"

    # Priority 3: error keywords
    assert get_line_tag("fatal failure") == "error"

    # Priority 4: fail
    assert get_line_tag("operation failed") == "fail"

def test_case_sensitivity_specifics():
    # Startswith "!!! [AUTO]" is case-sensitive in the implementation
    # "[StrategyBuilder]" is case-sensitive in the implementation
    assert get_line_tag("[strategybuilder] test") == "normal"

def test_default_normal():
    assert get_line_tag("just a regular log line") == "normal"
    assert get_line_tag("") == "normal"
