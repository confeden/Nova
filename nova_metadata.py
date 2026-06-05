import os
import re
from pathlib import Path

CURRENT_VERSION = "1.26"
WINWS_FILENAME = "winws.exe"
UPDATE_URL = "https://confeden.github.io/nova_updates/version.json"


def get_project_root(start_path=None):
    if start_path is None:
        start_path = Path(__file__).resolve().parent
    return Path(start_path).resolve()


def get_main_script_path(project_root=None):
    root = get_project_root(project_root)
    return root / "nova.pyw"


def read_project_version(project_root=None, default="Unknown"):
    root = get_project_root(project_root)
    candidates = [
        root / "nova_metadata.py",
        get_main_script_path(root),
    ]
    try:
        for path in candidates:
            try:
                content = path.read_text(encoding="utf-8")
            except Exception:
                continue
            match = re.search(r'CURRENT_VERSION\s*=\s*"([^"]+)"', content)
            if match:
                return match.group(1)
    except Exception:
        pass
    return str(default)


def read_project_version_from_env(default="Unknown"):
    env_value = str(os.environ.get("NOVA_VERSION", "") or "").strip()
    return env_value or str(default)
