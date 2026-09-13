import os
import re
from pathlib import Path

CURRENT_VERSION = "1.39"
WINWS_FILENAME = "winws.exe"
# Обновления берутся прямо из релизов основного репозитория, а не из отдельного
# version.json. Одно место вместо двух: релиз опубликован — обновление доступно,
# промежуточного файла, который надо не забыть обновить, больше нет.
#
# Именно /releases/latest, а не /releases: GitHub исключает отсюда черновики и
# предрелизы. Пока сборка лежит черновиком, пользователям она не предлагается, и
# ни один технический предрелиз не может подменить собой версию продукта.
UPDATE_URL = "https://api.github.com/repos/confeden/Nova/releases/latest"


def get_project_root(start_path=None):
    if start_path is None:
        start_path = Path(__file__).resolve().parent
    return Path(start_path).resolve()


def get_main_script_path(project_root=None):
    root = get_project_root(project_root)
    return root / "nova.pyw"


def read_project_version(project_root=None, default="Unknown"):
    root = get_project_root(project_root)
    # Модули Nova лежат в resources/, но вызывающий обычно передаёт корень
    # проекта — каталог с nova.pyw. Поэтому resources/ проверяется первым, а
    # корень остаётся в списке: так функция продолжает работать и для установок
    # прежней раскладки, и для копии, лежащей рядом с nova.pyw.
    candidates = [
        root / "resources" / "nova_metadata.py",
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
