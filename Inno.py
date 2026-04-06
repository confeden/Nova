# -*- coding: utf-8 -*-
import base64
import ctypes
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass


APP_NAME = "Nova"
APP_EXE = "Nova.exe"
INSTALLER_EXE = "NovaSetup.exe"
ISS_TEMPLATE = "NovaInstaller.iss"

BUILD_ROOT = Path(r"D:\Desktop\build\Inno")
TEMP_ROOT = Path(r"D:\Desktop\build\temp_inno")
PYI_DIST_DIR = TEMP_ROOT / "dist"
PYI_WORK_DIR = TEMP_ROOT / "work"
PYI_SPEC_DIR = TEMP_ROOT / "spec"
PYI_ASSET_DIR = TEMP_ROOT / "embedded_assets"

TOP_LEVEL_DIRS = ("ip", "list", "strat", "fake")
RESOURCE_DIRS = ("bin",)
IGNORED_PATTERNS = ("*.old", "*.tmp", "__pycache__")

BELOW_NORMAL_PRIORITY_CLASS = 0x00004000


def read_version(main_script: Path) -> str:
    content = main_script.read_text(encoding="utf-8")
    match = re.search(r'^\s*CURRENT_VERSION\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
    if not match:
        raise RuntimeError("CURRENT_VERSION was not found in nova.pyw")
    return match.group(1)


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-U", "pyinstaller", "pillow"])


def locate_iscc() -> str | None:
    env_path = os.environ.get("INNO_SETUP_COMPILER")
    candidates = [
        env_path,
        shutil.which("ISCC.exe"),
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def safe_rmtree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def ensure_clean_dir(path: Path) -> None:
    safe_rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def copytree_filtered(src: Path, dst: Path) -> None:
    if not src.exists():
        raise RuntimeError(f"Source path is missing: {src}")
    safe_rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*IGNORED_PATTERNS))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_iss(template_path: Path, output_path: Path, replacements: dict[str, str]) -> None:
    content = template_path.read_text(encoding="utf-8")
    for key, value in replacements.items():
        content = content.replace(key, value.replace('"', '""'))
    output_path.write_text(content, encoding="utf-8")


def set_low_priority_and_single_core() -> None:
    if os.name != "nt":
        return

    try:
        kernel32 = ctypes.windll.kernel32
        process = kernel32.GetCurrentProcess()
        kernel32.SetPriorityClass(process, BELOW_NORMAL_PRIORITY_CLASS)
        kernel32.SetProcessAffinityMask(process, 1)
        print("[BUILD] Ограничение сборки: низкий приоритет, 1 CPU.")
    except Exception as exc:
        print(f"[WARN] Не удалось ограничить приоритет/CPU: {exc}")


def run_checked(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, check=True, cwd=cwd, creationflags=BELOW_NORMAL_PRIORITY_CLASS if os.name == "nt" else 0)


def require_paths(base_dir: Path) -> None:
    required_paths = [
        base_dir / "nova.pyw",
        base_dir / "icon.ico",
        base_dir / "img" / "background.png",
        base_dir / "NovaInstaller.iss",
        base_dir / "bin",
        base_dir / "fake",
        base_dir / "ip",
        base_dir / "list",
        base_dir / "strat",
    ]

    missing = [str(path) for path in required_paths if not path.exists()]
    if missing:
        raise RuntimeError("Missing required project paths:\n - " + "\n - ".join(missing))


def build_embedded_assets_module(base_dir: Path) -> Path:
    ensure_clean_dir(PYI_ASSET_DIR)

    icon_b64 = base64.b64encode((base_dir / "icon.ico").read_bytes()).decode("ascii")
    bg_b64 = base64.b64encode((base_dir / "img" / "background.png").read_bytes()).decode("ascii")

    content = f'''# -*- coding: utf-8 -*-
import base64

_ICON_ICO_B64 = """{icon_b64}"""
_BACKGROUND_PNG_B64 = """{bg_b64}"""


def get_icon_ico_bytes():
    return base64.b64decode(_ICON_ICO_B64)


def get_background_png_bytes():
    return base64.b64decode(_BACKGROUND_PNG_B64)
'''
    module_path = PYI_ASSET_DIR / "embedded_assets.py"
    module_path.write_text(content, encoding="utf-8")
    return PYI_ASSET_DIR


def build_pyinstaller_dist(base_dir: Path, release_dir: Path) -> Path:
    ensure_pyinstaller()
    ensure_clean_dir(TEMP_ROOT)
    asset_dir = build_embedded_assets_module(base_dir)

    main_script = base_dir / "nova.pyw"
    icon_file = base_dir / "icon.ico"
    version = read_version(main_script)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--windowed",
        "--noupx",
        "--contents-directory",
        "resources",
        f"--name={APP_NAME}",
        f"--icon={icon_file}",
        f"--distpath={PYI_DIST_DIR}",
        f"--workpath={PYI_WORK_DIR}",
        f"--specpath={PYI_SPEC_DIR}",
        f"--paths={asset_dir}",
        "--hidden-import=embedded_assets",
        "--hidden-import=pystray._win32",
        "--hidden-import=PIL.ImageTk",
        "--collect-data=certifi",
        str(main_script),
    ]

    print(f"{'=' * 60}")
    print(f"[BUILD] PyInstaller onedir for v{version}")
    print(f"[BUILD] Staging layout target: {release_dir}")
    print(f"{'=' * 60}")
    run_checked(cmd, base_dir)

    built_dir = PYI_DIST_DIR / APP_NAME
    if not built_dir.exists():
        raise RuntimeError(f"PyInstaller did not produce expected directory: {built_dir}")

    staging_dir = release_dir / APP_NAME
    copytree_filtered(built_dir, staging_dir)

    for folder_name in TOP_LEVEL_DIRS:
        copytree_filtered(base_dir / folder_name, staging_dir / folder_name)

    resources_root = staging_dir / "resources"
    resources_root.mkdir(parents=True, exist_ok=True)
    for folder_name in RESOURCE_DIRS:
        copytree_filtered(base_dir / folder_name, resources_root / folder_name)

    (staging_dir / "temp").mkdir(parents=True, exist_ok=True)

    return staging_dir


def build_installer(base_dir: Path) -> None:
    require_paths(base_dir)
    set_low_priority_and_single_core()

    version = read_version(base_dir / "nova.pyw")
    release_dir = BUILD_ROOT / f"v{version}"
    ensure_clean_dir(release_dir)

    staging_dir = build_pyinstaller_dist(base_dir, release_dir)

    template_path = base_dir / ISS_TEMPLATE
    generated_iss = TEMP_ROOT / "NovaInstaller.generated.iss"
    render_iss(
        template_path,
        generated_iss,
        {
            "@@APP_VERSION@@": version,
            "@@SOURCE_DIR@@": str(staging_dir.resolve()),
            "@@OUTPUT_DIR@@": str(release_dir.resolve()),
            "@@REPO_DIR@@": str(base_dir.resolve()),
        },
    )

    iscc = locate_iscc()
    if not iscc:
        print("[WARN] Inno Setup compiler was not found.")
        print(f"[INFO] Release staging is ready: {staging_dir}")
        print(f"[INFO] Install Inno Setup 6 and compile: {generated_iss}")
        try:
            os.startfile(str(release_dir))
        except Exception:
            pass
        return

    print(f"[BUILD] Inno Setup installer via {iscc}")
    run_checked([iscc, str(generated_iss)], base_dir)

    installer_path = release_dir / INSTALLER_EXE
    if not installer_path.exists():
        raise RuntimeError(f"Installer was not created: {installer_path}")

    checksum_path = release_dir / "SHA256SUMS.txt"
    checksum_path.write_text(f"{sha256_file(installer_path)} *{INSTALLER_EXE}\n", encoding="utf-8")

    print(f"[DONE] App folder: {staging_dir}")
    print(f"[DONE] Installer: {installer_path}")
    print(f"[DONE] SHA256: {checksum_path}")

    try:
        os.startfile(str(release_dir))
    except Exception:
        pass


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    try:
        build_installer(base_dir)
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"[FATAL] Build command failed with exit code {exc.returncode}.")
        return exc.returncode or 1
    except Exception as exc:
        print(f"[FATAL] {exc}")
        return 1


if __name__ == "__main__":
    raise_code = main()
    try:
        input("\nНажмите Enter, чтобы закрыть окно...")
    except Exception:
        pass
    raise SystemExit(raise_code)
