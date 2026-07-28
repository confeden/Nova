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

from nova_metadata import read_project_version

try:
    sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")
    sys.stderr.reconfigure(line_buffering=True, encoding="utf-8")
except Exception:
    pass


APP_NAME = "Nova"
APP_EXE = "Nova.exe"
INSTALLER_EXE = "NovaSetup.exe"
ISS_TEMPLATE = "NovaInstaller.iss"

BASE_DIR = Path(__file__).resolve().parent

def resolve_shortcut_target(lnk_path: Path) -> Path:
    if not lnk_path.exists():
        return BASE_DIR.parent / "build"
    try:
        import subprocess
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk_path}').TargetPath"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        if res.returncode == 0:
            path_str = res.stdout.strip()
            if path_str:
                return Path(path_str)
    except Exception as e:
        print(f"[WARN] Failed to resolve shortcut target via PowerShell: {e}")
    return BASE_DIR.parent / "build"

BUILD_TARGET_DIR = resolve_shortcut_target(BASE_DIR / "build.lnk")
BUILD_ROOT = BUILD_TARGET_DIR / "Inno"
TEMP_ROOT = BUILD_TARGET_DIR / "temp_inno"
PYI_DIST_DIR = TEMP_ROOT / "dist"
PYI_WORK_DIR = TEMP_ROOT / "work"
PYI_SPEC_DIR = TEMP_ROOT / "spec"
PYI_ASSET_DIR = TEMP_ROOT / "embedded_assets"

TOP_LEVEL_DIRS = ("ip", "list", "strat", "fake", "awg", "licenses")
RESOURCE_DIRS = ("bin",)
RESOURCE_ROOT_FILES = ("nova_routing_profiles.py", "nova_transport_plans.py")
ROOT_DOC_FILES = ("LICENSE", "THIRD_PARTY_NOTICES.md", "README.md")
# The proxy helpers (NovaWFP\proxy\tcp_proxy.py, udp_proxy.py) run as separate
# real Python processes - the frozen Nova.exe cannot host them - so the
# installer has to ship an interpreter. Beyond the stdlib they only need
# cryptography, for tgrelay's MTProto ciphers; everything else in the build
# machine's site-packages is build-time only and would add ~110 MB.
HELPER_RUNTIME_PACKAGES = ("cryptography", "cffi", "pycparser")
HELPER_RUNTIME_LIB_SKIP = ("site-packages", "idlelib", "tkinter", "turtledemo",
                           "lib2to3", "ensurepip", "test", "tests",
                           # Help texts and tooling the helpers never touch.
                           "pydoc_data", "venv", "sqlite3", "_pyrepl",
                           "turtle.py", "turtledemo")
HELPER_RUNTIME_DLL_SKIP = ("_tkinter.pyd", "tcl86t.dll", "tk86t.dll", "_testcapi.pyd",
                           "sqlite3.dll", "_sqlite3.pyd")
# Sources NovaInstaller.iss copies straight from the repo (lines 78-81), which
# the PyInstaller staging tree never sees.
REPO_SOURCE_FILES = (
    Path("nova_routing_profiles.py"),
    Path("NovaWFP") / "proxy" / "tcp_proxy.py",
    Path("NovaWFP") / "proxy" / "udp_proxy.py",
    Path("NovaDivert") / "windivert_observer.py",
    Path("NovaDivert") / "windivert_redirect.py",
    Path("tgrelay") / "__init__.py",
    Path("tgrelay") / "transport.py",
    Path("tgrelay") / "udp_transport.py",
    Path("tgrelay") / "transparent_relay.py",
)
NON_EMPTY_DIRS = ("bin", "fake", "ip", "list", "strat", "awg")
# nova.pyw bootstraps its own dependencies when run from source (see the
# `sys.frozen` guard around _ensure_pip), and PyInstaller cannot see that the
# code is dead in a frozen build - it just follows `import pip` and bundles the
# installer machinery. None of these are reachable at runtime.
PYI_EXCLUDED_MODULES = (
    "pip", "ensurepip", "setuptools", "pkg_resources", "distutils",
    # Pulled in transitively by developer tooling in the build environment.
    "paramiko", "bcrypt", "nacl",
    # Never imported by Nova; excluded so a fat build environment cannot leak in.
    "numpy", "nuitka", "PyInstaller", "pytest", "_pytest", "rich", "pygments",
    "docutils", "nh3", "zstandard", "IPython", "matplotlib", "pandas",
)
IGNORED_PATTERNS = ("*.old", "*.tmp", "__pycache__", "old", "warp_official")
USER_OVERRIDE_HEADER_DEFAULTS = {
    ("list", "u_ru.txt"): "# user WARP override domains\n",
    ("list", "u_eu.txt"): "# user Opera override domains\n",
    ("ip", "u_ru.txt"): "# user WARP override IPs/CIDR\n",
    ("ip", "u_eu.txt"): "# user Opera override IPs/CIDR\n",
}

BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
TARGET_BUILD_CPUS = 7


def read_version(main_script: Path) -> str:
    version = str(read_project_version(main_script.parent, default="") or "").strip()
    if not version:
        raise RuntimeError("CURRENT_VERSION was not found in project metadata")
    return version


def to_version_info(version: str) -> str:
    parts = []
    for raw_part in str(version).split("."):
        raw_part = raw_part.strip()
        if not raw_part:
            continue
        match = re.match(r"(\d+)", raw_part)
        if not match:
            break
        parts.append(str(int(match.group(1))))
        if len(parts) == 4:
            break
    while len(parts) < 4:
        parts.append("0")
    return ".".join(parts[:4])


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-U", "pyinstaller", "pillow"])


def locate_iscc() -> str | None:
    env_path = os.environ.get("INNO_SETUP_COMPILER")
    shortcut_path = BASE_DIR / "Inno Setup.lnk"
    candidates = [
        env_path,
        shutil.which("ISCC.exe"),
    ]
    if shortcut_path.exists():
        resolved = resolve_shortcut_target(shortcut_path)
        if resolved.is_file():
            candidates.append(str(resolved))
        else:
            for sub in [Path("ISCC.exe"), Path("Compil2") / "ISCC.exe"]:
                p = resolved / sub
                if p.exists():
                    candidates.append(str(p))
                    break
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


def _extract_top_comment_header(content: str) -> str:
    lines = str(content or "").splitlines()
    header: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if header:
                header.append("")
            continue
        if stripped.startswith("#") or stripped.startswith(";"):
            header.append(line.rstrip("\r\n"))
            continue
        break
    while header and not header[-1].strip():
        header.pop()
    if not header:
        return ""
    return "\n".join(header).rstrip("\n") + "\n"


def sanitize_user_override_files(staging_dir: Path) -> None:
    for (folder_name, file_name), fallback_header in USER_OVERRIDE_HEADER_DEFAULTS.items():
        target = staging_dir / folder_name / file_name
        target.parent.mkdir(parents=True, exist_ok=True)
        header = ""
        if target.exists():
            try:
                header = _extract_top_comment_header(target.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                header = ""
        if not header:
            header = fallback_header
        target.write_text(header, encoding="utf-8")


def find_python_runtime_root() -> Path:
    """Locate a real CPython installation to copy into the bundle.

    sys.executable is not enough: inside a venv it points at Scripts\\, and a
    Microsoft Store install points at a WindowsApps shim. Neither directory has
    Lib\\ or DLLs\\, so copying from it produces an interpreter that dies with
    "Failed to import encodings module". sys.base_prefix is the real prefix in
    both cases, so try it first and confirm the stdlib is actually there.
    """
    candidates = [Path(sys.base_prefix), Path(sys.prefix), Path(sys.executable).parent]
    # The py launcher may default to a broken install (python.exe and DLLs but
    # no Lib), so fall back to whatever full interpreter is on PATH.
    for name in ("python", "python3"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found).parent)

    checked, usable = [], []
    for candidate in candidates:
        try:
            root = candidate.resolve()
        except Exception:
            continue
        if root in checked:
            continue
        checked.append(root)
        if (root / "Lib" / "os.py").is_file() and any(root.glob("python*.exe")):
            usable.append(root)

    # Prefer a root matching the running interpreter: the bundled cryptography
    # extension is compiled against one specific CPython version.
    version_dll = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
    for root in usable:
        if (root / version_dll).is_file():
            return root
    if usable:
        return usable[0]

    raise RuntimeError(
        "No usable CPython installation to bundle. Looked for Lib\\os.py plus "
        "python*.exe in:\n - " + "\n - ".join(str(p) for p in checked)
        + f"\nRun the build with a full Python installation (current: {sys.executable})."
    )


def copy_python_runtime(dst_root: Path) -> None:
    runtime_root = find_python_runtime_root()
    print(f"[BUILD] Bundling helper runtime from: {runtime_root}")
    python_exe = runtime_root / "python.exe"
    if not python_exe.exists():
        raise RuntimeError(f"Bundled helper runtime source not found: {python_exe}")

    target_root = dst_root / "pyruntime"
    safe_rmtree(target_root)
    target_root.mkdir(parents=True, exist_ok=True)

    copied_any = False
    for pattern in ("python*.exe", "python*.dll", "vcruntime*.dll"):
        for src_file in runtime_root.glob(pattern):
            if src_file.is_file():
                shutil.copy2(src_file, target_root / src_file.name)
                copied_any = True

    lib_src = runtime_root / "Lib"
    if lib_src.exists():
        shutil.copytree(
            lib_src,
            target_root / "Lib",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo",
                                          *HELPER_RUNTIME_LIB_SKIP),
            dirs_exist_ok=True,
        )
        copied_any = True

    dlls_src = runtime_root / "DLLs"
    if dlls_src.exists():
        shutil.copytree(
            dlls_src,
            target_root / "DLLs",
            ignore=shutil.ignore_patterns("__pycache__", *HELPER_RUNTIME_DLL_SKIP),
            dirs_exist_ok=True,
        )
        copied_any = True

    copy_helper_runtime_packages(runtime_root, target_root)

    if not copied_any:
        raise RuntimeError(f"Embedded Python runtime copy failed from: {runtime_root}")

    missing = [rel for rel in ("python.exe", "Lib/encodings/__init__.py", "DLLs")
               if not (target_root / rel).exists()]
    if not any(target_root.glob("python*.dll")):
        missing.append("python<XY>.dll")
    if missing:
        raise RuntimeError(
            f"Bundled helper runtime is incomplete (source: {runtime_root}). "
            "Missing: " + ", ".join(missing)
        )

    write_helper_runtime_path_file(target_root)
    verify_helper_runtime(target_root)


def write_helper_runtime_path_file(target_root: Path) -> None:
    """Pin sys.path to the bundled tree.

    A ._pth file makes the interpreter ignore PYTHONHOME/PYTHONPATH, skip the
    user site directory and skip the registry, so a Python already installed on
    the user's machine cannot hijack the helpers.
    """
    # The file has to be named after the executable that loads it, so write one
    # per interpreter rather than guessing from the DLL: python3.dll is the
    # stable-ABI forwarder and naming it after that has no effect at all.
    executables = [p for p in target_root.glob("python*.exe") if p.is_file()]
    if not executables:
        raise RuntimeError(f"No python*.exe in bundled runtime: {target_root}")
    content = "Lib\nLib\\site-packages\nDLLs\n.\nimport site\n"
    for exe in executables:
        (target_root / f"{exe.stem}._pth").write_text(content, encoding="ascii")


def helper_site_package_dirs(runtime_root: Path) -> list:
    """Where cryptography may live: a venv build has it outside runtime_root."""
    candidates = [runtime_root / "Lib" / "site-packages"]
    try:
        import site
        candidates.extend(Path(p) for p in site.getsitepackages())
        user_site = site.getusersitepackages()
        if isinstance(user_site, str):
            candidates.append(Path(user_site))
    except Exception:
        pass
    try:
        import sysconfig
        purelib = sysconfig.get_paths().get("purelib")
        if purelib:
            candidates.append(Path(purelib))
    except Exception:
        pass

    seen, result = set(), []
    for path in candidates:
        key = str(path).lower()
        if key not in seen and path.is_dir():
            seen.add(key)
            result.append(path)
    return result


def copy_helper_runtime_packages(runtime_root: Path, target_root: Path) -> None:
    site_dst = target_root / "Lib" / "site-packages"
    site_dst.mkdir(parents=True, exist_ok=True)
    sources = helper_site_package_dirs(runtime_root)

    for name in HELPER_RUNTIME_PACKAGES:
        for src_dir in sources:
            pkg = src_dir / name
            if pkg.is_dir():
                shutil.copytree(
                    pkg,
                    site_dst / name,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", "tests"),
                    dirs_exist_ok=True,
                )
                break
        else:
            raise RuntimeError(
                f"Helper runtime dependency {name!r} not found in: "
                + ", ".join(str(p) for p in sources)
            )

    for src_dir in sources:
        for extra in src_dir.glob("_cffi_backend*"):
            if extra.is_file() and not (site_dst / extra.name).exists():
                shutil.copy2(extra, site_dst / extra.name)


HELPER_RUNTIME_PROBE = """
import os, sys, ssl, socket, ctypes, asyncio, concurrent.futures
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
root = os.path.dirname(os.path.abspath(sys.executable)).lower()
outside = [p for p in sys.path if p and not os.path.abspath(p).lower().startswith(root)]
if outside:
    sys.exit('sys.path escapes the bundle: %r' % outside)
print('helper-runtime-ok')
"""


def verify_helper_runtime(target_root: Path) -> None:
    """Run the bundled interpreter the way Nova will, so a broken copy fails the build.

    Nova launches helpers as plain `python.exe -u script`, with no isolation
    flags, so the second pass poisons the environment the way a machine with its
    own Python installation would and checks that nothing leaks in.
    """
    exe = target_root / "python.exe"
    if not exe.exists():
        raise RuntimeError(f"Bundled helper runtime has no python.exe: {target_root}")

    hostile = dict(os.environ)
    hostile.update({
        "PYTHONHOME": r"C:\NoSuchPython",
        "PYTHONPATH": r"C:\NoSuchPython\Lib;C:\Somewhere\site-packages",
        "PYTHONNOUSERSITE": "",
        "PYTHONSTARTUP": r"C:\NoSuchPython\startup.py",
    })

    for label, env in (("clean env", None), ("hostile env", hostile)):
        result = subprocess.run([str(exe), "-B", "-c", HELPER_RUNTIME_PROBE],
                                capture_output=True, text=True, timeout=180, env=env)
        if result.returncode != 0 or "helper-runtime-ok" not in result.stdout:
            raise RuntimeError(
                f"Bundled helper runtime is not usable ({label}): "
                + (result.stderr.strip() or result.stdout.strip() or "no output")
            )
    print(f"[OK] Bundled helper runtime verified (isolated): {exe}")


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


def set_low_priority_and_build_affinity() -> None:
    if os.name != "nt":
        return

    try:
        kernel32 = ctypes.windll.kernel32
        process = kernel32.GetCurrentProcess()
        kernel32.SetPriorityClass(process, BELOW_NORMAL_PRIORITY_CLASS)
        cpu_count = max(1, int(os.cpu_count() or 1))
        usable_cpus = min(TARGET_BUILD_CPUS, cpu_count)
        affinity_mask = (1 << usable_cpus) - 1
        kernel32.SetProcessAffinityMask(process, affinity_mask)
        print(f"[BUILD] Ограничение сборки: низкий приоритет, {usable_cpus} CPU.")
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
    # NovaInstaller.iss pulls these from the repo instead of the staging tree, so
    # a missing one surfaces as an opaque ISCC "No files found matching" error.
    required_paths.extend(base_dir / rel for rel in REPO_SOURCE_FILES)

    missing = [str(path) for path in required_paths if not path.exists()]
    if missing:
        raise RuntimeError("Missing required project paths:\n - " + "\n - ".join(missing))

    # An empty directory compiles fine and ships a silently broken installer.
    empty = [name for name in NON_EMPTY_DIRS
             if not any((base_dir / name).iterdir())]
    if empty:
        raise RuntimeError("Required project directories are empty:\n - "
                           + "\n - ".join(str(base_dir / name) for name in empty))


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


def find_tcl_root() -> Path | None:
    """Robustly locate the Tcl/Tk library directory on the system."""
    candidates = []

    # 1. Active Python's prefix or executable folder
    python_root = Path(sys.base_prefix).resolve()
    candidates.append(python_root / "tcl")
    candidates.append(Path(sys.executable).resolve().parent / "tcl")

    # 2. Hardcoded typical Windows paths (including AppData)
    localappdata = os.environ.get("LOCALAPPDATA", "")
    if localappdata:
        python_dir = Path(localappdata) / "Programs" / "Python"
        if python_dir.exists():
            for p in python_dir.glob("Python*/tcl"):
                candidates.append(p)

    # 3. System-wide python installations
    candidates.append(Path(r"C:\Python314\tcl"))
    candidates.append(Path(r"C:\Python313\tcl"))
    candidates.append(Path(r"C:\Python312\tcl"))
    candidates.append(Path(r"C:\Program Files\Python314\tcl"))
    candidates.append(Path(r"C:\Program Files\Python313\tcl"))
    candidates.append(Path(r"C:\Program Files\Python312\tcl"))

    for cand in candidates:
        cand = cand.resolve()
        if cand.exists() and cand.is_dir():
            # Verify if it has a tcl subdirectory containing init.tcl
            for sub in cand.iterdir():
                if sub.is_dir() and sub.name.startswith("tcl") and (sub / "init.tcl").exists():
                    return cand
    return None


def ensure_tcl_data(resources_dir: Path) -> None:
    """Copy Tcl/Tk library data into resources/tcl_data and resources/tk_data if PyInstaller didn't."""
    tcl_data_dest = resources_dir / "_tcl_data"
    tk_data_dest = resources_dir / "_tk_data"

    if tcl_data_dest.exists() and any(tcl_data_dest.iterdir()) and tk_data_dest.exists() and any(tk_data_dest.iterdir()):
        print("[BUILD] tcl_data and tk_data already present — skipping.")
        return

    tcl_root = find_tcl_root()
    if not tcl_root:
        print("[WARN] Cannot find Tcl/Tk root directory — tkinter may fail at runtime.")
        return

    tcl_src = None
    tk_src = None
    for subdir in tcl_root.iterdir():
        if subdir.is_dir():
            if subdir.name.startswith("tcl") and (subdir / "init.tcl").exists():
                tcl_src = subdir
            elif subdir.name.startswith("tk") and (subdir / "tk.tcl").exists():
                tk_src = subdir

    if not tcl_src or not tk_src:
        print(f"[WARN] Incomplete Tcl/Tk data in {tcl_root} — tkinter may fail at runtime.")
        return

    # Copy tcl library contents directly to resources/tcl_data
    # Keep only essentials: init.tcl, pkgIndex, essential encoding mappings.
    # Strip: demos, msgs (localization for 50+ languages), http1.0, http1.1.
    if not (tcl_data_dest.exists() and any(tcl_data_dest.iterdir())):
        safe_rmtree(tcl_data_dest)
        shutil.copytree(tcl_src, tcl_data_dest, ignore=shutil.ignore_patterns(
            "__pycache__", "demos", "msgs", "http1.0", "http1.1",
            "opt0.4", "package.tcl",
        ))
        print(f"[BUILD] Patched tcl_data: copied {tcl_src} to {tcl_data_dest}")

    # Copy tk library contents directly to resources/tk_data
    # Strip: demos, images (large icon sets not used by Nova).
    if not (tk_data_dest.exists() and any(tk_data_dest.iterdir())):
        safe_rmtree(tk_data_dest)
        shutil.copytree(tk_src, tk_data_dest, ignore=shutil.ignore_patterns(
            "__pycache__", "demos", "images",
        ))
        print(f"[BUILD] Patched tk_data: copied {tk_src} to {tk_data_dest}")


def build_pyinstaller_dist(base_dir: Path, release_dir: Path) -> Path:
    ensure_pyinstaller()
    ensure_clean_dir(TEMP_ROOT)
    asset_dir = build_embedded_assets_module(base_dir)

    main_script = base_dir / "nova.pyw"
    icon_file = base_dir / "icon.ico"
    version = read_version(main_script)

    # Ensure PyInstaller can find Tcl/Tk data by setting env vars before launch.
    tcl_root = find_tcl_root()
    if tcl_root:
        for sub in tcl_root.iterdir():
            if sub.is_dir() and sub.name.startswith("tcl") and (sub / "init.tcl").exists():
                os.environ["TCL_LIBRARY"] = str(sub)
            elif sub.is_dir() and sub.name.startswith("tk") and (sub / "tk.tcl").exists():
                os.environ["TK_LIBRARY"] = str(sub)

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
        "--hidden-import=tkinter",
        "--hidden-import=_tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=tkinter.messagebox",
        "--hidden-import=tkinter.scrolledtext",
        "--hidden-import=tkinter.font",
        "--collect-data=certifi",
        str(main_script),
    ]
    cmd[-1:-1] = [f"--exclude-module={name}" for name in PYI_EXCLUDED_MODULES]

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

    # FIX: PyInstaller may fail to create tcl_data on Python 3.14+.
    # Manually copy Tcl/Tk library directories so pyi_rth_tkinter finds them.
    ensure_tcl_data(staging_dir / "resources")

    for folder_name in TOP_LEVEL_DIRS:
        src_dir = base_dir / folder_name
        dst_dir = staging_dir / folder_name
        if src_dir.exists():
            copytree_filtered(src_dir, dst_dir)
        else:
            dst_dir.mkdir(parents=True, exist_ok=True)

    for filename in ROOT_DOC_FILES:
        src_file = base_dir / filename
        if src_file.exists():
            shutil.copy2(src_file, staging_dir / filename)

    resources_root = staging_dir / "resources"
    resources_root.mkdir(parents=True, exist_ok=True)
    for folder_name in RESOURCE_DIRS:
        copytree_filtered(base_dir / folder_name, resources_root / folder_name)
    for filename in RESOURCE_ROOT_FILES:
        src_file = base_dir / filename
        if src_file.exists():
            shutil.copy2(src_file, resources_root / filename)

    # Without this the proxy helpers have no interpreter to run under on a
    # clean install, and every start fails with "Не найден Python launcher".
    copy_python_runtime(resources_root)

    sanitize_user_override_files(staging_dir)

    routing_settings_src = base_dir / "routing_settings.json"
    if routing_settings_src.exists():
        shutil.copy2(routing_settings_src, staging_dir / "routing_settings.json")

    # Strip unnecessary Python packaging artifacts from staging
    for pattern in ("setuptools", "setuptools-*"):
        for d in resources_root.glob(pattern):
            if d.is_dir():
                safe_rmtree(d)
    for d in resources_root.glob("*.dist-info"):
        if d.is_dir():
            safe_rmtree(d)

    (staging_dir / "temp").mkdir(parents=True, exist_ok=True)

    return staging_dir


def build_installer(base_dir: Path) -> None:
    require_paths(base_dir)
    set_low_priority_and_build_affinity()

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
            "@@APP_VERSION_INFO@@": to_version_info(version),
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
        return

    print(f"[BUILD] Inno Setup installer via {iscc}")
    run_checked([iscc, str(generated_iss)], base_dir)

    installer_path = release_dir / INSTALLER_EXE
    if not installer_path.exists():
        raise RuntimeError(f"Installer was not created: {installer_path}")

    try:
        safe_rmtree(staging_dir)
        print(f"[CLEANUP] Deleted staging folder: {staging_dir}")
    except Exception as e:
        print(f"[WARN] Failed to delete staging folder {staging_dir}: {e}")

    print(f"[DONE] Installer: {installer_path}")

    try:
        os.startfile(str(release_dir))
    except Exception:
        pass


def ensure_complete_interpreter() -> None:
    """Re-run the build under a full CPython if the current one is incomplete.

    The py launcher may default to an install that has python.exe but no Lib.
    Such an interpreter limps along by picking up whatever Lib\\site-packages
    sits next to the working directory, which makes the contents of the build
    depend on where it was started from.
    """
    if os.environ.get("NOVA_BUILD_REEXEC") == "1":
        return
    if (Path(sys.base_prefix) / "Lib" / "os.py").is_file():
        return

    root = find_python_runtime_root()
    exe = root / "python.exe"
    print(f"[BUILD] Incomplete interpreter: {sys.executable} (no stdlib at {sys.base_prefix})")
    print(f"[BUILD] Re-running the build under {exe}")
    env = dict(os.environ, NOVA_BUILD_REEXEC="1")
    completed = subprocess.run([str(exe), str(Path(__file__).resolve()), *sys.argv[1:]],
                               env=env)
    raise SystemExit(completed.returncode)


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    try:
        ensure_complete_interpreter()
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
    if raise_code != 0:
        try:
            input("\nНажмите Enter, чтобы закрыть окно...")
        except Exception:
            pass
    raise SystemExit(raise_code)
