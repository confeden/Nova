# -*- coding: utf-8 -*-
import ast
import base64
import contextlib
import ctypes
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent / "resources"))
from nova_metadata import read_project_version  # noqa: E402

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

TOP_LEVEL_DIRS = ("ip", "list", "strat", "fake", "profiles", "licenses")
RESOURCE_DIRS = ("bin",)
# profiles/ mixes what Nova ships with what belongs to one person: the
# developer's own WARP identity (WARPgen_*.conf, warp_identity.json), a Proton
# account seed and the confs issued for it, MASQUE credentials, imported configs
# in Custom/ and rendered runtime configs with private keys in .runtime/.
# Copying the folder wholesale would put all of that into every installer, so it
# is the one top-level dir that is staged by name: only the patterns below leave
# the machine, and verify_staged_profiles() re-walks the staged tree and fails
# the build if anything else got there anyway.
PROFILES_DIRNAME = "profiles"
LEGACY_AWG_DIRNAME = "awg"
PROFILE_GROUP_DIRS = ("MASQUE", "Custom", "AWG Proton", "AWG Cloudflare")
PROFILES_SHIP_WHITELIST = (
    "AWG Cloudflare/WARPv*.conf",    # shared seed pool, refreshed by name on upgrade
    "AWG Proton/proton_nodes.json",  # public starter node list
    "opera_relay.key",               # relay password; rotates with every release
)
# Shipped names never carry spaces or brackets. "WARPv1_11 (legacy).conf" and
# "x (2).conf" are what migration and import produce on a collision — a local
# leftover, not a pool file — and must not match WARPv*.conf by accident.
PROFILES_SHIP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# What earlier releases kept in awg/ and now lives in profiles/: (name pattern,
# group folder under profiles/, "" for the profiles/ root). The installer's
# [InstallDelete] removes exactly these from {app}\awg, so the build refuses to
# run while nova.pyw still reads them there, and while a copy is left behind in
# the dev tree's awg/ (a newer relay key written there would be ignored by the
# build and deleted by the migration on the next start).
LEGACY_AWG_MOVED_FILES = (
    ("WARPv*.conf", "AWG Cloudflare"),
    ("opera_relay.key", ""),
    ("cf_ws.key", ""),
)
# Tor comes from the official Tor Expert Bundle, renamed so that name-based
# kills (NovaInstaller.iss, restore_nova_network.ps1) never hit the user's own
# Tor Browser. RESOURCE_DIRS copies bin/ recursively, so bin/tor ships as-is.
TOR_BIN_SUBDIR = "tor"
TOR_REQUIRED_FILES = ("nova-tor.exe", "nova-lyrebird.exe")
TOR_OPTIONAL_FILES = ("geoip", "geoip6", "pt_config.json")
NOVA_GO_FILENAME = "nova-go.exe"
NOVA_GO_SOURCE_DIR = "nova-go"
NOVA_GO_PACKAGE = "./cmd/nova-go"
NOVA_GO_BUILD_TIMEOUT = 1800
NOVA_GO_SMOKE_TIMEOUT = 30
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# Nova's own modules live in resources/ in the source tree, which is the same
# place the installer puts them ({app}/resources). Source layout and installed
# layout are therefore identical, and the helper processes resolve imports the
# same way in development as they do on a user's machine.
# nova_privacy.py здесь по той же причине, что и остальные два: его
# импортируют NovaDivert и NovaWFP, а они исполняются отдельным
# интерпретатором и видят только то, что лежит на диске. Пропуск ниже
# молчаливый (`if src_file.exists()`), так что забытое имя не заметно.
# nova_vpn_slots.py: tcp_proxy.py and tgrelay/transport.py read the two-slot egress state through it
# (which egress the reserve is, whether the primary exits abroad). Missing, they fall back to the
# pre-1.39 routing in silence -- so it must be listed here, not merely present in the tree.
RESOURCE_ROOT_FILES = ("nova_routing_profiles.py", "nova_transport_plans.py", "nova_privacy.py", "nova_temp_log.py",
                       "nova_vpn_slots.py")
RESOURCE_SOURCE_DIR = "resources"
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
    Path("resources") / "nova_routing_profiles.py",
    Path("NovaWFP") / "proxy" / "tcp_proxy.py",
    Path("NovaWFP") / "proxy" / "udp_proxy.py",
    Path("NovaDivert") / "windivert_observer.py",
    Path("NovaDivert") / "windivert_redirect.py",
    Path("tgrelay") / "__init__.py",
    # Все четыре несущие для helper-процесса: transport импортирует terminator,
    # transparent_relay импортирует persona и phase. Отсутствие любого ломает
    # NovaWFP\proxy у пользователя, а не при сборке.
    Path("tgrelay") / "config.py",
    Path("tgrelay") / "persona.py",
    Path("tgrelay") / "phase.py",
    Path("tgrelay") / "raw_websocket.py",
    Path("tgrelay") / "terminator.py",
    Path("tgrelay") / "transport.py",
    Path("tgrelay") / "udp_transport.py",
    Path("tgrelay") / "transparent_relay.py",
)
# profiles/ is not here: any((profiles).iterdir()) is satisfied by an empty group
# folder and proves nothing. require_profile_sources() checks the actual files.
NON_EMPTY_DIRS = ("bin", "fake", "ip", "list", "strat")
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
# *.part: an interrupted install_binary() leaves one next to the exe in bin/.
IGNORED_PATTERNS = ("*.old", "*.tmp", "*.part", "__pycache__", "old", "warp_official")
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


def is_shippable_profile_path(rel_path: str) -> bool:
    """Может ли файл (путь относительно profiles/) попасть в установщик.

    Сравнение по сегментам, а не fnmatch по всей строке: у fnmatch `*`
    проглатывает `/`, и `AWG Cloudflare/WARPv*.conf` пропустил бы
    `AWG Cloudflare/WARPvX/чужой.conf`. Регистр учитывается: белый список —
    это имена, которые мы сами кладём, а не то, как их найдёт Проводник.
    """
    parts = PurePosixPath(str(rel_path).replace("\\", "/")).parts
    if not parts or not PROFILES_SHIP_NAME_RE.match(parts[-1]):
        return False
    for pattern in PROFILES_SHIP_WHITELIST:
        pattern_parts = PurePosixPath(pattern).parts
        if len(pattern_parts) != len(parts):
            continue
        if all(fnmatch.fnmatchcase(part, pat) for part, pat in zip(parts, pattern_parts)):
            return True
    return False


def verify_staged_profiles(staged_root: Path) -> None:
    """Провалить сборку, если в подготовленном profiles/ есть хоть что-то лишнее.

    Проверка идёт по готовому дереву, а не по списку скопированного: она ловит
    и будущую правку, которая вернёт profiles/ в общий copytree. Найденное
    удаляется сразу — личный ключ не должен остаться даже в папке сборки.
    """
    if not staged_root.exists():
        return
    offenders = []
    for dirpath, dirnames, filenames in os.walk(staged_root):
        rel_dir = Path(dirpath).relative_to(staged_root)
        for name in dirnames:
            rel = (rel_dir / name).as_posix()
            if rel not in PROFILE_GROUP_DIRS:
                offenders.append(rel + "/")
        for name in filenames:
            rel = (rel_dir / name).as_posix()
            if not is_shippable_profile_path(rel):
                offenders.append(rel)
    if not offenders:
        return
    safe_rmtree(staged_root)
    leftover = " (удалить не удалось — удалите вручную!)" if staged_root.exists() else ""
    raise RuntimeError(
        f"В подготовленном {staged_root} оказались файлы вне белого списка{leftover}:\n - "
        + "\n - ".join(sorted(offenders))
        + "\n  Белый список: " + ", ".join(PROFILES_SHIP_WHITELIST)
        + "\n  Это личные данные разработчика (свои WARP/Proton/MASQUE, Custom, .runtime) —"
          " в установщик они попасть не должны."
    )


def stage_profiles(src: Path, dst: Path) -> list[str]:
    """Разложить profiles/ в staging строго по PROFILES_SHIP_WHITELIST.

    Пустые папки групп создаются всегда: установщик кладёт их пользователю,
    и импорт/генерация пишут туда без собственного mkdir. Возвращает список
    скопированных путей (относительно profiles/, через `/`).
    """
    safe_rmtree(dst)
    if dst.exists():
        raise RuntimeError(f"Не удалось очистить {dst} перед раскладкой профилей.")
    for group in PROFILE_GROUP_DIRS:
        (dst / group).mkdir(parents=True, exist_ok=True)

    staged = []
    for pattern in PROFILES_SHIP_WHITELIST:
        pattern_parts = PurePosixPath(pattern).parts
        src_dir = src.joinpath(*pattern_parts[:-1])
        if not src_dir.is_dir():
            continue
        with os.scandir(src_dir) as entries:
            # Ссылки не копируются: symlink в группе мог бы увести за личным файлом.
            names = sorted(entry.name for entry in entries if entry.is_file(follow_symlinks=False))
        for name in names:
            rel = "/".join((*pattern_parts[:-1], name))
            if not fnmatch.fnmatchcase(name, pattern_parts[-1]) or not is_shippable_profile_path(rel):
                continue
            target = dst.joinpath(*pattern_parts[:-1], name)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_dir / name, target)
            staged.append(rel)

    verify_staged_profiles(dst)
    return staged


def nova_pyw_layout_problems(source: str) -> list[str]:
    """Почему nova.pyw ещё живёт в раскладке awg/; пустой список — перешёл на profiles/.

    Разбор через AST, а не поиск подстроки: комментарий «awg/opera_relay.key»
    или «migrate_legacy_layout(» в тексте ничего не читает и ничего не переносит.
    Признаки прежней раскладки — те, что были в nova.pyw до переезда:
    AWG_PROFILES_DIRNAME = "awg" и путь, собранный из "awg" и имени ключа или
    конфига. Признак новой — настоящий вызов migrate_legacy_layout().
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"nova.pyw не разбирается ({exc.msg}, строка {exc.lineno}) — раскладку профилей не проверить"]

    legacy_path_re = re.compile(r"(?i)(?:^|[\\/])" + re.escape(LEGACY_AWG_DIRNAME) + r"[\\/]+[^\\/]+\.(?:key|conf)$")
    migrates = False
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name == "migrate_legacy_layout":
                migrates = True
            args = [a.value if isinstance(a, ast.Constant) and isinstance(a.value, str) else None
                    for a in node.args]
            for left, right in zip(args, args[1:]):
                if (left is not None and right is not None and left.lower() == LEGACY_AWG_DIRNAME
                        and right.lower().endswith((".key", ".conf"))):
                    problems.append(f"строка {node.lineno}: путь {left}/{right}")
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if (isinstance(value, ast.Constant) and value.value == LEGACY_AWG_DIRNAME
                    and any(isinstance(t, ast.Name) and t.id == "AWG_PROFILES_DIRNAME" for t in targets)):
                problems.append(f'строка {node.lineno}: AWG_PROFILES_DIRNAME = "{LEGACY_AWG_DIRNAME}"')
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if legacy_path_re.search(node.value):
                problems.append(f"строка {node.lineno}: путь {node.value}")
    if not migrates:
        problems.append("нет вызова nova_profiles.migrate_legacy_layout() — awg/ на старте не переносится")
    return problems


def _short_list(names: list[str], limit: int = 8) -> str:
    shown = ", ".join(names[:limit])
    return shown + (f" и ещё {len(names) - limit}" if len(names) > limit else "")


def legacy_awg_leftovers(base_dir: Path) -> list[str]:
    """Что осталось в прежнем awg/ из того, что теперь живёт в profiles/.

    Любой такой файл — повод остановить сборку, в каком бы состоянии ни был
    profiles/. Сборка берёт только profiles/, так что новый ключ релея,
    записанный по старой памяти в awg/, молча не попал бы в установщик (релей
    ответит 407 на nova-pc-<версия>, а отсюда это выглядит мёртвым релеем), а
    перенос при следующем запуске удалил бы его как «прежний». Содержимое
    сравнивается по sha256 и никогда не печатается.
    """
    legacy = base_dir / LEGACY_AWG_DIRNAME
    if not legacy.is_dir():
        return []
    try:
        entries = sorted((p for p in legacy.iterdir() if p.is_file()), key=lambda p: p.name.lower())
    except OSError as exc:
        return [f"{legacy} не читается: {exc}"]

    problems = []
    for pattern, group in LEGACY_AWG_MOVED_FILES:
        where = f"{PROFILES_DIRNAME}/{group}/" if group else f"{PROFILES_DIRNAME}/"
        label = f"{LEGACY_AWG_DIRNAME}/{pattern}"
        same, differ, unmoved = [], [], []
        for entry in entries:
            if not fnmatch.fnmatchcase(entry.name.lower(), pattern.lower()):
                continue
            counterpart = (base_dir / PROFILES_DIRNAME / group / entry.name) if group \
                else (base_dir / PROFILES_DIRNAME / entry.name)
            if not counterpart.is_file():
                unmoved.append(entry.name)
                continue
            try:
                identical = sha256_file(entry) == sha256_file(counterpart)
            except OSError:
                identical = False
            (same if identical else differ).append(entry.name)

        def detail(names):
            return f" ({_short_list(names)})" if "*" in pattern else ""

        if same:
            problems.append(f"{label}{detail(same)}: такой же файл уже в {where} — удалите прежний из"
                            f" {LEGACY_AWG_DIRNAME}/, актуальная копия в {where}")
        if differ:
            problems.append(f"{label}{detail(differ)}: в {LEGACY_AWG_DIRNAME}/ и {where} разное содержимое —"
                            f" оставьте актуальное в {where}, прежнее удалите из {LEGACY_AWG_DIRNAME}/")
        if unmoved:
            problems.append(f"{label}{detail(unmoved)}: в {where} такого нет — запустите Nova из исходников"
                            " (перенос awg → profiles делается на старте)")
        if pattern == "opera_relay.key" and (same or differ or unmoved):
            problems[-1] += (f"\n   Ключ релея нового выпуска кладётся в {PROFILES_DIRNAME}/opera_relay.key:"
                             f" перенос на старте удаляет {LEGACY_AWG_DIRNAME}/opera_relay.key,"
                             f" если в {PROFILES_DIRNAME}/ ключ уже есть.")
    return problems


def require_profile_sources(base_dir: Path) -> None:
    """Проверить, что в profiles/ есть то, без чего установка не работает.

    Не «папка не пустая»: пустая папка группы проходит такую проверку, а
    установщик уезжает без пула WARP и без ключа релея (без ключа релей
    выглядит мёртвым, CLAUDE.md). Проверяются сами файлы.

    Сначала — что упаковываемый nova.pyw вообще читает profiles/. Установщик
    кладёт пул и ключ только туда, а [InstallDelete] стирает
    {app}\\awg\\WARPv*.conf и {app}\\awg\\opera_relay.key: с nova.pyw, который ищет
    их в awg/, каждое обновление теряет пул AWG и ключ релея.
    """
    main_script = base_dir / "nova.pyw"
    try:
        reader_problems = nova_pyw_layout_problems(main_script.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        reader_problems = [f"{main_script} не читается: {exc}"]
    if reader_problems:
        raise RuntimeError(
            f"{main_script} ещё читает прежний {LEGACY_AWG_DIRNAME}/ — установщик с profiles/ собирать нельзя:\n - "
            + "\n - ".join(reader_problems)
            + "\n  Установщик кладёт пул и ключ релея в profiles\\, а [InstallDelete] удаляет"
              " {app}\\awg\\WARPv*.conf и {app}\\awg\\opera_relay.key: такая сборка останется без пула AWG"
              " и без ключа релея (релей выглядит мёртвым)."
            + "\n  Сначала интеграция nova_profiles в nova.pyw. Файлы из awg/ до неё не трогайте:"
              " работающая Nova читает их именно там."
        )

    profiles = base_dir / PROFILES_DIRNAME
    problems = legacy_awg_leftovers(base_dir)

    cloudflare_dir = profiles / "AWG Cloudflare"
    pool = []
    if cloudflare_dir.is_dir():
        pool = [p for p in cloudflare_dir.iterdir()
                if p.is_file() and is_shippable_profile_path(f"AWG Cloudflare/{p.name}")]
    if not pool:
        problems.append(f"нет ни одного WARPv*.conf в {cloudflare_dir}")

    relay_key = profiles / "opera_relay.key"
    if not relay_key.is_file():
        problems.append(f"нет ключа релея {relay_key}")
    else:
        try:
            if not relay_key.read_bytes().strip():
                problems.append(f"ключ релея пуст: {relay_key}")
        except OSError as exc:
            problems.append(f"ключ релея не читается: {relay_key} ({exc})")

    if problems:
        raise RuntimeError("Профили для установщика не готовы:\n - " + "\n - ".join(problems))

    nodes = profiles / "AWG Proton" / "proton_nodes.json"
    if not nodes.is_file():
        print(f"[WARN] {nodes} отсутствует: выпуск Proton останется без запасного списка узлов.")
    print(f"[BUILD] Профили: {len(pool)} WARPv*.conf, ключ релея на месте.")


def require_tor_binaries(base_dir: Path) -> None:
    """Tor не собирается: бинарники кладутся из Tor Expert Bundle руками."""
    tor_dir = base_dir / "bin" / TOR_BIN_SUBDIR
    missing = [str(tor_dir / name) for name in TOR_REQUIRED_FILES if not (tor_dir / name).is_file()]
    if missing:
        raise RuntimeError(
            "Нет бинарников Tor:\n - " + "\n - ".join(missing)
            + "\n  Источник: Tor Expert Bundle (windows x86_64), распаковать в bin/tor и переименовать"
              " tor.exe -> nova-tor.exe, lyrebird.exe -> nova-lyrebird.exe."
            + "\n  Переименование обязательно: установщик убивает помощников по имени образа"
              " и не должен задеть Tor Browser пользователя."
        )
    for name in TOR_OPTIONAL_FILES:
        if not (tor_dir / name).is_file():
            print(f"[WARN] {tor_dir / name} отсутствует — Tor поедет без него.")


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


def stage_routing_settings(src: Path, dst: Path) -> None:
    """Ship a neutral routing file instead of the build machine's own settings.

    The installer hands this file to every new installation, so whatever route
    the developer happened to have selected silently became everyone's default
    — that is how Telegram shipped pinned to WARP. ``system`` is worse: it
    carries game_dvr_capture_backup, a snapshot of *this* machine's registry
    that Nova restores on uninstall.

    Only the machine-independent keys survive staging. Everything else falls
    back to DEFAULT_ROUTING_SETTINGS in nova.pyw, which is the single place the
    defaults should live.
    """
    payload = {}
    try:
        loaded = json.loads(src.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            payload = {key: loaded[key] for key in ("version", "opera_region") if key in loaded}
    except Exception:
        payload = {}
    dst.write_text(json.dumps(payload, ensure_ascii=False, indent=4), encoding="utf-8")


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

    # Cheap file checks first, so a missing key or Tor binary fails before minutes of builds.
    require_tor_binaries(base_dir)
    require_profile_sources(base_dir)

    ensure_tls_terminator(base_dir)
    ensure_nova_engine(base_dir)
    ensure_nova_go(base_dir)


def ensure_tls_terminator(base_dir: Path) -> None:
    """Привести bin/nova-tls-terminator.exe в соответствие с опубликованной сборкой.

    Терминатор собирается не здесь: он единственная часть Nova, которой нужен
    C-тулчейн (BoringSSL, а к нему cmake, MSVC, NASM, LLVM), поэтому его печёт
    GitHub. Сюда он попадает загрузкой, и делается это на месте, а не отдельной
    командой, которую надо помнить: ручной шаг перед сборкой — это шаг, который
    однажды забудут, и релиз молча уедет с прежней формой ClientHello.
    Единственное «тихо», которое здесь допустимо, — когда всё уже актуально.

    Приложение без терминатора работает: релей остаётся на прежнем TLS-пути.
    Поэтому отсутствие сети при уже скачанном файле — не ошибка, а отсутствие
    и файла, и сети — ошибка, потому что иначе установщик соберётся не тем,
    чем его считают.
    """
    if os.environ.get("NOVA_SKIP_TLS_TERMINATOR", "") == "1":
        print("[TLS] NOVA_SKIP_TLS_TERMINATOR=1 — терминатор в сборку не попадёт.")
        return

    sys.path.insert(0, str(base_dir))
    try:
        import fetch_tls_terminator
    except Exception as exc:
        raise RuntimeError(f"Не удалось загрузить fetch_tls_terminator.py: {exc}") from exc

    try:
        path = fetch_tls_terminator.ensure()
    except fetch_tls_terminator.FetchError as exc:
        raise RuntimeError(
            f"Терминатор TLS недоступен: {exc}\n"
            "  Опубликовать сборку: Actions -> Build TLS terminator, галочка publish\n"
            "  Собрать без него:    NOVA_SKIP_TLS_TERMINATOR=1"
        ) from exc

    if not Path(path).exists():
        raise RuntimeError(f"Терминатор TLS не появился по пути {path}.")


def ensure_nova_engine(base_dir: Path) -> None:
    """Собрать bin/nova-engine.exe локально, свежим на каждую сборку.

    В отличие от терминатора, nova-engine (крейт nova-cli) не тянет BoringSSL
    и вообще ни одного C-зависимого крейта — feature `shape` принадлежит
    только nova-tls и в графе зависимостей nova-cli не участвует. Значит
    I3/I5 (терминатор нельзя собрать локально, релиз всегда byte-иной) сюда
    не относятся: `cargo build --release` воспроизводим на обычной машине,
    и у Action enum, в отличие от TLS ClientHello, нет наблюдаемой формы,
    которую цензор мог бы отличить. Поэтому — без публикации на GitHub,
    без fetch-скрипта, просто пересобрать перед каждой упаковкой.

    Отсутствие cargo не валит сборку установщика: команда «Сообщить о
    заблокированном сайте» в этом случае сама сообщит, что nova-engine.exe
    не найден, и ничего не сделает — тот же принцип, что и у терминатора:
    сначала работает установщик, потом одна конкретная функция.
    """
    if os.environ.get("NOVA_SKIP_NOVA_ENGINE", "") == "1":
        print("[Engine] NOVA_SKIP_NOVA_ENGINE=1 — nova-engine.exe в сборку не попадёт.")
        return

    nova_rs_dir = base_dir / "nova-rs"
    if not nova_rs_dir.exists():
        print("[Engine] nova-rs/ отсутствует — nova-engine.exe в сборку не попадёт.")
        return

    cargo = shutil.which("cargo")
    if not cargo:
        print("[Engine] cargo не найден в PATH — nova-engine.exe в сборку не попадёт.")
        return

    print("[Engine] Сборка nova-engine.exe (cargo build --release -p nova-cli)...")
    result = subprocess.run(
        [cargo, "build", "--release", "-p", "nova-cli"],
        cwd=str(nova_rs_dir),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Сборка nova-engine (nova-cli) провалилась:\n"
            f"{result.stdout}\n{result.stderr}\n"
            "  Собрать без него: NOVA_SKIP_NOVA_ENGINE=1"
        )

    built = nova_rs_dir / "target" / "release" / "nova-engine.exe"
    if not built.exists():
        raise RuntimeError(f"cargo build завершился успешно, но {built} не появился.")

    bin_dir = base_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, bin_dir / "nova-engine.exe")
    print(f"[Engine] nova-engine.exe обновлён: {bin_dir / 'nova-engine.exe'}")


def nova_go_build_env(base_env=None) -> dict:
    """Окружение сборки nova-go: всё, от чего зависят байты, задано явно.

    -trimpath, -buildid= и -buildvcs=false делают выход функцией исходников,
    тулчейна и флагов: дерево всегда «грязное» (G29), и без -buildvcs=false
    каждая сборка несла бы свой vcs.modified. GOPROXY=off — сборка не ходит в
    сеть молча; GOTOOLCHAIN=local — не скачивает чужой тулчейн; GOWORK=off —
    go.work где-то выше по дереву не подменяет модули.
    """
    env = dict(os.environ if base_env is None else base_env)
    env.update({
        "CGO_ENABLED": "0",
        "GOOS": "windows",
        "GOARCH": "amd64",
        "GOAMD64": "v1",
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
        "GOWORK": "off",
        "GOFLAGS": "-mod=readonly -trimpath -buildvcs=false",
    })
    return env


def nova_go_build_command(go: str, version: str, out_path: Path) -> list[str]:
    return [
        go, "build",
        f"-ldflags=-s -w -buildid= -X main.version={version}",
        "-o", str(out_path),
        NOVA_GO_PACKAGE,
    ]


def nova_go_missing_replace_dirs(src_dir: Path) -> list[str]:
    """Локальные `replace` из go.mod, чьих каталогов нет на диске.

    Без этой проверки чистый клон падает посреди `go build` сообщением о
    модуле, по которому не понять, что не хватает соседнего репозитория.
    """
    missing = []
    in_block = False
    for raw in (src_dir / "go.mod").read_text(encoding="utf-8").splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            body = line
        elif line.startswith("replace"):
            body = line[len("replace"):].strip()
            if body == "(":
                in_block = True
                continue
        else:
            continue
        if "=>" not in body:
            continue
        right = body.split("=>", 1)[1].strip()
        if right.startswith('"'):
            end = right.find('"', 1)
            target, rest = (right[1:end], right[end + 1:].strip()) if end > 0 else (right[1:], "")
        else:
            target, _, rest = right.partition(" ")
            rest = rest.strip()
        if rest:
            continue  # module@version replacement, resolved from the module cache
        if not (target.startswith(("./", "../", ".\\", "..\\")) or os.path.isabs(target)):
            continue
        if not (src_dir / target).is_dir():
            missing.append(target)
    return missing


def install_binary(built: Path, target: Path) -> None:
    """Положить собранный exe на место так, чтобы запущенная Nova не мешала.

    Тот же приём, что у терминатора (fetch_tls_terminator.py): запись во
    временный файл рядом, затем os.replace; если exe занят работающим
    процессом, Windows не даёт его перезаписать, но даёт переименовать —
    старый уходит в `.old` и удаляется следующей сборкой.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    for suffix in (".old", ".part"):
        leftover = target.with_name(target.name + suffix)
        if leftover.exists():
            try:
                leftover.unlink()
            except OSError as exc:
                print(f"[WARN] Не удалось удалить {leftover}: {exc}")
    part = target.with_name(target.name + ".part")
    shutil.copy2(built, part)
    try:
        os.replace(part, target)
        return
    except PermissionError:
        pass
    except OSError as exc:
        with contextlib.suppress(OSError):
            part.unlink()
        raise RuntimeError(f"Не удалось записать {target}: {exc}") from exc

    aside = target.with_name(target.name + ".old")
    moved_aside = False
    try:
        os.replace(target, aside)
        moved_aside = True
        os.replace(part, target)
        print(f"[Go] {target.name} был запущен; заменён, прежний файл удалится следующей сборкой.")
    except OSError as exc:
        if moved_aside and not target.exists():
            # Never leave bin/ without the helper: put the running image's name back.
            try:
                os.replace(aside, target)
            except OSError as restore_exc:
                print(f"[WARN] Не удалось вернуть {aside} -> {target}: {restore_exc}")
        with contextlib.suppress(OSError):
            part.unlink()
        raise RuntimeError(f"Не удалось заменить {target}: {exc}. Закройте Nova и повторите.") from exc


def smoke_test_nova_go(exe: Path, version: str) -> str:
    """`nova-go.exe version` обязан завершиться успешно и назвать версию сборки."""
    try:
        result = subprocess.run(
            [str(exe), "version"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=NOVA_GO_SMOKE_TIMEOUT, creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"{exe} не запускается: {exc}") from exc
    output = (result.stdout or "").strip()
    if result.returncode != 0 or version not in output.split():
        raise RuntimeError(
            f"{exe} version: код {result.returncode}, вывод {output!r}, ожидалась версия {version}.\n"
            f"{(result.stderr or '').strip()}"
        )
    return output


def build_nova_go(src_dir: Path, out_path: Path, version: str, go: str) -> None:
    # go build runs with cwd=src_dir: a relative -o would land inside nova-go/.
    out_path = Path(out_path).resolve()
    cmd = nova_go_build_command(go, version, out_path)
    try:
        result = subprocess.run(
            cmd, cwd=str(src_dir), env=nova_go_build_env(),
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=NOVA_GO_BUILD_TIMEOUT, creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Сборка nova-go не уложилась в {NOVA_GO_BUILD_TIMEOUT} с.\n  Собрать без него: NOVA_SKIP_NOVA_GO=1"
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"Не удалось запустить {go}: {exc}") from exc
    if result.returncode != 0:
        hint = ""
        if "GOPROXY=off" in (result.stderr or ""):
            # By analogy with G50 (cargo): crates.io/proxy.golang.org are blocked here,
            # Nova's own egress on 1371 is the way out. Unverified for Go.
            hint = ("\n  Модуля нет в кэше, а сеть сборке запрещена (GOPROXY=off). Докачать один раз:"
                    "\n    cd nova-go && HTTPS_PROXY=http://127.0.0.1:1371 go mod download")
        raise RuntimeError(
            f"Сборка nova-go провалилась (код {result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}{hint}\n"
            "  Собрать без него: NOVA_SKIP_NOVA_GO=1"
        )
    if not out_path.is_file():
        raise RuntimeError(f"go build завершился успешно, но {out_path} не появился.")


def ensure_nova_go(base_dir: Path) -> None:
    """Собрать bin/nova-go.exe локально, свежим на каждую сборку.

    Модель nova-engine, а не терминатора: Go при -trimpath/-buildid=/
    -buildvcs=false и CGO_ENABLED=0 воспроизводим, форма ClientHello
    (uTLS, quic-go) задана исходниками, а не машиной сборки, так что
    публиковать бинарник ради формы (I3/I5) незачем.

    В отличие от nova-engine, отсутствие инструментов не пропускается молча:
    MASQUE, генератор WARP и Proton — видимые пользователю функции. Если
    собрать нечем, берётся уже лежащий exe той же версии; иначе сборка
    падает с понятной причиной.
    """
    target = base_dir / "bin" / NOVA_GO_FILENAME
    if os.environ.get("NOVA_SKIP_NOVA_GO", "") == "1":
        state = f"в сборку попадёт имеющийся {target}" if target.is_file() else "nova-go.exe в сборку не попадёт"
        print(f"[Go] NOVA_SKIP_NOVA_GO=1 — без пересборки; {state}.")
        return

    version = read_version(base_dir / "nova.pyw")
    if not re.fullmatch(r"[0-9A-Za-z._+-]+", version):
        raise RuntimeError(f"CURRENT_VERSION {version!r} нельзя передать в -X main.version.")

    src_dir = base_dir / NOVA_GO_SOURCE_DIR
    go = shutil.which("go")
    blocker = ""
    if not (src_dir / "go.mod").is_file():
        blocker = f"{src_dir / 'go.mod'} отсутствует"
    elif not go:
        blocker = "go не найден в PATH"
    else:
        missing = nova_go_missing_replace_dirs(src_dir)
        if missing:
            blocker = "нет каталогов из replace в go.mod: " + ", ".join(missing)

    if blocker:
        if not target.is_file():
            raise RuntimeError(
                f"nova-go.exe не собран, а собрать нечем: {blocker}.\n"
                "  Собрать без него: NOVA_SKIP_NOVA_GO=1"
            )
        # A helper from another release may not speak this nova.pyw's CLI.
        try:
            smoke_test_nova_go(target, version)
        except RuntimeError as exc:
            raise RuntimeError(
                f"{blocker}, а имеющийся {target} не подходит: {exc}\n"
                "  Собрать без него: NOVA_SKIP_NOVA_GO=1"
            ) from exc
        print(f"[Go] {blocker} — беру имеющийся {target} (версия {version} совпадает).")
        return

    try:
        go_version = subprocess.run(
            [go, "env", "GOVERSION"], env=nova_go_build_env(), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=60, creationflags=CREATE_NO_WINDOW,
        ).stdout.strip() or "?"
    except (OSError, subprocess.TimeoutExpired) as exc:
        go_version = f"? ({exc})"
    print(f"[Go] Сборка nova-go.exe {version} ({go_version}, GOAMD64=v1, CGO_ENABLED=0)...")

    with tempfile.TemporaryDirectory(prefix="nova-go-build-") as tmp:
        built = Path(tmp) / NOVA_GO_FILENAME
        build_nova_go(src_dir, built, version, go)
        smoke_test_nova_go(built, version)
        digest = sha256_file(built)
        install_binary(built, target)
    if sha256_file(target) != digest:
        raise RuntimeError(f"{target} после установки не совпадает с собранным файлом.")
    print(f"[Go] nova-go.exe обновлён: {target} (sha256 {digest})")


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
        f"--paths={BASE_DIR / RESOURCE_SOURCE_DIR}",
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
        if folder_name == PROFILES_DIRNAME:
            staged_profiles = stage_profiles(src_dir, dst_dir)
            print(f"[BUILD] profiles: {len(staged_profiles)} файлов по белому списку, "
                  f"группы: {', '.join(PROFILE_GROUP_DIRS)}")
        elif src_dir.exists():
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
        src_file = base_dir / RESOURCE_SOURCE_DIR / filename
        if src_file.exists():
            shutil.copy2(src_file, resources_root / filename)

    # Without this the proxy helpers have no interpreter to run under on a
    # clean install, and every start fails with "Не найден Python launcher".
    copy_python_runtime(resources_root)

    sanitize_user_override_files(staging_dir)

    routing_settings_src = base_dir / "routing_settings.json"
    if routing_settings_src.exists():
        stage_routing_settings(routing_settings_src, staging_dir / "routing_settings.json")

    # Strip unnecessary Python packaging artifacts from staging
    for pattern in ("setuptools", "setuptools-*"):
        for d in resources_root.glob(pattern):
            if d.is_dir():
                safe_rmtree(d)
    for d in resources_root.glob("*.dist-info"):
        if d.is_dir():
            safe_rmtree(d)

    (staging_dir / "temp").mkdir(parents=True, exist_ok=True)

    # Last word before Inno packs the tree: nothing after this line adds files.
    verify_staged_profiles(staging_dir / PROFILES_DIRNAME)
    if (staging_dir / LEGACY_AWG_DIRNAME).exists():
        safe_rmtree(staging_dir / LEGACY_AWG_DIRNAME)
        raise RuntimeError(f"В staging появился прежний {LEGACY_AWG_DIRNAME}/ — профили кладутся только в profiles/.")

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
