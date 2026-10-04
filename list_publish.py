"""Выгрузка list/*.txt (кроме u_*) в github.com/confeden/nova_updates, папка nova_pc/.

Клиенты сверяют свои списки с nova_pc/manifest.json по sha256 и считают сетевые
самыми свежими. Рабочая копия git (ПК владельца) сама с сетью не сверяется —
списки правятся здесь руками и уходят в сеть отсюда.

    python list_publish.py            выгрузить один раз
    pythonw list_publish.py --watch   следить за list/ и выгружать каждое изменение
    python list_publish.py --install  запускать --watch при входе в Windows
    python list_publish.py --uninstall

Inno.py вызывает publish_lists() перед сборкой. Обе дороги берут одну и ту же
блокировку temp/_nova_updates.lock, поэтому сборка и наблюдатель не делят клон.
Журнал наблюдателя — temp/list_publish.log.
"""
import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "resources"))
import nova_list_sync  # noqa: E402
from nova_metadata import read_project_version  # noqa: E402

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
REPO_URL = "https://github.com/confeden/nova_updates.git"
POLL_SEC = 3
QUIET_SEC = 20            # файл должен не меняться столько, прежде чем уйти в сеть
RETRY_SEC = 300
LOCK_WAIT_SEC = 600
PUSH_ATTEMPTS = 3
STARTUP_NAME = "Nova list_publish.lnk"


def _run_git(args, cwd=None):
    try:
        res = subprocess.run(
            ["git"] + args, cwd=cwd, capture_output=True, text=True,
            encoding="utf-8", check=True, creationflags=CREATE_NO_WINDOW,
        )
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{(e.stderr or '').strip()}")


@contextlib.contextmanager
def _clone_lock(base_dir: Path):
    import msvcrt
    lock_path = base_dir / "temp" / "_nova_updates.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a+b") as fh:
        deadline = time.monotonic() + LOCK_WAIT_SEC
        while True:
            try:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError(f"клон nova_updates занят дольше {LOCK_WAIT_SEC} с ({lock_path})")
                time.sleep(2)
        try:
            yield
        finally:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)


def _local_lists(base_dir: Path):
    return sorted(p for p in (base_dir / "list").glob("*.txt") if not p.name.startswith("u_"))


def _stage(base_dir: Path, clone_dir: Path, version: str) -> bool:
    """Разложить списки и манифест в клоне. True — есть что коммитить."""
    remote_dir = clone_dir / nova_list_sync.REMOTE_DIR
    remote_list_dir = remote_dir / "list"
    remote_list_dir.mkdir(parents=True, exist_ok=True)
    # Байт-в-байт (CRLF): иначе git переведёт концы строк и sha256 не сойдётся (G95).
    attributes = remote_dir / ".gitattributes"
    attributes_text = b"* -text\n"
    attributes_changed = not attributes.exists() or attributes.read_bytes() != attributes_text
    if attributes_changed:
        attributes.write_bytes(attributes_text)

    local_files = _local_lists(base_dir)
    local_names = {f.name for f in local_files}
    changed = attributes_changed
    for txt in local_files:
        remote_txt = remote_list_dir / txt.name
        if not remote_txt.exists() or remote_txt.read_bytes() != txt.read_bytes():
            shutil.copyfile(txt, remote_txt)
            changed = True
    for remote_txt in remote_list_dir.glob("*.txt"):
        if remote_txt.name not in local_names:
            remote_txt.unlink()
            changed = True

    rels = [f"list/{name}" for name in sorted(local_names)]
    manifest_files = nova_list_sync.build_manifest(str(base_dir), rels, 0)["files"]
    manifest_path = remote_dir / nova_list_sync.MANIFEST_NAME
    old_files = {}
    if manifest_path.exists():
        try:
            old_files = json.loads(manifest_path.read_text(encoding="utf-8")).get("files", {})
        except Exception:
            pass
    if not changed and old_files == manifest_files:
        return False
    manifest = {"schema": 1, "generated": int(time.time()), "version": version, "files": manifest_files}
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    return True


def publish_lists(base_dir: Path = BASE_DIR, version: str = "", log=print) -> bool:
    """Выгрузить списки. True — был коммит, False — nova_updates уже актуален."""
    base_dir = Path(base_dir)
    version = version or str(read_project_version(base_dir, default="") or "").strip() or "?"
    removed = nova_list_sync.remove_ai_overlaps(str(base_dir / "list"), keep=("ai.txt", "second.txt"))
    for file_name, removed_domains in removed.items():
        if removed_domains:
            log(f"[Списки] {file_name}: удалено {len(removed_domains)} дублей AI-доменов")

    clone_dir = base_dir / "temp" / "_nova_updates"
    with _clone_lock(base_dir):
        for attempt in range(1, PUSH_ATTEMPTS + 1):
            if not (clone_dir / ".git").exists():
                if clone_dir.exists():
                    shutil.rmtree(clone_dir, ignore_errors=True)
                _run_git(["-c", "core.autocrlf=false", "clone", "--depth", "1", REPO_URL, str(clone_dir)])
            _run_git(["-C", str(clone_dir), "config", "core.autocrlf", "false"])
            _run_git(["-C", str(clone_dir), "fetch", "--depth", "1", "origin", "main"])
            _run_git(["-C", str(clone_dir), "reset", "--hard", "origin/main"])

            if not _stage(base_dir, clone_dir, version):
                log("[Списки] nova_updates уже актуален")
                return False
            _run_git(["-C", str(clone_dir), "add", "-A", nova_list_sync.REMOTE_DIR])
            _run_git(["-C", str(clone_dir), "commit", "-m", f"Nova PC: списки {version}"])
            try:
                _run_git(["-C", str(clone_dir), "push", "origin", "HEAD:main"])
            except RuntimeError as exc:
                # nova_updates пишут и другие (workflow Novagram) — main мог уйти вперёд.
                if attempt == PUSH_ATTEMPTS:
                    raise
                log(f"[Списки] push отклонён, повтор {attempt + 1}/{PUSH_ATTEMPTS}: {exc}")
                continue
            head = _run_git(["-C", str(clone_dir), "rev-parse", "--short", "HEAD"])
            log(f"[Списки] Синхронизация успешна, коммит {head}")
            return True
    return False


# ---------------- наблюдатель ----------------

def _signature(base_dir: Path):
    sig = []
    for p in _local_lists(base_dir):
        try:
            st = p.stat()
            sig.append((p.name, st.st_size, st.st_mtime_ns))
        except OSError:
            pass
    return tuple(sig)


def _single_instance() -> bool:
    import ctypes
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, False, "Local\\NovaListPublishWatch")
    globals()["_MUTEX"] = handle  # держать до выхода процесса
    return kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def watch(base_dir: Path = BASE_DIR):
    log_path = base_dir / "temp" / "list_publish.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.exists() and log_path.stat().st_size > 512 * 1024:
        log_path.replace(log_path.with_suffix(".log.1"))

    def log(msg):
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        if sys.stdout:
            print(line, flush=True)

    if not _single_instance():
        log("[Списки] наблюдатель уже запущен, этот экземпляр выходит")
        return
    log(f"[Списки] наблюдатель запущен: {base_dir / 'list'}")

    # Первый проход — сразу: правки, сделанные пока наблюдатель не работал.
    published = None
    last_seen = _signature(base_dir)
    changed_at = time.monotonic() - QUIET_SEC
    retry_at = 0.0
    while True:
        sig = _signature(base_dir)
        now = time.monotonic()
        if sig != last_seen:
            last_seen, changed_at = sig, now
        if sig != published and now - changed_at >= QUIET_SEC and now >= retry_at:
            try:
                publish_lists(base_dir, log=log)
                # remove_ai_overlaps мог переписать файлы — это уже выгружено.
                published = last_seen = _signature(base_dir)
            except Exception as exc:
                log(f"[Списки] выгрузка не удалась, повтор через {RETRY_SEC} с: {exc}")
                retry_at = now + RETRY_SEC
        time.sleep(POLL_SEC)


# ---------------- автозапуск ----------------

def _startup_link() -> Path:
    return Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup" / STARTUP_NAME


def install():
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        raise SystemExit(f"не найден {pythonw}")
    link = _startup_link()
    ps = (
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:NOVA_LNK);"
        "$s.TargetPath=$env:NOVA_PYW;$s.Arguments=$env:NOVA_ARGS;"
        "$s.WorkingDirectory=$env:NOVA_CWD;$s.Save()"
    )
    env = dict(os.environ, NOVA_LNK=str(link), NOVA_PYW=str(pythonw),
               NOVA_ARGS=f'"{Path(__file__).resolve()}" --watch', NOVA_CWD=str(BASE_DIR))
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], env=env, check=True,
                   creationflags=CREATE_NO_WINDOW)
    subprocess.Popen([str(pythonw), str(Path(__file__).resolve()), "--watch"], cwd=str(BASE_DIR),
                     creationflags=CREATE_NO_WINDOW | getattr(subprocess, "DETACHED_PROCESS", 0))
    print(f"Автозапуск: {link}\nНаблюдатель запущен, журнал: {BASE_DIR / 'temp' / 'list_publish.log'}")


def uninstall():
    link = _startup_link()
    if link.exists():
        link.unlink()
    print(f"Автозапуск снят ({link}). Уже запущенный наблюдатель живёт до выхода из Windows.")


if __name__ == "__main__":
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--watch":
        watch()
    elif arg == "--install":
        install()
    elif arg == "--uninstall":
        uninstall()
    else:
        publish_lists()
