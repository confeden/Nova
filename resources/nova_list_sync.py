"""Списки доменов Nova без номеров версий.

* Пустой или отсутствующий список восстанавливается из встроенной копии
  (`resources/builtin/`, её кладёт установщик). Список с содержимым не трогается.
* Эталон — `github.com/confeden/nova_updates`, папка `nova_pc/`: `manifest.json`
  с sha256 каждого `list/*.txt`. Расходящийся локальный файл перезаписывается
  сетевым; обратно на встроенный он не откатывается.
* `ru`/`eu` переименованы в `main`/`second` (`migrate_legacy_names`).
* Домены из `ai.txt` не живут ни в одном списке, кроме `second.txt`
  (`remove_ai_overlaps`, вызывается при сборке установщика).
"""
import os
import json
import re
import hashlib
import requests

from nova_subscriptions import mirror_urls

def extract_domain(line: bytes) -> bytes:
    idx = line.find(b'#')
    if idx != -1:
        line = line[:idx]
    return line.strip().lower()

def parse_domains(data: bytes) -> set:
    domains = set()
    for line in data.splitlines():
        d = extract_domain(line)
        if d:
            domains.add(d)
    return domains

def migrate_legacy_names(base_dir, log=None):
    if log is None: log = lambda m: None
    LEGACY_RENAMES = (("ru.txt","main.txt"),("eu.txt","second.txt"),("u_ru.txt","u_main.txt"),("u_eu.txt","u_second.txt"))
    actions = []
    for d in ("list", "ip"):
        d_path = os.path.join(base_dir, d)
        if not os.path.isdir(d_path):
            continue
        for old, new in LEGACY_RENAMES:
            old_path = os.path.join(d_path, old)
            new_path = os.path.join(d_path, new)
            try:
                if not os.path.isfile(old_path):
                    continue
                if not os.path.isfile(new_path):
                    os.replace(old_path, new_path)
                    msg = f"Переименован {old} в {new} (в {d})"
                    log(msg)
                    actions.append(msg)
                elif old.startswith("u_"):
                    with open(new_path, "rb") as f:
                        new_data = f.read()
                    with open(old_path, "rb") as f:
                        old_data = f.read()
                    new_domains = parse_domains(new_data)
                    crlf = b"\r\n" if b"\r\n" in new_data else b"\n"
                    
                    to_append = []
                    for line in old_data.splitlines():
                        dom = extract_domain(line)
                        if dom and dom not in new_domains:
                            to_append.append(line.strip())
                            new_domains.add(dom)
                    
                    if to_append:
                        with open(new_path, "ab") as f:
                            if new_data and not new_data.endswith(b"\n"):
                                f.write(crlf)
                            for line in to_append:
                                f.write(line + crlf)
                    os.remove(old_path)
                    msg = f"Объединён {old} с {new} (в {d})"
                    log(msg)
                    actions.append(msg)
                else:
                    os.remove(old_path)
                    msg = f"Удалён устаревший {old} (в {d})"
                    log(msg)
                    actions.append(msg)
            except Exception as e:
                log(f"Ошибка миграции {old} в {d}: {e}")
    return actions

VERSION_LINE = re.compile(rb"^\s*#\s*version\s*:", re.I)

def strip_version_header(data: bytes) -> bytes:
    idx = data.find(b'\n')
    if idx == -1:
        first_line = data
        rest = b""
    else:
        first_line = data[:idx+1]
        rest = data[idx+1:]
    if VERSION_LINE.match(first_line):
        return rest
    return data

def strip_version_headers(base_dir, dirs=("list", "ip"), log=None):
    if log is None: log = lambda m: None
    actions = []
    for d in dirs:
        d_path = os.path.join(base_dir, d)
        if not os.path.isdir(d_path):
            continue
        try:
            files = os.listdir(d_path)
        except Exception:
            continue
        for f in files:
            if not f.endswith(".txt"):
                continue
            path = os.path.join(d_path, f)
            try:
                with open(path, "rb") as fp:
                    data = fp.read()
                new_data = strip_version_header(data)
                if new_data != data:
                    tmp = path + ".tmp"
                    with open(tmp, "wb") as fp:
                        fp.write(new_data)
                    os.replace(tmp, path)
                    msg = f"Удалён заголовок версии из {f}"
                    log(msg)
                    actions.append(msg)
            except Exception as e:
                log(f"Ошибка удаления заголовка из {f}: {e}")
    return actions

def strip_json_version(path) -> bool:
    try:
        with open(path, "rb") as f:
            data = f.read()
        try:
            parsed = json.loads(data)
        except Exception:
            return False
        if not isinstance(parsed, dict) or "version" not in parsed:
            return False
        
        pattern = re.compile(rb'^[ \t]*"version"[ \t]*:[ \t]*"[^"\\]*(?:\\.[^"\\]*)*"[ \t]*,?[ \t]*\r?\n?', re.MULTILINE)
        new_data = pattern.sub(b"", data, count=1)
        
        try:
            new_parsed = json.loads(new_data)
        except Exception:
            return False
        
        del parsed["version"]
        if new_parsed != parsed:
            return False
        
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(new_data)
        os.replace(tmp, path)
        return True
    except Exception:
        return False

def is_effectively_empty(path) -> bool:
    try:
        if not os.path.isfile(path):
            return True
        size = os.path.getsize(path)
        if size == 0:
            return True
        with open(path, "rb") as f:
            data = f.read()
        if path.endswith(".json"):
            try:
                parsed = json.loads(data)
                return not bool(parsed)
            except Exception:
                return True
        else:
            for line in data.splitlines():
                if extract_domain(line):
                    return False
            return True
    except Exception:
        return True

def builtin_dir(base_dir) -> str:
    return os.path.join(base_dir, "resources", "builtin")

def restore_from_builtin(base_dir, dirs=("list","ip","strat"), log=None):
    if log is None: log = lambda m: None
    b_dir = builtin_dir(base_dir)
    actions = []
    if not os.path.isdir(b_dir):
        return actions
    for d in dirs:
        src_d = os.path.join(b_dir, d)
        if not os.path.isdir(src_d):
            continue
        dst_d = os.path.join(base_dir, d)
        try:
            os.makedirs(dst_d, exist_ok=True)
            for f in os.listdir(src_d):
                src_path = os.path.join(src_d, f)
                if not os.path.isfile(src_path):
                    continue
                target_path = os.path.join(dst_d, f)
                try:
                    if f.startswith("u_"):
                        if not os.path.isfile(target_path):
                            with open(src_path, "rb") as sp, open(target_path, "wb") as dp:
                                dp.write(sp.read())
                            msg = f"Восстановлен {f} (в {d})"
                            log(msg)
                            actions.append(msg)
                    else:
                        # Встроенный файл без единой записи (только комментарии)
                        # восстанавливать нечем — иначе копия на каждом старте.
                        if is_effectively_empty(target_path) and not is_effectively_empty(src_path):
                            tmp = target_path + ".tmp"
                            with open(src_path, "rb") as sp, open(tmp, "wb") as dp:
                                dp.write(sp.read())
                            os.replace(tmp, target_path)
                            msg = f"Восстановлен встроенный {f} (в {d})"
                            log(msg)
                            actions.append(msg)
                except Exception as e:
                    log(f"Ошибка восстановления {f}: {e}")
        except Exception as e:
            log(f"Ошибка восстановления папки {d}: {e}")
    return actions

def remove_ai_overlaps(list_dir, keep=("ai.txt","second.txt"), log=None):
    if log is None: log = lambda m: None
    ai_path = os.path.join(list_dir, "ai.txt")
    if not os.path.isfile(ai_path):
        return {}
    
    try:
        with open(ai_path, "rb") as f:
            ai_data = f.read()
    except Exception as e:
        log(f"Ошибка чтения ai.txt: {e}")
        return {}
    
    ai_domains = parse_domains(ai_data)
    if not ai_domains:
        return {}
    
    def is_overlap(dom: bytes) -> bool:
        if dom in ai_domains:
            return True
        parts = dom.split(b".")
        for i in range(1, len(parts)):
            suffix = b".".join(parts[i:])
            if suffix in ai_domains:
                return True
        return False

    removed_dict = {}
    try:
        files = os.listdir(list_dir)
    except Exception as e:
        log(f"Ошибка чтения {list_dir}: {e}")
        return {}
    
    import io
    for fname in files:
        if not fname.endswith(".txt"): continue
        if fname in keep: continue
        if fname.startswith("u_"): continue
        
        path = os.path.join(list_dir, fname)
        try:
            with open(path, "rb") as f:
                data = f.read()
            
            f_io = io.BytesIO(data)
            lines = []
            changed = False
            removed = []
            for line in f_io:
                dom = extract_domain(line)
                if dom and is_overlap(dom):
                    changed = True
                    removed.append(dom.decode('utf-8', 'replace'))
                else:
                    lines.append(line)
            
            if changed:
                tmp = path + ".tmp"
                with open(tmp, "wb") as f:
                    for line in lines:
                        f.write(line)
                os.replace(tmp, path)
                removed_dict[fname] = removed
                log(f"Удалены перекрытия из {fname}: {len(removed)} шт.")
        except Exception as e:
            log(f"Ошибка обработки {fname}: {e}")
            
    return removed_dict

REPO = ("confeden", "nova_updates", "main")
REMOTE_DIR = "nova_pc"
MANIFEST_NAME = "manifest.json"

def raw_url(rel):
    return "https://raw.githubusercontent.com/confeden/nova_updates/main/nova_pc/" + rel

def build_manifest(base_dir, rels, generated):
    files = {}
    for rel in rels:
        path = os.path.join(base_dir, rel)
        try:
            with open(path, "rb") as f:
                data = f.read()
            files[rel] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data)
            }
        except Exception:
            pass
    return {"schema": 1, "generated": int(generated), "files": files}

_VALID_REL_RE = re.compile(r"^list/[A-Za-z0-9_.-]+\.txt$")
def valid_rel(rel):
    if ".." in rel: return False
    if not _VALID_REL_RE.match(rel): return False
    name = rel[5:]
    if name.startswith("u_"): return False
    return True

def is_dev_checkout(base_dir):
    return os.path.isdir(os.path.join(base_dir, ".git"))

def fetch_bytes(url, proxies=(), expect_sha256=None, limit=4*1024*1024, timeout=(5,15), session_factory=None):
    """Первое тело, ответившее 200 и (если задан) совпавшее по sha256.

    Маршруты: напрямую, затем каждый прокси; имена — `mirror_urls` (githack,
    raw.githubusercontent.com, jsdelivr). Зеркало с устаревшей копией отсеивается
    сверкой sha256 с манифестом, и перебор идёт дальше.
    """
    if session_factory is None:
        def session_factory(proxy_url):
            session = requests.Session()
            session.trust_env = False
            if proxy_url:
                session.proxies = {"http": proxy_url, "https": proxy_url}
            return session

    for route in [None] + list(proxies or ()):
        session = session_factory(route)
        try:
            for name in mirror_urls(url):
                try:
                    with session.get(name, timeout=timeout, stream=True) as resp:
                        if resp.status_code != 200:
                            continue
                        chunks = []
                        total = 0
                        for chunk in resp.iter_content(chunk_size=64 * 1024):
                            if chunk:
                                chunks.append(chunk)
                                total += len(chunk)
                                if total > limit:
                                    break
                    if total > limit:
                        continue
                    body = b"".join(chunks)
                    if expect_sha256 and hashlib.sha256(body).hexdigest() != expect_sha256:
                        continue
                    return body
                except Exception:
                    continue
        finally:
            session.close()
    return None


def sync_from_network(base_dir, proxies=(), log=None, fetch=None, state_path=None):
    if log is None: log = lambda m: None
    
    if is_dev_checkout(base_dir):
        log("[Списки] Рабочая копия git — сетевые списки не применяются")
        return {"skipped": "dev"}
        
    if fetch is None:
        fetch = fetch_bytes
        
    if state_path is None:
        state_path = os.path.join(base_dir, "temp", "list_sync_state.json")
        
    try:
        manifest_data = fetch(raw_url(MANIFEST_NAME), proxies=proxies)
    except Exception as e:
        log(f"[Списки] Ошибка загрузки манифеста: {e}")
        return {"error": "manifest"}
        
    if not manifest_data:
        return {"error": "manifest"}
        
    try:
        manifest = json.loads(manifest_data)
        if manifest.get("schema") != 1 or not isinstance(manifest.get("files"), dict):
            return {"error": "manifest"}
    except Exception:
        return {"error": "manifest"}
        
    try:
        generated = int(manifest.get("generated", 0))
    except Exception:
        return {"error": "manifest"}

    stored_gen = 0
    try:
        if os.path.isfile(state_path):
            with open(state_path, "r", encoding="utf-8") as f:
                stored = json.load(f)
                stored_gen = int(stored.get("generated", 0))
    except Exception:
        pass
        
    if generated < stored_gen:
        log("[Списки] Зеркало выдало старый манифест, обновление пропущено.")
        return {"skipped": "stale"}
        
    updated = []
    failed = []
    unchanged = 0
    
    files = manifest["files"]
    rels = sorted([r for r in files.keys() if valid_rel(r)])
    
    for rel in rels:
        local_path = os.path.join(base_dir, os.path.normpath(rel))
        entry = files[rel] if isinstance(files[rel], dict) else {}
        expected_sha = str(entry.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            failed.append(rel)
            continue
        
        match = False
        if os.path.isfile(local_path):
            try:
                with open(local_path, "rb") as f:
                    local_data = f.read()
                if hashlib.sha256(local_data).hexdigest() == expected_sha:
                    match = True
            except Exception:
                pass
                
        if match:
            unchanged += 1
            continue
            
        try:
            body = fetch(raw_url(rel), proxies=proxies, expect_sha256=expected_sha)
            if body is not None:
                if any(extract_domain(line) for line in body.splitlines()):
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    tmp = local_path + ".tmp"
                    with open(tmp, "wb") as f:
                        f.write(body)
                    os.replace(tmp, local_path)
                    updated.append(rel)
                else:
                    failed.append(rel)
            else:
                failed.append(rel)
        except Exception:
            failed.append(rel)
            
    if not failed:
        try:
            os.makedirs(os.path.dirname(state_path), exist_ok=True)
            tmp = state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"generated": generated}, f)
            os.replace(tmp, state_path)
        except Exception:
            pass
            
    log(f"[Списки] Сверка с сетью: обновлено {len(updated)}, без изменений {unchanged}, ошибок {len(failed)}")
    return {"updated": updated, "failed": failed, "unchanged": unchanged, "generated": generated}


_AI_CACHE = {"key": None, "domains": frozenset()}


def ai_domains(base_dir):
    """Домены list/ai.txt (кэш по mtime и размеру)."""
    path = os.path.join(base_dir, "list", "ai.txt")
    try:
        st = os.stat(path)
        key = (path, st.st_mtime_ns, st.st_size)
    except OSError:
        return frozenset()
    if _AI_CACHE["key"] != key:
        try:
            with open(path, "rb") as f:
                found = parse_domains(f.read())
            _AI_CACHE["domains"] = frozenset(d.decode("utf-8", "replace") for d in found)
            _AI_CACHE["key"] = key
        except OSError:
            return frozenset()
    return _AI_CACHE["domains"]


def is_ai_domain(base_dir, domain):
    """`domain` совпадает с доменом из ai.txt или является его поддоменом."""
    host = str(domain or "").strip().lower().rstrip(".")
    if not host:
        return False
    known = ai_domains(base_dir)
    parts = host.split(".")
    return any(".".join(parts[i:]) in known for i in range(len(parts)))
