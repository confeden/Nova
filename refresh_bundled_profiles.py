#!/usr/bin/env python3
"""Освежает встроенные профили перед сборкой установщика (как Nova Android).

Каждый установщик должен везти самые свежие профили, какие есть на этом ПК:

* WARP: у общих семян `profiles/AWG Cloudflare/WARPv*.conf` меняется ТОЛЬКО строка
  `Endpoint` (IPv4 host:port). Точки входа берутся из личного набора этой установки
  `WARPgen_*.conf` + `temp/warp-generated-state.json` (проверенные, без сбоев). Ключи,
  Address, S/H, мусор и I1 семян не трогаются, набор PrivateKey до и после сверяется.
  Подсети раскладываются по кругу: десять точек из одной /24 — один рубильник на всех.
* Proton: в начало `profiles/AWG Proton/proton_nodes.json` вливаются узлы текущего
  выданного набора (`*.conf` рядом). Только публичные факты: имя, страна, город, адрес
  входа, публичный ключ пира. Прежние узлы идут следом, всего не больше 150.

Сборку скрипт не ломает: на любой нехватке данных или ошибке возвращает результат и строки
журнала, файлы остаются как были. Запись атомарная (tmp + os.replace), повторный запуск
ничего не меняет.

    python refresh_bundled_profiles.py             освежить
    python refresh_bundled_profiles.py --dry-run   показать, что изменится, ничего не писать
    python refresh_bundled_profiles.py --check     только проверка формата и секретов

Inno.py вызывает refresh() перед require_profile_sources(); NOVA_SKIP_PROFILE_REFRESH=1 отключает.
Код возврата CLI: 0 — готово; 1 — нарушен формат или найден секрет.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path

PROFILES_DIRNAME = "profiles"
CLOUDFLARE_DIRNAME = "AWG Cloudflare"
PROTON_DIRNAME = "AWG Proton"
NODES_FILENAME = "proton_nodes.json"
WARP_STATE_RELPATH = ("temp", "warp-generated-state.json")

MIN_WARP_ENDPOINTS = 16
MIN_WARP_SUBNETS = 3
MAX_WARP_FAILURES = 0        # точка со сбоем на этой сети в семена не идёт
MIN_PROTON_NODES = 30
MIN_PROTON_COUNTRIES = 3
MAX_PROTON_NODES = 150

SEED_NAME = re.compile(r"^WARPv[A-Za-z0-9_.-]*\.conf$")
GEN_NAME = re.compile(r"^WARPgen_[A-Za-z0-9_.-]*\.conf$")
ENDPOINT_LINE = re.compile(rb"^([ \t]*Endpoint[ \t]*=[ \t]*)(\S+)([ \t]*)(?=\r?$)", re.M | re.I)
KEY_LINE = re.compile(rb"^[ \t]*PrivateKey[ \t]*=[ \t]*(\S+)", re.M | re.I)
SEED_ADDRESS = re.compile(rb"^[ \t]*Address[ \t]*=[ \t]*172\.16\.0\.2[ ,\r\n]", re.M | re.I)
PEER_COMMENT = re.compile(r"^#\s*(\S+)\s*\((.*)\)\s*$")
B64_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")

SECRET_KEYS = {
    "private_key", "privatekey", "access_token", "accesstoken", "refresh_token", "token",
    "seed", "seed_b64", "identity", "i1", "certificate", "password", "client_id", "device_id",
}
PROTON_NODE_FIELDS = ("server_name", "country", "city", "entry_ip", "peer_public_key")


def _warn(log, text: str) -> None:
    log(f"WARN: {text}")


# --------------------------------------------------------------------------- общее

def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _subnet(host: str) -> str:
    return ".".join(host.split(".")[:3])


def _ipv4(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 4
    except ValueError:
        return False


def _split_hostport(value: str):
    """`1.2.3.4:5` -> ('1.2.3.4', 5); IPv6 и всё непонятное -> None."""
    host, sep, port = value.rpartition(":")
    if not sep or not host or host.startswith("[") or not port.isdigit():
        return None
    number = int(port)
    if not 1 <= number <= 65535 or not _ipv4(host):
        return None
    return host, number


def _round_robin(groups: "dict[str, list]") -> list:
    groups = collections.OrderedDict((k, list(v)) for k, v in groups.items())
    out: list = []
    while any(groups.values()):
        for key in list(groups):
            if groups[key]:
                out.append(groups[key].pop(0))
    return out


def scan_secrets(value, where: str) -> list:
    """Имена полей из SECRET_KEYS и строки с ключами конфигурации в публичном JSON."""
    found: list = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in SECRET_KEYS:
                found.append(f"{where}: поле «{key}» — секрет, во встроенный список не кладётся")
            found += scan_secrets(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value[:5000]):
            found += scan_secrets(item, f"{where}[{index}]")
    elif isinstance(value, str) and re.search(r"privatekey\s*=", value, re.I):
        found.append(f"{where}: строка с PrivateKey")
    return found


# --------------------------------------------------------------------------- WARP

def _gen_endpoints(base_dir: Path):
    """Проверенные точки входа этой установки. Возвращает (список, замечания)."""
    notes: list = []
    state_path = base_dir.joinpath(*WARP_STATE_RELPATH)
    cf_dir = base_dir / PROFILES_DIRNAME / CLOUDFLARE_DIRNAME
    try:
        state = json.loads(state_path.read_text(encoding="utf-8-sig"))
        profiles = state["profiles"]
        if not isinstance(profiles, dict):
            raise ValueError("profiles не словарь")
    except (OSError, ValueError, KeyError) as exc:
        return [], [f"нет состояния генератора WARP ({state_path.name}: {type(exc).__name__})"]
    seen: set = set()
    out: list = []
    mismatched = failing = foreign = 0
    for name in sorted(profiles):
        info = profiles[name]
        path = cf_dir / f"{name}.conf"
        if not GEN_NAME.match(path.name) or not path.is_file() or not isinstance(info, dict):
            continue                      # в состоянии есть, файла нет (удалён) — не точка
        host = str(info.get("host", "")).strip()
        try:
            port = int(info.get("port", 0))
            failures = int(info.get("failures", 0) or 0)
            rtt = int(info.get("rtt_ms", 0) or 0)
        except (TypeError, ValueError):
            continue
        if not _ipv4(host) or not 1 <= port <= 65535:
            foreign += 1                  # IPv6 в семена не идёт: общий Address у них IPv4
            continue
        if failures > MAX_WARP_FAILURES:
            failing += 1
            continue
        try:
            match = ENDPOINT_LINE.search(path.read_bytes())
        except OSError:
            continue
        if not match or match.group(2).decode("ascii", "replace") != f"{host}:{port}":
            mismatched += 1               # состояние отстало от файла — верить нечему
            continue
        if (host, port) in seen:
            continue
        seen.add((host, port))
        out.append({"host": host, "port": port, "rtt_ms": rtt, "name": name})
    out.sort(key=lambda e: (e["rtt_ms"] <= 0, e["rtt_ms"], e["name"]))
    if failing or foreign or mismatched:
        notes.append(f"отброшено: со сбоями {failing}, не IPv4 {foreign}, не совпали с файлом {mismatched}")
    return out, notes


def rotate_order(endpoints: list) -> list:
    """Точки по кругу по /24: соседние семена получают разные подсети."""
    by_subnet: dict = collections.OrderedDict()
    for endpoint in endpoints:
        by_subnet.setdefault(_subnet(endpoint["host"]), []).append(endpoint)
    return _round_robin(by_subnet)


def _load_seeds(cf_dir: Path):
    """[(path, bytes)] годных семян и список замечаний о негодных."""
    seeds: list = []
    problems: list = []
    if not cf_dir.is_dir():
        return seeds, [f"нет папки {cf_dir}"]
    for path in sorted(cf_dir.iterdir(), key=lambda p: p.name):
        if not SEED_NAME.match(path.name) or not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            problems.append(f"{path.name}: не читается ({type(exc).__name__})")
            continue
        if len(ENDPOINT_LINE.findall(data)) != 1:
            problems.append(f"{path.name}: нужна ровно одна строка Endpoint")
        elif not SEED_ADDRESS.search(data):
            problems.append(f"{path.name}: внутренний адрес не 172.16.0.2")
        elif not KEY_LINE.search(data):
            problems.append(f"{path.name}: нет PrivateKey")
        else:
            seeds.append((path, data))
    return seeds, problems


def _private_keys(blobs) -> set:
    return {m.group(1) for blob in blobs for m in KEY_LINE.finditer(blob)}


def _rewrite_endpoint(data: bytes, host: str, port: int) -> bytes:
    """Меняет только значение Endpoint; всё остальное, включая переводы строк, побайтно прежнее."""
    new = f"{host}:{port}".encode("ascii")
    return ENDPOINT_LINE.sub(lambda m: m.group(1) + new + m.group(3), data, count=1)


def refresh_warp(base_dir: Path, dry_run: bool, log) -> dict:
    result = {"status": "skipped", "changed": 0, "endpoints": 0, "subnets": 0}
    cf_dir = base_dir / PROFILES_DIRNAME / CLOUDFLARE_DIRNAME
    endpoints, notes = _gen_endpoints(base_dir)
    for note in notes:
        log(f"WARP: {note}")
    result["endpoints"] = len(endpoints)
    result["subnets"] = len({_subnet(e["host"]) for e in endpoints})
    if len(endpoints) < MIN_WARP_ENDPOINTS or result["subnets"] < MIN_WARP_SUBNETS:
        _warn(log, f"WARP: пропуск — проверенных точек {len(endpoints)} (нужно {MIN_WARP_ENDPOINTS}), "
                   f"подсетей /24 {result['subnets']} (нужно {MIN_WARP_SUBNETS}); семена остаются как были")
        return result
    seeds, problems = _load_seeds(cf_dir)
    for problem in problems:
        _warn(log, f"WARP: семя пропущено — {problem}")
    if not seeds:
        _warn(log, "WARP: пропуск — нет ни одного годного WARPv*.conf")
        return result

    ordered = rotate_order(endpoints)
    planned: list = []                   # (path, old bytes, new bytes)
    for (path, data), endpoint in zip(seeds, ordered):
        updated = _rewrite_endpoint(data, endpoint["host"], endpoint["port"])
        if updated != data:
            planned.append((path, data, updated))
    # Ключи и всё прочее: после замены набор PrivateKey обязан остаться тем же.
    replaced = {path: new for path, _old, new in planned}
    if _private_keys(d for _, d in seeds) != _private_keys(replaced.get(p, d) for p, d in seeds):
        _warn(log, "WARP: набор PrivateKey семян изменился — прерываю, файлы не тронуты")
        result["status"] = "error"
        return result
    for path, old, new in planned:
        if len(ENDPOINT_LINE.findall(new)) != 1 or _strip_endpoint(old) != _strip_endpoint(new):
            _warn(log, f"WARP: {path.name}: изменилось не только Endpoint — прерываю, файлы не тронуты")
            result["status"] = "error"
            return result

    result["changed"] = len(planned)
    if not planned:
        result["status"] = "unchanged"
        log(f"WARP: семена уже на свежих точках ({min(len(seeds), len(ordered))} из {len(seeds)})")
        return result
    if dry_run:
        result["status"] = "would_update"
        for path, old, new in planned:
            log(f"WARP: (пробный прогон) {path.name}: "
                f"{ENDPOINT_LINE.search(old).group(2).decode()} -> {ENDPOINT_LINE.search(new).group(2).decode()}")
        log(f"WARP: (пробный прогон) обновил бы {len(planned)} семян из {len(seeds)}")
        return result
    written = 0
    try:
        for path, _old, new in planned:
            _atomic_write_bytes(path, new)
            written += 1
    except OSError as exc:
        _warn(log, f"WARP: запись остановилась на {written + 1}-м файле ({type(exc).__name__}: {exc})")
        result["status"] = "error"
        result["changed"] = written
        return result
    result["status"] = "updated"
    log(f"WARP: {len(planned)} семян из {len(seeds)} получили свежие точки входа "
        f"({len(endpoints)} точек, {result['subnets']} подсетей)")
    return result


def _strip_endpoint(data: bytes) -> bytes:
    return ENDPOINT_LINE.sub(lambda m: m.group(1) + b"-" + m.group(3), data, count=1)


# --------------------------------------------------------------------------- Proton

def _valid_node(node) -> bool:
    if not isinstance(node, dict):
        return False
    ip = str(node.get("entry_ip", "")).strip("[]")
    key = str(node.get("peer_public_key", ""))
    try:
        ipaddress.ip_address(ip)
        if not B64_KEY.match(key) or len(base64.b64decode(key, validate=True)) != 32:
            return False
    except (ValueError, binascii.Error):
        return False
    return bool(node.get("country")) and bool(node.get("server_name"))


def _public_node(node: dict) -> dict:
    return {field: str(node.get(field, "")).strip() for field in PROTON_NODE_FIELDS}


def _nodes_from_confs(proton_dir: Path) -> list:
    """Узлы текущего выданного набора: публичные поля из `# NAME (City)`, PublicKey, Endpoint."""
    nodes: list = []
    seen: set = set()
    for path in sorted(proton_dir.glob("*.conf"), key=lambda p: p.name):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        peer = text.partition("[Peer]")[2]
        if not peer:
            continue
        name = city = key = host = ""
        for line in peer.splitlines():
            line = line.strip()
            comment = PEER_COMMENT.match(line)
            if comment and not name:
                name, city = comment.group(1), comment.group(2).strip()
            elif re.match(r"PublicKey\s*=", line, re.I):
                key = line.split("=", 1)[1].strip()
            elif re.match(r"Endpoint\s*=", line, re.I):
                host = line.split("=", 1)[1].strip().rpartition(":")[0].strip("[]")
        node = {"server_name": name, "country": name.split("-", 1)[0], "city": city,
                "entry_ip": host, "peer_public_key": key}
        if not _valid_node(node) or (host, key) in seen:
            continue
        seen.add((host, key))
        nodes.append(node)
    return nodes


def merge_proton(fresh: list, old: list) -> list:
    """Свежие впереди (по кругу по странам), прежние следом; без повторов, не больше 150."""
    seen = {(n["entry_ip"], n["peer_public_key"]) for n in fresh}
    tail = []
    for node in old:
        ident = (node["entry_ip"], node["peer_public_key"])
        if ident not in seen:
            seen.add(ident)
            tail.append(node)

    def spread(nodes):
        groups: dict = collections.OrderedDict()
        for node in nodes:
            groups.setdefault(node["country"], []).append(dict(node))
        return _round_robin(groups)

    return (spread(fresh) + spread(tail))[:MAX_PROTON_NODES]


def refresh_proton(base_dir: Path, dry_run: bool, log) -> dict:
    result = {"status": "skipped", "added": 0, "total": 0}
    proton_dir = base_dir / PROFILES_DIRNAME / PROTON_DIRNAME
    nodes_path = proton_dir / NODES_FILENAME
    if not proton_dir.is_dir():
        _warn(log, f"Proton: пропуск — нет папки {proton_dir}")
        return result
    fresh = [_public_node(n) for n in _nodes_from_confs(proton_dir)]
    countries = {n["country"] for n in fresh}
    if len(fresh) < MIN_PROTON_NODES or len(countries) < MIN_PROTON_COUNTRIES:
        _warn(log, f"Proton: пропуск — свежих узлов {len(fresh)} (нужно {MIN_PROTON_NODES}), "
                   f"стран {len(countries)} (нужно {MIN_PROTON_COUNTRIES}); список остаётся как был")
        return result
    document: dict = {}
    old: list = []
    try:
        document = json.loads(nodes_path.read_text(encoding="utf-8-sig"))
        old = [_public_node(n) for n in document.get("nodes", []) if _valid_node(n)]
    except FileNotFoundError:
        pass
    except (OSError, ValueError, AttributeError) as exc:
        _warn(log, f"Proton: пропуск — {NODES_FILENAME} не читается ({type(exc).__name__})")
        return result
    if not isinstance(document, dict):
        _warn(log, f"Proton: пропуск — {NODES_FILENAME} не объект JSON")
        return result
    merged = merge_proton(fresh, old)
    problems = scan_secrets(merged, "proton_nodes")
    if problems:
        _warn(log, "Proton: " + "; ".join(problems[:3]) + " — прерываю")
        result["status"] = "error"
        return result
    result["total"] = len(merged)
    old_ids = {(n["entry_ip"], n["peer_public_key"]) for n in old}
    result["added"] = sum(1 for n in merged if (n["entry_ip"], n["peer_public_key"]) not in old_ids)
    if merged == old and document.get("nodes") == old:
        result["status"] = "unchanged"
        log(f"Proton: список уже свежий ({len(merged)} узлов)")
        return result
    record = {
        "generated_at": int(time.time() * 1000),
        "source": document.get("source") or "vpn-api.proton.me /vpn/logicals?Tier=0",
        "note": document.get("note")
        or "Only public server facts. No keys, no account: each device registers its own.",
        "nodes": merged,
    }
    if dry_run:
        result["status"] = "would_update"
        log(f"Proton: (пробный прогон) в списке стало бы {len(merged)} узлов "
            f"(новых {result['added']}, свежих из выдачи {len(fresh)})")
        return result
    body = (json.dumps(record, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    try:
        _atomic_write_bytes(nodes_path, body)
    except OSError as exc:
        _warn(log, f"Proton: запись {NODES_FILENAME} не удалась ({type(exc).__name__}: {exc})")
        result["status"] = "error"
        return result
    result["status"] = "updated"
    log(f"Proton: {len(merged)} узлов в списке (новых {result['added']}, стран {len(countries)} в свежем наборе)")
    return result


# --------------------------------------------------------------------------- вход

def refresh(base_dir, dry_run: bool = False, log=print) -> dict:
    """Освежить семена WARP и список Proton. Не бросает: проблемы идут в журнал и в результат."""
    base = Path(base_dir)
    result = {"warp": {"status": "error", "changed": 0, "endpoints": 0, "subnets": 0},
              "proton": {"status": "error", "added": 0, "total": 0}}
    for key, step in (("warp", refresh_warp), ("proton", refresh_proton)):
        try:
            result[key] = step(base, dry_run, log)
        except Exception as exc:  # noqa: BLE001 — освежение не должно ронять сборку
            _warn(log, f"{key}: непредвиденная ошибка {type(exc).__name__}: {exc}")
    return result


def check(base_dir) -> list:
    """Формат встроенных профилей: список проблем (пустой — всё в порядке)."""
    base = Path(base_dir)
    problems: list = []
    seeds, seed_problems = _load_seeds(base / PROFILES_DIRNAME / CLOUDFLARE_DIRNAME)
    problems += seed_problems
    if not seeds:
        problems.append("нет ни одного годного WARPv*.conf")
    nodes_path = base / PROFILES_DIRNAME / PROTON_DIRNAME / NODES_FILENAME
    try:
        document = json.loads(nodes_path.read_text(encoding="utf-8-sig"))
        nodes = document["nodes"]
        if not isinstance(nodes, list):
            raise ValueError("nodes не список")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        problems.append(f"{NODES_FILENAME}: не читается ({type(exc).__name__})")
        return problems
    problems += scan_secrets(document, NODES_FILENAME)
    for index, node in enumerate(nodes):
        if not _valid_node(node):
            problems.append(f"{NODES_FILENAME}: узел {index} негоден")
        elif set(node) - set(PROTON_NODE_FIELDS):
            problems.append(f"{NODES_FILENAME}: узел {index}: лишние поля {sorted(set(node) - set(PROTON_NODE_FIELDS))}")
    if len(nodes) > MAX_PROTON_NODES:
        problems.append(f"{NODES_FILENAME}: узлов {len(nodes)}, больше {MAX_PROTON_NODES}")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="показать, что изменится, и ничего не записывать")
    parser.add_argument("--check", action="store_true", help="только проверка формата и секретов")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    base = Path(__file__).resolve().parent
    if args.check:
        problems = check(base)
        for problem in problems:
            print(f"ОШИБКА: {problem}")
        if not problems:
            print("формат встроенных профилей в порядке, секретов нет")
        return 1 if problems else 0
    result = refresh(base, dry_run=args.dry_run, log=lambda line: print(f"[profiles] {line}"))
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
