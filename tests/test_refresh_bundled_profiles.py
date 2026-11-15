"""Освежение встроенных профилей: что меняется в семенах WARP и списке Proton, а что нет.

Все данные — во временной папке, настоящие profiles/ не трогаются.
"""

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import refresh_bundled_profiles as rbp  # noqa: E402

SEED_TEMPLATE = (
    "[Interface]\r\nPrivateKey = {key}\r\nAddress = 172.16.0.2, 2606:4700:110:1::1\r\nS1 = 0\r\nJc = 4\r\n"
    "I1 = <b 0xaabb>\r\n\r\n[Peer]\r\nPublicKey = peerpeer\r\nAllowedIPs = 0.0.0.0/0\r\n"
    "Endpoint = {endpoint}\r\n"
)
GEN_TEMPLATE = "[Interface]\nPrivateKey = GENSECRET{n}\nAddress = 172.16.0.2\n\n[Peer]\nEndpoint = {endpoint}\n"


def _key(n: int) -> str:
    return base64.b64encode(bytes([n]) * 32).decode()


def _write_gen(base: Path, count: int, *, subnets: int = 4, failures: dict | None = None, v6: int = 0):
    cf = base / "profiles" / "AWG Cloudflare"
    cf.mkdir(parents=True, exist_ok=True)
    (base / "temp").mkdir(exist_ok=True)
    state = {}
    for n in range(count):
        name = f"WARPgen_{n + 1:02d}"
        host = f"2606:4700::{n + 1}" if n < v6 else f"188.114.{90 + n % subnets}.{n + 1}"
        port = 2000 + n
        state[name] = {"host": host, "port": port, "rtt_ms": 40 + n,
                       "failures": (failures or {}).get(name, 0)}
        shown = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        (cf / f"{name}.conf").write_text(GEN_TEMPLATE.format(n=n, endpoint=shown), encoding="utf-8", newline="")
    (base / "temp" / "warp-generated-state.json").write_text(json.dumps({"profiles": state}), encoding="utf-8")


def _write_seeds(base: Path, count: int = 6):
    cf = base / "profiles" / "AWG Cloudflare"
    cf.mkdir(parents=True, exist_ok=True)
    for n in range(count):
        text = SEED_TEMPLATE.format(key=_key(n % 3), endpoint=f"8.8.{n}.1:{900 + n}")
        (cf / f"WARPv1_{n + 10}.conf").write_bytes(text.encode("utf-8"))


def _seed_bytes(base: Path) -> dict:
    cf = base / "profiles" / "AWG Cloudflare"
    return {p.name: p.read_bytes() for p in sorted(cf.glob("WARPv*.conf"))}


def _node(n: int, country: str) -> dict:
    return {"server_name": f"{country}-FREE#{n}", "country": country, "city": f"City{n}",
            "entry_ip": f"185.1.{n % 250}.{n % 200 + 1}", "peer_public_key": _key(n % 250 + 1)}


def _write_proton_confs(base: Path, nodes: list):
    pd = base / "profiles" / "AWG Proton"
    pd.mkdir(parents=True, exist_ok=True)
    for i, node in enumerate(nodes):
        (pd / f"{node['server_name'].replace('#', '-')}.conf").write_text(
            "[Interface]\nPrivateKey = PROTONSECRET\nAddress = 10.2.0.2/32\nI1 = <b 0x00>\n\n[Peer]\n"
            f"# {node['server_name']} ({node['city']})\nPublicKey = {node['peer_public_key']}\n"
            f"AllowedIPs = 0.0.0.0/0\nEndpoint = {node['entry_ip']}:443\n", encoding="utf-8")


def _write_nodes_file(base: Path, nodes: list):
    pd = base / "profiles" / "AWG Proton"
    pd.mkdir(parents=True, exist_ok=True)
    doc = {"generated_at": 1, "source": "s", "note": "n", "nodes": nodes}
    (pd / "proton_nodes.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")


def _fresh_nodes(count=40, countries=("CA", "CH", "JP", "NL")):
    return [_node(n, countries[n % len(countries)]) for n in range(1, count + 1)]


def _quiet():
    lines = []
    return lines, lines.append


# ------------------------------------------------------------------------------ WARP

def test_warp_changes_only_endpoint(tmp_path):
    _write_gen(tmp_path, 20)
    _write_seeds(tmp_path, 6)
    before = _seed_bytes(tmp_path)
    lines, log = _quiet()
    result = rbp.refresh_warp(tmp_path, False, log)
    after = _seed_bytes(tmp_path)
    assert result["status"] == "updated" and result["changed"] == 6
    for name, old in before.items():
        new = after[name]
        assert new != old
        assert b"\r\n" in new and b"\n" not in new.replace(b"\r\n", b"")      # переводы строк целы
        strip = lambda b: rbp.ENDPOINT_LINE.sub(b"", b)  # noqa: E731
        assert strip(old) == strip(new)                                        # кроме Endpoint — ни байта
        assert rbp.ENDPOINT_LINE.search(new).group(2).startswith(b"188.114.")
    assert rbp._private_keys(before.values()) == rbp._private_keys(after.values())
    assert not any(p.name.startswith(".") for p in (tmp_path / "profiles" / "AWG Cloudflare").iterdir())


def test_warp_rotation_spreads_subnets_and_skips_bad_endpoints(tmp_path):
    _write_gen(tmp_path, 20, subnets=4, failures={"WARPgen_05": 1}, v6=2)
    _write_seeds(tmp_path, 4)
    result = rbp.refresh_warp(tmp_path, False, lambda _l: None)
    # 20 - 2 IPv6 - 1 со сбоем
    assert result["endpoints"] == 17
    used = [rbp.ENDPOINT_LINE.search(b).group(2).decode() for b in _seed_bytes(tmp_path).values()]
    assert len({rbp._subnet(u.split(":")[0]) for u in used}) == 4              # соседние семена — разные /24
    assert not any("2606" in u for u in used)
    assert "188.114.90.5:2004" not in used                                     # WARPgen_05 со сбоем


def test_warp_key_set_guard(tmp_path, monkeypatch):
    _write_gen(tmp_path, 20)
    _write_seeds(tmp_path, 3)
    before = _seed_bytes(tmp_path)
    # Подменённая замена, трогающая ключ: сторож обязан отказаться и не записать ничего.
    monkeypatch.setattr(rbp, "_rewrite_endpoint", lambda data, h, p: data.replace(_key(0).encode(), _key(9).encode()))
    lines, log = _quiet()
    result = rbp.refresh_warp(tmp_path, False, log)
    assert result["status"] == "error"
    assert any("PrivateKey" in line for line in lines)
    assert _seed_bytes(tmp_path) == before


def test_warp_threshold_skip(tmp_path):
    _write_gen(tmp_path, 15)                                                   # < 16 точек
    _write_seeds(tmp_path, 3)
    before = _seed_bytes(tmp_path)
    lines, log = _quiet()
    assert rbp.refresh_warp(tmp_path, False, log)["status"] == "skipped"
    assert _seed_bytes(tmp_path) == before
    assert any(line.startswith("WARN: ") for line in lines)


def test_warp_needs_three_subnets(tmp_path):
    _write_gen(tmp_path, 20, subnets=2)
    _write_seeds(tmp_path, 3)
    before = _seed_bytes(tmp_path)
    result = rbp.refresh_warp(tmp_path, False, lambda _l: None)
    assert result["status"] == "skipped" and result["subnets"] == 2
    assert _seed_bytes(tmp_path) == before


def test_warp_no_state_file_skips(tmp_path):
    _write_seeds(tmp_path, 3)
    assert rbp.refresh_warp(tmp_path, False, lambda _l: None)["status"] == "skipped"


def test_warp_state_without_file_is_not_an_endpoint(tmp_path):
    _write_gen(tmp_path, 17)
    (tmp_path / "profiles" / "AWG Cloudflare" / "WARPgen_17.conf").unlink()
    _write_seeds(tmp_path, 3)
    assert rbp.refresh_warp(tmp_path, False, lambda _l: None)["endpoints"] == 16


def test_warp_idempotent(tmp_path):
    _write_gen(tmp_path, 20)
    _write_seeds(tmp_path, 6)
    assert rbp.refresh_warp(tmp_path, False, lambda _l: None)["status"] == "updated"
    once = _seed_bytes(tmp_path)
    again = rbp.refresh_warp(tmp_path, False, lambda _l: None)
    assert again["status"] == "unchanged" and again["changed"] == 0
    assert _seed_bytes(tmp_path) == once


# ------------------------------------------------------------------------------ Proton

def test_proton_merge_order_cap_and_dedup():
    fresh = [_node(n, "CA" if n % 2 else "NL") for n in range(1, 7)]
    old = [_node(100 + n, "US") for n in range(200)] + [dict(fresh[0])]
    merged = rbp.merge_proton(fresh, old)
    assert len(merged) == rbp.MAX_PROTON_NODES
    assert [n["server_name"] for n in merged[:6]] == [
        fresh[0]["server_name"], fresh[1]["server_name"], fresh[2]["server_name"],
        fresh[3]["server_name"], fresh[4]["server_name"], fresh[5]["server_name"]]
    assert all(n["country"] == "US" for n in merged[6:])
    assert len({(n["entry_ip"], n["peer_public_key"]) for n in merged}) == len(merged)


def test_proton_refresh_merges_fresh_in_front_public_fields_only(tmp_path):
    fresh = _fresh_nodes(40)
    old = [_node(500 + n, "RO") for n in range(5)]
    _write_proton_confs(tmp_path, fresh)
    _write_nodes_file(tmp_path, old)
    result = rbp.refresh_proton(tmp_path, False, lambda _l: None)
    assert result["status"] == "updated" and result["total"] == 45 and result["added"] == 40
    text = (tmp_path / "profiles" / "AWG Proton" / "proton_nodes.json").read_text(encoding="utf-8")
    doc = json.loads(text)
    assert "PROTONSECRET" not in text and "PrivateKey" not in text and "I1" not in text
    assert all(set(n) == set(rbp.PROTON_NODE_FIELDS) for n in doc["nodes"])
    assert doc["nodes"][0]["country"] in {"CA", "CH", "JP", "NL"}
    assert [n["country"] for n in doc["nodes"][-5:]] == ["RO"] * 5             # прежние — в хвосте
    assert doc["note"] == "n" and doc["source"] == "s"
    assert not any("PrivateKey" in p or "узел" in p for p in rbp.check(tmp_path))


def test_proton_threshold_skip(tmp_path):
    _write_proton_confs(tmp_path, _fresh_nodes(29))                            # < 30
    _write_nodes_file(tmp_path, [_node(1, "RO")])
    before = (tmp_path / "profiles" / "AWG Proton" / "proton_nodes.json").read_bytes()
    assert rbp.refresh_proton(tmp_path, False, lambda _l: None)["status"] == "skipped"
    assert (tmp_path / "profiles" / "AWG Proton" / "proton_nodes.json").read_bytes() == before


def test_proton_needs_three_countries(tmp_path):
    _write_proton_confs(tmp_path, _fresh_nodes(40, countries=("CA", "CH")))
    _write_nodes_file(tmp_path, [])
    assert rbp.refresh_proton(tmp_path, False, lambda _l: None)["status"] == "skipped"


def test_proton_idempotent(tmp_path):
    _write_proton_confs(tmp_path, _fresh_nodes(40))
    _write_nodes_file(tmp_path, [_node(500 + n, "RO") for n in range(5)])
    assert rbp.refresh_proton(tmp_path, False, lambda _l: None)["status"] == "updated"
    path = tmp_path / "profiles" / "AWG Proton" / "proton_nodes.json"
    once = path.read_bytes()
    assert rbp.refresh_proton(tmp_path, False, lambda _l: None)["status"] == "unchanged"
    assert path.read_bytes() == once


def test_secret_scan_rejects_private_fields():
    assert rbp.scan_secrets([{"server_name": "x", "private_key": "k"}], "n")
    assert rbp.scan_secrets({"nodes": [{"city": "PrivateKey = abc"}]}, "n")
    assert not rbp.scan_secrets({"nodes": [_node(1, "CA")]}, "n")


# ------------------------------------------------------------------------------ вход

def test_dry_run_writes_nothing(tmp_path):
    _write_gen(tmp_path, 20)
    _write_seeds(tmp_path, 6)
    _write_proton_confs(tmp_path, _fresh_nodes(40))
    _write_nodes_file(tmp_path, [_node(500, "RO")])
    snapshot = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    result = rbp.refresh(tmp_path, dry_run=True, log=lambda _l: None)
    assert result["warp"]["status"] == "would_update" and result["warp"]["changed"] == 6
    assert result["proton"]["status"] == "would_update"
    assert {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == snapshot


def test_refresh_never_raises_on_empty_tree(tmp_path):
    result = rbp.refresh(tmp_path, log=lambda _l: None)
    assert result["warp"]["status"] in {"skipped", "error"}
    assert result["proton"]["status"] in {"skipped", "error"}


def test_refresh_survives_step_exception(tmp_path, monkeypatch):
    def boom(*_a):
        raise RuntimeError("boom")
    monkeypatch.setattr(rbp, "refresh_warp", boom)
    lines, log = _quiet()
    result = rbp.refresh(tmp_path, log=log)
    assert result["warp"]["status"] == "error"
    assert any(line.startswith("WARN: ") and "boom" in line for line in lines)
