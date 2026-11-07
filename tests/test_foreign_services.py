import ast
from pathlib import Path

import nova_foreign_services as fs

ROOT = Path(__file__).resolve().parents[1]
BIN = r"D:\Apps\Nova\resources\bin"


def test_image_file_from_command_forms():
    assert fs.image_file_from_command('"D:\\Apps\\Nova\\resources\\bin\\warp-svc.exe"') == r"D:\Apps\Nova\resources\bin\warp-svc.exe"
    assert fs.image_file_from_command(r"\??\D:\Apps\Nova\resources\bin\WinDivert64.sys") == r"D:\Apps\Nova\resources\bin\WinDivert64.sys"
    assert fs.image_file_from_command(r"C:\Windows\System32\svchost.exe -k netsvcs") == r"C:\Windows\System32\svchost.exe"
    assert fs.image_file_from_command('"C:\\Program Files\\Cloudflare\\Cloudflare WARP\\warp-svc.exe" --flag') == r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe"


def test_path_in_dir_is_a_prefix_on_whole_components():
    assert fs.path_in_dir(BIN + r"\warp-svc.exe", BIN)
    assert fs.path_in_dir(BIN.upper() + r"\WARP-SVC.EXE", BIN)
    assert not fs.path_in_dir(BIN + r"x\warp-svc.exe", BIN)
    assert not fs.path_in_dir(r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe", BIN)
    assert not fs.path_in_dir("", BIN)


def _stub_service(monkeypatch, images, calls):
    monkeypatch.setattr(fs, "service_image_path", lambda name: images.get(name))
    monkeypatch.setattr(fs, "_wait_stopped", lambda name, timeout: True)

    def fake_sc(*args, timeout=8):
        calls.append(args)
        return 0, ""
    monkeypatch.setattr(fs, "run_sc", fake_sc)


def test_official_service_is_never_touched(monkeypatch):
    calls = []
    _stub_service(monkeypatch, {"CloudflareWARP": r'"C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe"'}, calls)
    assert fs.release_legacy_warp_service(BIN) == ""
    assert calls == []


def test_taken_over_service_goes_back_to_the_official_binary(monkeypatch):
    calls = []
    _stub_service(monkeypatch, {"CloudflareWARP": f'"{BIN}\\warp-svc.exe"'}, calls)
    official = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe"
    monkeypatch.setattr(fs, "official_warp_svc_path", lambda: official)
    assert fs.release_legacy_warp_service(BIN) == "restored"
    config = [c for c in calls if c[0] == "config"][0]
    assert config[config.index("binPath=") + 1] == f'"{official}"'
    assert not any(c[0] == "delete" for c in calls)


def test_taken_over_service_without_official_client_is_deleted(monkeypatch):
    calls = []
    _stub_service(monkeypatch, {"CloudflareWARP": f'"{BIN}\\warp-svc.exe"'}, calls)
    monkeypatch.setattr(fs, "official_warp_svc_path", lambda: "")
    assert fs.release_legacy_warp_service(BIN) == "deleted"
    assert ("delete", "CloudflareWARP") in calls


def test_windivert_deleted_only_when_it_points_at_nova(monkeypatch):
    calls = []
    _stub_service(monkeypatch, {"WinDivert": r"\??\C:\Tools\zapret\WinDivert64.sys"}, calls)
    assert fs.delete_windivert_if_nova(BIN) is False
    assert calls == []
    _stub_service(monkeypatch, {"WinDivert": f"\\??\\{BIN}\\WinDivert64.sys"}, calls)
    assert fs.delete_windivert_if_nova(BIN) is True
    assert ("delete", "WinDivert") in calls
    assert not any(call[0] == "stop" for call in calls)


def test_repair_never_reconfigures_a_running_or_foreign_driver(monkeypatch):
    calls = []
    _stub_service(monkeypatch, {"WinDivert": f"\\??\\{BIN}\\WinDivert64.sys"}, calls)
    assert not fs.windivert_repair_allowed(BIN, {"running": True})
    assert not fs.windivert_repair_allowed(BIN, {"stopped": True, "pending_delete": True})
    assert fs.windivert_repair_allowed(BIN, {"stopped": True})
    assert fs.windivert_repair_allowed(BIN, {"missing": True})
    _stub_service(monkeypatch, {"WinDivert": r"C:\Tools\zapret\WinDivert64.sys"}, calls)
    assert not fs.windivert_repair_allowed(BIN, {"stopped": True})
    assert not fs.windivert_repair_allowed(BIN, {})
    assert calls == []


def test_running_official_service_is_detected_only_for_a_foreign_binary(monkeypatch):
    monkeypatch.setattr(fs, "run_sc", lambda *a, timeout=8: (0, "STATE : 4 RUNNING"))
    monkeypatch.setattr(fs, "service_image_path", lambda n: f'"{BIN}\\warp-svc.exe"')
    assert fs.official_warp_service_running(BIN) is False
    monkeypatch.setattr(fs, "service_image_path", lambda n: r'"C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe"')
    assert fs.official_warp_service_running(BIN) is True


def test_nova_no_longer_uses_the_official_service_name_or_kills_warp_by_image():
    src = (ROOT / "nova.pyw").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "CloudflareWARP":
            raise AssertionError(f"'CloudflareWARP' literal at nova.pyw:{node.lineno}")
        if isinstance(node, ast.List):
            vals = [e.value for e in node.elts if isinstance(e, ast.Constant)]
            if vals[:2] == ["taskkill", "/F"] and any(v in ("warp-svc.exe", "warp-cli.exe") for v in vals):
                raise AssertionError(f"taskkill of warp by image at nova.pyw:{node.lineno}")
