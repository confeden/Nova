import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace

import pytest

import nova_routing_profiles as profiles
from NovaWFP.proxy import tcp_proxy as tp

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "NovaDivert"))
import windivert_redirect as wr


@pytest.fixture
def active(monkeypatch):
    state = {"active": True, "updated": time.time(), "servers": ["194.87.196.13", "2a00:b700:5::3:62"]}
    monkeypatch.setitem(profiles._dns_ai_cache, "checked", time.monotonic())
    monkeypatch.setitem(profiles._dns_ai_cache, "state", state)
    return state


def proxy(monkeypatch, main=True, second=True):
    instance = object.__new__(tp.NovaWfpTcpProxy)
    instance._warp_socks_available = lambda: main
    instance._route_label_is_bad = lambda *_a, **_k: False
    instance._attempt_by_label = lambda label: ({"label": label, "timeout": 3}
                                               if second or label != "opera-http" else None)
    # These must never influence a resolver's transport.
    monkeypatch.setattr(tp, "_get_app_route_mode", lambda _: "direct")
    instance._route_label_cache_get = lambda *_a, **_k: "direct"
    return instance


@pytest.mark.parametrize("main,second,expected", [
    (True, True, ["warp-socks", "opera-http"]),
    (False, True, ["opera-http"]),
    (True, False, ["warp-socks"]),
    (False, False, ["direct"]),
])
def test_resolver_order_ignores_site_lists_and_old_direct_cache(monkeypatch, active, main, second, expected):
    instance = proxy(monkeypatch, main, second)
    for host in active["servers"]:
        attempts = instance._build_attempts_for_target(host, 443, 3)
        assert [attempt["label"] for attempt in attempts] == expected


def test_client_family_uses_main_even_for_a_custom_upstream(monkeypatch, active):
    instance = proxy(monkeypatch)
    assert profiles.match_app_by_process_path(r"C:\DNS-AI\dns-ai-svc.exe") == "DNS-AI"
    assert tp.NovaWfpTcpProxy._app_family_from_app_id(r"C:\DNS-AI\dns-ai-svc.exe") == "dns_ai"
    attempts = instance._build_attempts_for_target("custom.resolver.test", 443, 2, app_family="dns_ai")
    assert [attempt["label"] for attempt in attempts] == ["warp-socks", "opera-http"]


def test_dns_ai_uses_faster_secondary_and_reverses_order_after_new_measurements(monkeypatch, active):
    instance = proxy(monkeypatch)
    active['vpn_up'] = {'warp-socks': True, 'opera-http': True}
    active['latency_ms'] = {'warp-socks': 90, 'opera-http': 25}
    route = lambda: [a['label'] for a in instance._build_attempts_for_target(active['servers'][0], 443, 3)]
    assert route() == ['opera-http', 'warp-socks']
    active['latency_ms']['warp-socks'] = 12
    assert route() == ['warp-socks', 'opera-http']
    active['vpn_up']['warp-socks'] = False
    assert route() == ['opera-http']
    active['vpn_up']['opera-http'] = False
    assert route() == ['direct']


@pytest.mark.parametrize('bad', [None, -1, float('nan'), float('inf'), '1', True])
def test_invalid_latency_cannot_win_the_route(bad):
    assert profiles.dns_ai_route_labels(True, True, {'latency_ms': {'warp-socks': bad, 'opera-http': 30}}) == [
        'opera-http', 'warp-socks']


def test_dns_ai_udp_cannot_escape_direct_when_the_fastest_vpn_is_tcp_only(monkeypatch, active):
    from NovaWFP.proxy import udp_proxy as udp
    monkeypatch.setattr(udp, 'get_udp_upstream_attempts', lambda: [
        {'label': 'warp-socks', 'kind': 'socks5'}, {'label': 'direct', 'kind': 'direct'}])
    instance = object.__new__(udp.NovaWfpUdpProxy)
    active['vpn_up'] = {'warp-socks': True, 'opera-http': True}
    active['latency_ms'] = {'warp-socks': 80, 'opera-http': 20}
    assert instance.build_attempts_for_target(active['servers'][0], 443, 'dns_ai') == []
    active['latency_ms']['warp-socks'] = 10
    assert instance.build_attempts_for_target(active['servers'][0], 443, 'dns_ai') == [
        {'label': 'warp-socks', 'kind': 'socks5'}]
    active['vpn_up'] = {'warp-socks': False, 'opera-http': False}
    assert instance.build_attempts_for_target(active['servers'][0], 443, 'dns_ai') == [
        {'label': 'direct', 'kind': 'direct'}]


def test_inactive_or_stale_detection_never_claims_a_destination(monkeypatch, active):
    assert profiles.is_dns_ai_endpoint(active["servers"][0], 443)
    assert not profiles.is_dns_ai_endpoint(active["servers"][0], 22)
    assert not profiles.is_dns_ai_endpoint("1.1.1.1", 443)
    active["active"] = False
    assert not profiles.is_dns_ai_endpoint(active["servers"][0], 443)
    active.update(active=True, updated=time.time() - 40)
    assert not profiles.is_dns_ai_endpoint(active["servers"][0], 443)


def service(tmp_path):
    instance = object.__new__(wr.RedirectService)
    instance._flow_lock = threading.Lock()
    instance._sessions = {}
    instance.map = SimpleNamespace(path=str(tmp_path / "temp" / "map.json"))
    instance._should_log = lambda _: True
    instance.log = lambda _: None
    return instance


def test_static_capture_excludes_proxys_direct_connections(monkeypatch, tmp_path, active):
    instance = service(tmp_path)
    (tmp_path / "temp").mkdir()
    (tmp_path / "temp" / "NovaDivertTcpProxy.pid").write_text(json.dumps({"pid": 1234}), encoding="utf-8")
    packet = {"src_ip": "192.168.1.10", "src_port": 42100, "dst_ip": active["servers"][0], "dst_port": 443}
    monkeypatch.setattr(wr, "_tcp_owner_pid", lambda _: 1234)
    assert instance._dns_ai_meta(packet)["app_family"] == "dns-ai-direct"
    monkeypatch.setattr(wr, "_tcp_owner_pid", lambda _: 5678)
    assert instance._dns_ai_meta(packet)["app_family"] == "dns_ai"
    monkeypatch.setattr(wr, "_tcp_owner_pid", lambda _: None)
    assert instance._dns_ai_meta(packet)["app_family"] == "dns-ai-direct"


def test_ipv6_response_cannot_inherit_an_ipv4_session_with_the_same_port(tmp_path):
    instance = service(tmp_path)
    instance._sessions[("tcp", "192.168.1.10", 42100)] = {"app_family": "dns_ai"}
    assert instance._lookup_session("tcp", "2001:db8::10", 42100) == {}


def test_ipv6_doh_packet_rewrite_preserves_client_and_remote_endpoints():
    packet = bytearray(60)
    packet[0], packet[6] = 0x60, 6
    packet[4:6] = (20).to_bytes(2, "big")
    packet[8:24] = socket.inet_pton(socket.AF_INET6, "2001:db8::10")
    packet[24:40] = socket.inet_pton(socket.AF_INET6, "2a00:b700:5::3:62")
    packet[40:42], packet[42:44] = (42100).to_bytes(2, "big"), (443).to_bytes(2, "big")
    packet[52], packet[53] = 0x50, wr.TCP_FLAG_SYN
    original = wr._parse_tcp_packet(packet)
    redirected = wr._parse_tcp_packet(wr._rewrite_tcp_packet(packet, dst_ip=original["src_ip"], dst_port=17870))
    assert redirected["dst_ip"] == original["src_ip"]
    assert redirected["dst_port"] == 17870
    restored = wr._parse_tcp_packet(wr._rewrite_tcp_packet(packet, src_ip=original["dst_ip"], src_port=443,
                                                          dst_ip=original["src_ip"], dst_port=42100))
    assert restored["src_ip"] == original["dst_ip"]
    assert restored["dst_port"] == original["src_port"]


@pytest.mark.skipif(os.name != "nt", reason="Windows socket ownership")
@pytest.mark.parametrize("family,host", [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")])
def test_native_tcp_owner_lookup_matches_real_connection(family, host):
    with socket.socket(family) as listener, socket.socket(family) as client:
        try:
            listener.bind((host, 0))
        except OSError as error:
            pytest.skip(str(error))
        listener.listen()
        client.connect(listener.getsockname())
        accepted, _ = listener.accept()
        with accepted:
            parsed = {"src_ip": host, "src_port": client.getsockname()[1],
                      "dst_ip": host, "dst_port": listener.getsockname()[1]}
            assert wr._tcp_owner_pid(parsed) == os.getpid()
