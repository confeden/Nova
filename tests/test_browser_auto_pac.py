"""Render the real PAC and execute it under Node, without touching the system proxy."""
import ast
import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'resources'))

import pytest
import nova_tor
import nova_vpn_slots as slots


@pytest.fixture
def render(tmp_path):
    source = Path(__file__).resolve().parents[1] / 'nova.pyw'
    tree = ast.parse(source.read_text(encoding='utf-8'))
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == 'PacManager')
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'generate_pac')
    domains = {'main.txt': {'main.test', 'main.youtube.test'}, 'second.txt': {'second.test', 'ai.second.test'},
               'u_main.txt': {'user.main.test'}, 'u_second.txt': {'user.second.test'},
               'ai.txt': {'ai.second.test'}, 'youtube.txt': {'main.youtube.test'}}
    runtime = types.SimpleNamespace(primary_foreign=lambda: False, primary_measured_foreign=lambda: False,
                                    secondary_foreign=lambda: False)
    mode = {'mode': 'hybrid', 'full_target': 'warp'}
    ns = dict(os=os, threading=threading, contextlib=contextlib, nova_vpn_slots=slots, nova_tor=nova_tor,
              get_base_dir=lambda: str(tmp_path), load_routing_settings=lambda: {},
              get_routing_pac_config=lambda _: mode, get_routing_app_mode=lambda *a: 'auto',
              get_routing_group_mode=lambda *a: 'auto', ROUTING_GROUP_KEYS=('browser',),
              get_discord_runtime_domains=lambda: set(), get_telegram_runtime_domains=lambda: set(),
              sanitize_youtube_domain_list=lambda value: value, SPOTIFY_DOMAINS=(), AI_APP_DOMAINS=(),
              tor_route_ready=lambda: True, vpn_slots_runtime=runtime,
              _env_bool_global=lambda *a: False, _nrpt_state={'system_dns_ai': True},
              _ai_region_lock=threading.Lock(), _ai_region_state={'unblockers': True},
              nova_ai_region=types.SimpleNamespace(direct_domains=lambda *a: {'ai.second.test'}))
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(source), 'exec'), ns)
    pac = types.SimpleNamespace(warp_port=1370, pac_file=str(tmp_path / 'nova.pac'),
                                _sync_winhttp_proxy=False, _winhttp_proxy_applied=False,
                                _load_domain_list=lambda path: domains.get(Path(path).name, set()),
                                _load_ip_list=lambda path: [], _parse_ip_list_entries=lambda value: [],
                                is_port_open=lambda port: False, refresh_system_options=lambda: None,
                                log_func=lambda message: None)
    for name in ('_last_cloudflare_ip_count', '_last_eu_route_state', '_last_pac_mode_signature',
                 '_last_proxy_diag_state', '_last_route_signature', '_last_ru_route_state',
                 '_last_status_signature', '_last_warp_diag_state', '_last_youtube_route_state'):
        setattr(pac, name, None)

    def make(primary, secondary, p_foreign=False, s_foreign=False, browser_mode='hybrid'):
        runtime.primary_foreign = runtime.primary_measured_foreign = lambda: p_foreign
        runtime.secondary_foreign = lambda: s_foreign
        mode['mode'] = browser_mode
        ns['generate_pac'](pac, warp_override=primary, opera_override=secondary)
        assert Path(pac.pac_file).is_file(), 'PAC generation failed'
        return Path(pac.pac_file).read_text(encoding='utf-8')
    return make


@pytest.mark.skipif(not shutil.which('node'), reason='node is not installed')
def test_rendered_auto_pac_routes_both_lists_and_ai_without_direct_escape(render):
    cases = []
    main = 'SOCKS5 127.0.0.1:1370'
    second = 'PROXY 127.0.0.1:1371'
    closed = 'SOCKS5 127.0.0.1:1'
    for p in (False, True):
        for s in (False, True):
            for pf in (False, True):
                for sf in (False, True):
                    if p and s:
                        expected = [main + ('; ' + second if sf else ''),
                                    second + ('; ' + main if pf else '')]
                    else:
                        route = main if p and pf else second if s and sf else closed
                        expected = [route, route]
                    cases.append(dict(pac=render(p, s, pf, sf), expected=expected))
    script = """
const vm = require('vm');
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
for (const c of cases) {
  const ctx = {isPlainHostName: h => !h.includes('.'), isInNet: () => false,
               dnsResolve: () => null, shExpMatch: () => false};
  vm.createContext(ctx); vm.runInContext(c.pac, ctx);
  for (const [host, index] of [['main.test',0], ['user.main.test',0], ['main.youtube.test',0],
                              ['second.test',1], ['user.second.test',1], ['ai.second.test',1]]) {
    const actual = ctx.FindProxyForURL('https://' + host + '/', host);
    if (actual !== c.expected[index]) throw Error(host + ': ' + actual + ' != ' + c.expected[index]);
  }
}
console.log('16 rendered PAC states passed');
"""
    result = subprocess.run(['node', '-e', script], input=json.dumps(cases), capture_output=True,
                            text=True, timeout=30, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    assert result.returncode == 0, result.stderr


def test_full_browser_mode_keeps_explicit_primary_route(render):
    script = render(True, True, True, True, browser_mode='full')
    assert 'var pac_full_route = "SOCKS5 127.0.0.1:1370";' in script
