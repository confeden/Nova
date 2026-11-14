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
    domains = {'main.txt': {'main.test', 'main.youtube.test', 'nova-app.eu'}, 'second.txt': {'second.test', 'ai.second.test'},
               'u_main.txt': {'user.main.test'}, 'u_second.txt': {'user.second.test'},
               'ai.txt': {'ai.second.test'}, 'youtube.txt': {'main.youtube.test'}}
    runtime = types.SimpleNamespace(primary_foreign=lambda: False, primary_measured_foreign=lambda: False,
                                    secondary_foreign=lambda: False)
    mode = {'mode': 'hybrid', 'full_target': 'warp'}
    direct_hosts = []
    app_modes = {}
    cf = {'on': False}
    ns = dict(os=os, threading=threading, contextlib=contextlib, nova_vpn_slots=slots, nova_tor=nova_tor,
              get_base_dir=lambda: str(tmp_path), load_routing_settings=lambda: {},
              get_routing_pac_config=lambda _: mode, get_routing_app_mode=lambda name, *a: app_modes.get(name, 'auto'),
              get_routing_group_mode=lambda *a: 'auto', ROUTING_GROUP_KEYS=('browser',),
              get_discord_runtime_domains=lambda: set(),
              get_telegram_runtime_domains=lambda: {'t.me', 'telegra.ph', 'telegram.org', 'web.telegram.org',
                                                    'telesco.pe', 'tdesktop.com'},
              sanitize_youtube_domain_list=lambda value: value, SPOTIFY_DOMAINS=(), AI_APP_DOMAINS=(),
              tor_route_ready=lambda: True, vpn_slots_runtime=runtime,
              _env_bool_global=lambda *a: False, _nrpt_state={'system_dns_ai': True},
              _ai_region_lock=threading.Lock(), _ai_region_state={'unblockers': True},
              nova_ai_region=types.SimpleNamespace(direct_domains=lambda *a: {'ai.second.test'}),
              route_verdict_direct_hosts=lambda: list(direct_hosts))
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(source), 'exec'), ns)
    pac = types.SimpleNamespace(warp_port=1370, pac_file=str(tmp_path / 'nova.pac'),
                                _sync_winhttp_proxy=False, _winhttp_proxy_applied=False,
                                _load_domain_list=lambda path: domains.get(Path(path).name, set()),
                                _load_ip_list=lambda path: ([['104.21.0.0', '255.255.0.0', 4]]
                                                            if cf['on'] and Path(path).name == 'cloudflare.txt' else []),
                                _parse_ip_list_entries=lambda value: [],
                                is_port_open=lambda port: False, refresh_system_options=lambda: None,
                                log_func=lambda message: None)
    for name in ('_last_cloudflare_ip_count', '_last_eu_route_state', '_last_pac_mode_signature',
                 '_last_proxy_diag_state', '_last_route_signature', '_last_ru_route_state',
                 '_last_status_signature', '_last_warp_diag_state', '_last_youtube_route_state'):
        setattr(pac, name, None)

    def make(primary, secondary, p_foreign=False, s_foreign=False, browser_mode='hybrid', direct=(),
             telegram='auto'):
        direct_hosts[:] = list(direct)
        app_modes['telegram'] = telegram
        runtime.primary_foreign = runtime.primary_measured_foreign = lambda: p_foreign
        runtime.secondary_foreign = lambda: s_foreign
        mode['mode'] = browser_mode
        ns['generate_pac'](pac, warp_override=primary, opera_override=secondary)
        assert Path(pac.pac_file).is_file(), 'PAC generation failed'
        return Path(pac.pac_file).read_text(encoding='utf-8')
    make.cf = cf
    return make


MAIN = 'SOCKS5 127.0.0.1:1370'
SECOND = 'PROXY 127.0.0.1:1371'
CLOSED = 'SOCKS5 127.0.0.1:1'
NODE_SCRIPT = """
const vm = require('vm');
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
for (const c of cases) {
  const ctx = {isPlainHostName: h => !h.includes('.'), isInNet: () => false,
               dnsResolve: () => null, shExpMatch: () => false};
  vm.createContext(ctx); vm.runInContext(c.pac, ctx);
  for (const [host, expected] of Object.entries(c.expected)) {
    const actual = ctx.FindProxyForURL('https://' + host + '/', host);
    if (actual !== expected) throw Error(c.label + ' ' + host + ': ' + actual + ' != ' + expected);
  }
}
console.log(cases.length + ' rendered PAC states passed');
"""


def run_node(cases):
    result = subprocess.run(['node', '-e', NODE_SCRIPT], input=json.dumps(cases), capture_output=True,
                            text=True, timeout=30, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not shutil.which('node'), reason='node is not installed')
def test_rendered_auto_pac_routes_both_lists_and_ai(render):
    """Main-class names (main.txt, YouTube) go DIRECT while no VPN can carry the main chain (D55);
    second-class names (second.txt, AI) and the user lists stay closed instead (D43)."""
    cases = []
    for p in (False, True):
        for s in (False, True):
            for pf in (False, True):
                for sf in (False, True):
                    if p and s:
                        main_chain = MAIN + ('; ' + SECOND if sf else '')
                        second_class = SECOND + ('; ' + MAIN if pf else '')
                        main_class = main_chain
                    else:
                        route = MAIN if p and pf else SECOND if s and sf else CLOSED
                        main_chain = second_class = route
                        main_class = 'DIRECT' if route == CLOSED else route
                    cases.append(dict(label=f'p={p} s={s} pf={pf} sf={sf}', pac=render(p, s, pf, sf),
                                      expected={'main.test': main_class, 'main.youtube.test': main_class,
                                                'user.main.test': main_chain,
                                                'second.test': second_class, 'user.second.test': second_class,
                                                'ai.second.test': second_class}))
    run_node(cases)


@pytest.mark.skipif(not shutil.which('node'), reason='node is not installed')
def test_unproven_exit_leaves_main_class_direct_but_second_class_closed(render):
    # A VPN whose exit is not measured abroad cannot carry main-class names, and with no foreign
    # exit there is nothing for second-class names either.
    cases = [dict(label='primary unproven', pac=render(True, False, False, False),
                  expected={'main.test': 'DIRECT', 'main.youtube.test': 'DIRECT', 'second.test': CLOSED}),
             dict(label='secondary unproven', pac=render(False, True, False, False),
                  expected={'main.test': 'DIRECT', 'main.youtube.test': 'DIRECT', 'second.test': CLOSED}),
             dict(label='none up', pac=render(False, False),
                  expected={'main.test': 'DIRECT', 'main.youtube.test': 'DIRECT', 'second.test': CLOSED}),
             dict(label='primary foreign', pac=render(True, False, True, False),
                  expected={'main.test': MAIN, 'main.youtube.test': MAIN, 'second.test': MAIN})]
    run_node(cases)


TELEGRAM_WEB = ('t.me', 'telegra.ph', 'telegram.org', 'web.telegram.org', 'telesco.pe', 'cdn1.telesco.pe')


@pytest.mark.skipif(not shutil.which('node'), reason='node is not installed')
def test_telegram_web_opens_through_second_then_main_whatever_the_client_row_says(render):
    """G133: with the Telegram client row on «Напрямую» only t.me left DIRECT-less; telegram.org and
    telesco.pe (the page's css/js/images) stayed DIRECT and hung under DPI. In browser Auto every
    Telegram web name takes second first, main behind it, even when the main exit is not foreign."""
    cases = []
    for row in ('auto', 'direct', 'warp', 'opera'):
        for p, s in ((True, True), (True, False), (False, True), (False, False)):
            for pf, sf in ((False, False), (True, True)):
                chain = '; '.join(part for part, up in ((SECOND, s), (MAIN, p)) if up) or CLOSED
                cases.append(dict(label=f'row={row} p={p} s={s} pf={pf} sf={sf}',
                                  pac=render(p, s, pf, sf, telegram=row),
                                  expected={host: chain for host in TELEGRAM_WEB}))
    run_node(cases)


@pytest.mark.skipif(not shutil.which('node'), reason='node is not installed')
def test_telegram_web_in_full_browser_mode_keeps_the_client_row(render):
    # The browser-only rule must not leak into full mode, where the explicit row is the contract.
    pac = render(True, True, False, False, browser_mode='full', telegram='direct')
    run_node([dict(label='full', pac=pac, expected={'t.me': 'DIRECT', 'telegram.org': 'DIRECT'})])


@pytest.mark.skipif(not shutil.which('node'), reason='node is not installed')
def test_auto_direct_hosts_go_direct_only_for_main_class_names(render):
    # Every name below passed the direct probe; only main.txt / YouTube names may act on it.
    probed = ('main.test', 'main.youtube.test', 'second.test', 'ai.second.test', 'user.main.test')
    cases = []
    for p, s, pf, sf in ((True, True, True, True), (True, True, False, False), (True, False, True, False),
                         (False, True, False, True), (False, False, False, False)):
        both = p and s
        second = (SECOND + ('; ' + MAIN if pf else '')) if both else (
            MAIN if p and pf else SECOND if s and sf else CLOSED)
        main_chain = (MAIN + ('; ' + SECOND if sf else '')) if both else second
        cases.append(dict(label=f'p={p} s={s} pf={pf} sf={sf}', pac=render(p, s, pf, sf, direct=probed),
                          expected={'main.test': 'DIRECT', 'main.youtube.test': 'DIRECT',
                                    'second.test': second, 'ai.second.test': second,
                                    'user.main.test': main_chain, 'user.second.test': second}))
    run_node(cases)


@pytest.mark.skipif(not shutil.which('node'), reason='node is not installed')
def test_auto_direct_is_empty_without_a_verdict_and_ignores_unlisted_hosts(render):
    plain = render(True, True, True, True)
    unlisted = render(True, True, True, True, direct=('unlisted.test', 'user.main.test', 'second.test'))
    assert 'var auto_direct = {};' in plain
    assert 'var auto_direct = {};' in unlisted
    both = MAIN + '; ' + SECOND
    run_node([dict(label='no verdicts', pac=plain, expected={'main.test': both, 'main.youtube.test': both}),
              dict(label='unlisted verdicts', pac=unlisted,
                   expected={'main.test': both, 'main.youtube.test': both, 'user.main.test': both,
                             'second.test': SECOND + '; ' + MAIN})])


@pytest.mark.skipif(not shutil.which('node'), reason='node is not installed')
def test_full_browser_mode_ignores_auto_direct(render):
    pac = render(True, True, True, True, browser_mode='full', direct=('main.test',))
    run_node([dict(label='full', pac=pac, expected={'main.test': MAIN, 'second.test': MAIN})])


def test_full_browser_mode_keeps_explicit_primary_route(render):
    script = render(True, True, True, True, browser_mode='full')
    assert 'var pac_full_route = "SOCKS5 127.0.0.1:1370";' in script


@pytest.mark.skipif(not shutil.which('node'), reason='node is not installed')
def test_novagram_relay_hosts_are_never_routed_or_closed(render):
    """kws<N> worker zones and *.nova-app.eu go DIRECT in every state, in both PAC entry points: NovaGram
    reads this PAC through WinINET, and a SOCKS5-only main slot used to collapse to the closed port."""
    hosts = ['kws5.offshor.co.uk', 'kws1.nothingthere.co.uk', 'kws5-1.pclead.co.uk',
             'relay-tg.nova-app.eu', 'kws5.nova-app.eu']
    render.cf['on'] = True  # the worker zones sit behind Cloudflare: their addresses hit the CF branch
    cases = []
    for p in (False, True):
        for s in (False, True):
            for pf in (False, True):
                cases.append(dict(label=f'p={p} s={s} pf={pf}', pac=render(p, s, pf, False), hosts=hosts))
    script = """
const vm = require('vm');
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const inNet = (ip, net, mask) => ip.startsWith('104.21.');
for (const c of cases) {
  const ctx = {isPlainHostName: h => !h.includes('.'), isInNet: inNet, dnsResolve: () => '104.21.80.254',
               shExpMatch: () => false};
  vm.createContext(ctx); vm.runInContext(c.pac, ctx);
  for (const host of c.hosts) {
    for (const fn of ['FindProxyForURL', 'FindProxyForURLEx']) {
      const actual = ctx[fn]('https://' + host + '/', host);
      if (actual !== 'DIRECT') throw Error(c.label + ' ' + fn + ' ' + host + ': ' + actual);
    }
  }
}
"""
    result = subprocess.run(['node', '-e', script], input=json.dumps(cases), capture_output=True, text=True,
                            timeout=30, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    assert result.returncode == 0, result.stderr
    # The bare site and other names keep their list routes.
    assert 'nova-app.eu' not in hosts
