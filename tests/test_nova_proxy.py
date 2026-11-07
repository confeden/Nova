"""Native protocol parsing, storage and subscription compatibility, with fictional credentials."""
import base64
import json
from pathlib import Path
import subprocess

import pytest
import nova_proxy as proxy
import nova_profiles as profiles
import nova_subscriptions as subscriptions

UUID = '00000000-0000-4000-8000-000000000001'


def vmess_link(name='VMess fixture'):
    fields = dict(v='2', ps=name, add='127.0.0.1', port=443, id=UUID, aid=0, net='ws', path='/fixture', tls='tls')
    return 'vmess://' + base64.b64encode(json.dumps(fields).encode()).decode()


def require_engine():
    if not Path(proxy.engine_path()).is_file():
        pytest.skip('Build nova-proxy first')


@pytest.mark.parametrize('link,protocol', [
    (vmess_link(), 'vmess'),
    ('hy2://p%40ss%3Aword@127.0.0.1:443?obfs=salamander&obfs-password=fixture&insecure=1#Hy2', 'hysteria2'),
    ('hysteria://127.0.0.1:443?auth=fixture&peer=localhost&upmbps=20&downmbps=80&obfs=fixture#Hysteria', 'hysteria'),
    ('trojan://fixture@127.0.0.1:443?sni=localhost#Trojan', 'trojan'),
    ('anytls://fixture@127.0.0.1:443?sni=localhost&insecure=1#AnyTLS', 'anytls'),
    (f'tuic://{UUID}:fixture@127.0.0.1:443?alpn=h3#TUIC', 'tuic'),
    ('ss://' + base64.b64encode(b'aes-128-gcm:fixture').decode() + '@127.0.0.1:8388#SS', 'ss'),
])
def test_native_accepts_real_share_link_shapes(link, protocol):
    require_engine()
    nodes, stats = proxy.parse_many(link)
    assert len(nodes) == 1 and nodes[0].protocol == protocol
    assert stats['skipped'] == 0
    if protocol == 'hysteria2':
        assert nodes[0].proxy['password'] == 'p@ss:word'


def test_vmess_optional_fragment_and_missing_remark_are_not_dropped():
    require_engine()
    fields = dict(add='127.0.0.1', port=443, id=UUID, aid=0, net='tcp', tls=False)
    link = 'vmess://' + base64.urlsafe_b64encode(json.dumps(fields).encode()).decode().rstrip('=') + '#Fixture%20name'
    nodes, _ = proxy.parse_many(link)
    assert len(nodes) == 1 and nodes[0].name == 'Fixture name'


def test_new_protocol_and_vless_import_together_without_ss_suffix_matches(tmp_path):
    require_engine()
    link = f'vless://{UUID}@127.0.0.1:443?security=none&type=tcp#VLESS'
    candidates = profiles.parse_import_text(link + '\n' + vmess_link())
    assert [c['kind'] for c in candidates] == ['vless', 'proxy']
    results = profiles.import_candidates(tmp_path, candidates)
    assert all(r['status'] == 'imported' and r['id'].startswith('Custom/') for r in results)
    records = profiles.list_profiles(tmp_path)
    assert {r['protocol'] for r in records} == {'vless', 'vmess'}
    plan = profiles.build_attempt_plan(records, dict(mode='group', group='Custom'))
    assert len(plan) == 2 and all(p['backend'] == 'vless' for p in plan)


def test_clash_transport_and_obfuscation_options_survive_import_and_runtime(tmp_path):
    require_engine()
    outbound = dict(type='ss', name='Obfuscated', server='127.0.0.1', port=8388, cipher='aes-128-gcm',
                    password='fixture', plugin='obfs', **{'plugin-opts': {'mode': 'http', 'host': 'example.org'},
                                                        'udp': True})
    nodes, _ = proxy.parse_many(json.dumps(dict(proxies=[outbound], tun={'enable': True},
                                                  **{'mixed-port': 1, 'rules': ['MATCH,DIRECT']})))
    assert nodes[0].proxy == outbound
    profiles.import_candidates(tmp_path, [proxy.candidate(nodes[0])])
    record = profiles.list_profiles(tmp_path)[0]
    config = proxy.config_for_record(record, 19999, 19998)
    assert config['proxies'] == [outbound]
    assert set(config) == {'proxies', 'selected', 'socks_port', 'http_port'}
    engine, path = proxy.prepare_runtime(record, 19999, 19998, base=tmp_path)
    result = subprocess.run([proxy.engine_path(), 'check', '--config', path], capture_output=True,
                            timeout=10, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    assert result.returncode == 0, result.stderr


def test_subscription_sync_is_scoped_and_does_not_remove_manual_nodes(tmp_path):
    require_engine()
    manual, _ = proxy.parse_many(vmess_link('manual'))
    profiles.import_candidates(tmp_path, [proxy.candidate(manual[0])])
    record = subscriptions.normalize_record(dict(url='https://example.org/fixture', name='Fixture', keep=10))
    body = ('trojan://fixture@127.0.0.1:443?sni=localhost#subscription').encode()
    def fetcher(*_a, **_k):
        return subscriptions.FetchResult(status='ok', body=body, size=len(body))
    status, saved, _ = subscriptions.refresh(tmp_path, record, fetcher=fetcher)
    assert status == 'updated'
    assert len(profiles.list_profiles(tmp_path)) == 2
    assert len(saved['identities']) == 1
    assert {r['origin'] for r in profiles.list_profiles(tmp_path)} == {'imported', 'subscription'}


def test_legacy_ids_share_custom_group_and_all_sort_modes_remain_available():
    records = [dict(id='VLESS/Zulu', name='Zulu', group='VLESS', kind='vless'),
               dict(id='Custom/Alpha', name='Alpha', group='Custom', kind='proxy', protocol='vmess'),
               dict(id='Custom/Beta', name='Beta', group='Custom', kind='awg')]
    merged = proxy.group_records(records, 'Custom')
    assert len(merged) == 3
    assert [r['name'] for r in proxy.sort_records(merged)] == ['Beta', 'Zulu', 'Alpha']
    assert [r['name'] for r in proxy.sort_records(merged, 'name')] == ['Alpha', 'Beta', 'Zulu']
    stats = {'Custom/Alpha':dict(last_ms=0,last_ok_at=1), 'VLESS/Zulu':dict(rtt_ms=30)}
    assert [r['name'] for r in proxy.sort_records(merged, 'ping', stats)] == ['Alpha', 'Zulu', 'Beta']


def test_no_remark_uses_stable_name_without_rejecting_valid_profile():
    value = dict(type='proxy', proxy=dict(type='vmess', name='', server='127.0.0.1', port=443, uuid=UUID))
    node = proxy.from_payload(value)
    assert node.name.startswith('VMESS ')
    assert proxy.from_payload(value).name == node.name


def test_duplicate_manual_profile_never_becomes_subscription_owned_or_deleted(tmp_path):
    require_engine()
    manual, _ = proxy.parse_many(vmess_link('manual'))
    profiles.import_candidates(tmp_path, [proxy.candidate(manual[0])])
    record = subscriptions.normalize_record(dict(url='https://example.org/fixture', name='Fixture', keep=10))
    body = vmess_link('renamed in subscription').encode()
    def fetcher(*_a, **_k):
        return subscriptions.FetchResult(status='ok', body=body, size=len(body))
    _, saved, _ = subscriptions.refresh(tmp_path, record, fetcher=fetcher)
    assert saved['identities'] == []
    body = b'trojan://fixture@127.0.0.1:443?sni=localhost#other'
    subscriptions.refresh(tmp_path, saved, fetcher=fetcher)
    records = profiles.list_profiles(tmp_path)
    assert len(records) == 2 and any(r['origin'] == 'imported' for r in records)


def test_bad_dependency_does_not_drop_unrelated_profiles():
    valid = dict(type='http', name='valid', server='127.0.0.1', port=80)
    broken = dict(type='http', name='broken', server='127.0.0.1', port=81, **{'dialer-proxy':'missing'})
    errors = []
    assert [n.name for n in proxy.nodes_from_proxies([valid, broken], errors)] == ['valid']
    assert errors == ['missing_or_cyclic_dependency']


def test_xray_native_transport_options_are_preserved_without_importing_global_routing(tmp_path):
    outbound = dict(tag='VMess-native', protocol='vmess', settings=dict(vnext=[dict(address='127.0.0.1', port=9,
                    users=[dict(id=UUID, alterId=0, security='auto')])]),
                    streamSettings=dict(network='ws', wsSettings=dict(path='/fixture', headers=dict(Host='example.org'))))
    document = dict(outbounds=[outbound], inbounds=[dict(protocol='tun')], routing=dict(domainStrategy='IPIfNonMatch'))
    nodes, _ = proxy.parse_many(json.dumps(document))
    assert nodes[0].engine == 'xray'
    profiles.import_candidates(tmp_path, [proxy.candidate(nodes[0])])
    record = profiles.list_profiles(tmp_path)[0]
    assert record['engine'] == 'xray' and proxy.engine_for_record(record).endswith('nova-xray.exe')
    config = proxy.config_for_record(record, 19999, 19998)
    assert config['outbounds'] == [outbound]
    assert 'routing' not in config
    assert all(p['listen'] == '127.0.0.1' and p['protocol'] in ('socks', 'http') for p in config['inbounds'])


def test_http_proxies_in_subscriptions_are_not_mistaken_for_metadata_or_subscription_links():
    text = ('#profile-web-page-url: https://example.org/\nhttps://user:fixture@example.org:8443#Proxy\n'
            'http://127.0.0.1:8080\nhttps://example.org/subscription/token')
    assert proxy.share_links(text) == ['https://user:fixture@example.org:8443#Proxy', 'http://127.0.0.1:8080']


def test_direct_entries_are_not_imported_as_working_vpn_endpoints():
    records = [dict(type='direct', name='DIRECT'),dict(type='http',name='proxy',server='127.0.0.1',port=80)]
    assert [node.name for node in proxy.nodes_from_proxies(records)] == ['proxy']


def test_existing_vless_tls_skip_setting_is_honored_without_changing_its_id(tmp_path):
    require_engine()
    link = f'vless://{UUID}@127.0.0.1:443?security=tls&sni=localhost&allowInsecure=1#Legacy'
    profiles.import_candidates(tmp_path, profiles.parse_import_text(link))
    record = profiles.list_profiles(tmp_path)[0]
    assert record['kind'] == 'vless' and record['engine'] == 'mihomo'
    identity = record['identity']
    assert proxy.engine_for_record(record).endswith('nova-proxy.exe')
    config = proxy.config_for_record(record, 19999)
    assert config['proxies'][0]['skip-cert-verify'] is True
    assert profiles.list_profiles(tmp_path)[0]['identity'] == identity
