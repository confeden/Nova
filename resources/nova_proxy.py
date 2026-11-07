"""Lossless subscription profiles for Nova's pinned Mihomo helper; no system tunnel changes."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
import re
import subprocess
import sys


KIND = 'proxy'
SCHEMES = ('vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'hy2', 'tuic',
           'anytls', 'socks', 'socks5', 'socks5h', 'http', 'https', 'mierus',
           'hysteria2+realm', 'hy2+realm', 'wireguard')
_LINK_SCHEMES = '|'.join(re.escape(s) for s in SCHEMES)
URI_RE = re.compile(r'(?i)(?<![A-Za-z0-9+.-])(?:' + _LINK_SCHEMES + r')://(?:(?!(?:vless|vpn|' + _LINK_SCHEMES + r')://)[^\r\n])+')
MAX_BYTES = 8 * 1024 * 1024


def share_links(text):
    links = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//')):
            continue
        for match in URI_RE.finditer(line):
            link = match.group(0).rstrip().rstrip('"<>')
            if link.lower().startswith(('http://', 'https://')):
                try:
                    parsed = urlsplit(link)
                    if not parsed.username and (not parsed.port or parsed.path not in ('', '/')):
                        continue
                except ValueError:
                    continue
            links.append(link)
    return links


def app_root():
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    base = Path(__file__).resolve().parent
    return base.parent if base.name.lower() == 'resources' else base


def engine_path(base=None):
    root = Path(base) if base else app_root()
    for path in (root / 'bin/nova-proxy.exe', root / 'resources/bin/nova-proxy.exe'):
        if path.is_file():
            return str(path)
    return str(root / 'bin/nova-proxy.exe')


def native_import(body):
    data = body.encode('utf-8') if isinstance(body, str) else bytes(body)
    if len(data) > MAX_BYTES:
        raise ValueError('Слишком большой список профилей')
    try:
        result = subprocess.run([engine_path(), 'import'], input=data, capture_output=True, timeout=90,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except FileNotFoundError as error:
        raise RuntimeError('Не найден nova-proxy.exe: требуется обновить ядро профилей') from error
    if result.returncode:
        raise ValueError('Ядро не распознало список профилей')
    return json.loads(result.stdout)


def fingerprint(proxy, dependencies=()):
    # Remarks do not change the endpoint identity. Preserve every protocol/obfuscation option.
    graph = [dict(item) for item in (*dependencies, proxy)]
    names = {str(item.get('name')): str(i) for i, item in enumerate(graph)}
    for item in graph:
        item.pop('name', None)
        if item.get('dialer-proxy') in names:
            item['dialer-proxy'] = names[item['dialer-proxy']]
    return hashlib.sha256(json.dumps(graph, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


@dataclass(frozen=True)
class ProxyNode:
    proxy: dict
    dependencies: tuple = ()
    engine: str = 'mihomo'

    @property
    def identity(self):
        return fingerprint(self.proxy, self.dependencies)

    @property
    def protocol(self):
        return str(self.proxy.get('type') or '').lower()

    @property
    def name(self):
        return str(self.proxy.get('name') or self.protocol.upper())

    @property
    def endpoint(self):
        host = str(self.proxy.get('server') or '')
        return f'[{host}]:{self.proxy.get("port", "")}' if ':' in host else f'{host}:{self.proxy.get("port", "")}'

    def to_dict(self):
        result = dict(type=KIND, proxy=self.proxy, dependencies=list(self.dependencies))
        if self.engine != 'mihomo':
            result['engine'] = self.engine
        return result


def from_payload(obj):
    if not isinstance(obj, dict) or obj.get('type') != KIND or not isinstance(obj.get('proxy'), dict):
        raise ValueError('Не распознан профиль прокси')
    proxy = dict(obj['proxy'])
    if proxy.get('type') and not proxy.get('name'):
        proxy['name'] = str(proxy['type']).upper() + ' ' + fingerprint(proxy)[:8]
    dependencies = obj.get('dependencies') or []
    if not isinstance(dependencies, list) or len(dependencies) > 511 or not all(isinstance(p, dict) for p in dependencies):
        raise ValueError('Неверная цепочка профиля')
    if not proxy.get('type') or not proxy.get('name'):
        raise ValueError('В профиле отсутствует протокол или имя')
    engine = obj.get('engine', 'mihomo')
    if engine not in ('mihomo', 'xray'):
        raise ValueError('Неизвестное ядро профиля')
    return ProxyNode(proxy, tuple(dependencies), engine)


def payload(node, source='imported', subscription=''):
    value = dict(node.to_dict(), source=source)
    if subscription:
        value['subscription'] = subscription
    return json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8')


def candidate(node):
    return dict(kind=KIND, protocol=node.protocol, name=node.name, text=payload(node).decode('utf-8'),
                endpoint=node.endpoint, issues=[], ok=True, fingerprint=node.identity)


def nodes_from_proxies(proxies, errors=None):
    proxies = [dict(p) for p in proxies]
    for proxy in proxies:
        if not proxy.get('name'):
            proxy['name'] = str(proxy.get('type', 'Proxy')).upper() + ' ' + fingerprint(proxy)[:8]
    by_name = {str(p.get('name')): p for p in proxies}
    nodes = []
    for proxy in proxies:
        if str(proxy.get('type') or '').lower() in ('direct', 'reject', 'dns', 'block', 'compatible'):
            continue
        dependencies, seen = [], {str(proxy.get('name'))}
        current = proxy
        invalid = False
        while current.get('dialer-proxy') and str(current['dialer-proxy']).upper() != 'DIRECT':
            name = str(current['dialer-proxy'])
            if name in seen or name not in by_name:
                invalid = True
                if errors is not None:
                    errors.append('missing_or_cyclic_dependency')
                break
            seen.add(name)
            current = by_name[name]
            dependencies.append(current)
        if not invalid:
            nodes.append(ProxyNode(proxy, tuple(dependencies)))
    return nodes


def singbox_proxies(document):
    """Translate native sing-box outbounds without importing their OS routing or listeners."""
    proxies = []
    for outbound in document.get('outbounds') or []:
        if not isinstance(outbound, dict) or outbound.get('type') in ('block', 'dns', 'selector', 'urltest'):
            continue
        if outbound.get('type') == 'direct':
            proxies.append(dict(type='direct', name=outbound.get('tag') or 'DIRECT'))
            continue
        if 'protocol' in outbound:
            raise ValueError('Для Xray JSON используйте ссылки профилей или список Clash/sing-box')
        kind = outbound.get('type')
        proxy = {'name': outbound.get('tag') or kind, 'type': {'shadowsocks': 'ss', 'socks': 'socks5'}.get(kind, kind),
                 'server': outbound.get('server'), 'port': outbound.get('server_port'), 'udp': True}
        rename = {'uuid': 'uuid', 'password': 'password', 'method': 'cipher', 'security': 'cipher',
                  'alter_id': 'alterId', 'flow': 'flow', 'username': 'username', 'version': 'version',
                  'up_mbps': 'up', 'down_mbps': 'down', 'auth_str': 'auth-str', 'auth': 'auth',
                  'server_ports': 'ports', 'hop_interval': 'hop-interval', 'detour': 'dialer-proxy',
                  'congestion_control': 'congestion-controller', 'udp_relay_mode': 'udp-relay-mode',
                  'zero_rtt_handshake': 'reduce-rtt', 'heartbeat': 'heartbeat-interval',
                  'idle_session_check_interval': 'idle-session-check-interval',
                  'idle_session_timeout': 'idle-session-timeout', 'min_idle_session': 'min-idle-session'}
        for source, target in rename.items():
            if source in outbound:
                proxy[target] = outbound[source]
        tls = outbound.get('tls') or {}
        if tls:
            proxy['tls'] = tls.get('enabled', True)
            proxy['servername' if kind in ('vless', 'vmess') else 'sni'] = tls.get('server_name') or outbound.get('server')
            for source, target in (('insecure', 'skip-cert-verify'), ('alpn', 'alpn')):
                if source in tls:
                    proxy[target] = tls[source]
            if (tls.get('utls') or {}).get('enabled'):
                proxy['client-fingerprint'] = tls['utls'].get('fingerprint') or 'chrome'
            reality = tls.get('reality') or {}
            if reality.get('enabled'):
                proxy['reality-opts'] = {'public-key': reality.get('public_key'), 'short-id': reality.get('short_id', '')}
        obfs = outbound.get('obfs')
        if isinstance(obfs, dict):
            proxy['obfs'] = obfs.get('type')
            proxy['obfs-password'] = obfs.get('password', '')
        elif obfs:
            proxy['obfs'] = obfs
        transport = outbound.get('transport') or {}
        network = transport.get('type')
        if network:
            proxy['network'] = 'ws' if network == 'httpupgrade' else network
            options = {k.replace('_', '-'): v for k, v in transport.items() if k != 'type'}
            if network == 'grpc' and 'service-name' in options:
                options['grpc-service-name'] = options.pop('service-name')
            if network == 'httpupgrade':
                options['v2ray-http-upgrade'] = True
            proxy[proxy['network'] + '-opts'] = options
        multiplex = outbound.get('multiplex') or {}
        if multiplex:
            proxy['smux'] = {k.replace('_', '-'): v for k, v in multiplex.items()}
        if outbound.get('plugin'):
            proxy['plugin'] = outbound['plugin']
            proxy['plugin-opts'] = dict(part.split('=', 1) if '=' in part else (part, '')
                                        for part in str(outbound.get('plugin_opts') or '').split(';') if part)
        proxies.append(proxy)
    return proxies


def xray_nodes(document):
    """Keep Xray's full transport settings, including options without a Clash equivalent."""
    outbounds = document.get('outbounds') or []
    by_tag = {str(p.get('tag') or f'outbound-{i}'): dict(p) for i, p in enumerate(outbounds) if isinstance(p, dict)}
    def wrap(tag):
        raw = dict(by_tag[tag], tag=tag)
        settings = raw.get('settings') or {}
        servers = settings.get('vnext') or settings.get('servers') or []
        server = servers[0] if servers else {}
        return dict(type=raw.get('protocol'), name=tag, server=server.get('address', ''),
                    port=server.get('port', ''), xray_outbound=raw)
    nodes = []
    for tag, raw in by_tag.items():
        if raw.get('protocol') in ('freedom', 'blackhole', 'dns', 'loopback'):
            continue
        dependencies, seen, queue = [], {tag}, [raw]
        while queue:
            current = queue.pop()
            ref = (current.get('proxySettings') or {}).get('tag') or ((current.get('streamSettings') or {}).get('sockopt') or {}).get('dialerProxy')
            if not ref:
                continue
            if ref not in by_tag or ref in seen:
                raise ValueError('В Xray-профиле отсутствует зависимость или найдена циклическая цепочка')
            seen.add(ref); dependencies.append(wrap(ref)); queue.append(by_tag[ref])
        nodes.append(ProxyNode(wrap(tag), tuple(dependencies), 'xray'))
    return nodes


def parse_many(body, limit=20000):
    data = body.encode('utf-8') if isinstance(body, str) else bytes(body)
    if len(data) > MAX_BYTES:
        raise ValueError('Слишком большой список профилей')
    text = data.decode('utf-8-sig', errors='replace').strip()
    if text.startswith(('{', '[')):
        try:
            document = json.loads(text)
        except ValueError:
            document = None
        if isinstance(document, dict) and document.get('type') == KIND:
            return [from_payload(document)], {'parsed': 1, 'skipped': 0}
        if isinstance(document, dict) and 'outbounds' in document:
            if any(isinstance(p, dict) and 'protocol' in p for p in document['outbounds']):
                nodes = xray_nodes(document)
                return nodes[:limit], dict(parsed=len(nodes), skipped=0, limited=max(0, len(nodes)-limit))
            data = json.dumps({'proxies': singbox_proxies(document)}).encode()
        if isinstance(document, dict) and 'server_port' in document and 'type' in document:
            data = json.dumps({'proxies':singbox_proxies({'outbounds':[document]})}).encode()
        servers = document.get('servers') if isinstance(document, dict) else document
        if isinstance(servers, list) and servers and all(isinstance(p, dict) and 'method' in p for p in servers):
            proxies = [dict(type='ss', name=p.get('remarks') or f'Shadowsocks {i+1}', server=p.get('server'),
                            port=p.get('server_port'), cipher=p.get('method'), password=p.get('password'),
                            **({'plugin':p['plugin'], 'plugin-opts':p.get('plugin_opts', {})} if p.get('plugin') else {}))
                       for i,p in enumerate(servers)]
            data = json.dumps({'proxies':proxies}).encode()
    result = native_import(data)
    errors = []
    nodes = nodes_from_proxies(result.get('proxies') or [], errors)
    return nodes[:limit], {'parsed': len(nodes), 'skipped': result.get('skipped', 0) + len(errors),
                          'limited': max(0, len(nodes) - limit)}


def is_document(text):
    if re.search(r'(?m)^\s*(?:proxies|type)\s*:', text):
        return True
    if text.lstrip().startswith(('{', '[')):
        try:
            value = json.loads(text)
        except ValueError:
            return False
        return (isinstance(value, list) and bool(value) and isinstance(value[0], dict)
                or isinstance(value, dict) and (any(key in value for key in ('proxies', 'outbounds', 'servers'))
                                               or value.get('type') == KIND
                                               or value.get('type') and ('server' in value or 'protocol' in value)))
    return False


def record_node(record):
    with open(record['path'], 'rb') as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Слишком большой файл профиля')
    return from_payload(json.loads(data.decode('utf-8-sig')))


def runtime_config(record, socks_port, http_port=0):
    node = record_node(record)
    return dict(proxies=[*node.dependencies, node.proxy], selected=node.name,
                socks_port=int(socks_port), http_port=int(http_port))


def vless_engine(node):
    # Modern Xray removed allowInsecure. Honor an explicit legacy TLS policy with Mihomo.
    return 'mihomo' if (node is not None and node.security == 'tls' and node.allow_insecure
                        and not node.extra and node.fingerprint != 'unsafe'
                        and node.network in ('tcp', 'ws', 'grpc', 'xhttp', 'httpupgrade')) else 'xray'


def engine_for_record(record, base=None):
    path = engine_path(base)
    return path if (record.get('engine') == 'mihomo' or record.get('kind') == KIND
                    and record.get('engine') != 'xray') else str(Path(path).with_name('nova-xray.exe'))


def config_for_record(record, socks_port, http_port=0, log_path=''):
    if record.get('kind') == KIND:
        node = record_node(record)
        if node.engine == 'xray':
            inbounds = [dict(listen='127.0.0.1', port=int(socks_port), protocol='socks', settings=dict(auth='noauth', udp=True))]
            if http_port:
                inbounds.append(dict(listen='127.0.0.1', port=int(http_port), protocol='http', settings={}))
            return dict(log=dict(loglevel='none'), inbounds=inbounds,
                        outbounds=[p['xray_outbound'] for p in (node.proxy, *node.dependencies)])
        return runtime_config(record, socks_port, http_port)
    import nova_profiles
    import nova_vless
    node = nova_profiles.vless_node_of_record(record)
    if node is None:
        raise ValueError('Не удалось прочитать профиль')
    reason = nova_vless.validate(node)
    if reason:
        raise ValueError(reason)
    if vless_engine(node) == 'mihomo':
        nodes, _ = parse_many(node.to_dict()['uri'])
        if len(nodes) != 1:
            raise ValueError('Не удалось подготовить TLS-профиль')
        parsed = nodes[0]
        return dict(proxies=[*parsed.dependencies, parsed.proxy], selected=parsed.name,
                    socks_port=int(socks_port), http_port=int(http_port))
    config = nova_vless.build_xray_config(node, int(socks_port), http_port=int(http_port) or None)
    config['log'] = {'loglevel': 'none'}
    return config


def prepare_runtime(record, socks_port, http_port=0, base=None, log_path=''):
    import nova_profiles
    config = config_for_record(record, socks_port, http_port, log_path)
    path = Path(nova_profiles.runtime_config_path(base or app_root(), record['id'])).with_suffix('.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    nova_profiles._atomic_write_json(str(path), config)
    return engine_for_record(record, base), str(path)


def group_records(records, group):
    return [r for r in records if r.get('group') == group
            or group in ('Custom', 'VLESS') and r.get('group') in ('Custom', 'VLESS')]


def protocol_of(record):
    return str(record.get('protocol') or record.get('kind') or '').upper()


def display_name(record):
    """Keep curated identity on disk; the table already has a protocol column."""
    name = str(record.get('name') or record.get('id') or '')
    prefix = protocol_of(record) + '_'
    if name.upper().startswith(prefix) and re.fullmatch(r'#\d+_\d{4}[a-z]{3}\d{1,2}', name[len(prefix):], re.I):
        return name[len(prefix):]
    return name


def uses_udp_transport(record):
    return record.get('kind') == KIND and str(record.get('protocol') or '').lower() in (
        'hysteria', 'hysteria2', 'tuic', 'wireguard', 'shadowquic', 'masque')


def sort_records(records, mode='protocol', stats=None):
    import nova_profiles
    stats = stats or {}
    def key(record):
        name = nova_profiles.natural_key(display_name(record))
        if mode == 'name':
            return (name, record.get('id', ''))
        if mode == 'ping':
            entry = stats.get(record.get('id')) or {}
            ms = entry.get('last_ms') if (entry.get('last_ok_at') or 0) >= (entry.get('last_fail_at') or 0) else None
            if ms is None:
                ms = entry.get('rtt_ms')
            return (ms is None, float(ms or 0), name)
        return (protocol_of(record), name)
    return sorted(records, key=key)
