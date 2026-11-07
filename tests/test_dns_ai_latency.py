import base64
import threading
import time

import pytest
import nova_dns_ai as dns
import nova_exit_probe


def test_latency_requires_a_real_dns_reply_and_uses_the_selected_local_proxy(monkeypatch):
    calls = []
    def fetch(kind, port, host, path, **kwargs):
        calls.append((kind, port, host, kwargs))
        query = base64.urlsafe_b64decode(path.split('dns=')[1] + '==')
        assert query[12:] == b'\x07example\x03com\x00\x00\x01\x00\x01'
        return query[:2] + b'\x81\x80' + query[4:]
    monkeypatch.setattr(nova_exit_probe, 'fetch_via_proxy', fetch)
    assert dns.measure_route_latency('http', 1371) >= 0
    assert calls[0][:3] == ('http', 1371, 'dns.dns-ai.ru')
    assert calls[0][3]['binary'] is True
    for body in (b'HTTP 200', b'\x00' * 12, b'\x4e\x56\x81\x82' + b'\x00' * 8):
        monkeypatch.setattr(nova_exit_probe, 'fetch_via_proxy', lambda *a, **k: body)
        with pytest.raises(nova_exit_probe.ProbeError):
            dns.measure_route_latency('socks5', 1370)


def settle(monitor):
    until = time.monotonic() + 3
    while time.monotonic() < until:
        with monitor._lock:
            if not monitor._running:
                return
        time.sleep(.005)
    pytest.fail('latency worker did not finish')


def test_samples_expire_and_a_replaced_helper_never_inherits_old_latency():
    now = [100.0]
    monitor = dns.RouteLatencyMonitor(probe=lambda kind, port: {1370: 80, 1371: 20}[port], clock=lambda: now[0])
    routes = {'warp-socks': (('main', 1), 'socks5', 1370), 'opera-http': (('second', 2), 'http', 1371)}
    monitor.refresh(routes); settle(monitor)
    assert monitor.snapshot(routes)['latency_ms'] == {'warp-socks': 80, 'opera-http': 20}
    routes['opera-http'] = (('second', 3), 'http', 1371)
    assert monitor.snapshot(routes)['latency_ms'] == {'warp-socks': 80}
    now[0] += 91
    assert monitor.snapshot(routes)['latency_ms'] == {}
    monitor.refresh({})
    assert not any(monitor.snapshot({})['vpn_up'].values())


def test_slow_probe_is_off_thread_and_cannot_publish_for_an_old_helper():
    entered, release = threading.Event(), threading.Event()
    def blocked(kind, port):
        entered.set()
        assert release.wait(3)
        return 10
    monitor = dns.RouteLatencyMonitor(probe=blocked)
    old = {'warp-socks': (('old', 1), 'socks5', 1370)}
    replacement = {'warp-socks': (('new', 2), 'socks5', 1370)}
    monitor.refresh(old)
    assert entered.wait(1)
    monitor.refresh(replacement)
    release.set(); settle(monitor)
    assert monitor.snapshot(replacement)['latency_ms'] == {}


def test_failed_probe_does_not_advertise_a_fast_route():
    def failed(kind, port):
        raise nova_exit_probe.ProbeError('offline')
    monitor = dns.RouteLatencyMonitor(probe=failed)
    routes = {'warp-socks': (('main', 1), 'socks5', 1370)}
    monitor.refresh(routes); settle(monitor)
    assert monitor.snapshot(routes) == {'vpn_up': {'warp-socks': True, 'opera-http': False},
                                       'latency_ms': {}, 'latency_errors': {'warp-socks': 'offline'}}


def test_proxy_fetch_preserves_binary_dns_body():
    from test_nova_exit_probe import FakeSocks5Server
    body = b'\x4e\x56\x81\x80' + b'\x00' * 8 + b'\xff\xfe'
    server = FakeSocks5Server(cf_body=body)
    try:
        result = nova_exit_probe.fetch_via_proxy('socks5', server.port, 'resolver.test', '/',
                                                 use_tls=False, binary=True)
        assert result == body
    finally:
        server.close()


@pytest.mark.parametrize('status', ['200', '503'])
def test_http2_wire_exchange_requires_success_status(status):
    import h2.config
    import h2.connection
    import h2.events
    class Peer:
        def __init__(self):
            self.server = h2.connection.H2Connection(
                config=h2.config.H2Configuration(client_side=False, header_encoding='utf-8'))
            self.server.initiate_connection()
            self.buffer = self.server.data_to_send()
        def settimeout(self, timeout):
            assert timeout > 0
        def sendall(self, data):
            for event in self.server.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    headers = dict(event.headers)
                    assert headers[':authority'] == 'resolver.test'
                    assert headers['accept'] == 'application/dns-message'
                    self.server.send_headers(event.stream_id, [(':status', status)])
                    self.server.send_data(event.stream_id, b'\x00\xffDNS', end_stream=True)
            self.buffer += self.server.data_to_send()
        def recv(self, count):
            data, self.buffer = self.buffer[:count], self.buffer[count:]
            return data
    peer = Peer()
    if status == '200':
        assert nova_exit_probe._http2_body(peer, 'resolver.test', '/dns-query', nova_exit_probe._Deadline(2)) == b'\x00\xffDNS'
    else:
        with pytest.raises(nova_exit_probe.ProbeError, match='503'):
            nova_exit_probe._http2_body(peer, 'resolver.test', '/dns-query', nova_exit_probe._Deadline(2))
