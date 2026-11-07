"""Isolated protocol checks: a private loopback helper and real HTTPS 204, never system routing."""

import json
import http.client
from functools import lru_cache
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

import nova_proxy
from nova_socks_probe import Deadline, _recv_exact, _skip_bound_address

TARGETS = ('https://www.google.com/generate_204', 'https://www.gstatic.com/generate_204',
           'https://cp.cloudflare.com/generate_204')
_slots = threading.BoundedSemaphore(3)


@lru_cache(maxsize=1)
def _tls_context():
    return ssl.create_default_context()


def https_status(port, target, budget):
    """Remote DNS via SOCKS5 and authenticated TLS; no optional PySocks dependency."""
    url = urlsplit(target)
    if url.scheme != 'https' or not url.hostname:
        raise ValueError('HTTPS probe target required')
    domain = url.hostname.encode('idna')
    if len(domain) > 255:
        raise ValueError('SOCKS domain exceeds 255 bytes')
    deadline = Deadline(budget)
    with socket.create_connection(('127.0.0.1', int(port)), timeout=deadline.timeout(cap=1.5)) as raw:
        raw.settimeout(deadline.timeout())
        raw.sendall(b'\x05\x01\x00')
        if _recv_exact(raw, 2, deadline) != b'\x05\x00':
            raise OSError('SOCKS authentication failed')
        raw.sendall(b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + struct.pack('!H', url.port or 443))
        reply = _recv_exact(raw, 4, deadline)
        if not reply or reply[:2] != b'\x05\x00' or not _skip_bound_address(raw, reply[3], deadline):
            raise OSError('SOCKS CONNECT failed')
        raw.settimeout(deadline.timeout())
        with _tls_context().wrap_socket(raw, server_hostname=url.hostname) as secure:
            path = (url.path or '/') + ('?' + url.query if url.query else '')
            secure.settimeout(deadline.timeout())
            secure.sendall((f'GET {path} HTTP/1.1\r\nHost: {url.netloc}\r\n'
                            'User-Agent: Nova/ProfileCheck\r\nConnection: close\r\n\r\n').encode('ascii'))
            with http.client.HTTPResponse(secure) as response:
                response.begin()
                return response.status


def probe_port(port, budget=12, should_stop=None, transport=https_status):
    started = time.monotonic()
    deadline = started + max(.2, float(budget))
    attempts = 0
    for index, target in enumerate(TARGETS):
        if should_stop and should_stop():
            return dict(ok=False, ms=None, status='cancelled', message='проверка отменена', _record=False)
        left = deadline - time.monotonic()
        if left <= .1:
            break
        attempts += 1
        before = time.monotonic()
        try:
            # Require an authenticated HTTPS 204, not a TCP listener, redirect or captive portal.
            if transport(port, target, max(.1, left / (len(TARGETS) - index))) == 204:
                return dict(ok=True, ms=max(0, round((time.monotonic() - before) * 1000)),
                    status='ok', message='HTTPS 204 через профиль', target=urlsplit(target).hostname, _record=True)
        except (OSError, http.client.HTTPException):
            # A failed target is not proof that the profile is broken; try an independent endpoint.
            continue
    return dict(ok=False, ms=None, status='inconclusive', _record=False, attempts=attempts,
                message='не удалось подтвердить HTTPS-доступ; профиль сохранён, можно повторить')


def test_record(record, base=None, should_stop=None, note_pid=None, budget=24):
    if str(record.get('protocol') or '').lower() in ('tailscale', 'zerotier', 'easytier'):
        return dict(ok=False, ms=None, status='inconclusive', _record=False,
                    message='Проверка без регистрации узла недоступна; профиль сохранён')
    should_stop = should_stop or (lambda: False)
    while not _slots.acquire(timeout=.2):
        if should_stop():
            return dict(ok=False, ms=None, status='cancelled', message='проверка отменена', _record=False)
    process = None
    work = None
    base = Path(base or nova_proxy.app_root())
    private = base / 'profiles/.runtime'
    try:
        if should_stop():
            return dict(ok=False, ms=None, status='cancelled', message='проверка отменена', _record=False)
        binary = nova_proxy.engine_for_record(record, base)
        if not Path(binary).is_file():
            return dict(ok=False, ms=None, status='local_error', message='не найдено ядро профиля', _record=False)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        config = nova_proxy.config_for_record(record, port)
        private.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix='profile-probe-', dir=private))
        config_path = work / 'config.json'
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding='utf-8')
        ready = work / 'ready.json'
        process = subprocess.Popen([binary, 'run', '--config', str(config_path), '--ready-file', str(ready),
                                    '--parent-pid', str(__import__('os').getpid())],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if note_pid:
            note_pid(process.pid, True)
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            if should_stop():
                return dict(ok=False, ms=None, status='cancelled', message='проверка отменена', _record=False)
            if process.poll() is not None:
                return dict(ok=False, ms=None, status='local_error', message='ядро не приняло конфигурацию', _record=False)
            if ready.is_file():
                try:
                    witness = json.loads(ready.read_text(encoding='utf-8'))
                except (OSError, ValueError):
                    time.sleep(.05)
                    continue
                if witness.get('pid') != process.pid:
                    return dict(ok=False, ms=None, status='local_error', message='неверное подтверждение запуска ядра', _record=False)
                return probe_port(port, budget=max(.2, deadline - time.monotonic()), should_stop=should_stop)
            time.sleep(.08)
        return dict(ok=False, ms=None, status='inconclusive', message='ядро не подтвердило готовность', _record=False)
    except (OSError, ValueError) as error:
        return dict(ok=False, ms=None, status='local_error', message=f'ошибка локальной проверки: {type(error).__name__}', _record=False)
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                if note_pid:
                    note_pid(process.pid, False)
            if work is not None:
                # Only this invocation's private directory, never another check or active tunnel.
                if not work.resolve().is_relative_to(private.resolve()) or not work.name.startswith('profile-probe-'):
                    raise RuntimeError('Unsafe profile probe cleanup path')
                shutil.rmtree(work)
        finally:
            _slots.release()
