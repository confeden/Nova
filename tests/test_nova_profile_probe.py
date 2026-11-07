"""Checks distinguish real HTTPS payload, blocked targets and local setup errors."""
import json
from pathlib import Path
import socket
import ssl
import threading
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import nova_profile_probe as probe
import nova_proxy


def test_failed_target_or_redirect_does_not_reject_working_profile():
    calls = []
    def transport(port, target, budget):
        calls.append(target)
        if len(calls) == 1:
            raise TimeoutError()
        return 302 if len(calls) == 2 else 204
    result = probe.probe_port(19999, transport=transport)
    assert result['ok'] and result['_record'] and len(calls) == 3


def test_inconclusive_check_never_records_a_failure_or_accepts_captive_portal():
    result = probe.probe_port(19999, transport=lambda *_: 200)
    assert not result['ok'] and not result['_record'] and result['status'] == 'inconclusive'


def test_cancelled_check_never_opens_a_socket():
    result = probe.probe_port(19999, should_stop=lambda: True,
                              transport=lambda *_: pytest.fail('cancelled check made network traffic'))
    assert result['status'] == 'cancelled' and not result['_record']


def test_real_socks_remote_dns_and_authenticated_https_204(tmp_path, monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False).sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path/'cert.pem', tmp_path/'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cafile=str(cert_path))
    monkeypatch.setattr(probe, '_tls_context', lambda: client_context)
    listener = socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(); listener.settimeout(4)
    errors, seen = [], []
    def exact(conn, count):
        data = b''
        while len(data) < count:
            part = conn.recv(count-len(data))
            if not part:
                raise EOFError()
            data += part
        return data
    def server():
        try:
            with listener.accept()[0] as conn:
                conn.settimeout(4)
                assert exact(conn,3) == b'\x05\x01\x00'
                conn.sendall(b'\x05\x00')
                assert exact(conn,4) == b'\x05\x01\x00\x03'
                host = exact(conn,exact(conn,1)[0]); port = exact(conn,2)
                seen.append((host,port))
                conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                with server_context.wrap_socket(conn,server_side=True) as secure:
                    request = secure.recv(4096)
                    assert b'GET /generate_204 HTTP/1.1' in request
                    secure.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
        except Exception as error:
            errors.append(error)
        finally:
            listener.close()
    thread=threading.Thread(target=server);thread.start()
    assert probe.https_status(listener.getsockname()[1],'https://localhost:44443/generate_204',4) == 204
    thread.join(5)
    assert not thread.is_alive() and not errors
    assert seen == [(b'localhost', (44443).to_bytes(2,'big'))]


def test_missing_core_is_local_error_and_preserves_profile(tmp_path):
    result = probe.test_record(dict(kind='proxy',path='unused'),base=tmp_path)
    assert result['status'] == 'local_error' and not result['_record']


def test_xray_native_profile_reaches_ready_and_only_its_own_helper_is_stopped(tmp_path, monkeypatch):
    import nova_profiles
    binary = Path(nova_proxy.engine_for_record({'kind':'vless'}))
    if not binary.is_file():
        pytest.skip('Build nova-xray first')
    document = {'outbounds':[{'tag':'fixture', 'protocol':'vmess', 'settings':{'vnext':[
        {'address':'127.0.0.1','port':9,'users':[{'id':'00000000-0000-4000-8000-000000000001','alterId':0}]}]}}]}
    node = nova_proxy.parse_many(json.dumps(document))[0][0]
    nova_profiles.import_candidates(tmp_path,[nova_proxy.candidate(node)])
    record = nova_profiles.list_profiles(tmp_path)[0]
    monkeypatch.setattr(nova_proxy,'engine_for_record',lambda *_:str(binary))
    seen, pids = [], []
    def ready(port, **_kwargs):
        seen.append(port)
        return dict(ok=True,ms=0,status='ok',_record=True)
    monkeypatch.setattr(probe,'probe_port',ready)
    sentinel = tmp_path/'profiles/.runtime/keep.json'
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.write_text('{}')
    result = probe.test_record(record,base=tmp_path,note_pid=lambda pid,active:pids.append((pid,active)),budget=8)
    assert result['ok'] and len(seen)==1
    assert len(pids)==2 and pids[0]==(pids[1][0],True) and pids[1][1] is False
    assert sentinel.is_file() and not list(sentinel.parent.glob('profile-probe-*'))
