"""Выпуск профилей Proton: что обязано совпасть с Android байт в байт и что обязано пережить сеть.

Что закреплено и почему:
- криптография — золотой вектор из and-proton.md §4.4 (seed = 00..1f): PEM для
  `/vpn/v1/certificate` и приватный ключ WireGuard. Разойдись они хоть в бите — Proton
  зарегистрирует один ключ, а туннель поднимется с другим и будет молчать;
- разбор `/vpn/logicals` — фильтры Tier/Status и «первый живой физический узел»
  (Android `fetchFreeServers`), чередование стран и портов;
- текст `.conf` — ровно DESIGN §7 (I1 от nova_quic_initial, при его отсутствии — заглушка);
- G56: `/auth/v4/credentialless` не идемпотентен, «Session already tied» лечится новой
  сессией и ровно одним повтором — проверяется на поддельном API на 127.0.0.1;
- живой сертификат не регистрируется повторно (Android `certAlive`);
- `407` с `X-Nova-Relay-Reason: outdated-client` превращается в «ключ релея устарел —
  обновите Nova», а пароль релея не попадает в журнал;
- чужой файл в папке (даже `wg-NL-FREE-12.conf` или `NL-FREE-1.conf`) не удаляется и не
  перезаписывается: своё доказывается ключом внутри, а не именем;
- новый ключ до записи набора лежит в учётке как pending, и прерванный прогон не выдаёт свежий
  сертификат за профили на старом ключе;
- полный свежий набор переиспользуется без сети, неудача включает паузу — иначе каждое
  подключение заводит новую анонимную учётку Proton.

Сервер и прокси настоящие, на localhost: мок сокета проверял бы мок, а не протокол.
"""

import base64
import hashlib
import json
import os
import random
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import nova_proton
from nova_proton import (
    PORTS,
    ProtonApiError,
    ProtonClient,
    RELAY_OUTDATED_MESSAGE,
    build_device_profile,
    build_proton_conf,
    conf_filename,
    derive_keys,
    is_valid_device_profile,
    issue_profiles,
    order_nodes,
    parse_logicals,
    plan_profiles,
    random_junk,
    redact_proxy_url,
    write_nodes_file,
)

GOLDEN_SEED = bytes(range(32))
GOLDEN_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n"
    "-----END PUBLIC KEY-----\n"
)
GOLDEN_WG_PRIVATE = "OJTupJxYCu+BaTV2K+BJVZ1tFEDe3hLmoSXxhB//jm8="
GOLDEN_WG_PUBLIC = "RwHQhIhFH1RaQJ+1iuPlhYHKQKw/fxFGmM1x3qxzygE="

RELAY_PASSWORD = "Relay-Pa55word-xyz"
OLD_SEED = hashlib.sha256(b"old-set").digest()


def fake_key(label):
    return base64.b64encode(hashlib.sha256(label.encode("utf-8")).digest()).decode("ascii")


def conf_body(private_key, endpoint="198.51.100.200:443"):
    return (f"[Interface]\nPrivateKey = {private_key}\nAddress = 10.2.0.2/32\n\n"
            f"[Peer]\nPublicKey = {fake_key('peer')}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}\n")


def logical(name, country, city, ip, *, tier=0, status=1, load=50, score=1.0, servers=None):
    return {
        "Name": name,
        "ExitCountry": country,
        "City": city,
        "Tier": tier,
        "Status": status,
        "Load": load,
        "Score": score,
        "Servers": servers if servers is not None else [
            {"Status": 1, "EntryIP": ip, "X25519PublicKey": fake_key(name)},
        ],
    }


def canned_logicals(per_country=4, countries=("NL", "US", "CA")):
    items = []
    serial = 1
    for c_index, country in enumerate(countries):
        for n in range(per_country):
            items.append(logical(
                f"{country}-FREE#{serial}", country, f"City{c_index}",
                f"198.51.{c_index}.{n + 1}", load=10 + n, score=float(n),
            ))
            serial += 1
    return {"Code": 1000, "LogicalServers": items}


def closed_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class I1Guard:
    """Реальный nova_quic_initial, если он импортируется; иначе заглушка в sys.modules на время теста."""

    STUB_I1 = "<b 0xc000000001" + "ab" * 40 + ">"

    def __init__(self, testcase):
        try:
            import nova_quic_initial  # noqa: F401
            self.real = True
        except Exception:
            self.real = False
            stub = types.ModuleType("nova_quic_initial")
            stub.WHITE_SNI = ("example.com",)
            stub.pick_sni = lambda index, rng=None: "example.com"
            stub.build_i1 = lambda sni, rng=os.urandom: I1Guard.STUB_I1
            patcher = mock.patch.dict(sys.modules, {"nova_quic_initial": stub})
            patcher.start()
            testcase.addCleanup(patcher.stop)

    def check(self, testcase, i1_value):
        testcase.assertTrue(i1_value.startswith("<b 0x"), i1_value[:20])
        if not self.real:
            testcase.assertEqual(i1_value, self.STUB_I1)
            return
        import nova_quic_initial
        packet = nova_quic_initial.i1_bytes(i1_value)
        testcase.assertEqual(len(packet), 1250)
        decoded = nova_quic_initial.decode_initial(packet)
        testcase.assertIn(decoded["sni"], nova_quic_initial.WHITE_SNI)


# ---------------------------------------------------------------------------------------------
# Fake Proton API
# ---------------------------------------------------------------------------------------------

class FakeProtonApi:
    """Поддельный Proton API: сессии, credentialless, logicals, certificate — с настраиваемыми отказами."""

    def __init__(self, logicals=None, *, tied_failures=0, credentialless_error=None,
                 logicals_status=200, logicals_raw=None, hv_answer=None):
        self.logicals = logicals if logicals is not None else canned_logicals()
        self.tied_failures = tied_failures
        self.credentialless_error = credentialless_error
        self.hv_answer = hv_answer   # a 9001 is lifted by exactly this HV header pair
        self.logicals_status = logicals_status
        self.logicals_raw = logicals_raw
        self.lock = threading.Lock()
        self.requests = []   # (method, path, headers, body)
        self.sessions = 0
        self.users = 0
        api = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def _body(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                return json.loads(raw.decode("utf-8")) if raw else None

            def _send(self, status, obj=None, raw=None):
                data = raw if raw is not None else json.dumps(obj).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json" if raw is None else "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                api.handle(self, "POST")

            def do_GET(self):
                api.handle(self, "GET")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def count(self, path):
        with self.lock:
            return sum(1 for _m, p, _h, _b in self.requests if p.split("?")[0] == path)

    def bodies(self, path):
        with self.lock:
            return [b for _m, p, _h, b in self.requests if p.split("?")[0] == path]

    def headers_of(self, path):
        with self.lock:
            return [h for _m, p, h, _b in self.requests if p.split("?")[0] == path]

    def _user_auth_ok(self, headers):
        return str(headers.get("Authorization", "")).startswith("Bearer user-token-")

    def handle(self, handler, method):
        body = handler._body()
        headers = {k: v for k, v in handler.headers.items()}
        path = handler.path
        with self.lock:
            self.requests.append((method, path, headers, body))
        if method == "POST" and path == "/auth/v4/sessions":
            with self.lock:
                self.sessions += 1
                n = self.sessions
            handler._send(200, {"Code": 1000, "UID": f"carrier-{n}", "AccessToken": f"carrier-token-{n}",
                                "RefreshToken": f"carrier-refresh-{n}", "Scopes": []})
            return
        if method == "POST" and path == "/auth/v4/credentialless":
            if not str(headers.get("Authorization", "")).startswith("Bearer carrier-token-"):
                handler._send(401, {"Code": 401, "Error": "Invalid access token"})
                return
            with self.lock:
                tied = self.tied_failures > 0
                if tied:
                    self.tied_failures -= 1
            if tied:
                handler._send(422, {"Code": 2500, "Error": "Session already tied to a user"})
                return
            lowered = {k.lower(): v for k, v in headers.items()}
            verified = (self.hv_answer is not None
                        and lowered.get("x-pm-human-verification-token") == self.hv_answer
                        and lowered.get("x-pm-human-verification-token-type") == "captcha")
            if self.credentialless_error is not None and not verified:
                status, obj = self.credentialless_error
                handler._send(status, obj)
                return
            with self.lock:
                self.users += 1
                n = self.users
            handler._send(200, {"Code": 1000, "UID": f"user-{n}", "AccessToken": f"user-token-{n}",
                                "RefreshToken": f"user-refresh-{n}", "Scopes": ["parent", "user", "vpn"]})
            return
        if method == "GET" and path == "/vpn/logicals?Tier=0":
            if not self._user_auth_ok(headers):
                handler._send(422, {"Code": 9106, "Error": "MissingScopes"})
                return
            if self.logicals_raw is not None:
                handler._send(self.logicals_status, raw=self.logicals_raw)
                return
            handler._send(self.logicals_status, self.logicals)
            return
        if method == "POST" and path == "/vpn/v1/certificate":
            if not self._user_auth_ok(headers):
                handler._send(422, {"Code": 9106, "Error": "MissingScopes"})
                return
            now = int(time.time())
            handler._send(200, {"Code": 1000, "SerialNumber": "1", "ClientKeyFingerprint": "fp",
                                "Certificate": "-----BEGIN CERTIFICATE-----\n...", "ExpirationTime": now + 365 * 86400,
                                "RefreshTime": now + 274 * 86400, "ServerPublicKey": "x"})
            return
        handler._send(404, {"Code": 404, "Error": "not found"})


class FakeRejectingProxy:
    """HTTP-прокси, отвечающий на любой CONNECT кодом 407 (с заголовком релея или без)."""

    def __init__(self, outdated=True, current="1.40"):
        self.outdated = outdated
        self.current = current
        self.connects = []
        self.lock = threading.Lock()
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self._listener.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(5.0)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            with self.lock:
                self.connects.append(data.decode("latin-1"))
            extra = ""
            if self.outdated:
                extra = (f"X-Nova-Relay-Reason: outdated-client\r\nX-Nova-Relay-Platform: pc\r\n"
                         f"X-Nova-Relay-Current: {self.current}\r\n")
            conn.sendall((
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                f"{extra}Content-Length: 0\r\nConnection: close\r\n\r\n"
            ).encode("latin-1"))
        except OSError:
            pass
        finally:
            conn.close()

    def url(self, password=RELAY_PASSWORD):
        return f"http://nova-pc-1.39:{password}@127.0.0.1:{self.port}"

    def close(self):
        self._stop.set()
        self._listener.close()


# ---------------------------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------------------------

class CryptoTests(unittest.TestCase):
    def test_golden_vector(self):
        keys = derive_keys(GOLDEN_SEED)
        self.assertEqual(keys["ed25519_pem"], GOLDEN_PEM)
        self.assertEqual(keys["wg_private"], GOLDEN_WG_PRIVATE)
        self.assertEqual(keys["wg_public"], GOLDEN_WG_PUBLIC)

    def test_spki_pem_is_byte_identical_to_cryptography(self):
        """Android собирает PEM строкой из фиксированной шапки; стандартный сериализатор даёт те же байты."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        for seed in (GOLDEN_SEED, bytes(32), bytes([0xFF]) * 32, hashlib.sha256(b"nova").digest()):
            reference = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
            self.assertEqual(derive_keys(seed)["ed25519_pem"].encode("ascii"), reference)
        self.assertTrue(GOLDEN_PEM.split("\n")[1].startswith("MCowBQYDK2VwAyEA"))

    def test_proton_side_birational_map_matches_wireguard_public_key(self):
        """Proton выводит X25519 из присланного ed25519: u = (1+y)/(1-y) обязан совпасть с нашим ключом."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        p = 2 ** 255 - 19
        for seed in (GOLDEN_SEED, hashlib.sha256(b"second").digest()):
            ed_pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            y = int.from_bytes(ed_pub, "little") & ((1 << 255) - 1)
            u = (1 + y) * pow((1 - y) % p, p - 2, p) % p
            self.assertEqual(base64.b64encode(u.to_bytes(32, "little")).decode("ascii"),
                             derive_keys(seed)["wg_public"])

    def test_seed_must_be_32_bytes(self):
        with self.assertRaises(ValueError):
            derive_keys(b"\x00" * 31)


# ---------------------------------------------------------------------------------------------
# Node list, ordering, config text
# ---------------------------------------------------------------------------------------------

class LogicalsParsingTests(unittest.TestCase):
    def test_filters_and_first_valid_physical(self):
        payload = {
            "Code": 1000,
            "LogicalServers": [
                logical("NL-FREE#1", "NL", "Amsterdam", "", load=33, score=2.5, servers=[
                    {"Status": 0, "EntryIP": "203.0.113.1", "X25519PublicKey": fake_key("a")},
                    {"Status": 1, "EntryIP": "203.0.113.2", "X25519PublicKey": fake_key("b")},
                    {"Status": 1, "EntryIP": "203.0.113.3", "X25519PublicKey": fake_key("c")},
                ]),
                logical("US-PAID#1", "US", "NYC", "203.0.113.10", tier=2),
                logical("US-FREE#2", "US", "NYC", "203.0.113.11", status=0),
                logical("CA-FREE#3", "CA", "Montreal", "", servers=[
                    {"Status": 1, "EntryIP": "", "X25519PublicKey": fake_key("d")},
                    {"Status": 1, "EntryIP": "203.0.113.20", "X25519PublicKey": "not-a-key"},
                ]),
                {"Tier": "0", "Status": "1", "Servers": [
                    {"Status": 1, "EntryIP": "203.0.113.30", "X25519PublicKey": fake_key("e")},
                ]},
                {"Tier": 0, "Status": 1, "Name": "JP-FREE#4"},
                "garbage",
            ],
        }
        nodes = parse_logicals(payload)
        self.assertEqual([n["entry_ip"] for n in nodes], ["203.0.113.2", "203.0.113.30"])
        first, fallback = nodes
        self.assertEqual(first["name"], "NL-FREE#1")
        self.assertEqual(first["country"], "NL")
        self.assertEqual(first["city"], "Amsterdam")
        self.assertEqual(first["peer_public_key"], fake_key("b"))
        self.assertEqual(first["load"], 33)
        self.assertEqual(first["score"], 2.5)
        self.assertEqual(fallback["name"], "PROTON")
        self.assertEqual(fallback["country"], "??")
        self.assertEqual(fallback["load"], 100)
        self.assertEqual(fallback["score"], float("inf"))

    def test_garbage_payloads_give_nothing(self):
        for payload in (None, [], "x", {}, {"LogicalServers": "x"}, {"LogicalServers": [None]}):
            self.assertEqual(parse_logicals(payload), [])

    def test_bundled_file_round_trips(self):
        nodes = parse_logicals(canned_logicals(per_country=2))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "proton_nodes.json")
            self.assertEqual(write_nodes_file(path, nodes, generated_at_ms=1), 6)
            loaded = nova_proton.load_bundled_nodes(path)
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        self.assertEqual(set(doc["nodes"][0].keys()),
                         {"server_name", "country", "city", "entry_ip", "peer_public_key"})
        self.assertEqual(sorted(n["entry_ip"] for n in loaded), sorted(n["entry_ip"] for n in nodes))
        self.assertTrue(all(n["load"] == 50 and n["score"] == 0.0 for n in loaded))

    def test_shipped_node_list_is_usable(self):
        """profiles/AWG Proton/proton_nodes.json — копия ассета Android: 50 узлов, все валидны."""
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(repo, "profiles", "AWG Proton", "proton_nodes.json")
        if not os.path.exists(path):
            self.skipTest("proton_nodes.json ещё не разложен в profiles/")
        nodes = nova_proton.load_bundled_nodes(path)
        self.assertEqual(len(nodes), 50)
        self.assertEqual(len({n["entry_ip"] for n in nodes}), 50)


def node(name, country, load, city="C"):
    return {"name": name, "country": country, "city": city, "entry_ip": f"198.51.100.{load}",
            "peer_public_key": fake_key(name), "load": load, "score": 0.0}


class OrderingTests(unittest.TestCase):
    def test_round_robin_by_country_least_loaded_first(self):
        nodes = [
            node("NL-FREE#1", "NL", 10), node("NL-FREE#2", "NL", 20), node("NL-FREE#3", "NL", 30),
            node("NL-FREE#4", "NL", 40), node("US-FREE#1", "US", 15), node("US-FREE#2", "US", 25),
            node("CA-FREE#1", "CA", 5),
        ]
        random.Random(7).shuffle(nodes)
        self.assertEqual(
            [n["name"] for n in order_nodes(nodes)],
            ["CA-FREE#1", "NL-FREE#1", "US-FREE#1", "NL-FREE#2", "US-FREE#2", "NL-FREE#3", "NL-FREE#4"],
        )

    def test_duplicates_are_dropped(self):
        a = node("NL-FREE#1", "NL", 10)
        same_pair = dict(a, name="NL-FREE#9")
        same_file = dict(node("nl-free#1", "NL", 11))
        self.assertEqual([n["name"] for n in order_nodes([a, same_pair, same_file])], ["NL-FREE#1"])

    def test_ports_rotate_by_index(self):
        nodes = [node(f"NL-FREE#{i}", "NL", i) for i in range(1, 21)]
        plan = plan_profiles(nodes, count=20)
        self.assertEqual(len(plan), 20)
        self.assertEqual([item["port"] for item in plan], [PORTS[i % len(PORTS)] for i in range(20)])
        # Ordered by the pass rate measured through wireproxy-awg on 2026-09-13.
        self.assertEqual(PORTS, (443, 1194, 88, 5060, 1224, 80, 4569, 51820, 4500))
        self.assertEqual(plan[9]["port"], 443)

    def test_taken_names_are_skipped_and_ports_stay_dense(self):
        nodes = [node(f"NL-FREE#{i}", "NL", i) for i in range(1, 6)]
        plan = plan_profiles(nodes, count=3, taken={"nl-free-1.conf"})
        self.assertEqual([item["filename"] for item in plan], ["NL-FREE-2.conf", "NL-FREE-3.conf", "NL-FREE-4.conf"])
        self.assertEqual([item["port"] for item in plan], list(PORTS[:3]))

    def test_count_caps_the_plan(self):
        nodes = [node(f"US-FREE#{i}", "US", i) for i in range(1, 11)]
        self.assertEqual(len(plan_profiles(nodes, count=4)), 4)
        self.assertEqual(len(plan_profiles(nodes, count=50)), 10)

    def test_live_nodes_take_the_places_first(self):
        nodes = [
            node("NL-FREE#1", "NL", 10), node("NL-FREE#2", "NL", 20), node("NL-FREE#3", "NL", 30),
            node("US-FREE#1", "US", 15), node("US-FREE#2", "US", 25), node("CA-FREE#1", "CA", 5),
        ]
        ip = {n["name"]: n["entry_ip"] for n in nodes}
        liveness = {
            ip["NL-FREE#3"]: 70, ip["NL-FREE#2"]: 60,  # both answer: the nearer first, whatever the load
            ip["NL-FREE#1"]: None,                      # silent: behind every unprobed node
            ip["CA-FREE#1"]: None,
            # US nodes were not probed at all
        }
        self.assertEqual(
            [n["name"] for n in order_nodes(nodes, liveness)],
            ["NL-FREE#2", "US-FREE#1", "CA-FREE#1", "NL-FREE#3", "US-FREE#2", "NL-FREE#1"],
        )
        plan = plan_profiles(nodes, count=2, liveness={ip["US-FREE#2"]: 90})
        self.assertEqual([item["node"]["name"] for item in plan], ["US-FREE#2", "CA-FREE#1"])
        # Without a probe the order is exactly the old one.
        self.assertEqual([n["name"] for n in order_nodes(nodes)], [n["name"] for n in order_nodes(nodes, {})])

    def test_a_shared_name_keeps_the_address_that_answers(self):
        silent = node("NL-FREE#7", "NL", 10)
        live = dict(node("NL-FREE#7", "NL", 90), entry_ip="203.0.113.7", peer_public_key=fake_key("other"))
        ordered = order_nodes([silent, live], {silent["entry_ip"]: None, "203.0.113.7": 80})
        self.assertEqual([n["entry_ip"] for n in ordered], ["203.0.113.7"])


class ConfTextTests(unittest.TestCase):
    def test_conf_text_exact(self):
        text = build_proton_conf(
            GOLDEN_WG_PRIVATE,
            {"name": "NL-FREE#128", "city": "Amsterdam", "entry_ip": "185.107.56.235",
             "peer_public_key": "ocCFVEDN+6fTFKg96mQ6fW+oBTTZ9gW6xEk8gxTiR1E="},
            4500,
            {"jc": 5, "jmin": 42, "jmax": 99},
            "<b 0xc0ffee>",
        )
        self.assertEqual(text, (
            "[Interface]\n"
            "PrivateKey = OJTupJxYCu+BaTV2K+BJVZ1tFEDe3hLmoSXxhB//jm8=\n"
            "Address = 10.2.0.2/32\n"
            "DNS = 10.2.0.1\n"
            "MTU = 1420\n"
            "S1 = 0\n"
            "S2 = 0\n"
            "S3 = 0\n"
            "S4 = 0\n"
            "Jc = 5\n"
            "Jmin = 42\n"
            "Jmax = 99\n"
            "H1 = 1\n"
            "H2 = 2\n"
            "H3 = 3\n"
            "H4 = 4\n"
            "I1 = <b 0xc0ffee>\n"
            "\n"
            "[Peer]\n"
            "# NL-FREE#128 (Amsterdam)\n"
            "PublicKey = ocCFVEDN+6fTFKg96mQ6fW+oBTTZ9gW6xEk8gxTiR1E=\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "Endpoint = 185.107.56.235:4500\n"
            "PersistentKeepalive = 25\n"
        ))

    def test_blank_or_garbage_i1_is_omitted(self):
        base = {"name": "US-FREE#1", "city": "", "entry_ip": "2001:db8::1", "peer_public_key": fake_key("u")}
        for i1 in ("", "   ", "<b 0x>", "garbage", "<b 0xzz>"):
            text = build_proton_conf(GOLDEN_WG_PRIVATE, base, 443, {"jc": 3, "jmin": 30, "jmax": 50}, i1)
            self.assertNotIn("I1", text)
        self.assertIn("Endpoint = [2001:db8::1]:443\n", text)
        self.assertIn("# US-FREE#1\n", text)

    def test_api_strings_cannot_inject_config_lines(self):
        text = build_proton_conf(
            GOLDEN_WG_PRIVATE,
            {"name": "NL-FREE#1\nPrivateKey = evil", "city": "A\r\nEndpoint = 6.6.6.6:1",
             "entry_ip": "198.51.100.1", "peer_public_key": fake_key("n")},
            80, {"jc": 3, "jmin": 30, "jmax": 50},
        )
        lines = text.splitlines()
        self.assertEqual(sum(1 for line in lines if line.startswith("PrivateKey")), 1)
        self.assertEqual(sum(1 for line in lines if line.startswith("Endpoint")), 1)
        self.assertIn("# NL-FREE#1 PrivateKey = evil (A  Endpoint = 6.6.6.6:1)", lines)

    def test_filenames(self):
        self.assertEqual(conf_filename("NL-FREE#128"), "NL-FREE-128.conf")
        self.assertEqual(conf_filename('bad:/name#1'), "bad__name-1.conf")
        self.assertEqual(conf_filename(""), "PROTON.conf")

    def test_junk_bounds(self):
        rng = random.Random(1)
        for _ in range(2000):
            junk = random_junk(rng)
            self.assertTrue(3 <= junk["jc"] <= 8)
            self.assertTrue(30 <= junk["jmin"] <= 70)
            self.assertTrue(junk["jmin"] + 20 <= junk["jmax"] <= min(junk["jmin"] + 80, 150))


class DeviceProfileTests(unittest.TestCase):
    def test_never_ru_and_always_valid(self):
        rng = random.Random(3)
        for _ in range(300):
            device = build_device_profile(rng)
            self.assertTrue(is_valid_device_profile(device))
            self.assertNotEqual(device["region_code"], "RU")
            self.assertTrue(10 ** 12 <= device["device_name_hash"] < 9 * 10 ** 15)

    def test_ru_or_incomplete_frame_is_rejected(self):
        device = build_device_profile(random.Random(4))
        self.assertFalse(is_valid_device_profile(dict(device, region_code="RU")))
        self.assertFalse(is_valid_device_profile({k: v for k, v in device.items() if k != "model"}))
        self.assertFalse(is_valid_device_profile(None))


class LayoutConstantsTests(unittest.TestCase):
    def test_constants_agree_with_nova_profiles(self):
        try:
            import nova_profiles
        except Exception:
            self.skipTest("nova_profiles ещё не готов")
        self.assertEqual(nova_proton.PROFILES_DIRNAME, nova_profiles.PROFILES_DIRNAME)
        self.assertEqual(nova_proton.GROUP_PROTON, nova_profiles.GROUP_PROTON)


# ---------------------------------------------------------------------------------------------
# Proxy hygiene and the relay's 407
# ---------------------------------------------------------------------------------------------

class RelayRejectionTests(unittest.TestCase):
    def test_redaction(self):
        self.assertEqual(redact_proxy_url("https://nova-pc-1.39:p%40ss@relay.nova-app.eu:8443"),
                         "https://relay.nova-app.eu:8443")
        self.assertEqual(redact_proxy_url("http://127.0.0.1:1371"), "http://127.0.0.1:1371")
        scrub = nova_proton._Scrubber([f"https://nova-pc-1.39:{RELAY_PASSWORD}@relay.nova-app.eu:8443"])
        cleaned = scrub(f"boom https://nova-pc-1.39:{RELAY_PASSWORD}@relay.nova-app.eu:8443 and {RELAY_PASSWORD}")
        self.assertNotIn(RELAY_PASSWORD, cleaned)
        self.assertIn("https://relay.nova-app.eu:8443", cleaned)

    def test_outdated_client_407_is_reported_in_words(self):
        proxy = FakeRejectingProxy(outdated=True, current="1.40")
        self.addCleanup(proxy.close)
        logs = []
        client = ProtonClient(build_device_profile(random.Random(1)), log=logs.append,
                              proxies=[proxy.url()], direct=False, hosts=("https://vpn-api.proton.me",))
        self.addCleanup(client.close)
        with self.assertRaises(ProtonApiError) as ctx:
            client.call("POST", "/auth/v4/sessions", body={})
        self.assertIn(RELAY_OUTDATED_MESSAGE, ctx.exception.message)
        self.assertIn("1.40", ctx.exception.message)
        self.assertTrue(ctx.exception.relay_outdated)
        self.assertTrue(client.relay_outdated)
        self.assertTrue(any("Proxy-Authorization: Basic" in c for c in proxy.connects))
        joined = "\n".join(logs)
        self.assertIn(RELAY_OUTDATED_MESSAGE, joined)
        self.assertIn(f"http://127.0.0.1:{proxy.port}", joined)
        self.assertNotIn(RELAY_PASSWORD, joined)
        self.assertNotIn(RELAY_PASSWORD, ctx.exception.message)

        # A rejected proxy is not asked again within the same run.
        seen = len(proxy.connects)
        with self.assertRaises(ProtonApiError) as again:
            client.call("GET", "/vpn/logicals?Tier=0")
        self.assertEqual(len(proxy.connects), seen)
        self.assertIn(RELAY_OUTDATED_MESSAGE, again.exception.message)

    def test_bare_407_is_not_called_outdated(self):
        proxy = FakeRejectingProxy(outdated=False)
        self.addCleanup(proxy.close)
        logs = []
        client = ProtonClient(build_device_profile(random.Random(1)), log=logs.append,
                              proxies=[proxy.url()], direct=False, hosts=("https://vpn-api.proton.me",))
        self.addCleanup(client.close)
        with self.assertRaises(ProtonApiError) as ctx:
            client.call("POST", "/auth/v4/sessions", body={})
        self.assertNotIn(RELAY_OUTDATED_MESSAGE, ctx.exception.message)
        self.assertIn("407", ctx.exception.message)
        self.assertFalse(client.relay_outdated)

    def test_issue_profiles_surfaces_outdated_relay(self):
        proxy = FakeRejectingProxy(outdated=True)
        self.addCleanup(proxy.close)
        logs = []
        with tempfile.TemporaryDirectory() as base, \
                mock.patch.object(nova_proton, "API_HOSTS", (f"https://127.0.0.1:{closed_port()}",)):
            summary = issue_profiles(base, log=logs.append, proxies=[proxy.url()], count=5)
            with open(os.path.join(base, "profiles", "AWG Proton", "proton_account.json"), encoding="utf-8") as fh:
                account_text = fh.read()
            # The cooldown answer still says why, and the stored failure carries no password.
            again = issue_profiles(base, log=logs.append, proxies=[proxy.url()], count=5)
        self.assertFalse(summary["ok"])
        self.assertTrue(summary["relay_outdated"])
        self.assertIn(RELAY_OUTDATED_MESSAGE, summary["error"])
        self.assertNotIn(RELAY_PASSWORD, "\n".join(logs) + summary["error"])
        self.assertNotIn(RELAY_PASSWORD, account_text)
        self.assertIn(RELAY_OUTDATED_MESSAGE, json.loads(account_text)["last_error"])
        self.assertTrue(again["relay_outdated"])
        self.assertIn("повтор позже", again["error"])
        self.assertNotIn(RELAY_PASSWORD, again["error"])
        # An updated build logs in under a new version: the old refusal does not hold it back.
        updated = proxy.url().replace("nova-pc-1.39", "nova-pc-1.40")
        self.assertTrue(nova_proton.should_issue(json.loads(account_text), time.time(), False,
                                                 proxies=[updated])[0])
        self.assertFalse(nova_proton.should_issue(json.loads(account_text), time.time(), False,
                                                  proxies=[proxy.url()])[0])


# ---------------------------------------------------------------------------------------------
# Full runs against the fake API
# ---------------------------------------------------------------------------------------------

class IssueProfilesTests(unittest.TestCase):
    def setUp(self):
        published = mock.patch("nova_proton.fetch_published_nodes", return_value=[])
        self.feed = published.start()
        self.addCleanup(published.stop)
        self.i1 = I1Guard(self)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name
        self.group = os.path.join(self.base, "profiles", "AWG Proton")
        os.makedirs(self.group)
        self.logs = []

    def start_api(self, **kwargs):
        api = FakeProtonApi(**kwargs)
        self.addCleanup(api.close)
        patcher = mock.patch.object(nova_proton, "API_HOSTS", (api.url,))
        patcher.start()
        self.addCleanup(patcher.stop)
        return api

    def account(self):
        with open(os.path.join(self.group, "proton_account.json"), "r", encoding="utf-8") as fh:
            return json.load(fh)

    def confs(self):
        return sorted(name for name in os.listdir(self.group) if name.endswith(".conf"))

    def read_conf(self, name):
        with open(os.path.join(self.group, name), "r", encoding="utf-8") as fh:
            return fh.read()

    def conf_value(self, text, key):
        for line in text.splitlines():
            if line.startswith(f"{key} = "):
                return line.split(" = ", 1)[1]
        return None

    def write_file(self, name, body):
        with open(os.path.join(self.group, name), "w", encoding="utf-8") as fh:
            fh.write(body)

    def write_account(self, account):
        with open(os.path.join(self.group, "proton_account.json"), "w", encoding="utf-8") as fh:
            json.dump(account, fh)

    def write_old_set(self, *, cert_days=10, checked_hours_ago=48, source="live"):
        """Прежний набор этой установки: учётка со старым ключом, ZZ-FREE-999.conf на нём и чужой my-own.conf."""
        keys = derive_keys(OLD_SEED)
        now = int(time.time())
        self.write_account({
            "version": 1,
            "seed_b64": base64.b64encode(OLD_SEED).decode("ascii"),
            "wg_public": keys["wg_public"],
            "set_wg_public": keys["wg_public"],
            "cert_expires_at": now + cert_days * 86400,
            "registered_at": now - 300 * 86400,
            "device": build_device_profile(random.Random(9)),
            "device_name": "Nova PC",
            "generated_files": ["ZZ-FREE-999.conf"],
            "requested_count": 50,
            "nodes_source": source,
            "nodes_checked_at": now - checked_hours_ago * 3600,
        })
        self.write_file("ZZ-FREE-999.conf", conf_body(keys["wg_private"]))
        self.write_file("my-own.conf", conf_body(fake_key("mine")))

    def test_already_tied_retries_once_with_a_fresh_session(self):
        api = self.start_api(tied_failures=1)
        self.write_old_set()
        summary = issue_profiles(self.base, log=self.logs.append, count=10)
        self.assertTrue(summary["ok"], summary)
        self.assertEqual(summary["count"], 10)
        self.assertTrue(summary["registered"])
        self.assertEqual(summary["nodes_source"], "live")

        # Retry took a NEW carrier session and happened exactly once.
        self.assertEqual(api.count("/auth/v4/sessions"), 2)
        cred_headers = api.headers_of("/auth/v4/credentialless")
        self.assertEqual([h.get("x-pm-uid") for h in cred_headers], ["carrier-1", "carrier-2"])
        self.assertTrue(any("привязана" in line for line in self.logs))

        # Headers and the anti-abuse frame.
        h = cred_headers[0]
        self.assertEqual(h.get("x-pm-appversion"), "android-vpn@5.20.21.0")
        self.assertEqual(h.get("x-pm-apiversion"), "3")
        self.assertEqual(h.get("Accept"), "application/vnd.protonmail.v1+json")
        self.assertTrue(h.get("User-Agent", "").startswith("ProtonVPN/5.20.21.0 (Android "))
        frame = api.bodies("/auth/v4/credentialless")[-1]["Payload"]["vpn-android-v4-challenge-0"]
        self.assertEqual(frame["v"], "2.0.7")
        self.assertNotEqual(frame["regionCode"], "RU")
        self.assertIsInstance(frame["deviceName"], int)
        self.assertIsInstance(frame["storageCapacity"], float)

        # Registration: one call, the key the confs are built from.
        account = self.account()
        seed = base64.b64decode(account["seed_b64"])
        keys = derive_keys(seed)
        cert_bodies = api.bodies("/vpn/v1/certificate")
        self.assertEqual(len(cert_bodies), 1)
        self.assertEqual(cert_bodies[0], {"ClientPublicKey": keys["ed25519_pem"], "Mode": "persistent",
                                          "DeviceName": "Nova PC"})
        self.assertGreater(account["cert_expires_at"], time.time() + 300 * 86400)
        self.assertTrue(is_valid_device_profile(account["device"]))
        self.assertNotIn("access_token", json.dumps(account))
        self.assertEqual([k for k in account if k.startswith("pending_")], [])
        self.assertEqual(account["set_wg_public"], keys["wg_public"])
        self.assertFalse(nova_proton.needs_renewal(account))

        confs = self.confs()
        self.assertNotIn("ZZ-FREE-999.conf", confs)          # old generated set replaced
        self.assertIn("my-own.conf", confs)                   # hand-dropped file kept
        generated = [c for c in confs if c != "my-own.conf"]
        self.assertEqual(len(generated), 10)
        self.assertEqual(sorted(account["generated_files"]), generated)
        self.assertFalse([n for n in os.listdir(self.group) if n.endswith(".tmp")])
        ports = []
        for name in generated:
            text = self.read_conf(name)
            self.assertEqual(self.conf_value(text, "PrivateKey"), keys["wg_private"])
            self.i1.check(self, self.conf_value(text, "I1"))
            ports.append(int(self.conf_value(text, "Endpoint").rsplit(":", 1)[1]))
        self.assertEqual(sorted(ports), sorted(PORTS[i % len(PORTS)] for i in range(10)))
        self.assertEqual(summary["countries"], {"NL": 4, "US": 3, "CA": 3})

        joined = "\n".join(self.logs)
        for secret in ("carrier-token", "user-token", account["seed_b64"], keys["wg_private"]):
            self.assertNotIn(secret, joined)
        self.assertTrue(all(line.startswith("[Proton]") for line in self.logs))

    def stamp_account(self, **fields):
        account = self.account()
        account.update(fields)
        self.write_account(account)

    def test_live_cert_is_reused_without_reregistration(self):
        api = self.start_api()
        first = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertTrue(first["ok"], first)
        key_before = self.account()["seed_b64"]
        self.assertEqual(api.count("/vpn/v1/certificate"), 1)

        # Stale live list: a new session and a new list, but the live cert is not registered again.
        self.stamp_account(nodes_checked_at=int(time.time()) - 25 * 3600)
        second = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertTrue(second["ok"], second)
        self.assertFalse(second["registered"])
        self.assertFalse(second["reused"])
        self.assertEqual(api.count("/vpn/v1/certificate"), 1)
        self.assertEqual(api.count("/vpn/logicals"), 2)
        self.assertEqual(self.account()["seed_b64"], key_before)
        wg_private = derive_keys(base64.b64decode(key_before))["wg_private"]
        for name in self.confs():
            self.assertEqual(self.conf_value(self.read_conf(name), "PrivateKey"), wg_private)

        forced = issue_profiles(self.base, log=self.logs.append, count=6, force=True)
        self.assertTrue(forced["ok"], forced)
        self.assertTrue(forced["registered"])
        self.assertEqual(api.count("/vpn/v1/certificate"), 2)
        account = self.account()
        self.assertNotEqual(account["seed_b64"], key_before)
        new_private = derive_keys(base64.b64decode(account["seed_b64"]))["wg_private"]
        self.assertEqual(len(self.confs()), 6)
        for name in self.confs():
            self.assertEqual(self.conf_value(self.read_conf(name), "PrivateKey"), new_private)

    def test_fresh_complete_set_is_reused_without_network(self):
        """proton-3: второй обычный прогон при живом ключе и свежем наборе не заводит новую анонимную учётку."""
        api = self.start_api()
        first = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertTrue(first["ok"], first)
        account = self.account()
        contents = {name: self.read_conf(name) for name in self.confs()}
        requests_before = len(api.requests)

        second = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertTrue(second["ok"], second)
        self.assertTrue(second["reused"])
        self.assertFalse(second["registered"])
        self.assertEqual(second["count"], 6)
        self.assertEqual(sorted(second["profiles"]), sorted(first["profiles"]))
        self.assertEqual(sorted(second["profile_ids"]), sorted(first["profile_ids"]))
        self.assertEqual(second["nodes_source"], "live")
        self.assertEqual(second["countries"], first["countries"])
        self.assertEqual(len(api.requests), requests_before)          # not a single request
        self.assertEqual(api.count("/auth/v4/credentialless"), 1)
        self.assertEqual(self.account()["generated_files"], account["generated_files"])
        self.assertEqual({name: self.read_conf(name) for name in self.confs()}, contents)
        self.assertEqual(nova_proton.should_issue(self.account(), time.time(), True)[0], False)

        # Asking for more than the set was issued for is a reason to go out again.
        bigger = issue_profiles(self.base, log=self.logs.append, count=9)
        self.assertTrue(bigger["ok"], bigger)
        self.assertFalse(bigger["reused"])
        self.assertEqual(api.count("/auth/v4/credentialless"), 2)
        self.assertEqual(api.count("/vpn/v1/certificate"), 1)

        # A profile deleted by hand breaks the set: a normal run rebuilds it.
        os.remove(os.path.join(self.group, self.confs()[0]))
        rebuilt = issue_profiles(self.base, log=self.logs.append, count=9)
        self.assertTrue(rebuilt["ok"], rebuilt)
        self.assertFalse(rebuilt["reused"])
        self.assertEqual(len(self.confs()), 9)

    def test_stale_live_set_is_kept_when_the_live_list_does_not_arrive(self):
        """proton-3: живой набор не подменяется встроенным списком, если API недоступен."""
        self.start_api()
        first = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertTrue(first["ok"], first)
        contents = {name: self.read_conf(name) for name in self.confs()}
        write_nodes_file(os.path.join(self.group, "proton_nodes.json"),
                         parse_logicals(canned_logicals(per_country=3, countries=("NO", "CH"))))
        self.stamp_account(nodes_checked_at=int(time.time()) - 25 * 3600)

        with mock.patch.object(nova_proton, "API_HOSTS", (f"http://127.0.0.1:{closed_port()}",)):
            kept = issue_profiles(self.base, log=self.logs.append, count=6)
            self.assertTrue(kept["ok"], kept)
            self.assertTrue(kept["reused"])
            self.assertIn("не обновился", kept["warning"])
            self.assertEqual(kept["nodes_source"], "live")
            self.assertEqual(sorted(kept["profiles"]), sorted(first["profiles"]))
            self.assertEqual({name: self.read_conf(name) for name in self.confs()}, contents)
            # The attempt is marked, so the next call does not walk the dead routes again.
            self.assertGreaterEqual(self.account()["nodes_checked_at"], int(time.time()) - 60)
            self.logs.clear()
            again = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertTrue(again["reused"], again)
        self.assertFalse([line for line in self.logs if line.startswith("[Proton] /auth/v4/sessions:")])

    def test_cert_close_to_expiry_gets_a_new_key(self):
        api = self.start_api()
        old_seed = base64.b64encode(hashlib.sha256(b"old").digest()).decode("ascii")
        with open(os.path.join(self.group, "proton_account.json"), "w", encoding="utf-8") as fh:
            json.dump({"seed_b64": old_seed, "cert_expires_at": int(time.time()) + 10 * 86400,
                       "device": build_device_profile(random.Random(5))}, fh)
        summary = issue_profiles(self.base, log=self.logs.append, count=3)
        self.assertTrue(summary["ok"], summary)
        self.assertTrue(summary["registered"])
        self.assertEqual(api.count("/vpn/v1/certificate"), 1)
        self.assertNotEqual(self.account()["seed_b64"], old_seed)

    def test_cancel_after_renewal_keeps_the_old_key_live(self):
        """proton-2: прерывание после регистрации не выдаёт свежий сертификат за записанный набор."""
        api = self.start_api()
        self.write_old_set(cert_days=5)
        old_private = derive_keys(OLD_SEED)["wg_private"]

        def progress(text):
            if "собираю профили" in text:
                raise RuntimeError("stop")

        cancelled = issue_profiles(self.base, log=self.logs.append, count=5, progress=progress)
        self.assertTrue(cancelled["cancelled"], cancelled)
        self.assertEqual(api.count("/vpn/v1/certificate"), 1)
        account = self.account()
        self.assertEqual(account["seed_b64"], base64.b64encode(OLD_SEED).decode("ascii"))
        self.assertLess(account["cert_expires_at"], time.time() + 30 * 86400)
        self.assertTrue(nova_proton.needs_renewal(account))
        self.assertTrue(nova_proton.should_issue(account, time.time(), True)[0])
        self.assertEqual(self.confs(), ["ZZ-FREE-999.conf", "my-own.conf"])
        self.assertEqual(self.conf_value(self.read_conf("ZZ-FREE-999.conf"), "PrivateKey"), old_private)
        self.assertNotIn(old_private, json.dumps({k: v for k, v in account.items() if k != "seed_b64"}))

        # The next run finishes the switch with the key registered above: no second certificate.
        finished = issue_profiles(self.base, log=self.logs.append, count=5)
        self.assertTrue(finished["ok"], finished)
        self.assertFalse(finished["registered"])
        self.assertEqual(api.count("/vpn/v1/certificate"), 1)
        account = self.account()
        self.assertNotEqual(account["seed_b64"], base64.b64encode(OLD_SEED).decode("ascii"))
        self.assertEqual([k for k in account if k.startswith("pending_")], [])
        self.assertGreater(account["cert_expires_at"], time.time() + 300 * 86400)
        self.assertFalse(nova_proton.needs_renewal(account))
        new_private = derive_keys(base64.b64decode(account["seed_b64"]))["wg_private"]
        self.assertNotIn("ZZ-FREE-999.conf", self.confs())
        self.assertIn("my-own.conf", self.confs())
        for name in account["generated_files"]:
            self.assertEqual(self.conf_value(self.read_conf(name), "PrivateKey"), new_private)

    def test_hand_dropped_free_confs_survive(self):
        """proton-1: удаляется и перезаписывается только то, что написано ключом этой установки."""
        self.start_api()   # 12 nodes: NL-FREE#1..4, US-FREE#5..8, CA-FREE#9..12
        self.write_old_set(cert_days=10)
        old_private = derive_keys(OLD_SEED)["wg_private"]
        foreign = {
            "wg-NL-FREE-12.conf": conf_body(fake_key("user-1")),
            "DE-FREE-7.conf": conf_body(fake_key("user-2")),
            "NL-FREE-1.conf": conf_body(fake_key("user-3")),       # same name as a planned node
            "my-CA-copy.conf": conf_body(old_private),              # user's copy of our profile
        }
        for name, body in foreign.items():
            self.write_file(name, body)
        self.write_file("SG-FREE-3.conf", conf_body(old_private))   # our leftover, not in the record

        summary = issue_profiles(self.base, log=self.logs.append, count=10)
        self.assertTrue(summary["ok"], summary)
        self.assertEqual(summary["count"], 10)
        for name, body in foreign.items():
            self.assertEqual(self.read_conf(name), body, name)
        account = self.account()
        self.assertNotIn("NL-FREE-1.conf", account["generated_files"])
        self.assertEqual(len(account["generated_files"]), 10)
        self.assertNotIn("ZZ-FREE-999.conf", self.confs())
        self.assertNotIn("SG-FREE-3.conf", self.confs())
        self.assertIn("my-own.conf", self.confs())
        self.assertEqual(summary["removed"], 2)
        ports = [int(self.conf_value(self.read_conf(n), "Endpoint").rsplit(":", 1)[1])
                 for n in account["generated_files"]]
        self.assertEqual(sorted(ports), sorted(PORTS[i % len(PORTS)] for i in range(10)))

    def test_generated_name_rule_agrees_with_nova_profiles(self):
        try:
            import nova_profiles
        except Exception:
            self.skipTest("nova_profiles недоступен")
        stems = ["NL-FREE-128", "usa-FREE-3", "wg-NL-FREE-12", "my-home-FREE-3", "NL-FREE-", "N-FREE-1",
                 "NLDX-FREE-1", "PROTON", "CA-FREE-27-1194", "ca-free-27"]
        for stem in stems:
            self.write_file(stem + ".conf", conf_body(fake_key(stem)))
        origins = {r["name"]: r["origin"] for r in nova_profiles.list_profiles(self.base)
                   if r["group"] == nova_proton.GROUP_PROTON}
        for stem in stems:
            self.assertEqual(nova_proton.is_generated_name(stem), origins[stem] == "generated", stem)
            self.assertEqual(nova_proton.is_generated_name(stem + ".conf"), origins[stem] == "generated", stem)

    def test_unreachable_api_without_cert_keeps_old_set(self):
        self.write_old_set(cert_days=10)
        with mock.patch.object(nova_proton, "API_HOSTS", (f"http://127.0.0.1:{closed_port()}",)):
            summary = issue_profiles(self.base, log=self.logs.append, count=5)
        self.assertFalse(summary["ok"])
        self.assertIn("API Proton недоступен", summary["error"])
        self.assertEqual(self.confs(), ["ZZ-FREE-999.conf", "my-own.conf"])
        account = self.account()
        self.assertEqual(account["seed_b64"], base64.b64encode(OLD_SEED).decode("ascii"))
        self.assertGreater(account["failed_at"], 0)

    def test_unreachable_api_with_live_cert_uses_bundled_nodes(self):
        seed = hashlib.sha256(b"alive").digest()
        with open(os.path.join(self.group, "proton_account.json"), "w", encoding="utf-8") as fh:
            json.dump({"seed_b64": base64.b64encode(seed).decode("ascii"),
                       "cert_expires_at": int(time.time()) + 200 * 86400,
                       "device": build_device_profile(random.Random(6))}, fh)
        write_nodes_file(os.path.join(self.group, "proton_nodes.json"),
                         parse_logicals(canned_logicals(per_country=3)))
        with mock.patch.object(nova_proton, "API_HOSTS", (f"http://127.0.0.1:{closed_port()}",)):
            summary = issue_profiles(self.base, log=self.logs.append, count=50)
        self.assertTrue(summary["ok"], summary)
        self.assertEqual(summary["nodes_source"], "bundled")
        self.assertFalse(summary["registered"])
        self.assertEqual(summary["count"], 9)
        self.assertIsNone(summary["code"])
        wg_private = derive_keys(seed)["wg_private"]
        for name in self.confs():
            self.assertEqual(self.conf_value(self.read_conf(name), "PrivateKey"), wg_private)

    def test_logicals_failure_falls_back_to_bundled_list(self):
        api = self.start_api(logicals_status=502, logicals_raw=b"<html>bad gateway</html>")
        write_nodes_file(os.path.join(self.group, "proton_nodes.json"),
                         parse_logicals(canned_logicals(per_country=2, countries=("NO", "CH"))))
        summary = issue_profiles(self.base, log=self.logs.append, count=50)
        self.assertTrue(summary["ok"], summary)
        self.assertEqual(summary["nodes_source"], "bundled")
        self.assertTrue(summary["registered"])
        self.assertEqual(summary["count"], 4)
        self.assertEqual(api.count("/vpn/v1/certificate"), 1)

    def test_human_verification_is_surfaced_not_retried(self):
        hv = (422, {
            "Code": 9001, "Error": "Human verification required",
            "Details": {"HumanVerificationToken": "hv-secret-token", "HumanVerificationMethods": ["captcha"]},
        })
        api = FakeProtonApi(credentialless_error=hv)
        second_host = FakeProtonApi()
        proxy_route = FakeProtonApi()     # speaks plain HTTP, so it serves as an http:// proxy route
        for server in (api, second_host, proxy_route):
            self.addCleanup(server.close)
        self.write_old_set(cert_days=10)
        with mock.patch.object(nova_proton, "API_HOSTS", (api.url, second_host.url)):
            summary = issue_profiles(self.base, log=self.logs.append, proxies=[proxy_route.url], count=5)
        self.assertFalse(summary["ok"])
        self.assertEqual(summary["code"], 9001)
        self.assertIn("9001", summary["error"])
        self.assertEqual(api.count("/auth/v4/credentialless"), 1)
        self.assertEqual(api.count("/vpn/v1/certificate"), 0)
        self.assertEqual(len(second_host.requests), 0)
        self.assertEqual(len(proxy_route.requests), 0)
        self.assertNotIn("hv-secret-token", "\n".join(self.logs))
        self.assertEqual(self.confs(), ["ZZ-FREE-999.conf", "my-own.conf"])

    HV_ERROR = (422, {
        "Code": 9001, "Error": "Human verification required",
        "Details": {"HumanVerificationToken": "hv-secret-token", "HumanVerificationMethods": ["captcha", "email"]},
    })

    def test_human_verification_solved_by_owner_repeats_the_request(self):
        """9001 + окно капчи: тот же запрос повторяется с ответом владельца, выпуск доходит до конца."""
        api = self.start_api(credentialless_error=self.HV_ERROR, hv_answer="hv-secret-token:answer")
        calls = []

        def verifier(host, hv_token, proxy_url):
            calls.append((host, hv_token, proxy_url))
            return "hv-secret-token:answer", ""

        summary = issue_profiles(self.base, log=self.logs.append, count=5, human_verifier=verifier)
        self.assertTrue(summary["ok"], summary)
        self.assertEqual(calls, [(api.url, "hv-secret-token", None)])
        self.assertEqual(api.count("/auth/v4/credentialless"), 2)
        self.assertEqual(api.count("/auth/v4/sessions"), 1)   # the same carrier session is repeated
        first, second = api.headers_of("/auth/v4/credentialless")
        self.assertNotIn("x-pm-human-verification-token", {k.lower() for k in first})
        self.assertEqual(second.get("Authorization"), first.get("Authorization"))
        self.assertEqual(api.count("/vpn/v1/certificate"), 1)
        self.assertNotIn("hv-secret-token", "\n".join(self.logs))

    def test_human_verification_window_closed_fails_without_retry(self):
        api = self.start_api(credentialless_error=self.HV_ERROR, hv_answer="hv-secret-token:answer")
        self.write_old_set(cert_days=10)
        summary = issue_profiles(self.base, log=self.logs.append, count=5,
                                 human_verifier=lambda *_a: (None, "окно капчи закрыто без ответа"))
        self.assertFalse(summary["ok"])
        self.assertEqual(summary["code"], 9001)
        self.assertIn("окно капчи закрыто без ответа", summary["error"])
        self.assertEqual(api.count("/auth/v4/credentialless"), 1)
        self.assertEqual(self.confs(), ["ZZ-FREE-999.conf", "my-own.conf"])

    def test_human_verification_wrong_answer_is_final(self):
        """Второй 9001 после ответа — конец, окно второй раз не открывается."""
        api = self.start_api(credentialless_error=self.HV_ERROR, hv_answer="right")
        calls = []
        summary = issue_profiles(self.base, log=self.logs.append, count=5,
                                 human_verifier=lambda *a: (calls.append(a), ("wrong", ""))[1])
        self.assertFalse(summary["ok"])
        self.assertEqual(summary["code"], 9001)
        self.assertEqual(len(calls), 1)
        self.assertEqual(api.count("/auth/v4/credentialless"), 2)

    def test_human_verification_without_captcha_method_skips_window(self):
        hv = (422, {"Code": 9001, "Error": "Human verification required",
                    "Details": {"HumanVerificationToken": "t", "HumanVerificationMethods": ["sms"]}})
        api = self.start_api(credentialless_error=hv)
        calls = []
        summary = issue_profiles(self.base, log=self.logs.append, count=5,
                                 human_verifier=lambda *a: (calls.append(a), (None, ""))[1])
        self.assertFalse(summary["ok"])
        self.assertEqual(calls, [])
        self.assertEqual(api.count("/auth/v4/credentialless"), 1)

    def test_unattended_human_verification_names_the_button(self):
        self.start_api(credentialless_error=self.HV_ERROR)
        summary = issue_profiles(self.base, log=self.logs.append, count=5)
        self.assertFalse(summary["ok"])
        self.assertIn("Выпустить профили", summary["error"])

    def test_button_run_after_unattended_9001_shows_the_captcha(self):
        """Фоновый 9001 велит нажать «Выпустить профили» — нажатие не должно упереться в паузу 9001."""
        api = self.start_api(credentialless_error=self.HV_ERROR, hv_answer="hv-secret-token:answer")
        first = issue_profiles(self.base, log=self.logs.append, count=5)
        self.assertFalse(first["ok"])
        self.assertEqual(self.account()["last_code"], 9001)
        calls = []

        def verifier(host, hv_token, proxy_url):
            calls.append(host)
            return "hv-secret-token:answer", ""

        summary = issue_profiles(self.base, log=self.logs.append, count=5, human_verifier=verifier)
        self.assertTrue(summary["ok"], summary)
        self.assertEqual(len(calls), 1)
        self.assertEqual(api.count("/vpn/v1/certificate"), 1)

    def test_failed_run_starts_a_cooldown(self):
        """proton-4: неудача записывается, и следующий обычный прогон не идёт в сеть."""
        api = self.start_api(credentialless_error=(422, {"Code": 9001, "Error": "Human verification required"}))
        self.write_old_set(cert_days=10)
        first = issue_profiles(self.base, log=self.logs.append, count=5)
        self.assertFalse(first["ok"])
        account = self.account()
        self.assertGreater(account["failed_at"], 0)
        self.assertEqual(account["last_code"], 9001)
        self.assertGreater(account["last_attempt_at"], 0)
        requests_before = len(api.requests)

        second = issue_profiles(self.base, log=self.logs.append, count=5)
        self.assertFalse(second["ok"])
        self.assertEqual(second["code"], 9001)
        self.assertIn("повтор позже", second["error"])
        self.assertEqual(len(api.requests), requests_before)
        self.assertEqual(self.confs(), ["ZZ-FREE-999.conf", "my-own.conf"])

        now = time.time()
        should, reason = nova_proton.should_issue(account, now, False)
        self.assertFalse(should)
        self.assertIn("не удалась", reason)
        two_hours = dict(account, failed_at=int(now) - 2 * 3600)
        self.assertFalse(nova_proton.should_issue(two_hours, now, False)[0])            # 9001: 6 h
        self.assertTrue(nova_proton.should_issue(dict(two_hours, last_code=None), now, False)[0])
        self.assertTrue(nova_proton.should_issue(dict(account, failed_at=int(now) - 7 * 3600), now, False)[0])

        forced = issue_profiles(self.base, log=self.logs.append, count=5, force=True)
        self.assertFalse(forced["ok"])
        self.assertGreater(len(api.requests), requests_before)

    def test_transport_failure_cooldown_skips_the_route_walk(self):
        with mock.patch.object(nova_proton, "API_HOSTS", (f"http://127.0.0.1:{closed_port()}",)):
            first = issue_profiles(self.base, log=self.logs.append, count=5)
            self.assertFalse(first["ok"])
            self.logs.clear()
            second = issue_profiles(self.base, log=self.logs.append, count=5)
        self.assertFalse(second["ok"])
        self.assertIn("повтор позже", second["error"])
        self.assertIn("API Proton недоступен", second["error"])
        self.assertFalse([line for line in self.logs if line.startswith("[Proton] /auth/v4/sessions:")])
        account = self.account()
        self.assertEqual(account["last_routes"], ["напрямую"])
        self.assertTrue(account["last_transport"])

        # A route the failed run did not have (Opera came up after Nova started) is tried at once.
        proxy = f"http://127.0.0.1:{closed_port()}"
        now = time.time()
        self.assertFalse(nova_proton.should_issue(account, now, False)[0])
        self.assertTrue(nova_proton.should_issue(account, now, False, proxies=[proxy])[0])
        with mock.patch.object(nova_proton, "API_HOSTS", (f"http://127.0.0.1:{closed_port()}",)):
            self.logs.clear()
            third = issue_profiles(self.base, log=self.logs.append, proxies=[proxy], count=5)
            self.assertNotIn("повтор позже", third["error"])
            self.assertTrue([line for line in self.logs if line.startswith("[Proton] /auth/v4/sessions:")])
            self.logs.clear()
            fourth = issue_profiles(self.base, log=self.logs.append, proxies=[proxy], count=5)
        self.assertIn("повтор позже", fourth["error"])
        self.assertFalse([line for line in self.logs if line.startswith("[Proton] /auth/v4/sessions:")])
        # A Proton answer (not a transport failure) is not routed around by a new proxy.
        refused = dict(account, last_transport=False, last_code=2028)
        self.assertFalse(nova_proton.should_issue(refused, now, False, proxies=[proxy])[0])

    def test_success_after_session_9001_reports_no_code(self):
        """proton-7: удачный выпуск со встроенным списком не несёт code 9001."""
        self.start_api(credentialless_error=(422, {"Code": 9001, "Error": "Human verification required"}))
        seed = hashlib.sha256(b"alive-9001").digest()
        self.write_account({"seed_b64": base64.b64encode(seed).decode("ascii"),
                            "cert_expires_at": int(time.time()) + 200 * 86400,
                            "device": build_device_profile(random.Random(6))})
        write_nodes_file(os.path.join(self.group, "proton_nodes.json"),
                         parse_logicals(canned_logicals(per_country=2)))
        summary = issue_profiles(self.base, log=self.logs.append, count=50)
        self.assertTrue(summary["ok"], summary)
        self.assertIsNone(summary["code"])
        self.assertEqual(summary["session_code"], 9001)
        self.assertIn("9001", summary["warning"])
        self.assertEqual(summary["nodes_source"], "bundled")

    def test_blocked_replace_leaves_no_drafts(self):
        """proton-5: занятый файл не оставляет черновиков с приватным ключом."""
        self.start_api()
        self.write_old_set(cert_days=10)
        real_replace = os.replace
        calls = {"n": 0}

        def blocked(src, dst, *args, **kwargs):
            if str(dst).endswith("NL-FREE-2.conf"):
                calls["n"] += 1
                raise PermissionError(13, "sharing violation")
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch.object(nova_proton.os, "replace", blocked):
            summary = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertFalse(summary["ok"])
        self.assertIn("NL-FREE-2.conf", summary["error"])
        self.assertGreater(calls["n"], 1)                      # retried before giving up
        self.assertFalse([n for n in os.listdir(self.group) if n.endswith(".tmp")])
        self.assertIn("ZZ-FREE-999.conf", self.confs())
        account = self.account()
        self.assertEqual(account["generated_files"], ["ZZ-FREE-999.conf"])
        self.assertTrue(nova_proton.needs_renewal(account))

    def test_transient_replace_failure_is_retried(self):
        self.start_api()
        real_replace = os.replace
        calls = {"n": 0}

        def flaky(src, dst, *args, **kwargs):
            if str(dst).endswith("US-FREE-5.conf") and calls["n"] < 2:
                calls["n"] += 1
                raise PermissionError(13, "sharing violation")
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch.object(nova_proton.os, "replace", flaky):
            summary = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertTrue(summary["ok"], summary)
        self.assertEqual(calls["n"], 2)
        self.assertIn("US-FREE-5.conf", self.confs())

    def test_failed_draft_write_leaves_no_drafts(self):
        self.start_api()
        self.write_old_set(cert_days=10)
        real_open = open

        class DiskFull:
            def __init__(self, fh):
                self.fh = fh

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                self.fh.close()
                return False

            def write(self, _text):
                raise OSError(28, "No space left on device")

        def fake_open(path, mode="r", *args, **kwargs):
            fh = real_open(path, mode, *args, **kwargs)
            if str(path).endswith("CA-FREE-9.conf.tmp") and "w" in mode:
                return DiskFull(fh)
            return fh

        with mock.patch.object(nova_proton, "open", fake_open, create=True):
            summary = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertFalse(summary["ok"])
        self.assertFalse([n for n in os.listdir(self.group) if n.endswith(".tmp")])
        self.assertEqual(self.confs(), ["ZZ-FREE-999.conf", "my-own.conf"])

    def test_leftover_drafts_of_this_install_are_removed(self):
        self.start_api()
        self.write_old_set(cert_days=10)
        self.write_file("SG-FREE-77.conf.tmp", conf_body(derive_keys(OLD_SEED)["wg_private"]))
        self.write_file("notes.conf.tmp", conf_body(fake_key("editor")))
        summary = issue_profiles(self.base, log=self.logs.append, count=6)
        self.assertTrue(summary["ok"], summary)
        leftovers = sorted(n for n in os.listdir(self.group) if n.endswith(".tmp"))
        self.assertEqual(leftovers, ["notes.conf.tmp"])

    def test_account_write_failure_leaves_no_seed_draft(self):
        path = os.path.join(self.group, "proton_account.json")
        real_replace = os.replace

        def blocked(src, dst, *args, **kwargs):
            if str(dst) == path:
                raise PermissionError(13, "sharing violation")
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch.object(nova_proton.os, "replace", blocked):
            with self.assertRaises(OSError):
                nova_proton._write_json_atomic(path, {"seed_b64": "secret"})
        self.assertEqual(os.listdir(self.group), [])

    def test_busy_account_file_is_not_a_new_identity(self):
        """proton-6: занятый proton_account.json откладывает выпуск, а не заводит новую личность."""
        api = self.start_api()
        self.write_old_set(cert_days=200)
        path = os.path.join(self.group, "proton_account.json")
        with open(path, "rb") as fh:
            raw_before = fh.read()
        real_open = open

        def busy_open(file, *args, **kwargs):
            if os.path.basename(str(file)) == "proton_account.json":
                raise PermissionError(13, "sharing violation")
            return real_open(file, *args, **kwargs)

        with mock.patch.object(nova_proton, "open", busy_open, create=True):
            summary = issue_profiles(self.base, log=self.logs.append, count=5)
            with self.assertRaises(ValueError):          # old callers keep working
                nova_proton.read_account(self.group)
            with self.assertRaises(OSError):
                nova_proton.read_account(self.group)
            with self.assertRaises(OSError):
                nova_proton._update_account(self.group, {"issued_at": 1})
        self.assertFalse(summary["ok"])
        self.assertIn("proton_account.json", summary["error"])
        self.assertEqual(len(api.requests), 0)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), raw_before)
        self.assertEqual(self.confs(), ["ZZ-FREE-999.conf", "my-own.conf"])

    def test_second_run_is_refused_while_one_is_going(self):
        self.assertTrue(nova_proton._RUN_LOCK.acquire(blocking=False))
        try:
            summary = issue_profiles(self.base, log=self.logs.append, count=5)
        finally:
            nova_proton._RUN_LOCK.release()
        self.assertFalse(summary["ok"])
        self.assertIn("уже идёт", summary["error"])

    def test_refresh_nodes_file_from_live_list(self):
        api = self.start_api(logicals=canned_logicals(per_country=2, countries=("SG", "RO")))
        result = nova_proton.refresh_nodes_file(self.base, log=self.logs.append)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 4)
        self.assertEqual(api.count("/vpn/v1/certificate"), 0)
        loaded = nova_proton.load_bundled_nodes(os.path.join(self.group, "proton_nodes.json"))
        self.assertEqual([n["country"] for n in loaded], ["SG", "RO", "SG", "RO"])
        self.assertTrue(is_valid_device_profile(self.account()["device"]))
        self.assertNotIn("seed_b64", self.account())

    def test_cancellation_leaves_old_set(self):
        self.start_api()
        self.write_old_set()

        def progress(text):
            if "список серверов" in text:
                raise RuntimeError("cancel")

        summary = issue_profiles(self.base, log=self.logs.append, count=5, progress=progress)
        self.assertFalse(summary["ok"])
        self.assertTrue(summary["cancelled"])
        self.assertEqual(self.confs(), ["ZZ-FREE-999.conf", "my-own.conf"])
        self.assertNotIn("failed_at", self.account())        # a cancel is not a failure

    def test_proven_nodes_take_the_places_and_a_proven_node_the_list_lost_is_kept(self):
        self.start_api()  # NL/US/CA x4: 198.51.{0,1,2}.{1..4}, loads 10..13
        keys = derive_keys(OLD_SEED)
        self.write_old_set(cert_days=200)
        # The previous set also had two nodes the new list does not carry: one carried traffic.
        self.write_file("NO-FREE-9.conf", build_proton_conf(
            keys["wg_private"], {"name": "NO-FREE#9", "city": "Oslo", "entry_ip": "203.0.113.9",
                                 "peer_public_key": fake_key("NO-FREE#9")}, 443, random_junk(random.Random(1))))
        self.write_file("PL-FREE-4.conf", build_proton_conf(
            keys["wg_private"], {"name": "PL-FREE#4", "city": "Warsaw", "entry_ip": "203.0.113.4",
                                 "peer_public_key": fake_key("PL-FREE#4")}, 88, random_junk(random.Random(2))))
        account = self.account()
        account["generated_files"] = ["ZZ-FREE-999.conf", "NO-FREE-9.conf", "PL-FREE-4.conf"]
        self.write_account(account)
        liveness = {"198.51.0.4": 60, "198.51.2.3": 150, "203.0.113.9": 55, "203.0.113.4": None,
                    "198.51.1.1": None}

        summary = issue_profiles(self.base, log=self.logs.append, count=4, liveness=liveness)
        self.assertTrue(summary["ok"], summary)
        self.assertFalse(summary["registered"])
        self.assertEqual(summary["alive"], 3)
        written = set(self.confs())
        self.assertTrue({"NO-FREE-9.conf", "NL-FREE-4.conf", "CA-FREE-11.conf"} <= written, written)
        self.assertNotIn("PL-FREE-4.conf", written)                    # silent and gone from the list
        self.assertNotIn("US-FREE-5.conf", written)                    # silent: behind the unknown US node
        self.assertIn("US-FREE-6.conf", written)
        self.assertEqual(len(written - {"my-own.conf"}), 4)
        self.assertTrue(any("эта установка уже подключалась: 3" in line for line in self.logs), self.logs)

    def test_without_liveness_the_order_is_load_only(self):
        self.start_api()
        for liveness in (None, {}):
            summary = issue_profiles(self.base, log=self.logs.append, count=3, liveness=liveness, force=True)
            self.assertTrue(summary["ok"], summary)
            self.assertIsNone(summary["alive"])
            self.assertEqual(sorted(self.confs()), ["CA-FREE-9.conf", "NL-FREE-1.conf", "US-FREE-5.conf"])


class PublishedNodeFeedTests(unittest.TestCase):
    def test_published_nodes_require_fresh_metadata_and_valid_peer_keys(self):
        import nova_proton
        payload = {"generated_at": int(time.time() * 1000), "nodes": [
            {"server_name": "NL-FREE-1", "country": "NL", "city": "Amsterdam",
             "entry_ip": "185.107.56.12", "peer_public_key": base64.b64encode(bytes(range(32))).decode()},
            {"entry_ip": "185.107.56.13", "peer_public_key": "not-a-wireguard-key"}]}
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(payload).encode()
        with mock.patch("nova_proton.urllib.request.urlopen", return_value=response) as request:
            nodes = nova_proton.fetch_published_nodes()
            self.assertEqual(len(nodes), 1)
            self.assertEqual(nodes[0]["country"], "NL")
            self.assertIn("/nova_pc/proton_nodes.json", request.call_args.args[0].full_url)
        payload["generated_at"] = int((time.time() - 15 * 86400) * 1000)
        response.read.return_value = json.dumps(payload).encode()
        with mock.patch("nova_proton.urllib.request.urlopen", return_value=response):
            self.assertEqual(nova_proton.fetch_published_nodes(), [])


class RenewalPolicyTests(unittest.TestCase):
    NOW = 1_800_000_000

    def account(self, **fields):
        keys = derive_keys(GOLDEN_SEED)
        base = {
            "seed_b64": base64.b64encode(GOLDEN_SEED).decode("ascii"),
            "wg_public": keys["wg_public"],
            "set_wg_public": keys["wg_public"],
            "cert_expires_at": self.NOW + 200 * 86400,
            "generated_files": ["NL-FREE-1.conf"],
            "nodes_source": "live",
            "nodes_checked_at": self.NOW - 3600,
        }
        base.update(fields)
        return base

    def test_needs_renewal(self):
        now = self.NOW
        pending = base64.b64encode(hashlib.sha256(b"pending").digest()).decode("ascii")
        self.assertFalse(nova_proton.needs_renewal(None, now))
        self.assertFalse(nova_proton.needs_renewal({}, now))
        self.assertFalse(nova_proton.needs_renewal({"device": {}}, now))
        self.assertFalse(nova_proton.needs_renewal(self.account(), now))
        self.assertTrue(nova_proton.needs_renewal(self.account(cert_expires_at=now + 10 * 86400), now))
        self.assertTrue(nova_proton.needs_renewal(
            self.account(pending_seed_b64=pending, pending_cert_expires_at=now + 365 * 86400), now))
        self.assertFalse(nova_proton.needs_renewal(
            self.account(pending_seed_b64=pending, pending_cert_expires_at=now + 86400), now))
        self.assertTrue(nova_proton.needs_renewal(self.account(set_wg_public=fake_key("other")), now))
        self.assertFalse(nova_proton.needs_renewal(
            {k: v for k, v in self.account().items() if k != "set_wg_public"}, now))

    def test_should_issue(self):
        now = self.NOW
        self.assertEqual(nova_proton.should_issue(self.account(), now, True)[0], False)
        self.assertEqual(nova_proton.should_issue(self.account(), now, False)[0], True)
        self.assertEqual(nova_proton.should_issue(None, now, False)[0], True)
        self.assertEqual(nova_proton.should_issue(self.account(nodes_checked_at=now - 25 * 3600), now, True)[0], True)
        bundled = self.account(nodes_source="bundled")
        self.assertEqual(nova_proton.should_issue(dict(bundled, nodes_checked_at=now - 5 * 3600), now, True)[0], False)
        self.assertEqual(nova_proton.should_issue(dict(bundled, nodes_checked_at=now - 7 * 3600), now, True)[0], True)
        self.assertEqual(nova_proton.should_issue(self.account(cert_expires_at=now + 86400), now, True)[0], True)
        failed = self.account(failed_at=now - 600, last_code=None, last_error="API Proton недоступен")
        should, reason = nova_proton.should_issue(failed, now, False)
        self.assertFalse(should)
        self.assertIn("повтор позже", reason)
        self.assertEqual(nova_proton.LIVE_NODES_REFRESH_S, 24 * 3600)
        self.assertEqual(nova_proton.BUNDLED_NODES_REFRESH_S, 6 * 3600)


if __name__ == "__main__":
    unittest.main()
