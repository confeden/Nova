"""Does a WireGuard server answer our key right now, and from which local UDP port?

A real handshake initiation (Noise_IKpsk2, exactly what amneziawg-go sends) with the profile's
AmneziaWG cover in front of it -- I1..I5, then Jc junk datagrams, then the initiation, back to back
-- and a response that is *authenticated*, not merely "something came back". A server that does
not know the key stays silent, the same way it stays silent when the path is blocked, so only a
decrypted response counts.

Why this exists (measured 2026-09-15 on the owner's PC, RU ISP, `kb/profiles.md#wg-probe`):

* TCP 443 answered on 50 of 50 Proton nodes while 36 of them were silent to WireGuard on every UDP
  port: the TCP ranking (nova_latency) says nothing about whether a tunnel can come up.
* A live Proton node answers a given (local port, node port) pair deterministically -- some pairs
  always, some never; the entry address spreads flows over servers and not every server takes our
  key. wireproxy binds a random local port, so a live node failed about one start in three, and a
  failed start retried from that same port for its whole life. Probing first and pinning the port
  that answered (`ListenPort`) makes the start deterministic.
* WireGuard drops a peer's initiations that arrive within 20 ms of each other
  (HandshakeInitationRate): six parallel probes of one server with one key got one answer where
  six sequential ones got four. Probes of one server therefore run one after another.
* A completed handshake is a session. On Proton the newest session of a key takes it over from
  the server that held it (the older tunnel went silent ~16 s later), so a caller must never probe
  Proton nodes with the key of a live Proton tunnel.

Pure Python: X25519 and ChaCha20-Poly1305 from `cryptography`, BLAKE2s from hashlib. No Nova
globals, so it is unit tested against an in-process responder (`tests/test_nova_wg_probe.py`).
"""

import base64
import concurrent.futures
import contextlib
import errno
import hashlib
import hmac
import os
import random
import re
import socket
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__all__ = [
    "DEFAULT_ATTEMPTS",
    "DEFAULT_TIMEOUT_SEC",
    "build_initiation",
    "cover_from_interface",
    "decode_key",
    "is_cookie_reply",
    "probe_endpoint",
    "probe_endpoints",
    "render_i_packet",
    "target_from_parsed",
    "verify_response",
]

# "ChaChaPoly", as in wireguard-go's NoiseConstruction. Nova Android's ProtonHandshakeVectorTest
# pins "ChaCha20Poly1305": that initiation is well-formed and every server drops it in silence.
CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"

MESSAGE_INITIATION = 1
MESSAGE_RESPONSE = 2
MESSAGE_COOKIE_REPLY = 3
INITIATION_SIZE = 148
RESPONSE_SIZE = 92
COOKIE_REPLY_SIZE = 64
_TAI64_BASE = 0x400000000000000A

DEFAULT_ATTEMPTS = 4
DEFAULT_TIMEOUT_SEC = 1.5
# Above WireGuard's 20 ms flood limit per peer, so a retry is never dropped for arriving too soon.
ATTEMPT_PAUSE_SEC = 0.05
MAX_WORKERS = 16
MAX_I_PACKET_BYTES = 8192
MAX_JUNK_COUNT = 128
MAX_JUNK_BYTES = 1280

_TAG_RE = re.compile(r"<([^<>]*)>")
_CHARS52 = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


# --- Noise IKpsk2 ------------------------------------------------------------------------------

def _hash(data):
    return hashlib.blake2s(data).digest()


def _hmac(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def _kdf(key, data, count):
    """WireGuard KDF1/KDF2/KDF3: HMAC-BLAKE2s chain over one pseudo-random key."""
    prk = _hmac(key, data)
    outputs = []
    previous = b""
    for index in range(1, count + 1):
        previous = _hmac(prk, previous + bytes((index,)))
        outputs.append(previous)
    return outputs


def _aead_seal(key, plaintext, associated):
    return ChaCha20Poly1305(key).encrypt(b"\x00" * 12, plaintext, associated)


def _aead_open(key, ciphertext, associated):
    return ChaCha20Poly1305(key).decrypt(b"\x00" * 12, ciphertext, associated)


def _public_key(private_raw):
    return X25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _dh(private_raw, public_raw):
    return X25519PrivateKey.from_private_bytes(private_raw).exchange(X25519PublicKey.from_public_bytes(public_raw))


def decode_key(value):
    """32 raw bytes of a standard-base64 WireGuard key, else None."""
    try:
        raw = base64.b64decode(str(value or "").strip(), validate=True)
    except (ValueError, TypeError):
        return None
    return raw if len(raw) == 32 else None


def _tai64n(now):
    seconds = int(now)
    nanoseconds = min(999_999_999, max(0, int((now - seconds) * 1e9)))
    return struct.pack(">QI", _TAI64_BASE + seconds, nanoseconds)


def build_initiation(static_private, peer_public, sender_index, *, ephemeral_private=None, timestamp=None):
    """(148-byte handshake initiation, state for `verify_response`).

    `static_private`/`peer_public` are 32 raw bytes; `ephemeral_private` and `timestamp` (12-byte
    TAI64N) are for tests only -- a real probe must use fresh ones, the server rejects a replayed
    timestamp.
    """
    eph_private = bytes(ephemeral_private) if ephemeral_private is not None else os.urandom(32)
    eph_public = _public_key(eph_private)
    chain = _hash(CONSTRUCTION)
    transcript = _hash(_hash(chain + IDENTIFIER) + peer_public)
    (chain,) = _kdf(chain, eph_public, 1)
    transcript = _hash(transcript + eph_public)
    chain, key = _kdf(chain, _dh(eph_private, peer_public), 2)
    encrypted_static = _aead_seal(key, _public_key(static_private), transcript)
    transcript = _hash(transcript + encrypted_static)
    chain, key = _kdf(chain, _dh(static_private, peer_public), 2)
    stamp = bytes(timestamp) if timestamp is not None else _tai64n(time.time())
    encrypted_stamp = _aead_seal(key, stamp, transcript)
    transcript = _hash(transcript + encrypted_stamp)
    body = (struct.pack("<II", MESSAGE_INITIATION, sender_index & 0xFFFFFFFF)
            + eph_public + encrypted_static + encrypted_stamp)
    mac1 = hashlib.blake2s(body, digest_size=16, key=_hash(LABEL_MAC1 + peer_public)).digest()
    packet = body + mac1 + b"\x00" * 16
    state = {
        "chain": chain,
        "transcript": transcript,
        "ephemeral_private": eph_private,
        "static_private": bytes(static_private),
        "sender_index": sender_index & 0xFFFFFFFF,
    }
    return packet, state


def verify_response(state, datagram):
    """True only for a handshake response to this initiation that authenticates (wireguard-go
    ConsumeMessageResponse): right type, size and receiver index, and an empty AEAD that opens."""
    data = bytes(datagram or b"")
    if len(data) != RESPONSE_SIZE:
        return False
    message_type, _sender, receiver = struct.unpack("<III", data[:12])
    if message_type != MESSAGE_RESPONSE or receiver != state["sender_index"]:
        return False
    responder_ephemeral = data[12:44]
    try:
        (chain,) = _kdf(state["chain"], responder_ephemeral, 1)
        transcript = _hash(state["transcript"] + responder_ephemeral)
        (chain,) = _kdf(chain, _dh(state["ephemeral_private"], responder_ephemeral), 1)
        (chain,) = _kdf(chain, _dh(state["static_private"], responder_ephemeral), 1)
        _chain, tau, key = _kdf(chain, b"\x00" * 32, 3)
        transcript = _hash(transcript + tau)
        return _aead_open(key, data[44:60], transcript) == b""
    except (InvalidTag, ValueError):
        return False


# --- AmneziaWG cover ---------------------------------------------------------------------------

def render_i_packet(spec, *, rng=os.urandom, now=time.time):
    """Bytes of one AmneziaWG `I1`..`I5` value, like amneziawg-go's obfChain; None when unusable.

    Supported tags: `<b 0x…>` bytes, `<r N>` random, `<rc N>` random letters, `<rd N>` random
    digits, `<t>` 4-byte big-endian unix time. amneziawg-go refuses a config with any other tag,
    so a probe that skips such a packet describes a tunnel that would not start anyway.
    """
    text = str(spec or "").strip()
    if not text:
        return None
    out = bytearray()
    tags = _TAG_RE.findall(text)
    if not tags:
        return None
    for tag in tags:
        parts = tag.split()
        if not parts:
            return None
        name, value = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
        try:
            if name == "b":
                hex_text = value[2:] if value.lower().startswith("0x") else value
                if not hex_text or len(hex_text) % 2:
                    return None
                out += bytes.fromhex(hex_text)
            elif name in ("r", "rc", "rd"):
                length = int(value)
                if length < 0 or length > MAX_I_PACKET_BYTES:
                    return None
                chunk = bytearray(rng(length))
                if name == "rc":
                    chunk = bytearray(_CHARS52[b % 52] for b in chunk)
                elif name == "rd":
                    chunk = bytearray(ord("0") + b % 10 for b in chunk)
                out += chunk
            elif name == "t":
                out += struct.pack(">I", int(now()) & 0xFFFFFFFF)
            else:
                return None
        except ValueError:
            return None
        if len(out) > MAX_I_PACKET_BYTES:
            return None
    return bytes(out) if out else None


def _as_int(value, default=0):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def cover_from_interface(interface):
    """`{"i_packets": [...], "junk": (jc, jmin, jmax)}` from a parsed `[Interface]` (lowercase keys,
    nova_profiles.parse_awg_conf). Specs stay text: `<t>` and `<r>` must change per attempt."""
    interface = interface if isinstance(interface, dict) else {}
    specs = [str(interface.get(f"i{n}") or "").strip() for n in range(1, 6)]
    jc = max(0, min(MAX_JUNK_COUNT, _as_int(interface.get("jc"))))
    jmin = max(0, min(MAX_JUNK_BYTES, _as_int(interface.get("jmin"))))
    jmax = max(0, min(MAX_JUNK_BYTES, _as_int(interface.get("jmax"))))
    if jmax < jmin:
        jmin, jmax = jmax, jmin
    return {"i_packets": [spec for spec in specs if spec], "junk": (jc, jmin, jmax)}


def _split_endpoint(endpoint):
    text = str(endpoint or "").strip()
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        port_text = rest[1:] if sep and rest.startswith(":") else ""
    else:
        host, _sep, port_text = text.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        return "", 0
    return (host, port) if host and 0 < port < 65536 else ("", 0)


def _plain_wireguard_framing(interface):
    """True when S1-S4 are 0 and H1-H4 are 1-4 (or absent): the only framing `build_initiation` produces.

    AmneziaWG's S prefixes the handshake with random bytes and H replaces the message types; a server
    configured for them drops a plain initiation, which would read as a silent node.
    """
    for n in range(1, 5):
        padding = str(interface.get(f"s{n}") or "").strip()
        if padding and _as_int(padding, default=-1) != 0:
            return False
        header = str(interface.get(f"h{n}") or "").strip()
        if header and header != str(n):
            return False
    return True


def target_from_parsed(parsed):
    """A `probe_endpoint` target from nova_profiles.parse_awg_conf output; None when it lacks a part.

    Keys: private_key, peer_public_key, host, port, cover -- the identity, the server and the cover
    the tunnel itself would send. None too for AmneziaWG framing the probe cannot reproduce (S1-S4,
    H1-H4 off their defaults): the start then goes on unprobed, as it did before the probe existed.
    """
    parsed = parsed if isinstance(parsed, dict) else {}
    interface = parsed.get("interface") if isinstance(parsed.get("interface"), dict) else {}
    peer = parsed.get("peer") if isinstance(parsed.get("peer"), dict) else {}
    host, port = _split_endpoint(peer.get("endpoint"))
    private_key = str(interface.get("privatekey") or "").strip()
    peer_public_key = str(peer.get("publickey") or "").strip()
    if not host or decode_key(private_key) is None or decode_key(peer_public_key) is None:
        return None
    if not _plain_wireguard_framing(interface):
        return None
    return {
        "private_key": private_key,
        "peer_public_key": peer_public_key,
        "host": host,
        "port": port,
        "cover": cover_from_interface(interface),
    }


def _cover_datagrams(cover, rng):
    cover = cover if isinstance(cover, dict) else {}
    datagrams = []
    for spec in cover.get("i_packets") or ():
        packet = render_i_packet(spec, rng=os.urandom)
        if packet:
            datagrams.append(packet)
    jc, jmin, jmax = tuple(cover.get("junk") or (0, 0, 0))
    for _ in range(max(0, int(jc))):
        size = rng.randint(int(jmin), int(jmax)) if jmax > jmin else int(jmin)
        if size > 0:
            datagrams.append(os.urandom(size))
    return datagrams


# --- probing -------------------------------------------------------------------------------------

def _result(ok=False, rtt_ms=None, source_port=None, attempts=0, error=""):
    return {"ok": ok, "rtt_ms": rtt_ms, "source_port": source_port, "attempts": attempts, "error": error}


def is_cookie_reply(state, datagram):
    """A WireGuard cookie reply to this initiation: the server is up but under load and wants mac2."""
    data = bytes(datagram or b"")
    return (len(data) == COOKIE_REPLY_SIZE
            and struct.unpack("<II", data[:8]) == (MESSAGE_COOKIE_REPLY, state["sender_index"]))


def _v6_port_taken(port):
    """True when [::]:port is held by someone else. wireguard-go binds a fixed ListenPort on udp4 **and**
    udp6 and gives up when the v6 half is taken, while a probe only ever held the v4 half."""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        return False  # no IPv6 stack: the helper skips udp6 as well
    try:
        with contextlib.suppress(OSError, AttributeError):
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(("::", int(port)))
        return False
    except OSError as exc:
        return getattr(exc, "winerror", None) in (10048, 10013) or exc.errno in (errno.EADDRINUSE, errno.EACCES)
    finally:
        sock.close()


def probe_endpoint(private_key, peer_public_key, host, port, *, cover=None, attempts=DEFAULT_ATTEMPTS,
                   timeout=DEFAULT_TIMEOUT_SEC, source_ports=None, should_stop=None, bind_host=None,
                   rng=None):
    """Handshake `host:port` from up to `attempts` local UDP ports, one after another.

    Returns `{"ok", "rtt_ms", "source_port", "attempts", "error"}`: `source_port` is the local port
    whose initiation got an authenticated response -- pin it with `ListenPort` and the tunnel's own
    handshake takes the same path. Each attempt uses a fresh socket, sender index, ephemeral key and
    timestamp; `source_ports` (an iterable) overrides the OS choice for tests. Never raises.
    Three answers are not verdicts about the node: `error` "cookie" (ok, no port: the server is under
    load and answered with a cookie reply, which the tunnel handles itself), "stopped" (not ok:
    `should_stop` fired, whatever the attempts before it saw) and "oserror-<code>" (not ok: some
    attempt could not bind or send -- no route while the network comes up, a port in use -- so the
    silence of the others proves nothing either). A port whose IPv6 half is taken comes back as ok
    with no port ("unpinned"): the helper could not bind it.
    """
    static_private = decode_key(private_key)
    peer_public = decode_key(peer_public_key)
    host = str(host or "").strip().strip("[]")
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0
    if static_private is None or peer_public is None:
        return _result(error="bad-key")
    if not host or not 0 < port < 65536:
        return _result(error="bad-endpoint")
    rng = rng or random.SystemRandom()
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    local = bind_host if bind_host is not None else ("::" if family == socket.AF_INET6 else "0.0.0.0")
    ports = iter(source_ports) if source_ports is not None else None
    error = "timeout"
    os_error = ""
    done = 0
    for attempt in range(max(1, int(attempts))):
        if callable(should_stop) and should_stop():
            return _result(False, None, None, done, "stopped")
        if attempt:
            time.sleep(ATTEMPT_PAUSE_SEC)
        done += 1
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            wanted = next(ports, 0) if ports is not None else 0
            sock.bind((local, int(wanted)))
            source_port = sock.getsockname()[1]
            sock.connect((host, port))
            sender = rng.getrandbits(32)
            initiation, state = build_initiation(static_private, peer_public, sender)
            for datagram in _cover_datagrams(cover, rng):
                sock.send(datagram)
            sent = time.monotonic()
            sock.send(initiation)
            deadline = sent + max(0.05, float(timeout))
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    error = "timeout"
                    break
                sock.settimeout(left)
                try:
                    datagram = sock.recv(2048)
                except socket.timeout:
                    error = "timeout"
                    break
                except ConnectionResetError:
                    # Windows turns an ICMP port unreachable into this on a connected UDP socket.
                    error = "unreachable"
                    break
                if verify_response(state, datagram):
                    rtt = max(1, int(round((time.monotonic() - sent) * 1000)))
                    if family == socket.AF_INET and _v6_port_taken(source_port):
                        return _result(True, rtt, None, done, "unpinned")
                    return _result(True, rtt, source_port, done)
                if is_cookie_reply(state, datagram):
                    return _result(True, None, None, done, "cookie")
        except ConnectionResetError:
            # The ICMP port unreachable of a cover datagram, reported by the next send instead of a recv.
            error = "unreachable"
        except OSError as exc:
            # With no route (a network coming up at logon, an adapter reconnecting) every attempt fails
            # here within milliseconds. Read as silence, that skipped each live node of a Proton group
            # and stored it as silent for hours (found in review before 1.39.1 shipped).
            os_error = f"oserror-{getattr(exc, 'winerror', None) or exc.errno}"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return _result(False, None, None, done, os_error or error)


def probe_endpoints(targets, *, attempts=DEFAULT_ATTEMPTS, timeout=DEFAULT_TIMEOUT_SEC,
                    max_workers=MAX_WORKERS, should_stop=None, prober=None):
    """`{key: {"private_key", "peer_public_key", "host", "port", "cover"}}` -> `{key: result}`.

    Different servers are probed in parallel; targets sharing a host are probed one after another
    in one worker, so no two initiations with one key reach one server together. `prober` replaces
    `probe_endpoint` in tests. `should_stop()` abandons what has not started (result "stopped").
    """
    probe = prober or probe_endpoint
    items = [(key, value) for key, value in dict(targets or {}).items() if isinstance(value, dict)]
    groups = {}
    for key, target in items:
        groups.setdefault(str(target.get("host") or "").strip().strip("[]").lower(), []).append((key, target))
    results = {}

    def run_group(group):
        out = {}
        for key, target in group:
            if callable(should_stop) and should_stop():
                out[key] = _result(error="stopped")
                continue
            try:
                out[key] = probe(
                    target.get("private_key"), target.get("peer_public_key"), target.get("host"),
                    target.get("port"), cover=target.get("cover"), attempts=attempts, timeout=timeout,
                    should_stop=should_stop,
                )
            except Exception as exc:  # a prober bug must not take the other groups with it
                out[key] = _result(error=f"error-{type(exc).__name__}")
        return out

    if groups:
        workers = max(1, min(int(max_workers), len(groups)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="NovaWgProbe") as pool:
            for future in concurrent.futures.as_completed([pool.submit(run_group, g) for g in groups.values()]):
                results.update(future.result())
    return {key: results.get(key, _result(error="stopped")) for key, _target in items}
