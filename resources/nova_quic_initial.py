"""Поддельный QUIC Initial для параметра `I1` AmneziaWG.

`I1` — произвольный UDP-пакет, который клиент отправляет перед рукопожатием.
Стоковый WireGuard на той стороне (узлы WARP и Proton) его просто отбрасывает,
поэтому приём безопасен для узлов, ничего не знающих про AmneziaWG. Смысл — в
первом пакете потока: DPI видит не WireGuard, а корректный QUIC Initial с
обычным SNI.

Порт `ProtonQuicInitial.buildI1` из Nova Android байт в байт: соль QUIC v1,
метки `client in` / `quic key` / `quic iv` / `quic hp` (RFC 9001 §5.2),
AES-128-GCM поверх CRYPTO-фрейма, защита заголовка через AES-ECB. Внутри —
минимальный ClientHello, у которого единственное расширение `server_name`.
Пакет ровно 1250 байт: RFC 9000 §14.1 требует от дейтаграммы с клиентским
Initial не меньше 1200, а короткий пакет любой разборщик выбрасывает (P7:
первая версия на ~150 байт с однобайтным DCID была заведомо невалидным QUIC).

Подделывать частично бессмысленно: либо пакет разбирается как QUIC, либо
выглядит мусором. Поэтому здесь же лежит `decode_initial` — честная обратная
операция (снять защиту заголовка, расшифровать, разобрать CRYPTO-фрейм и
ClientHello), которой тесты проверяют, что пакет действительно разбирается.

Не брать `mini_quic_generator` / `quic.js` сайта warp-generation (N28): лицензия
несвободная и несовместима с GPL. Этот код — собственный.
"""

from __future__ import annotations

__all__ = [
    "DCID_SIZE",
    "PAD_TO",
    "WHITE_SNI",
    "build_i1",
    "client_initial_keys",
    "decode_initial",
    "i1_bytes",
    "pick_sni",
]

import hashlib
import hmac
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Salt of QUIC version 1, RFC 9001 §5.2.
INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

QUIC_V1 = 1

# RFC 9000 §14.1: a client Initial datagram is at least 1200 bytes; real clients pad to ~1250.
PAD_TO = 1250

# Real clients use 8-byte DCIDs; a one-byte DCID is itself a tell.
DCID_SIZE = 8

TAG_SIZE = 16
SAMPLE_SIZE = 16
MAX_SNI_LENGTH = 250

# Neutral names for the SNI inside I1.
#
# Source: Nova Android `assets/proven_ru.sni` first (the hand-picked CDN/static set everybody
# starts with), then the rest of `assets/white.sni`. Removed on purpose: bank and payment hosts,
# government portals and their static hosts, identity/login pages (`id.*`). Those are formally
# allow-listed too, but a login page's normal profile is tens of kilobytes, so a large flow to it
# stands out; `proven_ru.sni` excludes them for the same reason. No VPN brands.
WHITE_SNI = (
    # proven_ru.sni
    "yastatic.net",
    "avatars.mds.yandex.net",
    "strm.yandex.net",
    "yandex.net",
    "sun9-40.userapi.com",
    "st.okcdn.ru",
    "cloud.cdn.yandex.net",
    "17.img.avito.st",
    "st.max.ru",
    "s3.yandex.net",
    "st-ok.cdn-vk.ru",
    "imgsmail.ru",
    "tile1.maps.2gis.com",
    "static.rutube.ru",
    # white.sni: CDN / static
    "sun9-41.userapi.com",
    "sun9-42.userapi.com",
    "00.img.avito.st",
    "42.img.avito.st",
    "i.max.ru",
    "download.max.ru",
    "tile0.maps.2gis.com",
    "tile2.maps.2gis.com",
    "i0.photo.2gis.com",
    "i5.photo.2gis.com",
    "pic.rutubelist.ru",
    "filekeeper-vod.2gis.com",
    "st.ozone.ru",
    "ir.ozone.ru",
    "st.avito.ru",
    "cs.avito.ru",
    "cdn.lemanapro.ru",
    "static.lemanapro.ru",
    "api.vk.ru",
    "push.vk.ru",
    "api.max.ru",
    "botapi.max.ru",
    "m.vk.ru",
    "api.ok.ru",
    "yabs.yandex.ru",
    "top-fwz1.mail.ru",
    "a.wb.ru",
    "msk.t2.ru",
    "mp.rzd.ru",
    "suggest.dzen.ru",
    # white.sni: marketplaces / retail
    "www.ozon.ru",
    "www.avito.ru",
    "ca.magnit.ru",
    "hr.magnit.ru",
    # white.sni: transport / navigation
    "gzd.rzd.ru",
    "ozd.rzd.ru",
    "m.tutu.ru",
    "m.2gis.ru",
    # white.sni: ecosystems / media
    "m.vk.com",
    "m.mail.ru",
    "m.yandex.ru",
    "www.dzen.ru",
    "d.rutube.ru",
    "m.kinopoisk.ru",
    "www.rbc.ru",
    "m.rbc.ru",
    # white.sni: telecom
    "www.mts.ru",
    "i.megafon.ru",
    "s.beeline.ru",
    "s.tele2.ru",
    "f.tele2.ru",
    "f.t2.ru",
    "tc.t2.ru",
    "ndd.rostelecom.ru",
    # white.sni: additional allow-list candidates (analytics / counters)
    "3475482542.mc.yandex.ru",
    "mc.yandex.ru",
    "statad.ru",
    "zen-yabro-morda.mediascope.mc.yandex.ru",
)


def _hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def _expand_label(secret: bytes, length: int, label: str) -> bytes:
    """HKDF-Expand-Label with a single iteration: every output here is <= 32 bytes."""
    full = b"tls13 " + label.encode("ascii")
    # uint16 length, label<7..255>, context<0..255> (empty), then the HKDF counter byte 0x01.
    info = length.to_bytes(2, "big") + bytes((len(full),)) + full + b"\x00" + b"\x01"
    return _hmac_sha256(secret, info)[:length]


def _varint(value: int) -> bytes:
    # Same encoding as the Kotlin original: 1, 2 or 4 bytes (all values here are far below 2^30).
    if value < 0x40:
        return bytes((value,))
    if value < 0x4000:
        return bytes((((value >> 8) & 0xFF) | 0x40, value & 0xFF))
    return bytes((((value >> 24) & 0xFF) | 0x80, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF))


def _varint_length(value: int) -> int:
    if value < 0x40:
        return 1
    if value < 0x4000:
        return 2
    return 4


def _u16(value: int) -> bytes:
    return bytes(((value >> 8) & 0xFF, value & 0xFF))


def _random_bytes(rng, size: int) -> bytes:
    data = rng(size)
    if not isinstance(data, (bytes, bytearray)) or len(data) != size:
        raise ValueError(f"rng returned {type(data).__name__} of wrong size, expected {size} bytes")
    return bytes(data)


def _encode_host(host: str) -> bytes:
    try:
        return host.encode("ascii")
    except UnicodeEncodeError:
        # SNI carries A-labels only (RFC 6066 §3); a raw UTF-8 name would itself be an anomaly.
        return host.encode("idna")


def client_initial_keys(dcid: bytes) -> dict:
    """RFC 9001 §5.2 client Initial secrets for a destination connection id."""
    initial_secret = _hmac_sha256(INITIAL_SALT, bytes(dcid))
    client_secret = _expand_label(initial_secret, 32, "client in")
    return {
        "secret": client_secret,
        "key": _expand_label(client_secret, 16, "quic key"),
        "iv": _expand_label(client_secret, 12, "quic iv"),
        "hp": _expand_label(client_secret, 16, "quic hp"),
    }


def _client_hello(name: bytes, random32: bytes) -> bytes:
    # server_name: list_len, name_type=0, host_len, host
    server_name_list = _u16(len(name) + 3) + b"\x00" + _u16(len(name)) + name
    sni_extension = _u16(0) + _u16(len(server_name_list)) + server_name_list
    extensions = _u16(len(sni_extension)) + sni_extension
    # legacy_version, random, session_id_len=0, cipher_suites_len=0, compression_len=0
    body = b"\x03\x03" + random32 + b"\x00\x00\x00\x00" + extensions
    return bytes((0x01, (len(body) >> 16) & 0xFF, (len(body) >> 8) & 0xFF, len(body) & 0xFF)) + body


def _header_protection_mask(hp: bytes, sample: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    return encryptor.update(sample) + encryptor.finalize()


def build_i1(sni: str, *, rng=os.urandom) -> str:
    """Build one QUIC v1 client Initial carrying `sni`, as an AmneziaWG `<b 0x…>` literal.

    `rng(n) -> bytes` supplies the DCID (first 8 bytes) and the ClientHello random (next 32),
    in that order, exactly like the Kotlin original.

    Returns "" when the name is unusable (blank, longer than 250 characters, not encodable).
    The caller must treat "" as "no I1 line at all", never substitute a stub: an `I1` with
    garbage inside is worse than none, and an empty `I1 = ` kills the tunnel (N6).
    """
    host = str(sni or "").strip().rstrip(".")
    if not host or len(host) > MAX_SNI_LENGTH:
        return ""
    try:
        name = _encode_host(host)
    except UnicodeError:
        return ""
    if not name or len(name) > MAX_SNI_LENGTH:
        return ""

    dcid = _random_bytes(rng, DCID_SIZE)
    pkn = b"\x00"
    hello = _client_hello(name, _random_bytes(rng, 32))
    # CRYPTO frame: type 0x06, offset 0, length, data
    payload = b"\x06" + _varint(0) + _varint(len(hello)) + hello

    # Padding is computed exactly like the original: the Length field's own varint size depends
    # on the padding, so it is fitted iteratively.
    base_header = 8 + len(dcid) + 0 + 0 + len(pkn)

    def overall(padding: int) -> int:
        remainder = len(pkn) + len(payload) + padding + TAG_SIZE
        return base_header + _varint_length(remainder) + len(payload) + padding + TAG_SIZE

    padding = 0
    if overall(0) < PAD_TO:
        padding = PAD_TO - overall(0)
        while padding > 0 and overall(padding) > PAD_TO:
            padding -= 1
        if overall(padding) < PAD_TO:
            padding += 1
    # The tail from the packet number on must be at least 20 bytes: the header-protection
    # sample is taken from it.
    if len(pkn) + len(payload) + padding + TAG_SIZE < 20:
        padding = 20 - len(pkn) - len(payload) - TAG_SIZE
    remainder = len(pkn) + len(payload) + padding + TAG_SIZE

    header = (
        bytes((0xC0 | (len(pkn) - 1),)) + QUIC_V1.to_bytes(4, "big")
        + bytes((len(dcid),)) + dcid
        + b"\x00"  # scid: empty
        + b"\x00"  # token: empty
        + _varint(remainder) + pkn
    )

    keys = client_initial_keys(dcid)
    nonce = bytearray(keys["iv"])
    for i, byte in enumerate(pkn):
        nonce[len(nonce) - len(pkn) + i] ^= byte

    encrypted = AESGCM(keys["key"]).encrypt(bytes(nonce), payload + bytes(padding), header)

    sample_offset = 4 - len(pkn)
    mask = _header_protection_mask(keys["hp"], encrypted[sample_offset:sample_offset + SAMPLE_SIZE])

    protected = bytearray(header)
    protected[0] ^= mask[0] & 0x0F
    for i in range(len(pkn)):
        protected[len(protected) - len(pkn) + i] ^= mask[1 + i]

    return "<b 0x" + (bytes(protected) + encrypted).hex() + ">"


_I1_LITERAL = re.compile(r"^\s*<b\s+0x([0-9a-fA-F]+)>\s*$")


def i1_bytes(value) -> bytes:
    """Bytes of an AmneziaWG `<b 0x…>` literal (bytes/bytearray pass through unchanged)."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    match = _I1_LITERAL.match(str(value or ""))
    if not match or len(match.group(1)) % 2:
        raise ValueError("not an AmneziaWG <b 0x…> literal")
    return bytes.fromhex(match.group(1))


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated varint")
    size = 1 << (data[offset] >> 6)
    if offset + size > len(data):
        raise ValueError("truncated varint")
    value = data[offset] & 0x3F
    for byte in data[offset + 1:offset + size]:
        value = (value << 8) | byte
    return value, offset + size


def _take(data: bytes, offset: int, size: int, what: str) -> tuple[bytes, int]:
    if size < 0 or offset + size > len(data):
        raise ValueError(f"truncated {what}")
    return data[offset:offset + size], offset + size


def _parse_frames(plaintext: bytes) -> tuple[bytes, int]:
    """CRYPTO stream (reassembled from offset 0) and the number of PADDING bytes."""
    chunks: dict[int, bytes] = {}
    padding = 0
    offset = 0
    while offset < len(plaintext):
        frame_type, offset = _read_varint(plaintext, offset)
        if frame_type == 0x00:
            padding += 1
        elif frame_type == 0x01:
            continue
        elif frame_type == 0x06:
            data_offset, offset = _read_varint(plaintext, offset)
            data_length, offset = _read_varint(plaintext, offset)
            chunk, offset = _take(plaintext, offset, data_length, "CRYPTO frame")
            chunks[data_offset] = chunk
        else:
            raise ValueError(f"unexpected frame type 0x{frame_type:x} in an Initial")
    stream = b""
    while len(stream) in chunks:
        chunk = chunks.pop(len(stream))
        if not chunk:
            break
        stream += chunk
    return stream, padding


def _parse_client_hello(stream: bytes) -> dict:
    if len(stream) < 4 or stream[0] != 0x01:
        raise ValueError("CRYPTO stream does not start with a ClientHello")
    body_length = int.from_bytes(stream[1:4], "big")
    body, _ = _take(stream, 4, body_length, "ClientHello")
    offset = 0
    legacy_version, offset = _take(body, offset, 2, "legacy_version")
    random32, offset = _take(body, offset, 32, "random")
    session_len, offset = _take(body, offset, 1, "session_id length")
    session_id, offset = _take(body, offset, session_len[0], "session_id")
    suites_len, offset = _take(body, offset, 2, "cipher_suites length")
    suites, offset = _take(body, offset, int.from_bytes(suites_len, "big"), "cipher_suites")
    compression_len, offset = _take(body, offset, 1, "compression length")
    _, offset = _take(body, offset, compression_len[0], "compression methods")
    extensions: list[int] = []
    sni = ""
    if offset < len(body):
        ext_total, offset = _take(body, offset, 2, "extensions length")
        ext_block, offset = _take(body, offset, int.from_bytes(ext_total, "big"), "extensions")
        pos = 0
        while pos < len(ext_block):
            ext_type, pos = _take(ext_block, pos, 2, "extension type")
            ext_len, pos = _take(ext_block, pos, 2, "extension length")
            ext_data, pos = _take(ext_block, pos, int.from_bytes(ext_len, "big"), "extension")
            kind = int.from_bytes(ext_type, "big")
            extensions.append(kind)
            if kind == 0x0000 and not sni:
                list_len, cur = _take(ext_data, 0, 2, "server_name_list length")
                names, _ = _take(ext_data, cur, int.from_bytes(list_len, "big"), "server_name_list")
                npos = 0
                while npos < len(names):
                    name_type, npos = _take(names, npos, 1, "name_type")
                    name_len, npos = _take(names, npos, 2, "host_name length")
                    name, npos = _take(names, npos, int.from_bytes(name_len, "big"), "host_name")
                    if name_type[0] == 0 and not sni:
                        sni = name.decode("ascii", errors="strict")
    return {
        "legacy_version": int.from_bytes(legacy_version, "big"),
        "random": random32,
        "session_id": session_id,
        "cipher_suites": suites,
        "extensions": extensions,
        "sni": sni,
    }


def decode_initial(packet) -> dict:
    """Inverse of `build_i1`: remove header protection, decrypt, parse CRYPTO + ClientHello.

    Accepts raw bytes or a `<b 0x…>` literal. Raises ValueError on anything that is not a
    decryptable QUIC v1 client Initial. Returns dcid/scid/token, packet number, sizes and the
    parsed ClientHello (`sni`, `random`, `extensions`).
    """
    data = i1_bytes(packet)
    if len(data) < 7:
        raise ValueError("too short for a QUIC long header")
    first = data[0]
    if not first & 0x80:
        raise ValueError("not a long header packet")
    if not first & 0x40:
        raise ValueError("fixed bit is not set")
    version = int.from_bytes(data[1:5], "big")
    if version != QUIC_V1:
        raise ValueError(f"unsupported QUIC version 0x{version:08x}")
    if (first & 0x30) >> 4 != 0:
        raise ValueError("long header packet is not an Initial")
    offset = 5
    dcid_len, offset = _take(data, offset, 1, "dcid length")
    if dcid_len[0] > 20:
        raise ValueError("dcid longer than 20 bytes")
    dcid, offset = _take(data, offset, dcid_len[0], "dcid")
    scid_len, offset = _take(data, offset, 1, "scid length")
    if scid_len[0] > 20:
        raise ValueError("scid longer than 20 bytes")
    scid, offset = _take(data, offset, scid_len[0], "scid")
    token_len, offset = _read_varint(data, offset)
    token, offset = _take(data, offset, token_len, "token")
    length, pn_offset = _read_varint(data, offset)
    if pn_offset + length > len(data):
        raise ValueError("Length field runs past the datagram")
    if pn_offset + 4 + SAMPLE_SIZE > len(data):
        raise ValueError("too short for a header-protection sample")

    keys = client_initial_keys(dcid)
    mask = _header_protection_mask(keys["hp"], data[pn_offset + 4:pn_offset + 4 + SAMPLE_SIZE])
    first_unprotected = first ^ (mask[0] & 0x0F)
    pn_len = (first_unprotected & 0x03) + 1
    if length < pn_len + TAG_SIZE:
        raise ValueError("Length field too small for packet number and tag")
    pn_bytes = bytes(b ^ m for b, m in zip(data[pn_offset:pn_offset + pn_len], mask[1:1 + pn_len]))
    packet_number = int.from_bytes(pn_bytes, "big")

    header = bytes((first_unprotected,)) + data[1:pn_offset] + pn_bytes
    nonce = bytearray(keys["iv"])
    for i, byte in enumerate(pn_bytes):
        nonce[len(nonce) - pn_len + i] ^= byte
    ciphertext = data[pn_offset + pn_len:pn_offset + length]
    try:
        plaintext = AESGCM(keys["key"]).decrypt(bytes(nonce), ciphertext, header)
    except InvalidTag as exc:
        raise ValueError("AEAD tag check failed: not an Initial for this DCID") from exc

    stream, padding = _parse_frames(plaintext)
    hello = _parse_client_hello(stream)
    return {
        "version": version,
        "first_byte": first_unprotected,
        "dcid": dcid,
        "scid": scid,
        "token": token,
        "packet_number": packet_number,
        "pn_length": pn_len,
        "length": pn_offset + length,
        "trailing": len(data) - (pn_offset + length),
        "padding": padding,
        "crypto": stream,
        "client_hello": hello,
        "sni": hello["sni"],
    }


def pick_sni(index: int, rng=None) -> str:
    """A name from `WHITE_SNI`.

    Without `rng` the choice is `WHITE_SNI[index % len]`, so consecutive indices spread distinct
    names across a profile set (N5: one shape for the whole set is one signature). Start from a
    random offset per run to vary sets between runs. With `rng` (a `random.Random`-like object)
    the name is drawn at random and `index` is ignored.
    """
    if rng is not None:
        return rng.choice(WHITE_SNI)
    return WHITE_SNI[int(index) % len(WHITE_SNI)]
