"""Which layer a failed tunnel attempt is allowed to blame.

The relay used to answer "did it work" with a boolean and charge the answer to
whatever it happened to be holding — the domain, the egress, or both. That is
wrong in a specific and expensive way. A resolver hiccup retires a Worker
domain that was fine. A ClientHello the network dislikes gets blamed on an
egress that was carrying traffic a second earlier. Every such mistake spends a
working option, and the supply of working options is what the relay lives on.

A connection clears an ordered series of gates — resolve, connect, handshake,
upgrade, carry — and the last one it cleared bounds what may be concluded.
Nothing before the ClientHello can say anything about the ClientHello's shape;
nothing after a completed handshake can either, because completing *is* the
proof the shape was accepted. The suspect window for our own TLS fingerprint is
exactly one gate wide.

This module is the Python half of ``nova-rs/crates/nova-probe``. The signature
names are the same strings the Rust enum serialises to, so a log line, a
persisted counter and a Rust verdict all say the same word for the same event.
Keep the two in step: the decision table lives there with its tests, and this
is the copy the running relay reads.
"""

import ssl
from enum import IntEnum


class Reached(IntEnum):
    """The last gate an attempt cleared. Ordered; the ordering is the point."""

    NOTHING = 0          # the name never became an address
    RESOLVED = 1         # address in hand, no TCP session
    CONNECTED = 2        # TCP up, nothing written yet
    HELLO_SENT = 3       # ClientHello written, no ServerHello back
    HANDSHAKE_DONE = 4   # TLS finished — our hello is a settled question
    UPGRADED = 5         # the WebSocket upgrade answered 101
    CARRYING = 6         # at least one byte arrived from the far side


class Ended(IntEnum):
    """How the attempt stopped."""

    OK = 0
    TIMEOUT = 1
    RESET = 2
    REFUSED = 3
    CLOSED = 4           # a clean FIN where a working peer would have kept talking
    CERT_MISMATCH = 5
    HTTP_STATUS = 6      # an HTTP response arrived instead of the upgrade
    RESOLVER_STUB = 7    # an address that cannot belong to the service


# --- Signatures, spelled exactly as nova_core::BlockSignature serialises -----

SUCCESS = "success"
DNS_FAILURE = "dns_failure"
DNS_POISONED = "dns_poisoned"
BLACKHOLED = "blackholed"
CONNECTION_REFUSED = "connection_refused"
RST_IMMEDIATE = "rst_immediate"
RST_AFTER_SERVER_HELLO = "rst_after_server_hello"
TLS_CERTIFICATE_MISMATCH = "tls_certificate_mismatch"
TUNNEL_HANDSHAKE_IGNORED = "tunnel_handshake_ignored"
TUNNEL_UPGRADE_REJECTED = "tunnel_upgrade_rejected"
TUNNEL_STALLED = "tunnel_stalled"
TUNNEL_SEVERED = "tunnel_severed"
UNKNOWN = "unknown"

# Which lever each signature asks for. One family per signature — the Rust side
# has a test that refuses to let these views disagree, and the same discipline
# is why this is a single table rather than four lists that drift apart.
_TLS_FINGERPRINT = frozenset({TUNNEL_HANDSHAKE_IGNORED})
_TRAFFIC_SHAPE = frozenset({TUNNEL_SEVERED})
_DIFFERENT_EGRESS = frozenset({
    BLACKHOLED,
    DNS_POISONED,
    TLS_CERTIFICATE_MISMATCH,
    TUNNEL_UPGRADE_REJECTED,
    TUNNEL_STALLED,
})
_NOT_OUR_FAULT = frozenset({CONNECTION_REFUSED, DNS_FAILURE})

# A reset cannot come from the peer sooner than a round trip. Well inside one
# means it was injected between here and there; around one means whoever sent it
# had time to read what the server said. Expressed against the measured RTT so
# the rule holds on a 12 ms city link and a 300 ms satellite one alike.
RESET_IMMEDIATE_PCT_OF_RTT = 50
RESET_IMMEDIATE_MS = 40
# A session that carried traffic for less than this *and* moved less than that
# did not really work. Both conditions, because a short connection that moved
# real volume did its job, and a long one that moved a handshake's worth did not.
SEVERED_WITHIN_MS = 10_000
SEVERED_UNDER_BYTES = 64 * 1024


def wants_tls_profile_change(signature: str) -> bool:
    """True when the tunnel should try a different ClientHello shape.

    Narrow by design. The pool of shapes a filtering network tolerates is small,
    and rotating on a failure that happened before the hello existed — or after
    it was already accepted — spends one of them for nothing.
    """
    return signature in _TLS_FINGERPRINT


def wants_traffic_reshape(signature: str) -> bool:
    return signature in _TRAFFIC_SHAPE


def needs_different_egress(signature: str) -> bool:
    return signature in _DIFFERENT_EGRESS


def is_not_our_fault(signature: str) -> bool:
    """True when the failure says nothing about Nova's configuration.

    Charging these to the active route is how a health tracker slowly poisons
    its own best option during somebody else's outage.
    """
    return signature in _NOT_OUR_FAULT


def classify(
    reached: int,
    ended: int,
    since_hello_ms=None,
    rtt_ms=None,
    bytes_down: int = 0,
    carried_ms: int = 0,
) -> str:
    """Name the phase that failed.

    Total: every combination produces a verdict, including incoherent ones such
    as a certificate error from an attempt that never resolved. Those are
    answered by the gate actually cleared rather than by the claim — an observer
    contradicting itself is likelier wrong about the detail than the milestone.
    """
    reached = int(reached)
    ended = int(ended)

    # Success needs the whole picture, so it is settled first; everything after
    # this line is a failure of some kind.
    if reached == Reached.CARRYING and ended == Ended.OK:
        return SUCCESS

    if reached == Reached.NOTHING:
        return DNS_POISONED if ended == Ended.RESOLVER_STUB else DNS_FAILURE

    if reached == Reached.RESOLVED:
        if ended == Ended.RESOLVER_STUB:
            return DNS_POISONED
        if ended in (Ended.REFUSED, Ended.RESET):
            return CONNECTION_REFUSED
        return BLACKHOLED

    if reached == Reached.CONNECTED:
        # TCP is up and the hello has not gone out. Nothing here is about the
        # hello; a peer that dies at this point is a peer that died.
        if ended == Ended.REFUSED:
            return CONNECTION_REFUSED
        if ended in (Ended.RESET, Ended.CLOSED):
            return BLACKHOLED
        return UNKNOWN

    if reached == Reached.HELLO_SENT:
        # The one window where our own hello is a live suspect.
        if ended == Ended.CERT_MISMATCH:
            return TLS_CERTIFICATE_MISMATCH
        if ended == Ended.HTTP_STATUS:
            # Nobody speaks HTTP to a ClientHello unless they terminated TLS
            # that was never offered to them. That is interception.
            return TLS_CERTIFICATE_MISMATCH
        if ended == Ended.RESET:
            return _reset_signature(since_hello_ms, rtt_ms)
        # Silence, or a polite close, in answer to a well-formed hello: somebody
        # read it and declined to continue.
        return TUNNEL_HANDSHAKE_IGNORED

    if reached == Reached.HANDSHAKE_DONE:
        if ended == Ended.CERT_MISMATCH:
            return TLS_CERTIFICATE_MISMATCH
        if ended == Ended.HTTP_STATUS:
            return TUNNEL_UPGRADE_REJECTED
        return TUNNEL_STALLED

    if reached == Reached.UPGRADED:
        return TUNNEL_STALLED

    # Bytes flowed. Everything static about this connection was accepted, which
    # leaves what a static check cannot see: sizes, timing, duration, volume.
    if int(carried_ms) < SEVERED_WITHIN_MS and int(bytes_down) < SEVERED_UNDER_BYTES:
        return TUNNEL_SEVERED
    return SUCCESS  # long enough and heavy enough to have done its job


def _reset_signature(since_hello_ms, rtt_ms) -> str:
    if since_hello_ms is None:
        # Guessing would put half the resets into a family that cannot address
        # them. UNKNOWN already routes to request-side desync, the larger one.
        return UNKNOWN
    if rtt_ms:
        budget = int(rtt_ms) * RESET_IMMEDIATE_PCT_OF_RTT // 100
    else:
        budget = RESET_IMMEDIATE_MS
    return RST_IMMEDIATE if int(since_hello_ms) <= budget else RST_AFTER_SERVER_HELLO


def ended_from_exception(exc: BaseException) -> int:
    """Map what Python raised onto how the connection actually stopped.

    An explicitly reported ending always wins. Once the TLS handshake happens
    in another process, the socket this side holds is a loopback hop and can
    only ever produce EOF — every distinction below would collapse into
    `CLOSED`, and with `HELLO_SENT` that is the one signature that both rotates
    the TLS profile and retires the zone's neutral SNI. So the helper says what
    happened and is believed. See `terminator.py`.
    """
    reported = getattr(exc, "nova_ended", None)
    if reported is not None:
        try:
            return int(reported)
        except (TypeError, ValueError):
            pass
    if isinstance(exc, ssl.SSLCertVerificationError):
        return Ended.CERT_MISMATCH
    if isinstance(exc, ssl.SSLError):
        # A handshake that failed for any other TLS reason: the peer answered
        # with something we could not continue from. Treated as a decline.
        return Ended.CLOSED
    if isinstance(exc, ConnectionRefusedError):
        return Ended.REFUSED
    if isinstance(exc, ConnectionResetError):
        return Ended.RESET
    if isinstance(exc, (TimeoutError, OSError)) and getattr(exc, "winerror", None) == 10060:
        return Ended.TIMEOUT
    if isinstance(exc, TimeoutError):
        return Ended.TIMEOUT
    if isinstance(exc, (EOFError, ConnectionAbortedError)):
        return Ended.CLOSED
    if isinstance(exc, OSError):
        # Windows spells a few of these without a dedicated subclass.
        return {10054: Ended.RESET, 10061: Ended.REFUSED, 10060: Ended.TIMEOUT}.get(
            getattr(exc, "winerror", None), Ended.CLOSED
        )
    return Ended.CLOSED


def reached_from_exception(exc: BaseException, default: int) -> int:
    """Read back the milestone an exception was tagged with on its way up.

    The transport annotates rather than wraps, so callers that only know how to
    catch ``OSError`` keep working untouched.
    """
    value = getattr(exc, "nova_reached", None)
    if value is None:
        return int(default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)
