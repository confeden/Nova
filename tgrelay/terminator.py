"""Talking to the process that owns Nova's TLS handshake.

The relay's outbound TLS used to be CPython's OpenSSL, whose ClientHello
matches no browser on any desktop — measured, `t13d181100`, a fingerprint that
identifies Nova and nothing else. The handshake now happens in a helper built
from `nova-rs/crates/nova-tls`, which emits the shape of a captured browser and
hands back a plaintext stream over loopback.

The one thing this module exists to get right is the *phase*. `phase.py` decides
which layer to blame by looking at what Python raised — an `ssl.SSLError`, a
`ConnectionResetError`, a Windows error number. None of those can happen once
the socket Python holds is a loopback hop: every failure would arrive as a bare
EOF and collapse into a single verdict. That verdict happens to be the one that
rotates the TLS profile *and* retires the zone's neutral SNI for fifteen
minutes, so a refused connection to a dead egress would quietly cost both.

So the helper reports `reached` and `ended` as numbers, this module copies them
onto the exception, and `phase.ended_from_exception` prefers them over anything
it could infer. Nothing downstream changes.

Disabled unless `NOVA_TLS_TERMINATOR_PORT` is set, and the relay keeps its old
path in that case — this is a lever, not a migration.
"""

import asyncio
import json
import os
from typing import Dict, List, Optional, Tuple

from . import phase


def _env_int(name: str, default: int = 0) -> int:
    try:
        return int(str(os.environ.get(name, "") or default).strip())
    except (TypeError, ValueError):
        return default


def runtime_path() -> str:
    """Where the supervisor publishes the port and token for this run.

    A file rather than environment variables because there are two client
    processes, not one: the relay runs on a thread inside Nova itself, and
    `NovaWFP/proxy/tcp_proxy.py` is a separate interpreter that imports the same
    relay module. A variable exported after that process started would never
    reach it.

    Under `temp/` because both values are regenerated every run — the token is
    not a secret to keep, it is a secret to hold for as long as the helper lives.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "temp", "tls_terminator.json")


def _runtime() -> Dict[str, object]:
    try:
        with open(runtime_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def terminator_port() -> int:
    """The loopback port the helper listens on, or 0 when it is not in use."""
    from_env = _env_int("NOVA_TLS_TERMINATOR_PORT", 0)
    if from_env > 0:
        return from_env
    try:
        return int(_runtime().get("port") or 0)
    except (TypeError, ValueError):
        return 0


def terminator_token() -> str:
    """The shared secret. Loopback is not a permission boundary on Windows.

    Without this, any process on the machine could use the helper as an open
    TLS proxy wearing a browser's fingerprint, which is a more useful thing to
    steal than an ordinary open proxy.
    """
    token = str(os.environ.get("NOVA_TLS_TERMINATOR_TOKEN", "") or "").strip()
    return token or str(_runtime().get("token") or "").strip()


def active_profile() -> str:
    """Which shape to ask for. One name drives this and the HTTP persona."""
    return str(os.environ.get("NOVA_TLS_PROFILE", "") or "yandex-windows").strip()


def is_enabled() -> bool:
    return terminator_port() > 0 and bool(terminator_token())


def _egress_of(attempt: Dict[str, object]) -> Optional[Dict[str, object]]:
    """Translate one of the relay's upstream attempts into the wire form."""
    kind = str(attempt.get("kind") or "").strip().lower()
    if kind == "direct":
        return {"kind": "direct"}
    host = str(attempt.get("host") or "127.0.0.1").strip()
    port = int(attempt.get("port") or 0)
    if kind == "socks5":
        return {"kind": "socks5", "host": host, "port": port}
    if kind == "http":
        return {"kind": "http", "host": host, "port": port}
    return None


def _tag(exc: BaseException, reached: int, ended: int) -> BaseException:
    """Carry the helper's verdict on the exception, the way transport.py does.

    Annotating rather than wrapping keeps every caller that catches `OSError`
    working untouched.
    """
    try:
        if not hasattr(exc, "nova_reached"):
            exc.nova_reached = int(reached)
        if not hasattr(exc, "nova_ended"):
            exc.nova_ended = int(ended)
    except Exception:
        pass
    return exc


async def _dial_once(
    target_host: str,
    target_port: int,
    sni: str,
    attempt: Dict[str, object],
    connect_timeout: float,
    handshake_timeout: float,
    verify: bool,
):
    egress = _egress_of(attempt)
    if egress is None:
        raise _tag(OSError(f"unsupported egress kind {attempt.get('kind')!r}"),
                   phase.Reached.NOTHING, phase.Ended.CLOSED)

    port = terminator_port()
    token = terminator_token()
    # The helper answers immediately or not at all; it is a local process.
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port), timeout=5.0
    )
    try:
        greeting = await asyncio.wait_for(reader.readline(), timeout=5.0)
        if not greeting:
            raise _tag(OSError("TLS helper closed without a greeting"),
                       phase.Reached.NOTHING, phase.Ended.CLOSED)

        request = {
            "token": token,
            "target": {"host": str(target_host), "port": int(target_port)},
            "egress": egress,
            "sni": str(sni or target_host),
            "profile": active_profile(),
            "connect_timeout_ms": max(200, int(connect_timeout * 1000)),
            "handshake_timeout_ms": max(200, int(handshake_timeout * 1000)),
            "verify": bool(verify),
        }
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()

        # The whole budget, because the helper is doing the connect and the
        # handshake on our behalf and both are inside this wait.
        budget = connect_timeout + handshake_timeout + 2.0
        line = await asyncio.wait_for(reader.readline(), timeout=budget)
        if not line:
            raise _tag(OSError("TLS helper closed before answering"),
                       phase.Reached.NOTHING, phase.Ended.CLOSED)
        status = json.loads(line.decode("utf-8", errors="replace"))
    except BaseException as exc:
        _abort(writer)
        # A failure talking to the helper itself is not evidence about the
        # network, and must not be charged to a domain or an egress.
        raise _tag(exc, phase.Reached.NOTHING, phase.ended_from_exception(exc))

    if not status.get("ok"):
        _abort(writer)
        message = str(status.get("error") or "TLS helper refused the tunnel")
        raise _tag(
            OSError(message),
            int(status.get("reached", phase.Reached.NOTHING)),
            int(status.get("ended", phase.Ended.CLOSED)),
        )
    return reader, writer


def _abort(writer) -> None:
    """Drop a half-built tunnel now, without awaiting.

    Abrupt rather than graceful: the helper reads a loopback close as "the
    relay gave up" and resets its upstream, which is what should happen to a
    tunnel that never became one.
    """
    try:
        transport = getattr(writer, "transport", None)
        if transport is not None and hasattr(transport, "abort"):
            transport.abort()
        else:
            writer.close()
    except Exception:
        pass


async def open_shaped_stream(
    target_host: str,
    target_port: int = 443,
    server_hostname: Optional[str] = None,
    timeout: float = 10.0,
    attempts: Optional[List[Dict[str, object]]] = None,
    verify: bool = False,
) -> Tuple[object, object, str]:
    """Same contract as `transport.open_tls_stream`, one process further out.

    The egress list is walked here rather than inside the helper so that the
    route label the relay logs and learns from stays the label it chose.
    """
    chosen = list(attempts or [])
    if not chosen:
        raise _tag(OSError("no upstream attempts available"),
                   phase.Reached.NOTHING, phase.Ended.CLOSED)

    last_error: Optional[BaseException] = None
    for attempt in chosen:
        label = str(attempt.get("label") or attempt.get("kind") or "unknown").strip() or "unknown"
        try:
            connect_timeout = max(0.2, float(attempt.get("timeout") or timeout))
        except (TypeError, ValueError):
            connect_timeout = float(timeout)
        try:
            reader, writer = await _dial_once(
                target_host,
                int(target_port),
                str(server_hostname or target_host),
                attempt,
                connect_timeout,
                float(timeout),
                verify,
            )
            return reader, writer, label
        except BaseException as exc:
            last_error = exc
            continue

    raise last_error if last_error is not None else _tag(
        OSError("no upstream attempts available"), phase.Reached.NOTHING, phase.Ended.CLOSED
    )
