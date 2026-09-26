"""Orchestrates the nova-cloudflare classifier for one reported host.

Pure glue, deliberately dependency-free of nova.pyw's globals (I15 -- this
lives in resources/ specifically so it stays importable by pytest): every
path and health flag the caller already knows is passed in, nothing is
re-derived from disk layout assumptions beyond what is passed.

Flow: skip if the host is already routed by something -> gather evidence
(nova_cloudflare_probe) -> ask nova-engine's cloudflare-classify subcommand
for a verdict -> on Action::Reroute{to: "warp"}, append the host to
list/u_main.txt, which the existing pac_updater_worker picks up within ~2s with
no restart. Any other action is a no-op by design (see the routing KB entry
for why DirectBypass is out of scope for v1).
"""

import json
import os
import subprocess

from nova_cloudflare_probe import gather_evidence

SUBPROCESS_TIMEOUT_SEC = 8


def _load_domain_set(path):
    domains = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.split("#", 1)[0].strip().lower()
                if line:
                    domains.add(line)
    except OSError:
        pass
    return domains


def _domain_or_parent_in(host, domain_set):
    parts = host.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in domain_set:
            return True
    return False


def already_routed(host, list_dir):
    """True if `host` (or a parent of it) already appears in any list that
    would keep the PAC's fragile dnsResolve() fallback from ever being
    reached for it -- matching the exact suffix-match order generate_pac()
    itself uses (nova.pyw:5156-5163), so this mirrors the live behaviour
    rather than guessing at it."""
    host = host.strip().lower()
    for name in ("u_main.txt", "u_second.txt", "exclude.txt", "ai.txt", "second.txt", "main.txt", "whatsapp.txt"):
        if _domain_or_parent_in(host, _load_domain_set(os.path.join(list_dir, name))):
            return True
    return False


def _run_nova_engine(bin_path, request, timeout=SUBPROCESS_TIMEOUT_SEC):
    payload = json.dumps(request)
    try:
        result = subprocess.run(
            [bin_path, "cloudflare-classify"],
            input=payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
        )
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"nova-engine spawn failed: {e}"
    if result.returncode != 0:
        detail = (result.stderr or "").strip() or f"exit code {result.returncode}"
        return None, f"nova-engine cloudflare-classify failed: {detail}"
    try:
        return json.loads(result.stdout), None
    except (ValueError, TypeError) as e:
        return None, f"nova-engine returned unparseable output: {e}"


USER_WARP_LIST = "u_main.txt"


def append_domain_to_user_ru_list(host, list_dir):
    """Append `host` to list/u_main.txt, CRLF-preserved (I6), skipping if it (or
    a parent of it) is already present. The next pac_updater_worker poll
    (<=2s) deduplicates, regenerates the PAC and refreshes it live.

    Not `main.txt`: that file is replaced by every upgrade and by the network
    reference list (`nova_list_sync`). `u_main.txt` is the user's own — the
    installer lays it `onlyifdoesntexist uninsneveruninstall`, so it survives
    upgrades, the network sync and even uninstall.

    Priority also happens to be right: `user_ru` is the PAC's first branch, above
    `exclude`. That cannot conflict here, because `already_routed()` refuses to
    append anything `exclude.txt` already claims.
    """
    path = os.path.join(list_dir, USER_WARP_LIST)
    host = host.strip().lower()
    if _domain_or_parent_in(host, _load_domain_set(path)):
        return False
    data = b""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        pass
    needs_crlf_prefix = data and not data.endswith(b"\r\n")
    with open(path, "ab") as f:
        if needs_crlf_prefix:
            f.write(b"\r\n")
        f.write(host.encode("ascii", errors="ignore") + b"\r\n")
    return True


def classify_and_maybe_reroute(host, list_dir, cloudflare_cidr_path, bin_path, warp_available, bypass_available=False, log_func=None):
    """Returns a result dict: {"status": ..., "detail": ...}.

    status is one of: "already_routed", "reachable" (baseline probe already
    works, nothing to do), "probe_inconclusive" (neither probe confirmed
    anything actionable), "engine_error", "kept" (classified but policy said
    Action::Keep), "rerouted" (appended to list/u_main.txt).
    """
    log = log_func or (lambda *_a, **_k: None)
    host = host.strip().lower()

    if already_routed(host, list_dir):
        return {"status": "already_routed", "detail": f"{host} is already covered by an existing list"}

    should_classify, evidence = gather_evidence(host, cloudflare_cidr_path)
    if not should_classify:
        if evidence.get("failure") is None:
            return {"status": "reachable", "detail": f"{host} already loads directly; nothing to change"}
        return {
            "status": "probe_inconclusive",
            "detail": f"{host} failed directly and Cloudflare's edge did not confirm it either "
            f"({evidence.get('failure')})",
        }

    if not bin_path or not os.path.exists(bin_path):
        return {"status": "engine_error", "detail": "nova-engine.exe not found; rebuild the installer to include it"}

    request = dict(evidence)
    request["host"] = host
    request["warp_available"] = bool(warp_available)
    request["bypass_available"] = bool(bypass_available)

    response, error = _run_nova_engine(bin_path, request)
    if error:
        log(f"[Cloudflare] {error}")
        return {"status": "engine_error", "detail": error}

    log(
        f"[Cloudflare] {host}: classification={response.get('classification')} "
        f"confidence={response.get('confidence'):.2f} action={response.get('action')}"
    )

    if response.get("action") != "reroute" or response.get("transport") != "warp":
        return {"status": "kept", "detail": f"{host} classified as {response.get('classification')}, no reroute"}

    appended = append_domain_to_user_ru_list(host, list_dir)
    if appended:
        log(f"[Cloudflare] {host} added to list/{USER_WARP_LIST} ({response.get('reason')})")
    return {
        "status": "rerouted",
        "detail": f"{host} added to list/{USER_WARP_LIST}; picked up live within a few seconds" if appended
        else f"{host} was already in list/{USER_WARP_LIST}",
    }
