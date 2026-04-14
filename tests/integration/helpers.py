"""Shared polling, lifecycle, and HOME-sandbox helpers for live integration.

These helpers exist to make integration failures diagnosable. Most of them are
small, but they define the timeout/error-reporting contract used across the
fixture and the in-process KERI workflow layer.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Iterable
from urllib.request import urlopen

from hio.base import doing

POLL_INTERVAL = float(os.getenv("W3C_CROSSWALK_INTEGRATION_POLL_INTERVAL", "0.25"))
PORT_POLL_INTERVAL = float(os.getenv("W3C_CROSSWALK_INTEGRATION_PORT_POLL_INTERVAL", "0.1"))


def _format_poll_value(value) -> str:
    """Render a poll value safely for timeout diagnostics."""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, sort_keys=True)
        except TypeError:
            return repr(value)
    return repr(value)


def poll_until(
    fetch,
    *,
    ready,
    timeout: float,
    interval: float,
    describe: str,
    retry_exceptions: tuple[type[BaseException], ...] = (),
):
    """Poll a fetch function until a readiness predicate succeeds or times out.

    The helper preserves both the last fetched value and the last retryable
    error so timeout messages explain whether the system was merely incomplete
    or repeatedly failing while being polled.
    """
    deadline = time.monotonic() + timeout
    last_value = None
    last_error = None

    while True:
        try:
            value = fetch()
        except retry_exceptions as err:
            last_error = str(err)
        else:
            last_value = value
            if ready(value):
                return value

        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"timed out waiting for {describe}; "
                f"last_error={last_error!r}; "
                f"last_value={_format_poll_value(last_value)}"
            )
        time.sleep(interval)


def read_log_tail(log_path: Path, *, max_chars: int = 8000) -> str:
    """Return the tail of a log file for startup and timeout diagnostics."""
    if not log_path.exists():
        return "(log file not found)"
    text = log_path.read_text(encoding="utf-8", errors="replace")
    return text[-max_chars:] if text else "(log file was empty)"


def terminate_process(proc: subprocess.Popen[bytes]) -> None:
    """Terminate a subprocess cleanly and escalate to kill if needed."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
        return
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def wait_for_port(
    host: str,
    port: int,
    proc: subprocess.Popen[bytes],
    name: str,
    *,
    log_path: Path,
    timeout: float = 45.0,
) -> None:
    """Wait until a subprocess has bound a TCP port or fail with log context.

    Startup failures in the live stack are often easiest to understand from the
    helper-service log tail, so this helper upgrades an ordinary port timeout
    into a log-backed startup diagnostic.
    """
    def _fetch() -> bool:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited early with code {proc.returncode}:\n{read_log_tail(log_path)}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex((host, port)) == 0

    try:
        poll_until(_fetch, ready=bool, timeout=timeout, interval=PORT_POLL_INTERVAL, describe=f"{name} on {host}:{port}")
    except TimeoutError as err:
        raise TimeoutError(f"{err}\n{read_log_tail(log_path)}") from err


def wait_for_json_health(url: str, *, timeout: float = 45.0) -> dict:
    """Poll an HTTP JSON health endpoint until it reports `{\"ok\": true}`."""
    def _fetch() -> dict:
        with urlopen(url, timeout=5.0) as response:
            return json.loads(response.read().decode("utf-8"))

    return poll_until(_fetch, ready=lambda body: bool(body.get("ok")), timeout=timeout, interval=POLL_INTERVAL, describe=url)

def run_doers_until(
    step: str,
    doers: list,
    *,
    timeout: float = 90.0,
    tock: float = 0.03125,
    ready=None,
    observe=None,
    cleanup=None,
):
    """Run one or more KERIpy doers until completion or timeout.

    The helper owns the doer lifecycle for integration tests: it enters the
    doers, advances the doist, captures optional observer state for diagnostics,
    and always attempts resource cleanup at the end.

    This is the core harness seam that lets the integration layer treat KERIpy
    ``Doer`` and ``DoDoer`` objects as deterministic workflow steps instead of
    shelling out to ``kli`` and scraping stdout.
    """
    doist = doing.Doist(limit=timeout, tock=tock, real=True)
    deeds = doist.enter(doers=doers)

    if ready is None:
        ready = lambda: all(getattr(doer, "done", False) for doer in doers)

    if observe is None:
        observe = lambda: {"done": {type(doer).__name__: getattr(doer, "done", False) for doer in doers}}

    deadline = time.monotonic() + timeout
    last_state = None

    try:
        while time.monotonic() < deadline:
            last_state = observe()
            if ready():
                return last_state
            doist.recur(deeds=deeds)
            last_state = observe()
            if ready():
                return last_state
        raise TimeoutError(f"timed out waiting for {step}; last_state={_format_poll_value(last_state)}")
    finally:
        doist.exit(deeds=deeds)
        if cleanup is not None:
            cleanup(doers)


def write_json(path: Path, body: dict) -> Path:
    """Write a JSON test artifact and return its path for call chaining."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return path


@contextmanager
def patched_home(path: Path):
    """
    Temporarily point `HOME` at the live-stack runtime directory.

    Changes ~/.keri or /usr/local/var/keri to a temp dir.
    """
    previous = os.environ.get("HOME")
    os.environ["HOME"] = str(path)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous
