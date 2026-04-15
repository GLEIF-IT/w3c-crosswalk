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
import threading
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


def wait_for_tcp_port(host: str, port: int, *, timeout: float = 45.0) -> None:
    """Wait until one TCP port accepts connections without requiring a subprocess."""
    def _fetch() -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex((host, port)) == 0

    poll_until(_fetch, ready=bool, timeout=timeout, interval=PORT_POLL_INTERVAL, describe=f"{host}:{port}")


class UntilReadyDoer(doing.DoDoer):
    """Own child doers until an external readiness predicate succeeds.

    This deliberately routes ``run_doers_until(...)`` through ``Doist.do()``
    instead of letting the helper call ``Doist.recur(...)`` in its own tight
    wall-clock loop. HIO doers advance on scheduler ticks, but some child doers
    also wait on real sockets, subprocesses, or other wall-clock resources. If
    a test helper repeatedly calls ``recur`` as fast as Python can loop, HIO
    logical time can run far ahead of real I/O progress and make "30 HIO
    seconds" much shorter than 30 elapsed seconds for those external systems.

    The supervisor gives HIO one normal root doer to run with
    ``Doist.do(real=True, limit=...)``. That preserves real-time pacing while
    still allowing the integration harness to stop early on an external
    readiness predicate that is not the same thing as child-doer completion.
    """

    def __init__(self, *, target_doers: list, ready, observe, tock: float = 0.03125):
        self.target_doers = list(target_doers)
        self.ready = ready
        self.observe = observe
        self.last_state = None
        self.ready_reached = False
        super().__init__(doers=self.target_doers, tock=tock)

    def recur(self, tyme, deeds=None):
        """Observe readiness before and after child recurrence."""
        self.last_state = self.observe()
        if self.ready():
            self.ready_reached = True
            self._remove_remaining_children()
            return True

        done = super().recur(tyme=tyme, deeds=deeds)

        self.last_state = self.observe()
        if self.ready():
            self.ready_reached = True
            self._remove_remaining_children()
            return True

        return done

    def _remove_remaining_children(self) -> None:
        """Stop any child doers still owned by this supervisor."""
        remaining = [doer for doer in self.target_doers if doer in self.doers]
        if remaining:
            self.remove(remaining)


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

    Parameters:
        step: Human-readable label for the workflow step. Included in timeout
            errors so failures point at the domain action, not just a helper.
        doers: The KERIpy ``Doer`` or ``DoDoer`` instances to enter and drive.
            These are the objects that actually mutate protocol state while the
            polling loop runs.
        timeout: Maximum wall-clock time to drive the doers before raising a
            ``TimeoutError``.
        tock: Polling cadence passed to the underlying ``Doist``.
        ready: Optional zero-argument predicate returning ``True`` once the
            workflow step has reached its success condition. This callable
            usually closes over mutable external state such as ``hby.db`` that
            the doers update over time. When omitted, readiness defaults to all
            supplied doers reporting ``done``.
        observe: Optional zero-argument callable returning a diagnostic snapshot
            of current state. Like ``ready``, this usually closes over mutable
            external state that the doers are changing. ``observe`` does not
            drive progress; it exists only so timeout errors can report what the
            world looked like while the step was running.
        cleanup: Optional callable receiving the original ``doers`` list after
            ``Doist.do(...)`` exits. Use this to close resources that the doers
            own but do not release deterministically on their own, such as
            hidden LMDB-backed notifier or registry handles.

    Returns:
        The last value returned by ``observe()`` when the step becomes ready.
        When no custom observer is supplied, returns the default doer ``done``
        snapshot.
    """
    if ready is None:
        ready = lambda: all(getattr(doer, "done", False) for doer in doers)

    if observe is None:
        observe = lambda: {"done": {type(doer).__name__: getattr(doer, "done", False) for doer in doers}}

    supervisor = UntilReadyDoer(target_doers=doers, ready=ready, observe=observe, tock=tock)
    doist = doing.Doist(limit=timeout, tock=tock, real=True)

    try:
        doist.do(doers=[supervisor], limit=timeout)
        if supervisor.ready_reached:
            return supervisor.last_state
        raise TimeoutError(
            f"timed out waiting for {step}; "
            f"last_state={_format_poll_value(supervisor.last_state)}"
        )
    finally:
        if cleanup is not None:
            cleanup(doers)


class BackgroundDoistRunner:
    """Run one long-lived HIO doer set in a background thread."""

    def __init__(self, *, name: str, doers: list, tock: float = 0.03125):
        self.name = name
        self.doers = doers
        self.tock = tock
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        self._error: BaseException | None = None

    def start(self, *, timeout: float = 10.0) -> None:
        """Start the background doist thread and fail early on startup errors."""
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            raise TimeoutError(f"timed out starting background doist runner {self.name}")
        self.raise_if_error()

    def close(self, *, timeout: float = 10.0) -> None:
        """Stop the background doist thread and surface any internal error."""
        self._stop.set()
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            raise TimeoutError(f"timed out stopping background doist runner {self.name}")
        self.raise_if_error()

    def raise_if_error(self) -> None:
        """Raise a runtime error when the background thread failed."""
        if self._error is not None:
            raise RuntimeError(f"background doist runner {self.name} failed: {self._error}") from self._error

    def _run(self) -> None:
        """Drive the owned doers until the runner is asked to stop."""
        doist = doing.Doist(limit=0.0, tock=self.tock, real=True)
        deeds = None
        try:
            deeds = doist.enter(doers=self.doers)
            self._ready.set()
            while not self._stop.is_set():
                doist.recur(deeds=deeds)
        except BaseException as exc:
            self._error = exc
            self._ready.set()
        finally:
            if deeds is not None:
                doist.exit(deeds=deeds)


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
