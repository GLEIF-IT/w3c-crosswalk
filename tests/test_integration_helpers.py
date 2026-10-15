from __future__ import annotations

import pytest
from hio.base import doing

from tests.integration.helpers import run_doers_until


def _counting_doer(state: dict, *, tock: float = 0.01):
    def count(tymth=None, tock=0.0, **kwa):
        _ = yield tock
        try:
            while True:
                state["ticks"] += 1
                yield tock
        finally:
            state["closed"] = True

    return doing.doify(count, tock=tock)


def test_run_doers_until_returns_observed_state_when_ready():
    state = {"ticks": 0, "closed": False}
    doer = _counting_doer(state)

    result = run_doers_until(
        "counting doer",
        [doer],
        timeout=1.0,
        tock=0.01,
        ready=lambda: state["ticks"] >= 2,
        observe=lambda: {"ticks": state["ticks"]},
    )

    assert result == {"ticks": 2}
    assert state["closed"] is True


def test_run_doers_until_timeout_includes_step_and_last_state():
    state = {"ticks": 0, "closed": False}
    doer = _counting_doer(state)

    with pytest.raises(TimeoutError) as caught:
        run_doers_until(
            "never ready",
            [doer],
            timeout=0.05,
            tock=0.01,
            ready=lambda: False,
            observe=lambda: {"ticks": state["ticks"]},
        )

    message = str(caught.value)
    assert "timed out waiting for never ready" in message
    assert "last_state=" in message
    assert "ticks" in message
    assert state["closed"] is True


def test_run_doers_until_calls_cleanup_on_success_and_timeout():
    success_state = {"ticks": 0, "closed": False}
    success_doer = _counting_doer(success_state)
    success_cleanup_calls = []

    run_doers_until(
        "cleanup success",
        [success_doer],
        timeout=1.0,
        tock=0.01,
        ready=lambda: success_state["ticks"] >= 1,
        observe=lambda: {"ticks": success_state["ticks"]},
        cleanup=lambda doers: success_cleanup_calls.append(doers),
    )

    assert success_cleanup_calls == [[success_doer]]

    timeout_state = {"ticks": 0, "closed": False}
    timeout_doer = _counting_doer(timeout_state)
    timeout_cleanup_calls = []

    with pytest.raises(TimeoutError):
        run_doers_until(
            "cleanup timeout",
            [timeout_doer],
            timeout=0.05,
            tock=0.01,
            ready=lambda: False,
            observe=lambda: {"ticks": timeout_state["ticks"]},
            cleanup=lambda doers: timeout_cleanup_calls.append(doers),
        )

    assert timeout_cleanup_calls == [[timeout_doer]]


def test_background_runner_paces_network_timeouts_and_closes_doers():
    """One virtual second must not expire during the first 50 ms of real I/O."""
    import threading

    from tests.integration.helpers import BackgroundDoistRunner

    expired = threading.Event()
    closed = threading.Event()

    def deadline(tymth=None, tock=0.0, **kwa):
        start = tymth()
        try:
            while tymth() - start < 1.0:
                yield tock
            expired.set()
            yield tock
        finally:
            closed.set()

    runner = BackgroundDoistRunner(
        name="paced-timeout", doers=[doing.doify(deadline)], tock=0.01
    )
    runner.start()
    try:
        assert not expired.wait(0.05)
    finally:
        runner.close()
    assert closed.is_set()
