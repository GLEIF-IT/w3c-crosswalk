"""Blocking did:webs setup helpers for SignifyPy wallets."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_INTERVAL_SECONDS = 1.0

CheckAbort = Callable[[dict[str, Any] | None], None]


def get_didwebs_setup(client: Any, name: str) -> dict[str, Any]:
    """Return KERIA did:webs setup state for one managed identifier."""
    return client.didwebs().setup(name)


def ensure_didwebs_setup(
    client: Any,
    name: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    check_abort: CheckAbort | None = None,
) -> dict[str, Any]:
    """Create missing did:webs registry/DA state and wait for readiness."""
    deadline = _deadline(timeout_seconds)
    setup = get_didwebs_setup(client, name)
    if setup.get("ready") is True:
        return setup

    registry = _required_mapping(setup, "registry")
    if registry.get("registryId") is None:
        _check_abort(check_abort, setup)
        create_args = _required_mapping(registry, "createArgs")
        result = client.registries().create(
            _required_string(create_args, "name"),
            _required_string(create_args, "registryName"),
        )
        _wait_for_operation(
            client,
            _operation_payload(result),
            deadline=deadline,
            interval_seconds=interval_seconds,
            check_abort=check_abort,
        )
        setup = get_didwebs_setup(client, name)
        registry = _required_mapping(setup, "registry")

    if setup.get("ready") is not True and registry.get("ready") is not True:
        setup = _wait_for_setup_state(
            client,
            name,
            deadline=deadline,
            interval_seconds=interval_seconds,
            check_abort=check_abort,
            predicate=lambda candidate: candidate.get("ready") is True
            or _required_mapping(candidate, "registry").get("ready") is True,
            label="did:webs registry",
        )

    designated_alias = _required_mapping(setup, "designatedAlias")
    if setup.get("ready") is not True and designated_alias.get("credentialSaid") is None:
        issue_args = designated_alias.get("issueArgs")
        if not isinstance(issue_args, dict):
            raise ValueError(f"KERIA did:webs setup for {name} did not include designated-alias issueArgs")
        _check_abort(check_abort, setup)
        result = client.credentials().issue(
            name,
            _required_string(_required_mapping(setup, "registry"), "name"),
            data=_required_mapping(issue_args, "a"),
            schema=_required_string(issue_args, "s"),
            rules=issue_args.get("r"),
        )
        _wait_for_operation(
            client,
            _operation_payload(result),
            deadline=deadline,
            interval_seconds=interval_seconds,
            check_abort=check_abort,
        )
        setup = get_didwebs_setup(client, name)

    if setup.get("ready") is True:
        return setup

    return wait_for_didwebs_ready(
        client,
        name,
        timeout_seconds=_remaining(deadline, "did:webs readiness", name),
        interval_seconds=interval_seconds,
        check_abort=check_abort,
    )


def wait_for_didwebs_ready(
    client: Any,
    name: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    check_abort: CheckAbort | None = None,
) -> dict[str, Any]:
    """Poll KERIA until one managed identifier has ready did:webs assets."""
    return _wait_for_setup_state(
        client,
        name,
        deadline=_deadline(timeout_seconds),
        interval_seconds=interval_seconds,
        check_abort=check_abort,
        predicate=lambda setup: setup.get("ready") is True,
        label="did:webs readiness",
    )


def _wait_for_setup_state(
    client: Any,
    name: str,
    *,
    deadline: float,
    interval_seconds: float,
    check_abort: CheckAbort | None,
    predicate: Callable[[dict[str, Any]], bool],
    label: str,
) -> dict[str, Any]:
    _validate_interval(interval_seconds)
    while True:
        _check_abort(check_abort, None)
        setup = get_didwebs_setup(client, name)
        if predicate(setup):
            return setup
        _sleep(deadline, interval_seconds, label, name)


def _wait_for_operation(
    client: Any,
    operation: dict[str, Any],
    *,
    deadline: float,
    interval_seconds: float,
    check_abort: CheckAbort | None,
) -> dict[str, Any]:
    return client.operations().wait(
        operation,
        timeout=_remaining(deadline, "did:webs operation", operation.get("name", "unknown")),
        interval=interval_seconds,
        max_interval=interval_seconds,
        backoff=1.0,
        check_abort=check_abort,
    )


def _operation_payload(result: Any) -> dict[str, Any]:
    if hasattr(result, "op"):
        operation = result.op()
    else:
        operation = result
    if not isinstance(operation, dict):
        raise TypeError(f"did:webs operation result must be a dict, got {type(operation)!r}")
    return operation


def _deadline(timeout_seconds: float) -> float:
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive number")
    return time.monotonic() + float(timeout_seconds)


def _validate_interval(interval_seconds: float) -> None:
    if not isinstance(interval_seconds, (int, float)) or interval_seconds <= 0:
        raise ValueError("interval_seconds must be a positive number")


def _remaining(deadline: float, label: str, name: Any) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"timed out waiting for {label} for {name}")
    return remaining


def _sleep(deadline: float, interval_seconds: float, label: str, name: str) -> None:
    remaining = _remaining(deadline, label, name)
    time.sleep(min(interval_seconds, remaining))


def _check_abort(check_abort: CheckAbort | None, value: dict[str, Any] | None) -> None:
    if check_abort is not None:
        check_abort(value)


def _required_mapping(container: dict[str, Any], key: str) -> dict[str, Any]:
    value = container.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"did:webs setup field {key!r} must be an object")
    return value


def _required_string(container: dict[str, Any], key: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"did:webs setup field {key!r} must be a non-empty string")
    return value


__all__ = [
    "DEFAULT_INTERVAL_SECONDS",
    "DEFAULT_TIMEOUT_SECONDS",
    "ensure_didwebs_setup",
    "get_didwebs_setup",
    "wait_for_didwebs_ready",
]
