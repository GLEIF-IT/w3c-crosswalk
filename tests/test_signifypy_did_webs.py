"""Python did:webs setup package tests."""

from __future__ import annotations

import pytest

from signifypy_did_webs import (
    ensure_didwebs_setup,
    get_didwebs_setup,
    wait_for_didwebs_ready,
)


ISSUE_ARGS = {
    "ri": "Eregistry",
    "s": "EdesignatedAliasSchema",
    "a": {"ids": ["did:webs:example:dws:Eaid"]},
    "r": {"usageDisclaimer": {"l": ""}},
}


class _Result:
    def __init__(self, name: str):
        self.name = name

    def op(self) -> dict[str, object]:
        return {"name": self.name, "done": False}


class _Client:
    def __init__(self, setups: list[dict[str, object]]):
        self.setups = list(setups)
        self.calls: list[tuple] = []

    def didwebs(self):
        return self

    def setup(self, name: str):
        self.calls.append(("setup", name))
        if len(self.setups) > 1:
            return self.setups.pop(0)
        return self.setups[0]

    def registries(self):
        return self

    def create(self, name: str, registry_name: str):
        self.calls.append(("registry.create", name, registry_name))
        return _Result("registry-op")

    def credentials(self):
        return self

    def issue(self, name: str, registry_name: str, *, data, schema, rules=None):
        self.calls.append(("credential.issue", name, registry_name, data, schema, rules))
        return _Result("credential-op")

    def operations(self):
        return self

    def wait(self, operation: dict[str, object], **kwargs):
        self.calls.append(("operation.wait", operation, kwargs))
        return {"name": operation["name"], "done": True}


def _setup(
    *,
    ready: bool = False,
    registry_id: str | None = None,
    registry_ready: bool = False,
    credential_said: str | None = None,
    issue_args: dict[str, object] | None = ISSUE_ARGS,
) -> dict[str, object]:
    return {
        "name": "aid1",
        "aid": "Eaid",
        "dws": "did:webs:example:dws:Eaid" if ready else None,
        "ready": ready,
        "registry": {
            "name": "didwebs-designated-aliases",
            "registryId": registry_id,
            "ready": registry_ready,
            "createArgs": {
                "name": "aid1",
                "registryName": "didwebs-designated-aliases",
            },
        },
        "designatedAlias": {
            "schema": "EdesignatedAliasSchema",
            "credentialSaid": credential_said,
            "ready": ready,
            "issueArgs": issue_args,
        },
    }


@pytest.fixture
def instant_clock(monkeypatch):
    clock = {"now": 0.0}

    import signifypy_did_webs

    monkeypatch.setattr(signifypy_did_webs.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(signifypy_did_webs.time, "sleep", lambda seconds: clock.update(now=clock["now"] + seconds))
    return clock


def test_get_didwebs_setup_delegates_to_client_didwebs_setup():
    client = _Client([_setup()])

    assert get_didwebs_setup(client, "aid1") == _setup()
    assert client.calls == [("setup", "aid1")]


def test_ensure_didwebs_setup_returns_immediately_when_ready():
    client = _Client([_setup(ready=True, registry_id="Eregistry", registry_ready=True, credential_said="Ecred")])

    result = ensure_didwebs_setup(client, "aid1")

    assert result["ready"] is True
    assert client.calls == [("setup", "aid1")]


def test_ensure_didwebs_setup_creates_registry_issues_da_and_waits_ready():
    client = _Client(
        [
            _setup(),
            _setup(registry_id="Eregistry", registry_ready=True),
            _setup(ready=True, registry_id="Eregistry", registry_ready=True, credential_said="Ecred"),
        ]
    )

    result = ensure_didwebs_setup(client, "aid1")

    assert result["ready"] is True
    assert client.calls[0] == ("setup", "aid1")
    assert client.calls[1] == ("registry.create", "aid1", "didwebs-designated-aliases")
    assert client.calls[2][0] == "operation.wait"
    assert client.calls[2][1] == {"name": "registry-op", "done": False}
    assert client.calls[3] == ("setup", "aid1")
    assert client.calls[4] == (
        "credential.issue",
        "aid1",
        "didwebs-designated-aliases",
        {"ids": ["did:webs:example:dws:Eaid"]},
        "EdesignatedAliasSchema",
        {"usageDisclaimer": {"l": ""}},
    )
    assert client.calls[5][0] == "operation.wait"
    assert client.calls[5][1] == {"name": "credential-op", "done": False}
    assert client.calls[6] == ("setup", "aid1")


def test_ensure_didwebs_setup_waits_for_pending_registry_before_issuing(instant_clock):
    client = _Client(
        [
            _setup(registry_id="Eregistry", registry_ready=False),
            _setup(registry_id="Eregistry", registry_ready=True),
            _setup(ready=True, registry_id="Eregistry", registry_ready=True, credential_said="Ecred"),
        ]
    )

    result = ensure_didwebs_setup(client, "aid1", interval_seconds=1.0)

    assert result["ready"] is True
    assert ("registry.create", "aid1", "didwebs-designated-aliases") not in client.calls
    assert any(call[0] == "credential.issue" for call in client.calls)


def test_ensure_didwebs_setup_waits_without_reissuing_existing_da(instant_clock):
    client = _Client(
        [
            _setup(registry_id="Eregistry", registry_ready=True, credential_said="Ecred"),
            _setup(ready=True, registry_id="Eregistry", registry_ready=True, credential_said="Ecred"),
        ]
    )

    result = ensure_didwebs_setup(client, "aid1", interval_seconds=1.0)

    assert result["ready"] is True
    assert not any(call[0] == "credential.issue" for call in client.calls)


def test_ensure_didwebs_setup_rejects_missing_issue_args():
    client = _Client([_setup(registry_id="Eregistry", registry_ready=True, issue_args=None)])

    with pytest.raises(ValueError, match="issueArgs"):
        ensure_didwebs_setup(client, "aid1")


def test_wait_for_didwebs_ready_times_out(instant_clock):
    client = _Client([_setup(registry_id="Eregistry", registry_ready=True)])

    with pytest.raises(TimeoutError, match="did:webs readiness"):
        wait_for_didwebs_ready(client, "aid1", timeout_seconds=2.0, interval_seconds=1.0)


def test_wait_for_didwebs_ready_honors_check_abort(instant_clock):
    client = _Client([_setup(registry_id="Eregistry", registry_ready=True)])
    calls = {"count": 0}

    def check_abort(_value):
        calls["count"] += 1
        if calls["count"] > 1:
            raise RuntimeError("aborted")

    with pytest.raises(RuntimeError, match="aborted"):
        wait_for_didwebs_ready(client, "aid1", interval_seconds=1.0, check_abort=check_abort)
