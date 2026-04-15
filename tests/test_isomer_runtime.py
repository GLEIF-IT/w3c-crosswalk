"""Tests for IsomerRuntime resource ownership."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from w3c_crosswalk.isomer_runtime import (
    IsomerRuntimeDoer,
    IsomerRuntimeError,
    IsomerSignerRuntimeDoer,
    open_isomer_runtime,
    open_isomer_signer_runtime,
)


@dataclass
class FakeHabery:
    """Data fake for the opened KERIpy Habery."""

    hab: Any = object()
    closed: bool = False

    def habByName(self, alias):
        return self.hab if alias == "qvi" else None

    def close(self):
        self.closed = True


@dataclass
class FakeRegery:
    """Data fake for Regery close ordering."""

    hby: Any
    name: str
    base: str
    events: list[str] = field(default_factory=list)

    def close(self):
        self.events.append("rgy")


class ClosingHabery(FakeHabery):
    """Habery fake that records close ordering into a shared list."""

    def __init__(self, *, events):
        super().__init__()
        self.events = events

    def close(self):
        self.events.append("hby")
        super().close()


def test_open_isomer_runtime_builds_projector_and_signer(monkeypatch):
    """Opening a runtime wires the non-owning projector and signer."""
    hby = FakeHabery()

    monkeypatch.setattr("w3c_crosswalk.isomer_runtime.existing.setupHby", lambda **_: hby)
    monkeypatch.setattr("w3c_crosswalk.isomer_runtime.credentialing.Regery", FakeRegery)

    runtime = open_isomer_runtime(name="qvi", base="", alias="qvi", passcode="0123456789abcdefghijk")
    try:
        assert runtime.hby is hby
        assert runtime.hab is hby.hab
        assert runtime.projector.hby is hby
        assert runtime.projector.rgy is runtime.rgy
        assert runtime.signer._hab is hby.hab
    finally:
        runtime.close()


def test_open_isomer_runtime_closes_habery_when_alias_missing(monkeypatch):
    """A failed alias lookup closes the opened Habery before raising."""
    hby = FakeHabery()

    monkeypatch.setattr("w3c_crosswalk.isomer_runtime.existing.setupHby", lambda **_: hby)

    with pytest.raises(IsomerRuntimeError, match="unable to locate habitat alias"):
        open_isomer_runtime(name="qvi", base="", alias="missing", passcode="0123456789abcdefghijk")
    assert hby.closed is True


def test_open_isomer_signer_runtime_builds_signer_without_regery(monkeypatch):
    """Signer-only runtime opens Habery/Hab without opening Regery."""
    hby = FakeHabery()
    opened_regery = []

    monkeypatch.setattr("w3c_crosswalk.isomer_runtime.existing.setupHby", lambda **_: hby)
    monkeypatch.setattr("w3c_crosswalk.isomer_runtime.credentialing.Regery", lambda **_: opened_regery.append(True))

    runtime = open_isomer_signer_runtime(name="qvi", base="", alias="qvi", passcode="0123456789abcdefghijk")
    try:
        assert runtime.hby is hby
        assert runtime.hab is hby.hab
        assert runtime.signer._hab is hby.hab
        assert opened_regery == []
    finally:
        runtime.close()


def test_isomer_runtime_close_closes_regery_before_habery(monkeypatch):
    """Runtime close unwinds Regery before Habery."""
    events = []
    hby = ClosingHabery(events=events)

    class OrderedRegery(FakeRegery):
        def __init__(self, **kwargs):
            super().__init__(events=events, **kwargs)

    monkeypatch.setattr("w3c_crosswalk.isomer_runtime.existing.setupHby", lambda **_: hby)
    monkeypatch.setattr("w3c_crosswalk.isomer_runtime.credentialing.Regery", OrderedRegery)

    runtime = open_isomer_runtime(name="qvi", base="", alias="qvi", passcode="0123456789abcdefghijk")
    runtime.close()

    assert events == ["rgy", "hby"]


def test_isomer_signer_runtime_doer_closes_runtime_after_failure(monkeypatch):
    """Signer runtime doer closes opened runtime even when command work raises."""
    closed = []

    class FakeRuntime:
        signer = object()

        def close(self):
            closed.append(True)

    class FailingDoer(IsomerSignerRuntimeDoer):
        def recur(self, tyme):
            raise RuntimeError("boom")

    monkeypatch.setattr("w3c_crosswalk.isomer_runtime.open_isomer_signer_runtime", lambda **_: FakeRuntime())
    doer = FailingDoer(name="qvi", base="", alias="qvi", passcode="0123456789abcdefghijk")
    dog = doer(tymth=lambda: 0.0)
    next(dog)

    with pytest.raises(RuntimeError, match="boom"):
        dog.send(0.0)

    assert closed == [True]


def test_isomer_runtime_doer_closes_runtime_after_failure(monkeypatch):
    """Doer exit closes opened runtime even when command work raises."""
    closed = []

    class FakeRuntime:
        projector = object()
        signer = object()

        def close(self):
            closed.append(True)

    class FailingDoer(IsomerRuntimeDoer):
        def recur(self, tyme):
            raise RuntimeError("boom")

    monkeypatch.setattr("w3c_crosswalk.isomer_runtime.open_isomer_runtime", lambda **_: FakeRuntime())
    doer = FailingDoer(name="qvi", base="", alias="qvi", passcode="0123456789abcdefghijk")
    dog = doer(tymth=lambda: 0.0)
    next(dog)

    with pytest.raises(RuntimeError, match="boom"):
        dog.send(0.0)

    assert closed == [True]
