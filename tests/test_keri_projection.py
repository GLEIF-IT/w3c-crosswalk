"""Tests for KERI-state backed W3C projection."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mockito import mock, unstub, when
import pytest

from w3c_crosswalk.common import load_json_file
from w3c_crosswalk.keri_projection import ACDCProjector, ProjectorError
from w3c_crosswalk.services import issue_vc_artifact


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@dataclass
class FakeCreder:
    """Data fake for the KERIpy Creder attributes consumed by the projector."""

    sad: dict[str, Any]
    said: str
    regi: str


@dataclass
class FakeTelState:
    """Data fake for accepted TEL state returned by Tever.vcState(...)."""

    et: str
    d: str
    s: str
    a: dict[str, Any] = field(default_factory=dict)
    dt: str = "2026-04-15T00:00:00Z"


@dataclass
class FakeRgy:
    """Tiny Regery holder; behavior stays on mocked reger/tever collaborators."""

    reger: Any


@pytest.fixture(autouse=True)
def _unstub_mockito():
    """Mockito is for behavior; named fakes above are for protocol-shaped data."""
    yield
    unstub()


def _projector(acdc, *, tel_state):
    creder = FakeCreder(sad=acdc, said=acdc["d"], regi=acdc["ri"])
    tever = mock()
    when(tever).vcState(acdc["d"]).thenReturn(tel_state)
    reger = mock()
    reger.tevers = {acdc["ri"]: tever}
    when(reger).cloneCred(acdc["d"]).thenReturn((creder, None, None, None))
    return ACDCProjector(hby=object(), hab=object(), rgy=FakeRgy(reger=reger))


def test_projector_reads_active_tel_state():
    """Active iss/bis TEL state projects as an active W3C status resource."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    state = FakeTelState(et="iss", d="EtelIssue", s="0", a={"s": 7, "d": "EanchorIssue"})
    projector = _projector(acdc, tel_state=state)

    projection = projector.project_credential(acdc["d"])
    status = projector.project_status(
        said=acdc["d"],
        issuer_did="did:webs:example.com:dws:Eissuer",
        base_url="http://status.example",
    )

    assert projection.acdc["d"] == acdc["d"]
    assert projection.state.revoked is False
    assert projection.state.sequence == 7
    assert status["revoked"] is False
    assert status["status"] == "iss"
    assert status["statusSaid"] == "EtelIssue"


def test_projector_reads_revoked_tel_state():
    """rev/brv TEL state is the only source of W3C revoked=true."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    state = FakeTelState(et="rev", d="EtelRevoke", s="1", a={"s": 9, "d": "EanchorRevoke"}, dt="2026-04-15T00:05:00Z")
    projector = _projector(acdc, tel_state=state)

    status = projector.project_status(
        said=acdc["d"],
        issuer_did="did:webs:example.com:dws:Eissuer",
        base_url="http://status.example",
    )

    assert status["revoked"] is True
    assert status["status"] == "rev"
    assert status["statusSequence"] == 9


def test_projector_fails_for_missing_credential():
    """Projection cannot proceed when the local credential clone is absent."""
    reger = mock()
    reger.tevers = {}
    when(reger).cloneCred("Emissing").thenRaise(KeyError("Emissing"))
    projector = ACDCProjector(hby=object(), hab=object(), rgy=FakeRgy(reger=reger))

    with pytest.raises(ProjectorError, match="unable to clone accepted credential"):
        projector.project_credential("Emissing")


def test_projector_fails_for_missing_tel_state():
    """Projection cannot proceed when no TEL state was accepted for the credential."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    creder = FakeCreder(sad=acdc, said=acdc["d"], regi=acdc["ri"])
    tever = mock()
    when(tever).vcState(acdc["d"]).thenReturn(None)
    reger = mock()
    reger.tevers = {acdc["ri"]: tever}
    when(reger).cloneCred(acdc["d"]).thenReturn((creder, None, None, None))
    projector = ACDCProjector(hby=object(), hab=object(), rgy=FakeRgy(reger=reger))

    with pytest.raises(ProjectorError, match="missing accepted TEL state"):
        projector.project_credential(acdc["d"])


def test_projector_fails_for_missing_registry_state():
    """Projection cannot proceed when the credential registry TEL is absent."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    creder = FakeCreder(sad=acdc, said=acdc["d"], regi=acdc["ri"])
    reger = mock()
    reger.tevers = {}
    when(reger).cloneCred(acdc["d"]).thenReturn((creder, None, None, None))
    projector = ACDCProjector(hby=object(), hab=object(), rgy=FakeRgy(reger=reger))

    with pytest.raises(ProjectorError, match="missing TEL registry state"):
        projector.project_credential(acdc["d"])


def test_projector_fails_for_unreadable_tel_state():
    """Projection surfaces broken TEL/anchor state as a projection error."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    creder = FakeCreder(sad=acdc, said=acdc["d"], regi=acdc["ri"])
    tever = mock()
    when(tever).vcState(acdc["d"]).thenRaise(ValueError("missing anchor"))
    reger = mock()
    reger.tevers = {acdc["ri"]: tever}
    when(reger).cloneCred(acdc["d"]).thenReturn((creder, None, None, None))
    projector = ACDCProjector(hby=object(), hab=object(), rgy=FakeRgy(reger=reger))

    with pytest.raises(ProjectorError, match="unable to read accepted TEL state"):
        projector.project_credential(acdc["d"])


def test_projector_fails_for_tel_state_without_anchor_sequence():
    """Projection requires the KEL event sequence anchoring the TEL state."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    state = FakeTelState(et="iss", d="EtelIssue", s="0", a={})
    projector = _projector(acdc, tel_state=state)

    with pytest.raises(ProjectorError, match="missing KEL anchor sequence"):
        projector.project_credential(acdc["d"])


def test_revoked_credential_cannot_be_issued_as_new_vc():
    """VC-JWT issuance refuses source credentials already revoked in accepted TEL state."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    state = FakeTelState(et="rev", d="EtelRevoke", s="1", a={"s": 9, "d": "EanchorRevoke"}, dt="2026-04-15T00:05:00Z")
    projector = _projector(acdc, tel_state=state)

    with pytest.raises(ProjectorError, match="revoked in accepted TEL state"):
        issue_vc_artifact(
            projector=projector,
            said=acdc["d"],
            issuer_did="did:webs:example.com:dws:Eissuer",
            status_base_url="http://status.example",
        )
