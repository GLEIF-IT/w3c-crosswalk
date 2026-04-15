"""Contract tests for local credential status projection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vc_isomer.common import load_json_file
from vc_isomer.status import JsonFileStatusStore


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@dataclass
class FakeCredState:
    """Data fake for the normalized TEL state consumed by status projection."""

    ilk: str
    said: str
    sequence: int
    date: str


def test_status_store_projects_tel_evidence(tmp_path):
    """Ensure projected records preserve the accepted TEL evidence."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    store = JsonFileStatusStore(tmp_path / "status-store.json")
    state = FakeCredState(
        ilk="iss",
        said="EtelEventSaid",
        sequence=0,
        date="2026-04-15T00:00:00Z",
    )
    projected = store.project_credential(
        acdc,
        "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001",
        state,
    )
    resource = projected.as_status_resource("http://status.example")
    assert projected.revoked is False
    assert resource["id"] == f"http://status.example/status/{acdc['d']}"
    assert resource["credSaid"] == acdc["d"]
    assert resource["status"] == "iss"
    assert resource["statusSaid"] == "EtelEventSaid"
    assert store.get(acdc["d"]).status == "iss"
