"""Contract tests for the Falcon service resources."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from falcon import testing

from vc_isomer.common import load_json_file
from vc_isomer.longrunning import OperationMonitor
from vc_isomer.service import create_status_app, create_verifier_app
from vc_isomer.services import VerifierOperationService
from vc_isomer.status import JsonFileStatusStore


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@dataclass
class FakeCredState:
    """Data fake for the normalized TEL state consumed by status projection."""

    ilk: str
    said: str
    sequence: int
    date: str


def test_status_service_health_and_get(tmp_path):
    """Serve health and fetch projected TEL-backed status resources."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    store = JsonFileStatusStore(tmp_path / "status-store.json")
    store.project_credential(
        acdc,
        "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001",
        FakeCredState(ilk="iss", said="EtelEventSaid", sequence=0, date="2026-04-15T00:00:00Z"),
    )

    client = testing.TestClient(create_status_app(store=store, base_url="http://status.example"))

    health = client.simulate_get("/healthz")
    assert health.status_code == 200
    assert health.json == {"ok": True, "service": "status"}

    said = acdc["d"]
    fetched = client.simulate_get(f"/status/{said}")
    assert fetched.status_code == 200
    assert fetched.json["credSaid"] == said
    assert fetched.json["revoked"] is False
    assert fetched.json["status"] == "iss"
    assert client.simulate_post(f"/status/{said}/revoke").status_code == 404


def test_verifier_service_submits_and_manages_operations(tmp_path):
    """Submit verifier operations and inspect them through operation resources."""
    monitor = OperationMonitor(head_dir_path=str(tmp_path), name="service-ops")
    try:
        client = testing.TestClient(create_verifier_app(operation_service=VerifierOperationService(monitor=monitor)))

        submitted = client.simulate_post("/verify/vc", json={"token": "abc"})
        assert submitted.status_code == 202
        assert submitted.json["done"] is False
        assert set(submitted.json.keys()) == {"name", "done"}

        name = submitted.json["name"]
        fetched = client.simulate_get(f"/operations/{name}")
        assert fetched.status_code == 200
        assert fetched.json["name"] == name
        assert fetched.json["metadata"]["state"] == "pending"
        assert "submittedAt" in fetched.json["metadata"]
        assert "updatedAt" in fetched.json["metadata"]

        listed = client.simulate_get("/operations", params={"type": "verify-vc"})
        assert listed.status_code == 200
        assert len(listed.json) == 1

        deleted = client.simulate_delete(f"/operations/{name}")
        assert deleted.status_code == 204
        assert client.simulate_get(f"/operations/{name}").status_code == 404
    finally:
        monitor.close()
