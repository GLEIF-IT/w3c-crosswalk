"""Contract tests for the Falcon service resources."""

from __future__ import annotations

from pathlib import Path

from falcon import testing

from w3c_crosswalk.common import load_json_file
from w3c_crosswalk.longrunning import OperationMonitor
from w3c_crosswalk.service import create_status_app, create_verifier_app
from w3c_crosswalk.services import VerifierOperationService
from w3c_crosswalk.status import JsonFileStatusStore


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_status_service_health_get_and_revoke(tmp_path):
    """Serve health, fetch status, and mutate revocation through Falcon resources."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    store = JsonFileStatusStore(tmp_path / "status-store.json")
    store.project_acdc(acdc, "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001")

    client = testing.TestClient(create_status_app(store=store, base_url="http://status.example"))

    health = client.simulate_get("/healthz")
    assert health.status_code == 200
    assert health.json == {"ok": True, "service": "status"}

    said = acdc["d"]
    fetched = client.simulate_get(f"/status/{said}")
    assert fetched.status_code == 200
    assert fetched.json["credentialSaid"] == said
    assert fetched.json["revoked"] is False

    revoked = client.simulate_post(f"/status/{said}/revoke")
    assert revoked.status_code == 200
    assert revoked.json["revoked"] is True
    assert store.get(said).revoked is True


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
