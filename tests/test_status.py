"""Contract tests for local credential status projection and revocation."""

from __future__ import annotations

from pathlib import Path

from w3c_crosswalk.common import load_json_file
from w3c_crosswalk.status import JsonFileStatusStore


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_status_store_projects_and_revokes_credentials(tmp_path):
    """Ensure projected records can be created, revoked, and reloaded."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    store = JsonFileStatusStore(tmp_path / "status-store.json")
    projected = store.project_acdc(acdc, "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001")
    assert projected.revoked is False
    revoked = store.set_revoked(acdc["d"], True, reason="test revoke")
    assert revoked.revoked is True
    assert store.get(acdc["d"]).reason == "test revoke"
