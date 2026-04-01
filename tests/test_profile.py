"""Contract tests for ACDC-to-W3C profile projection.

These tests protect the semantic shape of the derived W3C VC rather than the
mechanics of signing or DID resolution.
"""

from __future__ import annotations

from pathlib import Path

from w3c_crosswalk.common import load_json_file
from w3c_crosswalk.profile import transpose_acdc_to_w3c_vc


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_transpose_vrd_credential_has_crosswalk_metadata():
    """Ensure VRD projection preserves source lineage and status linkage."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did="did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001",
        verification_method="did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001#test",
        status_base_url="http://127.0.0.1:8787",
    )
    assert "VRDCredential" in vc["type"]
    assert vc["crosswalk"]["sourceCredentialSaid"] == acdc["d"]
    assert vc["credentialStatus"]["id"].endswith(acdc["d"])


def test_transpose_vrd_auth_includes_authorized_qvi():
    """Ensure VRD Auth projection preserves the authorized QVI relationship."""
    acdc = load_json_file(FIXTURES / "vrd-auth-acdc.json")
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did="did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001",
        verification_method="did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001#test",
        status_base_url="http://127.0.0.1:8787",
    )
    assert "VRDAuthorizationCredential" in vc["type"]
    assert vc["credentialSubject"]["authorizedQviAid"] == acdc["a"]["i"]
