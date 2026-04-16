"""Contract tests for ACDC-to-W3C profile projection.

These tests protect the semantic shape of the derived W3C VC rather than the
mechanics of signing or DID resolution.
"""

from __future__ import annotations

from pathlib import Path
from importlib import resources

from jsonschema import Draft7Validator

from vc_isomer.common import load_json_file
from vc_isomer.profile import transpose_acdc_to_w3c_vc


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_transpose_vrd_credential_has_isomer_metadata():
    """Ensure VRD projection preserves source lineage and status linkage."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did="did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001",
        status_base_url="http://127.0.0.1:8787",
    )
    assert "VRDCredential" in vc["type"]
    assert vc["@context"][0] == "https://www.w3.org/2018/credentials/v1"
    assert "issuanceDate" in vc
    assert "validFrom" not in vc
    assert vc["isomer"]["sourceCredentialSaid"] == acdc["d"]
    assert vc["credentialStatus"]["id"].endswith(acdc["d"])
    assert vc["credentialStatus"]["type"] == "KERICredentialStatus"
    assert vc["credentialStatus"]["statusRegistryId"] == acdc["ri"]
    assert vc["credentialSchema"] == {
        "id": "https://www.gleif.org/schemas/isomer/v1/vrd-credential.json",
        "type": "JsonSchemaValidator2018",
    }
    assert "proof" not in vc

    subject = vc["credentialSubject"]
    assert subject["AID"] == acdc["a"]["AID"]
    assert "aid" not in subject
    assert subject["address"]["type"] == "PostalAddress"
    assert subject["legalEntityCredential"] == {
        "id": f"urn:said:{acdc['e']['le']['n']}",
        "type": "LegalEntityvLEICredential",
        "schema": acdc["e"]["le"]["s"],
    }


def test_transpose_vrd_auth_includes_authorized_qvi():
    """Ensure VRD Auth projection preserves the authorized QVI relationship."""
    acdc = load_json_file(FIXTURES / "vrd-auth-acdc.json")
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did="did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001",
        status_base_url="http://127.0.0.1:8787",
    )
    assert "VRDAuthorizationCredential" in vc["type"]
    assert vc["credentialSubject"]["authorizedQviAid"] == acdc["a"]["i"]
    assert vc["isomer"]["sourceAuthorizedQviAid"] == acdc["a"]["i"]


def test_isomer_schema_validates_signed_vrd_projection():
    """Ensure the packaged W3C schema matches the signed VC shape."""
    from vc_isomer.jwt import issue_vc_jwt
    from vc_isomer.signing import HabSigner

    from keri_test_support import open_test_hab

    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did="did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001",
        status_base_url="http://127.0.0.1:8787",
    )
    with open_test_hab("schema-vrd-issuer", b"1234567890abcdef") as (_hby, hab):
        signer = HabSigner(hab)
        _token, signed_vc = issue_vc_jwt(
            vc,
            signer=signer,
            verification_method=f"{vc['issuer']}#{signer.kid}",
            proof_created="2026-04-15T00:00:00Z",
        )

    schema_path = resources.files("vc_isomer.resources.schemas").joinpath("isomer-vrd-v1.schema.json")
    schema = load_json_file(schema_path)
    errors = sorted(Draft7Validator(schema).iter_errors(signed_vc), key=lambda error: list(error.path))
    assert errors == []
