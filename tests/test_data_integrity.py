"""Contract tests for Isomer Data Integrity proof handling."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from vc_isomer.common import canonicalize_did_url, canonicalize_did_webs, load_json_file
from vc_isomer.data_integrity import (
    JsonLdCanonicalizationError,
    add_data_integrity_proof,
    canonicalize_jsonld,
    create_proof_configuration,
    create_verify_data,
    verify_proof,
)
from vc_isomer.profile import transpose_acdc_to_w3c_vc
from vc_isomer.signing import HabSigner

from keri_test_support import open_test_hab


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _project_fixture(acdc: dict, *, signer: HabSigner) -> tuple[dict, dict]:
    """Project and sign a fixture with a deterministic proof timestamp."""
    issuer_did = canonicalize_did_webs(
        "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
    )
    verification_method = canonicalize_did_url(f"{issuer_did}#{signer.kid}")
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did=issuer_did,
        status_base_url="http://status.example",
    )
    signed_vc = add_data_integrity_proof(
        vc,
        signer=signer,
        verification_method=verification_method,
        created="2026-04-15T00:00:00Z",
    )
    method = {
        "id": f"#{signer.kid}",
        "type": "JsonWebKey",
        "controller": issuer_did,
        "publicKeyJwk": signer.public_jwk,
        "publicKeyMultibase": signer.public_key_multibase,
    }
    return signed_vc, method


def test_data_integrity_proof_verifies_and_detects_tampering():
    """Verify a KERI-backed proof and reject signed document mutation."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    with open_test_hab("di-proof-issuer", b"1234567890abcdef") as (_hby, hab):
        signed_vc, method = _project_fixture(acdc, signer=HabSigner(hab))

        assert verify_proof(signed_vc, method) is True

        tampered = deepcopy(signed_vc)
        tampered["credentialSubject"]["legalName"] = "Tampered Legal Name"
        assert verify_proof(tampered, method) is False


def test_jsonld_canonicalization_is_field_order_independent():
    """Protect the URDNA2015 canonicalization contract."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    with open_test_hab("di-canon-issuer", b"abcdef1234567890") as (_hby, hab):
        signed_vc, _method = _project_fixture(acdc, signer=HabSigner(hab))

    reordered = {
        "proof": signed_vc["proof"],
        "isomer": signed_vc["isomer"],
        "termsOfUse": signed_vc["termsOfUse"],
        "credentialStatus": signed_vc["credentialStatus"],
        "credentialSchema": signed_vc["credentialSchema"],
        "credentialSubject": signed_vc["credentialSubject"],
        "issuanceDate": signed_vc["issuanceDate"],
        "issuer": signed_vc["issuer"],
        "id": signed_vc["id"],
        "type": signed_vc["type"],
        "@context": signed_vc["@context"],
    }

    assert canonicalize_jsonld(signed_vc) == canonicalize_jsonld(reordered)


def test_jsonld_canonicalization_rejects_unregistered_context():
    """Fail closed when a signed document asks for an unknown JSON-LD context."""
    with pytest.raises(JsonLdCanonicalizationError, match="no local JSON-LD context registered"):
        canonicalize_jsonld({"@context": ["https://example.com/unknown.jsonld"], "type": ["Example"]})


def test_create_verify_data_binds_proof_configuration_fields():
    """Different proof options must produce different verify-data bytes."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    issuer_did = canonicalize_did_webs(
        "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
    )
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did=issuer_did,
        status_base_url="http://status.example",
    )
    method = canonicalize_did_url(f"{issuer_did}#key-1")
    first = create_proof_configuration(verification_method=method, created="2026-04-15T00:00:00Z")
    second = create_proof_configuration(verification_method=method, created="2026-04-15T00:00:01Z")

    assert create_verify_data(vc, first) != create_verify_data(vc, second)


def test_create_verify_data_labels_proof_configuration_canonicalization_failures(monkeypatch):
    """Surface proof-option canonicalization failures with a precise label."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    issuer_did = canonicalize_did_webs(
        "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
    )
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did=issuer_did,
        status_base_url="http://status.example",
    )
    proof = create_proof_configuration(
        verification_method=canonicalize_did_url(f"{issuer_did}#key-1"),
        created="2026-04-15T00:00:00Z",
    )
    calls = {"count": 0}
    original = canonicalize_jsonld

    def fail_on_second_call(data):
        calls["count"] += 1
        if calls["count"] == 2:
            raise JsonLdCanonicalizationError("document", "boom")
        return original(data)

    monkeypatch.setattr("vc_isomer.data_integrity.canonicalize_jsonld", fail_on_second_call)

    with pytest.raises(JsonLdCanonicalizationError, match="proof configuration: boom"):
        create_verify_data(vc, proof)
