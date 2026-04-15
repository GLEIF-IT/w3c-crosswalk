"""Contract tests for the lightweight JWT signing helpers."""

from __future__ import annotations

from pathlib import Path

from vc_isomer.common import canonicalize_did_url, canonicalize_did_webs, load_json_file
from vc_isomer.jwt import decode_jwt, encode_jwt, issue_vc_jwt, verify_jwt_signature
from vc_isomer.profile import transpose_acdc_to_w3c_vc
from vc_isomer.signing import HabSigner

from keri_test_support import open_test_hab


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_encode_and_verify_eddsa_jwt():
    """Verify that KERI-backed Ed25519 JWTs round-trip correctly."""
    with open_test_hab("jwt-test-hab", b"0123456789abcdef") as (_hby, hab):
        signer = HabSigner(hab)
        token = encode_jwt({"hello": "world"}, typ="vc+jwt", kid=f"did:webs:example#{signer.kid}", signer=signer)
        decoded = decode_jwt(token)
        assert decoded.payload == {"hello": "world"}
        assert verify_jwt_signature(token, signer.public_jwk) is True


def test_issue_vc_jwt_canonicalizes_did_webs_issuer_and_kid():
    """Repair raw-port did:webs issuer values before they become wire artifacts."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")

    with open_test_hab("jwt-test-issuer", b"1111222233334444") as (_hby, hab):
        signer = HabSigner(hab)
        issuer_did = canonicalize_did_webs("did:webs:127.0.0.1:7676:dws:ELEGALAID000000000000000000000000000000000000000001")
        verification_method = canonicalize_did_url(f"{issuer_did}#{signer.kid}")
        vc = transpose_acdc_to_w3c_vc(
            acdc,
            issuer_did=issuer_did,
            verification_method=verification_method,
            status_base_url="http://127.0.0.1:8787",
        )
        token, vc = issue_vc_jwt(
            vc,
            signer=signer,
            verification_method=verification_method,
        )

        decoded = decode_jwt(token)
        assert vc["issuer"] == "did:webs:127.0.0.1%3A7676:dws:ELEGALAID000000000000000000000000000000000000000001"
        assert decoded.payload["issuer"] == vc["issuer"]
        assert decoded.header["kid"].startswith(f"{vc['issuer']}#")
