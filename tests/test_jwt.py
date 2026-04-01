"""Contract tests for the lightweight JWT signing helpers."""

from __future__ import annotations

from w3c_crosswalk.jwt import KeriHabSigner, decode_jwt, encode_jwt, verify_jwt_signature

from keri_test_support import open_test_hab


def test_encode_and_verify_eddsa_jwt():
    """Verify that KERI-backed Ed25519 JWTs round-trip correctly."""
    with open_test_hab("jwt-test-hab", b"0123456789abcdef") as (_hby, hab):
        signer = KeriHabSigner(hab)
        token = encode_jwt({"hello": "world"}, typ="vc+jwt", kid=f"did:webs:example#{signer.kid}", signer=signer)
        decoded = decode_jwt(token)
        assert decoded.payload == {"hello": "world"}
        assert verify_jwt_signature(token, signer.public_jwk) is True
