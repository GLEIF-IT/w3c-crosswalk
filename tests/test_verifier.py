"""Contract tests for the pure W3C verification engine."""

from __future__ import annotations

from pathlib import Path

from vc_isomer.common import canonicalize_did_url, canonicalize_did_webs, load_json_file
from vc_isomer.didwebs import DidWebsClient
from vc_isomer.jwt import issue_vc_jwt, issue_vp_jwt
from vc_isomer.profile import transpose_acdc_to_w3c_vc
from vc_isomer.signing import HabSigner
from vc_isomer.verifier import VerificationEngine

from keri_test_support import open_test_hab


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _method_for(did_document: dict, kid: str):
    """Resolve one verification method from an in-memory DID document."""
    return DidWebsClient.find_verification_method(did_document, kid)


def _issue_projected_fixture(acdc: dict, *, issuer_did: str, status_base_url: str, signer: HabSigner):
    """Project a fixture ACDC explicitly, then sign the resulting VC."""
    canonical_issuer = canonicalize_did_webs(issuer_did)
    verification_method = canonicalize_did_url(f"{canonical_issuer}#{signer.kid}")
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did=canonical_issuer,
        verification_method=verification_method,
        status_base_url=status_base_url,
    )
    return issue_vc_jwt(vc, signer=signer, verification_method=verification_method)


def test_engine_accepts_active_status_when_signature_inputs_are_present():
    """Accept an active VC-JWT once the runtime has already resolved its dependencies."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    engine = VerificationEngine()

    with open_test_hab("issuer-hab-1", b"0123456789abcdef") as (_hby, hab):
        signer = HabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        did_document = {
            "id": issuer_did,
            "verificationMethod": [{
                "id": f"#{signer.kid}",
                "type": "JsonWebKey",
                "controller": issuer_did,
                "publicKeyJwk": signer.public_jwk,
            }],
        }

        base_url = "http://status.example"
        token, _vc = _issue_projected_fixture(acdc, issuer_did=issuer_did, status_base_url=base_url, signer=signer)
        prepared = engine.prepare_vc_token(token)
        result = engine.evaluate_prepared_vc(
            prepared,
            method=_method_for(did_document, prepared.header["kid"]),
            status_doc={
                "id": f"{base_url}/status/{acdc['d']}",
                "credSaid": acdc["d"],
                "revoked": False,
                "status": "iss",
            },
        )

        assert result.ok is True
        assert result.checks["issuerResolved"] is True
        assert result.checks["signatureValid"] is True


def test_engine_rejects_revoked_status_and_isomer_pair_mismatch():
    """Reject revoked credentials and mismatched ACDC/W3C projections."""
    acdc = load_json_file(FIXTURES / "vrd-auth-acdc.json")
    engine = VerificationEngine()

    with open_test_hab("issuer-hab-2", b"fedcba9876543210") as (_hby, hab):
        signer = HabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        did_document = {
            "id": issuer_did,
            "verificationMethod": [{
                "id": f"#{signer.kid}",
                "type": "JsonWebKey",
                "controller": issuer_did,
                "publicKeyJwk": signer.public_jwk,
            }],
        }

        base_url = "http://status.example"
        token, _vc = _issue_projected_fixture(acdc, issuer_did=issuer_did, status_base_url=base_url, signer=signer)
        prepared = engine.prepare_vc_token(token)
        result = engine.evaluate_prepared_vc(
            prepared,
            method=_method_for(did_document, prepared.header["kid"]),
            status_doc={
                "id": f"{base_url}/status/{acdc['d']}",
                "credSaid": acdc["d"],
                "revoked": True,
                "status": "rev",
            },
        )

        tampered = load_json_file(FIXTURES / "vrd-auth-acdc.json")
        tampered["a"]["LegalName"] = "Wrong Name"
        pair_result = engine.evaluate_isomer_pair(tampered, result)

        assert result.ok is False
        assert any("revoked" in error for error in result.errors)
        assert pair_result.ok is False
        assert any("legalNameMatches" in error for error in pair_result.errors)


def test_engine_accepts_signed_vp_with_embedded_vc():
    """Accept a VP-JWT when holder and embedded credential verification succeeds."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    engine = VerificationEngine()

    with open_test_hab("issuer-hab-3", b"AAAABBBBCCCCDDDD") as (_hby_issuer, issuer_hab):
        with open_test_hab("holder-hab-1", b"DDDDEEEEFFFFGGGG") as (_hby_holder, holder_hab):
            issuer_signer = HabSigner(issuer_hab)
            holder_signer = HabSigner(holder_hab)
            issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
            holder_did = "did:webs:example.com:dws:EHOLDERAID000000000000000000000000000000000000000001"

            did_documents = {
                issuer_did: {
                    "id": issuer_did,
                    "verificationMethod": [{
                        "id": f"#{issuer_signer.kid}",
                        "type": "JsonWebKey",
                        "controller": issuer_did,
                        "publicKeyJwk": issuer_signer.public_jwk,
                    }],
                },
                holder_did: {
                    "id": holder_did,
                    "verificationMethod": [{
                        "id": f"#{holder_signer.kid}",
                        "type": "JsonWebKey",
                        "controller": holder_did,
                        "publicKeyJwk": holder_signer.public_jwk,
                    }],
                },
            }
            base_url = "http://status.example"
            vc_token, _vc = _issue_projected_fixture(
                acdc,
                issuer_did=issuer_did,
                status_base_url=base_url,
                signer=issuer_signer,
            )
            vp_token, _vp = issue_vp_jwt([vc_token], holder_did=holder_did, signer=holder_signer)

            prepared_vc = engine.prepare_vc_token(vc_token)
            vc_result = engine.evaluate_prepared_vc(
                prepared_vc,
                method=_method_for(did_documents[issuer_did], prepared_vc.header["kid"]),
                status_doc={
                    "id": f"{base_url}/status/{acdc['d']}",
                    "credSaid": acdc["d"],
                    "revoked": False,
                    "status": "iss",
                },
            )

            prepared_vp = engine.prepare_vp_token(vp_token)
            result = engine.evaluate_prepared_vp(
                prepared_vp,
                method=_method_for(did_documents[holder_did], prepared_vp.header["kid"]),
                nested_results=[vc_result],
            )

            assert result.ok is True
            assert result.checks["signatureValid"] is True
            assert len(result.nested) == 1
            assert result.nested[0]["ok"] is True
