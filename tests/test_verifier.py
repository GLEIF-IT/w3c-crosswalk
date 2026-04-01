"""Contract tests for VC-JWT, VP-JWT, and crosswalk verification behavior."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote

from w3c_crosswalk.common import load_json_file
from w3c_crosswalk.didwebs import DidWebsClient
from w3c_crosswalk.jwt import KeriHabSigner, issue_vc_jwt, issue_vp_jwt
from w3c_crosswalk.status import HttpStatusResolver
from w3c_crosswalk.verifier import CrosswalkVerifier

from keri_test_support import open_test_hab


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def build_resolver_and_status_clients(
    did_documents: dict[str, dict],
    statuses: dict[str, dict],
) -> tuple[DidWebsClient, HttpStatusResolver]:
    """Build in-memory resolver and status clients for verifier tests."""
    def resolve_loader(url: str, _timeout: float):
        did = unquote(url.split("/1.0/identifiers/", 1)[1])
        return {"didDocument": did_documents[did]}

    def status_loader(url: str, _timeout: float):
        said = url.rsplit("/", 1)[-1]
        return statuses[said]

    return (
        DidWebsClient("http://resolver.example/1.0/identifiers", loader=resolve_loader),
        HttpStatusResolver(loader=status_loader),
    )


def test_verifier_resolves_didwebs_and_accepts_active_status():
    """Accept an active VC-JWT when DID resolution and signature checks pass."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    with open_test_hab("issuer-hab-1", b"0123456789abcdef") as (_hby, hab):
        signer = KeriHabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        verifier_method = {
            "id": f"#{signer.kid}",
            "type": "JsonWebKey",
            "controller": issuer_did,
            "publicKeyJwk": signer.public_jwk,
        }
        did_document = {"id": issuer_did, "verificationMethod": [verifier_method]}

        base_url = "http://status.example"
        token, _vc = issue_vc_jwt(acdc, issuer_did=issuer_did, status_base_url=base_url, signer=signer)
        statuses = {
            acdc["d"]: {
                "id": f"{base_url}/statuses/{acdc['d']}",
                "credentialSaid": acdc["d"],
                "revoked": False,
                "status": "active",
            }
        }
        resolver, status_resolver = build_resolver_and_status_clients({issuer_did: did_document}, statuses)
        verifier = CrosswalkVerifier(resolver=resolver, status_resolver=status_resolver)
        result = verifier.verify_vc_jwt(token)
        assert result.ok is True
        assert result.checks["issuerResolved"] is True
        assert result.checks["signatureValid"] is True


def test_verifier_rejects_revoked_status_and_crosswalk_pair_mismatch():
    """Reject revoked credentials and mismatched ACDC/W3C projections."""
    acdc = load_json_file(FIXTURES / "vrd-auth-acdc.json")
    with open_test_hab("issuer-hab-2", b"fedcba9876543210") as (_hby, hab):
        signer = KeriHabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        verifier_method = {
            "id": f"#{signer.kid}",
            "type": "JsonWebKey",
            "controller": issuer_did,
            "publicKeyJwk": signer.public_jwk,
        }
        did_document = {"id": issuer_did, "verificationMethod": [verifier_method]}

        base_url = "http://status.example"
        token, _vc = issue_vc_jwt(acdc, issuer_did=issuer_did, status_base_url=base_url, signer=signer)
        statuses = {
            acdc["d"]: {
                "id": f"{base_url}/statuses/{acdc['d']}",
                "credentialSaid": acdc["d"],
                "revoked": True,
                "status": "revoked",
            }
        }
        resolver, status_resolver = build_resolver_and_status_clients({issuer_did: did_document}, statuses)
        verifier = CrosswalkVerifier(resolver=resolver, status_resolver=status_resolver)
        result = verifier.verify_vc_jwt(token)
        tampered = load_json_file(FIXTURES / "vrd-auth-acdc.json")
        tampered["a"]["LegalName"] = "Wrong Name"
        pair_result = verifier.verify_crosswalk_pair(tampered, token)
        assert result.ok is False
        assert any("revoked" in error for error in result.errors)
        assert pair_result.ok is False
        assert any("legalNameMatches" in error for error in pair_result.errors)


def test_verifier_accepts_signed_vp_with_embedded_vc():
    """Accept a VP-JWT when holder and embedded credential verification succeeds."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    with open_test_hab("issuer-hab-3", b"AAAABBBBCCCCDDDD") as (_hby_issuer, issuer_hab):
        with open_test_hab("holder-hab-1", b"DDDDEEEEFFFFGGGG") as (_hby_holder, holder_hab):
            issuer_signer = KeriHabSigner(issuer_hab)
            holder_signer = KeriHabSigner(holder_hab)
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
            vc_token, _vc = issue_vc_jwt(acdc, issuer_did=issuer_did, status_base_url=base_url, signer=issuer_signer)
            vp_token, _vp = issue_vp_jwt([vc_token], holder_did=holder_did, signer=holder_signer)
            statuses = {
                acdc["d"]: {
                    "id": f"{base_url}/statuses/{acdc['d']}",
                    "credentialSaid": acdc["d"],
                    "revoked": False,
                    "status": "active",
                }
            }
            resolver, status_resolver = build_resolver_and_status_clients(did_documents, statuses)
            verifier = CrosswalkVerifier(resolver=resolver, status_resolver=status_resolver)
            result = verifier.verify_vp_jwt(vp_token)
            assert result.ok is True
            assert result.checks["signatureValid"] is True
            assert len(result.nested) == 1
            assert result.nested[0]["ok"] is True
