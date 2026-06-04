"""KERIA W3C workflow helpers for edge-built VC-JWT and VP-JWT artifacts."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

from signify.app.exchanging import Exchanges
from vc_isomer.common import canonicalize_did_webs
from vc_isomer.jwt import issue_vc_jwt, issue_vp_jwt
from vc_isomer.profile import transpose_acdc_to_w3c_vc

from .constants import W3C_GRANT_ROUTE
from .signify import signer_for_identifier


class W3CKeriaClient:
    """Small KERIA W3C route wrapper over a SignifyPy-style client."""

    def __init__(self, client: Any):
        """Bind the wrapper to one connected SignifyPy client."""
        self.client = client

    def create_issuance(self, name: str, source_credential_said: str) -> dict[str, Any]:
        """Create or resume issuer-side W3C issuance context."""
        return self.client.post(
            f"/identifiers/{name}/w3c/issuances",
            json={"sourceCredentialSaid": source_credential_said},
        ).json()

    def issuance(self, name: str, issuance_id: str) -> dict[str, Any]:
        """Return one issuer-side W3C issuance context."""
        return self.client.get(f"/identifiers/{name}/w3c/issuances/{_path(issuance_id)}").json()

    def submit_vc_jwt(self, name: str, issuance_id: str, vc_jwt: str) -> dict[str, Any]:
        """Submit one edge-built VC-JWT for KERIA validation and storage."""
        return self.client.post(
            f"/identifiers/{name}/w3c/issuances/{_path(issuance_id)}/vc-jwt",
            json={"vcJwt": vc_jwt},
        ).json()

    def deliver_issuance(self, name: str, issuance: dict[str, Any]) -> dict[str, Any]:
        """Sign and submit the issuer grant EXN for one finalized W3C issuance."""
        issuance_id = _required_string(issuance, "issuanceId", "W3C issuance id")
        sender = self.client.identifiers().get(name)
        issuer_aid = _required_string(issuance, "issuerAid", "W3C issuance issuer AID")
        sender_prefix = sender.get("prefix") if isinstance(sender, dict) else None
        if sender_prefix != issuer_aid:
            raise ValueError(f"W3C issuance {issuance_id} belongs to {issuer_aid}, not {sender_prefix or name}")

        payload = {
            "holderAid": _required_string(issuance, "holderAid", "W3C issuance holder AID"),
            "holderDid": canonicalize_did_webs(_required_string(issuance, "holderDid", "W3C issuance holder DID")),
            "issuerAid": issuer_aid,
            "issuerDid": canonicalize_did_webs(_required_string(issuance, "issuerDid", "W3C issuance issuer DID")),
            "sourceCredentialSaid": _required_string(
                issuance,
                "sourceCredentialSaid",
                "W3C issuance source credential SAID",
            ),
            "schemaSaid": _required_string(issuance, "schemaSaid", "W3C issuance schema SAID"),
            "issuanceId": issuance_id,
            "vcJwt": _required_string(issuance, "vcJwt", "W3C issuance VC-JWT"),
            "statusUrl": _required_string(issuance, "statusUrl", "W3C issuance status URL"),
            "profile": _required_string(issuance, "profile", "W3C issuance profile"),
        }
        exn, sigs, atc = Exchanges(self.client).createExchangeMessage(
            sender,
            W3C_GRANT_ROUTE,
            payload,
            {},
            recipient=payload["holderAid"],
        )
        return self.client.post(
            f"/identifiers/{name}/w3c/issuances/{_path(issuance_id)}/grant",
            json={"exn": exn.ked, "sigs": sigs, "atc": atc, "rec": [payload["holderAid"]]},
        ).json()

    def credentials(self, name: str) -> list[dict[str, Any]]:
        """Return holder W3C credential inventory."""
        return self.client.get(f"/identifiers/{name}/w3c/credentials").json()["credentials"]

    def credential(self, name: str, credential_id: str) -> dict[str, Any]:
        """Return one holder W3C credential detail record."""
        return self.client.get(f"/identifiers/{name}/w3c/credentials/{_path(credential_id)}").json()

    def present(self, name: str, descriptor: dict[str, Any], vp_jwt: str) -> dict[str, Any]:
        """Submit one edge-built VP-JWT to KERIA for validation and forwarding."""
        return self.client.post(
            f"/identifiers/{name}/w3c/presentations",
            json={**descriptor, "vpJwt": vp_jwt},
        ).json()

    def presentation(self, name: str, presentation_id: str) -> dict[str, Any]:
        """Return one holder W3C presentation result."""
        return self.client.get(f"/identifiers/{name}/w3c/presentations/{_path(presentation_id)}").json()


def issue_w3c_credential(
    *,
    client: Any,
    issuer_name: str,
    source_credential_said: str,
    timeout_seconds: float = 120.0,
    poll_interval: float = 1.0,
) -> dict[str, Any]:
    """Build, sign, validate, and deliver one W3C VC-JWT from an issuer edge."""
    w3c = W3CKeriaClient(client)
    issuance = w3c.create_issuance(issuer_name, source_credential_said)
    if not issuance.get("vcJwt"):
        source_credential = issuance.get("sourceCredential")
        if not isinstance(source_credential, dict):
            raise ValueError("KERIA issuance context did not include sourceCredential")
        status_base_url = _required_string(issuance, "statusBaseUrl", "W3C issuance status base URL")
        issuer_did = _required_string(issuance, "issuerDid", "W3C issuance issuer DID")
        unsecured_vc = transpose_acdc_to_w3c_vc(
            source_credential,
            issuer_did=issuer_did,
            status_base_url=status_base_url,
        )
        signer = signer_for_identifier(client, issuer_name)
        vc_jwt, _secured_vc = issue_vc_jwt(
            unsecured_vc,
            signer=signer,
            verification_method=f"{canonicalize_did_webs(issuer_did)}#{signer.kid}",
        )
        issuance = w3c.submit_vc_jwt(issuer_name, _required_string(issuance, "issuanceId"), vc_jwt)

    deadline = time.monotonic() + timeout_seconds
    while True:
        if issuance.get("state") == "grant_sent" and issuance.get("vcJwt"):
            return issuance
        if issuance.get("state") in {"issued", "delivery_pending"}:
            issuance = w3c.deliver_issuance(issuer_name, issuance)
            continue
        if issuance.get("state") == "failed":
            raise RuntimeError(issuance.get("error") or f"W3C issuance {issuance.get('issuanceId')} failed")
        if time.monotonic() >= deadline:
            raise TimeoutError(
                "Timed out waiting for W3C issuance delivery "
                f"{issuance.get('issuanceId')}. Last state: {issuance.get('state')}."
            )
        time.sleep(poll_interval)
        issuance = w3c.issuance(issuer_name, _required_string(issuance, "issuanceId"))


def present_w3c_credential(
    *,
    client: Any,
    holder_name: str,
    credential_id: str,
    verifier_request: dict[str, Any],
) -> dict[str, Any]:
    """Build, sign, validate, and submit one holder VP-JWT in a single edge action."""
    w3c = W3CKeriaClient(client)
    credential = w3c.credential(holder_name, credential_id)
    vc_jwt = _required_string(credential, "vcJwt", "held W3C VC-JWT")
    holder_did = _required_string(credential, "holderDid", "held W3C holder DID")
    signer = signer_for_identifier(client, holder_name)
    audience = _string_value(verifier_request.get("aud")) or _string_value(verifier_request.get("client_id"))
    nonce = _string_value(verifier_request.get("nonce"))
    vp_jwt, _vp = issue_vp_jwt([vc_jwt], holder_did=holder_did, signer=signer, audience=audience, nonce=nonce)
    return w3c.present(holder_name, {**verifier_request, "credentialId": credential_id}, vp_jwt)


def _path(value: str) -> str:
    return quote(value, safe="")


def _required_string(record: dict[str, Any], key: str, label: str | None = None) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label or key} is required")
    return value


def _string_value(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
