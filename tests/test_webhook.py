"""Contract tests for verifier webhook event construction."""

from __future__ import annotations

from vc_isomer.verifier import VerificationResult
from vc_isomer.webhook import (
    PRESENTATION_VERIFIED_EVENT,
    build_credential_verified_event,
    build_presentation_verified_event,
)


def test_build_presentation_webhook_event_omits_raw_nested_tokens():
    """Expose decoded VP and VC payloads without forwarding raw JWT strings."""
    vc_payload = {
        "id": "urn:example:vc",
        "type": ["VerifiableCredential", "VRDCredential"],
        "issuer": "did:webs:issuer",
        "credentialSubject": {"id": "did:webs:holder"},
    }
    result = VerificationResult(
        ok=True,
        kind="vp+jwt",
        payload={
            "id": "urn:example:vp",
            "holder": "did:webs:holder",
            "verifiableCredential": ["raw-vc-jwt"],
        },
        checks={"signatureValid": True, "embeddedCredentialCount": 1},
        nested=[{
            "ok": True,
            "kind": "vc+jwt",
            "errors": [],
            "warnings": [],
            "payload": vc_payload,
            "checks": {"signatureValid": True},
            "nested": [],
        }],
    )

    event = build_presentation_verified_event(result, verifier_id="isomer-python-test")

    assert event["type"] == PRESENTATION_VERIFIED_EVENT
    assert event["verifier"]["language"] == "Python"
    assert event["presentation"]["holder"] == "did:webs:holder"
    assert event["presentation"]["credentialTypes"] == ["VerifiableCredential", "VRDCredential"]
    assert event["presentation"]["payload"]["verifiableCredential"][0]["id"] == "urn:example:vc"
    assert "raw-vc-jwt" not in str(event)
    assert event["presentation"]["credentials"][0]["payload"] == vc_payload


def test_build_credential_webhook_event_omits_raw_tokens():
    """Expose a successful top-level VC verification as one dashboard event."""
    vc_payload = {
        "id": "urn:example:vc",
        "type": ["VerifiableCredential", "VRDCredential"],
        "issuer": "did:webs:issuer",
        "credentialSubject": {"id": "did:webs:holder"},
    }
    result = VerificationResult(
        ok=True,
        kind="vc+jwt",
        payload=vc_payload,
        checks={"signatureValid": True, "statusActive": True},
    )

    event = build_credential_verified_event(result, verifier_id="isomer-python-test")

    assert event["type"] == PRESENTATION_VERIFIED_EVENT
    assert event["verifier"]["language"] == "Python"
    assert event["presentation"]["kind"] == "vc+jwt"
    assert event["presentation"]["id"] == "urn:example:vc"
    assert event["presentation"]["holder"] == "did:webs:holder"
    assert event["presentation"]["credentialTypes"] == ["VerifiableCredential", "VRDCredential"]
    assert event["presentation"]["credentials"][0]["payload"] == vc_payload
    assert event["verification"]["nested"] == []
