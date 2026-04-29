"""Webhook event construction for successful verifier presentations and VCs."""

from __future__ import annotations

from copy import deepcopy
from typing import Any
from uuid import uuid4

from .common import utc_timestamp
from .verifier import VerificationResult


PRESENTATION_VERIFIED_EVENT = "isomer.presentation.verified.v1"


def python_verifier_metadata(*, verifier_id: str, verifier_label: str | None = None) -> dict[str, Any]:
    """Return the stable dashboard metadata for the Python verifier."""
    return {
        "id": verifier_id,
        "label": verifier_label or "Isomer Python",
        "type": "isomer-python",
        "language": "Python",
        "libraries": [
            {"name": "vc_isomer", "role": "Isomer verifier engine"},
            {"name": "PyLD", "role": "JSON-LD canonicalization"},
            {"name": "did-webs-resolver", "role": "did:webs resolution"},
        ],
    }


def build_presentation_verified_event(
    result: VerificationResult,
    *,
    verifier_id: str,
    verifier_label: str | None = None,
) -> dict[str, Any]:
    """Build one raw-token-free webhook event from a successful VP result."""
    credentials = [_credential_entry(nested) for nested in result.nested]
    return {
        "type": PRESENTATION_VERIFIED_EVENT,
        "eventId": uuid4().hex,
        "verifiedAt": utc_timestamp(),
        "verifier": python_verifier_metadata(verifier_id=verifier_id, verifier_label=verifier_label),
        "presentation": {
            "kind": result.kind,
            "id": _string(result.payload, "id"),
            "holder": _string(result.payload, "holder"),
            "credentialTypes": _credential_types(credentials),
            "payload": _presentation_payload(result.payload, credentials),
            "credentials": credentials,
        },
        "verification": {
            "ok": result.ok,
            "kind": result.kind,
            "checks": deepcopy(result.checks),
            "warnings": list(result.warnings),
            "nested": [_nested_verification_summary(nested) for nested in result.nested],
        },
    }


def build_credential_verified_event(
    result: VerificationResult,
    *,
    verifier_id: str,
    verifier_label: str | None = None,
) -> dict[str, Any]:
    """Build one raw-token-free webhook event from a successful VC result."""
    credential = _credential_entry(result.to_dict())
    credentials = [credential]
    return {
        "type": PRESENTATION_VERIFIED_EVENT,
        "eventId": uuid4().hex,
        "verifiedAt": utc_timestamp(),
        "verifier": python_verifier_metadata(verifier_id=verifier_id, verifier_label=verifier_label),
        "presentation": {
            "kind": result.kind,
            "id": credential.get("id"),
            "holder": credential.get("subject"),
            "credentialTypes": _credential_types(credentials),
            "payload": deepcopy(result.payload) if isinstance(result.payload, dict) else None,
            "credentials": credentials,
        },
        "verification": {
            "ok": result.ok,
            "kind": result.kind,
            "checks": deepcopy(result.checks),
            "warnings": list(result.warnings),
            "nested": [],
        },
    }


def _credential_entry(nested: dict[str, Any]) -> dict[str, Any]:
    """Return the decoded credential payload plus dashboard summary fields."""
    payload = nested.get("payload") if isinstance(nested.get("payload"), dict) else {}
    subject = payload.get("credentialSubject", {})
    return {
        "kind": nested.get("kind", "vc+jwt"),
        "id": payload.get("id"),
        "issuer": payload.get("issuer"),
        "subject": subject.get("id") if isinstance(subject, dict) else None,
        "types": _as_string_list(payload.get("type")),
        "payload": deepcopy(payload),
    }


def _presentation_payload(payload: dict[str, Any] | None, credentials: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Copy a VP payload while replacing embedded raw JWTs with summaries."""
    if not isinstance(payload, dict):
        return None
    cleaned = deepcopy(payload)
    cleaned["verifiableCredential"] = [
        {
            "kind": credential.get("kind"),
            "id": credential.get("id"),
            "issuer": credential.get("issuer"),
            "types": credential.get("types", []),
        }
        for credential in credentials
    ]
    return cleaned


def _nested_verification_summary(nested: dict[str, Any]) -> dict[str, Any]:
    """Return nested verifier result metadata without duplicating payload bodies."""
    return {
        "ok": nested.get("ok"),
        "kind": nested.get("kind"),
        "checks": deepcopy(nested.get("checks", {})),
        "warnings": list(nested.get("warnings", [])),
        "errors": list(nested.get("errors", [])),
    }


def _credential_types(credentials: list[dict[str, Any]]) -> list[str]:
    """Collect distinct credential types from all nested credential payloads."""
    seen: set[str] = set()
    types: list[str] = []
    for credential in credentials:
        for item in credential.get("types", []):
            if item not in seen:
                seen.add(item)
                types.append(item)
    return types


def _as_string_list(value: Any) -> list[str]:
    """Normalize one credential type field into strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _string(payload: dict[str, Any] | None, key: str) -> str | None:
    """Read an optional string field from one payload."""
    if not isinstance(payload, dict):
        return None
    value = payload.get(key)
    return value if isinstance(value, str) else None
