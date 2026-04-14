"""Verify VC-JWT, VP-JWT, and ACDC/W3C crosswalk equivalence.

This module owns the W3C-side verification rules for the repository. It
resolves did:webs key material, verifies JWT signatures, checks projected
status, and compares derived W3C credentials against their source ACDC.

The key boundary is this: the verifier validates the projected W3C representation,
but its correctness still depends on the KERI-side source credential and status
projection seams.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .didwebs import DidWebsClient, DidWebsResolutionError
from .jwt import decode_jwt, verify_jwt_signature
from .profile import expected_credential_type, subject_aid
from .status import HttpStatusResolver


@dataclass
class VerificationResult:
    """Normalized verification result returned by all verifier entrypoints."""

    ok: bool
    kind: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    payload: dict[str, Any] | None = None
    checks: dict[str, Any] = field(default_factory=dict)
    nested: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the result to a JSON-serializable dictionary."""
        return asdict(self)


class CrosswalkVerifier:
    """Verify W3C artifacts and their consistency with source ACDCs.

    Verification proceeds in layers:
    - resolve key state,
    - verify signature,
    - dereference projected status, and only then
    - compare the W3C payload against source ACDC content.
    """

    def __init__(self, resolver: DidWebsClient | None = None, status_resolver: HttpStatusResolver | None = None):
        """Create a verifier with overridable DID and status resolvers."""
        self.resolver = resolver or DidWebsClient()
        self.status_resolver = status_resolver or HttpStatusResolver()

    def verify_vc_jwt(self, token: str) -> VerificationResult:
        """Verify a VC-JWT through did:webs resolution and status lookup."""
        decoded = decode_jwt(token)
        errors: list[str] = []
        payload = decoded.payload
        header = decoded.header

        if header.get("alg") != "EdDSA":
            errors.append(f"unsupported alg: {header.get('alg')}")
        if header.get("typ") != "vc+jwt":
            errors.append(f"unsupported typ: {header.get('typ')}")

        issuer = payload.get("issuer")
        if not issuer:
            errors.append("missing issuer")

        method = None
        if issuer:
            try:
                resolution = self.resolver.resolve(issuer)
                method = self.resolver.find_verification_method(resolution.did_document, header.get("kid", ""))
            except DidWebsResolutionError as exc:
                errors.append(str(exc))

        signature_ok = False
        if method is not None:
            public_jwk = method.get("publicKeyJwk")
            if not isinstance(public_jwk, dict):
                errors.append("resolved verification method did not expose publicKeyJwk")
            else:
                signature_ok = verify_jwt_signature(token, public_jwk)
                if not signature_ok:
                    errors.append("VC-JWT signature verification failed")

        status_resource = payload.get("credentialStatus", {})
        status_ok = True
        if isinstance(status_resource, dict) and status_resource.get("id"):
            status_doc = self.status_resolver.fetch(status_resource["id"])
            status_ok = not bool(status_doc.get("revoked"))
            if not status_ok:
                errors.append(f"credential {status_doc.get('credentialSaid')} is revoked")

        return VerificationResult(
            ok=not errors,
            kind="vc+jwt",
            errors=errors,
            payload=payload,
            checks={
                "issuerResolved": bool(issuer and method is not None),
                "signatureValid": signature_ok,
                "statusActive": status_ok,
                "credentialTypes": payload.get("type", []),
            },
        )

    def verify_vp_jwt(self, token: str) -> VerificationResult:
        """Verify a VP-JWT and recursively verify embedded VC-JWTs."""
        decoded = decode_jwt(token)
        errors: list[str] = []
        payload = decoded.payload
        holder = payload.get("holder")
        header = decoded.header

        if header.get("typ") != "vp+jwt":
            errors.append(f"unsupported typ: {header.get('typ')}")
        if not holder:
            errors.append("missing holder")

        method = None
        if holder:
            try:
                resolution = self.resolver.resolve(holder)
                method = self.resolver.find_verification_method(resolution.did_document, header.get("kid", ""))
            except DidWebsResolutionError as exc:
                errors.append(str(exc))

        signature_ok = False
        if method is not None:
            public_jwk = method.get("publicKeyJwk")
            if isinstance(public_jwk, dict):
                signature_ok = verify_jwt_signature(token, public_jwk)
                if not signature_ok:
                    errors.append("VP-JWT signature verification failed")

        nested_results = []
        for vc_token in payload.get("verifiableCredential", []):
            vc_result = self.verify_vc_jwt(vc_token)
            nested_results.append(vc_result.to_dict())
            if not vc_result.ok:
                errors.append("embedded VC-JWT verification failed")

        return VerificationResult(
            ok=not errors,
            kind="vp+jwt",
            errors=errors,
            payload=payload,
            checks={
                "holderResolved": bool(holder and method is not None),
                "signatureValid": signature_ok,
                "embeddedCredentialCount": len(payload.get("verifiableCredential", [])),
            },
            nested=nested_results,
        )

    def verify_crosswalk_pair(self, acdc: dict[str, Any], token: str) -> VerificationResult:
        """Verify a VC-JWT and compare it against its source ACDC content."""
        vc_result = self.verify_vc_jwt(token)
        errors = list(vc_result.errors)
        payload = vc_result.payload or {}

        if not payload:
            return VerificationResult(ok=False, kind="crosswalk", errors=errors, payload=payload)

        subject = payload.get("credentialSubject", {})
        crosswalk = payload.get("crosswalk", {})
        expected_type = expected_credential_type(acdc)
        expected_subject_aid = subject_aid(acdc.get("a", {}))

        checks = {
            "sourceCredentialSaidMatches": crosswalk.get("sourceCredentialSaid") == acdc.get("d"),
            "sourceSchemaSaidMatches": crosswalk.get("sourceSchemaSaid") == acdc.get("s"),
            "sourceIssuerAidMatches": crosswalk.get("sourceIssuerAid") == acdc.get("i"),
            "sourceRegistryMatches": crosswalk.get("sourceRegistry") == acdc.get("ri"),
            "subjectDidMatches": subject.get("id") == acdc.get("a", {}).get("DID"),
            "subjectAidMatches": subject.get("aid") == expected_subject_aid,
            "legalNameMatches": subject.get("legalName") == acdc.get("a", {}).get("LegalName"),
            "addressMatches": subject.get("headquartersAddress") == acdc.get("a", {}).get("HeadquartersAddress"),
            "typeMatches": expected_type in payload.get("type", []),
        }

        for name, ok in checks.items():
            if not ok:
                errors.append(f"crosswalk check failed: {name}")

        return VerificationResult(
            ok=not errors,
            kind="crosswalk",
            errors=errors,
            payload=payload,
            checks=checks,
        )
