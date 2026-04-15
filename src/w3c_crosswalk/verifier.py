"""Pure verification engine for W3C JWT artifacts and crosswalk checks.

This module intentionally owns only the verification rules themselves. It does
not perform outbound DID resolution or credential-status dereferencing. Those
transport concerns belong to the long-running verifier runtime so the service
can stay fully cooperative under HIO.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .common import canonicalize_did_url, canonicalize_did_webs
from .constants import EDDSA, VC_JWT_TYP, VP_JWT_TYP
from .jwt import decode_jwt, verify_jwt_signature
from .profile import expected_credential_type, subject_aid


@dataclass(frozen=True)
class PreparedVcToken:
    """Decoded VC-JWT envelope plus the dependency hints needed by the runtime."""

    token: str
    header: dict[str, Any]
    payload: dict[str, Any]
    issuer: str | None
    status_url: str | None
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PreparedVpToken:
    """Decoded VP-JWT envelope plus nested VC tokens for later verification."""

    token: str
    header: dict[str, Any]
    payload: dict[str, Any]
    holder: str | None
    vc_tokens: list[str]
    errors: list[str] = field(default_factory=list)


@dataclass
class VerificationResult:
    """Normalized verification result returned by the pure verification engine."""

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


class VerificationEngine:
    """Evaluate decoded W3C artifacts once their external dependencies are known."""

    def prepare_vc_token(self, token: str) -> PreparedVcToken:
        """Decode a VC-JWT and collect the runtime dependencies it will need."""
        try:
            decoded = decode_jwt(token)
        except ValueError as exc:
            return PreparedVcToken(token=token, header={}, payload={}, issuer=None, status_url=None, errors=[str(exc)])

        header = dict(decoded.header)
        payload = decoded.payload
        errors: list[str] = []

        if header.get("alg") != EDDSA:
            errors.append(f"unsupported alg: {header.get('alg')}")
        if header.get("typ") != VC_JWT_TYP:
            errors.append(f"unsupported typ: {header.get('typ')}")

        kid = header.get("kid")
        if isinstance(kid, str):
            header["kid"] = canonicalize_did_url(kid)

        issuer = payload.get("issuer")
        if not issuer:
            errors.append("missing issuer")
        elif isinstance(issuer, str):
            issuer = canonicalize_did_webs(issuer)

        status_resource = payload.get("credentialStatus", {})
        status_url = status_resource.get("id") if isinstance(status_resource, dict) else None

        return PreparedVcToken(
            token=token,
            header=header,
            payload=payload,
            issuer=issuer,
            status_url=status_url,
            errors=errors,
        )

    def prepare_vp_token(self, token: str) -> PreparedVpToken:
        """Decode a VP-JWT and collect nested VC tokens for later verification."""
        try:
            decoded = decode_jwt(token)
        except ValueError as exc:
            return PreparedVpToken(token=token, header={}, payload={}, holder=None, vc_tokens=[], errors=[str(exc)])

        header = dict(decoded.header)
        payload = decoded.payload
        errors: list[str] = []

        if header.get("typ") != VP_JWT_TYP:
            errors.append(f"unsupported typ: {header.get('typ')}")

        kid = header.get("kid")
        if isinstance(kid, str):
            header["kid"] = canonicalize_did_url(kid)

        holder = payload.get("holder")
        if not holder:
            errors.append("missing holder")

        vc_tokens = payload.get("verifiableCredential", [])
        if not isinstance(vc_tokens, list):
            errors.append("verifiableCredential must be a list")
            vc_tokens = []

        return PreparedVpToken(
            token=token,
            header=header,
            payload=payload,
            holder=canonicalize_did_webs(holder) if isinstance(holder, str) else holder,
            vc_tokens=list(vc_tokens),
            errors=errors,
        )

    def evaluate_prepared_vc(
        self,
        prepared: PreparedVcToken,
        *,
        method: dict[str, Any] | None,
        status_doc: dict[str, Any] | None,
    ) -> VerificationResult:
        """Evaluate one prepared VC-JWT using resolved DID and status material."""
        errors = list(prepared.errors)
        signature_ok = self._verify_signature(
            token=prepared.token,
            method=method,
            label="VC-JWT",
            errors=errors,
        )
        status_ok = self._check_status_doc(status_doc, errors)

        return VerificationResult(
            ok=not errors,
            kind="vc+jwt",
            errors=errors,
            payload=prepared.payload,
            checks={
                "issuerResolved": bool(prepared.issuer and method is not None),
                "signatureValid": signature_ok,
                "statusActive": status_ok,
                "credentialTypes": prepared.payload.get("type", []),
            },
        )

    def evaluate_prepared_vp(
        self,
        prepared: PreparedVpToken,
        *,
        method: dict[str, Any] | None,
        nested_results: list[VerificationResult],
    ) -> VerificationResult:
        """Evaluate one prepared VP-JWT using resolved holder state and nested VC results."""
        errors = list(prepared.errors)
        signature_ok = self._verify_signature(
            token=prepared.token,
            method=method,
            label="VP-JWT",
            errors=errors,
        )

        nested = []
        for result in nested_results:
            nested.append(result.to_dict())
            if not result.ok:
                errors.append("embedded VC-JWT verification failed")

        return VerificationResult(
            ok=not errors,
            kind="vp+jwt",
            errors=errors,
            payload=prepared.payload,
            checks={
                "holderResolved": bool(prepared.holder and method is not None),
                "signatureValid": signature_ok,
                "embeddedCredentialCount": len(prepared.vc_tokens),
            },
            nested=nested,
        )

    def evaluate_crosswalk_pair(self, acdc: dict[str, Any], vc_result: VerificationResult) -> VerificationResult:
        """Compare a successful or unsuccessful VC result against its source ACDC."""
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

    @staticmethod
    def _verify_signature(
        *,
        token: str,
        method: dict[str, Any] | None,
        label: str,
        errors: list[str],
    ) -> bool:
        """Verify a JWT signature from a resolved method and append errors in place."""
        if method is None:
            errors.append(f"unable to resolve verification method for {label}")
            return False

        public_jwk = method.get("publicKeyJwk")
        if not isinstance(public_jwk, dict):
            errors.append(f"resolved verification method did not expose publicKeyJwk for {label}")
            return False

        signature_ok = verify_jwt_signature(token, public_jwk)
        if not signature_ok:
            errors.append(f"{label} signature verification failed")
        return signature_ok

    @staticmethod
    def _check_status_doc(status_doc: dict[str, Any] | None, errors: list[str]) -> bool:
        """Interpret one fetched status document for a VC result."""
        if status_doc is None:
            return True

        status_ok = not bool(status_doc.get("revoked"))
        if not status_ok:
            errors.append(f"credential {status_doc.get('credentialSaid')} is revoked")
        return status_ok
