"""Pure verification engine for W3C JWT artifacts and isomer checks.

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
from .data_integrity import JsonLdCanonicalizationError, verify_proof
from .jwt import decode_jwt, unix_timestamp, verify_jwt_signature
from .profile import expected_credential_type, parse_address, subject_aid


@dataclass(frozen=True)
class PreparedVcToken:
    """Decoded VC-JWT envelope plus the dependency hints needed by the runtime."""

    # Original compact VC-JWT string submitted to the verifier.
    token: str
    # Decoded JOSE header; kid is canonicalized as a DID URL when present.
    header: dict[str, Any]
    # Raw VCDM 1.1 JWT claims decoded from the compact token.
    jwt_payload: dict[str, Any]
    # Decoded W3C VC payload from the VCDM 1.1 "vc" claim.
    payload: dict[str, Any]
    # Canonicalized W3C issuer DID from payload["issuer"], used for did:webs resolution.
    issuer: str | None
    # Credential status URL from payload["credentialStatus"]["id"], fetched by the runtime if present.
    status_url: str | None
    # Decode/header validation errors collected before external DID/status dependencies are fetched.
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PreparedVpToken:
    """Decoded VP-JWT envelope plus nested VC tokens for later verification."""

    # Original compact VP-JWT string submitted to the verifier.
    token: str
    # Decoded JOSE header; kid is canonicalized as a DID URL when present.
    header: dict[str, Any]
    # Raw VCDM 1.1 JWT claims decoded from the compact token.
    jwt_payload: dict[str, Any]
    # Decoded W3C VP payload from the VCDM 1.1 "vp" claim.
    payload: dict[str, Any]
    # Holder DID from payload["holder"], canonicalized before did:webs resolution.
    holder: str | None
    # Embedded VC-JWT strings from payload["verifiableCredential"].
    vc_tokens: list[str]
    # Decode/header validation errors collected before holder or embedded VC checks run.
    errors: list[str] = field(default_factory=list)


@dataclass
class VerificationResult:
    """Normalized verification result returned by the pure verification engine."""

    # Overall verifier outcome; false when any error was recorded.
    ok: bool
    # Result family such as vc+jwt, vp+jwt, or isomer.
    kind: str
    # Human-readable verification failures surfaced into operation responses.
    errors: list[str] = field(default_factory=list)
    # Non-fatal verifier observations reserved for future policy checks.
    warnings: list[str] = field(default_factory=list)
    # Verified W3C VC/VP payload, or the best decoded payload available on failure.
    payload: dict[str, Any] | None = None
    # Boolean/detail checks for UI/tests, e.g. signatureValid, statusActive, typeMatches.
    checks: dict[str, Any] = field(default_factory=dict)
    # Nested verification results for VP embedded credentials.
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
            return PreparedVcToken(
                token=token,
                header={},
                jwt_payload={},
                payload={},
                issuer=None,
                status_url=None,
                errors=[str(exc)],
            )

        header = dict(decoded.header)
        jwt_payload = decoded.payload
        errors: list[str] = []

        if header.get("alg") != EDDSA:
            errors.append(f"unsupported alg: {header.get('alg')}")
        if header.get("typ") != VC_JWT_TYP:
            errors.append(f"unsupported typ: {header.get('typ')}")

        kid = header.get("kid")
        if isinstance(kid, str):
            header["kid"] = canonicalize_did_url(kid)

        payload = jwt_payload.get("vc")
        if not isinstance(payload, dict):
            errors.append("missing vc claim")
            payload = {}
        else:
            errors.extend(self._validate_vc_jwt_claims(jwt_payload, payload))

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
            jwt_payload=jwt_payload,
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
            return PreparedVpToken(token=token, header={}, jwt_payload={}, payload={}, holder=None, vc_tokens=[], errors=[str(exc)])

        header = dict(decoded.header)
        jwt_payload = decoded.payload
        errors: list[str] = []

        if header.get("alg") != EDDSA:
            errors.append(f"unsupported alg: {header.get('alg')}")
        if header.get("typ") != VP_JWT_TYP:
            errors.append(f"unsupported typ: {header.get('typ')}")

        kid = header.get("kid")
        if isinstance(kid, str):
            header["kid"] = canonicalize_did_url(kid)

        payload = jwt_payload.get("vp")
        if not isinstance(payload, dict):
            errors.append("missing vp claim")
            payload = {}
        else:
            errors.extend(self._validate_vp_jwt_claims(jwt_payload, payload))

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
            jwt_payload=jwt_payload,
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
        proof_ok = self._verify_proof(prepared.payload, method, errors)
        status_ok = self._check_status_doc(status_doc, errors)

        return VerificationResult(
            ok=not errors,
            kind="vc+jwt",
            errors=errors,
            payload=prepared.payload,
            checks={
                "issuerResolved": bool(prepared.issuer and method is not None),
                "signatureValid": signature_ok,
                "dataIntegrityProofValid": proof_ok,
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

    def evaluate_isomer_pair(self, acdc: dict[str, Any], vc_result: VerificationResult) -> VerificationResult:
        """Compare a successful or unsuccessful VC result against its source ACDC."""
        errors = list(vc_result.errors)
        payload = vc_result.payload or {}

        if not payload:
            return VerificationResult(ok=False, kind="isomer", errors=errors, payload=payload)

        subject = payload.get("credentialSubject", {})
        isomer = payload.get("isomer", {})
        legal_entity_credential = subject.get("legalEntityCredential", {})
        legal_entity_edge = acdc.get("e", {}).get("le", {})
        expected_type = expected_credential_type(acdc)
        expected_subject_aid = subject_aid(acdc.get("a", {}))

        checks = {
            "sourceCredentialSaidMatches": isomer.get("sourceCredentialSaid") == acdc.get("d"),
            "sourceSchemaSaidMatches": isomer.get("sourceSchemaSaid") == acdc.get("s"),
            "sourceIssuerAidMatches": isomer.get("sourceIssuerAid") == acdc.get("i"),
            "sourceRegistryMatches": isomer.get("sourceRegistry") == acdc.get("ri"),
            "sourceLegalEntityCredentialSaidMatches": isomer.get("sourceLegalEntityCredentialSaid") == legal_entity_edge.get("n"),
            "sourceLegalEntityCredentialSchemaMatches": isomer.get("sourceLegalEntityCredentialSchema") == legal_entity_edge.get("s"),
            "subjectDidMatches": subject.get("id") == acdc.get("a", {}).get("DID"),
            "subjectAidMatches": subject.get("AID") == expected_subject_aid,
            "legalNameMatches": subject.get("legalName") == acdc.get("a", {}).get("LegalName"),
            "addressMatches": subject.get("address") == parse_address(acdc.get("a", {}).get("HeadquartersAddress", "")),
            "legalEntityCredentialSaidMatches": legal_entity_credential.get("id") == f"urn:said:{legal_entity_edge.get('n', '')}",
            "legalEntityCredentialSchemaMatches": legal_entity_credential.get("schema") == legal_entity_edge.get("s"),
            "typeMatches": expected_type in payload.get("type", []),
        }

        for name, ok in checks.items():
            if not ok:
                errors.append(f"isomer check failed: {name}")

        return VerificationResult(
            ok=not errors,
            kind="isomer",
            errors=errors,
            payload=payload,
            checks=checks,
        )

    @staticmethod
    def _validate_vc_jwt_claims(jwt_payload: dict[str, Any], vc: dict[str, Any]) -> list[str]:
        """Validate VCDM 1.1 registered JWT claims against the embedded VC."""
        errors: list[str] = []
        subject = vc.get("credentialSubject", {})
        expected_claims = {
            "iss": vc.get("issuer"),
            "sub": subject.get("id") if isinstance(subject, dict) else None,
            "jti": vc.get("id"),
        }
        for claim, expected in expected_claims.items():
            if jwt_payload.get(claim) != expected:
                errors.append(f"JWT claim {claim} does not match embedded VC")

        try:
            issuance_numeric_date = unix_timestamp(vc["issuanceDate"])
        except (KeyError, TypeError, ValueError):
            errors.append("embedded VC has invalid issuanceDate")
        else:
            if jwt_payload.get("nbf") != issuance_numeric_date:
                errors.append("JWT claim nbf does not match embedded VC issuanceDate")
        return errors

    @staticmethod
    def _validate_vp_jwt_claims(jwt_payload: dict[str, Any], vp: dict[str, Any]) -> list[str]:
        """Validate VCDM 1.1 registered JWT claims against the embedded VP."""
        errors: list[str] = []
        expected_claims = {
            "iss": vp.get("holder"),
            "jti": vp.get("id"),
        }
        for claim, expected in expected_claims.items():
            if jwt_payload.get(claim) != expected:
                errors.append(f"JWT claim {claim} does not match embedded VP")
        return errors

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
    def _verify_proof(payload: dict[str, Any], method: dict[str, Any] | None, errors: list[str]) -> bool:
        """Verify the embedded VC Data Integrity proof and append failures."""
        if method is None:
            errors.append("unable to resolve verification method for VC Data Integrity proof")
            return False
        try:
            proof_ok = verify_proof(payload, method)
        except JsonLdCanonicalizationError as exc:
            errors.append(str(exc))
            return False
        except ValueError as exc:
            errors.append(str(exc))
            return False
        if not proof_ok:
            errors.append("VC Data Integrity proof verification failed")
        return proof_ok

    @staticmethod
    def _check_status_doc(status_doc: dict[str, Any] | None, errors: list[str]) -> bool:
        """Interpret one fetched status document for a VC result."""
        if status_doc is None:
            return True

        status_ok = not bool(status_doc.get("revoked"))
        if not status_ok:
            credential = status_doc.get("credSaid", status_doc.get("credentialSaid"))
            errors.append(f"credential {credential} is revoked")
        return status_ok
