"""JWT issuance and verification helpers for VC-JWT and VP-JWT flows.

This module keeps the JOSE mechanics intentionally small and explicit so the
repository can bind W3C JWT artifacts to live KERI Ed25519 signing keys
without pulling in a heavier JWT abstraction.

This module is the cryptographic binding seam between the projected W3C payload
and a signer adapter. Habitat lifecycle and keystore opening live in
``signing.py``.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .common import canonicalize_did_url, canonicalize_did_webs, utc_timestamp
from .constants import EDDSA, VC_CONTEXT, VC_JWT_TYP, VP_JWT_TYP
from .data_integrity import add_data_integrity_proof
from .signing import SignerLike

try:
    from keri.core import coring
except ImportError as exc:  # pragma: no cover - exercised only in misconfigured envs
    raise RuntimeError("isomer requires the 'keri' package in the active Python environment") from exc


def b64url_encode(data: bytes) -> str:
    """Encode bytes using unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(data: str) -> bytes:
    """Decode a base64url string with optional missing padding."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Serialize JSON deterministically for signing and verification."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def unix_timestamp(value: str) -> int:
    """Convert an RFC3339 UTC timestamp to a JWT NumericDate."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def timestamp_now() -> int:
    """Return the current JWT NumericDate."""
    return unix_timestamp(utc_timestamp())


def verfer_from_public_jwk(jwk: dict[str, Any]) -> coring.Verfer:
    """Convert an Ed25519 OKP JWK into the KERI verifier type.

    For OKP JWKs, ``x`` is the base64url-encoded public-key octet string, not
    an affine x-coordinate. Decoding it yields the raw Ed25519 bytes KERI uses
    as ``Verfer.raw``; CESR qualification happens in the verifier code/qb64
    layer, not inside the JWK field.
    """
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("only Ed25519 OKP JWKs are supported")
    # Decoding OKP "x" gives the raw public-key bytes expected by Verfer.
    raw = b64url_decode(jwk["x"])
    return coring.Verfer(raw=raw, code=coring.MtrDex.Ed25519N)


@dataclass(frozen=True)
class DecodedJwt:
    """Decoded JWT pieces used during verification and inspection."""

    # JOSE header decoded from the first compact-JWT segment; includes alg, typ, and kid.
    header: dict[str, Any]
    # Raw JWT claims decoded from the second compact-JWT segment; VC-JWT and
    # VP-JWT payloads usually carry the embedded W3C object under `vc` or `vp`.
    payload: dict[str, Any]
    # Raw signature bytes decoded from the third compact-JWT segment.
    signature: bytes
    # ASCII bytes of "base64url(header).base64url(payload)" used as the EdDSA signing input.
    signing_input: bytes

def encode_jwt(payload: dict[str, Any], *, typ: str, kid: str, signer: SignerLike) -> str:
    """Encode a claims object as a compact signed JWT.

    Args:
        payload: Decoded JWT claims to serialize into the second compact-JWT
            segment.
        typ: JOSE `typ` header value such as `JWT`.
        kid: JOSE `kid` header value naming the signing verification method.
        signer: Live signer that produces the Ed25519 signature bytes.

    Returns:
        Compact signed JWT string of the form `header.payload.signature`.
    """
    header = {"alg": EDDSA, "kid": kid, "typ": typ}
    encoded_header = b64url_encode(canonical_json_bytes(header))
    encoded_payload = b64url_encode(canonical_json_bytes(payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    signature = signer.sign(signing_input)
    return f"{encoded_header}.{encoded_payload}.{b64url_encode(signature)}"


def decode_jwt(token: str) -> DecodedJwt:
    """Decode a compact JWT into structured JOSE and claim components.

    This helper stays generic: it returns the raw JWT claims object rather than
    interpreting VC-JWT or VP-JWT profile fields for the caller.
    """
    pieces = token.split(".")
    if len(pieces) != 3:
        raise ValueError("JWT must contain exactly three segments")
    header_b64, payload_b64, signature_b64 = pieces
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    return DecodedJwt(
        header=json.loads(b64url_decode(header_b64)),
        payload=json.loads(b64url_decode(payload_b64)),
        signature=b64url_decode(signature_b64),
        signing_input=signing_input,
    )


def verify_jwt_signature(token: str, public_jwk: dict[str, Any]) -> bool:
    """Verify the compact JWT envelope with the supplied Ed25519 public JWK.

    This checks only the JOSE signature over `header.payload`. Embedded W3C Data
    Integrity proofs inside VC payloads are verified elsewhere.
    """
    decoded = decode_jwt(token)
    verfer = verfer_from_public_jwk(public_jwk)
    return bool(verfer.verify(decoded.signature, decoded.signing_input))


def issue_vc_jwt(
    vc: dict[str, Any],
    *,
    signer: SignerLike,
    verification_method: str | None = None,
    proof_created: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Issue a projected W3C VC document as a VCDM 1.1 VC-JWT.

    Args:
        vc: Projected W3C VC JSON document, not a compact JWT. The document may
            already contain a Data Integrity `proof`; if not, this helper adds
            one before building the JWT claims.
        signer: Live signer used for both Data Integrity proof generation and
            compact JWT signing.
        verification_method: DID URL to use for the embedded proof and JOSE
            `kid`. When omitted, reuse `vc["proof"]["verificationMethod"]`.
        proof_created: Optional RFC3339 timestamp override for a proof created
            during this call.

    Returns:
        Tuple of `(compact_vc_jwt, secured_vc_document)`.

        The resulting JWT claims are shaped like:
        `{"iss": ..., "sub": ..., "jti": ..., "iat": ..., "nbf": ..., "vc": {...}}`

        The `vc` claim embeds the full secured VC JSON object.
    """
    method = verification_method or vc.get("proof", {}).get("verificationMethod")
    if not isinstance(method, str) or not method:
        raise ValueError("VC-JWT issuance requires a verification method")
    kid = canonicalize_did_url(method)
    secured_vc = vc if isinstance(vc.get("proof"), dict) else add_data_integrity_proof(
        vc,
        signer=signer,
        verification_method=kid,
        created=proof_created,
    )
    jwt_payload = build_vc_jwt_payload(secured_vc)
    return encode_jwt(jwt_payload, typ=VC_JWT_TYP, kid=kid, signer=signer), secured_vc


def build_vc_jwt_payload(vc: dict[str, Any]) -> dict[str, Any]:
    """Build the VCDM 1.1 JWT claim set that envelopes one VC document.

    Claim mapping:
        - `iss <- vc["issuer"]`
        - `sub <- vc["credentialSubject"]["id"]`
        - `jti <- vc["id"]`
        - `iat <- issuanceDate`
        - `nbf <- issuanceDate`
        - `vc <- full secured VC document`

    Example abbreviated shape:
        `{"iss": "...", "sub": "...", "jti": "urn:said:...", "iat": 1713225600,`
        ` "nbf": 1713225600, "vc": {...}}`
    """
    subject = vc.get("credentialSubject", {})
    issued_at = unix_timestamp(vc["issuanceDate"])
    return {
        "iss": vc["issuer"],
        "sub": subject.get("id"),
        "jti": vc["id"],
        "iat": issued_at,
        "nbf": issued_at,
        "vc": vc,
    }


def issue_vp_jwt(
    vc_tokens: list[str],
    *,
    holder_did: str,
    signer: SignerLike,
    audience: str | None = None,
    nonce: str | None = None,
    presentation_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Issue a VCDM 1.1 VP-JWT that wraps one or more compact VC-JWT strings.

    Args:
        vc_tokens: Compact VC-JWT strings to embed in
            `vp["verifiableCredential"]`. These are JWTs, not VC JSON objects.
        holder_did: DID of the presenter; becomes both `vp["holder"]` and the
            JWT `iss` claim after canonicalization.
        signer: Live signer for the compact VP-JWT envelope.
        audience: Optional JWT `aud` claim. This stays on the JWT envelope and
            is not copied into the embedded `vp` object.
        nonce: Optional JWT `nonce` claim used by challenge flows. This also
            stays on the JWT envelope, not in the embedded `vp` object.
        presentation_id: Optional identifier reused for both `vp["id"]` and
            JWT `jti`. When omitted, generate a fresh `urn:uuid:...` value.

    Returns:
        Tuple of `(compact_vp_jwt, vp_document)`.

        The resulting JWT claims are shaped like:
        `{"iss": ..., "jti": ..., "iat": ..., "aud"?: ..., "nonce"?: ..., "vp": {...}}`

        The embedded VP object is shaped like:
        `{"@context": [...], "id": ..., "type": ["VerifiablePresentation"],`
        ` "holder": ..., "verifiableCredential": ["<compact vc-jwt>", ...]}`
    """
    canonical_holder_did = canonicalize_did_webs(holder_did)
    # Keep the embedded VP `id` and the JWT `jti` aligned for the same artifact.
    vp_id = presentation_id or f"urn:uuid:{uuid4()}"
    vp: dict[str, Any] = {
        "@context": [VC_CONTEXT],
        "id": vp_id,
        "type": ["VerifiablePresentation"],
        "holder": canonical_holder_did,
        # VP-JWT embeds compact VC-JWT strings here, not decoded VC JSON objects.
        "verifiableCredential": vc_tokens,
    }
    payload: dict[str, Any] = {
        "iss": canonical_holder_did,
        "jti": vp_id,
        "iat": timestamp_now(),
        "vp": vp,
    }
    if audience:
        payload["aud"] = audience
    if nonce:
        payload["nonce"] = nonce
    token = encode_jwt(
        payload,
        typ=VP_JWT_TYP,
        kid=canonicalize_did_url(f"{canonical_holder_did}#{signer.kid}"),
        signer=signer,
    )
    return token, vp
