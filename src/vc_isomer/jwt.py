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
from typing import Any

from .constants import EDDSA, VC_JWT_TYP, VP_JWT_TYP
from .common import canonicalize_did_url, canonicalize_did_webs
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


def verfer_from_public_jwk(jwk: dict[str, Any]) -> coring.Verfer:
    """Convert an Ed25519 OKP JWK into the KERI verifier type."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("only Ed25519 OKP JWKs are supported")
    raw = b64url_decode(jwk["x"])
    return coring.Verfer(raw=raw, code=coring.MtrDex.Ed25519N)


@dataclass(frozen=True)
class DecodedJwt:
    """Decoded JWT pieces used during verification and inspection."""

    # JOSE header decoded from the first compact-JWT segment; includes alg, typ, and kid.
    header: dict[str, Any]
    # JSON payload decoded from the second compact-JWT segment; for VC-JWT this is the W3C VC document.
    payload: dict[str, Any]
    # Raw signature bytes decoded from the third compact-JWT segment.
    signature: bytes
    # ASCII bytes of "base64url(header).base64url(payload)" used as the EdDSA signing input.
    signing_input: bytes

def encode_jwt(payload: dict[str, Any], *, typ: str, kid: str, signer: SignerLike) -> str:
    """Encode and sign a compact JWT with an EdDSA header."""
    header = {"alg": EDDSA, "kid": kid, "typ": typ}
    encoded_header = b64url_encode(canonical_json_bytes(header))
    encoded_payload = b64url_encode(canonical_json_bytes(payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    signature = signer.sign(signing_input)
    return f"{encoded_header}.{encoded_payload}.{b64url_encode(signature)}"


def decode_jwt(token: str) -> DecodedJwt:
    """Decode a compact JWT into structured header, payload, and signature parts."""
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
    """Verify a compact JWT with the supplied Ed25519 public JWK."""
    decoded = decode_jwt(token)
    verfer = verfer_from_public_jwk(public_jwk)
    return bool(verfer.verify(decoded.signature, decoded.signing_input))


def issue_vc_jwt(
    vc: dict[str, Any],
    *,
    signer: SignerLike,
    verification_method: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Issue an already-projected W3C VC document as a VC-JWT."""
    method = verification_method or vc.get("proof", {}).get("verificationMethod")
    if not isinstance(method, str) or not method:
        raise ValueError("VC-JWT issuance requires a verification method")
    kid = canonicalize_did_url(method)
    return encode_jwt(vc, typ=VC_JWT_TYP, kid=kid, signer=signer), vc


def issue_vp_jwt(
    vc_tokens: list[str],
    *,
    holder_did: str,
    signer: SignerLike,
    audience: str | None = None,
    nonce: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Wrap one or more VC-JWTs in a signed VP-JWT payload."""
    canonical_holder_did = canonicalize_did_webs(holder_did)
    payload: dict[str, Any] = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": canonical_holder_did,
        "verifiableCredential": vc_tokens,
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
    return token, payload
