"""JWT issuance and verification helpers for VC-JWT and VP-JWT flows.

This module keeps the JOSE mechanics intentionally small and explicit so the
repository can bind W3C JWT artifacts to live KERI Ed25519 signing keys
without pulling in a heavier JWT abstraction.

This module is the cryptographic binding seam between the
projected W3C payload and a live KERI habitat signer.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Protocol

from keri.app import habbing

from .constants import EDDSA, VC_JWT_TYP, VP_JWT_TYP
from .profile import transpose_acdc_to_w3c_vc

try:
    from keri.core import coring, signing
except ImportError as exc:  # pragma: no cover - exercised only in misconfigured envs
    raise RuntimeError("w3c-crosswalk requires the 'keri' package in the active Python environment") from exc


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


class SignerLike(Protocol):
    """Minimal signer interface required by the JWT helpers."""

    @property
    def kid(self) -> str:
        """Return the signer-specific key identifier fragment."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Sign the supplied JWT signing input bytes."""
        ...


@dataclass(frozen=True)
class DecodedJwt:
    """Decoded JWT pieces used during verification and inspection."""

    header: dict[str, Any]
    payload: dict[str, Any]
    signature: bytes
    signing_input: bytes


class KeriHabSigner:
    """Adapter for a live KERI habitat signer.

    This object is intentionally small: it exposes the minimum JWT-signing
    interface while preserving the ability to close the owned habery when the
    signer opened it.
    """

    def __init__(self, hab: Any, hby: habbing.Habery | None = None):
        """Wrap a habitat and optional habery owner for later cleanup."""
        self._hab = hab
        self._hby = hby

    @classmethod
    def open(cls, *, name: str, base: str, alias: str, passcode: str | None) -> "KeriHabSigner":
        """Open a live habitat signer from a KERIpy keystore."""
        hby = habbing.Habery(name=name, base=base, bran=passcode)
        hab = hby.habByName(alias)
        if hab is None:
            hby.close()
            raise ValueError(f"unable to locate habitat alias '{alias}' in habery '{name}'")
        return cls(hab=hab, hby=hby)

    @property
    def kid(self) -> str:
        """Return the qb64 public key identifier used in JWT `kid` fragments."""
        return self._hab.kever.verfers[0].qb64

    @property
    def public_jwk(self) -> dict[str, str]:
        """Expose the habitat's current signing key as an Ed25519 OKP JWK."""
        return {
            "kid": self.kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url_encode(self._hab.kever.verfers[0].raw),
        }

    def sign(self, message: bytes) -> bytes:
        """Sign raw bytes with the habitat's current Ed25519 key."""
        return self._hab.sign(message)[0].raw

    def close(self) -> None:
        """Close the owned habery when this signer opened it."""
        if self._hby is not None:
            self._hby.close()


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
    acdc: dict[str, Any],
    *,
    issuer_did: str,
    status_base_url: str,
    signer: SignerLike,
) -> tuple[str, dict[str, Any]]:
    """Project an ACDC into W3C VC form and issue it as a VC-JWT."""
    verification_method = f"{issuer_did}#{signer.kid}"
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did=issuer_did,
        verification_method=verification_method,
        status_base_url=status_base_url,
    )
    return encode_jwt(vc, typ=VC_JWT_TYP, kid=verification_method, signer=signer), vc


def issue_vp_jwt(
    vc_tokens: list[str],
    *,
    holder_did: str,
    signer: SignerLike,
    audience: str | None = None,
    nonce: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Wrap one or more VC-JWTs in a signed VP-JWT payload."""
    payload: dict[str, Any] = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": vc_tokens,
    }
    if audience:
        payload["aud"] = audience
    if nonce:
        payload["nonce"] = nonce
    token = encode_jwt(payload, typ=VP_JWT_TYP, kid=f"{holder_did}#{signer.kid}", signer=signer)
    return token, payload
