"""Signer adapters for binding JWT issuance to live KERI habitats.

This module is the KERI-facing signing seam for the package. JWT helpers only
depend on the small ``SignerLike`` protocol; habitat lifecycle and keystore
opening live in runtime components instead of signer adapters or JOSE helpers.
"""

from __future__ import annotations

from typing import Any, Protocol

class SignerLike(Protocol):
    """Minimal signer interface required by isomer issuance services."""

    @property
    def kid(self) -> str:
        """Return the signer-specific key identifier fragment."""
        ...

    @property
    def public_jwk(self) -> dict[str, str]:
        """Expose the current verification key as a JWK."""
        ...

    @property
    def public_key_multibase(self) -> str:
        """Expose the current verification key as a Multikey value."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Sign the supplied JWT signing input bytes."""
        ...


class HabSigner:
    """Adapter for a live KERI habitat signing key.

    The object intentionally stays narrow: it exposes the minimum surface the
    service layer needs over an already-opened habitat. It does not own or close
    Habery resources; that lifecycle belongs to an isomer runtime.
    """

    def __init__(self, hab: Any):
        """Wrap an already-opened habitat."""
        self._hab = hab

    @property
    def kid(self) -> str:
        """Return the qb64 public key identifier used in JWT `kid` fragments."""
        return self._hab.kever.verfers[0].qb64

    @property
    def public_jwk(self) -> dict[str, str]:
        """Expose the habitat's current signing key as an Ed25519 OKP JWK.

        For OKP JWKs such as Ed25519, ``x`` is the base64url-encoded public-key
        octet string. It is not an affine x-coordinate the way maintainers might
        expect from EC JWKs.
        """
        return {
            "kid": self.kid,
            "kty": "OKP",
            "crv": "Ed25519",
            # For OKP/Ed25519 JWKs, "x" carries the raw public-key octets after
            # base64url encoding, not an elliptic-curve x-coordinate.
            "x": _b64url_encode(self._hab.kever.verfers[0].raw),
        }

    @property
    def public_key_multibase(self) -> str:
        """Expose the habitat's current signing key as an Ed25519 Multikey."""
        from .data_integrity import public_key_multibase_from_jwk

        return public_key_multibase_from_jwk(self.public_jwk)

    def sign(self, message: bytes) -> bytes:
        """Sign raw bytes with the habitat's current Ed25519 key."""
        return self._hab.sign(message)[0].raw


def _b64url_encode(data: bytes) -> str:
    """Encode bytes using unpadded base64url."""
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")
