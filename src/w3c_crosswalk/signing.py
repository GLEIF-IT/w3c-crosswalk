"""Signer adapters for binding JWT issuance to live KERI habitats.

This module is the KERI-facing signing seam for the package. JWT helpers only
depend on the small ``SignerLike`` protocol; habitat lifecycle and keystore
opening live here instead of inside the JOSE utility module.
"""

from __future__ import annotations

from typing import Any, Protocol

from keri.app import habbing


class SignerLike(Protocol):
    """Minimal signer interface required by crosswalk issuance services."""

    @property
    def kid(self) -> str:
        """Return the signer-specific key identifier fragment."""
        ...

    @property
    def public_jwk(self) -> dict[str, str]:
        """Expose the current verification key as a JWK."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Sign the supplied JWT signing input bytes."""
        ...


class KeriHabSigner:
    """Adapter for a live KERI habitat signing key.

    The object intentionally stays narrow: it exposes the minimum surface the
    service layer needs while preserving deterministic cleanup of the owned
    habery when the signer opened it.
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
            "x": _b64url_encode(self._hab.kever.verfers[0].raw),
        }

    def sign(self, message: bytes) -> bytes:
        """Sign raw bytes with the habitat's current Ed25519 key."""
        return self._hab.sign(message)[0].raw

    def close(self) -> None:
        """Close the owned habery when this signer opened it."""
        if self._hby is not None:
            self._hby.close()


def _b64url_encode(data: bytes) -> str:
    """Encode bytes using unpadded base64url."""
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")
