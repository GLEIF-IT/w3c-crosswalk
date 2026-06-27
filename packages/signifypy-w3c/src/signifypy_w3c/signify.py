"""SignifyPy signer adapters for crosswalk W3C artifact creation."""

from __future__ import annotations

import base64
from typing import Any

BASE58_BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_MULTIKEY_PREFIX = bytes([0xED, 0x01])


class SignifyEdgeSigner:
    """SignerLike adapter over one local SignifyPy-managed identifier."""

    def __init__(self, client: Any, name: str, kid: str | None = None):
        """Resolve the local identifier and its current edge signer."""
        self.hab = client.identifiers().get(name)
        self.keeper = client.manager.get(aid=self.hab)
        signers = self.keeper.signers()
        if not signers:
            raise ValueError(f"identifier {name!r} did not expose an edge signer")
        self.signer = signers[0]
        self._kid = kid or self._identifier_key() or self.signer.verfer.qb64

    @property
    def kid(self) -> str:
        """Return the public-key qb64 used as the JWT `kid` fragment."""
        return self._kid

    @property
    def public_jwk(self) -> dict[str, str]:
        """Expose the current signing key as an Ed25519 OKP JWK."""
        return {
            "kid": self.kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_encode(self.signer.verfer.raw),
        }

    @property
    def public_key_multibase(self) -> str:
        """Expose the current signing key as an Ed25519 Multikey value."""
        return _public_key_multibase_from_jwk(self.public_jwk)

    def sign(self, message: bytes) -> bytes:
        """Sign raw bytes with the live edge key."""
        return self.signer.sign(message).raw

    def _identifier_key(self) -> str | None:
        state = self.hab.get("state") if isinstance(self.hab, dict) else None
        keys = state.get("k") if isinstance(state, dict) else None
        if isinstance(keys, list) and keys and isinstance(keys[0], str):
            return keys[0]
        return None


def signer_for_identifier(client: Any, name: str, kid: str | None = None) -> SignifyEdgeSigner:
    """Return a SignerLike adapter for one SignifyPy-managed identifier."""
    return SignifyEdgeSigner(client, name, kid=kid)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("utf-8"))


def _public_key_multibase_from_jwk(jwk: dict[str, str]) -> str:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("expected an Ed25519 OKP public JWK")
    return _encode_multibase_base58btc(ED25519_MULTIKEY_PREFIX + _b64url_decode(jwk["x"]))


def _encode_multibase_base58btc(data: bytes) -> str:
    value = int.from_bytes(data, "big")
    encoded = ""
    while value > 0:
        value, remainder = divmod(value, 58)
        encoded = BASE58_BTC_ALPHABET[remainder] + encoded
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return "z" + (BASE58_BTC_ALPHABET[0] * leading_zeroes) + (encoded or BASE58_BTC_ALPHABET[0])
