"""Data Integrity proof helpers for KERI-backed Isomer credentials.

This module implements the small eddsa-rdfc-2022 surface Isomer needs: local
JSON-LD canonicalization, proof hash construction, KERI habitat signing, and
verification against resolved did:webs verification methods.
"""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
from importlib import resources
from typing import Any

from .common import canonicalize_did_url, load_json_file, utc_timestamp
from .constants import DATA_INTEGRITY_CONTEXT, ISOMER_CONTEXT, VC_CONTEXT
from .signing import SignerLike

try:
    from keri.core import coring
except ImportError as exc:  # pragma: no cover - exercised only in misconfigured envs
    raise RuntimeError("isomer requires the 'keri' package in the active Python environment") from exc

try:
    from pyld import jsonld
except ImportError as exc:  # pragma: no cover - exercised only in misconfigured envs
    raise RuntimeError("isomer requires PyLD for JSON-LD Data Integrity proofs") from exc


EDDSA_RDFC_2022 = "eddsa-rdfc-2022"
DATA_INTEGRITY_PROOF = "DataIntegrityProof"
ASSERTION_METHOD = "assertionMethod"
ED25519_MULTIKEY_PREFIX = b"\xed\x01"
BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class JsonLdCanonicalizationError(ValueError):
    """Raised when strict local JSON-LD normalization cannot complete."""

    def __init__(self, label: str, detail: str):
        self.label = label
        self.detail = detail
        super().__init__(f"JSON-LD canonicalization failed for {label}: {detail}")


def document_loader(url: str, _options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Load only the local contexts this profile signs over."""
    context_paths = {
        VC_CONTEXT: "vc-v1.jsonld",
        DATA_INTEGRITY_CONTEXT: "security-data-integrity-v2.jsonld",
        ISOMER_CONTEXT: "isomer-v1.jsonld",
    }
    filename = context_paths.get(url)
    if filename is None:
        raise ValueError(f"no local JSON-LD context registered for {url}")

    path = resources.files("vc_isomer.resources.contexts").joinpath(filename)
    return {
        "contentType": "application/ld+json",
        "contextUrl": None,
        "documentUrl": url,
        "document": load_json_file(path),
    }


def canonicalize_jsonld(data: dict[str, Any]) -> str:
    """Return URDNA2015-normalized N-Quads for a JSON-LD document."""
    try:
        return jsonld.normalize(
            data,
            {
                "algorithm": "URDNA2015",
                "format": "application/n-quads",
                "documentLoader": document_loader,
            },
        )
    except Exception as exc:
        raise JsonLdCanonicalizationError("document", str(exc)) from exc


def create_proof_configuration(
    *,
    verification_method: str,
    created: str | None = None,
    proof_purpose: str = ASSERTION_METHOD,
) -> dict[str, str]:
    """Build the eddsa-rdfc-2022 proof options object."""
    return {
        "type": DATA_INTEGRITY_PROOF,
        "cryptosuite": EDDSA_RDFC_2022,
        "created": created or utc_timestamp(),
        "verificationMethod": canonicalize_did_url(verification_method),
        "proofPurpose": proof_purpose,
    }


def create_verify_data(document: dict[str, Any], proof_config: dict[str, Any]) -> bytes:
    """Return the 64-byte eddsa-rdfc-2022 hash data for signing or verifying."""
    if (   proof_config.get("type")        != DATA_INTEGRITY_PROOF
        or proof_config.get("cryptosuite") != EDDSA_RDFC_2022):
        raise ValueError("proof configuration must be DataIntegrityProof with eddsa-rdfc-2022")

    unsecured_document = deepcopy(document)
    unsecured_document.pop("proof", None)

    normalized_proof_config = deepcopy(proof_config)
    normalized_proof_config.pop("proofValue", None)
    # the below @context is required for PyLD to turn object fields into RDF terms for proper canonicalization
    # two completely different proof configs without @context would normalize to ''.
    # So without this line, changes to created, verificationMethod, proofPurpose, or cryptosuite
    # would not affect the proof-options hash at all, which would be both a
    # 1. unsecured document - a serious security vulnerability
    # 2. invitation to logic errors and drift
    # So @context here is required for secure, deterministic, schema-supported canonicalization
    normalized_proof_config["@context"] = unsecured_document.get("@context", [])

    try:
        transformed_document = canonicalize_jsonld(unsecured_document).encode("utf-8")
    except JsonLdCanonicalizationError as exc:
        raise JsonLdCanonicalizationError("unsecured document", exc.detail) from exc

    try:
        canonical_proof_config = canonicalize_jsonld(normalized_proof_config).encode("utf-8")
    except JsonLdCanonicalizationError as exc:
        raise JsonLdCanonicalizationError("proof configuration", exc.detail) from exc

    proof_config_hash = hashlib.sha256(canonical_proof_config).digest()
    transformed_document_hash = hashlib.sha256(transformed_document).digest()
    return proof_config_hash + transformed_document_hash


def generate_proof(
    document: dict[str, Any],
    *,
    signer: SignerLike,
    verification_method: str,
    created: str | None = None,
) -> dict[str, str]:
    """Create a KERI-backed Data Integrity proof for one unsecured VC document."""
    proof = create_proof_configuration(verification_method=verification_method, created=created)
    proof_value = encode_multibase_base58btc(signer.sign(create_verify_data(document, proof)))
    return {**proof, "proofValue": proof_value}


def add_data_integrity_proof(
    document: dict[str, Any],
    *,
    signer: SignerLike,
    verification_method: str,
    created: str | None = None,
) -> dict[str, Any]:
    """Return a copy of the document with a fresh Data Integrity proof attached."""
    secured_document = deepcopy(document)
    secured_document["proof"] = generate_proof(
        secured_document,
        signer=signer,
        verification_method=verification_method,
        created=created,
    )
    return secured_document


def verify_proof(document: dict[str, Any], method: dict[str, Any]) -> bool:
    """Verify one embedded eddsa-rdfc-2022 Data Integrity proof."""
    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("credential has no Data Integrity proof")
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value:
        raise ValueError("Data Integrity proof has no proofValue")

    method_id = method.get("id")
    proof_method = proof.get("verificationMethod")
    if isinstance(method_id, str) and isinstance(proof_method, str):
        fragment = proof_method.split("#", 1)[1] if "#" in proof_method else proof_method
        if method_id not in {proof_method, f"#{fragment}"} and not method_id.endswith(f"#{fragment}"):
            raise ValueError("resolved verification method does not match proof verificationMethod")

    signature = decode_multibase_base58btc(proof_value)
    verify_data = create_verify_data(document, proof)
    return bool(_verfer_from_method(method).verify(signature, verify_data))


def public_key_multibase_from_jwk(jwk: dict[str, str]) -> str:
    """Convert an Ed25519 OKP JWK to Multikey publicKeyMultibase form."""
    return encode_multibase_base58btc(ED25519_MULTIKEY_PREFIX + _b64url_decode(jwk["x"]))


def encode_multibase_base58btc(data: bytes) -> str:
    """Encode raw bytes as a multibase base58btc string.

    The returned value starts with ``z``, the multibase selector meaning "the
    remaining characters are base58btc". That prefix is transport metadata, not
    part of the base58 payload itself.

    Base58 integer conversion would normally discard leading ``0x00`` bytes, so
    base58btc preserves them by writing one leading ``1`` character for each
    leading zero byte in the original input.
    """
    if not data:
        return "z"

    value = int.from_bytes(data, byteorder="big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded

    # Each leading zero byte becomes a leading "1" in the base58btc payload so
    # the decode path can restore the exact original byte string.
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return "z" + ("1" * leading_zeroes) + encoded


def decode_multibase_base58btc(value: str) -> bytes:
    """Decode a multibase base58btc string into raw bytes.

    The leading ``z`` is the multibase selector; it says "the rest of this
    string is base58btc", but it is not itself part of the base58 payload.

    Within the base58btc payload, leading zero bytes from the original binary
    value are preserved by writing one leading ``1`` character for each
    ``0x00`` byte. After reconstructing the integer value from the remaining
    characters, we prepend those zero bytes back onto the decoded byte string.
    """
    if not value.startswith("z"):
        raise ValueError("expected multibase base58btc value with z prefix")

    # Drop the multibase prefix before interpreting the remainder as base58btc.
    encoded = value[1:]
    number = 0
    for character in encoded:
        try:
            digit = BASE58BTC_ALPHABET.index(character)
        except ValueError as exc:
            raise ValueError(f"invalid base58btc character {character!r}") from exc
        number = number * 58 + digit

    raw = b"" if number == 0 else number.to_bytes((number.bit_length() + 7) // 8, byteorder="big")
    # In base58btc, each leading "1" stands for one leading zero byte that
    # would otherwise disappear during integer conversion.
    leading_zeroes = len(encoded) - len(encoded.lstrip("1"))
    return (b"\x00" * leading_zeroes) + raw


def _verfer_from_method(method: dict[str, Any]) -> coring.Verfer:
    """Build a KERI verifier from a resolved DID verification method."""
    public_jwk = method.get("publicKeyJwk")
    if isinstance(public_jwk, dict):
        return _verfer_from_public_jwk(public_jwk)

    public_key_multibase = method.get("publicKeyMultibase")
    if isinstance(public_key_multibase, str):
        raw = decode_multibase_base58btc(public_key_multibase)
        if not raw.startswith(ED25519_MULTIKEY_PREFIX):
            raise ValueError("only Ed25519 Multikey publicKeyMultibase values are supported")
        return coring.Verfer(raw=raw[len(ED25519_MULTIKEY_PREFIX) :], code=coring.MtrDex.Ed25519N)

    raise ValueError("resolved verification method did not expose publicKeyJwk or publicKeyMultibase")


def _verfer_from_public_jwk(jwk: dict[str, Any]) -> coring.Verfer:
    """Convert an Ed25519 OKP JWK into the KERI verifier type."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("only Ed25519 OKP JWKs are supported")
    return coring.Verfer(raw=_b64url_decode(jwk["x"]), code=coring.MtrDex.Ed25519N)


def _b64url_decode(data: str) -> bytes:
    """Decode an unpadded base64url value."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
