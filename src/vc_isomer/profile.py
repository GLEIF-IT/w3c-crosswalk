"""Project ACDC credentials into the repository's W3C isomer profile.

This module is the semantic core of the repository. It defines how live ACDC
credentials are transposed into W3C VC-shaped documents while preserving
source lineage, credential-chain semantics, and revocation/status references.

Read this module as the W3C mapping policy layer.
It does not fetch key state, read LMDB directly, or sign tokens.
It only defines what the projected W3C document means.
"""

from __future__ import annotations

from typing import Any

from .common import canonicalize_did_url, canonicalize_did_webs, require_mapping
from .constants import (
    ISOMER_PROFILE,
    ISOMER_VERSION,
    LE_SCHEMA,
    STATUS_TYPE,
    SUPPORTED_SCHEMA_TYPES,
    VC_CONTEXT,
    VRD_AUTH_SCHEMA,
    VRD_SCHEMA,
)
from .status import status_url


class IsomerProfileError(ValueError):
    """Raised when an ACDC credential cannot be projected into the isomer profile."""


def schema_type(acdc: dict[str, Any]) -> str:
    """Map a supported ACDC schema SAID to the emitted W3C credential type."""
    schema = acdc.get("s")
    if schema not in SUPPORTED_SCHEMA_TYPES:
        raise IsomerProfileError(f"unsupported schema SAID: {schema}")
    return SUPPORTED_SCHEMA_TYPES[schema]


def subject_aid(attributes: dict[str, Any]) -> str:
    """Return the subject AID field used by the current credential flavor."""
    return attributes.get("AID") or attributes.get("LE") or ""


def build_terms_of_use(rules: dict[str, Any]) -> list[dict[str, str]]:
    """Normalize ACDC rules into a simple W3C `termsOfUse` list."""
    return [
        {"type": "vLEIUsageDisclaimer", "text": rules.get("usageDisclaimer", {}).get("l", "")},
        {"type": "vLEIIssuanceDisclaimer", "text": rules.get("issuanceDisclaimer", {}).get("l", "")},
        {"type": "vLEIPrivacyDisclaimer", "text": rules.get("privacyDisclaimer", {}).get("l", "")},
    ]


def build_subject(acdc: dict[str, Any]) -> dict[str, Any]:
    """Build the W3C `credentialSubject` block from the source ACDC."""
    attributes = require_mapping("attributes", acdc.get("a", {}))
    edges = require_mapping("edges", acdc.get("e", {}))
    cred_type = schema_type(acdc)

    subject = {
        "id": attributes.get("DID", ""),
        "aid": subject_aid(attributes),
        "legalName": attributes.get("LegalName", ""),
        "headquartersAddress": attributes.get("HeadquartersAddress", ""),
        "legalEntityVleiCredential": {
            "said": edges.get("le", {}).get("n", ""),
            "schema": edges.get("le", {}).get("s", LE_SCHEMA),
        },
    }
    if cred_type == "VRDAuthorizationCredential":
        subject["authorizedQviAid"] = attributes.get("i", "")
    return subject


def build_isomer_metadata(acdc: dict[str, Any]) -> dict[str, Any]:
    """Build the isomer provenance block embedded in the W3C VC."""
    edges = require_mapping("edges", acdc.get("e", {}))
    return {
        "profile": ISOMER_PROFILE,
        "version": ISOMER_VERSION,
        "sourceCredentialSaid": acdc.get("d", ""),
        "sourceSchemaSaid": acdc.get("s", ""),
        "sourceIssuerAid": acdc.get("i", ""),
        "sourceRegistry": acdc.get("ri", ""),
        "sourceCredentialType": schema_type(acdc),
        "sourceEdges": edges,
    }


def build_status_reference(acdc: dict[str, Any], status_base_url: str) -> dict[str, str]:
    """Build the dereferenceable W3C credential status reference.

    The returned object is a projection hook into the local status-service seam,
    not an authoritative status engine of its own.
    """
    return {
        "id": status_url(status_base_url, acdc.get("d", "")),
        "type": STATUS_TYPE,
        "statusPurpose": "revocation",
    }


def transpose_acdc_to_w3c_vc(
    acdc: dict[str, Any],
    *,
    issuer_did: str,
    verification_method: str,
    status_base_url: str,
) -> dict[str, Any]:
    """Transpose a supported ACDC credential into the repository's W3C VC shape.

    Args:
        acdc: Expanded ACDC credential body.
        issuer_did: DID used as the W3C issuer identifier.
        verification_method: DID URL that points to the signing key.
        status_base_url: Base URL for the projected credential status service.
    """
    attributes = require_mapping("attributes", acdc.get("a", {}))
    rules = require_mapping("rules", acdc.get("r", {}))
    cred_type = schema_type(acdc)
    canonical_issuer_did = canonicalize_did_webs(issuer_did)
    canonical_verification_method = canonicalize_did_url(verification_method)

    return {
        "@context": [VC_CONTEXT],
        "type": ["VerifiableCredential", cred_type, "KERIIsomerCredential"],
        "id": f"urn:said:{acdc.get('d', '')}",
        "issuer": canonical_issuer_did,
        "validFrom": attributes.get("dt", ""),
        "credentialSubject": build_subject(acdc),
        "credentialSchema": {
            "id": f"urn:said:{acdc.get('s', '')}",
            "type": "JsonSchemaCredential",
        },
        "credentialStatus": build_status_reference(acdc, status_base_url),
        "termsOfUse": build_terms_of_use(rules),
        "isomer": build_isomer_metadata(acdc),
        "proof": {
            "type": "DataDerivedFromKERI",
            "verificationMethod": canonical_verification_method,
            "source": "live-hab-derived",
        },
    }


def expected_credential_type(acdc: dict[str, Any]) -> str:
    """Return the expected W3C type for pairwise ACDC/W3C verification."""
    schema = acdc.get("s")
    if schema == VRD_AUTH_SCHEMA:
        return "VRDAuthorizationCredential"
    if schema == VRD_SCHEMA:
        return "VRDCredential"
    raise IsomerProfileError(f"unsupported schema SAID: {schema}")
