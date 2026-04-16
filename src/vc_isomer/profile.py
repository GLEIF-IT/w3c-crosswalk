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

from .common import canonicalize_did_webs, require_mapping
from .constants import (
    DATA_INTEGRITY_CONTEXT,
    ISOMER_CONTEXT,
    ISOMER_PROFILE,
    ISOMER_VRD_SCHEMA_ID,
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
    return attributes.get("AID") or ""


def said_urn(said: str) -> str:
    """Represent one KERI/ACDC SAID as an absolute JSON-LD identifier."""
    return f"urn:said:{said}" if said else ""


def build_terms_of_use(rules: dict[str, Any]) -> list[dict[str, str]]:
    """Normalize ACDC rules into a simple W3C `termsOfUse` list."""
    return [
        {"type": "vLEIUsageDisclaimer", "text": rules.get("usageDisclaimer", {}).get("l", "")},
        {"type": "vLEIIssuanceDisclaimer", "text": rules.get("issuanceDisclaimer", {}).get("l", "")},
        {"type": "vLEIPrivacyDisclaimer", "text": rules.get("privacyDisclaimer", {}).get("l", "")},
    ]


def parse_address(address_string: str) -> dict[str, str]:
    """Parse a vLEI comma-separated headquarters address into PostalAddress."""
    parts = [part.strip() for part in address_string.split(",")]
    address = {
        "type": "PostalAddress",
        "streetAddress": "",
        "addressLocality": "",
        "addressCountry": "",
    }
    if len(parts) >= 1:
        address["streetAddress"] = parts[0]
    if len(parts) >= 2 and parts[1]:
        address["streetAddress"] = f"{address['streetAddress']}, {parts[1]}" if address["streetAddress"] else parts[1]
    if len(parts) >= 3:
        address["addressLocality"] = parts[2]
    if len(parts) >= 4:
        region_postal = parts[3].split()
        if region_postal:
            address["addressRegion"] = region_postal[0]
        if len(region_postal) >= 2:
            address["postalCode"] = region_postal[1]
    if len(parts) >= 5:
        address["addressCountry"] = parts[4]
    return address


def build_subject(acdc: dict[str, Any]) -> dict[str, Any]:
    """Build the W3C `credentialSubject` block from the source ACDC."""
    attributes = require_mapping("attributes", acdc.get("a", {}))
    edges = require_mapping("edges", acdc.get("e", {}))
    cred_type = schema_type(acdc)
    legal_entity_edge = edges.get("le", {})

    subject = {
        "id": attributes.get("DID", ""),
        "AID": subject_aid(attributes),
        "legalName": attributes.get("LegalName", ""),
        "address": parse_address(attributes.get("HeadquartersAddress", "")),
        "legalEntityCredential": {
            "id": said_urn(legal_entity_edge.get("n", "")),
            "type": "LegalEntityvLEICredential",
            "schema": legal_entity_edge.get("s", LE_SCHEMA),
        },
    }
    if cred_type == "VRDAuthorizationCredential":
        subject["authorizedQviAid"] = attributes.get("i", "")
    return subject


def build_isomer_metadata(acdc: dict[str, Any]) -> dict[str, Any]:
    """Build the isomer provenance block embedded in the W3C VC."""
    attributes = require_mapping("attributes", acdc.get("a", {}))
    edges = require_mapping("edges", acdc.get("e", {}))
    legal_entity_edge = edges.get("le", {})
    metadata = {
        "profile": ISOMER_PROFILE,
        "version": ISOMER_VERSION,
        "sourceCredentialSaid": acdc.get("d", ""),
        "sourceSchemaSaid": acdc.get("s", ""),
        "sourceIssuerAid": acdc.get("i", ""),
        "sourceRegistry": acdc.get("ri", ""),
        "sourceCredentialType": schema_type(acdc),
        "sourceLegalEntityCredentialSaid": legal_entity_edge.get("n", ""),
        "sourceLegalEntityCredentialSchema": legal_entity_edge.get("s", LE_SCHEMA),
    }
    if schema_type(acdc) == "VRDAuthorizationCredential":
        metadata["sourceAuthorizedQviAid"] = attributes.get("i", "")
    return metadata


def build_status_reference(acdc: dict[str, Any], status_base_url: str) -> dict[str, str]:
    """Build the dereferenceable W3C credential status reference.

    The returned object is a projection hook into the local status-service seam,
    not an authoritative status engine of its own.
    """
    return {
        "id": status_url(status_base_url, acdc.get("d", "")),
        "type": STATUS_TYPE,
        "statusPurpose": "revocation",
        "statusRegistryId": acdc.get("ri", ""),
    }


def transpose_acdc_to_w3c_vc(
    acdc: dict[str, Any],
    *,
    issuer_did: str,
    status_base_url: str,
) -> dict[str, Any]:
    """Transpose a supported ACDC credential into the repository's W3C VC shape.

    Args:
        acdc: Expanded ACDC credential body.
        issuer_did: DID used as the W3C issuer identifier.
        status_base_url: Base URL for the projected credential status service.
    """
    attributes = require_mapping("attributes", acdc.get("a", {}))
    rules = require_mapping("rules", acdc.get("r", {}))
    cred_type = schema_type(acdc)
    canonical_issuer_did = canonicalize_did_webs(issuer_did)

    return {
        "@context": [VC_CONTEXT, DATA_INTEGRITY_CONTEXT, ISOMER_CONTEXT],
        "type": ["VerifiableCredential", cred_type, "KERIIsomerCredential"],
        "id": f"urn:said:{acdc.get('d', '')}",
        "issuer": canonical_issuer_did,
        "issuanceDate": attributes.get("dt", ""),
        "credentialSubject": build_subject(acdc),
        "credentialSchema": {
            "id": ISOMER_VRD_SCHEMA_ID,
            "type": "JsonSchemaValidator2018",
        },
        "credentialStatus": build_status_reference(acdc, status_base_url),
        "termsOfUse": build_terms_of_use(rules),
        "isomer": build_isomer_metadata(acdc),
    }


def expected_credential_type(acdc: dict[str, Any]) -> str:
    """Return the expected W3C type for pairwise ACDC/W3C verification."""
    schema = acdc.get("s")
    if schema == VRD_AUTH_SCHEMA:
        return "VRDAuthorizationCredential"
    if schema == VRD_SCHEMA:
        return "VRDCredential"
    raise IsomerProfileError(f"unsupported schema SAID: {schema}")
