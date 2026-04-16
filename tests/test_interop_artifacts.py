"""Contract tests for developer-facing W3C/OpenID interop artifacts."""

from __future__ import annotations

from pathlib import Path

from vc_isomer.common import load_json_file


ROOT = Path(__file__).resolve().parents[1]


def test_openid4vci_configuration_advertises_vcdm_1_1_json_ld_jwt():
    """Keep OpenID4VCI metadata aligned with the Isomer VC profile."""
    config = load_json_file(ROOT / "interop" / "openid4vci-credential-configuration.json")
    supported = config["credential_configurations_supported"]

    assert supported["IsomerVRDCredential"]["format"] == "jwt_vc_json-ld"
    assert supported["IsomerVRDCredential"]["credential_signing_alg_values_supported"] == ["EdDSA"]
    definition = supported["IsomerVRDCredential"]["credential_definition"]
    assert definition["@context"][0] == "https://www.w3.org/2018/credentials/v1"
    assert "KERIIsomerCredential" in definition["type"]


def test_openid4vp_presentation_definition_requests_isomer_schema():
    """Keep OpenID4VP presentation matching focused on the Isomer schema."""
    definition = load_json_file(ROOT / "interop" / "openid4vp-presentation-definition.json")
    descriptor = definition["input_descriptors"][0]

    assert descriptor["format"]["jwt_vc_json-ld"]["alg"] == ["EdDSA"]
    schema_filter = descriptor["constraints"]["fields"][1]["filter"]
    assert schema_filter["const"] == "https://www.gleif.org/schemas/isomer/v1/vrd-credential.json"
