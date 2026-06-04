"""Runtime config tests for live headless W3C E2E inputs."""

from __future__ import annotations

import base64
import json

from headless_w3c_e2e import HeadlessLiveRunConfig
from headless_w3c_e2e.runtime import _expected_dashboard_presentations, _match_dashboard_presentations, _strip_raw_tokens


def test_config_reads_signifypy_seed_manifest(tmp_path):
    """Use the existing VRD chain seeder manifest as live-run input."""
    manifest = {
        "actors": {
            "qvi": {"name": "w3c-vrd-qvi-abcd", "passcode": "qvi-passcode-000000"},
            "le": {"name": "w3c-vrd-le-abcd", "passcode": "le-passcode-0000000"},
        },
        "credentials": {"vrd": "EVrdCredential"},
        "sourceCredentialSaid": "EVrdCredential",
        "holderPresentation": {
            "issuerName": "w3c-vrd-qvi-abcd",
            "holderName": "w3c-vrd-le-abcd",
            "sourceCredentialSaid": "EVrdCredential",
        },
        "verifierUrls": {
            "python": "http://127.0.0.1:8788/",
            "node": "http://127.0.0.1:8789",
            "go": "http://127.0.0.1:8790",
        },
    }
    path = tmp_path / "seed-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    config = HeadlessLiveRunConfig.from_sources(
        stack="attach",
        manifest_path=str(path),
        environ={},
        overrides={},
    )

    assert config.qvi.name == "w3c-vrd-qvi-abcd"
    assert config.qvi.passcode == "qvi-passcode-000000"
    assert config.holder.name == "w3c-vrd-le-abcd"
    assert config.holder.passcode == "le-passcode-0000000"
    assert config.source_credential_said == "EVrdCredential"
    assert config.verifier_urls == {
        "python": "http://127.0.0.1:8788",
        "node": "http://127.0.0.1:8789",
        "go": "http://127.0.0.1:8790",
    }


def test_config_ignores_empty_overrides_so_manifest_values_survive(tmp_path):
    """Pytest and CLI optional flags must not mask manifest-provided values."""
    manifest = {
        "qviWallet": {"name": "qvi", "passcode": "qvi-passcode-000000"},
        "holderWallet": {"name": "holder", "passcode": "holder-passcode-00"},
        "sourceCredentialSaid": "EVrd",
        "verifierUrls": {
            "python": "http://127.0.0.1:8788",
            "node": "http://127.0.0.1:8789",
            "go": "http://127.0.0.1:8790",
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    config = HeadlessLiveRunConfig.from_sources(
        stack="attach",
        manifest_path=str(path),
        environ={},
        overrides={
            "qviAlias": None,
            "holderAlias": None,
            "verifierUrls": {"python": None, "node": None, "go": None},
        },
    )

    assert config.qvi.name == "qvi"
    assert config.holder.name == "holder"
    assert config.verifier_urls["python"] == "http://127.0.0.1:8788"


def test_config_separates_host_verifier_urls_from_keria_submission_urls(tmp_path):
    """Docker-backed runs need host polling URLs and container submission URLs."""
    manifest = {
        "qviWallet": {"name": "qvi", "passcode": "qvi-passcode-000000"},
        "holderWallet": {"name": "holder", "passcode": "holder-passcode-00"},
        "sourceCredentialSaid": "EVrd",
        "verifierUrls": {
            "python": "http://127.0.0.1:8788",
            "node": "http://127.0.0.1:8789",
            "go": "http://127.0.0.1:8790",
        },
        "verifierSubmissionUrls": {
            "python": "http://isomer-python:8788",
            "node": "http://isomer-node:8788",
            "go": "http://isomer-go:8788",
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    config = HeadlessLiveRunConfig.from_sources(
        stack="attach",
        manifest_path=str(path),
        environ={},
        overrides={},
    )

    assert config.verifier_urls["python"] == "http://127.0.0.1:8788"
    assert config.verifier_submission_urls == {
        "python": "http://isomer-python:8788",
        "node": "http://isomer-node:8788",
        "go": "http://isomer-go:8788",
    }


def test_config_reads_dashboard_url_from_manifest(tmp_path):
    """Dashboard evidence is optional but must be configurable for live runs."""
    manifest = {
        "qviWallet": {"name": "qvi", "passcode": "qvi-passcode-000000"},
        "holderWallet": {"name": "holder", "passcode": "holder-passcode-00"},
        "sourceCredentialSaid": "EVrd",
        "dashboardUrl": "http://127.0.0.1:8791",
        "verifierUrls": {
            "python": "http://127.0.0.1:8788",
            "node": "http://127.0.0.1:8789",
            "go": "http://127.0.0.1:8790",
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    config = HeadlessLiveRunConfig.from_sources(
        stack="attach",
        manifest_path=str(path),
        environ={},
        overrides={},
    )

    assert config.dashboard_url == "http://127.0.0.1:8791"


def test_dashboard_evidence_matches_presentations_by_verifier_and_tx_id():
    """Dashboard events must correspond to the current KERIA presentation txs."""
    events = [
        {
            "eventId": "event-python",
            "verifiedAt": "2026-06-02T00:00:00Z",
            "verifier": {"id": "isomer-python"},
            "presentation": {"id": "urn:said:EPython", "credentialTypes": ["VRDCredential"]},
            "verification": {"ok": True},
        },
        {
            "eventId": "event-node",
            "verifiedAt": "2026-06-02T00:00:01Z",
            "verifier": {"id": "isomer-node"},
            "presentation": {"id": "urn:said:ENode", "credentialTypes": ["VRDCredential"]},
            "verification": {"ok": True},
        },
    ]
    expected = [
        {"verifier": "python", "presentTxId": "EPython"},
        {"verifier": "node", "presentTxId": "ENode"},
    ]

    assert _match_dashboard_presentations(events, expected) == [
        {
            "verifier": "python",
            "presentTxId": "EPython",
            "eventId": "event-python",
            "verifiedAt": "2026-06-02T00:00:00Z",
            "verificationOk": True,
            "credentialTypes": ["VRDCredential"],
        },
        {
            "verifier": "node",
            "presentTxId": "ENode",
            "eventId": "event-node",
            "verifiedAt": "2026-06-02T00:00:01Z",
            "verificationOk": True,
            "credentialTypes": ["VRDCredential"],
        },
    ]


def test_dashboard_expected_presentations_use_vp_jwt_id_before_keria_transaction_id():
    """Dashboard events are keyed by the VP JWT id, not the KERIA transaction id."""
    scenario = {
        "presentationTxs": [
            {
                "vpJwt": _compact_jwt({"jti": "urn:uuid:vp-id", "vp": {"id": "urn:uuid:vp-id"}}),
                "presentationId": "EPresentation",
                "requestDescriptor": {"verifierId": "python"},
            }
        ]
    }

    assert _expected_dashboard_presentations(scenario) == [
        {"verifier": "python", "presentTxId": "urn:uuid:vp-id"}
    ]


def test_dashboard_expected_presentations_fall_back_to_keria_presentation_id():
    """KERIA presentationId remains a fallback when the raw VP JWT is unavailable."""
    scenario = {
        "presentationTxs": [
            {
                "presentationId": "EPresentation",
                "requestDescriptor": {"verifierId": "python"},
            }
        ]
    }

    assert _expected_dashboard_presentations(scenario) == [
        {"verifier": "python", "presentTxId": "EPresentation"}
    ]


def _compact_jwt(payload: dict) -> str:
    def encode(data: dict | bytes) -> str:
        raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8") if isinstance(data, dict) else data
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")

    return f"{encode({'alg': 'EdDSA', 'typ': 'vp+jwt'})}.{encode(payload)}.{encode(b'sig')}"


def test_strip_raw_tokens_redacts_nested_compact_jwt_strings():
    """Default manifests should not leak compact JWTs from nested VP payloads."""
    compact = (
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJkaWQ6d2ViczpleeGFtcGxlOmR3czpFSVNTVUVSIiwianRpIjoidXJuOnNhaWQ6RUFiYyJ9."
        "z2RsXHJxs7h6t74tum3wkHnfkNwqSwnctC2hDxkUVhxaNngTcmdjNKL6yqSJdfArVD54FW5vHkSxGmud"
    )

    assert _strip_raw_tokens({"payload": {"verifiableCredential": [compact]}}) == {
        "payload": {"verifiableCredential": ["[redacted-jwt]"]}
    }
