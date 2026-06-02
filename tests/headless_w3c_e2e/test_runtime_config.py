"""Runtime config tests for live headless W3C E2E inputs."""

from __future__ import annotations

import json

from headless_w3c_e2e import HeadlessLiveRunConfig


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
