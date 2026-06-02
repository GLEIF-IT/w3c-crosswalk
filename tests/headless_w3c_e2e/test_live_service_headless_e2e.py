"""Explicit live-service E2E for the headless holder W3C presentation path."""

from __future__ import annotations

import pytest

from headless_w3c_e2e import HeadlessLiveRunConfig, run_live_headless, write_manifest


def test_live_service_headless_e2e(pytestconfig, tmp_path):
    """Run the browserless QVI-holder-verifier flow against live services."""
    stack = pytestconfig.getoption("--w3c-stack")
    if stack is None:
        pytest.skip("explicit live acceptance only; pass --w3c-stack=attach|process|docker")

    manifest_out = pytestconfig.getoption("--manifest-out") or str(
        tmp_path / "headless-w3c-live-manifest.json"
    )
    config = HeadlessLiveRunConfig.from_sources(
        stack=stack,
        manifest_path=pytestconfig.getoption("--manifest"),
        overrides={
            "admin_url": pytestconfig.getoption("--keria-admin-url"),
            "boot_url": pytestconfig.getoption("--keria-boot-url"),
            "qviAlias": pytestconfig.getoption("--qvi-alias"),
            "qviPasscode": pytestconfig.getoption("--qvi-passcode"),
            "holderAlias": pytestconfig.getoption("--holder-alias"),
            "holderPasscode": pytestconfig.getoption("--holder-passcode"),
            "sourceCredentialSaid": pytestconfig.getoption("--source-credential-said"),
            "manifestOut": manifest_out,
            "bootIfNeeded": pytestconfig.getoption("--boot-if-needed"),
            "unsafeRawTokens": pytestconfig.getoption("--unsafe-raw-tokens"),
            "verifierUrls": {
                "python": pytestconfig.getoption("--python-verifier-url"),
                "node": pytestconfig.getoption("--node-verifier-url"),
                "go": pytestconfig.getoption("--go-verifier-url"),
            },
            "verifierSubmissionUrls": {
                "python": pytestconfig.getoption("--python-verifier-submission-url"),
                "node": pytestconfig.getoption("--node-verifier-submission-url"),
                "go": pytestconfig.getoption("--go-verifier-submission-url"),
            },
        },
    )

    body = run_live_headless(config)
    write_manifest(manifest_out, body)

    scenario = body["scenario"]
    assert scenario["failures"] == []
    assert scenario["verifierEvidence"]["accepted"] is True
    assert len(scenario["presentationTxs"]) == 3
