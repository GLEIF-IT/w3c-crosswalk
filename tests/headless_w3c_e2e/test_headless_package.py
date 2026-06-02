# -*- encoding: utf-8 -*-
"""Headless W3C E2E package boundary tests."""

import pytest

from headless_w3c_e2e import HeadlessW3CE2E, HeadlessW3CWallet, KeriaW3CApi, VerifierSuite


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, path, **kwargs):
        self.calls.append(("get", path, kwargs))
        return FakeResponse(self.responses.get(("get", path), {}))

    def post(self, path, **kwargs):
        self.calls.append(("post", path, kwargs))
        return FakeResponse(self.responses.get(("post", path), {}))


class FakeW3C:
    def __init__(self, name):
        self.name = name
        self.calls = []

    def start_issuance(self, name, source_credential_said):
        self.calls.append(("start_issuance", name, source_credential_said))
        return {
            "issuanceId": "issuance-id",
            "sourceCredentialSaid": source_credential_said,
            "vcJwt": "qvi.vc.jwt",
        }

    def credentials(self, name):
        self.calls.append(("credentials", name))
        return [{"credentialId": "held-id", "vcJwt": "qvi.vc.jwt"}]

    def start_present_tx(self, name, descriptor):
        self.calls.append(("start_present_tx", name, descriptor))
        return {
            "presentTxId": "present-tx-id",
            "aud": descriptor["aud"],
            "nonce": descriptor["nonce"],
            "vpJwt": "le.vp.jwt",
            "verifierResponse": {"accepted": True},
        }

    def submit_present_tx_signature(self, name, present_tx_id, signature=None, vp_jwt=None):
        self.calls.append(("submit_present_tx_signature", name, present_tx_id, signature, vp_jwt))
        return {"presentTxId": present_tx_id, "state": "submitted", "vpJwt": vp_jwt}


class FakeAutomator:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def pollOnce(self, name=None):
        self.calls.append(("pollOnce", name))
        if not self.outcomes:
            return []
        return [self.outcomes.pop(0)]

    def handleEnvelope(self, envelope):
        self.calls.append(("handleEnvelope", envelope))
        return {"outcome": "submitted", "requestId": "signal-id"}


def accepting_verifier(name):
    def verify(artifacts):
        return {
            "name": name,
            "accepted": artifacts["vcJwt"] == "qvi.vc.jwt"
            and artifacts["vpJwt"] == "le.vp.jwt"
            and artifacts["audience"] == "https://verifier.example"
            and artifacts["nonce"] == "nonce-1",
            "details": {"audience": artifacts["audience"], "nonce": artifacts["nonce"]},
        }

    return verify


def test_keria_w3c_api_uses_holder_routes():
    client = FakeClient(
        {
            ("post", "/identifiers/qvi/w3c/credentials"): {"issuanceId": "issuance-id"},
            ("get", "/identifiers/le/w3c/credentials/import-requests"): {"requests": []},
            ("post", "/identifiers/le/w3c/credentials/import"): {"credentialId": "held-id"},
            ("post", "/identifiers/le/w3c/present-txs"): {"presentTxId": "tx-id"},
        }
    )
    api = KeriaW3CApi(client)

    assert api.start_issuance("qvi", "credential-said") == {"issuanceId": "issuance-id"}
    assert api.import_requests("le") == []
    assert api.import_credential("le", "import-id") == {"credentialId": "held-id"}
    assert api.start_present_tx("le", {"aud": "https://verifier.example"}) == {"presentTxId": "tx-id"}

    assert (
        "post",
        "/identifiers/qvi/w3c/credentials",
        {"json": {"sourceCredentialSaid": "credential-said"}},
    ) in client.calls
    assert (
        "post",
        "/identifiers/le/w3c/credentials/import",
        {"json": {"importRequestId": "import-id"}},
    ) in client.calls


def test_headless_scenario_emits_manifest_with_all_verifier_evidence():
    qvi = HeadlessW3CWallet(
        name="qvi",
        w3c=FakeW3C("qvi"),
        automator=FakeAutomator([{"outcome": "submitted", "requestId": "issuer-signing-id"}]),
    )
    holder = HeadlessW3CWallet(
        name="le",
        w3c=FakeW3C("le"),
        automator=FakeAutomator([{"outcome": "imported", "requestId": "import-id"}]),
    )
    suite = VerifierSuite(
        {
            "python": accepting_verifier("python"),
            "node": accepting_verifier("node"),
            "go": accepting_verifier("go"),
        }
    )

    manifest = HeadlessW3CE2E(qvi, holder, suite).run_happy_path(
        "credential-said",
        {"aud": "https://verifier.example", "nonce": "nonce-1"},
    )
    data = manifest.to_dict()

    assert data["sourceCredentialSaid"] == "credential-said"
    assert data["issuance"]["vcJwt"] == "qvi.vc.jwt"
    assert data["holderImportOutcomes"][0]["outcome"] == "imported"
    assert data["presentationTx"]["vpJwt"] == "le.vp.jwt"
    assert data["verifierEvidence"]["accepted"] is True
    assert [check["name"] for check in data["verifierEvidence"]["checks"]] == ["python", "node", "go"]
    assert data["failures"] == []


def test_headless_scenario_records_verifier_rejection_for_wrong_nonce():
    qvi = HeadlessW3CWallet(name="qvi", w3c=FakeW3C("qvi"), automator=FakeAutomator([]))
    holder = HeadlessW3CWallet(name="le", w3c=FakeW3C("le"), automator=FakeAutomator([]))
    suite = VerifierSuite(
        {
            "python": accepting_verifier("python"),
            "node": accepting_verifier("node"),
            "go": accepting_verifier("go"),
        }
    )

    manifest = HeadlessW3CE2E(qvi, holder, suite).run_happy_path(
        "credential-said",
        {"aud": "https://verifier.example", "nonce": "wrong-nonce"},
    )

    assert manifest.verifierEvidence["accepted"] is False
    assert manifest.failures[0]["stage"] == "verifier"


def test_verifier_suite_requires_python_node_and_go():
    suite = VerifierSuite({"python": accepting_verifier("python")})

    with pytest.raises(ValueError, match="missing verifier adapters: node, go"):
        suite.verify({"vcJwt": "qvi.vc.jwt", "vpJwt": "le.vp.jwt"})
