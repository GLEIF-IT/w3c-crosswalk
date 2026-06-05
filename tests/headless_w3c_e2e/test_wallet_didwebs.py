"""Headless wallet did:webs setup orchestration tests."""

from __future__ import annotations

from headless_w3c_e2e import wallet as walleting


def test_issue_credential_ensures_didwebs_before_w3c_issuance(monkeypatch):
    calls: list[tuple[str, str]] = []

    def fake_ensure(client, name, **_kwargs):
        calls.append(("ensure", name))
        assert client is client_obj
        return {"ready": True, "dws": "did:webs:example:dws:Eissuer"}

    def fake_issue_w3c_credential(*, client, issuer_name, source_credential_said):
        calls.append(("issue", issuer_name))
        assert client is client_obj
        assert source_credential_said == "EVRD"
        return {"issuanceId": "EISS", "state": "grant_sent"}

    client_obj = object()
    monkeypatch.setattr(walleting, "ensure_didwebs_setup", fake_ensure)
    monkeypatch.setattr(walleting, "issue_w3c_credential", fake_issue_w3c_credential)

    wallet = walleting.HeadlessW3CWallet.from_client("issuer", client_obj)
    result = wallet.issue_credential("EVRD")

    assert result["issuanceId"] == "EISS"
    assert calls == [("ensure", "issuer"), ("issue", "issuer")]


def test_present_credential_ensures_didwebs_before_w3c_presentation(monkeypatch):
    calls: list[tuple[str, str]] = []

    def fake_ensure(client, name, **_kwargs):
        calls.append(("ensure", name))
        assert client is client_obj
        return {"ready": True, "dws": "did:webs:example:dws:Eholder"}

    def fake_present_w3c_credential(*, client, holder_name, credential_id, verifier_request):
        calls.append(("present", holder_name))
        assert client is client_obj
        assert credential_id == "ECRED"
        assert verifier_request == {"aud": "https://verifier.example", "nonce": "nonce-1"}
        return {"presentationId": "EPRES", "state": "submitted"}

    client_obj = object()
    monkeypatch.setattr(walleting, "ensure_didwebs_setup", fake_ensure)
    monkeypatch.setattr(walleting, "present_w3c_credential", fake_present_w3c_credential)

    wallet = walleting.HeadlessW3CWallet.from_client("holder", client_obj)
    result = wallet.present_credential("ECRED", {"aud": "https://verifier.example", "nonce": "nonce-1"})

    assert result["presentationId"] == "EPRES"
    assert calls == [("ensure", "holder"), ("present", "holder")]
