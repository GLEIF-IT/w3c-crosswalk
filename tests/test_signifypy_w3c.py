"""Python edge-wallet helpers for KERIA W3C workflows."""

from __future__ import annotations

from types import SimpleNamespace

import signifypy_w3c.keria as keria
from signifypy_w3c import SignifyEdgeSigner, W3CKeriaClient, issue_w3c_credential, present_w3c_credential


class _Response:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class _Identifiers:
    def __init__(self, hab):
        self.hab = hab

    def get(self, name):
        assert name
        return self.hab


class _Keeper:
    def __init__(self, signer=None):
        self.signer = signer or _Signer()

    def signers(self):
        return [self.signer]


class _Manager:
    def __init__(self, keeper=None):
        self.keeper = keeper or _Keeper()

    def get(self, *_, **__):
        return self.keeper


class _Signer:
    verfer = SimpleNamespace(qb64="EKEY", raw=b"\x01" * 32)

    def sign(self, message):
        assert isinstance(message, bytes)
        return SimpleNamespace(raw=b"\x02" * 64)


class _Client:
    def __init__(self, *, gets=None, posts=None, hab=None, keeper=None):
        self.gets = gets or {}
        self.posts = posts or {}
        self.calls = []
        self.manager = _Manager(keeper)
        self._identifiers = _Identifiers(
            hab
            or {
                "prefix": "EISSUER",
                "state": {"k": ["EKEY"]},
            }
        )

    def identifiers(self):
        return self._identifiers

    def get(self, path, **kwargs):
        self.calls.append(("GET", path, kwargs))
        return _Response(self.gets[path])

    def post(self, path, json=None, **kwargs):
        self.calls.append(("POST", path, json, kwargs))
        response = self.posts[path]
        if isinstance(response, list):
            return _Response(response.pop(0))
        return _Response(response)


def test_w3c_keria_client_uses_edge_owned_routes():
    """The Python helper must not target old signing-request or present-tx routes."""
    client = _Client(
        gets={
            "/identifiers/le/w3c/issuances/E%2FISS": {"issuanceId": "E/ISS"},
            "/identifiers/le/w3c/credentials": {"credentials": [{"credentialId": "ECRED"}]},
            "/identifiers/le/w3c/credentials/E%2FCRED": {"credentialId": "E/CRED"},
        },
        posts={
            "/identifiers/le/w3c/issuances": {"issuanceId": "EISS"},
            "/identifiers/le/w3c/issuances/EISS/vc-jwt": {"issuanceId": "EISS", "vcJwt": "vc.jwt"},
            "/identifiers/le/w3c/presentations": {"presentationId": "EPRES"},
        },
    )
    w3c = W3CKeriaClient(client)

    assert w3c.create_issuance("le", "EVRD")["issuanceId"] == "EISS"
    assert w3c.issuance("le", "E/ISS")["issuanceId"] == "E/ISS"
    assert w3c.submit_vc_jwt("le", "EISS", "vc.jwt")["vcJwt"] == "vc.jwt"
    assert w3c.credentials("le")[0]["credentialId"] == "ECRED"
    assert w3c.credential("le", "E/CRED")["credentialId"] == "E/CRED"
    assert w3c.present("le", {"nonce": "n"}, "vp.jwt")["presentationId"] == "EPRES"

    routed = "\n".join(call[1] for call in client.calls)
    assert "/w3c/signing-requests" not in routed
    assert "/w3c/present-txs" not in routed
    assert "/w3c/credentials/import-requests" not in routed


def test_signify_edge_signer_exposes_signer_like_contract():
    client = _Client()
    signer = SignifyEdgeSigner(client, "le")

    assert signer.kid == "EKEY"
    assert signer.public_jwk == {
        "kid": "EKEY",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    }
    assert signer.public_key_multibase.startswith("z")
    assert signer.sign(b"message") == b"\x02" * 64


def test_present_w3c_credential_builds_vp_jwt_and_submits_once():
    client = _Client(
        gets={
            "/identifiers/le/w3c/credentials/ECRED": {
                "credentialId": "ECRED",
                "holderDid": "did:webs:example%3A3902:dws:ELE",
                "vcJwt": "header.payload.signature",
            }
        },
        posts={
            "/identifiers/le/w3c/presentations": {"presentationId": "EPRES", "state": "submitted"},
        },
    )

    result = present_w3c_credential(
        client=client,
        holder_name="le",
        credential_id="ECRED",
        verifier_request={"aud": "https://verifier.example", "nonce": "nonce-1"},
    )

    assert result["presentationId"] == "EPRES"
    post = client.calls[-1]
    assert post[0] == "POST"
    assert post[1] == "/identifiers/le/w3c/presentations"
    assert post[2]["credentialId"] == "ECRED"
    assert isinstance(post[2]["vpJwt"], str)
    assert len(post[2]["vpJwt"].split(".")) == 3


def test_issue_w3c_credential_builds_vc_jwt_and_delivers_grant(monkeypatch):
    client = _Client(
        posts={
            "/identifiers/qvi/w3c/issuances": {
                "issuanceId": "EISS",
                "issuerAid": "EISSUER",
                "holderAid": "EHOLDER",
                "issuerDid": "did:webs:example%3A3902:dws:EISSUER",
                "holderDid": "did:webs:example%3A3902:dws:EHOLDER",
                "sourceCredentialSaid": "EVRD",
                "schemaSaid": "ESCHEMA",
                "profile": "isomer-vrd-v1",
                "state": "ready",
                "statusUrl": "http://127.0.0.1:3901/status/EVRD",
                "statusBaseUrl": "http://127.0.0.1:3901",
                "sourceCredential": {"d": "EVRD"},
            },
            "/identifiers/qvi/w3c/issuances/EISS/vc-jwt": {
                "issuanceId": "EISS",
                "issuerAid": "EISSUER",
                "holderAid": "EHOLDER",
                "issuerDid": "did:webs:example%3A3902:dws:EISSUER",
                "holderDid": "did:webs:example%3A3902:dws:EHOLDER",
                "sourceCredentialSaid": "EVRD",
                "schemaSaid": "ESCHEMA",
                "profile": "isomer-vrd-v1",
                "state": "issued",
                "statusUrl": "http://127.0.0.1:3901/status/EVRD",
                "vcJwt": "vc.jwt",
            },
            "/identifiers/qvi/w3c/issuances/EISS/grant": {
                "issuanceId": "EISS",
                "state": "grant_sent",
                "vcJwt": "vc.jwt",
            },
        },
    )

    monkeypatch.setattr(keria, "transpose_acdc_to_w3c_vc", lambda *_args, **_kwargs: {"id": "urn:said:EVRD"})
    monkeypatch.setattr(keria, "issue_vc_jwt", lambda *_args, **_kwargs: ("vc.jwt", {"id": "urn:said:EVRD"}))

    class _FakeExchanges:
        def __init__(self, client):
            self.client = client

        def createExchangeMessage(self, *_args, **_kwargs):
            return SimpleNamespace(ked={"r": "/w3c/vc/grant"}), ["sig"], "atc"

    monkeypatch.setattr(keria, "Exchanges", _FakeExchanges)

    result = issue_w3c_credential(
        client=client,
        issuer_name="qvi",
        source_credential_said="EVRD",
        timeout_seconds=0.1,
    )

    assert result["state"] == "grant_sent"
    assert [call[1] for call in client.calls] == [
        "/identifiers/qvi/w3c/issuances",
        "/identifiers/qvi/w3c/issuances/EISS/vc-jwt",
        "/identifiers/qvi/w3c/issuances/EISS/grant",
    ]
