"""End-to-end HIO tests for the verifier operation runtime."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import socket
from urllib.parse import unquote

import falcon
from vc_isomer.common import canonicalize_did_url, canonicalize_did_webs, load_json_file
from vc_isomer.jwt import issue_vc_jwt, issue_vp_jwt
from vc_isomer.profile import transpose_acdc_to_w3c_vc
from vc_isomer.service import VerifierServerConfig, setup_verifier_doers
from vc_isomer.runtime_http import setup_server_doers
from vc_isomer.signing import HabSigner
from vc_isomer.verifier_client import verify_vc_doer, verify_vp_doer

from keri_test_support import open_test_hab
from tests.integration.helpers import run_doers_until


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _issue_projected_fixture(acdc: dict, *, issuer_did: str, status_base_url: str, signer: HabSigner):
    """Project a fixture ACDC explicitly, then sign the resulting VC."""
    canonical_issuer = canonicalize_did_webs(issuer_did)
    verification_method = canonicalize_did_url(f"{canonical_issuer}#{signer.kid}")
    vc = transpose_acdc_to_w3c_vc(
        acdc,
        issuer_did=canonical_issuer,
        status_base_url=status_base_url,
    )
    return issue_vc_jwt(vc, signer=signer, verification_method=verification_method)


def _free_port() -> int:
    """Allocate one currently free localhost port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ResolverResource:
    """Serve one in-memory DID document through the local resolver route."""

    def __init__(self, did_documents: dict[str, dict]):
        self.did_documents = did_documents

    def on_get(self, _req: falcon.Request, resp: falcon.Response, did: str) -> None:
        document = self.did_documents.get(did) or self.did_documents.get(_decode_did_segment(did))
        if document is None:
            resp.status = falcon.HTTP_404
            resp.media = {"error": "not found"}
            return
        resp.media = {"didDocument": document}


def _decode_did_segment(value: str) -> str:
    """Decode a resolver path segment until it stabilizes."""
    decoded = value
    while True:
        next_value = unquote(decoded)
        if next_value == decoded:
            return decoded
        decoded = next_value


class StatusResource:
    """Serve one in-memory credential status document."""

    def __init__(self, statuses: dict[str, dict]):
        self.statuses = statuses

    def on_get(self, _req: falcon.Request, resp: falcon.Response, credential_said: str) -> None:
        document = self.statuses.get(credential_said)
        if document is None:
            resp.status = falcon.HTTP_404
            resp.media = {"error": "not found"}
            return
        resp.media = document


class WebhookResource:
    """Collect webhook events posted by the verifier runtime."""

    def __init__(self, *, status: str = falcon.HTTP_202):
        self.status = status
        self.events: list[dict] = []

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        """Store one webhook event body."""
        self.events.append(req.media)
        resp.status = self.status
        resp.media = {"ok": self.status < "400"}


def _verify_state(verify_doer) -> dict:
    """Return compact verifier state for supervisor timeout errors."""
    return {
        "done": verify_doer.done,
        "operation": verify_doer.operation,
        "error": str(verify_doer.error) if verify_doer.error else None,
    }


def _verifier_log_events(caplog) -> list[dict]:
    """Return structured verifier log events captured by pytest."""
    events = []
    for record in caplog.records:
        if record.name != "vc_isomer.verifier":
            continue
        events.append(json.loads(record.message))
    return events


def _token_sha256_prefix(token: str) -> str:
    """Return the verifier log token digest prefix."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _event(events: list[dict], name: str, **matches) -> dict:
    """Find one captured verifier event by event name and field matches."""
    for event in events:
        if event.get("event") != name:
            continue
        if all(event.get(key) == value for key, value in matches.items()):
            return event
    raise AssertionError(f"missing event {name!r} with {matches!r}; events={events!r}")


def test_verifier_runtime_completes_vc_operation_via_hio_doers(tmp_path, caplog):
    """Run the verifier service and dependency stubs under one explicit HIO doist."""
    caplog.set_level(logging.INFO, logger="vc_isomer.verifier")
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")

    with open_test_hab("runtime-issuer-hab", b"1122334455667788") as (_hby, hab):
        signer = HabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        resolver_port = _free_port()
        status_port = _free_port()
        verifier_port = _free_port()

        did_document = {
            "id": issuer_did,
            "verificationMethod": [{
                "id": f"#{signer.kid}",
                "type": "JsonWebKey",
                "controller": issuer_did,
                "publicKeyJwk": signer.public_jwk,
            }],
        }
        status_base_url = f"http://127.0.0.1:{status_port}"
        token, _vc = _issue_projected_fixture(acdc, issuer_did=issuer_did, status_base_url=status_base_url, signer=signer)

        resolver_app = falcon.App()
        resolver_app.add_route("/1.0/identifiers/{did}", ResolverResource({issuer_did: did_document}))
        _resolver_server, resolver_doers = setup_server_doers(host="127.0.0.1", port=resolver_port, app=resolver_app)

        statuses = {
            acdc["d"]: {
                "id": f"{status_base_url}/status/{acdc['d']}",
                "credSaid": acdc["d"],
                "revoked": False,
                "status": "iss",
            }
        }
        status_app = falcon.App()
        status_app.add_route("/status/{credential_said}", StatusResource(statuses))
        _status_server, status_doers = setup_server_doers(host="127.0.0.1", port=status_port, app=status_app)

        _verifier_server, verifier_doers = setup_verifier_doers(
            VerifierServerConfig(
                host="127.0.0.1",
                port=verifier_port,
                resolver_url=f"http://127.0.0.1:{resolver_port}/1.0/identifiers",
                operation_store_root=str(tmp_path),
                operation_store_name="runtime-ops",
            )
        )

        verify_doer = verify_vc_doer(
            base_url=f"http://127.0.0.1:{verifier_port}",
            token=token,
            timeout=2.0,
            poll_interval=0.05,
        )

        run_doers_until(
            "verifier runtime successful VC operation",
            [*resolver_doers, *status_doers, *verifier_doers, verify_doer],
            timeout=3.0,
            ready=lambda: verify_doer.done,
            observe=lambda: _verify_state(verify_doer),
        )

        assert verify_doer.error is None
        assert verify_doer.operation is not None
        assert verify_doer.operation["done"] is True
        assert verify_doer.operation["response"]["ok"] is True
        assert verify_doer.operation["response"]["checks"]["statusActive"] is True
        assert verify_doer.operation["metadata"]["state"] == "completed"

        events = _verifier_log_events(caplog)
        operation_name = verify_doer.operation["name"]
        received = _event(events, "verification.received", operationName=operation_name)
        assert received["verifier"] == "isomer-python"
        assert received["route"] == "/verify/vc"
        assert received["artifactKind"] == "vc+jwt"
        assert received["token"] == token
        assert received["tokenLength"] == len(token)
        assert received["tokenSha256"] == _token_sha256_prefix(token)
        result = _event(events, "verification.result", operationName=operation_name)
        assert result["ok"] is True
        assert result["kind"] == "vc+jwt"
        assert result["checks"]["statusActive"] is True
        skipped = _event(events, "webhook.skipped", artifactKind="vc+jwt")
        assert skipped["reason"] == "no_webhook_url"


def test_verifier_runtime_posts_webhook_for_successful_vc_operation(tmp_path, caplog):
    """Emit one best-effort webhook after a successful top-level VC verification."""
    caplog.set_level(logging.INFO, logger="vc_isomer.verifier")
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")

    with open_test_hab("runtime-webhook-vc", b"1122334455667788") as (_hby, hab):
        signer = HabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        resolver_port = _free_port()
        status_port = _free_port()
        webhook_port = _free_port()
        verifier_port = _free_port()

        did_document = {
            "id": issuer_did,
            "verificationMethod": [{
                "id": f"#{signer.kid}",
                "type": "JsonWebKey",
                "controller": issuer_did,
                "publicKeyJwk": signer.public_jwk,
            }],
        }
        status_base_url = f"http://127.0.0.1:{status_port}"
        vc_token, _vc = _issue_projected_fixture(acdc, issuer_did=issuer_did, status_base_url=status_base_url, signer=signer)

        resolver_app = falcon.App()
        resolver_app.add_route("/1.0/identifiers/{did}", ResolverResource({issuer_did: did_document}))
        _resolver_server, resolver_doers = setup_server_doers(host="127.0.0.1", port=resolver_port, app=resolver_app)

        statuses = {
            acdc["d"]: {
                "id": f"{status_base_url}/status/{acdc['d']}",
                "credSaid": acdc["d"],
                "revoked": False,
                "status": "iss",
            }
        }
        status_app = falcon.App()
        status_app.add_route("/status/{credential_said}", StatusResource(statuses))
        _status_server, status_doers = setup_server_doers(host="127.0.0.1", port=status_port, app=status_app)

        webhook = WebhookResource()
        webhook_app = falcon.App()
        webhook_app.add_route("/webhooks/presentations", webhook)
        _webhook_server, webhook_doers = setup_server_doers(host="127.0.0.1", port=webhook_port, app=webhook_app)

        _verifier_server, verifier_doers = setup_verifier_doers(
            VerifierServerConfig(
                host="127.0.0.1",
                port=verifier_port,
                resolver_url=f"http://127.0.0.1:{resolver_port}/1.0/identifiers",
                operation_store_root=str(tmp_path),
                operation_store_name="runtime-webhook-vc",
                webhook_url=f"http://127.0.0.1:{webhook_port}/webhooks/presentations",
                verifier_id="python-vc-webhook-test",
            )
        )

        verify_doer = verify_vc_doer(
            base_url=f"http://127.0.0.1:{verifier_port}",
            token=vc_token,
            timeout=2.0,
            poll_interval=0.05,
        )

        run_doers_until(
            "verifier runtime successful VC webhook",
            [*resolver_doers, *status_doers, *webhook_doers, *verifier_doers, verify_doer],
            timeout=3.0,
            ready=lambda: verify_doer.done,
            observe=lambda: _verify_state(verify_doer) | {"webhook_events": len(webhook.events)},
        )

        assert verify_doer.error is None
        assert verify_doer.operation["response"]["ok"] is True
        assert len(webhook.events) == 1
        event = webhook.events[0]
        assert event["type"] == "isomer.presentation.verified.v1"
        assert event["verifier"]["id"] == "python-vc-webhook-test"
        assert event["verifier"]["language"] == "Python"
        assert event["presentation"]["kind"] == "vc+jwt"
        assert event["presentation"]["holder"] == _vc["credentialSubject"]["id"]
        assert event["presentation"]["credentials"][0]["id"] == _vc["id"]
        assert vc_token not in str(event)

        events = _verifier_log_events(caplog)
        request_log = _event(events, "webhook.request", artifactKind="vc+jwt")
        assert request_log["webhookUrl"] == f"http://127.0.0.1:{webhook_port}/webhooks/presentations"
        assert request_log["body"]["eventId"] == event["eventId"]
        assert request_log["body"]["presentation"]["credentials"][0]["id"] == _vc["id"]
        assert vc_token not in str(request_log["body"])
        response_log = _event(events, "webhook.response", eventId=event["eventId"])
        assert response_log["httpStatus"] == 202
        assert response_log["ok"] is True


def test_verifier_runtime_posts_webhook_for_successful_vp_operation(tmp_path, caplog):
    """Emit one best-effort webhook after a successful top-level VP verification."""
    caplog.set_level(logging.INFO, logger="vc_isomer.verifier")
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")

    with open_test_hab("runtime-webhook-vp", b"1122334455667788") as (_hby, hab):
        signer = HabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        resolver_port = _free_port()
        status_port = _free_port()
        webhook_port = _free_port()
        verifier_port = _free_port()

        did_document = {
            "id": issuer_did,
            "verificationMethod": [{
                "id": f"#{signer.kid}",
                "type": "JsonWebKey",
                "controller": issuer_did,
                "publicKeyJwk": signer.public_jwk,
            }],
        }
        status_base_url = f"http://127.0.0.1:{status_port}"
        vc_token, _vc = _issue_projected_fixture(acdc, issuer_did=issuer_did, status_base_url=status_base_url, signer=signer)
        vp_token, _vp = issue_vp_jwt([vc_token], holder_did=issuer_did, signer=signer)

        resolver_app = falcon.App()
        resolver_app.add_route("/1.0/identifiers/{did}", ResolverResource({issuer_did: did_document}))
        _resolver_server, resolver_doers = setup_server_doers(host="127.0.0.1", port=resolver_port, app=resolver_app)

        statuses = {
            acdc["d"]: {
                "id": f"{status_base_url}/status/{acdc['d']}",
                "credSaid": acdc["d"],
                "revoked": False,
                "status": "iss",
            }
        }
        status_app = falcon.App()
        status_app.add_route("/status/{credential_said}", StatusResource(statuses))
        _status_server, status_doers = setup_server_doers(host="127.0.0.1", port=status_port, app=status_app)

        webhook = WebhookResource()
        webhook_app = falcon.App()
        webhook_app.add_route("/webhooks/presentations", webhook)
        _webhook_server, webhook_doers = setup_server_doers(host="127.0.0.1", port=webhook_port, app=webhook_app)

        _verifier_server, verifier_doers = setup_verifier_doers(
            VerifierServerConfig(
                host="127.0.0.1",
                port=verifier_port,
                resolver_url=f"http://127.0.0.1:{resolver_port}/1.0/identifiers",
                operation_store_root=str(tmp_path),
                operation_store_name="runtime-webhook-vp",
                webhook_url=f"http://127.0.0.1:{webhook_port}/webhooks/presentations",
                verifier_id="python-webhook-test",
            )
        )

        verify_doer = verify_vp_doer(
            base_url=f"http://127.0.0.1:{verifier_port}",
            token=vp_token,
            timeout=2.0,
            poll_interval=0.05,
        )

        run_doers_until(
            "verifier runtime successful VP webhook",
            [*resolver_doers, *status_doers, *webhook_doers, *verifier_doers, verify_doer],
            timeout=3.0,
            ready=lambda: verify_doer.done,
            observe=lambda: _verify_state(verify_doer) | {"webhook_events": len(webhook.events)},
        )

        assert verify_doer.error is None
        assert verify_doer.operation["response"]["ok"] is True
        assert len(webhook.events) == 1
        event = webhook.events[0]
        assert event["type"] == "isomer.presentation.verified.v1"
        assert event["verifier"]["id"] == "python-webhook-test"
        assert event["verifier"]["language"] == "Python"
        assert event["presentation"]["holder"] == issuer_did
        assert event["presentation"]["credentials"][0]["id"] == _vc["id"]
        assert vc_token not in str(event)

        events = _verifier_log_events(caplog)
        operation_name = verify_doer.operation["name"]
        received = _event(events, "verification.received", operationName=operation_name)
        assert received["route"] == "/verify/vp"
        assert received["artifactKind"] == "vp+jwt"
        assert received["token"] == vp_token
        result = _event(events, "verification.result", operationName=operation_name)
        assert result["ok"] is True
        assert result["kind"] == "vp+jwt"
        request_log = _event(events, "webhook.request", artifactKind="vp+jwt")
        assert request_log["body"]["eventId"] == event["eventId"]
        response_log = _event(events, "webhook.response", eventId=event["eventId"])
        assert response_log["httpStatus"] == 202


def test_verifier_runtime_marks_malformed_token_as_failed_operation(tmp_path, caplog):
    """Fail malformed verifier input as a terminal failed operation."""
    caplog.set_level(logging.INFO, logger="vc_isomer.verifier")
    resolver_port = _free_port()
    verifier_port = _free_port()

    resolver_app = falcon.App()
    resolver_app.add_route("/1.0/identifiers/{did}", ResolverResource({}))
    _resolver_server, resolver_doers = setup_server_doers(host="127.0.0.1", port=resolver_port, app=resolver_app)
    _verifier_server, verifier_doers = setup_verifier_doers(
        VerifierServerConfig(
            host="127.0.0.1",
            port=verifier_port,
            resolver_url=f"http://127.0.0.1:{resolver_port}/1.0/identifiers",
            operation_store_root=str(tmp_path),
            operation_store_name="runtime-failed-ops",
        )
    )

    verify_doer = verify_vc_doer(
        base_url=f"http://127.0.0.1:{verifier_port}",
        token="not-a-jwt",
        timeout=2.0,
        poll_interval=0.05,
    )

    run_doers_until(
        "verifier runtime malformed token failure",
        [*resolver_doers, *verifier_doers, verify_doer],
        timeout=3.0,
        ready=lambda: verify_doer.done,
        observe=lambda: _verify_state(verify_doer),
    )

    assert verify_doer.error is not None
    assert str(verify_doer.error).startswith("verification failed:")
    assert verify_doer.operation is not None
    assert verify_doer.operation["done"] is True
    assert verify_doer.operation["error"]["code"] == 400
    assert verify_doer.operation["metadata"]["state"] == "failed"
    assert "errors" in verify_doer.operation["error"]["details"]

    events = _verifier_log_events(caplog)
    operation_name = verify_doer.operation["name"]
    received = _event(events, "verification.received", operationName=operation_name)
    assert received["token"] == "not-a-jwt"
    result = _event(events, "verification.result", operationName=operation_name)
    assert result["ok"] is False
    assert result["error"]["code"] == 400
    assert result["error"]["message"] == "invalid vc+jwt"


def test_verifier_runtime_surfaces_resolver_failure_details(tmp_path):
    """Annotate resolver failures with the relevant DID and HTTP status."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")

    with open_test_hab("runtime-resolver-failure", b"1122334455667788") as (_hby, hab):
        signer = HabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        resolver_port = _free_port()
        status_port = _free_port()
        verifier_port = _free_port()

        token, _vc = _issue_projected_fixture(
            acdc,
            issuer_did=issuer_did,
            status_base_url=f"http://127.0.0.1:{status_port}",
            signer=signer,
        )

        resolver_app = falcon.App()
        resolver_app.add_route("/1.0/identifiers/{did}", ResolverResource({}))
        _resolver_server, resolver_doers = setup_server_doers(host="127.0.0.1", port=resolver_port, app=resolver_app)

        status_app = falcon.App()
        status_app.add_route("/status/{credential_said}", StatusResource({acdc["d"]: {"revoked": False, "status": "iss"}}))
        _status_server, status_doers = setup_server_doers(host="127.0.0.1", port=status_port, app=status_app)

        _verifier_server, verifier_doers = setup_verifier_doers(
            VerifierServerConfig(
                host="127.0.0.1",
                port=verifier_port,
                resolver_url=f"http://127.0.0.1:{resolver_port}/1.0/identifiers",
                operation_store_root=str(tmp_path),
                operation_store_name="runtime-resolver-failure",
            )
        )

        verify_doer = verify_vc_doer(
            base_url=f"http://127.0.0.1:{verifier_port}",
            token=token,
            timeout=2.0,
            poll_interval=0.05,
        )

        run_doers_until(
            "verifier runtime resolver failure",
            [*resolver_doers, *status_doers, *verifier_doers, verify_doer],
            timeout=3.0,
            ready=lambda: verify_doer.done,
            observe=lambda: _verify_state(verify_doer),
        )

        assert verify_doer.operation["error"]["details"]["did"] == issuer_did
        assert verify_doer.operation["error"]["details"]["httpStatus"] == 404


def test_verifier_runtime_surfaces_status_failure_details(tmp_path):
    """Annotate status dereference failures with the relevant URL and HTTP status."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")

    with open_test_hab("runtime-status-failure", b"1122334455667788") as (_hby, hab):
        signer = HabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        resolver_port = _free_port()
        status_port = _free_port()
        verifier_port = _free_port()

        did_document = {
            "id": issuer_did,
            "verificationMethod": [{
                "id": f"#{signer.kid}",
                "type": "JsonWebKey",
                "controller": issuer_did,
                "publicKeyJwk": signer.public_jwk,
            }],
        }
        token, _vc = _issue_projected_fixture(
            acdc,
            issuer_did=issuer_did,
            status_base_url=f"http://127.0.0.1:{status_port}",
            signer=signer,
        )

        resolver_app = falcon.App()
        resolver_app.add_route("/1.0/identifiers/{did}", ResolverResource({issuer_did: did_document}))
        _resolver_server, resolver_doers = setup_server_doers(host="127.0.0.1", port=resolver_port, app=resolver_app)

        status_app = falcon.App()
        status_app.add_route("/status/{credential_said}", StatusResource({}))
        _status_server, status_doers = setup_server_doers(host="127.0.0.1", port=status_port, app=status_app)

        _verifier_server, verifier_doers = setup_verifier_doers(
            VerifierServerConfig(
                host="127.0.0.1",
                port=verifier_port,
                resolver_url=f"http://127.0.0.1:{resolver_port}/1.0/identifiers",
                operation_store_root=str(tmp_path),
                operation_store_name="runtime-status-failure",
            )
        )

        verify_doer = verify_vc_doer(
            base_url=f"http://127.0.0.1:{verifier_port}",
            token=token,
            timeout=2.0,
            poll_interval=0.05,
        )

        run_doers_until(
            "verifier runtime status failure",
            [*resolver_doers, *status_doers, *verifier_doers, verify_doer],
            timeout=3.0,
            ready=lambda: verify_doer.done,
            observe=lambda: _verify_state(verify_doer),
        )

        assert verify_doer.operation["error"]["details"]["url"].startswith(f"http://127.0.0.1:{status_port}/status/")
        assert verify_doer.operation["error"]["details"]["httpStatus"] == 404
