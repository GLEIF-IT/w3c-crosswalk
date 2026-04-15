"""End-to-end HIO tests for the verifier operation runtime."""

from __future__ import annotations

from pathlib import Path
import socket
from urllib.parse import unquote

import falcon
from w3c_crosswalk.common import load_json_file
from w3c_crosswalk.jwt import issue_vc_jwt
from w3c_crosswalk.service import VerifierServerConfig, setup_verifier_doers
from w3c_crosswalk.runtime_http import setup_server_doers
from w3c_crosswalk.signing import KeriHabSigner
from w3c_crosswalk.verifier_client import verify_vc_doer

from keri_test_support import open_test_hab
from tests.integration.helpers import run_doers_until


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


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


def _verify_state(verify_doer) -> dict:
    """Return compact verifier state for supervisor timeout errors."""
    return {
        "done": verify_doer.done,
        "operation": verify_doer.operation,
        "error": str(verify_doer.error) if verify_doer.error else None,
        "timeout_error": str(verify_doer.timeout_error) if verify_doer.timeout_error else None,
    }


def test_verifier_runtime_completes_vc_operation_via_hio_doers(tmp_path):
    """Run the verifier service and dependency stubs under one explicit HIO doist."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")

    with open_test_hab("runtime-issuer-hab", b"1122334455667788") as (_hby, hab):
        signer = KeriHabSigner(hab)
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
        token, _vc = issue_vc_jwt(acdc, issuer_did=issuer_did, status_base_url=status_base_url, signer=signer)

        resolver_app = falcon.App()
        resolver_app.add_route("/1.0/identifiers/{did}", ResolverResource({issuer_did: did_document}))
        _resolver_server, resolver_doers = setup_server_doers(host="127.0.0.1", port=resolver_port, app=resolver_app)

        statuses = {
            acdc["d"]: {
                "id": f"{status_base_url}/status/{acdc['d']}",
                "credentialSaid": acdc["d"],
                "revoked": False,
                "status": "active",
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

        assert verify_doer.timeout_error is None
        assert verify_doer.operation is not None
        assert verify_doer.operation["done"] is True
        assert verify_doer.operation["response"]["ok"] is True
        assert verify_doer.operation["response"]["checks"]["statusActive"] is True
        assert verify_doer.operation["metadata"]["state"] == "completed"


def test_verifier_runtime_marks_malformed_token_as_failed_operation(tmp_path):
    """Fail malformed verifier input as a terminal failed operation."""
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

    assert verify_doer.timeout_error is None
    assert verify_doer.operation is not None
    assert verify_doer.operation["done"] is True
    assert verify_doer.operation["error"]["code"] == 400
    assert verify_doer.operation["metadata"]["state"] == "failed"
    assert "errors" in verify_doer.operation["error"]["details"]


def test_verifier_runtime_surfaces_resolver_failure_details(tmp_path):
    """Annotate resolver failures with the relevant DID and HTTP status."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")

    with open_test_hab("runtime-resolver-failure", b"1122334455667788") as (_hby, hab):
        signer = KeriHabSigner(hab)
        issuer_did = "did:webs:example.com:dws:ELEGALAID000000000000000000000000000000000000000001"
        resolver_port = _free_port()
        status_port = _free_port()
        verifier_port = _free_port()

        token, _vc = issue_vc_jwt(
            acdc,
            issuer_did=issuer_did,
            status_base_url=f"http://127.0.0.1:{status_port}",
            signer=signer,
        )

        resolver_app = falcon.App()
        resolver_app.add_route("/1.0/identifiers/{did}", ResolverResource({}))
        _resolver_server, resolver_doers = setup_server_doers(host="127.0.0.1", port=resolver_port, app=resolver_app)

        status_app = falcon.App()
        status_app.add_route("/status/{credential_said}", StatusResource({acdc["d"]: {"revoked": False, "status": "active"}}))
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
        signer = KeriHabSigner(hab)
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
        token, _vc = issue_vc_jwt(
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
