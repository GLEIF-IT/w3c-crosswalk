"""Live HTTP service-client tests for the headless W3C verifier boundary."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any

from headless_w3c_e2e import LiveVerifierService, LiveVerifierServiceSet, VerifierServiceClient


class VerifierHandler(BaseHTTPRequestHandler):
    """Minimal network-facing verifier service for client contract tests."""

    server: "VerifierServer"

    def do_GET(self) -> None:
        """Serve health, operation list, and operation fetch routes."""
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json(200, {"ok": True, "service": "verifier"})
            return
        if path == "/operations":
            self._send_json(200, list(self.server.operations.values()))
            return
        if path.startswith("/operations/"):
            name = path.rsplit("/", 1)[-1]
            operation = self.server.operations.get(name)
            if operation is None:
                self._send_json(404, {"ok": False, "error": f"unknown operation {name}"})
                return
            self.server.operation_gets[name] = self.server.operation_gets.get(name, 0) + 1
            if self.server.operation_gets[name] >= 2:
                operation["done"] = True
                operation["metadata"]["state"] = "completed"
                operation["response"] = self.server.responses[name]
            self._send_json(200, operation)
            return
        self._send_json(404, {"ok": False, "error": f"unknown route {path}"})

    def do_POST(self) -> None:
        """Accept VP/VC verification submissions and create operations."""
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw.decode("utf-8")) if raw else {}
        self.server.requests.append({"path": self.path, "body": body})
        if self.path not in {"/verify/vc", "/verify/vp"}:
            self._send_json(404, {"ok": False, "error": f"unknown route {self.path}"})
            return

        op_type = "verify-vp" if self.path == "/verify/vp" else "verify-vc"
        name = f"{op_type}.{len(self.server.operations) + 1}"
        operation = {
            "name": name,
            "done": False,
            "metadata": {"state": "pending", "request": body},
        }
        self.server.operations[name] = operation
        self.server.responses[name] = {
            "ok": True,
            "checks": {
                "signatureValid": True,
                "expectedHolderMatches": True,
                "audienceMatches": True,
                "nonceMatches": True,
            },
            "request": body,
        }
        self._send_json(202, {"name": name, "done": False})

    def log_message(self, _format: str, *_args: Any) -> None:
        """Keep pytest output focused on assertion failures."""

    def _send_json(self, status: int, body: Any) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class VerifierServer(ThreadingHTTPServer):
    """Threaded test service with captured operation state."""

    def __init__(self):
        super().__init__(("127.0.0.1", 0), VerifierHandler)
        self.requests: list[dict[str, Any]] = []
        self.operations: dict[str, dict[str, Any]] = {}
        self.responses: dict[str, dict[str, Any]] = {}
        self.operation_gets: dict[str, int] = {}

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"


@contextmanager
def live_verifier_server():
    """Run a real local HTTP service for the duration of a test."""
    server = VerifierServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_service_client_submits_vp_and_waits_for_operation():
    """Use HTTP submission and operation polling instead of a callable verifier."""
    with live_verifier_server() as server:
        client = VerifierServiceClient(server.base_url, poll_interval=0.01)

        health = client.health()
        submitted = client.submit_vp("vp.jwt", audience="https://verifier.example", nonce="nonce-1")
        operation = client.wait_operation(submitted["name"], timeout=2, poll_interval=0.01)

    assert health == {"ok": True, "service": "verifier"}
    assert operation["done"] is True
    assert operation["response"]["ok"] is True
    assert server.requests == [
        {
            "path": "/verify/vp",
            "body": {
                "token": "vp.jwt",
                "audience": "https://verifier.example",
                "nonce": "nonce-1",
            },
        }
    ]


def test_live_service_descriptor_matches_keria_present_tx_contract():
    """Build a descriptor with the fields KERIA uses for holder presentation txs."""
    service = LiveVerifierService(name="python", base_url="http://127.0.0.1:8788")

    descriptor = service.descriptor(nonce="nonce-2", audience="https://verifier.example/python")

    assert descriptor["verifierId"] == "python"
    assert descriptor["format"] == "vp+jwt"
    assert descriptor["formats"] == ["vp+jwt"]
    assert descriptor["aud"] == "https://verifier.example/python"
    assert descriptor["nonce"] == "nonce-2"
    assert descriptor["response_uri"] == "http://127.0.0.1:8788/verify/vp"
    assert descriptor["submissionEndpoint"] == "http://127.0.0.1:8788/verify/vp"


def test_live_service_descriptor_can_use_separate_keria_submission_url():
    """Keep public verifier audience separate from container-network submission."""
    service = LiveVerifierService(
        name="python",
        base_url="http://127.0.0.1:8788",
        submission_base_url="http://isomer-python:8788",
    )

    descriptor = service.descriptor(nonce="nonce-2")

    assert descriptor["aud"] == "http://127.0.0.1:8788/verify/vp"
    assert descriptor["response_uri"] == "http://isomer-python:8788/verify/vp"
    assert descriptor["submissionEndpoint"] == "http://isomer-python:8788/verify/vp"
    assert descriptor["verifierOrigin"] == "http://127.0.0.1:8788"


def test_service_set_collects_evidence_from_keria_submission_operation():
    """Collect final evidence only from the operation created by service submission."""
    with live_verifier_server() as server:
        client = VerifierServiceClient(server.base_url, poll_interval=0.01)
        service = LiveVerifierService(name="python", base_url=server.base_url, client=client)
        services = LiveVerifierServiceSet(
            {
                "python": service,
                "node": LiveVerifierService(name="node", base_url=server.base_url, client=client),
                "go": LiveVerifierService(name="go", base_url=server.base_url, client=client),
            }
        )
        descriptor = service.descriptor(nonce="nonce-3", audience="https://verifier.example/python")
        submitted = client.submit_vp("vp.jwt", audience=descriptor["aud"], nonce=descriptor["nonce"])
        artifacts = {
            "verifierDescriptor": descriptor,
            "presentationTx": {
                "d": "EPresTx",
                "state": "submitted",
                "aud": descriptor["aud"],
                "nonce": descriptor["nonce"],
                "submissionState": "submitted",
                "submissionEndpoint": descriptor["submissionEndpoint"],
                "verifierResponse": submitted,
            },
        }

        evidence = services.collect_after_keria(artifacts).to_dict()

    assert evidence["accepted"] is True
    assert evidence["checks"][0]["name"] == "python"
    assert evidence["checks"][0]["details"]["operation"]["done"] is True
    assert evidence["checks"][0]["details"]["requestBinding"]["audMatches"] is True
    assert evidence["checks"][0]["details"]["requestBinding"]["nonceMatches"] is True


def test_service_set_requires_all_language_verifiers():
    """Acceptance service sets must include Python, Node, and Go verifier URLs."""
    services = LiveVerifierServiceSet({"python": LiveVerifierService(name="python", base_url="http://127.0.0.1:8788")})

    try:
        services.require_complete()
    except ValueError as exc:
        assert "missing live verifier services: node, go" in str(exc)
    else:
        raise AssertionError("incomplete live verifier service set was accepted")
