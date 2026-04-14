"""HTTP service handlers for status and verification endpoints.

These handlers intentionally keep protocol logic thin. They decode requests,
delegate to the status store or verifier, and return JSON responses suitable
for the local demo stack and integration tests.

They should be read as transport adapters, not as the place where status or
verification semantics are defined.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .common import load_json_file
from .status import JsonFileStatusStore
from .verifier import CrosswalkVerifier


class StatusServiceHandler(BaseHTTPRequestHandler):
    """Serve health and credential status resources from a JSON status store.

    The handler publishes projected status state for W3C consumers. It does not
    derive status truth independently of the backing store.
    """

    store: JsonFileStatusStore
    base_url: str

    def _status_record(self):
        """Return the requested status record for a `/statuses/{said}` path."""
        if not self.path.startswith("/statuses/"):
            return None
        credential_said = self.path.rsplit("/", 1)[-1]
        return credential_said, self.store.get(credential_said)

    def do_GET(self) -> None:  # noqa: N802
        """Handle health and credential status lookups."""
        if self.path == "/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "status"})
            return

        status_record = self._status_record()
        if status_record is not None:
            credential_said, record = status_record
            if record is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"unknown credential SAID: {credential_said}"})
                return
            self._send_json(HTTPStatus.OK, record.as_status_resource(self.base_url))
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        """Handle revocation updates for projected status records."""
        if self.path.startswith("/statuses/") and self.path.endswith("/revoke"):
            credential_said = self.path.split("/")[2]
            record = self.store.set_revoked(credential_said, True, reason="revoked via status service")
            self._send_json(HTTPStatus.OK, record.as_status_resource(self.base_url))
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        """Suppress default request logging in test and local service runs."""
        return

    def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        """Serialize and return a JSON response body."""
        payload = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class VerifierServiceHandler(BaseHTTPRequestHandler):
    """Expose VC, VP, and dual crosswalk verification over HTTP."""

    verifier: CrosswalkVerifier

    def _read_json_body(self) -> dict[str, Any]:
        """Read and decode one request JSON body."""
        content_length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(content_length) or b"{}")

    def _crosswalk_acdc(self, body: dict[str, Any]) -> dict[str, Any]:
        """Load the ACDC input for crosswalk verification from inline JSON or a file path."""
        if "acdcPath" in body:
            return load_json_file(Path(body["acdcPath"]))
        return body["acdc"]

    def do_GET(self) -> None:  # noqa: N802
        """Handle service health checks."""
        if self.path == "/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "verifier"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        """Route verification requests to the appropriate verifier method."""
        body = self._read_json_body()
        if self.path == "/verify/vc-jwt":
            self._send_json(HTTPStatus.OK, self.verifier.verify_vc_jwt(body["token"]).to_dict())
            return
        if self.path == "/verify/vp-jwt":
            self._send_json(HTTPStatus.OK, self.verifier.verify_vp_jwt(body["token"]).to_dict())
            return
        if self.path == "/verify/crosswalk":
            acdc = self._crosswalk_acdc(body)
            self._send_json(HTTPStatus.OK, self.verifier.verify_crosswalk_pair(acdc, body["token"]).to_dict())
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        """Suppress default request logging in test and local service runs."""
        return

    def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        """Serialize and return a JSON response body."""
        payload = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve_status_service(*, host: str, port: int, store_path: str, base_url: str) -> None:
    """Start the threaded status service and block forever."""
    StatusServiceHandler.store = JsonFileStatusStore(store_path)
    StatusServiceHandler.base_url = base_url
    with ThreadingHTTPServer((host, port), StatusServiceHandler) as server:
        server.serve_forever()


def serve_verifier_service(*, host: str, port: int, verifier: CrosswalkVerifier) -> None:
    """Start the threaded verifier service and block forever."""
    VerifierServiceHandler.verifier = verifier
    with ThreadingHTTPServer((host, port), VerifierServiceHandler) as server:
        server.serve_forever()
