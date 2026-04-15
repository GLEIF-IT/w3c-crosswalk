"""Runtime tests for cooperative HIO HTTP client/server helpers."""

from __future__ import annotations

import socket

import falcon
from vc_isomer.runtime_http import Clienter, JsonRequestDoer, setup_server_doers

from tests.integration.helpers import run_doers_until


class EchoResource:
    """Echo request media so the requester test can assert round-trip behavior."""

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.media = {"echo": req.get_media()}


def test_json_request_doer_round_trips_against_hio_server():
    """Send one JSON request through cooperative HIO clienting to an HIO-hosted Falcon app."""
    app = falcon.App()
    app.add_route("/echo", EchoResource())
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    _server, server_doers = setup_server_doers(host="127.0.0.1", port=port, app=app)
    clienter = Clienter()
    request_doer = JsonRequestDoer(
        method="POST",
        url=f"http://127.0.0.1:{port}/echo",
        body={"hello": "world"},
        clienter=clienter,
    )

    run_doers_until(
        "cooperative HIO JSON request",
        [*server_doers, clienter, request_doer],
        timeout=1.5,
        ready=lambda: request_doer.response is not None,
        observe=lambda: {
            "response": request_doer.response.status if request_doer.response else None,
            "error": str(request_doer.error) if request_doer.error else None,
        },
    )

    assert request_doer.response is not None
    assert request_doer.response.status == 200
    assert request_doer.response.data == {"echo": {"hello": "world"}}
