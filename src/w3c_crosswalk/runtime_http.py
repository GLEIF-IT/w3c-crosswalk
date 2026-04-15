"""HIO HTTP runtime helpers for inbound Falcon serving and outbound JSON clienting.

The runtime rule for this package is simple:
- long-lived HTTP services are Falcon apps hosted by HIO servers
- outbound HTTP fetches use HIO clienting
- helper code returns doers and yields cooperatively while requests complete

This module is the transport seam that keeps that rule consistent.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping
from urllib import parse
from urllib.parse import urlparse

from hio.base import doing
from hio.core import http
from keri.app import httping


@dataclass(frozen=True)
class JsonResponse:
    """Structured result returned by one outbound JSON HTTP request."""

    # HTTP status code returned by the peer.
    status: int
    # HTTP reason phrase when HIO exposes one.
    reason: str | None
    # Response headers normalized into a plain dictionary.
    headers: dict[str, Any]
    # Parsed JSON body when parsing succeeds; otherwise None.
    data: Any
    # Raw response body bytes retained for diagnostics and non-JSON failure handling.
    body: bytes


@dataclass(frozen=True)
class JsonRequestError(RuntimeError):
    """Terminal failure while executing one outbound JSON request."""

    # Human-readable error message returned by __str__.
    message: str
    # Full URL originally requested by the outbound HIO client.
    url: str
    # HTTP method used for the failed request.
    method: str
    # Path/query actually sent to HIO after URL normalization.
    effective_path: str | None = None

    def __str__(self) -> str:
        return self.message


class OpenedServerDoer(http.ServerDoer):
    """Server doer for servers already opened during setup.

    We open servers before entering the long-running doist so startup failures
    surface immediately in the launching process instead of later as a silent
    port timeout.
    """

    def enter(self):
        """Skip reopen because setup already bound the socket."""
        return


class Clienter(httping.Clienter):
    """Local Clienter wrapper that preserves path targets when no query exists.

    KERIpy's current ``Clienter.request`` always appends ``?{query}``, which can
    degrade the effective request target under HIO when ``query`` is empty. This
    wrapper keeps the KERIpy lifecycle model but normalizes the request target
    to ``path`` or ``path?query`` as appropriate.
    """

    def request(self, method, url, body=None, headers=None):  # noqa: D401
        purl = parse.urlparse(url)

        try:
            client = http.clienting.Client(
                scheme=purl.scheme,
                hostname=purl.hostname,
                port=purl.port,
                portOptional=True,
            )
        except Exception as e:
            print(f"error establishing client connection={e}")
            return None

        if hasattr(body, "encode"):
            body = body.encode("utf-8")

        path = purl.path or "/"
        if purl.query:
            path = f"{path}?{purl.query}"

        client.request(
            method=method,
            path=path,
            qargs=None,
            headers=headers,
            body=body,
        )

        client_doer = http.clienting.ClientDoer(client=client)
        self.extend([client_doer])
        self.clients.append((client, client_doer, httping.helping.nowUTC()))

        return client


class JsonRequestDoer(doing.DoDoer):
    """One cooperative outbound JSON request driven by HIO clienting.

    The doer requires a parent-owned `Clienter`. This keeps outbound HTTP on a
    single explicit KERIpy-style lifecycle.
    """

    def __init__(
        self,
        *,
        method: str,
        url: str,
        body: Any | None = None,
        headers: Mapping[str, str] | None = None,
        clienter: Clienter,
        timeout: float = 10.0,
        tock: float = 0.03125,
    ):
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(f"expected absolute URL for JSON request, got: {url}")

        self.url = url
        self.parsed = parsed
        self.method = method.upper()
        self.clienter = clienter
        if self.clienter is None:
            raise ValueError("JsonRequestDoer requires a parent-owned Clienter")
        self.timeout = timeout
        request_headers = dict(headers or {})
        lowered = {name.lower(): value for name, value in request_headers.items()}
        if "accept" not in lowered:
            request_headers["Accept"] = "application/json"
        if body is not None and "content-type" not in lowered:
            request_headers["Content-Type"] = "application/json"

        self.request_headers = request_headers
        self.request_body = b"" if body is None else json.dumps(body).encode("utf-8")
        self.response: JsonResponse | None = None
        self.error: JsonRequestError | None = None
        self.effective_path: str | None = None
        self.client = None
        super().__init__(doers=[doing.doify(self.request_do)], tock=tock)

    def request_do(self, tymth=None, tock=0.0, **kwa):
        """Send one request and yield until a response is available."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)
        deadline = self.tyme + self.timeout

        try:
            self.client = self.clienter.request(
                method=self.method,
                url=self.url,
                headers=self.request_headers,
                body=self.request_body,
            )
            if self.client is None:
                self.error = JsonRequestError(
                    message=f"failed to establish HTTP client for {self.method} {self.url}",
                    url=self.url,
                    method=self.method,
                )
                return True

            self.effective_path = _effective_request_path(self.client)

            while not self.client.responses:
                if self.tyme >= deadline:
                    self.error = JsonRequestError(
                        message=f"timed out waiting for HTTP response to {self.method} {self.url}",
                        url=self.url,
                        method=self.method,
                        effective_path=self.effective_path,
                    )
                    return True
                yield self.tock

            response = self.client.respond()
            self.response = JsonResponse(
                status=response.status,
                reason=response.reason,
                headers=_response_headers(response.headers),
                data=_response_data(response),
                body=bytes(response.body),
            )
            return True
        except Exception as exc:
            self.error = JsonRequestError(
                message=str(exc),
                url=self.url,
                method=self.method,
                effective_path=self.effective_path,
            )
            return True
        finally:
            if self.client is not None:
                self.clienter.remove(self.client)
                self.client = None


def create_http_server(*, host: str, port: int, app) -> http.Server:
    """Create one HIO HTTP server for a Falcon app."""
    return http.Server(host=host, port=port, app=app)


def setup_server_doers(*, host: str, port: int, app) -> tuple[http.Server, list[doing.Doer]]:
    """Create, open, and wrap one HIO HTTP server for long-running service use."""
    server = create_http_server(host=host, port=port, app=app)
    if not server.reopen():
        raise RuntimeError(f"cannot create http server on port {port}")
    return server, [OpenedServerDoer(server=server)]


def _response_headers(headers: Any) -> dict[str, Any]:
    """Normalize HIO response headers into a regular dictionary."""
    if hasattr(headers, "items"):
        return dict(headers.items())
    return dict(headers)


def _response_data(response) -> Any:
    """Return decoded JSON from a HIO response or raise on malformed content."""
    if response.data is not None:
        return response.data
    if not response.body:
        return None
    return json.loads(bytes(response.body).decode("utf-8"))


def _effective_request_path(client) -> str | None:
    """Return the normalized request target HIO will send for one client."""
    requester = getattr(client, "requester", None)
    if requester is None:
        return None
    path = getattr(requester, "path", None)
    qargs = getattr(requester, "qargs", None)
    if qargs:
        from urllib.parse import urlencode

        return f"{path}?{urlencode(qargs, doseq=True)}"
    return path
