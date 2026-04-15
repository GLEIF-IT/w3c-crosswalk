"""Cooperative HIO doers for the verifier operation API.

This module intentionally does not expose a blocking client. Top-level callers
such as the CLI and integration tests should compose these doers under one
explicit process or test `Doist`, just like KERIpy CLI commands do.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any
from urllib.parse import urlencode

from hio.base import doing

from .constants import (
    OPERATIONS_ROUTE_PREFIX,
    VERIFY_PAIR_ROUTE,
    VERIFY_VC_ROUTE,
    VERIFY_VP_ROUTE,
)
from .runtime_http import Clienter


@dataclass(frozen=True)
class VerifierApiError(RuntimeError):
    """Raised when the verifier API returns an unexpected response."""

    message: str

    def __str__(self) -> str:
        return self.message


class VerifierApiDoDoer(doing.DoDoer):
    """Base verifier API workflow doer with one explicit sibling `Clienter`."""

    def __init__(
        self,
        *,
        base_url: str,
        clienter: Clienter | None = None,
        tock: float = 0.03125,
    ):
        self.base_url = base_url.rstrip("/")
        self.error: Exception | None = None
        self.clienter = clienter if clienter is not None else Clienter()
        super().__init__(doers=[self.clienter, doing.doify(self.run, tock=tock)], tock=tock)

    def run(self, tymth=None, tock=0.0, **kwa):
        """Subclasses implement the cooperative API workflow."""
        raise NotImplementedError

    def _close_clienter(self) -> None:
        """Remove the owned client manager once the workflow reaches a terminal state."""
        if self.clienter in self.doers:
            self.remove([self.clienter])

    def _request_json(
        self,
        *,
        method: str,
        path: str,
        expected_status: int,
        body: dict[str, Any] | None = None,
        step: float,
        headers: dict[str, str] | None = None,
    ):
        """Send one cooperative API request and validate the response status."""
        timeout = (
            getattr(self, "post_timeout", 30.0)
            if method.upper() == "POST"
            else getattr(self, "get_timeout", 10.0)
        )
        request_headers = {
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if body is not None else {}),
            **(headers or {}),
        }
        client = self.clienter.request(
            method=method,
            url=f"{self.base_url}{path}",
            body=None if body is None else json.dumps(body).encode("utf-8"),
            headers=request_headers,
        )
        if client is None:
            raise VerifierApiError(
                f"verifier API request failed for {method} {path}: could not establish HTTP client",
            )

        deadline = self.tyme + timeout
        try:
            while not client.responses:
                if self.tyme >= deadline:
                    raise VerifierApiError(
                        f"verifier API request failed for {method} {path}: "
                        "timed out waiting for HTTP response"
                    )
                yield step
            response = client.respond()
        finally:
            self.clienter.remove(client)

        if response.status != expected_status:
            raise VerifierApiError(
                f"verifier API returned HTTP {response.status} for {method} {path}: {self._response_data(response)!r}",
            )

        return self._response_data(response)

    @staticmethod
    def _step(tock: float) -> float:
        """Use a stable worker cadence without mutating the parent DoDoer."""
        return tock if tock and tock > 0.0 else 0.03125

    @staticmethod
    def _response_data(response) -> Any:
        """Decode one HIO response body as JSON when needed."""
        if response.data is not None:
            return response.data
        if not response.body:
            return None
        return json.loads(bytes(response.body).decode("utf-8"))


class SubmitVerificationDoDoer(VerifierApiDoDoer):
    """Submit one VC, VP, or pair verification request."""

    def __init__(
        self,
        *,
        base_url: str,
        route: str,
        body: dict[str, Any],
        clienter: Clienter | None = None,
        tock: float = 0.03125,
    ):
        self.route = route
        self.body = body
        self.operation: dict[str, Any] | None = None
        super().__init__(base_url=base_url, clienter=clienter, tock=tock)

    def run(self, tymth=None, tock=0.0, **kwa):
        """Submit one verification request and store the pending operation."""
        try:
            step = self._step(tock)
            result = yield from self._request_json(
                method="POST",
                path=self.route,
                expected_status=202,
                body=self.body,
                step=step,
            )
            if not isinstance(result, dict):
                raise VerifierApiError("verification submission did not return an operation object")
            self.operation = result
            return True
        except Exception as exc:
            self.error = exc
            return True
        finally:
            self._close_clienter()


class WaitOperationDoDoer(VerifierApiDoDoer):
    """Poll one operation resource cooperatively until it reaches terminal state."""

    def __init__(
        self,
        *,
        base_url: str,
        name: str,
        timeout: float,
        poll_interval: float,
        clienter: Clienter | None = None,
        tock: float = 0.03125,
    ):
        self.name = name
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.operation: dict[str, Any] | None = None
        self.timeout_error: TimeoutError | None = None
        super().__init__(base_url=base_url, clienter=clienter, tock=tock)

    def run(self, tymth=None, tock=0.0, **kwa):
        """Poll the operation resource without blocking the surrounding doist."""
        try:
            step = self._step(tock)
            deadline = self.tyme + self.timeout

            while True:
                result = yield from self._request_json(
                    method="GET",
                    path=f"{OPERATIONS_ROUTE_PREFIX}/{self.name}",
                    expected_status=200,
                    step=step,
                )
                if not isinstance(result, dict):
                    raise VerifierApiError("operation fetch did not return an operation object")
                self.operation = result
                if result.get("done") is True:
                    return True
                if self.tyme >= deadline:
                    self.timeout_error = TimeoutError(
                        f"timed out waiting for operation {self.name}; last_seen={result!r}"
                    )
                    return True
                yield self.poll_interval
        except Exception as exc:
            self.error = exc
            return True
        finally:
            self._close_clienter()


class VerifyOperationDoDoer(VerifierApiDoDoer):
    """Submit one verification request and wait for the terminal operation."""

    def __init__(
        self,
        *,
        base_url: str,
        route: str,
        body: dict[str, Any],
        timeout: float,
        poll_interval: float,
        clienter: Clienter | None = None,
        tock: float = 0.03125,
    ):
        self.route = route
        self.body = body
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.submitted_operation: dict[str, Any] | None = None
        self.operation: dict[str, Any] | None = None
        self.timeout_error: TimeoutError | None = None
        super().__init__(base_url=base_url, clienter=clienter, tock=tock)

    def run(self, tymth=None, tock=0.0, **kwa):
        """Submit the request, then poll the operation resource cooperatively."""
        try:
            step = self._step(tock)

            result = yield from self._request_json(
                method="POST",
                path=self.route,
                expected_status=202,
                body=self.body,
                step=step,
            )
            if not isinstance(result, dict):
                raise VerifierApiError("verification submission did not return an operation object")
            self.submitted_operation = result

            name = self._operation_name(result)
            deadline = self.tyme + self.timeout
            while True:
                operation = yield from self._request_json(
                    method="GET",
                    path=f"{OPERATIONS_ROUTE_PREFIX}/{name}",
                    expected_status=200,
                    step=step,
                )
                if not isinstance(operation, dict):
                    raise VerifierApiError("operation fetch did not return an operation object")
                self.operation = operation
                if operation.get("done") is True:
                    return True
                if self.tyme >= deadline:
                    self.timeout_error = TimeoutError(
                        f"timed out waiting for operation {name}; last_seen={operation!r}"
                    )
                    return True
                yield self.poll_interval
        except Exception as exc:
            self.error = exc
            return True
        finally:
            self._close_clienter()

    @staticmethod
    def _operation_name(operation: dict[str, Any] | None) -> str:
        """Load one required operation resource name from a submission body."""
        if not isinstance(operation, dict):
            raise VerifierApiError("verification submission did not return an operation object")
        name = operation.get("name")
        if not isinstance(name, str) or not name:
            raise VerifierApiError("verification submission did not return an operation name")
        return name


class ListOperationsDoDoer(VerifierApiDoDoer):
    """Fetch the verifier operation collection cooperatively."""

    def __init__(
        self,
        *,
        base_url: str,
        op_type: str | None = None,
        clienter: Clienter | None = None,
        tock: float = 0.03125,
    ):
        self.op_type = op_type
        self.operations: list[dict[str, Any]] | None = None
        super().__init__(base_url=base_url, clienter=clienter, tock=tock)

    def run(self, tymth=None, tock=0.0, **kwa):
        """Fetch and store the current operation collection."""
        try:
            step = self._step(tock)
            path = OPERATIONS_ROUTE_PREFIX
            if self.op_type:
                path = f"{path}?{urlencode({'type': self.op_type})}"
            result = yield from self._request_json(method="GET", path=path, expected_status=200, step=step)
            if not isinstance(result, list):
                raise VerifierApiError("operation collection did not return a JSON list")
            self.operations = result
            return True
        except Exception as exc:
            self.error = exc
            return True
        finally:
            self._close_clienter()


class GetOperationDoDoer(VerifierApiDoDoer):
    """Fetch one operation resource cooperatively."""

    def __init__(
        self,
        *,
        base_url: str,
        name: str,
        clienter: Clienter | None = None,
        tock: float = 0.03125,
    ):
        self.name = name
        self.operation: dict[str, Any] | None = None
        super().__init__(base_url=base_url, clienter=clienter, tock=tock)

    def run(self, tymth=None, tock=0.0, **kwa):
        """Fetch and store one operation resource."""
        try:
            step = self._step(tock)
            result = yield from self._request_json(
                method="GET",
                path=f"{OPERATIONS_ROUTE_PREFIX}/{self.name}",
                expected_status=200,
                step=step,
            )
            if not isinstance(result, dict):
                raise VerifierApiError("operation fetch did not return an operation object")
            self.operation = result
            return True
        except Exception as exc:
            self.error = exc
            return True
        finally:
            self._close_clienter()


class DeleteOperationDoDoer(VerifierApiDoDoer):
    """Delete one operation resource cooperatively."""

    def __init__(
        self,
        *,
        base_url: str,
        name: str,
        clienter: Clienter | None = None,
        tock: float = 0.03125,
    ):
        self.name = name
        self.deleted = False
        super().__init__(base_url=base_url, clienter=clienter, tock=tock)

    def run(self, tymth=None, tock=0.0, **kwa):
        """Delete the target operation resource."""
        try:
            step = self._step(tock)
            yield from self._request_json(
                method="DELETE",
                path=f"{OPERATIONS_ROUTE_PREFIX}/{self.name}",
                expected_status=204,
                step=step,
            )
            self.deleted = True
            return True
        except Exception as exc:
            self.error = exc
            return True
        finally:
            self._close_clienter()


def verify_vc_doer(
    *,
    base_url: str,
    token: str,
    timeout: float,
    poll_interval: float,
    clienter: Clienter | None = None,
    tock: float = 0.03125,
) -> VerifyOperationDoDoer:
    """Create one cooperative VC verification doer."""
    return VerifyOperationDoDoer(
        base_url=base_url,
        route=VERIFY_VC_ROUTE,
        body={"token": token},
        timeout=timeout,
        poll_interval=poll_interval,
        clienter=clienter,
        tock=tock,
    )


def verify_vp_doer(
    *,
    base_url: str,
    token: str,
    timeout: float,
    poll_interval: float,
    clienter: Clienter | None = None,
    tock: float = 0.03125,
) -> VerifyOperationDoDoer:
    """Create one cooperative VP verification doer."""
    return VerifyOperationDoDoer(
        base_url=base_url,
        route=VERIFY_VP_ROUTE,
        body={"token": token},
        timeout=timeout,
        poll_interval=poll_interval,
        clienter=clienter,
        tock=tock,
    )


def verify_pair_doer(
    *,
    base_url: str,
    token: str,
    acdc: dict[str, Any],
    timeout: float,
    poll_interval: float,
    clienter: Clienter | None = None,
    tock: float = 0.03125,
) -> VerifyOperationDoDoer:
    """Create one cooperative crosswalk-pair verification doer."""
    return VerifyOperationDoDoer(
        base_url=base_url,
        route=VERIFY_PAIR_ROUTE,
        body={"token": token, "acdc": acdc},
        timeout=timeout,
        poll_interval=poll_interval,
        clienter=clienter,
        tock=tock,
    )


def submit_verify_vc_doer(
    *,
    base_url: str,
    token: str,
    clienter: Clienter | None = None,
    tock: float = 0.03125,
) -> SubmitVerificationDoDoer:
    """Create one cooperative VC submission doer."""
    return SubmitVerificationDoDoer(
        base_url=base_url,
        route=VERIFY_VC_ROUTE,
        body={"token": token},
        clienter=clienter,
        tock=tock,
    )


def submit_verify_vp_doer(
    *,
    base_url: str,
    token: str,
    clienter: Clienter | None = None,
    tock: float = 0.03125,
) -> SubmitVerificationDoDoer:
    """Create one cooperative VP submission doer."""
    return SubmitVerificationDoDoer(
        base_url=base_url,
        route=VERIFY_VP_ROUTE,
        body={"token": token},
        clienter=clienter,
        tock=tock,
    )


def submit_verify_pair_doer(
    *,
    base_url: str,
    token: str,
    acdc: dict[str, Any],
    clienter: Clienter | None = None,
    tock: float = 0.03125,
) -> SubmitVerificationDoDoer:
    """Create one cooperative pair submission doer."""
    return SubmitVerificationDoDoer(
        base_url=base_url,
        route=VERIFY_PAIR_ROUTE,
        body={"token": token, "acdc": acdc},
        clienter=clienter,
        tock=tock,
    )
