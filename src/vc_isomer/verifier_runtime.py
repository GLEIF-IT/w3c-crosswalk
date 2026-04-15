"""Cooperative HIO runtime for long-running verifier operations.

The verifier service never performs outbound HTTP inside Falcon handlers. Those
handlers only submit operation records. This module owns the background doers
that claim pending records, perform DID/status fetches cooperatively, and write
terminal results back to the operation store.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hio.base import doing
from keri.app import httping

from .constants import VERIFY_PAIR_OPERATION, VERIFY_VC_OPERATION, VERIFY_VP_OPERATION
from .didwebs import DidWebsClient, DidWebsResolutionError, resolution_url
from .longrunning import OperationMonitor
from .runtime_http import Clienter, JsonRequestDoer, JsonResponse
from .status import HttpStatusResolver
from .verifier import PreparedVcToken, PreparedVpToken, VerificationEngine, VerificationResult


@dataclass(frozen=True)
class VerificationRuntimeError(RuntimeError):
    """Terminal operation error raised while executing one verifier job."""

    # HTTP-style error code written to the failed operation resource.
    code: int
    # Human-readable terminal failure message returned by __str__.
    message: str
    # Optional domain details such as token parse errors, DID URL, HTTP status, or verifier errors.
    details: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message


class VerificationJobDoer(doing.DoDoer):
    """Execute one verifier operation cooperatively to terminal state."""

    def __init__(
        self,
        *,
        monitor: OperationMonitor,
        operation_name: str,
        resolver_base_url: str,
        tock: float = 0.03125,
    ):
        self.monitor = monitor
        self.operation_name = operation_name
        self.resolver_base_url = resolver_base_url.rstrip("/")
        self.clienter = Clienter()
        self.engine = VerificationEngine()
        super().__init__(doers=[self.clienter, doing.doify(self.run)], tock=tock)

    def run(self, tymth=None, tock=0.0, **kwa):
        """Claim one pending record, execute it, and persist its terminal state."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        self.monitor.mark_running(self.operation_name)
        try:
            record = self.monitor.require_record(self.operation_name)
            request = record.metadata.get("request", {})
            result = yield from self._dispatch(record.type, request)
        except VerificationRuntimeError as exc:
            self.monitor.fail(
                self.operation_name,
                code=exc.code,
                message=exc.message,
                details=exc.details,
            )
            return True
        except Exception as exc:  # pragma: no cover - catastrophic runtime failures are integration-covered
            self.monitor.fail(
                self.operation_name,
                code=500,
                message=str(exc),
                details={"exception": type(exc).__name__},
            )
            return True

        self.monitor.complete(self.operation_name, result.to_dict())
        return True

    def _dispatch(self, op_type: str, request: dict[str, Any]):
        """Route one stored operation request to its verifier workflow."""
        if op_type == VERIFY_VC_OPERATION:
            return (yield from self._verify_vc_request(request))
        if op_type == VERIFY_VP_OPERATION:
            return (yield from self._verify_vp_request(request))
        if op_type == VERIFY_PAIR_OPERATION:
            return (yield from self._verify_pair_request(request))
        raise VerificationRuntimeError(code=400, message=f"unsupported verification operation type {op_type!r}")

    def _verify_vc_request(self, request: dict[str, Any]):
        """Execute one VC verification request to completion."""
        token = self._require_string(request, "token")
        return (yield from self._verify_vc_token(token))

    def _verify_pair_request(self, request: dict[str, Any]):
        """Execute one isomer pair verification request to completion."""
        token = self._require_string(request, "token")
        acdc = request.get("acdc")
        if not isinstance(acdc, dict):
            raise VerificationRuntimeError(code=400, message="verify pair requires an `acdc` object")
        vc_result = yield from self._verify_vc_token(token)
        result = self.engine.evaluate_isomer_pair(acdc, vc_result)
        return result

    def _verify_vp_request(self, request: dict[str, Any]):
        """Execute one VP verification request, including nested VC evaluation."""
        token = self._require_string(request, "token")
        prepared = self.engine.prepare_vp_token(token)
        self._raise_on_prepare_errors(prepared.errors, kind="vp+jwt")

        method = yield from self._resolve_method(
            did=prepared.holder,
            kid=prepared.header.get("kid", ""),
            label="holder",
        )

        nested_results = []
        for vc_token in prepared.vc_tokens:
            nested_results.append((yield from self._verify_vc_token(vc_token)))

        result = self.engine.evaluate_prepared_vp(prepared, method=method, nested_results=nested_results)
        return result

    def _verify_vc_token(self, token: str):
        """Prepare and evaluate one VC token, fetching its dependencies cooperatively."""
        prepared = self.engine.prepare_vc_token(token)
        self._raise_on_prepare_errors(prepared.errors, kind="vc+jwt")

        method = yield from self._resolve_method(
            did=prepared.issuer,
            kid=prepared.header.get("kid", ""),
            label="issuer",
        )
        status_doc = None
        if prepared.status_url:
            status_doc = yield from self._fetch_status(prepared.status_url)

        result = self.engine.evaluate_prepared_vc(prepared, method=method, status_doc=status_doc)
        return result

    def _resolve_method(self, *, did: str | None, kid: str, label: str):
        """Resolve one DID document and return the requested verification method."""
        if not did:
            raise VerificationRuntimeError(code=400, message=f"missing {label}")

        url = resolution_url(self.resolver_base_url, did)
        response = yield from self._request_json(method="GET", url=url)
        try:
            resolution = DidWebsClient.parse_resolution(did, response)
        except DidWebsResolutionError as exc:
            raise VerificationRuntimeError(
                code=response.status if response.status >= 400 else 502,
                message=str(exc),
                details={"did": did, "httpStatus": response.status},
            ) from exc

        try:
            return DidWebsClient.find_verification_method(resolution.did_document, kid)
        except DidWebsResolutionError:
            return None

    def _fetch_status(self, url: str):
        """Fetch one credential-status document cooperatively."""
        response = yield from self._request_json(method="GET", url=url)
        try:
            status_doc = HttpStatusResolver.parse_response(url, response)
        except RuntimeError as exc:
            raise VerificationRuntimeError(
                code=response.status if response.status >= 400 else 502,
                message=str(exc),
                details={"url": url, "httpStatus": response.status},
            ) from exc
        return status_doc

    def _request_json(self, *, method: str, url: str, body: Any | None = None):
        """Run one outbound HTTP request as a child doer and yield until it completes."""
        request_doer = JsonRequestDoer(
            method=method,
            url=url,
            body=body,
            clienter=self.clienter,
            timeout=10.0,
            tock=self.tock,
        )
        self.extend([request_doer])
        try:
            while request_doer.response is None and request_doer.error is None:
                yield self.tock
            if request_doer.error is not None:
                raise VerificationRuntimeError(
                    code=504,
                    message=str(request_doer.error),
                    details={
                        "url": url,
                        "method": method,
                        "effective_path": request_doer.error.effective_path,
                    },
                )
            return request_doer.response
        finally:
            if request_doer in self.doers:
                self.remove([request_doer])

    @staticmethod
    def _require_string(body: dict[str, Any], field: str) -> str:
        """Load one required string field from an operation request body."""
        value = body.get(field)
        if not isinstance(value, str) or not value.strip():
            raise VerificationRuntimeError(code=400, message=f"verification request requires `{field}`")
        return value

    @staticmethod
    def _raise_on_prepare_errors(errors: list[str], *, kind: str) -> None:
        """Promote token-prepare failures to terminal failed operations."""
        if errors:
            raise VerificationRuntimeError(
                code=400,
                message=f"invalid {kind}",
                details={"errors": errors},
            )


class VerificationManagerDoer(doing.DoDoer):
    """Watch the operation store and launch verification jobs for pending work."""

    def __init__(self, *, monitor: OperationMonitor, resolver_base_url: str, tock: float = 0.03125):
        self.monitor = monitor
        self.resolver_base_url = resolver_base_url
        self.active: dict[str, VerificationJobDoer] = {}
        super().__init__(doers=[doing.doify(self.manage)], always=True, tock=tock)

    def manage(self, tymth=None, tock=0.0, **kwa):
        """Continuously claim pending work and retire completed child jobs."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self._launch_pending_jobs()
            self._reap_finished_jobs()
            yield self.tock

    def exit(self, deeds=None):
        """Close child doers and the underlying operation store on shutdown."""
        try:
            super().exit(deeds=deeds)
        finally:
            if deeds is None:
                self.monitor.close()

    def _launch_pending_jobs(self) -> None:
        """Start one child job doer for each unclaimed pending/running record."""
        records = self.monitor.list_records(states={self.monitor.PENDING, self.monitor.RUNNING})
        for record in records:
            name = self.monitor.op_name(record)
            if name in self.active:
                continue
            job = VerificationJobDoer(
                monitor=self.monitor,
                operation_name=name,
                resolver_base_url=self.resolver_base_url,
                tock=self.tock,
            )
            self.active[name] = job
            self.extend([job])

    def _reap_finished_jobs(self) -> None:
        """Remove completed child jobs from the manager's active set."""
        finished = [name for name, job in self.active.items() if job.done]
        for name in finished:
            job = self.active.pop(name)
            if job in self.doers:
                self.remove([job])
