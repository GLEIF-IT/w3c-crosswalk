"""Live verifier-service adapters for headless W3C E2E evidence.

These adapters intentionally speak the public HTTP operation contract exposed
by each Isomer verifier service. They do not run CLI commands, import verifier
functions directly, or accept verifier test doubles for E2E acceptance.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from uuid import uuid4


VERIFY_VC_ROUTE = "/verify/vc"
VERIFY_VP_ROUTE = "/verify/vp"
OPERATIONS_ROUTE = "/operations"
HEALTH_ROUTE = "/healthz"
VP_JWT_FORMAT = "vp+jwt"


class VerifierServiceError(RuntimeError):
    """Raised when a live verifier service cannot satisfy the HTTP contract."""


@dataclass
class VerifierEvidence:
    """Verifier result bundle collected from live services."""

    accepted: bool
    checks: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable verifier evidence dictionary."""
        return asdict(self)


class VerifierServiceClient:
    """Blocking HTTP client for one live Isomer-compatible verifier service.

    The accepted contract is ``GET /healthz``, ``POST /verify/vc``,
    ``POST /verify/vp``, ``GET /operations``, and
    ``GET /operations/{name}``. Submissions return operation stubs; evidence is
    collected only after polling the service's operation document to terminal
    state.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        operation_timeout: float = 45.0,
        poll_interval: float = 0.25,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.operation_timeout = operation_timeout
        self.poll_interval = poll_interval

    def health(self) -> dict[str, Any]:
        """Fetch and validate the verifier health document."""
        body = self._request_json("GET", HEALTH_ROUTE, expected_status=200)
        if body.get("ok") is not True:
            raise VerifierServiceError(f"verifier health check failed for {self.base_url}: {body!r}")
        return body

    def submit_vc(self, token: str) -> dict[str, Any]:
        """Submit one VC-JWT and return the created operation document stub."""
        return self._request_json("POST", VERIFY_VC_ROUTE, body={"token": token}, expected_status=202)

    def submit_vp(self, token: str, *, audience: str | None = None, nonce: str | None = None) -> dict[str, Any]:
        """Submit one VP-JWT and return the created operation document stub."""
        body: dict[str, Any] = {"token": token}
        if audience is not None:
            body["audience"] = audience
        if nonce is not None:
            body["nonce"] = nonce
        return self._request_json("POST", VERIFY_VP_ROUTE, body=body, expected_status=202)

    def verify_vc(self, token: str) -> dict[str, Any]:
        """Submit one VC-JWT and wait for the terminal operation document."""
        return self.wait_operation(self._operation_name(self.submit_vc(token)))

    def verify_vp(self, token: str, *, audience: str | None = None, nonce: str | None = None) -> dict[str, Any]:
        """Submit one VP-JWT and wait for the terminal operation document."""
        return self.wait_operation(self._operation_name(self.submit_vp(token, audience=audience, nonce=nonce)))

    def operation(self, name: str) -> dict[str, Any]:
        """Fetch one verifier operation document."""
        return self._request_json("GET", f"{OPERATIONS_ROUTE}/{name}", expected_status=200)

    def operations(self, *, type: str | None = None) -> list[dict[str, Any]]:
        """Fetch verifier operation documents, optionally filtered by operation type."""
        path = OPERATIONS_ROUTE
        if type:
            path = f"{path}?{urlencode({'type': type})}"
        body = self._request_json("GET", path, expected_status=200)
        if not isinstance(body, list):
            raise VerifierServiceError(f"operation collection from {self.base_url} was not a JSON list: {body!r}")
        return body

    def wait_operation(
        self,
        name: str,
        *,
        timeout: float | None = None,
        poll_interval: float | None = None,
    ) -> dict[str, Any]:
        """Poll one operation until the live service reports terminal state.

        A verifier that accepts submissions but cannot expose a pollable
        operation is not compatible with the live-service E2E harness.
        """
        deadline = time.monotonic() + (self.operation_timeout if timeout is None else timeout)
        interval = self.poll_interval if poll_interval is None else poll_interval
        last: dict[str, Any] | None = None
        while True:
            last = self.operation(name)
            if last.get("done") is True:
                return last
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for verifier operation {name}; last_seen={last!r}")
            time.sleep(interval)

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        expected_status: int,
        body: dict[str, Any] | None = None,
    ) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                status = response.status
        except HTTPError as exc:
            raw = exc.read()
            raise VerifierServiceError(
                f"verifier service {self.base_url} returned HTTP {exc.code} for {method} {path}: "
                f"{_decode_response(raw)!r}"
            ) from exc
        except URLError as exc:
            raise VerifierServiceError(
                f"verifier service {self.base_url} was unreachable for {method} {path}: {exc.reason}"
            ) from exc

        payload = _decode_response(raw)
        if status != expected_status:
            raise VerifierServiceError(
                f"verifier service {self.base_url} returned HTTP {status} for {method} {path}: {payload!r}"
            )
        return payload

    @staticmethod
    def _operation_name(operation: dict[str, Any]) -> str:
        name = operation.get("name")
        if not isinstance(name, str) or not name:
            raise VerifierServiceError(f"verifier submission did not return an operation name: {operation!r}")
        return name


@dataclass
class LiveVerifierService:
    """One live verifier endpoint used by KERIA holder presentation txs."""

    name: str
    base_url: str
    submission_base_url: str | None = None
    audience: str | None = None
    label: str | None = None
    client: VerifierServiceClient | None = None
    response_path: str = VERIFY_VP_ROUTE

    def __post_init__(self) -> None:
        """Attach a default HTTP client when the caller did not provide one."""
        self.base_url = self.base_url.rstrip("/")
        if self.submission_base_url is not None:
            self.submission_base_url = self.submission_base_url.rstrip("/")
        if self.client is None:
            self.client = VerifierServiceClient(self.base_url)

    @property
    def response_uri(self) -> str:
        """Return the VP submission endpoint KERIA should call."""
        return f"{self.submission_base_url or self.base_url}{self.response_path}"

    @property
    def audience_uri(self) -> str:
        """Return the verifier audience URI bound into the holder VP-JWT."""
        return f"{self.base_url}{self.response_path}"

    def health(self) -> dict[str, Any]:
        """Fetch the live service health document."""
        return self.client.health()

    def descriptor(self, *, nonce: str | None = None, audience: str | None = None) -> dict[str, Any]:
        """Build a verifier request descriptor accepted by KERIA presentations.

        ``aud`` is bound into the VP-JWT. ``response_uri`` is where KERIA posts
        the signed VP. In Docker mode that URI may be container-internal while
        ``base_url`` remains the host URL used by this harness to poll evidence.
        """
        request_nonce = nonce or f"headless-{uuid4().hex}"
        request_audience = audience or self.audience or self.audience_uri
        return {
            "verifierId": self.name,
            "verifierLabel": self.label or f"{self.name} live verifier",
            "verifierOrigin": self.base_url,
            "origin": self.base_url,
            "format": VP_JWT_FORMAT,
            "formats": [VP_JWT_FORMAT],
            "aud": request_audience,
            "nonce": request_nonce,
            "response_uri": self.response_uri,
            "submissionEndpoint": self.response_uri,
        }

    def collect_after_keria(self, presentation_tx: dict[str, Any]) -> dict[str, Any]:
        """Collect acceptance evidence for a VP submission KERIA already made."""
        submission = presentation_tx.get("verifierResponse")
        check = {
            "name": self.name,
            "accepted": False,
            "details": {
                "presentationTx": _presentation_tx_summary(presentation_tx),
                "submission": submission,
            },
        }
        if not isinstance(submission, dict):
            check["details"]["error"] = "KERIA presentation transaction has no verifier service response"
            return check

        operation_name = submission.get("name")
        if isinstance(operation_name, str) and operation_name:
            operation = self.client.wait_operation(operation_name)
            response = operation.get("response") if isinstance(operation, dict) else None
            check["details"]["operation"] = operation
            check["accepted"] = _operation_accepted(operation)
            if isinstance(response, dict):
                check["details"]["response"] = response
            return check

        if submission.get("done") is True:
            check["accepted"] = _operation_accepted(submission)
            check["details"]["operation"] = submission
            return check

        check["details"]["error"] = "KERIA verifier response did not include a pollable operation name"
        return check


@dataclass
class LiveVerifierServiceSet:
    """Required Python, Node, and Go verifier services for acceptance evidence."""

    services: dict[str, LiveVerifierService] = field(default_factory=dict)

    REQUIRED = ("python", "node", "go")

    @classmethod
    def from_urls(
        cls,
        urls: dict[str, str],
        *,
        submission_urls: dict[str, str] | None = None,
    ) -> "LiveVerifierServiceSet":
        """Create a required service set from name-to-base-URL configuration."""
        submission_urls = submission_urls or {}
        return cls(
            {
                name: LiveVerifierService(
                    name=name,
                    base_url=base_url,
                    submission_base_url=submission_urls.get(name),
                )
                for name, base_url in urls.items()
            }
        )

    def require_complete(self) -> None:
        """Fail when a required live verifier service is not configured."""
        missing = [name for name in self.REQUIRED if name not in self.services]
        if missing:
            raise ValueError(f"missing live verifier services: {', '.join(missing)}")

    def healthcheck_all(self) -> dict[str, dict[str, Any]]:
        """Health-check every required live verifier service."""
        self.require_complete()
        return {name: self.services[name].health() for name in self.REQUIRED}

    def descriptor_for(
        self,
        name: str,
        *,
        nonce: str | None = None,
        audience: str | None = None,
    ) -> dict[str, Any]:
        """Build a KERIA presentation descriptor for one live service."""
        return self.services[name].descriptor(nonce=nonce, audience=audience)

    def collect_after_keria(self, artifacts: dict[str, Any]) -> VerifierEvidence:
        """Collect evidence for a single KERIA-submitted presentation transaction."""
        self.require_complete()
        descriptor = artifacts.get("verifierDescriptor")
        presentation_tx = artifacts.get("presentationTx")
        if not isinstance(descriptor, dict) or not isinstance(presentation_tx, dict):
            return VerifierEvidence(
                accepted=False,
                checks=[{
                    "name": "verifier-service-set",
                    "accepted": False,
                    "details": {"error": "artifacts must include verifierDescriptor and presentationTx objects"},
                }],
            )

        service = self._service_for_descriptor(descriptor)
        check = service.collect_after_keria(presentation_tx)
        _add_request_binding_details(check, descriptor, presentation_tx)
        return VerifierEvidence(accepted=bool(check["accepted"]), checks=[check])

    def collect_many_after_keria(self, artifacts_by_service: dict[str, dict[str, Any]]) -> VerifierEvidence:
        """Collect evidence for one KERIA-submitted presentation per service."""
        self.require_complete()
        checks: list[dict[str, Any]] = []
        for name in self.REQUIRED:
            artifacts = artifacts_by_service.get(name)
            if artifacts is None:
                checks.append({
                    "name": name,
                    "accepted": False,
                    "details": {"error": "missing KERIA presentation artifacts for live verifier service"},
                })
                continue
            evidence = self.collect_after_keria(artifacts)
            checks.extend(evidence.checks)
        return VerifierEvidence(accepted=all(check["accepted"] for check in checks), checks=checks)

    def _service_for_descriptor(self, descriptor: dict[str, Any]) -> LiveVerifierService:
        verifier_id = descriptor.get("verifierId")
        if isinstance(verifier_id, str) and verifier_id in self.services:
            return self.services[verifier_id]
        response_uri = descriptor.get("response_uri") or descriptor.get("submissionEndpoint")
        if isinstance(response_uri, str):
            for service in self.services.values():
                if response_uri.rstrip("/") == service.response_uri.rstrip("/"):
                    return service
        raise ValueError(f"verifier descriptor does not match a configured live service: {descriptor!r}")


def _decode_response(raw: bytes) -> Any:
    if not raw:
        return {}
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _operation_accepted(operation: dict[str, Any]) -> bool:
    if operation.get("done") is not True:
        return False
    if operation.get("error") is not None:
        return False
    response = operation.get("response")
    if isinstance(response, dict):
        return response.get("ok") is True or response.get("accepted") is True
    return True


def _presentation_tx_summary(tx: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": tx.get("d") or tx.get("presentTxId"),
        "state": tx.get("state"),
        "holderAid": tx.get("holderAid"),
        "holderDid": tx.get("holderDid"),
        "selectedCredentialId": tx.get("selectedCredentialId"),
        "aud": tx.get("aud"),
        "nonce": tx.get("nonce"),
        "submissionEndpoint": tx.get("submissionEndpoint"),
        "submissionState": tx.get("submissionState"),
    }


def _add_request_binding_details(
    check: dict[str, Any],
    descriptor: dict[str, Any],
    presentation_tx: dict[str, Any],
) -> None:
    details = check.setdefault("details", {})
    expected_aud = descriptor.get("aud") or descriptor.get("client_id")
    expected_nonce = descriptor.get("nonce")
    actual_aud = presentation_tx.get("aud")
    actual_nonce = presentation_tx.get("nonce")
    details["requestBinding"] = {
        "expectedAud": expected_aud,
        "actualAud": actual_aud,
        "audMatches": expected_aud == actual_aud,
        "expectedNonce": expected_nonce,
        "actualNonce": actual_nonce,
        "nonceMatches": expected_nonce == actual_nonce,
    }
    if expected_aud != actual_aud or expected_nonce != actual_nonce:
        check["accepted"] = False
