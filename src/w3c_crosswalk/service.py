"""Falcon + HIO hosting for crosswalk status and verifier services.

The runtime rule is strict:
- Falcon handlers parse requests and submit or retrieve state only
- long-running verification happens in background HIO doers
- outbound DID/status HTTP never runs inside request handlers
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable

import falcon

from .constants import (
    HEALTH_ROUTE,
    OPERATIONS_ROUTE_PREFIX,
    STATUS_ROUTE_PREFIX,
    VERIFY_PAIR_ROUTE,
    VERIFY_VC_ROUTE,
    VERIFY_VP_ROUTE,
)
from .longrunning import OperationCollectionResource, OperationMonitor, OperationResource
from .runtime_http import setup_server_doers
from .services import VerifierOperationService, revoke_status
from .status import JsonFileStatusStore
from .verifier_runtime import VerificationManagerDoer


@dataclass(frozen=True)
class StatusServerConfig:
    """Runtime inputs for the local status projection service."""

    host: str
    port: int
    store_path: str
    base_url: str
    tock: float = 0.03125


@dataclass(frozen=True)
class VerifierServerConfig:
    """Runtime inputs for the long-running verifier service."""

    host: str
    port: int
    resolver_url: str
    operation_store_root: str
    operation_store_name: str = "verifier"
    tock: float = 0.03125


class HealthResource:
    """Serve a simple JSON health document for one named service."""

    def __init__(self, service_name: str):
        self.service_name = service_name

    def on_get(self, _req: falcon.Request, resp: falcon.Response) -> None:
        """Respond with a basic readiness document."""
        resp.media = {"ok": True, "service": self.service_name}


class CredentialStatusResource:
    """Publish one projected credential status resource."""

    def __init__(self, *, store: JsonFileStatusStore, base_url: str):
        self.store = store
        self.base_url = base_url

    def on_get(self, _req: falcon.Request, resp: falcon.Response, credential_said: str) -> None:
        """Load and return one projected status document."""
        record = self.store.get(credential_said)
        if record is None:
            resp.status = falcon.HTTP_404
            resp.media = {"ok": False, "error": f"unknown credential SAID: {credential_said}"}
            return
        resp.media = record.as_status_resource(self.base_url)


class CredentialStatusRevokeResource:
    """Mutate one projected credential status record into a revoked state."""

    def __init__(self, *, store: JsonFileStatusStore, base_url: str):
        self.store = store
        self.base_url = base_url

    def on_post(self, _req: falcon.Request, resp: falcon.Response, credential_said: str) -> None:
        """Revoke one credential status resource."""
        try:
            resp.media = revoke_status(
                store=self.store,
                credential_said=credential_said,
                base_url=self.base_url,
                reason="revoked via status service",
            )
        except KeyError as exc:
            resp.status = falcon.HTTP_404
            resp.media = {"ok": False, "error": str(exc)}


class VerificationSubmissionResource:
    """Submit one verifier operation without executing it in the request handler."""

    def __init__(self, *, route: str, submit: Callable[..., Any]):
        self.route = route
        self.submit = submit

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        """Validate one submission body and create the corresponding operation."""
        raw = req.bounded_stream.read()
        try:
            body = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise falcon.HTTPBadRequest(description=f"verification submission body was not valid JSON: {exc}") from exc
        if not isinstance(body, dict):
            raise falcon.HTTPBadRequest(description="verification submission body must be a JSON object")
        try:
            operation = self.submit(body)
        except ValueError as exc:
            raise falcon.HTTPBadRequest(description=str(exc)) from exc

        resp.status = falcon.HTTP_202
        resp.media = {"name": operation.name, "done": operation.done}


def create_status_app(*, store: JsonFileStatusStore, base_url: str) -> falcon.App:
    """Create the Falcon app for the local status projection service."""
    app = falcon.App()
    app.add_route(HEALTH_ROUTE, HealthResource("status"))
    app.add_route(f"{STATUS_ROUTE_PREFIX}/{{credential_said}}", CredentialStatusResource(store=store, base_url=base_url))
    app.add_route(
        f"{STATUS_ROUTE_PREFIX}/{{credential_said}}/revoke",
        CredentialStatusRevokeResource(store=store, base_url=base_url),
    )
    return app


def create_verifier_app(*, operation_service: VerifierOperationService) -> falcon.App:
    """Create the Falcon app for long-running verifier submission and polling."""
    app = falcon.App()
    app.add_route(HEALTH_ROUTE, HealthResource("verifier"))
    app.add_route(
        VERIFY_VC_ROUTE,
        VerificationSubmissionResource(
            route=VERIFY_VC_ROUTE,
            submit=operation_service.submit_verify_vc,
        ),
    )
    app.add_route(
        VERIFY_VP_ROUTE,
        VerificationSubmissionResource(
            route=VERIFY_VP_ROUTE,
            submit=operation_service.submit_verify_vp,
        ),
    )
    app.add_route(
        VERIFY_PAIR_ROUTE,
        VerificationSubmissionResource(
            route=VERIFY_PAIR_ROUTE,
            submit=operation_service.submit_verify_pair,
        ),
    )
    app.add_route(OPERATIONS_ROUTE_PREFIX, OperationCollectionResource(monitor=operation_service.monitor))
    app.add_route(f"{OPERATIONS_ROUTE_PREFIX}/{{name}}", OperationResource(monitor=operation_service.monitor))
    return app


def setup_status_doers(config: StatusServerConfig) -> tuple[Any, list[Any]]:
    """Assemble the HIO doers that host the status service."""
    store = JsonFileStatusStore(config.store_path)
    app = create_status_app(store=store, base_url=config.base_url)
    return setup_server_doers(host=config.host, port=config.port, app=app)


def setup_verifier_api_doers(
    config: VerifierServerConfig,
    *,
    monitor: OperationMonitor | None = None,
) -> tuple[Any, list[Any]]:
    """Assemble the HIO doers that host the verifier submission/polling API."""
    owned_monitor = monitor if monitor is not None else OperationMonitor(
        name=config.operation_store_name,
        head_dir_path=config.operation_store_root,
    )
    operation_service = VerifierOperationService(monitor=owned_monitor)
    app = create_verifier_app(operation_service=operation_service)
    return setup_server_doers(host=config.host, port=config.port, app=app)


def setup_verifier_worker_doers(
    config: VerifierServerConfig,
    *,
    monitor: OperationMonitor | None = None,
) -> list[Any]:
    """Assemble the background verifier worker doers that execute pending operations."""
    owned_monitor = monitor if monitor is not None else OperationMonitor(
        name=config.operation_store_name,
        head_dir_path=config.operation_store_root,
    )
    manager = VerificationManagerDoer(monitor=owned_monitor, resolver_base_url=config.resolver_url, tock=config.tock)
    return [manager]


def setup_verifier_doers(config: VerifierServerConfig) -> tuple[Any, list[Any]]:
    """Assemble the verifier API and worker doers in one process for local tests."""
    monitor = OperationMonitor(name=config.operation_store_name, head_dir_path=config.operation_store_root)
    server, api_doers = setup_verifier_api_doers(config, monitor=monitor)
    worker_doers = setup_verifier_worker_doers(config, monitor=monitor)
    return server, [*api_doers, *worker_doers]
