"""Service-layer use cases for issuance, status projection, and verifier operations.

Transport adapters such as the CLI and Falcon resources should call these
services instead of embedding orchestration logic directly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .constants import VERIFY_PAIR_OPERATION, VERIFY_VC_OPERATION, VERIFY_VP_OPERATION
from .jwt import issue_vc_jwt, issue_vp_jwt
from .longrunning import BaseOperation, OperationMonitor
from .signing import SignerLike
from .status import JsonFileStatusStore


@dataclass(frozen=True)
class IssueArtifact:
    """Normalized issuance result returned by service-layer issue flows."""

    ok: bool
    kind: str
    token: str
    document: dict[str, Any]
    signer: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert the issuance result to a JSON-serializable dictionary."""
        return asdict(self)


class VerifierOperationService:
    """Submission and retrieval API for long-running verifier operations."""

    def __init__(self, *, monitor: OperationMonitor):
        self.monitor = monitor

    def submit_verify_vc(self, body: dict[str, Any]) -> BaseOperation:
        """Submit one VC-JWT verification request."""
        token = self._require_string(body, "token")
        return self.monitor.submit(typ=VERIFY_VC_OPERATION, request={"token": token})

    def submit_verify_vp(self, body: dict[str, Any]) -> BaseOperation:
        """Submit one VP-JWT verification request."""
        token = self._require_string(body, "token")
        return self.monitor.submit(typ=VERIFY_VP_OPERATION, request={"token": token})

    def submit_verify_pair(self, body: dict[str, Any]) -> BaseOperation:
        """Submit one VC/ACDC crosswalk pair verification request."""
        token = self._require_string(body, "token")
        acdc = body.get("acdc")
        if not isinstance(acdc, dict):
            raise ValueError("verify pair requires an `acdc` object")
        return self.monitor.submit(typ=VERIFY_PAIR_OPERATION, request={"token": token, "acdc": acdc})

    def get_operation(self, name: str) -> BaseOperation | None:
        """Return one operation document by resource name."""
        return self.monitor.get(name)

    def list_operations(self, *, type: str | None = None) -> list[BaseOperation]:
        """Return operation documents, optionally filtered by type."""
        return self.monitor.get_ops(type=type)

    def delete_operation(self, name: str) -> bool:
        """Delete one stored operation resource."""
        return self.monitor.rem(name)

    @staticmethod
    def _require_string(body: dict[str, Any], field: str) -> str:
        """Load one required request field as a non-empty string."""
        value = body.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"verification request requires `{field}`")
        return value

def issue_vc_artifact(
    *,
    acdc: dict[str, Any],
    issuer_did: str,
    status_base_url: str,
    signer: SignerLike,
    status_store: JsonFileStatusStore | None = None,
) -> IssueArtifact:
    """Issue a VC-JWT and optionally project initial status state."""
    token, document = issue_vc_jwt(acdc, issuer_did=issuer_did, status_base_url=status_base_url, signer=signer)
    if status_store is not None:
        status_store.project_acdc(acdc, issuer_did)
    return IssueArtifact(
        ok=True,
        kind="vc+jwt",
        token=token,
        document=document,
        signer={"kid": signer.kid, "publicKeyJwk": signer.public_jwk},
    )


def issue_vp_artifact(
    *,
    vc_tokens: list[str],
    holder_did: str,
    signer: SignerLike,
    audience: str | None = None,
    nonce: str | None = None,
) -> IssueArtifact:
    """Issue a VP-JWT that wraps one or more VC-JWT strings."""
    token, document = issue_vp_jwt(vc_tokens, holder_did=holder_did, signer=signer, audience=audience, nonce=nonce)
    return IssueArtifact(
        ok=True,
        kind="vp+jwt",
        token=token,
        document=document,
        signer={"kid": signer.kid, "publicKeyJwk": signer.public_jwk},
    )


def project_status(
    *,
    store: JsonFileStatusStore,
    acdc: dict[str, Any],
    issuer_did: str,
    base_url: str,
) -> dict[str, Any]:
    """Project one source ACDC credential into the local status store."""
    return store.project_acdc(acdc, issuer_did).as_status_resource(base_url)


def revoke_status(
    *,
    store: JsonFileStatusStore,
    credential_said: str,
    base_url: str,
    reason: str,
) -> dict[str, Any]:
    """Mark one projected credential as revoked."""
    return store.set_revoked(credential_said, True, reason=reason).as_status_resource(base_url)
