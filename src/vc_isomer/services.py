"""Service-layer use cases for issuance, status projection, and verifier operations.

Transport adapters such as the CLI and Falcon resources should call these
services instead of embedding orchestration logic directly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .common import canonicalize_did_url, canonicalize_did_webs
from .constants import VERIFY_PAIR_OPERATION, VERIFY_VC_OPERATION, VERIFY_VP_OPERATION
from .jwt import issue_vc_jwt, issue_vp_jwt
from .keri_projection import ACDCProjector, ProjectorError
from .longrunning import BaseOperation, OperationMonitor
from .signing import SignerLike
from .status import JsonFileStatusStore


@dataclass(frozen=True)
class IssueArtifact:
    """Normalized issuance result returned by service-layer issue flows."""

    # True when artifact construction and signing completed.
    ok: bool
    # JWT artifact family, currently vc+jwt or vp+jwt.
    kind: str
    # Compact signed JWT string written to .token files and submitted to verifier APIs.
    token: str
    # Projected W3C VC/VP JSON payload before compact JWT encoding.
    document: dict[str, Any]
    # Public signing metadata exposed for debugging/manual verification.
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
        """Submit one VC/ACDC isomer pair verification request."""
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
    projector: ACDCProjector,
    signer: SignerLike,
    said: str,
    issuer_did: str,
    status_base_url: str,
    status_store: JsonFileStatusStore | None = None,
) -> IssueArtifact:
    """Issue a VC-JWT artifact from accepted local KERI credential/TEL state.

    Returns an :class:`IssueArtifact` where `token` is the compact VC-JWT string
    and `document` is the secured W3C VC JSON document embedded in its `vc`
    claim.
    """
    projection = projector.project_credential(said)
    if projection.state.revoked:
        raise ProjectorError(f"credential {said} is revoked in accepted TEL state")

    canonical_issuer = canonicalize_did_webs(issuer_did)
    verification_method = canonicalize_did_url(f"{canonical_issuer}#{signer.kid}")
    document = projector.project_vc(
        said=said,
        issuer_did=canonical_issuer,
        status_base_url=status_base_url,
    )
    token, document = issue_vc_jwt(
        document,
        signer=signer,
        verification_method=verification_method,
    )
    if status_store is not None:
        status_store.project_credential(projection.acdc, issuer_did, projection.state)
    return IssueArtifact(
        ok=True,
        kind="vc+jwt",
        token=token,
        document=document,
        signer={"kid": signer.kid, "publicKeyJwk": signer.public_jwk, "publicKeyMultibase": signer.public_key_multibase},
    )


def issue_vp_artifact(
    *,
    vc_tokens: list[str],
    holder_did: str,
    signer: SignerLike,
    audience: str | None = None,
    nonce: str | None = None,
) -> IssueArtifact:
    """Issue a VP-JWT artifact that wraps one or more compact VC-JWT strings.

    Args:
        vc_tokens: Compact VC-JWT strings that become
            `vp["verifiableCredential"]` in the embedded VP document.

    Returns:
        :class:`IssueArtifact` where `token` is the compact VP-JWT string and
        `document` is the embedded VP JSON object carried in the JWT `vp` claim.
    """
    token, document = issue_vp_jwt(vc_tokens, holder_did=holder_did, signer=signer, audience=audience, nonce=nonce)
    return IssueArtifact(
        ok=True,
        kind="vp+jwt",
        token=token,
        document=document,
        signer={"kid": signer.kid, "publicKeyJwk": signer.public_jwk, "publicKeyMultibase": signer.public_key_multibase},
    )


def project_status(
    *,
    store: JsonFileStatusStore,
    projector: ACDCProjector,
    said: str,
    issuer_did: str,
    base_url: str,
) -> dict[str, Any]:
    """Project one accepted local credential TEL state into the local status store."""
    projection = projector.project_credential(said)
    return store.project_credential(projection.acdc, issuer_did, projection.state).as_status_resource(base_url)
