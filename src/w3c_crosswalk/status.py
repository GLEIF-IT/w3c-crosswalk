"""Project KERI registry state into W3C credential status resources.

This module provides the local status-store abstraction used by the CLI,
service layer, and verifier. It is intentionally small so that later status
implementations can replace storage or transport without changing callers.

The important maintainer mental model is that status here is a projection seam.
The authoritative state still comes from KERI registry/TEL state.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
import os
from pathlib import Path
import tempfile
from typing import Any, Protocol

from .common import canonicalize_did_webs, utc_timestamp
from .constants import STATUS_ROUTE_PREFIX
from .runtime_http import JsonResponse


@dataclass
class CredentialStatusRecord:
    """Persisted status projection for one source credential."""

    credential_said: str
    source_registry: str
    source_schema_said: str
    source_issuer_aid: str
    issuer_did: str
    revoked: bool
    updated_at: str
    reason: str | None = None

    @classmethod
    def from_acdc(cls, acdc: dict[str, Any], issuer_did: str) -> "CredentialStatusRecord":
        """Create an active status record from an issued ACDC credential."""
        return cls(
            credential_said=acdc["d"],
            source_registry=acdc["ri"],
            source_schema_said=acdc["s"],
            source_issuer_aid=acdc["i"],
            issuer_did=canonicalize_did_webs(issuer_did),
            revoked=False,
            updated_at=utc_timestamp(),
        )

    def as_status_resource(self, base_url: str) -> dict[str, Any]:
        """Render the record as a W3C-friendly status resource document."""
        return {
            "id": status_url(base_url, self.credential_said),
            "type": "KERICredentialRegistryStatus",
            "credentialSaid": self.credential_said,
            "sourceRegistry": self.source_registry,
            "sourceSchemaSaid": self.source_schema_said,
            "sourceIssuerAid": self.source_issuer_aid,
            "issuer": self.issuer_did,
            "revoked": self.revoked,
            "status": "revoked" if self.revoked else "active",
            "updatedAt": self.updated_at,
            "reason": self.reason,
        }


class StatusStore(Protocol):
    """Minimal store protocol used by status projection services."""

    def project_acdc(self, acdc: dict[str, Any], issuer_did: str) -> CredentialStatusRecord:
        """Project a source ACDC credential into a local status record."""
        ...

    def set_revoked(self, credential_said: str, revoked: bool, reason: str | None = None) -> CredentialStatusRecord:
        """Update revocation state for a previously projected credential."""
        ...

    def get(self, credential_said: str) -> CredentialStatusRecord | None:
        """Load one credential status record by source credential SAID."""
        ...


class JsonFileStatusStore:
    """Persist projected credential status records in a local JSON file.

    This store is deliberately simple because it serves local integration and
    proof-of-concept status publication. It is not the intended long-term
    production architecture.
    """

    def __init__(self, path: str | Path):
        """Initialize the store with a backing path but do not eagerly mutate it."""
        self.path = Path(path)

    def ensure_exists(self) -> None:
        """Create the backing file and parent directories on first use."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}\n", encoding="utf-8")

    def _load(self) -> dict[str, Any]:
        """Load the entire status store into memory."""
        self.ensure_exists()
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data: dict[str, Any]) -> None:
        """Write the full in-memory status map back to disk atomically."""
        self.ensure_exists()
        with tempfile.NamedTemporaryFile("w", delete=False, dir=self.path.parent, encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
            temp_path = Path(handle.name)
        os.replace(temp_path, self.path)

    def project_acdc(self, acdc: dict[str, Any], issuer_did: str) -> CredentialStatusRecord:
        """Project a source ACDC credential into an active status record."""
        data = self._load()
        record = CredentialStatusRecord.from_acdc(acdc, issuer_did)
        data[record.credential_said] = asdict(record)
        self._save(data)
        return record

    def set_revoked(self, credential_said: str, revoked: bool, reason: str | None = None) -> CredentialStatusRecord:
        """Update revocation state for a previously projected credential."""
        data = self._load()
        if credential_said not in data:
            raise KeyError(f"unknown credential SAID: {credential_said}")
        record = CredentialStatusRecord(**data[credential_said])
        record.revoked = revoked
        record.reason = reason
        record.updated_at = utc_timestamp()
        data[credential_said] = asdict(record)
        self._save(data)
        return record

    def get(self, credential_said: str) -> CredentialStatusRecord | None:
        """Load one credential status record by source credential SAID."""
        data = self._load()
        record = data.get(credential_said)
        return CredentialStatusRecord(**record) if record else None


class HttpStatusResolver:
    """Namespace for status-service response validation.

    Outbound status dereferencing is driven by cooperative HIO doers elsewhere
    in the runtime. This class intentionally owns only response validation.
    """

    @staticmethod
    def parse_response(url: str, response: JsonResponse) -> dict[str, Any]:
        """Validate and normalize one status-service JSON response."""
        if response.status >= 400:
            raise RuntimeError(f"status lookup returned HTTP {response.status} for {url}")
        if not isinstance(response.data, dict):
            raise RuntimeError(f"status lookup did not return a JSON object for {url}")
        return response.data


def status_url(base_url: str, credential_said: str) -> str:
    """Return the canonical status resource URL for one credential SAID."""
    return f"{base_url.rstrip('/')}{STATUS_ROUTE_PREFIX}/{credential_said}"
