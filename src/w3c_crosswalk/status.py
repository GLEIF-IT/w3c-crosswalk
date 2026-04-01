"""Project KERI registry state into W3C credential status resources.

This module provides the local status-store abstraction used by the CLI,
service layer, and verifier. It is intentionally small so that later status
implementations can replace storage or transport without changing callers.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.request import urlopen

from .common import utc_timestamp


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
            issuer_did=issuer_did,
            revoked=False,
            updated_at=utc_timestamp(),
        )

    def as_status_resource(self, base_url: str) -> dict[str, Any]:
        """Render the record as a W3C-friendly status resource document."""
        return {
            "id": f"{base_url.rstrip('/')}/statuses/{self.credential_said}",
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


class StatusResolver(Protocol):
    """Minimal protocol implemented by status fetch clients."""

    def fetch(self, url: str) -> dict[str, Any]:
        """Fetch and decode one status resource from its URL."""
        ...


class JsonFileStatusStore:
    """Persist projected credential status records in a local JSON file."""

    def __init__(self, path: str | Path):
        """Initialize the store and create an empty file on first use."""
        self.path = Path(path)
        if not self.path.exists():
            self.path.write_text("{}\n", encoding="utf-8")

    def _load(self) -> dict[str, Any]:
        """Load the entire status store into memory."""
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data: dict[str, Any]) -> None:
        """Write the full in-memory status map back to disk."""
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

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
    """Fetch status resources over HTTP or through a test loader hook."""

    def __init__(self, timeout: float = 5.0, loader: Callable[[str, float], dict[str, Any]] | None = None):
        """Configure the resolver timeout and optional test loader override."""
        self.timeout = timeout
        self.loader = loader

    def fetch(self, url: str) -> dict[str, Any]:
        """Fetch and decode a remote status resource."""
        if self.loader is not None:
            return self.loader(url, self.timeout)
        with urlopen(url, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))
