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
from .constants import STATUS_ROUTE_PREFIX, STATUS_TYPE
from .runtime_http import JsonResponse


@dataclass
class CredentialStatusRecord:
    """Persisted W3C status projection of accepted KERI TEL state."""

    # ACDC credential SAID, copied from the source credential's "d" field.
    cred_said: str
    # Source credential registry identifier, copied from ACDC "ri".
    registry: str
    # Source credential schema SAID, copied from ACDC "s".
    schema_said: str
    # Source credential issuer AID, copied from ACDC "i".
    issuer_aid: str
    # Canonical W3C issuer DID used when projecting/signing the VC twin.
    issuer_did: str
    # Convenience boolean derived from TEL ilk rev/brv; iss/bis project as not revoked.
    revoked: bool
    # Raw TEL ilk from Tever.vcState(...).et: iss, bis, rev, or brv; not "active"/"revoked".
    status: str
    # Latest TEL event SAID/digest from Tever.vcState(...).d.
    source_status_said: str
    # KEL sequence number from Tever.vcState(...).a["s"]; this is not the TEL sequence state.s.
    source_status_sequence: int
    # TEL event timestamp from Tever.vcState(...).dt.
    status_date: str
    # Local projection write time; this is not a KERI/TEL event timestamp.
    updated_at: str

    @classmethod
    def from_tel_state(cls, acdc: dict[str, Any], *, issuer_did: str, state: Any) -> "CredentialStatusRecord":
        """Create a status record from accepted TEL state for the source credential."""
        if state.ilk not in {"iss", "bis", "rev", "brv"}:
            raise ValueError(f"status projection requires iss/bis/rev/brv TEL state, got {state.ilk!r}")
        revoked = state.ilk in {"rev", "brv"}
        return cls(
            cred_said=acdc["d"],
            registry=acdc["ri"],
            schema_said=acdc["s"],
            issuer_aid=acdc["i"],
            issuer_did=canonicalize_did_webs(issuer_did),
            revoked=revoked,
            status=state.ilk,
            source_status_said=state.said,
            source_status_sequence=state.sequence,
            status_date=state.date,
            updated_at=utc_timestamp(),
        )

    def as_status_resource(self, base_url: str) -> dict[str, Any]:
        """Render the record as a W3C-friendly status resource document."""
        return {
            "id": status_url(base_url, self.cred_said),
            "type": STATUS_TYPE,
            "credSaid": self.cred_said,
            "registry": self.registry,
            "statusRegistryId": self.registry,
            "schemaSaid": self.schema_said,
            "issuerAid": self.issuer_aid,
            "issuer": self.issuer_did,
            "revoked": self.revoked,
            "status": self.status,
            "statusSaid": self.source_status_said,
            "statusSequence": self.source_status_sequence,
            "statusDate": self.status_date,
            "updatedAt": self.updated_at,
        }


class StatusStore(Protocol):
    """Minimal store protocol used by status projection services."""

    def project_credential(self, acdc: dict[str, Any], issuer_did: str, state: Any) -> CredentialStatusRecord:
        """Project a source ACDC credential and accepted TEL state into a local status record."""
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

    def project_credential(self, acdc: dict[str, Any], issuer_did: str, state: Any) -> CredentialStatusRecord:
        """Project a source ACDC credential and accepted TEL state into a status record."""
        data = self._load()
        record = CredentialStatusRecord.from_tel_state(acdc, issuer_did=issuer_did, state=state)
        data[record.cred_said] = asdict(record)
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
