"""In-memory wallet actor wrappers for edge-owned KERIA W3C workflows.

The wrapper stores scenario evidence, but every transition goes through live
KERIA routes and local SignifyPy edge keys via ``signifypy-w3c``. It does not
poll staged W3C signing requests or run a background automator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from signifypy_w3c import W3CKeriaClient, issue_w3c_credential, present_w3c_credential


@dataclass
class HeadlessW3CWallet:
    """Actor wrapper around one SignifyPy/KERIA W3C edge client."""

    name: str
    client: Any
    w3c: W3CKeriaClient
    issuances: list[dict[str, Any]] = field(default_factory=list)
    held_credentials: list[dict[str, Any]] = field(default_factory=list)
    presentations: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_client(cls, name: str, client: Any):
        """Create a wallet actor from a connected SignifyPy-style client."""
        return cls(name=name, client=client, w3c=W3CKeriaClient(client))

    def issue_credential(self, source_credential_said: str) -> dict[str, Any]:
        """Build, sign, validate, and deliver one issuer W3C credential."""
        issuance = issue_w3c_credential(
            client=self.client,
            issuer_name=self.name,
            source_credential_said=source_credential_said,
        )
        self.issuances.append(issuance)
        return issuance

    def refresh_issuance(self, issuance: dict[str, Any]) -> dict[str, Any]:
        """Reload one issuer issuance from KERIA and record the current view."""
        issuance_id = _record_id(issuance, "issuanceId")
        refreshed = self.w3c.issuance(self.name, issuance_id)
        self.issuances.append(refreshed)
        return refreshed

    def refresh_credentials(self) -> list[dict[str, Any]]:
        """Refresh and return the holder W3C credential inventory."""
        self.held_credentials = self.w3c.credentials(self.name)
        return self.held_credentials

    def credential(self, credential_id: str) -> dict[str, Any]:
        """Return one held W3C credential detail record."""
        return self.w3c.credential(self.name, credential_id)

    def present_credential(self, credential_id: str, descriptor: dict[str, Any]) -> dict[str, Any]:
        """Build, sign, validate, and submit one holder VP-JWT."""
        presentation = present_w3c_credential(
            client=self.client,
            holder_name=self.name,
            credential_id=credential_id,
            verifier_request=descriptor,
        )
        self.presentations.append(presentation)
        return presentation

    def refresh_presentation(self, presentation: dict[str, Any]) -> dict[str, Any]:
        """Reload one holder presentation result from KERIA."""
        presentation_id = _record_id(presentation, "presentationId")
        refreshed = self.w3c.presentation(self.name, presentation_id)
        self.presentations.append(refreshed)
        return refreshed

    def manifest(self) -> dict[str, Any]:
        """Return the wallet-local manifest slice for later comparison."""
        return {
            "name": self.name,
            "issuances": self.issuances,
            "heldCredentials": self.held_credentials,
            "presentations": self.presentations,
        }


def _record_id(record: dict[str, Any], preferred: str) -> str:
    """Return a KERIA record id from a response object."""
    record_id = record.get(preferred) or record.get("d")
    if not isinstance(record_id, str) or not record_id:
        raise RuntimeError(f"W3C record has no {preferred}: {record!r}")
    return record_id
