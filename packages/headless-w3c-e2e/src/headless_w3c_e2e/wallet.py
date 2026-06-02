"""In-memory wallet actor wrappers for KERIA W3C holder workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from keri.core import coring


class KeriaW3CApi:
    """Small KERIA W3C route wrapper over a SignifyPy-style client."""

    def __init__(self, client):
        self.client = client

    def start_issuance(self, name: str, source_credential_said: str) -> dict[str, Any]:
        """Start W3C issuance for one native source credential SAID."""
        return self.client.post(
            f"/identifiers/{name}/w3c/credentials",
            json={"sourceCredentialSaid": source_credential_said},
        ).json()

    def credential(self, name: str, credential_id: str) -> dict[str, Any]:
        """Return one issuer issuance or holder credential view."""
        return self.client.get(f"/identifiers/{name}/w3c/credentials/{credential_id}").json()

    def signing_requests(self, name: str, include_complete: bool = False) -> list[dict[str, Any]]:
        """Return durable W3C signing requests for one identifier."""
        params = {"includeComplete": "true"} if include_complete else None
        return self.client.get(
            f"/identifiers/{name}/w3c/signing-requests",
            params=params,
        ).json()["requests"]

    def submit_signature(self, name: str, request_id: str, signature: str) -> dict[str, Any]:
        """Submit a managed-AID edge signature for one KERIA signing request."""
        return self.client.post(
            f"/identifiers/{name}/w3c/signing-requests/{request_id}/signatures",
            json={"signature": signature},
        ).json()

    def import_requests(self, name: str, include_complete: bool = False) -> list[dict[str, Any]]:
        """Return durable holder import requests for one identifier."""
        params = {"includeComplete": "true"} if include_complete else None
        return self.client.get(
            f"/identifiers/{name}/w3c/credentials/import-requests",
            params=params,
        ).json()["requests"]

    def import_credential(self, name: str, import_request_id: str) -> dict[str, Any]:
        """Import one portable W3C credential through KERIA's canonical route."""
        return self.client.post(
            f"/identifiers/{name}/w3c/credentials/import",
            json={"importRequestId": import_request_id},
        ).json()

    def create_import_request(self, grant: dict[str, Any]) -> dict[str, Any]:
        """Deliver one W3C grant to KERIA's live holder import endpoint."""
        return self.client.post("/w3c/vc/grant", json=grant).json()

    def credentials(self, name: str) -> list[dict[str, Any]]:
        """Return holder W3C credential inventory."""
        return self.client.get(f"/identifiers/{name}/w3c/credentials").json()["credentials"]

    def start_present_tx(self, name: str, descriptor: dict[str, Any]) -> dict[str, Any]:
        """Hand a verifier request descriptor to KERIA."""
        return self.client.post(
            f"/identifiers/{name}/w3c/present-txs",
            json=descriptor,
        ).json()

    def present_tx(self, name: str, present_tx_id: str) -> dict[str, Any]:
        """Return one presentation transaction view."""
        return self.client.get(f"/identifiers/{name}/w3c/present-txs/{present_tx_id}").json()

    def submit_present_tx_signature(
        self,
        name: str,
        present_tx_id: str,
        signature: str | None = None,
        vp_jwt: str | None = None,
    ) -> dict[str, Any]:
        """Submit holder VP signature material for a presentation transaction."""
        body: dict[str, Any] = {}
        if signature is not None:
            body["signature"] = signature
        if vp_jwt is not None:
            body["vpJwt"] = vp_jwt
        return self.client.post(
            f"/identifiers/{name}/w3c/present-txs/{present_tx_id}/signatures",
            json=body,
        ).json()


@dataclass
class HeadlessW3CWallet:
    """In-memory actor wrapper around one SignifyPy/KERIA W3C client."""

    name: str
    w3c: Any
    automator: Any | None = None
    signals: list[dict[str, Any]] = field(default_factory=list)
    automation_outcomes: list[dict[str, Any]] = field(default_factory=list)
    issuances: list[dict[str, Any]] = field(default_factory=list)
    held_credentials: list[dict[str, Any]] = field(default_factory=list)
    present_txs: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_client(cls, name: str, client, automator: Any | None = None):
        """Create a wallet actor from a SignifyPy-style client."""
        return cls(name=name, w3c=KeriaW3CApi(client), automator=automator)

    def start_issuance(self, source_credential_said: str) -> dict[str, Any]:
        """Start issuer-side W3C issuance and record the returned view."""
        issuance = self.w3c.start_issuance(self.name, source_credential_said)
        self.issuances.append(issuance)
        return issuance

    def refresh_issuance(self, issuance: dict[str, Any]) -> dict[str, Any]:
        """Reload one issuer issuance from KERIA and record the current view."""
        issuance_id = _record_id(issuance, "issuanceId")
        refreshed = self.w3c.credential(self.name, issuance_id)
        self.issuances.append(refreshed)
        return refreshed

    def deliver_issuance_to_holder(self, holder_wallet: "HeadlessW3CWallet", issuance: dict[str, Any]) -> dict[str, Any]:
        """Deliver a finalized issuer W3C issuance through KERIA's grant route."""
        grant = _grant_from_issuance(holder_wallet.name, issuance)
        return holder_wallet.w3c.create_import_request(grant)

    def handle_signal(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Verify and handle one signed W3C signal through the configured automator."""
        if self.automator is None:
            raise RuntimeError("headless wallet has no W3C automator")
        self.signals.append(envelope)
        outcome = self.automator.handleEnvelope(envelope)
        self.automation_outcomes.append(outcome)
        return outcome

    def poll_once(self) -> list[dict[str, Any]]:
        """Poll KERIA durable W3C queues once through the configured automator."""
        if self.automator is None:
            return []
        outcomes = self.automator.pollOnce(name=self.name)
        self.automation_outcomes.extend(outcomes)
        return outcomes

    def drain_automation(self, max_rounds: int = 5) -> list[dict[str, Any]]:
        """Poll until one round produces no action outcomes or the round limit is hit."""
        collected: list[dict[str, Any]] = []
        actionable = {"submitted", "imported", "blocked", "failed", "rejected"}
        for _round in range(max_rounds):
            outcomes = self.poll_once()
            collected.extend(outcomes)
            if not any(outcome.get("outcome") in actionable for outcome in outcomes):
                break
        return collected

    def refresh_credentials(self) -> list[dict[str, Any]]:
        """Refresh and return the holder W3C credential inventory."""
        self.held_credentials = self.w3c.credentials(self.name)
        return self.held_credentials

    def import_request_ids(self, include_complete: bool = False) -> list[str]:
        """Return import request ids visible to this wallet actor."""
        return [
            request.get("d") or request.get("importRequestId")
            for request in self.w3c.import_requests(self.name, include_complete)
        ]

    def start_presentation(self, descriptor: dict[str, Any]) -> dict[str, Any]:
        """Create a holder presentation transaction from a verifier descriptor."""
        tx = self.w3c.start_present_tx(self.name, descriptor)
        self.present_txs.append(tx)
        return tx

    def refresh_presentation(self, presentation_tx: dict[str, Any]) -> dict[str, Any]:
        """Reload one holder presentation transaction from KERIA."""
        present_tx_id = presentation_tx.get("presentTxId") or presentation_tx.get("d")
        if not isinstance(present_tx_id, str) or not present_tx_id:
            raise RuntimeError(f"presentation transaction has no id: {presentation_tx!r}")
        tx = self.w3c.present_tx(self.name, present_tx_id)
        self.present_txs.append(tx)
        return tx

    def submit_presentation_signature(
        self,
        present_tx_id: str,
        signature: str | None = None,
        vp_jwt: str | None = None,
    ) -> dict[str, Any]:
        """Submit holder VP signature material and record the updated transaction."""
        tx = self.w3c.submit_present_tx_signature(
            self.name,
            present_tx_id,
            signature=signature,
            vp_jwt=vp_jwt,
        )
        self.present_txs.append(tx)
        return tx

    def manifest(self) -> dict[str, Any]:
        """Return the wallet-local manifest slice for later comparison."""
        return {
            "name": self.name,
            "signals": self.signals,
            "automationOutcomes": self.automation_outcomes,
            "issuances": self.issuances,
            "heldCredentials": self.held_credentials,
            "presentTxs": self.present_txs,
        }


def _record_id(record: dict[str, Any], preferred: str) -> str:
    """Return a KERIA record id from a response object."""
    record_id = record.get(preferred) or record.get("d")
    if not isinstance(record_id, str) or not record_id:
        raise RuntimeError(f"W3C record has no {preferred}: {record!r}")
    return record_id


def _grant_from_issuance(holder_name: str, issuance: dict[str, Any]) -> dict[str, Any]:
    """Build the live grant body consumed by KERIA's W3C holder import route."""
    required = (
        "holderAid",
        "holderDid",
        "issuerAid",
        "issuerDid",
        "sourceCredentialSaid",
        "schemaSaid",
        "vcJwt",
        "statusUrl",
    )
    missing = [key for key in required if not issuance.get(key)]
    if missing:
        raise RuntimeError(f"W3C issuance is not deliverable; missing {', '.join(missing)}")

    body = {
        "holderName": holder_name,
        "holderAid": issuance["holderAid"],
        "holderDid": issuance["holderDid"],
        "issuerAid": issuance["issuerAid"],
        "issuerDid": issuance["issuerDid"],
        "sourceCredentialSaid": issuance["sourceCredentialSaid"],
        "schemaSaid": issuance["schemaSaid"],
        "issuanceId": _record_id(issuance, "issuanceId"),
        "vcJwt": issuance["vcJwt"],
        "statusUrl": issuance["statusUrl"],
        "profile": issuance.get("profile"),
    }
    said_input = {"d": "", **body}
    _saider, saided = coring.Saider.saidify(said_input)
    body["grantSaid"] = saided["d"]
    return body
