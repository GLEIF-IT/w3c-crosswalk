"""Scenario orchestration for the headless W3C holder E2E harness."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ScenarioManifest:
    """Executable evidence emitted by one headless W3C E2E scenario run."""

    sourceCredentialSaid: str
    issuance: dict[str, Any]
    holderImportOutcomes: list[dict[str, Any]]
    holderCredentials: list[dict[str, Any]]
    presentationTx: dict[str, Any]
    verifierEvidence: dict[str, Any]
    qviWallet: dict[str, Any]
    holderWallet: dict[str, Any]
    failures: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable manifest dictionary."""
        return asdict(self)


class HeadlessW3CE2E:
    """Coordinate a QVI wallet, holder wallet, and verifier suite."""

    def __init__(self, qvi_wallet, holder_wallet, verifier_suite):
        self.qvi_wallet = qvi_wallet
        self.holder_wallet = holder_wallet
        self.verifier_suite = verifier_suite

    def run_happy_path(
        self,
        source_credential_said: str,
        verifier_descriptor: dict[str, Any],
        *,
        vc_jwt: str | None = None,
        vp_jwt: str | None = None,
    ) -> ScenarioManifest:
        """Run the core issuer-holder-verifier flow and return evidence."""
        issuance = self.qvi_wallet.start_issuance(source_credential_said)
        self.qvi_wallet.drain_automation()

        holder_import_outcomes = self.holder_wallet.drain_automation()
        holder_credentials = self.holder_wallet.refresh_credentials()

        presentation_tx = self.holder_wallet.start_presentation(verifier_descriptor)
        self.holder_wallet.drain_automation()
        presentation_tx = self._latest_presentation_tx(presentation_tx)

        artifacts = self._artifact_bundle(
            issuance=issuance,
            holder_credentials=holder_credentials,
            presentation_tx=presentation_tx,
            verifier_descriptor=verifier_descriptor,
            vc_jwt=vc_jwt,
            vp_jwt=vp_jwt,
        )
        verifier_evidence = self.verifier_suite.verify(artifacts).to_dict()

        failures = []
        if not verifier_evidence["accepted"]:
            failures.append(
                {
                    "stage": "verifier",
                    "error": "one or more verifier checks rejected the artifacts",
                    "evidence": verifier_evidence,
                }
            )

        return ScenarioManifest(
            sourceCredentialSaid=source_credential_said,
            issuance=issuance,
            holderImportOutcomes=holder_import_outcomes,
            holderCredentials=holder_credentials,
            presentationTx=presentation_tx,
            verifierEvidence=verifier_evidence,
            qviWallet=self.qvi_wallet.manifest(),
            holderWallet=self.holder_wallet.manifest(),
            failures=failures,
        )

    def _latest_presentation_tx(self, fallback: dict[str, Any]) -> dict[str, Any]:
        if self.holder_wallet.present_txs:
            return self.holder_wallet.present_txs[-1]
        return fallback

    @staticmethod
    def _artifact_bundle(
        *,
        issuance: dict[str, Any],
        holder_credentials: list[dict[str, Any]],
        presentation_tx: dict[str, Any],
        verifier_descriptor: dict[str, Any],
        vc_jwt: str | None,
        vp_jwt: str | None,
    ) -> dict[str, Any]:
        credential = holder_credentials[0] if holder_credentials else {}
        return {
            "vcJwt": vc_jwt or issuance.get("vcJwt") or credential.get("vcJwt"),
            "vpJwt": vp_jwt or presentation_tx.get("vpJwt"),
            "issuance": issuance,
            "heldCredential": credential,
            "presentationTx": presentation_tx,
            "verifierDescriptor": verifier_descriptor,
            "audience": presentation_tx.get("aud") or verifier_descriptor.get("aud"),
            "nonce": presentation_tx.get("nonce") or verifier_descriptor.get("nonce"),
        }
