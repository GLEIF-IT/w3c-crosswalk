"""Scenario orchestration for the headless W3C holder E2E harness."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import time
from typing import Any


@dataclass
class ScenarioManifest:
    """Executable evidence emitted by one headless W3C E2E scenario run."""

    sourceCredentialSaid: str
    issuance: dict[str, Any]
    holderImportRequest: dict[str, Any]
    holderImportOutcomes: list[dict[str, Any]]
    holderCredentials: list[dict[str, Any]]
    presentationTx: dict[str, Any]
    verifierEvidence: dict[str, Any]
    qviWallet: dict[str, Any]
    holderWallet: dict[str, Any]
    presentationTxs: list[dict[str, Any]] = field(default_factory=list)
    verifierEvidenceByService: dict[str, dict[str, Any]] = field(default_factory=dict)
    failures: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable manifest dictionary."""
        return asdict(self)


class HeadlessW3CE2E:
    """Coordinate QVI/holder wallets and live verifier service evidence."""

    def __init__(
        self,
        qvi_wallet,
        holder_wallet,
        verifier_services,
        presentation_approver=None,
        *,
        wait_timeout: float = 60.0,
        poll_interval: float = 0.5,
    ):
        self.qvi_wallet = qvi_wallet
        self.holder_wallet = holder_wallet
        self.verifier_services = verifier_services
        self.presentation_approver = presentation_approver
        self.wait_timeout = wait_timeout
        self.poll_interval = poll_interval

    def run_happy_path(
        self,
        source_credential_said: str,
        verifier_descriptor: dict[str, Any],
        *,
        vc_jwt: str | None = None,
        vp_jwt: str | None = None,
    ) -> ScenarioManifest:
        """Run the core issuer-holder-verifier flow and return evidence."""
        issuance, holder_import_request, holder_import_outcomes, holder_credentials = self._issue_deliver_import(
            source_credential_said
        )

        presentation_tx = self.holder_wallet.start_presentation(verifier_descriptor)
        self._approve_presentation_tx(presentation_tx, verifier_descriptor)
        presentation_tx = self._wait_for_presentation_submission(presentation_tx)

        artifacts = self._artifact_bundle(
            issuance=issuance,
            holder_credentials=holder_credentials,
            presentation_tx=presentation_tx,
            verifier_descriptor=verifier_descriptor,
            vc_jwt=vc_jwt,
            vp_jwt=vp_jwt,
        )
        verifier_evidence = self.verifier_services.collect_after_keria(artifacts).to_dict()

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
            holderImportRequest=holder_import_request,
            holderImportOutcomes=holder_import_outcomes,
            holderCredentials=holder_credentials,
            presentationTx=presentation_tx,
            verifierEvidence=verifier_evidence,
            qviWallet=self.qvi_wallet.manifest(),
            holderWallet=self.holder_wallet.manifest(),
            presentationTxs=[presentation_tx],
            failures=failures,
        )

    def run_happy_path_for_services(
        self,
        source_credential_said: str,
        *,
        nonces: dict[str, str] | None = None,
    ) -> ScenarioManifest:
        """Run one KERIA-submitted holder presentation against each live service."""
        self.verifier_services.healthcheck_all()
        issuance, holder_import_request, holder_import_outcomes, holder_credentials = self._issue_deliver_import(
            source_credential_said
        )

        artifacts_by_service: dict[str, dict[str, Any]] = {}
        presentation_txs: list[dict[str, Any]] = []
        for service_name in self.verifier_services.REQUIRED:
            verifier_descriptor = self.verifier_services.descriptor_for(
                service_name,
                nonce=None if nonces is None else nonces.get(service_name),
            )
            presentation_tx = self.holder_wallet.start_presentation(verifier_descriptor)
            self._approve_presentation_tx(presentation_tx, verifier_descriptor)
            presentation_tx = self._wait_for_presentation_submission(presentation_tx)
            presentation_txs.append(presentation_tx)
            artifacts_by_service[service_name] = self._artifact_bundle(
                issuance=issuance,
                holder_credentials=holder_credentials,
                presentation_tx=presentation_tx,
                verifier_descriptor=verifier_descriptor,
                vc_jwt=None,
                vp_jwt=None,
            )

        verifier_evidence = self.verifier_services.collect_many_after_keria(artifacts_by_service).to_dict()
        failures = []
        if not verifier_evidence["accepted"]:
            failures.append(
                {
                    "stage": "verifier",
                    "error": "one or more live verifier services rejected the KERIA-submitted presentation",
                    "evidence": verifier_evidence,
                }
            )

        return ScenarioManifest(
            sourceCredentialSaid=source_credential_said,
            issuance=issuance,
            holderImportRequest=holder_import_request,
            holderImportOutcomes=holder_import_outcomes,
            holderCredentials=holder_credentials,
            presentationTx=presentation_txs[-1] if presentation_txs else {},
            verifierEvidence=verifier_evidence,
            qviWallet=self.qvi_wallet.manifest(),
            holderWallet=self.holder_wallet.manifest(),
            presentationTxs=presentation_txs,
            verifierEvidenceByService={
                check["name"]: check for check in verifier_evidence.get("checks", []) if isinstance(check, dict)
            },
            failures=failures,
        )

    def _latest_presentation_tx(self, fallback: dict[str, Any]) -> dict[str, Any]:
        if self.holder_wallet.present_txs:
            return self.holder_wallet.present_txs[-1]
        return fallback

    def _refresh_presentation_tx(self, fallback: dict[str, Any]) -> dict[str, Any]:
        if hasattr(self.holder_wallet, "refresh_presentation"):
            return self.holder_wallet.refresh_presentation(fallback)
        return self._latest_presentation_tx(fallback)

    def _approve_presentation_tx(self, presentation_tx: dict[str, Any], verifier_descriptor: dict[str, Any]) -> None:
        if self.presentation_approver is not None:
            self.presentation_approver(presentation_tx, verifier_descriptor)

    def _issue_deliver_import(self, source_credential_said: str):
        issuance = self.qvi_wallet.start_issuance(source_credential_said)
        issuance = self._wait_for_issuance(issuance)
        holder_import_request = self.qvi_wallet.deliver_issuance_to_holder(self.holder_wallet, issuance)
        holder_import_outcomes, holder_credentials = self._wait_for_holder_credential(source_credential_said)
        return issuance, holder_import_request, holder_import_outcomes, holder_credentials

    def _wait_for_issuance(self, issuance: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + self.wait_timeout
        current = issuance
        while True:
            self.qvi_wallet.drain_automation(max_rounds=3)
            current = self.qvi_wallet.refresh_issuance(current)
            if current.get("state") == "issued" and current.get("vcJwt"):
                return current
            if current.get("state") == "failed":
                raise RuntimeError(f"W3C issuance failed: {current!r}")
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for W3C issuance to finalize; last_seen={current!r}")
            time.sleep(self.poll_interval)

    def _wait_for_holder_credential(self, source_credential_said: str):
        deadline = time.monotonic() + self.wait_timeout
        outcomes: list[dict[str, Any]] = []
        last_credentials: list[dict[str, Any]] = []
        while True:
            outcomes.extend(self.holder_wallet.drain_automation(max_rounds=3))
            last_credentials = self.holder_wallet.refresh_credentials()
            matching = [
                credential
                for credential in last_credentials
                if credential.get("sourceCredentialSaid") == source_credential_said
            ]
            admitted = [credential for credential in matching if credential.get("state") == "admitted"]
            if len(admitted) == 1:
                return outcomes, last_credentials

            blocking = [
                outcome
                for outcome in outcomes
                if outcome.get("outcome") in {"blocked", "failed", "rejected"}
            ]
            if blocking:
                raise RuntimeError(f"W3C holder import failed or was blocked: {blocking!r}")
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "timed out waiting for holder W3C credential import/admit; "
                    f"last_credentials={last_credentials!r}"
                )
            time.sleep(self.poll_interval)

    def _wait_for_presentation_submission(self, presentation_tx: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + self.wait_timeout
        current = presentation_tx
        while True:
            self.holder_wallet.drain_automation(max_rounds=3)
            current = self._refresh_presentation_tx(current)
            if (
                current.get("state") == "submitted"
                and current.get("submissionState") == "submitted"
                and isinstance(current.get("verifierResponse"), dict)
            ):
                return current
            if current.get("state") == "failed":
                return current
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for holder presentation submission; last_seen={current!r}")
            time.sleep(self.poll_interval)

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
