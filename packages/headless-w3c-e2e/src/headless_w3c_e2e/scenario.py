"""Scenario orchestration for the headless W3C holder E2E harness.

The scenario follows the edge-owned browser model without a browser: the QVI
edge builds and signs the VC-JWT, KERIA validates and forwards the issuer grant,
the holder edge builds and signs the VP-JWT, and KERIA validates and forwards
the verifier submission.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import time
from typing import Any


@dataclass
class ScenarioManifest:
    """Executable evidence emitted by one headless W3C E2E scenario run."""

    sourceCredentialSaid: str
    issuance: dict[str, Any]
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
        *,
        wait_timeout: float = 60.0,
        poll_interval: float = 0.5,
    ):
        self.qvi_wallet = qvi_wallet
        self.holder_wallet = holder_wallet
        self.verifier_services = verifier_services
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
        issuance, holder_credentials = self._issue_and_wait_for_holder_credential(source_credential_said)
        credential_id = self._credential_id_for_source(holder_credentials, source_credential_said)

        presentation_tx = self.holder_wallet.present_credential(credential_id, verifier_descriptor)
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
        """Submit one holder-built VP-JWT to each live verifier service."""
        self.verifier_services.healthcheck_all()
        issuance, holder_credentials = self._issue_and_wait_for_holder_credential(source_credential_said)
        credential_id = self._credential_id_for_source(holder_credentials, source_credential_said)

        artifacts_by_service: dict[str, dict[str, Any]] = {}
        presentation_txs: list[dict[str, Any]] = []
        for service_name in self.verifier_services.REQUIRED:
            verifier_descriptor = self.verifier_services.descriptor_for(
                service_name,
                nonce=None if nonces is None else nonces.get(service_name),
            )
            presentation_tx = self.holder_wallet.present_credential(credential_id, verifier_descriptor)
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

    def _issue_and_wait_for_holder_credential(self, source_credential_said: str):
        """Run QVI edge issuance and wait for holder KERIA materialization."""
        issuance = self.qvi_wallet.issue_credential(source_credential_said)
        holder_credentials = self._wait_for_holder_credential(source_credential_said)
        return issuance, holder_credentials

    def _wait_for_holder_credential(self, source_credential_said: str) -> list[dict[str, Any]]:
        deadline = time.monotonic() + self.wait_timeout
        last_credentials: list[dict[str, Any]] = []
        while True:
            last_credentials = self.holder_wallet.refresh_credentials()
            matching = [
                credential
                for credential in last_credentials
                if credential.get("sourceCredentialSaid") == source_credential_said
            ]
            admitted = [credential for credential in matching if credential.get("state") == "admitted"]
            if len(admitted) == 1:
                return last_credentials
            if len(admitted) > 1:
                raise RuntimeError(f"holder has multiple W3C credentials for {source_credential_said}: {admitted!r}")
            failures = [credential for credential in matching if credential.get("state") == "failed"]
            if failures:
                raise RuntimeError(f"W3C holder credential materialization failed: {failures!r}")
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "timed out waiting for holder W3C credential materialization; "
                    f"last_credentials={last_credentials!r}"
                )
            time.sleep(self.poll_interval)

    def _wait_for_presentation_submission(self, presentation_tx: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + self.wait_timeout
        current = presentation_tx
        while True:
            if (
                current.get("state") in {"submitted", "verified"}
                and current.get("submissionState") == "submitted"
                and isinstance(current.get("verifierResponse"), dict)
            ):
                return current
            if current.get("state") == "failed":
                return current
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for holder presentation submission; last_seen={current!r}")
            time.sleep(self.poll_interval)
            current = self.holder_wallet.refresh_presentation(current)

    @staticmethod
    def _credential_id_for_source(holder_credentials: list[dict[str, Any]], source_credential_said: str) -> str:
        matches = [
            credential
            for credential in holder_credentials
            if credential.get("sourceCredentialSaid") == source_credential_said
            and credential.get("state") == "admitted"
        ]
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one admitted W3C credential for {source_credential_said}: {matches!r}")
        credential_id = matches[0].get("credentialId") or matches[0].get("d")
        if not isinstance(credential_id, str) or not credential_id:
            raise RuntimeError(f"holder W3C credential has no id: {matches[0]!r}")
        return credential_id

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
