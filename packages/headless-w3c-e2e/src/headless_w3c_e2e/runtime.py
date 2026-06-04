"""Executable live-stack runtime for the headless W3C holder E2E harness.

The runtime is the browserless equivalent of the React holder flow. It connects
real SignifyPy clients to live KERIA, builds W3C VC-JWT and VP-JWT artifacts at
the edge, and collects evidence from live Python, Node, and Go verifier HTTP
services. It must not be replaced with verifier test doubles or CLI-only
verification commands.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from signifypy_w3c import SignifyEdgeSigner
from vc_isomer.jwt import decode_jwt, issue_vc_jwt, issue_vp_jwt

from .scenario import HeadlessW3CE2E, ScenarioManifest
from .verifiers import LiveVerifierServiceSet
from .wallet import HeadlessW3CWallet


class HeadlessLiveConfigError(ValueError):
    """Raised when a live headless E2E run is missing required inputs."""


class HeadlessLiveDependencyError(RuntimeError):
    """Raised when an optional live-run dependency is not installed."""


@dataclass(frozen=True)
class WalletConnection:
    """KERIA wallet connection inputs for one SignifyPy edge actor."""

    name: str
    passcode: str


@dataclass(frozen=True)
class HeadlessLiveRunConfig:
    """Inputs required to run the live headless holder presentation flow.

    ``verifier_urls`` are used by the harness to health-check and poll operation
    documents. ``verifier_submission_urls`` are the URLs KERIA embeds in holder
    presentation descriptors; they may differ in Docker mode where KERIA talks
    to service names while the harness polls localhost.
    """

    stack: str
    admin_url: str
    boot_url: str
    qvi: WalletConnection
    holder: WalletConnection
    source_credential_said: str
    verifier_urls: dict[str, str]
    verifier_submission_urls: dict[str, str]
    dashboard_url: str | None = None
    boot_if_needed: bool = False
    unsafe_raw_tokens: bool = False
    manifest_out: str | None = None

    REQUIRED_VERIFIERS = ("python", "node", "go")

    @classmethod
    def from_sources(
        cls,
        *,
        stack: str,
        manifest_path: str | None = None,
        environ: dict[str, str] | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> "HeadlessLiveRunConfig":
        """Build config from a manifest, environment, and explicit overrides.

        The config intentionally requires Python, Node, and Go verifier service
        URLs. Missing any verifier is an acceptance failure because cross-isomer
        compatibility is the point of this harness.
        """
        env = os.environ if environ is None else environ
        manifest = _load_manifest(manifest_path)
        data: dict[str, Any] = {**manifest, **_clean_overrides(overrides or {})}

        admin_url = _first_string(
            data.get("admin_url"),
            data.get("adminUrl"),
            env.get("KERIA_ADMIN_URL"),
            env.get("W3C_KERIA_ADMIN_URL"),
            "http://127.0.0.1:3901",
        )
        boot_url = _first_string(
            data.get("boot_url"),
            data.get("bootUrl"),
            env.get("KERIA_BOOT_URL"),
            env.get("W3C_KERIA_BOOT_URL"),
            "http://127.0.0.1:3903",
        )
        credentials = data.get("credentials") if isinstance(data.get("credentials"), dict) else {}
        source_credential_said = _required_string(
            "source credential SAID",
            data.get("sourceCredentialSaid"),
            data.get("credentialSaid"),
            credentials.get("vrd"),
            env.get("W3C_SOURCE_CREDENTIAL_SAID"),
            env.get("W3C_CREDENTIAL_SAID"),
        )

        qvi_wallet = _wallet_data(data, direct_key="qviWallet", actor_keys=("qvi",))
        holder_wallet = _wallet_data(data, direct_key="holderWallet", actor_keys=("holder", "le"))
        qvi = WalletConnection(
            name=_required_string(
                "QVI wallet alias",
                data.get("qviAlias"),
                data.get("qviName"),
                qvi_wallet.get("name"),
                env.get("W3C_QVI_ALIAS"),
            ),
            passcode=_required_string(
                "QVI wallet passcode",
                data.get("qviPasscode"),
                qvi_wallet.get("passcode"),
                env.get("W3C_QVI_PASSCODE"),
            ),
        )
        holder = WalletConnection(
            name=_required_string(
                "holder wallet alias",
                data.get("holderAlias"),
                data.get("holderName"),
                holder_wallet.get("name"),
                env.get("W3C_HOLDER_ALIAS"),
            ),
            passcode=_required_string(
                "holder wallet passcode",
                data.get("holderPasscode"),
                holder_wallet.get("passcode"),
                env.get("W3C_HOLDER_PASSCODE"),
            ),
        )

        verifier_urls = _verifier_urls(data, env)
        missing = [name for name in cls.REQUIRED_VERIFIERS if name not in verifier_urls]
        if missing:
            raise HeadlessLiveConfigError(f"missing verifier service URLs: {', '.join(missing)}")
        verifier_submission_urls = _verifier_submission_urls(data, env, verifier_urls)

        return cls(
            stack=stack,
            admin_url=admin_url,
            boot_url=boot_url,
            qvi=qvi,
            holder=holder,
            source_credential_said=source_credential_said,
            verifier_urls=verifier_urls,
            verifier_submission_urls=verifier_submission_urls,
            dashboard_url=_first_string(
                data.get("dashboardUrl"),
                data.get("dashboard_url"),
                env.get("W3C_DASHBOARD_URL"),
                env.get("ISOMER_DASHBOARD_URL"),
            ),
            boot_if_needed=_bool(data.get("bootIfNeeded"), env.get("W3C_BOOT_IF_NEEDED")),
            unsafe_raw_tokens=_bool(data.get("unsafeRawTokens"), env.get("W3C_UNSAFE_RAW_TOKENS")),
            manifest_out=_first_string(data.get("manifestOut"), env.get("W3C_MANIFEST_OUT")),
        )

    def to_safe_dict(self) -> dict[str, Any]:
        """Return config facts safe for an evidence manifest."""
        body = asdict(self)
        body["qvi"] = {"name": self.qvi.name}
        body["holder"] = {"name": self.holder.name}
        body.pop("unsafe_raw_tokens", None)
        return body


def run_live_headless(config: HeadlessLiveRunConfig) -> dict[str, Any]:
    """Run the configured live headless holder presentation flow.

    The flow starts W3C issuance from the QVI edge, waits for holder W3C
    credential materialization, presents to each live verifier service, then
    polls verifier operations for evidence. VC-JWT and VP-JWT signing uses
    SignifyPy keepers through ``signifypy-w3c``.
    """
    if config.stack not in {"attach", "process", "docker"}:
        raise HeadlessLiveConfigError(f"unsupported stack mode {config.stack!r}")

    signify = _load_signifypy()
    qvi_client = _connect_client(signify, config.qvi, config)
    holder_client = _connect_client(signify, config.holder, config)

    services = LiveVerifierServiceSet.from_urls(
        config.verifier_urls,
        submission_urls=config.verifier_submission_urls,
    )
    qvi_wallet = HeadlessW3CWallet.from_client(config.qvi.name, qvi_client)
    holder_wallet = HeadlessW3CWallet.from_client(config.holder.name, holder_client)
    scenario = HeadlessW3CE2E(qvi_wallet, holder_wallet, services)

    manifest = scenario.run_happy_path_for_services(config.source_credential_said)
    negative_evidence = _collect_negative_live_evidence(
        services,
        manifest,
        qvi_client=qvi_client,
        qvi_name=config.qvi.name,
        holder_client=holder_client,
        holder_name=config.holder.name,
    )
    return render_manifest(config, manifest, negative_evidence=negative_evidence)


def render_manifest(
    config: HeadlessLiveRunConfig,
    manifest: ScenarioManifest,
    *,
    negative_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Render one live run manifest, omitting raw tokens unless requested.

    The manifest is evidence, not a fixture source. Raw JWTs stay redacted by
    default so validation output can be shared without leaking signed artifacts.
    """
    scenario = manifest.to_dict()
    if negative_evidence is not None:
        scenario["negativeEvidence"] = negative_evidence
        if negative_evidence.get("passed") is not True:
            scenario.setdefault("failures", []).append(
                {
                    "stage": "negative",
                    "error": "one or more live negative verifier cases did not reject",
                    "evidence": negative_evidence,
                }
            )
    dashboard_evidence = _collect_dashboard_evidence(config.dashboard_url, scenario)
    if dashboard_evidence is not None:
        scenario["dashboardEvidence"] = dashboard_evidence
        if dashboard_evidence.get("accepted") is not True:
            scenario.setdefault("failures", []).append(
                {
                    "stage": "dashboard",
                    "error": "verifier dashboard did not report every live presentation webhook",
                    "evidence": dashboard_evidence,
                }
            )
    body = {
        "runtime": config.to_safe_dict(),
        "scenario": scenario,
    }
    if not config.unsafe_raw_tokens:
        body = _strip_raw_tokens(body)
    return body


def write_manifest(path: str | Path, body: dict[str, Any]) -> None:
    """Write one JSON manifest to disk."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _collect_negative_live_evidence(
    services: LiveVerifierServiceSet,
    manifest: ScenarioManifest,
    *,
    qvi_client: Any | None = None,
    qvi_name: str | None = None,
    holder_client: Any | None = None,
    holder_name: str | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for tx in manifest.presentationTxs:
        descriptor = tx.get("requestDescriptor") if isinstance(tx, dict) else None
        if not isinstance(descriptor, dict):
            continue
        service_name = descriptor.get("verifierId")
        token = tx.get("vpJwt")
        if not isinstance(service_name, str) or not isinstance(token, str):
            continue
        service = services.services.get(service_name)
        if service is None:
            continue
        aud = tx.get("aud") or descriptor.get("aud")
        nonce = tx.get("nonce") or descriptor.get("nonce")
        if isinstance(aud, str):
            checks.append(
                _run_negative_vp_case(
                    service_name=service_name,
                    case="wrong_aud",
                    service=service,
                    token=token,
                    audience=f"{aud}#wrong",
                    nonce=nonce if isinstance(nonce, str) else None,
                )
            )
        if isinstance(nonce, str):
            checks.append(
                _run_negative_vp_case(
                    service_name=service_name,
                    case="wrong_nonce",
                    service=service,
                    token=token,
                    audience=aud if isinstance(aud, str) else None,
                    nonce=f"{nonce}-wrong",
                )
            )
        checks.extend(
            _collect_qvi_signed_vp_negative_cases(
                services=services,
                manifest=manifest,
                tx=tx,
                qvi_client=qvi_client,
                qvi_name=qvi_name,
            )
        )
        checks.extend(
            _collect_le_as_issuer_vc_negative_cases(
                services=services,
                manifest=manifest,
                tx=tx,
                holder_client=holder_client,
                holder_name=holder_name,
            )
        )
    return {
        "passed": bool(checks) and all(check.get("rejected") is True for check in checks),
        "checks": checks,
    }


def _collect_qvi_signed_vp_negative_cases(
    *,
    services: LiveVerifierServiceSet,
    manifest: ScenarioManifest,
    tx: dict[str, Any],
    qvi_client: Any | None,
    qvi_name: str | None,
) -> list[dict[str, Any]]:
    descriptor = tx.get("requestDescriptor") if isinstance(tx, dict) else None
    service_name = descriptor.get("verifierId") if isinstance(descriptor, dict) else None
    if not isinstance(service_name, str):
        return []
    service = services.services.get(service_name)
    if service is None:
        return []

    check: dict[str, Any] = {
        "name": service_name,
        "case": "qvi_signed_vp",
        "rejected": False,
        "expectedError": "embedded credential subject DID does not match VP holder",
    }
    if qvi_client is None or not qvi_name:
        check["error"] = "QVI client inputs were unavailable for live edge signing"
        return [check]

    vc_token = manifest.issuance.get("vcJwt")
    qvi_did = manifest.issuance.get("issuerDid")
    aud = tx.get("aud") or descriptor.get("aud")
    nonce = tx.get("nonce") or descriptor.get("nonce")
    if not all(isinstance(value, str) and value for value in (vc_token, qvi_did, aud, nonce)):
        check["error"] = "QVI-signed VP negative case was missing VC token, QVI DID, audience, or nonce"
        return [check]

    try:
        signer = SignifyEdgeSigner(qvi_client, qvi_name)
        token, _vp = issue_vp_jwt(
            [vc_token],
            holder_did=qvi_did,
            signer=signer,
            audience=aud,
            nonce=nonce,
        )
    except Exception as exc:
        check["error"] = f"failed to create QVI-signed VP with live edge signer: {exc}"
        return [check]

    return [
        _run_negative_vp_case(
            service_name=service_name,
            case="qvi_signed_vp",
            service=service,
            token=token,
            audience=aud,
            nonce=nonce,
            expected_error="embedded credential subject DID does not match VP holder",
        )
    ]


def _collect_le_as_issuer_vc_negative_cases(
    *,
    services: LiveVerifierServiceSet,
    manifest: ScenarioManifest,
    tx: dict[str, Any],
    holder_client: Any | None,
    holder_name: str | None,
) -> list[dict[str, Any]]:
    descriptor = tx.get("requestDescriptor") if isinstance(tx, dict) else None
    service_name = descriptor.get("verifierId") if isinstance(descriptor, dict) else None
    if not isinstance(service_name, str):
        return []
    service = services.services.get(service_name)
    if service is None:
        return []

    check: dict[str, Any] = {
        "name": service_name,
        "case": "le_as_issuer_vc",
        "rejected": False,
        "expectedError": "VC issuer DID does not match isomer source issuer AID",
    }
    if holder_client is None or not holder_name:
        check["error"] = "holder client inputs were unavailable for live edge signing"
        return [check]

    vc_token = manifest.issuance.get("vcJwt")
    holder_did = manifest.issuance.get("holderDid")
    if not isinstance(vc_token, str) or not isinstance(holder_did, str) or not holder_did:
        check["error"] = "LE-as-issuer VC negative case was missing VC token or holder DID"
        return [check]

    try:
        signer = SignifyEdgeSigner(holder_client, holder_name)
        decoded = decode_jwt(vc_token)
        source_vc = decoded.payload.get("vc")
        if not isinstance(source_vc, dict):
            raise HeadlessLiveConfigError("issuer VC-JWT did not contain a VC payload")
        vc = deepcopy(source_vc)
        vc["issuer"] = holder_did
        vc.pop("proof", None)
        token, _vc = issue_vc_jwt(
            vc,
            signer=signer,
            verification_method=f"{holder_did}#{signer.kid}",
        )
    except Exception as exc:
        check["error"] = f"failed to create LE-as-issuer VC with live edge signer: {exc}"
        return [check]

    return [
        _run_negative_vc_case(
            service_name=service_name,
            case="le_as_issuer_vc",
            service=service,
            token=token,
            expected_error="VC issuer DID does not match isomer source issuer AID",
        )
    ]


def _run_negative_vc_case(
    *,
    service_name: str,
    case: str,
    service: Any,
    token: str,
    expected_error: str,
) -> dict[str, Any]:
    check: dict[str, Any] = {
        "name": service_name,
        "case": case,
        "rejected": False,
        "expectedError": expected_error,
    }
    try:
        operation = service.client.verify_vc(token)
    except Exception as exc:
        check["rejected"] = True
        check["error"] = str(exc)
        check["expectedErrorObserved"] = expected_error in str(exc)
        check["rejected"] = check["rejected"] and check["expectedErrorObserved"]
        return check
    response = operation.get("response") if isinstance(operation, dict) else None
    check["operation"] = operation
    check["rejected"] = (response.get("ok") is False if isinstance(response, dict) else False) or operation.get("error") is not None
    if isinstance(response, dict):
        check["response"] = response
    observed = _operation_contains_error(operation, expected_error)
    check["expectedErrorObserved"] = observed
    check["rejected"] = check["rejected"] and observed
    return check


def _run_negative_vp_case(
    *,
    service_name: str,
    case: str,
    service: Any,
    token: str,
    audience: str | None,
    nonce: str | None,
    expected_error: str | None = None,
) -> dict[str, Any]:
    check: dict[str, Any] = {
        "name": service_name,
        "case": case,
        "rejected": False,
        "audience": audience,
        "nonce": nonce,
    }
    if expected_error is not None:
        check["expectedError"] = expected_error
    try:
        operation = service.client.verify_vp(token, audience=audience, nonce=nonce)
    except Exception as exc:
        check["rejected"] = True
        check["error"] = str(exc)
        return check
    response = operation.get("response") if isinstance(operation, dict) else None
    ok = response.get("ok") if isinstance(response, dict) else None
    check["operation"] = operation
    check["rejected"] = ok is False or operation.get("error") is not None
    if isinstance(response, dict):
        check["response"] = response
    if expected_error is not None:
        observed = _operation_contains_error(operation, expected_error)
        check["expectedErrorObserved"] = observed
        check["rejected"] = check["rejected"] and observed
    return check


def _operation_contains_error(operation: dict[str, Any], expected: str) -> bool:
    """Return true when a verifier operation includes the expected error text."""
    return any(expected in item for item in _operation_error_strings(operation))


def _operation_error_strings(value: Any) -> list[str]:
    """Collect error strings from a nested verifier operation/response object."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        items: list[str] = []
        for entry in value:
            items.extend(_operation_error_strings(entry))
        return items
    if isinstance(value, dict):
        items: list[str] = []
        for key in ("message", "error"):
            if key in value:
                items.extend(_operation_error_strings(value[key]))
        errors = value.get("errors")
        if errors is not None:
            items.extend(_operation_error_strings(errors))
        response = value.get("response")
        if response is not None:
            items.extend(_operation_error_strings(response))
        details = value.get("details")
        if details is not None:
            items.extend(_operation_error_strings(details))
        return items
    return []


def _collect_dashboard_evidence(dashboard_url: str | None, scenario: dict[str, Any]) -> dict[str, Any] | None:
    if not dashboard_url:
        return None

    expected = _expected_dashboard_presentations(scenario)
    evidence = {
        "dashboardUrl": dashboard_url.rstrip("/"),
        "accepted": False,
        "expected": expected,
        "matches": [],
        "errors": [],
    }
    if not expected:
        evidence["errors"].append("scenario did not include expected presentation transactions")
        return evidence

    deadline = time.monotonic() + 10.0
    last_events: list[dict[str, Any]] = []
    while True:
        try:
            events = _dashboard_presentations(dashboard_url)
        except Exception as exc:
            evidence["errors"] = [str(exc)]
            events = []
        last_events = events
        matches = _match_dashboard_presentations(events, expected)
        if len(matches) == len(expected):
            evidence["accepted"] = True
            evidence["matches"] = matches
            return evidence
        if time.monotonic() >= deadline:
            evidence["matches"] = matches
            evidence["seen"] = _dashboard_seen_summary(last_events)
            evidence["errors"].append("timed out waiting for dashboard presentation events")
            return evidence
        time.sleep(0.25)


def _expected_dashboard_presentations(scenario: dict[str, Any]) -> list[dict[str, str]]:
    expected: list[dict[str, str]] = []
    for tx in scenario.get("presentationTxs", []):
        if not isinstance(tx, dict):
            continue
        descriptor = tx.get("requestDescriptor")
        verifier = descriptor.get("verifierId") if isinstance(descriptor, dict) else None
        present_tx_id = tx.get("presentTxId") or tx.get("d")
        if isinstance(verifier, str) and isinstance(present_tx_id, str):
            expected.append({"verifier": verifier, "presentTxId": present_tx_id})
    return expected


def _dashboard_presentations(dashboard_url: str) -> list[dict[str, Any]]:
    request = Request(f"{dashboard_url.rstrip('/')}/api/presentations", headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=3.0) as response:
            body = response.read()
            status = response.status
    except HTTPError as exc:
        raise RuntimeError(f"dashboard returned HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')}") from exc
    except URLError as exc:
        raise RuntimeError(f"dashboard unreachable: {exc.reason}") from exc
    if status != 200:
        raise RuntimeError(f"dashboard returned HTTP {status}")
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, list):
        raise RuntimeError(f"dashboard presentation list was not a JSON array: {payload!r}")
    return [event for event in payload if isinstance(event, dict)]


def _match_dashboard_presentations(
    events: list[dict[str, Any]],
    expected: list[dict[str, str]],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in expected:
        for event in events:
            verifier = event.get("verifier") if isinstance(event.get("verifier"), dict) else {}
            presentation = event.get("presentation") if isinstance(event.get("presentation"), dict) else {}
            verification = event.get("verification") if isinstance(event.get("verification"), dict) else {}
            if not _dashboard_verifier_matches(verifier.get("id"), item["verifier"]):
                continue
            if not _dashboard_presentation_id_matches(presentation.get("id"), item["presentTxId"]):
                continue
            matches.append(
                {
                    **item,
                    "eventId": event.get("eventId"),
                    "verifiedAt": event.get("verifiedAt"),
                    "verificationOk": verification.get("ok"),
                    "credentialTypes": presentation.get("credentialTypes"),
                }
            )
            break
    return matches


def _dashboard_verifier_matches(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and actual in {expected, f"isomer-{expected}"}


def _dashboard_presentation_id_matches(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and actual in {expected, f"urn:said:{expected}"}


def _dashboard_seen_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for event in events[:20]:
        verifier = event.get("verifier") if isinstance(event.get("verifier"), dict) else {}
        presentation = event.get("presentation") if isinstance(event.get("presentation"), dict) else {}
        verification = event.get("verification") if isinstance(event.get("verification"), dict) else {}
        summary.append(
            {
                "verifier": verifier.get("id"),
                "presentationId": presentation.get("id"),
                "verificationOk": verification.get("ok"),
                "eventId": event.get("eventId"),
            }
        )
    return summary


def _load_signifypy():
    try:
        from keri import kering
        from keri.core.coring import Tiers
        from signify.app.clienting import SignifyClient
    except ImportError as exc:
        raise HeadlessLiveDependencyError(
            "live headless runs require SignifyPy and KERIpy; install signifypy in this environment"
        ) from exc
    return _SignifyPy(
        ConfigurationError=kering.ConfigurationError,
        Tiers=Tiers,
        SignifyClient=SignifyClient,
    )


@dataclass(frozen=True)
class _SignifyPy:
    ConfigurationError: type[Exception]
    Tiers: Any
    SignifyClient: Any


def _connect_client(signify: _SignifyPy, wallet: WalletConnection, config: HeadlessLiveRunConfig):
    client = signify.SignifyClient(
        passcode=wallet.passcode,
        url=config.admin_url,
        boot_url=config.boot_url,
        tier=signify.Tiers.low,
    )
    try:
        client.connect()
    except signify.ConfigurationError as exc:
        if not config.boot_if_needed or "agent does not exist" not in str(exc):
            raise
        client.boot()
        client.connect()
    return client


def _load_manifest(path: str | None) -> dict[str, Any]:
    if path is None or not path:
        return {}
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise HeadlessLiveConfigError(f"manifest {path} must contain a JSON object")
    return manifest


def _clean_overrides(overrides: dict[str, Any]) -> dict[str, Any]:
    """Drop empty explicit inputs so manifests and env remain usable defaults."""
    cleaned: dict[str, Any] = {}
    for key, value in overrides.items():
        if value is None:
            continue
        if isinstance(value, dict):
            nested = _clean_overrides(value)
            if nested:
                cleaned[key] = nested
            continue
        cleaned[key] = value
    return cleaned


def _wallet_data(data: dict[str, Any], *, direct_key: str, actor_keys: tuple[str, ...]) -> dict[str, Any]:
    """Extract wallet connection data from direct or seeder actor manifests."""
    direct = data.get(direct_key)
    if isinstance(direct, dict):
        return direct
    actors = data.get("actors")
    if isinstance(actors, dict):
        for actor_key in actor_keys:
            actor = actors.get(actor_key)
            if isinstance(actor, dict):
                return actor
    return {}


def _verifier_urls(data: dict[str, Any], env: dict[str, str]) -> dict[str, str]:
    urls = data.get("verifierUrls")
    if not isinstance(urls, dict):
        urls = {}
    parsed = {str(name): str(value).rstrip("/") for name, value in urls.items() if isinstance(value, str) and value}
    env_map = {
        "python": env.get("W3C_PYTHON_VERIFIER_URL") or env.get("PYTHON_VERIFIER_URL"),
        "node": env.get("W3C_NODE_VERIFIER_URL") or env.get("NODE_VERIFIER_URL"),
        "go": env.get("W3C_GO_VERIFIER_URL") or env.get("GO_VERIFIER_URL"),
    }
    for name, value in env_map.items():
        if isinstance(value, str) and value.strip():
            parsed[name] = value.strip().rstrip("/")
    return parsed


def _verifier_submission_urls(
    data: dict[str, Any],
    env: dict[str, str],
    verifier_urls: dict[str, str],
) -> dict[str, str]:
    urls = data.get("verifierSubmissionUrls")
    if not isinstance(urls, dict):
        urls = {}
    parsed = {str(name): str(value).rstrip("/") for name, value in urls.items() if isinstance(value, str) and value}
    env_map = {
        "python": env.get("W3C_PYTHON_VERIFIER_SUBMISSION_URL") or env.get("PYTHON_VERIFIER_SUBMISSION_URL"),
        "node": env.get("W3C_NODE_VERIFIER_SUBMISSION_URL") or env.get("NODE_VERIFIER_SUBMISSION_URL"),
        "go": env.get("W3C_GO_VERIFIER_SUBMISSION_URL") or env.get("GO_VERIFIER_SUBMISSION_URL"),
    }
    for name, value in env_map.items():
        if isinstance(value, str) and value.strip():
            parsed[name] = value.strip().rstrip("/")
    return {name: parsed.get(name, verifier_urls[name]) for name in verifier_urls}


def _required_string(label: str, *values: Any) -> str:
    value = _first_string(*values)
    if value is None:
        raise HeadlessLiveConfigError(f"{label} is required")
    return value


def _first_string(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _bool(*values: Any) -> bool:
    for value in values:
        if value is None:
            continue
        if isinstance(value, bool):
            return value
        return str(value).lower() in {"1", "true", "yes", "on"}
    return False


def _strip_raw_tokens(body: Any) -> Any:
    token_fields = {"vcJwt", "vpJwt", "token"}
    if isinstance(body, dict):
        stripped = {}
        for key, value in body.items():
            if key in token_fields:
                stripped[key] = "[redacted]"
            else:
                stripped[key] = _strip_raw_tokens(value)
        return stripped
    if isinstance(body, list):
        return [_strip_raw_tokens(item) for item in body]
    if isinstance(body, str) and _looks_like_compact_jwt(body):
        return "[redacted-jwt]"
    return body


def _looks_like_compact_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3 or len(value) < 80:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
    return all(part and set(part) <= allowed for part in parts)
