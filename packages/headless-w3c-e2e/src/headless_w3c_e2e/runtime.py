"""Executable live-stack runtime for the headless W3C holder E2E harness."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from typing import Any

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
    """Inputs required to run the live headless holder presentation flow."""

    stack: str
    admin_url: str
    boot_url: str
    qvi: WalletConnection
    holder: WalletConnection
    source_credential_said: str
    verifier_urls: dict[str, str]
    verifier_submission_urls: dict[str, str]
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
        """Build config from a manifest, environment, and explicit overrides."""
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
    """Run the configured live headless holder presentation flow."""
    if config.stack not in {"attach", "process", "docker"}:
        raise HeadlessLiveConfigError(f"unsupported stack mode {config.stack!r}")

    signify = _load_signifypy()
    qvi_client = _connect_client(signify, config.qvi, config)
    holder_client = _connect_client(signify, config.holder, config)
    holder_aid = _identifier_prefix(holder_client, config.holder.name)
    approvals: dict[str, dict[str, Any]] = {}
    holder_w3c = signify.W3C(holder_client)

    def approve_presentation_tx(tx: dict[str, Any], descriptor: dict[str, Any]) -> None:
        present_tx_id = _present_tx_id(tx)
        approvals[present_tx_id] = {
            "aud": tx.get("aud") or descriptor.get("aud") or descriptor.get("client_id"),
            "nonce": tx.get("nonce") or descriptor.get("nonce"),
            "sourceCredentialSaid": config.source_credential_said,
        }

    def holder_signing_policy(request: dict[str, Any]) -> bool:
        if signify.defaultSigningPolicy(request):
            return True
        if request.get("purpose") != signify.W3C_PURPOSE_HOLDER_VP_JWT:
            return False
        if request.get("name") != config.holder.name or request.get("aid") != holder_aid:
            return False
        present_tx_id = request.get("related")
        if not isinstance(present_tx_id, str):
            return False
        approval = approvals.get(present_tx_id)
        if approval is None:
            return False
        tx = holder_w3c.presentTx(config.holder.name, present_tx_id)
        if tx.get("aud") != approval["aud"] or tx.get("nonce") != approval["nonce"]:
            return False
        selected = tx.get("selectedCredentialId")
        if isinstance(selected, str) and selected:
            held = holder_w3c.credential(config.holder.name, selected)
            if held.get("sourceCredentialSaid") != approval["sourceCredentialSaid"]:
                return False
        return True

    services = LiveVerifierServiceSet.from_urls(
        config.verifier_urls,
        submission_urls=config.verifier_submission_urls,
    )
    qvi_wallet = HeadlessW3CWallet.from_client(
        config.qvi.name,
        qvi_client,
        automator=signify.W3CEdgeAutomator(
            qvi_client,
            store=signify.MemoryW3CAutomationStore(),
        ),
    )
    holder_wallet = HeadlessW3CWallet.from_client(
        config.holder.name,
        holder_client,
        automator=signify.W3CEdgeAutomator(
            holder_client,
            store=signify.MemoryW3CAutomationStore(),
            signingPolicy=holder_signing_policy,
        ),
    )
    scenario = HeadlessW3CE2E(
        qvi_wallet,
        holder_wallet,
        services,
        presentation_approver=approve_presentation_tx,
    )

    manifest = scenario.run_happy_path_for_services(config.source_credential_said)
    return render_manifest(config, manifest)


def render_manifest(config: HeadlessLiveRunConfig, manifest: ScenarioManifest) -> dict[str, Any]:
    """Render one live run manifest, omitting raw tokens unless requested."""
    body = {
        "runtime": config.to_safe_dict(),
        "scenario": manifest.to_dict(),
    }
    if not config.unsafe_raw_tokens:
        body = _strip_raw_tokens(body)
    return body


def write_manifest(path: str | Path, body: dict[str, Any]) -> None:
    """Write one JSON manifest to disk."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_signifypy():
    try:
        from keri import kering
        from keri.core.coring import Tiers
        from signify.app.clienting import SignifyClient
        from signify.app.w3cing import (
            MemoryW3CAutomationStore,
            W3C,
            W3CEdgeAutomator,
            W3C_PURPOSE_HOLDER_VP_JWT,
            defaultSigningPolicy,
        )
    except ImportError as exc:
        raise HeadlessLiveDependencyError(
            "live headless runs require SignifyPy and KERIpy; install signifypy in this environment"
        ) from exc
    return _SignifyPy(
        ConfigurationError=kering.ConfigurationError,
        Tiers=Tiers,
        SignifyClient=SignifyClient,
        W3C=W3C,
        W3CEdgeAutomator=W3CEdgeAutomator,
        MemoryW3CAutomationStore=MemoryW3CAutomationStore,
        W3C_PURPOSE_HOLDER_VP_JWT=W3C_PURPOSE_HOLDER_VP_JWT,
        defaultSigningPolicy=defaultSigningPolicy,
    )


@dataclass(frozen=True)
class _SignifyPy:
    ConfigurationError: type[Exception]
    Tiers: Any
    SignifyClient: Any
    W3C: Any
    W3CEdgeAutomator: Any
    MemoryW3CAutomationStore: Any
    W3C_PURPOSE_HOLDER_VP_JWT: str
    defaultSigningPolicy: Any


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


def _identifier_prefix(client, name: str) -> str:
    aid = client.identifiers().get(name)
    prefix = aid.get("prefix")
    if not isinstance(prefix, str) or not prefix:
        raise HeadlessLiveConfigError(f"identifier {name!r} did not return a prefix")
    return prefix


def _present_tx_id(tx: dict[str, Any]) -> str:
    present_tx_id = tx.get("presentTxId") or tx.get("d")
    if not isinstance(present_tx_id, str) or not present_tx_id:
        raise HeadlessLiveConfigError(f"presentation transaction did not include an id: {tx!r}")
    return present_tx_id


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
    return body
