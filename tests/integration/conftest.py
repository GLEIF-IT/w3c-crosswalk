"""Live-stack fixtures for the W3C crosswalk integration layer."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess

import pytest

W3C_CROSSWALK_ROOT = Path(__file__).resolve().parents[2]
INTEGRATION_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = W3C_CROSSWALK_ROOT.parent
KERIPY_ROOT = SOURCE_ROOT / "keripy"
VLEI_ROOT = SOURCE_ROOT / "vLEI"
VRD_SCHEMA_ROOT = SOURCE_ROOT / "vrd-schema"

from .helpers import read_log_tail, terminate_process, wait_for_json_health, wait_for_port
from .constants import WITNESS_AIDS
from .topology import make_stack_topology, stack_runtime_name

CROSSWALK_PYTHON = W3C_CROSSWALK_ROOT / ".venv" / "bin" / "python"
VLEI_SERVER_BIN = VLEI_ROOT / "venv" / "bin" / "vLEI-server"
DWS_BIN = W3C_CROSSWALK_ROOT / ".venv" / "bin" / "dws"

KERIPY_WITNESS_CONFIG_DIR = KERIPY_ROOT / "scripts" / "keri" / "cf" / "main"
WITNESS_CONFIG_NAMES = ("wan", "wil", "wes")
SERVICE_SCRIPTS_ROOT = INTEGRATION_ROOT / "_services"
WITNESS_SERVER_SCRIPT = SERVICE_SCRIPTS_ROOT / "witness_server.py"
DWS_SERVICE_SCRIPT = SERVICE_SCRIPTS_ROOT / "did_webs_resolver.py"


def _require_path(path: Path, label: str) -> str:
    """Return a required path or skip the test when the dependency is absent."""
    if not path.exists():
        pytest.skip(f"{label} is unavailable at {path}")
    return str(path)


def _write_canonical_witness_configs(config_root: Path, live_stack: dict) -> None:
    """Write witness configs with ports rewritten for the active stack."""
    target_dir = config_root / "keri" / "cf" / "main"
    target_dir.mkdir(parents=True, exist_ok=True)

    for index, name in enumerate(WITNESS_CONFIG_NAMES):
        source = KERIPY_WITNESS_CONFIG_DIR / f"{name}.json"
        config = json.loads(source.read_text(encoding="utf-8"))
        config[name]["curls"] = [
            curl if not curl.startswith("http://") else f"http://{live_stack['host']}:{live_stack['witness_ports'][index]}/"
            for curl in config[name]["curls"]
        ]
        (target_dir / f"{name}.json").write_text(json.dumps(config), encoding="utf-8")


def _write_common_habery_config(config_root: Path, live_stack: dict) -> None:
    """Write the common KERI config consumed by newly initialized haberies."""
    target_dir = config_root / "keri" / "cf"
    target_dir.mkdir(parents=True, exist_ok=True)
    body = {
        "dt": "2026-03-31T00:00:00+00:00",
        "iurls": live_stack["witness_oobis"],
        "durls": list(live_stack["schema_oobis"].values()),
    }
    (target_dir / "common-habery-config.json").write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


def _ensure_link(target: Path, source: Path) -> None:
    """Point one staged asset path at its canonical source file."""
    if target.is_symlink() and target.resolve() == source.resolve():
        return
    if target.exists() or target.is_symlink():
        target.unlink()
    target.symlink_to(source)


def _ensure_shared_vlei_assets(shared_root: Path) -> dict[str, Path]:
    """Stage reusable live-stack assets once and return their shared paths.

    Credentials and OOBIs are served directly from their source directories.
    Schemas are staged in one shared directory as symlinks so the live stack
    does not recopy them for every test runtime.
    """
    schema_root = shared_root / "schema"
    schema_root.mkdir(parents=True, exist_ok=True)

    for schema_path in (VLEI_ROOT / "schema" / "acdc").iterdir():
        if schema_path.is_file():
            _ensure_link(schema_root / schema_path.name, schema_path)

    _ensure_link(schema_root / "vrd-auth-schema.json", VRD_SCHEMA_ROOT / "vrd-auth-schema.json")
    _ensure_link(schema_root / "vrd-schema.json", VRD_SCHEMA_ROOT / "vrd-schema.json")

    return {
        "schema_root": schema_root,
        "cred_root": VLEI_ROOT / "samples" / "acdc",
        "oobi_root": VLEI_ROOT / "samples" / "oobis",
    }


def _prepare_vlei_runtime_assets(live_stack: dict, *, shared_assets: dict[str, Path]) -> None:
    """Attach the shared vLEI asset roots to the live-stack contract."""
    live_stack["schema_root"] = shared_assets["schema_root"]
    live_stack["cred_root"] = shared_assets["cred_root"]
    live_stack["oobi_root"] = shared_assets["oobi_root"]


def _terminate_all(procs: list[tuple[str, subprocess.Popen[bytes]]]) -> None:
    """Terminate all managed subprocesses in reverse launch order."""
    for _, proc in reversed(procs):
        terminate_process(proc)


def _wait_process_port(live_stack: dict, proc: subprocess.Popen[bytes], name: str, port: int, log_path: Path) -> None:
    """Wait for one managed subprocess to bind its advertised TCP port."""
    wait_for_port(live_stack["host"], port, proc, name, log_path=log_path)


def _launch_did_webs_for_actor(live_stack: dict, *, name: str, alias: str, passcode: str) -> dict[str, str]:
    """Launch did:webs artifact and resolver services on first use.

    The service pair is started lazily because only the W3C issuance and
    verification phase needs it.
    """
    if live_stack.get("did_webs_running"):
        return {
            "artifact_url": live_stack["dws_artifact_url"],
            "resolver_url": live_stack["dws_resolver_url"],
        }

    script = _require_path(DWS_SERVICE_SCRIPT, "did-webs service wrapper")
    dws_bin = _require_path(DWS_BIN, "did-webs CLI")
    env = os.environ.copy()
    env["HOME"] = str(live_stack["home"])

    artifact_log_path = Path(live_stack["log_root"]) / "did-webs-artifact.log"
    resolver_log_path = Path(live_stack["log_root"]) / "did-webs-resolver.log"
    artifact_log = artifact_log_path.open("wb")
    resolver_log = resolver_log_path.open("wb")
    live_stack["open_logs"].extend([artifact_log, resolver_log])

    artifact = subprocess.Popen(
        [
            str(CROSSWALK_PYTHON),
            "-u",
            script,
            "--mode",
            "artifact",
            "--dws-bin",
            dws_bin,
            "--name",
            name,
            "--alias",
            alias,
            "--passcode",
            passcode,
            "--http-port",
            str(live_stack["topology"].dws_artifact_port),
            "--did-path",
            "dws",
        ],
        cwd=W3C_CROSSWALK_ROOT,
        env=env,
        stdout=artifact_log,
        stderr=subprocess.STDOUT,
    )
    live_stack["runtime_procs"].append(("did-webs-artifact", artifact))
    _wait_process_port(live_stack, artifact, "did-webs-artifact", live_stack["topology"].dws_artifact_port, artifact_log_path)

    resolver = subprocess.Popen(
        [
            str(CROSSWALK_PYTHON),
            "-u",
            script,
            "--mode",
            "resolver",
            "--dws-bin",
            dws_bin,
            "--name",
            name,
            "--passcode",
            passcode,
            "--http-port",
            str(live_stack["topology"].dws_resolver_port),
            "--did-path",
            "dws",
        ],
        cwd=W3C_CROSSWALK_ROOT,
        env=env,
        stdout=resolver_log,
        stderr=subprocess.STDOUT,
    )
    live_stack["runtime_procs"].append(("did-webs-resolver", resolver))
    _wait_process_port(live_stack, resolver, "did-webs-resolver", live_stack["topology"].dws_resolver_port, resolver_log_path)
    live_stack["did_webs_running"] = True
    return {"artifact_url": live_stack["dws_artifact_url"], "resolver_url": live_stack["dws_resolver_url"]}


@contextmanager
def _launch_live_stack(live_stack: dict, *, shared_assets: dict[str, Path]):
    """Launch the subprocess-managed services that make up the live stack.

    The fixture contract uses subprocesses only for long-lived network-facing
    services. All KERI workflow steps run separately in-process through the
    workflow helpers.
    """
    witness_python = _require_path(CROSSWALK_PYTHON, "crosswalk python")
    vlei_server_bin = _require_path(VLEI_SERVER_BIN, "vLEI-server binary")

    _prepare_vlei_runtime_assets(live_stack, shared_assets=shared_assets)
    _write_canonical_witness_configs(Path(live_stack["config_root"]), live_stack)
    _write_common_habery_config(Path(live_stack["config_root"]), live_stack)

    shared_env = os.environ.copy()
    shared_env["HOME"] = str(live_stack["home"])
    shared_env["PYTHONWARNINGS"] = "ignore"

    procs: list[tuple[str, subprocess.Popen[bytes]]] = []
    open_logs = []
    live_stack["runtime_procs"] = procs
    live_stack["open_logs"] = open_logs
    live_stack["dws_bin"] = _require_path(DWS_BIN, "did-webs CLI")
    live_stack["crosswalk_python"] = witness_python
    live_stack["witness_aids"] = WITNESS_AIDS
    live_stack["status_store"] = Path(live_stack["runtime_root"]) / "status-store.json"
    live_stack["launch_did_webs"] = _launch_did_webs_for_actor
    live_stack["did_webs_running"] = False

    witness_log_path = Path(live_stack["log_root"]) / "witness.log"
    vlei_log_path = Path(live_stack["log_root"]) / "vlei.log"
    status_log_path = Path(live_stack["log_root"]) / "status.log"
    witness_log = witness_log_path.open("wb")
    vlei_log = vlei_log_path.open("wb")
    status_log = status_log_path.open("wb")
    open_logs.extend([witness_log, vlei_log, status_log])

    witness = subprocess.Popen(
        [
            witness_python,
            "-u",
            _require_path(WITNESS_SERVER_SCRIPT, "witness service script"),
            "--config-dir",
            str(live_stack["config_root"]),
            "--wan-port",
            str(live_stack["witness_ports"][0]),
            "--wil-port",
            str(live_stack["witness_ports"][1]),
            "--wes-port",
            str(live_stack["witness_ports"][2]),
        ],
        cwd=W3C_CROSSWALK_ROOT,
        env=shared_env,
        stdout=witness_log,
        stderr=subprocess.STDOUT,
    )
    procs.append(("witness-demo", witness))
    for port in live_stack["witness_ports"]:
        _wait_process_port(live_stack, witness, "witness-demo", port, witness_log_path)

    vlei = subprocess.Popen(
        [
            vlei_server_bin,
            "--schema-dir",
            str(live_stack["schema_root"]),
            "--cred-dir",
            str(live_stack["cred_root"]),
            "--oobi-dir",
            str(live_stack["oobi_root"]),
            "--http",
            str(live_stack["topology"].vlei_port),
        ],
        cwd=W3C_CROSSWALK_ROOT,
        env=shared_env,
        stdout=vlei_log,
        stderr=subprocess.STDOUT,
    )
    procs.append(("vlei-server", vlei))
    _wait_process_port(live_stack, vlei, "vlei-server", live_stack["topology"].vlei_port, vlei_log_path)

    status = subprocess.Popen(
        [
            witness_python,
            "-u",
            "-m",
            "w3c_crosswalk.cli",
            "status-serve",
            "--host",
            live_stack["host"],
            "--port",
            str(live_stack["topology"].status_port),
            "--status-store",
            str(live_stack["status_store"]),
            "--base-url",
            live_stack["status_base_url"],
        ],
        cwd=W3C_CROSSWALK_ROOT,
        env=shared_env,
        stdout=status_log,
        stderr=subprocess.STDOUT,
    )
    procs.append(("status-service", status))
    _wait_process_port(live_stack, status, "status-service", live_stack["topology"].status_port, status_log_path)
    wait_for_json_health(f"{live_stack['status_base_url']}/health")

    try:
        yield live_stack
    finally:
        _terminate_all(procs)
        for handle in open_logs:
            handle.close()


def _port_conflict(err: BaseException) -> bool:
    """Return whether an exception looks like a transient port-allocation clash."""
    text = str(err).lower()
    return (
        "address already in use" in text
        or "cannot create http server on port" in text
        or "errno 98" in text
        or "errno 48" in text
    )


def _current_worker_id() -> str:
    """Return the current pytest-xdist worker id or `master`."""
    return os.getenv("PYTEST_XDIST_WORKER", "master")


def _stack_fixture(tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest, *, mode: str):
    """Create and yield a live stack, retrying a few times on port conflicts."""
    shared_assets = _ensure_shared_vlei_assets(tmp_path_factory.getbasetemp() / "shared-vlei-assets")
    last_err = None
    for attempt in range(3):
        worker_id = _current_worker_id()
        nodeid = request.node.nodeid if mode == "isolated" else None
        runtime_root = tmp_path_factory.mktemp(stack_runtime_name(mode=mode, worker_id=worker_id, nodeid=nodeid, attempt=attempt))
        topology = make_stack_topology(runtime_root, worker_id=worker_id, mode=mode)
        live_stack = topology.as_live_stack()
        try:
            with _launch_live_stack(live_stack, shared_assets=shared_assets) as launched:
                yield launched
                return
        except (RuntimeError, TimeoutError) as err:
            if not _port_conflict(err):
                raise
            last_err = err
    raise RuntimeError("failed to launch live stack after repeated port conflicts") from last_err


@pytest.fixture
def live_stack(tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest):
    """Yield an isolated live stack for one integration test invocation."""
    yield from _stack_fixture(tmp_path_factory, request, mode="isolated")
