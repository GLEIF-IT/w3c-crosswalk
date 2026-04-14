"""Launch and manage the subprocess side of the live integration stack.

This module owns the network-facing portion of the end to end integration test:
- runtime directory setup (test run root and KERI home override),
- shared staged assets (vLEI schemas, VRD schemas, witness config),
- long-lived helper subprocesses (witness, vLEI-server, did:webs resolver),
- and the mutable ``live_stack`` contract that later workflow helpers consume.

KERI workflow steps do not run here. They run in-process through
``kli_flow.py`` after this fixture has established a HOME sandbox, witness
reachability, schema/helper services, and the local W3C status endpoint.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess

import pytest

from .helpers import read_log_tail, terminate_process, wait_for_json_health, wait_for_port
from .constants import WITNESS_AIDS
from .topology import make_stack_topology, stack_runtime_name

# Directory Setup
# should resolve to w3c-crosswalk/
W3C_CROSSWALK_ROOT = Path(__file__).resolve().parents[2]
# should resolve to w3c-crosswalk/tests/integration
INTEGRATION_ROOT = Path(__file__).resolve().parent
# should resolve to w3c-crosswalk/tests/integration/_assets
ASSET_ROOT = INTEGRATION_ROOT / "_assets"
WITNESS_CONFIG_ROOT = ASSET_ROOT / "keri" / "cf" / "main"
VLEI_ASSET_ROOT = ASSET_ROOT / "vlei"
VLEI_SCHEMA_ROOT = VLEI_ASSET_ROOT / "schema" / "acdc"
VLEI_CRED_ROOT = VLEI_ASSET_ROOT / "samples" / "acdc"
VLEI_OOBI_ROOT = VLEI_ASSET_ROOT / "samples" / "oobis"

# Local venv Python and binary setup
PYTHON_BIN = W3C_CROSSWALK_ROOT / ".venv" / "bin" / "python"
VLEI_SVR_BIN = W3C_CROSSWALK_ROOT / ".venv" / "bin" / "vLEI-server"
DWS_BIN = W3C_CROSSWALK_ROOT / ".venv" / "bin" / "dws"

# Witness and other service config and script names
WITNESS_CONFIG_NAMES = ("wan", "wil", "wes")
SERVICE_SCRIPTS_ROOT = INTEGRATION_ROOT / "_services"
WITNESS_SERVER_SCRIPT = SERVICE_SCRIPTS_ROOT / "witness_server.py"
DWS_SERVICE_SCRIPT = SERVICE_SCRIPTS_ROOT / "did_webs_resolver.py"


def _require_path(path: Path, label: str) -> str:
    """Return a required path or skip the test when the dependency is absent."""
    if not path.exists():
        pytest.skip(f"{label} is unavailable at {path}")
    return str(path)


def _write_witness_configs(config_root: Path, live_stack: dict) -> None:
    """
    Copy vendored witness configs into a run-specific directory with live ports.
    """
    target_dir = config_root / "keri" / "cf" / "main"
    target_dir.mkdir(parents=True, exist_ok=True)

    for index, name in enumerate(WITNESS_CONFIG_NAMES):
        source = WITNESS_CONFIG_ROOT / f"{name}.json"
        config = json.loads(source.read_text(encoding="utf-8"))
        config[name]["curls"] = [
            curl if not curl.startswith("http://") else f"http://{live_stack['host']}:{live_stack['witness_ports'][index]}/"
            for curl in config[name]["curls"]
        ]
        (target_dir / f"{name}.json").write_text(json.dumps(config), encoding="utf-8")


def _write_habery_config(config_root: Path, live_stack: dict) -> None:
    """
    Write the common KERI config consumed by newly initialized keystores including:
    - witness OOBI URLs
    - ACDC Schema URLs
    read in from the live config.

    This is the config seam that lets later KERIpy habery initialization pull
    witness and ACDC schema material from the run-specific, local live stack
    instead of from the user's machine-global environment.
    """
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


def _ensure_vlei_assets(shared_root: Path) -> dict[str, Path]:
    """
    Stage reusable live-stack assets (schemas, well knowns, .cesr streams) once
    and return their shared paths.

    Credentials and OOBIs are served directly from vendored asset directories.
    Schemas are staged in one shared directory as symlinks so the live stack
    does not recopy them for every test runtime.

    ``shared_root`` lives under ``tmp_path_factory.getbasetemp()`` and is
    shared across one pytest session or xdist worker. This is intentionally
    different from the per-stack ``runtime_root`` created with ``mktemp(...)``
    inside ``_stack_fixture(...)``.
    """
    schema_root = shared_root / "schema"  # place to host ACDC schema files
    schema_root.mkdir(parents=True, exist_ok=True)

    for schema_path in VLEI_SCHEMA_ROOT.iterdir():
        if schema_path.is_file():
            _ensure_link(schema_root / schema_path.name, schema_path)

    return {
        "schema_root": schema_root,
        "cred_root": VLEI_CRED_ROOT,
        "oobi_root": VLEI_OOBI_ROOT,
    }


def _set_vlei_dirs(live_stack: dict, *, shared_assets: dict[str, Path]) -> None:
    """Attach staged helper-asset roots to the live-stack contract.

    These directories are consumed only by the helper services. They are not
    the KERI source of truth for issued credentials or registry state.
    """
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


def _lazy_didwebs_launcher(live_stack: dict, *, name: str, alias: str, passcode: str) -> dict[str, str]:
    """Launch did:webs artifact and resolver services on first use.

    The service pair is started lazily because only the W3C issuance and
    verification phase needs it. The KERI issuance workflow deliberately does
    not depend on did:webs until the final interoperability projection phase.
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

    artifact = _did_webs_static_process(live_stack, script, dws_bin, name, alias, passcode, W3C_CROSSWALK_ROOT, env, artifact_log)
    live_stack["runtime_procs"].append(("did-webs-artifact", artifact))
    _wait_process_port(live_stack, artifact, "did-webs-artifact", live_stack["topology"].dws_artifact_port, artifact_log_path)

    resolver = _did_webs_resolver_process(live_stack, script, dws_bin, name, passcode, W3C_CROSSWALK_ROOT, env, artifact_log)
    live_stack["runtime_procs"].append(("did-webs-resolver", resolver))
    _wait_process_port(live_stack, resolver, "did-webs-resolver", live_stack["topology"].dws_resolver_port, resolver_log_path)
    live_stack["did_webs_running"] = True
    return {"artifact_url": live_stack["dws_artifact_url"], "resolver_url": live_stack["dws_resolver_url"]}


def _did_webs_static_process(
        live_stack, didwebs_runner_script, dws_bin_path, name, alias, passcode, cwd, env, stdout_log
):
    """
    Runs a did:webs static artifact server for did.json and keri.cesr by running the did_webs_resolver.py
    helper script in "artifact" mode. Also sets the current working directory of the process, environment
    for KERI Home override, and the standard out log.
    """
    return subprocess.Popen(
        [
            str(PYTHON_BIN),
            "-u",
            didwebs_runner_script,
            "--mode",
            "artifact",
            "--dws-bin",
            dws_bin_path,
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
        cwd=cwd,
        env=env,
        stdout=stdout_log,
        stderr=subprocess.STDOUT,
    )


def _did_webs_resolver_process(
        live_stack, didwebs_runner_script, dws_bin_path, name, passcode, cwd, env, stdout_log
):
    """
    Runs a did:webs resolver process with the did:webs helper script, overridden KERI home,
    working directory, and standard out log.
    """
    return subprocess.Popen(
        [
            str(PYTHON_BIN),
            "-u",
            didwebs_runner_script,
            "--mode",
            "resolver",
            "--dws-bin",
            dws_bin_path,
            "--name",
            name,
            "--passcode",
            passcode,
            "--http-port",
            str(live_stack["topology"].dws_resolver_port),
            "--did-path",
            "dws",
        ],
        cwd=cwd,
        env=env,
        stdout=stdout_log,
        stderr=subprocess.STDOUT,
    )

@contextmanager
def _launch_live_stack(live_stack: dict, *, shared_assets: dict[str, Path]):
    """Launch the subprocess-managed services that make up the live stack including log files

    Uses subprocess.Popen to run:
    - A witness process with three witnesses:
      - wan (dynamic port customized by individual stack run)
      - wil (dynamic port customized by individual stack run)
      - wes (dynamic port customized by individual stack run)
    - vLEI-server for ACDC schema resolution via schema OOBIs
    - Credential Status service backed by a simple JSON document credential status registry DB.
    - did:webs service (lazily executed)

    The fixture contract uses subprocesses only for long-lived network-facing
    services. All KERI workflow steps run separately in-process through the
    workflow helpers.

    ``live_stack["status_store"]`` is created here as the per-stack backing
    path for the local status projection service. The file is not generic temp
    scratch space. It is the W3C-facing status projection store used by the
    verifier path later in the test.
    """
    witness_python = _require_path(PYTHON_BIN, "crosswalk python")
    vlei_server_bin = _require_path(VLEI_SVR_BIN, "vLEI-server binary")

    _set_vlei_dirs(live_stack, shared_assets=shared_assets)
    # Writes wan, wes, and wil configs to the local stack temp dir
    _write_witness_configs(Path(live_stack["config_root"]), live_stack)
    # Write witness and schema OOBIs to local stack Habery config file
    _write_habery_config(Path(live_stack["config_root"]), live_stack)

    # Isolates KERI Home for this stack by overriding `$PATH/.keri` or `/usr/local/var/keri`
    shared_env = os.environ.copy()
    shared_env["HOME"] = str(live_stack["home"])  # Actual home override
    shared_env["PYTHONWARNINGS"] = "ignore"  # Cleans up warnings to reduce noise

    # Sets up processes and Python binaries to use
    procs: list[tuple[str, subprocess.Popen[bytes]]] = []
    open_logs = []
    live_stack["runtime_procs"] = procs
    live_stack["open_logs"] = open_logs
    live_stack["dws_bin"] = _require_path(DWS_BIN, "did-webs CLI")
    live_stack["crosswalk_python"] = witness_python  # Main python version to use
    live_stack["witness_aids"] = WITNESS_AIDS  # wan, wil, wes
    live_stack["status_store"] = Path(live_stack["runtime_root"]) / "status-store.json"
    live_stack["launch_did_webs"] = _lazy_didwebs_launcher  # lazy loaded did:webs subprocess
    live_stack["did_webs_running"] = False

    # Set up log file paths for later monitoring.
    witness_log_path = Path(live_stack["log_root"]) / "witness.log"
    vlei_log_path = Path(live_stack["log_root"]) / "vlei.log"
    status_log_path = Path(live_stack["log_root"]) / "status.log"

    # Open log files
    witness_log = witness_log_path.open("wb")
    vlei_log = vlei_log_path.open("wb")
    status_log = status_log_path.open("wb")
    open_logs.extend([witness_log, vlei_log, status_log])

    # runs three witnesses in one subprocess.
    witness = _witness_process(live_stack, witness_python, W3C_CROSSWALK_ROOT, shared_env, witness_log)
    procs.append(("witness-demo", witness))
    for port in live_stack["witness_ports"]:
        _wait_process_port(live_stack, witness, "witness-demo", port, witness_log_path)

    # runs a vLEI server
    vlei = _vlei_process(live_stack, vlei_server_bin, W3C_CROSSWALK_ROOT, shared_env, vlei_log)
    procs.append(("vlei-server", vlei))
    _wait_process_port(live_stack, vlei, "vlei-server", live_stack["topology"].vlei_port, vlei_log_path)

    # Credential Status service for checking whether a W3C VC-JWT is revoked or not
    status = _credential_status_process(live_stack, witness_python, W3C_CROSSWALK_ROOT, shared_env, status_log)
    procs.append(("status-service", status))
    _wait_process_port(live_stack, status, "status-service", live_stack["topology"].status_port, status_log_path)
    wait_for_json_health(f"{live_stack['status_base_url']}/health")

    try:
        yield live_stack
    finally:
        _terminate_all(procs)
        for handle in open_logs:
            handle.close()


def _witness_process(live_stack, python_bin, cwd, env, log):
    """
    Runs a witness process with three witnesses configured from the local live stack using the cwd
    as the working directory, passed in environment for the KERI HOME override, and the passed in
    log file for logging.
    """
    return subprocess.Popen(
        [
            python_bin,
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
        cwd=cwd,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )


def _vlei_process(live_stack, python_bin, cwd, env, log):
    """
    Runs a vLEI-server process configured from the local live stack using the cwd as the working
    directory, passed in environment for the KERI HOME override, and the passed in log file for logging.
    """
    return subprocess.Popen(
        [
            python_bin,
            "--schema-dir",
            str(live_stack["schema_root"]),
            "--cred-dir",
            str(live_stack["cred_root"]),
            "--oobi-dir",
            str(live_stack["oobi_root"]),
            "--http",
            str(live_stack["topology"].vlei_port),
        ],
        cwd=cwd,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )


def _credential_status_process(live_stack, python_bin, cwd, env, log):
    """
    Runs a simple POC credential status server process using the local w3c-crosswalk CLI configured
    from the local live stack using the cwd as the working directory, passed in environment for the
    KERI HOME override, and the passed in log file for logging.
    """
    return subprocess.Popen(
        [
            python_bin,
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
        cwd=cwd,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )


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
    """
    Create and yield a live stack, retrying a few times on port conflicts.

    Uses the TempPathFactory to set up the following directory and symlink
    structure:
    - shared helper assets: basetemp / shared-vlei-assets
    - runtime root:
      - config
      - logs
      - tmp

    ``getbasetemp()`` yields a worker/session-scoped shared staging area for
    reusable helper assets. ``mktemp(...)`` yields the isolated runtime root
    whose path becomes the stack HOME sandbox.
    """
    # attrs used for custom $HOME keystore dir, replacing KERI home of `$HOME/.keri` or /usr/local/var/keri
    worker_id = _current_worker_id()
    nodeid = request.node.nodeid if mode == "isolated" else None

    vlei_temp = tmp_path_factory.getbasetemp()

    shared_assets = _ensure_vlei_assets(vlei_temp / "shared-vlei-assets")
    last_err = None
    for attempt in range(3):  # only retries on port error, up to three times
        run_name = stack_runtime_name(mode=mode, worker_id=worker_id, nodeid=nodeid, attempt=attempt)
        runtime_root = tmp_path_factory.mktemp(run_name)
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
