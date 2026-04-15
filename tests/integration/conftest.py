"""Launch and manage the live integration stack.

This module owns the network-facing portion of the end to end integration test:
- runtime directory setup (test run root and KERI home override),
- shared staged assets (vLEI schemas, VRD schemas, witness config),
- long-lived helper subprocesses (witness, vLEI-server),
- lazily launched in-process did:webs artifact and resolver doers,
- and the mutable ``live_stack`` contract that later workflow helpers consume.

KERI workflow steps do not run here. They run in-process through
``kli_flow.py`` after this fixture has established a HOME sandbox, witness
reachability, schema/helper services, and the local W3C status endpoint.
"""

from __future__ import annotations

from contextlib import contextmanager
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from .helpers import (
    BackgroundDoistRunner,
    patched_home,
    read_log_tail,
    terminate_process,
    wait_for_json_health,
    wait_for_port,
    wait_for_tcp_port,
)
from .constants import WITNESS_AIDS
from .topology import make_stack_topology, stack_runtime_name

# Directory Setup
# should resolve to isomer/
W3C_ISOMER_ROOT = Path(__file__).resolve().parents[2]
# should resolve to isomer/tests/integration
INTEGRATION_ROOT = Path(__file__).resolve().parent
# should resolve to isomer/tests/integration/_assets
ASSET_ROOT = INTEGRATION_ROOT / "_assets"
WITNESS_CONFIG_ROOT = ASSET_ROOT / "keri" / "cf" / "main"
VLEI_ASSET_ROOT = ASSET_ROOT / "vlei"
VLEI_SCHEMA_ROOT = VLEI_ASSET_ROOT / "schema" / "acdc"
VLEI_CRED_ROOT = VLEI_ASSET_ROOT / "samples" / "acdc"
VLEI_OOBI_ROOT = VLEI_ASSET_ROOT / "samples" / "oobis"

# Local venv Python and binary setup
PYTHON_BIN = W3C_ISOMER_ROOT / ".venv" / "bin" / "python"
VLEI_SVR_BIN = W3C_ISOMER_ROOT / ".venv" / "bin" / "vLEI-server"

# Witness and other service config and script names
WITNESS_CONFIG_NAMES = ("wan", "wil", "wes")
SERVICE_SCRIPTS_ROOT = INTEGRATION_ROOT / "_services"
WITNESS_SERVER_SCRIPT = SERVICE_SCRIPTS_ROOT / "witness_server.py"


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


def _stop_all_runners(runners: list[BackgroundDoistRunner]) -> None:
    """Stop all managed background HIO runners in reverse launch order."""
    for runner in reversed(runners):
        runner.close()


def _wait_process_port(live_stack: dict, proc: subprocess.Popen[bytes], name: str, port: int, log_path: Path) -> None:
    """Wait for one managed subprocess to bind its advertised TCP port."""
    wait_for_port(live_stack["host"], port, proc, name, log_path=log_path)


def _didwebs_urls(live_stack: dict) -> dict[str, str]:
    """Return the did:webs artifact and resolver URLs already assigned to the stack."""
    return {
        "artifact_url": live_stack["dws_artifact_url"],
        "resolver_url": live_stack["dws_resolver_url"],
    }


def _open_process_log(live_stack: dict, filename: str):
    """Open one process log file and register it for stack teardown."""
    log_path = Path(live_stack["log_root"]) / filename
    handle = log_path.open("wb")
    live_stack["open_logs"].append(handle)
    return log_path, handle


def _prepare_didwebs_home_snapshot(live_stack: dict, *, label: str) -> Path:
    """Copy the live stack's `.keri` state into an isolated did:webs HOME.

    The did:webs artifact and resolver doers keep their Habery open for the
    life of the background runner. The rest of the test continues reopening the
    original actor keystores for issuance and signing, so we must give did:webs
    its own snapshot to avoid LMDB's same-process open restriction.
    """
    source_keri = Path(live_stack["home"]) / ".keri"
    if not source_keri.exists():
        raise RuntimeError(f"did:webs launch requested before KERI home existed at {source_keri}")

    target_home = Path(live_stack["runtime_root"]) / f"did-webs-{label}-home"
    target_keri = target_home / ".keri"
    if target_keri.exists():
        shutil.rmtree(target_keri)
    target_home.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_keri, target_keri)
    return target_home


def _spawn_process(
    live_stack: dict,
    *,
    proc_name: str,
    display_name: str,
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
    log_handle,
    port: int,
) -> subprocess.Popen[bytes]:
    """Launch one managed subprocess, register it, and wait for its port."""
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    live_stack["runtime_procs"].append((proc_name, proc))
    _wait_process_port(live_stack, proc, display_name, port, log_path)
    return proc


def _didwebs_launcher(live_stack: dict, *, name: str, alias: str, passcode: str) -> dict[str, str]:
    """Launch did:webs artifact and resolver services on first use.

    The service pair is started lazily because only the W3C issuance and
    verification phase needs it. The KERI issuance workflow deliberately does
    not depend on did:webs until the final interoperability projection phase.
    """
    if live_stack.get("did_webs_running"):
        return _didwebs_urls(live_stack)

    try:
        artifact_module = importlib.import_module("dws.app.cli.commands.did.webs.service")
        resolver_module = importlib.import_module("dws.app.cli.commands.did.webs.resolver-service")
    except Exception as exc:
        pytest.skip(f"did:webs in-process modules are unavailable: {exc}")
        raise exc

    artifact_home = _prepare_didwebs_home_snapshot(live_stack, label="artifact")
    with patched_home(artifact_home):
        artifact_doers = artifact_module.create_artifact_server_doers(
            name=name,
            base="",
            bran=passcode,
            config_file=None,
            config_dir=None,
            alias=alias,
            meta=False,
            did_path="dws",
            http_port=live_stack["topology"].dws_artifact_port,
            keypath=None,
            certpath=None,
            cafilepath=None,
        )

    resolver_home = _prepare_didwebs_home_snapshot(live_stack, label="resolver")
    with patched_home(resolver_home):
        resolver_doers = resolver_module.create_did_webs_doers(
            name=name,
            base="",
            bran=passcode,
            config_file=None,
            config_dir=None,
            static_files_dir=None,
            did_path="dws",
            http_port=live_stack["topology"].dws_resolver_port,
            keypath=None,
            certpath=None,
            cafilepath=None,
        )

    artifact_runner = BackgroundDoistRunner(name="did-webs-artifact", doers=artifact_doers)
    resolver_runner = BackgroundDoistRunner(name="did-webs-resolver", doers=resolver_doers)
    artifact_runner.start()
    resolver_runner.start()
    live_stack["runtime_runners"].extend([artifact_runner, resolver_runner])

    wait_for_tcp_port(live_stack["host"], live_stack["topology"].dws_artifact_port)
    wait_for_tcp_port(live_stack["host"], live_stack["topology"].dws_resolver_port)

    live_stack["did_webs_running"] = True
    return _didwebs_urls(live_stack)

@contextmanager
def _launch_live_stack(live_stack: dict, *, shared_assets: dict[str, Path]):
    """
    Context manager for live, testrun specific processes and config bootstrapping.
    Launch the subprocess-managed services that make up the live stack including log files

    Uses subprocess.Popen to run:
    - A witness process with three witnesses:
      - wan (dynamic port customized by individual stack run)
      - wil (dynamic port customized by individual stack run)
      - wes (dynamic port customized by individual stack run)
    - vLEI-server for ACDC schema resolution via schema OOBIs
    - Credential Status service backed by a simple JSON document credential status registry DB.
    - Verifier service backed by a local LMDB long-running operation store.
    - did:webs services (lazily executed in-process as background doers)

    The fixture contract uses subprocesses only for long-lived network-facing
    services. All KERI workflow steps run separately in-process through the
    workflow helpers.

    ``live_stack["status_store"]`` is created here as the per-stack backing
    path for the local status projection service. The file is not generic temp
    scratch space. It is the W3C-facing status projection store used by the
    verifier path later in the test.
    """
    witness_python = _require_path(PYTHON_BIN, "isomer python")
    vlei_server_bin = _require_path(VLEI_SVR_BIN, "vLEI-server binary")
    cwd = W3C_ISOMER_ROOT

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
    runners: list[BackgroundDoistRunner] = []
    open_logs: list = []
    live_stack["runtime_procs"] = procs
    live_stack["runtime_runners"] = runners
    live_stack["open_logs"] = open_logs
    live_stack["witness_aids"] = WITNESS_AIDS
    live_stack["status_store"] = Path(live_stack["runtime_root"]) / "status-store.json"
    live_stack["operation_store_root"] = Path(live_stack["runtime_root"]) / "verifier-operations"
    live_stack["launch_did_webs"] = _didwebs_launcher
    live_stack["did_webs_running"] = False

    witness_log_path, witness_log = _open_process_log(live_stack, "witness.log")
    vlei_log_path, vlei_log = _open_process_log(live_stack, "vlei.log")
    status_log_path, status_log = _open_process_log(live_stack, "status.log")
    verifier_log_path, verifier_log = _open_process_log(live_stack, "verifier.log")

    witness_argv = _witness_process(live_stack, witness_python)
    witness = subprocess.Popen(
        witness_argv,
        cwd=cwd,
        env=shared_env,
        stdout=witness_log,
        stderr=subprocess.STDOUT,
    )
    procs.append(("witness-demo", witness))
    for port in live_stack["witness_ports"]:
        _wait_process_port(live_stack, witness, "witness-demo", port, witness_log_path)

    vlei_argv = _vlei_process(live_stack, vlei_server_bin)
    _spawn_process(
        live_stack,
        proc_name="vlei-server",
        display_name="vlei-server",
        argv=vlei_argv,
        cwd=cwd,
        env=shared_env,
        log_path=vlei_log_path,
        log_handle=vlei_log,
        port=live_stack["topology"].vlei_port,
    )

    status_argv = _credential_status_process(live_stack, witness_python)
    _spawn_process(
        live_stack,
        proc_name="status-service",
        display_name="status-service",
        argv=status_argv,
        cwd=cwd,
        env=shared_env,
        log_path=status_log_path,
        log_handle=status_log,
        port=live_stack["topology"].status_port,
    )
    wait_for_json_health(f"{live_stack['status_base_url']}/healthz")

    verifier_argv = _verifier_process(live_stack, witness_python)
    _spawn_process(
        live_stack,
        proc_name="verifier-service",
        display_name="verifier-service",
        argv=verifier_argv,
        cwd=cwd,
        env=shared_env,
        log_path=verifier_log_path,
        log_handle=verifier_log,
        port=live_stack["topology"].verifier_port,
    )
    wait_for_json_health(f"{live_stack['verifier_base_url']}/healthz")

    try:
        yield live_stack
    finally:
        _stop_all_runners(runners)
        _terminate_all(procs)
        for handle in open_logs:
            handle.close()


def _witness_process(live_stack, python_bin):
    """Return argv for the witness helper process."""
    return [
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
    ]


def _vlei_process(live_stack, python_bin):
    """Return argv for the vLEI helper process."""
    return [
        python_bin,
        "--schema-dir",
        str(live_stack["schema_root"]),
        "--cred-dir",
        str(live_stack["cred_root"]),
        "--oobi-dir",
        str(live_stack["oobi_root"]),
        "--http",
        str(live_stack["topology"].vlei_port),
    ]


def _credential_status_process(live_stack, python_bin):
    """Return argv for the local credential status service."""
    return [
        python_bin,
        "-u",
        "-m",
        "vc_isomer.cli",
        "status",
        "serve",
        "--host",
        live_stack["host"],
        "--port",
        str(live_stack["topology"].status_port),
        "--store",
        str(live_stack["status_store"]),
        "--base-url",
        live_stack["status_base_url"],
    ]


def _verifier_process(live_stack, python_bin):
    """Return argv for the verifier submission/polling API service."""
    return [
        python_bin,
        "-u",
        "-m",
        "vc_isomer.cli",
        "verifier",
        "serve",
        "--host",
        live_stack["host"],
        "--port",
        str(live_stack["topology"].verifier_port),
        "--resolver",
        live_stack["dws_resolver_url"],
        "--operation-root",
        str(live_stack["operation_store_root"]),
        "--operation-name",
        "verifier",
    ]


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

    shared_assets = _ensure_vlei_assets(tmp_path_factory.getbasetemp() / "shared-vlei-assets")

    def launch_attempt(attempt: int):
        run_name = stack_runtime_name(mode=mode, worker_id=worker_id, nodeid=nodeid, attempt=attempt)
        runtime_root = tmp_path_factory.mktemp(run_name)
        topology = make_stack_topology(runtime_root, worker_id=worker_id, mode=mode)
        live_stack = topology.as_live_stack()
        return _launch_live_stack(live_stack, shared_assets=shared_assets)

    last_err = None
    for attempt in range(3):  # only retries on port error, up to three times
        try:
            with launch_attempt(attempt) as launched:
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
