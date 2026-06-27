"""Managed local-process stack for live headless W3C E2E runs.

Process mode starts the same kinds of external services the browser flow needs:
KERIA, vLEI, did:webs resolver, dashboard, and Python/Node/Go verifier HTTP
services. It is not a unit-test helper and must not replace those services with
verifier test doubles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


class ProcessStackError(RuntimeError):
    """Raised when the managed local process stack cannot start cleanly."""


@dataclass(frozen=True)
class ProcessStackPorts:
    """Reserved local TCP ports for one process-mode run."""

    keria_admin: int
    keria_http: int
    keria_boot: int
    vlei: int
    did_webs_resolver: int
    python_verifier: int
    node_verifier: int
    go_verifier: int
    dashboard: int

    @classmethod
    def reserve(cls, host: str = "127.0.0.1") -> "ProcessStackPorts":
        """Reserve a set of currently free loopback TCP ports."""
        return cls(*[_reserve_tcp_port(host) for _ in range(9)])


@dataclass
class ManagedProcessStack:
    """Own a KERIA plus live verifier local-process stack.

    The stack is intentionally process-only: it does not shell into Docker and
    it does not replace verifier services with in-process callables. KERIA still
    owns holder presentation submission; the verifier processes only expose the
    HTTP service contracts KERIA calls.
    """

    repo_root: Path | None = None
    runtime_root: Path | None = None
    keep_stack: bool = False
    host: str = "127.0.0.1"
    keria_bin: str | None = None
    python_bin: str = sys.executable
    node_bin: str = "npm"
    go_bin: str = "go"
    alias_prefix: str = "w3c-vrd-process"
    ports: ProcessStackPorts = field(default_factory=lambda: ProcessStackPorts.reserve())

    def __post_init__(self) -> None:
        if self.repo_root is None:
            self.repo_root = _default_repo_root()
        if self.runtime_root is None:
            self.runtime_root = Path(tempfile.mkdtemp(prefix="headless-w3c-process-"))
        else:
            self.runtime_root = Path(self.runtime_root)
            self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.repo_root = Path(self.repo_root)
        self.log_root = self.runtime_root / "logs"
        self.log_root.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.runtime_root / "w3c-vrd-chain-manifest.json"
        self._processes: list[_ManagedProcess] = []

    def __enter__(self) -> "ManagedProcessStack":
        """Start the process stack and seed the holder manifest."""
        self.start()
        return self

    def __exit__(self, *_exc_info) -> None:
        """Stop managed processes unless the caller requested persistence."""
        self.close()

    @property
    def admin_url(self) -> str:
        """Return the local KERIA admin URL."""
        return f"http://{self.host}:{self.ports.keria_admin}"

    @property
    def boot_url(self) -> str:
        """Return the local KERIA boot URL."""
        return f"http://{self.host}:{self.ports.keria_boot}"

    @property
    def resolver_url(self) -> str:
        """Return the DID webs resolver endpoint used by verifier sidecars."""
        return f"http://{self.host}:{self.ports.did_webs_resolver}/1.0/identifiers"

    @property
    def dashboard_url(self) -> str:
        """Return the dashboard base URL."""
        return f"http://{self.host}:{self.ports.dashboard}"

    def config_overrides(self) -> dict[str, Any]:
        """Return HeadlessLiveRunConfig overrides for this stack."""
        return {
            "admin_url": self.admin_url,
            "boot_url": self.boot_url,
            "manifestOut": str(self.runtime_root / "headless-w3c-live-manifest.json"),
            "verifierUrls": {
                "python": f"http://{self.host}:{self.ports.python_verifier}",
                "node": f"http://{self.host}:{self.ports.node_verifier}",
                "go": f"http://{self.host}:{self.ports.go_verifier}",
            },
            "verifierSubmissionUrls": {
                "python": f"http://{self.host}:{self.ports.python_verifier}",
                "node": f"http://{self.host}:{self.ports.node_verifier}",
                "go": f"http://{self.host}:{self.ports.go_verifier}",
            },
            "dashboardUrl": self.dashboard_url,
        }

    def start(self) -> None:
        """Launch service processes and create a seeded holder manifest.

        The ordering mirrors the dependency graph: KERIA and resolver must be
        healthy before seeding wallets, and all verifier services must be live
        before the runtime attempts holder presentation evidence collection.
        """
        self._start_vlei()
        self._start_keria()
        self._start_did_webs_resolver()
        self._start_dashboard()
        self._start_python_verifier()
        self._start_node_verifier()
        self._start_go_verifier()
        self._seed_wallets()

    def close(self) -> None:
        """Terminate child processes in reverse start order."""
        if self.keep_stack:
            return
        for process in reversed(self._processes):
            process.terminate()

    def _start_vlei(self) -> None:
        schema_root = self.repo_root / "tests" / "integration" / "_assets" / "vlei" / "schema"
        cred_root = self.repo_root / "tests" / "integration" / "_assets" / "vlei" / "samples" / "acdc"
        oobi_root = self.repo_root / "tests" / "integration" / "_assets" / "vlei" / "samples" / "oobis"
        self._spawn(
            "vlei",
            [
                self._repo_binary("vLEI-server"),
                "--http",
                str(self.ports.vlei),
                "--schema-dir",
                str(schema_root),
                "--cred-dir",
                str(cred_root),
                "--oobi-dir",
                str(oobi_root),
            ],
            wait_port=self.ports.vlei,
        )

    def _start_keria(self) -> None:
        config_dir, config_file = self._write_keria_config()
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(self.runtime_root / "keria-home"),
                "KERI_AGENT_CORS": "1",
                "KERIA_DID_WEBS_ENABLED": "true",
                "KERIA_DID_WEBS_PUBLIC_BASE_URL": f"http://{self.host}:{self.ports.keria_http}/dws",
                "KERIA_DID_WEBS_PATH": "dws",
                "KERIA_DID_WEBS_REGISTRY_NAME_PREFIX": "didwebs-designated-aliases",
                "KERIA_W3C_ENABLED": "true",
                "KERIA_W3C_STATUS_BASE_URL": f"http://{self.host}:{self.ports.keria_http}",
                "PYTHONWARNINGS": "ignore",
            }
        )
        self._spawn(
            "keria",
            [
                self._keria_binary(),
                "start",
                "--admin",
                str(self.ports.keria_admin),
                "--http",
                str(self.ports.keria_http),
                "--boot",
                str(self.ports.keria_boot),
                "--config-dir",
                str(config_dir),
                "--config-file",
                config_file,
                "--loglevel",
                "INFO",
            ],
            env=env,
            wait_url=f"{self.boot_url}/health",
        )

    def _start_did_webs_resolver(self) -> None:
        self._spawn(
            "did-webs-resolver",
            [
                self.python_bin,
                "-m",
                "headless_w3c_e2e.did_webs_resolver_service",
                "--host",
                self.host,
                "--port",
                str(self.ports.did_webs_resolver),
            ],
            env=self._python_env(),
            wait_url=f"http://{self.host}:{self.ports.did_webs_resolver}/healthz",
        )

    def _start_dashboard(self) -> None:
        env = os.environ.copy()
        env["ISOMER_DASHBOARD_HOST"] = self.host
        env["ISOMER_DASHBOARD_PORT"] = str(self.ports.dashboard)
        self._spawn(
            "isomer-dashboard",
            [self.node_bin, "run", "serve"],
            cwd=self.repo_root / "apps" / "isomer-dashboard",
            env=env,
            wait_url=f"{self.dashboard_url}/healthz",
        )

    def _start_python_verifier(self) -> None:
        self._spawn(
            "isomer-python",
            [
                self._repo_binary("isomer"),
                "verifier",
                "serve",
                "--host",
                self.host,
                "--port",
                str(self.ports.python_verifier),
                "--resolver",
                self.resolver_url,
                "--operation-root",
                str(self.runtime_root / "python-verifier-operations"),
                "--operation-name",
                "isomer-python",
                "--webhook-url",
                f"{self.dashboard_url}/webhooks/presentations",
                "--verifier-id",
                "isomer-python",
                "--verifier-label",
                "Isomer Python",
            ],
            wait_url=f"http://{self.host}:{self.ports.python_verifier}/healthz",
        )

    def _start_node_verifier(self) -> None:
        self._spawn(
            "isomer-node",
            [
                self.node_bin,
                "run",
                "serve",
                "--",
                "--host",
                self.host,
                "--port",
                str(self.ports.node_verifier),
                "--resolver-url",
                self.resolver_url,
                "--resource-root",
                str(self.repo_root),
                "--webhook-url",
                f"{self.dashboard_url}/webhooks/presentations",
                "--verifier-id",
                "isomer-node",
                "--verifier-label",
                "Isomer Node",
            ],
            cwd=self.repo_root / "apps" / "isomer-node",
            wait_url=f"http://{self.host}:{self.ports.node_verifier}/healthz",
        )

    def _start_go_verifier(self) -> None:
        self._spawn(
            "isomer-go",
            [
                self.go_bin,
                "run",
                "./cmd/isomer-go",
                "--host",
                self.host,
                "--port",
                str(self.ports.go_verifier),
                "--resolver-url",
                self.resolver_url,
                "--resource-root",
                str(self.repo_root),
                "--webhook-url",
                f"{self.dashboard_url}/webhooks/presentations",
                "--verifier-id",
                "isomer-go",
                "--verifier-label",
                "Isomer Go",
            ],
            cwd=self.repo_root / "apps" / "isomer-go",
            wait_url=f"http://{self.host}:{self.ports.go_verifier}/healthz",
        )

    def _seed_wallets(self) -> None:
        log_path = self.log_root / "seed.log"
        argv = [
            self.python_bin,
            "-m",
            "headless_w3c_e2e.seed",
            "--admin-url",
            self.admin_url,
            "--boot-url",
            self.boot_url,
            "--schema-base-url",
            f"http://{self.host}:{self.ports.vlei}",
            "--alias-prefix",
            self.alias_prefix,
            "--unwitnessed",
            "--output",
            str(self.manifest_path),
        ]
        with log_path.open("wb") as log:
            completed = subprocess.run(
                argv,
                cwd=self.repo_root,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=self._python_env(),
                timeout=600,
            )
        if completed.returncode != 0:
            raise ProcessStackError(
                f"holder W3C seed command failed with exit {completed.returncode}\n{_log_tail(log_path)}"
            )

    def _keria_binary(self) -> str:
        if self.keria_bin:
            return self.keria_bin
        sibling = Path("/Users/kbull/code/keri/kentbull/core/python/keria/.venv/bin/keria")
        if sibling.exists():
            return str(sibling)
        return _required_binary("keria")

    def _repo_binary(self, name: str) -> str:
        binary = self.repo_root / ".venv" / "bin" / name
        if binary.exists():
            return str(binary)
        return _required_binary(name)

    def _write_keria_config(self) -> tuple[Path, str]:
        config_name = "process-stack"
        config_dir = self.runtime_root / "keria-config"
        target = config_dir / "keri" / "cf"
        target.mkdir(parents=True, exist_ok=True)
        body = {
            "dt": "2026-06-02T00:00:00.000000+00:00",
            "keria": {
                "dt": "2026-06-02T00:00:00.000000+00:00",
                "curls": [
                    f"http://{self.host}:{self.ports.keria_http}/",
                ],
            },
            "iurls": [],
        }
        (target / f"{config_name}.json").write_text(
            json.dumps(body, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return config_dir, config_name

    def _python_env(self) -> dict[str, str]:
        env = os.environ.copy()
        paths = [
            str(self.repo_root / "packages" / "headless-w3c-e2e" / "src"),
            str(self.repo_root / "packages" / "signifypy-w3c" / "src"),
            str(self.repo_root / "packages" / "signifypy-did-webs" / "src"),
            str(self.repo_root / "src"),
        ]
        existing = env.get("PYTHONPATH")
        if existing:
            paths.append(existing)
        env["PYTHONPATH"] = os.pathsep.join(paths)
        return env

    def _spawn(
        self,
        name: str,
        argv: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        wait_port: int | None = None,
        wait_url: str | None = None,
    ) -> None:
        log_path = self.log_root / f"{name}.log"
        log_handle = log_path.open("wb")
        process = subprocess.Popen(
            argv,
            cwd=cwd or self.repo_root,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            env=env or os.environ.copy(),
        )
        managed = _ManagedProcess(name=name, process=process, log_path=log_path, log_handle=log_handle)
        self._processes.append(managed)
        try:
            if wait_url is not None:
                _wait_for_http(wait_url, managed)
            if wait_port is not None:
                _wait_for_port(self.host, wait_port, managed)
        except Exception:
            self.close()
            raise


@dataclass(frozen=True)
class _ManagedProcess:
    """One subprocess plus log resources."""

    name: str
    process: subprocess.Popen[bytes]
    log_path: Path
    log_handle: Any

    def terminate(self) -> None:
        """Terminate the subprocess and close its log handle."""
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=8)
        self.log_handle.close()


def run_with_process_stack(
    *,
    base_overrides: dict[str, Any],
    manifest_path: str | None,
    keep_stack: bool = False,
    runtime_root: str | None = None,
) -> tuple[dict[str, Any], ManagedProcessStack]:
    """Start process mode and merge stack-derived config overrides."""
    stack = ManagedProcessStack(
        runtime_root=None if runtime_root is None else Path(runtime_root),
        keep_stack=keep_stack,
    )
    stack.start()
    merged = {**base_overrides, **stack.config_overrides()}
    return {
        "manifest_path": manifest_path or str(stack.manifest_path),
        "overrides": merged,
    }, stack


def _default_repo_root() -> Path:
    return Path(os.environ.get("W3C_CROSSWALK_ROOT", Path(__file__).resolve().parents[4]))


def _required_binary(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise ProcessStackError(f"required process-mode binary {name!r} was not found on PATH")
    return found


def _reserve_tcp_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        bind_host = "" if host in {"127.0.0.1", "localhost"} else host
        sock.bind((bind_host, 0))
        return int(sock.getsockname()[1])


def _wait_for_port(host: str, port: int, managed: _ManagedProcess, *, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _raise_if_exited(managed)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return
            except OSError:
                time.sleep(0.25)
    raise ProcessStackError(f"{managed.name} did not open {host}:{port}\n{_log_tail(managed.log_path)}")


def _wait_for_http(url: str, managed: _ManagedProcess, *, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _raise_if_exited(managed)
        request = Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with urlopen(request, timeout=1.0) as response:
                if 200 <= response.status < 300:
                    return
        except (OSError, URLError):
            time.sleep(0.25)
    raise ProcessStackError(f"{managed.name} did not become healthy at {url}\n{_log_tail(managed.log_path)}")


def _raise_if_exited(managed: _ManagedProcess) -> None:
    code = managed.process.poll()
    if code is not None:
        raise ProcessStackError(f"{managed.name} exited with {code}\n{_log_tail(managed.log_path)}")


def _log_tail(path: Path, *, limit: int = 80) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-limit:])
