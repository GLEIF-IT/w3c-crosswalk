"""Managed Docker compose stack for live headless W3C E2E runs.

Docker mode exercises the portable stack: published packages, pinned Git SHAs,
or OCI images are consumed through compose configuration instead of sibling
local source-tree dependencies. Host URLs are used for harness polling; service
DNS URLs are used where KERIA posts verifier submissions inside the network.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


class DockerStackError(RuntimeError):
    """Raised when the managed Docker stack cannot start cleanly."""


@dataclass
class ManagedDockerStack:
    """Own the local compose-backed KERIA plus verifier service stack."""

    repo_root: Path | None = None
    project: str = "w3c-crosswalk"
    env_file: Path | None = None
    keep_stack: bool = False
    engine: str = "docker"

    def __post_init__(self) -> None:
        if self.repo_root is None:
            self.repo_root = _default_repo_root()
        self.repo_root = Path(self.repo_root)
        self.env_file = Path(self.env_file) if self.env_file is not None else self.repo_root / ".env"
        self.compose_file = self.repo_root / "docker" / "compose.local.yml"
        self.local_stack_tmp = self.repo_root / ".tmp" / "local-stack"
        self.manifest_path = self.local_stack_tmp / "w3c-vrd-chain-manifest.json"
        self.evidence_manifest_path = self.local_stack_tmp / "headless-w3c-live-manifest.json"

    def __enter__(self) -> "ManagedDockerStack":
        """Start the compose stack and seed holder inputs."""
        self.start()
        return self

    def __exit__(self, *_exc_info) -> None:
        """Stop compose services unless the caller requested persistence."""
        self.close()

    def config_overrides(self) -> dict[str, Any]:
        """Return HeadlessLiveRunConfig overrides for this Docker stack."""
        return {
            "admin_url": "http://127.0.0.1:3901",
            "boot_url": "http://127.0.0.1:3903",
            "manifestOut": str(self.evidence_manifest_path),
            "verifierUrls": {
                "python": "http://127.0.0.1:8788",
                "node": "http://127.0.0.1:8789",
                "go": "http://127.0.0.1:8790",
            },
            "verifierSubmissionUrls": {
                "python": "http://isomer-python:8788",
                "node": "http://isomer-node:8788",
                "go": "http://isomer-go:8788",
            },
            "dashboardUrl": "http://127.0.0.1:8791",
        }

    def start(self) -> None:
        """Launch compose services and create a seeded holder manifest.

        Failure tears the compose stack down unless ``keep_stack`` is set so a
        partial service graph does not masquerade as reusable E2E state.
        """
        self._ensure_env_file()
        self.local_stack_tmp.mkdir(parents=True, exist_ok=True)
        self._run_compose(["--profile", "seed", "config"], timeout=90)
        self._run_compose(["up", "-d"], timeout=300)
        try:
            self._wait_for_stack_health()
            self._run_compose(["run", "--rm", "signifypy-seed"], timeout=900)
        except Exception:
            self.close()
            raise
        if not self.manifest_path.exists():
            raise DockerStackError(f"Docker seed did not write manifest {self.manifest_path}")

    def close(self) -> None:
        """Stop compose services unless keep_stack was requested."""
        if self.keep_stack:
            return
        self._run_compose(["down", "--remove-orphans"], timeout=180, check=False)

    def _ensure_env_file(self) -> None:
        if self.env_file.exists():
            return
        example = self.repo_root / ".env.example"
        if not example.exists():
            raise DockerStackError(f"missing Docker env file {self.env_file} and template {example}")
        shutil.copyfile(example, self.env_file)

    def _run_compose(self, args: list[str], *, timeout: int, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = [
            self.engine,
            "compose",
            "--env-file",
            str(self.env_file),
            "-p",
            self.project,
            "-f",
            str(self.compose_file),
            *args,
        ]
        completed = subprocess.run(
            command,
            cwd=self.repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        if check and completed.returncode != 0:
            raise DockerStackError(
                f"Docker compose command failed with exit {completed.returncode}: {' '.join(command)}\n"
                f"{completed.stdout}"
            )
        return completed

    def _wait_for_stack_health(self) -> None:
        for url in [
            "http://127.0.0.1:3903/health",
            "http://127.0.0.1:8788/healthz",
            "http://127.0.0.1:8789/healthz",
            "http://127.0.0.1:8790/healthz",
            "http://127.0.0.1:8791/healthz",
        ]:
            _wait_for_http(url)


def _default_repo_root() -> Path:
    return Path(os.environ.get("W3C_CROSSWALK_ROOT", Path(__file__).resolve().parents[4]))


def _wait_for_http(url: str, *, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        request = Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with urlopen(request, timeout=1.0) as response:
                if 200 <= response.status < 300:
                    return
        except (OSError, URLError) as exc:
            last_error = exc
            time.sleep(0.5)
    raise DockerStackError(f"Docker stack service did not become healthy at {url}: {last_error}")
