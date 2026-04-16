"""Subprocess harness for external W3C verifier sidecars.

The sidecars prove Isomer artifacts against non-Python W3C verifier stacks.
They are intentionally long-lived network-facing subprocesses, matching the
repo rule that subprocesses are reserved for services rather than KERI
workflow steps.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ExternalVerifierConfig:
    """Runtime configuration for one external verifier sidecar."""

    kind: str
    repo_root: Path
    resolver_url: str
    log_dir: Path
    host: str = "127.0.0.1"
    port: int | None = None


class ExternalVerifierProcess:
    """Own one external verifier sidecar subprocess."""

    def __init__(self, config: ExternalVerifierConfig):
        self.config = config
        self.port = config.port or reserve_tcp_port(config.host)
        self.base_url = f"http://{config.host}:{self.port}"
        self.log_path = config.log_dir / f"isomer-{config.kind}.log"
        self._log_handle = None
        self._proc: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> "ExternalVerifierProcess":
        """Start the sidecar and wait for readiness."""
        self.start()
        return self

    def __exit__(self, *_exc_info) -> None:
        """Stop the sidecar and close its log."""
        self.close()

    def start(self) -> None:
        """Launch the configured sidecar process."""
        ensure_prerequisites(self.config.kind, self.config.repo_root)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_handle = self.log_path.open("wb")
        self._proc = subprocess.Popen(
            self._argv(),
            cwd=self._cwd(),
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            env=os.environ.copy(),
        )
        try:
            wait_for_health(f"{self.base_url}/healthz", self._proc, self.log_path)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        """Terminate the sidecar if it is still running."""
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        if self._log_handle is not None:
            self._log_handle.close()

    def verify_vc(self, token: str) -> dict[str, Any]:
        """Submit one VC-JWT to the sidecar."""
        return self._post_json("/verify/vc", {"token": token})

    def verify_vp(self, token: str, *, audience: str | None = None, nonce: str | None = None) -> dict[str, Any]:
        """Submit one VP-JWT to the sidecar."""
        body: dict[str, Any] = {"token": token}
        if audience is not None:
            body["audience"] = audience
        if nonce is not None:
            body["nonce"] = nonce
        return self._post_json("/verify/vp", body)

    def _post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(body).encode("utf-8"),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=45.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError(f"{self.config.kind} verifier returned non-object JSON: {payload!r}")
        return payload

    def _cwd(self) -> Path:
        if self.config.kind == "node":
            return self.config.repo_root / "apps" / "isomer-node"
        if self.config.kind == "go":
            return self.config.repo_root / "apps" / "isomer-go"
        raise ValueError(f"unsupported external verifier kind {self.config.kind!r}")

    def _argv(self) -> list[str]:
        if self.config.kind == "node":
            return [
                "npm",
                "run",
                "serve",
                "--",
                "--host",
                self.config.host,
                "--port",
                str(self.port),
                "--resolver-url",
                self.config.resolver_url,
                "--resource-root",
                str(self.config.repo_root),
            ]
        if self.config.kind == "go":
            return [
                "go",
                "run",
                "./cmd/isomer-go",
                "--host",
                self.config.host,
                "--port",
                str(self.port),
                "--resolver-url",
                self.config.resolver_url,
                "--resource-root",
                str(self.config.repo_root),
            ]
        raise ValueError(f"unsupported external verifier kind {self.config.kind!r}")


def requested_external_verifiers(value: str | None = None) -> list[str]:
    """Parse the external verifier selection from the environment."""
    raw = value if value is not None else os.getenv("ISOMER_EXTERNAL_VERIFIERS", "")
    selected = [item.strip().lower() for item in raw.split(",") if item.strip()]
    allowed = {"node", "go"}
    unknown = [item for item in selected if item not in allowed]
    if unknown:
        raise ValueError(f"unsupported external verifier selection: {', '.join(unknown)}")
    return selected


def ensure_prerequisites(kind: str, repo_root: Path) -> None:
    """Fail early with a useful setup hint when a sidecar is not ready."""
    if kind == "node":
        sibling = repo_root.parent / "did-jwt-vc"
        node_modules = repo_root / "apps" / "isomer-node" / "node_modules"
        if not sibling.exists():
            raise RuntimeError(f"missing sibling did-jwt-vc clone at {sibling}")
        if not (sibling / "lib" / "index.module.js").exists():
            raise RuntimeError("sibling did-jwt-vc is not built; run `make external-node-sync`")
        if not node_modules.exists():
            raise RuntimeError("apps/isomer-node dependencies are missing; run `make external-node-sync`")
        return
    if kind == "go":
        sibling = repo_root.parent / "vc-go"
        if not sibling.exists():
            raise RuntimeError(f"missing sibling vc-go clone at {sibling}")
        return
    raise ValueError(f"unsupported external verifier kind {kind!r}")


def assert_external_result_ok(kind: str, label: str, result: dict[str, Any], log_path: Path) -> None:
    """Assert a sidecar result succeeded and include log context on failure."""
    if result.get("ok") is True:
        return
    rendered = json.dumps(result, indent=2, sort_keys=True)
    raise AssertionError(f"{kind} {label} verification failed\n{rendered}\n{read_log_tail(log_path)}")


def reserve_tcp_port(host: str) -> int:
    """Reserve and release one local TCP port for a sidecar process."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def wait_for_health(url: str, proc: subprocess.Popen[bytes], log_path: Path, *, timeout: float = 45.0) -> None:
    """Poll a sidecar health endpoint until it reports ready."""
    deadline = time.monotonic() + timeout
    last_error: str | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"external verifier exited early with code {proc.returncode}\n{read_log_tail(log_path)}")
        try:
            with urlopen(url, timeout=2.0) as response:
                body = json.loads(response.read().decode("utf-8"))
            if isinstance(body, dict) and body.get("ok") is True:
                return
        except (OSError, URLError, json.JSONDecodeError) as exc:
            last_error = str(exc)
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for {url}; last_error={last_error!r}\n{read_log_tail(log_path)}")


def read_log_tail(path: Path, *, max_chars: int = 8000) -> str:
    """Return a small sidecar log tail for diagnostics."""
    if not path.exists():
        return "(log file not found)"
    text = path.read_text(encoding="utf-8", errors="replace")
    return text[-max_chars:] if text else "(log file was empty)"
