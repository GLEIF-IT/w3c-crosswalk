"""Runtime-generated topology for live W3C crosswalk integration tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import secrets
import socket

from .constants import SCHEMA_OOBI_SAIDS, WITNESS_AIDS


def _slug(text: str) -> str:
    """Normalize arbitrary text into a filesystem-safe slug."""
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", text).strip("-")
    return slug or "default"


def reserve_random_ports(*, count: int, host: str = "127.0.0.1") -> tuple[int, ...]:
    """Reserve a set of currently free ports for one live-stack instance."""
    ports: list[int] = []
    while len(ports) < count:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
            port = sock.getsockname()[1]
        if port not in ports:
            ports.append(port)
    return tuple(ports)


@dataclass(frozen=True)
class IntegrationStackTopology:
    """Resolved runtime topology for one live integration stack instance.

    The topology owns all runtime paths and ephemeral ports used by the local
    services so tests can run in parallel without hard-coded port collisions.
    """

    stack_id: str
    worker_id: str
    mode: str
    runtime_root: Path
    config_root: Path
    log_root: Path
    temp_root: Path
    home: Path
    host: str
    witness_ports: tuple[int, int, int]
    vlei_port: int
    dws_artifact_port: int
    dws_resolver_port: int
    status_port: int

    @property
    def vlei_schema_url(self) -> str:
        """Return the base URL of the local vLEI helper server."""
        return f"http://{self.host}:{self.vlei_port}"

    @property
    def dws_artifact_url(self) -> str:
        """Return the base URL of the local did:webs artifact server."""
        return f"http://{self.host}:{self.dws_artifact_port}"

    @property
    def dws_resolver_url(self) -> str:
        """Return the base URL of the local did:webs resolver endpoint."""
        return f"http://{self.host}:{self.dws_resolver_port}/1.0/identifiers"

    @property
    def status_base_url(self) -> str:
        """Return the base URL of the local status service."""
        return f"http://{self.host}:{self.status_port}"

    @property
    def witness_oobis(self) -> list[str]:
        """Return controller OOBIs for the three local witness identities."""
        return [
            f"http://{self.host}:{port}/oobi/{aid}/controller?name={name.title()}&tag=witness"
            for port, aid, name in zip(self.witness_ports, WITNESS_AIDS, ("wan", "wil", "wes"))
        ]

    @property
    def schema_oobis(self) -> dict[str, str]:
        """Return schema OOBIs served by the local vLEI helper server."""
        return {alias: f"{self.vlei_schema_url}/oobi/{said}" for alias, said in SCHEMA_OOBI_SAIDS.items()}

    def did_webs_did(self, aid: str, *, did_path: str = "dws") -> str:
        """Construct the did:webs DID that resolves through this stack."""
        return f"did:webs:{self.host}%3A{self.dws_artifact_port}:{did_path}:{aid}"

    def as_live_stack(self) -> dict:
        """Project the topology into the mutable `live_stack` fixture contract."""
        return {
            "topology": self,
            "stack_id": self.stack_id,
            "worker_id": self.worker_id,
            "mode": self.mode,
            "runtime_root": self.runtime_root,
            "config_root": self.config_root,
            "log_root": self.log_root,
            "temp_root": self.temp_root,
            "home": self.home,
            "host": self.host,
            "witness_ports": self.witness_ports,
            "witness_oobis": self.witness_oobis,
            "vlei_schema_url": self.vlei_schema_url,
            "schema_oobis": self.schema_oobis,
            "dws_artifact_url": self.dws_artifact_url,
            "dws_resolver_url": self.dws_resolver_url,
            "status_base_url": self.status_base_url,
        }


def make_stack_topology(
    runtime_root: Path,
    *,
    worker_id: str,
    mode: str,
    host: str = "127.0.0.1",
    stack_id: str | None = None,
    ports: tuple[int, ...] | None = None,
) -> IntegrationStackTopology:
    """Create runtime directories and reserve ports for one live stack."""
    runtime_root.mkdir(parents=True, exist_ok=True)
    config_root = runtime_root / "config"
    log_root = runtime_root / "logs"
    temp_root = runtime_root / "tmp"
    config_root.mkdir(parents=True, exist_ok=True)
    log_root.mkdir(parents=True, exist_ok=True)
    temp_root.mkdir(parents=True, exist_ok=True)

    allocated_ports = ports or reserve_random_ports(count=7, host=host)
    witness_ports = tuple(allocated_ports[:3])
    vlei_port, dws_artifact_port, dws_resolver_port, status_port = allocated_ports[3:]

    return IntegrationStackTopology(
        stack_id=stack_id or f"{mode}-{_slug(worker_id)}-{secrets.token_hex(4)}",
        worker_id=worker_id,
        mode=mode,
        runtime_root=runtime_root,
        config_root=config_root,
        log_root=log_root,
        temp_root=temp_root,
        home=runtime_root,
        host=host,
        witness_ports=witness_ports,
        vlei_port=vlei_port,
        dws_artifact_port=dws_artifact_port,
        dws_resolver_port=dws_resolver_port,
        status_port=status_port,
    )


def stack_runtime_name(*, mode: str, worker_id: str, nodeid: str | None = None, attempt: int = 0) -> str:
    """Build a stable pytest temp-directory name for one stack instance."""
    parts = ["crosswalk-live-stack", mode, _slug(worker_id)]
    if nodeid is not None:
        parts.append(_slug(nodeid))
    if attempt:
        parts.append(f"retry{attempt}")
    return "-".join(parts)
