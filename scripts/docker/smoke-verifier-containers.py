"""Smoke-test local Isomer verifier Docker images.

The smoke test intentionally checks only container startup and `/healthz`.
Full VC-JWT verification through KERIA lives in KERIA's gated Docker acceptance
test.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from dataclasses import dataclass
from urllib.request import urlopen


@dataclass
class StartedContainer:
    """Container metadata needed for health checks and cleanup."""

    kind: str
    cid: str
    base_url: str


def main() -> int:
    """Run the smoke check and return a process exit code."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", default="local")
    args = parser.parse_args()

    containers: list[StartedContainer] = []
    try:
        for kind in ("python", "node", "go", "dashboard"):
            containers.append(start_container(kind, args.tag))
        for container in containers:
            wait_for_health(container)
            print(f"{container.kind}: {container.base_url}/healthz ok")
        return 0
    finally:
        for container in containers:
            subprocess.run(["docker", "rm", "-f", container.cid], check=False, stdout=subprocess.DEVNULL)


def start_container(kind: str, tag: str) -> StartedContainer:
    """Start one verifier container on a random loopback host port."""
    image = f"w3c-crosswalk/isomer-{kind}:{tag}"
    container_port = "8791" if kind == "dashboard" else "8788"
    command = [
        "docker",
        "run",
        "--rm",
        "--detach",
        "--add-host=host.docker.internal:host-gateway",
        "-p",
        f"127.0.0.1::{container_port}",
    ]
    if kind != "dashboard":
        command.extend(["-e", "ISOMER_RESOLVER_URL=http://host.docker.internal:9/1.0/identifiers"])
    command.append(image)
    cid = subprocess.check_output(command, text=True).strip()
    port = published_port(cid, container_port)
    return StartedContainer(kind=kind, cid=cid, base_url=f"http://127.0.0.1:{port}")


def published_port(cid: str, container_port: str) -> str:
    """Return the random host port mapped to container port 8788."""
    output = subprocess.check_output(["docker", "port", cid, f"{container_port}/tcp"], text=True).strip()
    if not output:
        raise RuntimeError(f"container {cid} did not publish {container_port}/tcp")
    return output.splitlines()[0].rsplit(":", 1)[1]


def wait_for_health(container: StartedContainer, timeout: float = 45.0) -> None:
    """Poll one container health endpoint until it reports ready."""
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    url = f"{container.base_url}/healthz"
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2.0) as response:
                body = json.loads(response.read().decode("utf-8"))
            if body.get("ok") is True:
                return
        except Exception as ex:  # pragma: no cover - diagnostics only
            last_error = ex
        time.sleep(0.2)
    logs = subprocess.run(["docker", "logs", container.cid], text=True, capture_output=True, check=False)
    raise TimeoutError(f"{container.kind} did not become healthy: {last_error}\n{logs.stdout[-4000:]}")


if __name__ == "__main__":
    raise SystemExit(main())
