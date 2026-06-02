"""Verifier-suite adapters for headless W3C E2E evidence."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Callable


@dataclass
class VerifierEvidence:
    """Verifier result bundle over one shared VC-JWT and VP-JWT artifact set."""

    accepted: bool
    checks: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable verifier evidence dictionary."""
        return asdict(self)


class CommandVerifier:
    """Run one verifier command with the artifact bundle on stdin as JSON."""

    def __init__(self, name: str, command: list[str], timeout: int = 30):
        self.name = name
        self.command = command
        self.timeout = timeout

    def __call__(self, artifacts: dict[str, Any]) -> dict[str, Any]:
        """Return verifier evidence from the configured command."""
        proc = subprocess.run(
            self.command,
            input=json.dumps(artifacts),
            text=True,
            capture_output=True,
            timeout=self.timeout,
            check=False,
        )
        details: dict[str, Any] = {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
        try:
            parsed = json.loads(proc.stdout) if proc.stdout else {}
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            details.update(parsed)
        return {
            "name": self.name,
            "accepted": proc.returncode == 0 and parsed.get("accepted", True),
            "details": details,
        }


class VerifierSuite:
    """Run Python, Node, and Go verifier checks over the same artifacts."""

    REQUIRED = ("python", "node", "go")

    def __init__(self, verifiers: dict[str, Callable[[dict[str, Any]], Any]]):
        self.verifiers = verifiers

    def require_complete(self):
        """Fail when the suite is missing a required language verifier."""
        missing = [name for name in self.REQUIRED if name not in self.verifiers]
        if missing:
            raise ValueError(f"missing verifier adapters: {', '.join(missing)}")

    def verify(self, artifacts: dict[str, Any]) -> VerifierEvidence:
        """Run all configured verifier adapters and combine their results."""
        self.require_complete()
        checks = [normalize_result(name, verifier(artifacts)) for name, verifier in self.verifiers.items()]
        return VerifierEvidence(
            accepted=all(check["accepted"] for check in checks),
            checks=checks,
        )


def normalize_result(name: str, result: Any) -> dict[str, Any]:
    """Normalize bool, dict, or exception-free callable output into evidence."""
    if isinstance(result, bool):
        return {"name": name, "accepted": result, "details": {}}
    if isinstance(result, dict):
        accepted = result.get("accepted")
        if accepted is None:
            accepted = result.get("ok", False)
        return {
            "name": result.get("name", name),
            "accepted": bool(accepted),
            "details": result.get("details", result),
        }
    return {"name": name, "accepted": bool(result), "details": {"result": result}}
