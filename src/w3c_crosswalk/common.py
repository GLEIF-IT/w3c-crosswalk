"""Shared utility helpers used across the crosswalk package.

The functions in this module intentionally stay small and dependency-light so
they can be reused by CLI commands, service handlers, and tests without
dragging in protocol-specific logic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json_file(path: str | Path) -> dict[str, Any]:
    """Load a UTF-8 encoded JSON document from disk."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json_file(path: str | Path, data: Any) -> None:
    """Write JSON to disk using stable formatting for human review."""
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def utc_timestamp() -> str:
    """Return an RFC3339-style UTC timestamp without fractional seconds."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def require_mapping(name: str, value: Any) -> dict[str, Any]:
    """Require an embedded mapping rather than a compact SAID reference.

    The crosswalk profile needs full `a`, `e`, and `r` blocks when projecting
    ACDC into W3C form. This helper raises early when a caller passes a compact
    reference instead of the expanded object.
    """
    if not isinstance(value, dict):
        raise ValueError(f"{name} block must be present as a full object, not a SAID reference")
    return value
