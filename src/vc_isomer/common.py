"""Shared utility helpers used across the isomer package.

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

    The isomer profile needs full `a`, `e`, and `r` blocks when projecting
    ACDC into W3C form. This helper raises early when a caller passes a compact
    reference instead of the expanded object.
    """
    if not isinstance(value, dict):
        raise ValueError(f"{name} block must be present as a full object, not a SAID reference")
    return value


def canonicalize_did_webs(did: str) -> str:
    """Return one did:webs DID in canonical form.

    The canonical did:webs form encodes the host/port separator as ``%3A``
    inside the DID value itself. This helper leaves already-canonical DIDs
    untouched and repairs the common malformed ``did:webs:host:port:...``
    variant that can slip in from local stack assembly.
    """
    if not did.startswith("did:webs:"):
        return did

    if "%3a" in did.lower():
        return did

    # Only canonicalize the DID body. Any DID URL query string is preserved as-is
    # and reattached after we repair the host/port encoding.
    body, query_separator, query = did.partition("?")
    segments = body[len("did:webs:") :].split(":")
    # The malformed shape we repair here is specifically:
    #   did:webs:<host>:<port>:<rest>
    #          segments[1] ↑
    # If the second segment is not a decimal port, leave the DID untouched.
    if len(segments) < 3 or not segments[1].isdigit():
        return did

    domain, port = segments[0], segments[1]
    # Everything after host and port remains in the original colon-delimited
    # structure; only the host/port separator itself becomes %3A.
    remainder = ":".join(segments[2:])
    encoded = f"did:webs:{domain}%3A{port}:{remainder}"
    return f"{encoded}{query_separator}{query}" if query_separator else encoded


def canonicalize_did_url(value: str) -> str:
    """Canonicalize the DID portion of one DID URL while preserving fragments."""
    did, separator, fragment = value.partition("#")
    normalized = canonicalize_did_webs(did)
    return f"{normalized}{separator}{fragment}" if separator else normalized
