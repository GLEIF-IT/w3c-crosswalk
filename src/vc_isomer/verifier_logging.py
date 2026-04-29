"""Structured JSON logging helpers for verifier diagnostics."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any


LOGGER = logging.getLogger("vc_isomer.verifier")
TOKEN_HASH_HEX_LENGTH = 16


def configure_verifier_logging() -> None:
    """Make verifier JSON events visible from CLI-launched verifier processes."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")


def token_observability(token: str) -> dict[str, Any]:
    """Return raw-token and correlation fields for local verifier debugging."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return {
        "token": token,
        "tokenLength": len(token),
        "tokenSha256": digest[:TOKEN_HASH_HEX_LENGTH],
    }


def log_verifier_event(event: str, **fields: Any) -> None:
    """Emit one structured verifier event as a JSON log line."""
    body = {"event": event, **fields}
    LOGGER.info(json.dumps(body, default=str, separators=(",", ":"), sort_keys=True))
