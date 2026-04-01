"""Resolve did:webs identifiers through the configured resolver service.

The W3C verification path in this repo must not trust embedded keys or raw
`did.json` fetches. This client is the narrow seam that enforces resolver-based
key-state lookup.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import quote
from urllib.request import urlopen

from .constants import RESOLVER_DEFAULT


class DidWebsResolutionError(RuntimeError):
    """Raised when did:webs resolution fails or returns an invalid document."""


@dataclass(frozen=True)
class DidResolution:
    """Resolved DID material returned by :class:`DidWebsClient`."""

    did: str
    did_document: dict[str, Any]
    raw: dict[str, Any]


class DidWebsClient:
    """Resolve did:webs DIDs and locate verification methods within them."""

    def __init__(
        self,
        base_url: str = RESOLVER_DEFAULT,
        timeout: float = 5.0,
        loader: Callable[[str, float], dict[str, Any]] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.loader = loader

    def resolve(self, did: str) -> DidResolution:
        """Resolve a did:webs DID and return the resolver response details."""
        url = f"{self.base_url}/{quote(did, safe='')}"
        try:
            if self.loader is not None:
                data = self.loader(url, self.timeout)
            else:
                with urlopen(url, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # pragma: no cover - error path is exercised in higher-level tests
            raise DidWebsResolutionError(f"failed to resolve did:webs DID {did}: {exc}") from exc

        did_document = data.get("didDocument", data)
        if not isinstance(did_document, dict) or "verificationMethod" not in did_document:
            raise DidWebsResolutionError(f"resolver response did not contain a usable didDocument for {did}")

        return DidResolution(did=did, did_document=did_document, raw=data)

    @staticmethod
    def find_verification_method(did_document: dict[str, Any], kid: str) -> dict[str, Any]:
        """Find the verification method referenced by a JWT `kid` value."""
        fragment = kid.split("#", 1)[1] if "#" in kid else kid.lstrip("#")
        full_matches = {kid, f"#{fragment}"}
        for method in did_document.get("verificationMethod", []):
            method_id = method.get("id", "")
            if method_id in full_matches or method_id.endswith(f"#{fragment}"):
                return method
        raise DidWebsResolutionError(f"verification method {kid} not found in resolved DID document")
