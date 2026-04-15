"""Pure did:webs resolver parsing helpers.

The W3C verification path in this repo must not trust embedded keys or raw
`did.json` fetches. Outbound resolver HTTP is performed by cooperative doers;
this module only owns URL construction and response validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .runtime_http import JsonResponse


class DidWebsResolutionError(RuntimeError):
    """Raised when did:webs resolution fails or returns an invalid document."""


@dataclass(frozen=True)
class DidResolution:
    """Resolved DID material returned by :class:`DidWebsClient`."""

    did: str
    did_document: dict[str, Any]
    raw: dict[str, Any]


class DidWebsClient:
    """Namespace for did:webs resolver response validation and method lookup."""

    @staticmethod
    def parse_resolution(did: str, response: JsonResponse) -> DidResolution:
        """Validate and normalize one resolver JSON response."""
        if response.status >= 400:
            raise DidWebsResolutionError(
                f"resolver returned HTTP {response.status} while resolving did:webs DID {did}"
            )

        data = response.data
        if not isinstance(data, dict):
            raise DidWebsResolutionError(f"resolver response was not a JSON object for {did}")

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


def resolution_url(base_url: str, did: str) -> str:
    """Return the canonical resolver URL for one did:webs DID."""
    # Do not percent-encode here. HIO clienting quotes the request path during
    # transport, and did-webs-resolver's didding.requote expects exactly that
    # one path-encoding layer before it repairs the DID for parsing.
    return f"{base_url.rstrip('/')}/{did}"
