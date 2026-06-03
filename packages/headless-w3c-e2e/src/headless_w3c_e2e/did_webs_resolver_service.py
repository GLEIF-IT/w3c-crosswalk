"""Small HTTP did:webs resolver used by process-mode E2E runs."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlparse
from urllib.request import urlopen


def main() -> None:
    """Run the process-mode did:webs resolver service."""
    args = parser().parse_args()
    server = ThreadingHTTPServer((args.host, args.port), ResolverHandler)
    server.timeout = 1
    server.serve_forever()


def parser() -> argparse.ArgumentParser:
    """Return the resolver process CLI parser."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    return p


class ResolverHandler(BaseHTTPRequestHandler):
    """Resolve did:webs IDs by fetching their KERIA did:web artifacts."""

    def do_GET(self) -> None:
        """Serve health and DID document lookups."""
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._json(200, {"ok": True, "service": "process-did-webs-resolver"})
            return
        prefix = "/1.0/identifiers/"
        if not parsed.path.startswith(prefix):
            self._json(404, {"error": "not found"})
            return

        did = parsed.path[len(prefix):]
        try:
            document = resolve_did_webs(did)
        except Exception as exc:
            self._json(404, {"error": str(exc)})
            return
        self._json(200, document)

    def log_message(self, _format: str, *_args: Any) -> None:
        """Suppress noisy stdlib request logging."""

    def _json(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def resolve_did_webs(did: str) -> dict[str, Any]:
    """Fetch and normalize one KERIA did:webs DID document."""
    did, url = did_webs_artifact_url(did)
    with urlopen(url, timeout=10) as response:
        document = json.loads(response.read().decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"did:webs artifact at {url} was not a JSON object")
    return normalize_document(document, did)


def did_webs_artifact_url(did: str) -> tuple[str, str]:
    """Return the canonical DID and KERIA did:web artifact URL for a resolver path value."""
    did = _decode_identifier_until_did_webs(did)
    if not did.startswith("did:webs:"):
        raise ValueError(f"unsupported DID method for process resolver: {did}")
    method_specific_id = did[len("did:webs:") :]
    parts = method_specific_id.split(":")
    if len(parts) < 2:
        raise ValueError(f"invalid did:webs identifier: {did}")
    host, path_parts = _split_method_specific_id(parts)
    if not host or not path_parts:
        raise ValueError(f"invalid did:webs identifier: {did}")
    path = "/".join(path_parts)
    return did, f"http://{host}/{path}/did.json"


def _decode_identifier_until_did_webs(identifier: str) -> str:
    did = identifier
    for _ in range(3):
        if did.startswith("did:webs:"):
            return did
        decoded = unquote(did)
        if decoded == did:
            return did
        did = decoded
    return did


def _split_method_specific_id(parts: list[str]) -> tuple[str, list[str]]:
    host = unquote(parts[0])
    path_parts = parts[1:]
    if len(parts) >= 3 and _looks_like_port(parts[1]) and "%" not in parts[0]:
        host = f"{parts[0]}:{parts[1]}"
        path_parts = parts[2:]
    return host, path_parts


def _looks_like_port(value: str) -> bool:
    return value.isdigit() and 0 < int(value) <= 65535


def normalize_document(document: dict[str, Any], did: str) -> dict[str, Any]:
    """Rewrite KERIA's did:web artifact identifiers to did:webs."""
    source_id = document.get("id")
    normalized = _rewrite_value(document, source_id, did)
    if isinstance(normalized, dict):
        normalized["id"] = did
        also_known_as = normalized.get("alsoKnownAs")
        if isinstance(also_known_as, list):
            normalized["alsoKnownAs"] = _dedupe_json_values(also_known_as)
        return normalized
    raise ValueError("DID document normalization produced a non-object")


def _dedupe_json_values(items: list[Any]) -> list[Any]:
    seen: set[str] = set()
    deduped: list[Any] = []
    for item in items:
        key = json.dumps(item, sort_keys=True, separators=(",", ":"))
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _rewrite_value(value: Any, source_id: Any, target_id: str) -> Any:
    if isinstance(value, dict):
        return {key: _rewrite_value(item, source_id, target_id) for key, item in value.items()}
    if isinstance(value, list):
        return [_rewrite_value(item, source_id, target_id) for item in value]
    if isinstance(value, str):
        if isinstance(source_id, str) and value.startswith(source_id):
            return f"{target_id}{value[len(source_id):]}"
        if value.startswith("#"):
            return f"{target_id}{value}"
    return value


if __name__ == "__main__":
    main()
