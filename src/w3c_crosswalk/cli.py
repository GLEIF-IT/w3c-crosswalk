"""Command-line entrypoints for issuing, verifying, and serving crosswalk artifacts.

The CLI is intentionally thin: it loads files and keystores, delegates to the
package's runtime modules, and prints JSON so the commands remain easy to
compose in scripts and integration tests.

Treat this module as an adapter surface, not as the primary architecture.
The semantic core lives in ``profile.py``, ``jwt.py``, ``didwebs.py``,
``status.py``, ``service.py``, and ``verifier.py``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .common import load_json_file, write_json_file
from .didwebs import DidWebsClient
from .jwt import KeriHabSigner, issue_vc_jwt, issue_vp_jwt
from .service import serve_status_service, serve_verifier_service
from .status import JsonFileStatusStore
from .verifier import CrosswalkVerifier


def add_common_output_args(parser: argparse.ArgumentParser) -> None:
    """Add the shared optional output path argument used by write commands."""
    parser.add_argument("--output", help="Optional path to write the JSON or token result to")


def add_live_signer_args(parser: argparse.ArgumentParser) -> None:
    """Add the arguments required to open a live KERI habitat signer.

    These arguments intentionally mirror KERIpy keystore concepts rather than
    hiding them behind crosswalk-specific abstractions.
    """
    parser.add_argument("--name", required=True, help="KLI/KERIpy keystore name")
    parser.add_argument("--base", default="", help="KLI/KERIpy keystore base path")
    parser.add_argument("--alias", required=True, help="Habitat alias inside the keystore")
    parser.add_argument("--passcode", help="Passcode/bran for opening the KLI/KERIpy keystore")
    parser.add_argument(
        "--passcode-env",
        default="SIGNER_PASS",
        help="Environment variable to read the passcode from when --passcode is omitted",
    )


def load_passcode(args: argparse.Namespace) -> str | None:
    """Load the signer passcode from CLI args or the configured environment variable."""
    if args.passcode:
        return args.passcode
    if args.passcode_env:
        value = os.environ.get(args.passcode_env)
        if value:
            return value.strip()
    raise ValueError("a live habitat signer requires --passcode or a populated --passcode-env variable")


def cmd_issue_vc(args: argparse.Namespace) -> int:
    """Issue a VC-JWT from an input ACDC and optionally project status state.

    The CLI path composes three runtime seams: ACDC-to-W3C projection, live
    habitat signing, and optional status projection.
    """
    acdc = load_json_file(args.acdc)
    signer = KeriHabSigner.open(name=args.name, base=args.base, alias=args.alias, passcode=load_passcode(args))
    try:
        token, vc = issue_vc_jwt(acdc, issuer_did=args.issuer_did, status_base_url=args.status_base_url, signer=signer)
        if args.status_store:
            JsonFileStatusStore(args.status_store).project_acdc(acdc, args.issuer_did)
        result = {"token": token, "credential": vc, "kid": signer.kid, "publicKeyJwk": signer.public_jwk}
        if args.output:
            write_json_file(args.output, result)
        else:
            print(json.dumps(result, indent=2))
        return 0
    finally:
        signer.close()


def cmd_issue_vp(args: argparse.Namespace) -> int:
    """Wrap one or more VC-JWT strings in a signed VP-JWT."""
    vc_tokens = [Path(path).read_text(encoding="utf-8").strip() for path in args.vc_token]
    signer = KeriHabSigner.open(name=args.name, base=args.base, alias=args.alias, passcode=load_passcode(args))
    try:
        token, vp = issue_vp_jwt(
            vc_tokens,
            holder_did=args.holder_did,
            signer=signer,
            audience=args.audience,
            nonce=args.nonce,
        )
        result = {"token": token, "presentation": vp, "kid": signer.kid, "publicKeyJwk": signer.public_jwk}
        if args.output:
            write_json_file(args.output, result)
        else:
            print(json.dumps(result, indent=2))
        return 0
    finally:
        signer.close()


def cmd_verify_vc(args: argparse.Namespace) -> int:
    """Verify a VC-JWT from a file path or inline token value."""
    token = Path(args.token).read_text(encoding="utf-8").strip() if Path(args.token).exists() else args.token
    verifier = CrosswalkVerifier(resolver=DidWebsClient(args.resolver))
    result = verifier.verify_vc_jwt(token).to_dict()
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def cmd_verify_vp(args: argparse.Namespace) -> int:
    """Verify a VP-JWT from a file path or inline token value."""
    token = Path(args.token).read_text(encoding="utf-8").strip() if Path(args.token).exists() else args.token
    verifier = CrosswalkVerifier(resolver=DidWebsClient(args.resolver))
    result = verifier.verify_vp_jwt(token).to_dict()
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def cmd_verify_crosswalk(args: argparse.Namespace) -> int:
    """Verify a VC-JWT against its source ACDC document."""
    token = Path(args.token).read_text(encoding="utf-8").strip() if Path(args.token).exists() else args.token
    acdc = load_json_file(args.acdc)
    verifier = CrosswalkVerifier(resolver=DidWebsClient(args.resolver))
    result = verifier.verify_crosswalk_pair(acdc, token).to_dict()
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def cmd_status_project(args: argparse.Namespace) -> int:
    """Create an active status record for a source ACDC credential."""
    acdc = load_json_file(args.acdc)
    result = JsonFileStatusStore(args.status_store).project_acdc(acdc, args.issuer_did)
    print(json.dumps(result.as_status_resource(args.base_url), indent=2))
    return 0


def cmd_status_revoke(args: argparse.Namespace) -> int:
    """Mark a projected status record as revoked."""
    result = JsonFileStatusStore(args.status_store).set_revoked(args.credential_said, True, reason=args.reason)
    print(json.dumps(result.as_status_resource(args.base_url), indent=2))
    return 0


def cmd_status_serve(args: argparse.Namespace) -> int:
    """Start the local HTTP status service."""
    serve_status_service(host=args.host, port=args.port, store_path=args.status_store, base_url=args.base_url)
    return 0


def cmd_verifier_serve(args: argparse.Namespace) -> int:
    """Start the local HTTP verifier service."""
    verifier = CrosswalkVerifier(resolver=DidWebsClient(args.resolver))
    serve_verifier_service(host=args.host, port=args.port, verifier=verifier)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser and all subcommands."""
    parser = argparse.ArgumentParser(prog="crosswalk", description="W3C VRD crosswalk CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    issue_vc = subparsers.add_parser("issue-vc", help="Issue a VC-JWT from an ACDC fixture")
    issue_vc.add_argument("--acdc", required=True)
    issue_vc.add_argument("--issuer-did", required=True)
    issue_vc.add_argument("--status-base-url", required=True)
    issue_vc.add_argument("--status-store")
    add_live_signer_args(issue_vc)
    add_common_output_args(issue_vc)
    issue_vc.set_defaults(func=cmd_issue_vc)

    issue_vp = subparsers.add_parser("issue-vp", help="Wrap one or more VC-JWTs in a VP-JWT")
    issue_vp.add_argument("--vc-token", action="append", required=True)
    issue_vp.add_argument("--holder-did", required=True)
    issue_vp.add_argument("--audience")
    issue_vp.add_argument("--nonce")
    add_live_signer_args(issue_vp)
    add_common_output_args(issue_vp)
    issue_vp.set_defaults(func=cmd_issue_vp)

    verify_vc = subparsers.add_parser("verify-vc", help="Verify a VC-JWT")
    verify_vc.add_argument("--token", required=True)
    verify_vc.add_argument("--resolver", required=True)
    verify_vc.set_defaults(func=cmd_verify_vc)

    verify_vp = subparsers.add_parser("verify-vp", help="Verify a VP-JWT")
    verify_vp.add_argument("--token", required=True)
    verify_vp.add_argument("--resolver", required=True)
    verify_vp.set_defaults(func=cmd_verify_vp)

    verify_crosswalk = subparsers.add_parser("verify-crosswalk", help="Verify a VC-JWT against its source ACDC")
    verify_crosswalk.add_argument("--acdc", required=True)
    verify_crosswalk.add_argument("--token", required=True)
    verify_crosswalk.add_argument("--resolver", required=True)
    verify_crosswalk.set_defaults(func=cmd_verify_crosswalk)

    status_project = subparsers.add_parser("status-project", help="Create an active status record from an ACDC")
    status_project.add_argument("--acdc", required=True)
    status_project.add_argument("--issuer-did", required=True)
    status_project.add_argument("--status-store", required=True)
    status_project.add_argument("--base-url", required=True)
    status_project.set_defaults(func=cmd_status_project)

    status_revoke = subparsers.add_parser("status-revoke", help="Revoke a projected credential")
    status_revoke.add_argument("--credential-said", required=True)
    status_revoke.add_argument("--status-store", required=True)
    status_revoke.add_argument("--base-url", required=True)
    status_revoke.add_argument("--reason", default="revoked via crosswalk CLI")
    status_revoke.set_defaults(func=cmd_status_revoke)

    status_serve = subparsers.add_parser("status-serve", help="Serve credential status resources")
    status_serve.add_argument("--host", default="127.0.0.1")
    status_serve.add_argument("--port", type=int, default=8787)
    status_serve.add_argument("--status-store", required=True)
    status_serve.add_argument("--base-url", required=True)
    status_serve.set_defaults(func=cmd_status_serve)

    verifier_serve = subparsers.add_parser("verifier-serve", help="Serve VC/VP verification endpoints")
    verifier_serve.add_argument("--host", default="127.0.0.1")
    verifier_serve.add_argument("--port", type=int, default=8788)
    verifier_serve.add_argument("--resolver", required=True)
    verifier_serve.set_defaults(func=cmd_verifier_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, dispatch to the selected command, and return its exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
