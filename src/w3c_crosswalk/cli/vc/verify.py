"""`crosswalk vc verify` command."""

from __future__ import annotations

import argparse
from typing import Any

from w3c_crosswalk.cli.common import add_verifier_wait_args, load_token_argument, response_for_doers
from w3c_crosswalk.verifier_client import verify_vc_doer


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk vc verify`."""
    return [
        verify_vc_doer(
            base_url=args.server,
            token=load_token_argument(args.token),
            timeout=args.timeout,
            poll_interval=args.poll,
        )
    ]


def _credential_type(payload: dict[str, Any]) -> str:
    types = payload.get("type", [])
    if isinstance(types, list):
        for typ in reversed(types):
            if isinstance(typ, str) and typ != "VerifiableCredential":
                return typ
    return "unknown"


def report_success(doers) -> None:
    """Print one compact success line for a verified VC-JWT."""
    response = response_for_doers(doers) or {}
    payload = response.get("payload", {})
    if not isinstance(payload, dict):
        payload = {}
    print(
        "verified vc+jwt: "
        f"\ntype={_credential_type(payload)} "
        f"\nid={payload.get('id', '')} "
        f"\nissuer={payload.get('issuer', '')}"
    )


def add_verify_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk vc verify`."""
    verify_vc = subparsers.add_parser("verify", help="Verify a VC-JWT")
    verify_vc.add_argument("--token", required=True)
    add_verifier_wait_args(verify_vc)
    verify_vc.set_defaults(handler=handle, success_reporter=report_success)
