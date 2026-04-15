"""`crosswalk verify vp` command."""

from __future__ import annotations

import argparse

from w3c_crosswalk.cli.common import add_verifier_wait_args, load_token_argument, response_for_doers
from w3c_crosswalk.verifier_client import verify_vp_doer


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk verify vp`."""
    return [
        verify_vp_doer(
            base_url=args.server,
            token=load_token_argument(args.token),
            timeout=args.timeout,
            poll_interval=args.poll,
        )
    ]


def report_success(doers) -> None:
    """Print one compact success line for a verified VP-JWT."""
    response = response_for_doers(doers) or {}
    payload = response.get("payload", {})
    checks = response.get("checks", {})
    if not isinstance(payload, dict):
        payload = {}
    if not isinstance(checks, dict):
        checks = {}
    print(
        "verified vp+jwt: "
        f"\nholder={payload.get('holder', '')} "
        f"\nembeddedCredentials={checks.get('embeddedCredentialCount', 0)}"
    )


def add_vp_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk verify vp`."""
    verify_vp = subparsers.add_parser("vp", help="Verify a VP-JWT")
    verify_vp.add_argument("--token", required=True)
    add_verifier_wait_args(verify_vp)
    verify_vp.set_defaults(handler=handle, success_reporter=report_success)
