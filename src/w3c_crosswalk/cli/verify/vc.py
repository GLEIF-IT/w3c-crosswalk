"""`crosswalk verify vc` command."""

from __future__ import annotations

import argparse

from w3c_crosswalk.cli.common import add_verifier_wait_args, load_token_argument
from w3c_crosswalk.verifier_client import verify_vc_doer


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk verify vc`."""
    return [
        verify_vc_doer(
            base_url=args.server,
            token=load_token_argument(args.token),
            timeout=args.timeout,
            poll_interval=args.poll,
        )
    ]


def add_vc_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk verify vc`."""
    verify_vc = subparsers.add_parser("vc", help="Verify a VC-JWT")
    verify_vc.add_argument("--token", required=True)
    add_verifier_wait_args(verify_vc)
    verify_vc.set_defaults(handler=handle)
