"""`crosswalk verify pair` command."""

from __future__ import annotations

import argparse

from w3c_crosswalk.cli.common import add_verifier_wait_args, load_token_argument
from w3c_crosswalk.common import load_json_file
from w3c_crosswalk.verifier_client import verify_pair_doer


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk verify pair`."""
    return [
        verify_pair_doer(
            base_url=args.server,
            token=load_token_argument(args.token),
            acdc=load_json_file(args.acdc),
            timeout=args.timeout,
            poll_interval=args.poll,
        )
    ]


def add_pair_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk verify pair`."""
    verify_pair = subparsers.add_parser("pair", help="Verify a VC-JWT against its source ACDC")
    verify_pair.add_argument("--acdc", required=True)
    verify_pair.add_argument("--token", required=True)
    add_verifier_wait_args(verify_pair)
    verify_pair.set_defaults(handler=handle)
