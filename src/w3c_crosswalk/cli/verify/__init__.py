"""`crosswalk verify ...` command family."""

from __future__ import annotations

import argparse

from .pair import add_pair_command
from .vc import add_vc_command
from .vp import add_vp_command


def add_verify_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the `crosswalk verify ...` command family."""
    verify = subparsers.add_parser("verify", help="Submit and wait for verifier operations")
    verify_subparsers = verify.add_subparsers(dest="verify_command", required=True)

    add_vc_command(verify_subparsers)
    add_vp_command(verify_subparsers)
    add_pair_command(verify_subparsers)
