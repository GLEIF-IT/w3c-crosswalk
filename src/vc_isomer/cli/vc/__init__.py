"""`isomer vc ...` command family."""

from __future__ import annotations

import argparse

from .issue import add_issue_command
from .verify import add_verify_command
from .verify_pair import add_verify_pair_command


def add_vc_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the `isomer vc ...` command family."""
    vc = subparsers.add_parser("vc", help="Issue and verify VC-JWT artifacts")
    vc_subparsers = vc.add_subparsers(dest="vc_command", required=True)

    add_issue_command(vc_subparsers)
    add_verify_command(vc_subparsers)
    add_verify_pair_command(vc_subparsers)
