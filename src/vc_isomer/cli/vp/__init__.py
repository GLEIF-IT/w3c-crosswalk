"""`isomer vp ...` command family."""

from __future__ import annotations

import argparse

from .issue import add_issue_command
from .verify import add_verify_command


def add_vp_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the `isomer vp ...` command family."""
    vp = subparsers.add_parser("vp", help="Issue and verify VP-JWT artifacts")
    vp_subparsers = vp.add_subparsers(dest="vp_command", required=True)

    add_issue_command(vp_subparsers)
    add_verify_command(vp_subparsers)
