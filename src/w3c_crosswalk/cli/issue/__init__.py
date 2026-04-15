"""`crosswalk issue ...` command family."""

from __future__ import annotations

import argparse

from .vc import add_vc_command
from .vp import add_vp_command


def add_issue_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the `crosswalk issue ...` command family."""
    issue = subparsers.add_parser("issue", help="Issue W3C JWT artifacts")
    issue_subparsers = issue.add_subparsers(dest="issue_command", required=True)

    add_vc_command(issue_subparsers)
    add_vp_command(issue_subparsers)
