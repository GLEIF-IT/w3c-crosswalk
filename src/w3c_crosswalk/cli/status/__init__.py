"""`crosswalk status ...` command family."""

from __future__ import annotations

import argparse

from .project import add_project_command
from .revoke import add_revoke_command


def add_status_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the `crosswalk status ...` command family."""
    status = subparsers.add_parser("status", help="Project and mutate local credential status")
    status_subparsers = status.add_subparsers(dest="status_command", required=True)

    add_project_command(status_subparsers)
    add_revoke_command(status_subparsers)
