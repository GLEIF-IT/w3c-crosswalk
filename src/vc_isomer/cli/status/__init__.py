"""`isomer status ...` command family."""

from __future__ import annotations

import argparse

from .project import add_project_command
from .serve import add_serve_command


def add_status_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the `isomer status ...` command family."""
    status = subparsers.add_parser("status", help="Project local KERI TEL state into credential status")
    status_subparsers = status.add_subparsers(dest="status_command", required=True)

    add_project_command(status_subparsers)
    add_serve_command(status_subparsers)
