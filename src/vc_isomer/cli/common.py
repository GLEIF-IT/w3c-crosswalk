"""Shared CLI argument and output helpers."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from vc_isomer.common import write_json_file


def emit_json(body: dict | list, *, output: str | None = None) -> None:
    """Write one JSON result to disk or stdout."""
    if output:
        write_json_file(output, body)
        return
    print(json.dumps(body, indent=2))


def load_token_argument(value: str) -> str:
    """Load a token from a file path when present, otherwise treat it as inline."""
    path = Path(value)
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return value


def load_passcode(args: argparse.Namespace) -> str | None:
    """Load the signer passcode from CLI args or the configured environment variable."""
    if args.passcode:
        return args.passcode
    if args.passcode_env:
        value = os.environ.get(args.passcode_env)
        if value:
            return value.strip()
    raise ValueError("a live habitat signer requires --passcode or a populated --passcode-env variable")


def add_common_output_args(parser: argparse.ArgumentParser) -> None:
    """Add the shared optional output path argument used by write commands."""
    parser.add_argument("--output", help="Optional path to write the JSON result to")


def add_live_signer_args(parser: argparse.ArgumentParser) -> None:
    """Add the arguments required to open a live KERI habitat signer."""
    parser.add_argument("--name", required=True, help="KLI/KERIpy keystore name")
    parser.add_argument("--base", default="", help="KLI/KERIpy keystore base path")
    parser.add_argument("--alias", required=True, help="Habitat alias inside the keystore")
    parser.add_argument("--passcode", help="Passcode/bran for opening the KLI/KERIpy keystore")
    parser.add_argument(
        "--passcode-env",
        default="SIGNER_PASS",
        help="Environment variable to read the passcode from when --passcode is omitted",
    )


def add_verifier_wait_args(parser: argparse.ArgumentParser) -> None:
    """Add the shared verifier server and wait controls used by verify commands."""
    parser.add_argument("--server", required=True, help="Base URL of the verifier operation service")
    parser.add_argument("--timeout", type=float, default=90.0, help="Maximum seconds to wait for completion")
    parser.add_argument("--poll", type=float, default=0.25, help="Polling interval in seconds while waiting")


def failure_message_for_doers(doers) -> str | None:
    """Return a compact human-readable failure message for completed command doers."""
    for doer in doers:
        error = getattr(doer, "error", None)
        if error is not None:
            return str(error)
    return None


def response_for_doers(doers) -> dict | None:
    """Return the first terminal verifier response available on completed doers."""
    for doer in doers:
        operation = getattr(doer, "operation", None)
        if not isinstance(operation, dict):
            continue
        response = operation.get("response")
        if isinstance(response, dict):
            return response
    return None


def report_failure_for_doers(doers) -> int:
    """Print a compact failure message to stderr and return a process exit code."""
    message = failure_message_for_doers(doers)
    if message is None:
        return 0
    print(message, file=sys.stderr)
    return 1
