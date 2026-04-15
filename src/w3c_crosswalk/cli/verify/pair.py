"""`crosswalk verify pair` command."""

from __future__ import annotations

import argparse
from typing import Any

from w3c_crosswalk.cli.common import add_live_signer_args, add_verifier_wait_args, load_passcode, load_token_argument, response_for_doers
from w3c_crosswalk.keri_projection import ACDCProjector
from w3c_crosswalk.verifier_client import verify_pair_doer


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk verify pair`."""
    projector = ACDCProjector.open(
        name=args.name,
        base=args.base,
        alias=args.alias,
        passcode=load_passcode(args),
    )
    try:
        acdc = projector.project_credential(args.said).acdc
    finally:
        projector.close()
    return [
        verify_pair_doer(
            base_url=args.server,
            token=load_token_argument(args.token),
            acdc=acdc,
            timeout=args.timeout,
            poll_interval=args.poll,
        )
    ]


def _credential_type(payload: dict[str, Any]) -> str:
    types = payload.get("type", [])
    if isinstance(types, list):
        for typ in reversed(types):
            if isinstance(typ, str) and typ != "VerifiableCredential":
                return typ
    return "unknown"


def report_success(doers) -> None:
    """Print one compact success line for a verified ACDC/VC pair."""
    response = response_for_doers(doers) or {}
    payload = response.get("payload", {})
    if not isinstance(payload, dict):
        payload = {}
    crosswalk = payload.get("crosswalk", {})
    if not isinstance(crosswalk, dict):
        crosswalk = {}
    print(
        "verified crosswalk pair: "
        f"\ntype={_credential_type(payload)} "
        f"\nsource={crosswalk.get('sourceCredentialSaid', '')} "
        f"\nvc={payload.get('id', '')}"
    )


def add_pair_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk verify pair`."""
    verify_pair = subparsers.add_parser("pair", help="Verify a VC-JWT against its source ACDC")
    verify_pair.add_argument("--said", required=True, help="Source ACDC credential SAID to compare against the VC-JWT")
    verify_pair.add_argument("--token", required=True)
    add_live_signer_args(verify_pair)
    add_verifier_wait_args(verify_pair)
    verify_pair.set_defaults(handler=handle, success_reporter=report_success)
