"""`crosswalk vc verify-pair` command."""

from __future__ import annotations

import argparse
from typing import Any

from w3c_crosswalk.cli.common import add_live_signer_args, add_verifier_wait_args, load_passcode, load_token_argument, response_for_doers
from w3c_crosswalk.isomer_runtime import IsomerRuntimeDoDoer
from w3c_crosswalk.verifier_client import verify_pair_doer


class VerifyPairCommandDoer(IsomerRuntimeDoDoer):
    """Project the source ACDC under IsomerRuntime, then verify the pair."""

    def __init__(self, *, args: argparse.Namespace, **kwa):
        self.args = args
        self.verify_doer = None
        self.error = None
        self.operation = None
        super().__init__(
            name=args.name,
            base=args.base,
            alias=args.alias,
            passcode=load_passcode(args),
            **kwa,
        )

    def build_doers(self):
        """Create the verifier child after IsomerRuntime has opened."""
        acdc = self.projector.project_credential(self.args.said).acdc
        self.verify_doer = verify_pair_doer(
            base_url=self.args.server,
            token=load_token_argument(self.args.token),
            acdc=acdc,
            timeout=self.args.timeout,
            poll_interval=self.args.poll,
        )
        return [self.verify_doer]

    def recur(self, tyme, deeds=None):
        """Run the verifier child and mirror its public result fields."""
        done = super().recur(tyme=tyme, deeds=deeds)
        if self.verify_doer is not None:
            self.error = getattr(self.verify_doer, "error", None)
            self.operation = getattr(self.verify_doer, "operation", None)
        return done


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk vc verify-pair`."""
    return [VerifyPairCommandDoer(args=args)]


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


def add_verify_pair_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk vc verify-pair`."""
    verify_pair = subparsers.add_parser("verify-pair", help="Verify a VC-JWT against its source ACDC")
    verify_pair.add_argument("--said", required=True, help="Source ACDC credential SAID to compare against the VC-JWT")
    verify_pair.add_argument("--token", required=True)
    add_live_signer_args(verify_pair)
    add_verifier_wait_args(verify_pair)
    verify_pair.set_defaults(handler=handle, success_reporter=report_success)
