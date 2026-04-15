"""`crosswalk issue vc` command."""

from __future__ import annotations

import argparse

from hio.base import doing

from w3c_crosswalk.cli.common import add_common_output_args, add_live_signer_args, emit_json, load_passcode
from w3c_crosswalk.common import load_json_file
from w3c_crosswalk.services import issue_vc_artifact
from w3c_crosswalk.signing import KeriHabSigner
from w3c_crosswalk.status import JsonFileStatusStore


class IssueVcDoer(doing.Doer):
    """Issue one VC-JWT artifact as a single explicit CLI doer."""

    def __init__(self, *, args: argparse.Namespace, **kwa):
        self.args = args
        super().__init__(**kwa)

    def recur(self, tyme):
        acdc = load_json_file(self.args.acdc)
        signer = KeriHabSigner.open(
            name=self.args.name,
            base=self.args.base,
            alias=self.args.alias,
            passcode=load_passcode(self.args),
        )
        try:
            store = JsonFileStatusStore(self.args.store) if self.args.store else None
            result = issue_vc_artifact(
                acdc=acdc,
                issuer_did=self.args.issuer_did,
                status_base_url=self.args.status_base_url,
                signer=signer,
                status_store=store,
            )
            emit_json(result.to_dict(), output=self.args.output)
        finally:
            signer.close()
        return True


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk issue vc`."""
    return [IssueVcDoer(args=args)]


def add_vc_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk issue vc`."""
    issue_vc = subparsers.add_parser("vc", help="Issue a VC-JWT from an ACDC fixture")
    issue_vc.add_argument("--acdc", required=True)
    issue_vc.add_argument("--issuer-did", required=True)
    issue_vc.add_argument("--status-base-url", required=True)
    issue_vc.add_argument("--store")
    add_live_signer_args(issue_vc)
    add_common_output_args(issue_vc)
    issue_vc.set_defaults(handler=handle)
