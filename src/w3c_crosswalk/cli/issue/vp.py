"""`crosswalk issue vp` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from hio.base import doing

from w3c_crosswalk.cli.common import add_common_output_args, add_live_signer_args, emit_json, load_passcode
from w3c_crosswalk.services import issue_vp_artifact
from w3c_crosswalk.signing import HabSigner


class IssueVpDoer(doing.Doer):
    """Issue one VP-JWT artifact as a single explicit CLI doer."""

    def __init__(self, *, args: argparse.Namespace, **kwa):
        self.args = args
        super().__init__(**kwa)

    def recur(self, tyme):
        vc_tokens = [Path(path).read_text(encoding="utf-8").strip() for path in self.args.vc_token]
        signer = HabSigner.open(
            name=self.args.name,
            base=self.args.base,
            alias=self.args.alias,
            passcode=load_passcode(self.args),
        )
        try:
            result = issue_vp_artifact(
                vc_tokens=vc_tokens,
                holder_did=self.args.holder_did,
                signer=signer,
                audience=self.args.audience,
                nonce=self.args.nonce,
            )
            emit_json(result.to_dict(), output=self.args.output)
        finally:
            signer.close()
        return True


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk issue vp`."""
    return [IssueVpDoer(args=args)]


def add_vp_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk issue vp`."""
    issue_vp = subparsers.add_parser("vp", help="Wrap one or more VC-JWTs in a VP-JWT")
    issue_vp.add_argument("--vc-token", action="append", required=True)
    issue_vp.add_argument("--holder-did", required=True)
    issue_vp.add_argument("--audience")
    issue_vp.add_argument("--nonce")
    add_live_signer_args(issue_vp)
    add_common_output_args(issue_vp)
    issue_vp.set_defaults(handler=handle)
