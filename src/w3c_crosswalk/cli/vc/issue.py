"""`crosswalk vc issue` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from w3c_crosswalk.cli.common import add_common_output_args, add_live_signer_args, emit_json, load_passcode
from w3c_crosswalk.isomer_runtime import IsomerRuntimeDoer
from w3c_crosswalk.services import issue_vc_artifact
from w3c_crosswalk.status import JsonFileStatusStore


def default_token_output_path(output: str) -> Path:
    """Return the default token path beside the JSON artifact output."""
    return Path(output).with_suffix(".token")


class IssueVcDoer(IsomerRuntimeDoer):
    """Issue one VC-JWT artifact as a single explicit CLI doer."""

    def __init__(self, *, args: argparse.Namespace, **kwa):
        self.args = args
        super().__init__(
            name=args.name,
            base=args.base,
            alias=args.alias,
            passcode=load_passcode(args),
            **kwa,
        )

    def recur(self, tyme):
        store = JsonFileStatusStore(self.args.store) if self.args.store else None
        result = issue_vc_artifact(
            projector=self.projector,
            signer=self.signer,
            said=self.args.said,
            issuer_did=self.args.issuer_did,
            status_base_url=self.args.status_base_url,
            status_store=store,
        )
        emit_json(result.to_dict(), output=self.args.output)
        if self.args.output:
            json_path = Path(self.args.output)
            token_path = Path(self.args.token_output) if self.args.token_output else default_token_output_path(self.args.output)
            token_path.parent.mkdir(parents=True, exist_ok=True)
            token_path.write_text(result.token, encoding="utf-8")
            print(f"vc: {json_path}")
            print(f"jwt: {token_path}")
        return True


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk vc issue`."""
    return [IssueVcDoer(args=args)]


def add_issue_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk vc issue`."""
    issue_vc = subparsers.add_parser("issue", help="Issue a VC-JWT from accepted local KERI credential state")
    issue_vc.add_argument("--said", required=True, help="Source ACDC credential SAID to project")
    issue_vc.add_argument("--issuer-did", required=True)
    issue_vc.add_argument("--status-base-url", required=True)
    issue_vc.add_argument("--store")
    issue_vc.add_argument("--token-output", help="Optional raw VC-JWT path; defaults beside --output with .token suffix")
    add_live_signer_args(issue_vc)
    add_common_output_args(issue_vc)
    issue_vc.set_defaults(handler=handle)
