"""CLI entrypoint for the headless W3C holder E2E harness."""

from __future__ import annotations

import argparse
import json
import sys

from .runtime import HeadlessLiveRunConfig, run_live_headless, write_manifest


def main(argv: list[str] | None = None) -> int:
    """Run the headless W3C holder presentation harness."""
    parser = argparse.ArgumentParser(prog="headless-w3c-e2e")
    parser.add_argument("--w3c-stack", choices=("attach", "process", "docker"), default="attach")
    parser.add_argument("--manifest", help="Input JSON manifest with wallet and verifier connection data")
    parser.add_argument("--manifest-out", help="Output evidence manifest path")
    parser.add_argument("--admin-url")
    parser.add_argument("--boot-url")
    parser.add_argument("--qvi-alias")
    parser.add_argument("--qvi-passcode")
    parser.add_argument("--holder-alias")
    parser.add_argument("--holder-passcode")
    parser.add_argument("--source-credential-said")
    parser.add_argument("--python-verifier-url")
    parser.add_argument("--node-verifier-url")
    parser.add_argument("--go-verifier-url")
    parser.add_argument("--python-verifier-submission-url")
    parser.add_argument("--node-verifier-submission-url")
    parser.add_argument("--go-verifier-submission-url")
    parser.add_argument("--boot-if-needed", action="store_true")
    parser.add_argument("--unsafe-raw-tokens", action="store_true")
    args = parser.parse_args(argv)

    overrides = {
        "admin_url": args.admin_url,
        "boot_url": args.boot_url,
        "qviAlias": args.qvi_alias,
        "qviPasscode": args.qvi_passcode,
        "holderAlias": args.holder_alias,
        "holderPasscode": args.holder_passcode,
        "sourceCredentialSaid": args.source_credential_said,
        "manifestOut": args.manifest_out,
        "bootIfNeeded": args.boot_if_needed,
        "unsafeRawTokens": args.unsafe_raw_tokens,
        "verifierUrls": {
            key: value
            for key, value in {
                "python": args.python_verifier_url,
                "node": args.node_verifier_url,
                "go": args.go_verifier_url,
            }.items()
            if value
        },
        "verifierSubmissionUrls": {
            key: value
            for key, value in {
                "python": args.python_verifier_submission_url,
                "node": args.node_verifier_submission_url,
                "go": args.go_verifier_submission_url,
            }.items()
            if value
        },
    }
    overrides = {
        key: value
        for key, value in overrides.items()
        if value is not None and value is not False and value != {}
    }

    config = HeadlessLiveRunConfig.from_sources(
        stack=args.w3c_stack,
        manifest_path=args.manifest,
        overrides=overrides,
    )
    body = run_live_headless(config)
    if args.manifest_out or config.manifest_out:
        write_manifest(args.manifest_out or config.manifest_out, body)
    else:
        sys.stdout.write(json.dumps(body, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
