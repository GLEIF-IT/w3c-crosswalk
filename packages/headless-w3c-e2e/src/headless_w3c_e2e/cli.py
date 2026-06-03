"""CLI entrypoint for the headless W3C holder E2E harness."""

from __future__ import annotations

import argparse
import json
import sys

from .docker_stack import ManagedDockerStack
from .runtime import HeadlessLiveRunConfig, run_live_headless, write_manifest
from .process_stack import ManagedProcessStack


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
    parser.add_argument("--dashboard-url")
    parser.add_argument("--boot-if-needed", action="store_true")
    parser.add_argument("--unsafe-raw-tokens", action="store_true")
    parser.add_argument("--keep-stack", action="store_true", help="Keep a managed process stack running after exit")
    parser.add_argument("--process-root", help="Runtime directory for --w3c-stack=process logs and manifests")
    parser.add_argument("--keria-bin", help="KERIA binary path for --w3c-stack=process")
    parser.add_argument("--docker-project", default="w3c-crosswalk", help="Compose project for --w3c-stack=docker")
    parser.add_argument("--env-file", help="Compose env file for --w3c-stack=docker")
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
        "dashboardUrl": args.dashboard_url,
    }
    overrides = {
        key: value
        for key, value in overrides.items()
        if value is not None and value is not False and value != {}
    }

    if args.w3c_stack == "process":
        with ManagedProcessStack(
            runtime_root=args.process_root,
            keep_stack=args.keep_stack,
            keria_bin=args.keria_bin,
        ) as stack:
            config = HeadlessLiveRunConfig.from_sources(
                stack=args.w3c_stack,
                manifest_path=str(stack.manifest_path),
                overrides={**overrides, **stack.config_overrides()},
            )
            body = run_live_headless(config)
            _write_or_print(body, args.manifest_out or config.manifest_out)
    elif args.w3c_stack == "docker":
        with ManagedDockerStack(
            project=args.docker_project,
            env_file=args.env_file,
            keep_stack=args.keep_stack,
        ) as stack:
            config = HeadlessLiveRunConfig.from_sources(
                stack=args.w3c_stack,
                manifest_path=str(stack.manifest_path),
                overrides={**overrides, **stack.config_overrides()},
            )
            body = run_live_headless(config)
            _write_or_print(body, args.manifest_out or config.manifest_out)
    else:
        config = HeadlessLiveRunConfig.from_sources(
            stack=args.w3c_stack,
            manifest_path=args.manifest,
            overrides=overrides,
        )
        body = run_live_headless(config)
        _write_or_print(body, args.manifest_out or config.manifest_out)
    return 0


def _write_or_print(body: dict, path: str | None) -> None:
    if path:
        write_manifest(path, body)
    else:
        sys.stdout.write(json.dumps(body, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
