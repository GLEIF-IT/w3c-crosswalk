#!/usr/bin/env python
"""Seeds vLEI trust chain and VRD credential then projects W3C for presentation.

Workflow includes:
- modified KERIA (+SSE, +did:webs, +W3Cing)
  - actors (GEDA, QVI, LE)
  - projects VRD ACDC to W3C serialization
  - presents W3C to W3C verifiers (Python, Node, Go)
- modified SignifyPy (+SSE, +did:webs, +W3Cing)
- auto-signs KERIA's W3C proof and VC-JWT requests through SignifyPy
- and waits for each verifier operation to finish.

Manually running this:
0. Stop a prior stack with ``make local-down``. Use ``make local-reset`` only
   when you intentionally want to wipe local KERIA/witness/resolver volumes and
   generated seed manifests.
1. Run ``make local-up`` from the ``w3c-crosswalk`` repository to start KERIA,
   the verifier services, and supporting services.
2. Run ``make local-seed`` to execute SignifyPy's
   ``scripts/setup_vrd_projection_chain.py`` helper. That helper creates the
   GEDA -> QVI -> LE VRD credential chain and writes this script's manifest.

   ATTENTION: You can stop here if you want to run the W3C project steps from
              the UI rather than the CLI through SignifyPy.

3. Run ``make local-project`` to execute this script in the ``signifypy``
   container. ``make local-test`` runs this projection check after portability
   guards, but it expects ``make local-seed`` to have already written the
   manifest.

The default manifest path is
``/workspace/.tmp/local-stack/w3c-vrd-chain-manifest.json`` inside the
container. The script currently depends on the following manifest fields:

.. code-block:: json

    {
      "actors": {
        "qvi": {
          "passcode": "seeded-qvi-agent-passcode"
        }
      },
      "projection": {
        "identifierName": "seeded-qvi-aid-name",
        "credentialSaid": "seeded-vrd-credential-said"
      }
    }

The seeder writes additional actor, registry, credential, and did:webs fields
for operators and later workflow checks, but this script does not read them.

Service dependencies:

- KERIA admin and boot endpoints must be reachable. The defaults are
  compose-internal URLs: ``http://keria:3901`` and ``http://keria:3903``.
- KERIA must expose a W3C verifier allowlist through ``/w3c/verifiers``.
- Each allowlisted verifier must expose ``GET /operations/{operationName}``.
  The default verifier base URLs are compose-internal service names for the
  Python, Node, and Go verifier containers.
- The vLEI server and did:webs resolver are indirect prerequisites. They are
  needed by ``make local-seed`` and by verifier validation, but this script only
  talks directly to KERIA and the verifier operation APIs.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import requests
from keri.core.coring import Tiers

from signify.app.clienting import SignifyClient
from signify.app.w3cing import MemoryW3CDedupeStore, W3CProjectionAutoApprover


DEFAULT_VERIFIER_BASES = {
    "isomer-python-local": "http://isomer-python:8788",
    "isomer-node-local": "http://isomer-node:8788",
    "isomer-go-local": "http://isomer-go:8788",
}


def main() -> None:
    """Run the seeded VRD projection workflow against every KERIA verifier.

    The workflow intentionally keeps validation implicit: missing manifest keys,
    unreachable services, failed verifier responses, and timed-out projection
    sessions all fail the process instead of being recovered locally. That makes
    this helper useful as a compose-stack acceptance check.

    Side Effects:
        Creates W3C projection sessions in KERIA, submits signatures for KERIA's
        W3C signing requests, writes the optional result JSON file, and prints
        the same result shape to stdout.

    Raises:
        SystemExit: A projection, verifier operation, or verifier ``ok`` check
            fails.
    """
    args = parser().parse_args()

    # The seeder owns this contract. Keep this script focused on consuming the
    # QVI passcode plus the identifier/credential pair selected for projection.
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    qvi = manifest["actors"]["qvi"]
    name = manifest["projection"]["identifierName"]
    credential_said = manifest["projection"]["credentialSaid"]

    # Reconnect as the seeded QVI actor because KERIA asks the credential issuer
    # to sign both the Data Integrity proof and VC-JWT projection requests.
    qvi_client = SignifyClient(
        passcode=qvi["passcode"],
        tier=Tiers.low,
        url=args.admin_url,
        boot_url=args.boot_url,
    )
    qvi_client.connect()

    # Defaults target compose-internal service names; overrides support running
    # the helper from a different network namespace without changing the stack.
    verifier_bases = dict(DEFAULT_VERIFIER_BASES)
    verifier_bases.update(parse_verifier_bases(args.verifier_base))

    results = []
    for verifier in qvi_client.w3c().verifiers():
        verifier_id = verifier["id"]
        # KERIA owns projection state and signature requests; the external
        # verifier owns the long-running operation result referenced by KERIA.
        session = project_and_sign(
            qvi_client,
            name=name,
            credential_said=credential_said,
            verifier_id=verifier_id,
            timeout=args.timeout,
        )
        operation = wait_for_verifier_operation(
            verifier_bases[verifier_id],
            session["verifierResponse"]["name"],
            timeout=args.timeout,
        )
        response = operation.get("response") or {}
        if not response.get("ok"):
            raise SystemExit(
                json.dumps(
                    {"verifier": verifier_id, "operation": operation},
                    indent=2,
                    sort_keys=True,
                )
            )

        results.append(
            {
                "verifier": verifier_id,
                "operation": operation["name"],
                "ok": response["ok"],
                "checks": response.get("checks", {}),
            }
        )

    # Keep the result shape stable for Makefile checks and human debugging.
    output = {"verified": results}
    if args.output:
        Path(args.output).write_text(
            json.dumps(output, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(output, indent=2, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    """Build the CLI parser for the compose-local projection helper.

    Defaults are intentionally container-oriented because the Makefile runs this
    script through the ``signifypy-project`` compose service. Host-machine or
    alternate network execution should pass explicit endpoint overrides.

    Returns:
        Configured argument parser.
    """
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--manifest",
        default="/workspace/.tmp/local-stack/w3c-vrd-chain-manifest.json",
        help="seed manifest written by setup_vrd_projection_chain.py",
    )
    p.add_argument("--admin-url", default="http://keria:3901")
    p.add_argument("--boot-url", default="http://keria:3903")
    p.add_argument(
        "--verifier-base",
        action="append",
        default=[],
        help="override verifier base as verifier-id=http://host:port",
    )
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--output", default="/workspace/.tmp/local-stack/w3c-projection-results.json")
    return p


def parse_verifier_bases(values: list[str]) -> dict[str, str]:
    """Parse verifier endpoint overrides from ``verifier-id=url`` strings.

    Args:
        values: Repeatable ``--verifier-base`` values.

    Returns:
        Mapping from KERIA verifier id to base URL without a trailing slash.

    Raises:
        SystemExit: An override does not contain ``=``.
    """
    parsed = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"invalid --verifier-base {value!r}; expected verifier-id=url")
        verifier_id, base_url = value.split("=", 1)
        parsed[verifier_id] = base_url.rstrip("/")
    return parsed


def project_and_sign(
    client: SignifyClient,
    *,
    name: str,
    credential_said: str,
    verifier_id: str,
    timeout: float,
) -> dict:
    """Create a KERIA projection session and sign its W3C requests.

    KERIA emits short-lived W3C signing requests for the projection session.
    This helper polls durable requests, auto-approves them with the connected
    Signify client, reconciles submitted request state, and watches the KERIA
    projection session until it reaches a terminal state. The in-memory dedupe
    store is deliberate because this script is a one-shot acceptance helper.

    Args:
        client: Connected Signify client for the credential issuer AID.
        name: KERIA identifier name that owns the credential.
        credential_said: SAID of the seeded ACDC credential to project.
        verifier_id: KERIA verifier allowlist id to target.
        timeout: Maximum seconds to wait for session completion.

    Returns:
        Completed KERIA projection session.

    Raises:
        SystemExit: The session reaches ``failed`` or ``expired`` state, or does
            not complete before the timeout.
    """
    session = client.w3c().project(name, credential_said, verifier_id)
    approver = W3CProjectionAutoApprover(client, store=MemoryW3CDedupeStore())
    deadline = time.time() + timeout
    while time.time() < deadline:
        approver.pollOnce(name=name)
        approver.reconcile(name=name)
        session = client.w3c().projection(name, session["d"])
        if session["state"] in {"complete", "failed", "expired"}:
            break
        time.sleep(0.5)

    if session["state"] != "complete":
        raise SystemExit(
            f"projection for {verifier_id} ended in {session['state']}: {session.get('error')}"
        )
    return session


def wait_for_verifier_operation(base_url: str, operation_name: str, *, timeout: float) -> dict:
    """Poll one verifier long-running operation until it is done.

    The W3C verifier services return operation names to KERIA, and KERIA stores
    those names in the projection session's verifier response. This helper polls
    the verifier's ``GET /operations/{operationName}`` endpoint until the
    operation reports ``done``. The caller is responsible for checking the
    operation's ``response.ok`` value.

    Args:
        base_url: Base URL for a W3C verifier service.
        operation_name: Operation name returned by the verifier through KERIA.
        timeout: Maximum seconds to wait for ``done``.

    Returns:
        Completed verifier operation document.

    Raises:
        SystemExit: The operation does not finish before the timeout.
    """
    deadline = time.time() + timeout
    url = f"{base_url.rstrip('/')}/operations/{operation_name}"
    operation = {}
    while time.time() < deadline:
        operation = requests.get(url, timeout=10).json()
        if operation.get("done"):
            return operation
        time.sleep(0.5)
    raise SystemExit(f"timed out waiting for verifier operation {operation_name}: {operation}")


if __name__ == "__main__":
    main()
