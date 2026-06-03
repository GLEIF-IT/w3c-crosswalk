# Live-Service Headless W3C E2E

This runbook covers `packages/headless-w3c-e2e`, the browserless wallet harness
for holder-based W3C VRD presentation.

## Acceptance Rule

The harness must validate against live services:

- live KERIA with W3C and did:webs enabled,
- live QVI and holder SignifyPy wallets,
- live Python, Node, and Go verifier HTTP services,
- live verifier operation polling after KERIA submits the VP-JWT.

Verifier test doubles, direct verifier library calls, CLI-only commands, and
fixture-only verifier responses are not acceptance evidence.

Signing stays at the edge. KERIA stages signing inputs and verifies submitted
signatures. SignifyPy edge automators sign locally owned, policy-approved
requests.

## Stack Modes

`--w3c-stack attach`
    Attach to already-running KERIA and verifier services. Provide wallet,
    credential, and verifier URLs through a manifest, environment variables, or
    CLI overrides.

`--w3c-stack process`
    Start real local processes for KERIA, vLEI, did:webs resolver, dashboard,
    and Python/Node/Go verifiers, then seed wallets.

`--w3c-stack docker`
    Start the portable Docker compose stack, run the seed service, and use host
    URLs for harness polling plus container DNS URLs for KERIA verifier
    submission.

## Workflow

The happy path is:

1. QVI edge starts W3C issuance from the native VRD credential.
2. QVI `W3CEdgeAutomator` signs issuer VC proof and VC-JWT requests.
3. KERIA finalizes the W3C VC-JWT.
4. Holder receives the W3C grant, imports it, and signs holder admit.
5. KERIA creates one holder presentation transaction per verifier service.
6. Holder presentation policy records the approved audience, nonce, holder, and
   source credential.
7. Holder `W3CEdgeAutomator` signs the VP-JWT request only if the live KERIA
   transaction still matches the approval.
8. KERIA submits the VP-JWT to the verifier response URI.
9. The harness polls the verifier operation documents and records evidence.

## Inputs

Common configuration sources:

- seed manifest from `.tmp/local-stack/w3c-vrd-chain-manifest.json`,
- `KERIA_ADMIN_URL` / `W3C_KERIA_ADMIN_URL`,
- `KERIA_BOOT_URL` / `W3C_KERIA_BOOT_URL`,
- `W3C_QVI_ALIAS`, `W3C_QVI_PASSCODE`,
- `W3C_HOLDER_ALIAS`, `W3C_HOLDER_PASSCODE`,
- `W3C_SOURCE_CREDENTIAL_SAID` / `W3C_CREDENTIAL_SAID`,
- `W3C_PYTHON_VERIFIER_URL`, `W3C_NODE_VERIFIER_URL`,
  `W3C_GO_VERIFIER_URL`,
- `W3C_PYTHON_SUBMISSION_URL`, `W3C_NODE_SUBMISSION_URL`,
  `W3C_GO_SUBMISSION_URL` when KERIA needs container-internal URLs,
- `W3C_DASHBOARD_URL` / `ISOMER_DASHBOARD_URL`.

## Evidence Manifest

The output manifest includes sanitized runtime config, issuance state, holder
import/admit evidence, presentation transactions, verifier operation evidence,
negative-case evidence, and optional dashboard webhook evidence.

Raw JWTs are redacted by default. Use `--unsafe-raw-tokens` only for local
debugging where signed artifacts are acceptable in logs.

## Troubleshooting

`missing verifier service URLs`
    All Python, Node, and Go verifier URLs are required.

`pending_signature`
    The relevant edge automator is not servicing KERIA signing requests, or the
    signing policy rejected the request.

`blocked_native_vrd`
    The holder lacks the native VRD ACDC needed to import the W3C grant.

`presentation requires exactly one eligible held credential`
    Holder import/admit did not create exactly one eligible held W3C credential,
    or duplicate eligible credentials exist.

`KERIA verifier response did not include a pollable operation name`
    The verifier service is not implementing the shared live-service operation
    contract expected by the harness.
