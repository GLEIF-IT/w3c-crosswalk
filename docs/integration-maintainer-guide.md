# Integration Maintainer Guide

This guide is for maintainers debugging the live Isomer integration path. It
does not teach W3C VC-JWT from scratch. It explains where truth lives, what
launches, and where to start when the live test fails.

## Three-Layer Model

1. Live stack orchestration
   `tests/integration/conftest.py` and `tests/integration/topology.py` own
   runtime directories, reserved ports, subprocess launch, staged assets, logs,
   and the `live_stack` fixture contract.
2. In-process KERI workflow orchestration
   `tests/integration/kli_flow.py` owns actor setup, OOBI resolution,
   delegated inception, registry inception, issue/grant/admit, mailbox sync,
   and cleanup.
3. Isomer runtime seams
   `src/vc_isomer/` owns ACDC-to-VC projection, JWT issuance, `did:webs`
   resolution, status projection, HTTP service wrappers, and verification.

Everything before W3C projection is the real KERI/ACDC issuance workflow. W3C
material is the final interoperability projection.

## Source Of Truth

- KEL state is authoritative for identifier state.
- TEL/registry state is authoritative for credential issuance and revocation.
- IPEX exchange state and mailbox delivery drive grant/admit flow.
- W3C VC-JWT/VP-JWT artifacts are derived twins.
- The local status service projects registry state for W3C verifier
  consumption.

If a semantic failure appears in a JWT, check KERI/TEL state first. Debugging
the projection while the source state is wrong wastes time.

## Service Process Model

The live stack launches four services immediately:

1. Witness subprocess with `wan`, `wil`, and `wes`.
2. `vLEI-server` for schema OOBIs and helper material.
3. Status service for W3C `credentialStatus` resources.
4. Verifier operation service.

`did:webs` artifact and resolver services launch lazily when the workflow
reaches W3C issuance and verification. The KERI issuance path does not need
`did:webs`, so starting it late keeps the dependency boundary honest.

## Live Test Phases

The flagship test in `tests/integration/test_single_sig_vrd_isomer.py`
proceeds through:

1. Stack launch and HOME sandbox setup.
2. Actor keystore/bootstrap setup.
3. OOBI resolution.
4. Delegated QVI inception.
5. TEL registry creation.
6. GEDA -> QVI -> LE -> VRD Auth -> VRD credential chain.
7. Status projection for the final VRD credential.
8. Lazy `did:webs` launch.
9. VC-JWT issuance from the source VRD ACDC.
10. Verifier-operation submission and polling.
11. DID resolution, status dereference, and Isomer verification.

The key boundary is between phase 6 and phase 9. Phase 9 onward is projection,
not issuance.

## Headless Holder E2E

`packages/headless-w3c-e2e` validates the holder-based W3C VRD path after the
KERIA W3C workflow work. It is browserless, but it follows the same wallet
roles as the React app:

1. QVI edge starts W3C issuance from the native VRD.
2. QVI edge signs issuer VC proof and VC-JWT requests.
3. Holder receives the W3C grant, imports it, and signs holder admit.
4. Holder starts KERIA presentation transactions from verifier descriptors.
5. Holder edge signs VP-JWT requests only after approval binding checks pass.
6. KERIA submits to live verifier services.
7. The harness polls Python, Node, and Go operation resources for evidence.

Stack modes:

- `attach`: use an already-running service graph.
- `process`: start real local processes.
- `docker`: use the portable compose stack.

Do not replace any verifier with an in-process callable for this acceptance
path. Unit tests may use fakes to cover route contracts, but holder E2E
evidence must come from live HTTP services.

## Mailbox Sync Before Admit

`AdmitDoer` expects the referenced `/ipex/grant` exchange message to already
exist in the recipient store. The integration layer therefore performs an
explicit mailbox sync before admission:

- sender creates and sends `/ipex/grant`
- recipient mailbox director receives `/credential` traffic
- helper waits for the exact grant exchange SAID locally
- admit workflow runs

Without this ordering, failures look like IPEX or registry bugs when they are
really mailbox sequencing bugs.

## Runtime Seams

- `profile.py` projects supported ACDCs into the Isomer W3C VC shape.
- `jwt.py` binds projected payloads to live KERI habitat signing keys.
- `didwebs.py` owns the narrow `did:webs` resolver seam.
- `status.py` owns local status projection and status fetch behavior.
- `service.py` wraps status and verifier submission/polling in HTTP.
- `verifier.py` performs pure W3C and ACDC/W3C pair verification.
- `verifier_runtime.py` runs verifier work in background HIO doers.
- `longrunning.py` stores local operation resources.
- `verifier_client.py` is the CLI/integration client for operation flows.
- `cli/` composes runtime seams by command family.

The CLI package is not the architecture. Runtime modules and live services are
the architecture. The CLI walkthrough is useful diagnostics, not holder
presentation acceptance evidence.

## Current Debt

- Local managed doer wrappers are integration debt. Prefer stock KERIpy doers
  and upstream cleanup fixes when the dependency exposes the needed seams.
- The JSON-file-backed status service is a POC projection, not a production
  credential-status architecture.
- `vLEI-server` is a schema/OOBI helper. It is not a source of truth for issued
  credentials.
- KLI subprocess workflow remains transitional where equivalent KERIpy doers
  or library APIs are available.

## Debug Order

Use this order before collecting broad logs:

1. stack launch and service logs
2. topology URLs and ports
3. actor HOME sandbox and `.keri` state
4. OOBI resolution and witness-backed key state
5. registry/TEL state
6. exchange and mailbox state
7. status projection
8. `did:webs` resolution
9. W3C token issuance and verification
10. holder import/admit state for headless or browser presentation
11. verifier service operation documents

If you start from the JWT when registry state is wrong, you are debugging the
shadow instead of the source.
