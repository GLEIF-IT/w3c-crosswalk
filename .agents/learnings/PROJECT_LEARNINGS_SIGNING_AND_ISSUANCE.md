# PROJECT_LEARNINGS_SIGNING_AND_ISSUANCE

Persistent memory for signer policy, issuance flow rules, and signing-related
interop behavior.

## Current Status

1. Demo signers are banned.
2. Runtime and integration signing must use live KERI habitat signers from
   KLI/KERIpy-managed keystores.
3. Test determinism is allowed only through real temporary habitats created
   from KERI salt or passcode inputs.
4. Any CLI or service path that mints a W3C credential without opening a real
   habitat signer is incomplete.

## Scope

Use this doc for signer selection, issuance invariants, runtime-vs-test
boundaries, and wallet/KLI signer integration notes.

## Decision Log

### 2026-04-17 - isomer-node Verifier Flow Refactored for Maintainability

- Changed: Split the Node sidecar into a command-level `serve` operation, a
  small Effection promise adapter, explicit `did-jwt-vc` interop wrappers, and
  separate VC/VP verification operations with typed check payloads and
  dependency seams for tests.
- Why: The sidecar was correct but hard to review because verification,
  transport, library boundaries, and testability were too entangled.
- Verified: `npm --prefix apps/isomer-node run check` and
  `npm --prefix apps/isomer-node test`.
- Touched/Risks: `apps/isomer-node` only. Behavior stayed stable, but future
  feature work should keep Promise-based library calls wrapped at the Effection
  boundary rather than reintroducing ad hoc async seams.

### 2026-04-15 - External W3C Verifier Sidecars Added

- Changed: Added Node and Go verifier sidecars, a pytest harness in
  `src/vc_isomer/interop/external_verifiers.py`, env-based selection via
  `ISOMER_EXTERNAL_VERIFIERS`, and `urn:said:<SAID>` for nested
  `legalEntityCredential.id`.
- Why: Isomer needs acceptance evidence from independent W3C tooling, not only
  the Python verifier.
- Verified: `make external-node-check`, `make external-go-check`, focused
  profile/data-integrity/verifier tests, and live single-sig integration with
  none, Node, Go, and both sidecars.
- Touched/Risks: `plans/isomer-w3c-sidecars.md`, sidecar apps, harness, live
  integration test, and related docs. Sidecars are acceptance tools, not
  TEL/ACDC-aware verifier replacements; Go VP wrapper JSON-LD remains partial;
  Node deps need audit review before any production hardening.

### 2026-04-15 - VCDM 1.1 VC-JWT with Embedded KERI Data Integrity Proofs

- Changed: Retargeted projected credentials to VCDM 1.1 JSON-LD with
  `issuanceDate`, the 2018 credentials context, VCDM 1.1 `vc`/`vp` JWT
  envelopes, KERI-backed `eddsa-rdfc-2022` proofs, packaged JSON-LD contexts, a
  packaged Isomer VRD JSON Schema, and OpenID4VCI/OpenID4VP examples.
- Why: The W3C projection must validate outside the custom pair verifier.
- Verified: Profile, JWT, Data Integrity, verifier, service/runtime, interop
  artifact, live single-sig integration, `make smoke`, and `make dist-check`.
- Touched/Risks: `src/vc_isomer/{profile,data_integrity,jwt,verifier}.py`,
  `docs/isomer-profile.md`, and `plans/w3c-vrd-isomer-plan.md`. External
  verifier sidecars remained the next hardening step.

### 2026-04-15 - Packaging and Release Path Finalized

- Changed: Added a Makefile-driven publish pipeline, split packaging to
  distribution `vc-isomer` and import package `vc_isomer`, and hard-cut product
  identity to Isomer naming without compatibility aliases.
- Why: First publication needed a repeatable release gate and a valid PyPI
  namespace while preserving product branding.
- Verified: `make help`, `make smoke`, `make dist-check`, package/import/CLI
  smoke checks, focused pytest runs, and expected failure of legacy imports.
- Touched/Risks: `Makefile`, `pyproject.toml`, `uv.lock`, `README.md`,
  `docs/isomer-profile.md`, `plans/w3c-vrd-isomer-plan.md`, and
  `.agents/PROJECT_LEARNINGS.md`. Use TestPyPI first, keep worktrees clean
  unless `ALLOW_DIRTY=1`, and accept that the `isomer` console script may still
  conflict with other installed tools.

### 2026-04-15 - Integration Doer Supervision and Verifier Simplification

- Changed: `run_doers_until(...)` now uses supervisory `DoDoer` ownership under
  `Doist.do(real=True, limit=timeout)`, and verifier observability bloat was
  removed so operations again store only name, state timestamps, terminal
  response, and terminal error.
- Why: The old helper mixed wall-clock and logical-time pacing, and the extra
  tracing made the verifier harder to read before the architecture stabilized.
- Verified: Focused helper tests plus refreshed long-running, service, client,
  runtime, and DID resolver test coverage.
- Touched/Risks: `.agents/PROJECT_LEARNINGS.md`. Remaining timing work should
  target real I/O deadlines and scheduler pacing, not rebuild fine-grained
  tracing.

### 2026-04-15 - did:webs Resolver URL Quoting Fixed

- Changed: Stopped pre-quoting full did:webs DIDs before HIO clienting;
  `resolution_url(...)` now passes the canonical DID path component and lets HIO
  quote the HTTP path once.
- Why: Double-quoting broke `didding.requote(...)` inside
  `did-webs-resolver`.
- Verified: `tests/test_didwebs.py`, compile checks for `didwebs.py`, and the
  live single-sig integration path.
- Touched/Risks: Resolver DID parsing is fixed; remaining live failures moved to
  verifier POST timing.

### 2026-04-14 - did:webs Fixture Moved In-Process with Snapshot Isolation

- Changed: Replaced the `dws` CLI wrapper with in-process background HIO doers
  for did:webs artifact and resolver services, copied the live stack's `.keri`
  state into separate snapshot HOME roots, and switched resolver startup checks
  to a direct TCP port wait.
- Why: In-process debugging was required, but shared qvi keystore paths caused
  same-process LMDB collisions.
- Verified: Compile checks for integration fixture helpers and the live
  single-sig test path.
- Touched/Risks: `.agents/PROJECT_LEARNINGS.md`. Snapshot isolation is correct
  for stable identifier state, but wrong for future tests that require
  post-launch identifier mutation.

### 2026-03-31 - Stock KERIpy Doers Must Own Cleanup

- Changed: Removed local managed copies of registry, issuance, grant, and admit
  doers; patched KERIpy stock doers to own `Notifier` instances and close
  `Noter`, `Regery`, and `Habery`; fixed `RegistryInceptor` temp forwarding,
  `CredentialIssuer` completion, and recipient-side grant lookup before admit.
- Why: Hidden `Notifier` ownership caused LMDB leaks and pushed Isomer toward
  the wrong local-wrapper abstraction.
- Verified: Compile checks on patched KERIpy doers and
  `tests/integration/kli_flow.py`, focused verifier/profile/status/JWT tests,
  and repeated live single-sig runs.
- Touched/Risks: `AGENTS.md` and `.agents/PROJECT_LEARNINGS.md`. Keep driving
  the live flow on stock KERIpy doers and upstream the fixes.

### 2026-03-31 - Schema Fixes Belong in Schemas, Not KERIpy Core

- Changed: Removed the VRD Auth schema workaround from KERIpy core, fixed the
  schema source to define `AID` directly, re-SAIDified it as
  `EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc`, and updated Isomer constants,
  fixtures, and integration references.
- Why: Product-specific behavior does not belong in KERIpy core, and schema
  body changes without re-SAIDification are dishonest.
- Verified: Focused profile, JWT, status, and verifier pytest runs.
- Touched/Risks: `AGENTS.md` and `.agents/PROJECT_LEARNINGS.md`. External repos
  may still reference the old schema artifact until they migrate.

### 2026-03-31 - Workflow Commands Must Run In-Process

- Changed: Recorded a hard rule against orchestrating KERI workflow steps
  through `kli` subprocesses when equivalent KERIpy doers or library APIs
  exist; kept subprocesses for long-lived services such as witnesses,
  `vLEI-server`, and `did-webs-resolver`.
- Why: Subprocess-driven KLI orchestration adds races, hides state, and makes
  debugging harder.
- Verified: The live-stack harness exposed multiple failures whose diagnosis was
  worsened by `kli` subprocess indirection.
- Touched/Risks: `AGENTS.md`. `tests/integration/kli_flow.py` still needed a
  full refactor away from `kli`.

### 2026-03-26 - Demo Signers Explicitly Banned

- Changed: Recorded a hard ban on demo signers, required CLI issuance and
  presentation paths to open live KERI habitats, and required tests to create
  real temporary habitats through KERI APIs when determinism is needed.
- Why: Bypassing live habitat signers would drift from the interoperability
  story Isomer is supposed to prove.
- Verified: KERI-backed JWT and verifier tests now use real temporary habitats
  instead of convenience signers.
- Touched/Risks: `AGENTS.md`, `docs/design-docs/PROJECT_LEARNINGS.md`, and
  `plans/w3c-vrd-isomer-plan.md`. The first true end-to-end workflow still
  needed wallet/KLI-backed live signer wiring beyond fixture-only inputs.
