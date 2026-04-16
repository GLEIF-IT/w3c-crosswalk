# W3C VRD Isomer Plan

## Summary

Target plan doc location: `isomer/plans/w3c-vrd-isomer-plan.md`.

This project will be run as a Python-first, CLI-first isomer program with 
`isomer` as the canonical home, 
`wallet` as the first holder and issuer integration target, 
`did-webs-resolver` as the mandatory W3C key-state resolution dependency, and `sally` as the ACDC verifier branch point. The first deliverable is a complete issue-hold-verify-revoke story for VRD Auth and VRD across both ACDC and W3C VC-JWT, with real revocation and a dual verifier that requires both forms in one workflow.

Active code repos for phase 1:
- `isomer`: new monorepo for isomer-specific packages, services, CLIs, docs, fixtures, and demo orchestration.
- `wallet`: KF wallet integration on `feat/workflows-flet-1-0`.
- `did-webs-resolver`: resolver hardening and any interface additions needed for production W3C verification.
- `sally`: ACDC-specific VRD verifier variants on a dedicated branch.

Reference-only repos for phase 1:
- `qvi-software`: issuance spine and workflow reference.
- `w3c-signer`: mapping and signing reference only, not a runtime dependency.
- `keri-ts`: roadmap consumer of the shared profile and fixtures, not a parallel implementation target in phase 1.

## Seven Phases

### 1. Foundation, Repo Shape, and Canonical Profile
- Initialize `isomer` as a real git repo and create `plans/`, `docs/`, `packages/`, `apps/`, `fixtures/`, and `scripts/`.
- Create a normative isomer profile for both VRD Auth and VRD that freezes claim mapping, issuer and holder semantics, source ACDC references, schema lineage, revocation semantics, and error taxonomy.
- Define one language-neutral fixture set in `isomer/fixtures/` that becomes the contract for both Python now and `keri-ts` later.
- Decision: phase 1 uses VCDM 1.1 JSON-LD credentials with VC-JWT envelopes
  and embedded KERI-backed Data Integrity proofs. SD-JWT, BBS, and COSE
  envelopes remain explicitly deferred.

### 2. CLI-First Demo Spine and Environment Orchestration
- Treat [`vlei-workflow.sh`](/Users/kbull/code/gleif-it/qvi-software/qvi-workflow/kli_only/vlei-workflow.sh#L5) as the issuance authority for the ACDC side and do not fork its semantics.
- Build an isomer orchestration layer in `isomer/scripts/` that boots witnesses, wallet dependencies, `did-webs-resolver`, Sally, the W3C verifier, and the status service with one command.
- Standardize on CLI entrypoints first for issuance, export, present, verify, revoke, and status sync. UI work starts only after the CLI path is stable.
- Decision: every demo path must be reproducible from a clean machine with scripted startup and seeded fixtures.

### 3. Wallet ACDC Issue and Hold Flow
- Extend the wallet’s existing issuing and credential management surfaces to support VRD Auth and VRD ACDCs end to end, using the same GEDA -> QVI -> LE story as the baseline.
- Keep wallet as the first issuer-holder UX surface. Phase 1 will use scripted wallet actions or thin CLI wrappers before any Flet UX work.
- Make VRD Auth and VRD both mandatory phase-1 scope. Neither is allowed to lag the other because the edge chain is part of the story.
- Decision: wallet remains the first integration target; KERIA, SignifyPy, and SignifyTS are explicitly second-pass adapter targets.

### 4. W3C Twin Issuance with did:webs as the Key-State Bridge
- Add W3C twin generation inside `isomer` with wallet integration hooks, not inside `w3c-signer`.
- The wallet-issued W3C twin must be derived from the authoritative ACDC,
  signed by the LE Ed25519 key bound to the LE AID, include an
  `eddsa-rdfc-2022` Data Integrity proof, and be enveloped as a VCDM 1.1
  VC-JWT using the `vc` claim.
- All W3C verification of issuer key material must resolve through `did-webs-resolver`. The verifier must not trust embedded JWK shortcuts, raw exported keys, or direct `did.json` fetches.
- Standardize on the `did-webs-resolver` Universal Resolver service contract as the runtime dependency. Local tests may wrap it with a thin `didwebs-client` package in `isomer`, but resolution still goes through the resolver semantics.
- Decision: `did:webs` is the canonical bridge DID for this project.

### 5. Real Status and Revocation from Day 1
- Create a dedicated isomer status service in `isomer` that exposes dereferenceable W3C `credentialStatus` resources backed by KERI TEL and registry state.
- Keep `did-webs-resolver` focused on DID and key-state resolution only. Status does not live in the resolver.
- Add CLI tooling for revocation and propagation so revoking the ACDC VRD updates the W3C twin’s status path and causes W3C verification to fail on the next check.
- Add a simple sync mechanism in phase 1 that lets the W3C issuer observe registry changes and project them into the W3C status layer. More advanced automation can come later, but manual sync is not acceptable as the steady-state verifier path.
- Decision: phase 1 uses an isomer-owned status endpoint backed by TEL state. Broader status-list standardization can be added later if needed for third-party verifier interop.

### 6. Verifier Suite: ACDC, W3C, and Dual
- Keep ACDC-specific verification in Sally on a dedicated branch. Extend Sally with VRD Auth and VRD validation rules in the same style as its existing credential-chain validators.
- Build the W3C verifier as a separate service in `isomer`. It verifies the
  VC-JWT/VP-JWT envelope, the embedded VC Data Integrity proof, DID resolution
  through `did-webs-resolver`, and revocation through the isomer status service.
- Build a dual verifier in `isomer` that requires both the ACDC and W3C forms in one workflow and rejects on any mismatch in issuer, subject, LEI, type, chain references, source linkage, or revocation state.
- Decision: Sally stays ACDC-native. The W3C verifier and dual orchestration live in `isomer`.

### 7. Presentation Surface, UX Pass, and TS-Ready Handoff
- Support four W3C presentation modes in phase 1. These are direct VC-JWT
  verification, direct VP-JWT verification, OpenID4VP same-device, and
  OpenID4VP cross-device QR.
- Add developer-facing OpenID4VCI/OpenID4VP metadata examples for the VCDM 1.1
  `jwt_vc_json-ld` flow, but do not build a full OpenID issuer or verifier
  server until a concrete interop target appears.
- Add the second-pass Flet UX flow in the wallet after the CLI path is stable and testable. The UI must wrap the same underlying commands and services, not reimplement the workflow.
- Preserve all profile docs, fixtures, and verifier conformance cases as language-neutral assets so the later `keri-ts` effort can reimplement against the same contract.
- Decision: Python first, shared profile and fixtures from day 1, TypeScript second.

## Important Interfaces and Public Changes

### `isomer` monorepo contents
- `packages/isomer_profile`: normative mappings, fixtures, and profile docs for VRD Auth and VRD.
- `packages/didwebs_client`: thin client for the resolver service contract used by issuer and verifier components.
- `apps/isomer_cli`: CLI for issue, export, present, verify, revoke, and status sync flows.
- `apps/w3c_verifier`: W3C verifier service for VC-JWT, VP-JWT, embedded Data
  Integrity proof verification, OpenID4VP, DID resolution, and revocation
  checks.
- `apps/status_service`: W3C `credentialStatus` service backed by KERI TEL.
- `scripts/demo`: startup, seeding, and end-to-end demo orchestration.

### Runtime contracts
- W3C verifier resolves every `did:webs` issuer or presenter DID via `did-webs-resolver` service semantics.
- W3C credentials carry stable machine-readable linkage to their source ACDC and schema lineage.
- Revocation checks for W3C credentials go through the isomer status service, which projects KERI registry truth.
- Dual verification requires both ACDC and W3C artifacts and compares semantic equivalence before returning success.

### Repo ownership
- `wallet`: issuer and holder integration, later Flet UX.
- `did-webs-resolver`: DID and key-state resolution only.
- `sally`: ACDC verification only.
- `isomer`: all W3C-specific logic, isomer-specific logic, demo tooling, and orchestration.

## Test Plan

### Core conformance
- Fixture-driven tests for VRD Auth and VRD mapping from ACDC to W3C.
- Signature verification tests where the verifier succeeds only when key material is resolved through `did-webs-resolver`.
- Revocation tests where ACDC revoke state is projected into W3C status and later verification fails.

### Integration
- End-to-end flow from GEDA issuance to wallet-held VRD Auth and VRD ACDCs.
- Wallet export of W3C VC-JWT twins signed by the LE AID key.
- Sally validation of ACDC VRD Auth and VRD presentations.
- W3C verifier validation of direct VC-JWT and VP-JWT presentations.
- Dual verifier success path requiring both ACDC and W3C forms.
- OpenID4VP same-device and cross-device QR flows.

### Failure scenarios
- `did-webs-resolver` unavailable or returning mismatched key state.
- W3C twin claims drift from the source ACDC.
- Revoked ACDC still presented as if valid W3C.
- VRD Auth and VRD edge mismatch.
- Wrong LEI, wrong issuer DID, wrong source linkage, or stale status response.
- Sally passes while W3C fails, and vice versa, with the dual verifier correctly rejecting both partial-truth cases.

## Assumptions and Defaults

- Canonical plan path is `isomer/plans/w3c-vrd-isomer-plan.md`.
- `isomer` is the canonical project home even though `wallet`, `did-webs-resolver`, and `sally` remain separate repos.
- Phase 1 is CLI first and Python first.
- The later `keri-ts` effort will reuse the same fixtures and profile, not the Python implementation.
- `did:webs` is the bridge DID method and `did-webs-resolver` is a hard dependency for W3C verification.
- Real status and revocation are required in phase 1.
- `w3c-signer` is reference material only and will not be treated as production foundation.
- Deterministic demo signers are banned; all runtime and integration signing must come from live KLI/KERIpy habitat signers, with tests allowed to use only KERI-created temporary habitats via salt or passcode.
