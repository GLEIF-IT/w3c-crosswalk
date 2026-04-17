# W3C VRD Isomer Plan

## Summary

Target plan doc location: `isomer/plans/w3c-vrd-isomer-plan.md`.

This plan now starts from the current baseline rather than a greenfield phase-1
story. The core Isomer path already exists: live KERI-habitat-backed issuance
from GEDA -> QVI -> LE -> VRD Auth -> VRD, authoritative VRD ACDC projection
into a VRD W3C VC, and presentation or verification acceptance across the three
current verifier implementations: Python, Node, and Go.

The remaining roadmap is:

1. lock the completed end-to-end backbone as the baseline,
2. add key rotation with latest-key verification semantics,
3. add revocation with TEL-backed W3C status projection and rejection across
   all three verifiers,
4. build the mobile and verifier UI surfaces from the
   `verifier-initiated-openid4vp-cli-parity` direction,
5. defer KF Wallet and other wallet integrations to an explicit bonus round.

`did-webs-resolver` remains the mandatory W3C key-state resolution dependency.
Isomer remains the home for W3C projection, verification, status projection,
CLI orchestration, and the new UI surfaces.

## Nine Phases + Bonus Round

### 1. Foundation, Profile, and Fixture Contract - DONE
- Isomer now exists as the canonical home for the Python-first implementation,
  profile docs, fixtures, tests, plans, and demo/runtime seams.
- The repo has a stable Isomer profile for VRD Auth and VRD and a fixture set
  that captures the contract for projection and verification work.
- The W3C bridge target is VCDM 1.1 JSON-LD credentials with VC-JWT or VP-JWT
  envelopes and embedded KERI-backed `eddsa-rdfc-2022` Data Integrity proofs.

### 2. Live ACDC Issuance Spine - DONE
- The baseline live flow already proves KERI-habitat-backed issuance through
  the GEDA -> QVI -> LE -> VRD Auth -> VRD chain.
- Runtime and integration signing are live-habitat only; deterministic demo
  signers are explicitly out of scope.
- The flagship integration path is now the authoritative source of truth for
  Isomer's issuance story.

### 3. VRD W3C Projection - DONE
- Isomer already projects the authoritative VRD ACDC into a VRD W3C VC rather
  than treating W3C artifacts as the source of truth.
- The projected credential uses the current Isomer profile, VCDM 1.1 JSON-LD
  conventions, and KERI-backed Data Integrity proofs.
- The CLI and runtime surfaces already support the projection and verification
  path needed for the live story.

### 4. did:webs Resolution and Verifier Bridge - DONE
- W3C issuer or presenter key-state verification runs through
  `did-webs-resolver`, not embedded JWK shortcuts or direct `did.json` trust.
- Isomer already uses `did:webs` as the bridge DID method for the W3C side of
  the flow.
- The current runtime contract keeps DID resolution and key-state lookup in the
  resolver dependency rather than collapsing those concerns into Isomer.

### 5. Three-Verifier Acceptance Baseline - DONE
- The current end-to-end baseline now includes presentation or verification
  acceptance across Python, Node, and Go verifier implementations.
- Python remains the authoritative Isomer verifier for TEL-aware and
  ACDC-to-W3C pair semantics, while Node and Go provide independent W3C-side
  acceptance evidence.
- This three-verifier path is now the baseline that later key-rotation,
  revocation, and UI work must preserve.

### 6. Key Rotation
- Add support for issuer and presenter key rotation while preserving the same
  VRD ACDC -> VRD W3C VC verification story.
- Prove that Python, Node, and Go verifiers all resolve and validate against
  the latest key state exposed through `did-webs-resolver`.
- Prove that verification fails when an artifact is checked against superseded
  or stale prior keys.
- Treat latest-key resolution semantics as the phase success condition, not an
  implementation detail.

### 7. Revocation and TEL-Backed Status Projection
- Implement credential revocation for the TEL-backed VRD ACDC and project that
  revocation state into the W3C `credentialStatus` surface.
- Update the Isomer credential status service so revocation becomes visible to
  the W3C verification path through the projected status endpoint.
- Prove that Python, Node, and Go each reject the revoked credential after the
  status update lands.
- Keep the W3C status layer as a projection of TEL truth rather than a separate
  source of truth.

### 8. `isomer-mobile`
- Build the minimal mobile-first holder or presenter app described in
  `verifier-initiated-openid4vp-cli-parity.md`.
- Scope the app narrowly: hold one or more W3C VC-JWT artifacts locally, load
  or fetch an OpenID4VP request object, present through the standards-shaped
  OpenID4VP flow, and show recent request or presentation history.
- Favor a polished demo-grade product surface over broad wallet functionality.
- Keep the implementation aligned with the existing Isomer CLI and verifier
  semantics instead of inventing a parallel protocol.

### 9. `isomer-verifier-ui`
- Build the minimal verifier dashboard or web app described in
  `verifier-initiated-openid4vp-cli-parity.md`.
- Scope the UI to request creation, QR or deep-link launch material, recent
  presentation status, and single-presentation drill-down views.
- Include the small signed admin or control API needed to drive those flows.
  Use signed requests rooted in a whitelisted KERI AID rather than shared
  secrets or password-only control auth.
- Keep the verifier UI aligned with the same OpenID4VP request or response
  semantics used by the Python CLI and the backend verifier surfaces.

## Bonus Round: KF Wallet and Other Wallet Integrations

- KF Wallet, Flet app work, and other wallet integrations are now explicitly
  outside the critical path.
- Treat them as follow-on integration work after the mobile and verifier UI
  surfaces are stable.
- Any future KF Wallet integration should wrap the same settled Isomer
  verification and presentation contracts rather than redefining the roadmap.

## Important Interfaces and Public Changes

### Isomer ownership
- `isomer` remains the canonical home for W3C projection, Python verification,
  status projection, CLI orchestration, OpenID4VP request/response handling,
  `isomer-mobile`, and `isomer-verifier-ui`.
- `did-webs-resolver` remains the hard DID and latest-key-state dependency for
  W3C verification.
- The active verifier set this plan names explicitly is Python, Node, and Go.

### Runtime contracts
- W3C verification resolves `did:webs` issuer or presenter DIDs through
  `did-webs-resolver`.
- W3C credentials continue to carry stable linkage to their source ACDC and
  schema lineage.
- W3C status remains an Isomer-owned projection of TEL and registry truth.
- Key rotation work must preserve latest-key verification semantics across
  Python, Node, and Go.
- Revocation work must preserve rejection semantics across Python, Node, and
  Go after TEL-backed status projection updates.
- UI work should follow the `verifier-initiated-openid4vp-cli-parity` model,
  including a signed KERI-AID-based admin/control API for verifier-side control
  actions.

## Test Plan

### Current baseline
- End-to-end flow from GEDA issuance through QVI, LE, VRD Auth, and VRD ACDC
  issuance.
- Projection of the authoritative VRD ACDC into the VRD W3C VC.
- Presentation or verification acceptance across Python, Node, and Go.
- DID and key-state verification through `did-webs-resolver`.

### Phase 6
- Rotate issuer or presenter keys and verify that Python, Node, and Go all use
  the latest resolved key state.
- Verify that artifacts checked against stale prior keys fail.

### Phase 7
- Revoke the TEL-backed VRD ACDC, update the projected W3C status surface, and
  confirm rejection across Python, Node, and Go.
- Verify that the credential status service reflects the revocation update
  needed by the W3C verification path.

### Phases 8-9
- `isomer-mobile` can load or fetch an OpenID4VP request and complete the
  standards-shaped presentation flow with the current verifier surfaces.
- `isomer-verifier-ui` can create requests, render QR or deep-link launch
  material, and show recent presentation outcomes.
- Signed admin/control API requests succeed only for authorized KERI AIDs.

## Assumptions and Defaults

- Canonical plan path remains `isomer/plans/w3c-vrd-isomer-plan.md`.
- The plan structure is now `Nine Phases + Bonus Round`.
- Python, Node, and Go are the primary verifier implementations this roadmap
  names explicitly.
- `verifier-initiated-openid4vp-cli-parity.md` is the source of truth for the
  direction of `isomer-mobile`, `isomer-verifier-ui`, and the signed
  KERI-AID-based admin/control API.
- KF Wallet/Flet is deferred and explicitly removed from the critical path.
- `did:webs` remains the bridge DID method and `did-webs-resolver` remains a
  hard dependency for W3C verification.
- Real runtime and integration signing must continue to use live KERI habitats.
