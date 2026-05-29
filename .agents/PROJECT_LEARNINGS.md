# PROJECT_LEARNINGS

Routing index and durable cross-topic memory for `isomer`.

## Current Focus

1. Keep the live ACDC -> W3C VRD Isomer flow honest and test-backed.
2. Keep `did-webs-resolver` mandatory for W3C key-state verification.
3. Enforce live KERI habitat signers everywhere; no demo signers.
4. Keep default local setup portable through packages, pinned refs, or images.

## Topic Learnings Index

| Topic | File | Scope |
| ----- | ---- | ----- |
| Signing and Issuance | `.agents/learnings/PROJECT_LEARNINGS_SIGNING_AND_ISSUANCE.md` | Signing policy, issuance invariants, verifier boundaries |

## Context Pack Policy

At session start:

1. Read `AGENTS.md`.
2. Read this file.
3. Read only task-relevant topic docs.
4. Read task-relevant source, tests, docs, and plans.

## Current Invariants

1. KERI KEL/TEL/ACDC state is the source of truth; W3C artifacts are
   interoperability projections.
2. Runtime and integration signing must use live KERI-managed habitats.
3. Test determinism is acceptable only through real temporary habitats created
   from KERI-managed salt or passcode inputs.
4. `did-webs-resolver` is the hard DID and key-state dependency for W3C
   verification.
5. `w3c-signer` is legacy reference material, not a production base.
6. Python Isomer is authoritative for TEL-aware and ACDC/W3C pair verification.
7. Node and Go are external W3C acceptance gates.
8. JSON-LD contexts are pinned locally and unknown contexts fail closed.
9. Nested ACDC SAIDs that become W3C `id` values use `urn:said:<SAID>`.
10. Default scripts, Dockerfiles, and compose files must not require sibling
    source checkouts.

## Handoff Template

When updating topic memory, capture:

1. What changed
2. Why it changed
3. Verification used
4. Contracts or plans touched
5. Risks and TODOs
