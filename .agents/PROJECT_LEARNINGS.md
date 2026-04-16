# PROJECT_LEARNINGS

Routing index and durable cross-topic memory for `isomer`.

## Current Focus

1. Land the first true end-to-end ACDC -> W3C VRD Isomer flow.
2. Keep `did-webs-resolver` mandatory for W3C key-state verification.
3. Enforce live KERI habitat signers everywhere; no demo signers.
4. Move integration workflow helpers from `kli` subprocess orchestration to
   in-process KERIpy doers.

## Topic Learnings Index

| Topic | File | Scope |
| ----- | ---- | ----- |
| Signing and Issuance | `.agents/learnings/PROJECT_LEARNINGS_SIGNING_AND_ISSUANCE.md` | Signer policy, issuance seams, runtime vs test boundaries |

## Context Pack Policy

At session start:

1. Read `AGENTS.md`.
2. Read this file.
3. Read only the topic doc(s) relevant to the task.
4. Read any plan docs those topic docs reference.

## Cross-Topic Snapshot

1. Demo signers are banned; runtime and integration signing must use live
   KERI-managed habitats.
2. Test determinism is acceptable only through real temporary habitats created
   from KERI-managed salt or passcode inputs.
3. `did-webs-resolver` is a hard dependency for W3C verification; verifier key
   lookup must not bypass it.
4. `w3c-signer` is legacy reference material, not a production base.
5. Long-lived services may be subprocesses, but KERI workflow logic should stay
   in-process through KERIpy doers or library APIs.
6. Maintainer-facing Python code in `src/` and `tests/` should use concise
   Google-style docstrings.
7. Product-specific schema defects belong in the schema layer, not in KERIpy
   core validation.
8. Any schema body change must be re-SAIDified, and all constants, fixtures,
   and docs must move to the new SAID.
9. Prefer stock KERIpy doers over local managed copies; if cleanup or lifecycle
   behavior is wrong, fix KERIpy instead of growing a parallel doer layer.
10. For live-stack debugging, start with short pytest traces, 20-40 line source
    slices, and narrow log reads.
11. Verifier operation metadata stays intentionally minimal for the PoC; do not
    reintroduce heavy tracing unless the project commits to a real observability
    design.
12. In-process `did:webs` debugging should run artifact and resolver services as
    background HIO doers, each with its own snapshot HOME/`.keri` tree to avoid
    same-process LMDB collisions.
13. Packaging uses a three-name split: distribution `vc-isomer`, import package
    `vc_isomer`, CLI `isomer`; product-facing naming stays Isomer.
14. Publishing is Makefile-driven with `uv build`, `twine check` via `uvx`, and
    guarded `uv publish` targets that require a clean worktree unless
    `ALLOW_DIRTY=1`.
15. Isomer's W3C bridge target is VCDM 1.1 first: 2018 credentials context,
    `issuanceDate`, VCDM 1.1 `vc`/`vp` JWT claims, and KERI-backed
    `eddsa-rdfc-2022` Data Integrity proofs.
16. First interop artifacts include packaged JSON-LD contexts, a packaged W3C
    JSON Schema, and OpenID4VCI/OpenID4VP metadata examples.
17. External acceptance runs through Node and Go sidecars to validate VC-JWT,
    VP-JWT, embedded Data Integrity proof, and status interop without replacing
    Isomer's TEL/ACDC-aware Python pair verifier.
18. JSON-LD `id` values must be absolute IRIs; when a nested ACDC SAID becomes a
    W3C `id`, represent it as `urn:said:<SAID>` and keep the raw SAID in the
    signed Isomer provenance block.

## Handoff Template

When updating a topic doc, capture:

1. What changed
2. Why it changed
3. Verification used
4. Contracts or plans touched
5. Risks and TODOs
