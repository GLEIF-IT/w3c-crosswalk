# PROJECT_LEARNINGS_SIGNING_AND_ISSUANCE

Persistent memory for signer policy, issuance flow rules, and signing-related
interop behavior.

## Current Status

1. Demo signers are banned.
2. Runtime and integration signing must use live KERI habitat signers.
3. Test determinism is allowed only through real temporary habitats created via
   KERI APIs.
4. CLI or service paths that mint W3C credentials without opening a real
   habitat signer are incomplete.

## Active Contracts

- `docs/isomer-profile.md` is the W3C projection contract.
- `docs/verifier-contract.md` is the Python/Node/Go verifier boundary.
- `docs/integration-maintainer-guide.md` is the live-stack mental model.
- `plans/w3c-vrd-isomer-plan.md` is the current roadmap.

## Durable Decisions

### Holder Presentation Boundary

- W3C holder presentation verification must bind three separate facts:
  QVI-issued VC issuer DID, LE-signed VP holder DID, and verifier request
  binding through `aud` and `nonce`.
- A verifier accepting a QVI-signed VP is a boundary bug. The QVI issues the
  VC; the LE holder presents it.
- A verifier accepting an LE-as-issuer VC is also a boundary bug for VRD W3C
  credentials. The final VRD W3C VC issuer is QVI did:webs and the subject is
  LE did:webs.
- `headless-w3c-e2e` is the Python-first acceptance harness boundary under
  `packages/headless-w3c-e2e`; it is an integration-style E2E utility. Fake
  in-process verifier callables, CLI-only verifier commands, and fixture-only
  verifier responses are not acceptance evidence. Signing artifacts and live
  acceptance must come from real KERI-backed signers and live verifier services.
- `headless-w3c-e2e` now exposes live HTTP verifier service clients instead of
  `CommandVerifier`/callable verifier suites. Acceptance evidence is collected
  from KERIA-created verifier operations after KERIA submits the holder VP-JWT.
  Direct harness POSTs are diagnostic only and are not the holder presentation
  path under test.
- Python, Node, and Go verifier services enforce holder-role semantics in the
  W3C service path: successful embedded VC `credentialSubject.id` values must
  match `vp.holder`, and Isomer `sourceIssuerAid` must match the terminal AID
  segment of `vc.issuer`. This makes QVI-signed VPs and LE-as-issuer VCs live
  service rejections, not only Python pair-verifier policy failures.

### Signing

- Use live KERIpy habitats (`Hab`, `Habery`) for signing.
- For KERIA W3C holder presentation, signing happens at the Signify edge only.
  KERIA may stage exact signing inputs over signed SSE or polling fallback and
  verify returned signatures, but KERIA must not hold private edge keys or sign
  W3C token material server-side.
- Stable salts, passcodes, and aliases are acceptable for deterministic tests.
- Do not reintroduce deterministic demo signers.

### DID Resolution

- W3C key-state verification goes through `did-webs-resolver`.
- Do not bypass DID resolution with embedded JWK shortcuts.
- Preserve query-bearing DID URLs such as `?versionId=...`.

### Data Integrity And JSON-LD

- Isomer targets VCDM 1.1 first.
- Use `issuanceDate`, VCDM 1.1 `vc`/`vp` claims, and KERI-backed
  `eddsa-rdfc-2022` proofs.
- Verify data order is `proofConfigHash + transformedDocumentHash`.
- Proof-option canonicalization includes the VC `@context`.
- Unknown JSON-LD contexts fail closed.
- `publicKeyJwk` and `publicKeyMultibase` are both acceptable Ed25519
  verification material when resolved from DID documents.

### Identifier Safety

- JSON-LD `id` values must be absolute IRIs.
- Nested ACDC SAIDs represented as W3C identifiers use `urn:said:<SAID>`.
- The raw SAID remains in signed Isomer provenance where needed.

### Verifier Boundaries

- Python Isomer remains authoritative for TEL-aware and ACDC/W3C pair checks.
- Node uses `did-jwt-vc` plus explicit embedded-proof and status checks.
- Go uses pinned `vc-go` plus explicit sidecar checks.
- Node and Go do not import or call Python verifier logic.
- Raw-token debug logging is demo/local observability and must not become
  production posture.

### Workflow

- Long-lived external services may be subprocesses.
- KERI workflow logic should use KERIpy doers or library APIs when available.
- Local managed doer wrappers are integration debt until upstream cleanup seams
  are available.

### Portability

- Default local setup consumes packages, pinned refs, or images.
- Editable installs are developer overrides only.
- Default commands must not require sibling source checkouts.

## Current Follow-Ups

- Resolve the Go VP JSON-LD validation gap in
  `plans/isomer-go-vp-vc-go-jsonld-fix.md`.
- Add key rotation and TEL-backed revocation acceptance across Python, Node,
  and Go.
- Build OpenID4VP from the Python reference backend before UI work.
