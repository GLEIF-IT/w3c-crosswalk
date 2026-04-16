# isomer-go / vc-go VP JSON-LD Verification Fix Plan

## Summary

`apps/isomer-go` currently verifies Isomer VP-JWTs, but it does not yet run the
full `vc-go` JSON-LD validation path for the VP document. The sidecar validates:

- the VP-JWT compact serialization shape,
- the VP JWT registered claims,
- the VP JOSE EdDSA signature against the resolved `did:webs` key,
- the `vp.verifiableCredential` list shape,
- each nested VC-JWT through the full `verifyVC` path, including VC JOSE,
  embedded VC Data Integrity proof, status, and `vc-go/verifiable` VC parsing.

The current limitation is narrower and important: `verifyVP` calls
`verifiable.ParsePresentation(..., verifiable.WithDisabledJSONLDChecks())`.
That keeps the Go acceptance gate green, but it means the Go sidecar is not yet
proving that `vc-go` accepts the Isomer VP document through its JSON-LD checking
path.

Verdict: this is a real interop gap worth fixing, but it is not a blocker for
VC acceptance and it is not evidence that Isomer's VP-JWT is invalid. The next
task is to determine whether `vc-go` needs different parser options, a more
complete local document loader / DID resolver setup, a VP shape adjustment, or
an upstream/local `vc-go` fix for VCDM 1.1 VP-JWTs containing nested compact
VC-JWT strings.

## Current Working Baseline

Relevant files:

- `apps/isomer-go/internal/sidecar/verifier.go`
  - `verifyVC` uses `verifiable.ParseCredential` for the VC-JWT, manually
    verifies the VC JWT signature, verifies the embedded `DataIntegrityProof`
    with `vc-go/dataintegrity`, and dereferences `credentialStatus.id`.
  - `verifyVP` uses `verifiable.ParsePresentation` with
    `WithPresDisabledProofCheck()` and `WithDisabledJSONLDChecks()`, then
    manually verifies the VP JWT signature and verifies each nested VC-JWT by
    calling `verifyVC`.
- `apps/isomer-go/internal/sidecar/context_loader.go`
  - strict local document loader for:
    - `https://www.w3.org/2018/credentials/v1`
    - `https://w3id.org/security/data-integrity/v2`
    - `https://www.gleif.org/contexts/isomer-v1.jsonld`
- `apps/isomer-go/internal/sidecar/resolver.go`
  - resolves `did:webs` through the live Python stack,
  - adds DID/JWS contexts when missing,
  - normalizes KERI-style `JsonWebKey` Ed25519 methods into `JsonWebKey2020`,
  - expands `assertionMethod` and `authentication` relationships for tooling.
- `tests/integration/test_single_sig_vrd_isomer.py`
  - sends the same live VC-JWT and VP-JWT artifacts to sidecars when
    `ISOMER_EXTERNAL_VERIFIERS` is set to `go` or `node,go`.

Commands known to pass at the time this plan was written:

```bash
make external-go-check
ISOMER_EXTERNAL_VERIFIERS=go ./.venv/bin/python -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short
ISOMER_EXTERNAL_VERIFIERS=node,go ./.venv/bin/python -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short
```

The passing behavior means Go VP verification currently proves JOSE signature
validity plus nested VC acceptance. It does not yet prove `vc-go` VP JSON-LD
acceptance.

## Problem Statement

When the Go sidecar was first implemented, the VP path became unstable when
`verifiable.ParsePresentation` was allowed to run JSON-LD checks on the VP-JWT.
The practical fix was:

```go
verifiable.ParsePresentation(
    []byte(token),
    verifiable.WithPresDisabledProofCheck(),
    verifiable.WithDisabledJSONLDChecks(),
)
```

This avoided sidecar crashes or parse failures and kept the acceptance test
meaningful for JOSE plus nested VC-JWT verification. The remaining problem is
to remove `WithDisabledJSONLDChecks()` without regressing the e2e gate.

## Constraints

- Target VCDM 1.1 first. Do not drift into VCDM 2.0 semantics while fixing
  this.
- Keep the sidecar small. It is an acceptance harness and developer tool, not
  a replacement for Python Isomer's TEL/ACDC-aware verifier.
- Keep `vc-go` as the independent Go verifier stack. Do not call Python Isomer
  verifier logic from `apps/isomer-go`.
- Use the local sibling clone at `/Users/kbull/code/keri/kentbull/vc-go` via
  the existing Go module `replace`.
- Preserve the current HTTP contract:
  - `GET /healthz`
  - `POST /verify/vc`
  - `POST /verify/vp`
- Keep nested compact VC-JWT support. OpenID4VP-style VP-JWT flows commonly
  carry nested VC-JWT strings, so a fix that only works for embedded VC JSON
  objects is incomplete unless explicitly documented as an additional mode.

## Leading Hypotheses

1. `vc-go` may expect `vp.verifiableCredential` entries to be JSON objects
   during JSON-LD validation and may not treat compact VC-JWT strings as
   acceptable VCDM 1.1 JWT presentation content.
2. The sidecar may need a different `vc-go/verifiable` option set for JWT VPs,
   such as a JWT proof checker, a presentation-specific document loader, or a
   custom credential parser for nested JWT strings.
3. The local document loader may be sufficient for VC Data Integrity but
   incomplete for `vc-go`'s VP JSON-LD path. The VP path may request DID,
   security, JWS, or additional W3C contexts not currently registered.
4. The resolved `did:webs` document normalization may be enough for JOSE and VC
   Data Integrity, but not enough for `vc-go` presentation validation.
5. The Isomer VP shape may be valid for VC-JWT but too sparse for `vc-go`'s
   JSON-LD presentation parser. For example, `@context`, `type`, `holder`,
   `id`, or the nested credential representation may need close inspection.
6. There may be a real panic or bug in the local `vc-go` clone when parsing
   VCDM 1.1 JWT presentations that contain nested compact VC-JWT strings.

## Phase 1: Reproduce The Failure In A Focused Test

Goal: create a small failing test before changing behavior.

Steps:

1. Add a temporary or committed targeted test around `verifyVP` that exercises
   `verifiable.ParsePresentation` without `WithDisabledJSONLDChecks()`.
2. Prefer using a live artifact captured from
   `tests/integration/test_single_sig_vrd_isomer.py`, or add a test helper that
   writes the generated VP-JWT to a temp file when
   `ISOMER_CAPTURE_EXTERNAL_ARTIFACTS=1`.
3. Capture:
   - exact error message or panic,
   - VP JWT header,
   - decoded VP claim,
   - requested JSON-LD context URLs,
   - whether failure occurs before or after nested credential processing.
4. Keep the current green e2e behavior in place while developing. Do not remove
   `WithDisabledJSONLDChecks()` until the failing reproduction is understood.

Useful commands:

```bash
cd apps/isomer-go
env GOCACHE=/tmp/isomer-go-cache go test ./... -run TestName -count=1 -v
cd ../..
ISOMER_EXTERNAL_VERIFIERS=go ./.venv/bin/python -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short
```

## Phase 2: Inspect The Local vc-go Parsing Path

Goal: determine what `vc-go` expects for JWT presentations.

Use the sibling clone:

```bash
cd /Users/kbull/code/keri/kentbull/vc-go
rg -n "ParsePresentation|WithDisabledJSONLDChecks|WithPresDisabledProofCheck|verifiableCredential|jwt" .
```

Questions to answer:

- Does `vc-go/verifiable.ParsePresentation` officially support compact
  VP-JWTs?
- Does it support nested compact VC-JWT strings inside
  `vp.verifiableCredential`, or only embedded VC JSON objects?
- Is there an option for supplying a credential parser, proof checker, or JWT
  verifier for nested credentials?
- Does JSON-LD validation run on the VP object before or after nested
  credentials are decoded?
- Is `WithDisabledJSONLDChecks()` disabling only JSON-LD expansion/validation,
  or is it also bypassing other checks we should replace manually?

## Phase 3: Try Parser-Configuration Fixes First

Goal: fix `isomer-go` without changing Isomer's VP wire shape if possible.

Attempt these in order:

1. Pass the local document loader into the VP parser if `vc-go` exposes a
   presentation option for it.
2. Pass the sidecar DID resolver / public key fetcher into the VP parser if
   `vc-go` can use it for JWT presentation proof checks.
3. Register any additional contexts requested by the VP path, but keep tests
   strict: missing contexts should fail locally, not trigger remote fetch.
4. Check whether `vc-go` has a parser option for nested JWT credentials. If it
   does, wire that option so nested credentials are parsed through the same
   `verifyVC`-compatible path.
5. Keep manual JOSE verification if it remains clearer, but avoid duplicating
   `vc-go` checks once the library can do them safely.

Acceptance for this phase:

- `verifyVP` can call `verifiable.ParsePresentation` without
  `WithDisabledJSONLDChecks()`.
- Existing Node and Python e2e behavior remains unchanged.
- `ISOMER_EXTERNAL_VERIFIERS=go` still passes.

## Phase 4: Decide Whether Isomer VP Shape Must Change

Goal: only change the emitted VP shape if the current shape is invalid or too
non-idiomatic for VCDM 1.1 / VP-JWT interop.

Review the decoded VP-JWT payload from `vc_isomer.jwt.issue_vp_jwt` and compare
it to VCDM 1.1 VC-JWT/VP-JWT expectations:

- JWT claims: `iss`, `aud`, `nonce`, `iat`, `jti`, `vp`.
- VP document: `@context`, `type`, `holder`, `verifiableCredential`.
- Nested credential representation: compact VC-JWT strings versus embedded VC
  JSON objects.

If a shape change is needed, record the standard/library reason and update all
three verifier paths together:

- Python Isomer verifier,
- Node sidecar,
- Go sidecar.

Do not make a Go-only VP shape.

## Phase 5: Patch vc-go Only If Necessary

Goal: keep Isomer maintainable while preserving an independent verifier.

If the failure is a local `vc-go` bug or missing feature:

1. Create a minimal reproduction in `/Users/kbull/code/keri/kentbull/vc-go`.
2. Add or update a `vc-go` test demonstrating VCDM 1.1 VP-JWT parsing with
   nested compact VC-JWT strings.
3. Patch the local clone.
4. Keep `apps/isomer-go/go.mod` pointing at the sibling clone via `replace`.
5. Re-run the Isomer e2e gates.

Do not copy `vc-go` code into `w3c-crosswalk`.

## Desired End State

- `apps/isomer-go/internal/sidecar/verifier.go` no longer needs
  `verifiable.WithDisabledJSONLDChecks()` in `verifyVP`.
- Go sidecar result checks distinguish:
  - `jwtEnvelopeValid`,
  - `signatureValid`,
  - `vcGoParsed`,
  - `vpJsonLdValid`,
  - `embeddedCredentialsVerified`.
- The Go sidecar README no longer describes VP JSON-LD as disabled, or it
  documents a much narrower and intentional limitation.
- `docs/w3c-vc-libs-options.md` reflects the final `vc-go` behavior.
- The live integration test passes with:

```bash
ISOMER_EXTERNAL_VERIFIERS=go ./.venv/bin/python -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short
ISOMER_EXTERNAL_VERIFIERS=node,go ./.venv/bin/python -m pytest tests/integration/test_single_sig_vrd_isomer.py -q --tb=short
```

## Non-Goals

- Do not implement Isomer ACDC/W3C pair equivalence in Go.
- Do not implement TEL verification in Go.
- Do not replace Python Isomer's authoritative verifier.
- Do not switch this task to VCDM 2.0, SD-JWT VC, BBS, or COSE.
- Do not weaken the Python or Node sidecar behavior to match Go's current gap.

## Handoff Notes

The fastest next move is to make the failure observable. Temporarily remove
`verifiable.WithDisabledJSONLDChecks()` from `verifyVP`, run the Go unit tests
and the live `ISOMER_EXTERNAL_VERIFIERS=go` pytest gate, and capture the exact
error. Once the error is concrete, inspect the local `vc-go` parsing path before
changing Isomer's emitted VP shape.
