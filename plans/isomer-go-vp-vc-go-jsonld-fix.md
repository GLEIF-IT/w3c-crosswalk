# isomer-go VP JSON-LD Verification Fix Plan

## Summary

`apps/isomer-go` verifies Isomer VP-JWTs today, but the VP path does not yet
prove full `vc-go` JSON-LD acceptance for the VP document.

Current Go VP verification proves:

- VP-JWT compact serialization shape
- VP JWT registered claims
- VP JOSE EdDSA signature against resolved `did:webs` key state
- `vp.verifiableCredential` list shape
- nested VC-JWT verification through the full VC path

The remaining gap is removing `verifiable.WithDisabledJSONLDChecks()` from the
VP parsing path without regressing the live sidecar gate.

Verdict: this is a real interop gap, but it is not evidence that Isomer's
VP-JWT shape is invalid. The next step is a focused reproduction.

## Current Baseline

Relevant files:

- `apps/isomer-go/internal/sidecar/vp_verifier.go`
- `apps/isomer-go/internal/sidecar/vc_verifier.go`
- `apps/isomer-go/internal/sidecar/context_loader.go`
- `apps/isomer-go/internal/sidecar/resolver.go`
- `tests/integration/test_single_sig_vrd_isomer.py`

Known green gates:

```bash
make external-go-check
ISOMER_EXTERNAL_VERIFIERS=go ./.venv/bin/python -m pytest \
  tests/integration/test_single_sig_vrd_isomer.py -q --tb=short
ISOMER_EXTERNAL_VERIFIERS=node,go ./.venv/bin/python -m pytest \
  tests/integration/test_single_sig_vrd_isomer.py -q --tb=short
```

## Constraints

- Target VCDM 1.1 first.
- Keep Go as an independent W3C acceptance sidecar.
- Do not call Python verifier logic from Go.
- Do not copy `vc-go` code into this repo.
- Keep the current `/verify/vc` and `/verify/vp` HTTP contract.
- Preserve nested compact VC-JWT support.

## Leading Hypotheses

1. `vc-go` may expect JSON object credentials during VP JSON-LD validation and
   may not accept nested compact VC-JWT strings in VCDM 1.1 presentations.
2. The VP parser may need different options for JWT presentations, document
   loading, DID resolution, or nested JWT credential parsing.
3. The local document loader may be missing contexts used only by the VP path.
4. Resolved `did:webs` normalization may satisfy JOSE and VC proof checks but
   not presentation validation.
5. The Isomer VP document may be too sparse for `vc-go` JSON-LD parsing.
6. The pinned `vc-go` module may have a bug or missing feature for this shape.

## Work Plan

### 1. Reproduce In A Focused Test

Add or temporarily run a targeted Go test that calls
`verifiable.ParsePresentation` without `WithDisabledJSONLDChecks()`.

Capture:

- exact error or panic
- decoded VP claim
- requested JSON-LD context URLs
- whether failure happens before or after nested credential handling

Keep the current green e2e path until the failure is understood.

### 2. Inspect `vc-go` Parsing Expectations

Inspect the pinned Go module source for:

- compact VP-JWT support
- nested compact VC-JWT support
- parser options for document loaders, proof checkers, DID resolvers, or nested
  credential parsers
- the scope of `WithDisabledJSONLDChecks()`

### 3. Try Parser Configuration First

Prefer configuration over wire-shape changes:

- pass the local document loader if supported
- wire resolver/public-key hooks if supported
- add missing local contexts only when explicitly requested by the VP path
- use a nested JWT credential parser if `vc-go` exposes one

Acceptance: Go VP parsing runs without disabled JSON-LD checks and the current
Node/Python behavior remains unchanged.

### 4. Change Isomer VP Shape Only If Required

Only change emitted VP shape if the current shape is invalid or materially
non-idiomatic for VCDM 1.1 / VP-JWT interop.

If shape changes are required, update Python, Node, and Go together. Do not
create a Go-only VP shape.

### 5. Patch Upstream Dependency Only If Necessary

If the failure is a `vc-go` bug or missing feature, create a minimal
reproduction in the dependency module, patch there, and keep Isomer consuming
the dependency through its pinned non-local module replacement.

## Desired End State

- Go no longer disables VP JSON-LD checks.
- Go result checks distinguish JWT envelope validity, signature validity,
  `vc-go` parsing, VP JSON-LD validity, and nested credential verification.
- `apps/isomer-go/README.md` and `docs/verifier-contract.md` reflect the final
  limitation or resolved behavior.
