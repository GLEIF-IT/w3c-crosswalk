# Isomer External W3C Verifier Sidecars

> Note:
> This plan reflects the earlier "external verifier sidecar" phase of the work.
> The newer verifier-initiated OpenID4VP parity plan in
> `plans/verifier-initiated-openid4vp-cli-parity.md` supersedes it for any work
> that turns Node and Go into full verifier backends driven by the same Python
> `isomer` CLI. Keep this document for historical sidecar context, but treat the
> newer parity plan as authoritative for backend convergence work.

## Summary

Build external W3C verifier acceptance in two ordered phases: first a fully
functional TypeScript/Node sidecar, then a Go sidecar after Node is green.
These sidecars prove that Isomer's VCDM 1.1 VC-JWT and VP-JWT artifacts can be
verified outside the Python Isomer verifier.

Confirmed local sources:

- `../did-jwt-vc` exists at `/Users/kbull/code/keri/kentbull/did-jwt-vc`.
- `../vc-go` exists at `/Users/kbull/code/keri/kentbull/vc-go`.
- Sidecars depend on those sibling clones during local and CI interop work.

The sidecars are acceptance harnesses and developer tools. They do not replace
Python Isomer's TEL/ACDC-aware verifier because external W3C libraries cannot
verify KERI TEL state or Isomer ACDC/W3C pair equivalence.

## Phase 0: Capture The Plan

- Keep this file as the restartable implementation plan.
- Update it when library behavior forces a meaningful contract change.
- Keep the sidecars trim: no operation store, no pair verification, no
  Isomer-specific ACDC/TEL logic beyond dereferencing the projected status URL.

## Phase 1: Node Sidecar First

- Build `apps/isomer-node` before starting `apps/isomer-go`.
- Use TypeScript with Effection structured concurrency, following local
  `keri-ts` runtime style.
- Use Hono plus a Node HTTP adapter.
- Depend on the sibling `did-jwt-vc` clone through the app-local file
  dependency `file:../../../did-jwt-vc`.
- Use the `did-jwt-vc` verifier for VC-JWT and VP-JWT envelopes.
- Verify embedded `DataIntegrityProof` / `eddsa-rdfc-2022` with strict local
  JSON-LD contexts and Ed25519 verification against resolved did:webs key
  material.
- Resolve did:webs documents through the existing live-stack resolver URL.
- Dereference `credentialStatus.id` against the existing Python status service.

HTTP contract:

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`
- `POST /verify/vp` with `{ "token": "<vp-jwt>", "audience"?: "...", "nonce"?: "..." }`

Responses use Isomer-shaped verifier results:

```json
{
  "ok": true,
  "kind": "vc+jwt",
  "errors": [],
  "warnings": [],
  "checks": {},
  "payload": {}
}
```

## Phase 2: Python Wrapper And Node E2E Gate

- Add `src/vc_isomer/interop/external_verifiers.py`.
- The wrapper starts/stops sidecars, waits on `/healthz`, posts verification
  requests, and captures log tails for pytest diagnostics.
- Extend `tests/integration/test_single_sig_vrd_isomer.py` so the same live
  VC-JWT and VP-JWT are transmitted to the Node sidecar.
- Gate the external Node check with `ISOMER_EXTERNAL_VERIFIERS=node`.
- If the env var is unset, the existing Python e2e path remains unchanged.

## Phase 3: Go Sidecar After Node Is Green

- Build `apps/isomer-go` after Node is functional.
- Use the sibling `vc-go` clone through:

```go
replace github.com/trustbloc/vc-go => ../../../vc-go
```

- Implement the same HTTP contract as Node.
- Use `vc-go/verifiable` to parse VC and VP artifacts as the independent Go
  W3C stack.
- Use Go `context.Context` and `net/http` for lifecycle and cancellation.
- Verify JOSE EdDSA signatures against did:webs JWK material.
- Verify embedded Data Integrity proof using the same strict local context and
  Ed25519 semantics. Prefer `vc-go` Data Integrity helpers where the local
  context and did:webs method model fit cleanly; otherwise keep the verifier
  logic small and document the gap.

## Phase 4: Go E2E Gate And Shared CI Entry Points

- Extend the Python subprocess wrapper to start/stop `apps/isomer-go`.
- Extend the live e2e integration test so the same VC-JWT and VP-JWT are sent
  to Go.
- Support:
  - `ISOMER_EXTERNAL_VERIFIERS=node`
  - `ISOMER_EXTERNAL_VERIFIERS=go`
  - `ISOMER_EXTERNAL_VERIFIERS=node,go`
- Add Makefile targets:
  - `external-node-sync`
  - `external-node-check`
  - `external-go-check`
  - `test-external-w3c-node`
  - `test-external-w3c-go`
  - `test-external-w3c-all`
- Keep external sidecar tests out of `prepublish` until dependency setup is
  stable in CI.

## Docs And Acceptance

- Update `docs/cli-e2e-walkthrough.md` with an external verifier acceptance
  section.
- Update `docs/w3c-vc-libs-options.md` with the Node-first, Go-second strategy
  and the local sibling clone dependency model.
- Update `.agents` learnings after implementation.

Acceptance criteria:

- Existing Python e2e still passes.
- Node sidecar verifies the live VC-JWT and VP-JWT from the existing e2e flow.
- Go sidecar verifies the live VC-JWT and the VP-JWT plus nested VC-JWTs.
- Revoked status remains checked through the Python status service.
- External sidecars do not import or call Python Isomer verifier logic.
