# isomer-go

Minimal Go verifier sidecar for external W3C acceptance.

This app verifies the same VC-JWT and VP-JWT artifacts as `apps/isomer-node`,
using a pinned non-local `vc-go` module replacement as the independent Go W3C
stack.

For shared verifier semantics, see `../../docs/verifier-contract.md`.

## Scope

Owns:

- VC/VP parsing through `vc-go`
- JOSE EdDSA signature verification against `did:webs` key state
- embedded VC `DataIntegrityProof` verification
- projected status fetch/check
- optional dashboard webhook emission

Does not own:

- Isomer ACDC/W3C pair verification
- TEL-aware verification
- issuer, holder, or wallet workflow
- Python verifier behavior

## Dependency

The module uses a pinned non-local replacement:

```go
replace github.com/trustbloc/vc-go => github.com/kentbull/vc-go v0.0.0-20260129140819-c99b4c46239e
```

Default commands must not require a sibling `vc-go` checkout.

## Setup

```bash
cd apps/isomer-go
make sync
make check
```

From the repo root, `make external-go-check` delegates to the app-local
`check` target.

## Manual Run

```bash
cd apps/isomer-go
make serve
```

Override defaults with `ISOMER_HOST`, `ISOMER_PORT`, `ISOMER_RESOLVER_URL`, or
`ISOMER_RESOURCE_ROOT`.

Build the local container image:

```bash
cd apps/isomer-go
make image
```

The image target keeps the repo root as Docker context so it can copy
`src/vc_isomer/resources`. Those resources should eventually be factored into
the Go app.

Optional webhook settings:

- `--webhook-url` / `ISOMER_WEBHOOK_URL`
- `--verifier-id` / `ISOMER_VERIFIER_ID`, default `isomer-go`
- `--verifier-label` / `ISOMER_VERIFIER_LABEL`

## API

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`
- `POST /verify/vp` with
  `{ "token": "<vp-jwt>", "audience"?: "...", "nonce"?: "..." }`
- `GET /operations`
- `GET /operations/{name}`

Verify submissions return `202` operation stubs. Poll the operation resource
for the shared Isomer verifier result shape. This live operation surface is
what KERIA and the headless holder E2E harness validate.

VP JSON-LD checks remain the active gap tracked in
`../../plans/isomer-go-vp-vc-go-jsonld-fix.md`.
